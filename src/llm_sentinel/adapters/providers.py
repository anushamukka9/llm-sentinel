"""Shared plumbing for the provider SDK wrappers (OpenAI, Anthropic).

The wrappers in ``adapters.openai`` and ``adapters.anthropic`` are
duck-typed on purpose: they never import the provider SDKs, they just
wrap a client object that has the usual shape (``chat.completions.create``
for OpenAI, ``messages.create`` for Anthropic). That keeps the core
package dependency-free and makes the wrappers testable with small fake
clients, no API keys and no network.

Semantics, stated plainly, mirroring the ``@guarded`` decorator:

- Message text going in is scanned before the provider is called. A
  blocked input raises :class:`ProviderBlockedError` and the provider
  call never happens. Inputs are refused, never scrubbed and passed
  through, because redacting an injection does not make it safe.
- Response text coming back is scanned after the call. A blocked output
  raises too, unless ``redact=True``, in which case each blocked text
  field is replaced in place with its redacted version. If a response
  object refuses in-place edits, redaction raises instead of silently
  returning the leaking text.
- Error messages name the scanners that fired, never the matched text:
  exception text has a habit of ending up in logs.
- Streaming calls (``stream=True``) are the one gap: inputs are still
  scanned, but the streamed output is passed through unscanned, because
  the wrapper returns before the chunks exist. If you need streamed
  output scanned, buffer it and scan it yourself with the same Vault.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..vault import Vault


class ProviderBlockedError(ValueError):
    """Raised when a Vault blocks a provider call's input or output."""


def get_field(obj: Any, name: str) -> Any:
    """Read ``name`` from a dict or an object; None when absent."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def set_field(obj: Any, name: str, value: Any) -> None:
    """Write ``name`` on a dict or an object."""
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


class TextField:
    """One mutable text slot inside a response object.

    Responses nest text in different places per provider (a choice's
    message content, a content block's text, a top-level output_text),
    so each slot is captured as a getter/setter pair over wherever it
    actually lives: a dict key, an object attribute, or a list index.
    """

    def __init__(self, getter: Callable[[], Any], setter: Callable[[str], None]) -> None:
        self._getter = getter
        self._setter = setter

    @property
    def text(self) -> Any:
        return self._getter()

    def replace(self, value: str) -> None:
        self._setter(value)


def attr_field(obj: Any, name: str) -> TextField:
    return TextField(lambda: get_field(obj, name), lambda v: set_field(obj, name, v))


def index_field(items: list, index: int) -> TextField:
    return TextField(lambda: items[index], lambda v: items.__setitem__(index, v))


def texts_from_content(content: Any) -> list[str]:
    """Pull every text string out of a message content value.

    Content shows up as a plain string, a list of blocks (dicts or
    objects with a ``text`` field, or a nested ``content`` for tool
    results), or None. Non-text blocks (images, tool calls) contribute
    nothing. Unknown shapes are ignored, never an error: scanning is a
    guardrail, it should not crash the call it guards.
    """
    if content is None:
        return []
    if isinstance(content, str):
        return [content]
    if isinstance(content, (list, tuple)):
        texts: list[str] = []
        for block in content:
            if isinstance(block, str):
                texts.append(block)
                continue
            text = get_field(block, "text")
            if isinstance(text, str):
                texts.append(text)
            texts.extend(texts_from_content(get_field(block, "content")))
        return texts
    return []


def texts_from_messages(messages: Any) -> list[str]:
    """All text in a chat-style messages list (dicts or objects)."""
    texts: list[str] = []
    if not isinstance(messages, (list, tuple)):
        return texts
    for message in messages:
        texts.extend(texts_from_content(get_field(message, "content")))
    return texts


class ProviderGuard:
    """The scan policy both provider wrappers share."""

    def __init__(
        self,
        vault: Vault,
        *,
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        redact: bool = False,
    ) -> None:
        self.vault = vault
        self.scan_inputs = scan_inputs
        self.scan_outputs = scan_outputs
        self.redact = redact

    def _scanners(self, result) -> str:
        return ", ".join(sorted({f.scanner for f in result.findings}))

    def check_inputs(self, texts: list[str], provider: str) -> None:
        if not self.scan_inputs:
            return
        for text in texts:
            if not text:
                continue
            result = self.vault.scan(text)
            if result.blocked:
                raise ProviderBlockedError(
                    f"{provider} call blocked by guardrails on input: {self._scanners(result)}"
                )

    def check_outputs(self, fields: list[TextField], provider: str) -> None:
        """Scan response text fields; redact in place when allowed."""
        if not self.scan_outputs:
            return
        for field in fields:
            text = field.text
            if not isinstance(text, str) or not text:
                continue
            result = self.vault.scan(text, redact=self.redact)
            if not result.blocked:
                continue
            if self.redact and result.redacted_text is not None:
                try:
                    field.replace(result.redacted_text)
                except Exception as exc:
                    raise ProviderBlockedError(
                        f"{provider} response blocked by guardrails on output: "
                        f"{self._scanners(result)}; redaction failed because the "
                        "response object would not accept an in-place edit"
                    ) from exc
                continue
            raise ProviderBlockedError(
                f"{provider} response blocked by guardrails on output: {self._scanners(result)}"
            )
