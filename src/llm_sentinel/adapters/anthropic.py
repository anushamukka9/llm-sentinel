"""Anthropic SDK wrapper: scan every call through a Vault, one wrapper.

Example:
    import anthropic
    from llm_sentinel import Vault, default_scanners
    from llm_sentinel.adapters.anthropic import guard_anthropic

    client = guard_anthropic(anthropic.Anthropic(), Vault(default_scanners()))
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_text}],
    )

What gets guarded:

- ``messages.create``: the ``system`` prompt (string or text blocks)
  and every message's text are scanned before the call; each text
  block in the response ``content`` is scanned after it.
- ``completions.create`` (legacy): the ``prompt`` is scanned before,
  the response ``completion`` after.

Sync and async clients both work: wrap an ``AsyncAnthropic`` client in
``GuardedAsyncAnthropic`` (or ``guard_anthropic_async``) and ``create``
stays a coroutine. Anything the wrapper does not know about passes
straight through to the real client untouched.

The wrapper never imports the Anthropic SDK. It wraps whatever object
has the shape above, which is also how the tests drive it with fakes.
Streaming (``stream=True``) scans the input only; see
``adapters.providers`` for why, and for the block/redact semantics.
"""

from __future__ import annotations

from typing import Any

from ..vault import Vault
from .providers import (
    ProviderBlockedError,
    ProviderGuard,
    TextField,
    attr_field,
    get_field,
    index_field,
    texts_from_content,
    texts_from_messages,
)

AnthropicBlockedError = ProviderBlockedError

_PROVIDER = "Anthropic"


def _input_texts(args: tuple, kwargs: dict) -> list[str]:
    texts: list[str] = []
    messages = kwargs.get("messages")
    if messages is None and args:
        messages = args[0]
    texts.extend(texts_from_messages(messages))
    texts.extend(texts_from_content(kwargs.get("system")))
    prompt = kwargs.get("prompt")
    if isinstance(prompt, str):
        texts.append(prompt)
    return texts


def _output_fields(response: Any) -> list[TextField]:
    fields: list[TextField] = []
    content = get_field(response, "content")
    if isinstance(content, list):
        for i, block in enumerate(content):
            if isinstance(get_field(block, "text"), str):
                fields.append(attr_field(block, "text"))
            elif isinstance(block, str):
                fields.append(index_field(content, i))
    if isinstance(get_field(response, "completion"), str):
        fields.append(attr_field(response, "completion"))
    return fields


class _MessagesProxy:
    def __init__(self, real: Any, guard: ProviderGuard) -> None:
        self._real = real
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self._guard.check_inputs(_input_texts(args, kwargs), _PROVIDER)
        response = self._real.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._guard.check_outputs(_output_fields(response), _PROVIDER)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _AsyncMessagesProxy:
    def __init__(self, real: Any, guard: ProviderGuard) -> None:
        self._real = real
        self._guard = guard

    async def create(self, *args: Any, **kwargs: Any) -> Any:
        self._guard.check_inputs(_input_texts(args, kwargs), _PROVIDER)
        response = await self._real.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._guard.check_outputs(_output_fields(response), _PROVIDER)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _GuardedAnthropicBase:
    _messages_proxy_cls: type = _MessagesProxy

    def __init__(self, client: Any, guard: ProviderGuard) -> None:
        self._client = client
        self._guard = guard

    @property
    def messages(self) -> Any:
        return self._messages_proxy_cls(self._client.messages, self._guard)

    @property
    def completions(self) -> Any:
        return self._messages_proxy_cls(self._client.completions, self._guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class GuardedAnthropic(_GuardedAnthropicBase):
    """A sync Anthropic client with a Vault on its create() calls."""

    _messages_proxy_cls = _MessagesProxy

    def __init__(self, client: Any, vault: Vault, **guard_kwargs: Any) -> None:
        super().__init__(client, ProviderGuard(vault, **guard_kwargs))


class GuardedAsyncAnthropic(_GuardedAnthropicBase):
    """An async Anthropic client with a Vault on its create() calls."""

    _messages_proxy_cls = _AsyncMessagesProxy

    def __init__(self, client: Any, vault: Vault, **guard_kwargs: Any) -> None:
        super().__init__(client, ProviderGuard(vault, **guard_kwargs))


def guard_anthropic(client: Any, vault: Vault, **guard_kwargs: Any) -> GuardedAnthropic:
    """Wrap a sync Anthropic client. See the module docstring for the shape."""
    return GuardedAnthropic(client, vault, **guard_kwargs)


def guard_anthropic_async(client: Any, vault: Vault, **guard_kwargs: Any) -> GuardedAsyncAnthropic:
    """Wrap an AsyncAnthropic client; create() calls stay coroutines."""
    return GuardedAsyncAnthropic(client, vault, **guard_kwargs)
