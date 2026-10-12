"""OpenAI SDK wrapper: scan every call through a Vault, one wrapper.

Example:
    from openai import OpenAI
    from llm_sentinel import Vault, default_scanners
    from llm_sentinel.adapters.openai import guard_openai

    client = guard_openai(OpenAI(), Vault(default_scanners()))
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": user_text}],
    )

What gets guarded:

- ``chat.completions.create``: every message's text (string content and
  text blocks) is scanned before the call; each choice's message
  content is scanned after it.
- ``completions.create``: the ``prompt`` is scanned before, each
  choice's ``text`` after.
- ``responses.create``: the ``input`` (string, message list, or content
  blocks) is scanned before, ``output_text`` and the output items'
  text blocks after.

Sync and async clients both work: wrap an ``AsyncOpenAI`` client in
``GuardedAsyncOpenAI`` (or ``guard_openai_async``) and ``create`` stays
a coroutine. Anything the wrapper does not know about (``client.models``,
``client.beta``, plain attributes) passes straight through to the real
client untouched.

The wrapper never imports the OpenAI SDK. It wraps whatever object has
the shape above, which is also how the tests drive it with fakes.
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

OpenAIBlockedError = ProviderBlockedError

_PROVIDER = "OpenAI"


def _input_texts(args: tuple, kwargs: dict) -> list[str]:
    texts: list[str] = []
    messages = kwargs.get("messages")
    if messages is None and args:
        messages = args[0]
    texts.extend(texts_from_messages(messages))
    prompt = kwargs.get("prompt")
    if isinstance(prompt, str):
        texts.append(prompt)
    elif isinstance(prompt, (list, tuple)):
        texts.extend(t for t in prompt if isinstance(t, str))
    raw_input = kwargs.get("input")
    if isinstance(raw_input, str):
        texts.append(raw_input)
    else:
        texts.extend(texts_from_messages(raw_input))
        texts.extend(texts_from_content(raw_input if not isinstance(raw_input, list) else None))
    instructions = kwargs.get("instructions")
    if isinstance(instructions, str):
        texts.append(instructions)
    return texts


def _chat_output_fields(response: Any) -> list[TextField]:
    fields: list[TextField] = []
    choices = get_field(response, "choices") or []
    for choice in choices:
        message = get_field(choice, "message")
        if message is not None and isinstance(get_field(message, "content"), str):
            fields.append(attr_field(message, "content"))
        if isinstance(get_field(choice, "text"), str):
            fields.append(attr_field(choice, "text"))
    return fields


def _responses_output_fields(response: Any) -> list[TextField]:
    fields: list[TextField] = []
    if isinstance(get_field(response, "output_text"), str):
        fields.append(attr_field(response, "output_text"))
    output = get_field(response, "output") or []
    for item in output:
        content = get_field(item, "content")
        if isinstance(content, list):
            for i, block in enumerate(content):
                if isinstance(get_field(block, "text"), str):
                    fields.append(attr_field(block, "text"))
                elif isinstance(block, str):
                    fields.append(index_field(content, i))
    fields.extend(_chat_output_fields(response))
    return fields


class _CompletionsProxy:
    """Wraps one create() surface (chat completions or legacy completions)."""

    def __init__(self, real: Any, guard: ProviderGuard, fields_fn) -> None:
        self._real = real
        self._guard = guard
        self._fields_fn = fields_fn

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self._guard.check_inputs(_input_texts(args, kwargs), _PROVIDER)
        response = self._real.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._guard.check_outputs(self._fields_fn(response), _PROVIDER)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _AsyncCompletionsProxy:
    def __init__(self, real: Any, guard: ProviderGuard, fields_fn) -> None:
        self._real = real
        self._guard = guard
        self._fields_fn = fields_fn

    async def create(self, *args: Any, **kwargs: Any) -> Any:
        self._guard.check_inputs(_input_texts(args, kwargs), _PROVIDER)
        response = await self._real.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._guard.check_outputs(self._fields_fn(response), _PROVIDER)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _ChatProxy:
    def __init__(self, real: Any, guard: ProviderGuard, proxy_cls) -> None:
        self._real = real
        self._guard = guard
        self._proxy_cls = proxy_cls

    @property
    def completions(self) -> Any:
        return self._proxy_cls(self._real.completions, self._guard, _chat_output_fields)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _GuardedOpenAIBase:
    _proxy_cls: type = _CompletionsProxy
    _chat_proxy_cls: type = _ChatProxy

    def __init__(self, client: Any, guard: ProviderGuard) -> None:
        self._client = client
        self._guard = guard

    @property
    def chat(self) -> Any:
        return self._chat_proxy_cls(self._client.chat, self._guard, self._proxy_cls)

    @property
    def completions(self) -> Any:
        return self._proxy_cls(self._client.completions, self._guard, _chat_output_fields)

    @property
    def responses(self) -> Any:
        return self._proxy_cls(self._client.responses, self._guard, _responses_output_fields)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class GuardedOpenAI(_GuardedOpenAIBase):
    """A sync OpenAI client with a Vault on its create() calls."""

    _proxy_cls = _CompletionsProxy
    _chat_proxy_cls = _ChatProxy

    def __init__(self, client: Any, vault: Vault, **guard_kwargs: Any) -> None:
        super().__init__(client, ProviderGuard(vault, **guard_kwargs))


class GuardedAsyncOpenAI(_GuardedOpenAIBase):
    """An async OpenAI client with a Vault on its create() calls."""

    _proxy_cls = _AsyncCompletionsProxy
    _chat_proxy_cls = _ChatProxy

    def __init__(self, client: Any, vault: Vault, **guard_kwargs: Any) -> None:
        super().__init__(client, ProviderGuard(vault, **guard_kwargs))


def guard_openai(client: Any, vault: Vault, **guard_kwargs: Any) -> GuardedOpenAI:
    """Wrap a sync OpenAI client. See the module docstring for the shape."""
    return GuardedOpenAI(client, vault, **guard_kwargs)


def guard_openai_async(client: Any, vault: Vault, **guard_kwargs: Any) -> GuardedAsyncOpenAI:
    """Wrap an AsyncOpenAI client; create() calls stay coroutines."""
    return GuardedAsyncOpenAI(client, vault, **guard_kwargs)
