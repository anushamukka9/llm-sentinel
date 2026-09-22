"""LangChain adapter: scan prompts and model outputs through a Vault.

Two thin pieces:

- ``SentinelCallbackHandler``: a LangChain callback that scans every
  prompt on ``on_llm_start`` and every generation on ``on_llm_end``.
  Blocked prompts raise ``SentinelBlockedError`` before the model is
  called; blocked outputs raise after.
- ``guard_runnable``: wraps any ``Runnable`` so ``invoke`` scans the
  input first and the output after.

Example:
    from langchain_core.runnables import RunnableLambda
    from llm_sentinel import Vault, default_scanners
    from llm_sentinel.adapters.langchain import guard_runnable

    chain = RunnableLambda(lambda x: "echo: " + x["q"])
    safe = guard_runnable(chain, Vault(default_scanners()))
    safe.invoke({"q": "hello"})
"""

from __future__ import annotations

from typing import Any

from ..vault import Vault

try:
    from langchain_core.callbacks import BaseCallbackHandler

    _HAVE_LC = True
except ImportError:  # pragma: no cover
    _HAVE_LC = False


class SentinelBlockedError(ValueError):
    """Raised when the Vault blocks a prompt or a model output."""


def _flatten_prompts(prompts: list[str]) -> str:
    return "\n".join(prompts)


class SentinelCallbackHandler(BaseCallbackHandler if _HAVE_LC else object):  # type: ignore[misc]
    """LangChain callback handler enforcing a Vault on prompts and outputs.

    ``raise_error`` is set so a blocked prompt/output raises
    ``SentinelBlockedError`` out of ``invoke`` instead of being swallowed
    by LangChain's callback manager (which logs handler errors by default).
    """

    raise_error = True

    def __init__(
        self,
        vault: Vault,
        *,
        scan_prompts: bool = True,
        scan_outputs: bool = True,
    ) -> None:
        if not _HAVE_LC:  # pragma: no cover
            raise ImportError(
                "SentinelCallbackHandler needs langchain-core installed: "
                "pip install llm-sentinel[langchain]"
            )
        super().__init__()
        self.vault = vault
        self.scan_prompts = scan_prompts
        self.scan_outputs = scan_outputs

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        if not self.scan_prompts:
            return
        result = self.vault.scan(_flatten_prompts(prompts))
        if result.blocked:
            raise SentinelBlockedError(
                "Prompt blocked by guardrails: " + "; ".join(f.message for f in result.findings[:3])
            )

    def on_llm_end(self, response, **kwargs: Any) -> None:
        if not self.scan_outputs:
            return
        texts = []
        for generation in getattr(response, "generations", []):
            for gen in generation:
                texts.append(getattr(gen, "text", ""))
        result = self.vault.scan("\n".join(texts))
        if result.blocked:
            raise SentinelBlockedError(
                "Model output blocked by guardrails: "
                + "; ".join(f.message for f in result.findings[:3])
            )


def guard_runnable(runnable, vault: Vault, **kwargs):
    """Wrap a LangChain Runnable with input/output scanning.

    Returns a new Runnable; the original is untouched.
    """
    if not _HAVE_LC:  # pragma: no cover
        raise ImportError(
            "guard_runnable needs langchain-core installed: pip install llm-sentinel[langchain]"
        )
    from langchain_core.runnables import RunnableLambda

    handler = SentinelCallbackHandler(vault, **kwargs)

    def _guarded(input_value):
        text = input_value if isinstance(input_value, str) else str(input_value)
        result = vault.scan(text)
        if result.blocked:
            raise SentinelBlockedError(
                "Input blocked by guardrails: " + "; ".join(f.message for f in result.findings[:3])
            )
        output = runnable.invoke(input_value)
        out_text = output if isinstance(output, str) else str(output)
        out_result = vault.scan(out_text)
        if out_result.blocked:
            raise SentinelBlockedError(
                "Output blocked by guardrails: "
                + "; ".join(f.message for f in out_result.findings[:3])
            )
        return output

    inner = RunnableLambda(_guarded)
    inner.callbacks = [handler]
    return inner
