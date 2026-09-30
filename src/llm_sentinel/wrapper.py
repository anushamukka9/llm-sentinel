"""Function middleware: the ``@guarded`` decorator.

Wraps any callable so its string inputs and its string return value pass
through a Vault:

    @guarded(vault)
    def summarize(user_request: str) -> str:
        ...

Semantics, stated plainly:
- Every string positional/keyword argument is scanned before the function
  runs. A blocked input raises :class:`GuardedError`; it is refused, never
  scrubbed and passed through, because redacting an injection does not
  make it safe.
- A string return value is scanned after the function runs. A blocked
  output raises :class:`GuardedError`, unless ``redact=True``, in which
  case the redacted text is returned instead.
- Non-string arguments and return values pass through untouched.

This is the simple per-function version of the framework middleware in
``llm_sentinel.adapters`` (FastAPI, LangChain): no framework required.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TypeVar

from .vault import Vault

F = TypeVar("F", bound=Callable[..., object])


class GuardedError(ValueError):
    """Raised when a Vault blocks a guarded function's input or output.

    The message names the blocked side and the scanners that fired, never
    the matched text itself: exception text has a habit of ending up in
    logs.
    """


def guarded(
    vault: Vault,
    *,
    on_input: bool = True,
    on_output: bool = True,
    redact: bool = False,
) -> Callable[[F], F]:
    """Decorate a function so a Vault scans its string inputs and output.

    Args:
        vault: the policy to enforce.
        on_input: scan string arguments before the call (default True).
        on_output: scan a string return value after the call (default True).
        redact: on a blocked output, return the redacted text instead of
            raising. Inputs are never redacted: a blocked input always
            raises.
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            if on_input:
                for text in list(args) + list(kwargs.values()):
                    if not isinstance(text, str):
                        continue
                    result = vault.scan(text)
                    if result.blocked:
                        scanners = sorted({f.scanner for f in result.findings})
                        raise GuardedError(
                            f"guarded function {fn.__name__!r}: input blocked by "
                            + ", ".join(scanners)
                        )
            out = fn(*args, **kwargs)
            if on_output and isinstance(out, str):
                result = vault.scan(out, redact=redact)
                if result.blocked:
                    if redact and result.redacted_text is not None:
                        return result.redacted_text
                    scanners = sorted({f.scanner for f in result.findings})
                    raise GuardedError(
                        f"guarded function {fn.__name__!r}: output blocked by "
                        + ", ".join(scanners)
                    )
            return out

        return wrapper  # type: ignore[return-value]

    return decorator
