"""Token-limit scanner.

Estimates the token count of the text with the classic chars/4 heuristic
and flags text that exceeds ``max_tokens``. Useful as a cheap pre-check
before sending a prompt to a model with a context window (or a bill).

Limitations, stated plainly:
- chars/4 is a rough average for English prose. Code, non-English text,
  and emoji-heavy text tokenize very differently; the estimate can be
  off by 2x or more. For exact counts, use the model's real tokenizer;
  this scanner deliberately has no tokenizer dependency.
- It estimates, then flags. It does not truncate; truncation that splits
  mid-instruction is a policy decision for your code, not this scanner.
"""

from __future__ import annotations

from ..core import Finding, Scanner


def estimate_tokens(text: str) -> int:
    """Rough token estimate: one token per four characters."""
    return max(1, len(text) // 4)


class TokenLimitScanner(Scanner):
    """Flags text estimated to exceed ``max_tokens`` tokens."""

    name = "token_limit"

    def __init__(self, max_tokens: int = 4000) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        self.max_tokens = max_tokens

    def scan(self, text: str) -> list[Finding]:
        estimated = estimate_tokens(text)
        if estimated <= self.max_tokens:
            return []
        return [
            Finding(
                scanner=self.name,
                score=0.9,
                start=0,
                end=len(text),
                matched_text=text[:60],
                message=(f"Estimated {estimated} tokens exceeds limit of {self.max_tokens}"),
            )
        ]
