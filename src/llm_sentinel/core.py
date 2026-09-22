"""Core primitives: findings, scan results, and the Scanner protocol.

Everything in llm-sentinel is built on these three ideas:

- A ``Scanner`` looks at text and reports ``Finding`` objects. It never
  mutates the text and never calls a model. Deterministic in, deterministic out.
- A ``Finding`` is a fact about a span of text: which scanner found it, how
  confident the scanner is (``score`` in 0..1), and where it is.
- A ``Vault`` chains scanners together and applies a policy: block the text,
  redact the offending spans, or just report.

Scores are scanner-local confidence values, not calibrated probabilities.
A score of 0.9 from the secrets scanner does not mean "90% chance this is a
secret" in any statistical sense; it means the pattern is a strong,
unambiguous match. Do not compare scores across scanners.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Finding:
    """One thing a scanner noticed in the text.

    Attributes:
        scanner: Name of the scanner that produced this finding.
        score: Scanner-local confidence in 0..1. Higher is stronger.
        start: Character offset where the match starts.
        end: Character offset where the match ends (exclusive).
        matched_text: The exact text that matched.
        message: Short human-readable explanation.
    """

    scanner: str
    score: float
    start: int
    end: int
    matched_text: str
    message: str


@dataclass
class ScanResult:
    """Outcome of running a Vault over one piece of text.

    Attributes:
        text: The original input text (never modified).
        findings: All findings, sorted by score descending.
        blocked: True when the policy says this text must not pass through.
        redacted_text: Text with every finding span replaced by a
            placeholder, or None when redaction was not requested.
    """

    text: str
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False
    redacted_text: str | None = None

    @property
    def passed(self) -> bool:
        """True when no finding met the block threshold."""
        return not self.blocked

    def findings_for(self, scanner: str) -> list[Finding]:
        """All findings from one scanner, highest score first."""
        return [f for f in self.findings if f.scanner == scanner]


class Scanner(Protocol):
    """The contract every scanner implements.

    A scanner is a pure function over text: no network, no model calls,
    no side effects. ``scan`` must be safe to call from any thread.
    """

    name: str

    def scan(self, text: str) -> list[Finding]:
        """Return findings for ``text``. Empty list means clean."""
        ...
