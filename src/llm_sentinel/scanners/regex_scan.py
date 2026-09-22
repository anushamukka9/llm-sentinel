"""User-defined regex scanner.

The escape hatch: when none of the built-in scanners matches your policy,
bring your own patterns.

- ``forbidden``: patterns that must NOT appear. Each hit is a finding.
- ``required``: patterns that MUST appear. Each missing pattern is one
  finding on the whole text ("required pattern not found").

Limitations, stated plainly:
- This scanner is exactly as good as the regexes you write. Bad regexes
  (catastrophic backtracking, over-broad matches) are your problem;
  keep patterns simple and test them.
- A missing required pattern produces a single finding covering the whole
  text, which redacts everything. Think about whether that is the
  redaction behavior you want before combining with ``redact=True``.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding


class RegexScanner(Scanner):
    """Enforces custom required/forbidden regex patterns."""

    name = "regex"

    def __init__(
        self,
        *,
        forbidden: list[str] | None = None,
        required: list[str] | None = None,
    ) -> None:
        if not forbidden and not required:
            raise ValueError("RegexScanner needs at least one forbidden or required pattern")
        self.forbidden = [re.compile(p) for p in (forbidden or [])]
        self.required = [re.compile(p) for p in (required or [])]

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.forbidden:
            for match in find_all(pattern, text):
                findings.append(
                    make_finding(
                        self.name, match, 0.8, f"Forbidden pattern matched: {pattern.pattern!r}"
                    )
                )
        for pattern in self.required:
            if not pattern.search(text):
                findings.append(
                    Finding(
                        scanner=self.name,
                        score=0.8,
                        start=0,
                        end=len(text),
                        matched_text=text[:60],
                        message=f"Required pattern not found: {pattern.pattern!r}",
                    )
                )
        return findings
