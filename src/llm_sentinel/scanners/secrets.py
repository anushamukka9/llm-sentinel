"""Secrets scanner.

Detects credentials that should never appear in a prompt or a model
output: provider API keys (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic),
generic ``key = value`` assignments, and unlabelled high-entropy tokens.

Limitations, stated plainly:
- Regexes cover the well-known formats. Private or in-house key formats
  will not match unless you add them via ``extra_patterns``.
- The entropy heuristic (``looks_random``) is deliberately conservative and
  still produces false positives on UUIDs, hashes, and random-looking
  non-secrets. It also misses short or low-entropy secrets entirely.
- A key split across lines, redacted with asterisks, or shown only
  partially will not be caught. This scanner sees literal text, not intent.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, looks_random, make_finding

_NAMED: list[tuple[str, re.Pattern[str], float]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.98),
    (
        "GitHub token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        0.98,
    ),
    (
        "GitHub fine-grained token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        0.98,
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.97,
    ),
    ("Stripe key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0.97),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), 0.95),
    (
        "Anthropic key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        0.97,
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        0.95,
    ),
    (
        "Generic secret assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|"
            r"access[_-]?token|private[_-]?key|password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=]{12,})['\"]?",
        ),
        0.85,
    ),
]

# Bare tokens with no label nearby: word-boundary runs of token-ish chars.
_BARE_TOKEN = re.compile(r"\b[A-Za-z0-9_\-+/=]{24,}\b")


class SecretsScanner(Scanner):
    """Flags API keys, tokens, and other credentials in text.

    Pass ``extra_patterns`` as ``[(label, regex_string, score), ...]`` to
    cover in-house key formats. Set ``entropy_scan=False`` to disable the
    heuristic bare-token check (fewer false positives, more misses).
    """

    name = "secrets"

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, float]] | None = None,
        entropy_scan: bool = True,
    ) -> None:
        self.patterns: list[tuple[str, re.Pattern[str], float]] = list(_NAMED)
        for label, rx, score in extra_patterns or []:
            self.patterns.append((label, re.compile(rx), score))
        self.entropy_scan = entropy_scan

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        for label, pattern, score in self.patterns:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, f"Possible {label}"))
                claimed.append(match.span())
        if self.entropy_scan:
            for match in find_all(_BARE_TOKEN, text):
                start, end = match.span()
                if any(s <= start and end <= e for s, e in claimed):
                    continue
                token = match.group()
                if looks_random(token):
                    findings.append(
                        make_finding(
                            self.name,
                            match,
                            0.55,
                            "High-entropy token (unlabelled; verify before treating as a secret)",
                        )
                    )
        return findings
