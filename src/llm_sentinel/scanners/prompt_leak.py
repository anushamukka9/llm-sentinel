"""Prompt-leak scanner (output side).

Detects model output that discloses system or developer instructions:
"my system prompt", "my instructions are", "I was instructed to", and
similar disclosure phrasing. Built for scanning model output before it
reaches the user: a model that quotes its own instructions is either
misconfigured or being steered.

This is deliberately not in ``default_scanners()``, which is the
input-side set. Add it explicitly when you scan model output:

    Vault(default_scanners() + [PromptLeakScanner()])

Limitations, stated plainly:
- This is phrase matching, not understanding. Paraphrased disclosures and
  partial quotes will slip through.
- Benign self-reference ("my instructions are to be helpful") flags too.
  Pair with a human review step or tune the block threshold when that
  hurts.
- Scores are per-pattern severity guesses, not probabilities.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding

# (compiled pattern, score, message)
_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (
        re.compile(
            r"\bmy\s+(system prompt|system instructions|initial instructions|"
            r"hidden instructions|developer instructions|developer message)\b",
            re.IGNORECASE,
        ),
        0.9,
        "References its own system/developer instructions",
    ),
    (
        re.compile(
            r"\bhere('s| is) my (system prompt|instructions)\b",
            re.IGNORECASE,
        ),
        0.95,
        "Offers up its system prompt or instructions",
    ),
    (
        re.compile(
            r"\b(according to|per)\s+my\s+(instructions|system prompt)\b",
            re.IGNORECASE,
        ),
        0.85,
        "Quotes its own instructions as authority",
    ),
    (
        re.compile(
            r"\bmy\s+instructions\s+(are|say|state|tell me)\b",
            re.IGNORECASE,
        ),
        0.8,
        "States its own instructions",
    ),
    (
        re.compile(
            r"\bi\s+(was|am)\s+(instructed|told|programmed)\s+to\b",
            re.IGNORECASE,
        ),
        0.8,
        "Discloses being instructed",
    ),
    (
        re.compile(
            r"\bthe\s+(system|developer)\s+(prompt|instructions|message)\s+"
            r"(says?|states?|tells me|instructs me)\b",
            re.IGNORECASE,
        ),
        0.85,
        "Reveals what its system/developer instructions say",
    ),
]


class PromptLeakScanner(Scanner):
    """Flags model output that discloses system or developer instructions.

    See the module docstring for honest limitations. Output-side only;
    add it explicitly, it is not in ``default_scanners()``.
    """

    name = "prompt_leak"

    def __init__(self, patterns: list[tuple[re.Pattern[str], float, str]] | None = None) -> None:
        self.patterns = patterns if patterns is not None else _PATTERNS

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, score, message in self.patterns:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, message))
        return findings
