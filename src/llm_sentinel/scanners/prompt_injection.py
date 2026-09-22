"""Prompt injection scanner.

Detects known prompt-injection shapes in text: instruction-override
attempts ("ignore all previous instructions"), delimiter smuggling
(fake system tags such as ``<<SYS>>`` or ``[INST]``), role-play jailbreak
markers ("DAN", "developer mode"), and a few common encoding tricks.

Limitations, stated plainly:
- This is pattern matching, not understanding. Novel phrasings, non-English
  attacks, and paraphrased overrides will sail through.
- Obfuscation (zero-width characters, homoglyphs, heavy leetspeak) defeats
  most of these patterns. A normalizer for that is on the roadmap, not here.
- Legitimate text can trip it: a security article *about* prompt injection,
  or a user quoting an attack, will flag. That is expected; pair with a
  human review step or an allowlist when false positives hurt.
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
            r"\b(ignore|disregard|forget|override|bypass|circumvent)\b"
            r"[^.\n]{0,60}\b(previous|prior|earlier|all|your|system|above)\b"
            r"[^.\n]{0,40}\b(instructions?|rules?|guidelines?|directives?|prompts?)\b",
            re.IGNORECASE,
        ),
        0.95,
        "Instruction-override attempt",
    ),
    (
        re.compile(
            r"\b(you are now|you will now|act as|pretend (to be|you are)|"
            r"roleplay as|role-play as|simulate being)\b",
            re.IGNORECASE,
        ),
        0.75,
        "Role-play / persona-switch marker",
    ),
    (
        re.compile(
            r"(<<\s*SYS\s*>>|<\|?\s*system\s*\|?>|\[INST\]|\[/INST\]|"
            r"```\s*system|###\s*system\b|\(system\))",
            re.IGNORECASE,
        ),
        0.9,
        "Delimiter smuggling: fake system tag",
    ),
    (
        re.compile(
            r"\b(DAN|jailbreak|developer mode|do anything now|"
            r"unrestricted mode|evil mode)\b",
            re.IGNORECASE,
        ),
        0.9,
        "Known jailbreak marker",
    ),
    (
        re.compile(
            r"\b(new (instructions?|directives?|orders?) (follow|below)|"
            r"from now on,? (you|follow)|system update:)",
            re.IGNORECASE,
        ),
        0.8,
        "Fake system-directive injection",
    ),
    (
        re.compile(
            r"\b(decode|decrypt|deobfuscate)\b[^.\n]{0,40}"
            r"\b(base64|hex|rot13|caesar)\b",
            re.IGNORECASE,
        ),
        0.7,
        "Encoded-payload instruction",
    ),
    (
        re.compile(
            r"\b(reveal|disclose|print|output|repeat|recite)\b"
            r"[^.\n]{0,50}\b(system prompt|initial instructions?|"
            r"hidden instructions?|your instructions?)\b",
            re.IGNORECASE,
        ),
        0.85,
        "System-prompt extraction attempt",
    ),
]


class PromptInjectionScanner(Scanner):
    """Flags known prompt-injection and jailbreak patterns.

    See the module docstring for honest limitations. This scanner is a
    tripwire, not a proof of safety.
    """

    name = "prompt_injection"

    def __init__(self, patterns: list[tuple[re.Pattern[str], float, str]] | None = None) -> None:
        self.patterns = patterns if patterns is not None else _PATTERNS

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, score, message in self.patterns:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, message))
        return findings
