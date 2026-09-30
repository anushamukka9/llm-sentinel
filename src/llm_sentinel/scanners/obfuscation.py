"""Obfuscation scanner.

Detects text shaped to dodge pattern matching or to hide content from
human readers: zero-width and formatting characters, Unicode direction
overrides, stray control characters, mixed-script confusables (Cyrillic or
Greek letters inside otherwise Latin text), and long encoded-looking blobs.

Limitations, stated plainly:
- Non-English text and emoji-heavy text can trip the script-mixing and
  control-character heuristics. This scanner is off by default in
  ``default_scanners()`` for exactly that reason: opt in when your traffic
  is mostly ASCII and you want the tripwire.
- It catches the shape of obfuscation, not intent. A zero-width joiner
  inside an emoji sequence is legitimate typography, not an attack.
- Homoglyph detection is a small confusable set (Cyrillic/Greek lookalikes
  of Latin letters), not full Unicode confusable coverage.
- Scores are per-signal severity guesses, not probabilities.
"""

from __future__ import annotations

import re
import unicodedata

from ..core import Finding, Scanner
from .base import find_all, make_finding, shannon_entropy

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BIDI = re.compile(r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f]")
_LITERAL_ESCAPE = re.compile(r"(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})")

_CYRILLIC = re.compile(r"[\u0400-\u045f]")
_GREEK = re.compile(r"[\u0370-\u03ff]")
_LATIN = re.compile(r"[a-zA-Z]")
_MIXED_RUN = re.compile(r"[\u0400-\u045f\u0370-\u03ff]+")


def _control_chars(text: str) -> list[re.Match[str]]:
    hits = []
    for match in re.finditer(r".", text, re.DOTALL):
        ch = match.group()
        if ch in "\t\n\r":
            continue
        if _ZERO_WIDTH.match(ch) or _BIDI.match(ch):
            continue  # reported by their own, sharper signals above
        if unicodedata.category(ch) in ("Cc", "Cf"):
            hits.append(match)
    return hits


class ObfuscationScanner(Scanner):
    """Flags obfuscation shapes: invisible chars, bidi overrides, mixed scripts.

    Not in ``default_scanners()``: multilingual text trips it, so it is
    opt-in. See the module docstring for the trade-off.
    """

    name = "obfuscation"

    def __init__(self, blob_min_length: int = 40, min_entropy: float = 4.5) -> None:
        self.blob_min_length = blob_min_length
        self.min_entropy = min_entropy

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in find_all(_ZERO_WIDTH, text):
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.9,
                    "Zero-width/format character (possible hidden text)",
                )
            )
        for match in find_all(_BIDI, text):
            findings.append(make_finding(self.name, match, 0.9, "Unicode direction override"))
        for match in _control_chars(text):
            findings.append(make_finding(self.name, match, 0.7, "Stray control character"))
        for match in find_all(_LITERAL_ESCAPE, text):
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.5,
                    "Literal unicode escape (possible obfuscated payload)",
                )
            )
        latin = len(_LATIN.findall(text))
        cyrillic = len(_CYRILLIC.findall(text))
        greek = len(_GREEK.findall(text))
        if latin >= 10 and (cyrillic + greek) >= 2:
            for match in find_all(_MIXED_RUN, text):
                findings.append(
                    make_finding(
                        self.name,
                        match,
                        0.7,
                        "Mixed-script run inside Latin text (possible homoglyph attack)",
                    )
                )
        blob_rx = re.compile(rf"[A-Za-z0-9+/=]{{{self.blob_min_length},}}")
        for match in find_all(blob_rx, text):
            blob = match.group().rstrip("=")
            if len(blob) >= self.blob_min_length and shannon_entropy(blob) >= self.min_entropy:
                findings.append(
                    make_finding(
                        self.name, match, 0.55, "Long high-entropy blob (possible encoded payload)"
                    )
                )
        return findings
