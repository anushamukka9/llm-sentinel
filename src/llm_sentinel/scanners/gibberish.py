"""Gibberish scanner.

Flags text that looks like random character soup: keyboard mashing,
pasted binary fragments, or model output that degenerated into noise.
Three signals, weakest to strongest:

- A single very long consonant-heavy token (16+ chars, 80% consonants):
  no natural text looks like this.
- Distributed noise: the mean consonant ratio across words is far above
  what natural language produces (English averages around 0.6).
- Whole-text character entropy outside the band natural text lives in.

Limitations, stated plainly:
- This is a heuristic over character statistics, not a language model.
  Code snippets, URLs, hashes, and non-English text can all look
  "gibberish" to it. Do not run it on text you expect to contain code.
- Short gibberish ("asdf") will not flag; the scanner needs enough
  characters to judge. Tune ``min_words`` down if short noise matters.
- Competent nonsense (grammatical but meaningless prose) passes clean.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding, shannon_entropy

_WORD = re.compile(r"[A-Za-z]{4,}")
_VOWELS = set("aeiouAEIOU")


def _consonant_ratio(word: str) -> float:
    letters = [c for c in word if c.isalpha()]
    if not letters:
        return 0.0
    consonants = sum(1 for c in letters if c not in _VOWELS)
    return consonants / len(letters)


class GibberishScanner(Scanner):
    """Flags consonant-heavy or entropic noise in text."""

    name = "gibberish"

    def __init__(
        self,
        *,
        min_words: int = 4,
        monster_token_len: int = 16,
        monster_consonant_ratio: float = 0.80,
        mean_consonant_ratio: float = 0.80,
    ) -> None:
        self.min_words = min_words
        self.monster_token_len = monster_token_len
        self.monster_consonant_ratio = monster_consonant_ratio
        self.mean_consonant_ratio = mean_consonant_ratio

    def scan(self, text: str) -> list[Finding]:
        words = find_all(_WORD, text)
        ratios = [(m, _consonant_ratio(m.group())) for m in words]
        findings: list[Finding] = []

        # A monster token is damning on its own, even in a short text.
        for match, ratio in ratios:
            if (
                len(match.group()) >= self.monster_token_len
                and ratio >= self.monster_consonant_ratio
            ):
                findings.append(
                    make_finding(
                        self.name,
                        match,
                        0.85,
                        "Gibberish-like token (very long, consonant-heavy)",
                    )
                )
        if findings:
            return findings

        if len(words) < self.min_words:
            return []

        mean_ratio = sum(r for _, r in ratios) / len(ratios)
        if mean_ratio >= self.mean_consonant_ratio:
            noisy = [m for m, r in ratios if r >= 0.8]
            score = round(min(0.9, 0.5 + (mean_ratio - 0.6) * 2), 2)
            for match in noisy:
                findings.append(
                    make_finding(
                        self.name,
                        match,
                        score,
                        "Gibberish-like token (text-wide consonant anomaly)",
                    )
                )
            return findings

        entropy = shannon_entropy(re.sub(r"\s+", "", text))
        if not 2.8 <= entropy <= 5.2:
            findings.append(
                Finding(
                    scanner=self.name,
                    score=0.45,
                    start=0,
                    end=len(text),
                    matched_text=text[:60],
                    message="Abnormal character entropy for natural text",
                )
            )
        return findings
