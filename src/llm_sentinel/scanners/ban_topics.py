"""Banned-topics scanner.

Flags text that touches topics you have decided are out of bounds, using
keyword matching against configurable topic lists. The defaults cover a
small set of widely-agreed harmful categories; they are a starting point,
not a safety policy.

Limitations, stated plainly:
- Keyword matching, not topic understanding. "How do I make a bomb
  calorimeter for chemistry class" and "how do I make a bomb" both match
  "bomb". Euphemisms, coded language, and other languages miss entirely.
- The default lists are short and opinionated. If you deploy this, you
  are responsible for reviewing and extending them for your threat model.
- This scanner cannot judge intent or context. Treat hits as "needs a
  look", not as verdicts.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding

DEFAULT_TOPICS: dict[str, list[str]] = {
    "weapons": [
        "build a bomb",
        "make a bomb",
        "pipe bomb",
        "molotov",
        "ricin",
        "anthrax",
        "dirty bomb",
        "improvised explosive",
        "3d printed gun",
        "ghost gun",
    ],
    "self_harm": [
        "kill myself",
        "suicide methods",
        "how to self-harm",
        "cutting myself",
        "end my life",
    ],
    "illicit_behavior": [
        "how to hack",
        "break into",
        "pick a lock",
        "shoplifting tips",
        "make meth",
        "cook meth",
        "credit card fraud",
    ],
}


class BanTopicsScanner(Scanner):
    """Flags configured banned topics by keyword matching.

    ``topics`` maps a topic name to a list of phrases. Matching is
    case-insensitive substring matching on word boundaries.
    """

    name = "ban_topics"

    def __init__(self, topics: dict[str, list[str]] | None = None) -> None:
        self.topics = topics if topics is not None else DEFAULT_TOPICS
        self._compiled: list[tuple[str, str, re.Pattern[str]]] = []
        for topic, phrases in self.topics.items():
            for phrase in phrases:
                self._compiled.append(
                    (topic, phrase, re.compile(r"\b" + re.escape(phrase) + r"\b", re.IGNORECASE))
                )

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for topic, phrase, pattern in self._compiled:
            for match in find_all(pattern, text):
                findings.append(
                    make_finding(
                        self.name,
                        match,
                        0.7,
                        f"Banned topic '{topic}': matched {phrase!r}",
                    )
                )
        return findings
