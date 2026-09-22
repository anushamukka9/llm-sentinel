"""Toxicity scanner (wordlist-based).

Flags text containing words from a built-in profanity list. Each hit
scores by frequency: one mild word is a weak signal, a barrage is strong.

Limitations, stated plainly:
- This is a wordlist, not a toxicity model. It has no notion of context,
  intent, reclaimed language, or non-English profanity.
- It misses obfuscation ("sh1t", "f*ck") and creative spelling entirely.
- It will flag legitimate uses: quotes, clinical discussion, song lyrics.
- The list itself is a judgment call and will offend someone no matter
  what is in it. Review ``_PROFANITY`` and override it for your locale
  and audience via the ``words`` constructor argument.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding

_PROFANITY = frozenset(
    """
    fuck fucking fucker fucked shit shitting shite bullshit horseshit
    asshole arsehole bitch bitches bastard bastards dick dicks prick
    cunt twat wanker tosser piss pissed pissing damn damned goddamn
    crap crappy slut whore skank douche douchebag jackass
    motherfucker sonofabitch dipshit dumbass smartass badass
    """.split()
)

# Deliberately excluded: racial and ethnic slurs. A wordlist cannot tell
# quoted or reclaimed usage from abuse, and a wrong call in either
# direction is harmful. If your policy needs slur detection, supply your
# own list via ``words=`` and own the review process.


class ToxicityScanner(Scanner):
    """Flags profanity from a configurable wordlist."""

    name = "toxicity"

    def __init__(self, words: frozenset[str] | None = None) -> None:
        self.words = words if words is not None else _PROFANITY
        escaped = sorted((re.escape(w) for w in self.words), key=len, reverse=True)
        self.pattern = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE)

    def scan(self, text: str) -> list[Finding]:
        matches = find_all(self.pattern, text)
        if not matches:
            return []
        # Score grows with density: 0.5 for a lone word, up to 0.95.
        score = min(0.95, 0.4 + 0.15 * len(matches))
        return [
            make_finding(
                self.name,
                m,
                round(score, 2),
                f"Profanity ({len(matches)} hit(s) in text)",
            )
            for m in matches
        ]
