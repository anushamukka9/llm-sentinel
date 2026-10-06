"""Text normalization before scanning.

The cheapest evasion tricks are typographic, not clever: zero-width
characters slipped inside a banned word ("ig\\u200bnore"), fullwidth
lookalikes ("\\uff49\\uff47\\uff4e\\uff4f\\uff52\\uff45"), and common
cross-script homoglyphs (Cyrillic "\\u0435" for Latin "e"). This module
undoes those before the scanners run.

``normalize_with_map`` returns the normalized text plus an index map so
the Vault can translate match offsets back to the original text. Findings
and redaction always refer to the original text you passed in, never to
the normalized copy.

Honest limits, stated plainly:
- The confusables table is small and curated, not the full Unicode
  confusables list. It covers the lookalikes I see in the wild.
- The table is case-complete: every entry has its uppercase/lowercase
  counterpart, so a SHOUTY homoglyph attack folds just like a quiet one.
  (An earlier version missed the uppercase forms, and the adversarial
  eval caught it.)
- Normalization is per character plus NFKC. It will not catch paraphrase,
  heavy leetspeak, non-English attacks, or meaning-level evasion.
- Stripping zero-width characters changes nothing for legitimate text,
  but if you rely on those characters for something real, pass
  ``normalize=False`` to the Vault.
"""

from __future__ import annotations

import unicodedata

# Invisible characters that exist only to break up words for machines
# while staying invisible to humans. Stripped before scanning.
_STRIPPED = frozenset(
    [
        "\u00ad",  # soft hyphen
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2060",  # word joiner
        "\u180e",  # mongolian vowel separator
        "\ufeff",  # zero-width no-break space / BOM
    ]
)

# Common cross-script lookalikes, mapped to their Latin equivalent.
# Curated, not exhaustive. NFKC handles fullwidth and compatibility
# forms; this table handles the rest of what I actually see.
_CONFUSABLES = {
    # Cyrillic lowercase
    "\u0430": "a",
    "\u0432": "b",
    "\u0441": "c",
    "\u0435": "e",
    "\u0456": "i",
    "\u0458": "j",
    "\u043a": "k",
    "\u043c": "m",
    "\u043d": "h",
    "\u043e": "o",
    "\u0440": "p",
    "\u0455": "s",
    "\u0442": "t",
    "\u0445": "x",
    "\u0443": "y",
    # Cyrillic uppercase
    "\u0405": "S",
    "\u0406": "I",
    "\u0408": "J",
    "\u0410": "A",
    "\u0412": "B",
    "\u0421": "C",
    "\u0415": "E",
    "\u041d": "H",
    "\u041a": "K",
    "\u041c": "M",
    "\u041e": "O",
    "\u0420": "P",
    "\u0422": "T",
    "\u0423": "Y",
    "\u0425": "X",
    # Greek lowercase
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03b7": "n",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u03b6": "z",
    # Greek uppercase
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u0396": "Z",
}


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize ``text`` and return ``(normalized, index_map)``.

    ``index_map[i]`` is the index in the original text of the character
    that produced normalized character ``i``. Use it to translate scanner
    match offsets back to the original text.
    """
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in _STRIPPED:
            continue
        ch = _CONFUSABLES.get(ch, ch)
        for nch in unicodedata.normalize("NFKC", ch):
            out.append(nch)
            index_map.append(i)
    return "".join(out), index_map


def normalize_text(text: str) -> str:
    """Normalize ``text`` for scanning. See ``normalize_with_map``."""
    return normalize_with_map(text)[0]
