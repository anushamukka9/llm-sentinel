"""Text normalization before scanning.

The cheapest evasion tricks are typographic, not clever: zero-width
characters slipped inside a banned word ("ig\\u200bnore"), fullwidth
lookalikes ("\\uff49\\uff47\\uff4e\\uff4f\\uff52\\uff45"), and common
cross-script homoglyphs (Cyrillic "\\u0435" for Latin "e"). This module
undoes those before the scanners run.

The v0.7.6 pass widened the net to the smuggling tricks that showed up
after the first version shipped:

- Unicode tag characters (U+E0000 to U+E007F), the invisible block
  people use to smuggle a second, hidden instruction past a human
  reader (so-called ASCII smuggling). Stripped.
- Variation selectors (U+FE00 to U+FE0F and U+E0100 to U+E01EF) slipped
  inside words. Stripped. They still work in your original text; only
  the scan copy loses them.
- Bidi isolates and invisible operators (U+2061 to U+206F). Stripped,
  alongside the bidi embeddings and overrides the first version had.
- Combining diacritical marks, whether typed as separate characters
  inside a word ("ig\\u0301nore") or hiding inside an accented letter
  used as a lookalike ("p\\u00e0ssword", where the a-grave is really an
  "a" plus a combining grave). Stripped from the scan copy, so accented
  lookalikes fold to their base letters before matching. Letters with
  no such decomposition (o-slash, ae ligature) are left as they are.

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
- Stripping combining marks means the scan copy reads accented text as
  its base letters. That is the point for lookalike attacks, but it can
  in principle fold a benign accented word into a flagged one in
  contrived cases. Your original text is never changed; only matching
  happens on the folded copy.
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
        "\u061c",  # arabic letter mark
    ]
)

# Whole blocks that exist to be invisible or to decorate the character
# before them. None of them carry meaning a scanner should match on, and
# all of them break naive matching when slipped inside a word. Checked
# as ranges so the supplementary planes (tag characters, variation
# selectors) are covered without a giant literal table.
_STRIPPED_RANGES = (
    (0x0300, 0x036F),  # combining diacritical marks
    (0x0483, 0x0489),  # combining cyrillic marks
    (0x1AB0, 0x1AFF),  # combining diacritical marks extended
    (0x1DC0, 0x1DFF),  # combining diacritical marks supplement
    (0x20D0, 0x20FF),  # combining marks for symbols
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFE20, 0xFE2F),  # combining half marks
    (0x2061, 0x206F),  # invisible operators, bidi isolates, deprecated formats
    (0xFFF9, 0xFFFB),  # interlinear annotation anchors
    (0xE0000, 0xE007F),  # tag characters (ASCII smuggling block)
    (0xE0100, 0xE01EF),  # variation selectors supplement
)


def _is_stripped(ch: str) -> bool:
    """True when ``ch`` is dropped from the scan copy entirely."""
    if ch in _STRIPPED:
        return True
    code = ord(ch)
    return any(lo <= code <= hi for lo, hi in _STRIPPED_RANGES)


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
    "\u0454": "e",  # cyrillic ukrainian ie
    "\u0501": "d",  # cyrillic komi de
    "\u04bb": "h",  # cyrillic shha
    "\u0473": "v",  # cyrillic izhitsa
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
    "\u0404": "E",  # cyrillic ukrainian ie, uppercase
    "\u0500": "D",  # cyrillic komi de, uppercase
    "\u04ba": "H",  # cyrillic shha, uppercase
    "\u0472": "V",  # cyrillic izhitsa, uppercase
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
    "\u03f2": "c",  # greek lunate sigma
    # Armenian lowercase
    "\u0585": "o",  # armenian oh
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
    "\u03f9": "C",  # greek lunate sigma, uppercase
    # Armenian uppercase
    "\u0555": "O",  # armenian oh, uppercase
}


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize ``text`` and return ``(normalized, index_map)``.

    ``index_map[i]`` is the index in the original text of the character
    that produced normalized character ``i``. Use it to translate scanner
    match offsets back to the original text.

    Performance note: most real traffic is plain ASCII, and ASCII is a
    fixed point of this whole pass (no ASCII character is stripped, none
    is a confusable key, and NFKC maps every ASCII character to itself).
    Pure-ASCII text takes a fast path that skips the per-character
    ``unicodedata.normalize`` call, which was the single hottest loop in
    the pipeline. Mixed text still pays for NFKC, but only on its
    non-ASCII characters. The output is identical either way; the
    equivalence is pinned by tests in ``tests/test_perf.py``.
    """
    if text.isascii():
        return text, list(range(len(text)))
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if _is_stripped(ch):
            continue
        ch = _CONFUSABLES.get(ch, ch)
        if ch.isascii():
            out.append(ch)
            index_map.append(i)
            continue
        # NFKC alone keeps accented letters composed (a-grave stays
        # a-grave), so the accent never surfaces as a mark to strip.
        # When a character decomposes into a base character plus only
        # combining marks, scan the decomposition instead and drop the
        # marks: that folds accented lookalikes to their base letters.
        # Anything else (Hangul syllables, ligatures, symbols) keeps
        # the plain NFKC result.
        decomposed = unicodedata.normalize("NFKD", ch)
        if (
            decomposed != ch
            and not unicodedata.combining(decomposed[0])
            and all(
                unicodedata.combining(c) or unicodedata.category(c) in ("Mn", "Me", "Mc")
                for c in decomposed[1:]
            )
        ):
            candidates = decomposed
        else:
            candidates = unicodedata.normalize("NFKC", ch)
        for nch in candidates:
            if _is_stripped(nch):
                continue
            out.append(_CONFUSABLES.get(nch, nch))
            index_map.append(i)
    return "".join(out), index_map


def normalize_text(text: str) -> str:
    """Normalize ``text`` for scanning. See ``normalize_with_map``."""
    return normalize_with_map(text)[0]
