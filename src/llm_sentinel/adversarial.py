"""Deterministic evasion transforms for the adversarial robustness eval.

These are the cheap typographic tricks from the normalizer's threat model:
zero-width characters slipped inside words, fullwidth lookalikes, common
cross-script homoglyphs, and mixed case. Every transform is deterministic
(same input gives the same output on every run), so the eval table is
reproducible without storing transformed fixtures.

What this is not: paraphrase, heavy leetspeak, non-English attacks, or
meaning-level evasion. Those need a real red team, not string munging.
The eval measures whether the Vault pipeline (normalization on, the
shipped default) defeats the typographic tricks, nothing more.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Callable

from .normalize import _CONFUSABLES

# Invisible characters an attacker slips inside a word so the human sees
# one thing and a naive matcher sees another.
_ZERO_WIDTHS = ["\u200b", "\u200c", "\u200d", "\ufeff"]


def _rng(text: str, salt: str) -> random.Random:
    """A PRNG seeded by the text itself, so the transform is deterministic."""
    digest = hashlib.sha256((salt + "\x00" + text).encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def zero_width_inject(text: str, probability: float = 0.6) -> str:
    """Slip a zero-width character inside some words, at random positions.

    Short words (under 4 chars) are left alone. Deterministic per input.
    """
    rng = _rng(text, "zero_width")
    out: list[str] = []
    for part in re.split(r"(\s+)", text):
        if len(part) >= 4 and not part.isspace() and rng.random() < probability:
            pos = rng.randrange(1, len(part))
            part = part[:pos] + rng.choice(_ZERO_WIDTHS) + part[pos:]
        out.append(part)
    return "".join(out)


def to_fullwidth(text: str) -> str:
    """Map ASCII to its fullwidth forms (NFKC folds them back)."""
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        elif ch == " ":
            out.append("\u3000")  # ideographic space, NFKC folds to space
        else:
            out.append(ch)
    return "".join(out)


# Invert the normalizer's confusables table: Latin -> one lookalike.
# Several lookalikes can map to the same Latin letter; the first one in
# the table wins, which keeps the transform deterministic.
_HOMOGLYPHS: dict[str, str] = {}
for _confusable, _latin in _CONFUSABLES.items():
    _HOMOGLYPHS.setdefault(_latin, _confusable)


def homoglyph_swap(text: str) -> str:
    """Replace every mappable Latin letter with a same-case lookalike.

    Case matters: Greek lowercase upsilon looks like "u" but the uppercase
    looks like "Y", so an uppercased confusable would garble the attacker's
    own text. Same-case swaps are what a real attacker uses.
    """
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def mixed_case(text: str) -> str:
    """Alternate upper/lower across the alphabetic characters."""
    out: list[str] = []
    i = 0
    for ch in text:
        if ch.isalpha():
            out.append(ch.upper() if i % 2 == 0 else ch.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def combined(text: str) -> str:
    """Stack every trick at once: the worst case the pipeline must survive.

    Case is alternated before the homoglyph swap so each letter gets a
    same-case lookalike; stacking the swap under the case flip would
    garble letters whose lookalike changes with case.
    """
    return zero_width_inject(to_fullwidth(homoglyph_swap(mixed_case(text))))


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "zero_width": zero_width_inject,
    "fullwidth": to_fullwidth,
    "homoglyph": homoglyph_swap,
    "mixed_case": mixed_case,
    "combined": combined,
}
