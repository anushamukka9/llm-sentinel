"""Obfuscation scanner.

Detects text shaped to dodge pattern matching or to hide content from
human readers: zero-width and formatting characters, Unicode direction
overrides, stray control characters, fullwidth character runs, mixed-script
confusables (Cyrillic or Greek letters inside otherwise Latin text, at the
document level and inside a single word), and long encoded-looking blobs.
Literal escapes and blobs are also checked on a folded copy of the text
(normalization applied internally, offsets mapped back), because an
attacker who writes the escape or the blob with lookalike characters
breaks the raw patterns while keeping the payload readable to a decoder.

Limitations, stated plainly:
- Non-English text and emoji-heavy text can trip the script-mixing and
  control-character heuristics. Legitimate fullwidth text (common with
  Japanese and Chinese input methods) trips the fullwidth-run signal.
  This scanner is off by default in ``default_scanners()`` for exactly
  that reason: opt in when your traffic is mostly ASCII and you want
  the tripwire.
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
from ..normalize import normalize_with_map
from .base import find_all, make_finding, shannon_entropy

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BIDI = re.compile(r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f]")
_LITERAL_ESCAPE = re.compile(r"(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})")

_CYRILLIC = re.compile(r"[\u0400-\u045f]")
_GREEK = re.compile(r"[\u0370-\u03ff]")
_LATIN = re.compile(r"[a-zA-Z]")
_MIXED_RUN = re.compile(r"[\u0400-\u045f\u0370-\u03ff]+")
_CONFUSABLE_CHAR = re.compile(r"[\u0400-\u045f\u0370-\u03ff]")
_WORD = re.compile(r"[^\W\d_]+")
_FULLWIDTH_CHARS = "\uff01-\uff5e"


_ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\ufeff")
_BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")


def _control_char_spans(text: str) -> list[tuple[int, int]]:
    """Spans of stray control characters, as (start, end) pairs.

    The old version built a regex match object per character with
    ``re.finditer(r".", text)``; on a long text that was most of this
    scanner's time. A plain loop over the characters reports exactly
    the same spans: tabs, newlines, and carriage returns are allowed,
    zero-width and bidi characters are skipped here because their own
    sharper signals above already report them, and the rest is the
    ``Cc``/``Cf`` category check.
    """
    hits: list[tuple[int, int]] = []
    for i, ch in enumerate(text):
        if ch in "\t\n\r":
            continue
        if ch in _ZERO_WIDTH_CHARS or ch in _BIDI_CHARS:
            continue
        if unicodedata.category(ch) in ("Cc", "Cf"):
            hits.append((i, i + 1))
    return hits


class ObfuscationScanner(Scanner):
    """Flags obfuscation shapes: invisible chars, bidi overrides, mixed scripts.

    Not in ``default_scanners()``: multilingual text trips it, so it is
    opt-in. See the module docstring for the trade-off.

    This scanner opts out of the Vault's normalization pass
    (``normalize_input = False``): it detects the very tricks
    normalization removes, so it must see the raw text. Pair it with the
    other scanners in one Vault and each gets the text it needs.
    """

    name = "obfuscation"
    normalize_input = False

    def __init__(
        self,
        blob_min_length: int = 40,
        min_entropy: float = 4.5,
        fullwidth_min_length: int = 4,
    ) -> None:
        self.blob_min_length = blob_min_length
        self.min_entropy = min_entropy
        self.fullwidth_min_length = fullwidth_min_length
        # Compiled once here, not on every scan: these two patterns
        # depend only on the constructor arguments.
        self._fullwidth_rx = re.compile(rf"[{_FULLWIDTH_CHARS}]{{{fullwidth_min_length},}}")
        self._blob_rx = re.compile(rf"[A-Za-z0-9+/=]{{{blob_min_length},}}")

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
        for start, end in _control_char_spans(text):
            findings.append(
                Finding(
                    scanner=self.name,
                    score=0.7,
                    start=start,
                    end=end,
                    matched_text=text[start:end],
                    message="Stray control character",
                )
            )
        escape_spans: list[tuple[int, int]] = []
        for match in find_all(_LITERAL_ESCAPE, text):
            escape_spans.append(match.span())
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.5,
                    "Literal unicode escape (possible obfuscated payload)",
                )
            )
        for match in find_all(self._fullwidth_rx, text):
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.7,
                    "Fullwidth character run (possible lookalike evasion)",
                )
            )
        # Counts only: finditer avoids building three throwaway lists
        # of one-character strings on every scan.
        latin = sum(1 for _ in _LATIN.finditer(text))
        cyrillic = sum(1 for _ in _CYRILLIC.finditer(text))
        greek = sum(1 for _ in _GREEK.finditer(text))
        mixed_spans: list[tuple[int, int]] = []
        if latin >= 10 and (cyrillic + greek) >= 2:
            for match in find_all(_MIXED_RUN, text):
                mixed_spans.append(match.span())
                findings.append(
                    make_finding(
                        self.name,
                        match,
                        0.7,
                        "Mixed-script run inside Latin text (possible homoglyph attack)",
                    )
                )
        # Per-word mixing catches the case the document-level tripwire
        # misses: a heavily swapped text where so few Latin letters survive
        # that latin >= 10 never holds. One lookalike letter in a word stays
        # below the tripwire on purpose (a borrowed name, a typo); two or
        # more lookalikes sharing a word with Latin letters is the attack
        # shape. Words already covered by a mixed-script run are skipped.
        for match in find_all(_WORD, text):
            word = match.group()
            if len(word) < 4:
                continue
            if len(_CONFUSABLE_CHAR.findall(word)) < 2:
                continue
            if not _LATIN.search(word):
                continue
            start, end = match.span()
            if any(start < span_end and span_start < end for span_start, span_end in mixed_spans):
                continue
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.7,
                    "Mixed-script word (possible homoglyph attack)",
                )
            )
        blob_spans: list[tuple[int, int]] = []
        for match in find_all(self._blob_rx, text):
            blob = match.group().rstrip("=")
            if len(blob) >= self.blob_min_length and shannon_entropy(blob) >= self.min_entropy:
                blob_spans.append(match.span())
                findings.append(
                    make_finding(
                        self.name, match, 0.55, "Long high-entropy blob (possible encoded payload)"
                    )
                )
        findings.extend(self._folded_findings(text, escape_spans, blob_spans, self._blob_rx))
        return findings

    def _folded_findings(
        self,
        text: str,
        escape_spans: list[tuple[int, int]],
        blob_spans: list[tuple[int, int]],
        blob_rx: re.Pattern[str],
    ) -> list[Finding]:
        """Re-check escapes and blobs on a folded copy of the text.

        The raw patterns only see ASCII. An escape written with a Greek
        upsilon, or a blob written in fullwidth letters, is the same payload
        to anything that decodes it later. Fold a copy with the same
        normalization the Vault uses, run the same two patterns there, and
        map the spans back to the original text. Spans that overlap a raw
        finding are the same signal seen twice, so they are skipped.
        """
        if text.isascii():
            # Folding cannot change pure-ASCII text (normalization is
            # the identity there), so the folded pass would find
            # exactly what the raw pass already found. Skip it.
            return []
        folded, index_map = normalize_with_map(text)
        if folded == text:
            return []

        def to_original(start: int, end: int) -> tuple[int, int]:
            return index_map[start], index_map[end - 1] + 1

        def overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
            return any(start < span_end and span_start < end for span_start, span_end in spans)

        findings: list[Finding] = []
        for match in find_all(_LITERAL_ESCAPE, folded):
            start, end = to_original(*match.span())
            if overlaps(escape_spans, start, end):
                continue
            findings.append(
                Finding(
                    scanner=self.name,
                    score=0.5,
                    start=start,
                    end=end,
                    matched_text=text[start:end],
                    message="Literal unicode escape (possible obfuscated payload)",
                )
            )
        for match in find_all(blob_rx, folded):
            blob = match.group().rstrip("=")
            if len(blob) < self.blob_min_length or shannon_entropy(blob) < self.min_entropy:
                continue
            start, end = to_original(*match.span())
            if overlaps(blob_spans, start, end):
                continue
            findings.append(
                Finding(
                    scanner=self.name,
                    score=0.55,
                    start=start,
                    end=end,
                    matched_text=text[start:end],
                    message="Long high-entropy blob (possible encoded payload)",
                )
            )
        return findings
