"""Shared building blocks for scanners."""

from __future__ import annotations

import math
import re
from collections import Counter

from ..core import Finding


def find_all(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    return list(pattern.finditer(text))


def make_finding(
    scanner: str,
    match: re.Match[str],
    score: float,
    message: str,
    group: int = 0,
) -> Finding:
    start, end = match.span(group)
    return Finding(
        scanner=scanner,
        score=score,
        start=start,
        end=end,
        matched_text=match.group(group),
        message=message,
    )


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_random(token: str, *, min_length: int = 20, min_entropy: float = 4.2) -> bool:
    """Heuristic: long, high-entropy alphanumeric token.

    Catches unlabelled secrets (a bare 40-char blob with no "api key"
    next to it). Pure-hex tokens get their own bar: hex maxes out at 4.0
    bits/char, so a separate length/entropy pair applies.

    Deliberately conservative: it will miss short or low-entropy secrets,
    and it will flag things like hashes that are not secrets at all. That
    is the documented trade-off.
    """
    if not re.fullmatch(r"[A-Za-z0-9_\-+/=]+", token):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        return len(token) >= 32 and shannon_entropy(token) >= 3.7
    if len(token) < min_length:
        return False
    return shannon_entropy(token) >= min_entropy
