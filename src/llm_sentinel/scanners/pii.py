"""PII scanner.

Detects common personally identifying information: email addresses, phone
numbers, US Social Security numbers, and credit card numbers (validated
with the Luhn check so random 16-digit strings do not flag).

Limitations, stated plainly:
- Coverage is deliberately narrow (email, phone, SSN, card). Names,
  addresses, dates of birth, passport numbers, and non-US identifiers are
  not covered. This is not a general PII solution.
- Phone detection is US-centric and heuristic; it will flag some
  non-phone number sequences and miss international formats.
- The Luhn check removes most false positives on card numbers, but a
  Luhn-valid number is not proof it is a real card.
- Context is ignored: "my email is X" and "contact support@example.com"
  both flag. Decide in your policy whether that is acceptable.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def luhn_valid(digits: str) -> bool:
    """True when the digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PIIScanner(Scanner):
    """Flags email addresses, phone numbers, SSNs, and card numbers."""

    name = "pii"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in find_all(_EMAIL, text):
            findings.append(make_finding(self.name, match, 0.9, "Email address"))
        for match in find_all(_PHONE, text):
            findings.append(make_finding(self.name, match, 0.7, "Possible phone number"))
        for match in find_all(_SSN, text):
            findings.append(make_finding(self.name, match, 0.95, "US Social Security number"))
        for match in find_all(_CARD_CANDIDATE, text):
            digits = re.sub(r"[ -]", "", match.group())
            if not digits.isdigit() or not 13 <= len(digits) <= 19:
                continue
            if luhn_valid(digits):
                findings.append(
                    make_finding(self.name, match, 0.9, "Credit card number (Luhn-valid)")
                )
        return findings
