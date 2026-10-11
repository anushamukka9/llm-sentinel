"""Exfiltration scanner (output side).

Detects model output that discloses sensitive data: credentials, keys,
and PII leaking in responses. This closes the output side that the
input-side scanners do not cover. A prompt containing an API key is
your user pasting a secret; a response containing one is your system
handing it out.

It pairs three things:

1. Disclosure framing: a model that says "here is the API key" or "the
   password is ..." is volunteering the secret, not mentioning it.
2. Credentialed artifacts: PEM private key blocks, database connection
   strings with embedded passwords, tokens smuggled in URL query
   parameters, and internal key paths.
3. The secrets and PII detectors re-aimed at output: provider key
   formats, generic ``key = value`` assignments, emails, phones, SSNs,
   and Luhn-valid card numbers. Their findings are reported under the
   "exfiltration" name so one scanner answers the output-side question.

This is deliberately not in ``default_scanners()``, which is the
input-side set. Add it explicitly when you scan model output:

    Vault(default_scanners() + [ExfiltrationScanner()])

Limitations, stated plainly:
- Framing patterns are phrase matching. "Here is the API key policy"
  reads as a mention and stays quiet, but a model that discloses a key
  with no framing words at all is caught only by the artifact and
  format checks below.
- PII findings carry no context: a model echoing back the email address
  you just gave it flags the same as a real leak. Tune your block
  threshold, or redact instead of blocking, when that hurts.
- Like every scanner here, this sees literal text, not intent. A
  redacted, truncated, or paraphrased disclosure will slip through.
"""

from __future__ import annotations

import re
from dataclasses import replace

from ..core import Finding, Scanner
from .base import find_all, make_finding
from .pii import PIIScanner
from .secrets import SecretsScanner

# (compiled pattern, score, message). Output-side framing and artifacts;
# the secrets/PII formats come from the delegated scanners below.
_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (
        re.compile(
            r"\bhere(?:'s| is) (?:the |your |a )?"
            r"(?:api key|secret key|client secret|access token|"
            r"password|private key|credentials)\b",
            re.IGNORECASE,
        ),
        0.90,
        "Model volunteering a credential",
    ),
    (
        re.compile(
            r"\b(?:your|the) (?:database |db )?"
            r"(?:api key|secret key|password|access token|client secret)"
            r" (?:is|was)\b",
            re.IGNORECASE,
        ),
        0.85,
        "Model stating a credential value",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
        0.98,
        "Private key block",
    ),
    (
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^/\s:]+:[^@\s]+@[^\s\"']+"
        ),
        0.97,
        "Connection string with embedded credentials",
    ),
    (
        re.compile(r"[?&](?:api_?key|token|auth_?token|secret)\s*=\s*[A-Za-z0-9_\-]{8,}"),
        0.90,
        "Token in URL query parameter",
    ),
    (
        re.compile(r"(?i)(?:/etc/shadow|\.ssh/id_rsa)\b"),
        0.65,
        "Internal key path disclosed",
    ),
]


class ExfiltrationScanner(Scanner):
    """Flags credentials, keys, and PII spilling out in model output.

    Pass ``extra_patterns`` as ``[(label, regex_string, score), ...]`` to
    cover in-house key formats; they are checked on the output side and
    also handed to the delegated secrets scanner. Set
    ``entropy_scan=False`` to disable the unlabelled high-entropy token
    check (fewer false positives, more misses).

    See the module docstring for the honest limitations. Output-side
    only; add it explicitly, it is not in ``default_scanners()``.
    """

    name = "exfiltration"

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, float]] | None = None,
        entropy_scan: bool = True,
    ) -> None:
        self.patterns: list[tuple[re.Pattern[str], float, str]] = list(_PATTERNS)
        for label, rx, score in extra_patterns or []:
            self.patterns.append((re.compile(rx), score, label))
        self._secrets = SecretsScanner(extra_patterns=extra_patterns, entropy_scan=entropy_scan)
        self._pii = PIIScanner()

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, score, message in self.patterns:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, message))
        # The input-side detectors re-aimed at output. Findings keep their
        # original messages but report under this scanner's name, so one
        # output-side policy sees every disclosure signal in one place.
        for sub in (self._secrets, self._pii):
            for finding in sub.scan(text):
                findings.append(replace(finding, scanner=self.name))
        return findings
