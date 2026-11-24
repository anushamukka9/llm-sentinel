"""Secrets scanner.

Detects credentials that should never appear in a prompt or a model
output: provider API keys (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic),
platform tokens (GitLab, Hugging Face, npm, PyPI, SendGrid,
DigitalOcean, Shopify, Square, Twilio),
JSON Web Tokens, generic ``key = value`` assignments, and unlabelled
high-entropy tokens.
The AWS pattern covers both long-term key ids (``AKIA``) and temporary
session key ids (``ASIA``) from STS. The OpenAI patterns cover the legacy
``sk-`` keys and the current project and service-account keys
(``sk-proj-`` / ``sk-svcacct-``), whose bodies are hyphen-separated
segments, so a single alphanumeric run never matches them.

The platform token formats (GitLab ``glpat-``, Hugging Face ``hf_``,
npm ``npm_``, PyPI ``pypi-``, SendGrid ``SG.<segment>.<segment>``,
DigitalOcean ``dop_v1_``, Shopify ``shpat_``, Square ``sq0atp-``,
Twilio ``SK`` plus hex) are prefix-anchored with strict body lengths,
so the bare prefix or a short stub does not flag. The prefix is the
tell: these strings have no innocent reason to appear in a prompt or
a model output. The hex formats (DigitalOcean, Shopify, Twilio) only
accept hex bodies, so a same-prefix string with non-hex characters
stays quiet.

JSON Web Tokens (JWTs) are validated, not just pattern-matched, in the
same spirit as the Luhn check on card numbers and the structural check
on SSNs: a dotted three-segment candidate only flags when its header
segment base64url-decodes to a JSON object carrying an ``alg`` claim
and its payload segment decodes to a JSON object. A dotted string that
fails either decode is not a JWT, however random it looks. The
signature is never verified; a structurally valid token is a live
session credential until it expires, signed or not, and the third
segment only has to be present and non-empty.

Limitations, stated plainly:
- Regexes cover the well-known formats. Private or in-house key formats
  will not match unless you add them via ``extra_patterns``.
- The entropy heuristic (``looks_random``) is deliberately conservative and
  still produces false positives on UUIDs, hashes, and random-looking
  non-secrets. It also misses short or low-entropy secrets entirely.
- Unsigned JWTs (``alg: none``, empty third segment) do not flag: with
  no signature segment there is no credential material to leak, only
  claims. A token whose header or payload is not a JSON object does
  not flag either, even though some issuers bend that shape.
- A key split across lines, redacted with asterisks, or shown only
  partially will not be caught. This scanner sees literal text, not intent.
"""

from __future__ import annotations

import base64
import json
import re

from ..core import Finding, Scanner
from .base import find_all, looks_random, make_finding

_NAMED: list[tuple[str, re.Pattern[str], float]] = [
    # AKIA is a long-term access key id; ASIA is the temporary session
    # key id STS hands out. Both are live credentials in text.
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.98),
    (
        "GitHub token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        0.98,
    ),
    (
        "GitHub fine-grained token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        0.98,
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.97,
    ),
    ("Stripe key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0.97),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), 0.95),
    (
        # Project and service-account keys: the body after the prefix is
        # hyphen/underscore-separated segments, so the legacy run above
        # stops at the first hyphen and never reaches 20 characters.
        "OpenAI project key",
        re.compile(r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b"),
        0.95,
    ),
    (
        "Anthropic key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        0.97,
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        0.95,
    ),
    # Platform tokens: each format is a distinctive literal prefix plus
    # a body of a fixed minimum length, so a bare prefix or a short
    # stub in documentation text stays quiet.
    (
        "GitLab token",
        re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
        0.98,
    ),
    (
        "Hugging Face token",
        re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        0.97,
    ),
    (
        "npm token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
        0.97,
    ),
    (
        "PyPI token",
        re.compile(r"\bpypi-[A-Za-z0-9\-_]{50,}\b"),
        0.98,
    ),
    (
        # SendGrid keys are two base64url segments after the SG. prefix:
        # a 22 character id segment and a 43 character secret segment.
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43,}\b"),
        0.97,
    ),
    (
        # DigitalOcean personal access tokens are the dop_v1_ prefix
        # plus a 64 character hex body.
        "DigitalOcean token",
        re.compile(r"\bdop_v1_[0-9a-f]{64,}\b"),
        0.98,
    ),
    (
        # Shopify admin access tokens are the shpat_ prefix plus a
        # 32 character hex body.
        "Shopify access token",
        re.compile(r"\bshpat_[0-9a-f]{32,}\b"),
        0.98,
    ),
    (
        # Square access tokens are the sq0atp- prefix plus a body of
        # at least 22 characters.
        "Square access token",
        re.compile(r"\bsq0atp-[A-Za-z0-9\-_]{22,}\b"),
        0.97,
    ),
    (
        # Twilio API keys start with SK plus a 32 character hex body.
        # The hex-only body keeps ordinary words starting with SK and
        # short SKU-like strings quiet.
        "Twilio API key",
        re.compile(r"\bSK[0-9a-f]{32,}\b"),
        0.96,
    ),
    (
        "Generic secret assignment",
        re.compile(
            r"(?i)\b(api[ _-]?key|secret[ _-]?key|client[ _-]?secret|"
            r"access[ _-]?token|private[ _-]?key|password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=]{12,})['\"]?",
        ),
        0.85,
    ),
]

# Bare tokens with no label nearby: word-boundary runs of token-ish chars.
_BARE_TOKEN = re.compile(r"\b[A-Za-z0-9_\-+/=]{24,}\b")

# A JWT candidate: three base64url segments joined by dots. The dots are
# why the bare-token heuristic above never sees a whole token: it matches
# one segment at a time, and a lone segment usually stays under its
# entropy bar. Candidates are validated by jwt_valid before they flag.
_JWT_CANDIDATE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")


def _decode_json_segment(segment: str) -> dict | None:
    """Base64url-decode one JWT segment; return it when it is a JSON object."""
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def jwt_valid(token: str) -> bool:
    """True when ``token`` is shaped like a real JSON Web Token.

    The token must split into exactly three non-empty segments, the
    header segment must decode to a JSON object with an ``alg`` claim,
    and the payload segment must decode to a JSON object. This is a
    shape check, not a signature check: it proves the string is a JWT,
    not that any particular issuer signed it.
    """
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    header = _decode_json_segment(parts[0])
    if header is None or "alg" not in header:
        return False
    return _decode_json_segment(parts[1]) is not None


class SecretsScanner(Scanner):
    """Flags API keys, tokens, and other credentials in text.

    Pass ``extra_patterns`` as ``[(label, regex_string, score), ...]`` to
    cover in-house key formats. Set ``entropy_scan=False`` to disable the
    heuristic bare-token check (fewer false positives, more misses).
    """

    name = "secrets"

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, float]] | None = None,
        entropy_scan: bool = True,
    ) -> None:
        self.patterns: list[tuple[str, re.Pattern[str], float]] = list(_NAMED)
        for label, rx, score in extra_patterns or []:
            self.patterns.append((label, re.compile(rx), score))
        self.entropy_scan = entropy_scan

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        for label, pattern, score in self.patterns:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, f"Possible {label}"))
                claimed.append(match.span())
        # Validated JWTs claim their whole span, so the entropy pass
        # below does not pile weaker per-segment findings on top.
        for match in find_all(_JWT_CANDIDATE, text):
            if jwt_valid(match.group()):
                findings.append(make_finding(self.name, match, 0.95, "JSON Web Token (JWT)"))
                claimed.append(match.span())
        if self.entropy_scan:
            for match in find_all(_BARE_TOKEN, text):
                start, end = match.span()
                if any(s <= start and end <= e for s, e in claimed):
                    continue
                token = match.group()
                if looks_random(token):
                    findings.append(
                        make_finding(
                            self.name,
                            match,
                            0.55,
                            "High-entropy token (unlabelled; verify before treating as a secret)",
                        )
                    )
        return findings
