"""URL allowlist scanner.

Extracts URLs from the text and flags any whose domain is not on the
configured allowlist. Built for the agent era: model output that links
out to attacker-controlled domains is a phishing and exfiltration vector.

Limitations, stated plainly:
- With no allowlist configured the scanner does nothing (returns no
  findings). An allowlist you never maintain is security theater; this
  scanner forces you to choose.
- Matching is on the registered domain. Lookalike domains
  (``examp1e.com`` vs ``example.com``) are different domains and will
  only be caught if you think to block them.
- URL parsing is heuristic. Obscure schemes, URLs without schemes, and
  links hidden in markdown reference definitions may be missed.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import Finding, Scanner
from .base import find_all, make_finding

_URL = re.compile(r"https?://[^\s<>\")\]]+")


def _registered_domain(netloc: str) -> str:
    host = netloc.split("@")[-1].split(":")[0].lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class URLAllowlistScanner(Scanner):
    """Flags URLs pointing at domains outside the allowlist.

    ``allowed_domains`` is a list like ``["example.com", "docs.internal"]``.
    Subdomains of an allowed domain are allowed.
    """

    name = "url_allowlist"

    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self.allowed = {d.lower().lstrip(".") for d in (allowed_domains or [])}

    def _allowed(self, netloc: str) -> bool:
        host = netloc.split("@")[-1].split(":")[0].lower()
        return any(host == domain or host.endswith("." + domain) for domain in self.allowed)

    def scan(self, text: str) -> list[Finding]:
        if not self.allowed:
            return []
        findings: list[Finding] = []
        for match in find_all(_URL, text):
            netloc = urlparse(match.group()).netloc
            if not netloc or self._allowed(netloc):
                continue
            findings.append(
                make_finding(
                    self.name,
                    match,
                    0.75,
                    f"URL points outside the allowlist ({_registered_domain(netloc)})",
                )
            )
        return findings
