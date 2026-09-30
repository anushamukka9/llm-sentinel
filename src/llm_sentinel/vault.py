"""The Vault: compose scanners into an enforceable policy.

A Vault holds an ordered list of scanners and decides what happens when
they find something:

- ``mode="collect_all"`` (default): run every scanner, report everything.
- ``mode="fail_fast"``: stop at the first scanner that finds anything.

The block decision is per-scanner threshold: a finding blocks the text when
its score is at or above that scanner's threshold. Thresholds default to
0.5 and can be tuned per scanner.

Redaction replaces each finding span with a placeholder such as
``[REDACTED:SECRET]``. It is a lossy, best-effort transform: it removes the
matched characters, not the meaning around them. Do not rely on it alone
for high-stakes data; pair it with blocking for anything you cannot afford
to leak.
"""

from __future__ import annotations

from collections.abc import Sequence

from .core import Finding, Scanner, ScanResult

COLLECT_ALL = "collect_all"
FAIL_FAST = "fail_fast"

_MODES = (COLLECT_ALL, FAIL_FAST)


def redact_spans(
    text: str,
    findings: Sequence[Finding],
    placeholders: dict[str, str] | None = None,
) -> str:
    """Replace every finding span with a placeholder.

    The default placeholder is ``[REDACTED:<SCANNER>]``. ``placeholders``
    maps scanner names to replacement text, e.g.
    ``{"pii": "[CONTACT]"}``; a scanner without an entry keeps its
    default.

    Spans are applied from the end of the text backwards so offsets stay
    valid. Overlapping spans collapse into the outermost one.
    """
    spans = sorted(
        (
            (f.start, f.end, (placeholders or {}).get(f.scanner, f"[REDACTED:{f.scanner.upper()}]"))
            for f in findings
        ),
        key=lambda s: (s[0], -s[1]),
    )
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            continue  # inside an already-redacted span
        merged.append((start, end, label))
    out = text
    for start, end, label in reversed(merged):
        out = out[:start] + label + out[end:]
    return out


class Vault:
    """A policy made of scanners.

    Example:
        vault = Vault([PromptInjectionScanner(), SecretsScanner()])
        result = vault.scan(user_input)
        if result.blocked:
            raise ValueError("blocked by guardrails")

    To get a redacted copy instead of a yes/no answer:
        result = vault.scan(text, redact=True)
        safe = result.redacted_text
    """

    def __init__(
        self,
        scanners: Sequence[Scanner] | None = None,
        *,
        mode: str = COLLECT_ALL,
        thresholds: dict[str, float] | None = None,
        default_threshold: float = 0.5,
        placeholders: dict[str, str] | None = None,
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
        self.scanners: list[Scanner] = list(scanners or [])
        self.mode = mode
        self.thresholds = dict(thresholds or {})
        self.default_threshold = default_threshold
        self.placeholders = dict(placeholders or {})

    @classmethod
    def from_dict(cls, config: dict) -> Vault:
        """Build a Vault from a plain dict (config files, feature flags).

        Example:
            config = {
                "mode": "fail_fast",
                "default_threshold": 0.6,
                "scanners": [
                    "prompt_injection",
                    {"name": "ban_topics", "kwargs": {"topics": ["politics"]}},
                    {"name": "secrets", "threshold": 0.9},
                ],
                "thresholds": {"pii": 0.7},
                "placeholders": {"pii": "[CONTACT]"},
            }
            vault = Vault.from_dict(config)

        A scanner entry is either a registered name or a dict with ``name``
        plus optional ``kwargs`` (passed to the scanner constructor) and
        ``threshold``. Unknown names raise ValueError listing the registry.
        """
        from .scanners import SCANNER_REGISTRY

        thresholds: dict[str, float] = dict(config.get("thresholds", {}))
        scanners = []
        for spec in config.get("scanners", []):
            entry = {"name": spec} if isinstance(spec, str) else dict(spec)
            name = entry.get("name")
            if name not in SCANNER_REGISTRY:
                raise ValueError(f"unknown scanner {name!r}; available: {sorted(SCANNER_REGISTRY)}")
            scanner = SCANNER_REGISTRY[name](**entry.get("kwargs", {}))
            scanners.append(scanner)
            if "threshold" in entry:
                thresholds[scanner.name] = entry["threshold"]
        return cls(
            scanners,
            mode=config.get("mode", COLLECT_ALL),
            thresholds=thresholds,
            default_threshold=config.get("default_threshold", 0.5),
            placeholders=config.get("placeholders"),
        )

    def add(self, scanner: Scanner, *, threshold: float | None = None) -> Vault:
        """Append a scanner. Returns self so calls chain."""
        self.scanners.append(scanner)
        if threshold is not None:
            self.thresholds[scanner.name] = threshold
        return self

    def threshold_for(self, scanner_name: str) -> float:
        return self.thresholds.get(scanner_name, self.default_threshold)

    def scan(self, text: str, *, redact: bool = False) -> ScanResult:
        findings: list[Finding] = []
        for scanner in self.scanners:
            found = scanner.scan(text)
            findings.extend(found)
            if found and self.mode == FAIL_FAST:
                break
        findings.sort(key=lambda f: f.score, reverse=True)
        blocked = any(f.score >= self.threshold_for(f.scanner) for f in findings)
        redacted = redact_spans(text, findings, self.placeholders) if redact else None
        return ScanResult(text=text, findings=findings, blocked=blocked, redacted_text=redacted)

    def check(self, text: str) -> bool:
        """True when the text passes the policy (nothing blocks it)."""
        return self.scan(text).passed
