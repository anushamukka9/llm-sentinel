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


def redact_spans(text: str, findings: Sequence[Finding]) -> str:
    """Replace every finding span with a ``[REDACTED:<SCANNER>]`` placeholder.

    Spans are applied from the end of the text backwards so offsets stay
    valid. Overlapping spans collapse into the outermost one.
    """
    spans = sorted(
        ((f.start, f.end, f.scanner.upper()) for f in findings),
        key=lambda s: (s[0], -s[1]),
    )
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            continue  # inside an already-redacted span
        merged.append((start, end, label))
    out = text
    for start, end, label in reversed(merged):
        out = out[:start] + f"[REDACTED:{label}]" + out[end:]
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
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
        self.scanners: list[Scanner] = list(scanners or [])
        self.mode = mode
        self.thresholds = dict(thresholds or {})
        self.default_threshold = default_threshold

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
        redacted = redact_spans(text, findings) if redact else None
        return ScanResult(text=text, findings=findings, blocked=blocked, redacted_text=redacted)

    def check(self, text: str) -> bool:
        """True when the text passes the policy (nothing blocks it)."""
        return self.scan(text).passed
