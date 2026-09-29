"""Redact pipeline: scrub secrets and PII out of text, from the shell.

Read from a file or stdin, write redacted text to stdout or a file:

    echo "contact me at jane@example.com, key sk-test-abc123" | python examples/redact_pipeline.py
    python examples/redact_pipeline.py --input raw.log --output clean.log

Exit code is 0 on success. With --strict, the pipeline refuses to emit
anything when a finding scores at or above the block threshold and exits
with code 2 instead. Use that in CI when redacted output is not good
enough and the input must be clean.

A per-run summary goes to stderr so it never pollutes the redacted
output on stdout.
"""

from __future__ import annotations

import argparse
import sys

from llm_sentinel import PIIScanner, SecretsScanner, Vault

_SCANNERS = {
    "secrets": SecretsScanner,
    "pii": PIIScanner,
}


def build_vault(scanner_names: list[str]) -> Vault:
    scanners = []
    for name in scanner_names:
        try:
            scanners.append(_SCANNERS[name]())
        except KeyError:
            raise SystemExit(
                f"unknown scanner: {name} (choose from: {sorted(_SCANNERS)})"
            ) from None
    return Vault(scanners)


def redact_text(text: str, vault: Vault) -> tuple[str, object]:
    result = vault.scan(text, redact=True)
    assert result.redacted_text is not None
    return result.redacted_text, result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scrub secrets and PII from text using llm-sentinel."
    )
    parser.add_argument("--input", help="input file (default: stdin)")
    parser.add_argument("--output", help="output file (default: stdout)")
    parser.add_argument(
        "--scanners",
        default="secrets,pii",
        help="comma-separated scanners (default: secrets,pii)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 without emitting output when anything blocks",
    )
    args = parser.parse_args(argv)

    vault = build_vault([s.strip() for s in args.scanners.split(",") if s.strip()])

    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    redacted, result = redact_text(text, vault)

    findings = result.findings
    print(
        f"scanned {len(text)} chars: {len(findings)} finding(s), blocked={result.blocked}",
        file=sys.stderr,
    )
    for finding in findings[:10]:
        print(f"  [{finding.scanner}] {finding.message}", file=sys.stderr)

    if args.strict and result.blocked:
        print("strict mode: findings above threshold, refusing to emit", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(redacted)
    else:
        sys.stdout.write(redacted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
