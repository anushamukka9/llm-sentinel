"""Benchmark harness: precision/recall per scanner on labeled corpora.

Each ``benchmarks/<scanner>.json`` file holds labeled cases:
    {"cases": [{"text": "...", "expected": true}, ...]}

Run:
    python -m llm_sentinel.benchmark

Prints a per-scanner precision/recall/F1 table plus a corpus-wide
summary. A scanner "passes" a case when it produces at least one finding
for an expected-positive case, or none for an expected-negative case.

These corpora are small and hand-written. They measure whether the
patterns fire on the obvious cases, not whether the scanner is robust
in the wild. Treat the numbers as a smoke test with a table, not as a
safety certification.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .scanners import (
    BanTopicsScanner,
    CodeExecutionScanner,
    GibberishScanner,
    PIIScanner,
    PromptInjectionScanner,
    RegexScanner,
    SecretsScanner,
    TokenLimitScanner,
    ToxicityScanner,
    URLAllowlistScanner,
)

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks"

# Scanner name -> zero-arg factory. Constructors here mirror what the
# corpus files were written against; keep them in sync.
FACTORIES = {
    "prompt_injection": PromptInjectionScanner,
    "secrets": SecretsScanner,
    "pii": PIIScanner,
    "toxicity": ToxicityScanner,
    "gibberish": GibberishScanner,
    "ban_topics": BanTopicsScanner,
    "code_execution": CodeExecutionScanner,
    "url_allowlist": lambda: URLAllowlistScanner(allowed_domains=["example.com", "trusted.org"]),
    "token_limit": lambda: TokenLimitScanner(max_tokens=50),
    "regex": lambda: RegexScanner(
        forbidden=[r"\bclassified\b"],
        required=[r"\bhello\b"],
    ),
}


def run_one(name: str, factory) -> dict:
    path = BENCHMARK_DIR / f"{name}.json"
    corpus = json.loads(path.read_text(encoding="utf-8"))["cases"]
    scanner = factory()
    tp = fp = tn = fn = 0
    failures: list[str] = []
    for case in corpus:
        found = bool(scanner.scan(case["text"]))
        expected = case["expected"]
        if found and expected:
            tp += 1
        elif found and not expected:
            fp += 1
            failures.append(f"FP: {case['text'][:80]!r}")
        elif not found and not expected:
            tn += 1
        else:
            fn += 1
            failures.append(f"FN: {case['text'][:80]!r}")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "name": name,
        "cases": len(corpus),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "failures": failures,
    }


def main() -> int:
    rows = []
    for name, factory in FACTORIES.items():
        path = BENCHMARK_DIR / f"{name}.json"
        if not path.exists():
            print(f"warning: no corpus for {name}, skipping", file=sys.stderr)
            continue
        rows.append(run_one(name, factory))

    print(f"{'scanner':<18}{'n':>4}{'prec':>7}{'rec':>7}{'f1':>7}")
    print("-" * 43)
    tot = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "cases": 0}
    for r in rows:
        print(
            f"{r['name']:<18}{r['cases']:>4}"
            f"{r['precision']:>7.2f}{r['recall']:>7.2f}{r['f1']:>7.2f}"
        )
        for k in tot:
            tot[k] += r[k]
    p = tot["tp"] / (tot["tp"] + tot["fp"]) if (tot["tp"] + tot["fp"]) else 0
    rec = tot["tp"] / (tot["tp"] + tot["fn"]) if (tot["tp"] + tot["fn"]) else 0
    f1 = 2 * p * rec / (p + rec) if (p + rec) else 0
    print("-" * 43)
    print(f"{'overall':<18}{tot['cases']:>4}{p:>7.2f}{rec:>7.2f}{f1:>7.2f}")

    show_failures = "--failures" in sys.argv
    if show_failures:
        for r in rows:
            if r["failures"]:
                print(f"\n{r['name']} failures:")
                for f in r["failures"]:
                    print("  " + f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
