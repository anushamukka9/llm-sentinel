"""Policy eval: run a composed Vault over a small labeled set.

    python -m llm_sentinel.eval [--failures]

``eval/policy_eval.json`` holds cases: ``{"text", "expected", "category"}``,
where expected=true means the policy should block. The script builds one
fixed policy (the input-side defaults plus the two opt-in scanners), scores
verdicts per category and overall, and prints the table.

This is a smoke test of composition, not a red-team exercise: 17
hand-written cases can tell you the wiring is right, not that the policy
is sufficient. The per-scanner benchmarks (``python -m
llm_sentinel.benchmark``) measure the scanners individually.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from . import Vault, default_scanners
from .scanners import ObfuscationScanner, PromptLeakScanner

EVAL_FILE = Path(__file__).resolve().parent.parent.parent / "eval" / "policy_eval.json"


def build_eval_vault() -> Vault:
    """The policy under test: defaults plus the two opt-in scanners."""
    return Vault(default_scanners() + [ObfuscationScanner(), PromptLeakScanner()])


def run_eval() -> dict:
    cases = json.loads(EVAL_FILE.read_text())["cases"]
    vault = build_eval_vault()
    per_category: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
    failures = []
    for case in cases:
        blocked = vault.scan(case["text"]).blocked
        correct = blocked == case["expected"]
        stats = per_category[case["category"]]
        stats["total"] += 1
        if correct:
            stats["correct"] += 1
        else:
            failures.append(case)
    total = sum(s["total"] for s in per_category.values())
    correct = sum(s["correct"] for s in per_category.values())
    return {
        "per_category": dict(per_category),
        "total": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "failures": failures,
    }


def main() -> int:
    show_failures = "--failures" in sys.argv[1:]
    result = run_eval()
    print(f"{'category':<14}{'correct':>8}{'total':>7}{'acc':>7}")
    print("-" * 36)
    for category in sorted(result["per_category"]):
        stats = result["per_category"][category]
        acc = stats["correct"] / stats["total"]
        print(f"{category:<14}{stats['correct']:>8}{stats['total']:>7}{acc:>7.2f}")
    print("-" * 36)
    print(f"{'overall':<14}{result['correct']:>8}{result['total']:>7}{result['accuracy']:>7.2f}")
    if show_failures and result["failures"]:
        print("\nfailures:")
        for case in result["failures"]:
            print(f"  [{case['category']}] expected={case['expected']}: {case['text'][:80]}")
    return 0 if result["accuracy"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
