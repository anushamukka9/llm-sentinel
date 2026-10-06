"""Adversarial robustness eval: clean vs evasion-transformed corpora.

Runs every labeled benchmark case through the full Vault pipeline
(normalization on, the shipped default), once clean and once per evasion
transform in ``llm_sentinel.adversarial``, and reports clean vs adversarial
precision/recall/F1.

Run:
    python -m llm_sentinel.adversarial_eval [--failures]

A case "passes" when the Vault produces at least one finding for an
expected-positive case, or none for an expected-negative case. Same
definition as the scanner-direct benchmark; the difference is the
pipeline under test. The scanner-direct benchmark calls each scanner on
the raw text, so it measures the patterns. This eval runs the Vault, so
it measures the pipeline: normalization plus the per-scanner opt-outs
(ObfuscationScanner sees the raw text and flags the tricks themselves).

What the numbers mean: adversarial recall is the share of attack cases
the pipeline still catches after evasion tricks are applied. Adversarial
neg-clean is the share of benign cases that stay clean after the same
tricks (normalization must not invent findings). Both should be high;
where they are not, the --failures flag shows exactly which cases fell
over, and that is the honest signal.
"""

from __future__ import annotations

import json
import sys
from statistics import mean

from .adversarial import TRANSFORMS
from .benchmark import BENCHMARK_DIR, FACTORIES
from .vault import Vault


def run_scanner(name: str, factory) -> dict:
    path = BENCHMARK_DIR / f"{name}.json"
    corpus = json.loads(path.read_text(encoding="utf-8"))["cases"]
    vault = Vault([factory()])

    def passes(text: str) -> bool:
        return bool(vault.scan(text).findings)

    def empty_scores() -> dict:
        return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    clean = empty_scores()
    adv = {t: empty_scores() for t in TRANSFORMS}
    failures: list[str] = []

    for case in corpus:
        text, expected = case["text"], case["expected"]
        variants = {"clean": text}
        variants.update({t: fn(text) for t, fn in TRANSFORMS.items()})
        for label, variant in variants.items():
            found = passes(variant)
            scores = clean if label == "clean" else adv[label]
            if found and expected:
                scores["tp"] += 1
            elif found and not expected:
                scores["fp"] += 1
                failures.append(f"[{label}] FP: {variant[:80]!r}")
            elif not found and not expected:
                scores["tn"] += 1
            else:
                scores["fn"] += 1
                failures.append(f"[{label}] FN: {variant[:80]!r}")

    def prf(s: dict) -> tuple[float, float, float]:
        precision = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 0.0
        recall = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return precision, recall, f1

    per_transform = {t: prf(adv[t]) for t in TRANSFORMS}
    # Transformed negatives that stayed clean, pooled across transforms.
    neg_total = sum(adv[t]["tn"] + adv[t]["fp"] for t in TRANSFORMS)
    neg_clean = sum(adv[t]["tn"] for t in TRANSFORMS) / neg_total if neg_total else 0.0

    return {
        "name": name,
        "cases": len(corpus),
        "clean": prf(clean),
        "per_transform": per_transform,
        "adv_neg_clean": neg_clean,
        "failures": failures,
    }


def main() -> int:
    rows = []
    for name, factory in FACTORIES.items():
        path = BENCHMARK_DIR / f"{name}.json"
        if not path.exists():
            print(f"warning: no corpus for {name}, skipping", file=sys.stderr)
            continue
        rows.append(run_scanner(name, factory))

    tkeys = list(TRANSFORMS)
    cols = "".join(f"{t[:7]:>8}" for t in tkeys)
    header = f"{'scanner':<16}{'n':>4}{'clean':>7}" + cols + f"{'neg_ok':>8}"
    print(header)
    print("-" * len(header))
    tot_cases = 0
    tot_clean_rec: list[float] = []
    tot_rec: dict[str, list[float]] = {t: [] for t in tkeys}
    tot_neg: list[float] = []
    for r in rows:
        recalls = [r["per_transform"][t][1] for t in tkeys]
        print(
            f"{r['name']:<16}{r['cases']:>4}{r['clean'][1]:>7.2f}"
            + "".join(f"{rec:>8.2f}" for rec in recalls)
            + f"{r['adv_neg_clean']:>8.2f}"
        )
        # Case-weighted means for the overall row.
        tot_cases += r["cases"]
        tot_clean_rec.extend([r["clean"][1]] * r["cases"])
        for t in tkeys:
            tot_rec[t].extend([r["per_transform"][t][1]] * r["cases"])
        tot_neg.extend([r["adv_neg_clean"]] * r["cases"])
    print("-" * len(header))
    print(
        f"{'overall':<16}{tot_cases:>4}{mean(tot_clean_rec):>7.2f}"
        + "".join(f"{mean(tot_rec[t]):>8.2f}" for t in tkeys)
        + f"{mean(tot_neg):>8.2f}"
    )

    print()
    print("Column key: clean = recall on the unmodified corpus; the transform")
    print("columns = recall after that evasion trick; neg_ok = share of")
    print("transformed benign cases that stayed clean (no invented findings).")
    print("Run with --failures to list every case the pipeline missed.")

    if "--failures" in sys.argv:
        for r in rows:
            if r["failures"]:
                print(f"\n{r['name']} failures:")
                for f in r["failures"]:
                    print("  " + f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
