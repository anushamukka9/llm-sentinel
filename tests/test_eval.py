"""Smoke tests for the policy eval (eval/policy_eval.json + eval runner)."""

import json
from pathlib import Path

from llm_sentinel.eval import EVAL_FILE, build_eval_vault, run_eval


def test_eval_file_exists_and_is_labeled():
    assert EVAL_FILE.exists()
    cases = json.loads(EVAL_FILE.read_text())["cases"]
    assert len(cases) >= 10
    for case in cases:
        assert set(case) >= {"text", "expected", "category"}
        assert isinstance(case["expected"], bool)


def test_eval_vault_includes_opt_in_scanners():
    vault = build_eval_vault()
    names = {s.name for s in vault.scanners}
    assert {"obfuscation", "prompt_leak"} <= names


def test_eval_accuracy_is_perfect_on_labeled_set():
    result = run_eval()
    assert result["accuracy"] == 1.0
    assert result["failures"] == []


def test_eval_covers_block_and_pass_categories():
    cases = json.loads(Path(EVAL_FILE).read_text())["cases"]
    assert any(c["expected"] for c in cases)
    assert any(not c["expected"] for c in cases)
