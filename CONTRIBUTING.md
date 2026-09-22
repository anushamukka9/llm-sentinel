# Contributing to llm-sentinel

Thanks for considering a contribution. This is a small, focused library and
we want to keep it that way.

## What fits here

- New **deterministic** scanners: no model calls, no network, no heavy
  dependencies. If your scanner needs a 2GB model download, it does not
  belong in the default path.
- Better patterns, better wordlists, better heuristics for existing
  scanners, with benchmark cases to prove it.
- Adapters for frameworks people actually use.
- Docs, examples, and benchmark corpus additions.

## What does not fit

- LLM-as-judge scanners in the core (a pluggable interface for them is on
  the roadmap; the default path stays offline).
- Features that phone home, require API keys, or add large dependencies.

## How to contribute

1. Fork the repo and create a branch: `git checkout -b fix/short-desc`.
2. Add your change plus tests. Every scanner needs true-positive and
   true-negative tests, including at least one adversarial case (obfuscated
   input, near-miss, or known false-positive shape).
3. If you touch a scanner, add labeled cases to `benchmarks/<scanner>.json`
   and run `python -m llm_sentinel.benchmark`. Do not land a change that
   regresses the table without a very good reason, stated in the PR.
4. Run the gates: `pytest` and `ruff check` / `ruff format --check`.
   Both must be clean.
5. Write your scanner's limitations honestly in its docstring. Every
   scanner documents what it cannot do. That is a requirement, not a
   suggestion.
6. Open a PR with a short description: what it does, why, and the test
   evidence. Keep the human voice: plain sentences, no hype.

## A note on example secrets

GitHub's secret scanner blocks pushes containing real provider key
formats, even obviously fake ones (notably `xoxb-` Slack tokens in the
real `xoxb-<12 digits>-<12 digits>-<24 chars>` shape). If your test or
benchmark fixture trips it, reshape the fake value so it no longer
matches the provider's real format while still exercising the scanner's
pattern. Do not disable push protection to land a fixture.

## Style

- Python 3.10+, `src/` layout, type hints on public APIs.
- Line length 100, ruff-enforced.
- Commit messages in imperative mood: `fix: handle empty batch`, not
  `fixed empty batch`.
