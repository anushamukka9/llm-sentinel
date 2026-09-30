# Benchmarks

Every scanner ships with a small labeled corpus under `benchmarks/`
(true positives and true negatives, including adversarial and near-miss
cases). Run them yourself:

```bash
python -m llm_sentinel.benchmark
```

Results on the bundled corpora (155 cases, measured 2026-09-30 against
v0.3.0):

| scanner | n | precision | recall | F1 |
|---|---|---|---|---|
| prompt_injection | 20 | 1.00 | 1.00 | 1.00 |
| secrets | 17 | 1.00 | 1.00 | 1.00 |
| pii | 17 | 1.00 | 1.00 | 1.00 |
| toxicity | 14 | 1.00 | 1.00 | 1.00 |
| gibberish | 10 | 1.00 | 1.00 | 1.00 |
| ban_topics | 16 | 1.00 | 1.00 | 1.00 |
| code_execution | 16 | 1.00 | 1.00 | 1.00 |
| url_allowlist | 10 | 1.00 | 1.00 | 1.00 |
| token_limit | 6 | 1.00 | 1.00 | 1.00 |
| regex | 7 | 1.00 | 1.00 | 1.00 |
| obfuscation | 12 | 1.00 | 1.00 | 1.00 |
| prompt_leak | 10 | 1.00 | 1.00 | 1.00 |
| **overall** | **155** | **1.00** | **1.00** | **1.00** |

## What these numbers actually mean

A scanner "passes" a case when it produces at least one finding for an
expected-positive case, or none for an expected-negative case. That is
it. The corpora are small and hand-written by me, which means they
measure whether the patterns fire on the obvious cases, not whether the
scanner is robust in the wild.

Take these numbers for what they are: a smoke test with a table, not a
safety certification. Real attacks are more creative than any corpus I
can write alone.

## What the benchmark does not measure

- The Vault's normalization pass (zero-width stripping, NFKC folding,
  homoglyph mapping). The benchmark calls each scanner directly on the
  raw corpus text, so the table measures the scanners, not the pipeline.
  Evasion variants that normalization defeats are covered in
  `tests/test_adversarial.py` and `tests/test_normalize.py` instead.
- Latency or throughput. There is a performance pass on the roadmap;
  the numbers will go here when it lands.
- Your data. The single most useful thing you can do with this library
  is run it against your own traffic and tell me where it is wrong.

## Contributing cases

If you evaluate against your own data, please contribute the cases back.
Each corpus file is JSON:

```json
{"cases": [{"text": "...", "expected": true}, ...]}
```

A good case is a real string from real traffic: an attack that slipped
through (expected true), or a legitimate message that got flagged
(expected false). Near-misses are the most valuable kind. Open a PR
against `develop` with the case added to the right file and a one-line
note about where it came from.
