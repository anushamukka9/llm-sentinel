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

## Adversarial robustness

The table above calls each scanner directly on the raw corpus text, so
it measures the patterns, not the pipeline. This section measures the
pipeline: every case run through a real Vault (normalization on, the
shipped default), once clean and once per evasion transform. Run it
yourself:

```bash
python -m llm_sentinel.adversarial_eval
```

The transforms are deterministic string munging in
`llm_sentinel/adversarial.py`: zero-width injection, fullwidth folding,
homoglyph swaps, mixed case, and all of them stacked (combined). Same
pass definition as above: a finding on an expected-positive case, or
silence on a negative one. `neg_ok` is the share of transformed benign
cases that stayed clean (normalization must not invent findings).

Results (155 cases, measured 2026-10-06 against v0.4.0):

| scanner | n | clean | zero_width | fullwidth | homoglyph | mixed_case | combined | neg_ok |
|---|---|---|---|---|---|---|---|---|
| prompt_injection | 20 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| secrets | 17 | 1.00 | 1.00 | 1.00 | 1.00 | 0.78 | 0.78 | 1.00 |
| pii | 17 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| toxicity | 14 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| gibberish | 10 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| ban_topics | 16 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| code_execution | 16 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 |
| url_allowlist | 10 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| token_limit | 6 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| regex | 7 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.60 |
| obfuscation | 12 | 1.00 | 1.00 | 0.57 | 0.71 | 1.00 | 1.00 | 0.56 |
| prompt_leak | 10 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **overall** | **155** | **1.00** | **1.00** | **0.97** | **0.98** | **0.87** | **0.87** | **0.95** |

The headline: normalization defeats zero-width, fullwidth, and homoglyph
evasion almost everywhere. The cells that are not 1.00 are worth reading
closely, because most of them are the eval being honest, not the
pipeline failing:

- `secrets` mixed_case 0.78: the transform defangs the secret. A
  mixed-case `AkIa...` is not a well-formed AWS key, so the scanner is
  right to stay quiet.
- `code_execution` mixed_case/combined 0.00: `Os.SyStEm(` does not
  execute in Python, and this scanner's threat model is executable code
  (a compromised tool handing the agent a snippet that escapes the
  sandbox when run). Case-mangled variants are correctly ignored. If you
  want those flagged anyway, run prompt_injection alongside it.
- `regex` neg_ok 0.60: the bundled `required=[r"\bhello\b"]` pattern is
  case-sensitive, so mixed-case benign text fails the required pattern.
  That is user configuration, not a library bug; add `(?i)` to your own
  patterns if you want case-insensitive matching.
- `obfuscation` fullwidth 0.57 / homoglyph 0.71: this scanner reads the
  raw text (it must, it detects the tricks normalization removes), and
  fullwidth runs plus fully-homoglyphed text evade its current
  heuristics. Every other scanner still folds these to 1.00 through
  normalization. Fullwidth-run detection is queued.
- `obfuscation` neg_ok 0.56: by construction. The transforms inject
  zero-width, fullwidth, and homoglyph characters into benign text,
  which is exactly what this scanner detects.

Two real bugs came out of building this eval, both fixed in v0.4.0:

- Uppercased homoglyphs walked past normalization. The confusables table
  had lowercase Cyrillic/Greek lookalikes but was missing most uppercase
  forms, so `ІdІoΤ` never folded back. The table is now case-complete.
- `url_allowlist` missed mixed-case schemes. Schemes are
  case-insensitive per RFC 3986, so `hTTpS://evil.example` is a URL;
  the extractor regex is now case-insensitive too.

## What the benchmark does not measure

- Latency or throughput. There is a performance pass on the roadmap;
  the numbers will go here when it lands.
- Paraphrase, leetspeak, non-English attacks, or meaning-level evasion.
  The adversarial transforms are typographic only. Those need a real red
  team, not string munging.
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
