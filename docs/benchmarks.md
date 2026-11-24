# Benchmarks

Every scanner ships with a small labeled corpus under `benchmarks/`
(true positives and true negatives, including adversarial and near-miss
cases). Run them yourself:

```bash
python -m llm_sentinel.benchmark
```

Results on the bundled corpora (410 cases, measured 2026-11-24 against
v0.7.5):

| scanner | n | precision | recall | F1 |
|---|---|---|---|---|
| prompt_injection | 40 | 1.00 | 1.00 | 1.00 |
| secrets | 58 | 1.00 | 1.00 | 1.00 |
| pii | 40 | 1.00 | 1.00 | 1.00 |
| toxicity | 28 | 1.00 | 1.00 | 1.00 |
| gibberish | 22 | 1.00 | 1.00 | 1.00 |
| ban_topics | 32 | 1.00 | 1.00 | 1.00 |
| code_execution | 32 | 1.00 | 1.00 | 1.00 |
| url_allowlist | 24 | 1.00 | 1.00 | 1.00 |
| token_limit | 16 | 1.00 | 1.00 | 1.00 |
| regex | 20 | 1.00 | 1.00 | 1.00 |
| obfuscation | 26 | 1.00 | 1.00 | 1.00 |
| prompt_leak | 25 | 1.00 | 1.00 | 1.00 |
| exfiltration | 47 | 1.00 | 1.00 | 1.00 |
| **overall** | **410** | **1.00** | **1.00** | **1.00** |

The October 2026 expansion added 200 cases (175 to 375), weighted toward
the newer scanners: exfiltration and prompt_injection doubled, and every
scanner gained near-miss negatives alongside fresh positives (lookalike
domains for url_allowlist, case-sensitivity traps for regex, test-card
numbers for pii, documentation-style example keys for secrets). Same
honest caveat, doubled: a bigger hand-written corpus is still a
hand-written corpus, written by the same person who wrote the patterns.
It proves broader coverage of the obvious cases, not robustness in the
wild.

The November 2026 addition is smaller: six cases for the new JWT check
in the secrets scanner (four in `secrets`, two in `exfiltration`, which
inherits the check through delegation). Two positives are real-shaped
tokens, one in a sentence and one in a Bearer header. The negatives are
the point of the feature: a dotted three-segment blob that decodes to
nothing, and a token whose header is a valid JWT header but whose
payload is plain text, not JSON. Both stay quiet, because the check
validates the decode instead of trusting the shape.

A second November addition (v0.7.4) covers five platform token
formats the secrets scanner had no patterns for: GitLab (`glpat-`),
Hugging Face (`hf_`), npm (`npm_`), PyPI (`pypi-`), and SendGrid
(`SG.<segment>.<segment>`). Twelve cases: five positives in
`secrets`, four near-miss negatives (a bare `glpat-` prefix, a short
`hf_` stub, an `npm_` mention with no token, a SendGrid shape note
with no key), two positives in `exfiltration`, which inherits the
formats through its delegated secrets scanner, and one negative
there. The patterns are prefix-anchored with strict body lengths,
so the negatives are the point again: documentation that talks
about the formats does not flag. One corpus quirk: the GitLab and
SendGrid benchmark fakes use over-length bodies, because GitHub
secret scanning blocks exact-length fakes in these files on push.
The unit tests pin the exact documented lengths; the benchmark
copies still prove the patterns fire on the format family.

A third November addition (v0.7.5) covers four more formats the
secrets scanner had no patterns for: DigitalOcean (`dop_v1_` plus
hex), Shopify (`shpat_` plus hex), Square (`sq0atp-`), and Twilio
(`SK` plus hex). Nine cases: three positives and four near-miss
negatives in `secrets` (a bare `dop_v1_` prefix, a short `shpat_`
stub, an `sq0atp-` mention with no token, an `SK` stock label), one
positive in `exfiltration`, which inherits the formats through its
delegated secrets scanner, and one negative there. The hex formats
only accept hex bodies, so a same-prefix string with non-hex
characters stays quiet. Same corpus quirk as v0.7.4: the benchmark
fakes use over-length bodies, because GitHub secret scanning can
block exact-length fakes in these files on push. The unit tests pin
the exact documented lengths. One format has no benchmark positive
at all: Shopify. Verified directly, GitHub secret scanning blocks a
literal `shpat_` fake at 32, 40, and 64 hex characters alike, so no
over-length trick works there. The Shopify pattern is covered by
unit tests instead, where the fake is built by concatenation and
never sits in the source as a literal.

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

Results (410 cases, measured 2026-11-24 against v0.7.5):

| scanner | n | clean | zero_width | fullwidth | homoglyph | mixed_case | combined | neg_ok |
|---|---|---|---|---|---|---|---|---|
| prompt_injection | 40 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| secrets | 58 | 1.00 | 1.00 | 1.00 | 1.00 | 0.84 | 0.84 | 0.98 |
| pii | 40 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| toxicity | 28 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| gibberish | 22 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| ban_topics | 32 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| code_execution | 32 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 |
| url_allowlist | 24 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| token_limit | 16 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| regex | 20 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.60 |
| obfuscation | 26 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.24 |
| prompt_leak | 25 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| exfiltration | 47 | 1.00 | 1.00 | 1.00 | 1.00 | 0.76 | 0.76 | 1.00 |
| **overall** | **410** | **1.00** | **1.00** | **1.00** | **1.00** | **0.87** | **0.87** | **0.93** |

The headline: normalization defeats zero-width, fullwidth, and homoglyph
evasion in every row. The cells that are not 1.00 are worth reading
closely, because most of them are the eval being honest, not the
pipeline failing:

- `secrets` mixed_case 0.84 (was 0.86 in v0.7.4): the transform
  defangs the secret. A mixed-case `AkIa...` is not a well-formed AWS
  key, so the scanner is right to stay quiet. The cases that survive
  are the ones whose format is case-insensitive by design (generic
  assignments, hex tokens). The JWT cases added in v0.7.3 behave the
  same way: a case-mangled token no longer decodes to a JSON header,
  so it is not a working token anymore, and the validated check stays
  quiet on it. The platform tokens added in v0.7.4 split the
  difference: their prefixes are case-sensitive, so the named
  patterns stay quiet on the mangled text (verified directly: with
  the entropy heuristic off, all five mangled cases scan clean), but
  their long bodies still trip the entropy heuristic as unlabelled
  tokens, which is why this cell ticked up instead of down. The
  v0.7.5 formats pull the other way: their prefixes are
  case-sensitive and the hex bodies only accept lowercase hex, so a
  case-mangled copy is not a working token anymore, and verified
  directly, all four new formats scan clean when case-mangled,
  with the entropy heuristic off. That is why this cell ticked down instead.
- `secrets` neg_ok 0.98 (was 1.00 before the JWT cases): the one
  transformed negative that flags is not the JWT check misfiring. The
  mixed-case transform rewrites a benign dotted blob's payload segment
  into a mixed-case string diverse enough to trip the older entropy
  heuristic. With the entropy heuristic off, the transformed text is
  clean and `jwt_valid` rejects the mangled token outright. The dip
  is the heuristic's known false-positive shape, surfaced by a new
  near-miss case, and the case stays in the corpus so it stays
  visible.
- `code_execution` mixed_case/combined 0.00: `Os.SyStEm(` does not
  execute in Python, and this scanner's threat model is executable code
  (a compromised tool handing the agent a snippet that escapes the
  sandbox when run). Case-mangled variants are correctly ignored. If you
  want those flagged anyway, run prompt_injection alongside it.
- `regex` neg_ok 0.60: the bundled `required=[r"\bhello\b"]` pattern is
  case-sensitive, so mixed-case benign text fails the required pattern.
  That is user configuration, not a library bug; add `(?i)` to your own
  patterns if you want case-insensitive matching.
- `obfuscation` fullwidth and homoglyph are 1.00 since v0.6.0 (they
  were 0.57 and 0.71 in v0.4.0). The scanner now flags fullwidth runs
  directly, catches mixed-script words even when so little Latin
  survives that the document-level tripwire misses, and re-checks
  literal escapes and encoded blobs on a folded copy of the text with
  spans mapped back to the original.
- `obfuscation` neg_ok 0.24: by construction, and lower than it used
  to be. The transforms inject zero-width, fullwidth, and homoglyph
  characters into benign text, which is exactly what this scanner
  detects, and v0.6.0 detects more of it. A benign sentence rewritten
  in fullwidth is indistinguishable from an evasive one, which is why
  this scanner stays opt-in.
- `exfiltration` mixed_case 0.76 (was 0.79 in v0.7.4): same
  defanging logic as `secrets`, plus the same entropy-heuristic
  pickup on the new platform token bodies.
  The scanner reuses the secrets and PII detectors, whose formats are
  case-sensitive for a reason: a mixed-case PEM header is not a working
  key block, and `AkIa...` is not a working AWS key. The v0.7.5
  DigitalOcean cases in this corpus behave the same way.

Two real bugs came out of building this eval, both fixed in v0.4.0:

- Uppercased homoglyphs walked past normalization. The confusables table
  had lowercase Cyrillic/Greek lookalikes but was missing most uppercase
  forms, so `ІdІoΤ` never folded back. The table is now case-complete.
- `url_allowlist` missed mixed-case schemes. Schemes are
  case-insensitive per RFC 3986, so `hTTpS://evil.example` is a URL;
  the extractor regex is now case-insensitive too.

## Latency

Measured 2026-11-14, before (v0.7.1) and after (v0.7.2) the
performance pass. The harness ships with the package, so you can run
the same table on your own machine:

```bash
python -m llm_sentinel.perf
```

Method: median of five runs, each run timing a fixed number of scans
with `time.perf_counter` and dividing, on one shared development VM
running Python 3.12. Four fixed texts: a short prompt (87 chars), a
medium document (1,536 chars), a long document (15,360 chars), and a
short attack string (161 chars). "Vault, full" is the default
scanners plus the three opt-in ones (obfuscation, prompt_leak,
exfiltration).

| measurement | before | after | change |
|---|---|---|---|
| Vault (default), short | 0.204 ms | 0.180 ms | 12% faster |
| Vault (default), medium | 3.047 ms | 2.595 ms | 15% faster |
| Vault (default), long | 30.630 ms | 25.520 ms | 17% faster |
| Vault (default), attack | 0.368 ms | 0.329 ms | 11% faster |
| Vault (full), medium | 5.737 ms | 4.600 ms | 20% faster |
| Vault (full), long | 56.038 ms | 44.320 ms | 21% faster |
| Normalization only, medium | 0.336 ms | 0.025 ms | about 13x faster |
| Normalization only, long | 3.527 ms | 0.276 ms | about 13x faster |
| Obfuscation scanner, medium | 1.639 ms | 0.750 ms | about 2.2x faster |
| Obfuscation scanner, long | 15.798 ms | 7.433 ms | about 2.1x faster |

What changed, in the order it mattered:

- Normalization ran `unicodedata.normalize` once per character. Plain
  ASCII is a fixed point of the whole pass (nothing to strip, no
  confusable keys, NFKC is the identity on ASCII), so ASCII text now
  takes a fast path, and mixed text only pays for NFKC on its
  non-ASCII characters. Most real prompts are ASCII, which is why
  this one change dominates the table.
- The obfuscation scanner recompiled two of its patterns on every
  scan; they are compiled once in the constructor now. Its
  control-character check built a regex match object per character;
  it loops over the characters directly. Its script counts used
  `findall` lists it immediately threw away; they count with
  `finditer` now. And its folded re-check is skipped for pure-ASCII
  text, where folding provably changes nothing.
- The Vault compared the normalized copy against the original once
  per scanner to decide whether offsets needed remapping. That was a
  full extra pass over the text for every scanner; it is decided once
  per scan now.
- Smaller stuff in the same spirit: precompiled patterns for the card
  separator cleanup in PII and the token-shape checks behind the
  secrets entropy heuristic, and a single-pass consonant ratio in the
  gibberish scanner.

Honest limits on these numbers:

- No behavior changed. The 383-case benchmark above still reads 1.00
  across the board, the adversarial eval table is unchanged, and new
  tests in `tests/test_perf.py` pin the optimized normalization and
  obfuscation paths to the original algorithms output for output.
  Speed claims without that check would just be a faster way to be
  wrong.
- The end-to-end gain is real but modest, because the remaining cost
  is structural: every scanner walks the text with its own set of
  patterns (ban_topics alone runs 22). Merging patterns into a single
  pass would change which findings come back and how they are scored,
  so I did not do it. If scan latency ever matters more than finding
  granularity, that is the lever, and it is a behavior change, not an
  optimization.
- One shared VM is a noisy place to measure. Expect plus or minus
  10% between runs of the harness; the medians above are the middle
  of five runs, not a best case.

## What the benchmark does not measure

- Latency on your workload. The latency table above is four fixed
  synthetic texts on one machine; run the shipped harness on your own
  traffic and hardware before quoting any of it.
- Paraphrase, leetspeak, non-English attacks, or meaning-level evasion.
  The adversarial transforms are typographic only. Those need a real red
  team, not string munging.
- Your data. The single most useful thing you can do with this library
  is run it against your own traffic and tell me where it is wrong.
- Independence. The October 2026 expansion grew the corpus from 175 to
  375 cases, but I wrote every new case myself, against patterns I also
  wrote. A 1.00 table under that setup shows the patterns do what I
  meant them to do. It says nothing about attacks I did not think of,
  which is exactly the set that matters in production.

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
