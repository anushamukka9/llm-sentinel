# llm-sentinel

Deterministic guardrails for LLM apps. Scan prompts and model outputs for
prompt injection, leaked secrets, PII, toxicity, gibberish, banned topics,
and more. No model calls, no network, no data leaves your process.

## Why this exists

The category-defining library here, `llm-guard`, was archived in July 2026
with millions of monthly downloads and dozens of open issues on a now
read-only repo. If you are migrating off it, llm-sentinel covers the same
core idea with a smaller, stricter contract: everything is deterministic.
Patterns, entropy math, and wordlists. Nothing that needs a GPU, an API
key, or a second opinion from another model.

That strictness is the point. A guardrail that calls a model to check the
output of a model inherits all the failure modes it is supposed to guard
against, plus latency and cost. These scanners answer in microseconds with
behavior you can read in the source.

Migrating off llm-guard? See [the migration guide](docs/migrating-from-llm-guard.md)
for a scanner-by-scanner mapping, including what is and is not covered.

## Quickstart

```bash
pip install llm-sentinel
```

```python
from llm_sentinel import Vault, default_scanners

vault = Vault(default_scanners())

result = vault.scan(user_input)
if result.blocked:
    raise ValueError("blocked by guardrails")

# Or get a redacted copy instead of a yes/no answer:
safe = vault.scan(text, redact=True).redacted_text
```

Compose your own policy with per-scanner thresholds:

```python
from llm_sentinel import Vault, SecretsScanner, PIIScanner, PromptInjectionScanner

vault = (
    Vault(mode="fail_fast", default_threshold=0.5)
    .add(PromptInjectionScanner())
    .add(SecretsScanner(), threshold=0.7)
    .add(PIIScanner())
)
```

Scan model output too. The threat model changed when agents started
executing tool output: untrusted text does not only come from users
anymore.

```python
result = vault.scan(model_output)
```

## Normalization

Before scanning, the Vault normalizes the text: zero-width characters
are stripped, fullwidth forms are folded (NFKC), and common cross-script
homoglyphs are mapped to Latin. This defeats the cheapest evasion
tricks, like slipping a zero-width space into "ignore". Finding offsets
are translated back to your original text, so redaction still works on
what you passed in.

```python
from llm_sentinel import normalize_text

normalize_text("ig\u200bnore")  # "ignore"

# Opt out if you normalize yourself or need raw offsets:
raw_vault = Vault(default_scanners(), normalize=False)
```

Two things to know. The confusables table is small and curated, not the
full Unicode list: it raises the bar, it does not remove it. And the
`obfuscation` scanner opts itself out of normalization
(`normalize_input = False`), because it detects the very tricks
normalization removes. Run both in one Vault and each gets the text it
needs: the tripwire sees the raw attempt, the other scanners see the
cleaned text.

## Scanners

| Scanner | What it catches |
|---|---|
| `prompt_injection` | Instruction overrides, delimiter smuggling (`<<SYS>>`, `[INST]`), jailbreak markers, role-play switches, system-prompt extraction |
| `secrets` | AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, Google keys; generic `key = value` assignments; unlabelled high-entropy tokens |
| `pii` | Emails, phone numbers, US SSNs, credit card numbers (Luhn-validated) |
| `toxicity` | Profanity wordlist, scored by density |
| `gibberish` | Keyboard-mash and degenerated-model noise via consonant-ratio and entropy signals |
| `ban_topics` | Configurable banned-topic keywords (weapons, self-harm, illicit behavior by default) |
| `code_execution` | `os.system`, `subprocess`, `eval`/`exec`, `pickle.loads`, and friends, aimed at untrusted tool output |
| `url_allowlist` | URLs pointing outside your configured domain allowlist |
| `token_limit` | Text estimated over your token budget (chars/4 heuristic) |
| `regex` | Your own required/forbidden patterns |
| `obfuscation` | Zero-width chars, bidi overrides, stray control chars, mixed-script confusables, encoded-looking blobs (opt-in, see below) |
| `prompt_leak` | Model output that discloses system/developer instructions (opt-in, output-side) |

Every scanner documents its limitations in its docstring. Read them before
you trust a scanner with anything important.

Two scanners stay out of `default_scanners()` on purpose:

- `obfuscation`: multilingual text trips its heuristics (accents are fine,
  but Cyrillic/Greek runs and stray control chars in non-English text are
  not). Opt in when your traffic is mostly ASCII and you want the tripwire:
  `Vault(default_scanners() + [ObfuscationScanner()])`. It opts out of the
  Vault's normalization pass so it still sees the raw tricks; the other
  scanners in the same Vault get the normalized text.
- `prompt_leak`: it is an output-side scanner; the default set is the
  input-side set. Add it when you scan model output:
  `Vault(default_scanners() + [PromptLeakScanner()])`.

(For the same reason, `url_allowlist` is excluded: with no allowlist
configured it would be a no-op pretending to protect you.)

## Building a policy from config

```python
from llm_sentinel import Vault

config = {
    "mode": "fail_fast",
    "default_threshold": 0.6,
    "scanners": [
        "prompt_injection",
        {"name": "ban_topics", "kwargs": {"topics": {"politics": ["election"]}}},
        {"name": "secrets", "threshold": 0.9},
    ],
    "thresholds": {"pii": 0.7},
    "placeholders": {"pii": "[CONTACT]"},
}
vault = Vault.from_dict(config)
```

Scanner entries are registered names (see `SCANNER_REGISTRY`) or dicts
with `name`, optional constructor `kwargs`, and an optional per-scanner
`threshold`. Unknown names raise `ValueError` listing what is available.
`placeholders` gives you custom redaction text per scanner instead of the
`[REDACTED:SCANNER]` default.

## Guarding a function

For plain functions with no framework, `@guarded` scans string inputs
before the call and the string return value after:

```python
from llm_sentinel import guarded, GuardedError

@guarded(vault, redact=True)
def summarize(user_request: str) -> str:
    return call_model(user_request)
```

A blocked input raises `GuardedError` (refused, never scrubbed and
passed through). A blocked output raises too, unless `redact=True`,
which returns the redacted text instead. The error message names the
scanners that fired, never the matched text.

## Benchmarks

Each scanner ships with a labeled corpus under `benchmarks/` (true
positives and true negatives, including adversarial and near-miss cases).
Run them yourself:

```bash
python -m llm_sentinel.benchmark
```

Results on the bundled corpora (155 cases):

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

Take these numbers for what they are: a smoke test proving the patterns
fire on the obvious cases, not a safety certification. The corpora are
small and hand-written. Real attacks are more creative than any corpus.
If you evaluate against your own data, please contribute the cases back.
Methodology, what the numbers do not measure, and how to add cases:
[docs/benchmarks.md](docs/benchmarks.md).

## Policy eval

The per-scanner benchmarks above measure scanners in isolation. The
policy eval measures a composed Vault end to end: `eval/policy_eval.json`
holds 17 labeled cases (injection, secrets, PII, prompt leaks,
obfuscation, and benign traffic), and the runner builds one fixed policy
(defaults plus the two opt-in scanners) and scores verdicts per category:

```bash
python -m llm_sentinel.eval
```

```
category       correct  total    acc
------------------------------------
benign               5      5   1.00
injection            4      4   1.00
obfuscation          2      2   1.00
pii                  2      2   1.00
prompt_leak          2      2   1.00
secrets              2      2   1.00
------------------------------------
overall             17     17   1.00
```

Same caveat as the benchmarks, doubled: 17 hand-written cases prove the
wiring is right, not that the policy is sufficient. Pass `--failures` to
see the cases a run gets wrong.

## Adapters

Thin integrations, all optional:

```python
# FastAPI: scan request and response bodies
# pip install llm-sentinel[fastapi]
from llm_sentinel.adapters.fastapi import SentinelMiddleware
app.add_middleware(SentinelMiddleware, vault=vault, block_status_code=400)

# LangChain: scan prompts and generations via callback, or wrap a Runnable
# pip install llm-sentinel[langchain]
from llm_sentinel.adapters.langchain import SentinelCallbackHandler, guard_runnable
safe_chain = guard_runnable(chain, vault)
```

## Examples

Runnable programs in [`examples/`](examples/), each one self-contained:

- `fastapi_app.py`: a chat API guarded by `SentinelMiddleware`, with
  block and redact modes (`pip install "llm-sentinel[fastapi]" uvicorn`)
- `langchain_chain.py`: a chain wrapped in `guard_runnable`, plus the
  callback-handler style, running offline on a fake model
  (`pip install "llm-sentinel[langchain]"`)
- `redact_pipeline.py`: a shell-friendly scrubber, stdin/file in,
  redacted text out, with a `--strict` mode for CI
- `guarded_function.py`: the `@guarded` decorator on a plain function:
  clean input passes, a leaky answer comes back redacted, an injection
  attempt raises `GuardedError`

See `examples/README.md` for the exact commands.

## Honest limitations

- Pattern matching is not understanding. Novel phrasings, non-English
  attacks, and paraphrased overrides will get through the
  prompt-injection scanner. The cheap typographic tricks (zero-width
  characters, fullwidth lookalikes, common homoglyphs) are normalized
  away by the Vault before scanning; heavy leetspeak and full Unicode
  confusable coverage are still out of scope.
- The secrets entropy heuristic misses short secrets and flags some
  non-secrets. In-house key formats need your own patterns.
- PII coverage is narrow by design (email, phone, SSN, card). Names,
  addresses, and non-US identifiers are not covered.
- Toxicity and ban-topics are wordlists. They have no sense of context
  and will flag legitimate discussion of the thing they police.
- Redaction removes matched characters, not meaning. Do not rely on it
  alone for data you cannot afford to leak; pair it with blocking.
- `obfuscation` catches the shape of obfuscation, not intent: a
  zero-width joiner in an emoji sequence is typography, not an attack,
  and hex-heavy tokens may not clear the blob entropy bar. It is opt-in
  because multilingual text trips it.
- `prompt_leak` is phrase matching. Paraphrased disclosures slip through,
  and benign self-reference ("my instructions are to be helpful") flags
  too.

## Roadmap

- Pluggable LLM-as-judge scanner interface (opt-in, never default)
- Reversible anonymize transform for PII (local key, not just redaction)
- More adapters (Django middleware, crewAI callbacks)
- Larger, community-sourced benchmark corpora

## License

MIT. See LICENSE.
