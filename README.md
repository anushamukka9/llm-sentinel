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

Every scanner documents its limitations in its docstring. Read them before
you trust a scanner with anything important.

## Benchmarks

Each scanner ships with a labeled corpus under `benchmarks/` (true
positives and true negatives, including adversarial and near-miss cases).
Run them yourself:

```bash
python -m llm_sentinel.benchmark
```

Results on the bundled corpora (133 cases):

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
| **overall** | **133** | **1.00** | **1.00** | **1.00** |

Take these numbers for what they are: a smoke test proving the patterns
fire on the obvious cases, not a safety certification. The corpora are
small and hand-written. Real attacks are more creative than any corpus.
If you evaluate against your own data, please contribute the cases back.

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

## Honest limitations

- Pattern matching is not understanding. Novel phrasings, non-English
  attacks, and heavy obfuscation (zero-width chars, homoglyphs) will get
  through the prompt-injection scanner.
- The secrets entropy heuristic misses short secrets and flags some
  non-secrets. In-house key formats need your own patterns.
- PII coverage is narrow by design (email, phone, SSN, card). Names,
  addresses, and non-US identifiers are not covered.
- Toxicity and ban-topics are wordlists. They have no sense of context
  and will flag legitimate discussion of the thing they police.
- Redaction removes matched characters, not meaning. Do not rely on it
  alone for data you cannot afford to leak; pair it with blocking.

## Roadmap

- Unicode normalization pass (zero-width chars, homoglyphs) before scanning
- Pluggable LLM-as-judge scanner interface (opt-in, never default)
- Anonymize transform for PII (replace with typed placeholders, reversible
  with a local key)
- More adapters (Django middleware, crewAI callbacks)
- Larger, community-sourced benchmark corpora

## License

MIT. See LICENSE.
