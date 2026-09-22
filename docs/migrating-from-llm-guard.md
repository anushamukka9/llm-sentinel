# Migrating from llm-guard

`llm-guard` (Protect AI) was archived in July 2026 and is no longer maintained.
If your `requirements.txt` still pins it, you are frozen on a dead version with
no migration path and no security patches. This guide maps llm-guard concepts
to llm-sentinel so you can move the deterministic parts of your pipeline today.

The honest headline first: llm-sentinel is not a drop-in replacement. It covers
the deterministic core (patterns, entropy math, wordlists) with a stricter
contract and no model calls. Anything in llm-guard that needed a classifier
model is deliberately out of scope. The mapping table below says exactly what
is covered, what is partial, and what is missing, so you can decide with real
information.

## Install

PyPI publishing is pending, so install from GitHub for now:

```bash
pip install git+https://github.com/anushamukka9/llm-sentinel.git
```

Python 3.10+.

## The Vault, translated

llm-guard:

```python
from llm_guard import scan_prompt, scan_output
from llm_guard.input_scanners import Anonymize, PromptInjection, Toxicity
from llm_guard.output_scanners import Sensitive
from llm_guard.vault import Vault

vault = Vault()
input_scanners = [Anonymize(vault), Toxicity(), PromptInjection()]
output_scanners = [Sensitive()]

sanitized, valid, scores = scan_prompt(input_scanners, prompt)
sanitized_out, valid, scores = scan_output(output_scanners, prompt, response)
```

llm-sentinel:

```python
from llm_sentinel import Vault, default_scanners

vault = Vault(default_scanners())

result = vault.scan(prompt)          # replaces scan_prompt
if result.blocked:
    raise ValueError("blocked by guardrails")

result = vault.scan(model_output)    # replaces scan_output
```

Two differences to notice. First, there is no separate input/output scanner
split: the same vault scans prompts and model outputs. If you kept different
policies for each direction, build two vaults. Second, `scan()` returns a
result object (`blocked`, `findings`, `scores`) instead of three tuples, and
redaction is a flag: `vault.scan(text, redact=True).redacted_text`.

A custom policy with per-scanner thresholds:

```python
from llm_sentinel import (
    COLLECT_ALL, Vault, PIIScanner, PromptInjectionScanner, SecretsScanner,
)

vault = (
    Vault(mode=COLLECT_ALL, default_threshold=0.5)
    .add(PromptInjectionScanner())
    .add(SecretsScanner(), threshold=0.7)
    .add(PIIScanner())
)
```

`COLLECT_ALL` runs every scanner and reports everything (closest to llm-guard's
default reporting). `FAIL_FAST` stops at the first block, which is cheaper in
a hot path.

## Scanner mapping

"Partial" means the concept exists but the semantics differ; read the note.

| llm-guard scanner | llm-sentinel equivalent | Notes |
|---|---|---|
| `PromptInjection` (input) | `PromptInjectionScanner` | Partial. llm-guard used a classifier model; this is pattern-based (instruction overrides, delimiter smuggling, jailbreak markers). Catches known phrasings in microseconds; will not catch novel phrasings a model might. That trade is the design: a classifier can itself be bypassed (the `LANGUAGE` flip-token bypass is what got llm-guard archived), patterns cannot. |
| `Secrets` (input) | `SecretsScanner` | Yes. Provider key formats plus generic high-entropy token detection. |
| `Toxicity` (input/output) | `ToxicityScanner` | Yes, wordlist-based, density-scored. The wordlist deliberately excludes slurs; see the scanner docstring. |
| `Gibberish` (input/output) | `GibberishScanner` | Yes. |
| `BanTopics` (input/output) | `BanTopicsScanner` | Yes, configurable keywords. |
| `TokenLimit` (input) | `TokenLimitScanner` | Yes, chars/4 estimation heuristic. |
| `Regex` (input/output) | `RegexScanner` | Yes. |
| `BanSubstrings` (input/output) | `RegexScanner` | Partial. Express your forbidden substrings as patterns. |
| `BanCompetitors` (input/output) | `RegexScanner` | Partial. Competitor names as forbidden patterns. |
| `BanCode` (input/output) | None | `BanCode` kept code out of prompts. `CodeExecutionScanner` looks for execution-capable calls (`os.system`, `eval`, `pickle.loads`) in untrusted output instead. Different job. If you used `BanCode` on inputs, `RegexScanner` with code-pattern rules gets you there. |
| `Code` (input/output) | `CodeExecutionScanner` | Partial, same note as above: aimed at agent tool output, not at detecting code blocks in chat. |
| `Anonymize` (input) | `PIIScanner` | Partial. Detects emails, phones, SSNs, Luhn-validated cards, and redacts via `vault.scan(text, redact=True)`. No faker-based placeholder substitution and no `Deanonymize` round-trip. |
| `Sensitive` (output) | `PIIScanner` | Partial, same note. |
| `Deanonymize` (output) | None | Faker round-trip is not implemented. |
| `MaliciousURLs` (output) | `URLAllowlistScanner` | Partial, inverted semantics: allowlist (deny-by-default) instead of blocklist. If you need blocklist behavior, use `RegexScanner`. |
| `URLReachability` (output) | None | Requires network access; llm-sentinel makes no network calls by design. |
| `Language`, `LanguageSame` | None | Model-based language detection; out of scope. |
| `InvisibleText` | None | Zero-width/homoglyph handling is on the roadmap, not in v0.1.0. |
| `Sentiment`, `EmotionDetection`, `Bias` | None | Model-based judges; out of scope by design. |
| `Relevance`, `FactualConsistency` | None | Model-based judges; out of scope by design. |
| `NoRefusal` | None | No equivalent. |
| `ReadingTime` | None | Trivial to compute yourself; not worth a dependency. |
| `JSON` (output) | None | Structural validation; `RegexScanner` covers shape constraints. |

## What is deliberately not covered

Three categories, all intentional:

1. **Model-based judges.** Anything that needed a classifier or an LLM call
   (sentiment, relevance, factuality, language detection) is out. If your
   threat model needs those, keep a judge model for that layer and put
   llm-sentinel in front of it as the cheap deterministic first pass. The two
   compose: deterministic first, model second, and the deterministic layer
   cannot be prompt-injected.
2. **Anything needing the network.** No URL reachability checks, no remote
   model calls, no telemetry. Your data never leaves the process.
3. **Anonymize/deanonymize round-trips.** Redaction is supported; replacing
   PII with fake values and restoring them later is not.

## Suggested migration order

1. Start in `COLLECT_ALL` mode with `default_scanners()` alongside your
   existing llm-guard setup. Log findings; do not block yet.
2. Compare against what llm-guard was flagging on real traffic for a week.
   Tune per-scanner thresholds where the two disagree.
3. Switch blocking over scanner by scanner, starting with secrets and PII
   (highest precision, lowest controversy).
4. Remove llm-guard. Keep your model-based judges if you had them; they were
   never this library's job.

If you hit a gap that blocks your migration, open an issue on the repo with
the llm-guard scanner name and your use case. Migration-driven feature
requests get priority.
