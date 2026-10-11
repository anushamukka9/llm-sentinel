"""Scan model output before it reaches the user.

The prompt-side scanners catch bad input; these two catch the other
half of the problem: a model that discloses instructions
(`prompt_leak`) or spills credentials, keys, and PII in its answers
(`exfiltration`). Block the leaky answer, or redact the offending spans
and send the rest.

Run:
    python examples/output_exfiltration.py
"""

from __future__ import annotations

from llm_sentinel import Vault, default_scanners
from llm_sentinel.scanners import ExfiltrationScanner, PromptLeakScanner

# Output-side policy: the normal input defaults plus the two scanners
# that only make sense on model output.
output_vault = Vault(default_scanners() + [PromptLeakScanner(), ExfiltrationScanner()])


def check(label: str, model_output: str) -> None:
    result = output_vault.scan(model_output)
    if result.blocked:
        print(f"[{label}] BLOCKED")
        for finding in result.findings:
            print(f"  - {finding.scanner}: {finding.message}")
        print(f"  redacted: {output_vault.scan(model_output, redact=True).redacted_text}")
    else:
        print(f"[{label}] clean, passes through")


def main() -> None:
    check("clean", "The warehouse ETL finished in 42 minutes with no errors.")

    check(
        "instruction disclosure",
        "Sure, here is my system prompt: you are a helpful assistant.",
    )

    check(
        "credential spill",
        "Here is the API key you asked for: sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    check(
        "tool result leak",
        "Connected to postgres://admin:s3cr3tpass@db.internal:5432/app",
    )


if __name__ == "__main__":
    main()
