"""llm-sentinel: deterministic guardrails for LLM apps.

Scan prompts and outputs for prompt injection, leaked secrets, PII,
toxicity, gibberish, banned topics, and more. No model calls, no network,
no data leaves your process.

Quickstart:
    from llm_sentinel import Vault, default_scanners

    vault = Vault(default_scanners())
    result = vault.scan(user_input)
    if result.blocked:
        ...  # refuse, log, or ask for confirmation

    # or get a redacted copy:
    safe = vault.scan(text, redact=True).redacted_text
"""

from .core import Finding, Scanner, ScanResult
from .scanners import (
    BanTopicsScanner,
    CodeExecutionScanner,
    GibberishScanner,
    PIIScanner,
    PromptInjectionScanner,
    RegexScanner,
    SecretsScanner,
    TokenLimitScanner,
    ToxicityScanner,
    URLAllowlistScanner,
    default_scanners,
)
from .vault import COLLECT_ALL, FAIL_FAST, Vault, redact_spans

__version__ = "0.1.0"

__all__ = [
    "COLLECT_ALL",
    "FAIL_FAST",
    "BanTopicsScanner",
    "CodeExecutionScanner",
    "Finding",
    "GibberishScanner",
    "PIIScanner",
    "PromptInjectionScanner",
    "RegexScanner",
    "Scanner",
    "ScanResult",
    "SecretsScanner",
    "TokenLimitScanner",
    "ToxicityScanner",
    "URLAllowlistScanner",
    "Vault",
    "default_scanners",
    "redact_spans",
]
