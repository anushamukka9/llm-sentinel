"""Built-in scanners."""

from .ban_topics import DEFAULT_TOPICS, BanTopicsScanner
from .code_execution import CodeExecutionScanner
from .gibberish import GibberishScanner
from .pii import PIIScanner, luhn_valid
from .prompt_injection import PromptInjectionScanner
from .regex_scan import RegexScanner
from .secrets import SecretsScanner
from .token_limit import TokenLimitScanner, estimate_tokens
from .toxicity import ToxicityScanner
from .url_allowlist import URLAllowlistScanner

__all__ = [
    "BanTopicsScanner",
    "DEFAULT_TOPICS",
    "CodeExecutionScanner",
    "GibberishScanner",
    "PIIScanner",
    "PromptInjectionScanner",
    "RegexScanner",
    "SecretsScanner",
    "TokenLimitScanner",
    "ToxicityScanner",
    "URLAllowlistScanner",
    "estimate_tokens",
    "luhn_valid",
    "default_scanners",
]


def default_scanners() -> list:
    """The standard input-side scanner set, in a sensible order.

    URLAllowlistScanner is excluded: with no allowlist configured it is a
    no-op, and silently including it would imply protection that is not
    there. Add it explicitly with your domains.
    """
    return [
        PromptInjectionScanner(),
        SecretsScanner(),
        PIIScanner(),
        ToxicityScanner(),
        GibberishScanner(),
        BanTopicsScanner(),
        CodeExecutionScanner(),
        TokenLimitScanner(),
    ]
