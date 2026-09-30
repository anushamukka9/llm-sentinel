"""Built-in scanners."""

from .ban_topics import DEFAULT_TOPICS, BanTopicsScanner
from .code_execution import CodeExecutionScanner
from .gibberish import GibberishScanner
from .obfuscation import ObfuscationScanner
from .pii import PIIScanner, luhn_valid
from .prompt_injection import PromptInjectionScanner
from .prompt_leak import PromptLeakScanner
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
    "ObfuscationScanner",
    "PIIScanner",
    "PromptInjectionScanner",
    "PromptLeakScanner",
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

    ObfuscationScanner is excluded: multilingual text trips its heuristics,
    so it is opt-in for traffic you know is mostly ASCII.

    PromptLeakScanner is excluded: it is an output-side scanner. Add it
    explicitly when you scan model output.
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


#: Scanner name -> class, for config-driven construction (Vault.from_dict).
SCANNER_REGISTRY: dict = {
    "prompt_injection": PromptInjectionScanner,
    "secrets": SecretsScanner,
    "pii": PIIScanner,
    "toxicity": ToxicityScanner,
    "gibberish": GibberishScanner,
    "ban_topics": BanTopicsScanner,
    "code_execution": CodeExecutionScanner,
    "url_allowlist": URLAllowlistScanner,
    "token_limit": TokenLimitScanner,
    "regex": RegexScanner,
    "obfuscation": ObfuscationScanner,
    "prompt_leak": PromptLeakScanner,
}
