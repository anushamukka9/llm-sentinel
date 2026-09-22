"""Code-execution scanner.

Flags markers of arbitrary code execution in text: ``os.system``,
``subprocess`` calls, ``eval``/``exec``, deserialization of untrusted
data (``pickle.loads``), and dynamic imports. The threat model is agent
tool output: a compromised tool can hand the agent a "helpful" snippet
that escapes the sandbox when executed.

Limitations, stated plainly:
- Pattern matching on code is inherently fragile. Renamed imports
  (``import subprocess as sp``), getattr tricks, and string-built calls
  evade it. This is a tripwire for the obvious cases, not a sandbox.
- It will flag legitimate code discussion: documentation, Stack Overflow
  answers, and code review all mention these calls. Run it on *tool
  output about to be executed*, not on prose about code.
- It says nothing about whether the code is actually dangerous, only
  that the markers are present.
"""

from __future__ import annotations

import re

from ..core import Finding, Scanner
from .base import find_all, make_finding

_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (
        re.compile(r"\bos\.system\s*\("),
        0.9,
        "Shell command via os.system",
    ),
    (
        re.compile(r"\bsubprocess\.\s*(Popen|call|run|check_output|check_call)\s*\("),
        0.9,
        "Subprocess invocation",
    ),
    (
        re.compile(r"(?<![\w.])\beval\s*\("),
        0.85,
        "Dynamic evaluation via eval()",
    ),
    (
        re.compile(r"(?<![\w.])\bexec\s*\("),
        0.85,
        "Dynamic execution via exec()",
    ),
    (
        re.compile(r"\b__import__\s*\("),
        0.8,
        "Dynamic import via __import__",
    ),
    (
        re.compile(r"\bpickle\.loads\s*\("),
        0.85,
        "Deserialization of untrusted data (pickle.loads)",
    ),
    (
        re.compile(r"\byaml\.load\s*\("),
        0.7,
        "Unsafe YAML deserialization (yaml.load without Loader)",
    ),
    (
        re.compile(r"\bsocket\.\s*(socket|create_connection)\s*\("),
        0.7,
        "Raw socket use",
    ),
]


class CodeExecutionScanner(Scanner):
    """Flags code-execution markers, aimed at untrusted tool output."""

    name = "code_execution"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, score, message in _PATTERNS:
            for match in find_all(pattern, text):
                findings.append(make_finding(self.name, match, score, message))
        return findings
