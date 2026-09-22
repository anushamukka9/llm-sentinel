"""Tests for TokenLimitScanner, URLAllowlistScanner, CodeExecutionScanner, RegexScanner."""

from llm_sentinel.scanners import (
    CodeExecutionScanner,
    RegexScanner,
    TokenLimitScanner,
    URLAllowlistScanner,
)


class TestTokenLimit:
    def test_under_limit_passes(self):
        s = TokenLimitScanner(max_tokens=100)
        assert s.scan("A short prompt.") == []

    def test_over_limit_flags(self):
        s = TokenLimitScanner(max_tokens=10)
        findings = s.scan("word " * 100)
        assert findings
        assert "exceeds limit" in findings[0].message

    def test_invalid_limit_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            TokenLimitScanner(max_tokens=0)


class TestURLAllowlist:
    def test_external_domain_flagged(self):
        s = URLAllowlistScanner(allowed_domains=["example.com"])
        findings = s.scan("See https://evil.example.net/login for more.")
        assert findings
        assert "allowlist" in findings[0].message

    def test_allowed_domain_passes(self):
        s = URLAllowlistScanner(allowed_domains=["example.com"])
        assert s.scan("Docs at https://example.com/docs.") == []

    def test_subdomain_allowed(self):
        s = URLAllowlistScanner(allowed_domains=["example.com"])
        assert s.scan("See https://api.example.com/v2.") == []

    def test_no_allowlist_is_noop(self):
        s = URLAllowlistScanner()
        assert s.scan("See https://evil.example.net/.") == []

    def test_ip_url_flagged(self):
        s = URLAllowlistScanner(allowed_domains=["example.com"])
        assert s.scan("Go to http://192.168.1.1/admin.")

    def test_no_urls_clean(self):
        s = URLAllowlistScanner(allowed_domains=["example.com"])
        assert s.scan("No links here.") == []


class TestCodeExecution:
    scanner = CodeExecutionScanner()

    def test_os_system(self):
        assert self.scanner.scan('Run os.system("ls") now.')

    def test_subprocess(self):
        assert self.scanner.scan('Use subprocess.Popen(["x"]) here.')

    def test_eval(self):
        assert self.scanner.scan("Just eval(user_input) please.")

    def test_exec(self):
        assert self.scanner.scan("Call exec(code) to run it.")

    def test_pickle_loads(self):
        assert self.scanner.scan("data = pickle.loads(blob)")

    def test_dunder_import(self):
        assert self.scanner.scan('mod = __import__("os")')

    def test_prose_about_code_clean(self):
        # Discussing the os module is not executing anything.
        assert self.scanner.scan("The os module provides OS interfaces.") == []

    def test_evaluated_not_eval(self):
        assert self.scanner.scan("We evaluated the model.") == []


class TestRegex:
    def test_forbidden_hit(self):
        s = RegexScanner(forbidden=[r"\bclassified\b"])
        assert s.scan("this is classified info")

    def test_forbidden_miss(self):
        s = RegexScanner(forbidden=[r"\bclassified\b"])
        assert s.scan("this is public info") == []

    def test_required_present(self):
        s = RegexScanner(required=[r"\bhello\b"])
        assert s.scan("well hello there") == []

    def test_required_missing(self):
        s = RegexScanner(required=[r"\bhello\b"])
        findings = s.scan("goodbye world")
        assert findings
        assert "Required pattern not found" in findings[0].message

    def test_needs_at_least_one_pattern(self):
        import pytest

        with pytest.raises(ValueError):
            RegexScanner()
