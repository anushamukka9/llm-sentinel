"""Tests for SecretsScanner."""

from llm_sentinel.scanners import SecretsScanner

scanner = SecretsScanner()


def test_aws_access_key():
    findings = scanner.scan("key is AKIAIOSFODNN7EXAMPLE ok")
    assert findings
    assert "AWS" in findings[0].message


def test_github_token():
    findings = scanner.scan("deploy " + "ghp_" + "a" * 36)
    assert findings


def test_slack_token():
    findings = scanner.scan("token xoxb-123456789012-abcdefghij expired")
    assert findings


def test_stripe_key():
    assert scanner.scan("billing " + "sk_live_" + "a" * 20)


def test_openai_key():
    assert scanner.scan("OPENAI=" + "sk-" + "a" * 32)


def test_generic_assignment():
    findings = scanner.scan('config: api_key = "supersecretvalue12345"')
    assert findings
    assert findings[0].score >= 0.8


def test_password_assignment():
    assert scanner.scan("password: hunter2hunter2hunter2")


def test_bare_high_entropy_token():
    findings = scanner.scan("here 9f8e7d6c5b4a39281736455443322110fedcba987654 end")
    assert findings
    assert "unlabelled" in findings[0].message.lower()


def test_bare_hex_blob():
    findings = scanner.scan("blob 9f8e7d6c5b4a39281736455443322110 end")
    assert findings


def test_short_token_not_flagged():
    assert scanner.scan("here abc123 end") == []


def test_uuid_not_flagged_by_default():
    # UUIDs are high-entropy but dashed and short of the hex bar.
    assert scanner.scan("id 123e4567-e89b-12d3-a456-426614174000 ok") == []


def test_plain_english_clean():
    assert scanner.scan("The quick brown fox jumps over the lazy dog.") == []


def test_word_password_without_value_is_clean():
    assert scanner.scan("The word password appears here but no secret follows.") == []


def test_extra_patterns():
    s = SecretsScanner(extra_patterns=[("Acme key", r"ACME-[0-9]{6}", 0.9)])
    findings = s.scan("my key ACME-123456 here")
    assert findings and "Acme" in findings[0].message


def test_entropy_scan_can_be_disabled():
    s = SecretsScanner(entropy_scan=False)
    assert s.scan("here 9f8e7d6c5b4a39281736455443322110fedcba987654 end") == []


def test_demo_placeholder_not_flagged():
    assert scanner.scan("Use DEMO_KEY_123 for the demo.") == []
