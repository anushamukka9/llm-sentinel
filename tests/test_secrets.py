"""Tests for SecretsScanner."""

import base64
import json

from llm_sentinel.scanners import SecretsScanner, jwt_valid

scanner = SecretsScanner()


def _b64url(value) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(header=None, payload=None, signature="dGVzdHNpZ25hdHVyZQ") -> str:
    header = {"alg": "HS256", "typ": "JWT"} if header is None else header
    payload = {"sub": "user-123", "name": "Test User"} if payload is None else payload
    return ".".join([_b64url(header), _b64url(payload), signature])


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


def test_openai_project_key():
    # Current default key format: hyphen-separated segments after the
    # sk-proj- prefix. Built by concatenation like the other fake keys.
    key = "sk-proj-" + "Ab1Cd2Ef3" + "-Gh4Ij5Kl6" + "_Mn7Op8Qr9" + "-St0UvWx2Yz3"
    findings = scanner.scan("key " + key + " here")
    named = [f for f in findings if "OpenAI project key" in f.message]
    assert named and named[0].score >= 0.9
    assert named[0].matched_text == key


def test_openai_project_key_without_entropy_scan():
    # With the entropy heuristic off, the named pattern alone must catch
    # project keys; before the fix this scan came back empty.
    s = SecretsScanner(entropy_scan=False)
    key = "sk-proj-" + "Ab1Cd2Ef3" + "-Gh4Ij5Kl6" + "_Mn7Op8Qr9"
    findings = s.scan("key " + key + " here")
    assert findings and "OpenAI project key" in findings[0].message


def test_openai_service_account_key():
    s = SecretsScanner(entropy_scan=False)
    key = "sk-svcacct-" + "Ab1Cd2Ef3" + "-Gh4Ij5Kl6" + "_Mn7Op8Qr9"
    findings = s.scan("key " + key + " here")
    assert findings and "OpenAI project key" in findings[0].message


def test_openai_project_key_single_finding():
    # The bare-token heuristic must not add a second, weaker finding on
    # top of the named match for the same key.
    key = "sk-proj-" + "Ab1Cd2Ef3" + "-Gh4Ij5Kl6" + "_Mn7Op8Qr9" + "-St0UvWx2Yz3"
    findings = scanner.scan("key " + key + " here")
    assert len(findings) == 1


def test_openai_project_prefix_alone_not_flagged():
    s = SecretsScanner(entropy_scan=False)
    assert s.scan("the sk-proj- prefix starts a project key") == []


def test_aws_temporary_key():
    # ASIA ids are STS temporary credentials, same leak as AKIA.
    s = SecretsScanner(entropy_scan=False)
    findings = s.scan("temp key " + "ASIA" + "1234567890ABCDEF" + " in env")
    assert findings and "AWS" in findings[0].message


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


def test_jwt_detected():
    token = _jwt()
    findings = scanner.scan("session token " + token + " keep it safe")
    named = [f for f in findings if "JWT" in f.message]
    assert named and named[0].score >= 0.9
    assert named[0].matched_text == token


def test_jwt_detected_without_entropy_scan():
    # The validated check stands on its own; before it existed, a JWT
    # with the entropy heuristic off produced no finding at all, and
    # with it on, at most a weak per-segment one.
    s = SecretsScanner(entropy_scan=False)
    findings = s.scan("token " + _jwt() + " here")
    assert findings and "JWT" in findings[0].message


def test_jwt_single_finding():
    # The whole token is claimed, so the entropy heuristic must not add
    # weaker findings for its individual segments.
    findings = scanner.scan("token " + _jwt() + " here")
    assert len(findings) == 1


def test_jwt_in_bearer_header():
    findings = scanner.scan("Authorization: Bearer " + _jwt())
    assert findings and any("JWT" in f.message for f in findings)


def test_jwt_valid_accepts_demo_shape():
    assert jwt_valid(_jwt())


def test_jwt_valid_rejects_wrong_segment_count():
    assert not jwt_valid(_b64url({"alg": "HS256"}) + "." + _b64url({"sub": "x"}))
    assert not jwt_valid(_jwt() + ".extra")


def test_jwt_valid_rejects_header_without_alg():
    assert not jwt_valid(_jwt(header={"typ": "JWT"}))


def test_jwt_valid_rejects_non_object_payload():
    assert not jwt_valid(_jwt(payload=["not", "an", "object"]))


def test_jwt_valid_rejects_non_json_segments():
    assert not jwt_valid("aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccc")


def test_jwt_valid_rejects_empty_signature():
    token = _b64url({"alg": "none"}) + "." + _b64url({"sub": "x"}) + "."
    assert not jwt_valid(token)


def test_dotted_non_jwt_not_flagged():
    # Three dotted base64url-looking segments that do not decode to a
    # JSON header and payload are not a token, however long they are.
    s = SecretsScanner(entropy_scan=False)
    assert s.scan("blob aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccc stored") == []


def test_semver_not_flagged():
    s = SecretsScanner(entropy_scan=False)
    assert s.scan("shipped version 1.2024.11 today") == []
