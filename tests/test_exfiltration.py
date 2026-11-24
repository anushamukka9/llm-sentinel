"""Tests for ExfiltrationScanner."""

from llm_sentinel.scanners import ExfiltrationScanner

scanner = ExfiltrationScanner()


def test_framing_here_is_api_key():
    findings = scanner.scan("Here is the API key you asked for: " + "sk-ant-" + "a" * 40)
    assert findings
    assert findings[0].scanner == "exfiltration"
    assert "volunteering" in findings[0].message


def test_framing_password_is():
    findings = scanner.scan("Your database password is s3cr3tP@ssw0rd123")
    assert findings
    assert "stating" in findings[0].message


def test_private_key_block():
    findings = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert findings
    assert "Private key block" in findings[0].message


def test_connection_string_with_credentials():
    findings = scanner.scan("Connected to postgres://admin:s3cr3tpass@db.internal:5432/app")
    assert findings
    assert "Connection string" in findings[0].message


def test_connection_string_without_credentials_is_quiet():
    assert scanner.scan("Connected to postgres://db.internal:5432/app") == []


def test_token_in_query_param():
    findings = scanner.scan("https://api.example.com/data?token=abcdef123456")
    assert findings
    assert "query parameter" in findings[0].message


def test_internal_key_path():
    findings = scanner.scan("Found the deploy key at ~/.ssh/id_rsa")
    assert findings
    assert "key path" in findings[0].message


def test_provider_key_format_flagged():
    findings = scanner.scan("key is AKIAIOSFODNN7EXAMPLE ok")
    assert findings
    assert "AWS" in findings[0].message


def test_github_token_flagged():
    assert scanner.scan("deploy " + "ghp_" + "a" * 36)


def test_generic_assignment_flagged():
    assert scanner.scan('config: api_key = "supersecretvalue12345"')


def test_ssn_flagged():
    findings = scanner.scan("SSN on file: 123-45-6789")
    assert findings
    assert "Social Security" in findings[0].message


def test_never_issued_ssn_is_quiet_on_output_side():
    # The delegated PII scanner carries the structural check: a
    # never-issued combination in a model response does not flag.
    findings = scanner.scan("SSN on file: 666-12-3456")
    assert [f for f in findings if "Social Security" in f.message] == []


def test_card_flagged():
    findings = scanner.scan("Card charged: 4539148803436467")
    assert findings
    assert "Credit card" in findings[0].message


def test_email_flagged():
    findings = scanner.scan("Reach me at jane.doe@example.com")
    assert findings
    assert "Email" in findings[0].message


def test_phone_flagged():
    findings = scanner.scan("Call me at 555-123-4567")
    assert findings
    assert "phone" in findings[0].message.lower()


def test_mention_without_disclosure_is_quiet():
    assert scanner.scan("Keep your API key secret and never share it.") == []


def test_refusal_is_quiet():
    assert scanner.scan("I can't share credentials; that's against policy.") == []


def test_blank_password_field_is_quiet():
    assert scanner.scan("The password field was left blank on the form.") == []


def test_plain_summary_is_quiet():
    assert scanner.scan("Here is the summary you asked for.") == []


def test_jwt_flagged_on_output_side():
    # The delegated secrets scanner carries the validated JWT check: a
    # session token in a model response flags under the exfiltration
    # name even with the entropy heuristic off.
    import base64
    import json

    def seg(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    token = ".".join(
        [seg({"alg": "HS256", "typ": "JWT"}), seg({"sub": "user-123"}), "dGVzdHNpZ25hdHVyZQ"]
    )
    quiet = ExfiltrationScanner(entropy_scan=False)
    findings = quiet.scan("here is the session token: " + token)
    assert findings and any("JWT" in f.message for f in findings)
    assert all(f.scanner == "exfiltration" for f in findings)


def test_gitlab_token_flagged_on_output_side():
    # The delegated secrets scanner carries the platform token formats:
    # a GitLab token in a model response flags even with the entropy
    # heuristic off.
    token = "glpat-" + "aB3dE5fG7hJ9" + "kL1mN3pQ"
    quiet = ExfiltrationScanner(entropy_scan=False)
    findings = quiet.scan("the ci token is " + token)
    assert findings and any("GitLab" in f.message for f in findings)
    assert all(f.scanner == "exfiltration" for f in findings)


def test_openai_project_key_flagged_on_output_side():
    # The delegated secrets scanner carries the fix: a project key in a
    # model response flags even with the entropy heuristic off.
    key = "sk-proj-" + "Ab1Cd2Ef3" + "-Gh4Ij5Kl6" + "_Mn7Op8Qr9"
    quiet = ExfiltrationScanner(entropy_scan=False)
    findings = quiet.scan("the key is " + key)
    assert findings and all(f.scanner == "exfiltration" for f in findings)


def test_sub_scanner_findings_carry_exfiltration_name():
    findings = scanner.scan("key is AKIAIOSFODNN7EXAMPLE ok")
    assert findings
    assert all(f.scanner == "exfiltration" for f in findings)


def test_extra_patterns():
    custom = ExfiltrationScanner(extra_patterns=[("Acme key", r"\bacme_[A-Za-z0-9]{16}\b", 0.9)])
    assert custom.scan("rotated acme_abcdefghijklmnop today")
    assert scanner.scan("rotated acme_abcdefghijklmnop today") == []


def test_entropy_scan_can_be_disabled():
    blob = "here 9f8e7d6c5b4a39281736455443322110fedcba987654 end"
    assert ExfiltrationScanner().scan(blob)
    assert ExfiltrationScanner(entropy_scan=False).scan(blob) == []


def test_digitalocean_token_flagged_on_output_side():
    # The delegated secrets scanner carries the new formats: a
    # DigitalOcean token in a model response flags even with the
    # entropy heuristic off.
    token = (
        "dop_v1_"
        + "9f8e7d6c5b4a3928"
        + "1736455443322110"
        + "fedcba9876543210"
        + "0011223344556677"
    )
    quiet = ExfiltrationScanner(entropy_scan=False)
    findings = quiet.scan("the deploy token is " + token)
    assert findings and any("DigitalOcean" in f.message for f in findings)
    assert all(f.scanner == "exfiltration" for f in findings)
