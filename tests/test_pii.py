"""Tests for PIIScanner, incl. Luhn and SSN structural edge cases."""

from llm_sentinel.scanners import PIIScanner, luhn_valid, ssn_valid

scanner = PIIScanner()


def test_email():
    findings = scanner.scan("Contact jane.doe@example.com today.")
    assert findings and findings[0].score >= 0.9


def test_email_subdomain():
    assert scanner.scan("Mail john_smith123@mail.co.uk now.")


def test_phone_dashes():
    assert scanner.scan("Call 415-555-0132 after six.")


def test_phone_parens():
    assert scanner.scan("Her number is (415) 555-0199.")


def test_phone_country_code():
    assert scanner.scan("Reach us at +1 415-555-0142.")


def test_ssn():
    findings = scanner.scan("SSN 123-45-6789 on file.")
    assert findings and findings[0].score >= 0.9


def _ssn_findings(text):
    return [f for f in scanner.scan(text) if "Social Security" in f.message]


def test_ssn_never_issued_combinations_not_flagged():
    # The SSA never issues area 000, 666, or 900-999, group 00, or
    # serial 0000. These are shaped like SSNs but cannot be real ones,
    # the same false-positive family the Luhn check removes for cards.
    for candidate in (
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "987-65-4320",
        "123-00-6789",
        "123-45-0000",
    ):
        assert _ssn_findings(f"SSN {candidate} on file.") == [], candidate


def test_ssn_valid_shapes_still_flagged():
    # Boundary shapes the structural check must not eat: the smallest
    # valid area/group/serial, the area just under 900, and the two
    # sample SSNs already in the benchmark corpus.
    for candidate in ("001-01-0001", "899-12-3456", "078-05-1120", "219-09-9999"):
        findings = _ssn_findings(f"SSN {candidate} on file.")
        assert len(findings) == 1, candidate
        assert findings[0].matched_text == candidate


def test_ssn_valid_function():
    assert ssn_valid("123-45-6789")
    assert ssn_valid("123456789")
    assert ssn_valid("899-99-9999")
    assert not ssn_valid("000-45-6789")
    assert not ssn_valid("666-45-6789")
    assert not ssn_valid("900-45-6789")
    assert not ssn_valid("123-00-6789")
    assert not ssn_valid("123-45-0000")
    assert not ssn_valid("123-45-678")
    assert not ssn_valid("123-45-67890")
    assert not ssn_valid("not-an-ssn")


def test_credit_card_luhn_valid():
    findings = scanner.scan("Charged 4111111111111111 twice.")
    assert findings
    assert "Luhn" in findings[0].message


def test_credit_card_with_spaces():
    assert scanner.scan("Card 5500 0000 0000 0004 expired.")


def _card_findings(text):
    return [f for f in scanner.scan(text) if "Credit card" in f.message]


def test_card_span_ends_on_last_digit_spaced():
    text = "Card 4111 1111 1111 1111 expired."
    findings = _card_findings(text)
    assert len(findings) == 1
    assert findings[0].matched_text == "4111 1111 1111 1111"
    assert text[findings[0].start : findings[0].end] == findings[0].matched_text
    assert findings[0].end == text.index(" expired")


def test_card_span_ends_on_last_digit_dashed():
    text = "Card 4111-1111-1111-1111- was charged"
    findings = _card_findings(text)
    assert len(findings) == 1
    assert findings[0].matched_text == "4111-1111-1111-1111"


def test_card_span_ends_on_last_digit_contiguous():
    text = "Charged 4111111111111111 twice."
    findings = _card_findings(text)
    assert len(findings) == 1
    assert findings[0].matched_text == "4111111111111111"
    assert text[findings[0].end] == " "


def test_card_span_short_and_amex_lengths():
    for number in ("4222222222222", "378282246310005"):
        text = f"Card {number} on file"
        findings = _card_findings(text)
        assert len(findings) == 1
        assert findings[0].matched_text == number


def test_card_redaction_keeps_following_space():
    from llm_sentinel import Vault

    vault = Vault([PIIScanner()])
    result = vault.scan("Card 4111 1111 1111 1111 expired", redact=True)
    assert result.redacted_text == "Card [REDACTED:PII] expired"


def test_luhn_invalid_number_not_flagged():
    assert scanner.scan("Invoice 4111111111111112 pending.") == []


def test_luhn_function():
    assert luhn_valid("4111111111111111")
    assert luhn_valid("5500000000000004")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("12345")


def test_short_extension_not_phone():
    assert scanner.scan("Call extension 415 for support.") == []


def test_zip_not_phone():
    assert scanner.scan("Zip code 94110.") == []


def test_email_without_tld_not_flagged():
    assert scanner.scan("Mail support@example for help.") == []


def test_plain_text_clean():
    assert scanner.scan("The quarterly report is due Friday.") == []


def test_multiple_pii_all_found():
    findings = scanner.scan("Email jane@example.com, phone 415-555-0132.")
    kinds = {f.message for f in findings}
    assert any("Email" in k for k in kinds)
    assert any("phone" in k for k in kinds)
