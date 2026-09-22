"""Tests for PIIScanner, incl. Luhn edge cases."""

from llm_sentinel.scanners import PIIScanner, luhn_valid

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


def test_credit_card_luhn_valid():
    findings = scanner.scan("Charged 4111111111111111 twice.")
    assert findings
    assert "Luhn" in findings[0].message


def test_credit_card_with_spaces():
    assert scanner.scan("Card 5500 0000 0000 0004 expired.")


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
