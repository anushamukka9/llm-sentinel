"""Tests for ObfuscationScanner: invisible chars, bidi, mixed scripts, blobs."""

from llm_sentinel.scanners import ObfuscationScanner

scanner = ObfuscationScanner()
ZW = chr(0x200B)
BIDI = chr(0x202E)


def test_zero_width_char_flags():
    findings = scanner.scan(f"pay{ZW}pal the invoice")
    assert any("Zero-width" in f.message for f in findings)


def test_zero_width_joiner_flags():
    findings = scanner.scan(f"hello{chr(0x200D)}world")
    assert any("Zero-width" in f.message for f in findings)


def test_bidi_override_flags_once():
    findings = scanner.scan(f"click {BIDI}here")
    bidi = [f for f in findings if "direction override" in f.message]
    assert len(bidi) == 1
    assert not any("Stray control" in f.message for f in findings)


def test_stray_control_char_flags():
    findings = scanner.scan("total" + chr(0x07) + "due")
    assert any("Stray control" in f.message for f in findings)


def test_literal_unicode_escapes_flag():
    findings = scanner.scan("run \\u0041\\u0042 now")
    assert any("unicode escape" in f.message for f in findings)


def test_mixed_script_run_flags():
    text = "send to " + chr(0x0430) + "dmin@ex" + chr(0x0430) + "mple.com today please"
    findings = scanner.scan(text)
    assert any("Mixed-script" in f.message for f in findings)


def test_single_foreign_char_does_not_flag():
    # One Cyrillic letter in Latin text is below the tripwire on purpose.
    findings = scanner.scan("send to " + chr(0x0430) + "dmin today please sir")
    assert not any("Mixed-script" in f.message for f in findings)


def test_long_high_entropy_blob_flags():
    findings = scanner.scan("payload: " + "aB3xK9mQ2vL7pR4tY8wZ1cN6bV5dF0gHj=" * 2)
    assert any("encoded payload" in f.message for f in findings)


def test_short_or_low_entropy_run_does_not_flag():
    findings = scanner.scan("The total is 42 dollars for the invoice dated Monday.")
    assert findings == []


def test_clean_ascii_passes():
    assert scanner.scan("The meeting is at 3pm in room 402.") == []


def test_accented_latin_passes():
    # Accented Latin (U+00E9) is not a confusable-script signal.
    assert scanner.scan("The café was excellent.") == []


def test_custom_blob_length():
    strict = ObfuscationScanner(blob_min_length=10, min_entropy=3.0)
    assert any("encoded payload" in f.message for f in strict.scan("token aB3xK9mQ2vL7 end"))
