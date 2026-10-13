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


def test_fullwidth_run_flags():
    # "ignore this" written with fullwidth letters (U+FF49 and friends).
    text = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in "ignore this payload")
    findings = scanner.scan(text)
    assert any("Fullwidth" in f.message for f in findings)


def test_short_fullwidth_run_does_not_flag():
    # Two fullwidth characters are below the run length on purpose: a
    # single fullwidth punctuation mark in CJK text is not evasion.
    text = "status" + chr(0xFF01) + chr(0xFF01) + " ok"
    assert not any("Fullwidth" in f.message for f in scanner.scan(text))


def test_custom_fullwidth_length():
    strict = ObfuscationScanner(fullwidth_min_length=2)
    text = "a" + chr(0xFF41) + chr(0xFF42) + " b"
    assert any("Fullwidth" in f.message for f in strict.scan(text))


def test_mixed_script_word_flags_when_document_tripwire_misses():
    # Heavily swapped text: so few Latin letters survive that the
    # document-level latin >= 10 tripwire never holds, but single words
    # still mix two or more lookalikes with Latin letters.
    word = chr(0x0455) + chr(0x0435) + chr(0x03B7) + "d"  # lookalikes + Latin d
    findings = scanner.scan(f"{word} ok")
    assert any("Mixed-script word" in f.message for f in findings)


def test_mixed_script_word_two_lookalikes_minimum():
    # One lookalike in a word stays below the per-word tripwire too, same
    # reasoning as test_single_foreign_char_does_not_flag.
    word = chr(0x0430) + "dmin"
    findings = scanner.scan(f"send to {word} today")
    assert not any("Mixed-script" in f.message for f in findings)


def test_pure_foreign_word_does_not_flag_as_mixed_word():
    # A word written entirely in Cyrillic is foreign text, not a
    # homoglyph mix, even with several Cyrillic letters.
    word = chr(0x043F) + chr(0x0440) + chr(0x0438) + chr(0x0432) + chr(0x0435) + chr(0x0442)
    findings = scanner.scan(f"greeting {word} friend")
    assert not any("Mixed-script word" in f.message for f in findings)


def test_fullwidth_literal_escape_flags_via_folded_copy():
    # The escape written in fullwidth: backslash, u, and digits are all
    # fullwidth forms, so the raw escape pattern cannot see it.
    raw = "run \\u0041\\u0042 now"
    text = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in raw)
    findings = scanner.scan(text)
    escapes = [f for f in findings if "unicode escape" in f.message]
    assert escapes
    # The folded finding span must point at the original fullwidth text.
    assert escapes[0].matched_text in text


def test_homoglyph_literal_escape_flags_via_folded_copy():
    # Greek upsilon (U+03C5) stands in for the "u" in the escape.
    text = "run \\" + chr(0x03C5) + "0041 now"
    findings = scanner.scan(text)
    assert any("unicode escape" in f.message for f in findings)


def test_raw_literal_escape_not_double_reported_by_folded_copy():
    findings = scanner.scan("run \\u0041\\u0042 now")
    escapes = [f for f in findings if "unicode escape" in f.message]
    assert len(escapes) == 2


def test_fullwidth_blob_flags():
    blob = "aB3xK9mQ2vL7pR4tY8wZ1cN6bV5dF0gHj=" * 2
    text = "payload: " + "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in blob)
    findings = scanner.scan(text)
    assert any("Fullwidth" in f.message or "encoded payload" in f.message for f in findings)


def test_homoglyph_blob_flags_via_folded_copy():
    from llm_sentinel.adversarial import homoglyph_swap

    blob = "aB3xK9mQ2vL7pR4tY8wZ1cN6bV5dF0gHj=" * 2
    findings = scanner.scan("payload: " + homoglyph_swap(blob))
    assert any("encoded payload" in f.message for f in findings)
