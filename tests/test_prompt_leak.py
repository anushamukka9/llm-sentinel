"""Tests for PromptLeakScanner: output-side disclosure of instructions."""

from llm_sentinel.scanners import PromptLeakScanner

scanner = PromptLeakScanner()


def test_offers_up_system_prompt():
    findings = scanner.scan("Sure, here is my system prompt: you are helpful.")
    assert findings
    assert all(f.score >= 0.9 for f in findings)


def test_quotes_own_instructions():
    findings = scanner.scan("According to my instructions, I cannot help with that.")
    assert findings


def test_states_own_instructions():
    findings = scanner.scan("My system instructions are to be concise.")
    assert findings


def test_discloses_being_instructed():
    findings = scanner.scan("I was instructed to refuse harmful requests.")
    assert findings


def test_reveals_developer_message():
    findings = scanner.scan("The developer message says to greet every user.")
    assert findings


def test_discussing_system_prompts_in_abstract_passes():
    assert scanner.scan("The user asked about the system prompt feature.") == []


def test_following_user_instructions_passes():
    assert scanner.scan("I will follow your instructions carefully.") == []


def test_developer_documentation_passes():
    assert scanner.scan("The developer documentation is available online.") == []


def test_plain_output_passes():
    assert scanner.scan("Here is a summary of the meeting notes.") == []


def test_custom_patterns():
    custom = PromptLeakScanner(patterns=[])
    assert custom.scan("Here is my system prompt: hello.") == []
