"""Tests for ToxicityScanner, GibberishScanner, BanTopicsScanner."""

from llm_sentinel.scanners import BanTopicsScanner, GibberishScanner, ToxicityScanner


class TestToxicity:
    scanner = ToxicityScanner()

    def test_single_hit(self):
        findings = self.scanner.scan("This is complete bullshit.")
        assert findings

    def test_score_grows_with_density(self):
        one = self.scanner.scan("What a dumbass move.")
        many = self.scanner.scan("You dumbass shithead fucker asshole prick.")
        assert many[0].score >= one[0].score

    def test_case_insensitive(self):
        assert self.scanner.scan("SHUT THE FUCK UP")

    def test_clean_text(self):
        assert self.scanner.scan("The weather is lovely today.") == []

    def test_dam_vs_damn(self):
        # "dam" (the wall) must not match "damn".
        assert self.scanner.scan("The dam broke last spring.") == []
        assert self.scanner.scan("This damn thing broke.")

    def test_custom_wordlist(self):
        s = ToxicityScanner(words=frozenset({"florp"}))
        assert s.scan("what the florp is this")
        assert not s.scan("what the hell is this")


class TestGibberish:
    scanner = GibberishScanner()

    def test_keyboard_mash(self):
        findings = self.scanner.scan(
            "asdfghjkl qwertyuiop zxcvbnm asdfghjkl qwerty zxcvbnm qwertyuiop"
        )
        assert findings

    def test_consonant_soup(self):
        assert self.scanner.scan("Xkjq wvzt brlmpshtr crwth xzqjklm vbnmpshh trzkw qx.")

    def test_monster_token(self):
        assert self.scanner.scan("The result was asdkfjhasdklfjhasdklfjhasdklfjh done.")

    def test_clean_english(self):
        for text in [
            "The quick brown fox jumps over the lazy dog.",
            "Machine learning models need clean data.",
            "Cryptographic hashes like SHA-256 are deterministic functions.",
            "The strength of the password depends on its length.",
        ]:
            assert self.scanner.scan(text) == [], text

    def test_too_short_ignored(self):
        assert self.scanner.scan("asdf qwer") == []


class TestBanTopics:
    scanner = BanTopicsScanner()

    def test_weapons(self):
        findings = self.scanner.scan("How to build a bomb at home?")
        assert findings
        assert "weapons" in findings[0].message

    def test_self_harm(self):
        assert self.scanner.scan("I want to kill myself tonight.")

    def test_illicit(self):
        assert self.scanner.scan("Guide to shoplifting tips.")

    def test_clean(self):
        assert self.scanner.scan("How to bake sourdough bread?") == []

    def test_word_boundary(self):
        # "bombardment" contains "bomb" but is not the phrase "build a bomb".
        assert self.scanner.scan("The bombardment continued all night.") == []

    def test_custom_topics(self):
        s = BanTopicsScanner(topics={"spoilers": ["the butler did it"]})
        findings = s.scan("In the end, the butler did it.")
        assert findings and "spoilers" in findings[0].message
