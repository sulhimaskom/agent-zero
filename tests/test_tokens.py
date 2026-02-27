"""Tests for token counting utilities.

Tests the token counting, approximation, and trimming functions.
"""

from python.helpers.tokens import (
    approximate_tokens,
    count_tokens,
    trim_to_tokens,
)


class TestCountTokens:
    """Test count_tokens function"""

    def test_empty_string(self):
        """Test empty string returns 0 tokens"""
        result = count_tokens("")
        assert result == 0

    def test_simple_text(self):
        """Test simple text returns expected token count"""
        result = count_tokens("hello world")
        assert result == 2

    def test_longer_text(self):
        """Test longer text token counting"""
        text = "The quick brown fox jumps over the lazy dog"
        result = count_tokens(text)
        assert result > 0

    def test_special_characters(self):
        """Test special characters are counted"""
        result = count_tokens("hello\n\tworld!")
        assert result >= 2


class TestApproximateTokens:
    """Test approximate_tokens function"""

    def test_empty_string(self):
        """Test empty string returns 0"""
        result = approximate_tokens("")
        assert result == 0

    def test_simple_text(self):
        """Test approximation includes buffer"""
        text = "hello world"
        approx = approximate_tokens(text)
        exact = count_tokens(text)
        # Approximate should be >= exact (buffer adds overhead)
        assert approx >= exact

    def test_buffer_consistency(self):
        """Test buffer is applied consistently"""
        text = "testing token approximation buffer"
        result = approximate_tokens(text)
        assert isinstance(result, int)


class TestTrimToTokens:
    """Test trim_to_tokens function"""

    def test_text_under_limit(self):
        """Test text under max_tokens returns unchanged"""
        text = "short"
        result = trim_to_tokens(text, max_tokens=100, direction="start")
        assert result == text

    def test_trim_from_start(self):
        """Test trimming from start keeps beginning, adds ellipsis at end"""
        text = "This is a very long string that should be trimmed"
        result = trim_to_tokens(text, max_tokens=5, direction="start")
        # direction="start" keeps the start of text, adds ellipsis at end
        assert result.endswith("...")
        assert result.startswith("This")

    def test_trim_from_end(self):
        """Test trimming from end keeps end, adds ellipsis at start"""
        text = "This is a very long string that should be trimmed"
        result = trim_to_tokens(text, max_tokens=5, direction="end")
        # direction="end" keeps the end of text, adds ellipsis at start
        assert result.startswith("...")
        assert result.endswith("trimmed")

    def test_custom_ellipsis(self):
        """Test custom ellipsis character"""
        text = "This is a very long string that should be trimmed"
        result = trim_to_tokens(
            text, max_tokens=5, direction="start", ellipsis="***"
        )
        # direction="start" keeps start, adds ellipsis at end
        assert result.endswith("***")
        assert result.startswith("This")


class TestTokenIntegration:
    """Integration tests for token functions"""

    def test_count_approximate_trim_flow(self):
        """Test full flow: count -> approximate -> trim"""
        original = "The quick brown fox jumps over the lazy dog"
        max_tokens = 5

        # Should be able to count and trim
        token_count = count_tokens(original)
        approx = approximate_tokens(original)
        trimmed = trim_to_tokens(original, max_tokens=max_tokens, direction="start")

        assert token_count > 0
        assert approx >= token_count
        # Trimmed should have ellipsis since original is long
        assert "..." in trimmed or len(trimmed) >= len(original) - 5
