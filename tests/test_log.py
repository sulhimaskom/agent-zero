"""Tests for log.py utility functions.

Tests the truncate functions that are pure and don't depend on external state.
"""

import pytest

from python.helpers import log


class TestTruncateHeading:
    """Test _truncate_heading function."""

    def test_truncate_heading_returns_string(self):
        """Test that _truncate_heading returns a string."""
        result = log._truncate_heading("test heading")
        assert isinstance(result, str)

    def test_truncate_heading_none_returns_empty(self):
        """Test that None input returns empty string."""
        result = log._truncate_heading(None)
        assert result == ""

    def test_truncate_heading_short_string_unchanged(self):
        """Test that short strings are not modified."""
        short = "short"
        result = log._truncate_heading(short)
        assert result == short

    def test_truncate_heading_long_string_truncated(self):
        """Test that long strings are truncated."""
        # Create a string longer than HEADING_MAX_LEN
        long = "x" * (log.HEADING_MAX_LEN + 100)
        result = log._truncate_heading(long)
        assert len(result) <= log.HEADING_MAX_LEN
        assert result.endswith("...")

    def test_truncate_heading_exactly_max_len(self):
        """Test string at exactly max length."""
        exact = "x" * log.HEADING_MAX_LEN
        result = log._truncate_heading(exact)
        assert len(result) == log.HEADING_MAX_LEN


class TestTruncateProgress:
    """Test _truncate_progress function."""

    def test_truncate_progress_returns_string(self):
        """Test that _truncate_progress returns a string."""
        result = log._truncate_progress("test progress")
        assert isinstance(result, str)

    def test_truncate_progress_none_returns_empty(self):
        """Test that None input returns empty string."""
        result = log._truncate_progress(None)
        assert result == ""

    def test_truncate_progress_short_string_unchanged(self):
        """Test that short strings are not modified."""
        short = "short"
        result = log._truncate_progress(short)
        assert result == short

    def test_truncate_progress_long_string_truncated(self):
        """Test that long strings are truncated."""
        long = "x" * (log.PROGRESS_MAX_LEN + 100)
        result = log._truncate_progress(long)
        assert len(result) <= log.PROGRESS_MAX_LEN
        assert result.endswith("...")


class TestTruncateKey:
    """Test _truncate_key function."""

    def test_truncate_key_returns_string(self):
        """Test that _truncate_key returns a string."""
        result = log._truncate_key("test_key")
        assert isinstance(result, str)

    def test_truncate_key_short_key_unchanged(self):
        """Test that short keys are not modified."""
        short = "key"
        result = log._truncate_key(short)
        assert result == short

    def test_truncate_key_long_key_truncated(self):
        """Test that long keys are truncated."""
        long = "x" * (log.KEY_MAX_LEN + 100)
        result = log._truncate_key(long)
        assert len(result) <= log.KEY_MAX_LEN
        assert result.endswith("...")


class TestTruncateValue:
    """Test _truncate_value function."""

    def test_truncate_value_string_unchanged(self):
        """Test that short strings are not modified."""
        short = "short value"
        result = log._truncate_value(short)
        assert result == short

    def test_truncate_value_long_string_truncated(self):
        """Test that long strings are truncated."""
        long = "x" * (log.VALUE_MAX_LEN + 100)
        result = log._truncate_value(long)
        assert isinstance(result, str)
        assert len(result) <= log.VALUE_MAX_LEN
        assert "Characters hidden" in result

    def test_truncate_value_dict_unchanged(self):
        """Test that small dicts are not modified."""
        small = {"key": "value"}
        result = log._truncate_value(small)
        assert result == small

    def test_truncate_value_dict_long_values_truncated(self):
        """Test that long values in dict are truncated."""
        long_value = "x" * (log.VALUE_MAX_LEN + 100)
        data = {"key": long_value}
        result = log._truncate_value(data)
        assert isinstance(result, dict)
        # The value should be truncated
        assert len(result["key"]) <= log.VALUE_MAX_LEN
        assert "Characters hidden" in result["key"]

    def test_truncate_value_dict_nested_truncation(self):
        """Test that nested dict values are truncated."""
        long_value = "x" * (log.VALUE_MAX_LEN + 100)
        data = {"outer": {"inner": long_value}}
        result = log._truncate_value(data)
        assert isinstance(result, dict)
        assert isinstance(result["outer"], dict)
        assert len(result["outer"]["inner"]) <= log.VALUE_MAX_LEN

    def test_truncate_value_list_unchanged(self):
        """Test that small lists are not modified."""
        small = ["a", "b", "c"]
        result = log._truncate_value(small)
        assert result == small

    def test_truncate_value_list_long_items_truncated(self):
        """Test that long items in list are truncated."""
        long_item = "x" * (log.VALUE_MAX_LEN + 100)
        data = [long_item]
        result = log._truncate_value(data)
        assert isinstance(result, list)
        assert len(result[0]) <= log.VALUE_MAX_LEN

    def test_truncate_value_tuple_unchanged(self):
        """Test that small tuples are not modified."""
        small = ("a", "b", "c")
        result = log._truncate_value(small)
        assert result == small

    def test_truncate_value_tuple_long_items_truncated(self):
        """Test that long items in tuple are truncated."""
        long_item = "x" * (log.VALUE_MAX_LEN + 100)
        data = (long_item,)
        result = log._truncate_value(data)
        assert isinstance(result, tuple)
        assert len(result[0]) <= log.VALUE_MAX_LEN


class TestTruncateContent:
    """Test _truncate_content function."""

    def test_truncate_content_returns_string(self):
        """Test that _truncate_content returns a string."""
        result = log._truncate_content("test content", "info")
        assert isinstance(result, str)

    def test_truncate_content_none_returns_empty(self):
        """Test that None input returns empty string."""
        result = log._truncate_content(None, "info")
        assert result == ""

    def test_truncate_content_short_string_unchanged(self):
        """Test that short strings are not modified."""
        short = "short content"
        result = log._truncate_content(short, "info")
        assert result == short

    def test_truncate_content_long_string_truncated(self):
        """Test that long strings are truncated."""
        long = "x" * (log.CONTENT_MAX_LEN + 100)
        result = log._truncate_content(long, "info")
        assert isinstance(result, str)
        # Should be truncated
        assert "Characters hidden" in result

    def test_truncate_content_response_type_uses_different_limit(self):
        """Test that response type uses RESPONSE_CONTENT_MAX_LEN."""
        long = "x" * (log.RESPONSE_CONTENT_MAX_LEN + 100)
        result = log._truncate_content(long, "response")
        assert isinstance(result, str)
        # Should be truncated
        assert "Characters hidden" in result

    def test_truncate_content_different_types(self):
        """Test truncation works with different log types."""
        long = "x" * (log.CONTENT_MAX_LEN + 100)
        for log_type in ["agent", "browser", "code_exe", "error", "hint", "info", "progress", "tool", "input", "user", "util", "warning"]:
            result = log._truncate_content(long, log_type)
            assert isinstance(result, str)
            # Should contain hidden message to show truncation happened
            assert "Characters hidden" in result


class TestConstants:
    """Test that constants are properly defined."""

    def test_heading_max_len_is_positive(self):
        """Test that HEADING_MAX_LEN is a positive integer."""
        assert log.HEADING_MAX_LEN > 0
        assert isinstance(log.HEADING_MAX_LEN, int)

    def test_content_max_len_is_positive(self):
        """Test that CONTENT_MAX_LEN is a positive integer."""
        assert log.CONTENT_MAX_LEN > 0
        assert isinstance(log.CONTENT_MAX_LEN, int)

    def test_response_content_max_len_is_positive(self):
        """Test that RESPONSE_CONTENT_MAX_LEN is a positive integer."""
        assert log.RESPONSE_CONTENT_MAX_LEN > 0
        assert isinstance(log.RESPONSE_CONTENT_MAX_LEN, int)

    def test_key_max_len_is_positive(self):
        """Test that KEY_MAX_LEN is a positive integer."""
        assert log.KEY_MAX_LEN > 0
        assert isinstance(log.KEY_MAX_LEN, int)

    def test_value_max_len_is_positive(self):
        """Test that VALUE_MAX_LEN is a positive integer."""
        assert log.VALUE_MAX_LEN > 0
        assert isinstance(log.VALUE_MAX_LEN, int)

    def test_progress_max_len_is_positive(self):
        """Test that PROGRESS_MAX_LEN is a positive integer."""
        assert log.PROGRESS_MAX_LEN > 0
        assert isinstance(log.PROGRESS_MAX_LEN, int)

    def test_response_max_len_greater_than_content(self):
        """Test that RESPONSE_CONTENT_MAX_LEN > CONTENT_MAX_LEN."""
        # Response content allows for longer output
        assert log.RESPONSE_CONTENT_MAX_LEN > log.CONTENT_MAX_LEN
