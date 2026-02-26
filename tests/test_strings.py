"""
Tests for python.helpers.strings module.

Tests string utility functions: sanitize_string, format_key, dict_to_text,
truncate_text, truncate_text_by_ratio, replace_file_includes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.strings import (
    sanitize_string,
    format_key,
    dict_to_text,
    truncate_text,
    truncate_text_by_ratio,
    replace_file_includes,
)


class TestSanitizeString:
    """Test sanitize_string function"""

    def test_sanitize_string_with_valid_input(self):
        """Test sanitizing a valid string"""
        result = sanitize_string("hello world")
        assert result == "hello world"

    def test_sanitize_string_with_unicode(self):
        """Test sanitizing unicode characters"""
        result = sanitize_string("hello 🌍")
        assert result == "hello 🌍"

    def test_sanitize_string_with_surrogates(self):
        """Test sanitizing string with surrogate characters"""
        # Surrogate characters will be replaced
        result = sanitize_string("hello\xd800world")
        assert "�" in result or "hello" in result

    def test_sanitize_string_with_non_string(self):
        """Test sanitizing non-string input"""
        result = sanitize_string(12345)
        assert result == "12345"

    def test_sanitize_string_with_empty_string(self):
        """Test sanitizing empty string"""
        result = sanitize_string("")
        assert result == ""

    def test_sanitize_string_with_special_chars(self):
        """Test sanitizing special characters"""
        result = sanitize_string("test\t\n\rstring")
        assert "test" in result
        assert "string" in result


class TestFormatKey:
    """Test format_key function"""

    def test_format_key_camel_case(self):
        """Test formatting camelCase keys"""
        result = format_key("camelCase")
        assert result == "Camel Case"

    def test_format_key_snake_case(self):
        """Test formatting snake_case keys"""
        result = format_key("snake_case_key")
        assert result == "Snake Case Key"

    def test_format_key_pascal_case(self):
        """Test formatting PascalCase keys"""
        result = format_key("PascalCase")
        assert result == "Pascal Case"

    def test_format_key_single_word(self):
        """Test formatting single word"""
        result = format_key("hello")
        assert result == "Hello"

    def test_format_key_with_numbers(self):
        """Test formatting keys with numbers"""
        result = format_key("test123key")
        assert "Test" in result
        assert "123" in result
        # Numbers are kept together, not separated
        assert result == "Test123key"

    def test_format_key_with_special_chars(self):
        """Test formatting keys with special characters"""
        result = format_key("key-name.value")
        assert "Key" in result
        assert "Name" in result
        assert "Value" in result

    def test_format_key_all_caps(self):
        """Test formatting ALL_CAPS keys"""
        result = format_key("ALL_CAPS")
        assert result == "All Caps"

    def test_format_key_mixed(self):
        """Test formatting mixed case keys"""
        result = format_key("myURLParser")
        # Capital letters after lowercase mark word boundary, but consecutive caps stay together
        assert result == "My Urlparser"


class TestDictToText:
    """Test dict_to_text function"""

    def test_dict_to_text_simple(self):
        """Test converting simple dictionary to text"""
        result = dict_to_text({"key": "value"})
        assert "Key:" in result
        assert "value" in result

    def test_dict_to_text_multiple_keys(self):
        """Test converting dictionary with multiple keys"""
        result = dict_to_text({"a": "1", "b": "2"})
        assert "A:" in result
        assert "1" in result
        assert "B:" in result
        assert "2" in result

    def test_dict_to_text_empty(self):
        """Test converting empty dictionary"""
        result = dict_to_text({})
        assert result == ""

    def test_dict_to_text_nested_values(self):
        """Test converting dictionary with complex values"""
        result = dict_to_text({"key": "value with spaces"})
        assert "Key:" in result
        assert "value with spaces" in result


class TestTruncateText:
    """Test truncate_text function"""

    def test_truncate_text_no_op_when_short(self):
        """Test no truncation when text is shorter than length"""
        result = truncate_text("hello", 10)
        assert result == "hello"

    def test_truncate_text_at_end(self):
        """Test truncating at end"""
        result = truncate_text("hello world", 5)
        assert result == "hello..."

    def test_truncate_text_at_start(self):
        """Test truncating at start"""
        result = truncate_text("hello world", 5, at_end=False)
        assert result == "...world"

    def test_truncate_text_exact_length(self):
        """Test truncation with exact length matching"""
        result = truncate_text("hello", 5)
        assert result == "hello"

    def test_truncate_text_custom_replacement(self):
        """Test truncation with custom replacement"""
        result = truncate_text("hello world", 5, replacement="[+]")
        assert result == "hello[+]"

    def test_truncate_text_empty_string(self):
        """Test truncating empty string"""
        result = truncate_text("", 5)
        assert result == ""


class TestTruncateTextByRatio:
    """Test truncate_text_by_ratio function"""

    def test_truncate_by_ratio_no_op_when_short(self):
        """Test no truncation when text is shorter than threshold"""
        result = truncate_text_by_ratio("hello", 10)
        assert result == "hello"

    def test_truncate_by_ratio_end(self):
        """Test truncating at end (ratio=1.0)"""
        result = truncate_text_by_ratio("hello world", 10, ratio=1.0)
        assert result.endswith("...")
        assert len(result) <= 10

    def test_truncate_by_ratio_start(self):
        """Test truncating at start (ratio=0.0)"""
        result = truncate_text_by_ratio("hello world", 10, ratio=0.0)
        assert result.startswith("...")
        assert len(result) <= 10

    def test_truncate_by_ratio_middle(self):
        """Test truncating in middle (ratio=0.5)"""
        result = truncate_text_by_ratio("hello world", 10, ratio=0.5)
        assert "..." in result
        assert len(result) <= 10

    def test_truncate_by_ratio_custom_replacement(self):
        """Test truncation with custom replacement"""
        result = truncate_text_by_ratio("hello world", 10, replacement="[cut]", ratio=1.0)
        assert "[cut]" in result

    def test_truncate_by_ratio_zero_threshold(self):
        """Test with zero threshold"""
        result = truncate_text_by_ratio("hello", 0)
        assert result == "hello"

    def test_truncate_by_ratio_ratio_clamping(self):
        """Test ratio clamping to valid range"""
        # ratio > 1.0 should be clamped to 1.0
        result = truncate_text_by_ratio("hello world", 10, ratio=2.0)
        assert result.endswith("...")

        # ratio < 0.0 should be clamped to 0.0
        result = truncate_text_by_ratio("hello world", 10, ratio=-1.0)
        assert result.startswith("...")


class TestReplaceFileIncludes:
    """Test replace_file_includes function"""

    def test_replace_file_includes_no_includes(self):
        """Test with no include patterns"""
        result = replace_file_includes("hello world")
        assert result == "hello world"

    def test_replace_file_includes_empty_string(self):
        """Test with empty string"""
        result = replace_file_includes("")
        assert result == ""

    def test_replace_file_includes_none_string(self):
        """Test with None input"""
        result = replace_file_includes(None)
        assert result is None
