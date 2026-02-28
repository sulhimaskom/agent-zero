from python.helpers.strings import (
    dict_to_text,
    format_key,
    sanitize_string,
    truncate_text,
    truncate_text_by_ratio,
)


class TestSanitizeString:
    """Test sanitize_string function"""

    def test_basic_string(self):
        """Test sanitizing a normal string returns unchanged"""
        result = sanitize_string("hello world")
        assert result == "hello world"

    def test_with_unicode(self):
        """Test sanitizing string with unicode characters"""
        result = sanitize_string("hello \u0000world")
        assert "hello" in result
        assert "world" in result

    def test_with_surrogates(self):
        """Test handling of surrogate characters"""
        # Surrogate pair
        result = sanitize_string("test\ud800test")
        assert "test" in result

    def test_non_string_input(self):
        """Test converting non-string to string"""
        result = sanitize_string(123)
        assert result == "123"

    def test_empty_string(self):
        """Test empty string returns empty"""
        result = sanitize_string("")
        assert result == ""

    def test_with_invalid_encoding(self):
        """Test with custom encoding"""
        result = sanitize_string("test", encoding="ascii")
        assert result == "test"

    def test_with_emoji(self):
        """Test handling of emoji characters"""
        result = sanitize_string("hello 😀 world")
        assert "hello" in result
        assert "world" in result


class TestFormatKey:
    """Test format_key function"""

    def test_camel_case(self):
        """Test converting camelCase to Title Case"""
        result = format_key("camelCase")
        assert result == "Camel Case"

    def test_snake_case(self):
        """Test converting snake_case to Title Case"""
        result = format_key("snake_case")
        assert result == "Snake Case"

    def test_plain_word(self):
        """Test plain word is capitalized"""
        result = format_key("hello")
        assert result == "Hello"

    def test_mixed_case(self):
        """Test mixed case input"""
        result = format_key("myTestKey")
        assert result == "My Test Key"

    def test_multiple_underscores(self):
        """Test multiple underscores"""
        result = format_key("key_one_two")
        assert result == "Key One Two"

    def test_already_title_case(self):
        """Test input that's already Title Case"""
        result = format_key("Already Title")
        assert result == "Already Title"

    def test_with_numbers(self):
        """Test key with numbers"""
        result = format_key("key123")
        assert result == "Key123"

    def test_empty_string(self):
        """Test empty string returns empty"""
        result = format_key("")
        assert result == ""


class TestDictToText:
    """Test dict_to_text function"""

    def test_simple_dict(self):
        """Test converting simple dictionary to text"""
        result = dict_to_text({"name": "John", "age": "30"})
        assert "Name:" in result
        assert "John" in result
        assert "Age:" in result
        assert "30" in result

    def test_single_key(self):
        """Test dictionary with single key"""
        result = dict_to_text({"key": "value"})
        assert "Key:" in result
        assert "value" in result

    def test_empty_dict(self):
        """Test empty dictionary returns empty"""
        result = dict_to_text({})
        assert result == ""

    def test_nested_dict_as_string(self):
        """Test nested dict converted to string"""
        result = dict_to_text({"nested": {"key": "value"}})
        assert "Nested:" in result

    def test_numeric_values(self):
        """Test dictionary with numeric values"""
        result = dict_to_text({"count": 42})
        assert "Count:" in result
        assert "42" in result

    def test_boolean_values(self):
        """Test dictionary with boolean values"""
        result = dict_to_text({"active": True})
        assert "Active:" in result
        assert "True" in result


class TestTruncateText:
    """Test truncate_text function"""

    def test_text_shorter_than_length(self):
        """Test text shorter than max length returns unchanged"""
        result = truncate_text("hello", 10)
        assert result == "hello"

    def test_text_equal_to_length(self):
        """Test text equal to max length returns unchanged"""
        result = truncate_text("hello", 5)
        assert result == "hello"

    def test_truncate_at_end(self):
        """Test truncating at end with default replacement"""
        result = truncate_text("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8

    def test_truncate_at_beginning(self):
        """Test truncating at beginning"""
        result = truncate_text("hello world", 8, at_end=False)
        assert result == "...world"
        assert len(result) == 8

    def test_custom_replacement(self):
        """Test with custom replacement string"""
        result = truncate_text("hello world", 8, replacement="...")
        assert result == "hello..."

    def test_zero_length(self):
        """Test zero max length returns only replacement"""
        result = truncate_text("hello", 0)
        assert len(result) == 3  # Just the replacement

    def test_length_one(self):
        """Test length of 1"""
        result = truncate_text("hello", 1)
        assert len(result) == 1


class TestTruncateTextByRatio:
    """Test truncate_text_by_ratio function"""

    def test_text_shorter_than_threshold(self):
        """Test text shorter than threshold returns unchanged"""
        result = truncate_text_by_ratio("hello", 10)
        assert result == "hello"

    def test_threshold_zero(self):
        """Test zero threshold returns original text"""
        result = truncate_text_by_ratio("hello", 0)
        assert result == "hello"

    def test_ratio_zero(self):
        """Test ratio 0 replaces at start"""
        result = truncate_text_by_ratio("hello world", 10, ratio=0.0)
        # Should replace from start
        assert "..." in result
        assert len(result) == 10

    def test_ratio_one(self):
        """Test ratio 1 replaces at end"""
        result = truncate_text_by_ratio("hello world", 10, ratio=1.0)
        # Should replace from end
        assert "..." in result
        assert len(result) == 10

    def test_ratio_half(self):
        """Test ratio 0.5 replaces in middle"""
        result = truncate_text_by_ratio("hello world", 10, ratio=0.5)
        assert "..." in result
        assert len(result) == 10

    def test_custom_replacement(self):
        """Test with custom replacement"""
        result = truncate_text_by_ratio("hello world", 10, replacement=">>>")
        assert ">>>" in result
        assert len(result) == 10

    def test_ratio_out_of_bounds_clamped(self):
        """Test ratio outside 0-1 is clamped"""
        result_high = truncate_text_by_ratio("hello world", 10, ratio=2.0)
        result_low = truncate_text_by_ratio("hello world", 10, ratio=-1.0)
        # Both should be clamped
        assert "..." in result_high
        assert "..." in result_low
