import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.extract_tools import (
    extract_json_object_string,
    fix_json_string,
    json_parse_dirty,
)


class TestExtractJsonObjectString:
    """Test extract_json_object_string function - extracts JSON object from string."""

    def test_extract_simple_object(self):
        result = extract_json_object_string('{"key": "value"}')
        assert result == '{"key": "value"}'

    def test_extract_object_with_text_before(self):
        result = extract_json_object_string('some text {"key": "value"} after')
        assert result == '{"key": "value"}'

    def test_extract_object_with_text_after(self):
        result = extract_json_object_string('{"key": "value"} some text after')
        assert result == '{"key": "value"}'

    def test_extract_nested_object(self):
        result = extract_json_object_string('{"outer": {"inner": 42}}')
        assert result == '{"outer": {"inner": 42}}'

    def test_extract_object_with_array(self):
        result = extract_json_object_string('{"items": [1, 2, 3]}')
        assert result == '{"items": [1, 2, 3]}'

    def test_no_opening_brace(self):
        # Returns empty string when no opening brace found
        result = extract_json_object_string('no json here')
        assert result == ''

    def test_no_closing_brace(self):
        result = extract_json_object_string('{"key": "value"')
        assert result == '{"key": "value"'

    def test_empty_input(self):
        result = extract_json_object_string('')
        assert result == ''

    def test_only_braces(self):
        result = extract_json_object_string('{}')
        assert result == '{}'


class TestFixJsonString:
    """Test fix_json_string function - fixes unescaped newlines in JSON."""

    def test_fix_simple_string(self):
        result = fix_json_string('{"key": "value"}')
        assert result == '{"key": "value"}'

    def test_fix_string_with_newline_in_value(self):
        result = fix_json_string('{"key": "line1\nline2"}')
        assert result == '{"key": "line1\\nline2"}'

    def test_fix_multiple_newlines(self):
        result = fix_json_string('{"text": "a\nb\nc"}')
        assert result == '{"text": "a\\nb\\nc"}'

    def test_fix_empty_value(self):
        result = fix_json_string('{"key": ""}')
        assert result == '{"key": ""}'

    def test_fix_already_escaped(self):
        result = fix_json_string('{"key": "line1\\nline2"}')
        assert result == '{"key": "line1\\nline2"}'


class TestJsonParseDirty:
    """Test json_parse_dirty function - parses dirty JSON."""

    def test_parse_valid_json(self):
        result = json_parse_dirty('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_with_whitespace(self):
        result = json_parse_dirty('  {"key": "value"}  ')
        assert result == {"key": "value"}

    def test_parse_dirty_json_with_text_before(self):
        result = json_parse_dirty('some text {"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_dirty_json_with_text_after(self):
        result = json_parse_dirty('{"key": "value"} some text after')
        assert result == {"key": "value"}

    def test_parse_nested_object(self):
        result = json_parse_dirty('{"outer": {"inner": 42}}')
        assert result == {"outer": {"inner": 42}}

    def test_parse_invalid_json_returns_none(self):
        result = json_parse_dirty('not json at all')
        assert result is None

    def test_parse_empty_string(self):
        result = json_parse_dirty('')
        assert result is None

    def test_parse_none_returns_none(self):
        result = json_parse_dirty(None)
        assert result is None

    def test_parse_object_with_special_chars(self):
        result = json_parse_dirty('{"name": "John Doe", "age": 30}')
        assert result == {"name": "John Doe", "age": 30}

    def test_parse_object_with_unicode(self):
        result = json_parse_dirty('{"emoji": "🎉", "japanese": "日本語"}')
        assert result == {"emoji": "🎉", "japanese": "日本語"}

    def test_parse_object_with_boolean_and_null(self):
        result = json_parse_dirty('{"active": true, "deleted": false, "meta": null}')
        assert result == {"active": True, "deleted": False, "meta": None}
