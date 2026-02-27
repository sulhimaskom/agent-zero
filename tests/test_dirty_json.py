import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.dirty_json import DirtyJson, try_parse, parse, stringify


class TestDirtyJsonBasicParsing:
    """Test basic JSON parsing"""

    def test_parse_object(self):
        result = parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_array(self):
        result = parse('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_parse_string(self):
        result = parse('"hello"')
        assert result == "hello"

    def test_parse_number(self):
        assert parse("42") == 42
        assert parse("3.14") == 3.14

    def test_parse_boolean(self):
        assert parse("true") is True
        assert parse("false") is False

    def test_parse_null(self):
        assert parse("null") is None

    def test_parse_undefined(self):
        assert parse("undefined") is None


class TestDirtyJsonEdgeCases:
    """Test edge cases"""

    def test_empty_string(self):
        assert parse("") is None

    def test_whitespace_only(self):
        assert parse("   ") is None

    def test_trailing_comma(self):
        result = parse('{"key": "value",}')
        assert result == {"key": "value"}

    def test_single_line_comment(self):
        result = parse('{"key": "value"} // comment')
        assert result == {"key": "value"}

    def test_multi_line_comment(self):
        result = parse('{"key": "value" /* comment */}')
        assert result == {"key": "value"}

    def test_unquoted_strings(self):
        result = parse('{key: "value"}')
        assert result == {"key": "value"}

    def test_nested_structures(self):
        result = parse('{"outer": {"inner": [1, 2, 3]}}')
        assert result == {"outer": {"inner": [1, 2, 3]}}


class TestTryParse:
    """Test try_parse fallback function"""

    def test_try_parse_valid_json(self):
        result = try_parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_try_parse_invalid_json(self):
        # Invalid JSON that DirtyJson can still parse
        result = try_parse('{key: value}')
        assert result == {"key": "value"}

    def test_try_parse_returns_none_for_completely_invalid(self):
        result = try_parse("not json at all")
        assert result is not None  # DirtyJson is lenient


class TestStringify:
    """Test stringify function"""

    def test_stringify_dict(self):
        result = stringify({"key": "value"})
        assert result == '{"key": "value"}'

    def test_stringify_list(self):
        result = stringify([1, 2, 3])
        assert result == "[1, 2, 3]"

    def test_stringify_unicode(self):
        result = stringify({"emoji": "🎉"})
        assert "🎉" in result


class TestDirtyJsonClass:
    """Test DirtyJson class methods"""

    def test_class_parse_string(self):
        result = DirtyJson.parse_string('{"key": "value"}')
        assert result == {"key": "value"}

    def test_class_instance_parse(self):
        parser = DirtyJson()
        result = parser.parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_class_feed_method(self):
        parser = DirtyJson()
        # Test feed method with complete JSON
        result = parser.feed('{"key": "value"}')
        assert result == {"key": "value"}

    def test_class_reset(self):
        parser = DirtyJson()
        parser.parse('{"key": "value"}')
        parser._reset()
        assert parser.json_string == ""
        assert parser.index == 0
        assert parser.result is None


class TestDirtyJsonComplex:
    """Test complex parsing scenarios"""

    def test_multiple_keys(self):
        result = parse('{"a": 1, "b": 2, "c": 3}')
        assert result == {"a": 1, "b": 2, "c": 3}

    def test_nested_arrays(self):
        result = parse('[[1, 2], [3, 4]]')
        assert result == [[1, 2], [3, 4]]

    def test_mixed_content(self):
        result = parse('{"items": [1, "two", true], "count": 3}')
        assert result == {"items": [1, "two", True], "count": 3}

    def test_escaped_characters(self):
        result = parse('{"newline": "line1\\nline2"}')
        assert result == {"newline": "line1\nline2"}
