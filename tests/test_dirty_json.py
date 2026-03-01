import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.dirty_json import DirtyJson, parse, stringify, try_parse


class TestBasicParsing:
    """Test basic JSON parsing - objects, arrays, strings, numbers, booleans, null"""

    def test_parse_empty_object(self):
        result = parse("{}")
        assert result == {}

    def test_parse_object_with_single_key(self):
        result = parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_object_with_multiple_keys(self):
        result = parse('{"name": "test", "count": 42, "active": true}')
        assert result == {"name": "test", "count": 42, "active": True}

    def test_parse_empty_array(self):
        result = parse("[]")
        assert result == []

    def test_parse_array_with_values(self):
        result = parse('[1, 2, 3, "four", true]')
        assert result == [1, 2, 3, "four", True]

    def test_parse_string(self):
        result = parse('"hello world"')
        assert result == "hello world"

    def test_parse_number_integer(self):
        result = parse("42")
        assert result == 42

    def test_parse_number_negative(self):
        result = parse("-17")
        assert result == -17

    def test_parse_number_float(self):
        result = parse("3.14")
        assert result == 3.14

    def test_parse_boolean_true(self):
        result = parse("true")
        assert result is True

    def test_parse_boolean_false(self):
        result = parse("false")
        assert result is False

    def test_parse_null(self):
        result = parse("null")
        assert result is None

    def test_parse_undefined(self):
        result = parse("undefined")
        assert result is None


class TestEdgeCases:
    """Test edge cases - empty strings, malformed JSON, comments"""

    def test_parse_empty_string(self):
        result = parse("")
        assert result is None

    def test_parse_whitespace_only(self):
        result = parse("   ")
        assert result is None

    def test_parse_object_with_trailing_comma(self):
        result = parse('{"key": "value",}')
        assert result == {"key": "value"}

    def test_parse_array_with_trailing_comma(self):
        result = parse('[1, 2, 3,]')
        assert result == [1, 2, 3]

    def test_parse_single_line_comment(self):
        result = parse('{"key": "value"} // this is a comment')
        assert result == {"key": "value"}

    def test_parse_multi_line_comment(self):
        result = parse('{"key": "value"} /* comment */')
        assert result == {"key": "value"}

    def test_parse_unquoted_strings(self):
        result = parse("{key: value}")
        assert result == {"key": "value"}

    def test_parse_nested_objects(self):
        result = parse('{"outer": {"inner": "value"}}')
        assert result == {"outer": {"inner": "value"}}

    def test_parse_nested_arrays(self):
        result = parse('[[1, 2], [3, 4]]')
        assert result == [[1, 2], [3, 4]]

    def test_parse_mixed_nesting(self):
        result = parse('{"array": [1, {"nested": true}], "num": 42}')
        assert result == {"array": [1, {"nested": True}], "num": 42}


class TestTryParse:
    """Test try_parse function that falls back to custom parser"""

    def test_try_parse_valid_json(self):
        result = try_parse('{"valid": true}')
        assert result == {"valid": True}

    def test_try_parse_invalid_json(self):
        # Invalid JSON that dirty parser should handle
        result = try_parse("{key: value}")
        assert result == {"key": "value"}

    def test_try_parse_invalid_json_unclosed(self):
        # Invalid JSON with unclosed brace
        result = try_parse('{"key": "value"')
        assert result == {"key": "value"}


class TestStringify:
    """Test stringify function"""

    def test_stringify_object(self):
        result = stringify({"key": "value"})
        assert '"key": "value"' in result

    def test_stringify_array(self):
        result = stringify([1, 2, 3])
        assert result == "[1, 2, 3]"

    def test_stringify_nested(self):
        result = stringify({"outer": {"inner": [1, 2]}})
        assert "outer" in result
        assert "inner" in result

    def test_stringify_with_kwargs(self):
        result = stringify({"key": "value"}, indent=2)
        assert "key" in result


class TestDirtyJsonClass:
    """Test DirtyJson class directly"""

    def test_dirty_json_parse_string(self):
        result = DirtyJson.parse_string('{"test": true}')
        assert result == {"test": True}

    def test_dirty_json_instance_parse(self):
        parser = DirtyJson()
        result = parser.parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_dirty_json_feed_complete(self):
        parser = DirtyJson()
        # Test feeding complete JSON at once
        result = parser.feed('{"key": "value"}')
        assert result == {"key": "value"}

    def test_dirty_json_feed_incremental(self):
        parser = DirtyJson()
        # Test feeding valid JSON in valid chunks
        result = parser.feed('{"key": "value"')  # Incomplete but wont error
        # feed() with incomplete valid start
        assert result is None or isinstance(result, dict)

    def test_dirty_json_get_start_pos(self):
        parser = DirtyJson()
        assert parser.get_start_pos('{"key": "value"}') == 0
        assert parser.get_start_pos('  {"key": "value"}') == 2
        assert parser.get_start_pos('   [1,2,3]') == 3
