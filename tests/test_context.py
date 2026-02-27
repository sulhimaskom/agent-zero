import pytest

from python.helpers.context import (
    clear_context_data,
    delete_context_data,
    get_context_data,
    set_context_data,
)


class TestContextData:
    """Test context data functions"""

    def setup_method(self):
        """Clear context before each test"""
        clear_context_data()

    def teardown_method(self):
        """Clear context after each test"""
        clear_context_data()

    def test_set_and_get_string_value(self):
        """Test setting and retrieving a string value"""
        set_context_data("name", "test_value")
        result = get_context_data("name")
        assert result == "test_value"

    def test_set_and_get_integer_value(self):
        """Test setting and retrieving an integer value"""
        set_context_data("count", 42)
        result = get_context_data("count")
        assert result == 42

    def test_set_and_get_list_value(self):
        """Test setting and retrieving a list value"""
        test_list = [1, 2, 3]
        set_context_data("items", test_list)
        result = get_context_data("items")
        assert result == test_list

    def test_get_nonexistent_key_returns_default(self):
        """Test that getting a nonexistent key returns the default value"""
        result = get_context_data("nonexistent", default="default_value")
        assert result == "default_value"

    def test_get_nonexistent_key_with_none_default(self):
        """Test that getting a nonexistent key with None default returns None"""
        result = get_context_data("nonexistent", default=None)
        assert result is None

    def test_get_all_context_data(self):
        """Test getting all context data when key is None"""
        set_context_data("key1", "value1")
        set_context_data("key2", "value2")
        result = get_context_data()
        assert result == {"key1": "value1", "key2": "value2"}

    def test_delete_existing_key(self):
        """Test deleting an existing key"""
        set_context_data("to_delete", "value")
        delete_context_data("to_delete")
        result = get_context_data("to_delete", default=None)
        assert result is None

    def test_delete_nonexistent_key(self):
        """Test deleting a nonexistent key does not raise"""
        delete_context_data("nonexistent")  # Should not raise

    def test_clear_context_data(self):
        """Test clearing all context data"""
        set_context_data("key1", "value1")
        set_context_data("key2", "value2")
        clear_context_data()
        result = get_context_data()
        assert result == {}

    def test_set_same_key_updates_value(self):
        """Test that setting the same key updates the value"""
        set_context_data("key", "first_value")
        set_context_data("key", "second_value")
        result = get_context_data("key")
        assert result == "second_value"

    def test_multiple_keys_maintained(self):
        """Test that multiple keys are maintained independently"""
        set_context_data("key1", "value1")
        set_context_data("key2", "value2")
        set_context_data("key3", "value3")
        assert get_context_data("key1") == "value1"
        assert get_context_data("key2") == "value2"
        assert get_context_data("key3") == "value3"

    def test_delete_preserves_other_keys(self):
        """Test that deleting one key preserves other keys"""
        set_context_data("key1", "value1")
        set_context_data("key2", "value2")
        delete_context_data("key1")
        assert get_context_data("key1", default=None) is None
        assert get_context_data("key2") == "value2"

    def test_default_parameter_type_preserved(self):
        """Test that default value type is preserved"""
        result = get_context_data("nonexistent", default=0)
        assert result == 0
        assert isinstance(result, int)

    def test_empty_string_as_value(self):
        """Test that empty string can be set as value"""
        set_context_data("empty", "")
        result = get_context_data("empty")
        assert result == ""

    def test_none_as_value(self):
        """Test that None can be set as value"""
        set_context_data("null", None)
        result = get_context_data("null")
        assert result is None

    def test_boolean_values(self):
        """Test boolean values are preserved"""
        set_context_data("flag", True)
        assert get_context_data("flag") is True
        set_context_data("other_flag", False)
        assert get_context_data("other_flag") is False

    def test_nested_dict_as_value(self):
        """Test that nested dictionaries work as values"""
        nested = {"outer": {"inner": "value"}}
        set_context_data("nested", nested)
        result = get_context_data("nested")
        assert result == nested

    def test_context_isolation_between_clears(self):
        """Test context is properly isolated after clear"""
        set_context_data("key", "value")
        clear_context_data()
        result = get_context_data("key", default=None)
        assert result is None
