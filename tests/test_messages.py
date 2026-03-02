import pytest
from unittest.mock import MagicMock

from python.helpers import messages
from python.helpers.constants import Limits


class MockAgent:
    """Mock agent for testing message truncation functions"""

    def __init__(self, placeholder_text="...content truncated..."):
        self._placeholder_text = placeholder_text

    def read_prompt(self, prompt_name, **kwargs):
        """Mock read_prompt that returns placeholder text"""
        return self._placeholder_text


class TestTruncateText:
    """Test truncate_text function"""

    def test_truncate_text_returns_unchanged_when_below_threshold(self):
        """Test that text below threshold is returned unchanged"""
        agent = MockAgent()
        output = "short text"
        result = messages.truncate_text(agent, output, threshold=1000)
        assert result == "short text"

    def test_truncate_text_returns_unchanged_when_at_threshold(self):
        """Test that text at threshold is returned unchanged"""
        agent = MockAgent()
        output = "a" * 1000  # exactly at threshold
        result = messages.truncate_text(agent, output, threshold=1000)
        assert result == "a" * 1000

    def test_truncate_text_truncates_above_threshold(self):
        """Test that text above threshold is truncated"""
        agent = MockAgent(placeholder_text="...truncated...")
        output = "a" * 2000  # above threshold
        result = messages.truncate_text(agent, output, threshold=1000)
        # Result should be shorter than original
        assert len(result) == 1000
        assert result.startswith("a")
        assert result.endswith("a")

    def test_truncate_text_with_zero_threshold(self):
        """Test that zero threshold returns original text"""
        agent = MockAgent()
        output = "some text"
        result = messages.truncate_text(agent, output, threshold=0)
        assert result == "some text"

    def test_truncate_text_with_none_threshold(self):
        """Test that None threshold raises TypeError"""
        agent = MockAgent()
        output = "some text"
        with pytest.raises(TypeError):
            messages.truncate_text(agent, output, threshold=None)

    def test_truncate_text_uses_default_threshold(self):
        """Test that default threshold from Limits is used"""
        agent = MockAgent(placeholder_text="...truncated...")
        output = "a" * 2000  # above default threshold of 1000
        result = messages.truncate_text(agent, output)
        assert len(result) == 1000
        assert result.startswith("a")

    def test_truncate_text_custom_threshold(self):
        """Test truncation with custom threshold value"""
        agent = MockAgent(placeholder_text="[TRUNCATED]")
        output = "x" * 500
        result = messages.truncate_text(agent, output, threshold=100)
        # Should be truncated to 100 chars with placeholder
        assert len(result) == 100
        assert result.startswith("x")
        assert "[TRUNCATED]" in result


class TestTruncateDictByRatio:
    """Test truncate_dict_by_ratio function"""

    def test_truncate_dict_by_ratio_returns_unchanged_small_dict(self):
        """Test that small dict is returned unchanged"""
        agent = MockAgent()
        data = {"key": "value"}
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == {"key": "value"}

    def test_truncate_dict_by_ratio_truncates_large_string_value(self):
        """Test that large string values are truncated"""
        agent = MockAgent(placeholder_text="...truncated...")
        large_string = "x" * 2000
        data = {"key": large_string}
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=100, truncate_to=50)
        # The serialized value should exceed threshold_chars
        assert isinstance(result, dict)
        # Value should be truncated to ~50 chars
        assert len(result["key"]) <= 60  # Allow some margin

    def test_truncate_dict_by_ratio_handles_list(self):
        """Test that lists are processed correctly"""
        agent = MockAgent(placeholder_text="...truncated...")
        data = ["item1", "item2", "item3"]
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == ["item1", "item2", "item3"]

    def test_truncate_dict_by_ratio_truncates_large_list_items(self):
        """Test that large list items are truncated"""
        agent = MockAgent(placeholder_text="...truncated...")
        large_item = "x" * 2000
        data = ["small", large_item]
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=100, truncate_to=50)
        assert isinstance(result, list)
        assert result[0] == "small"
        # Large item should be truncated
        assert len(result[1]) <= 60

    def test_truncate_dict_by_ratio_handles_nested_dict(self):
        """Test that nested dicts are processed correctly"""
        agent = MockAgent()
        data = {"outer": {"inner": "value"}}
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == {"outer": {"inner": "value"}}

    def test_truncate_dict_by_ratio_handles_nested_list(self):
        """Test that nested lists are processed correctly"""
        agent = MockAgent()
        data = {"list": [1, 2, 3]}
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == {"list": [1, 2, 3]}

    def test_truncate_dict_by_ratio_handles_mixed_types(self):
        """Test that mixed dict/list/str types are handled"""
        agent = MockAgent(placeholder_text="...truncated...")
        data = {
            "string": "short",
            "list": [1, 2],
            "nested": {"a": "b"},
            "large_string": "x" * 2000
        }
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=50, truncate_to=30)
        assert isinstance(result, dict)
        assert result["string"] == "short"
        assert result["list"] == [1, 2]
        assert result["nested"] == {"a": "b"}
        # Large string should be truncated
        assert len(result["large_string"]) <= 40

    def test_truncate_dict_by_ratio_handles_string_input(self):
        """Test that string input is handled correctly"""
        agent = MockAgent(placeholder_text="...truncated...")
        data = "short string"
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == "short string"

    def test_truncate_dict_by_ratio_truncates_large_string_input(self):
        """Test that large string input is truncated"""
        agent = MockAgent(placeholder_text="...truncated...")
        large_string = "y" * 2000
        result = messages.truncate_dict_by_ratio(agent, large_string, threshold_chars=100, truncate_to=50)
        # Should be truncated to approximately truncate_to chars
        assert len(result) <= 60

    def test_truncate_dict_by_ratio_handles_empty_dict(self):
        """Test that empty dict is handled correctly"""
        agent = MockAgent()
        data = {}
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == {}

    def test_truncate_dict_by_ratio_handles_empty_list(self):
        """Test that empty list is handled correctly"""
        agent = MockAgent()
        data = []
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == []

    def test_truncate_dict_by_ratio_handles_empty_string(self):
        """Test that empty string is handled correctly"""
        agent = MockAgent()
        data = ""
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result == ""

    def test_truncate_dict_by_ratio_handles_non_string_values(self):
        """Test that non-string values (int, float, bool, None) pass through"""
        agent = MockAgent()
        data = {
            "int": 42,
            "float": 3.14,
            "bool": True,
            "none": None
        }
        result = messages.truncate_dict_by_ratio(agent, data, threshold_chars=1000, truncate_to=100)
        assert result["int"] == 42
        assert result["float"] == 3.14
        assert result["bool"] is True
        assert result["none"] is None
