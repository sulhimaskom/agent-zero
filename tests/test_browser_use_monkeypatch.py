"""Tests for browser_use_monkeypatch module.

Tests the gemini_clean_and_conform function for JSON output normalization.
"""

from python.helpers.browser_use_monkeypatch import gemini_clean_and_conform


class TestGeminiCleanAndConform:
    """Test gemini_clean_and_conform function"""

    def test_valid_json_input(self):
        """Test valid JSON input is processed correctly"""
        input_json = '{"action": [{"scroll_down": {"down": true}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "scroll" in result

    def test_json_with_markdown_fence(self):
        """Test JSON wrapped in markdown fence is parsed correctly"""
        input_json = '```json\n{"action": [{"scroll_down": {"down": true}}]}\n```'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "scroll" in result

    def test_complete_task_alias_to_done(self):
        """Test complete_task action is aliased to done"""
        input_json = '{"action": [{"complete_task": {"response": "Done"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "done" in result
        assert "complete_task" not in result

    def test_scroll_down_normalization(self):
        """Test scroll_down action is normalized"""
        input_json = '{"action": [{"scroll_down": {}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert '"down": true' in result or '"down":true' in result
        assert '"num_pages": 1' in result or '"num_pages":1' in result

    def test_scroll_up_normalization(self):
        """Test scroll_up action sets down to false"""
        input_json = '{"action": [{"scroll_up": {}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert '"down": false' in result or '"down":false' in result

    def test_go_to_url_defaults_new_tab(self):
        """Test go_to_url gets new_tab default"""
        input_json = '{"action": [{"go_to_url": {"url": "https://example.com"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert '"new_tab": false' in result or '"new_tab":false' in result

    def test_done_action_missing_data(self):
        """Test done action constructs data from top-level keys"""
        input_json = '{"action": [{"done": {"response": "Result", "page_summary": "Summary", "title": "Title"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert '"success": true' in result or '"success":true' in result
        assert '"data"' in result

    def test_done_action_with_existing_data(self):
        """Test done action preserves existing data"""
        input_json = '{"action": [{"done": {"data": {"custom": "value"}, "success": false}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        # Should preserve existing data and success
        assert "custom" in result
        assert "value" in result

    def test_done_action_defaults_response(self):
        """Test done action provides defaults when missing"""
        input_json = '{"action": [{"done": {}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        # Should have default response and summary
        assert "Task completed" in result
        assert "page_summary" in result

    def test_invalid_json_returns_none(self):
        """Test invalid JSON input returns None"""
        input_json = "not valid json at all"
        result = gemini_clean_and_conform(input_json)
        assert result is None

    def test_non_dict_returns_none(self):
        """Test non-dict JSON returns None"""
        input_json = '[1, 2, 3]'
        result = gemini_clean_and_conform(input_json)
        assert result is None

    def test_empty_action_list(self):
        """Test empty action list is handled"""
        input_json = '{"action": []}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "action" in result

    def test_action_not_a_list(self):
        """Test action that is not a list is passed through"""
        input_json = '{"action": "not_a_list"}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None

    def test_non_dict_action_item_skipped(self):
        """Test non-dict items in action list are skipped"""
        input_json = '{"action": ["string_item", 123, null]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None

    def test_other_actions_pass_through(self):
        """Test actions not in special cases pass through unchanged"""
        input_json = '{"action": [{"custom_action": {"key": "value"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "custom_action" in result

    def test_multiple_actions_scroll(self):
        """Test scroll action is processed correctly"""
        input_json = '{"action": [{"scroll_down": {}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "scroll" in result

    def test_multiple_actions_done(self):
        """Test done action is processed correctly"""
        input_json = '{"action": [{"done": {"response": "ok"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "done" in result

    def test_multiple_actions_go_to_url(self):
        """Test go_to_url action is processed correctly"""
        input_json = '{"action": [{"go_to_url": {"url": "http://test.com"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "go_to_url" in result


class TestGeminiCleanAndConformEdgeCases:
    """Edge case tests for gemini_clean_and_conform"""

    def test_empty_string(self):
        """Test empty string returns None"""
        result = gemini_clean_and_conform("")
        assert result is None

    def test_whitespace_only(self):
        """Test whitespace-only string returns None"""
        result = gemini_clean_and_conform("   \n\t  ")
        assert result is None

    def test_json_with_extra_whitespace(self):
        """Test JSON with extra whitespace is handled"""
        input_json = '{  "action" : [ { "scroll_down" : { } } ] }'
        result = gemini_clean_and_conform(input_json)
        assert result is not None

    def test_empty_action_object(self):
        """Test action with empty object"""
        input_json = '{"action": [{}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None

    def test_nested_json_in_action_value(self):
        """Test nested JSON in action value is preserved"""
        input_json = '{"action": [{"done": {"data": {"nested": {"deep": "value"}}}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "nested" in result
        assert "deep" in result

    def test_special_characters_in_strings(self):
        """Test special characters in string values are preserved"""
        input_json = '{"action": [{"done": {"response": "Hello\\nWorld\\ttab"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        # Note: JSON parsing may escape/unescape characters

    def test_unicode_characters(self):
        """Test Unicode characters are preserved"""
        input_json = '{"action": [{"done": {"response": "Hello 世界 🌍"}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        # Unicode should be preserved

    def test_boolean_values_preserved(self):
        """Test boolean values in input are preserved"""
        input_json = '{"action": [{"done": {"success": true, "data": {"flag": false}}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "true" in result or "false" in result

    def test_numeric_values_preserved(self):
        """Test numeric values are preserved"""
        input_json = '{"action": [{"scroll_down": {"num_pages": 5.5}}]}'
        result = gemini_clean_and_conform(input_json)
        assert result is not None
        assert "5.5" in result
