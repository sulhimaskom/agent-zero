"""Tests for python/helpers/secrets.py - Secret management and masking."""

import pytest
import threading
import re

from python.helpers.secrets import (
    SecretsManager,
    StreamingSecretsFilter,
    EnvLine,
    alias_for_key,
    ALIAS_PATTERN,
)


class TestAliasForKey:
    """Tests for alias_for_key function."""

    def test_alias_for_key_basic(self):
        """Test basic alias generation."""
        result = alias_for_key("my_secret")
        assert result == "§§secret(MY_SECRET)"

    def test_alias_for_key_preserves_case_in_placeholder(self):
        """Test that key is uppercased in placeholder."""
        result = alias_for_key("Api_Key")
        assert result == "§§secret(API_KEY)"

    def test_alias_for_key_custom_placeholder(self):
        """Test custom placeholder format."""
        result = alias_for_key("token", placeholder="{key}::secret")
        assert result == "TOKEN::secret"

    def test_alias_for_key_empty_key(self):
        """Test empty key handling."""
        result = alias_for_key("")
        assert result == "§§secret()"


class TestEnvLineDataclass:
    """Tests for EnvLine dataclass."""

    def test_env_line_pair(self):
        """Test EnvLine for key-value pair."""
        line = EnvLine(raw="API_KEY=abc123", type="pair", key="API_KEY", value="abc123")
        assert line.type == "pair"
        assert line.key == "API_KEY"
        assert line.value == "abc123"

    def test_env_line_comment(self):
        """Test EnvLine for comment line."""
        line = EnvLine(raw="# This is a comment", type="comment")
        assert line.type == "comment"
        assert line.key is None

    def test_env_line_blank(self):
        """Test EnvLine for blank line."""
        line = EnvLine(raw="", type="blank")
        assert line.type == "blank"
        assert line.key is None

    def test_env_line_with_inline_comment(self):
        """Test EnvLine with inline comment."""
        line = EnvLine(
            raw='SECRET="value"  # inline comment',
            type="pair",
            key="SECRET",
            value="value",
            inline_comment="  # inline comment"
        )
        assert line.inline_comment == "  # inline comment"

    def test_env_line_other_type(self):
        """Test EnvLine for other/unknown lines."""
        line = EnvLine(raw="SOME_INVALID_LINE", type="other")
        assert line.type == "other"
        assert line.key is None


class TestStreamingSecretsFilter:
    """Tests for StreamingSecretsFilter class."""

    def test_filter_no_secrets(self):
        """Test filter with no secrets configured."""
        key_to_value = {}
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        result = filter_obj.process_chunk("Hello world")
        assert result == "Hello world"

    def test_filter_full_secret_replacement(self):
        """Test replacement of full secret values."""
        key_to_value = {"API_KEY": "secret123"}
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        result = filter_obj.process_chunk("My API_KEY is secret123")
        assert result == "My API_KEY is §§secret(API_KEY)"

    def test_filter_partial_secret_hold(self):
        """Test that partial secrets are held until complete."""
        key_to_value = {"TOKEN": "abc123"}
        filter_obj = StreamingSecretsFilter(key_to_value, min_trigger=3)
        
        # First chunk ends with partial secret
        result1 = filter_obj.process_chunk("Token: abc")
        # Should hold the partial
        assert result1 == "Token: "
        
        # Second chunk completes the secret
        result2 = filter_obj.process_chunk("123 more")
        assert result2 == "§§secret(TOKEN) more"

    def test_filter_finalize_unresolved_partial(self):
        """Test finalize masks unresolved partial secrets."""
        key_to_value = {"SECRET": "mysecret"}
        filter_obj = StreamingSecretsFilter(key_to_value, min_trigger=3)
        
        # Partial secret at end
        filter_obj.process_chunk("Value: myse")
        result = filter_obj.finalize()
        
        # Should mask the unresolved partial
        assert "***" in result

    def test_filter_multiple_secrets(self):
        """Test filtering multiple different secrets."""
        key_to_value = {
            "KEY1": "value1",
            "KEY2": "value2"
        }
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        result = filter_obj.process_chunk("key1=value1 and key2=value2")
        assert "§§secret(KEY1)" in result
        assert "§§secret(KEY2)" in result

    def test_filter_longest_secret_first(self):
        """Test that longer secrets are replaced first to avoid partial issues."""
        key_to_value = {
            "SHORT": "ab",
            "LONGER": "abcd"
        }
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        # Test that longer value is handled correctly
        result = filter_obj.process_chunk("ab and abcd")
        # Both should be replaced
        assert "§§secret(SHORT)" in result or "§§secret(LONGER)" in result

    def test_filter_empty_chunk(self):
        """Test filter with empty chunk."""
        key_to_value = {"KEY": "value"}
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        result = filter_obj.process_chunk("")
        assert result == ""

    def test_filter_finalize_empty(self):
        """Test finalize with no pending data."""
        key_to_value = {"KEY": "value"}
        filter_obj = StreamingSecretsFilter(key_to_value)
        
        result = filter_obj.finalize()
        assert result == ""


class TestSecretsManagerReplacePlaceholders:
    """Tests for SecretsManager.replace_placeholders method."""

    def test_replace_simple_placeholder(self):
        """Test replacing a simple placeholder."""
        # Create a proper manager with a temporary file
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"API_KEY": "secret123"}
        manager._lock = threading.RLock()  # Ensure lock is set
        
        result = manager.replace_placeholders("My key is §§secret(API_KEY)")
        assert result == "My key is secret123"

    def test_replace_multiple_placeholders(self):
        """Test replacing multiple placeholders."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY1": "val1", "KEY2": "val2"}
        manager._lock = threading.RLock()
        
        result = manager.replace_placeholders("§§secret(KEY1) and §§secret(KEY2)")
        assert result == "val1 and val2"

    def test_replace_missing_key_raises(self):
        """Test that missing key raises exception."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"EXISTING_KEY": "value"}
        manager._lock = threading.RLock()
        
        with pytest.raises(Exception):
            # Should raise RepairableException
            manager.replace_placeholders("§§secret(NONEXISTENT)")

    def test_replace_empty_text(self):
        """Test replacing in empty text."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY": "value"}
        manager._lock = threading.RLock()
        
        result = manager.replace_placeholders("")
        assert result == ""


class TestSecretsManagerMaskValues:
    """Tests for SecretsManager.mask_values method."""

    def test_mask_simple_value(self):
        """Test masking a simple value."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"API_KEY": "mysecret"}
        manager._lock = threading.RLock()
        
        result = manager.mask_values("The API_KEY is mysecret")
        assert "mysecret" not in result
        assert "§§secret(API_KEY)" in result

    def test_mask_multiple_values(self):
        """Test masking multiple values."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY1": "val1", "KEY2": "val2"}
        manager._lock = threading.RLock()
        
        result = manager.mask_values("key1=val1 and key2=val2")
        assert "val1" not in result
        assert "val2" not in result

    def test_mask_empty_text(self):
        """Test masking empty text."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY": "value"}
        manager._lock = threading.RLock()
        
        result = manager.mask_values("")
        assert result == ""

    def test_mask_min_length(self):
        """Test min_length parameter."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY": "ab"}  # Only 2 chars
        manager._lock = threading.RLock()
        
        result = manager.mask_values("ab", min_length=4)
        # Short value shouldn't be masked
        assert "ab" in result


class TestSecretsManagerGetKeys:
    """Tests for SecretsManager.get_keys method."""

    def test_get_keys_returns_list(self):
        """Test that get_keys returns a list of keys."""
        manager = SecretsManager("/nonexistent/env/file")
        manager._secrets_cache = {"KEY1": "val1", "KEY2": "val2"}
        manager._lock = threading.RLock()
        
        keys = manager.get_keys()
        
        assert isinstance(keys, list)
        assert "KEY1" in keys
        assert "KEY2" in keys


class TestAliasPattern:
    """Tests for ALIAS_PATTERN regex."""

    def test_pattern_matches_valid_alias(self):
        """Test that pattern matches valid secret placeholders."""
        matches = re.findall(ALIAS_PATTERN, "Use §§secret(API_KEY) here")
        assert "API_KEY" in matches

    def test_pattern_matches_underscore_key(self):
        """Test pattern matches keys with underscores."""
        matches = re.findall(ALIAS_PATTERN, "Use §§secret(MY_API_KEY) here")
        assert "MY_API_KEY" in matches

    def test_pattern_matches_numeric_key(self):
        """Test pattern matches keys with numbers."""
        matches = re.findall(ALIAS_PATTERN, "Use §§secret(KEY123) here")
        assert "KEY123" in matches

    def test_pattern_no_match_invalid(self):
        """Test pattern does not match invalid formats."""
        matches = re.findall(ALIAS_PATTERN, "Use §secret(INVALID) here")
        assert len(matches) == 0

    def test_pattern_matches_lowercase(self):
        """Test pattern matches lowercase keys."""
        matches = re.findall(ALIAS_PATTERN, "key=§§secret(lowercase)")
        assert "lowercase" in matches


class TestSecretsManagerSerialization:
    """Tests for SecretsManager._serialize_env_lines method."""

    def test_serialize_with_values(self):
        """Test serialization with values included."""
        manager = SecretsManager()
        lines = [
            EnvLine(raw="KEY=value", type="pair", key="KEY", value="value")
        ]
        
        result = manager._serialize_env_lines(lines, with_values=True)
        assert "value" in result

    def test_serialize_without_values(self):
        """Test serialization without values (for prompts)."""
        manager = SecretsManager()
        lines = [
            EnvLine(raw="KEY=value", type="pair", key="KEY", value="value")
        ]
        
        result = manager._serialize_env_lines(lines, with_values=False)
        assert "KEY" in result
        assert "value" not in result

    def test_serialize_with_comments(self):
        """Test serialization preserves comments."""
        manager = SecretsManager()
        lines = [
            EnvLine(raw="# comment", type="comment", key=None)
        ]
        
        result = manager._serialize_env_lines(lines, with_comments=True)
        assert "# comment" in result or "#comment" in result

    def test_serialize_key_formatter(self):
        """Test serialization with custom key formatter."""
        manager = SecretsManager()
        lines = [
            EnvLine(raw="KEY=value", type="pair", key="KEY", value="value")
        ]
        
        # Use a simple formatter
        def format_key(k):
            return "SECRET_" + k
        
        result = manager._serialize_env_lines(lines, key_formatter=format_key)
        assert "SECRET_KEY" in result

    def test_serialize_without_blank(self):
        """Test serialization can exclude blank lines."""
        manager = SecretsManager()
        lines = [
            EnvLine(raw="", type="blank", key=None),
            EnvLine(raw="KEY=value", type="pair", key="KEY", value="value")
        ]
        
        result = manager._serialize_env_lines(lines, with_blank=False)
        # Blank line should not appear
        lines_in_result = [l for l in result.split("\n") if l]
        assert len(lines_in_result) == 1


class TestSecretsManagerConstants:
    """Tests for SecretsManager constants."""

    def test_default_placeholder_pattern(self):
        """Test that PLACEHOLDER_PATTERN is alias pattern."""
        manager = SecretsManager()
        assert manager.PLACEHOLDER_PATTERN == ALIAS_PATTERN

    def test_mask_value_constant(self):
        """Test MASK_VALUE constant."""
        manager = SecretsManager()
        assert manager.MASK_VALUE == "***"
