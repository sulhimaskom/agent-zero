"""Tests for providers module - provider configuration management.

These tests verify the ProviderManager class and convenience functions
for loading and accessing provider configurations.
"""

from unittest.mock import MagicMock, patch

from python.helpers.providers import (
    FieldOption,
    ProviderManager,
    get_provider_config,
    get_providers,
    get_raw_providers,
)


class TestFieldOption:
    """Tests for FieldOption TypedDict"""

    def test_field_option_creation(self):
        """Test creating a FieldOption"""
        option: FieldOption = {"value": "test", "label": "Test"}
        assert option["value"] == "test"
        assert option["label"] == "Test"


class TestProviderManager:
    """Tests for ProviderManager class"""

    def test_singleton_pattern(self):
        """Test that ProviderManager is a singleton"""
        # Reset the singleton for testing
        ProviderManager._instance = None
        ProviderManager._raw = None
        ProviderManager._options = None

        with patch('python.helpers.providers.files.get_abs_path') as mock_path, \
             patch('builtins.open', MagicMock()), \
             patch('yaml.safe_load') as mock_yaml:
            mock_path.return_value = "/fake/path"
            mock_yaml.return_value = {
                "chat": [{"id": "openai", "name": "OpenAI"}]
            }
            instance1 = ProviderManager.get_instance()
            instance2 = ProviderManager.get_instance()
            assert instance1 is instance2

    def test_get_providers_with_mock_data(self):
        """Test get_providers returns correct format"""
        # Reset for testing
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "openai", "name": "OpenAI"},
                {"id": "anthropic", "name": "Anthropic"}
            ]
        }
        ProviderManager._options = {
            "chat": [
                {"value": "openai", "label": "OpenAI"},
                {"value": "anthropic", "label": "Anthropic"}
            ]
        }

        manager = ProviderManager.get_instance()
        result = manager.get_providers("chat")

        assert len(result) == 2
        assert result[0]["value"] == "openai"
        assert result[1]["label"] == "Anthropic"

    def test_get_providers_unknown_type(self):
        """Test get_providers with unknown provider type returns empty list"""
        ProviderManager._instance = None
        ProviderManager._raw = {}
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_providers("unknown_type")

        assert result == []

    def test_get_raw_providers(self):
        """Test get_raw_providers returns raw provider data"""
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "openai", "name": "OpenAI", "api_key": "test-key"}
            ]
        }
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_raw_providers("chat")

        assert len(result) == 1
        assert result[0]["id"] == "openai"
        assert result[0]["api_key"] == "test-key"

    def test_get_raw_providers_unknown_type(self):
        """Test get_raw_providers with unknown type returns empty list"""
        ProviderManager._instance = None
        ProviderManager._raw = {}
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_raw_providers("unknown")

        assert result == []

    def test_get_provider_config_found(self):
        """Test get_provider_config returns config for existing provider"""
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "openai", "name": "OpenAI", "api_base": "https://api.openai.com"}
            ]
        }
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_provider_config("chat", "openai")

        assert result is not None
        assert result["id"] == "openai"
        assert result["api_base"] == "https://api.openai.com"

    def test_get_provider_config_case_insensitive(self):
        """Test get_provider_config is case insensitive"""
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "OpenAI", "name": "OpenAI"}
            ]
        }
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_provider_config("chat", "openai")

        assert result is not None
        assert result["id"] == "OpenAI"

    def test_get_provider_config_not_found(self):
        """Test get_provider_config returns None for non-existent provider"""
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "openai", "name": "OpenAI"}
            ]
        }
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_provider_config("chat", "nonexistent")

        assert result is None

    def test_get_provider_config_uses_value_fallback(self):
        """Test get_provider_config falls back to 'value' if 'id' not present"""
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"value": "openai", "name": "OpenAI"}
            ]
        }
        ProviderManager._options = {}

        manager = ProviderManager.get_instance()
        result = manager.get_provider_config("chat", "openai")

        assert result is not None
        assert result["value"] == "openai"


class TestProviderConvenienceFunctions:
    """Tests for module-level convenience functions"""

    def test_get_providers_function(self):
        """Test the get_providers convenience function"""
        # Reset singleton
        ProviderManager._instance = None
        ProviderManager._raw = {
            "embedding": [
                {"id": "sentence-transformers", "name": "Sentence Transformers"}
            ]
        }
        ProviderManager._options = {
            "embedding": [
                {"value": "sentence-transformers", "label": "Sentence Transformers"}
            ]
        }

        result = get_providers("embedding")

        assert len(result) == 1
        assert result[0]["value"] == "sentence-transformers"

    def test_get_raw_providers_function(self):
        """Test the get_raw_providers convenience function"""
        # Reset singleton
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "test", "name": "Test"}
            ]
        }
        ProviderManager._options = {}

        result = get_raw_providers("chat")

        assert len(result) == 1

    def test_get_provider_config_function(self):
        """Test the get_provider_config convenience function"""
        # Reset singleton
        ProviderManager._instance = None
        ProviderManager._raw = {
            "chat": [
                {"id": "test-provider", "name": "Test Provider"}
            ]
        }
        ProviderManager._options = {}

        result = get_provider_config("chat", "test-provider")

        assert result is not None
        assert result["name"] == "Test Provider"


class TestProviderManagerLoading:
    """Tests for ProviderManager data loading"""

    def test_load_providers_handles_empty_yaml(self):
        """Test loading handles empty YAML gracefully"""
        ProviderManager._instance = None
        ProviderManager._raw = None
        ProviderManager._options = None

        with patch('python.helpers.providers.files.get_abs_path') as mock_path, \
             patch('builtins.open', MagicMock()), \
             patch('yaml.safe_load') as mock_yaml:
            mock_path.return_value = "/fake/path"
            mock_yaml.return_value = {}
            manager = ProviderManager()
            assert manager._raw == {}
            assert manager._options == {}

    def test_load_providers_normalises_dict_format(self):
        """Test loading normalises new dict format to list format"""
        ProviderManager._instance = None
        ProviderManager._raw = None
        ProviderManager._options = None

        with patch('python.helpers.providers.files.get_abs_path') as mock_path, \
             patch('builtins.open', MagicMock()), \
             patch('yaml.safe_load') as mock_yaml:
            mock_path.return_value = "/fake/path"
            # New dict format
            mock_yaml.return_value = {
                "chat": {
                    "openai": {"name": "OpenAI"},
                    "anthropic": {"name": "Anthropic"}
                }
            }
            manager = ProviderManager()

            # Should be normalised to list format
            assert "chat" in manager._raw
            chat_providers = manager._raw["chat"]
            assert len(chat_providers) == 2
            # Each should have id added
            ids = [p.get("id") for p in chat_providers]
            assert "openai" in ids
            assert "anthropic" in ids

    def test_load_providers_preserves_list_format(self):
        """Test loading preserves existing list format"""
        ProviderManager._instance = None
        ProviderManager._raw = None
        ProviderManager._options = None

        with patch('python.helpers.providers.files.get_abs_path') as mock_path, \
             patch('builtins.open', MagicMock()), \
             patch('yaml.safe_load') as mock_yaml:
            mock_path.return_value = "/fake/path"
            # Legacy list format
            mock_yaml.return_value = {
                "chat": [
                    {"id": "openai", "name": "OpenAI"}
                ]
            }
            manager = ProviderManager()

            assert "chat" in manager._raw
            assert len(manager._raw["chat"]) == 1
            assert manager._raw["chat"][0]["id"] == "openai"
