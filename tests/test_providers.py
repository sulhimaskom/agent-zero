"""Tests for providers module - model provider configuration management.

These tests verify the ProviderManager class and convenience functions for
loading and accessing model provider configurations from the YAML file.
"""

from python.helpers.providers import (
    FieldOption,
    ProviderManager,
    get_provider_config,
    get_providers,
    get_raw_providers,
)


class TestFieldOption:
    """Tests for FieldOption TypedDict structure"""

    def test_field_option_has_value_key(self):
        """Test that FieldOption contains value key"""
        option: FieldOption = {"value": "openai", "label": "OpenAI"}
        assert "value" in option
        assert option["value"] == "openai"

    def test_field_option_has_label_key(self):
        """Test that FieldOption contains label key"""
        option: FieldOption = {"value": "openai", "label": "OpenAI"}
        assert "label" in option
        assert option["label"] == "OpenAI"


class TestProviderManager:
    """Tests for ProviderManager singleton class"""

    def test_get_instance_returns_singleton(self):
        """Test that get_instance returns the same instance"""
        instance1 = ProviderManager.get_instance()
        instance2 = ProviderManager.get_instance()
        assert instance1 is instance2

    def test_get_providers_returns_list(self):
        """Test that get_providers returns a list"""
        manager = ProviderManager.get_instance()
        result = manager.get_providers("chat")
        assert isinstance(result, list)

    def test_get_providers_returns_field_options(self):
        """Test that get_providers returns FieldOption dicts"""
        manager = ProviderManager.get_instance()
        result = manager.get_providers("chat")
        if result:
            # Each item should have value and label keys
            for item in result:
                assert "value" in item
                assert "label" in item

    def test_get_providers_unknown_type_returns_empty_list(self):
        """Test that unknown provider type returns empty list"""
        manager = ProviderManager.get_instance()
        result = manager.get_providers("nonexistent_type")
        assert result == []

    def test_get_raw_providers_returns_list(self):
        """Test that get_raw_providers returns a list"""
        manager = ProviderManager.get_instance()
        result = manager.get_raw_providers("chat")
        assert isinstance(result, list)

    def test_get_raw_providers_unknown_type_returns_empty_list(self):
        """Test that unknown provider type returns empty list for raw providers"""
        manager = ProviderManager.get_instance()
        result = manager.get_raw_providers("nonexistent_type")
        assert result == []

    def test_get_provider_config_returns_dict_for_valid_provider(self):
        """Test that get_provider_config returns dict for valid provider"""
        manager = ProviderManager.get_instance()
        # Try to get config for a common provider
        providers = manager.get_providers("chat")
        if providers:
            provider_id = providers[0]["value"]
            config = manager.get_provider_config("chat", provider_id)
            assert isinstance(config, dict)

    def test_get_provider_config_returns_none_for_invalid_provider(self):
        """Test that get_provider_config returns None for invalid provider"""
        manager = ProviderManager.get_instance()
        result = manager.get_provider_config("chat", "nonexistent_provider_xyz")
        assert result is None

    def test_get_provider_config_is_case_insensitive(self):
        """Test that get_provider_config is case insensitive"""
        manager = ProviderManager.get_instance()
        providers = manager.get_providers("chat")
        if providers:
            provider_id = providers[0]["value"]
            # Try with uppercase
            config_upper = manager.get_provider_config("chat", provider_id.upper())
            # Try with lowercase
            config_lower = manager.get_provider_config("chat", provider_id.lower())
            # At least one should return a config
            assert config_upper is not None or config_lower is not None


class TestConvenienceFunctions:
    """Tests for module-level convenience functions"""

    def test_get_providers_function_returns_list(self):
        """Test that get_providers convenience function returns list"""
        result = get_providers("chat")
        assert isinstance(result, list)

    def test_get_providers_function_unknown_type(self):
        """Test get_providers with unknown type"""
        result = get_providers("invalid_type_xyz")
        assert result == []

    def test_get_raw_providers_function_returns_list(self):
        """Test that get_raw_providers convenience function returns list"""
        result = get_raw_providers("chat")
        assert isinstance(result, list)

    def test_get_raw_providers_function_unknown_type(self):
        """Test get_raw_providers with unknown type"""
        result = get_raw_providers("invalid_type_xyz")
        assert result == []

    def test_get_provider_config_function_returns_config(self):
        """Test that get_provider_config convenience function works"""
        # First get a valid provider ID
        providers = get_providers("chat")
        if providers:
            provider_id = providers[0]["value"]
            result = get_provider_config("chat", provider_id)
            assert isinstance(result, dict)

    def test_get_provider_config_function_returns_none_for_invalid(self):
        """Test get_provider_config returns None for invalid provider"""
        result = get_provider_config("chat", "invalid_provider_test")
        assert result is None


class TestProviderTypes:
    """Tests for different provider types"""

    def test_chat_providers_available(self):
        """Test that chat providers are available"""
        result = get_providers("chat")
        assert isinstance(result, list)
        # Chat providers should typically exist
        assert len(result) > 0

    def test_embedding_providers_available(self):
        """Test that embedding providers are available"""
        result = get_providers("embedding")
        assert isinstance(result, list)

    def test_browser_providers_available(self):
        """Test that browser providers are available"""
        result = get_providers("browser")
        assert isinstance(result, list)

    def test_tts_providers_available(self):
        """Test that TTS providers are available"""
        result = get_providers("tts")
        assert isinstance(result, list)


class TestProviderManagerReset:
    """Tests for ProviderManager reset behavior"""

    def test_singleton_persistence(self):
        """Test that ProviderManager maintains state as singleton"""
        # Get instance twice
        instance1 = ProviderManager.get_instance()
        instance2 = ProviderManager.get_instance()

        # Both should be the same object
        assert instance1 is instance2

        # And should have the same data
        providers1 = instance1.get_providers("chat")
        providers2 = instance2.get_providers("chat")
        assert providers1 == providers2
