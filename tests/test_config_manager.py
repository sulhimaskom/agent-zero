"""Tests for the unified ConfigManager.

This test module validates the configuration centralization system
designed to address the "Configuration Sprawl" architectural debt.
"""

import os
from unittest.mock import patch

import pytest

from python.helpers.config_manager import (
    ConfigManager,
    ConfigValidationError,
    LimitConfig,
    ModelConfig,
    ModelType,
    TimeoutConfig,
    get_config,
    reset_config,
)


class TestModelConfig:
    """Test ModelConfig dataclass."""

    def test_valid_model_config(self):
        """Test creating valid model configuration."""
        config = ModelConfig(
            provider="openai",
            name="gpt-4",
            api_base="https://api.openai.com",
            ctx_length=8192,
        )
        assert config.provider == "openai"
        assert config.name == "gpt-4"
        assert config.api_base == "https://api.openai.com"
        assert config.ctx_length == 8192

    def test_empty_provider_raises_error(self):
        """Test that empty provider raises validation error."""
        with pytest.raises(ConfigValidationError, match="provider cannot be empty"):
            ModelConfig(provider="", name="gpt-4")

    def test_empty_name_raises_error(self):
        """Test that empty name raises validation error."""
        with pytest.raises(ConfigValidationError, match="name cannot be empty"):
            ModelConfig(provider="openai", name="")

    def test_negative_context_length_raises_error(self):
        """Test that negative context length raises validation error."""
        with pytest.raises(ConfigValidationError, match="Context length must be positive"):
            ModelConfig(provider="openai", name="gpt-4", ctx_length=-1)

    def test_zero_context_length_raises_error(self):
        """Test that zero context length raises validation error."""
        with pytest.raises(ConfigValidationError, match="Context length must be positive"):
            ModelConfig(provider="openai", name="gpt-4", ctx_length=0)


class TestTimeoutConfig:
    """Test TimeoutConfig dataclass."""

    def test_default_timeouts(self):
        """Test default timeout values."""
        config = TimeoutConfig()
        assert config.http_request > 0
        assert config.code_execution > 0
        assert config.document_download > 0
        assert config.browser_operation > 0

    def test_custom_timeouts(self):
        """Test custom timeout configuration."""
        config = TimeoutConfig(
            http_request=60,
            code_execution=120,
            document_download=30,
            browser_operation=45,
        )
        assert config.http_request == 60
        assert config.code_execution == 120
        assert config.document_download == 30
        assert config.browser_operation == 45


class TestLimitConfig:
    """Test LimitConfig dataclass."""

    def test_default_limits(self):
        """Test default limit values."""
        config = LimitConfig()
        assert config.max_memory_results > 0
        assert config.max_file_size > 0
        assert config.max_message_length > 0


class TestConfigManager:
    """Test ConfigManager functionality."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_config()

    def teardown_method(self):
        """Clean up environment after each test."""
        reset_config()

    def test_singleton_pattern(self):
        """Test that get_config returns singleton instance."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_get_chat_model(self):
        """Test retrieving chat model configuration."""
        config = ConfigManager()
        model = config.get_model(ModelType.CHAT)
        assert isinstance(model, ModelConfig)
        assert model.provider  # Should have default value
        assert model.name  # Should have default value

    def test_get_model_by_string(self):
        """Test retrieving model by string name."""
        config = ConfigManager()
        model = config.get_model("chat")
        assert isinstance(model, ModelConfig)

    def test_get_model_invalid_type_raises_error(self):
        """Test that invalid model type raises error."""
        config = ConfigManager()
        with pytest.raises(ConfigValidationError, match="Unknown model type"):
            config.get_model("invalid_type")

    def test_feature_flags_default(self):
        """Test default feature flag values."""
        config = ConfigManager()
        # These should have defaults
        assert isinstance(config.is_feature_enabled("memory_recall"), bool)
        assert isinstance(config.is_feature_enabled("memory_memorize"), bool)

    def test_unknown_feature_returns_false(self):
        """Test that unknown features return False."""
        config = ConfigManager()
        assert config.is_feature_enabled("unknown_feature") is False

    def test_timeouts_property(self):
        """Test timeouts property returns TimeoutConfig."""
        config = ConfigManager()
        timeouts = config.timeouts
        assert isinstance(timeouts, TimeoutConfig)

    def test_limits_property(self):
        """Test limits property returns LimitConfig."""
        config = ConfigManager()
        limits = config.limits
        assert isinstance(limits, LimitConfig)


class TestConfigManagerEnvironment:
    """Test ConfigManager environment variable loading."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_config()

    def teardown_method(self):
        """Clean up environment after each test."""
        reset_config()

    @patch.dict(
        os.environ,
        {"A0_CHAT_MODEL_PROVIDER": "custom_provider", "A0_CHAT_MODEL_NAME": "custom-model"},
    )
    def test_chat_model_from_env(self):
        """Test that chat model config loads from environment."""
        config = ConfigManager()
        model = config.get_model(ModelType.CHAT)
        assert model.provider == "custom_provider"
        assert model.name == "custom-model"

    @patch.dict(os.environ, {"A0_MEMORY_RECALL_ENABLED": "false"})
    def test_feature_flag_from_env(self):
        """Test that feature flags load from environment."""
        config = ConfigManager()
        assert config.is_feature_enabled("memory_recall") is False

    @patch.dict(os.environ, {"A0_TIMEOUT_HTTP_REQUEST": "120"})
    def test_timeout_from_env(self):
        """Test that timeouts load from environment."""
        config = ConfigManager()
        assert config.timeouts.http_request == 120

    @patch.dict(os.environ, {"A0_MAX_MEMORY_RESULTS": "20"})
    def test_limit_from_env(self):
        """Test that limits load from environment."""
        config = ConfigManager()
        assert config.limits.max_memory_results == 20


class TestConfigManagerValidation:
    """Test ConfigManager validation."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_config()

    def teardown_method(self):
        """Clean up environment after each test."""
        reset_config()

    def test_validate_with_valid_config(self):
        """Test validation passes with valid configuration."""
        config = ConfigManager()
        errors = config.validate()
        assert len(errors) == 0


class TestAllModelTypes:
    """Test all model types can be retrieved."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_config()

    def teardown_method(self):
        """Clean up environment after each test."""
        reset_config()

    @pytest.mark.parametrize(
        "model_type",
        [
            ModelType.CHAT,
            ModelType.UTILITY,
            ModelType.EMBEDDING,
            ModelType.BROWSER,
        ],
    )
    def test_all_model_types_available(self, model_type):
        """Test that all model types are configured."""
        config = ConfigManager()
        model = config.get_model(model_type)
        assert isinstance(model, ModelConfig)
        assert model.provider  # Should have some provider
        assert model.name  # Should have some name
