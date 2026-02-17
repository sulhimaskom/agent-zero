"""Unified Configuration System for Agent Zero.

This module provides a centralized, validated configuration system to address
the "Configuration Sprawl" architectural debt identified in blueprint.md.

Design Goals:
1. Single source of truth for all configuration
2. Type-safe with runtime validation
3. Clear inheritance: defaults -> constants -> env vars -> user settings
4. Backward compatible migration path

Usage:
    from python.helpers.config_manager import ConfigManager

    config = ConfigManager()
    chat_model = config.get_model("chat")
    timeout = config.get_timeout("http_request")
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar, overload

from python.helpers.constants import (
    AgentDefaults,
    Config,
    Limits,
    Timeouts,
)

T = TypeVar("T")


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    pass


class ModelType(Enum):
    """Supported model types."""

    CHAT = "chat"
    UTILITY = "utility"
    EMBEDDING = "embedding"
    BROWSER = "browser"


@dataclass(frozen=True)
class ModelConfig:
    """Immutable model configuration with validation.

    Attributes:
        provider: Model provider (openai, anthropic, etc.)
        name: Model name/identifier
        api_base: Custom API base URL (optional)
        ctx_length: Context window length in tokens
        kwargs: Additional provider-specific arguments
    """

    provider: str
    name: str
    api_base: str | None = None
    ctx_length: int = field(default=Limits.DEFAULT_CHAT_MODEL_CTX_LENGTH)
    kwargs: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate configuration."""
        if not self.provider:
            raise ConfigValidationError("Model provider cannot be empty")
        if not self.name:
            raise ConfigValidationError("Model name cannot be empty")
        if self.ctx_length <= 0:
            raise ConfigValidationError(f"Context length must be positive, got {self.ctx_length}")


@dataclass(frozen=True)
class TimeoutConfig:
    """Timeout configuration for various operations."""

    http_request: int = Timeouts.HTTP_CACHE_MAX_AGE  # Using as default
    code_execution: int = Timeouts.CODE_EXEC_MAX
    document_download: int = Timeouts.BROWSER_OPERATION_TIMEOUT
    browser_operation: int = Timeouts.BROWSER_OPERATION_TIMEOUT


@dataclass(frozen=True)
class LimitConfig:
    """Resource limit configuration."""

    max_file_size: int = Limits.FILE_READ_MAX_SIZE
    max_message_length: int = Limits.MESSAGE_TRUNCATE_THRESHOLD
    max_memory_results: int = Limits.MEMORY_DEFAULT_LIMIT


class ConfigManager:
    """Centralized configuration manager.

    Provides a single source of truth for all Agent Zero configuration
    with proper validation and type safety.

    Configuration priority (highest to lowest):
    1. Explicitly set values
    2. Environment variables
    3. Constants from python.helpers.constants
    4. Default values

    Example:
        config = ConfigManager()

        # Get model configuration
        chat = config.get_model(ModelType.CHAT)

        # Get timeouts
        timeouts = config.timeouts

        # Check if feature enabled
        if config.is_feature_enabled("memory_recall"):
            ...
    """

    def __init__(self):
        """Initialize configuration manager."""
        self._model_configs: dict[ModelType, ModelConfig] = {}
        self._feature_flags: dict[str, bool] = {}
        self._timeouts: TimeoutConfig | None = None
        self._limits: LimitConfig | None = None

        # Load configurations
        self._load_model_configs()
        self._load_feature_flags()
        self._load_timeouts()
        self._load_limits()

    def _load_model_configs(self) -> None:
        """Load model configurations from environment and constants."""
        # Chat model
        self._model_configs[ModelType.CHAT] = ModelConfig(
            provider=os.getenv("A0_CHAT_MODEL_PROVIDER", Config.DEFAULT_CHAT_MODEL_PROVIDER),
            name=os.getenv("A0_CHAT_MODEL_NAME", Config.DEFAULT_CHAT_MODEL_NAME),
            api_base=os.getenv("A0_CHAT_MODEL_API_BASE") or None,
            ctx_length=int(
                os.getenv("A0_CHAT_MODEL_CTX_LENGTH", Limits.DEFAULT_CHAT_MODEL_CTX_LENGTH)
            ),
        )

        # Utility model
        self._model_configs[ModelType.UTILITY] = ModelConfig(
            provider=os.getenv("A0_UTIL_MODEL_PROVIDER", Config.DEFAULT_UTIL_MODEL_PROVIDER),
            name=os.getenv("A0_UTIL_MODEL_NAME", Config.DEFAULT_UTIL_MODEL_NAME),
            api_base=os.getenv("A0_UTIL_MODEL_API_BASE") or None,
            ctx_length=int(
                os.getenv("A0_UTIL_MODEL_CTX_LENGTH", Limits.DEFAULT_UTIL_MODEL_CTX_LENGTH)
            ),
        )

        # Embedding model
        self._model_configs[ModelType.EMBEDDING] = ModelConfig(
            provider=os.getenv("A0_EMBED_MODEL_PROVIDER", Config.DEFAULT_EMBED_MODEL_PROVIDER),
            name=os.getenv("A0_EMBED_MODEL_NAME", Config.DEFAULT_EMBED_MODEL_NAME),
            api_base=os.getenv("A0_EMBED_MODEL_API_BASE") or None,
        )

        # Browser model
        self._model_configs[ModelType.BROWSER] = ModelConfig(
            provider=os.getenv("A0_BROWSER_MODEL_PROVIDER", Config.DEFAULT_BROWSER_MODEL_PROVIDER),
            name=os.getenv("A0_BROWSER_MODEL_NAME", Config.DEFAULT_BROWSER_MODEL_NAME),
            api_base=os.getenv("A0_BROWSER_MODEL_API_BASE") or None,
        )

    def _load_feature_flags(self) -> None:
        """Load feature flags from environment."""
        self._feature_flags = {
            "memory_recall": os.getenv("A0_MEMORY_RECALL_ENABLED", "true").lower() == "true",
            "memory_memorize": os.getenv("A0_MEMORY_MEMORIZE_ENABLED", "true").lower() == "true",
            "memory_consolidation": os.getenv("A0_MEMORY_CONSOLIDATION_ENABLED", "true").lower()
            == "true",
            "mcp_server": os.getenv("A0_MCP_SERVER_ENABLED", "false").lower() == "true",
            "auto_update_check": os.getenv("A0_AUTO_UPDATE_CHECK", "true").lower() == "true",
        }

    def _load_timeouts(self) -> None:
        """Load timeout configuration."""
        self._timeouts = TimeoutConfig(
            http_request=int(os.getenv("A0_TIMEOUT_HTTP_REQUEST", Timeouts.HTTP_CACHE_MAX_AGE)),
            code_execution=int(os.getenv("A0_TIMEOUT_CODE_EXEC", Timeouts.CODE_EXEC_MAX)),
            document_download=int(
                os.getenv("A0_TIMEOUT_DOC_DOWNLOAD", Timeouts.BROWSER_OPERATION_TIMEOUT)
            ),
            browser_operation=int(
                os.getenv("A0_TIMEOUT_BROWSER", Timeouts.BROWSER_OPERATION_TIMEOUT)
            ),
        )

    def _load_limits(self) -> None:
        """Load resource limit configuration."""
        self._limits = LimitConfig(
            max_file_size=int(os.getenv("A0_MAX_FILE_SIZE", Limits.FILE_READ_MAX_SIZE)),
            max_message_length=int(
                os.getenv("A0_MAX_MESSAGE_LENGTH", Limits.MESSAGE_TRUNCATE_THRESHOLD)
            ),
            max_memory_results=int(os.getenv("A0_MAX_MEMORY_RESULTS", Limits.MEMORY_DEFAULT_LIMIT)),
        )

    @overload
    def get_model(self, model_type: ModelType) -> ModelConfig: ...

    @overload
    def get_model(self, model_type: str) -> ModelConfig: ...

    def get_model(self, model_type: ModelType | str) -> ModelConfig:
        """Get configuration for a specific model type.

        Args:
            model_type: Type of model (chat, utility, embedding, browser)

        Returns:
            ModelConfig for the specified model type

        Raises:
            ConfigValidationError: If model type not found
        """
        if isinstance(model_type, str):
            try:
                model_type = ModelType(model_type.lower())
            except ValueError:
                raise ConfigValidationError(f"Unknown model type: {model_type}")

        if model_type not in self._model_configs:
            raise ConfigValidationError(f"Model configuration not found: {model_type}")

        return self._model_configs[model_type]

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature flag is enabled.

        Args:
            feature: Feature name (memory_recall, memory_memorize, etc.)

        Returns:
            True if feature is enabled, False otherwise
        """
        return self._feature_flags.get(feature, False)

    @property
    def timeouts(self) -> TimeoutConfig:
        """Get timeout configuration."""
        if self._timeouts is None:
            raise ConfigValidationError("Timeouts not initialized")
        return self._timeouts

    @property
    def limits(self) -> LimitConfig:
        """Get resource limit configuration."""
        if self._limits is None:
            raise ConfigValidationError("Limits not initialized")
        return self._limits

    def get_env(self, key: str, default: T | None = None) -> str | T:
        """Get environment variable with default.

        Args:
            key: Environment variable name
            default: Default value if not set

        Returns:
            Environment variable value or default
        """
        return os.getenv(key, default)  # type: ignore

    def validate(self) -> list[str]:
        """Validate all configuration settings.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate model configs
        for model_type, config in self._model_configs.items():
            try:
                # Re-validate by attempting to recreate
                ModelConfig(**config.__dict__)
            except ConfigValidationError as e:
                errors.append(f"{model_type.value}: {e}")

        # Validate timeouts are positive
        if self._timeouts:
            for field_name, value in self._timeouts.__dict__.items():
                if value <= 0:
                    errors.append(f"timeout.{field_name}: Must be positive, got {value}")

        # Validate limits are positive
        if self._limits:
            for field_name, value in self._limits.__dict__.items():
                if value <= 0:
                    errors.append(f"limit.{field_name}: Must be positive, got {value}")

        return errors


# Singleton instance for application-wide access
_config_manager: ConfigManager | None = None


def get_config() -> ConfigManager:
    """Get the singleton ConfigManager instance.

    Returns:
        ConfigManager singleton instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def reset_config() -> None:
    """Reset the singleton ConfigManager instance.

    Useful for testing or when configuration needs to be reloaded.
    """
    global _config_manager
    _config_manager = None
