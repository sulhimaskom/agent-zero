"""Configuration validation system for Agent Zero.

Centralizes configuration validation to provide a single source of truth
and clear error messages for configuration issues.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ValidationLevel(Enum):
    """Validation severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """A single validation issue."""

    field: str
    message: str
    level: ValidationLevel
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "message": self.message,
            "level": self.level.value,
            "suggestion": self.suggestion,
        }


@dataclass
class ValidationResult:
    """Result of configuration validation."""

    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    config_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.level == ValidationLevel.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.level == ValidationLevel.WARNING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [i.to_dict() for i in self.issues],
            "config_summary": self.config_summary,
        }


class ConfigValidator:
    """Validates Agent Zero configuration."""

    # Required environment variables
    REQUIRED_VARS: list[str] = []

    # Optional but recommended variables
    RECOMMENDED_VARS: list[str] = [
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
    ]

    # Sensitive variables that should not be logged
    SENSITIVE_VARS: set[str] = {
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "COHERE_API_KEY",
        "DEEPSEEK_API_KEY",
        "MISTRAL_API_KEY",
        "GROQ_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_API_KEY",
        "API_KEY",
        "SECRET_KEY",
        "PASSWORD",
        "TOKEN",
    }

    # Valid log levels
    VALID_LOG_LEVELS: set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    # Valid model providers (from typical config)
    VALID_PROVIDERS: set[str] = {
        "openai",
        "anthropic",
        "openrouter",
        "ollama",
        "gemini",
        "groq",
        "azure",
        "cohere",
        "deepseek",
        "mistral",
    }

    def __init__(self):
        self.issues: list[ValidationIssue] = []

    def validate_all(self) -> ValidationResult:
        """Run all validation checks.

        Returns:
            ValidationResult with all issues found
        """
        self.issues = []

        self._validate_environment_variables()
        self._validate_api_keys()
        self._validate_paths()
        self._validate_settings()

        config_summary = self._generate_config_summary()

        return ValidationResult(
            valid=self.error_count == 0, issues=self.issues, config_summary=config_summary
        )

    def validate_environment(self) -> ValidationResult:
        """Validate environment variables only.

        Returns:
            ValidationResult for environment config
        """
        self.issues = []
        self._validate_environment_variables()

        return ValidationResult(
            valid=self.error_count == 0,
            issues=self.issues,
            config_summary={"source": "environment"},
        )

    def validate_api_config(self) -> ValidationResult:
        """Validate API configuration.

        Returns:
            ValidationResult for API config
        """
        self.issues = []
        self._validate_api_keys()

        return ValidationResult(
            valid=self.error_count == 0, issues=self.issues, config_summary={"source": "api_config"}
        )

    def _validate_environment_variables(self) -> None:
        """Check environment variables."""
        # Check required variables
        for var in self.REQUIRED_VARS:
            if not os.environ.get(var):
                self.issues.append(
                    ValidationIssue(
                        field=var,
                        message=f"Required environment variable '{var}' is not set",
                        level=ValidationLevel.ERROR,
                        suggestion=f"Set {var} in your .env file or environment",
                    )
                )

        # Check recommended variables
        api_key_found = False
        for var in self.RECOMMENDED_VARS:
            if os.environ.get(var):
                api_key_found = True
                break

        if not api_key_found:
            self.issues.append(
                ValidationIssue(
                    field="API_KEY",
                    message="No LLM API key found in environment",
                    level=ValidationLevel.WARNING,
                    suggestion="Set at least one API key (OPENROUTER_API_KEY, OPENAI_API_KEY, etc.)",
                )
            )

    def _validate_api_keys(self) -> None:
        """Validate API key formats."""
        key_patterns = {
            "OPENAI_API_KEY": r"^sk-[a-zA-Z0-9]{48}$",
            "ANTHROPIC_API_KEY": r"^sk-ant-[a-zA-Z0-9]{32,}$",
        }

        for var, pattern in key_patterns.items():
            value = os.environ.get(var)
            if value and not re.match(pattern, value):
                self.issues.append(
                    ValidationIssue(
                        field=var,
                        message=f"{var} appears to have an invalid format",
                        level=ValidationLevel.WARNING,
                        suggestion=f"Verify your {var} is correct",
                    )
                )

    def _validate_paths(self) -> None:
        """Validate important paths exist."""
        paths_to_check = [
            ("prompts", "Prompts directory"),
            ("python/tools", "Tools directory"),
            ("python/helpers", "Helpers directory"),
        ]

        for path, description in paths_to_check:
            if not os.path.exists(path):
                self.issues.append(
                    ValidationIssue(
                        field=f"path:{path}",
                        message=f"{description} not found at '{path}'",
                        level=ValidationLevel.ERROR,
                        suggestion=f"Ensure '{path}' exists in your installation",
                    )
                )

    def _validate_settings(self) -> None:
        """Validate settings from environment."""
        # Check log level if set
        log_level = os.environ.get("LOG_LEVEL", "").upper()
        if log_level and log_level not in self.VALID_LOG_LEVELS:
            self.issues.append(
                ValidationIssue(
                    field="LOG_LEVEL",
                    message=f"Invalid log level: {log_level}",
                    level=ValidationLevel.WARNING,
                    suggestion=f"Use one of: {', '.join(self.VALID_LOG_LEVELS)}",
                )
            )

    def _generate_config_summary(self) -> dict[str, Any]:
        """Generate a safe summary of configuration."""
        summary: dict[str, Any] = {
            "environment": {},
            "api_configured": False,
        }

        # Check which API keys are configured (without exposing values)
        for var in self.RECOMMENDED_VARS:
            if os.environ.get(var):
                summary["api_configured"] = True
                summary["environment"][var] = "[CONFIGURED]"
            else:
                summary["environment"][var] = "[NOT SET]"

        # Add other non-sensitive env vars
        for key, value in os.environ.items():
            if key not in self.SENSITIVE_VARS and not any(
                s in key.lower() for s in ["key", "secret", "token", "password"]
            ):
                if key.startswith(("AGENT_ZERO", "A0", "APP_")):
                    summary["environment"][key] = value

        return summary

    @property
    def error_count(self) -> int:
        """Number of validation errors."""
        return sum(1 for i in self.issues if i.level == ValidationLevel.ERROR)

    @property
    def warning_count(self) -> int:
        """Number of validation warnings."""
        return sum(1 for i in self.issues if i.level == ValidationLevel.WARNING)

    @staticmethod
    def is_sensitive_key(key: str) -> bool:
        """Check if a key contains sensitive data.

        Args:
            key: Environment variable name

        Returns:
            True if key should be treated as sensitive
        """
        key_upper = key.upper()
        return key_upper in ConfigValidator.SENSITIVE_VARS or any(
            s in key_upper for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "API_KEY"]
        )


# Global validator instance
_validator: ConfigValidator | None = None


def get_validator() -> ConfigValidator:
    """Get or create global validator instance.

    Returns:
        ConfigValidator singleton
    """
    global _validator
    if _validator is None:
        _validator = ConfigValidator()
    return _validator


def validate_config() -> ValidationResult:
    """Quick validation using global validator.

    Returns:
        ValidationResult
    """
    return get_validator().validate_all()
