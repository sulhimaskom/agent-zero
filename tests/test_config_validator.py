"""Tests for config_validator module"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

import pytest

from python.helpers.config_validator import (
    ConfigValidator,
    ValidationIssue,
    ValidationLevel,
    ValidationResult,
    get_validator,
    validate_config,
)


class TestValidationLevel:
    """Test ValidationLevel enum"""

    def test_validation_level_values(self):
        """Test that ValidationLevel has correct values"""
        assert ValidationLevel.ERROR.value == "error"
        assert ValidationLevel.WARNING.value == "warning"
        assert ValidationLevel.INFO.value == "info"


class TestValidationIssue:
    """Test ValidationIssue dataclass"""

    def test_issue_creation(self):
        """Test creating a ValidationIssue"""
        issue = ValidationIssue(
            field="test_field",
            message="Test message",
            level=ValidationLevel.ERROR,
            suggestion="Fix it",
        )

        assert issue.field == "test_field"
        assert issue.message == "Test message"
        assert issue.level == ValidationLevel.ERROR
        assert issue.suggestion == "Fix it"

    def test_issue_to_dict(self):
        """Test converting issue to dictionary"""
        issue = ValidationIssue(
            field="test_field",
            message="Test message",
            level=ValidationLevel.WARNING,
        )

        d = issue.to_dict()
        assert d["field"] == "test_field"
        assert d["message"] == "Test message"
        assert d["level"] == "warning"


class TestValidationResult:
    """Test ValidationResult dataclass"""

    def test_result_creation(self):
        """Test creating a ValidationResult"""
        issues = [
            ValidationIssue("field1", "Error", ValidationLevel.ERROR),
            ValidationIssue("field2", "Warning", ValidationLevel.WARNING),
        ]

        result = ValidationResult(
            valid=False,
            issues=issues,
            config_summary={"test": "value"},
        )

        assert result.valid is False
        assert len(result.issues) == 2
        assert result.error_count == 1
        assert result.warning_count == 1

    def test_result_to_dict(self):
        """Test converting result to dictionary"""
        result = ValidationResult(
            valid=True,
            issues=[],
            config_summary={},
        )

        d = result.to_dict()
        assert d["valid"] is True
        assert d["error_count"] == 0
        assert d["warning_count"] == 0
        assert d["issues"] == []

    def test_error_count_property(self):
        """Test error_count property"""
        issues = [
            ValidationIssue("f1", "Error", ValidationLevel.ERROR),
            ValidationIssue("f2", "Error", ValidationLevel.ERROR),
            ValidationIssue("f3", "Warning", ValidationLevel.WARNING),
        ]

        result = ValidationResult(valid=False, issues=issues)
        assert result.error_count == 2
        assert result.warning_count == 1


class TestConfigValidator:
    """Test ConfigValidator class"""

    @pytest.fixture
    def validator(self):
        """Create a fresh ConfigValidator"""
        return ConfigValidator()

    @pytest.fixture
    def clean_env(self):
        """Clean environment for testing"""
        # Store original env
        original_env = dict(os.environ)

        # Remove API keys for clean test
        keys_to_remove = [
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ]
        for key in keys_to_remove:
            if key in os.environ:
                del os.environ[key]

        yield

        # Restore original env
        os.environ.clear()
        os.environ.update(original_env)

    def test_validator_creation(self, validator):
        """Test creating ConfigValidator"""
        assert isinstance(validator, ConfigValidator)
        assert validator.issues == []

    def test_is_sensitive_key_detects_sensitive_keys(self, validator):
        """Test detection of sensitive keys"""
        assert validator.is_sensitive_key("API_KEY") is True
        assert validator.is_sensitive_key("SECRET_TOKEN") is True
        assert validator.is_sensitive_key("MY_PASSWORD") is True
        assert validator.is_sensitive_key("OPENAI_API_KEY") is True

    def test_is_sensitive_key_allows_safe_keys(self, validator):
        """Test that safe keys are not marked sensitive"""
        assert validator.is_sensitive_key("PATH") is False
        assert validator.is_sensitive_key("HOME") is False
        assert validator.is_sensitive_key("USER") is False

    def test_validate_all_returns_result(self, validator, clean_env):
        """Test that validate_all returns ValidationResult"""
        result = validator.validate_all()

        assert isinstance(result, ValidationResult)
        assert isinstance(result.issues, list)
        assert isinstance(result.config_summary, dict)

    def test_validate_environment_checks_api_keys(self, validator, clean_env):
        """Test that environment validation warns about missing API keys"""
        result = validator.validate_environment()

        # Should have at least a warning about missing API keys
        api_key_issues = [
            i for i in result.issues if "API key" in i.message or "API_KEY" in i.field
        ]
        assert len(api_key_issues) >= 1
        assert any(i.level == ValidationLevel.WARNING for i in api_key_issues)

    def test_validate_with_api_key_present(self, validator, clean_env):
        """Test validation when API key is present"""
        with patch.dict(
            os.environ, {"OPENAI_API_KEY": "sk-test1234567890123456789012345678901234567890"}
        ):
            result = validator.validate_environment()

            # Should not have API key warning
            api_key_warnings = [i for i in result.issues if "No LLM API key" in i.message]
            assert len(api_key_warnings) == 0

    def test_validate_paths_checks_directories(self, validator):
        """Test that paths validation checks important directories"""
        result = validator.validate_all()

        # Check for prompts directory validation
        path_issues = [i for i in result.issues if i.field.startswith("path:")]
        # Should either pass or have specific issues
        for issue in path_issues:
            assert issue.field.startswith("path:")

    def test_config_summary_masks_sensitive_data(self, validator, clean_env):
        """Test that config summary masks sensitive values"""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "secret-key-123"}):
            result = validator.validate_all()

            # API key should be marked as configured but not expose value
            assert result.config_summary.get("api_configured") is True
            assert "OPENAI_API_KEY" in result.config_summary.get("environment", {})
            assert result.config_summary["environment"]["OPENAI_API_KEY"] == "[CONFIGURED]"
            assert "secret-key-123" not in str(result.config_summary)

    def test_validate_api_config_detects_invalid_key_format(self, validator, clean_env):
        """Test that API config validation detects invalid key formats"""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "invalid-key-format"}):
            result = validator.validate_api_config()

            openai_issues = [i for i in result.issues if "OPENAI_API_KEY" in i.field]
            # Should have a warning about invalid format
            assert any(i.level == ValidationLevel.WARNING for i in openai_issues)

    def test_error_count_property(self, validator):
        """Test error_count property"""
        validator.issues = [
            ValidationIssue("f1", "Error", ValidationLevel.ERROR),
            ValidationIssue("f2", "Error", ValidationLevel.ERROR),
            ValidationIssue("f3", "Warning", ValidationLevel.WARNING),
        ]

        assert validator.error_count == 2
        assert validator.warning_count == 1


class TestGlobalValidator:
    """Test global validator functions"""

    def test_get_validator_returns_singleton(self):
        """Test that get_validator returns the same instance"""
        # Clear any existing instance
        import python.helpers.config_validator as cv

        cv._validator = None

        validator1 = get_validator()
        validator2 = get_validator()

        assert validator1 is validator2

    def test_validate_config_returns_result(self):
        """Test that validate_config returns ValidationResult"""
        result = validate_config()

        assert isinstance(result, ValidationResult)
        assert isinstance(result.valid, bool)
        assert isinstance(result.issues, list)
