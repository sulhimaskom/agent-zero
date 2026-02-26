"""
Tests for python/helpers/errors.py module.

Tests error handling utilities: error_text, format_error, handle_error,
and the RepairableException custom exception class.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.errors import (
    RepairableException,
    error_text,
    format_error,
    handle_error,
)


class TestErrorText:
    """Test error_text() function"""

    def test_error_text_with_simple_exception(self):
        """Test error_text returns string representation of exception"""
        e = ValueError("test error message")
        result = error_text(e)
        assert result == "test error message"

    def test_error_text_with_empty_message(self):
        """Test error_text with exception that has empty message"""
        e = ValueError("")
        result = error_text(e)
        assert result == ""

    def test_error_text_with_custom_exception(self):
        """Test error_text with custom exception class"""
        e = RepairableException("custom error")
        result = error_text(e)
        assert result == "custom error"


class TestFormatError:
    """Test format_error() function"""

    def test_format_error_with_simple_exception(self):
        """Test format_error returns formatted error with traceback"""
        e = ValueError("test error")
        result = format_error(e, start_entries=6, end_entries=4)

        assert "test error" in result
        assert "ValueError" in result

    def test_format_error_trimmed_traceback(self):
        """Test format_error trims traceback when many entries"""
        # Create exception with deep stack trace
        def deep_function():
            raise ValueError("deep error")

        def middle_function():
            deep_function()

        try:
            middle_function()
        except ValueError as e:
            result = format_error(e, start_entries=2, end_entries=2)
            # Should contain trimmed marker if there are many stack entries
            assert "ValueError" in result

    def test_format_error_with_zero_entries(self):
        """Test format_error with zero start and end entries"""
        e = ValueError("minimal error")
        result = format_error(e, start_entries=0, end_entries=0)
        # Should only contain the error message
        assert "minimal error" in result

    def test_format_error_preserves_message(self):
        """Test format_error preserves the error message"""
        e = RuntimeError("important error message")
        result = format_error(e)
        assert "important error message" in result


class TestHandleError:
    """Test handle_error() function"""

    def test_handle_error_re_raises_cancelled_error(self):
        """Test handle_error re-raises asyncio.CancelledError"""
        e = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            handle_error(e)

    def test_handle_error_does_not_raise_for_other_exceptions(self):
        """Test handle_error does not raise for regular exceptions"""
        e = ValueError("normal error")
        # Should not raise
        handle_error(e)

    def test_handle_error_with_type_error(self):
        """Test handle_error with TypeError"""
        e = TypeError("type mismatch")
        # Should not raise
        handle_error(e)


class TestRepairableException:
    """Test RepairableException custom exception class"""

    def test_repairable_exception_inherits_from_exception(self):
        """Test RepairableException inherits from Exception"""
        assert issubclass(RepairableException, Exception)

    def test_repairable_exception_can_be_raised(self):
        """Test RepairableException can be raised with message"""
        with pytest.raises(RepairableException) as exc_info:
            raise RepairableException("repairable error")

        assert str(exc_info.value) == "repairable error"

    def test_repairable_exception_can_hold_data(self):
        """Test RepairableException can hold additional data"""
        error = RepairableException("test message")
        assert error.args == ("test message",)

    def test_repairable_exception_with_no_message(self):
        """Test RepairableException with no message"""
        error = RepairableException()
        assert str(error) == ""
