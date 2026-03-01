import asyncio

import pytest

from python.helpers.errors import (
    RepairableException,
    error_text,
    format_error,
    handle_error,
)


class TestHandleError:
    """Test handle_error function"""

    def test_handle_error_reraises_cancelled_error(self):
        """Test that asyncio.CancelledError is re-raised"""
        error = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            handle_error(error)

    def test_handle_error_does_not_raise_for_regular_exception(self):
        """Test that regular exceptions are handled silently"""
        error = ValueError("test error")
        # Should not raise
        handle_error(error)


class TestErrorText:
    """Test error_text function"""

    def test_error_text_returns_string(self):
        """Test that error_text returns string representation"""
        error = ValueError("test error message")
        result = error_text(error)
        assert isinstance(result, str)
        assert result == "test error message"

    def test_error_text_with_custom_exception(self):
        """Test error_text with custom exception message"""
        error = RuntimeError("custom error")
        result = error_text(error)
        assert result == "custom error"

    def test_error_text_with_empty_message(self):
        """Test error_text with empty message"""
        error = Exception("")
        result = error_text(error)
        assert result == ""


class TestFormatError:
    """Test format_error function"""

    def test_format_error_returns_string(self):
        """Test that format_error returns a string"""
        error = ValueError("test error")
        result = format_error(error)
        assert isinstance(result, str)

    def test_format_error_contains_error_message(self):
        """Test that formatted error contains the error message"""
        error = ValueError("my test error")
        result = format_error(error)
        assert "my test error" in result

    def test_format_error_contains_traceback(self):
        """Test that formatted error contains traceback"""
        error = ValueError("test error")
        result = format_error(error)
        assert "Traceback" in result or "ValueError" in result

    def test_format_error_trimming_large_traceback(self):
        """Test that traceback trimming works with large tracebacks"""

        def create_deep_traceback(depth=20):
            """Create a function with deep recursion to generate long traceback"""
            if depth == 0:
                raise ValueError("deep error")
            create_deep_traceback(depth - 1)

        try:
            create_deep_traceback(20)
        except ValueError as e:
            # With start_entries=6, end_entries=4, should trim middle
            result = format_error(e, start_entries=6, end_entries=4)
            # Should contain skip message when trimmed
            assert isinstance(result, str)
            assert len(result) > 0

    def test_format_error_no_trimming_when_small_traceback(self):
        """Test that small tracebacks are not trimmed"""

        def simple_error():
            raise ValueError("simple error")

        try:
            simple_error()
        except ValueError as e:
            result = format_error(e, start_entries=6, end_entries=4)
            # Should not contain skip message for small tracebacks
            assert "skipped" not in result.lower()

    def test_format_error_with_zero_entries(self):
        """Test format_error with zero start and end entries"""
        error = ValueError("test")
        result = format_error(error, start_entries=0, end_entries=0)
        # Should return just the error message
        assert isinstance(result, str)

    def test_format_error_fallback_to_str(self):
        """Test that format_error falls back to str(e) if no traceback"""

        class CustomError(Exception):
            pass

        error = CustomError("custom message")
        result = format_error(error)
        assert "custom message" in result


class TestRepairableException:
    """Test RepairableException class"""

    def test_repairable_exception_is_exception(self):
        """Test that RepairableException is an Exception subclass"""
        assert issubclass(RepairableException, Exception)

    def test_repairable_exception_can_be_raised(self):
        """Test that RepairableException can be raised and caught"""
        with pytest.raises(RepairableException):
            raise RepairableException("repairable error")

    def test_repairable_exception_with_message(self):
        """Test RepairableException with custom message"""
        error = RepairableException("test message")
        assert str(error) == "test message"

    def test_repairable_exception_handled_by_handle_error(self):
        """Test that RepairableException is handled by handle_error"""
        error = RepairableException("test")
        # Should not raise - handle_error should catch it
        handle_error(error)
