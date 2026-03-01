"""Tests for timed_input.py helper module.

Tests cover the timeout_input function which provides cross-platform
timed user input functionality.
"""

from unittest.mock import patch

from python.helpers.constants import Timeouts
from python.helpers.timed_input import timeout_input


class TestTimeoutInput:
    """Test cases for timeout_input function."""

    def test_timeout_input_returns_user_input(self):
        """Test that timeout_input returns user input when provided within timeout."""
        mock_input = "test input"
        with patch("python.helpers.timed_input.inputimeout", return_value=mock_input):
            result = timeout_input("Enter value: ")
            assert result == mock_input

    def test_timeout_input_uses_default_timeout(self):
        """Test that timeout_input uses default timeout from constants."""
        with patch("python.helpers.timed_input.inputimeout", return_value="test") as mock_timeout:
            timeout_input("Enter value: ")
            call_kwargs = mock_timeout.call_args[1]
            assert call_kwargs["timeout"] == Timeouts.INPUT_DEFAULT_TIMEOUT

    def test_timeout_input_accepts_custom_timeout(self):
        """Test that timeout_input accepts custom timeout parameter."""
        custom_timeout = 5
        with patch("python.helpers.timed_input.inputimeout", return_value="test") as mock_timeout:
            timeout_input("Enter value: ", timeout=custom_timeout)
            call_kwargs = mock_timeout.call_args[1]
            assert call_kwargs["timeout"] == custom_timeout

    def test_timeout_input_passes_prompt_correctly(self):
        """Test that timeout_input passes prompt to inputimeout."""
        prompt = "Please enter your name: "
        with patch("python.helpers.timed_input.inputimeout", return_value="test") as mock_timeout:
            timeout_input(prompt)
            call_kwargs = mock_timeout.call_args[1]
            assert call_kwargs["prompt"] == prompt

    def test_timeout_input_with_empty_input(self):
        """Test that timeout_input handles empty string input correctly."""
        with patch("python.helpers.timed_input.inputimeout", return_value=""):
            result = timeout_input("Enter value: ")
            assert result == ""

    def test_timeout_input_with_special_characters(self):
        """Test that timeout_input handles special characters in input."""
        special_input = "Test!@#$%^&*()"
        with patch("python.helpers.timed_input.inputimeout", return_value=special_input):
            result = timeout_input("Enter value: ")
            assert result == special_input

    def test_timeout_input_with_unicode_characters(self):
        """Test that timeout_input handles unicode characters in input."""
        unicode_input = "Hello 世界 🌍"
        with patch("python.helpers.timed_input.inputimeout", return_value=unicode_input):
            result = timeout_input("Enter value: ")
            assert result == unicode_input

    def test_timeout_input_with_multiline_input(self):
        """Test that timeout_input handles multiline input correctly."""
        multiline_input = "Line 1\nLine 2\nLine 3"
        with patch("python.helpers.timed_input.inputimeout", return_value=multiline_input):
            result = timeout_input("Enter value: ")
            assert result == multiline_input
