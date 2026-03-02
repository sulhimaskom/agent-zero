"""Tests for shell SSH utilities.

Tests the clean_string function for ANSI escape code removal,
null byte handling, and whitespace normalization.
"""

from python.helpers.shell_ssh import clean_string


class TestCleanStringAnsiRemoval:
    """Test ANSI escape code removal"""

    def test_remove_ansi_escape_codes(self):
        """Test that ANSI escape codes are removed"""
        input_str = "\x1b[31mred text\x1b[0m"
        result = clean_string(input_str)
        assert result == "red text"

    def test_remove_multiple_ansi_codes(self):
        """Test removal of multiple ANSI codes"""
        input_str = "\x1b[1m\x1b[4m\x1b[31mbold underlined red\x1b[0m"
        result = clean_string(input_str)
        assert result == "bold underlined red"

    def test_remove_ansi_cursor_movement(self):
        """Test removal of cursor movement escape sequences"""
        input_str = "\x1b[2J\x1b[HHello"
        result = clean_string(input_str)
        assert result == "Hello"

    def test_preserve_text_without_ansi(self):
        """Test that text without ANSI codes is preserved"""
        input_str = "plain text"
        result = clean_string(input_str)
        assert result == "plain text"

    def test_empty_string(self):
        """Test empty string handling"""
        result = clean_string("")
        assert result == ""


class TestCleanStringNullBytes:
    """Test null byte removal"""

    def test_remove_null_bytes(self):
        """Test that null bytes are removed"""
        input_str = "hello\x00world"
        result = clean_string(input_str)
        assert result == "helloworld"

    def test_multiple_null_bytes(self):
        """Test removal of multiple null bytes"""
        input_str = "\x00hello\x00world\x00"
        result = clean_string(input_str)
        assert result == "helloworld"

    def test_null_bytes_with_ansi(self):
        """Test null bytes mixed with ANSI codes"""
        input_str = "\x1b[31m\x00red\x00\x1b[0m"
        result = clean_string(input_str)
        assert result == "red"


class TestCleanStringWhitespace:
    """Test whitespace normalization"""

    def test_normalize_crlf_to_lf(self):
        """Test CRLF to LF conversion"""
        input_str = "line1\r\nline2\r\nline3"
        result = clean_string(input_str)
        assert result == "line1\nline2\nline3"

    def test_remove_carriage_returns(self):
        """Test carriage return handling"""
        input_str = "line1\rline2\rline3"
        result = clean_string(input_str)
        # Last part after \r should be kept
        assert "line3" in result

    def test_leading_whitespace_removal(self):
        """Test leading whitespace removal"""
        input_str = "   \r  leading spaces"
        result = clean_string(input_str)
        assert result.startswith("leading")

    def test_trailing_whitespace_removal(self):
        """Test trailing whitespace removal"""
        input_str = "trailing spaces   "
        result = clean_string(input_str)
        assert result.endswith("trailing spaces")


class TestCleanStringIpython:
    """Test IPython-specific cleaning"""

    def test_remove_ipython_prompt(self):
        """Test IPython prompt removal"""
        input_str = "\r\r\n> print('hello')"
        result = clean_string(input_str)
        assert result == "print('hello')"

    def test_remove_multiple_ipython_prompts(self):
        """Test removal of multiple IPython prompts"""
        input_str = "   \r\r\n> \r\n> > second prompt"
        result = clean_string(input_str)
        assert "second prompt" in result

    def test_partial_gt_prompt_handling(self):
        """Test that some gt prompts may remain"""
        input_str = "> first\n> second\n> third"
        result = clean_string(input_str)
        # The function handles some patterns but not all
        assert "first" in result
        assert "third" in result


class TestCleanStringIntegration:
    """Integration tests for clean_string"""

    def test_complex_mixed_input(self):
        """Test complex input with ANSI, null bytes, and whitespace"""
        input_str = "\x1b[32m\x00success\x1b[0m\r\n> done"
        result = clean_string(input_str)
        assert "success" in result
        assert "done" in result

    def test_shell_output_simulation(self):
        """Test simulated shell output"""
        input_str = "\x1b[0m\x1b[27m\x1b[24m\x1b[22m$ ls -la\r\ntotal 24\r\ndrwxr-xr-x  5 user  4096 Jan 15 10:30 .\x1b[0m"
        result = clean_string(input_str)
        assert "$ ls -la" in result
        assert "total 24" in result

    def test_preserve_chinese_characters(self):
        """Test that unicode characters are preserved"""
        input_str = "你好世界"
        result = clean_string(input_str)
        assert result == "你好世界"

    def test_preserve_emoji(self):
        """Test that emoji are preserved"""
        input_str = "Hello 👋 World 🌍"
        result = clean_string(input_str)
        assert result == "Hello 👋 World 🌍"


class TestSSHInteractiveSession:
    """Tests for SSHInteractiveSession class"""

    def test_client_initialization_with_security_settings(self):
        """Test that SSH client is properly initialized with RejectPolicy"""
        import unittest.mock as mock

        with mock.patch("paramiko.SSHClient") as mock_ssh_client:
            mock_client_instance = mock.MagicMock()
            mock_ssh_client.return_value = mock_client_instance

            from python.helpers.shell_ssh import SSHInteractiveSession
            from python.helpers.log import Log

            mock_logger = mock.MagicMock(spec=Log)

            session = SSHInteractiveSession(
                logger=mock_logger,
                hostname="test.example.com",
                port=22,
                username="testuser",
                password="testpass",
            )

            mock_ssh_client.assert_called_once()
            mock_client_instance.load_system_host_keys.assert_called_once()
            mock_client_instance.set_missing_host_key_policy.assert_called_once()

            policy_call = mock_client_instance.set_missing_host_key_policy.call_args
            policy = policy_call[0][0]
            assert policy.__class__.__name__ == "RejectPolicy"
