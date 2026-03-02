"""Tests for shell_local.py - LocalInteractiveSession.

Tests the LocalInteractiveSession class for local TTY shell sessions,
including connection, command sending, and output reading.
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mock tty_session at module level before importing shell_local
# to avoid stdin errors in tests (tty_session tries to configure stdin on import)
_tty_session_mock = MagicMock()
sys.modules["python.helpers.tty_session"] = _tty_session_mock

from python.helpers.shell_local import LocalInteractiveSession  # noqa: E402


class TestLocalInteractiveSessionInit:
    """Test LocalInteractiveSession initialization"""

    def test_default_initialization(self):
        """Test default initialization with no arguments"""
        session = LocalInteractiveSession()
        assert session.session is None
        assert session.full_output == ""
        assert session.cwd is None

    def test_initialization_with_cwd(self):
        """Test initialization with custom working directory"""
        session = LocalInteractiveSession(cwd="/home/user")
        assert session.cwd == "/home/user"
        assert session.session is None
        assert session.full_output == ""

    def test_initialization_with_none_cwd(self):
        """Test initialization with explicit None cwd"""
        session = LocalInteractiveSession(cwd=None)
        assert session.cwd is None


class TestLocalInteractiveSessionConnect:
    """Test LocalInteractiveSession.connect() method"""

    @pytest.mark.asyncio
    async def test_connect_creates_session(self):
        """Test that connect creates a TTY session"""
        session = LocalInteractiveSession()

        with patch("python.helpers.shell_local.runtime") as mock_runtime, \
             patch("python.helpers.shell_local.tty_session") as mock_tty_session:
            
            mock_runtime.get_terminal_executable.return_value = "/bin/bash"
            mock_tty_session.TTYSession.return_value = MagicMock()
            mock_tty_session.TTYSession.return_value.start = AsyncMock()
            mock_tty_session.TTYSession.return_value.read_full_until_idle = AsyncMock(
                return_value=""
            )

            await session.connect()

            mock_runtime.get_terminal_executable.assert_called_once()
            mock_tty_session.TTYSession.assert_called_once_with(
                "/bin/bash", cwd=None
            )
            mock_tty_session.TTYSession.return_value.start.assert_called_once()
            assert session.session is not None

    @pytest.mark.asyncio
    async def test_connect_with_cwd(self):
        """Test that connect uses custom cwd"""
        session = LocalInteractiveSession(cwd="/home/user")

        with patch("python.helpers.shell_local.runtime") as mock_runtime, \
             patch("python.helpers.shell_local.tty_session") as mock_tty_session:
            
            mock_runtime.get_terminal_executable.return_value = "/bin/bash"
            mock_tty_session.TTYSession.return_value = MagicMock()
            mock_tty_session.TTYSession.return_value.start = AsyncMock()
            mock_tty_session.TTYSession.return_value.read_full_until_idle = AsyncMock(
                return_value=""
            )

            await session.connect()

            mock_tty_session.TTYSession.assert_called_once_with(
                "/bin/bash", cwd="/home/user"
            )

    @pytest.mark.asyncio
    async def test_connect_reads_until_idle(self):
        """Test that connect reads until idle after starting"""
        session = LocalInteractiveSession()
        mock_session = MagicMock()
        mock_session.start = AsyncMock()
        mock_session.read_full_until_idle = AsyncMock(return_value="welcome message")

        with patch("python.helpers.shell_local.runtime") as mock_runtime, \
             patch("python.helpers.shell_local.tty_session") as mock_tty_session:
            
            mock_runtime.get_terminal_executable.return_value = "/bin/bash"
            mock_tty_session.TTYSession.return_value = mock_session

            await session.connect()

            mock_session.read_full_until_idle.assert_called_once()


class TestLocalInteractiveSessionClose:
    """Test LocalInteractiveSession.close() method"""

    @pytest.mark.asyncio
    async def test_close_kills_session(self):
        """Test that close kills the session"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.kill = MagicMock()

        await session.close()

        session.session.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self):
        """Test that close works when session is None"""
        session = LocalInteractiveSession()

        # Should not raise any exception
        await session.close()

        assert session.session is None


class TestLocalInteractiveSessionSendCommand:
    """Test LocalInteractiveSession.send_command() method"""

    @pytest.mark.asyncio
    async def test_send_command_success(self):
        """Test sending a command"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.sendline = AsyncMock()

        await session.send_command("ls -la")

        session.session.sendline.assert_called_once_with("ls -la")
        assert session.full_output == ""

    @pytest.mark.asyncio
    async def test_send_command_resets_output(self):
        """Test that send_command resets full_output"""
        session = LocalInteractiveSession()
        session.full_output = "previous output"
        session.session = MagicMock()
        session.session.sendline = AsyncMock()

        await session.send_command("pwd")

        assert session.full_output == ""

    @pytest.mark.asyncio
    async def test_send_command_raises_when_not_connected(self):
        """Test that send_command raises ConnectionError when not connected"""
        session = LocalInteractiveSession()

        with pytest.raises(ConnectionError, match="Shell not connected"):
            await session.send_command("ls")


class TestLocalInteractiveSessionReadOutput:
    """Test LocalInteractiveSession.read_output() method"""

    @pytest.mark.asyncio
    async def test_read_output_returns_cleaned_output(self):
        """Test that read_output returns cleaned output"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.read_full_until_idle = AsyncMock(
            return_value="raw \x1b[31moutput\x1b[0m"
        )

        full_output, partial = await session.read_output(timeout=1.0)

        assert "raw output" in full_output
        assert "\x1b[" not in full_output  # ANSI codes removed

    @pytest.mark.asyncio
    async def test_read_output_returns_partial(self):
        """Test that read_output returns partial output"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.read_full_until_idle = AsyncMock(return_value="new output")

        full_output, partial = await session.read_output(timeout=1.0)

        assert partial == "new output"

    @pytest.mark.asyncio
    async def test_read_output_returns_none_when_empty(self):
        """Test that read_output returns None for partial when no new output"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.read_full_until_idle = AsyncMock(return_value="")

        full_output, partial = await session.read_output(timeout=1.0)

        assert partial is None

    @pytest.mark.asyncio
    async def test_read_output_accumulates_full_output(self):
        """Test that full_output accumulates across calls"""
        session = LocalInteractiveSession()
        session.session = MagicMock()
        session.session.read_full_until_idle = AsyncMock(side_effect=["first", "second"])

        await session.read_output(timeout=1.0)
        await session.read_output(timeout=1.0)

        assert "first" in session.full_output
        assert "second" in session.full_output

    @pytest.mark.asyncio
    async def test_read_output_reset_full_output(self):
        """Test that read_output can reset full_output"""
        session = LocalInteractiveSession()
        session.full_output = "old output"
        session.session = MagicMock()
        session.session.read_full_until_idle = AsyncMock(return_value="new")

        full_output, partial = await session.read_output(
            timeout=1.0, reset_full_output=True
        )

        assert session.full_output == "new"

    @pytest.mark.asyncio
    async def test_read_output_raises_when_not_connected(self):
        """Test that read_output raises ConnectionError when not connected"""
        session = LocalInteractiveSession()

        with pytest.raises(ConnectionError, match="Shell not connected"):
            await session.read_output(timeout=1.0)


class TestLocalInteractiveSessionIntegration:
    """Integration tests for LocalInteractiveSession"""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete workflow: connect, send command, read output, close"""
        session = LocalInteractiveSession(cwd="/home/user")
        
        mock_session = MagicMock()
        mock_session.start = AsyncMock()
        mock_session.read_full_until_idle = AsyncMock(return_value="welcome")
        mock_session.sendline = AsyncMock()
        mock_session.kill = MagicMock()

        with patch("python.helpers.shell_local.runtime") as mock_runtime, \
             patch("python.helpers.shell_local.tty_session") as mock_tty_session:
            
            mock_runtime.get_terminal_executable.return_value = "/bin/bash"
            mock_tty_session.TTYSession.return_value = mock_session

            # Connect
            await session.connect()
            assert session.session is not None

            # Send command
            await session.send_command("echo hello")
            mock_session.sendline.assert_called_once_with("echo hello")

            # Read output
            mock_session.read_full_until_idle = AsyncMock(return_value="hello\n")
            full, partial = await session.read_output(timeout=1.0)
            assert "hello" in full

            # Close
            await session.close()
            mock_session.kill.assert_called_once()
