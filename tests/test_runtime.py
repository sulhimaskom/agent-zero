"""Tests for runtime utilities.

Tests the runtime module for environment detection, argument handling,
port management, and platform detection.
"""

from unittest.mock import patch


class TestArgumentHandling:
    """Test get_arg and has_arg functions"""

    def setup_method(self):
        """Reset args before each test"""
        import python.helpers.runtime as runtime_module

        self._original_args = runtime_module.args.copy() if runtime_module.args else {}

    def teardown_method(self):
        """Restore original args after each test"""
        import python.helpers.runtime as runtime_module

        runtime_module.args = self._original_args.copy()

    def test_get_arg_existing(self):
        """Test get_arg returns value for existing argument"""
        from python.helpers.runtime import get_arg

        with patch("python.helpers.runtime.args", {"port": 5000, "host": "localhost"}):
            result = get_arg("port")
            assert result == 5000

    def test_get_arg_nonexistent(self):
        """Test get_arg returns None for nonexistent argument"""
        from python.helpers.runtime import get_arg

        with patch("python.helpers.runtime.args", {}):
            result = get_arg("nonexistent")
            assert result is None

    def test_get_arg_with_default(self):
        """Test get_arg returns None for nonexistent argument"""
        from python.helpers.runtime import get_arg

        with patch("python.helpers.runtime.args", {"existing": "value"}):
            result = get_arg("missing")
            assert result is None

    def test_has_arg_existing(self):
        """Test has_arg returns True for existing argument"""
        from python.helpers.runtime import has_arg

        with patch("python.helpers.runtime.args", {"port": 5000}):
            result = has_arg("port")
            assert result is True

    def test_has_arg_nonexistent(self):
        """Test has_arg returns False for nonexistent argument"""
        from python.helpers.runtime import has_arg

        with patch("python.helpers.runtime.args", {}):
            result = has_arg("nonexistent")
            assert result is False


class TestEnvironmentDetection:
    """Test is_dockerized and is_development functions"""

    def test_is_dockerized_true(self):
        """Test is_dockerized returns True when dockerized arg is set"""
        from python.helpers.runtime import is_dockerized

        with patch("python.helpers.runtime.args", {"dockerized": True}):
            result = is_dockerized()
            assert result is True

    def test_is_dockerized_false(self):
        """Test is_dockerized returns False when dockerized arg is not set"""
        from python.helpers.runtime import is_dockerized

        with patch("python.helpers.runtime.args", {}):
            result = is_dockerized()
            assert result is False

    def test_is_development_true(self):
        """Test is_development returns True when not dockerized"""
        from python.helpers.runtime import is_development

        with patch("python.helpers.runtime.args", {}):
            result = is_development()
            assert result is True

    def test_is_development_false(self):
        """Test is_development returns False when dockerized"""
        from python.helpers.runtime import is_development

        with patch("python.helpers.runtime.args", {"dockerized": True}):
            result = is_development()
            assert result is False


class TestURLGeneration:
    """Test get_local_url function"""

    def test_get_local_url_dockerized(self):
        """Test get_local_url returns host.docker.internal in docker"""
        from python.helpers.runtime import get_local_url

        with patch("python.helpers.runtime.is_dockerized", return_value=True):
            result = get_local_url()
            assert result == "host.docker.internal"

    def test_get_local_url_localhost(self):
        """Test get_local_url returns localhost when not dockerized"""
        from python.helpers.constants import Network
        from python.helpers.runtime import get_local_url

        with patch("python.helpers.runtime.is_dockerized", return_value=False):
            result = get_local_url()
            assert result == Network.DEFAULT_LOCALHOST


class TestRuntimeID:
    """Test get_runtime_id and get_persistent_id functions"""

    def test_get_runtime_id_returns_string(self):
        """Test get_runtime_id returns a hex string"""
        from python.helpers.runtime import get_runtime_id

        result = get_runtime_id()
        assert isinstance(result, str)
        assert len(result) == 16

    def test_get_runtime_id_is_hex(self):
        """Test get_runtime_id returns valid hex characters"""
        from python.helpers.runtime import get_runtime_id

        result = get_runtime_id()
        int(result, 16)

    def test_get_runtime_id_consistent(self):
        """Test get_runtime_id returns same ID on subsequent calls"""
        from python.helpers.runtime import get_runtime_id

        id1 = get_runtime_id()
        id2 = get_runtime_id()
        assert id1 == id2


class TestPortManagement:
    """Test get_web_ui_port and get_tunnel_api_port functions"""

    @patch("python.helpers.runtime.get_arg")
    def test_get_web_ui_port_from_arg(self, mock_get_arg):
        """Test get_web_ui_port returns value from args"""
        from python.helpers.runtime import get_web_ui_port

        mock_get_arg.return_value = 8080
        with patch("python.helpers.runtime.get_arg", return_value=8080):
            result = get_web_ui_port()
            assert result == 8080

    @patch("python.helpers.runtime.get_arg")
    def test_get_web_ui_port_default(self, mock_get_arg):
        """Test get_web_ui_port returns default when no arg set"""
        from python.helpers.constants import Network
        from python.helpers.runtime import get_web_ui_port

        with patch("python.helpers.runtime.get_arg", return_value=None), \
             patch("python.helpers.runtime.dotenv.get_dotenv_value", return_value="0"):
            result = get_web_ui_port()
            assert result == Network.WEB_UI_PORT_DEFAULT

    @patch("python.helpers.runtime.get_arg")
    def test_get_tunnel_api_port_from_arg(self, mock_get_arg):
        """Test get_tunnel_api_port returns value from args"""
        from python.helpers.runtime import get_tunnel_api_port

        mock_get_arg.return_value = 9090
        with patch("python.helpers.runtime.get_arg", return_value=9090):
            result = get_tunnel_api_port()
            assert result == 9090


class TestPlatformDetection:
    """Test get_platform, is_windows, and get_terminal_executable functions"""

    def test_get_platform_returns_string(self):
        """Test get_platform returns a string"""
        from python.helpers.runtime import get_platform

        result = get_platform()
        assert isinstance(result, str)

    @patch("sys.platform", "win32")
    def test_is_windows_true(self):
        """Test is_windows returns True on Windows"""
        import importlib

        import python.helpers.runtime
        importlib.reload(python.helpers.runtime)

        result = python.helpers.runtime.is_windows()
        assert result is True

    @patch("sys.platform", "linux")
    def test_is_windows_false(self):
        """Test is_windows returns False on Linux"""
        import importlib

        import python.helpers.runtime
        importlib.reload(python.helpers.runtime)

        result = python.helpers.runtime.is_windows()
        assert result is False

    @patch("sys.platform", "darwin")
    def test_is_windows_false_macos(self):
        """Test is_windows returns False on macOS"""
        import importlib

        import python.helpers.runtime
        importlib.reload(python.helpers.runtime)

        result = python.helpers.runtime.is_windows()
        assert result is False


class TestTerminalExecutable:
    """Test get_terminal_executable function"""

    @patch("python.helpers.runtime.is_windows")
    def test_get_terminal_executable_powershell(self, mock_is_windows):
        """Test get_terminal_executable returns PowerShell on Windows"""
        from python.helpers.constants import Shell
        from python.helpers.runtime import get_terminal_executable

        mock_is_windows.return_value = True
        result = get_terminal_executable()
        assert result == Shell.SHELL_POWERSHELL

    @patch("python.helpers.runtime.is_windows")
    def test_get_terminal_executable_bash(self, mock_is_windows):
        """Test get_terminal_executable returns Bash on non-Windows"""
        from python.helpers.constants import Shell
        from python.helpers.runtime import get_terminal_executable

        mock_is_windows.return_value = False
        result = get_terminal_executable()
        assert result == Shell.SHELL_BASH
