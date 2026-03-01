import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from python.helpers import playwright
from python.helpers.constants import Paths


class TestGetPlaywrightCacheDir:
    """Test playwright.get_playwright_cache_dir() function"""

    def test_returns_path_from_files_helper(self):
        """Test that get_playwright_cache_dir uses files helper"""
        with patch("python.helpers.playwright.files.get_abs_path") as mock_get_path:
            mock_get_path.return_value = "/test/playwright"
            
            result = playwright.get_playwright_cache_dir()
            
            mock_get_path.assert_called_once_with(Paths.PLAYWRIGHT_DIR)
            assert result == "/test/playwright"


class TestGetPlaywrightBinary:
    """Test playwright.get_playwright_binary() function"""

    @patch("python.helpers.playwright.get_playwright_cache_dir")
    def test_returns_binary_when_found(self, mock_cache_dir):
        """Test that binary path is returned when found"""
        mock_cache_dir.return_value = "/test/playwright"
        
        # Create mock path objects for glob results
        mock_binary = MagicMock(spec=Path)
        mock_binary.__str__ = lambda self: "/test/playwright/chromium_headless_shell-123/chrome-456/headless_shell"
        
        with patch("pathlib.Path.glob") as mock_glob:
            # First pattern returns a binary
            mock_glob.return_value = iter([mock_binary])
            
            result = playwright.get_playwright_binary()
            
        assert result is not None

    @patch("python.helpers.playwright.get_playwright_cache_dir")
    def test_returns_none_when_not_found(self, mock_cache_dir):
        """Test that None is returned when no binary found"""
        mock_cache_dir.return_value = "/test/playwright"
        
        with patch("pathlib.Path.glob") as mock_glob:
            # Empty results for both patterns
            mock_glob.return_value = iter([])
            
            result = playwright.get_playwright_binary()
            
        assert result is None

    @patch("python.helpers.playwright.get_playwright_cache_dir")
    def test_checks_all_patterns(self, mock_cache_dir):
        """Test that all glob patterns are checked"""
        mock_cache_dir.return_value = "/test/playwright"
        
        mock_binary = MagicMock(spec=Path)
        
        with patch("pathlib.Path.glob") as mock_glob:
            # First pattern returns None, second returns binary
            mock_glob.side_effect = [
                iter([]),  # First pattern (chromium_headless_shell-*/.../headless_shell)
                iter([mock_binary])  # Second pattern (with .exe)
            ]
            
            result = playwright.get_playwright_binary()
            
        # glob should have been called twice (both patterns)
        assert mock_glob.call_count == 2

    @patch("python.helpers.playwright.get_playwright_cache_dir")
    def test_prefers_first_pattern_match(self, mock_cache_dir):
        """Test that first pattern match is returned"""
        mock_cache_dir.return_value = "/test/playwright"
        
        mock_binary1 = MagicMock(spec=Path)
        mock_binary1.__str__ = lambda self: "/test/binary1"
        
        mock_binary2 = MagicMock(spec=Path)
        mock_binary2.__str__ = lambda self: "/test/binary2"
        
        with patch("pathlib.Path.glob") as mock_glob:
            # First pattern returns a binary (should be used)
            mock_glob.return_value = iter([mock_binary1, mock_binary2])
            
            result = playwright.get_playwright_binary()
            
        # Should return the first match from first pattern
        assert result is not None


class TestEnsurePlaywrightBinary:
    """Test playwright.ensure_playwright_binary() function"""

    @patch("python.helpers.playwright.get_playwright_binary")
    @patch("python.helpers.playwright.get_playwright_cache_dir")
    @patch("python.helpers.playwright.subprocess.check_call")
    def test_returns_binary_when_already_installed(
        self, mock_check_call, mock_cache_dir, mock_get_binary
    ):
        """Test that binary is returned without installation when present"""
        mock_get_binary.return_value = Path("/test/playwright/chromium/headless_shell")
        mock_cache_dir.return_value = "/test/playwright"
        
        result = playwright.ensure_playwright_binary()
        
        # subprocess.check_call should NOT be called
        mock_check_call.assert_not_called()
        assert result is not None

    @patch("python.helpers.playwright.get_playwright_binary")
    @patch("python.helpers.playwright.get_playwright_cache_dir")
    @patch("python.helpers.playwright.subprocess.check_call")
    def test_installs_when_not_found(
        self, mock_check_call, mock_cache_dir, mock_get_binary
    ):
        """Test that installation is triggered when binary not found"""
        mock_get_binary.return_value = None  # Not found initially
        mock_cache_dir.return_value = "/test/playwright"
        
        # After installation, binary is found
        mock_get_binary.side_effect = [None, Path("/test/playwright/chromium/headless_shell")]
        
        result = playwright.ensure_playwright_binary()
        
        # subprocess.check_call SHOULD be called
        mock_check_call.assert_called_once()
        call_kwargs = mock_check_call.call_args.kwargs
        assert "env" in call_kwargs
        assert "PLAYWRIGHT_BROWSERS_PATH" in call_kwargs["env"]
        
    @patch("python.helpers.playwright.get_playwright_binary")
    @patch("python.helpers.playwright.get_playwright_cache_dir")
    @patch("python.helpers.playwright.subprocess.check_call")
    def test_raises_runtime_error_when_installation_fails(
        self, mock_check_call, mock_cache_dir, mock_get_binary
    ):
        """Test that RuntimeError is raised when binary not found after installation"""
        mock_get_binary.return_value = None  # Not found, even after install
        mock_cache_dir.return_value = "/test/playwright"
        
        # Empty result even after installation attempt
        with patch("pathlib.Path.glob") as mock_glob:
            mock_glob.return_value = iter([])
            
            with pytest.raises(RuntimeError, match="Playwright binary not found after installation"):
                playwright.ensure_playwright_binary()

    @patch("python.helpers.playwright.get_playwright_binary")
    @patch("python.helpers.playwright.get_playwright_cache_dir")
    @patch("python.helpers.playwright.subprocess.check_call")
    def test_sets_correct_env_for_installation(
        self, mock_check_call, mock_cache_dir, mock_get_binary
    ):
        """Test that correct environment is set for playwright installation"""
        mock_get_binary.return_value = None
        mock_cache_dir.return_value = "/custom/playwright/path"
        
        # After installation attempt, return binary
        mock_get_binary.side_effect = [None, Path("/test/chromium/headless_shell")]
        
        with patch("pathlib.Path.glob"):
            playwright.ensure_playwright_binary()
        
        # Verify environment setup
        call_kwargs = mock_check_call.call_args.kwargs
        env = call_kwargs.get("env", {})
        
        assert "PLAYWRIGHT_BROWSERS_PATH" in env
        assert env["PLAYWRIGHT_BROWSERS_PATH"] == "/custom/playwright/path"

    @patch("python.helpers.playwright.get_playwright_binary")
    @patch("python.helpers.playwright.get_playwright_cache_dir")
    @patch("python.helpers.playwright.subprocess.check_call")
    def test_calls_correct_playwright_command(
        self, mock_check_call, mock_cache_dir, mock_get_binary
    ):
        """Test that correct playwright install command is called"""
        mock_get_binary.return_value = None
        mock_cache_dir.return_value = "/test/playwright"
        
        # After installation attempt, return binary
        mock_get_binary.side_effect = [None, Path("/test/chromium/headless_shell")]
        
        with patch("pathlib.Path.glob"):
            playwright.ensure_playwright_binary()
        
        # Verify the command called
        call_args = mock_check_call.call_args.args[0]  # First positional arg is command list
        assert "playwright" in call_args
        assert "install" in call_args
        assert "chromium" in call_args
        assert "--only-shell" in call_args
