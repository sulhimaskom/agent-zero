"""Tests for dotenv utilities.

Tests the dotenv helper functions for loading and saving environment variables.
"""

from unittest.mock import MagicMock, patch

from python.helpers.dotenv import (
    KEY_AUTH_LOGIN,
    KEY_AUTH_PASSWORD,
    KEY_RFC_PASSWORD,
    KEY_ROOT_PASSWORD,
    get_dotenv_file_path,
    get_dotenv_value,
    load_dotenv,
    save_dotenv_value,
)


class TestDotenvConstants:
    """Test dotenv key constants"""

    def test_auth_login_constant(self):
        assert KEY_AUTH_LOGIN == "AUTH_LOGIN"

    def test_auth_password_constant(self):
        assert KEY_AUTH_PASSWORD == "AUTH_PASSWORD"

    def test_rfc_password_constant(self):
        assert KEY_RFC_PASSWORD == "RFC_PASSWORD"

    def test_root_password_constant(self):
        assert KEY_ROOT_PASSWORD == "ROOT_PASSWORD"


class TestGetDotenvFilePath:
    """Test get_dotenv_file_path function"""

    @patch("python.helpers.dotenv.get_abs_path")
    def test_returns_dotenv_path(self, mock_get_abs_path):
        """Test that it returns the .env file path"""
        mock_get_abs_path.return_value = "/test/.env"
        result = get_dotenv_file_path()
        assert result == "/test/.env"
        mock_get_abs_path.assert_called_once_with(".env")


class TestGetDotenvValue:
    """Test get_dotenv_value function"""

    @patch("python.helpers.dotenv.os.getenv")
    def test_returns_value_when_exists(self, mock_getenv):
        """Test that it returns the value when key exists"""
        mock_getenv.return_value = "test_value"
        result = get_dotenv_value("TEST_KEY")
        assert result == "test_value"
        mock_getenv.assert_called_once_with("TEST_KEY", None)

    @patch("python.helpers.dotenv.os.getenv")
    def test_returns_default_when_not_exists(self, mock_getenv):
        """Test that it returns default when key doesn't exist"""
        # When os.getenv doesn't find the key, it returns the default
        mock_getenv.return_value = "default_value"
        result = get_dotenv_value("MISSING_KEY", default="default_value")
        assert result == "default_value"
        mock_getenv.assert_called_once_with("MISSING_KEY", "default_value")

    @patch("python.helpers.dotenv.os.getenv")
    def test_returns_none_default_when_not_exists(self, mock_getenv):
        """Test that it returns None as default when not specified"""
        mock_getenv.return_value = None
        result = get_dotenv_value("MISSING_KEY")
        assert result is None
        mock_getenv.assert_called_once_with("MISSING_KEY", None)

    @patch("python.helpers.dotenv.os.getenv")
    def test_empty_string_as_value(self, mock_getenv):
        """Test that empty string is a valid value"""
        mock_getenv.return_value = ""
        result = get_dotenv_value("EMPTY_KEY")
        assert result == ""
        # Empty string is falsy but should be returned
        mock_getenv.assert_called_once()


class TestSaveDotenvValue:
    """Test save_dotenv_value function"""

    @patch("python.helpers.dotenv.get_dotenv_file_path")
    @patch("python.helpers.dotenv.load_dotenv")
    @patch("python.helpers.dotenv.open", create=True)
    def test_save_new_key(self, mock_open, mock_load_dotenv, mock_get_path):
        """Test saving a new key to .env file"""
        mock_get_path.return_value = "/test/.env"

        # Mock file that doesn't exist initially
        mock_file = MagicMock()
        mock_file.readlines.return_value = []
        mock_open.return_value = mock_file

        with patch("os.path.isfile", return_value=True):
            save_dotenv_value("NEW_KEY", "new_value")

        # Should have called load_dotenv at the end
        mock_load_dotenv.assert_called_once()

    @patch("python.helpers.dotenv.get_dotenv_file_path")
    @patch("python.helpers.dotenv.load_dotenv")
    @patch("python.helpers.dotenv.open", create=True)
    def test_update_existing_key(self, mock_open, mock_load_dotenv, mock_get_path):
        """Test updating an existing key in .env file"""
        mock_get_path.return_value = "/test/.env"

        # Mock file with existing key
        mock_file = MagicMock()
        mock_file.readlines.return_value = ["EXISTING_KEY=old_value\n"]
        mock_open.return_value = mock_file

        with patch("os.path.isfile", return_value=True):
            save_dotenv_value("EXISTING_KEY", "new_value")

        # Should have called load_dotenv at the end
        mock_load_dotenv.assert_called_once()

    @patch("python.helpers.dotenv.get_dotenv_file_path")
    @patch("python.helpers.dotenv.load_dotenv")
    @patch("python.helpers.dotenv.open", create=True)
    def test_create_file_if_not_exists(
        self, mock_open, mock_load_dotenv, mock_get_path
    ):
        """Test creating .env file if it doesn't exist"""
        mock_get_path.return_value = "/test/.env"

        mock_file = MagicMock()
        mock_open.return_value = mock_file

        with patch("os.path.isfile", return_value=False):
            save_dotenv_value("NEW_KEY", "value")
            with patch("os.path.isfile", return_value=False):
                save_dotenv_value("NEW_KEY", "value")

        # Should have called open with 'w' mode to create file
        mock_open.assert_any_call("/test/.env", "w")

    @patch("python.helpers.dotenv.get_dotenv_file_path")
    @patch("python.helpers.dotenv.load_dotenv")
    @patch("python.helpers.dotenv.open", create=True)
    def test_none_value_becomes_empty_string(
        self, mock_open, mock_load_dotenv, mock_get_path
    ):
        """Test that None value is converted to empty string"""
        mock_get_path.return_value = "/test/.env"

        mock_file = MagicMock()
        mock_file.readlines.return_value = []
        mock_open.return_value = mock_file

        with patch("os.path.isfile", return_value=True):
            save_dotenv_value("KEY", None)

        # Should write empty string
        mock_load_dotenv.assert_called_once()


class TestLoadDotenv:
    """Test load_dotenv function"""

    @patch("python.helpers.dotenv._load_dotenv")
    @patch("python.helpers.dotenv.get_dotenv_file_path")
    def test_load_dotenv_calls_underlying_function(self, mock_get_path, mock_load):
        """Test that load_dotenv calls the underlying dotenv load function"""
        mock_get_path.return_value = "/test/.env"

        load_dotenv()

        mock_load.assert_called_once_with("/test/.env", override=True)
