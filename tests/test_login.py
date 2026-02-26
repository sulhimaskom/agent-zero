"""Tests for login module - credentials hashing and login requirement"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib

from python.helpers import login


class TestGetCredentialsHash:
    """Test get_credentials_hash function"""

    def test_get_credentials_hash_no_login(self, monkeypatch):
        """Test that get_credentials_hash returns None when AUTH_LOGIN is not set"""
        monkeypatch.delenv("AUTH_LOGIN", raising=False)
        monkeypatch.delenv("AUTH_PASSWORD", raising=False)
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.get_credentials_hash()
        assert result is None

    def test_get_credentials_hash_no_password(self, monkeypatch):
        """Test that get_credentials_hash returns hash with None when only login is set"""
        monkeypatch.setenv("AUTH_LOGIN", "testuser")
        monkeypatch.delenv("AUTH_PASSWORD", raising=False)
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.get_credentials_hash()
        # Should return SHA256 hash of "testuser:None" when password is not set
        expected = hashlib.sha256("testuser:None".encode()).hexdigest()
        assert result == expected

    def test_get_credentials_hash_with_credentials(self, monkeypatch):
        """Test that get_credentials_hash returns SHA256 hash when credentials are set"""
        monkeypatch.setenv("AUTH_LOGIN", "testuser")
        monkeypatch.setenv("AUTH_PASSWORD", "testpassword")
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.get_credentials_hash()
        # Should return SHA256 hash of "testuser:testpassword"
        expected = hashlib.sha256("testuser:testpassword".encode()).hexdigest()
        assert result == expected


class TestIsLoginRequired:
    """Test is_login_required function"""

    def test_is_login_required_no_auth(self, monkeypatch):
        """Test that is_login_required returns False when AUTH_LOGIN is not set"""
        monkeypatch.delenv("AUTH_LOGIN", raising=False)
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.is_login_required()
        assert result is False

    def test_is_login_required_with_auth(self, monkeypatch):
        """Test that is_login_required returns True when AUTH_LOGIN is set"""
        monkeypatch.setenv("AUTH_LOGIN", "testuser")
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.is_login_required()
        assert result is True

    def test_is_login_required_empty_string(self, monkeypatch):
        """Test that is_login_required returns False when AUTH_LOGIN is empty string"""
        monkeypatch.setenv("AUTH_LOGIN", "")
        # Reload dotenv to pick up new env values
        import importlib

        import python.helpers.dotenv
        importlib.reload(python.helpers.dotenv)

        result = login.is_login_required()
        assert result is False
