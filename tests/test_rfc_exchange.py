"""Tests for RFC Exchange utilities.

Tests the root password retrieval and encryption functions for development environments.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from python.helpers import rfc_exchange


class TestGetRootPassword:
    """Test get_root_password function"""

    @pytest.mark.asyncio
    async def test_get_root_password_dockerized(self):
        """Test password retrieval in dockerized environment"""
        with patch("python.helpers.runtime.is_dockerized", return_value=True), \
             patch("python.helpers.rfc_exchange._get_root_password", return_value="test_password"):
            result = await rfc_exchange.get_root_password()
            assert result == "test_password"

    @pytest.mark.asyncio
    async def test_get_root_password_development(self):
        """Test password retrieval in development environment"""
        mock_private_key = MagicMock()
        mock_public_key = "mock_public_key_hex"
        mock_encrypted = "encrypted_password"
        mock_decrypted = "decrypted_password"

        with patch("python.helpers.runtime.is_dockerized", return_value=False), \
             patch("python.helpers.crypto._generate_private_key", return_value=mock_private_key), \
             patch("python.helpers.crypto._generate_public_key", return_value=mock_public_key), \
             patch("python.helpers.runtime.call_development_function", new_callable=AsyncMock, return_value=mock_encrypted), \
             patch("python.helpers.crypto.decrypt_data", return_value=mock_decrypted):
            result = await rfc_exchange.get_root_password()
            assert result == mock_decrypted

    @pytest.mark.asyncio
    async def test_get_root_password_development_calls_correct_functions(self):
        """Test that development flow calls correct functions in order"""
        mock_private_key = MagicMock()
        mock_public_key = "mock_public_key_hex"
        mock_encrypted = "encrypted_password"

        with patch("python.helpers.runtime.is_dockerized", return_value=False), \
             patch("python.helpers.crypto._generate_private_key", return_value=mock_private_key) as mock_gen_priv, \
             patch("python.helpers.crypto._generate_public_key", return_value=mock_public_key) as mock_gen_pub, \
             patch("python.helpers.runtime.call_development_function", new_callable=AsyncMock, return_value=mock_encrypted) as mock_call_dev, \
             patch("python.helpers.crypto.decrypt_data", return_value="result") as mock_decrypt:
            await rfc_exchange.get_root_password()

            # Verify call order
            mock_gen_priv.assert_called_once()
            mock_gen_pub.assert_called_once_with(mock_private_key)
            mock_call_dev.assert_called_once()
            mock_decrypt.assert_called_once_with(mock_encrypted, mock_private_key)


class TestProvideRootPassword:
    """Test _provide_root_password function"""

    def test_provide_root_password(self):
        """Test password provision and encryption"""
        mock_public_key = "mock_public_key_hex"
        expected_encrypted = "encrypted_password"

        with patch("python.helpers.rfc_exchange._get_root_password", return_value="original_password"), \
             patch("python.helpers.crypto.encrypt_data", return_value=expected_encrypted) as mock_encrypt:
            result = rfc_exchange._provide_root_password(mock_public_key)

            assert result == expected_encrypted
            mock_encrypt.assert_called_once_with("original_password", mock_public_key)

    def test_provide_root_password_calls_functions(self):
        """Test that _provide_root_password calls expected functions"""
        with patch("python.helpers.rfc_exchange._get_root_password", return_value="test_pwd") as mock_get_pwd, \
             patch("python.helpers.crypto.encrypt_data", return_value="enc") as mock_encrypt:
            rfc_exchange._provide_root_password("pub_key")

            mock_get_pwd.assert_called_once()
            mock_encrypt.assert_called_once_with("test_pwd", "pub_key")


class TestGetRootPasswordInternal:
    """Test _get_root_password internal function"""

    def test_get_root_password_returns_dotenv_value(self):
        """Test _get_root_password retrieves from dotenv"""
        expected_password = "secret_password_123"

        with patch("python.helpers.dotenv.get_dotenv_value", return_value=expected_password) as mock_get:
            result = rfc_exchange._get_root_password()

            assert result == expected_password
            mock_get.assert_called_once()

    def test_get_root_password_empty_when_not_set(self):
        """Test _get_root_password returns empty string when not set"""
        with patch("python.helpers.dotenv.get_dotenv_value", return_value=None):
            result = rfc_exchange._get_root_password()
            assert result == ""

    def test_get_root_password_calls_correct_key(self):
        """Test _get_root_password uses correct dotenv key"""
        from python.helpers import dotenv

        with patch("python.helpers.dotenv.get_dotenv_value") as mock_get:
            rfc_exchange._get_root_password()

            # Verify it was called with the root password key
            mock_get.assert_called_once_with(dotenv.KEY_ROOT_PASSWORD)
