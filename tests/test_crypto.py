"""Tests for cryptographic utilities.

Tests the hashing, verification, and encryption/decryption functions.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from python.helpers.crypto import (
    hash_data,
    verify_data,
    encrypt_data,
    decrypt_data,
    _generate_private_key,
    _generate_public_key,
    _decode_public_key,
)


class TestHashData:
    """Test hash_data function"""

    def test_empty_strings(self):
        """Test hashing empty strings returns valid hex"""
        result = hash_data("", "")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 produces 32 bytes = 64 hex chars

    def test_simple_data(self):
        """Test hashing simple data"""
        result = hash_data("hello", "password")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_different_data_different_hash(self):
        """Test different data produces different hashes"""
        hash1 = hash_data("data1", "password")
        hash2 = hash_data("data2", "password")
        assert hash1 != hash2

    def test_different_password_different_hash(self):
        """Test different passwords produce different hashes"""
        hash1 = hash_data("data", "password1")
        hash2 = hash_data("data", "password2")
        assert hash1 != hash2

    def test_same_inputs_produce_same_hash(self):
        """Test same inputs always produce same hash"""
        hash1 = hash_data("test data", "test password")
        hash2 = hash_data("test data", "test password")
        assert hash1 == hash2

    def test_unicode_data(self):
        """Test hashing unicode data"""
        result = hash_data("hello world", "password")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_long_data(self):
        """Test hashing long data"""
        long_data = "a" * 10000
        result = hash_data(long_data, "password")
        assert isinstance(result, str)
        assert len(result) == 64


class TestVerifyData:
    """Test verify_data function"""

    def test_valid_verification(self):
        """Test correct hash verifies successfully"""
        data = "test data"
        password = "test password"
        hash_value = hash_data(data, password)
        assert verify_data(data, hash_value, password) is True

    def test_invalid_hash(self):
        """Test invalid hash fails verification"""
        data = "test data"
        password = "test password"
        invalid_hash = "0" * 64
        assert verify_data(data, invalid_hash, password) is False

    def test_wrong_data(self):
        """Test wrong data fails verification"""
        data = "test data"
        wrong_data = "wrong data"
        password = "test password"
        hash_value = hash_data(data, password)
        assert verify_data(wrong_data, hash_value, password) is False

    def test_wrong_password(self):
        """Test wrong password fails verification"""
        data = "test data"
        password = "test password"
        wrong_password = "wrong password"
        hash_value = hash_data(data, password)
        assert verify_data(data, hash_value, wrong_password) is False

    def test_empty_strings(self):
        """Test verification with empty strings"""
        assert verify_data("", hash_data("", ""), "") is True
        assert verify_data("", hash_data("", "wrong"), "") is False


class TestKeyGeneration:
    """Test key generation functions"""

    def test_generate_private_key(self):
        """Test private key generation"""
        private_key = _generate_private_key()
        assert private_key is not None
        assert isinstance(private_key, rsa.RSAPrivateKey)

    def test_generate_public_key(self):
        """Test public key generation from private key"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        assert isinstance(public_key_hex, str)
        assert len(public_key_hex) > 0

    def test_decode_public_key(self):
        """Test public key decoding"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        decoded_key = _decode_public_key(public_key_hex)
        assert isinstance(decoded_key, rsa.RSAPublicKey)

    def test_roundtrip_public_key(self):
        """Test public key encode/decode roundtrip"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        decoded_key = _decode_public_key(public_key_hex)

        # Verify the decoded key works by encoding it again
        reencoded = decoded_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex()
        assert reencoded == public_key_hex


class TestEncryptData:
    """Test encrypt_data function"""

    def _get_public_key_hex(self):
        """Helper to generate test public key (hex format)"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        return private_key, public_key_hex

    def test_encrypt_empty_string(self):
        """Test encrypting empty string"""
        private_key, public_key_hex = self._get_public_key_hex()
        encrypted = encrypt_data("", public_key_hex)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

    def test_encrypt_simple_text(self):
        """Test encrypting simple text"""
        private_key, public_key_hex = self._get_public_key_hex()
        encrypted = encrypt_data("hello", public_key_hex)
        assert isinstance(encrypted, str)

    def test_encrypt_unicode(self):
        """Test encrypting unicode text"""
        private_key, public_key_hex = self._get_public_key_hex()
        encrypted = encrypt_data("hello world", public_key_hex)
        assert isinstance(encrypted, str)

    def test_encrypt_long_data(self):
        """Test encrypting long data (within RSA limits)"""
        private_key, public_key_hex = self._get_public_key_hex()
        # RSA with OAEP has limits on data size
        # With 2048-bit key, max is ~190 bytes
        data = "a" * 100
        encrypted = encrypt_data(data, public_key_hex)
        assert isinstance(encrypted, str)


class TestDecryptData:
    """Test decrypt_data function"""

    def _get_public_key_hex(self):
        """Helper to generate test public key (hex format)"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        return private_key, public_key_hex

    def test_decrypt_empty_string(self):
        """Test decrypting empty string"""
        private_key, public_key_hex = self._get_public_key_hex()
        encrypted = encrypt_data("", public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == ""

    def test_decrypt_simple_text(self):
        """Test encrypt then decrypt returns original"""
        private_key, public_key_hex = self._get_public_key_hex()
        original = "hello"
        encrypted = encrypt_data(original, public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == original

    def test_decrypt_unicode(self):
        """Test encrypt then decrypt unicode"""
        private_key, public_key_hex = self._get_public_key_hex()
        original = "hello world"
        encrypted = encrypt_data(original, public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == original

    def test_decrypt_long_data(self):
        """Test encrypt then decrypt long data"""
        private_key, public_key_hex = self._get_public_key_hex()
        original = "a" * 100
        encrypted = encrypt_data(original, public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == original

    def test_decrypt_special_characters(self):
        """Test encrypt then decrypt special characters"""
        private_key, public_key_hex = self._get_public_key_hex()
        original = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        encrypted = encrypt_data(original, public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == original


class TestCryptoIntegration:
    """Integration tests for cryptographic functions"""

    def _get_public_key_hex(self):
        """Helper to generate test public key (hex format)"""
        private_key = _generate_private_key()
        public_key_hex = _generate_public_key(private_key)
        return private_key, public_key_hex

    def test_hash_then_verify(self):
        """Test hash and verify workflow"""
        data = "sensitive data"
        password = "secret password"
        hash_value = hash_data(data, password)
        assert verify_data(data, hash_value, password) is True

    def test_encrypt_decrypt_roundtrip(self):
        """Test full encrypt/decrypt roundtrip"""
        private_key, public_key_hex = self._get_public_key_hex()
        original = "This is a secret message"
        encrypted = encrypt_data(original, public_key_hex)
        decrypted = decrypt_data(encrypted, private_key)
        assert decrypted == original

    def test_multiple_messages(self):
        """Test encrypting multiple different messages"""
        private_key, public_key_hex = self._get_public_key_hex()
        messages = ["first", "second", "third", "fourth", "fifth"]
        decrypted_messages = []
        for msg in messages:
            encrypted = encrypt_data(msg, public_key_hex)
            decrypted = decrypt_data(encrypted, private_key)
            decrypted_messages.append(decrypted)
        assert decrypted_messages == messages
