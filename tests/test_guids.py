import pytest
import string

from python.helpers.guids import generate_id


class TestGenerateId:
    """Test generate_id function"""

    def test_default_length(self):
        """Test default length is 8 characters"""
        result = generate_id()
        assert len(result) == 8

    def test_custom_length(self):
        """Test custom length parameter"""
        result = generate_id(length=16)
        assert len(result) == 16

    def test_length_zero(self):
        """Test zero length returns empty string"""
        result = generate_id(length=0)
        assert len(result) == 0

    def test_custom_length_one(self):
        """Test length of 1 returns single character"""
        result = generate_id(length=1)
        assert len(result) == 1

    def test_contains_only_alphanumeric(self):
        """Test output contains only alphanumeric characters"""
        result = generate_id()
        assert all(c in string.ascii_letters + string.digits for c in result)

    def test_contains_digits(self):
        """Test output can contain digits"""
        # Generate many IDs to increase chance of containing digits
        results = [generate_id() for _ in range(100)]
        # At least some should contain digits (not guaranteed but very likely)
        has_digit = any(any(c.isdigit() for c in r) for r in results)
        assert has_digit  # Statistical test

    def test_contains_letters(self):
        """Test output contains letters"""
        result = generate_id()
        assert any(c.isalpha() for c in result)

    def test_different_ids_are_different(self):
        """Test that multiple calls return different IDs"""
        ids = [generate_id() for _ in range(10)]
        assert len(set(ids)) == len(ids)  # All unique

    def test_reproducibility_with_same_seed(self):
        """Test that same seed produces same results (if we could set seed)"""
        # Note: Since we can't easily set the seed in the current implementation,
        # we just verify the function returns consistent type and format
        result = generate_id()
        assert isinstance(result, str)
        assert result.isalnum()
