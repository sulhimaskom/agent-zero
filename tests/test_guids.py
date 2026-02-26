import pytest

from python.helpers.guids import generate_id


class TestGuids:
    """Tests for python/helpers/guids.py"""

    def test_generate_id_default_length(self):
        """Test generate_id produces correct default length."""
        result = generate_id()
        assert len(result) == 8

    def test_generate_id_custom_length(self):
        """Test generate_id produces correct custom length."""
        result = generate_id(length=16)
        assert len(result) == 16

    def test_generate_id_length_zero(self):
        """Test generate_id with zero length returns empty string."""
        result = generate_id(length=0)
        assert result == ""

    def test_generate_id_uses_alphanumeric(self):
        """Test generate_id only uses alphanumeric characters."""
        result = generate_id()
        assert result.isalnum()

    def test_generate_id_returns_string(self):
        """Test generate_id returns a string type."""
        result = generate_id()
        assert isinstance(result, str)

    def test_generate_id_different_results(self):
        """Test generate_id produces different results (statistically)."""
        results = [generate_id() for _ in range(100)]
        unique_results = set(results)
        # With 62^8 possible combinations, we should have very few duplicates
        assert len(unique_results) >= 95  # Allow some duplicates but not many
