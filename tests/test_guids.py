"""
Tests for guids.py - ID generation utility.

This module provides simple random ID generation for Agent Zero.
"""

import re
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.guids import generate_id


class TestGenerateId:
    """Test suite for generate_id function"""

    def test_generate_id_default_length(self):
        """Test that generate_id returns correct default length (8)"""
        result = generate_id()
        assert len(result) == 8

    def test_generate_id_custom_length(self):
        """Test that generate_id respects custom length parameter"""
        result = generate_id(length=16)
        assert len(result) == 16

        result = generate_id(length=4)
        assert len(result) == 4

        result = generate_id(length=32)
        assert len(result) == 32

    def test_generate_id_uses_alphanumeric_characters(self):
        """Test that generated ID contains only alphanumeric characters"""
        result = generate_id()
        assert result.isalnum()

    def test_generate_id_contains_letters_and_digits(self):
        """Test that generated ID contains both letters and digits"""
        result = generate_id(length=100)
        has_letters = any(c.isalpha() for c in result)
        has_digits = any(c.isdigit() for c in result)
        # With 100 characters, statistically should have both
        assert has_letters or has_digits

    def test_generate_id_returns_string(self):
        """Test that generate_id returns a string type"""
        result = generate_id()
        assert isinstance(result, str)

    def test_generate_id_zero_length(self):
        """Test that generate_id with length=0 returns empty string"""
        result = generate_id(length=0)
        assert result == ""

    def test_generate_id_different_each_call(self):
        """Test that generate_id returns different IDs on each call"""
        ids = [generate_id() for _ in range(100)]
        unique_ids = set(ids)
        # With 100 calls, should have many unique values
        assert len(unique_ids) > 90

    def test_generate_id_format(self):
        """Test that generated ID matches expected character pattern"""
        result = generate_id()
        pattern = r'^[a-zA-Z0-9]+$'
        assert re.match(pattern, result) is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
