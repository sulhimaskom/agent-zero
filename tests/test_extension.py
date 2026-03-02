"""Tests for extension utilities.

Tests the extension helper functions for loading and managing extensions.
"""

import pytest

from python.helpers.extension import _get_file_from_module


class TestGetFileFromModule:
    """Test _get_file_from_module function"""

    def test_simple_module_name(self):
        """Test extracting filename from simple module path"""
        result = _get_file_from_module("example")
        assert result == "example"

    def test_dotted_module_path(self):
        """Test extracting filename from dotted module path"""
        result = _get_file_from_module("python.helpers.extension")
        assert result == "extension"

    def test_deeply_nested_module(self):
        """Test extracting filename from deeply nested module path"""
        result = _get_file_from_module("python.helpers.subdir.module_name")
        assert result == "module_name"

    def test_with_init_module(self):
        """Test extracting filename from __init__ module path"""
        result = _get_file_from_module("package.subpackage.__init__")
        assert result == "__init__"

    def test_single_dotted_name(self):
        """Test with single dot in module name"""
        result = _get_file_from_module("os.path")
        assert result == "path"

    def test_no_dot(self):
        """Test module with no dots returns itself"""
        result = _get_file_from_module("module")
        assert result == "module"

    def test_leading_dot_handling(self):
        """Test module name with leading dot"""
        # Edge case - this is unusual but should not crash
        result = _get_file_from_module(".hidden_module")
        # Should return the part after the last dot
        assert isinstance(result, str)
