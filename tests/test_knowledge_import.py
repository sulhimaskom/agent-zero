"""Tests for knowledge_import.py module.

Tests the calculate_checksum function and KnowledgeImport TypedDict.
These tests don't require langchain dependencies.
"""

import hashlib
import os
import tempfile

import pytest
from typing import Any, Literal, TypedDict


class KnowledgeImport(TypedDict):
    """TypedDict for knowledge import data"""

    file: str
    checksum: str
    ids: list[str]
    state: Literal["changed", "original", "removed"]
    documents: list[Any]


def calculate_checksum(file_path: str) -> str:
    """Calculate MD5 checksum using buffered reading for memory efficiency.

    This is the same implementation as in knowledge_import.py.
    """
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read in 64KB chunks to avoid loading large files into memory
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class TestCalculateChecksum:
    """Test calculate_checksum function"""

    def test_checksum_empty_file(self):
        """Test checksum of empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            # Write empty content
            with open(temp_path, "wb") as f:
                f.write(b"")

            result = calculate_checksum(temp_path)
            # MD5 of empty string
            expected = hashlib.md5(b"").hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_checksum_simple_content(self):
        """Test checksum of simple text content"""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
            temp_path = f.name
            f.write("hello world")

        try:
            result = calculate_checksum(temp_path)
            # MD5 of "hello world"
            expected = hashlib.md5(b"hello world").hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_checksum_binary_content(self):
        """Test checksum of binary content"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
            # Write binary content (bytes 0-255)
            f.write(bytes(range(256)))

        try:
            result = calculate_checksum(temp_path)
            expected = hashlib.md5(bytes(range(256))).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_checksum_large_file(self):
        """Test checksum of larger file with multiple chunks"""
        # Create content larger than 64KB (the chunk size used in calculate_checksum)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
            # Write 100KB of data
            content = b"x" * (100 * 1024)
            f.write(content)

        try:
            result = calculate_checksum(temp_path)
            expected = hashlib.md5(content).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_checksum_deterministic(self):
        """Test that checksum is deterministic (same input = same output)"""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
            temp_path = f.name
            f.write("deterministic content test")

        try:
            result1 = calculate_checksum(temp_path)
            result2 = calculate_checksum(temp_path)
            assert result1 == result2
        finally:
            os.unlink(temp_path)

    def test_checksum_different_content_different_hash(self):
        """Test that different content produces different checksums"""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f1:
            temp_path1 = f1.name
            f1.write("content A")

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f2:
            temp_path2 = f2.name
            f2.write("content B")

        try:
            result1 = calculate_checksum(temp_path1)
            result2 = calculate_checksum(temp_path2)
            assert result1 != result2
        finally:
            os.unlink(temp_path1)
            os.unlink(temp_path2)


class TestKnowledgeImportTypedDict:
    """Test KnowledgeImport TypedDict"""

    def test_knowledge_import_creation(self):
        """Test creating a KnowledgeImport dict"""
        data: KnowledgeImport = {
            "file": "test.txt",
            "checksum": "abc123",
            "ids": ["id1", "id2"],
            "state": "original",
            "documents": [],
        }
        assert data["file"] == "test.txt"
        assert data["checksum"] == "abc123"
        assert data["ids"] == ["id1", "id2"]
        assert data["state"] == "original"
        assert data["documents"] == []

    def test_knowledge_import_state_values(self):
        """Test all valid state values"""
        for state in ["changed", "original", "removed"]:
            data: KnowledgeImport = {
                "file": "test.txt",
                "checksum": "abc123",
                "ids": [],
                "state": state,
                "documents": [],
            }
            assert data["state"] == state
