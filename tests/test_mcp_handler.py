"""Tests for mcp_handler module - MCP server/client functionality

These tests verify the core utility functions in the MCP handler.
Due to pydantic mocking in conftest.py, we only test pure functions.
"""
import pytest

from python.helpers.mcp_handler import (
    normalize_name,
    _determine_server_type,
    _is_streaming_http_type,
)


class TestNormalizeName:
    """Test normalize_name function"""

    def test_normalize_name_basic(self):
        """Test basic string normalization"""
        assert normalize_name("Hello World") == "hello_world"
        assert normalize_name("Test") == "test"

    def test_normalize_name_special_chars(self):
        """Test handling of special characters"""
        assert normalize_name("hello@world") == "hello_world"
        assert normalize_name("test.name") == "test_name"
        assert normalize_name("a-b-c") == "a_b_c"

    def test_normalize_name_unicode(self):
        """Test handling of unicode characters"""
        # Unicode letters are preserved as word characters
        assert "caf" in normalize_name("café")
        assert "üniçodé" in normalize_name("üniçodé")

    def test_normalize_name_multiple_spaces(self):
        """Test multiple consecutive spaces - each space becomes an underscore"""
        assert normalize_name("hello   world") == "hello___world"
        assert normalize_name("a  b") == "a__b"

    def test_normalize_name_empty(self):
        """Test empty string"""
        assert normalize_name("") == ""

    def test_normalize_name_already_normalized(self):
        """Test already normalized string"""
        assert normalize_name("already_normalized") == "already_normalized"

    def test_normalize_name_numbers(self):
        """Test string with numbers"""
        assert normalize_name("test123") == "test123"
        assert normalize_name("123test") == "123test"


class TestDetermineServerType:
    """Test _determine_server_type function"""

    def test_determine_server_type_url(self):
        """Test server type detection from URL"""
        assert _determine_server_type({"url": "http://localhost:8000"}) == "MCPServerRemote"
        assert _determine_server_type({"serverUrl": "http://localhost:8000"}) == "MCPServerRemote"

    def test_determine_server_type_stdio(self):
        """Test stdio type detection"""
        assert _determine_server_type({"command": "npx"}) == "MCPServerLocal"
        assert _determine_server_type({"command": "python", "args": ["-m", "server"]}) == "MCPServerLocal"

    def test_determine_server_type_explicit_sse(self):
        """Test explicit SSE type"""
        config = {"type": "sse", "url": "http://localhost:8000"}
        assert _determine_server_type(config) == "MCPServerRemote"

    def test_determine_server_type_explicit_stdio(self):
        """Test explicit stdio type"""
        config = {"type": "stdio", "command": "npx"}
        assert _determine_server_type(config) == "MCPServerLocal"

    def test_determine_server_type_streaming_http_variants(self):
        """Test streaming HTTP variants"""
        for variant in ["http-stream", "streaming-http", "streamable-http", "http-streaming"]:
            config = {"type": variant, "url": "http://localhost:8000"}
            assert _determine_server_type(config) == "MCPServerRemote"

    def test_determine_server_type_empty_config(self):
        """Test empty config defaults to local"""
        assert _determine_server_type({}) == "MCPServerLocal"


class TestIsStreamingHttpType:
    """Test _is_streaming_http_type function"""

    def test_is_streaming_http_true(self):
        """Test streaming HTTP types return True"""
        for variant in ["http-stream", "streaming-http", "streamable-http", "http-streaming"]:
            assert _is_streaming_http_type(variant) is True

    def test_is_streaming_http_false(self):
        """Test non-streaming types return False"""
        assert _is_streaming_http_type("sse") is False
        assert _is_streaming_http_type("stdio") is False
        assert _is_streaming_http_type("unknown") is False

    def test_is_streaming_http_case_insensitive(self):
        """Test case insensitivity"""
        assert _is_streaming_http_type("HTTP-STREAM") is True
        assert _is_streaming_http_type("Streaming-Http") is True
