"""Tests for SearXNG search utility.

Tests the search function and URL construction for the SearXNG search provider.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from python.helpers import searxng


class TestSearxngSearch:
    """Test searxng search functionality"""

    @pytest.mark.asyncio
    async def test_search_returns_json_results(self):
        """Test that search returns parsed JSON results"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            # Create mock_response as MagicMock and set up as async context manager
            mock_response = MagicMock()
            mock_response.json = AsyncMock(
                return_value=[
                    {"title": "Test Result 1", "url": "https://example.com/1"},
                    {"title": "Test Result 2", "url": "https://example.com/2"},
                ]
            )
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            # Create mock_session and set up post to return mock_response
            mock_session = MagicMock()
            mock_session.post = MagicMock(return_value=mock_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session):
                result = await searxng._search("test query")

            assert len(result) == 2
            assert result[0]["title"] == "Test Result 1"
            assert result[1]["url"] == "https://example.com/2"

    @pytest.mark.asyncio
    async def test_search_uses_correct_url(self):
        """Test that search uses the correct SearXNG URL"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            # Use mutable container to capture values in closure
            captured = {"url": None, "data": None}

            def mock_post(url, data=None, **kwargs):
                captured["url"] = url
                captured["data"] = data
                # Create mock_response as MagicMock and set up as async context manager
                mock_response = MagicMock()
                mock_response.json = AsyncMock(return_value=[])
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response

            mock_session = MagicMock()
            mock_session.post = mock_post
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with (
                patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session),
                patch("python.helpers.searxng.URL", "http://localhost:8080/search"),
            ):
                await searxng._search("test query")

            assert captured["url"] == "http://localhost:8080/search"
            assert captured["data"] == {"q": "test query", "format": "json"}

    @pytest.mark.asyncio
    async def test_search_empty_results(self):
        """Test that search handles empty results"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            # Create mock_response as MagicMock and set up as async context manager
            mock_response = MagicMock()
            mock_response.json = AsyncMock(return_value=[])
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post = MagicMock(return_value=mock_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session):
                result = await searxng._search("nonexistent query")

            assert result == []

    @pytest.mark.asyncio
    async def test_search_includes_query_parameter(self):
        """Test that search includes the query in the request"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            # Use mutable container to capture values in closure
            captured = {"data": None}

            def capture_post(url, data=None, **kwargs):
                captured["data"] = data
                # Create mock_response as MagicMock and set up as async context manager
                mock_response = MagicMock()
                mock_response.json = AsyncMock(return_value=[])
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response

            mock_session = MagicMock()
            mock_session.post = capture_post
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session):
                await searxng._search("my search query")

            assert captured["data"] is not None
            assert captured["data"]["q"] == "my search query"
            assert captured["data"]["format"] == "json"


class TestSearxngURL:
    """Test SearXNG URL configuration"""

    def test_url_contains_search_path(self):
        """Test that URL ends with /search"""
        # URL is constructed as f"http://{host}:{port}/search"
        # We just verify the URL ends with /search
        assert searxng.URL.endswith("/search")

    def test_url_starts_with_http(self):
        """Test that URL uses HTTP protocol"""
        assert searxng.URL.startswith("http://")

    def test_url_contains_port(self):
        """Test that URL contains port number"""
        # URL format: http://host:port/search
        assert ":" in searxng.URL
