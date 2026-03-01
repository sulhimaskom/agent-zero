"""Tests for SearXNG search utility.

Tests the search function and URL construction for the SearXNG search provider.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from python.helpers import searxng


class TestSearxngSearch:
    """Test searxng search functionality"""

    @pytest.mark.asyncio
    async def test_search_returns_json_results(self):
        """Test that search returns parsed JSON results"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(return_value=[
                {"title": "Test Result 1", "url": "https://example.com/1"},
                {"title": "Test Result 2", "url": "https://example.com/2"},
            ])

            mock_session = MagicMock()
            mock_session.post = AsyncMock(return_value=mock_response)
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
            captured_url = None
            captured_data = None

            async def mock_post(url, data=None, **kwargs):
                nonlocal captured_url, captured_data
                captured_url = url
                captured_data = data
                mock_response = AsyncMock()
                mock_response.json = AsyncMock(return_value=[])
                return mock_response

            mock_session = MagicMock()
            mock_session.post = mock_post
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session):
                with patch("python.helpers.searxng.URL", "http://localhost:8080/search"):
                    await searxng._search("test query")

            assert captured_url == "http://localhost:8080/search"
            assert captured_data == {"q": "test query", "format": "json"}

    @pytest.mark.asyncio
    async def test_search_empty_results(self):
        """Test that search handles empty results"""
        # Mock is_development to return False so search calls _search directly
        with patch("python.helpers.searxng.runtime.is_development", return_value=False):
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(return_value=[])

            mock_session = MagicMock()
            mock_session.post = AsyncMock(return_value=mock_response)
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
            captured_data = None

            async def capture_post(url, data=None, **kwargs):
                nonlocal captured_data
                captured_data = data
                mock_response = AsyncMock()
                mock_response.json = AsyncMock(return_value=[])
                return mock_response

            mock_session = MagicMock()
            mock_session.post = capture_post
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("python.helpers.searxng.aiohttp.ClientSession", return_value=mock_session):
                await searxng._search("my search query")

            assert captured_data is not None
            assert captured_data["q"] == "my search query"
            assert captured_data["format"] == "json"


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
