import pytest
from unittest.mock import patch, MagicMock
from python.helpers import duckduckgo_search
from python.helpers.constants import Search


class TestDuckDuckGoSearch:
    """Test duckduckgo_search.search() function"""

    def test_search_returns_list_of_strings(self):
        """Test that search returns a list of string results"""
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter([
            {"title": "Result 1", "href": "https://example.com/1", "body": "Description 1"},
            {"title": "Result 2", "href": "https://example.com/2", "body": "Description 2"},
        ])

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            results = duckduckgo_search.search("test query")

        assert isinstance(results, list)
        assert len(results) == 2

    def test_search_with_default_params(self):
        """Test search uses default parameters from Search constants"""
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter([])

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            duckduckgo_search.search("test query")

        mock_ddgs.text.assert_called_once()
        call_args = mock_ddgs.text.call_args

        # Check positional and keyword args
        # DDGS.text(query, **kwargs) - query is positional
        if call_args.args:
            assert call_args.args[0] == "test query"
        
        # Check keyword arguments
        call_kwargs = call_args.kwargs
        assert call_kwargs.get("max_results") == Search.DDG_DEFAULT_RESULTS
        assert call_kwargs.get("region") == Search.DDG_DEFAULT_REGION
        assert call_kwargs.get("safesearch") == Search.DDG_DEFAULT_SAFESEARCH
        assert call_kwargs.get("timelimit") == Search.DDG_DEFAULT_TIME_LIMIT

    def test_search_with_custom_params(self):
        """Test search accepts custom parameters"""
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter([])

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            duckduckgo_search.search(
                query="custom query",
                results=10,
                region="us-en",
                time="m"  # past month
            )

        call_kwargs = mock_ddgs.text.call_args.kwargs
        assert call_kwargs.get("max_results") == 10
        assert call_kwargs.get("region") == "us-en"
        assert call_kwargs.get("timelimit") == "m"

    def test_search_converts_dict_to_string(self):
        """Test that search converts dict results to string representation"""
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter([
            {"title": "Test Title", "href": "https://test.com", "body": "Test body text"}
        ])

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            results = duckduckgo_search.search("test")

        # Should convert dict to string
        assert len(results) == 1
        assert "Test Title" in results[0]
        assert "https://test.com" in results[0]
        assert "Test body text" in results[0]

    def test_search_empty_results(self):
        """Test search handles empty results"""
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter([])

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            results = duckduckgo_search.search("nonexistent query xyz")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_multiple_results(self):
        """Test search handles multiple results"""
        mock_results = [
            {"title": f"Result {i}", "href": f"https://example.com/{i}", "body": f"Body {i}"}
            for i in range(5)
        ]
        
        mock_ddgs = MagicMock()
        mock_ddgs.text.return_value = iter(mock_results)

        with patch("python.helpers.duckduckgo_search.DDGS", return_value=mock_ddgs):
            results = duckduckgo_search.search("test", results=5)

        assert len(results) == 5

    def test_search_creates_ddgs_instance(self):
        """Test that search creates a DDGS instance"""
        with patch("python.helpers.duckduckgo_search.DDGS") as mock_ddgs_class:
            mock_ddgs = MagicMock()
            mock_ddgs.text.return_value = iter([])
            mock_ddgs_class.return_value = mock_ddgs
            
            duckduckgo_search.search("test")
            
            mock_ddgs_class.assert_called_once()
