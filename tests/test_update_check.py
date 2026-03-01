import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import hashlib
import sys
from python.helpers import update_check


class TestCheckVersion:
    """Test update_check.check_version() function"""

    @pytest.mark.asyncio
    async def test_check_version_returns_version_info(self):
        """Test that check_version returns parsed version info from response"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "version": "1.0.0",
            "update_available": True,
            "release_notes": "Bug fixes"
        }

        # Create mock httpx module
        mock_httpx = MagicMock()
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Patch httpx module directly in sys.modules before the function runs
        with patch.dict(sys.modules, {'httpx': mock_httpx}):
            with patch("python.helpers.update_check.git.get_version", return_value="0.9.0"):
                with patch("python.helpers.update_check.runtime.get_persistent_id", return_value="test-id-123"):
                    result = await update_check.check_version()

        assert result == {
            "version": "1.0.0",
            "update_available": True,
            "release_notes": "Bug fixes"
        }

    @pytest.mark.asyncio
    async def test_check_version_sends_correct_payload(self):
        """Test that check_version sends the correct payload to update server"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "1.0.0"}

        # Create mock httpx module
        mock_httpx = MagicMock()
        mock_post = AsyncMock(return_value=mock_response)
        mock_client = MagicMock()
        mock_client.post = mock_post
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch.dict(sys.modules, {'httpx': mock_httpx}):
            with patch("python.helpers.update_check.git.get_version", return_value="0.9.0"):
                with patch("python.helpers.update_check.runtime.get_persistent_id", return_value="test-id-123"):
                    await update_check.check_version()

        # Verify POST was called with correct URL and payload structure
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        
        # Get payload from args or kwargs
        if call_args.kwargs and "json" in call_args.kwargs:
            payload = call_args.kwargs["json"]
        else:
            payload = call_args.args[1] if len(call_args.args) > 1 else {}
            
        assert payload is not None
        assert "current_version" in payload
        assert "anonymized_id" in payload

    @pytest.mark.asyncio
    async def test_check_version_uses_correct_url(self):
        """Test that check_version uses the correct update check URL"""
        from python.helpers.constants import Network
        
        mock_response = MagicMock()
        mock_response.json.return_value = {}

        # Create mock httpx module
        mock_httpx = MagicMock()
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch.dict(sys.modules, {'httpx': mock_httpx}):
            with patch("python.helpers.update_check.git.get_version", return_value="0.9.0"):
                with patch("python.helpers.update_check.runtime.get_persistent_id", return_value="test-id"):
                    await update_check.check_version()

            # Verify the URL used
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert Network.UPDATE_CHECK_URL in str(call_args)

    @pytest.mark.asyncio
    async def test_check_version_anonymizes_id(self):
        """Test that the anonymized ID is properly hashed"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "1.0.0"}

        # Create mock httpx module
        mock_httpx = MagicMock()
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch.dict(sys.modules, {'httpx': mock_httpx}):
            with patch("python.helpers.update_check.git.get_version", return_value="0.9.0"):
                with patch("python.helpers.update_check.runtime.get_persistent_id", return_value="my-unique-id"):
                    await update_check.check_version()

            # Get the call args
            call_args = mock_client.post.call_args
            
            # Get payload from args or kwargs
            if call_args.kwargs and "json" in call_args.kwargs:
                payload = call_args.kwargs["json"]
            else:
                payload = call_args.args[1] if len(call_args.args) > 1 else {}
            
            # Verify anonymized_id is first 20 chars of SHA256 hash
            expected_hash = hashlib.sha256("my-unique-id".encode()).hexdigest()[:20]
            assert payload["anonymized_id"] == expected_hash
