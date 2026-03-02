"""Tests for RFC (Remote Function Call) utilities.

Tests the RFC module functions for secure remote function invocation.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from python.helpers import rfc
from python.helpers.rfc import (
    RFCInput,
    RFCCall,
    _get_function,
    _call_function,
)


class TestGetFunction:
    """Test _get_function utility"""

    def test_get_builtin_function(self):
        """Test getting a builtin function"""
        func = _get_function("json", "dumps")
        assert callable(func)
        assert func({"a": 1}) == '{"a": 1}'

    def test_get_os_function(self):
        """Test getting os.path.join"""
        func = _get_function("os.path", "join")
        assert callable(func)
        result = func("a", "b", "c")
        import os
        expected = os.path.join("a", "b", "c")
        assert result == expected

    def test_get_nonexistent_module_raises(self):
        """Test that nonexistent module raises ImportError"""
        with pytest.raises(ModuleNotFoundError):
            _get_function("nonexistent_module_xyz", "function")

    def test_get_nonexistent_function_raises(self):
        """Test that nonexistent function raises AttributeError"""
        with pytest.raises(AttributeError):
            _get_function("json", "nonexistent_function_xyz")


class TestCallFunction:
    """Test _call_function utility"""

    @pytest.mark.asyncio
    async def test_call_sync_function(self):
        """Test calling a synchronous function"""
        def test_func(a, b):
            return a + b

        with patch('python.helpers.rfc._get_function', return_value=test_func):
            result = await _call_function("module", "func", 1, 2)
            assert result == 3

    @pytest.mark.asyncio
    async def test_call_async_function(self):
        """Test calling an async function"""
        async def async_func(x, y):
            return x * y

        with patch('python.helpers.rfc._get_function', return_value=async_func):
            result = await _call_function("module", "func", 3, 4)
            assert result == 12

    @pytest.mark.asyncio
    async def test_call_with_kwargs(self):
        """Test calling function with keyword arguments"""
        def test_func(a=1, b=2, c=3):
            return a + b + c

        with patch('python.helpers.rfc._get_function', return_value=test_func):
            result = await _call_function("module", "func", a=1, b=2, c=3)
            assert result == 6


class TestCallRfcInput:
    """Test RFC call input generation (without network)"""

    @pytest.mark.asyncio
    async def test_call_rfc_generates_input(self):
        """Test that call_rfc generates correct RFCInput structure"""
        # We only test that it generates proper input structure
        # Network call is mocked
        with patch('python.helpers.rfc._send_json_data', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {"result": "success"}
            
            result = await rfc.call_rfc(
                url="http://test.example.com/rfc",
                password="testpassword",
                module="json",
                function_name="dumps",
                args=[{"test": "data"}],
                kwargs={}
            )
            
            # Verify _send_json_data was called
            mock_send.assert_called_once()
            
            # Check the call structure
            call_args = mock_send.call_args
            call_data = call_args[0][1]  # Second positional arg
            
            assert "rfc_input" in call_data
            assert "hash" in call_data
            
            # Verify hash was generated (HMAC-SHA256 produces 64 hex chars)
            assert len(call_data["hash"]) == 64


class TestHandleRfc:
    """Test RFC handler (without network)"""

    @pytest.mark.asyncio
    async def test_handle_rfc_valid_call(self):
        """Test handling valid RFC call"""
        import json
        
        # Create valid RFC call
        input_data = RFCInput(
            module="json",
            function_name="dumps",
            args=[{"key": "value"}],
            kwargs={"indent": 2}
        )
        rfc_input = json.dumps(input_data)
        
        # Generate valid hash
        from python.helpers.crypto import hash_data
        password = "testpassword"
        valid_hash = hash_data(rfc_input, password)
        
        rfc_call = RFCCall(
            rfc_input=rfc_input,
            hash=valid_hash
        )
        
        # Handle should succeed (function will be called)
        with patch('python.helpers.rfc._call_function', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = '{"key": "value"}'
            result = await rfc.handle_rfc(rfc_call, password)
            mock_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_rfc_invalid_hash_raises(self):
        """Test that invalid hash raises ValueError"""
        import json
        
        input_data = RFCInput(
            module="json",
            function_name="dumps",
            args=[],
            kwargs={}
        )
        rfc_input = json.dumps(input_data)
        
        # Invalid hash (wrong password)
        rfc_call = RFCCall(
            rfc_input=rfc_input,
            hash="0" * 64
        )
        
        with pytest.raises(ValueError, match="Invalid RFC hash"):
            await rfc.handle_rfc(rfc_call, "correctpassword")

    @pytest.mark.asyncio
    async def test_handle_rfc_tampered_input_raises(self):
        """Test that tampered input raises ValueError"""
        import json
        
        input_data = RFCInput(
            module="json",
            function_name="dumps",
            args=[],
            kwargs={}
        )
        rfc_input = json.dumps(input_data)
        
        # Generate valid hash
        from python.helpers.crypto import hash_data
        password = "testpassword"
        valid_hash = hash_data(rfc_input, password)
        
        # Tamper with the input
        tampered_call = RFCCall(
            rfc_input=rfc_input + "tampered",
            hash=valid_hash
        )
        
        with pytest.raises(ValueError, match="Invalid RFC hash"):
            await rfc.handle_rfc(tampered_call, password)
