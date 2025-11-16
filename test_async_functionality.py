#!/usr/bin/env python3
"""
Simple test to verify async functionality in modified files works correctly.
"""
import asyncio
import tempfile
import os
import base64
from python.api.download_work_dir_file import fetch_file


async def test_fetch_file():
    """Test the async fetch_file function."""
    # Create a temporary file with test content
    test_content = b"Hello, this is test content for async file reading!"
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(test_content)
        temp_file_path = temp_file.name
    
    try:
        # Test the async fetch_file function
        result = await fetch_file(temp_file_path)
        
        # Decode the result and verify
        decoded_content = base64.b64decode(result).decode('utf-8')
        expected_content = test_content.decode('utf-8')
        
        assert decoded_content == expected_content, f"Content mismatch: {decoded_content} != {expected_content}"
        print("✓ fetch_file async test passed")
        
    finally:
        # Clean up
        os.unlink(temp_file_path)


async def test_tunnel_proxy_import():
    """Test that tunnel_proxy imports correctly and has expected structure."""
    from python.api.tunnel_proxy import TunnelProxy
    
    # Verify the class exists and has expected methods
    assert hasattr(TunnelProxy, 'process'), "TunnelProxy should have process method"
    print("✓ tunnel_proxy import test passed")


async def main():
    """Run all async tests."""
    print("Running async functionality tests...")
    
    await test_fetch_file()
    await test_tunnel_proxy_import()
    
    print("All tests passed! ✅")


if __name__ == "__main__":
    asyncio.run(main())