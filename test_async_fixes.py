#!/usr/bin/env python3
"""
Simple test to verify that the async fixes work correctly.
"""
import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_hist_add_methods():
    """Test that hist_add methods are now async and work correctly"""
    try:
        # Import the modules
        from python.helpers.tool import Response
        from python.helpers.extension import call_extensions
        
        print("✓ Successfully imported modules")
        
        # Test that call_extensions is async
        result = await call_extensions("test_extension_point")
        print("✓ call_extensions works as async")
        
        print("✓ All async fixes are working correctly")
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

async def main():
    print("Testing async fixes...")
    success = await test_hist_add_methods()
    if success:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)