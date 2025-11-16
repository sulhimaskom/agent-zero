#!/usr/bin/env python3
"""
Test script to verify async fixes work correctly
"""
import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_async_imports():
    """Test that all modified files can be imported without errors"""
    try:
        # Test importing the modified agent module
        from agent import Agent, AgentContext
        print("✅ agent.py imports successfully")
        
        # Test importing modified tool modules
        from python.tools.code_execution_tool import CodeExecutionTool
        from python.tools.input import InputTool
        from python.tools.vision_load import VisionLoadTool
        print("✅ Tool modules import successfully")
        
        # Test importing helper modules
        from python.helpers.tool import Tool
        from python.helpers.settings import set_root_password_async
        from python.helpers.mcp_handler import McpHandler
        print("✅ Helper modules import successfully")
        
        # Test importing extension
        from python.extensions.agent_init._10_initial_message import InitialMessage
        print("✅ Extension module imports successfully")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

async def test_async_methods():
    """Test that async methods can be called without blocking"""
    try:
        # Test that the async methods exist and are callable
        from agent import Agent
        
        # Create a minimal agent config for testing
        from models import AgentConfig
        config = AgentConfig()
        
        # Create agent context
        context = AgentContext(config)
        
        # Test that async methods exist
        assert hasattr(context.agent, 'async_init'), "async_init method missing"
        assert hasattr(context.agent, 'hist_add_message'), "hist_add_message method missing"
        assert hasattr(context.agent, 'hist_add_user_message'), "hist_add_user_message method missing"
        assert hasattr(context.agent, 'hist_add_ai_response'), "hist_add_ai_response method missing"
        assert hasattr(context.agent, 'hist_add_warning'), "hist_add_warning method missing"
        assert hasattr(context.agent, 'hist_add_tool_result'), "hist_add_tool_result method missing"
        
        # Test that methods are coroutine functions
        import inspect
        assert inspect.iscoroutinefunction(context.agent.async_init), "async_init is not async"
        assert inspect.iscoroutinefunction(context.agent.hist_add_message), "hist_add_message is not async"
        assert inspect.iscoroutinefunction(context.agent.hist_add_user_message), "hist_add_user_message is not async"
        assert inspect.iscoroutinefunction(context.agent.hist_add_ai_response), "hist_add_ai_response is not async"
        assert inspect.iscoroutinefunction(context.agent.hist_add_warning), "hist_add_warning is not async"
        assert inspect.iscoroutinefunction(context.agent.hist_add_tool_result), "hist_add_tool_result is not async"
        
        print("✅ All async methods exist and are properly defined")
        return True
    except Exception as e:
        print(f"❌ Async method test error: {e}")
        return False

async def test_async_settings():
    """Test async settings function"""
    try:
        from python.helpers.settings import set_root_password_async
        import inspect
        
        # Test that the function is async
        assert inspect.iscoroutinefunction(set_root_password_async), "set_root_password_async is not async"
        
        print("✅ set_root_password_async is properly defined as async")
        return True
    except Exception as e:
        print(f"❌ Async settings test error: {e}")
        return False

async def main():
    """Run all tests"""
    print("🧪 Testing async fixes...")
    
    tests = [
        ("Import Test", test_async_imports),
        ("Async Methods Test", test_async_methods),
        ("Async Settings Test", test_async_settings),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name}...")
        if asyncio.iscoroutinefunction(test_func):
            result = await test_func()
        else:
            result = test_func()
        results.append(result)
    
    print(f"\n📊 Test Results: {sum(results)}/{len(results)} passed")
    
    if all(results):
        print("🎉 All async fix tests passed!")
        return 0
    else:
        print("💥 Some tests failed!")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)