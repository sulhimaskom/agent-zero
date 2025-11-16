#!/usr/bin/env python3
"""
Simple syntax test for async fixes
"""
import ast
import sys
import os

def check_async_methods(filename, expected_methods):
    """Check that expected methods are async in a file"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        async_methods = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                async_methods.append(node.name)
        
        results = {}
        for method in expected_methods:
            results[method] = method in async_methods
        
        return results
    except Exception as e:
        print(f"Error checking {filename}: {e}")
        return {}

def main():
    """Check that all expected methods are async"""
    print("🔍 Checking async method signatures...")
    
    # Expected async methods in agent.py
    agent_methods = [
        'async_init',
        'hist_add_message',
        'hist_add_user_message', 
        'hist_add_ai_response',
        'hist_add_warning',
        'hist_add_tool_result'
    ]
    
    # Expected async methods in settings.py
    settings_methods = [
        'set_root_password_async'
    ]
    
    results = {}
    
    # Check agent.py
    print("\n📋 Checking agent.py...")
    agent_results = check_async_methods('agent.py', agent_methods)
    for method, is_async in agent_results.items():
        status = "✅" if is_async else "❌"
        print(f"  {status} {method}: {'async' if is_async else 'not async'}")
    results['agent.py'] = all(agent_results.values())
    
    # Check settings.py
    print("\n📋 Checking python/helpers/settings.py...")
    settings_results = check_async_methods('python/helpers/settings.py', settings_methods)
    for method, is_async in settings_results.items():
        status = "✅" if is_async else "❌"
        print(f"  {status} {method}: {'async' if is_async else 'not async'}")
    results['settings.py'] = all(settings_results.values())
    
    # Check that await is used in tool files
    print("\n📋 Checking await usage in tool files...")
    tool_files = [
        'python/tools/code_execution_tool.py',
        'python/tools/input.py', 
        'python/tools/vision_load.py',
        'python/helpers/tool.py',
        'python/helpers/mcp_handler.py'
    ]
    
    await_results = {}
    for tool_file in tool_files:
        try:
            with open(tool_file, 'r') as f:
                content = f.read()
            has_await = 'await self.agent.hist_add_' in content
            await_results[tool_file] = has_await
            status = "✅" if has_await else "❌"
            print(f"  {status} {tool_file}: {'uses await' if has_await else 'missing await'}")
        except Exception as e:
            print(f"  ❌ {tool_file}: error - {e}")
            await_results[tool_file] = False
    
    results['tool_awaits'] = all(await_results.values())
    
    # Summary
    print(f"\n📊 Results Summary:")
    print(f"  agent.py async methods: {'✅' if results['agent.py'] else '❌'}")
    print(f"  settings.py async methods: {'✅' if results['settings.py'] else '❌'}")
    print(f"  tool file awaits: {'✅' if results['tool_awaits'] else '❌'}")
    
    overall_success = all(results.values())
    print(f"\n🎯 Overall: {'✅ All checks passed!' if overall_success else '❌ Some checks failed!'}")
    
    return 0 if overall_success else 1

if __name__ == "__main__":
    sys.exit(main())