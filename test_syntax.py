#!/usr/bin/env python3
"""
Simple syntax test to verify that the async fixes are syntactically correct.
"""
import ast
import sys
import os

def test_syntax(file_path):
    """Test that a file has valid Python syntax"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, str(e)

def main():
    print("Testing syntax of modified files...")
    
    files_to_test = [
        'agent.py',
        'python/helpers/tool.py',
        'python/helpers/settings.py',
        'python/helpers/mcp_handler.py',
        'python/tools/code_execution_tool.py',
        'python/tools/input.py',
        'python/tools/vision_load.py'
    ]
    
    all_passed = True
    
    for file_path in files_to_test:
        success, error = test_syntax(file_path)
        if success:
            print(f"✓ {file_path} - syntax OK")
        else:
            print(f"✗ {file_path} - syntax error: {error}")
            all_passed = False
    
    # Check for remaining asyncio.run calls in async contexts
    print("\nChecking for remaining asyncio.run calls...")
    with open('agent.py', 'r') as f:
        agent_content = f.read()
    
    # Look for asyncio.run calls that are not in __init__ method
    lines = agent_content.split('\n')
    problematic_lines = []
    
    for i, line in enumerate(lines, 1):
        if 'asyncio.run(' in line and '__init__' not in line:
            # Check if this line is in an async method by looking backwards
            in_async_method = False
            for j in range(i-1, max(0, i-20), -1):
                if lines[j-1].strip().startswith('async def '):
                    in_async_method = True
                    break
                elif lines[j-1].strip().startswith('def '):
                    break
            
            if in_async_method:
                problematic_lines.append(f"Line {i}: {line.strip()}")
    
    if problematic_lines:
        print("✗ Found asyncio.run calls in async contexts:")
        for line in problematic_lines:
            print(f"  {line}")
        all_passed = False
    else:
        print("✓ No problematic asyncio.run calls found")
    
    if all_passed:
        print("\n✓ All syntax tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)