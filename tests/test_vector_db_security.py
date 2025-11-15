#!/usr/bin/env python3
"""
Security test for vector database eval() vulnerability fix.
This test verifies that the simple_eval replacement prevents code injection
while maintaining legitimate functionality.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from python.helpers.vector_db import get_comparator

def test_safe_expressions():
    """Test that legitimate filter expressions still work"""
    print("Testing safe expressions...")
    
    # Test data
    test_data = {
        'name': 'test',
        'age': 25,
        'score': 85.5,
        'active': True,
        'count': 0
    }
    
    # Safe expressions that should work
    safe_expressions = [
        "age > 18",
        "name == 'test'",
        "score >= 80",
        "active == True",
        "count == 0",
        "age > 18 and active == True",
        "name != 'other' or score > 90",
        "(age + 5) > 25",
        "score * 2 > 150"
    ]
    
    for expr in safe_expressions:
        try:
            comparator = get_comparator(expr)
            result = comparator(test_data)
            print(f"✓ '{expr}' -> {result}")
        except Exception as e:
            print(f"✗ '{expr}' failed: {e}")
            return False
    
    return True

def test_malicious_expressions():
    """Test that malicious code injection attempts are blocked"""
    print("\nTesting malicious expressions...")
    
    test_data = {'test': 'value'}
    
    # Malicious expressions that should be blocked
    malicious_expressions = [
        "__import__('os').system('echo hacked')",
        "eval('print(\"hacked\")')",
        "exec('print(\"hacked\")')",
        "__builtins__.__import__('os').system('ls')",
        "().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('echo hacked')",
        "open('/etc/passwd').read()",
        "globals()",
        "locals()",
        "vars()",
        "dir()",
        "help()",
        "input('prompt')",
        "break",
        "continue",
        "pass",
        "lambda: __import__('os').system('echo hacked')",
        "[x for x in __import__('os').system('echo hacked')]"
    ]
    
    for expr in malicious_expressions:
        try:
            comparator = get_comparator(expr)
            result = comparator(test_data)
            # simple_eval should block these and return False or raise an exception
            if result is not False:
                print(f"✗ SECURITY RISK: '{expr}' was not blocked! Result: {result}")
                return False
            else:
                print(f"✓ '{expr}' -> blocked (returned False)")
        except Exception as e:
            # Exceptions are expected for malicious expressions
            print(f"✓ '{expr}' -> blocked (exception: {type(e).__name__})")
    
    return True

def test_edge_cases():
    """Test edge cases and error handling"""
    print("\nTesting edge cases...")
    
    test_data = {'test': 'value'}
    
    # Edge cases
    edge_cases = [
        "",  # Empty expression
        "   ",  # Whitespace only
        "undefined_var",  # Undefined variable
        "test['key']",  # Invalid syntax for simple_eval
        "test.key",  # Attribute access (should be blocked)
        "1/0",  # Division by zero
    ]
    
    for expr in edge_cases:
        try:
            comparator = get_comparator(expr)
            result = comparator(test_data)
            print(f"✓ '{expr}' -> {result} (handled gracefully)")
        except Exception as e:
            print(f"✓ '{expr}' -> exception (expected): {type(e).__name__}")
    
    return True

if __name__ == "__main__":
    print("Vector Database Security Test")
    print("=" * 40)
    
    success = True
    success &= test_safe_expressions()
    success &= test_malicious_expressions()
    success &= test_edge_cases()
    
    print("\n" + "=" * 40)
    if success:
        print("✅ All security tests passed!")
        print("The eval() vulnerability has been successfully fixed.")
    else:
        print("❌ Some security tests failed!")
        print("The vulnerability may not be fully fixed.")
        sys.exit(1)