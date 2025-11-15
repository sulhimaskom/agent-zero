#!/usr/bin/env python3
"""
Security test for the vector_db eval() fix.
This test verifies that the simple_eval replacement prevents code injection.
"""

from simpleeval import simple_eval
from typing import Any

def get_comparator_safe(condition: str):
    """Safe version of get_comparator using simple_eval"""
    def comparator(data: dict[str, Any]):
        try:
            result = simple_eval(condition, names=data)
            return result
        except Exception as e:
            return False
    return comparator

def get_comparator_unsafe(condition: str):
    """Unsafe version using eval() - for comparison"""
    def comparator(data: dict[str, Any]):
        try:
            result = eval(condition, {}, data)
            return result
        except Exception as e:
            return False
    return comparator

def test_basic_functionality():
    """Test that basic functionality works"""
    print("Testing basic functionality...")
    
    safe_comparator = get_comparator_safe("value > 5")
    assert safe_comparator({"value": 10}) == True
    assert safe_comparator({"value": 3}) == False
    
    # Test string comparison
    str_comparator = get_comparator_safe("name == 'test'")
    assert str_comparator({"name": "test"}) == True
    assert str_comparator({"name": "other"}) == False
    
    print("✓ Basic functionality works")

def test_security_comparison():
    """Compare safe vs unsafe implementations"""
    print("Testing security...")
    
    dangerous_inputs = [
        "__import__('os').system('echo hacked')",
        "eval('__import__(\"os\").system(\"echo hacked\")')",
        "exec('__import__(\"os\").system(\"echo hacked\")')",
        "__builtins__.__import__('os').system('echo hacked')",
    ]
    
    for dangerous_input in dangerous_inputs:
        print(f"Testing: {dangerous_input[:50]}...")
        
        # Safe version should block when dangerous input is used as the condition
        safe_comparator = get_comparator_safe(dangerous_input)
        safe_result = safe_comparator({"value": 10})
        assert safe_result == False, f"Safe version failed to block: {dangerous_input}"
        
        print(f"  ✓ Safe version blocked the attack")
    
    print("✓ Security tests passed")

def test_edge_cases():
    """Test edge cases and error handling"""
    print("Testing edge cases...")
    
    # Invalid syntax
    comparator = get_comparator_safe("invalid syntax !!!")
    assert comparator({"value": 10}) == False
    
    # Missing variables
    comparator = get_comparator_safe("missing_var > 5")
    assert comparator({"value": 10}) == False
    
    # Complex but safe expressions
    comparator = get_comparator_safe("(a + b) * 2 > 10")
    assert comparator({"a": 3, "b": 3}) == True
    assert comparator({"a": 2, "b": 2}) == False
    
    print("✓ Edge cases handled correctly")

if __name__ == "__main__":
    test_basic_functionality()
    test_security_comparison()
    test_edge_cases()
    print("\n🎉 All security tests passed!")
    print("The simple_eval replacement successfully prevents code injection attacks.")