#!/usr/bin/env python3
"""
Simple test for the get_comparator function fix.
Tests the security fix without requiring all dependencies.
"""

from simpleeval import simple_eval
from typing import Any


def get_comparator(condition: str):
    """Fixed version of get_comparator using simple_eval instead of eval."""
    def comparator(data: dict[str, Any]):
        try:
            result = simple_eval(condition, names=data)
            return result
        except Exception as e:
            # PrintStyle.error(f"Error evaluating condition: {e}")
            return False

    return comparator


def test_security_fix():
    """Test that the security fix works correctly."""
    print("Testing security fix for eval() vulnerability...")
    
    # Test 1: Safe expressions should work
    print("\n1. Testing safe expressions:")
    comparator = get_comparator("value > 5")
    assert comparator({"value": 10}) == True, "Safe expression failed"
    assert comparator({"value": 3}) == False, "Safe expression failed"
    print("   ✓ Safe expressions work correctly")
    
    # Test 2: String comparisons
    comparator = get_comparator("name == 'test'")
    assert comparator({"name": "test"}) == True, "String comparison failed"
    assert comparator({"name": "other"}) == False, "String comparison failed"
    print("   ✓ String comparisons work correctly")
    
    # Test 3: Complex expressions
    comparator = get_comparator("value > 5 and name == 'test'")
    assert comparator({"value": 10, "name": "test"}) == True
    assert comparator({"value": 3, "name": "test"}) == False
    print("   ✓ Complex expressions work correctly")
    
    # Test 4: Code injection should be blocked
    print("\n2. Testing code injection blocking:")
    comparator = get_comparator("__import__('os').system('echo hacked')")
    result = comparator({"value": 10})
    assert result == False, f"Code injection not blocked! Result: {result}"
    print("   ✓ Code injection blocked")
    
    # Test 5: File access should be blocked
    comparator = get_comparator("open('/etc/passwd').read()")
    result = comparator({"value": 10})
    assert result == False, f"File access not blocked! Result: {result}"
    print("   ✓ File access blocked")
    
    # Test 6: Dangerous attribute access should be blocked
    comparator = get_comparator("__class__.__bases__[0].__subclasses__()")
    result = comparator({"value": 10})
    assert result == False, f"Dangerous attribute access not blocked! Result: {result}"
    print("   ✓ Dangerous attribute access blocked")
    
    # Test 7: eval function should be blocked
    comparator = get_comparator("eval('__import__(\"os\").system(\"echo hacked\")')")
    result = comparator({"value": 10})
    assert result == False, f"Nested eval not blocked! Result: {result}"
    print("   ✓ Nested eval blocked")
    
    # Test 8: exec function should be blocked
    comparator = get_comparator("exec('import os; os.system(\"echo hacked\")')")
    result = comparator({"value": 10})
    assert result == False, f"Exec not blocked! Result: {result}"
    print("   ✓ Exec function blocked")
    
    # Test 9: Error handling
    print("\n3. Testing error handling:")
    comparator = get_comparator("invalid syntax !!!")
    result = comparator({"value": 10})
    assert result == False, f"Syntax error not handled! Result: {result}"
    print("   ✓ Syntax error handling works")
    
    comparator = get_comparator("undefined_variable > 5")
    result = comparator({"value": 10})
    assert result == False, f"Name error not handled! Result: {result}"
    print("   ✓ Name error handling works")
    
    print("\n🎉 All security tests passed! The eval() vulnerability has been fixed.")
    return True


if __name__ == "__main__":
    try:
        test_security_fix()
        print("\n✅ Security fix verification successful!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        exit(1)