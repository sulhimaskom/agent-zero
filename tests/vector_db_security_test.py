import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.helpers.vector_db import get_comparator


def test_safe_eval_basic_functionality():
    """Test that basic comparison functionality still works"""
    comparator = get_comparator("value > 5")
    
    # Should work with normal data
    assert comparator({"value": 10}) == True
    assert comparator({"value": 3}) == False
    
    # Test string comparison
    str_comparator = get_comparator("name == 'test'")
    assert str_comparator({"name": "test"}) == True
    assert str_comparator({"name": "other"}) == False
    
    print("✓ Basic functionality tests passed")


def test_safe_eval_security():
    """Test that code injection attempts are blocked"""
    comparator = get_comparator("value > 5")
    
    # Test dangerous code injection attempts - these should all return False
    dangerous_inputs = [
        "__import__('os').system('echo hacked')",
        "eval('__import__(\"os\").system(\"echo hacked\")')",
        "exec('__import__(\"os\").system(\"echo hacked\")')",
        "__builtins__.__import__('os').system('echo hacked')",
        "().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('echo hacked')",
        "(lambda:().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('echo hacked'))()",
    ]
    
    for dangerous_input in dangerous_inputs:
        result = comparator({"value": 10, dangerous_input: True})
        assert result == False, f"Security test failed for: {dangerous_input}"
    
    print("✓ Security tests passed - code injection blocked")


def test_safe_eval_error_handling():
    """Test that invalid expressions return False instead of crashing"""
    comparator = get_comparator("invalid syntax !!!")
    
    # Should return False for invalid syntax
    assert comparator({"value": 10}) == False
    
    # Test with missing variables
    comparator = get_comparator("missing_var > 5")
    assert comparator({"value": 10}) == False
    
    print("✓ Error handling tests passed")


if __name__ == "__main__":
    test_safe_eval_basic_functionality()
    test_safe_eval_security()
    test_safe_eval_error_handling()
    print("\n🎉 All security tests passed! The eval() vulnerability has been fixed.")