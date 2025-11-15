#!/usr/bin/env python3
"""
Security tests for vector database comparator function.
Tests the fix for critical eval() vulnerability.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.vector_db import get_comparator


class TestVectorDbSecurity:
    """Test security of vector database comparator function."""
    
    def test_safe_expressions_work(self):
        """Test that legitimate expressions still work."""
        comparator = get_comparator("value > 5")
        
        # Should work with valid data
        assert comparator({"value": 10}) == True
        assert comparator({"value": 3}) == False
        
        # Test string comparisons
        comparator = get_comparator("name == 'test'")
        assert comparator({"name": "test"}) == True
        assert comparator({"name": "other"}) == False
        
        # Test compound expressions
        comparator = get_comparator("value > 5 and name == 'test'")
        assert comparator({"value": 10, "name": "test"}) == True
        assert comparator({"value": 3, "name": "test"}) == False
        assert comparator({"value": 10, "name": "other"}) == False
    
    def test_code_injection_blocked(self):
        """Test that code injection attempts are blocked."""
        comparator = get_comparator("__import__('os').system('echo hacked')")
        
        # Should return False, not execute the command
        result = comparator({"value": 10})
        assert result == False
    
    def test_file_access_blocked(self):
        """Test that file system access is blocked."""
        comparator = get_comparator("open('/etc/passwd').read()")
        
        # Should return False, not read the file
        result = comparator({"value": 10})
        assert result == False
    
    def test_attribute_access_blocked(self):
        """Test that dangerous attribute access is blocked."""
        comparator = get_comparator("__class__.__bases__[0].__subclasses__()")
        
        # Should return False, not access internal attributes
        result = comparator({"value": 10})
        assert result == False
    
    def test_eval_function_blocked(self):
        """Test that eval function cannot be accessed."""
        comparator = get_comparator("eval('__import__(\"os\").system(\"echo hacked\")')")
        
        # Should return False, not execute nested eval
        result = comparator({"value": 10})
        assert result == False
    
    def test_exec_function_blocked(self):
        """Test that exec function cannot be accessed."""
        comparator = get_comparator("exec('import os; os.system(\"echo hacked\")')")
        
        # Should return False, not execute exec
        result = comparator({"value": 10})
        assert result == False
    
    def test_malicious_string_operations_blocked(self):
        """Test that malicious string operations are blocked."""
        # Try to use string formatting to access builtins
        comparator = get_comparator("''.__class__.__mro__[1].__subclasses__()[104]('echo hacked').read()")
        
        # Should return False
        result = comparator({"value": 10})
        assert result == False
    
    def test_syntax_error_handling(self):
        """Test that syntax errors are handled gracefully."""
        comparator = get_comparator("invalid syntax !!!")
        
        # Should return False on syntax error
        result = comparator({"value": 10})
        assert result == False
    
    def test_name_error_handling(self):
        """Test that name errors are handled gracefully."""
        comparator = get_comparator("undefined_variable > 5")
        
        # Should return False on name error
        result = comparator({"value": 10})
        assert result == False
    
    def test_empty_condition(self):
        """Test behavior with empty condition."""
        comparator = get_comparator("")
        
        # Should handle gracefully
        result = comparator({"value": 10})
        # simple_eval might raise an exception for empty expressions
        assert result == False
    
    def test_none_data_handling(self):
        """Test handling of None values in data."""
        comparator = get_comparator("value > 5")
        
        # Should handle None values gracefully
        result = comparator({"value": None})
        assert result == False
    
    def test_complex_nested_expressions(self):
        """Test complex but safe nested expressions."""
        comparator = get_comparator("(a + b) * 2 > 10 and c != 'test'")
        
        # Should work with valid complex expressions
        assert comparator({"a": 3, "b": 3, "c": "other"}) == True
        assert comparator({"a": 2, "b": 2, "c": "test"}) == False


if __name__ == "__main__":
    # Run tests if script is executed directly
    test_instance = TestVectorDbSecurity()
    
    print("Running security tests for vector database comparator...")
    
    try:
        test_instance.test_safe_expressions_work()
        print("✓ Safe expressions work correctly")
        
        test_instance.test_code_injection_blocked()
        print("✓ Code injection blocked")
        
        test_instance.test_file_access_blocked()
        print("✓ File access blocked")
        
        test_instance.test_attribute_access_blocked()
        print("✓ Dangerous attribute access blocked")
        
        test_instance.test_eval_function_blocked()
        print("✓ Nested eval blocked")
        
        test_instance.test_exec_function_blocked()
        print("✓ Exec function blocked")
        
        test_instance.test_malicious_string_operations_blocked()
        print("✓ Malicious string operations blocked")
        
        test_instance.test_syntax_error_handling()
        print("✓ Syntax error handling works")
        
        test_instance.test_name_error_handling()
        print("✓ Name error handling works")
        
        test_instance.test_empty_condition()
        print("✓ Empty condition handled")
        
        test_instance.test_none_data_handling()
        print("✓ None values handled")
        
        test_instance.test_complex_nested_expressions()
        print("✓ Complex safe expressions work")
        
        print("\n🎉 All security tests passed! The eval() vulnerability has been fixed.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)