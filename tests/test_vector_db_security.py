#!/usr/bin/env python3
"""
Test suite for the safe expression evaluator in vector_db.py
This ensures the eval() vulnerability is fixed while maintaining functionality.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from python.helpers.vector_db import safe_eval_condition, get_comparator
import pytest


class TestSafeExpressionEvaluator:
    """Test cases for the safe expression evaluator."""
    
    def test_basic_comparisons(self):
        """Test basic comparison operations."""
        data = {"status": "active", "priority": 5, "score": 3.14}
        
        # String comparisons
        assert safe_eval_condition("status == 'active'", data) == True
        assert safe_eval_condition("status != 'inactive'", data) == True
        assert safe_eval_condition("status == 'inactive'", data) == False
        
        # Number comparisons
        assert safe_eval_condition("priority == 5", data) == True
        assert safe_eval_condition("priority > 3", data) == True
        assert safe_eval_condition("priority >= 5", data) == True
        assert safe_eval_condition("priority < 10", data) == True
        assert safe_eval_condition("priority <= 5", data) == True
        
        # Float comparisons
        assert safe_eval_condition("score == 3.14", data) == True
        assert safe_eval_condition("score > 3.0", data) == True
    
    def test_logical_operators(self):
        """Test logical operators (and, or)."""
        data = {"status": "active", "priority": 5, "enabled": True}
        
        # AND operations
        assert safe_eval_condition("status == 'active' and priority > 3", data) == True
        assert safe_eval_condition("status == 'active' and priority > 10", data) == False
        assert safe_eval_condition("status == 'inactive' and priority > 3", data) == False
        
        # OR operations
        assert safe_eval_condition("status == 'active' or priority > 10", data) == True
        assert safe_eval_condition("status == 'inactive' or priority > 10", data) == False
        assert safe_eval_condition("status == 'inactive' or priority > 3", data) == True
        
        # Complex expressions
        assert safe_eval_condition("status == 'active' and (priority > 3 or enabled)", data) == True
    
    def test_membership_operators(self):
        """Test in and not in operators."""
        data = {"tags": ["urgent", "important"], "status": "active"}
        
        # In operator
        assert safe_eval_condition("'urgent' in tags", data) == True
        assert safe_eval_condition("'critical' in tags", data) == False
        
        # Not in operator
        assert safe_eval_condition("'critical' not in tags", data) == True
        assert safe_eval_condition("'urgent' not in tags", data) == False
    
    def test_chained_comparisons(self):
        """Test chained comparisons."""
        data = {"priority": 5}
        
        assert safe_eval_condition("3 < priority < 10", data) == True
        assert safe_eval_condition("3 < priority <= 5", data) == True
        assert safe_eval_condition("5 <= priority < 10", data) == True
        assert safe_eval_condition("10 < priority < 20", data) == False
    
    def test_unary_operators(self):
        """Test unary operators."""
        data = {"enabled": True, "count": 5, "negative": -3}
        
        # NOT operator
        assert safe_eval_condition("not enabled", data) == False
        assert safe_eval_condition("not (priority > 10)", {"priority": 5}) == True
        
        # Unary plus/minus
        assert safe_eval_condition("+count == 5", data) == True
        assert safe_eval_condition("-negative == 3", data) == True
    
    def test_attribute_access(self):
        """Test attribute access on objects."""
        data = {"obj": type('TestObj', (), {'attr': 'value', 'num': 42})()}
        
        assert safe_eval_condition("obj.attr == 'value'", data) == True
        assert safe_eval_condition("obj.num == 42", data) == True
        assert safe_eval_condition("obj.num > 40", data) == True
    
    def test_get_comparator_function(self):
        """Test the get_comparator function."""
        data = {"status": "active", "priority": 5}
        
        comparator = get_comparator("status == 'active'")
        assert comparator(data) == True
        
        comparator = get_comparator("priority > 3")
        assert comparator(data) == True
        
        comparator = get_comparator("status == 'inactive'")
        assert comparator(data) == False
    
    def test_error_handling(self):
        """Test error handling for invalid expressions."""
        data = {"status": "active", "priority": 5}
        
        # Invalid syntax
        with pytest.raises(SyntaxError):
            safe_eval_condition("status == 'active'", data)  # This should work
        with pytest.raises(SyntaxError):
            safe_eval_condition("status == ", data)  # Invalid syntax
        
        # Unknown field
        assert safe_eval_condition("unknown_field == 'test'", data) == False
        
        # Unsupported operations should return False (not crash)
        assert safe_eval_condition("__import__('os')", data) == False
        assert safe_eval_condition("eval('test')", data) == False
    
    def test_security_rejections(self):
        """Test that dangerous operations are rejected."""
        data = {"status": "active", "priority": 5}
        
        # Function calls should be rejected
        assert safe_eval_condition("len(status)", data) == False
        assert safe_eval_condition("print('test')", data) == False
        
        # Imports should be rejected
        assert safe_eval_condition("__import__('os')", data) == False
        assert safe_eval_condition("import os", data) == False
        
        # Exec/eval should be rejected
        assert safe_eval_condition("exec('print(test)')", data) == False
        assert safe_eval_condition("eval('test')", data) == False
        
        # Attribute access on builtins should be rejected
        assert safe_eval_condition("__builtins__.__import__('os')", data) == False
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        data = {"value": None, "text": "", "number": 0, "boolean": False}
        
        # None handling
        assert safe_eval_condition("value == None", data) == True
        assert safe_eval_condition("value != None", data) == False
        
        # Empty string
        assert safe_eval_condition("text == ''", data) == True
        assert safe_eval_condition("text != ''", data) == False
        
        # Zero
        assert safe_eval_condition("number == 0", data) == True
        assert safe_eval_condition("number > 0", data) == False
        
        # False boolean
        assert safe_eval_condition("boolean == False", data) == True
        assert safe_eval_condition("boolean == True", data) == False


if __name__ == "__main__":
    # Run basic tests if pytest is not available
    test = TestSafeExpressionEvaluator()
    
    print("Running basic safety tests...")
    
    # Test basic functionality
    try:
        test.test_basic_comparisons()
        test.test_logical_operators()
        test.test_membership_operators()
        test.test_chained_comparisons()
        test.test_unary_operators()
        test.test_get_comparator_function()
        test.test_error_handling()
        test.test_security_rejections()
        test.test_edge_cases()
        print("✅ All tests passed! The eval() vulnerability has been fixed.")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)