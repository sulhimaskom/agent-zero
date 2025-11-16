"""
Comprehensive security tests for the safe expression evaluator.
Tests ensure that the evaluator prevents code injection while maintaining functionality.
"""

import pytest
import sys
import os

# Add the python directory to the path so we can import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from python.helpers.vector_db import SafeExpressionEvaluator, get_comparator


class TestSafeExpressionEvaluator:
    """Test cases for the SafeExpressionEvaluator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.evaluator = SafeExpressionEvaluator()
        self.test_data = {
            'age': 25,
            'name': 'John',
            'score': 85.5,
            'active': True,
            'tags': ['admin', 'user'],
            'permissions': {'read': True, 'write': False},
            'count': 0,
            'balance': -100.50
        }
    
    def test_safe_comparisons(self):
        """Test safe comparison operations."""
        # Equality
        assert self.evaluator.evaluate("age == 25", self.test_data) == True
        assert self.evaluator.evaluate("name == 'John'", self.test_data) == True
        assert self.evaluator.evaluate("age == 30", self.test_data) == False
        
        # Inequality
        assert self.evaluator.evaluate("age != 30", self.test_data) == True
        assert self.evaluator.evaluate("name != 'Jane'", self.test_data) == True
        
        # Less than
        assert self.evaluator.evaluate("age < 30", self.test_data) == True
        assert self.evaluator.evaluate("score < 90", self.test_data) == True
        
        # Less than or equal
        assert self.evaluator.evaluate("age <= 25", self.test_data) == True
        assert self.evaluator.evaluate("score <= 85.5", self.test_data) == True
        
        # Greater than
        assert self.evaluator.evaluate("age > 20", self.test_data) == True
        assert self.evaluator.evaluate("score > 80", self.test_data) == True
        
        # Greater than or equal
        assert self.evaluator.evaluate("age >= 25", self.test_data) == True
        assert self.evaluator.evaluate("score >= 85.5", self.test_data) == True
    
    def test_boolean_operations(self):
        """Test boolean AND and OR operations."""
        # AND operations
        assert self.evaluator.evaluate("age > 20 and name == 'John'", self.test_data) == True
        assert self.evaluator.evaluate("age > 30 and name == 'John'", self.test_data) == False
        assert self.evaluator.evaluate("age > 20 and name == 'Jane'", self.test_data) == False
        
        # OR operations
        assert self.evaluator.evaluate("age > 30 or name == 'John'", self.test_data) == True
        assert self.evaluator.evaluate("age > 30 or name == 'Jane'", self.test_data) == False
        
        # Complex boolean expressions
        assert self.evaluator.evaluate("(age > 20 and name == 'John') or active == False", self.test_data) == True
        assert self.evaluator.evaluate("age > 20 and (name == 'John' or name == 'Jane')", self.test_data) == True
    
    def test_membership_operations(self):
        """Test 'in' and 'not in' operations."""
        # In operations
        assert self.evaluator.evaluate("'admin' in tags", self.test_data) == True
        assert self.evaluator.evaluate("'guest' in tags", self.test_data) == False
        assert self.evaluator.evaluate("25 in [25, 30, 35]", self.test_data) == True
        
        # Not in operations
        assert self.evaluator.evaluate("'guest' not in tags", self.test_data) == True
        assert self.evaluator.evaluate("'admin' not in tags", self.test_data) == False
    
    def test_arithmetic_operations(self):
        """Test safe arithmetic operations."""
        # Basic arithmetic
        assert self.evaluator.evaluate("age + 5 == 30", self.test_data) == True
        assert self.evaluator.evaluate("age - 5 == 20", self.test_data) == True
        assert self.evaluator.evaluate("age * 2 == 50", self.test_data) == True
        assert self.evaluator.evaluate("age / 5 == 5", self.test_data) == True
        assert self.evaluator.evaluate("age % 3 == 1", self.test_data) == True
        assert self.evaluator.evaluate("2 ** 3 == 8", self.test_data) == True
        
        # Negative numbers
        assert self.evaluator.evaluate("balance < 0", self.test_data) == True
        assert self.evaluator.evaluate("-balance > 0", self.test_data) == True
        
        # Unary operations
        assert self.evaluator.evaluate("+age == 25", self.test_data) == True
        assert self.evaluator.evaluate("-age == -25", self.test_data) == True
        assert self.evaluator.evaluate("not active == False", self.test_data) == True
    
    def test_chained_comparisons(self):
        """Test chained comparison operations."""
        assert self.evaluator.evaluate("20 < age < 30", self.test_data) == True
        assert self.evaluator.evaluate("80 < score <= 85.5", self.test_data) == True
        assert self.evaluator.evaluate("30 < age < 40", self.test_data) == False
    
    def test_complex_data_structures(self):
        """Test operations with lists, tuples, sets, and dictionaries."""
        # List operations - function calls should be rejected for security
        with pytest.raises(ValueError, match="Unsafe or invalid expression"):
            self.evaluator.evaluate("len(tags) == 2", self.test_data)
        assert self.evaluator.evaluate("tags == ['admin', 'user']", self.test_data) == True
        
        # Dictionary access through values
        test_data_with_dict = {'data': {'key': 'value'}}
        assert self.evaluator.evaluate("data == {'key': 'value'}", test_data_with_dict) == True
    
    def test_code_injection_attempts(self):
        """Test that various code injection attempts are blocked."""
        dangerous_expressions = [
            # Function calls
            "__import__('os').system('echo hacked')",
            "eval('print(hacked)')",
            "exec('print(hacked)')",
            "open('/etc/passwd', 'r')",
            "print('hacked')",
            
            # Attribute access
            "os.system('echo hacked')",
            "().__class__.__bases__[0].__subclasses__()[0]('etc/passwd').read()",
            
            # List comprehensions (can be used for code execution)
            "[x for x in range(10)]",
            "{x: x*2 for x in range(5)}",
            
            # Lambda expressions
            "lambda x: x*2",
            
            # Generator expressions
            "(x for x in range(10))",
            
            # Slicing with complex expressions
            "tags[0:__import__('os').system('echo hacked')]",
            
            # Format strings that can execute code
            "f'{__import__(\"os\").system(\"echo hacked\")}'",
            
            # Comprehensions with side effects
            "[__import__('os').system('echo hacked') for x in range(1)]",
            
            # Built-in function access
            "globals()",
            "locals()",
            "vars()",
            "dir()",
            
            # Module access
            "sys.modules",
            "sys.path",
            
            # Type operations
            "type('')",
            "isinstance('', str)",
            
            # Subscript with dangerous expressions
            "tags[__import__('os').system('echo hacked')]",
        ]
        
        for expr in dangerous_expressions:
            with pytest.raises(ValueError, match="Unsafe or invalid expression"):
                self.evaluator.evaluate(expr, self.test_data)
    
    def test_undefined_variables(self):
        """Test that undefined variables are properly rejected."""
        with pytest.raises(ValueError, match="Undefined variable"):
            self.evaluator.evaluate("undefined_var == 5", self.test_data)
        
        with pytest.raises(ValueError, match="Undefined variable"):
            self.evaluator.evaluate("unknown_field > 10", self.test_data)
    
    def test_syntax_errors(self):
        """Test that syntax errors are properly handled."""
        invalid_expressions = [
            "age ==",  # Incomplete expression
            "age > 20 and",  # Incomplete boolean expression
            "name == 'John' or",  # Incomplete OR expression
            "age + + 5",  # Invalid syntax
            "age && 20",  # Invalid operator
            "age || 20",  # Invalid operator
        ]
        
        for expr in invalid_expressions:
            with pytest.raises((ValueError, SyntaxError)):
                self.evaluator.evaluate(expr, self.test_data)
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Empty strings
        assert self.evaluator.evaluate("name == ''", {'name': ''}) == True
        
        # Zero values
        assert self.evaluator.evaluate("count == 0", self.test_data) == True
        
        # Boolean values
        assert self.evaluator.evaluate("active == True", self.test_data) == True
        assert self.evaluator.evaluate("active == False", {'active': False}) == True
        
        # None values
        assert self.evaluator.evaluate("value == None", {'value': None}) == True
        
        # Float precision
        assert self.evaluator.evaluate("score == 85.5", self.test_data) == True
        
        # Large numbers
        large_data = {'big': 999999999999999999}
        assert self.evaluator.evaluate("big == 999999999999999999", large_data) == True


class TestGetComparator:
    """Test cases for the get_comparator function."""
    
    def test_get_comparator_basic_functionality(self):
        """Test that get_comparator returns a working function."""
        comparator = get_comparator("age > 18")
        assert comparator({'age': 25}) == True
        assert comparator({'age': 15}) == False
    
    def test_get_comparator_exception_handling(self):
        """Test that get_comparator handles exceptions gracefully."""
        comparator = get_comparator("invalid expression with undefined_var")
        # Should return False instead of raising exception
        assert comparator({'age': 25}) == False
        
        comparator = get_comparator("age > 18 and name == 'John'")
        assert comparator({'age': 25, 'name': 'John'}) == True
        assert comparator({'age': 25, 'name': 'Jane'}) == False
    
    def test_get_comparator_with_complex_data(self):
        """Test get_comparator with complex data structures."""
        comparator = get_comparator("'admin' in tags")
        assert comparator({'tags': ['user', 'admin']}) == True
        assert comparator({'tags': ['user']}) == False


class TestSecurityVulnerabilityFix:
    """Test that the original security vulnerability is fixed."""
    
    def test_prevent_code_execution_via_eval(self):
        """Test that the original eval() vulnerability is completely fixed."""
        # These expressions would have worked with the original eval() implementation
        # but should now be blocked
        dangerous_expressions = [
            "__import__('os').system('echo pwned')",
            "().__class__.__bases__[0].__subclasses__()[0]('/etc/passwd').read()",
            "eval('__import__(\"os\").system(\"echo pwned\")')",
            "exec('__import__(\"os\").system(\"echo pwned\")')",
            "open('/etc/passwd', 'r').read()",
            "globals()['__import__']('os').system('echo pwned')",
        ]
        
        test_data = {'safe_var': 'safe_value'}
        
        for expr in dangerous_expressions:
            comparator = get_comparator(expr)
            # Should always return False, never execute the dangerous code
            result = comparator(test_data)
            assert result == False, f"Dangerous expression was not blocked: {expr}"


if __name__ == '__main__':
    # Run the tests
    pytest.main([__file__, '-v'])