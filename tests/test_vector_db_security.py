import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.vector_db import get_comparator


class TestVectorDBSecurity(unittest.TestCase):
    """Test suite for vector database security validation."""

    def test_safe_expression_evaluation(self):
        """Test that safe expressions work correctly."""
        test_data = {"name": "test", "value": 42, "active": True}
        
        # Test safe comparisons
        safe_expressions = [
            ("name == 'test'", True),
            ("value == 42", True),
            ("value > 40", True),
            ("active == True", True),
            ("name != 'other'", True),
            ("value >= 42", True),
            ("value <= 42", True),
        ]
        
        for expression, expected in safe_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertEqual(result, expected, f"Expression '{expression}' should return {expected}")

    def test_code_injection_attempts_blocked(self):
        """Test that code injection attempts are blocked."""
        test_data = {"name": "test", "value": 42}
        
        # Dangerous code injection attempts
        dangerous_expressions = [
            "__import__('os').system('echo hacked')",
            "exec('print(\"hacked\")')",
            "eval('__import__(\"os\").system(\"echo hacked\")')",
            "open('/etc/passwd', 'r').read()",
            "globals()",
            "locals()",
            "__builtins__",
            "().__class__.__bases__[0].__subclasses__()",
            "test_data.update({'hacked': True}) or True",
            "lambda: __import__('os').system('echo hacked')",
        ]
        
        for expression in dangerous_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertFalse(result, f"Dangerous expression '{expression}' should be blocked")

    def test_malformed_expressions_handled_safely(self):
        """Test that malformed expressions are handled safely."""
        test_data = {"name": "test", "value": 42}
        
        # Malformed expressions
        malformed_expressions = [
            "name == ",  # incomplete
            "value > > 42",  # syntax error
            "active and and True",  # syntax error
            "name == 'test",  # unclosed quote
            "42 +",  # incomplete operation
            "",  # empty string
            "   ",  # whitespace only
        ]
        
        for expression in malformed_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertFalse(result, f"Malformed expression '{expression}' should return False")

    def test_complex_logical_expressions(self):
        """Test that complex logical expressions work safely."""
        test_data = {
            "name": "test", 
            "value": 42, 
            "active": True, 
            "category": "important",
            "score": 85.5
        }
        
        # Safe complex expressions
        complex_expressions = [
            ("name == 'test' and value == 42", True),
            ("active == True and category == 'important'", True),
            ("value > 40 and score > 80", True),
            ("name == 'test' or category == 'other'", True),
            ("not (name == 'other')", True),
            ("value >= 40 and value <= 50 and active == True", True),
        ]
        
        for expression, expected in complex_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertEqual(result, expected, f"Complex expression '{expression}' should return {expected}")

    def test_data_access_isolation(self):
        """Test that only provided data can be accessed."""
        test_data = {"name": "test", "value": 42}
        
        # Attempts to access external data should fail
        external_access_attempts = [
            "test_data.get('name') == 'test'",  # test_data shouldn't be in scope
            "len(name) > 0",  # len function shouldn't be available
            "str(value) == '42'",  # str function shouldn't be available
        ]
        
        for expression in external_access_attempts:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertFalse(result, f"External access attempt '{expression}' should be blocked")

    def test_exception_handling(self):
        """Test that exceptions are handled gracefully."""
        test_data = {"name": "test", "value": 42}
        
        # Expressions that might cause exceptions
        exception_causing_expressions = [
            "nonexistent_field == 'test'",  # KeyError
            "value / 0 == 0",  # ZeroDivisionError
            "name.upper() == 'TEST'",  # AttributeError (method calls not allowed)
        ]
        
        for expression in exception_causing_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertFalse(result, f"Exception-causing expression '{expression}' should return False")

    def test_numeric_operations(self):
        """Test that numeric operations work correctly."""
        test_data = {"value": 42, "score": 85.5, "count": 0}
        
        # Safe numeric operations
        numeric_expressions = [
            ("value == 42", True),
            ("score > 80", True),
            ("count == 0", True),
            ("value + score > 100", True),
            ("value * 2 == 84", True),
            ("score - value > 40", True),
            ("value / 2 == 21", True),
        ]
        
        for expression, expected in numeric_expressions:
            with self.subTest(expression=expression):
                comparator = get_comparator(expression)
                result = comparator(test_data)
                self.assertEqual(result, expected, f"Numeric expression '{expression}' should return {expected}")


if __name__ == '__main__':
    unittest.main()