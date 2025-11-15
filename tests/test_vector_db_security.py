#!/usr/bin/env python3
"""
Security tests for the vector database safe expression evaluation.
Tests that the eval() vulnerability has been properly fixed.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from python.helpers.vector_db import safe_eval_condition, get_comparator


class TestSafeExpressionEvaluation:
    """Test safe expression evaluation functionality."""
    
    def test_safe_basic_expressions(self):
        """Test that basic safe expressions work correctly."""
        data = {"age": 25, "name": "John", "scores": [85, 90, 78]}
        
        # Basic comparisons
        assert safe_eval_condition("age > 18", data) == True
        assert safe_eval_condition("age < 30", data) == True
        assert safe_eval_condition("age == 25", data) == True
        assert safe_eval_condition("age != 30", data) == True
        assert safe_eval_condition("age >= 25", data) == True
        assert safe_eval_condition("age <= 25", data) == True
        
        # String comparisons
        assert safe_eval_condition("name == 'John'", data) == True
        assert safe_eval_condition("name != 'Jane'", data) == True
        
        # List operations
        assert safe_eval_condition("len(scores) == 3", data) == True
        assert safe_eval_condition("85 in scores", data) == True
        assert safe_eval_condition("95 not in scores", data) == True
    
    def test_safe_logical_expressions(self):
        """Test that logical expressions work correctly."""
        data = {"age": 25, "name": "John", "student": True}
        
        # AND operations
        assert safe_eval_condition("age > 18 and student", data) == True
        assert safe_eval_condition("age > 30 and student", data) == False
        
        # OR operations
        assert safe_eval_condition("age > 30 or student", data) == True
        assert safe_eval_condition("age > 30 or name == 'Jane'", data) == False
        
        # NOT operations
        assert safe_eval_condition("not (age > 30)", data) == True
        assert safe_eval_condition("not student", data) == False
    
    def test_safe_function_calls(self):
        """Test that safe function calls work correctly."""
        data = {"text": "hello world", "numbers": [1, 2, 3, 4, 5]}
        
        # String functions
        assert safe_eval_condition("len(text) == 11", data) == True
        assert safe_eval_condition("str(age) == '25'", {"age": 25}) == True
        
        # Math functions
        assert safe_eval_condition("abs(-5) == 5", {}) == True
        assert safe_eval_condition("min(1, 2, 3) == 1", {}) == True
        assert safe_eval_condition("max(1, 2, 3) == 3", {}) == True
        assert safe_eval_condition("sum([1, 2, 3]) == 6", {}) == True
        
        # List functions
        assert safe_eval_condition("any([True, False])", {}) == True
        assert safe_eval_condition("all([True, True])", {}) == True
        assert safe_eval_condition("all([True, False])", {}) == False
    
    def test_comparator_function(self):
        """Test that the get_comparator function works correctly."""
        data = {"age": 25, "name": "John", "active": True}
        
        comparator = get_comparator("age > 18")
        assert comparator(data) == True
        
        comparator = get_comparator("name == 'John' and active")
        assert comparator(data) == True
        
        comparator = get_comparator("age > 30")
        assert comparator(data) == False
    
    def test_malicious_code_injection_attempts(self):
        """Test that malicious code injection attempts are blocked."""
        data = {"age": 25, "name": "John"}
        
        # Import attempts (should be blocked)
        malicious_attempts = [
            "__import__('os').system('echo hacked')",
            "import os; os.system('echo hacked')",
            "eval('__import__(\"os\").system(\"echo hacked\")')",
            "exec('__import__(\"os\").system(\"echo hacked\")')",
            "globals()['__import__']('os').system('echo hacked')",
            "locals()['__import__']('os').system('echo hacked')",
            "().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('echo hacked')",
            "().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['builtins'].eval('__import__(\"os\").system(\"echo hacked\")')",
        ]
        
        for malicious_code in malicious_attempts:
            result = safe_eval_condition(malicious_code, data)
            assert result == False, f"Malicious code was not blocked: {malicious_code}"
    
    def test_unsafe_operations_blocked(self):
        """Test that unsafe operations are properly blocked."""
        data = {"age": 25, "name": "John"}
        
        # Unsafe operators and constructs
        unsafe_attempts = [
            "age + name",  # Type coercion that could be exploited
            "age ** 2",    # Exponentiation not in whitelist
            "age // 2",    # Floor division not in whitelist  
            "age % 2",     # Modulo not in whitelist
            "age << 1",    # Bitwise operations not in whitelist
            "age >> 1",    # Bitwise operations not in whitelist
            "age & 1",     # Bitwise operations not in whitelist
            "age | 1",     # Bitwise operations not in whitelist
            "age ^ 1",     # Bitwise operations not in whitelist
            "~age",        # Bitwise NOT not in whitelist
            "lambda x: x", # Lambda expressions not allowed
            "[x for x in []]", # List comprehensions not allowed
            "{x: x for x in []}", # Dict comprehensions not allowed
            "(x for x in [])", # Generator expressions not allowed
        ]
        
        for unsafe_code in unsafe_attempts:
            result = safe_eval_condition(unsafe_code, data)
            assert result == False, f"Unsafe operation was not blocked: {unsafe_code}"
    
    def test_unsafe_function_calls_blocked(self):
        """Test that unsafe function calls are blocked."""
        data = {"age": 25, "name": "John"}
        
        # Unsafe function calls
        unsafe_function_attempts = [
            "open('test.txt', 'w')",
            "print('hello')",
            "input('prompt')",
            "eval('1+1')",
            "exec('print(1)')",
            "compile('1+1', '', 'eval')",
            "getattr(data, 'keys')",
            "setattr(data, 'test', 1)",
            "delattr(data, 'age')",
            "hasattr(data, 'age')",
            "isinstance(data, dict)",
            "issubclass(dict, object)",
            "iter([1,2,3])",
            "next(iter([1,2,3]))",
            "range(10)",
            "enumerate([1,2,3])",
            "zip([1,2], [3,4])",
            "map(len, ['a', 'bb'])",
            "filter(lambda x: x>0, [1,-1,2])",
            "sorted([3,1,2])",
            "reversed([1,2,3])",
        ]
        
        for unsafe_code in unsafe_function_attempts:
            result = safe_eval_condition(unsafe_code, data)
            assert result == False, f"Unsafe function call was not blocked: {unsafe_code}"
    
    def test_unsafe_attribute_access_blocked(self):
        """Test that unsafe attribute access is blocked."""
        data = {"age": 25, "name": "John"}
        
        # Unsafe attribute access
        unsafe_attribute_attempts = [
            "data.__class__",
            "data.__dict__",
            "data.__bases__",
            "data.__subclasses__",
            "data.__mro__",
            "data.__globals__",
            "data.__builtins__",
            "data.__import__",
            "data.__file__",
            "data.__code__",
            "data.__func__",
            "data.__closure__",
            "data.__module__",
            "data.__name__",
            "data.__qualname__",
            "data.__annotations__",
            "data.__doc__",
            "data.__package__",
            "data.__spec__",
            "data.__loader__",
            "data.__path__",
        ]
        
        for unsafe_code in unsafe_attribute_attempts:
            result = safe_eval_condition(unsafe_code, data)
            assert result == False, f"Unsafe attribute access was not blocked: {unsafe_code}"
    
    def test_error_handling(self):
        """Test that errors are handled gracefully."""
        data = {"age": 25, "name": "John"}
        
        # Syntax errors
        assert safe_eval_condition("age > ", data) == False
        assert safe_eval_condition("age && name", data) == False  # && not valid in Python
        assert safe_eval_condition("age || name", data) == False  # || not valid in Python
        
        # Name errors
        assert safe_eval_condition("unknown_var > 10", data) == False
        assert safe_eval_condition("unknown_func()", data) == False
        
        # Type errors
        assert safe_eval_condition("age > 'text'", data) == False
        assert safe_eval_condition("name + 5", data) == False
        
        # Empty condition
        assert safe_eval_condition("", data) == False
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        data = {"value": 0, "text": "", "list": [], "none": None, "bool_false": False}
        
        # Edge values
        assert safe_eval_condition("value == 0", data) == True
        assert safe_eval_condition("text == ''", data) == True
        assert safe_eval_condition("len(list) == 0", data) == True
        assert safe_eval_condition("none is None", data) == False  # 'is' operator not supported
        assert safe_eval_condition("bool_false == False", data) == True
        
        # Complex nested expressions
        complex_data = {
            "users": [
                {"name": "Alice", "age": 25, "active": True},
                {"name": "Bob", "age": 30, "active": False},
                {"name": "Charlie", "age": 35, "active": True}
            ]
        }
        
        # This should work with safe operations
        assert safe_eval_condition("len(users) == 3", complex_data) == True
        assert safe_eval_condition("users[0]['age'] > 20", complex_data) == False  # Dict access not allowed


if __name__ == "__main__":
    # Run the tests
    test_instance = TestSafeExpressionEvaluation()
    
    print("Running safe expression evaluation tests...")
    
    # Run all test methods
    test_methods = [method for method in dir(test_instance) if method.startswith('test_')]
    
    passed = 0
    failed = 0
    
    for test_method in test_methods:
        try:
            getattr(test_instance, test_method)()
            print(f"✓ {test_method}")
            passed += 1
        except Exception as e:
            print(f"✗ {test_method}: {e}")
            failed += 1
    
    print(f"\nTest Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("All security tests passed! The eval() vulnerability has been successfully fixed.")
    else:
        print("Some tests failed. The vulnerability may not be fully fixed.")
        sys.exit(1)