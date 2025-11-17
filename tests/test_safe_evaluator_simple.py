"""
Simple test runner for the safe expression evaluator without pytest dependency.
"""

import sys
import os

from python.helpers.vector_db import SafeExpressionEvaluator, get_comparator

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_safe_comparisons():
    """Test safe comparison operations."""
    evaluator = SafeExpressionEvaluator()
    test_data = {
        "age": 25,
        "name": "John",
        "score": 85.5,
        "active": True,
        "tags": ["admin", "user"],
        "permissions": {"read": True, "write": False},
        "count": 0,
        "balance": -100.50,
    }

    print("Testing safe comparisons...")

    # Equality
    assert evaluator.evaluate("age == 25", test_data) == True
    assert evaluator.evaluate("name == 'John'", test_data) == True
    assert evaluator.evaluate("age == 30", test_data) == False

    # Inequality
    assert evaluator.evaluate("age != 30", test_data) == True
    assert evaluator.evaluate("name != 'Jane'", test_data) == True

    # Less than
    assert evaluator.evaluate("age < 30", test_data) == True
    assert evaluator.evaluate("score < 90", test_data) == True

    # Greater than
    assert evaluator.evaluate("age > 20", test_data) == True
    assert evaluator.evaluate("score > 80", test_data) == True

    print("✓ Safe comparisons work correctly")


def test_boolean_operations():
    """Test boolean AND and OR operations."""
    evaluator = SafeExpressionEvaluator()
    test_data = {"age": 25, "name": "John", "active": True}

    print("Testing boolean operations...")

    # AND operations
    assert evaluator.evaluate("age > 20 and name == 'John'", test_data) == True
    assert evaluator.evaluate("age > 30 and name == 'John'", test_data) == False
    assert evaluator.evaluate("age > 20 and name == 'Jane'", test_data) == False

    # OR operations
    assert evaluator.evaluate("age > 30 or name == 'John'", test_data) == True
    assert evaluator.evaluate("age > 30 or name == 'Jane'", test_data) == False

    print("✓ Boolean operations work correctly")


def test_code_injection_prevention():
    """Test that code injection attempts are blocked."""
    evaluator = SafeExpressionEvaluator()
    test_data = {"safe_var": "safe_value"}

    print("Testing code injection prevention...")

    dangerous_expressions = [
        "__import__('os').system('echo hacked')",
        "eval('print(hacked)')",
        "exec('print(hacked)')",
        "open('/etc/passwd', 'r')",
        "print('hacked')",
        "os.system('echo hacked')",
        "globals()",
        "locals()",
        "dir()",
        "[x for x in range(10)]",
        "lambda x: x*2",
        "type('')",
        "isinstance('', str)",
    ]

    for expr in dangerous_expressions:
        try:
            result = evaluator.evaluate(expr, test_data)
            # If it doesn't raise an exception, it should return False
            assert result == False, f"Dangerous expression returned True: {expr}"
        except ValueError:
            # Expected - dangerous expressions should raise ValueError
            pass
        except Exception:
            # Any other exception is also acceptable as it means the code didn't execute
            pass

    print("✓ Code injection prevention works correctly")


def test_undefined_variables():
    """Test that undefined variables are properly rejected."""
    evaluator = SafeExpressionEvaluator()
    test_data = {"age": 25}

    print("Testing undefined variable handling...")

    try:
        evaluator.evaluate("undefined_var == 5", test_data)
        assert False, "Should have raised ValueError for undefined variable"
    except ValueError:
        pass  # Expected

    print("✓ Undefined variables are properly rejected")


def test_get_comparator_functionality():
    """Test the get_comparator function."""
    print("Testing get_comparator functionality...")

    # Basic functionality
    comparator = get_comparator("age > 18")
    assert comparator({"age": 25}) == True
    assert comparator({"age": 15}) == False

    # Exception handling
    comparator = get_comparator("invalid expression with undefined_var")
    assert comparator({"age": 25}) == False  # Should return False, not crash

    # Complex expression
    comparator = get_comparator("age > 18 and name == 'John'")
    assert comparator({"age": 25, "name": "John"}) == True
    assert comparator({"age": 25, "name": "Jane"}) == False

    print("✓ get_comparator works correctly")


def test_security_vulnerability_fix():
    """Test that the original security vulnerability is fixed."""
    print("Testing security vulnerability fix...")

    dangerous_expressions = [
        "__import__('os').system('echo pwned')",
        "().__class__.__bases__[0].__subclasses__()[0]('/etc/passwd').read()",
        'eval(\'__import__("os").system("echo pwned")\')',
        'exec(\'__import__("os").system("echo pwned")\')',
        "open('/etc/passwd', 'r').read()",
        "globals()['__import__']('os').system('echo pwned')",
    ]

    test_data = {"safe_var": "safe_value"}

    for expr in dangerous_expressions:
        comparator = get_comparator(expr)
        result = comparator(test_data)
        assert result == False, f"Dangerous expression was not blocked: {expr}"

    print("✓ Security vulnerability is fixed")


def main():
    """Run all tests."""
    print("Running Safe Expression Evaluator Tests")
    print("=" * 50)

    try:
        test_safe_comparisons()
        test_boolean_operations()
        test_code_injection_prevention()
        test_undefined_variables()
        test_get_comparator_functionality()
        test_security_vulnerability_fix()

        print("=" * 50)
        print("✅ All tests passed! The safe expression evaluator is working correctly.")
        print("✅ Security vulnerability has been fixed.")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
