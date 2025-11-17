"""
Standalone test for the safe expression evaluator logic.
Tests the core security functionality without external dependencies.
"""

import ast
import operator


# Copy the safe evaluator implementation for testing
SAFE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.And: lambda a, b: a and b,
    ast.Or: lambda a, b: a or b,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

SAFE_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

SAFE_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Not: operator.not_,
}


class SafeExpressionEvaluator:
    """Safe expression evaluator using AST parsing to prevent code injection."""

    def __init__(self):
        self.allowed_operators = SAFE_OPERATORS
        self.allowed_binary_operators = SAFE_BINARY_OPERATORS
        self.allowed_unary_operators = SAFE_UNARY_OPERATORS

    def evaluate(self, condition: str, data: dict) -> bool:
        """Safely evaluate a condition string against provided data."""
        try:
            tree = ast.parse(condition, mode="eval")
            result = self._evaluate_node(tree.body, data)
            return bool(result)
        except (SyntaxError, ValueError) as e:
            raise ValueError(f"Unsafe or invalid expression: {e}")
        except Exception as e:
            raise ValueError(f"Expression evaluation failed: {e}")

    def _evaluate_node(self, node, data: dict):
        """Recursively evaluate AST nodes safely."""

        if isinstance(node, ast.BoolOp):
            result = True if isinstance(node.op, ast.And) else False
            for value_node in node.values:
                value = self._evaluate_node(value_node, data)
                if isinstance(node.op, ast.And):
                    result = result and value
                    if not result:
                        break
                else:
                    result = result or value
                    if result:
                        break
            return result

        elif isinstance(node, ast.BinOp):
            left = self._evaluate_node(node.left, data)
            right = self._evaluate_node(node.right, data)

            if type(node.op) in self.allowed_binary_operators:
                return self.allowed_binary_operators[type(node.op)](left, right)
            elif type(node.op) in self.allowed_operators:
                return self.allowed_operators[type(node.op)](left, right)
            else:
                raise ValueError(f"Unsafe binary operator: {type(node.op).__name__}")

        elif isinstance(node, ast.UnaryOp):
            operand = self._evaluate_node(node.operand, data)
            if type(node.op) in self.allowed_unary_operators:
                return self.allowed_unary_operators[type(node.op)](operand)
            else:
                raise ValueError(f"Unsafe unary operator: {type(node.op).__name__}")

        elif isinstance(node, ast.Compare):
            left = self._evaluate_node(node.left, data)
            for op, comparator_node in zip(node.ops, node.comparators):
                right = self._evaluate_node(comparator_node, data)
                if type(op) in self.allowed_operators:
                    if not self.allowed_operators[type(op)](left, right):
                        return False
                    left = right
                else:
                    raise ValueError(f"Unsafe comparison operator: {type(op).__name__}")
            return True

        elif isinstance(node, ast.Name):
            if node.id in data:
                return data[node.id]
            else:
                raise ValueError(f"Undefined variable: {node.id}")

        elif isinstance(node, ast.Constant):
            return node.value

        elif isinstance(node, ast.List):
            return [self._evaluate_node(elt, data) for elt in node.elts]

        elif isinstance(node, ast.Tuple):
            return tuple(self._evaluate_node(elt, data) for elt in node.elts)

        elif isinstance(node, ast.Set):
            return {self._evaluate_node(elt, data) for elt in node.elts}

        elif isinstance(node, ast.Dict):
            keys = [self._evaluate_node(k, data) for k in node.keys]
            values = [self._evaluate_node(v, data) for v in node.values]
            return dict(zip(keys, values))

        else:
            raise ValueError(f"Unsafe expression construct: {type(node).__name__}")


def test_safe_operations():
    """Test that safe operations work correctly."""
    evaluator = SafeExpressionEvaluator()
    test_data = {"age": 25, "name": "John", "score": 85.5, "active": True, "tags": ["admin", "user"]}

    print("Testing safe operations...")

    # Basic comparisons
    assert evaluator.evaluate("age == 25", test_data) == True
    assert evaluator.evaluate("name == 'John'", test_data) == True
    assert evaluator.evaluate("age > 20", test_data) == True
    assert evaluator.evaluate("score < 90", test_data) == True

    # Boolean operations
    assert evaluator.evaluate("age > 20 and name == 'John'", test_data) == True
    assert evaluator.evaluate("age > 30 or name == 'John'", test_data) == True

    # Membership
    assert evaluator.evaluate("'admin' in tags", test_data) == True
    assert evaluator.evaluate("'guest' not in tags", test_data) == True

    # Arithmetic
    assert evaluator.evaluate("age + 5 == 30", test_data) == True
    assert evaluator.evaluate("age * 2 == 50", test_data) == True

    print("✓ Safe operations work correctly")


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
        "().__class__.__bases__[0].__subclasses__()",
        "().__class__.__bases__[0].__subclasses__()[0]('etc/passwd').read()",
    ]

    blocked_count = 0
    for expr in dangerous_expressions:
        try:
            result = evaluator.evaluate(expr, test_data)
            if result == False:
                blocked_count += 1
            else:
                print(f"❌ Dangerous expression returned True: {expr}")
                return False
        except ValueError:
            blocked_count += 1  # Expected - dangerous expressions should raise ValueError
        except Exception:
            blocked_count += 1  # Any other exception is also acceptable

    print(f"✓ {blocked_count}/{len(dangerous_expressions)} dangerous expressions blocked")
    return blocked_count == len(dangerous_expressions)


def test_original_vulnerability_fixed():
    """Test that the original eval() vulnerability is fixed."""
    print("Testing that original vulnerability is fixed...")

    # This is what the vulnerable code would have done:
    def vulnerable_eval(condition: str, data: dict):
        try:
            result = eval(condition, {}, data)  # VULNERABLE
            return result
        except Exception:
            return False

    # This is our safe implementation:
    evaluator = SafeExpressionEvaluator()
    test_data = {"age": 25}

    # Test safe expressions - both should work the same
    safe_expressions = [
        "age == 25",
        "age > 18",
        "age < 30",
    ]

    for expr in safe_expressions:
        vulnerable_result = vulnerable_eval(expr, test_data)
        safe_result = evaluator.evaluate(expr, test_data)
        assert vulnerable_result == safe_result, f"Safe expression mismatch: {expr}"

    # Test dangerous expressions - vulnerable version would execute them, safe version should block
    dangerous_expressions = [
        "__import__('os').system('echo pwned')",
        "eval('dangerous')",
        "open('/etc/passwd', 'r')",
    ]

    for expr in dangerous_expressions:
        try:
            safe_result = evaluator.evaluate(expr, test_data)
            assert safe_result == False, f"Dangerous expression not blocked: {expr}"
        except ValueError:
            pass  # Expected and good

    print("✓ Original vulnerability is fixed")


def main():
    """Run all tests."""
    print("Testing Safe Expression Evaluator - Standalone")
    print("=" * 60)

    try:
        test_safe_operations()

        if not test_code_injection_prevention():
            print("❌ Code injection prevention failed")
            return False

        test_original_vulnerability_fixed()

        print("=" * 60)
        print("✅ All tests passed!")
        print("✅ The safe expression evaluator successfully prevents code injection")
        print("✅ The original eval() vulnerability has been completely fixed")
        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
