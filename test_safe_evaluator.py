#!/usr/bin/env python3
"""
Standalone security tests for the safe expression evaluator logic
"""

import ast
import operator
from typing import Any

# Copy the safe evaluator code here for testing
SAFE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.And: lambda a, b: a and b,
    ast.Or: lambda a, b: a or b,
    ast.Not: lambda a: not a,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: lambda a, b: a is b,
    ast.IsNot: lambda a, b: a is not b,
}

SAFE_FUNCTIONS = {
    'len': len,
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'any': any,
    'all': all,
}

def _safe_evaluate_node(node, data):
    """Safely evaluate an AST node with restricted operations."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Name):
        if node.id in data:
            return data[node.id]
        elif node.id in SAFE_FUNCTIONS:
            return SAFE_FUNCTIONS[node.id]
        else:
            raise ValueError(f"Unsafe name access: {node.id}")
    elif isinstance(node, ast.Attribute):
        # Allow attribute access on string objects for common methods
        if isinstance(node.value, ast.Name) and node.value.id in data:
            obj = data[node.value.id]
            if hasattr(obj, node.attr):
                return getattr(obj, node.attr)
        raise ValueError(f"Unsafe attribute access: {node.attr}")
    elif isinstance(node, ast.Compare):
        left = _safe_evaluate_node(node.left, data)
        for op, comparator in zip(node.ops, node.comparators):
            right = _safe_evaluate_node(comparator, data)
            if type(op) not in SAFE_OPERATORS:
                raise ValueError(f"Unsafe operator: {type(op)}")
            if not SAFE_OPERATORS[type(op)](left, right):
                return False
            left = right
        return True
    elif isinstance(node, ast.BoolOp):
        result = _safe_evaluate_node(node.values[0], data)
        for value_node in node.values[1:]:
            next_val = _safe_evaluate_node(value_node, data)
            if isinstance(node.op, ast.And):
                result = result and next_val
            elif isinstance(node.op, ast.Or):
                result = result or next_val
            else:
                raise ValueError(f"Unsafe boolean operator: {type(node.op)}")
        return result
    elif isinstance(node, ast.UnaryOp):
        operand = _safe_evaluate_node(node.operand, data)
        if isinstance(node.op, ast.Not):
            return not operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
        else:
            raise ValueError(f"Unsafe unary operator: {type(node.op)}")
    elif isinstance(node, ast.BinOp):
        left = _safe_evaluate_node(node.left, data)
        right = _safe_evaluate_node(node.right, data)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            return left / right
        elif isinstance(node.op, ast.Mod):
            return left % right
        elif isinstance(node.op, ast.Pow):
            return left ** right
        else:
            raise ValueError(f"Unsafe binary operator: {type(node.op)}")
    elif isinstance(node, ast.Call):
        func = _safe_evaluate_node(node.func, data)
        args = [_safe_evaluate_node(arg, data) for arg in node.args]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg is None:
                # **kwargs unpacking not allowed for security
                raise ValueError("Keyword argument unpacking (**kwargs) not allowed")
            kwargs[kw.arg] = _safe_evaluate_node(kw.value, data)
        return func(*args, **kwargs)
    elif isinstance(node, ast.List):
        return [_safe_evaluate_node(elt, data) for elt in node.elts]
    elif isinstance(node, ast.Tuple):
        return tuple(_safe_evaluate_node(elt, data) for elt in node.elts)
    elif isinstance(node, ast.Dict):
        result = {}
        for k, v in zip(node.keys, node.values):
            key = _safe_evaluate_node(k, data) if k is not None else None
            value = _safe_evaluate_node(v, data)
            result[key] = value
        return result
    else:
        raise ValueError(f"Unsafe expression type: {type(node)}")

def safe_eval_condition(condition: str, data: dict[str, Any]) -> bool:
    """Safely evaluate a condition string against data dictionary."""
    try:
        # Parse the condition into an AST
        tree = ast.parse(condition, mode='eval')
        
        # Validate the AST contains only safe operations
        result = _safe_evaluate_node(tree.body, data)
        
        # Ensure result is boolean
        return bool(result)
    except (SyntaxError, ValueError, TypeError, AttributeError, KeyError) as e:
        # Log error for debugging but don't expose details to prevent information leakage
        return False
    except Exception as e:
        # Catch-all for any unexpected errors
        return False

def test_safe_expressions():
    """Test that safe expressions work correctly."""
    test_data = {
        'name': 'test',
        'age': 25,
        'score': 85.5,
        'tags': ['python', 'security'],
        'active': True,
        'count': 0
    }
    
    # Test basic comparisons
    assert safe_eval_condition('age > 18', test_data) == True
    assert safe_eval_condition('name == "test"', test_data) == True
    assert safe_eval_condition('score >= 90', test_data) == False
    
    # Test boolean operations
    assert safe_eval_condition('age > 18 and active', test_data) == True
    assert safe_eval_condition('age < 18 or active', test_data) == True
    assert safe_eval_condition('not active', test_data) == False
    
    # Test membership
    assert safe_eval_condition('"python" in tags', test_data) == True
    assert safe_eval_condition('"java" not in tags', test_data) == True
    
    # Test arithmetic
    assert safe_eval_condition('age + 5 == 30', test_data) == True
    assert safe_eval_condition('score * 2 > 150', test_data) == True
    
    # Test functions
    assert safe_eval_condition('len(tags) == 2', test_data) == True
    assert safe_eval_condition('str(age) == "25"', test_data) == True
    assert safe_eval_condition('abs(count) == 0', test_data) == True
    
    print("✓ All safe expression tests passed")

def test_malicious_expressions():
    """Test that malicious expressions are blocked."""
    test_data = {'safe_value': 'test'}
    
    malicious_expressions = [
        # Code injection attempts
        '__import__("os").system("echo hacked")',
        'eval("__import__(\'os\').system(\'echo hacked\')")',
        'exec("__import__(\'os\').system(\'echo hacked\')")',
        
        # File system access
        'open("/etc/passwd", "r").read()',
        '__builtins__.__import__("os").system("ls")',
        
        # Attribute access on dangerous objects
        '__class__.__base__.__subclasses__()',
        '(lambda:0).__code__.co_consts',
        
        # Function definition
        '(lambda x: x*2)(5)',
        
        # List comprehensions that could be dangerous
        '[__import__("os") for _ in range(1)]',
        
        # Generator expressions
        '(__import__("os") for _ in range(1))',
        
        # Try to access globals
        'globals()',
        'locals()',
        'vars()',
        
        # Try to access builtins
        '__builtins__',
        '__import__',
        
        # Dangerous string operations
        '__import__("subprocess").getoutput("ls")',
        
        # Format string attacks
        '"{__import__}".format(__import__=__import__)',
    ]
    
    for expr in malicious_expressions:
        result = safe_eval_condition(expr, test_data)
        assert result == False, f"Malicious expression was not blocked: {expr}"
    
    print("✓ All malicious expression tests passed")

def test_edge_cases():
    """Test edge cases and error conditions."""
    test_data = {}
    
    # Empty expression
    assert safe_eval_condition('', test_data) == False
    
    # Invalid syntax
    assert safe_eval_condition('invalid syntax !!!', test_data) == False
    
    # Undefined variables
    assert safe_eval_condition('undefined_var == "test"', test_data) == False
    
    # Division by zero
    assert safe_eval_condition('1 / 0', test_data) == False
    
    # Type errors
    assert safe_eval_condition('"string" + 5', test_data) == False
    
    print("✓ Edge case tests passed")

if __name__ == '__main__':
    test_safe_expressions()
    test_malicious_expressions()
    test_edge_cases()
    print("\n🎉 All security tests passed! The safe evaluator is working correctly.")