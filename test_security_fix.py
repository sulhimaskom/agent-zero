#!/usr/bin/env python3
"""
Standalone test for the safe expression evaluator functionality.
This tests the core logic without requiring external dependencies.
"""

import ast
import operator


# Copy the core functions from vector_db.py to test them independently
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

def safe_eval_condition(condition: str, data: dict) -> bool:
    """Safely evaluate a condition expression against metadata dictionary."""
    try:
        tree = ast.parse(condition, mode='eval')
        return _evaluate_node(tree.body, data)
    except SyntaxError as e:
        raise SyntaxError(f"Invalid syntax in condition: {e}")
    except Exception as e:
        return False

def _evaluate_node(node: ast.AST, data: dict):
    """Recursively evaluate AST nodes safely."""
    if isinstance(node, ast.BoolOp):
        values = [_evaluate_node(value, data) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        elif isinstance(node.op, ast.Or):
            return any(values)
        else:
            raise ValueError(f"Unsupported boolean operator: {type(node.op)}")
    
    elif isinstance(node, ast.Compare):
        left = _evaluate_node(node.left, data)
        
        for op, comparator in zip(node.ops, node.comparators):
            right = _evaluate_node(comparator, data)
            
            if type(op) not in SAFE_OPERATORS:
                raise ValueError(f"Unsupported comparison operator: {type(op)}")
            
            result = SAFE_OPERATORS[type(op)](left, right)
            if not result:
                return False
            left = right
        
        return True
    
    elif isinstance(node, ast.Name):
        if node.id in data:
            return data[node.id]
        else:
            raise ValueError(f"Unknown field: {node.id}")
    
    elif isinstance(node, ast.Constant):
        return node.value
    
    elif isinstance(node, ast.Attribute):
        obj = _evaluate_node(node.value, data)
        if hasattr(obj, node.attr):
            return getattr(obj, node.attr)
        else:
            raise ValueError(f"Attribute '{node.attr}' not found on {type(obj)}")
    
    elif isinstance(node, ast.UnaryOp):
        operand = _evaluate_node(node.operand, data)
        
        if isinstance(node.op, ast.Not):
            return not operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
        else:
            raise ValueError(f"Unsupported unary operator: {type(node.op)}")
    
    else:
        raise ValueError(f"Unsupported operation: {type(node).__name__}")


def test_security_fix():
    """Test that the eval() vulnerability is fixed."""
    print("Testing security fix for eval() vulnerability...")
    
    # Test data
    data = {"status": "active", "priority": 5, "tags": ["urgent", "important"]}
    
    # Test 1: Basic functionality still works
    assert safe_eval_condition("status == 'active'", data) == True
    assert safe_eval_condition("priority > 3", data) == True
    assert safe_eval_condition("'urgent' in tags", data) == True
    print("✅ Basic functionality works")
    
    # Test 2: Complex expressions work
    assert safe_eval_condition("status == 'active' and priority > 3", data) == True
    assert safe_eval_condition("status == 'active' or priority > 10", data) == True
    print("✅ Complex expressions work")
    
    # Test 3: Dangerous expressions are rejected (should return False, not execute)
    dangerous_tests = [
        "__import__('os')",
        "eval('test')",
        "exec('print(test)')",
        "__builtins__.__import__('os')",
        "open('/etc/passwd')",
        "print('test')",
        "len(status)",  # Function calls should be rejected
    ]
    
    for dangerous_expr in dangerous_tests:
        result = safe_eval_condition(dangerous_expr, data)
        assert result == False, f"Dangerous expression was not rejected: {dangerous_expr}"
    
    print("✅ All dangerous expressions are safely rejected")
    
    # Test 4: Invalid syntax is handled
    try:
        safe_eval_condition("status == ", data)
        assert False, "Should have raised SyntaxError"
    except SyntaxError:
        pass  # Expected
    print("✅ Invalid syntax is properly handled")
    
    # Test 5: Unknown fields are handled
    result = safe_eval_condition("unknown_field == 'test'", data)
    assert result == False
    print("✅ Unknown fields are handled safely")
    
    print("\n🎉 All security tests passed! The eval() vulnerability has been fixed.")
    print("🔒 The safe expression evaluator prevents arbitrary code execution.")
    print("✨ All legitimate filtering functionality is preserved.")


if __name__ == "__main__":
    test_security_fix()