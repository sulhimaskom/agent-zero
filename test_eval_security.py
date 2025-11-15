#!/usr/bin/env python3
"""
Minimal security test to verify the eval() vulnerability fix.
This test isolates the get_comparator function to test it without dependencies.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_eval_vulnerability():
    """Test that demonstrates the original eval() vulnerability."""
    print("Testing original eval() vulnerability...")
    
    # This simulates the original vulnerable code
    def get_comparator_vulnerable(condition: str):
        def comparator(data: dict):
            try:
                result = eval(condition, {}, data)  # VULNERABLE
                return result
            except Exception as e:
                print(f"Error: {e}")
                return False
        return comparator
    
    test_data = {"name": "test", "value": 42}
    
    # Test safe expression (should work)
    safe_comparator = get_comparator_vulnerable("name == 'test'")
    result = safe_comparator(test_data)
    print(f"Safe expression result: {result}")
    
    # Test malicious expression (should demonstrate vulnerability)
    malicious_comparator = get_comparator_vulnerable("__import__('os').system('echo VULNERABLE')")
    try:
        result = malicious_comparator(test_data)
        print(f"Malicious expression result: {result}")
        print("❌ VULNERABILITY CONFIRMED: eval() allows code execution!")
    except Exception as e:
        print(f"Malicious expression failed: {e}")

def test_simple_eval_security():
    """Test that simple_eval is secure."""
    print("\nTesting simple_eval security...")
    
    try:
        from simpleeval import simple_eval
        
        def get_comparator_safe(condition: str):
            def comparator(data: dict):
                try:
                    result = simple_eval(condition, names=data)  # SAFE
                    return result
                except Exception as e:
                    print(f"Error: {e}")
                    return False
            return comparator
        
        test_data = {"name": "test", "value": 42}
        
        # Test safe expression (should work)
        safe_comparator = get_comparator_safe("name == 'test'")
        result = safe_comparator(test_data)
        print(f"Safe expression result: {result}")
        
        # Test malicious expression (should be blocked)
        malicious_comparator = get_comparator_safe("__import__('os').system('echo VULNERABLE')")
        result = malicious_comparator(test_data)
        print(f"Malicious expression result: {result}")
        
        if result is False:
            print("✅ SECURITY CONFIRMED: simple_eval blocks code execution!")
        else:
            print("❌ SECURITY ISSUE: simple_eval allowed code execution!")
            
    except ImportError:
        print("simpleeval not available for testing")

def test_actual_implementation():
    """Test the actual implementation in vector_db.py if possible."""
    print("\nTesting actual implementation...")
    
    try:
        # Try to import and test the actual function
        from python.helpers.vector_db import get_comparator
        
        test_data = {"name": "test", "value": 42}
        
        # Test safe expression
        safe_comparator = get_comparator("name == 'test'")
        result = safe_comparator(test_data)
        print(f"Safe expression result: {result}")
        
        # Test malicious expression
        malicious_comparator = get_comparator("__import__('os').system('echo VULNERABLE')")
        result = malicious_comparator(test_data)
        print(f"Malicious expression result: {result}")
        
        if result is False:
            print("✅ ACTUAL IMPLEMENTATION IS SECURE!")
        else:
            print("❌ ACTUAL IMPLEMENTATION IS VULNERABLE!")
            
    except ImportError as e:
        print(f"Cannot test actual implementation due to missing dependencies: {e}")

if __name__ == "__main__":
    print("=== Vector Database Security Test ===")
    test_eval_vulnerability()
    test_simple_eval_security()
    test_actual_implementation()
    print("\n=== Test Complete ===")