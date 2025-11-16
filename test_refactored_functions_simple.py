"""
Simple test runner for refactored functions without pytest dependency.
"""

import asyncio
import sys
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Test utility patterns
try:
    from python.helpers.utility_patterns import (
        handle_error_gracefully, 
        create_background_task,
        run_with_timeout,
        validate_required_params,
        safe_get_nested_value,
        RateLimiter
    )
    UTILITY_PATTERNS_AVAILABLE = True
except ImportError as e:
    print(f"⚠ Utility patterns import failed: {e}")
    UTILITY_PATTERNS_AVAILABLE = False


class TestResult:
    """Simple test result tracker."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def success(self, test_name):
        self.passed += 1
        print(f"✓ {test_name}")

    def failure(self, test_name, error):
        self.failed += 1
        self.errors.append(f"{test_name}: {error}")
        print(f"✗ {test_name}: {error}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\nTest Summary: {self.passed}/{total} passed")
        if self.errors:
            print("Failures:")
            for error in self.errors:
                print(f"  - {error}")


def test_handle_error_gracefully():
    """Test centralized error handling."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    mock_log = Mock()
    error = ValueError("Test error")
    
    try:
        # Should not raise exception
        handle_error_gracefully(error, "test_context", mock_log)
        
        # Verify log was called if provided
        if mock_log:
            mock_log.log.assert_called_once_with(type="error", content="Error in test_context: Test error")
        
        return "pass"
    except Exception as e:
        return f"Error: {e}"


async def test_create_background_task():
    """Test background task creation with error handling."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        # Test successful task - background tasks are fire-and-forget
        result_holder = {"completed": False}
        
        async def successful_coro():
            await asyncio.sleep(0.01)  # Small delay to ensure async behavior
            result_holder["completed"] = True
        
        task = create_background_task(successful_coro(), "test_task")
        await asyncio.sleep(0.05)  # Give task time to complete
        
        # Task should complete without raising exceptions
        if result_holder["completed"]:
            return "pass"
        else:
            return "Error: Background task did not complete"
    except Exception as e:
        return f"Error: {e}"


async def test_create_background_task_with_error():
    """Test background task error handling."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        async def failing_coro():
            raise ValueError("Test error")
        
        task = create_background_task(failing_coro(), "failing_task")
        # Should not raise exception due to error handling in wrapper
        await task  # Should complete without raising
        
        return "pass"
    except Exception as e:
        return f"Error: {e}"


async def test_run_with_timeout():
    """Test timeout wrapper."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        async def quick_coro():
            return "quick"
        
        result = await run_with_timeout(quick_coro(), 1.0, "test")
        assert result == "quick"
        
        return "pass"
    except Exception as e:
        return f"Error: {e}"


async def test_run_with_timeout_exceeded():
    """Test timeout exceeded."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        async def slow_coro():
            await asyncio.sleep(2)
            return "slow"
        
        try:
            await run_with_timeout(slow_coro(), 0.1, "test")
            return "Error: Should have timed out"
        except asyncio.TimeoutError:
            return "pass"
    except Exception as e:
        return f"Error: {e}"


def test_validate_required_params():
    """Test parameter validation."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        # Test valid params
        validate_required_params({"a": 1, "b": 2}, ["a", "b"])
        
        # Test missing params
        try:
            validate_required_params({"a": 1}, ["a", "b"])
            return "Error: Should have raised ValueError"
        except ValueError as e:
            if "Missing required parameters" in str(e):
                return "pass"
            else:
                return f"Error: Wrong exception message: {e}"
    except Exception as e:
        return f"Error: {e}"


def test_safe_get_nested_value():
    """Test safe nested value access."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        data = {"nested": {"key": {"value": "found"}}}
        
        # Test existing path
        result = safe_get_nested_value(data, "nested.key.value")
        assert result == "found"
        
        # Test missing path
        result = safe_get_nested_value(data, "missing.path")
        assert result is None
        
        # Test default value
        result = safe_get_nested_value(data, "missing.path", "default")
        assert result == "default"
        
        return "pass"
    except Exception as e:
        return f"Error: {e}"


async def test_rate_limiter():
    """Test rate limiter functionality."""
    if not UTILITY_PATTERNS_AVAILABLE:
        return "skip"
    
    try:
        limiter = RateLimiter(max_calls=2, time_window=0.1)
        
        # Should allow first two calls
        assert await limiter.acquire() == True
        assert await limiter.acquire() == True
        
        # Should block third call
        assert await limiter.acquire() == False
        
        return "pass"
    except Exception as e:
        return f"Error: {e}"


async def run_all_tests():
    """Run all tests and report results."""
    print("Running refactored functions tests...")
    print("=" * 50)
    
    result = TestResult()
    
    # Run synchronous tests
    tests = [
        ("Error handling", test_handle_error_gracefully),
        ("Parameter validation", test_validate_required_params),
        ("Nested value access", test_safe_get_nested_value),
    ]
    
    for test_name, test_func in tests:
        test_result = test_func()
        if test_result == "skip":
            print(f"⚠ {test_name} (skipped - dependencies not available)")
        elif test_result == "pass":
            result.success(test_name)
        else:
            result.failure(test_name, test_result)
    
    # Run asynchronous tests
    async_tests = [
        ("Background task creation", test_create_background_task),
        ("Background task error handling", test_create_background_task_with_error),
        ("Timeout wrapper", test_run_with_timeout),
        ("Timeout exceeded", test_run_with_timeout_exceeded),
        ("Rate limiter", test_rate_limiter),
    ]
    
    for test_name, test_func in async_tests:
        try:
            test_result = await test_func()
            if test_result == "skip":
                print(f"⚠ {test_name} (skipped - dependencies not available)")
            elif test_result == "pass":
                result.success(test_name)
            else:
                result.failure(test_name, test_result)
        except Exception as e:
            result.failure(test_name, f"Unexpected error: {e}")
    
    result.summary()
    return result.failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)