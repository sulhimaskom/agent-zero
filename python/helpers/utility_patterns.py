"""
Utility functions for common patterns across the codebase.

This module provides centralized implementations for frequently used patterns
like error handling, background tasks, and other common operations.
"""

import asyncio
from typing import Any, Optional
from python.helpers.print_style import PrintStyle
import python.helpers.log as Log


def handle_error_gracefully(error: Exception, context: str = "", log: Optional[Log.Log] = None):
    """
    Centralized error handling with consistent formatting and logging.
    
    Args:
        error: The exception that occurred
        context: Additional context about where the error occurred
        log: Optional logger instance for logging the error
    """
    error_msg = f"Error in {context}: {error}" if context else f"Error: {error}"
    
    # Print error in consistent format
    PrintStyle(font_color="red", padding=True).print(error_msg)
    
    # Log error if logger provided
    if log:
        log.log(type="error", content=error_msg)


def create_background_task(coro, name: Optional[str] = None):
    """
    Create a background task with proper error handling.
    
    This replaces the DeferredTask overuse pattern mentioned in the issue.
    
    Args:
        coro: The coroutine to run in the background
        name: Optional name for the task for debugging
        
    Returns:
        The created asyncio Task
    """
    async def safe_wrapper():
        try:
            await coro
        except Exception as e:
            handle_error_gracefully(e, f"background task {name}" if name else "background task")
    
    task_name = name or f"background_task_{id(coro)}"
    return asyncio.create_task(safe_wrapper(), name=task_name)


async def run_with_timeout(coro, timeout_seconds: float, context: str = ""):
    """
    Run a coroutine with timeout and proper error handling.
    
    Args:
        coro: The coroutine to run
        timeout_seconds: Maximum time to wait
        context: Context for error messages
        
    Returns:
        The result of the coroutine
        
    Raises:
        asyncio.TimeoutError: If the coroutine doesn't complete in time
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        timeout_msg = f"Timeout in {context}" if context else "Operation timed out"
        PrintStyle(font_color="orange", padding=True).print(timeout_msg)
        raise


def validate_required_params(params: dict, required_keys: list, context: str = "") -> None:
    """
    Validate that all required parameters are present.
    
    Args:
        params: Dictionary of parameters to validate
        required_keys: List of required parameter keys
        context: Context for error messages
        
    Raises:
        ValueError: If any required parameters are missing
    """
    missing_keys = [key for key in required_keys if key not in params or params[key] is None]
    
    if missing_keys:
        context_msg = f" in {context}" if context else ""
        raise ValueError(f"Missing required parameters{context_msg}: {', '.join(missing_keys)}")


def safe_get_nested_value(data: dict, key_path: str, default: Any = None) -> Any:
    """
    Safely get a nested value from a dictionary using dot notation.
    
    Args:
        data: The dictionary to get value from
        key_path: Dot-separated path to the value (e.g., "nested.key.value")
        default: Default value if key is not found
        
    Returns:
        The value at the key path or default if not found
    """
    keys = key_path.split('.')
    current = data
    
    try:
        for key in keys:
            current = current[key]
        return current
    except (KeyError, TypeError):
        return default


class RateLimiter:
    """
    Simple rate limiter for controlling operation frequency.
    
    This can be used to replace scattered rate limiting logic throughout the codebase.
    """
    
    def __init__(self, max_calls: int, time_window: float):
        """
        Initialize rate limiter.
        
        Args:
            max_calls: Maximum number of calls allowed in the time window
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    async def acquire(self) -> bool:
        """
        Try to acquire a rate limit slot.
        
        Returns:
            True if the call is allowed, False otherwise
        """
        import time
        
        current_time = time.time()
        
        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls if current_time - call_time < self.time_window]
        
        # Check if we can make a new call
        if len(self.calls) < self.max_calls:
            self.calls.append(current_time)
            return True
        
        return False
    
    async def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        import time
        
        while not await self.acquire():
            sleep_time = self.time_window / self.max_calls
            await asyncio.sleep(sleep_time)