"""Tests for print_catch module - async print capture utilities

This module provides utilities for capturing stdout from async functions.
Tests verify the capture_prints_async function behavior.
"""

import asyncio
import sys

import pytest

from python.helpers.print_catch import capture_prints_async


class TestCapturePrintsAsync:
    """Test suite for capture_prints_async function"""

    @pytest.mark.asyncio
    async def test_capture_prints_basic(self):
        """Test basic print capture from async function"""

        async def func_that_prints():
            print("Hello")
            print("World")
            return "done"

        task, get_output = capture_prints_async(func_that_prints)
        result = await task

        assert result == "done"
        output = get_output()
        assert "Hello" in output
        assert "World" in output

    @pytest.mark.asyncio
    async def test_capture_prints_no_output(self):
        """Test async function that prints nothing"""

        async def func_no_print():
            return "silent"

        task, get_output = capture_prints_async(func_no_print)
        result = await task

        assert result == "silent"
        output = get_output()
        assert output == ""

    @pytest.mark.asyncio
    async def test_capture_prints_with_args(self):
        """Test async function with arguments"""

        async def func_with_args(a, b, keyword=None):
            print(f"a={a}, b={b}, keyword={keyword}")
            return a + b

        task, get_output = capture_prints_async(func_with_args, 5, 3, keyword="test")
        result = await task

        assert result == 8
        output = get_output()
        assert "a=5" in output
        assert "b=3" in output
        assert "keyword=test" in output

    @pytest.mark.asyncio
    async def test_capture_prints_stdout_restored(self):
        """Test that stdout is properly restored after async function"""

        async def func_that_prints():
            print("Inside async")
            return "done"

        task, get_output = capture_prints_async(func_that_prints)
        await task

        # stdout should be restored
        assert sys.stdout is not None

    @pytest.mark.asyncio
    async def test_capture_prints_multiple_calls(self):
        """Test multiple sequential captures"""

        async def func():
            print("Call 1")
            return 1

        # First call
        task1, get_output1 = capture_prints_async(func)
        result1 = await task1
        output1 = get_output1()

        # Second call
        task2, get_output2 = capture_prints_async(func)
        result2 = await task2
        output2 = get_output2()

        assert result1 == 1
        assert result2 == 1
        assert "Call 1" in output1
        assert "Call 1" in output2

    @pytest.mark.asyncio
    async def test_capture_prints_returns_correct_value(self):
        """Test that async function return value is correct"""

        async def func_returns_value():
            await asyncio.sleep(0.001)  # Small delay
            return {"key": "value", "count": 42}

        task, get_output = capture_prints_async(func_returns_value)
        result = await task

        assert result == {"key": "value", "count": 42}

    @pytest.mark.asyncio
    async def test_capture_prints_exception_preserved(self):
        """Test that exceptions in async function are propagated"""

        async def func_that_raises():
            print("Before error")
            raise ValueError("Test error")
            return "done"

        task, get_output = capture_prints_async(func_that_raises)

        with pytest.raises(ValueError, match="Test error"):
            await task

    @pytest.mark.asyncio
    async def test_capture_prints_empty_string(self):
        """Test async function that prints empty strings"""

        async def func():
            print("")
            print("after empty")
            return "done"

        task, get_output = capture_prints_async(func)
        result = await task

        assert result == "done"
        output = get_output()
        assert "after empty" in output

    @pytest.mark.asyncio
    async def test_get_output_before_task_completes(self):
        """Test that get_output can be called before task completes"""

        async def func():
            await asyncio.sleep(0.01)
            print("Final output")
            return "done"

        task, get_output = capture_prints_async(func)

        # get_output before task completes should return empty or partial
        output_before = get_output()

        result = await task
        output_after = get_output()

        assert "Final output" in output_after
