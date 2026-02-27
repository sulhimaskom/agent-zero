import asyncio

import pytest

from python.helpers.defer import (
    DeferredTask,
    EventLoopThread,
    run_in_background,
)


class TestRunInBackground:
    """Test run_in_background function"""

    @pytest.mark.asyncio
    async def test_basic_execution(self):
        """Test that background task executes and returns result"""
        async def dummy_coro():
            await asyncio.sleep(0.01)
            return 42

        task = run_in_background(dummy_coro())
        result = await task
        assert result == 42

    @pytest.mark.asyncio
    async def test_multiple_background_tasks(self):
        """Test that multiple background tasks can run concurrently"""
        async def add(a, b):
            await asyncio.sleep(0.01)
            return a + b

        task1 = run_in_background(add(1, 2))
        task2 = run_in_background(add(3, 4))

        result1 = await task1
        result2 = await task2

        assert result1 == 3
        assert result2 == 7


class TestEventLoopThread:
    """Test EventLoopThread class"""

    def test_singleton_behavior(self):
        """Test that EventLoopThread returns same instance for same thread_name"""
        thread1 = EventLoopThread("test_thread")
        thread2 = EventLoopThread("test_thread")
        assert thread1 is thread2

    def test_different_thread_names_create_different_instances(self):
        """Test that different thread names create different instances"""
        thread1 = EventLoopThread("thread_a")
        thread2 = EventLoopThread("thread_b")
        assert thread1 is not thread2

    def test_thread_has_name(self):
        """Test that thread has the expected name"""
        thread = EventLoopThread("named_thread")
        assert thread.thread_name == "named_thread"

    def test_thread_is_daemon(self):
        """Test that thread is created as daemon"""
        thread = EventLoopThread("daemon_test")
        # The thread should have been started
        assert hasattr(thread, "thread")
        assert thread.thread is not None
        assert thread.thread.daemon is True


class TestDeferredTask:
    """Test DeferredTask class"""

    @pytest.mark.asyncio
    async def test_basic_task_execution(self):
        """Test that DeferredTask executes a simple async function"""
        task = DeferredTask("test_deferred")

        async def dummy_func():
            await asyncio.sleep(0.01)
            return "success"

        task.start_task(dummy_func)
        result = await task.result(timeout=5)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_task_with_arguments(self):
        """Test that DeferredTask passes arguments to function"""
        task = DeferredTask("test_args")

        async def add_numbers(a, b, c=0):
            await asyncio.sleep(0.01)
            return a + b + c

        task.start_task(add_numbers, 1, 2, c=3)
        result = await task.result(timeout=5)
        assert result == 6

    @pytest.mark.asyncio
    async def test_is_ready_before_completion(self):
        """Test is_ready returns False before task completes"""
        task = DeferredTask("test_ready")

        async def slow_func():
            await asyncio.sleep(0.1)
            return "done"

        task.start_task(slow_func)
        # Should not be ready immediately
        assert task.is_ready() is False

        # Wait for completion
        await task.result(timeout=5)
        # Should be ready now
        assert task.is_ready() is True

    @pytest.mark.asyncio
    async def test_is_alive(self):
        """Test is_alive returns correct status"""
        task = DeferredTask("test_alive")

        async def slow_func():
            await asyncio.sleep(0.1)
            return "done"

        task.start_task(slow_func)
        assert task.is_alive() is True

        # Wait for completion
        await task.result(timeout=5)
        assert task.is_alive() is False

    @pytest.mark.asyncio
    async def test_kill_task(self):
        """Test that kill stops the task"""
        task = DeferredTask("test_kill")

        async def long_running():
            await asyncio.sleep(10)  # Long sleep
            return "should not complete"

        task.start_task(long_running)
        # Give it a moment to start
        await asyncio.sleep(0.01)

        # Kill the task
        task.kill()

        # Task should no longer be alive
        assert task.is_alive() is False

    @pytest.mark.asyncio
    async def test_result_sync(self):
        """Test synchronous result retrieval"""
        task = DeferredTask("test_sync")

        async def quick_func():
            return "sync_result"

        task.start_task(quick_func)
        result = task.result_sync(timeout=5)
        assert result == "sync_result"

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        """Test that timeout raises TimeoutError"""
        task = DeferredTask("test_timeout")

        async def slow_func():
            await asyncio.sleep(10)
            return "late"

        task.start_task(slow_func)

        with pytest.raises(TimeoutError):
            await task.result(timeout=0.01)

        # Clean up
        task.kill()

    @pytest.mark.asyncio
    async def test_multiple_tasks_same_thread(self):
        """Test multiple tasks can run on same EventLoopThread"""
        thread_name = "shared_thread"

        task1 = DeferredTask(thread_name)
        task2 = DeferredTask(thread_name)

        async def func1():
            await asyncio.sleep(0.02)
            return 1

        async def func2():
            await asyncio.sleep(0.02)
            return 2

        task1.start_task(func1)
        task2.start_task(func2)

        # Both should complete
        result1 = await task1.result(timeout=5)
        result2 = await task2.result(timeout=5)

        assert result1 == 1
        assert result2 == 2

    @pytest.mark.asyncio
    async def test_task_with_exception(self):
        """Test that exceptions in tasks are properly propagated"""
        task = DeferredTask("test_exception")

        async def failing_func():
            await asyncio.sleep(0.01)
            raise ValueError("test error")

        task.start_task(failing_func)

        with pytest.raises(ValueError, match="test error"):
            await task.result(timeout=5)
