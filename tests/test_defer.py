import asyncio
import time

import pytest

from python.helpers.defer import DeferredTask, EventLoopThread, run_in_background


class TestEventLoopThread:
    """Test EventLoopThread class"""

    def test_singleton_pattern(self):
        """Test that EventLoopThread follows singleton pattern"""
        thread1 = EventLoopThread("test_singleton")
        thread2 = EventLoopThread("test_singleton")
        assert thread1 is thread2

    def test_different_thread_names_create_different_instances(self):
        """Test that different thread names create different instances"""
        thread1 = EventLoopThread("thread_a")
        thread2 = EventLoopThread("thread_b")
        assert thread1 is not thread2

    def test_thread_has_loop_attribute(self):
        """Test that thread has loop attribute after initialization"""
        thread = EventLoopThread("test_loop")
        assert hasattr(thread, "loop")
        assert thread.loop is not None

    def test_thread_has_thread_attribute(self):
        """Test that thread has thread attribute after initialization"""
        thread = EventLoopThread("test_thread")
        assert hasattr(thread, "thread")
        assert thread.thread is not None
        assert thread.thread.daemon is True


class TestDeferredTask:
    """Test DeferredTask class"""

    @pytest.mark.asyncio
    async def test_task_not_started_initially(self):
        """Test that task is not started initially"""
        task = DeferredTask("test_task_init")
        assert not task.is_ready()
        assert not task.is_alive()

    @pytest.mark.asyncio
    async def test_start_task_returns_self(self):
        """Test that start_task returns self for chaining"""
        async def dummy_func():
            return 42

        task = DeferredTask("test_return")
        result = task.start_task(dummy_func)
        assert result is task
        # Cleanup
        task.kill()

    @pytest.mark.asyncio
    async def test_task_executes_coroutine(self):
        """Test that task executes coroutine and returns result"""
        async def slow_func():
            await asyncio.sleep(0.1)
            return "completed"

        task = DeferredTask("test_exec")
        task.start_task(slow_func)
        # Wait for task to complete
        time.sleep(0.2)
        assert task.is_ready()
        assert task.is_alive() is False
        # Get result
        result = task.result_sync(timeout=1)
        assert result == "completed"

    @pytest.mark.asyncio
    async def test_result_sync_timeout(self):
        """Test that result_sync raises TimeoutError on timeout"""
        async def long_running():
            await asyncio.sleep(10)
            return "done"

        task = DeferredTask("test_timeout")
        task.start_task(long_running)
        with pytest.raises(TimeoutError):
            task.result_sync(timeout=0.1)
        # Cleanup
        task.kill()

    @pytest.mark.asyncio
    async def test_kill_cancels_task(self):
        """Test that kill cancels the running task"""
        async def infinite_loop():
            while True:
                await asyncio.sleep(0.01)

        task = DeferredTask("test_kill")
        task.start_task(infinite_loop)
        time.sleep(0.1)
        assert task.is_alive()
        task.kill()
        time.sleep(0.1)
        assert not task.is_alive()

    @pytest.mark.asyncio
    async def test_restart_task(self):
        """Test that restart kills old task and starts new one"""
        counter = {"value": 0}

        async def increment():
            counter["value"] += 1
            return counter["value"]

        task = DeferredTask("test_restart")
        task.start_task(increment)
        time.sleep(0.1)
        first_result = task.result_sync(timeout=1)
        assert first_result == 1

        # Restart and run again
        task.restart()
        time.sleep(0.1)
        second_result = task.result_sync(timeout=1)
        assert second_result == 2

    @pytest.mark.asyncio
    async def test_add_child_task(self):
        """Test that child tasks can be added"""
        async def parent_func():
            return "parent"

        async def child_func():
            return "child"

        parent = DeferredTask("test_parent")
        child = DeferredTask("test_child")

        parent.start_task(parent_func)
        child.start_task(child_func)
        parent.add_child_task(child, terminate_thread=False)

        assert len(parent.children) == 1
        assert parent.children[0].task is child
        assert parent.children[0].terminate_thread is False

    @pytest.mark.asyncio
    async def test_kill_children(self):
        """Test that kill_children terminates all child tasks"""
        async def long_running_child():
            await asyncio.sleep(10)
            return "child"

        parent = DeferredTask("test_parent_kill")
        parent.start_task(lambda: "parent")
        time.sleep(0.1)

        child1 = DeferredTask("test_child1")
        child1.start_task(long_running_child)
        child2 = DeferredTask("test_child2")
        child2.start_task(long_running_child)

        parent.add_child_task(child1, terminate_thread=False)
        parent.add_child_task(child2, terminate_thread=False)

        assert len(parent.children) == 2
        parent.kill_children()
        assert len(parent.children) == 0

    @pytest.mark.asyncio
    async def test_result_async(self):
        """Test async result() method"""
        async def get_value():
            await asyncio.sleep(0.1)
            return "async_result"

        task = DeferredTask("test_async_result")
        task.start_task(get_value)
        result = await asyncio.wait_for(task.result(timeout=2), timeout=3)
        assert result == "async_result"


class TestRunInBackground:
    """Test run_in_background function"""

    @pytest.mark.asyncio
    async def test_run_in_background_returns_task(self):
        """Test that run_in_background returns an asyncio.Task"""
        async def background_task():
            return "background"

        task = run_in_background(background_task())
        assert isinstance(task, asyncio.Task)
        # Wait for completion
        await asyncio.sleep(0.1)

    @pytest.mark.asyncio
    async def test_run_in_background_executes(self):
        """Test that background task executes"""
        result_container = {"value": None}

        async def set_value():
            await asyncio.sleep(0.05)
            result_container["value"] = "executed"

        run_in_background(set_value())
        # Wait and verify
        await asyncio.sleep(0.2)
        assert result_container["value"] == "executed"


class TestDeferredTaskWithArgs:
    """Test DeferredTask with various function signatures"""

    @pytest.mark.asyncio
    async def test_task_with_args(self):
        """Test task execution with positional arguments"""
        async def add(a, b):
            return a + b

        task = DeferredTask("test_args")
        task.start_task(add, 3, 4)
        time.sleep(0.1)
        result = task.result_sync(timeout=1)
        assert result == 7

    @pytest.mark.asyncio
    async def test_task_with_kwargs(self):
        """Test task execution with keyword arguments"""
        async def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        task = DeferredTask("test_kwargs")
        task.start_task(greet, "World", greeting="Hi")
        time.sleep(0.1)
        result = task.result_sync(timeout=1)
        assert result == "Hi, World!"

    @pytest.mark.asyncio
    async def test_task_with_args_and_kwargs(self):
        """Test task execution with both positional and keyword arguments"""
        async def func(a, b, c=10):
            return a + b + c

        task = DeferredTask("test_mixed")
        task.start_task(func, 1, 2, c=3)
        time.sleep(0.1)
        result = task.result_sync(timeout=1)
        assert result == 6
