import asyncio
import time

from python.helpers import errors, runtime
from python.helpers.constants import Limits
from python.helpers.print_style import PrintStyle
from python.helpers.task_scheduler import TaskScheduler

SLEEP_TIME = Limits.JOB_LOOP_SLEEP_TIME

keep_running = True
pause_time = 0
tick_in_progress = False
tick_lock = asyncio.Lock()


async def run_loop():
    global tick_in_progress
    while True:
        if runtime.is_development():
            # Signal to container that the job loop should be paused
            # if we are runing a development instance to avoid duble-running the jobs
            try:
                await runtime.call_development_function(pause_loop)
            except Exception as e:
                PrintStyle().error(
                    "Failed to pause job loop by development instance: " + errors.error_text(e)
                )
        if not keep_running and (time.time() - pause_time) > (SLEEP_TIME * 2):
            resume_loop()

        # Use lock to prevent race condition between check and set of tick_in_progress
        # This addresses the issue where SLEEP_TIME < tick_duration causes overlapping ticks
        if keep_running:
            async with tick_lock:
                if tick_in_progress:
                    # Log warning when skipping tick due to previous tick still running
                    PrintStyle().warning(
                        f"Skipping scheduler tick - previous tick still in progress "
                        f"(SLEEP_TIME={SLEEP_TIME}s may be too short)"
                    )
                else:
                    tick_in_progress = True
                    try:
                        await scheduler_tick()
                    except Exception as e:
                        PrintStyle().error(errors.format_error(e))
                    finally:
                        tick_in_progress = False

        await asyncio.sleep(SLEEP_TIME)


async def scheduler_tick():
    # Get the task scheduler instance and print detailed debug info
    scheduler = TaskScheduler.get()
    # Run the scheduler tick
    await scheduler.tick()


def pause_loop():
    global keep_running, pause_time
    keep_running = False
    pause_time = time.time()


def resume_loop():
    global keep_running, pause_time
    keep_running = True
    pause_time = 0
