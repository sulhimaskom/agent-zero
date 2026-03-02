import time

import python.helpers.job_loop as job_loop


class TestPauseLoop:
    """Tests for the pause_loop function."""

    def test_pause_loop_sets_keep_running_false(self):
        """Verify pause_loop sets keep_running to False."""
        # Save original state
        original_keep_running = job_loop.keep_running
        original_pause_time = job_loop.pause_time

        try:
            # Set to known state
            job_loop.keep_running = True
            job_loop.pause_time = 0

            # Call pause_loop
            job_loop.pause_loop()

            # Verify keep_running is False
            assert job_loop.keep_running is False
            # Verify pause_time is set to current time (greater than 0)
            assert job_loop.pause_time > 0
        finally:
            # Restore original state
            job_loop.keep_running = original_keep_running
            job_loop.pause_time = original_pause_time

    def test_pause_loop_preserves_pause_time_after_multiple_calls(self):
        """Verify pause_loop updates pause_time on subsequent calls."""
        # Save original state
        original_keep_running = job_loop.keep_running
        original_pause_time = job_loop.pause_time

        try:
            # Set to known state
            job_loop.keep_running = True
            job_loop.pause_time = 0

            # Call pause_loop first time
            first_pause_time = job_loop.pause_time
            job_loop.pause_loop()

            # Small delay to ensure different time
            time.sleep(0.01)

            # Call pause_loop second time
            job_loop.pause_loop()

            # Verify pause_time was updated (greater than first call)
            assert job_loop.pause_time > first_pause_time
            # keep_running should still be False
            assert job_loop.keep_running is False
        finally:
            # Restore original state
            job_loop.keep_running = original_keep_running
            job_loop.pause_time = original_pause_time


class TestResumeLoop:
    """Tests for the resume_loop function."""

    def test_resume_loop_sets_keep_running_true(self):
        """Verify resume_loop sets keep_running to True."""
        # Save original state
        original_keep_running = job_loop.keep_running
        original_pause_time = job_loop.pause_time

        try:
            # Set to known state
            job_loop.keep_running = False
            job_loop.pause_time = time.time()

            # Call resume_loop
            job_loop.resume_loop()

            # Verify keep_running is True
            assert job_loop.keep_running is True
            # Verify pause_time is reset to 0
            assert job_loop.pause_time == 0
        finally:
            # Restore original state
            job_loop.keep_running = original_keep_running
            job_loop.pause_time = original_pause_time

    def test_resume_loop_resets_pause_time(self):
        """Verify resume_loop resets pause_time to 0."""
        # Save original state
        original_keep_running = job_loop.keep_running
        original_pause_time = job_loop.pause_time

        try:
            # Set pause_time to a specific value
            job_loop.keep_running = False
            job_loop.pause_time = 12345.0

            # Call resume_loop
            job_loop.resume_loop()

            # Verify pause_time is reset
            assert job_loop.pause_time == 0
            assert job_loop.keep_running is True
        finally:
            # Restore original state
            job_loop.keep_running = original_keep_running
            job_loop.pause_time = original_pause_time


class TestPauseResumeCycle:
    """Tests for pause/resume cycle functionality."""

    def test_pause_resume_cycle(self):
        """Verify full pause/resume cycle works correctly."""
        # Save original state
        original_keep_running = job_loop.keep_running
        original_pause_time = job_loop.pause_time

        try:
            # Start with running state
            job_loop.keep_running = True
            job_loop.pause_time = 0

            # Pause
            job_loop.pause_loop()
            assert job_loop.keep_running is False
            assert job_loop.pause_time > 0

            paused_time = job_loop.pause_time

            # Resume
            job_loop.resume_loop()
            assert job_loop.keep_running is True
            assert job_loop.pause_time == 0

            # Pause again
            job_loop.pause_loop()
            assert job_loop.keep_running is False
            # New pause_time should be different
            assert job_loop.pause_time > paused_time
        finally:
            # Restore original state
            job_loop.keep_running = original_keep_running
            job_loop.pause_time = original_pause_time


class TestSleepTimeConstant:
    """Tests for the SLEEP_TIME constant."""

    def test_sleep_time_is_positive(self):
        """Verify SLEEP_TIME is a positive number."""
        assert job_loop.SLEEP_TIME > 0

    def test_sleep_time_is_integer_or_float(self):
        """Verify SLEEP_TIME is a number type."""
        assert isinstance(job_loop.SLEEP_TIME, (int, float))
