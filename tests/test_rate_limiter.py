import asyncio
import time

import pytest

from python.helpers.rate_limiter import RateLimiter


class TestRateLimiterInit:
    """Test RateLimiter initialization"""

    def test_default_initialization(self):
        """Test default initialization with no arguments"""
        limiter = RateLimiter()
        assert limiter.timeframe == 60  # Default from constants
        assert limiter.limits == {}
        assert limiter.values == {}

    def test_custom_timeframe(self):
        """Test initialization with custom timeframe"""
        limiter = RateLimiter(seconds=120)
        assert limiter.timeframe == 120

    def test_single_limit(self):
        """Test initialization with single limit"""
        limiter = RateLimiter(seconds=60, requests=10)
        assert limiter.limits == {"requests": 10}
        assert limiter.values == {"requests": []}

    def test_multiple_limits(self):
        """Test initialization with multiple limits"""
        limiter = RateLimiter(seconds=60, requests=10, tokens=1000)
        assert limiter.limits == {"requests": 10, "tokens": 1000}
        assert limiter.values == {"requests": [], "tokens": []}

    def test_non_numeric_limit_converted_to_zero(self):
        """Test that non-numeric limits are converted to 0"""
        limiter = RateLimiter(seconds=60, invalid="not_a_number")
        assert limiter.limits["invalid"] == 0

    def test_float_limit_accepted(self):
        """Test that float limits are accepted"""
        limiter = RateLimiter(seconds=60, rate=10.5)
        assert limiter.limits["rate"] == 10.5


class TestRateLimiterAdd:
    """Test RateLimiter.add() method"""

    def test_add_single_value(self):
        """Test adding a single value"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=1)
        assert len(limiter.values["requests"]) == 1

    def test_add_multiple_values(self):
        """Test adding multiple values at once"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=5, tokens=100)
        assert len(limiter.values["requests"]) == 1
        assert len(limiter.values["tokens"]) == 1

    def test_add_creates_new_key(self):
        """Test that adding to undefined key creates it"""
        limiter = RateLimiter(seconds=60)
        limiter.add(new_key=42)
        assert "new_key" in limiter.values
        assert len(limiter.values["new_key"]) == 1

    def test_add_multiple_calls(self):
        """Test multiple add calls accumulate values"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=1)
        limiter.add(requests=2)
        limiter.add(requests=3)
        assert len(limiter.values["requests"]) == 3


class TestRateLimiterCleanup:
    """Test RateLimiter.cleanup() method"""

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_entries(self):
        """Test that cleanup removes entries outside timeframe"""
        limiter = RateLimiter(seconds=1, requests=10)

        # Add old entry (2 seconds ago - outside 1 second timeframe)
        old_time = time.time() - 2
        limiter.values["requests"].append((old_time, 1))

        # Add new entry (now)
        limiter.add(requests=1)

        # Cleanup should remove the old entry
        await limiter.cleanup()

        # Only the new entry should remain
        assert len(limiter.values["requests"]) == 1

    @pytest.mark.asyncio
    async def test_cleanup_keeps_recent_entries(self):
        """Test that cleanup keeps recent entries"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=1)
        limiter.add(requests=2)

        await limiter.cleanup()

        # Both entries should remain
        assert len(limiter.values["requests"]) == 2


class TestRateLimiterGetTotal:
    """Test RateLimiter.get_total() method"""

    @pytest.mark.asyncio
    async def test_get_total_empty(self):
        """Test get_total returns 0 for empty key"""
        limiter = RateLimiter(seconds=60, requests=10)
        total = await limiter.get_total("requests")
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_total_unknown_key(self):
        """Test get_total returns 0 for unknown key"""
        limiter = RateLimiter(seconds=60)
        total = await limiter.get_total("unknown")
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_total_sums_values(self):
        """Test get_total correctly sums all values"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=1)
        limiter.add(requests=2)
        limiter.add(requests=3)

        total = await limiter.get_total("requests")
        assert total == 6


class TestRateLimiterWait:
    """Test RateLimiter.wait() method"""

    @pytest.mark.asyncio
    async def test_wait_no_limits_set(self):
        """Test wait completes immediately when no limits set"""
        limiter = RateLimiter(seconds=60)
        # Should complete without waiting
        await limiter.wait()

    @pytest.mark.asyncio
    async def test_wait_below_limit(self):
        """Test wait completes when below limit"""
        limiter = RateLimiter(seconds=60, requests=10)
        limiter.add(requests=5)

        # Should complete immediately (5 < 10)
        await limiter.wait()

    @pytest.mark.asyncio
    async def test_wait_at_limit(self):
        """Test wait completes when exactly at limit"""
        limiter = RateLimiter(seconds=60, requests=5)
        limiter.add(requests=5)

        # Should complete (5 == 5, not >)
        await limiter.wait()

    @pytest.mark.asyncio
    async def test_wait_zero_limit_skipped(self):
        """Test wait skips keys with zero or negative limit"""
        limiter = RateLimiter(seconds=60, requests=0)
        limiter.add(requests=100)

        # Should complete because limit <= 0 is skipped
        await limiter.wait()


class TestRateLimiterIntegration:
    """Integration tests for RateLimiter"""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete workflow: add, cleanup, check total"""
        limiter = RateLimiter(seconds=60, requests=10, tokens=100)

        # Add some values
        limiter.add(requests=3, tokens=50)

        # Check totals
        req_total = await limiter.get_total("requests")
        tok_total = await limiter.get_total("tokens")

        assert req_total == 3
        assert tok_total == 50

        # Cleanup
        await limiter.cleanup()

        # Totals should be the same after cleanup (entries are recent)
        req_total = await limiter.get_total("requests")
        tok_total = await limiter.get_total("tokens")

        assert req_total == 3
        assert tok_total == 50

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test async lock works correctly for concurrent access"""
        limiter = RateLimiter(seconds=60, counter=100)

        async def add_values():
            for _ in range(10):
                limiter.add(counter=1)
                await asyncio.sleep(0)

        # Run multiple coroutines concurrently
        await asyncio.gather(add_values(), add_values(), add_values())

        total = await limiter.get_total("counter")
        assert total == 30
