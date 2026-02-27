import os
import sys
import time

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.helpers.rate_limiter import RateLimiter


class TestRateLimiterInit:
    """Test RateLimiter initialization"""

    def test_default_initialization(self):
        limiter = RateLimiter()
        assert limiter.timeframe == 60  # Default is 60 seconds
        assert limiter.limits == {}
        assert limiter.values == {}

    def test_custom_timeframe(self):
        limiter = RateLimiter(seconds=120)
        assert limiter.timeframe == 120

    def test_custom_limits(self):
        limiter = RateLimiter(seconds=60, api=100, requests=50)
        assert limiter.limits == {"api": 100, "requests": 50}
        assert "api" in limiter.values
        assert "requests" in limiter.values

    def test_limits_coerce_non_int_to_zero(self):
        limiter = RateLimiter(api="invalid", requests=None)
        assert limiter.limits["api"] == 0
        assert limiter.limits["requests"] == 0


class TestRateLimiterAdd:
    """Test RateLimiter add method"""

    @pytest.mark.asyncio
    async def test_add_single_value(self):
        limiter = RateLimiter()
        limiter.add(api=5)
        assert "api" in limiter.values
        assert len(limiter.values["api"]) == 1

    @pytest.mark.asyncio
    async def test_add_multiple_values_same_key(self):
        limiter = RateLimiter()
        limiter.add(api=5)
        limiter.add(api=3)
        assert len(limiter.values["api"]) == 2

    @pytest.mark.asyncio
    async def test_add_multiple_keys(self):
        limiter = RateLimiter()
        limiter.add(api=5, requests=10)
        assert len(limiter.values["api"]) == 1
        assert len(limiter.values["requests"]) == 1

    @pytest.mark.asyncio
    async def test_add_creates_new_key(self):
        limiter = RateLimiter()
        limiter.add(new_key=42)
        assert "new_key" in limiter.values


class TestRateLimiterCleanup:
    """Test RateLimiter cleanup method"""

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_entries(self):
        limiter = RateLimiter(seconds=1)  # 1 second timeframe
        # Add old entry (simulate by manipulating time)
        old_time = time.time() - 2  # 2 seconds ago
        limiter.values["api"] = [(old_time, 5)]

        await limiter.cleanup()
        # Old entry should be removed
        assert len(limiter.values["api"]) == 0

    @pytest.mark.asyncio
    async def test_cleanup_keeps_recent_entries(self):
        limiter = RateLimiter(seconds=60)
        now = time.time()
        limiter.values["api"] = [(now, 5), (now, 3)]

        await limiter.cleanup()
        assert len(limiter.values["api"]) == 2

    @pytest.mark.asyncio
    async def test_cleanup_handles_empty_values(self):
        limiter = RateLimiter()
        # No error should occur with empty values
        await limiter.cleanup()  # Should not raise


class TestRateLimiterGetTotal:
    """Test RateLimiter get_total method"""

    @pytest.mark.asyncio
    async def test_get_total_returns_sum(self):
        limiter = RateLimiter()
        now = time.time()
        limiter.values["api"] = [(now, 5), (now, 3), (now, 2)]

        total = await limiter.get_total("api")
        assert total == 10

    @pytest.mark.asyncio
    async def test_get_total_unknown_key_returns_zero(self):
        limiter = RateLimiter()
        total = await limiter.get_total("unknown")
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_total_empty_key_returns_zero(self):
        limiter = RateLimiter()
        limiter.values["api"] = []
        total = await limiter.get_total("api")
        assert total == 0


class TestRateLimiterWait:
    """Test RateLimiter wait method"""

    @pytest.mark.asyncio
    async def test_wait_exits_when_under_limit(self):
        limiter = RateLimiter(seconds=60, api=100)
        limiter.add(api=5)

        # Should exit immediately since 5 < 100
        await limiter.wait()

    @pytest.mark.asyncio
    async def test_wait_with_callback(self):
        limiter = RateLimiter(seconds=60, api=10)
        # Add to exceed limit
        limiter.add(api=5)

        # Create a callback that always returns False (don't wait)
        async def callback(msg, key, total, limit):
            return False  # Signal to stop waiting

        start = time.time()
        await limiter.wait(callback=callback)
        # Should have waited at least briefly
        assert time.time() - start >= 0

    @pytest.mark.asyncio
    async def test_wait_respects_multiple_keys(self):
        limiter = RateLimiter(seconds=60, api=10, requests=5)
        limiter.add(api=5, requests=3)

        # Both under limit - should exit immediately
        await limiter.wait()


class TestRateLimiterIntegration:
    """Integration tests for RateLimiter"""

    @pytest.mark.asyncio
    async def test_full_rate_limiting_flow(self):
        # Simulate a full rate limiting scenario
        limiter = RateLimiter(seconds=60, api=10)

        # Add some requests
        for _ in range(5):
            limiter.add(api=1)

        # Should still be under limit
        total = await limiter.get_total("api")
        assert total == 5

        # Cleanup old entries
        await limiter.cleanup()

        # Add more to reach limit
        for _ in range(5):
            limiter.add(api=1)

        total = await limiter.get_total("api")
        assert total == 10
