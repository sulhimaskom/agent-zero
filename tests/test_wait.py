"""Tests for wait utilities.

Tests the format_remaining_time function for time formatting.
"""
from python.helpers.wait import format_remaining_time


class TestFormatRemainingTime:
    """Test format_remaining_time function"""

    def test_zero_seconds(self):
        """Test zero seconds returns 0.0s"""
        result = format_remaining_time(0)
        assert result == "0.0s remaining"

    def test_negative_seconds_returns_zero(self):
        """Test negative seconds returns 0.0s"""
        result = format_remaining_time(-10)
        assert result == "0.0s remaining"

    def test_seconds_only(self):
        """Test seconds only formatting"""
        result = format_remaining_time(45.5)
        assert "45.5s" in result
        assert "remaining" in result

    def test_minutes_only(self):
        """Test minutes only formatting"""
        result = format_remaining_time(120)
        assert "2m" in result
        assert "remaining" in result

    def test_hours_only(self):
        """Test hours only formatting"""
        result = format_remaining_time(7200)
        assert "2h" in result
        assert "remaining" in result

    def test_days_only(self):
        """Test days only formatting"""
        result = format_remaining_time(86400)
        assert "1d" in result
        assert "remaining" in result

    def test_days_and_hours(self):
        """Test days and hours formatting"""
        result = format_remaining_time(90000)  # 1 day + 1 hour
        assert "1d" in result
        assert "1h" in result
        assert "remaining" in result

    def test_days_and_minutes(self):
        """Test days and minutes formatting"""
        result = format_remaining_time(87000)  # 1 day + 10 minutes
        assert "1d" in result
        assert "10m" in result
        assert "remaining" in result

    def test_hours_minutes_seconds(self):
        """Test hours, minutes, and seconds formatting"""
        result = format_remaining_time(3723)  # 1h 2m 3s
        assert "1h" in result
        assert "2m" in result
        assert "3s" in result
        assert "remaining" in result

    def test_minutes_seconds_with_fractional(self):
        """Test minutes and seconds with fractional seconds"""
        result = format_remaining_time(125.5)  # 2m 5.5s
        assert "2m" in result
        assert "5.5s" in result
        assert "remaining" in result

    def test_fractional_seconds_only(self):
        """Test fractional seconds only"""
        result = format_remaining_time(0.5)
        assert "0.5s" in result
        assert "remaining" in result

    def test_single_second(self):
        """Test single second displays correctly"""
        result = format_remaining_time(1)
        assert "1.0s" in result
        assert "remaining" in result

    def test_single_minute(self):
        """Test single minute displays correctly"""
        result = format_remaining_time(60)
        assert "1m" in result
        assert "remaining" in result

    def test_single_hour(self):
        """Test single hour displays correctly"""
        result = format_remaining_time(3600)
        assert "1h" in result
        assert "remaining" in result

    def test_single_day(self):
        """Test single day displays correctly"""
        result = format_remaining_time(86400)
        assert "1d" in result
        assert "remaining" in result

    def test_large_value(self):
        """Test very large time values"""
        result = format_remaining_time(1000000)  # ~11 days
        assert "d" in result
        assert "remaining" in result

    def test_very_small_fractional(self):
        """Test very small fractional seconds"""
        result = format_remaining_time(0.1)
        assert "0.1s" in result
        assert "remaining" in result

    def test_format_contains_space_between_parts(self):
        """Test multiple parts are space-separated"""
        result = format_remaining_time(90061)  # 1d 1h 1m 1s
        parts = result.split()
        # Should have multiple parts
        assert len(parts) >= 2


class TestFormatRemainingTimeEdgeCases:
    """Edge case tests for format_remaining_time"""

    def test_negative_zero(self):
        """Test negative zero"""
        result = format_remaining_time(-0.0)
        # -0.0 is treated as negative so it shows -0.0s
        assert "0.0s remaining" in result or "-0.0s remaining" in result

    def test_just_under_minute_threshold(self):
        """Test just under minute threshold"""
        result = format_remaining_time(59.9)
        assert "59.9s" in result

    def test_just_over_minute_threshold(self):
        """Test just over minute threshold"""
        result = format_remaining_time(60.1)
        assert "1m" in result

    def test_just_under_hour_threshold(self):
        """Test just under hour threshold"""
        result = format_remaining_time(3599)
        assert "59m" in result

    def test_just_over_hour_threshold(self):
        """Test just over hour threshold"""
        result = format_remaining_time(3600.1)
        assert "1h" in result

    def test_just_under_day_threshold(self):
        """Test just under day threshold"""
        result = format_remaining_time(86399)
        assert "23h" in result

    def test_just_over_day_threshold(self):
        """Test just over day threshold"""
        result = format_remaining_time(86400.1)
        assert "1d" in result
