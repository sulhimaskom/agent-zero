"""Tests for localization utilities.

Tests the Localization class for timezone handling and conversion.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from python.helpers.localization import Localization


def mock_get_dotenv_value(key, default=None):
    """Mock get_dotenv_value based on key"""
    if key == "DEFAULT_USER_TIMEZONE":
        return "UTC"
    elif key == "DEFAULT_USER_UTC_OFFSET_MINUTES":
        return "0"
    return default


# Fixture to reset singleton before each test
@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the Localization singleton before each test"""
    Localization._instance = None
    yield
    Localization._instance = None


class TestLocalizationSingleton:
    """Test Localization singleton pattern"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_get_returns_singleton(self, mock_get_dotenv, mock_pytz):
        """Test that get() returns the same instance"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        instance1 = Localization.get()
        instance2 = Localization.get()

        assert instance1 is instance2


class TestGetTimezone:
    """Test get_timezone method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_get_timezone_returns_stored_value(self, mock_get_dotenv, mock_pytz):
        """Test get_timezone returns the stored timezone string"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc.timezone = "Europe/Paris"

        assert loc.get_timezone() == "Europe/Paris"


class TestGetOffsetMinutes:
    """Test get_offset_minutes method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_get_offset_minutes_returns_stored_value(self, mock_get_dotenv, mock_pytz):
        """Test get_offset_minutes returns the stored offset"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._offset_minutes = 330  # India Standard Time

        assert loc.get_offset_minutes() == 330


class TestCanChangeTimezone:
    """Test _can_change_timezone method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_can_change_when_none_changed(self, mock_get_dotenv, mock_pytz):
        """Test timezone can be changed if never changed before"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._last_timezone_change = None

        assert loc._can_change_timezone() is True

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_cannot_change_within_hour(self, mock_get_dotenv, mock_pytz):
        """Test timezone cannot be changed within 1 hour of last change"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._last_timezone_change = datetime.now() - timedelta(minutes=30)

        assert loc._can_change_timezone() is False

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_can_change_after_hour(self, mock_get_dotenv, mock_pytz):
        """Test timezone can be changed after 1 hour has passed"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._last_timezone_change = datetime.now() - timedelta(hours=2)

        assert loc._can_change_timezone() is True


class TestSetTimezone:
    """Test set_timezone method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.save_dotenv_value")
    @patch("python.helpers.localization.PrintStyle")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_set_timezone_valid(self, mock_get_dotenv, mock_print, mock_save, mock_pytz):
        """Test setting a valid timezone"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value

        loc = Localization()

        mock_tz = MagicMock()
        mock_pytz.timezone.return_value = mock_tz

        with patch.object(loc, "_compute_offset_minutes", return_value=60):
            loc.set_timezone("Europe/Berlin")

            assert loc.timezone == "Europe/Berlin"
            assert loc._offset_minutes == 60

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.save_dotenv_value")
    @patch("python.helpers.localization.PrintStyle")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_set_timezone_rate_limited(self, mock_get_dotenv, mock_print, mock_save, mock_pytz):
        """Test timezone change is rate limited"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value

        loc = Localization()
        loc._last_timezone_change = datetime.now() - timedelta(minutes=30)
        loc._offset_minutes = 0

        mock_tz = MagicMock()
        mock_pytz.timezone.return_value = mock_tz

        with patch.object(loc, "_compute_offset_minutes", return_value=60):
            original_tz = loc.timezone
            loc.set_timezone("Europe/Berlin")

            # Should not change due to rate limit
            assert loc.timezone == original_tz


class TestLocaltimeStrToUtcDt:
    """Test localtime_str_to_utc_dt method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_converts_valid_string_with_offset(self, mock_get_dotenv, mock_pytz):
        """Test converting a local time string with timezone offset"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._offset_minutes = -300  # UTC-5

        result = loc.localtime_str_to_utc_dt("2024-06-15T10:30:00")

        assert result is not None
        assert result.tzinfo is not None

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_returns_none_for_none_input(self, mock_get_dotenv, mock_pytz):
        """Test that None input returns None"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()

        result = loc.localtime_str_to_utc_dt(None)

        assert result is None

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_returns_none_for_empty_string(self, mock_get_dotenv, mock_pytz):
        """Test that empty string input returns None"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()

        result = loc.localtime_str_to_utc_dt("")

        assert result is None


class TestUtcDtToLocaltimeStr:
    """Test utc_dt_to_localtime_str method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_converts_utc_to_local(self, mock_get_dotenv, mock_pytz):
        """Test converting UTC datetime to local time string"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._offset_minutes = 120  # UTC+2

        utc_dt = datetime(2024, 6, 15, 10, 0, 0, tzinfo=UTC)

        result = loc.utc_dt_to_localtime_str(utc_dt)

        assert result is not None
        assert "2024-06-15" in result

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_returns_none_for_none_input(self, mock_get_dotenv, mock_pytz):
        """Test that None input returns None"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()

        result = loc.utc_dt_to_localtime_str(None)

        assert result is None


class TestSerializeDatetime:
    """Test serialize_datetime method"""

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_serializes_datetime_with_offset(self, mock_get_dotenv, mock_pytz):
        """Test serializing datetime with users timezone offset"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()
        loc._offset_minutes = 0

        dt = datetime(2024, 6, 15, 10, 30, 0, tzinfo=UTC)

        result = loc.serialize_datetime(dt)

        assert result is not None
        assert "2024-06-15" in result

    @patch("python.helpers.localization.pytz")
    @patch("python.helpers.localization.get_dotenv_value")
    def test_returns_none_for_none_input(self, mock_get_dotenv, mock_pytz):
        """Test that None input returns None"""
        mock_get_dotenv.side_effect = mock_get_dotenv_value
        mock_tz = MagicMock()
        mock_tz.utcoffset.return_value = timedelta(0)
        mock_pytz.timezone.return_value = mock_tz

        loc = Localization()

        result = loc.serialize_datetime(None)

        assert result is None
