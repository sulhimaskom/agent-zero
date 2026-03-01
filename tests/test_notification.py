# Project: Agent Zero
# File: tests/test_notification.py
# Description: Unit tests for python/helpers/notification.py helper module

import pytest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from python.helpers.notification import (
    NotificationType,
    NotificationPriority,
    NotificationItem,
    NotificationManager,
)


class TestNotificationType:
    """Test NotificationType enum"""

    def test_notification_type_values(self):
        """Test NotificationType enum values"""
        assert NotificationType.INFO.value == "info"
        assert NotificationType.SUCCESS.value == "success"
        assert NotificationType.WARNING.value == "warning"
        assert NotificationType.ERROR.value == "error"
        assert NotificationType.PROGRESS.value == "progress"

    def test_notification_type_count(self):
        """Test NotificationType has expected number of members"""
        members = list(NotificationType)
        assert len(members) == 5


class TestNotificationPriority:
    """Test NotificationPriority enum"""

    def test_notification_priority_values(self):
        """Test NotificationPriority enum values"""
        assert NotificationPriority.NORMAL.value == 10
        assert NotificationPriority.HIGH.value == 20

    def test_notification_priority_count(self):
        """Test NotificationPriority has expected number of members"""
        members = list(NotificationPriority)
        assert len(members) == 2


class TestNotificationItem:
    """Test NotificationItem dataclass"""

    def test_notification_item_creation(self):
        """Test creating a NotificationItem"""
        mock_manager = MagicMock()
        item = NotificationItem(
            manager=mock_manager,
            no=0,
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            title="Test Title",
            message="Test Message",
            detail="Test Detail",
            timestamp=datetime.now(UTC),
        )

        assert item.no == 0
        assert item.type == NotificationType.INFO
        assert item.priority == NotificationPriority.NORMAL
        assert item.title == "Test Title"
        assert item.message == "Test Message"
        assert item.detail == "Test Detail"
        assert item.read is False
        assert item.id != ""  # Should auto-generate ID

    def test_notification_item_string_type_conversion(self):
        """Test NotificationItem accepts string type"""
        mock_manager = MagicMock()
        item = NotificationItem(
            manager=mock_manager,
            no=0,
            type="info",  # String instead of enum
            priority=NotificationPriority.NORMAL,
            title="Test",
            message="Test",
            detail="",
            timestamp=datetime.now(UTC),
        )

        # Should convert string to enum
        assert item.type == NotificationType.INFO

    def test_notification_item_mark_read(self):
        """Test mark_read method"""
        mock_manager = MagicMock()
        item = NotificationItem(
            manager=mock_manager,
            no=0,
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            title="Test",
            message="Test",
            detail="",
            timestamp=datetime.now(UTC),
        )

        assert item.read is False
        item.mark_read()
        assert item.read is True
        mock_manager._update_item.assert_called_once_with(0, read=True)

    def test_notification_item_output(self):
        """Test output method returns expected dict"""
        mock_manager = MagicMock()
        test_time = datetime.now(UTC)
        item = NotificationItem(
            manager=mock_manager,
            no=0,
            type=NotificationType.WARNING,
            priority=NotificationPriority.HIGH,
            title="Warning",
            message="Something happened",
            detail="<b>Detail</b>",
            timestamp=test_time,
            display_time=5,
            read=True,
            group="test-group",
        )

        output = item.output()

        assert output["no"] == 0
        assert output["type"] == "warning"
        assert output["priority"] == 20
        assert output["title"] == "Warning"
        assert output["message"] == "Something happened"
        assert output["detail"] == "<b>Detail</b>"
        assert output["display_time"] == 5
        assert output["read"] is True
        assert output["group"] == "test-group"
        assert "timestamp" in output
        assert "id" in output


class TestNotificationManager:
    """Test NotificationManager class"""

    def test_notification_manager_creation(self):
        """Test creating a NotificationManager"""
        manager = NotificationManager()
        assert manager.guid != ""
        assert manager.notifications == []
        assert manager.updates == []

    def test_notification_manager_custom_max(self):
        """Test NotificationManager with custom max notifications"""
        manager = NotificationManager(max_notifications=50)
        assert manager.max_notifications == 50

    def test_add_notification(self):
        """Test adding a notification"""
        manager = NotificationManager()

        item = manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Test message",
            title="Test title",
            detail="Test detail",
            display_time=5,
            group="test-group",
        )

        assert len(manager.notifications) == 1
        assert item.title == "Test title"
        assert item.message == "Test message"
        assert item.detail == "Test detail"
        assert item.display_time == 5
        assert item.group == "test-group"

    def test_add_notification_string_type(self):
        """Test adding notification with string type"""
        manager = NotificationManager()

        item = manager.add_notification(
            type="error",  # String instead of enum
            priority=NotificationPriority.HIGH,
            message="Error occurred",
        )

        assert item.type == NotificationType.ERROR
        assert item.priority == NotificationPriority.HIGH

    def test_enforce_limit(self):
        """Test max notifications limit enforcement"""
        manager = NotificationManager(max_notifications=3)

        # Add 5 notifications
        for i in range(5):
            manager.add_notification(
                type=NotificationType.INFO,
                priority=NotificationPriority.NORMAL,
                message=f"Message {i}",
            )

        # Should only have 3
        assert len(manager.notifications) == 3

        # Oldest should be removed (first 2)
        assert manager.notifications[0].message == "Message 2"
        assert manager.notifications[1].message == "Message 3"
        assert manager.notifications[2].message == "Message 4"

    def test_enforce_limit_renumbers(self):
        """Test that enforce_limit renumbers notifications correctly"""
        manager = NotificationManager(max_notifications=2)

        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="First",
        )
        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Second",
        )
        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Third",
        )

        # Check notification numbers are correct
        assert manager.notifications[0].no == 0
        assert manager.notifications[1].no == 1

    def test_get_recent_notifications(self):
        """Test getting recent notifications"""
        manager = NotificationManager()

        # Add old notification
        old_time = datetime.now(UTC) - timedelta(seconds=100)
        old_item = NotificationItem(
            manager=manager,
            no=0,
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            title="Old",
            message="Old message",
            detail="",
            timestamp=old_time,
        )
        manager.notifications.append(old_item)

        # Add recent notification
        recent_item = manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Recent message",
        )

        # Get notifications from last 60 seconds
        recent = manager.get_recent_notifications(seconds=60)
        assert len(recent) == 1
        assert recent[0].message == "Recent message"

    def test_output(self):
        """Test output method"""
        manager = NotificationManager()

        manager.add_notification(
            type=NotificationType.SUCCESS,
            priority=NotificationPriority.NORMAL,
            message="Success message",
            title="Success",
        )

        output = manager.output()
        assert len(output) == 1
        assert output[0]["title"] == "Success"
        assert output[0]["message"] == "Success message"

    def test_output_with_range(self):
        """Test output with start/end range"""
        manager = NotificationManager()

        for i in range(5):
            manager.add_notification(
                type=NotificationType.INFO,
                priority=NotificationPriority.NORMAL,
                message=f"Message {i}",
            )

        output = manager.output(start=1, end=3)
        assert len(output) == 2

    def test_update_item(self):
        """Test updating a notification item"""
        manager = NotificationManager()

        item = manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Original",
        )

        manager._update_item(0, message="Updated")
        assert manager.notifications[0].message == "Updated"

    def test_mark_all_read(self):
        """Test marking all notifications as read"""
        manager = NotificationManager()

        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="First",
        )
        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Second",
        )

        manager.mark_all_read()

        assert manager.notifications[0].read is True
        assert manager.notifications[1].read is True

    def test_clear_all(self):
        """Test clearing all notifications"""
        manager = NotificationManager()

        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Test",
        )

        assert len(manager.notifications) == 1

        old_guid = manager.guid
        manager.clear_all()

        assert manager.notifications == []
        assert manager.updates == []
        assert manager.guid != old_guid  # New GUID generated

    def test_get_notifications_by_type(self):
        """Test filtering notifications by type"""
        manager = NotificationManager()

        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Info message",
        )
        manager.add_notification(
            type=NotificationType.ERROR,
            priority=NotificationPriority.NORMAL,
            message="Error message",
        )
        manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Another info",
        )

        info_notifications = manager.get_notifications_by_type(NotificationType.INFO)
        assert len(info_notifications) == 2

        error_notifications = manager.get_notifications_by_type(NotificationType.ERROR)
        assert len(error_notifications) == 1

    def test_updates_list_maintained(self):
        """Test that updates list is maintained correctly"""
        manager = NotificationManager()

        item1 = manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="First",
        )

        # Update the first item
        manager._update_item(item1.no, message="Updated first")

        # Add second item
        item2 = manager.add_notification(
            type=NotificationType.INFO,
            priority=NotificationPriority.NORMAL,
            message="Second",
        )

        # Should have 3 updates (add, update, add)
        assert len(manager.updates) == 3
