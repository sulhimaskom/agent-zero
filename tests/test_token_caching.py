from unittest.mock import MagicMock, patch

import pytest

from python.helpers.history import Bulk, History, Message, Topic


class TestTokenCaching:
    def test_message_token_caching(self):
        """Test that Message caches token calculations"""
        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 10

            # Create message after patching
            msg = Message(ai=True, content="Test message", tokens=0)

            # First call should calculate (already happened in __init__)
            tokens1 = msg.get_tokens()
            # Second call should return cached value
            tokens2 = msg.get_tokens()

            # Both should return the calculated value
            assert tokens1 == tokens2
            # Should only be called once (during __init__)
            mock_count.assert_called_once()

    def test_topic_token_caching(self):
        """Test that Topic caches token calculations"""
        topic = Topic(history=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 5

            # Add messages after patching
            topic.add_message(ai=True, content="Message 1")
            topic.add_message(ai=False, content="Message 2")

            tokens1 = topic.get_tokens()
            tokens2 = topic.get_tokens()

            assert tokens1 == tokens2
            # Should be called twice (once for each message)
            assert mock_count.call_count == 2

    def test_topic_cache_invalidation_on_add(self):
        """Test that Topic cache is invalidated when message is added"""
        topic = Topic(history=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 5

            topic.add_message(ai=True, content="Initial message")
            topic.get_tokens()  # Calculate and cache
            assert mock_count.call_count == 1

            mock_count.reset_mock()
            topic.add_message(ai=True, content="New message")
            topic.get_tokens()  # Recalculate

            assert mock_count.call_count == 1

    def test_topic_cache_invalidation_on_summary(self):
        """Test that Topic cache is invalidated when summary is set"""
        topic = Topic(history=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 5

            topic.add_message(ai=True, content="Message 1")
            topic.get_tokens()
            assert mock_count.call_count == 1

            mock_count.reset_mock()
            topic.set_summary("Summary text")
            topic.get_tokens()

            assert mock_count.call_count == 1

    def test_bulk_token_caching(self):
        """Test that Bulk caches token calculations"""
        bulk = Bulk(history=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 5

            # Add messages with pre-calculated tokens
            bulk.records.append(Message(ai=True, content="Message 1", tokens=5))
            bulk.records.append(Message(ai=False, content="Message 2", tokens=5))

            tokens1 = bulk.get_tokens()
            tokens2 = bulk.get_tokens()

            assert tokens1 == tokens2
            assert tokens1 == 10
            # Should not call count_tokens since we provided tokens
            mock_count.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_cache_invalidation_on_summarize(self):
        """Test that Bulk cache is invalidated when summarized"""
        bulk = Bulk(history=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 5

            bulk.records.append(Message(ai=True, content="Message 1", tokens=5))
            bulk.get_tokens()
            # Should not call count_tokens since we provided tokens
            assert mock_count.call_count == 0

            mock_count.reset_mock()
            # Set summary directly to invalidate cache
            bulk.summary = "Summary"
            bulk._tokens = None  # Invalidate cache
            bulk.get_tokens()

            # Should call count_tokens once for the summary
            assert mock_count.call_count == 1

    def test_history_token_caching(self):
        """Test that History caches token calculations"""
        history = History(agent=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 10

            # Add message with pre-calculated tokens
            history.current.add_message(ai=True, content="Message 1", tokens=10)

            tokens1 = history.get_tokens()
            tokens2 = history.get_tokens()

            assert tokens1 == tokens2
            assert tokens1 == 10
            # Should not call count_tokens since we provided tokens
            mock_count.assert_not_called()

    def test_history_cache_invalidation_on_add_message(self):
        """Test that History cache is invalidated when message is added"""
        history = History(agent=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 10

            history.current.add_message(ai=True, content="Initial", tokens=10)
            history.get_tokens()
            assert mock_count.call_count == 0  # No calls since tokens provided

            mock_count.reset_mock()
            history.add_message(ai=True, content="New message", tokens=10)
            history.get_tokens()

            assert mock_count.call_count == 0  # Still no calls

    def test_history_cache_invalidation_on_new_topic(self):
        """Test that History cache is invalidated when new topic is created"""
        history = History(agent=MagicMock())

        with patch("python.helpers.tokens.count_tokens") as mock_count:
            mock_count.return_value = 10

            history.current.add_message(ai=True, content="Message 1", tokens=10)
            history.get_tokens()
            assert mock_count.call_count == 0  # No calls since tokens provided

            mock_count.reset_mock()
            history.new_topic()
            history.get_tokens()

            assert mock_count.call_count == 0  # Still no calls

    def test_topic_with_summary_caching(self):
        """Test that Topic with summary uses cached summary tokens"""
        topic = Topic(history=MagicMock())
        topic.summary = "Pre-existing summary"

        with patch("python.helpers.tokens.approximate_tokens") as mock_approx:
            mock_approx.return_value = 16

            tokens1 = topic.get_tokens()
            tokens2 = topic.get_tokens()

            assert tokens1 == tokens2
            assert tokens1 == 16
            mock_approx.assert_called_once()

    def test_bulk_with_summary_caching(self):
        """Test that Bulk with summary uses cached summary tokens"""
        bulk = Bulk(history=MagicMock())
        bulk.summary = "Pre-existing summary"

        with patch("python.helpers.tokens.approximate_tokens") as mock_approx:
            mock_approx.return_value = 22

            tokens1 = bulk.get_tokens()
            tokens2 = bulk.get_tokens()

            assert tokens1 == tokens2
            assert tokens1 == 22
            mock_approx.assert_called_once()
