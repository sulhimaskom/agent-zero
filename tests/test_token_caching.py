import pytest
from unittest.mock import MagicMock, patch
from python.helpers.history import History, Topic, Bulk, Message


class TestTokenCaching:
    
    def test_message_token_caching(self):
        """Test that Message caches token calculations"""
        msg = Message(ai=True, content="Test message")
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 10
            
            tokens1 = msg.get_tokens()
            tokens2 = msg.get_tokens()
            
            assert tokens1 == 10
            assert tokens2 == 10
            mock_count.assert_called_once()  # Only called once due to caching
    
    def test_topic_token_caching(self):
        """Test that Topic caches token calculations"""
        topic = Topic(history=MagicMock())
        topic.add_message(ai=True, content="Message 1")
        topic.add_message(ai=False, content="Message 2")
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 5
            
            tokens1 = topic.get_tokens()
            tokens2 = topic.get_tokens()
            
            assert tokens1 == 10
            assert tokens2 == 10
            mock_count.assert_called_once()
    
    def test_topic_cache_invalidation_on_add(self):
        """Test that Topic cache is invalidated when message is added"""
        topic = Topic(history=MagicMock())
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 5
            
            topic.get_tokens()  # Calculate and cache
            assert mock_count.call_count == 2
            
            mock_count.reset_mock()
            topic.add_message(ai=True, content="New message")
            topic.get_tokens()  # Recalculate
            
            assert mock_count.call_count == 1
    
    def test_topic_cache_invalidation_on_summary(self):
        """Test that Topic cache is invalidated when summary is set"""
        topic = Topic(history=MagicMock())
        topic.add_message(ai=True, content="Message 1")
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 5
            
            topic.get_tokens()
            assert mock_count.call_count == 1
            
            mock_count.reset_mock()
            topic.set_summary("Summary text")
            topic.get_tokens()
            
            assert mock_count.call_count == 1
    
    def test_bulk_token_caching(self):
        """Test that Bulk caches token calculations"""
        bulk = Bulk(history=MagicMock())
        bulk.records.append(Message(ai=True, content="Message 1"))
        bulk.records.append(Message(ai=False, content="Message 2"))
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 5
            
            tokens1 = bulk.get_tokens()
            tokens2 = bulk.get_tokens()
            
            assert tokens1 == 10
            assert tokens2 == 10
            mock_count.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_cache_invalidation_on_summarize(self):
        """Test that Bulk cache is invalidated when summarized"""
        bulk = Bulk(history=MagicMock())
        bulk.records.append(Message(ai=True, content="Message 1"))
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 5
            
            bulk.get_tokens()
            assert mock_count.call_count == 1
            
            mock_count.reset_mock()
            async def mock_summarize():
                return "Summary"
            with patch.object(bulk, 'summarize', side_effect=mock_summarize):
                await bulk.summarize()
                bulk.get_tokens()
                
            assert mock_count.call_count == 1
    
    def test_history_token_caching(self):
        """Test that History caches token calculations"""
        history = History(agent=MagicMock())
        history.current.add_message(ai=True, content="Message 1")
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 10
            
            tokens1 = history.get_tokens()
            tokens2 = history.get_tokens()
            
            assert tokens1 == 10
            assert tokens2 == 10
            mock_count.assert_called_once()
    
    def test_history_cache_invalidation_on_add_message(self):
        """Test that History cache is invalidated when message is added"""
        history = History(agent=MagicMock())
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 10
            
            history.get_tokens()
            assert mock_count.call_count == 1
            
            mock_count.reset_mock()
            history.add_message(ai=True, content="New message")
            history.get_tokens()
            
            assert mock_count.call_count == 1
    
    def test_history_cache_invalidation_on_new_topic(self):
        """Test that History cache is invalidated when new topic is created"""
        history = History(agent=MagicMock())
        history.current.add_message(ai=True, content="Message 1")
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 10
            
            history.get_tokens()
            assert mock_count.call_count == 1
            
            mock_count.reset_mock()
            history.new_topic()
            history.get_tokens()
            
            assert mock_count.call_count == 1
    
    def test_topic_with_summary_caching(self):
        """Test that Topic with summary uses cached summary tokens"""
        topic = Topic(history=MagicMock())
        topic.summary = "Pre-existing summary"
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 15
            
            tokens1 = topic.get_tokens()
            tokens2 = topic.get_tokens()
            
            assert tokens1 == 15
            assert tokens2 == 15
            mock_count.assert_called_once()
    
    def test_bulk_with_summary_caching(self):
        """Test that Bulk with summary uses cached summary tokens"""
        bulk = Bulk(history=MagicMock())
        bulk.summary = "Pre-existing summary"
        
        with patch('python.helpers.tokens.count_tokens') as mock_count:
            mock_count.return_value = 20
            
            tokens1 = bulk.get_tokens()
            tokens2 = bulk.get_tokens()
            
            assert tokens1 == 20
            assert tokens2 == 20
            mock_count.assert_called_once()
