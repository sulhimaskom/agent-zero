import unittest
import time
import gc
from unittest.mock import Mock, patch
import sys
import os

# Add the python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from helpers.memory_manager import (
    MemoryCache, 
    memory_manager, 
    get_memory_usage, 
    check_memory_thresholds,
    trigger_emergency_cleanup,
    MEMORY_EXPIRY_TIME,
    EMBEDDING_EXPIRY_TIME,
    MAX_CACHE_SIZE,
    MAX_EMBEDDING_CACHE_SIZE
)


class TestMemoryCache(unittest.TestCase):
    """Test the MemoryCache class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cache = MemoryCache(max_size=3, expiry_time=1)  # 1 second expiry for testing
    
    def test_cache_put_and_get(self):
        """Test basic cache put and get operations."""
        self.cache.put("key1", "value1")
        self.assertEqual(self.cache.get("key1"), "value1")
        self.assertIsNone(self.cache.get("nonexistent"))
    
    def test_cache_size_limit(self):
        """Test that cache respects size limits."""
        # Fill cache to max size
        self.cache.put("key1", "value1")
        self.cache.put("key2", "value2")
        self.cache.put("key3", "value3")
        self.assertEqual(self.cache.size(), 3)
        
        # Add one more - should evict oldest
        self.cache.put("key4", "value4")
        self.assertEqual(self.cache.size(), 3)
        self.assertIsNone(self.cache.get("key1"))  # Should be evicted
        self.assertEqual(self.cache.get("key4"), "value4")
    
    def test_cache_expiry(self):
        """Test that cache items expire."""
        self.cache.put("key1", "value1")
        self.assertEqual(self.cache.get("key1"), "value1")
        
        # Wait for expiry
        time.sleep(1.1)
        
        # Force cleanup to remove expired items
        cleaned = self.cache.cleanup_expired()
        self.assertEqual(cleaned, 1)
        self.assertEqual(self.cache.size(), 0)
        
        # Should be expired after cleanup
        self.assertIsNone(self.cache.get("key1"))
    
    def test_cache_remove(self):
        """Test cache removal."""
        self.cache.put("key1", "value1")
        self.assertTrue(self.cache.remove("key1"))
        self.assertFalse(self.cache.remove("key1"))  # Already removed
        self.assertIsNone(self.cache.get("key1"))
    
    def test_cache_clear(self):
        """Test cache clearing."""
        self.cache.put("key1", "value1")
        self.cache.put("key2", "value2")
        self.assertEqual(self.cache.size(), 2)
        
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)
    
    def test_cache_stats(self):
        """Test cache statistics."""
        self.cache.put("key1", "value1")
        stats = self.cache.get_stats()
        
        self.assertEqual(stats['size'], 1)
        self.assertEqual(stats['max_size'], 3)
        self.assertIn('oldest_item', stats)
        self.assertIn('last_cleanup', stats)


class TestMemoryManager(unittest.TestCase):
    """Test the MemoryManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Clear caches before each test
        memory_manager.database_cache.clear()
        memory_manager.embedding_cache.clear()
    
    def test_database_cache_operations(self):
        """Test database cache operations."""
        # Test put and get
        mock_db = Mock()
        memory_manager.database_cache.put("test_db", mock_db)
        
        retrieved = memory_manager.database_cache.get("test_db")
        self.assertEqual(retrieved, mock_db)
        
        # Test cache size
        self.assertEqual(memory_manager.database_cache.size(), 1)
    
    def test_embedding_cache_operations(self):
        """Test embedding cache operations."""
        # Test put and get
        mock_embedding = Mock()
        memory_manager.embedding_cache.put("test_embedding", mock_embedding)
        
        retrieved = memory_manager.embedding_cache.get("test_embedding")
        self.assertEqual(retrieved, mock_embedding)
        
        # Test cache size
        self.assertEqual(memory_manager.embedding_cache.size(), 1)
    
    def test_cleanup_all(self):
        """Test cleanup of all caches."""
        # Add some items
        memory_manager.database_cache.put("db1", Mock())
        memory_manager.embedding_cache.put("emb1", Mock())
        
        # Cleanup should not remove non-expired items
        result = memory_manager.cleanup_all()
        self.assertEqual(result['databases_cleaned'], 0)
        self.assertEqual(result['embeddings_cleaned'], 0)
    
    def test_memory_stats(self):
        """Test memory statistics."""
        stats = memory_manager.get_memory_stats()
        
        self.assertIn('database_cache', stats)
        self.assertIn('embedding_cache', stats)
        self.assertIn('system_memory', stats)
        self.assertIn('timestamp', stats)
        
        # Check structure of cache stats
        db_stats = stats['database_cache']
        self.assertIn('size', db_stats)
        self.assertIn('max_size', db_stats)
        
        # Check system memory stats
        sys_stats = stats['system_memory']
        self.assertIn('usage_percent', sys_stats)
        self.assertIn('warning_threshold', sys_stats)
        self.assertIn('emergency_threshold', sys_stats)


class TestMemoryMonitoring(unittest.TestCase):
    """Test memory monitoring functions."""
    
    @patch('helpers.memory_manager.psutil.Process')
    def test_get_memory_usage(self, mock_process):
        """Test memory usage monitoring."""
        # Mock psutil.Process
        mock_process_instance = Mock()
        mock_process_instance.memory_percent.return_value = 75.5
        mock_process.return_value = mock_process_instance
        
        usage = get_memory_usage()
        self.assertEqual(usage, 75.5)
    
    @patch('helpers.memory_manager.get_memory_usage')
    @patch('helpers.memory_manager.trigger_emergency_cleanup')
    @patch('helpers.memory_manager.trigger_warning_cleanup')
    def test_check_memory_thresholds(self, mock_warning_cleanup, mock_emergency_cleanup, mock_get_memory):
        """Test memory threshold checking."""
        # Test normal usage
        mock_get_memory.return_value = 50.0
        status = check_memory_thresholds()
        self.assertFalse(status['warning'])
        self.assertFalse(status['emergency'])
        
        # Test warning threshold
        mock_get_memory.return_value = 85.0
        status = check_memory_thresholds()
        self.assertTrue(status['warning'])
        self.assertFalse(status['emergency'])
        mock_warning_cleanup.assert_called_once()
        
        # Reset mock
        mock_warning_cleanup.reset_mock()
        
        # Test emergency threshold
        mock_get_memory.return_value = 98.0
        status = check_memory_thresholds()
        self.assertTrue(status['warning'])
        self.assertTrue(status['emergency'])
        mock_emergency_cleanup.assert_called_once()
    
    @patch('helpers.memory_manager.gc.collect')
    def test_trigger_emergency_cleanup(self, mock_gc):
        """Test emergency cleanup."""
        # Add some items to caches
        memory_manager.database_cache.put("test", Mock())
        memory_manager.embedding_cache.put("test", Mock())
        
        trigger_emergency_cleanup()
        
        # Should call garbage collection twice
        self.assertEqual(mock_gc.call_count, 2)


class TestMemoryIntegration(unittest.TestCase):
    """Integration tests for memory management."""
    
    def setUp(self):
        """Set up test fixtures."""
        memory_manager.database_cache.clear()
        memory_manager.embedding_cache.clear()
    
    def test_cache_lifecycle(self):
        """Test complete cache lifecycle."""
        # Test database cache
        mock_db = Mock()
        
        # Put in cache
        memory_manager.database_cache.put("test_db", mock_db)
        self.assertEqual(memory_manager.database_cache.size(), 1)
        
        # Retrieve from cache
        retrieved = memory_manager.database_cache.get("test_db")
        self.assertEqual(retrieved, mock_db)
        
        # Remove from cache
        removed = memory_manager.database_cache.remove("test_db")
        self.assertTrue(removed)
        self.assertEqual(memory_manager.database_cache.size(), 0)
    
    def test_memory_health_decorator(self):
        """Test memory health check decorator."""
        from helpers.memory_manager import memory_health_check
        
        @memory_health_check
        def test_function():
            return "test_result"
        
        # Should execute normally
        result = test_function()
        self.assertEqual(result, "test_result")
    
    def test_configuration_constants(self):
        """Test that configuration constants are properly set."""
        self.assertGreater(MEMORY_EXPIRY_TIME, 0)
        self.assertGreater(EMBEDDING_EXPIRY_TIME, 0)
        self.assertGreater(MAX_CACHE_SIZE, 0)
        self.assertGreater(MAX_EMBEDDING_CACHE_SIZE, 0)


if __name__ == '__main__':
    unittest.main()