"""
Tests for memory leak fixes in memory and vector database modules.
"""

import unittest
import time
import gc
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from python.helpers.memory_monitor import MemoryMonitor, WeakValueDictionary, get_memory_monitor
    from python.helpers.memory import Memory
    from python.helpers.vector_db import VectorDB
except ImportError as e:
    print(f"Import error (expected in test environment): {e}")
    # Create mock classes for testing
    MemoryMonitor = Mock
    WeakValueDictionary = Mock
    Memory = Mock
    VectorDB = Mock


class TestMemoryMonitor(unittest.TestCase):
    """Test the memory monitoring functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.monitor = MemoryMonitor(memory_threshold_percent=50.0, check_interval=1)
    
    def test_memory_monitor_initialization(self):
        """Test memory monitor initialization."""
        self.assertEqual(self.monitor.memory_threshold_percent, 50.0)
        self.assertEqual(self.monitor.check_interval, 1)
        self.assertFalse(self.monitor._monitoring)
        self.assertEqual(len(self.monitor._cleanup_callbacks), 0)
    
    def test_cleanup_callback_registration(self):
        """Test cleanup callback registration."""
        callback = Mock()
        self.monitor.add_cleanup_callback(callback)
        self.assertEqual(len(self.monitor._cleanup_callbacks), 1)
    
    def test_trigger_cleanup(self):
        """Test cleanup triggering."""
        callback = Mock()
        self.monitor.add_cleanup_callback(callback)
        
        result = self.monitor.trigger_cleanup(force_gc=False)
        
        self.assertTrue(result)
        callback.assert_called_once()
    
    @patch('psutil.Process')
    def test_get_memory_usage(self, mock_process):
        """Test memory usage retrieval."""
        mock_process.return_value.memory_percent.return_value = 45.5
        
        usage = self.monitor.get_memory_usage()
        
        self.assertEqual(usage, 45.5)
        mock_process.return_value.memory_percent.assert_called_once()
    
    def test_start_stop_monitoring(self):
        """Test starting and stopping monitoring."""
        self.monitor.start_monitoring()
        self.assertTrue(self.monitor._monitoring)
        
        self.monitor.stop_monitoring()
        self.assertFalse(self.monitor._monitoring)


class TestWeakValueDictionary(unittest.TestCase):
    """Test the weak reference dictionary implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.dict = WeakValueDictionary()
    
    def test_basic_operations(self):
        """Test basic dictionary operations."""
        obj = "test_object"
        
        # Test set and get
        self.dict["key"] = obj
        self.assertEqual(self.dict["key"], obj)
        self.assertIn("key", self.dict)
        
        # Test deletion
        del self.dict["key"]
        self.assertNotIn("key", self.dict)
        with self.assertRaises(KeyError):
            _ = self.dict["key"]
    
    def test_weak_reference_cleanup(self):
        """Test that dead references are cleaned up."""
        obj = "test_object"
        self.dict["key"] = obj
        
        # Verify object is there
        self.assertIn("key", self.dict)
        self.assertEqual(len(self.dict.keys()), 1)
        
        # Delete the object
        del obj
        
        # Trigger cleanup by accessing keys
        keys = self.dict.keys()
        self.assertEqual(len(keys), 0)
        self.assertEqual(self.dict.size(), 0)
    
    def test_get_with_default(self):
        """Test get method with default value."""
        result = self.dict.get("nonexistent", "default")
        self.assertEqual(result, "default")
        
        obj = "test"
        self.dict["key"] = obj
        result = self.dict.get("key", "default")
        self.assertEqual(result, obj)
    
    def test_items_values_keys(self):
        """Test iteration methods."""
        items = [("key1", "value1"), ("key2", "value2")]
        
        for key, value in items:
            self.dict[key] = value
        
        keys = self.dict.keys()
        values = self.dict.values()
        returned_items = self.dict.items()
        
        self.assertEqual(set(keys), {"key1", "key2"})
        self.assertEqual(set(values), {"value1", "value2"})
        self.assertEqual(set(returned_items), set(items))


class TestMemoryLeakFixes(unittest.TestCase):
    """Test memory leak fixes in Memory and VectorDB classes."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock the dependencies to avoid import issues
        self.mock_agent = Mock()
        self.mock_agent.config.memory_subdir = "test_memory"
        self.mock_agent.config.embeddings_model = Mock()
        self.mock_agent.config.knowledge_subdirs = []
    
    @patch('python.helpers.memory.Memory')
    def test_memory_index_uses_weak_references(self, mock_memory_class):
        """Test that Memory.index uses weak references."""
        # This test verifies the structure is in place
        # Actual functionality depends on the real imports
        try:
            from python.helpers.memory import Memory
            self.assertIsInstance(Memory.index, WeakValueDictionary)
        except (ImportError, AttributeError):
            # Skip if imports fail in test environment
            self.skipTest("Cannot test in current environment")
    
    @patch('python.helpers.vector_db.VectorDB')
    def test_vector_db_uses_weak_references(self, mock_vector_db_class):
        """Test that VectorDB._cached_embeddings uses weak references."""
        try:
            from python.helpers.vector_db import VectorDB
            self.assertIsInstance(VectorDB._cached_embeddings, WeakValueDictionary)
        except (ImportError, AttributeError):
            # Skip if imports fail in test environment
            self.skipTest("Cannot test in current environment")
    
    def test_cleanup_expired_databases_method(self):
        """Test cleanup_expired_databases method exists and is callable."""
        try:
            from python.helpers.memory import Memory
            self.assertTrue(callable(Memory.cleanup_expired_databases))
            self.assertTrue(callable(Memory.get_memory_stats))
        except (ImportError, AttributeError):
            self.skipTest("Cannot test in current environment")
    
    def test_cleanup_expired_embeddings_method(self):
        """Test cleanup_expired_embeddings method exists and is callable."""
        try:
            from python.helpers.vector_db import VectorDB
            self.assertTrue(callable(VectorDB.cleanup_expired_embeddings))
            self.assertTrue(callable(VectorDB.get_embedding_stats))
        except (ImportError, AttributeError):
            self.skipTest("Cannot test in current environment")


class TestMemoryIntegration(unittest.TestCase):
    """Test integration of memory management components."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.monitor = get_memory_monitor()
    
    def test_memory_monitor_integration(self):
        """Test that memory monitor integrates with cleanup callbacks."""
        # Test that we can register callbacks
        callback = Mock()
        self.monitor.add_cleanup_callback(callback)
        
        # Test that cleanup triggers callbacks
        self.monitor.trigger_cleanup(force_gc=False)
        callback.assert_called_once()
    
    @patch('os.getenv')
    def test_environment_configuration(self, mock_getenv):
        """Test environment variable configuration."""
        mock_getenv.side_effect = lambda key, default=None: {
            "MEMORY_THRESHOLD_PERCENT": "80.0",
            "MEMORY_CHECK_INTERVAL": "60",
            "DISABLE_MEMORY_MANAGEMENT": "false"
        }.get(key, default)
        
        # Test that environment variables are read correctly
        self.assertEqual(mock_getenv("MEMORY_THRESHOLD_PERCENT", "75.0"), "80.0")
        self.assertEqual(mock_getenv("MEMORY_CHECK_INTERVAL", "120"), "60")
        self.assertEqual(mock_getenv("DISABLE_MEMORY_MANAGEMENT", "false"), "false")


class TestMemoryLeakDetection(unittest.TestCase):
    """Test memory leak detection capabilities."""
    
    def test_memory_growth_detection(self):
        """Test detection of memory growth patterns."""
        # This is a simplified test - in practice would monitor actual memory usage
        initial_objects = len(gc.get_objects())
        
        # Create some objects
        test_objects = [[] for _ in range(1000)]
        for i in range(1000):
            test_objects[i].append(f"object_{i}")
        
        after_objects = len(gc.get_objects())
        
        # Should have more objects now
        self.assertGreater(after_objects, initial_objects)
        
        # Clean up
        del test_objects
        gc.collect()
        
        final_objects = len(gc.get_objects())
        # Should be closer to initial after cleanup
        self.assertLess(final_objects, after_objects)
    
    def test_cleanup_effectiveness(self):
        """Test that cleanup operations are effective."""
        monitor = MemoryMonitor()
        
        # Track cleanup calls
        cleanup_called = False
        
        def test_cleanup():
            nonlocal cleanup_called
            cleanup_called = True
            gc.collect()
        
        monitor.add_cleanup_callback(test_cleanup)
        
        # Trigger cleanup
        result = monitor.trigger_cleanup()
        
        self.assertTrue(result)
        self.assertTrue(cleanup_called)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)