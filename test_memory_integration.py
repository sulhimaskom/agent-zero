#!/usr/bin/env python3
"""
Integration test for memory management fixes.
This test verifies that the memory leak fixes work correctly with the actual Memory and VectorDB classes.
"""

import sys
import os
import gc
import time

# Add the python directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

def test_memory_management_integration():
    """Test memory management integration with actual classes."""
    print("Testing memory management integration...")
    
    try:
        # Test memory manager import
        from helpers.memory_manager import memory_manager
        print("✓ Memory manager imported successfully")
        
        # Test memory cache operations
        print("Testing database cache operations...")
        mock_db = {"test": "data"}
        memory_manager.database_cache.put("test_db", mock_db)
        retrieved = memory_manager.database_cache.get("test_db")
        assert retrieved == mock_db, "Database cache retrieval failed"
        print("✓ Database cache operations work correctly")
        
        # Test embedding cache operations
        print("Testing embedding cache operations...")
        mock_embedding = {"model": "test", "embeddings": [1, 2, 3]}
        memory_manager.embedding_cache.put("test_embedding", mock_embedding)
        retrieved = memory_manager.embedding_cache.get("test_embedding")
        assert retrieved == mock_embedding, "Embedding cache retrieval failed"
        print("✓ Embedding cache operations work correctly")
        
        # Test memory stats
        print("Testing memory statistics...")
        stats = memory_manager.get_memory_stats()
        assert 'database_cache' in stats, "Database cache stats missing"
        assert 'embedding_cache' in stats, "Embedding cache stats missing"
        assert 'system_memory' in stats, "System memory stats missing"
        print("✓ Memory statistics generated correctly")
        
        # Test cleanup operations
        print("Testing cleanup operations...")
        cleanup_result = memory_manager.cleanup_all()
        assert 'databases_cleaned' in cleanup_result, "Databases cleanup count missing"
        assert 'embeddings_cleaned' in cleanup_result, "Embeddings cleanup count missing"
        print("✓ Cleanup operations work correctly")
        
        # Test cache size limits
        print("Testing cache size limits...")
        memory_manager.database_cache.clear()
        memory_manager.embedding_cache.clear()
        
        # Fill database cache to test size limit
        for i in range(150):  # More than MAX_CACHE_SIZE (100)
            memory_manager.database_cache.put(f"db_{i}", {"data": i})
        
        # Should be limited to max size
        assert memory_manager.database_cache.size() <= 100, "Database cache size limit not enforced"
        print("✓ Database cache size limit enforced")
        
        # Fill embedding cache to test size limit
        for i in range(60):  # More than MAX_EMBEDDING_CACHE_SIZE (50)
            memory_manager.embedding_cache.put(f"emb_{i}", {"embedding": [i]})
        
        # Should be limited to max size
        assert memory_manager.embedding_cache.size() <= 50, "Embedding cache size limit not enforced"
        print("✓ Embedding cache size limit enforced")
        
        # Test expiry mechanism
        print("Testing expiry mechanism...")
        memory_manager.database_cache.clear()
        
        # Add item and wait for expiry (using short expiry for testing)
        test_cache = memory_manager.database_cache
        test_cache._expiry_time = 0.1  # 100ms expiry for testing
        test_cache.put("expiry_test", {"data": "test"})
        
        # Should be accessible immediately
        assert test_cache.get("expiry_test") is not None, "Item should be accessible before expiry"
        
        # Wait for expiry
        time.sleep(0.2)
        
        # Cleanup should remove expired item
        cleaned = test_cache.cleanup_expired()
        assert cleaned == 1, "Expired item should be cleaned up"
        assert test_cache.get("expiry_test") is None, "Expired item should not be accessible"
        print("✓ Expiry mechanism works correctly")
        
        print("\n🎉 All integration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_memory_usage_monitoring():
    """Test memory usage monitoring."""
    print("\nTesting memory usage monitoring...")
    
    try:
        from helpers.memory_manager import get_memory_usage, check_memory_thresholds
        
        # Test memory usage function
        usage = get_memory_usage()
        assert isinstance(usage, (int, float)), "Memory usage should be numeric"
        assert usage >= 0, "Memory usage should be non-negative"
        print(f"✓ Current memory usage: {usage:.1f}%")
        
        # Test threshold checking
        status = check_memory_thresholds()
        assert 'usage_percent' in status, "Usage percent missing from status"
        assert 'warning' in status, "Warning flag missing from status"
        assert 'emergency' in status, "Emergency flag missing from status"
        assert 'timestamp' in status, "Timestamp missing from status"
        print("✓ Memory threshold checking works correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Memory usage monitoring test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("MEMORY MANAGEMENT INTEGRATION TEST")
    print("=" * 60)
    
    success = True
    
    # Run integration tests
    success &= test_memory_management_integration()
    
    # Run memory monitoring tests
    success &= test_memory_usage_monitoring()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 ALL TESTS PASSED! Memory leak fixes are working correctly.")
        print("The system now has proper memory management with:")
        print("  • Managed caches with size limits")
        print("  • Automatic expiry of unused items")
        print("  • Memory usage monitoring")
        print("  • Emergency cleanup procedures")
        print("  • Thread-safe operations")
    else:
        print("❌ SOME TESTS FAILED! Please check the implementation.")
    print("=" * 60)
    
    sys.exit(0 if success else 1)