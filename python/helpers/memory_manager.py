import time
import threading
import weakref
import gc
from typing import Any, Dict, Optional, Callable
from datetime import datetime, timedelta
import psutil
import logging

# Configuration constants
MEMORY_EXPIRY_TIME = 3600  # 1 hour in seconds
EMBEDDING_EXPIRY_TIME = 1800  # 30 minutes in seconds
MEMORY_WARNING_THRESHOLD = 80  # percentage
MEMORY_EMERGENCY_THRESHOLD = 95  # percentage
MAX_CACHE_SIZE = 100
MAX_EMBEDDING_CACHE_SIZE = 50
CLEANUP_INTERVAL = 300  # 5 minutes

logger = logging.getLogger(__name__)


class MemoryCache:
    """
    A thread-safe cache that tracks access times and provides automatic cleanup.
    """
    
    def __init__(self, max_size: int = MAX_CACHE_SIZE, expiry_time: int = MEMORY_EXPIRY_TIME):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._max_size = max_size
        self._expiry_time = expiry_time
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache and update access time."""
        with self._lock:
            if key in self._cache:
                item = self._cache[key]
                item['last_accessed'] = time.time()
                return item['value']
            return None
    
    def put(self, key: str, value: Any) -> None:
        """Put item in cache with access tracking."""
        with self._lock:
            current_time = time.time()
            
            # Remove oldest items if cache is full
            if len(self._cache) >= self._max_size and key not in self._cache:
                self._evict_oldest()
            
            self._cache[key] = {
                'value': value,
                'created': current_time,
                'last_accessed': current_time
            }
    
    def remove(self, key: str) -> bool:
        """Remove item from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def cleanup_expired(self) -> int:
        """Remove expired items from cache."""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key, item in self._cache.items():
                if current_time - item['last_accessed'] > self._expiry_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
            
            self._last_cleanup = current_time
            return len(expired_keys)
    
    def _evict_oldest(self) -> None:
        """Remove the least recently used item."""
        if not self._cache:
            return
        
        oldest_key = min(self._cache.keys(), 
                        key=lambda k: self._cache[k]['last_accessed'])
        del self._cache[oldest_key]
    
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)
    
    def clear(self) -> None:
        """Clear all items from cache."""
        with self._lock:
            self._cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            current_time = time.time()
            return {
                'size': len(self._cache),
                'max_size': self._max_size,
                'oldest_item': min(
                    [(current_time - item['last_accessed']) for item in self._cache.values()],
                    default=0
                ),
                'last_cleanup': self._last_cleanup
            }


def get_memory_usage() -> float:
    """Get current memory usage as percentage."""
    try:
        process = psutil.Process()
        return process.memory_percent()
    except Exception as e:
        logger.warning(f"Failed to get memory usage: {e}")
        return 0.0


def check_memory_thresholds() -> Dict[str, Any]:
    """Check memory usage against thresholds."""
    memory_percent = get_memory_usage()
    
    status = {
        'usage_percent': memory_percent,
        'warning': memory_percent > MEMORY_WARNING_THRESHOLD,
        'emergency': memory_percent > MEMORY_EMERGENCY_THRESHOLD,
        'timestamp': datetime.now().isoformat()
    }
    
    if status['emergency']:
        logger.critical(f"Emergency memory usage: {memory_percent:.1f}%")
        trigger_emergency_cleanup()
    elif status['warning']:
        logger.warning(f"High memory usage: {memory_percent:.1f}%")
        trigger_warning_cleanup()
    
    return status


def trigger_emergency_cleanup() -> None:
    """Trigger emergency cleanup procedures."""
    logger.info("Triggering emergency cleanup")
    
    # Force garbage collection
    gc.collect()
    
    # Clear any caches that might be holding references
    if hasattr(memory_manager, 'database_cache'):
        memory_manager.database_cache.cleanup_expired()
    
    if hasattr(memory_manager, 'embedding_cache'):
        memory_manager.embedding_cache.cleanup_expired()
    
    # Additional garbage collection
    gc.collect()


def trigger_warning_cleanup() -> None:
    """Trigger warning-level cleanup."""
    logger.info("Triggering warning cleanup")
    
    # Clean up expired items
    if hasattr(memory_manager, 'database_cache'):
        memory_manager.database_cache.cleanup_expired()
    
    if hasattr(memory_manager, 'embedding_cache'):
        memory_manager.embedding_cache.cleanup_expired()
    
    # Light garbage collection
    gc.collect()


class MemoryManager:
    """
    Central memory management coordinator.
    """
    
    def __init__(self):
        self.database_cache = MemoryCache(max_size=MAX_CACHE_SIZE, expiry_time=MEMORY_EXPIRY_TIME)
        self.embedding_cache = MemoryCache(max_size=MAX_EMBEDDING_CACHE_SIZE, expiry_time=EMBEDDING_EXPIRY_TIME)
        self._cleanup_timer = None
        self._start_cleanup_timer()
    
    def _start_cleanup_timer(self) -> None:
        """Start periodic cleanup timer."""
        if self._cleanup_timer:
            self._cleanup_timer.cancel()
        
        self._cleanup_timer = threading.Timer(CLEANUP_INTERVAL, self._periodic_cleanup)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()
    
    def _periodic_cleanup(self) -> None:
        """Perform periodic cleanup and restart timer."""
        try:
            # Check memory usage
            check_memory_thresholds()
            
            # Clean up expired items
            db_cleaned = self.database_cache.cleanup_expired()
            emb_cleaned = self.embedding_cache.cleanup_expired()
            
            if db_cleaned > 0 or emb_cleaned > 0:
                logger.info(f"Periodic cleanup: {db_cleaned} databases, {emb_cleaned} embeddings")
            
        except Exception as e:
            logger.error(f"Error in periodic cleanup: {e}")
        finally:
            # Restart timer
            self._start_cleanup_timer()
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics."""
        return {
            'database_cache': self.database_cache.get_stats(),
            'embedding_cache': self.embedding_cache.get_stats(),
            'system_memory': {
                'usage_percent': get_memory_usage(),
                'warning_threshold': MEMORY_WARNING_THRESHOLD,
                'emergency_threshold': MEMORY_EMERGENCY_THRESHOLD
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def cleanup_all(self) -> Dict[str, int]:
        """Clean up all caches."""
        db_cleaned = self.database_cache.cleanup_expired()
        emb_cleaned = self.embedding_cache.cleanup_expired()
        
        return {
            'databases_cleaned': db_cleaned,
            'embeddings_cleaned': emb_cleaned
        }
    
    def emergency_cleanup(self) -> None:
        """Perform emergency cleanup."""
        trigger_emergency_cleanup()


# Global memory manager instance
memory_manager = MemoryManager()


def memory_health_check(func: Callable) -> Callable:
    """
    Decorator to perform memory health check before function execution.
    """
    def wrapper(*args, **kwargs):
        # Check memory health
        status = check_memory_thresholds()
        
        # If emergency threshold exceeded, perform cleanup
        if status['emergency']:
            memory_manager.emergency_cleanup()
        
        return func(*args, **kwargs)
    
    return wrapper