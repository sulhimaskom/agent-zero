import gc
import os
import time
import weakref
import threading
from typing import Any, Dict, Optional, Callable
from datetime import datetime, timedelta
import psutil
from python.helpers.print_style import PrintStyle


class MemoryMonitor:
    """Memory monitoring and cleanup utilities for preventing memory leaks."""
    
    def __init__(self, memory_threshold_percent: float = 80.0, check_interval: int = 60):
        """
        Initialize memory monitor.
        
        Args:
            memory_threshold_percent: Memory usage percentage that triggers cleanup
            check_interval: Seconds between memory checks
        """
        self.memory_threshold_percent = memory_threshold_percent
        self.check_interval = check_interval
        self._cleanup_callbacks: list[Callable] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
    def add_cleanup_callback(self, callback: Callable):
        """Add a cleanup function to be called when memory threshold is exceeded."""
        with self._lock:
            self._cleanup_callbacks.append(callback)
    
    def get_memory_usage(self) -> float:
        """Get current memory usage percentage for this process."""
        try:
            process = psutil.Process(os.getpid())
            return process.memory_percent()
        except Exception as e:
            PrintStyle.error(f"Error getting memory usage: {e}")
            return 0.0
    
    def get_system_memory_info(self) -> Dict[str, Any]:
        """Get detailed system memory information."""
        try:
            memory = psutil.virtual_memory()
            process = psutil.Process(os.getpid())
            process_memory = process.memory_info()
            
            return {
                "system_total": memory.total,
                "system_available": memory.available,
                "system_percent": memory.percent,
                "process_rss": process_memory.rss,
                "process_vms": process_memory.vms,
                "process_percent": process.memory_percent(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            PrintStyle.error(f"Error getting system memory info: {e}")
            return {}
    
    def trigger_cleanup(self, force_gc: bool = True) -> bool:
        """
        Trigger all registered cleanup callbacks.
        
        Args:
            force_gc: Whether to force garbage collection
            
        Returns:
            True if cleanup was successful, False otherwise
        """
        try:
            with self._lock:
                for callback in self._cleanup_callbacks:
                    try:
                        callback()
                    except Exception as e:
                        PrintStyle.error(f"Error in cleanup callback: {e}")
            
            if force_gc:
                gc.collect()
                
            PrintStyle.success("Memory cleanup completed")
            return True
            
        except Exception as e:
            PrintStyle.error(f"Error during memory cleanup: {e}")
            return False
    
    def _monitor_loop(self):
        """Main monitoring loop that runs in a separate thread."""
        while self._monitoring:
            try:
                memory_percent = self.get_memory_usage()
                
                if memory_percent > self.memory_threshold_percent:
                    PrintStyle.warning(f"Memory usage ({memory_percent:.1f}%) exceeds threshold ({self.memory_threshold_percent}%)")
                    self.trigger_cleanup()
                    
                    # Check again after cleanup
                    new_memory_percent = self.get_memory_usage()
                    if new_memory_percent > self.memory_threshold_percent:
                        PrintStyle.error(f"Memory still high after cleanup: {new_memory_percent:.1f}%")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                PrintStyle.error(f"Error in memory monitoring loop: {e}")
                time.sleep(self.check_interval)
    
    def start_monitoring(self):
        """Start memory monitoring in a background thread."""
        if self._monitoring:
            return
            
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        PrintStyle.success("Memory monitoring started")
    
    def stop_monitoring(self):
        """Stop memory monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        PrintStyle.success("Memory monitoring stopped")


class WeakValueDictionary:
    """
    Thread-safe weak reference dictionary with automatic cleanup of dead references.
    """
    
    def __init__(self):
        self._data: Dict[str, weakref.ref] = {}
        self._lock = threading.RLock()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value by key, returning default if not found or object is dead."""
        with self._lock:
            ref = self._data.get(key)
            if ref is None:
                return default
            
            value = ref()
            if value is None:
                # Remove dead reference
                del self._data[key]
                return default
            
            return value
    
    def set(self, key: str, value: Any) -> None:
        """Set value with weak reference."""
        with self._lock:
            self._data[key] = weakref.ref(value)
    
    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)
    
    def __getitem__(self, key: str) -> Any:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value
    
    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None
    
    def __delitem__(self, key: str) -> None:
        with self._lock:
            if key in self._data:
                del self._data[key]
    
    def keys(self) -> list[str]:
        """Get all keys with live references."""
        with self._lock:
            live_keys = []
            dead_keys = []
            
            for key, ref in self._data.items():
                value = ref()
                if value is not None:
                    live_keys.append(key)
                else:
                    dead_keys.append(key)
            
            # Clean up dead references
            for key in dead_keys:
                del self._data[key]
            
            return live_keys
    
    def values(self) -> list[Any]:
        """Get all live values."""
        with self._lock:
            return [self.get(key) for key in self.keys()]
    
    def items(self) -> list[tuple[str, Any]]:
        """Get all live key-value pairs."""
        with self._lock:
            return [(key, self.get(key)) for key in self.keys()]
    
    def size(self) -> int:
        """Get number of live entries."""
        return len(self.keys())
    
    def cleanup_dead_references(self) -> int:
        """Clean up dead references and return count of cleaned items."""
        with self._lock:
            initial_size = len(self._data)
            self.keys()  # This triggers cleanup of dead references
            return initial_size - len(self._data)


# Global memory monitor instance
_global_monitor: Optional[MemoryMonitor] = None


def get_memory_monitor() -> MemoryMonitor:
    """Get or create the global memory monitor instance."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = MemoryMonitor()
    return _global_monitor


def start_memory_monitoring(threshold_percent: float = 80.0, check_interval: int = 60):
    """Start global memory monitoring."""
    monitor = get_memory_monitor()
    monitor.memory_threshold_percent = threshold_percent
    monitor.check_interval = check_interval
    monitor.start_monitoring()


def stop_memory_monitoring():
    """Stop global memory monitoring."""
    monitor = get_memory_monitor()
    monitor.stop_monitoring()


def trigger_emergency_cleanup():
    """Trigger emergency memory cleanup."""
    monitor = get_memory_monitor()
    return monitor.trigger_cleanup(force_gc=True)