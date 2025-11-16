"""
Memory management initialization module.
Sets up automatic memory monitoring and cleanup for the agent system.
"""

import os
import threading
from python.helpers.memory_monitor import get_memory_monitor, start_memory_monitoring
from python.helpers.memory import Memory
from python.helpers.vector_db import VectorDB


def setup_memory_management():
    """Initialize memory monitoring and register cleanup callbacks."""
    
    # Get the global memory monitor
    monitor = get_memory_monitor()
    
    # Register cleanup callbacks
    monitor.add_cleanup_callback(Memory.cleanup_expired_databases)
    monitor.add_cleanup_callback(VectorDB.cleanup_expired_embeddings)
    
    # Start monitoring with conservative thresholds
    # Use lower threshold for production environments
    memory_threshold = float(os.getenv("MEMORY_THRESHOLD_PERCENT", "75.0"))
    check_interval = int(os.getenv("MEMORY_CHECK_INTERVAL", "120"))  # 2 minutes
    
    start_memory_monitoring(
        threshold_percent=memory_threshold,
        check_interval=check_interval
    )
    
    print(f"Memory management initialized - Threshold: {memory_threshold}%, Check interval: {check_interval}s")


def get_memory_report():
    """Get comprehensive memory usage report."""
    monitor = get_memory_monitor()
    
    report = {
        "system_memory": monitor.get_system_memory_info(),
        "memory_databases": Memory.get_memory_stats(),
        "embedding_caches": VectorDB.get_embedding_stats(),
    }
    
    return report


def emergency_memory_cleanup():
    """Trigger emergency memory cleanup."""
    from python.helpers.memory_monitor import trigger_emergency_cleanup
    return trigger_emergency_cleanup()


# Initialize memory management when module is imported
def _auto_initialize():
    """Auto-initialize memory management in a separate thread to avoid blocking."""
    def init():
        try:
            setup_memory_management()
        except Exception as e:
            print(f"Failed to initialize memory management: {e}")
    
    # Run initialization in background thread
    init_thread = threading.Thread(target=init, daemon=True)
    init_thread.start()


# Auto-initialize unless explicitly disabled
if os.getenv("DISABLE_MEMORY_MANAGEMENT", "").lower() != "true":
    _auto_initialize()