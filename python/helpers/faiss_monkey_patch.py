"""
FAISS Monkey Patch for Python 3.12 on ARM platforms.

This disgusting hack was brought to you by:
https://github.com/facebookresearch/faiss/issues/3936

Import this module before importing faiss to fix compatibility issues.
"""

import sys
import types
from types import SimpleNamespace

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    raise ImportError("NumPy is required for FAISS compatibility patch")

def apply_faiss_monkey_patch():
    """Apply the monkey patch for FAISS compatibility."""
    if not NUMPY_AVAILABLE:
        raise ImportError("Cannot apply FAISS patch without NumPy")
    
    # Create fake numpy.distutils and numpy.distutils.cpuinfo packages
    dist = types.ModuleType("numpy.distutils")
    cpuinfo = types.ModuleType("numpy.distutils.cpuinfo")

    # CPU attribute that looks like the real one
    cpuinfo.cpu = SimpleNamespace(  # type: ignore
        # FAISS only does .info[0].get('Features', '')
        info=[{}]
    )

    # Register in sys.modules
    dist.cpuinfo = cpuinfo  # type: ignore
    sys.modules["numpy.distutils"] = dist
    sys.modules["numpy.distutils.cpuinfo"] = cpuinfo

    # Crucial: expose it as an *attribute* of the already-imported numpy package
    np.distutils = dist  # type: ignore

# Apply the patch
apply_faiss_monkey_patch()

# Now import faiss with error handling
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError as e:
    FAISS_AVAILABLE = False
    raise ImportError(
        f"Failed to import FAISS after applying compatibility patch: {e}. "
        "Please ensure FAISS is installed: pip install faiss-cpu"
    )

# Export availability flag
__all__ = ['FAISS_AVAILABLE', 'faiss']