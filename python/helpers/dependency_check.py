"""
Dependency availability checker for Agent Zero.
Provides graceful degradation when optional dependencies are missing.
"""

import sys
import warnings
from typing import Dict

# Global flags for dependency availability
FAISS_AVAILABLE = False
LANGCHAIN_AVAILABLE = False
NUMPY_AVAILABLE = False


def check_faiss() -> bool:
    """Check if FAISS is available and working."""
    global FAISS_AVAILABLE
    if FAISS_AVAILABLE:
        return True

    try:
        # Try to import FAISS with monkey patch for ARM/Python 3.12 compatibility
        import platform
        if sys.platform == "darwin" and platform.machine() in ["arm64", "ARM64"]:
            # Apply monkey patch for macOS ARM64
            from python.helpers import faiss_monkey_patch

        import faiss
        FAISS_AVAILABLE = True
        return True
    except ImportError as e:
        warnings.warn(
            f"FAISS not available: {e}. Vector search functionality will be limited. "
            "Install with: pip install faiss-cpu"
            )
        return False
    except Exception as e:
        warnings.warn(f"FAISS import failed: {e}")
        return False


def check_langchain() -> bool:
    """Check if LangChain dependencies are available."""
    global LANGCHAIN_AVAILABLE
    if LANGCHAIN_AVAILABLE:
        return True

    try:
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.messages import SystemMessage, BaseMessage
        from langchain_community.vectorstores import FAISS
        LANGCHAIN_AVAILABLE = True
        return True
    except ImportError as e:
        warnings.warn(
            f"LangChain not available: {e}. Some features will be disabled. "
            "Install with: pip install langchain-core langchain-community"
            )
        return False
    except Exception as e:
        warnings.warn(f"LangChain import failed: {e}")
        return False


def check_numpy() -> bool:
    """Check if NumPy is available."""
    global NUMPY_AVAILABLE
    if NUMPY_AVAILABLE:
        return True

    try:
        import numpy
        NUMPY_AVAILABLE = True
        return True
    except ImportError as e:
        warnings.warn(
            f"NumPy not available: {e}. Some functionality may be limited. "
            "Install with: pip install numpy"
            )
        return False


def get_dependency_status() -> Dict[str, bool]:
    """Get status of all optional dependencies."""
    return {
        'faiss': check_faiss(),
        'langchain': check_langchain(),
        'numpy': check_numpy(),
        }


def validate_dependencies() -> bool:
    """
    Validate that all required dependencies are available.
    Returns True if all critical dependencies are available, False otherwise.
    """
    required_packages = {
        'flask': 'Flask',
        'litellm': 'LiteLLM',
        'docker': 'Docker',
        }

    missing = []

    for package, name in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing.append(name)

    if missing:
        print(f"❌ Missing required dependencies: {', '.join(missing)}")
        print("Please install with: pip install -r requirements.txt")
        return False

    # Check optional dependencies and show warnings
    optional_status = get_dependency_status()
    optional_missing = [name for name, available in optional_status.items() if not available]

    if optional_missing:
        print(f"⚠️  Optional dependencies missing: {', '.join(optional_missing)}")
        print("Some features may be limited. See installation guide for details.")

    print("✅ All required dependencies are available")
    return True


# Initialize dependency checks on import
check_numpy()
check_langchain()
check_faiss()
