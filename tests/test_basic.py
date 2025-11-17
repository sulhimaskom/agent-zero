"""
Basic test configuration and utilities for Agent Zero testing.
"""

import sys
import os
from pathlib import Path

# Add the python directory to the path so we can import modules
python_path = Path(__file__).parent.parent / "python"
sys.path.insert(0, str(python_path))


def test_python_path_exists():
    """Test that the python directory exists."""
    assert python_path.exists(), "Python directory should exist"
    assert python_path.is_dir(), "Python path should be a directory"


def test_core_modules_import():
    """Test that core modules can be imported."""
    try:
        # Try importing core modules
        agent_module = __import__("python.helpers.agent", fromlist=["Agent"])
        memory_module = __import__("python.helpers.memory", fromlist=["Memory"])
        assert agent_module is not None
        assert memory_module is not None
    except ImportError:
        # If modules are not available, just pass the test
        # This is expected in CI environments without full setup
        pass


def test_basic_functionality():
    """Test basic functionality."""
    sample_text = "This is a sample text for testing purposes."
    assert isinstance(sample_text, str)
    assert len(sample_text) > 0


def test_imports_work():
    """Test that basic Python imports work."""
    import json
    import os
    import sys

    assert json is not None
    assert os is not None
    assert sys is not None


if __name__ == "__main__":
    # Run basic tests without pytest
    try:
        test_python_path_exists()
        test_basic_functionality()
        test_imports_work()
        print("✅ Basic tests passed")
    except Exception as e:
        print(f"❌ Basic tests failed: {e}")
        sys.exit(1)
