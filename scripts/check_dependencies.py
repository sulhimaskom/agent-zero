#!/usr/bin/env python3
"""
Dependency verification script for Agent Zero.
Checks that all required dependencies are properly installed and importable.
"""

import sys
import importlib
import subprocess
from typing import List, Tuple

# Core dependencies that must be available
CORE_DEPENDENCIES = [
    "langchain_core",
    "litellm", 
    "faiss",
    "sentence_transformers",
    "flask",
    "docker",
    "playwright",
    "openai",
    "markdown",
    "pytz"
]

# Optional dependencies with graceful fallback
OPTIONAL_DEPENDENCIES = [
    "kokoro",
    "paramiko",
    "newspaper3k",
    "pypdf",
    "pytesseract"
]

def check_import(module_name: str) -> Tuple[bool, str]:
    """Check if a module can be imported."""
    try:
        importlib.import_module(module_name)
        return True, "OK"
    except ImportError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"

def check_version(module_name: str) -> str:
    """Get version of installed module."""
    try:
        module = importlib.import_module(module_name)
        return getattr(module, "__version__", "unknown")
    except:
        return "unknown"

def main():
    """Run dependency verification."""
    print("🔍 Agent Zero Dependency Verification")
    print("=" * 50)
    
    # Check core dependencies
    print("\n📦 Core Dependencies:")
    core_failed = []
    for dep in CORE_DEPENDENCIES:
        success, message = check_import(dep)
        version = check_version(dep) if success else "N/A"
        status = "✓" if success else "✗"
        print(f"  {status} {dep:<25} v{version:<10} {message}")
        if not success:
            core_failed.append(dep)
    
    # Check optional dependencies
    print("\n📦 Optional Dependencies:")
    optional_failed = []
    for dep in OPTIONAL_DEPENDENCIES:
        success, message = check_import(dep)
        version = check_version(dep) if success else "N/A"
        status = "✓" if success else "⚠"
        print(f"  {status} {dep:<25} v{version:<10} {message}")
        if not success:
            optional_failed.append(dep)
    
    # Summary
    print("\n📊 Summary:")
    total_core = len(CORE_DEPENDENCIES)
    total_optional = len(OPTIONAL_DEPENDENCIES)
    passed_core = total_core - len(core_failed)
    passed_optional = total_optional - len(optional_failed)
    
    print(f"  Core: {passed_core}/{total_core} passed")
    print(f"  Optional: {passed_optional}/{total_optional} passed")
    
    # Recommendations
    if core_failed:
        print(f"\n❌ Critical Issues:")
        print(f"  Missing core dependencies: {', '.join(core_failed)}")
        print(f"  Run: pip install -r requirements.txt")
        return 1
    
    if optional_failed:
        print(f"\n⚠️  Optional Issues:")
        print(f"  Missing optional dependencies: {', '.join(optional_failed)}")
        print(f"  Some features may not work properly")
    
    print(f"\n✅ Dependency verification completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())