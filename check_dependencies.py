#!/usr/bin/env python3
"""
Dependency validation script for Agent Zero.
Run this script to check if all required dependencies are installed.
"""

import sys
import subprocess
import platform
from typing import List, Dict, Tuple

def check_python_version() -> Tuple[bool, str]:
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        return True, f"Python {version.major}.{version.minor}.{version.micro} ✓"
    else:
        return False, f"Python {version.major}.{version.minor}.{version.micro} - requires Python 3.8+"

def check_package(package_name: str, import_name: str = None) -> Tuple[bool, str]:
    """Check if a package is installed and importable."""
    if import_name is None:
        import_name = package_name.replace('-', '_')
    
    try:
        __import__(import_name)
        return True, f"{package_name} ✓"
    except ImportError:
        return False, f"{package_name} ✗"

def check_platform_specific_packages() -> Dict[str, Tuple[bool, str]]:
    """Check platform-specific packages."""
    results = {}
    
    # FAISS platform-specific checks
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "darwin" and machine in ["arm64", "aarch64"]:
        # macOS ARM64 - FAISS may have issues
        try:
            import faiss
            results["faiss-cpu"] = (True, "faiss-cpu ✓ (macOS ARM64)")
        except ImportError:
            results["faiss-cpu"] = (False, "faiss-cpu ✗ (optional for macOS ARM64)")
    else:
        # Other platforms - FAISS should work
        try:
            import faiss
            results["faiss-cpu"] = (True, "faiss-cpu ✓")
        except ImportError:
            results["faiss-cpu"] = (False, "faiss-cpu ✗")
    
    return results

def validate_dependencies() -> bool:
    """Validate all dependencies and return True if all critical ones are available."""
    print("🔍 Agent Zero Dependency Validation")
    print("=" * 40)
    
    # Check Python version
    python_ok, python_msg = check_python_version()
    print(python_msg)
    if not python_ok:
        print("❌ Python version is not compatible")
        return False
    
    print("\n📦 Checking required packages:")
    
    # Critical dependencies
    required_packages = [
        ("flask", "flask"),
        ("litellm", "litellm"),
        ("docker", "docker"),
        ("python-dotenv", "dotenv"),
        ("requests", "requests"),
        ("pytz", "pytz"),
    ]
    
    all_required_ok = True
    for package, import_name in required_packages:
        ok, msg = check_package(package, import_name)
        print(f"  {msg}")
        if not ok:
            all_required_ok = False
    
    print("\n🤖 Checking AI/ML dependencies:")
    
    # AI/ML dependencies
    ml_packages = [
        ("langchain-core", "langchain_core"),
        ("langchain-community", "langchain_community"),
        ("sentence-transformers", "sentence_transformers"),
        ("tiktoken", "tiktoken"),
    ]
    
    for package, import_name in ml_packages:
        ok, msg = check_package(package, import_name)
        print(f"  {msg}")
    
    print("\n🔧 Checking platform-specific packages:")
    
    # Platform-specific packages
    platform_results = check_platform_specific_packages()
    for package, (ok, msg) in platform_results.items():
        print(f"  {msg}")
    
    print("\n📚 Checking document processing:")
    
    # Document processing
    doc_packages = [
        ("unstructured", "unstructured"),
        ("pypdf", "pypdf"),
        ("newspaper3k", "newspaper"),
    ]
    
    for package, import_name in doc_packages:
        ok, msg = check_package(package, import_name)
        print(f"  {msg}")
    
    print("\n" + "=" * 40)
    
    if all_required_ok:
        print("✅ All required dependencies are available!")
        print("🚀 Agent Zero should run without issues.")
        return True
    else:
        print("❌ Some required dependencies are missing!")
        print("\n🔧 To install missing dependencies, run:")
        print("   pip install -r requirements.txt")
        print("\n📖 For platform-specific installation, see:")
        print("   - requirements-linux.txt (Linux)")
        print("   - requirements-macos.txt (macOS)")
        print("   - requirements-windows.txt (Windows)")
        return False

def install_platform_requirements():
    """Install platform-specific requirements."""
    system = platform.system().lower()
    
    if system == "linux":
        req_file = "requirements-linux.txt"
    elif system == "darwin":  # macOS
        req_file = "requirements-macos.txt"
    elif system == "windows":
        req_file = "requirements-windows.txt"
    else:
        print(f"❌ Unsupported platform: {system}")
        return False
    
    print(f"📦 Installing requirements for {system} using {req_file}...")
    
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", req_file
        ], check=True)
        print(f"✅ Successfully installed {req_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {req_file}: {e}")
        return False
    except FileNotFoundError:
        print(f"❌ {req_file} not found")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        install_platform_requirements()
    else:
        success = validate_dependencies()
        sys.exit(0 if success else 1)