#!/usr/bin/env python3
"""
Dependency Verification Script for Agent Zero

This script helps maintain security and functionality by:
1. Checking for duplicate dependencies
2. Verifying version bounds are properly set
3. Running security vulnerability scans
4. Validating requirements.txt format
5. Testing critical imports to ensure dependencies work
"""

import re
import subprocess
import sys
import importlib
from pathlib import Path
from typing import List, Tuple


def check_duplicate_packages(requirements_file):
    """Check for duplicate package entries in requirements.txt"""
    print("🔍 Checking for duplicate packages...")
    
    packages = {}
    duplicates = []
    
    with open(requirements_file, 'r') as f:
        lines = f.readlines()
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Extract package name (before version specifiers)
        pkg_name = re.split(r'[>=<==]', line)[0].strip()
        
        if pkg_name in packages:
            duplicates.append(f"Line {line_num}: {pkg_name} (previously on line {packages[pkg_name]})")
        else:
            packages[pkg_name] = line_num
    
    if duplicates:
        print("❌ Found duplicate packages:")
        for dup in duplicates:
            print(f"  {dup}")
        return False
    else:
        print("✅ No duplicate packages found")
        return True


def check_version_bounds(requirements_file):
    """Check that all dependencies have both lower and upper version bounds"""
    print("\n🔍 Checking version bounds...")
    
    issues = []
    
    with open(requirements_file, 'r') as f:
        lines = f.readlines()
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Skip platform-specific conditional dependencies
        if ';' in line and ('sys_platform' in line or 'platform_machine' in line):
            base_part = line.split(';')[0].strip()
        else:
            base_part = line
        
        # Check version specification
        if '>=' in base_part and '<' in base_part:
            continue  # Good - has both bounds
        elif '>=' in base_part:
            issues.append(f"Line {line_num}: Missing upper version bound: {base_part}")
        elif '<' in base_part:
            issues.append(f"Line {line_num}: Missing lower version bound: {base_part}")
        elif re.match(r'^[a-zA-Z0-9\-_]+==', base_part):
            issues.append(f"Line {line_num}: Using exact pin (should use range): {base_part}")
    
    if issues:
        print("❌ Version bound issues found:")
        for issue in issues:
            print(f"  {issue}")
        return False
    else:
        print("✅ All packages have proper version bounds")
        return True


def run_security_scan():
    """Run safety security vulnerability scan on requirements.txt"""
    print("\n🔍 Running security vulnerability scan...")
    
    import json
    
    try:
        # First try the newer 'scan' command
        result = subprocess.run(
            ['safety', 'scan', '--file', 'requirements.txt', '--json'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # If scan requires authentication, fall back to deprecated check command
        if "login or register" in result.stdout.lower() or result.returncode != 0:
            print("📝 Using legacy safety check command (authentication required for newer scan)...")
            result = subprocess.run(
                ['safety', 'check', '--file', 'requirements.txt', '--json'],
                capture_output=True,
                text=True,
                timeout=60
            )
        
        if result.returncode == 0:
            print("✅ No security vulnerabilities found in requirements.txt")
            return True
        else:
            print("⚠️  Security vulnerabilities detected in requirements.txt:")
            # Parse JSON output for cleaner display
            try:
                data = json.loads(result.stdout)
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    for vuln in vulns:
                        pkg_name = vuln.get('analyzed_dependency', {}).get('name', 'Unknown')
                        advisory = vuln.get('advisory', 'No details')
                        print(f"  - {pkg_name}: {advisory}")
                else:
                    print("  No vulnerabilities found in requirements.txt")
                    return True
            except json.JSONDecodeError:
                print(result.stdout)
            return False
    except subprocess.TimeoutExpired:
        print("⚠️  Security scan timed out")
        return False
    except FileNotFoundError:
        print("⚠️  Safety not installed. Run: pip install safety")
        return False


def validate_format(requirements_file):
    """Validate requirements.txt format"""
    print("\n🔍 Validating requirements.txt format...")
    
    issues = []
    
    with open(requirements_file, 'r') as f:
        lines = f.readlines()
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Check for basic format issues
        if not re.match(r'^[a-zA-Z0-9\-_\[\]]+', line):
            issues.append(f"Line {line_num}: Invalid package name format: {line}")
        
        # Check for trailing whitespace
        if line != lines[line_num - 1].rstrip():
            issues.append(f"Line {line_num}: Trailing whitespace")
    
    if issues:
        print("❌ Format issues found:")
        for issue in issues:
            print(f"  {issue}")
        return False
    else:
        print("✅ Requirements.txt format is valid")
        return True


# Critical dependencies that must be importable
CRITICAL_DEPENDENCIES = [
    "litellm",
    "langchain_core", 
    "langchain_community",
    "faiss",
    "sentence_transformers",
    "flask",
    "docker",
    "aiohttp",
    "aiofiles",
    "mcp",
    "fastmcp",
    "browser_use",
    "transformers",
    "torch",
    "numpy",
    "pandas"
]

# Optional dependencies that are nice to have but not critical
# Note: Some packages import under different names than their package names
OPTIONAL_DEPENDENCIES = [
    "openai",
    "anthropic", 
    "groq",
    "playwright",
    "spacy",
    "newspaper",  # newspaper3k package imports as 'newspaper'
    "paramiko",
    "git"  # GitPython package imports as 'git'
]

def check_import(package_name: str) -> Tuple[bool, str]:
    """Check if a package can be imported."""
    try:
        importlib.import_module(package_name)
        return True, f"✓ {package_name} imported successfully"
    except ImportError as e:
        return False, f"✗ {package_name} failed to import: {e}"
    except Exception as e:
        return False, f"✗ {package_name} error: {e}"

def test_critical_imports():
    """Test that critical dependencies can be imported."""
    print("\n🔍 Testing critical imports...")
    
    critical_failed = []
    for dep in CRITICAL_DEPENDENCIES:
        success, message = check_import(dep)
        print(message)
        if not success:
            critical_failed.append(dep)
    
    if critical_failed:
        print(f"\n❌ {len(critical_failed)} critical dependencies failed to import")
        return False
    else:
        print("\n✅ All critical dependencies imported successfully")
        return True

def test_optional_imports():
    """Test that optional dependencies can be imported."""
    print("\n🔍 Testing optional imports...")
    
    optional_failed = []
    for dep in OPTIONAL_DEPENDENCIES:
        success, message = check_import(dep)
        print(message)
        if not success:
            optional_failed.append(dep)
    
    if optional_failed:
        print(f"\n⚠️  {len(optional_failed)} optional dependencies failed to import")
        print("These are optional but may limit functionality.")
        return False
    else:
        print("\n✅ All optional dependencies imported successfully")
        return True

def check_version_conflicts():
    """Check for common version conflicts."""
    print("\n🔍 Checking for common version conflicts...")
    
    # Check aiofiles version (common conflict source)
    try:
        import aiofiles
        import pkg_resources
        version = pkg_resources.get_distribution("aiofiles").version
        print(f"✓ aiofiles version: {version}")
        
        # Parse version to check if it meets minimum requirements
        major, minor, patch = map(int, version.split('.'))
        if major > 24 or (major == 24 and minor >= 1):
            print("✓ aiofiles version meets requirements (>=24.1.0)")
        else:
            print(f"⚠ aiofiles version {version} may cause conflicts with unstructured-client")
    except ImportError:
        print("✗ aiofiles not installed")
    except Exception as e:
        print(f"⚠ Could not check aiofiles version: {e}")

def verify_dependency_installation():
    """Verify that pip can resolve dependencies without conflicts."""
    print("\n🔍 Verifying dependency resolution...")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "check"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ No dependency conflicts detected")
            return True
        else:
            print("⚠ Dependency conflicts found:")
            print(result.stdout)
            if result.stderr:
                print("Errors:", result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("✗ Dependency check timed out")
        return False
    except Exception as e:
        print(f"✗ Error checking dependencies: {e}")
        return False

def main():
    """Main verification function"""
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        sys.exit(1)
    
    print("🚀 Starting comprehensive dependency verification...\n")
    
    all_passed = True
    
    # Run security and format checks
    all_passed &= check_duplicate_packages(requirements_file)
    all_passed &= check_version_bounds(requirements_file)
    all_passed &= validate_format(requirements_file)
    all_passed &= run_security_scan()
    
    # Run functionality checks
    all_passed &= verify_dependency_installation()
    check_version_conflicts()
    
    # Test imports (critical for functionality)
    imports_ok = test_critical_imports()
    all_passed &= imports_ok
    
    # Test optional imports (don't fail the script but warn)
    test_optional_imports()
    
    print(f"\n{'='*50}")
    print("VERIFICATION SUMMARY")
    print("="*50)
    
    if all_passed and imports_ok:
        print("✅ All checks passed! Dependencies are secure and functional.")
        sys.exit(0)
    else:
        print("❌ Some checks failed. Please review the issues above.")
        if not imports_ok:
            print("\n💡 To fix import issues, try:")
            print("   pip install -r requirements.txt")
            print("   python scripts/verify_dependencies.py")
        sys.exit(1)


if __name__ == "__main__":
    main()