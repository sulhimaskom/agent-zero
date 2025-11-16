#!/usr/bin/env python3
"""
Repository Health Check Script

This script performs basic health checks on the Agent Zero repository
to ensure the main branch remains in a good state.
"""

import sys
import os
import subprocess
import ast
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"🔍 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            return True
        else:
            print(f"❌ {description} - FAILED")
            print(f"   Error: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"⏰ {description} - TIMEOUT")
        return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False


def check_syntax_files():
    """Check syntax of key Python files."""
    print("🔍 Checking Python file syntax...")
    
    key_files = [
        "agent.py",
        "models.py", 
        "run_ui.py",
        "agent.py"
    ]
    
    all_good = True
    for file_path in key_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    ast.parse(f.read())
                print(f"✅ Syntax OK: {file_path}")
            except SyntaxError as e:
                print(f"❌ Syntax Error in {file_path}: {e}")
                all_good = False
            except Exception as e:
                print(f"⚠️  Could not check {file_path}: {e}")
        else:
            print(f"⚠️  File not found: {file_path}")
    
    return all_good


def check_git_status():
    """Check git repository status."""
    print("🔍 Checking git repository status...")
    
    # Check if we're in a git repo
    if not os.path.exists(".git"):
        print("❌ Not in a git repository")
        return False
    
    # Check for uncommitted changes
    result = subprocess.run("git status --porcelain", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        if result.stdout.strip():
            print("⚠️  There are uncommitted changes")
            return False
        else:
            print("✅ Git working tree is clean")
            return True
    else:
        print("❌ Could not check git status")
        return False


def check_basic_tests():
    """Run basic tests to ensure functionality."""
    print("🔍 Running basic functionality tests...")
    
    # Try to run basic tests
    test_files = [
        "tests/test_basic.py",
        "test_refactoring_verification.py"
    ]
    
    all_passed = True
    for test_file in test_files:
        if os.path.exists(test_file):
            success = run_command(f"python {test_file}", f"Running {test_file}")
            if not success:
                all_passed = False
        else:
            print(f"⚠️  Test file not found: {test_file}")
    
    return all_passed


def check_documentation():
    """Check if key documentation files exist."""
    print("🔍 Checking documentation files...")
    
    doc_files = [
        "README.md",
        "docs/README.md",
        "docs/installation.md",
        "docs/usage.md",
        "CONTRIBUTING.md"
    ]
    
    all_exist = True
    for doc_file in doc_files:
        if os.path.exists(doc_file):
            print(f"✅ Documentation exists: {doc_file}")
        else:
            print(f"⚠️  Documentation missing: {doc_file}")
            all_exist = False
    
    return all_exist


def check_dependencies():
    """Check if requirements.txt exists and is well-formed."""
    print("🔍 Checking dependencies...")
    
    if not os.path.exists("requirements.txt"):
        print("❌ requirements.txt not found")
        return False
    
    try:
        with open("requirements.txt", 'r') as f:
            lines = f.readlines()
        
        # Basic validation - check for common dependency format
        valid_lines = 0
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line or '>' in line or '<' in line:
                    valid_lines += 1
        
        if valid_lines > 0:
            print(f"✅ requirements.txt looks good ({valid_lines} dependencies)")
            return True
        else:
            print("⚠️  requirements.txt seems empty or malformed")
            return False
            
    except Exception as e:
        print(f"❌ Error reading requirements.txt: {e}")
        return False


def main():
    """Run all health checks."""
    print("🏥 Agent Zero Repository Health Check")
    print("=" * 50)
    
    checks = [
        ("Git Status", check_git_status),
        ("Python Syntax", check_syntax_files),
        ("Basic Tests", check_basic_tests),
        ("Documentation", check_documentation),
        ("Dependencies", check_dependencies)
    ]
    
    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"❌ {check_name} check failed with exception: {e}")
            results.append((check_name, False))
        print()  # Add spacing between checks
    
    # Summary
    print("=" * 50)
    print("🏥 Health Check Summary:")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for check_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} {check_name}")
    
    print(f"\n📊 Overall: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 Repository is in excellent health!")
        return 0
    elif passed >= total * 0.8:
        print("⚠️  Repository is mostly healthy, but some issues need attention.")
        return 0
    else:
        print("🚨 Repository has significant health issues that should be addressed.")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)