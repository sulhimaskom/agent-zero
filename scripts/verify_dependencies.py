#!/usr/bin/env python3
"""
Dependency Security Verification Script

This script helps maintain security by:
1. Checking for duplicate dependencies
2. Verifying version bounds are properly set
3. Running security vulnerability scans
4. Validating requirements.txt format
"""

import re
import subprocess
import sys
from pathlib import Path


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
    """Run safety security vulnerability scan"""
    print("\n🔍 Running security vulnerability scan...")
    
    try:
        result = subprocess.run(
            ['safety', 'check', '--json'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("✅ No security vulnerabilities found")
            return True
        else:
            print("⚠️  Security vulnerabilities detected:")
            # Parse JSON output for cleaner display
            try:
                import json
                vulns = json.loads(result.stdout)
                for vuln in vulns:
                    print(f"  - {vuln.get('package', 'Unknown')}: {vuln.get('advisory', 'No details')}")
            except:
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


def main():
    """Main verification function"""
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        sys.exit(1)
    
    print("🚀 Starting dependency security verification...\n")
    
    all_passed = True
    
    # Run all checks
    all_passed &= check_duplicate_packages(requirements_file)
    all_passed &= check_version_bounds(requirements_file)
    all_passed &= validate_format(requirements_file)
    all_passed &= run_security_scan()
    
    print(f"\n{'='*50}")
    if all_passed:
        print("✅ All security checks passed!")
        sys.exit(0)
    else:
        print("❌ Some security checks failed. Please review the issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()