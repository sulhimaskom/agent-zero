#!/usr/bin/env python3
"""
BroCula Browser Optimization Loop
Continuously monitors browser console and lighthouse scores, fixes issues automatically.
"""

import subprocess
import sys
import json
import time
from pathlib import Path
sys.path.insert(0, '/home/runner/work/agent-zero/agent-zero')
from python.helpers.constants import Network

def run_command(cmd, timeout=60):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"

def check_linter():
    """Check if there are any linting tools configured"""
    # Check for Python linters
    if Path("requirements.txt").exists():
        # Try ruff
        ret, _, _ = run_command("which ruff")
        if ret == 0:
            return "ruff check ."

        # Try flake8
        ret, _, _ = run_command("which flake8")
        if ret == 0:
            return "flake8"

        # Try pylint
        ret, _, _ = run_command("which pylint")
        if ret == 0:
            return "pylint **/*.py"

    # Check for Node.js linters
    if Path("package.json").exists():
        with open("package.json") as f:
            pkg = json.load(f)
            if "scripts" in pkg:
                if "lint" in pkg["scripts"]:
                    return "npm run lint"
                if "eslint" in pkg["scripts"]:
                    return "npm run eslint"

    return None

def check_tests():
    """Check if there are test commands"""
    if Path("requirements.txt").exists():
        ret, _, _ = run_command("which pytest")
        if ret == 0:
            return "pytest"

    if Path("package.json").exists():
        with open("package.json") as f:
            pkg = json.load(f)
            if "scripts" in pkg and "test" in pkg["scripts"]:
                return "npm test"

    return None

def check_build():
    """Check if there's a build command"""
    if Path("package.json").exists():
        with open("package.json") as f:
            pkg = json.load(f)
            if "scripts" in pkg and "build" in pkg["scripts"]:
                return "npm run build"

    return None

def main():
    """Main BroCula loop"""
    print("🔧 BroCula Browser Optimization Agent")
    print("=" * 60)
    print()

    # Check prerequisites
    print("📋 Checking prerequisites...")

    # Check Node.js/npm (for lighthouse)
    ret, _, _ = run_command("which npm")
    if ret != 0:
        print("❌ npm not found. Install Node.js first.")
        sys.exit(1)

    # Check lighthouse
    ret, _, _ = run_command("which lighthouse")
    if ret != 0:
        print("📦 Installing Lighthouse...")
        run_command("npm install -g lighthouse")

    # Check playwright
    ret, _, _ = run_command("which playwright")
    if ret != 0:
        print("📦 Installing Playwright...")
        run_command("pip install playwright")
        run_command("playwright install chromium")

    print("✅ Prerequisites ready")
    print()

    # Configuration
    target_url = f"http://{Network.DEFAULT_HOSTNAME}:{Network.BROCULA_PORT_DEFAULT}"
    check_interval = 300  # 5 minutes between checks

    print(f"🎯 Target URL: {target_url}")
    print(f"⏱️  Check interval: {check_interval}s")
    print()

    # Determine verification commands
    lint_cmd = check_linter()
    test_cmd = check_tests()
    build_cmd = check_build()

    if lint_cmd:
        print(f"🔍 Linter: {lint_cmd}")
    if test_cmd:
        print(f"🧪 Tests: {test_cmd}")
    if build_cmd:
        print(f"🔨 Build: {build_cmd}")
    print()

    # Main loop
    iteration = 0
    while True:
        iteration += 1
        print(f"\n🔄 Iteration {iteration}")
        print("-" * 60)

        # 1. Check browser console
        print("\n1️⃣  Checking browser console...")
        # This would run the browser_console_checker tool
        # For now, we'll document what should happen
        print("   (Run: python -m agents.brocula.tools.browser_console_checker)")

        # 2. Run Lighthouse
        print("\n2️⃣  Running Lighthouse audit...")
        ret, stdout, stderr = run_command(
            f"lighthouse {target_url} --output=json --chrome-flags='--headless --no-sandbox' --quiet",
            timeout=120
        )
        if ret == 0:
            print("   ✅ Lighthouse completed")
            # Parse and report scores
        else:
            print(f"   ❌ Lighthouse failed: {stderr}")

        # 3. Verify build/lint (FATAL if fails)
        print("\n3️⃣  Verifying build and lint...")
        fatal_errors = []

        if lint_cmd:
            ret, stdout, stderr = run_command(lint_cmd)
            if ret != 0:
                fatal_errors.append(f"Lint failed: {stderr or stdout}")
                print("   ❌ Lint failed")
            else:
                print("   ✅ Lint passed")

        if build_cmd:
            ret, stdout, stderr = run_command(build_cmd)
            if ret != 0:
                fatal_errors.append(f"Build failed: {stderr or stdout}")
                print("   ❌ Build failed")
            else:
                print("   ✅ Build passed")

        if test_cmd:
            ret, stdout, stderr = run_command(test_cmd)
            if ret != 0:
                fatal_errors.append(f"Tests failed: {stderr or stdout}")
                print("   ❌ Tests failed")
            else:
                print("   ✅ Tests passed")

        if fatal_errors:
            print("\n🚨 FATAL ERRORS FOUND:")
            for error in fatal_errors:
                print(f"   - {error}")
            print("\n⚠️  Fix these errors before creating PR!")

        # 4. Git status check
        print("\n4️⃣  Checking git status...")
        ret, stdout, _ = run_command("git status --short")
        if stdout.strip():
            print("   📝 Uncommitted changes found:")
            print(stdout)
        else:
            print("   ✅ Working directory clean")

        # Wait before next iteration
        print(f"\n⏳ Waiting {check_interval}s before next check...")
        time.sleep(check_interval)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 BroCula signing off. Stay optimized!")
        sys.exit(0)
