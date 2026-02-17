#!/usr/bin/env python3
"""
BroCula - Browser Console & Lighthouse Optimization Specialist
Local execution script for manual runs.
"""

import contextlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from python.helpers.constants import Timeouts

BROCULA_PROMPT = """
ultrawork

You are BroCula - Browser Console & Lighthouse Optimization Specialist.

Execute the following strict workflow:

1. BROWSER CONSOLE MONITORING:
   - Use browser_agent tool to open the web application
   - Navigate to the main application URL (check run_ui.py or common ports)
   - Capture ALL console logs (errors, warnings, info)
   - If any errors found → FIX IMMEDIATELY
   - If warnings affect functionality → FIX
   - Document all findings with exact error messages

2. LIGHTHOUSE OPTIMIZATION:
   - Run Lighthouse audit using available tools
   - Check all metrics: Performance, Accessibility, Best Practices, SEO
   - Target scores: Performance 90+, others 100
   - Identify top 3 optimization opportunities
   - Implement fixes to improve scores
   - Re-run audit to verify improvements

3. BUILD & LINT VALIDATION (FATAL ERRORS CHECK):
   - Run production build (npm run build or equivalent)
   - ANY errors = FATAL FAILURE - must fix immediately
   - Run lint (npm run lint or equivalent)
   - ANY errors = FATAL FAILURE - must fix immediately
   - Document all errors/warnings found

4. BRANCH MANAGEMENT & PR CREATION:
   - Check current branch status
   - Sync with main: git fetch origin && git rebase origin/main
   - If any fixes were made:
     * Stage all changes: git add -A
     * Create descriptive commit
     * Create branch: brocula/fix-browser-issues-<timestamp>
     * Push to origin
     * Create PR with detailed report

5. DETAILED REPORT:
   Provide a comprehensive report with:

   ## Browser Console Report
   - **Errors Found**: [count] with details
   - **Warnings Found**: [count] with details
   - **Status**: ✅ Clean / 🔴 Fixed / ⚠️ Partial

   ## Lighthouse Report
   - **Performance**: [score]/100 (before → after)
   - **Accessibility**: [score]/100
   - **Best Practices**: [score]/100
   - **SEO**: [score]/100
   - **Optimizations Applied**: [list]

   ## Build & Lint Status
   - **Build**: ✅ Pass / 🔴 Fail → ✅ Fixed
   - **Lint**: ✅ Pass / 🔴 Fail → ✅ Fixed
   - **Errors Fixed**: [count]

   ## PR Status
   - **Branch**: [branch-name]
   - **Status**: ✅ Created / 🔴 Blocked / ⏭️ Not Needed
   - **PR URL**: [url if created]

STRICT RULES:
- Console errors are FATAL - never ignore
- Fix errors immediately, don't defer
- Always verify fixes by re-checking
- Branch must be synced with main before PR
- Build/lint errors block everything
- Document everything clearly

Remember: You are BroCula. You love working in the browser console.
You fix errors immediately. You optimize relentlessly.
You never leave a mess behind.
"""


def check_dependencies():
    """Check if required tools are available."""
    # Check Node.js
    try:
        subprocess.run(["node", "--version"], capture_output=True, text=True)
    except FileNotFoundError:
        return False

    # Check npm
    try:
        subprocess.run(["npm", "--version"], capture_output=True, text=True)
    except FileNotFoundError:
        return False

    # Check Python
    try:
        subprocess.run(["python3", "--version"], capture_output=True, text=True)
    except FileNotFoundError:
        return False

    # Check opencode CLI
    with contextlib.suppress(FileNotFoundError):
        subprocess.run(["opencode", "--version"], capture_output=True, text=True)

    return True


def get_project_info():
    """Get information about the project."""
    project_root = Path.cwd()

    info = {
        "has_package_json": (project_root / "package.json").exists(),
        "has_requirements_txt": (project_root / "requirements.txt").exists(),
        "has_run_ui": (project_root / "run_ui.py").exists(),
        "has_npm_scripts": False,
        "build_command": None,
        "lint_command": None,
    }

    if info["has_package_json"]:
        with open(project_root / "package.json") as f:
            package = json.load(f)
            if "scripts" in package:
                info["has_npm_scripts"] = True
                scripts = package["scripts"]
                # Detect build command
                for cmd in ["build", "build:prod", "build:production"]:
                    if cmd in scripts:
                        info["build_command"] = f"npm run {cmd}"
                        break
                # Detect lint command
                for cmd in ["lint", "eslint", "lint:check"]:
                    if cmd in scripts:
                        info["lint_command"] = f"npm run {cmd}"
                        break

    return info


def run_brocula():
    """Run BroCula agent with OpenCode."""
    # Save prompt to temp file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prompt_file = Path(f"/tmp/brocula_prompt_{timestamp}.txt")
    prompt_file.write_text(BROCULA_PROMPT)

    # Run opencode with the prompt
    try:
        result = subprocess.run(
            ["opencode", "run", BROCULA_PROMPT, "--model", "opencode/kimi-k2.5-free"],
            capture_output=False,
            text=True,
            timeout=Timeouts.BROCULA_OPCODE_TIMEOUT,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        return False


def main():
    """Main entry point."""
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Get project info
    info = get_project_info()
    for value in info.values():
        if value is None:
            pass

    # Confirm execution
    response = input("\n🚀 Start BroCula workflow? (yes/no): ").lower().strip()

    if response not in ["yes", "y"]:
        sys.exit(0)

    # Run BroCula
    success = run_brocula()

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
