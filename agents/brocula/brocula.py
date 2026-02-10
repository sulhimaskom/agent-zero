#!/usr/bin/env python3
"""
BroCula - Browser Console & Lighthouse Optimization Specialist
Local execution script for manual runs
"""

import subprocess
import sys
import json
from datetime import datetime
from pathlib import Path

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

Remember: You are BroCula. You love working in the browser console. You fix errors immediately. You optimize relentlessly. You never leave a mess behind.
"""

def check_dependencies():
    """Check if required tools are available"""
    print("🔍 Checking dependencies...")
    
    # Check Node.js
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        print(f"  ✅ Node.js: {result.stdout.strip()}")
    except FileNotFoundError:
        print("  ❌ Node.js not found")
        return False
    
    # Check npm
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
        print(f"  ✅ npm: {result.stdout.strip()}")
    except FileNotFoundError:
        print("  ❌ npm not found")
        return False
    
    # Check Python
    try:
        result = subprocess.run(['python3', '--version'], capture_output=True, text=True)
        print(f"  ✅ Python: {result.stdout.strip()}")
    except FileNotFoundError:
        print("  ❌ Python not found")
        return False
    
    # Check opencode CLI
    try:
        result = subprocess.run(['opencode', '--version'], capture_output=True, text=True)
        print(f"  ✅ OpenCode CLI: {result.stdout.strip()}")
    except FileNotFoundError:
        print("  ⚠️  OpenCode CLI not found. Install from: https://opencode.ai")
        print("     Continuing anyway...")
    
    return True

def get_project_info():
    """Get information about the project"""
    project_root = Path.cwd()
    
    info = {
        'has_package_json': (project_root / 'package.json').exists(),
        'has_requirements_txt': (project_root / 'requirements.txt').exists(),
        'has_run_ui': (project_root / 'run_ui.py').exists(),
        'has_npm_scripts': False,
        'build_command': None,
        'lint_command': None,
    }
    
    if info['has_package_json']:
        with open(project_root / 'package.json') as f:
            package = json.load(f)
            if 'scripts' in package:
                info['has_npm_scripts'] = True
                scripts = package['scripts']
                # Detect build command
                for cmd in ['build', 'build:prod', 'build:production']:
                    if cmd in scripts:
                        info['build_command'] = f"npm run {cmd}"
                        break
                # Detect lint command
                for cmd in ['lint', 'eslint', 'lint:check']:
                    if cmd in scripts:
                        info['lint_command'] = f"npm run {cmd}"
                        break
    
    return info

def run_brocula():
    """Run BroCula agent with OpenCode"""
    print("\n🧛 Starting BroCula - Browser Console & Lighthouse Specialist...")
    print("=" * 60)
    
    # Save prompt to temp file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    prompt_file = Path(f'/tmp/brocula_prompt_{timestamp}.txt')
    prompt_file.write_text(BROCULA_PROMPT)
    
    print(f"\n📄 Prompt saved to: {prompt_file}")
    print("\n🚀 Executing BroCula workflow...")
    print("-" * 60)
    
    # Run opencode with the prompt
    try:
        result = subprocess.run(
            ['opencode', 'run', BROCULA_PROMPT, '--model', 'opencode/kimi-k2.5-free'],
            capture_output=False,
            text=True,
            timeout=7200  # 2 hour timeout
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("\n⏰ BroCula workflow timed out after 2 hours")
        return False
    except Exception as e:
        print(f"\n❌ Error running BroCula: {e}")
        return False

def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  🧛 BroCula - Browser Console & Lighthouse Specialist       ║
║                                                              ║
║  Workflow:                                                   ║
║  1. Monitor browser console for errors/warnings              ║
║  2. Run Lighthouse audits & optimize                         ║
║  3. Validate build & lint (FATAL on errors)                  ║
║  4. Create PR with fixes                                     ║
║                                                              ║
║  Rules:                                                      ║
║  • Console errors are FATAL - fix immediately               ║
║  • Branch must sync with main before PR                     ║
║  • Build/lint errors block everything                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Missing required dependencies. Please install them first.")
        sys.exit(1)
    
    # Get project info
    print("\n📋 Project Information:")
    info = get_project_info()
    for key, value in info.items():
        icon = "✅" if value else "❌"
        if value is None:
            icon = "⚠️ "
        print(f"  {icon} {key}: {value}")
    
    # Confirm execution
    print("\n" + "=" * 60)
    response = input("\n🚀 Start BroCula workflow? (yes/no): ").lower().strip()
    
    if response not in ['yes', 'y']:
        print("\n👋 BroCula workflow cancelled.")
        sys.exit(0)
    
    # Run BroCula
    success = run_brocula()
    
    if success:
        print("\n✅ BroCula workflow completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ BroCula workflow encountered issues.")
        sys.exit(1)

if __name__ == '__main__':
    main()
