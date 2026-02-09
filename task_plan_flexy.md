# Task Plan: Flexy's Modularization Mission

## Goal
Eliminate hardcoded values throughout the Agent Zero codebase and make the system modular through configuration-driven architecture.

## Phases
- [x] Phase 1: Setup - Create isolated worktree and analyze codebase
  - Created worktree at `.worktrees/flexy-modularization/`
  - Branch: `flexy/modularization`
  - Added `.worktrees/` to .gitignore
- [x] Phase 2: Research - Identify all hardcoded values (magic numbers, strings, URLs, paths, timeouts, limits)
  - **DISCOVERY**: Python constants already exist at `python/helpers/constants.py`
    - Timeouts class: 25+ timeout constants
    - Limits class: 50+ limit constants
    - Network class: ports, URLs, CORS origins
    - Paths class: directory structures
    - Colors class: UI colors
    - Config class: environment variable support
  - **DISCOVERY**: JavaScript constants already exist at `webui/js/constants.js`
    - API object: ports, hosts, endpoints, status codes
    - TIMING object: display times, animation delays, polling intervals
    - SPEECH object: silence detection, recorder settings
    - UI object: z-index constants
    - LIMITS object: message, file, memory limits
    - COLORS object: semantic colors matching Python
  - **Files already importing constants**:
    - Python: 16+ files importing from constants.py
    - JavaScript: Multiple files importing from constants.js
- [ ] Phase 3: Verify - Ensure all hardcoded values use constants
  - Check for remaining hardcoded values in Python files
  - Check for remaining hardcoded values in JavaScript files
  - Verify consistency between Python and JavaScript constants
- [x] Phase 4: Fix - Refactor any remaining hardcoded values
  - **FIXED**: `python/tools/scheduler.py` - Now uses `Timeouts.SCHEDULER_DEFAULT_WAIT`
  - **FIXED**: `python/helpers/rate_limiter.py` - Now uses `Timeouts.RATE_LIMITER_DEFAULT_TIMEFRAME` (new constant added)
  - **FIXED**: `python/helpers/fasta2a_client.py` - Now uses `Timeouts.HTTP_CLIENT_DEFAULT_TIMEOUT` and `Timeouts.DOCUMENT_POLL_INTERVAL`
  - **FIXED**: `python/helpers/notification.py` - Now uses `Limits.NOTIFICATION_RECENT_SECONDS` (new constant added)
  - **FIXED**: `python/helpers/email_client.py` - Now uses `Limits.IMAP_MAX_LINE_LENGTH`
  - **FIXED**: `python/helpers/task_scheduler.py` - Now uses `Timeouts.SCHEDULER_CHECK_FREQUENCY` (new constant added)
  - **ADDED**: New constants to `python/helpers/constants.py`:
    - `RATE_LIMITER_DEFAULT_TIMEFRAME = 60`
    - `SCHEDULER_CHECK_FREQUENCY = 60.0`
    - `NOTIFICATION_RECENT_SECONDS = 30`
- [ ] Phase 5: Verify - Run build/lint, ensure no errors/warnings (fatal on failure)
- [ ] Phase 6: Complete - Update branch with main, create/update PR

## Key Findings
1. **System is ALREADY MODULAR!** Comprehensive constants modules exist
2. Most files are already using the constants
3. Some files may have missed hardcoded values that should use constants

## Status
**Currently in Phase 3** - Verifying all files properly use constants
