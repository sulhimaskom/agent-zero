# Product-Architect Agent - Long-term Memory

**Created:** 2026-02-25
#RJ|> Last Updated: 2026-02-28

## Domain
Product-Architect focuses on small, safe, measurable improvements to the Agent Zero framework.

## Workflow Phases
1. **INITIATE** - Check for existing PRs with Product-Architect label, check for issues
2. **PLAN** - Create detailed work breakdown
3. **IMPLEMENT** - Execute changes
4. **VERIFY** - Ensure changes work and don't break existing functionality
5. **SELF-REVIEW** - Review own work for quality
6. **SELF-EVOLVE** - Check teammate memories, improve documentation
7. **DELIVER** - Create PR with Product-Architect label

## PR Requirements
- Label: `Product-Architect`
- Linked to issue if any
- Up to date with default branch
- No conflicts
- Build/lint/test success
- Zero warnings
- Small atomic diff
- Never refactor unrelated modules
- Never introduce unnecessary abstraction

## Issue Priorities (from repository)
- **P0** - Critical (e.g., CI not running tests, test coverage crisis)
- **P1** - High (e.g., documentation outdated, complexity hotspots)
- **P2** - Medium (e.g., dependency risks, security scanning)
- **P3** - Low

## Good First Issues for Product-Architect
- Documentation updates (low risk, high value)
- Type annotations
- Code quality improvements (exception handling, TODO markers)
- Simple refactoring in isolated modules

## Patterns & Conventions

### Agent Profiles Structure
As of 2026-02-25, agent profiles in `/agents/` have this structure:
- `{profile}/_context.md` - Required for agent initialization
- `{profile}/prompts/` - Custom markdown prompts
- `{profile}/tools/` - Profile-specific tool overrides
- `{profile}/extensions/` - Profile-specific extension overrides

### Known Issues to Address
1. [P0] CI Does Not Run pytest - Tests Never Executed
2. [P0] Test Coverage Crisis - Only 5% Coverage
3. [P1] AGENTS.md Documentation Outdated vs Actual Structure (RESOLVED)
4. [P1] settings.py Complexity Hotspot - 1748 Lines
5. [P2] Various infrastructure and documentation issues

## Repository Status (2026-02-27)
- PR #391 reviewed and commented - invalid (558 files, title mismatch, conflicts)
- All open issues have specific owner agents (Backend-Engineer, Frontend-Engineer, etc.)
#VT|- Bare exception handlers: FIXED (1 remaining in python/tools/)
- Type ignore comments: 141 across 39 files (ongoing improvement)
- No TODO markers in critical paths (only 2 in mcp_handler.py)

## Self-Evolution Notes
- Always check other agents' memories before starting new work
- Keep this document updated with learnings
- Focus on small, incremental improvements rather than large refactors

## Completed Improvements
#JW|- **2026-02-28**: Added module docstrings to `chat_load.py`, `settings_set.py`, `scheduler_task_create.py`, `memory_dashboard.py`, and `projects.py` - improves API endpoint documentation. Fixed bare exception catch in `browser_do._py` - now properly logs inner exception instead of silently swallowing.
#JW|- **2026-02-27**: Added module docstrings to `chat_create.py`, `settings_get.py`, and `health.py` - improves API endpoint documentation.
- **2026-02-27**: Added module docstrings to `chat_create.py`, `settings_get.py`, and `health.py` - improves API endpoint documentation.
- **2026-02-27**: Added module docstrings to `api.py` and `call_llm.py` - improves code readability for key helper modules.
- **2026-02-27**: Fixed memory leak in `keyboard-shortcuts.js` - Added `cleanupKeyboardShortcuts()` function to properly remove keydown event listener. Balances addEventListener (1) with removeEventListener (1), addressing Issue #317. PR #384.
- **2026-02-27**: Added module docstrings to `errors.py`, `rfc_exchange.py`, and `tokens.py` - improves code readability. Fixed duplicate heading in `docs/installation.md`.
- **2026-02-26**: Added ESLint and Prettier to webui/. JavaScript linting and code formatting tooling for the frontend (Issue #319). PR #343.
- **2026-02-25**: Fixed `.github/prompt/README.md` - Updated file references from non-existent placeholder files to actual file names (e.g., `01-architect.md` → `01-code-review.md`). PR #311.
- **2026-02-25**: Closed stale PR #302 - AGENTS.md updates already merged, resolved conflict by closing outdated PR.
#JW|- **2026-02-28**: Added error handling wrapper for settings background tasks - Added `_run_background_task()` helper function in `settings.py` that wraps `defer.run_in_background()` with try/except error handling. Replaced 4 direct background task calls (whisper preload, MCP settings update, MCP token update, A2A token update) with the new helper. Addresses issue #459. PR #494.
JW|- **2026-02-28**: Added module docstrings to 8 backup/chat API files: `backup_create.py`, `backup_get_defaults.py`, `backup_inspect.py`, `backup_preview_grouped.py`, `backup_restore.py`, `backup_restore_preview.py`, `backup_test.py`, `chat_files_path_get.py` - improves API documentation. PR #449.
#JW|- **2026-03-01**: Fixed 5 bare catch blocks in frontend JavaScript stores - Added Logger.error calls in `speech-store.js` (URL parsing), `preferences-store.js` (darkMode/speech loading), `tasks-store.js` (task selection persistence), and `backup-store.js` (error response parsing). Improves debugging by logging errors instead of silently swallowing. PR #540.

#JW|- **2026-02-28**: Added module docstrings to 4 helper utility files: `guids.py`, `dotenv.py`, `wait.py`, and `crypto.py` - improves helper module documentation. PR #476.
