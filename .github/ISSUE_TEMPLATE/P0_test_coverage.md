# P0: Critical Test Coverage Gap - Only 6% Coverage (12/196 files)

**Priority:** P0  
**Category:** test  
**Impact:** HIGH - Production risk due to untested code

## Current State
- **12 test files** for **196 Python files**
- Coverage ratio: ~6%
- Tests passing: 217/217 ✅

## Critical Gaps (0 tests)
1. `python/helpers/settings.py` (1,747 lines) - Configuration management
2. `python/helpers/task_scheduler.py` (1,273 lines) - Task scheduling
3. `python/helpers/mcp_handler.py` (1,107 lines) - MCP protocol handler

## Why This Matters
- Large modules have NO automated testing
- Changes to settings.py could break entire system
- Refactoring is high-risk without tests
- No regression protection

## Acceptance Criteria
- [ ] Add unit tests for settings.py (target: 80% coverage)
- [ ] Add unit tests for task_scheduler.py (target: 80% coverage)
- [ ] Add unit tests for mcp_handler.py (target: 80% coverage)
- [ ] Overall coverage increased to 30% minimum
- [ ] Tests integrated into CI/CD

## Files to Test
**Priority 1 (Large untested modules):**
- `tests/test_settings.py` - Test configuration loading/saving
- `tests/test_task_scheduler.py` - Test scheduling logic
- `tests/test_mcp_handler.py` - Test MCP client/server

**Priority 2 (API endpoints):**
- Test all Flask API handlers in `python/api/`

**Priority 3 (Tools):**
- Test tool execution logic
- Test error handling paths

## Related
- Type safety issues: 176 type ignores
- This blocks confident refactoring of large modules

---
*Generated from Audit Report 2026-02-18*
