# P1: Refactor Oversized Modules (>1000 lines)

**Priority:** P1  
**Category:** refactor  
**Impact:** MEDIUM - Maintenance burden, SRP violations

## Current State
Three modules exceed maintainable size (>1000 lines):

| File | Lines | Responsibility Areas |
|------|-------|---------------------|
| settings.py | 1,747 | Settings loading, validation, persistence, UI integration |
| task_scheduler.py | 1,273 | Scheduling, task types, persistence, execution |
| mcp_handler.py | 1,107 | MCP client, server, tool management, configuration |

## Problems
- **Single Responsibility Principle violations**
- **High cognitive load** - too much to understand
- **High blast radius** - changes affect many areas
- **Difficult to test** - no tests exist for these files
- **Code review difficulty** - large files hard to review thoroughly

## Proposed Refactoring

### settings.py (1,747 lines)
Split into:
- `settings/loader.py` - Configuration loading
- `settings/validator.py` - Validation logic
- `settings/persistence.py` - Save/load operations
- `settings/manager.py` - Main coordination (facade)

### task_scheduler.py (1,273 lines)
Split into:
- `scheduler/models.py` - Task dataclasses
- `scheduler/crontab.py` - Crontab parsing
- `scheduler/executor.py` - Task execution
- `scheduler/persistence.py` - Database operations
- `scheduler/scheduler.py` - Main scheduler (facade)

### mcp_handler.py (1,107 lines)
Split into:
- `mcp/client.py` - MCP client operations
- `mcp/server.py` - MCP server operations
- `mcp/tools.py` - Tool management
- `mcp/config.py` - Configuration handling
- `mcp/handler.py` - Main handler (facade)

## Acceptance Criteria
- [ ] Each module <500 lines after refactoring
- [ ] Clear separation of concerns
- [ ] All tests pass after refactoring
- [ ] No functional changes (pure refactoring)
- [ ] Documentation updated

## Dependencies
- **BLOCKED BY:** Test coverage (P0) - Need tests before refactoring safely
- **BLOCKED BY:** Type safety (P0) - Need types for confidence

## Related
- settings.py TODO: Lines 1558, 1616, 1621, 1631, 1643 mention defer.run_in_background()
- task_scheduler.py TODO: About splitting task types from scheduler logic

---
*Generated from Audit Report 2026-02-18*
