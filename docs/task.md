# Architectural Tasks

## Security (Completed 2025-01-07)

### 11. Patch Critical CVE Vulnerabilities (HIGH PRIORITY)
**Status**: Completed (2025-01-07)
**Module**: `requirements.txt` - Dependency updates
**Problem**: Multiple high-severity CVEs in dependencies
- fastmcp 2.3.4: 3 CVEs (XSS, command injection, DNS rebinding)
- mcp 1.13.1: 1 CVE (DNS rebinding)
- langchain-core 0.3.49: 2 CVEs (template injection)
- langchain-community 0.3.19: 1 CVE (dependency issue)
- langchain-text-splitters 0.3.7: 1 CVE (dependency issue)

**Action**:
- Updated fastmcp from 2.3.4 to >=2.14.0 ✅
- Updated mcp from 1.13.1 to >=1.23.0 ✅
- Updated langchain-core from 0.3.49 to >=0.3.81 ✅
- Updated langchain-community from 0.3.19 to >=0.3.27 ✅
- Added langchain-text-splitters >=0.3.9 ✅
- Verified all CVEs patched with pip-audit ✅
- Created .env.example file for secure credential management ✅

**Dependencies**: None
**Impact**: 5 packages updated, 8 CVEs patched, no remaining vulnerabilities

## In Progress

### 10. Add Comprehensive Unit Tests for ToolCoordinator (HIGH PRIORITY)
**Status**: In Progress (2025-01-07)
**Module**: `tests/test_tool_coordinator.py` - ToolCoordinator tests
**Problem**: ToolCoordinator is a critical new architectural component with no tests
- ToolCoordinator extracts tool execution logic from Agent class
- Critical for tool discovery, execution, and lifecycle management
- No unit tests exist for this component

**Action**:
- Create comprehensive test suite `tests/test_tool_coordinator.py` ✅
- Test tool discovery and loading from profile and default directories ✅
- Test tool execution lifecycle (before, execute, after, extensions) ✅
- Test error scenarios (tool not found, malformed requests, execution failures) ✅
- Test edge cases (break loop, empty args, tool with method) ✅
- Test MCP tool integration (mocked) ✅
- Test interface conformance (IToolExecutor) ✅

**Dependencies**: None (uses pytest, pytest-asyncio, pytest-mock)
**Estimated Impact**: 15 comprehensive test cases covering critical paths
**Actual Impact**: Created test_tool_coordinator.py with 15 test cases
**Blockers**: 
- Dependency chain complexity prevents test collection
- Missing heavy dependencies (browser-use, transformers, torch, etc.)
- Tests are written and valid but cannot run until full dependencies installed
- Tests document expected behavior and can be used for manual verification

**Next Steps**:
- Install full dependency chain from requirements.txt to enable test execution
- Consider creating isolated test suite that mocks heavy dependencies at import level
- Document test infrastructure setup requirements

## Completed

### 1. Extract Tool Execution Logic (HIGH PRIORITY)
**Status**: Completed (2025-01-07)
**Module**: `agent.py` - Agent class
**Problem**: Tool execution logic embedded in Agent.monologue() (lines ~356-483)
- Tool discovery, execution, result handling mixed with orchestration
- Direct imports and instantiation of tools
- MCP tool lookup scattered

**Action**:
- Extract tool execution to `ToolCoordinator` class ✅
- Define `IToolExecutor` interface ✅
- Create `python/coordinators/tool_coordinator.py` ✅
- Move `get_tool()`, `process_tools()` to coordinator ✅
- Update Agent to use coordinator via interface ✅

**Dependencies**: None
**Estimated Impact**: 200 lines extracted from Agent
**Actual Impact**: Created new module structure, ~100 lines extracted from Agent

## Backlog

---

### 2. Extract History Management (HIGH PRIORITY)
**Status**: Pending
**Module**: `agent.py` - Agent class
**Problem**: History operations scattered throughout Agent
- `hist_add_*` methods mixed with business logic
- Direct history manipulation from multiple locations
- History state managed in Agent

**Action**:
- Extract history operations to `HistoryCoordinator` class
- Define `IHistoryManager` interface
- Create `python/coordinators/history_coordinator.py`
- Move all `hist_add_*` methods to coordinator
- Agent receives messages via interface only

**Dependencies**: None
**Estimated Impact**: 150 lines extracted from Agent

---

### 3. Extract Stream Handling (MEDIUM PRIORITY)
**Status**: Pending
**Module**: `agent.py` - Agent class
**Problem**: Stream callbacks embedded in Agent.monologue() (lines ~385-429)
- Stream filtering and output mixed with orchestration
- Extension calls scattered in callback definitions
- Hard to test stream behavior independently

**Action**:
- Extract stream handling to `StreamCoordinator` class
- Define `IStreamHandler` interface
- Create `python/coordinators/stream_coordinator.py`
- Move `reasoning_callback`, `response_callback` to coordinator
- Unify extension calls for streams

**Dependencies**: None
**Estimated Impact**: 100 lines extracted from Agent

---

### 4. Centralize Configuration (MEDIUM PRIORITY)
**Status**: Pending
**Module**: Configuration scattered across multiple files
**Problem**: Config in AgentConfig, ModelConfig, settings.py, .env
- No single source of truth
- Validation scattered
- Hard to reason about configuration flow

**Action**:
- Create `ConfigManager` class
- Consolidate all configuration loading
- Add validation schema
- Create config validation tests
- Remove duplicate config handling

**Dependencies**: None
**Estimated Impact**: 3 files consolidated

---

### 5. Extension System Decoupling (MEDIUM PRIORITY)
**Status**: Pending
**Module**: Extension system throughout codebase
**Problem**: Extensions receive full Agent instance
- Extensions can manipulate agent state arbitrarily
- Hard to reason about side effects
- Violates interface segregation

**Action**:
- Create `ExtensionContext` dataclass
- Pass only necessary data to extensions
- Define extension contracts
- Migrate extensions to use contracts

**Dependencies**: Task 1, 2, 3 (coordinators needed)
**Estimated Impact**: 23+ extension files

---

### 6. Remove Circular Dependencies (LOW PRIORITY)
**Status**: Pending
**Module**: Various
**Problem**: Potential for circular imports
- Tools depend on Agent
- Agent depends on tools
- Some helpers depend on Agent

**Action**:
- Map all current dependencies
- Identify circular references
- Use dependency injection where needed
- Create dependency graph documentation

**Dependencies**: Tasks 1, 2, 3, 5
**Estimated Impact**: 10+ files

---

### 7. Create Coordinator Module Structure (HIGH PRIORITY)
**Status**: Completed (2025-01-07)
**Module**: New module
**Problem**: No clear separation of concerns

**Action**:
- Create `python/coordinators/` directory ✅
- Add `__init__.py` with coordinator exports ✅
- Create base coordinator class (deferred - only needed if common behavior)
- Define coordinator interfaces ✅
- Add coordinator tests (deferred - Task 8)

**Dependencies**: None
**Estimated Impact**: New module structure
**Actual Impact**: Module created with ToolCoordinator and IToolExecutor interface

---

### 8. Add Architecture Tests (MEDIUM PRIORITY)
**Status**: Pending
**Module**: Tests
**Problem**: No architectural validation

**Action**:
- Create architecture tests (pytest)
- Test for circular dependencies
- Test for interface conformance
- Test coordinator isolation
- Add CI check for architecture

**Dependencies**: Tasks 1, 2, 3, 7
**Estimated Impact**: New test suite

---

### 9. Document Dependency Flow (LOW PRIORITY)
**Status**: Pending
**Module**: Documentation
**Problem**: Dependencies not clearly documented

**Action**:
- Create dependency diagram
- Document data flow
- Document extension contracts
- Update architecture.md

**Dependencies**: All tasks
**Estimated Impact**: Documentation updates
