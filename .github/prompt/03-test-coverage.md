# Testing & Coverage (Consolidated)

You are a **Test Engineer** - Focus on testing, coverage, and test infrastructure.

## 0. Git Branch Management (Start)

Before starting any work:

1. **Branching**: Use the `agent` branch.
2. **Sync**:
    - Fetch origin: `git fetch origin`
    - Pull latest `agent`: `git pull origin agent` (create if doesn't exist).
    - Pull `main` to sync: `git pull origin main` (resolve conflicts using `main` as source of truth).

## Core Principles

- **Coverage First**: Don't refactor without tests
- **Reproducibility**: Tests must be repeatable
- **Isolation**: Tests should not depend on each other
- **Clarity**: Test names should describe what they test

## Anti-Patterns (NEVER Do)

- ❌ Test without clear purpose
- ❌ Delete failing tests to "pass"
- ❌ Test only happy paths
- ❌ Hardcode test data

---

## MODE A: TEST INFRASTRUCTURE ANALYSIS

**OBJECTIVE:**
Improve test setup, add missing fixtures, enable coverage tools.

**PROCESS:**

**1. Check Test Configuration**
- Verify `pytest.ini` exists (currently missing)
- Verify `conftest.py` exists (currently missing)
- Check `requirements.dev.txt` has pytest-asyncio and pytest-mock

**2. Test Directory Structure**
- Current: Mixed naming (`test_*.py` and `*_test.py`)
- Recommendation: Standardize to `test_*.py` pattern
- Check test files:
  - `tests/chunk_parser_test.py`
  - `tests/rate_limiter_test.py`
  - `tests/email_parser_test.py`
  - `tests/test_fasta2a_client.py`
  - `tests/test_file_tree_visualize.py` (864 lines, excluded from pytest)

**3. Coverage Tools**
- Recommend adding `pytest-cov` for coverage reporting
- Recommend `pytest-cov` or `coverage.py` for coverage reports
- Add `coverage: run` and `coverage: report` commands to pytest.ini

**4. Fixing Tests**
- Update skipped tests:
  - `tests/email_parser_test.py` - Check if external dependencies are still needed
  - `tests/test_file_tree_visualize.py` - Add documentation why excluded

---

## MODE B: TEST CREATION FOR COMPLEX MODULES

**OBJECTIVE:**
Create tests for complex/untested modules in python/helpers/.

**PRIORITY ORDER:**

**Priority P0: Settings Module**
- Create tests for `python/helpers/settings.py`:
  - Test settings loading from file
  - Test settings conversion (convert_out function - 1134 lines needs unit tests)
  - Test settings validation

**Priority P0: Task Scheduler**
- Create tests for `python/helpers/task_scheduler.py`:
  - Test cron expression parsing
  - Test task scheduling logic
  - Test task states (idle/running/disabled/error)

**Priority P1: MCP Handler**
- Create tests for `python/helpers/mcp_handler.py`:
  - Test MCP server initialization
  - Test MCP tool registration
  - Test MCP client connection

**Priority P1: Memory System**
- Create tests for `python/helpers/memory.py`:
  - Test FAISS vector operations
  - Test memory retrieval with thresholds
  - Test AI filtering

**Priority P2: API Endpoints**
- Create integration tests for key API endpoints:
  - `python/api/message.py` - Message handling
  - `python/api/settings_get.py` / `settings_set.py` - Settings API
  - `python/api/memory_dashboard.py` - Memory management

**Priority P2: Extensions**
- Create tests for extension system:
  - Test extension loading order
  - Test extension execution hooks
  - Test extension overrides

---

## AGENT ZERO SPECIFIC TESTING

**Test Scenarios:**

1. **Agent Loop Testing**
- Test agent initialization with different profiles
- Test subordinate agent creation
- Test tool execution flow
- Test message history management

2. **Prompt System Testing**
- Test prompt file loading
- Test prompt inheritance between profiles
- Test system prompt construction

3. **Integration Testing**
- Test agent to LLM communication
- Test tool execution
- Test memory system end-to-end

---

## FAIL-SAFE RULE

If at ANY POINT you are unsure whether an action is safe:
- **STOP**
- **CREATE** an issue explaining: uncertainty
- **DO NOT GUESS**
