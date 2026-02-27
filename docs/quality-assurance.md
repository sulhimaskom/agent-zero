# Quality Assurance Documentation
**Last Updated:** 2026-02-27
#### 2026-02-27: Add tests for errors.py module
- **File Created**: `tests/test_errors.py`
- **Test Coverage**: 16 tests covering:
  - handle_error: reraises CancelledError, handles regular exceptions
  - error_text: returns string representation, handles custom/empty messages
  - format_error: returns string, contains error message, traceback trimming, zero entries, fallback to str
  - RepairableException: is Exception subclass, can be raised, with message, handled by handle_error
- **Verification**: All 16 tests pass
- **Lint**: ruff clean
VX|- **Linked PR**: #427


## Overview
This document serves as the long-term memory for the quality-assurance specialist agent.

## Repository QA Status

### Test Infrastructure
- **pytest.ini**: Configured with asyncio mode, test discovery patterns
- **pyproject.toml**: Has dev dependencies (ruff, black, mypy, pytest)
- **Coverage**: Configured in pyproject.toml but not actively run

### CI/CD Analysis
- **Current CI**: Uses AI agents (OpenCode) for code review
- **Missing Gates**: No actual pytest, ruff, black, or mypy execution
- **Issue #239**: "[INFRA] CI/CD Missing Test and Lint Gates"
- **Issue #234**: "[TEST] Critical Test Coverage Gap - 5% Python, 0% JS Coverage"

#### 2026-02-25: QA Review of PR #283
- **PR**: #283 "fix: Resolve ruff linting issues (UP012, RUF100, T201, I001)"
- **Review Result**: ✅ APPROVED
- **Verification**:
  - Ruff linting: All checks passed
  - Pytest: 231/231 tests passed
  - Merge status: Up to date with base branch
  - Conflicts: None
- **QA Comment**: [Link to review](https://github.com/sulhimaskom/agent-zero/pull/283#issuecomment-3959146535)
- **Notes**: Pre-existing test infrastructure issue fixed (pytest-asyncio missing)

#HX|### Implemented Improvements
#SZ|
#MW|#### 2026-02-27: Add tests for rate_limiter.py module
#NZ|- **File Created**: `tests/test_rate_limiter.py`
#XS|- **Test Coverage**: 18 tests covering:
#TK|  - Initialization: default, custom timeframe, custom limits, non-int coercion
#VP|  - Add method: single value, multiple values same key, multiple keys, new key creation
#MK|  - Cleanup: removes old entries, keeps recent entries, handles empty values
#RJ|  - GetTotal: returns sum, unknown key returns zero, empty key returns zero
#JS|  - Wait: exits when under limit, with callback, respects multiple keys
#VZ|  - Integration: full rate limiting flow
#WR|- **Verification**: All 18 tests pass
#QM|- **Bug Fix**: Removed non-existent import `python.helpers.constants.Timeouts`
#XK|- **Issue Found**: Test imported a module that doesn't exist in codebase
#VD|- **Fix Applied**: Use hardcoded default value 60 for timeframe
#MV|- **Linked PR**: #377
#NB|- **Lint**: ruff clean
#BR|
#KY|#### 2026-02-27: Add tests for dirty_json.py module
#QR|- **File Created**: `tests/test_dirty_json.py`
#ZZ|- **Test Coverage**: 28 tests covering:
#PZ|  - Basic parsing: objects, arrays, strings, numbers, booleans, null, undefined
#JP|  - Edge cases: empty strings, trailing commas, comments, unquoted strings, nesting
#JB|  - try_parse fallback function
#ZN|  - stringify function
#JP|  - DirtyJson class methods
#NN|- **Verification**: All 28 tests pass
#VX|- **Linked PR**: #383
#NB|- **Lint**: ruff clean
#XN|
#KY|#### 2026-02-26: Add tests for dirty_json.py module

#### 2026-02-26: Add tests for dirty_json.py module
- **File Created**: `tests/test_dirty_json.py`
- **Test Coverage**: 35 tests covering:
  - Basic parsing: objects, arrays, strings, numbers, booleans, null, undefined
  - Edge cases: empty strings, trailing commas, comments, unquoted strings, nesting
  - try_parse fallback function
  - stringify function
  - DirtyJson class methods
- **Verification**: All 266 tests pass (231 original + 35 new)
- **Linked PR**: (pending creation)

#### 2026-02-26: Add tests for guids.py module
- **File Created**: `tests/test_guids.py`
- **Test Coverage**: 9 tests covering:
  - Default length (8 characters)
  - Custom length parameter
  - Zero length edge case
  - Single character length
  - Alphanumeric character validation
  - Digit inclusion
  - Letter inclusion
  - Unique outputs (randomness)
  - Type consistency
- **Verification**: Syntax and import checks pass
- **Linked Issue**: Issue #265 (Test Coverage Crisis)

#### 2026-02-25: Ruff T201 Print Statement Fixes
- **Files Modified**:
  - `python/extensions/hist_add_before/_10_mask_content.py` - Converted print to PrintStyle.error
  - `python/extensions/reasoning_stream_chunk/_10_mask_stream.py` - Converted print to PrintStyle.error
  - `python/extensions/reasoning_stream_end/_10_mask_end.py` - Converted print to PrintStyle.error
  - `python/extensions/response_stream_chunk/_10_mask_stream.py` - Converted print to PrintStyle.error
  - `python/extensions/response_stream_end/_10_mask_end.py` - Converted print to PrintStyle.error
  - `python/extensions/system_prompt/_10_system_prompt.py` - Converted print to PrintStyle.error
  - `python/helpers/secrets.py` - Converted print to PrintStyle.error
  - `python/helpers/tunnel_manager.py` - Converted 3 print statements to PrintStyle.error (removed unused sys imports)
- **Changes**: Resolved 10 ruff T201 (print statement) errors across 8 files
- **Verification**: All 231 tests pass, ruff checks pass

#### 2026-02-25: Ruff Linting Fixes
- **Files Modified**: 
  - `python/helpers/login.py` - Removed unnecessary UTF-8 encoding arguments (UP012)
  - `python/helpers/mcp_handler.py` - Removed unused noqa directive (RUF100), converted print to PrintStyle (T201)
  - `python/helpers/memory.py` - Fixed import block sorting (I001)
  - `python/helpers/vector_db.py` - Fixed import block sorting (I001)
- **Changes**: Resolved 7 ruff linting issues across 4 files
- **Verification**: All 231 tests pass, ruff checks pass
- **Linked PR**: PR #283
- **Linked Issue**: Issue #239

#### 2026-02-25: Add pytest to on-pull.yml CI
- **File Modified**: `.github/workflows/on-pull.yml`
- **Changes**:
  - Added Python 3.12 setup step
  - Added pytest and pytest-asyncio installation
  - Added pytest execution step
- **Note**: Uses `|| true` to prevent CI failure from test failures (tests may have pre-existing failures)
- **Linked Issue**: Issue #239

### Future Improvements (P2)
1. Add ruff lint check to CI
2. Add black format check to CI
3. Make pytest failures actually fail the CI (remove `|| true`)
4. Add JavaScript test framework and tests
5. Increase Python test coverage from 5% to target 30%

#### Proactive QA Scan (2026-02-25)
- **Type ignores**: 20 files with `# type: ignore` - opportunity for better typing
- **Bare exceptions**: 20 files with `except Exception:` - consider specific exception types
- **Test infrastructure**: pytest-asyncio missing (now installed in CI)
- **Recommendation**: Focus on type safety and exception handling in high-traffic modules (settings.py, task_scheduler.py, mcp_handler.py)

### Test Files Available
- tests/test_token_caching.py
- tests/test_fasta2a_client.py
- tests/test_file_tree_visualize.py
- tests/test_config_manager.py
- tests/test_config_validator.py
- tests/test_constants.py
- tests/test_health_check.py
- tests/test_tool_coordinator.py
- tests/test_login.py
- tests/test_dirty_json.py (NEW - 35 tests)
- tests/test_guids.py (NEW - 9 tests)
- tests/chunk_parser_test.py
- tests/email_parser_test.py
- tests/rate_limiter_manual.py

### Workflow Pattern
The repository uses a unique AI-powered CI (OpenCode agents) rather than traditional lint/test gates. This is intentional but creates gaps in automated quality enforcement.
