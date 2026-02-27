# User Story Engineer Agent - Knowledge Base

**Created:** 2026-02-27
**Agent:** user-story-engineer (autonomous mode)

## Domain Scope

- Test coverage for helper modules
- Small, safe, measurable improvements
- Quality assurance via testing
- Test infrastructure maintenance

## Proactive Scan Focus Areas

### Test Coverage
- [ ] Modules without tests in python/helpers/
- [ ] Critical path functions lacking test coverage
- [ ] Edge cases in error handling

### Test Quality
- [ ] Test assertions meaningful
- [ ] Test isolation (no shared state)
- [ ] Proper use of fixtures
- [ ] Test readability

### Infrastructure
- [ ] Test configuration (pytest.ini, conftest.py)
- [ ] Test dependencies up to date
- [ ] CI/CD test execution

## Common Patterns

### Test File Location
Located in: `tests/`
- Name: `test_<module_name>.py`
- Follow existing test conventions

### Test Structure
```python
import pytest

class Test<FunctionOrClass>:
    """Test <function_or_class>"""
    
    def test_<description>(self):
        """Test <description>"""
        # Arrange
        ...
        # Act
        ...
        # Assert
        ...
```

### Running Tests
```bash
cd /home/runner/work/agent-zero/agent-zero
python -m pytest tests/test_<module>.py -v
```

### Lint Check
```bash
python -m ruff check tests/test_<module>.py
```

## PR Requirements

- Label: user-story-engineer
- Linked to issue if any
- Up to date with default branch
- No conflict
- Build/lint/test success
- ZERO warnings
- Small atomic diff

## Completed PRs

### PR #387 (2026-02-27)
- **Title:** test: add tests for errors.py module
- **Branch:** user-story-engineer/test-errors-py-v2
- **Changes:** Added tests/test_errors.py with 14 tests
- **Coverage:**
  - `error_text()` function - 3 tests
  - `format_error()` function - 4 tests
  - `handle_error()` function - 3 tests
  - `RepairableException` class - 4 tests
- **Status:** All 14 tests pass, ruff lint clean
- **Related:** Replaces PR #360 (outdated branch)

### PR #360 (2026-02-26) - CLOSED
- **Title:** test: add tests for errors.py module
- **Status:** Closed (branch too far behind main)
- **Replacement:** PR #387

## Working Notes

### INITIATE Phase
- Check for existing PRs with user-story-engineer label
- Found PR #360: "test: add tests for errors.py module"
- PR branch was far behind main (hundreds of commits divergence)
- Many merge conflicts during rebase attempt

### RESOLUTION
- Closed outdated PR #360
- Created fresh branch from main (user-story-engineer/test-errors-py-v2)
- Copied test file content
- Verified tests pass (14/14)
- Verified lint clean (ruff)
- Created new PR #387

### Key Learnings
1. Keep PR branches frequently updated with main
2. Small, atomic changes are easier to keep up to date
3. When rebase has too many conflicts, consider fresh branch approach

## Commands

### Check Open PRs
```bash
gh pr list --label "user-story-engineer" --state open
```

### Check Tests
```bash
cd /home/runner/work/agent-zero/agent-zero
python -m pytest tests/ -v
```

### Lint Check
```bash
cd /home/runner/work/agent-zero/agent-zero
python -m ruff check tests/
```
