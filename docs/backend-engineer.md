# Backend Engineer Agent - Knowledge Base

**Created:** 2026-02-26
**Agent:** backend-engineer (autonomous mode)

## Domain Scope
- Python backend code
- API endpoints (`python/api/*.py`)
- Helper modules (`python/helpers/*.py`)
- Agent logic (`agents/**/*.py`)
- Tool implementations (`python/tools/**/*.py`)

## Proactive Scan Focus Areas

### Error Handling
- [ ] Bare `except:` handlers - 71 instances found across 34 files (NEEDS FIX)
- [ ] Empty except blocks with only `pass`
- [ ] Uncaught exceptions in async code
- [ ] Missing error handling in API endpoints

### Code Quality
- [ ] TODO/FIXME comments
- [ ] Type hinting missing
- [ ] Inconsistent exception handling patterns
- [ ] Hardcoded credentials or secrets

### Security
- [ ] Path traversal vulnerabilities
- [ ] SQL injection risks
- [ ] Input validation
- [ ] Authentication/authorization issues

### Performance
- [ ] Inefficient database queries
- [ ] Missing caching
- [ ] Blocking I/O operations
- [ ] Memory leaks

## Common Patterns
- [x] Bare `except:` handlers - should catch specific exceptions
- [ ] Empty except blocks with only `pass`
- [ ] Uncaught exceptions in async code
- [ ] Missing error handling in API endpoints

### Code Quality
- [ ] TODO/FIXME comments
- [ ] Type hinting missing
- [ ] Inconsistent exception handling patterns
- [ ] Hardcoded credentials or secrets

### Security
- [ ] Path traversal vulnerabilities
- [ ] SQL injection risks
- [ ] Input validation
- [ ] Authentication/authorization issues

### Performance
- [ ] Inefficient database queries
- [ ] Missing caching
- [ ] Blocking I/O operations
- [ ] Memory leaks

## Common Patterns

### API Endpoints
Located in: `python/api/`
- Follow consistent error response format
- Use proper HTTP status codes
- Validate input parameters

### Helper Modules
Located in: `python/helpers/`
- Modular, single-responsibility functions
- Import from `python.helpers import runtime`
- Use `files.get_abs_path()` for path handling

### Error Handling
- Catch specific exceptions (`OSError`, `ValueError`, etc.)
- Never use bare `except:`
- Log errors with appropriate level
- Return meaningful error messages to callers

## Known Issues (2026-02-26)

1. **Bare except handlers**: 2 files with bare `except:` found and fixed (files.py, git.py)
2. **TODO comments**: ~16 TODO/FIXME comments across Python files
3. **Previous PR #340**: Fixed 26 bare exception handlers in test and helper files
4. **REMAINING ISSUE**: 71 bare `except Exception:` handlers found across 34 Python files - needs systematic fix

## Working Notes

### Third Task Completed (2026-02-26)
- Fixed 6 bare `except Exception:` handlers in python/helpers/git.py
- Changed all to `except Exception as e:` for better debugging
- PR #371 created

1. **Bare except handlers**: 2 files with bare `except:` found and fixed (files.py, git.py)
2. **TODO comments**: ~16 TODO/FIXME comments across Python files
3. **Previous PR #340**: Fixed 26 bare exception handlers in test and helper files

## Working Notes

### First Task Completed
- Fixed bare `except:` in `python/helpers/files.py` (line 448)
- Changed to `except OSError:` for proper error handling in delete_dir function

### Second Task Completed
- Fixed bare `except:` in `python/helpers/git.py` (line 52)
- Changed to `except Exception:` for proper error handling in get_git_info function

## Commands

### Python Syntax Check
```bash
python3 -m py_compile <file.py>
```

### Run Tests
```bash
cd /home/runner/work/agent-zero/agent-zero
python -m pytest tests/ -v
```
