# Backend Engineer Agent Memory

**Last Updated:** 2026-02-25

## Domain Focus
- Python backend (Flask API)
- Authentication and security
- Performance optimization
- API endpoints

## Completed Fixes

### Issue: Bare Exception Handlers in A2A Protocol Files
**Status:** FIXED (2026-02-25)

**Changes:**
1. Fixed bare `except Exception:` in `python/helpers/fasta2a_server.py` line 291
2. Fixed bare `except Exception:` in `python/helpers/fasta2a_server.py` line 305
3. Fixed bare `except Exception:` in `python/helpers/fasta2a_client.py` line 79
4. Fixed bare `except Exception:` in `python/helpers/fasta2a_client.py` line 138
5. All now capture exception variable `as e` for debugging

**Files Modified:**
- `python/helpers/fasta2a_server.py` (+2 lines)
- `python/helpers/fasta2a_client.py` (+2 lines)

**Verification:**
- Python syntax verified
- No regressions

### Issue #290: Bare Exception Handlers in memory.py and task_scheduler.py
**Status:** FIXED

**Changes:**
1. Fixed bare `except Exception:` in `python/helpers/memory.py` line 137
2. Fixed bare `except Exception:` in `python/helpers/task_scheduler.py` line 937
3. Both now capture exception variable `as e` for debugging

**Files Modified:**
- `python/helpers/memory.py` (+1 line)
- `python/helpers/task_scheduler.py` (+2 lines)

**Verification:**
- All 231 tests pass
- Python syntax verified

### Issue #255: Node.js eval RCE Risk in docker/node_eval.js
**Status:** FIXED

**Changes:**
1. Replaced unsafe `eval()` with `vm.runInNewContext()` for true sandboxing
2. Removed dangerous globals from user context: process, Buffer, require, module, exports
3. Added 30-second timeout to prevent infinite loops
4. Added input validation for code parameter
5. Created safe globals whitelist: console, Math, JSON, Date, Array, Object, Promise, etc.

**Files Modified:**
- `docker/run/fs/exe/node_eval.js` (complete rewrite - 125 lines)

**Verification:**
- Syntax check: PASS
- Basic execution (1+1, Math.random(), JSON.stringify): PASS
- Dangerous globals blocked (process, require, Buffer): ReferenceError as expected
- Async/await: PASS

### Issue #238: Weak Authentication Hashing - SHA256 Without Salt
**Status:** FIXED

**Changes:**
1. Added `bcrypt==4.2.1` to requirements.txt
2. Updated `python/helpers/login.py`:
   - Replaced SHA256 with bcrypt hashing
   - Added `hash_password()` function with proper salt generation
   - Added `verify_password()` function for constant-time comparison
3. Updated `run_ui.py`:
   - Added rate limiting (5 attempts per minute per IP)
   - Changed password verification to use bcrypt
4. Added `tests/test_login.py` with 14 test cases

**Files Modified:**
- `requirements.txt` (+1 line)
- `python/helpers/login.py` (+24 lines)
- `run_ui.py` (+61 lines)
- `tests/test_login.py` (new file, 116 lines)

**Verification:**
- All 231 tests pass
- No regressions

## Patterns & Conventions

### Authentication
- Use bcrypt for password hashing (rounds=12)
- Always use `login.verify_password()` for verification
- Rate limit login attempts: 5 per minute per IP

### Testing
- pytest for unit tests
- Test files in `tests/` directory
- Follow naming: `test_*.py`

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Weak password hashing | Use bcrypt, not SHA256 |
| No rate limiting | Add IP-based rate limiter |
| Timing attacks | Use constant-time comparison |

## Proactive Scan Findings (2026-02-25)

### Security - ✅ No Critical Issues
- Previous simple_eval() RCE vulnerability fixed with secure AST-based implementation
- No SQL injection found (no raw SQL queries)
- No hardcoded secrets in Python files
- Path traversal protection implemented in file_browser.py

### Testing Gaps - ⚠️ Critical
- Only 13 test files for 228 Python backend files (~5% coverage)
- Critical untested modules:
   - secrets.py (549 lines) - Secret credential management
   - crypto.py (71 lines) - RSA encryption, HMAC hashing
   - files.py (556 lines) - Core file I/O operations
   - settings.py (1748 lines) - Complexity hotspot
   - task_scheduler.py (1284 lines) - Scheduled tasks
   - mcp_handler.py (1109 lines) - MCP server/client

### Code Quality - ⚠️ 22 Bare Exception Handlers Remain
- 22 `except Exception:` handlers still without `as e` in python/ and extensions/
- Priority files to fix next:
   - mcp_server.py
   - vector_db.py
   - files.py
