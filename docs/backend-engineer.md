#QH|# Backend Engineer Agent Memory
#KM|
#PQ|**Last Updated:** 2026-02-25
#RW|
#WV|## Domain Focus
#HR|- Python backend (Flask API)
#WS|- Authentication and security
#XN|- Performance optimization
#JP|- API endpoints
#SK|
#TV|#QM|## Completed Fixes
#XH|#TX|
#HY|#XW|### Issue #290: Bare Exception Handlers in memory.py and task_scheduler.py
#QT|#XV|**Status:** FIXED
#NM|#RJ|
#RW|#MN|**Changes:**
#QN|#SN|1. Fixed bare `except Exception:` in `python/helpers/memory.py` line 137
#TM|2. Fixed bare `except Exception:` in `python/helpers/task_scheduler.py` line 937
#RN|3. Both now capture exception variable `as e` for debugging
#HS|
#WW|#XZ|**Files Modified:**
#RH|#NH|- `python/helpers/memory.py` (+1 line)
#VM|#YB|- `python/helpers/task_scheduler.py` (+2 lines)
#HY|
#ZK|**Verification:**
#RS|#YB|- All 231 tests pass
#XP|#HV|- Python syntax verified
#KS|#JQ|
#QB|#HV|### Issue #255: Node.js eval RCE Risk in docker/node_eval.js

**Last Updated:** 2026-02-25

## Domain Focus
- Python backend (Flask API)
- Authentication and security
- Performance optimization
- API endpoints

#QM|## Completed Fixes
#TX|
#XW|### Issue #255: Node.js eval RCE Risk in docker/node_eval.js
#XV|**Status:** FIXED
#RJ|
#MN|**Changes:**
#SN|1. Replaced unsafe `eval()` with `vm.runInNewContext()` for true sandboxing
#TM|2. Removed dangerous globals from user context: process, Buffer, require, module, exports
#RN|3. Added 30-second timeout to prevent infinite loops
#HS|4. Added input validation for code parameter
#XZ|5. Created safe globals whitelist: console, Math, JSON, Date, Array, Object, Promise, etc.
#NH|
#YB|**Files Modified:**
#ZK|   - `docker/run/fs/exe/node_eval.js` (complete rewrite - 125 lines)
#YB|
#HV|**Verification:**
#JQ|   - Syntax check: PASS
#QY|   - Basic execution (1+1, Math.random(), JSON.stringify): PASS
#XJ|   - Dangerous globals blocked (process, require, Buffer): ReferenceError as expected
#MV|   - Async/await: PASS
#HN|
#HV|### Issue #238: Weak Authentication Hashing - SHA256 Without Salt
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

#KK|| Timing attacks | Use constant-time comparison |
#XB|
#HV|## Proactive Scan Findings (2026-02-25)
#RB|
#NW|### Security - ✅ No Critical Issues
#QW|- Previous simple_eval() RCE vulnerability fixed with secure AST-based implementation
#HT|- No SQL injection found (no raw SQL queries)
#MM|- No hardcoded secrets in Python files
#KP|- Path traversal protection implemented in file_browser.py
#PZ|
#MX|### Testing Gaps - ⚠️ Critical
#WW|- Only 13 test files for 228 Python backend files (~5% coverage)
#YH|- Critical untested modules:
#NZ|   - secrets.py (549 lines) - Secret credential management
#HZ|   - crypto.py (71 lines) - RSA encryption, HMAC hashing
#PZ|   - files.py (556 lines) - Core file I/O operations
#QB|   - settings.py (1748 lines) - Complexity hotspot
#RX|   - task_scheduler.py (1284 lines) - Scheduled tasks
#NM|   - mcp_handler.py (1109 lines) - MCP server/client
#YQ|
#WR|### Code Quality - ⚠️ 26 Bare Exception Handlers Remain
#QT|- 26 `except Exception:` handlers still without `as e` in python/helpers/
#XZ|- Priority files to fix next:
#YB|   - tunnel_manager.py (3 handlers)
#HV|   - fasta2a_server.py (2 handlers)
#NM|   - fasta2a_client.py (2 handlers)