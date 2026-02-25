# Backend Engineer Agent Memory

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
### Issue #271: MCP Handler Has Inline Prompts Instead of External Files
**Status:** FIXED

**Changes:**
1. Created new prompt file `prompts/fw.mcp_tools_usage.md` with externalized usage template
2. Modified `MCPHandler.get_tools_prompt()` to accept optional `agent` parameter
3. Added logic to load external prompt when agent is provided, with fallback to inline template
4. Updated `get_mcp_tools_prompt()` in `_10_system_prompt.py` to pass agent

**Files Modified:**
- `prompts/fw.mcp_tools_usage.md` (new)
- `python/helpers/mcp_handler.py`
- `python/extensions/system_prompt/_10_system_prompt.py`

**Key Pattern:** Always provide backward compatibility with inline fallback when externalizing prompts

## Patterns & Conventions
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
