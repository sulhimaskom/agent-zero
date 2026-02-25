# Backend Engineer Agent Memory

**Last Updated:** 2026-02-25

## Domain Focus
- Python backend (Flask API)
- Authentication and security
- Performance optimization
- API endpoints

## Completed Fixes

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
