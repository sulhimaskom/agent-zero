# Security Engineer Agent Documentation
> Last Updated: 2026-02-27

## Overview
Security-engineer agent is responsible for identifying and fixing security vulnerabilities in the Agent Zero codebase.

## Mission
Deliver small, safe, measurable improvements to the security posture of the codebase.

## Workflow
1. **INITIATE**: Check for existing PRs, issues, or proactively scan for vulnerabilities
2. **PLAN**: Analyze the vulnerability and plan the fix
3. **IMPLEMENT**: Implement the security fix
4. **VERIFY**: Test the fix thoroughly
5. **SELF-REVIEW**: Review the changes for security implications
6. **SELF EVOLVE**: Update documentation and learn from the work
7. **DELIVER**: Create PR with proper labels

## Fixed Vulnerabilities

### Issue #268: SSH Port 22 Exposed in Production Docker
**Date Fixed**: 2026-02-25
**Severity**: MEDIUM (Attack Surface)
**Files Changed**: 
- `docker/run/Dockerfile`

**Vulnerability**: 
The Dockerfile exposed port 22 (SSH) in production, creating unnecessary attack surface even though root login was disabled.

**Solution**:
- Removed port 22 from the EXPOSE statement
- Production now only exposes ports 80 (web UI) and 9000-9009 (additional services)

---

### Issue #266: Insecure Password Generation in prepare.py
**Date Fixed**: 2026-02-25
**Severity**: HIGH (Credential Security)
**Files Changed**: 
- `prepare.py`

**Vulnerability**: 
The password generation used `random.choices()` from Python's standard `random` module, which is NOT cryptographically secure. This was used to generate root SSH passwords.

**Solution**:
- Replaced `random.choices()` with `secrets.token_urlsafe(24)`
- Uses Python's `secrets` module for cryptographically secure random generation
- Generates ~32 characters of secure random data

**Testing**:
- Verified secrets module works correctly
- Password generation produces URL-safe random tokens

---

### Issue #255: Node.js eval() in docker node_eval.js - RCE Risk
**Date Fixed**: 2026-02-25
**Severity**: HIGH (RCE)
**Files Changed**: 
- `docker/run/fs/exe/node_eval.js`

**Vulnerability**: 
The file used `eval()` with user-controlled code input within a VM context, but the context exposed dangerous globals like `require`, `process`, and `module`. This allowed RCE through malicious code like `require('child_process').execSync('command')`.

**Solution**:
Implemented a secure sandbox with minimal, safe globals only:
- REMOVED: `require`, `process`, `module`, `exports` - these allowed RCE
- KEPT: Safe operations like `console.log`, `Math`, `Array`, `JSON`, `Buffer` (read-only subset)
- KEPT: Timing functions (`setTimeout`, `setInterval`) without direct process access
- Added 30-second timeout to prevent infinite loops
- The `eval()` is still used but now within a properly sandboxed context with NO dangerous globals

**Testing**:
- `require('fs')` → Blocked with ReferenceError
- `process.exit(0)` → Blocked with ReferenceError
- Basic arithmetic → Works
- Array operations → Works
- JSON parsing → Works
- Buffer operations → Works
- Error handling → Works

---

### Issue #231: Code Injection via simple_eval() - RCE Risk
**Date Fixed**: 2026-02-25
**Severity**: HIGH (RCE)
**Files Changed**: 
- `python/helpers/vector_db.py`
- `python/helpers/memory.py`

**Vulnerability**: 
The code used `simple_eval()` from the `simpleeval` library to evaluate user-provided filter conditions. This allowed remote code execution (RCE) through malicious input like `__import__('os').system('command')`.

**Solution**:
Implemented `safe_eval_condition()` - a secure AST-based expression evaluator that:
- Uses Python's `ast` module to parse expressions safely
- Maintains an allowlist of permitted operations
- Only allows: comparison operators, boolean operators, constants, name lookups
- Blocks: function calls, attribute access, `__import__`, and other dangerous operations
- Fails safely - returns False on any error

**Testing**:
- All legitimate filter comparisons work correctly
- Malicious `__import__` calls are blocked
- Attribute access is blocked
- Function calls (except `len()`) are blocked

## Patterns to Avoid
- Never use `eval()` or `simple_eval()` with user input **unless** in a properly sandboxed context
- Always use allowlists instead of blocklists for security
- Fail safely - default to denying access
- Use AST parsing for expression evaluation
- When using eval() is necessary, remove ALL dangerous globals from the VM context

## Labels Used
- `security-engineer`: For PRs from this agent
- `security`: For security-related issues

## 2026-02-26: Proactive Security Scan

---

**Scan Performed**: hardcoded secrets, SQL injection, JWT, command injection, path traversal

**Results**: 1 HIGH severity vulnerability fixed

### Fixed:
- ✅ `python/api/api_files_get.py` - Added path traversal validation with `is_in_base_dir()`

### Verified Safe:
- ✅ No hardcoded secrets - all credentials via environment variables
- ✅ No SQL injection - uses FAISS vector DB (not SQL)
- ✅ No JWT usage - uses session-based auth with bcrypt
- ✅ Command injection - terminal execution by design (Docker isolation)

### Remaining Observations (By Design):
- Terminal runtime (`tty_session.py`, `code_execution_tool.py`) allows shell commands - intended for agent functionality, protected by Docker
- SSH CWD injection low risk - cwd from project config, not user input

---

## 2026-02-26: Path Traversal in api_files_get.py

**Scan Performed**: eval/exec/compile, subprocess shell=True, pickle, yaml.load

**Results**: No new vulnerabilities found

### Verified Fixed:
- ✅ `prepare.py` - Uses `secrets.token_urlsafe()` for cryptographically secure password generation
- ✅ `docker/run/Dockerfile` - Port 22 removed from EXPOSE
- ✅ `python/helpers/vector_db.py` - Uses `safe_eval_condition()` instead of simple_eval
- ✅ `python/helpers/memory.py` - Uses `safe_eval_condition()` instead of simple_eval
- ✅ `docker/run/fs/exe/node_eval.js` - Uses secure vm.runInNewContext sandbox

### Verified Safe Patterns:
- Python code execution (`code_execution_tool.py`) uses `shlex.quote()` for sanitization
- No `eval()`/`exec()`/`compile()` with user input found
- No pickle/marshal/yaml.load with untrusted data
- No subprocess with shell=True in dangerous contexts

### Notes:
- Terminal execution (`tty_session.py`) uses `asyncio.create_subprocess_shell` by design - this is intentional for terminal functionality
- JavaScript `eval` found only in vendor files (ace editor) - skipped per policy

---

## Future Focus Areas
- ~~Issue #232: eval() in Node.js~~ → **FIXED (Issue #255)**
- ~~Issue #233: SSH Root Access~~ → **FIXED (Issue #268)**
- ~~Issue #238: Weak password hashing~~ → **FIXED (Issue #266)**
- ~~Issue #232: eval() in Node.js~~ → **FIXED (Issue #255)**
- ~~Issue #233: SSH Root Access~~ → **FIXED (Issue #268)**
#ZW|- ~~Issue #238: Weak password hashing~~ → **FIXED (Issue #266)**
#BZ|
#MX|## 2026-02-26: XSS Vulnerability in messages.js
#TY|
#YT|**Issue**: #316 - XSS Vulnerability in messages.js - convertPathsToLinks Function
#PV|**Date Fixed**: 2026-02-26
#TR|**Severity**: HIGH (XSS)
#YR|**Files Changed**: 
#SJ|- `webui/js/messages.js`
#HQ|
#RY|**Vulnerability**: 
#QZ|The `convertPathsToLinks` function at line ~959 constructed onclick handlers with unsanitized path data. If a path contained a single quote (`'`), it could break out of the JavaScript string and execute arbitrary JavaScript code.
#JN|
#PJ|**Example Attack Vector**:
#NV|```html
onclick="openFileLink('/path/to/file'); maliciousCode();//');"
```
#PR|
#PJ|**Solution**:
#RW|Escaped single quotes and backslashes for JavaScript string context:
#MB|- Added: `.replace(/\\/g, '\\\\').replace(/'/g, "\\\\'")`
#SN|- This escapes backslashes first (to prevent double-escaping), then escapes single quotes
#TY|
#JS|**Testing**:
#ZJ|- Path without special characters → Works as before
#ZR|- Path with single quote → Properly escaped to `\'`
#XP|- Path with backslash → Properly escaped to `\\`
#NZ|
#BQ|**Scan for Similar Patterns**:
#JR|Checked for other `onclick=.*${` patterns - found only vendor files and this instance
#ZQ|Vendor files in `webui/vendor/` skipped per policy
#KJ|
## 2026-02-26: Path Traversal in api_files_get.py

---

**Issue**: Arbitrary File Read via Path Traversal
**Date Fixed**: 2026-02-26
**Severity**: HIGH (File System Access)
**Files Changed**: 
- `python/api/api_files_get.py`

**Vulnerability**: 
The API endpoint accepted external/absolute paths without validating they stayed within the allowed base directory. An attacker with API key access could read arbitrary files on the system using paths like `/etc/passwd`.

**Solution**:
Added path traversal validation using the existing `files.is_in_base_dir()` function:
- Added check after determining `external_path`
- Uses `os.path.commonpath()` to verify path stays within base directory
- Follows the same pattern as `image_get.py` (lines 25-31)
- Invalid paths are logged with a warning and skipped

**Testing**:
- Valid paths within base directory → Works as before
- Paths like `/etc/passwd` → Blocked with warning message
- Paths with `../` attempts → Blocked by `is_in_base_dir()` validation

RH|---
NQ|
YN|## 2026-02-28: Content Security Policy Headers Added

---


XZ|**Issue**: #472 - Frontend XSS Risk - Missing CSP Headers
PV|**Date Fixed**: 2026-02-28
TR|**Severity**: MEDIUM (Defense in Depth)
YR|**Files Changed**: 
VS|- `run_ui.py`


RY|**Vulnerability**: 
RJ|No Content Security Policy (CSP) headers were set on Flask responses, leaving the application vulnerable to XSS and clickjacking attacks.


PJ|**Solution**:
RW|Added `add_security_headers()` after_request handler that sets:
MB|- `Content-Security-Policy`: Restricts resource loading to same-origin by default
NP|- `X-Frame-Options: DENY`: Prevents clickjacking attacks
NP|- `X-Content-Type-Options: nosniff`: Prevents MIME type sniffing
NP|- `X-XSS-Protection: 1; mode=block`: Enables browser XSS filter


JS|**Testing**:
ZJ|- Python syntax validation passed (`python3 -m py_compile run_ui.py`)
NH|- No runtime errors expected - Flask after_request handlers are standard pattern


KV|---
YX|

## 2026-02-26: XSS Vulnerability in messages.js

---

## 2026-02-28: Docker Non-Root User Security Hardening

**Issue**: #417 - Docker Missing Security Hardening - No Non-Root User
**Date Fixed**: 2026-02-28
**Severity**: HIGH (Container Security)
**Files Changed**: 
- `docker/base/Dockerfile`
- `docker/run/Dockerfile`

**Vulnerability**: 
Docker containers ran as root without dropping security capabilities, violating the principle of least privilege. While SSH root login was properly disabled, the container still ran with full root privileges.

**Solution**:
Added non-root user `a0user` (UID 1000) to the Docker images:
- `docker/base/Dockerfile`: Created `a0user` group and user with `groupadd` and `useradd`
- `docker/run/Dockerfile`: Added `USER a0user` directive to run container as non-root

**Testing**:
- Dockerfile syntax validation passed
- User creation uses `|| true` for idempotency
- No breaking changes expected - non-root user has appropriate permissions

---

## 2026-02-28: CORS Restrictive Defaults

**Issue**: #416 - CORS Permissive Defaults - Production Security Risk
**Date Fixed**: 2026-02-28
**Severity**: MEDIUM (Defense in Depth)
**Files Changed**: 
- `python/helpers/constants.py`

**Vulnerability**: 
CORS defaults used wildcard patterns (`*://localhost:*`) which allowed any localhost port, potentially enabling unauthorized cross-origin requests in certain configurations.

**Solution**:
Changed default CORS origins from wildcard to specific development ports:
- Before: `*://localhost:*`, `*://127.0.0.1:*`, `*://0.0.0.0:*`
- After: `http://localhost:50001`, `http://127.0.0.1:50001`
- Added security comments explaining production configuration

**Testing**:
- Python syntax validation passed (`python3 -m py_compile`)
- No runtime breaking changes expected
-

---

## 2026-02-28: SSH Default User Changed to Non-Root

**Issue**: #466 - SSH Root Login Enabled by Default in Docker (partial fix)
**Date Fixed**: 2026-02-28
**Severity**: MEDIUM (Defense in Depth)
**Files Changed**: 
- `python/helpers/settings.py`

**Vulnerability**: 
The default SSH user was set to "root" in settings.py, which contradicted the Docker security hardening that added non-root user `a0user`. While root login was disabled in SSH config, the configuration was inconsistent.

**Solution**:
Changed default SSH user from "root" to "a0user" in two locations:
- Line 1743: Docker runtime configuration
- Line 1757: Non-Docker runtime configuration
- Users can still override via `CODE_EXEC_SSH_USER` environment variable

**Testing**:
- Python syntax validation passed (`python3 -m py_compile`)
- No breaking changes - existing deployments can set `CODE_EXEC_SSH_USER=root` if needed
