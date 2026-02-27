# Security Engineer Agent Documentation

**Last Updated:** 2026-02-27

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

## 2026-02-26: XSS Vulnerability in messages.js

**Issue**: #316 - XSS Vulnerability in messages.js - convertPathsToLinks Function
**Date Fixed**: 2026-02-26
**Severity**: HIGH (XSS)
**Files Changed**: 
- `webui/js/messages.js`

**Vulnerability**: 
The `convertPathsToLinks` function at line ~959 constructed onclick handlers with unsanitized path data. If a path contained a single quote (`'`), it could break out of the JavaScript string and execute arbitrary JavaScript code.

**Example Attack Vector**:
```html
onclick="openFileLink('/path/to/file'); maliciousCode();//');"
```

**Solution**:
Escaped single quotes and backslashes for JavaScript string context:
- Added: `.replace(/\\/g, '\\\\').replace(/'/g, "\\'")`
- This escapes backslashes first (to prevent double-escaping), then escapes single quotes

**Testing**:
- Path without special characters → Works as before
- Path with single quote → Properly escaped to `\'`
- Path with backslash → Properly escaped to `\\`

**Scan for Similar Patterns**:
Checked for other `onclick=.*${` patterns - found only vendor files and this instance
Vendor files in `webui/vendor/` skipped per policy

---

## 2026-02-27: Command Injection in brocula_loop.py

---

**Issue**: Command Injection via shell=True with f-strings
**Date Fixed**: 2026-02-27
**Severity**: HIGH (Command Injection)
**Files Changed**: 
- `agents/brocula/brocula_loop.py`

**Vulnerability**: 
The `run_command()` function used `shell=True` with f-string commands, allowing command injection. Variables like `target_url` and `chrome_flags` were directly inserted into shell commands.

**Solution**:
Replaced `shell=True` with `shell=False` and used `shlex.split()` to parse commands:
- Changed `subprocess.run(cmd, shell=True, ...)` to `subprocess.run(cmd_list, shell=False, ...)`
- Used `shlex.split()` to safely parse command strings into list format
- Added error handling for malformed commands
- Maintains compatibility while preventing shell injection attacks

**Testing**:
- `which` commands → Work as before
- Lighthouse command → Works with list-formatted arguments
- Git commands → Work with shlex.split()

---

## 2026-02-27: Path Traversal in file_info.py and download_work_dir_file.py

---

**Issue**: Path Traversal in file info and download endpoints
**Date Fixed**: 2026-02-27
**Severity**: HIGH (File System Access)
**Files Changed**: 
- `python/api/file_info.py`
- `python/api/download_work_dir_file.py`

**Vulnerability**: 
These API endpoints accepted user-controlled paths without validating they stayed within the allowed base directory. An attacker could use path traversal (e.g., `../../etc/passwd`) to access files outside the work directory.

**Solution**:
Added path traversal validation using the existing `files.is_in_base_dir()` function:
- Added validation check in `file_info.py` before calling `get_file_info()`
- Added validation check in `download_work_dir_file.py` before processing file download
- Returns error message if path is outside allowed directory
- Follows the same pattern as `api_files_get.py` and `image_get.py`

**Testing**:
- Valid paths within base directory → Works as before
- Paths like `../../../etc/passwd` → Blocked with "Access denied" message
- Absolute paths outside work directory → Blocked with "Access denied" message

---

## Future Focus Areas
- ~~Issue #232: eval() in Node.js~~ → **FIXED (Issue #255)**
- ~~Issue #233: SSH Root Access~~ → **FIXED (Issue #268)**
- ~~Issue #238: Weak password hashing~~ → **FIXED (Issue #266)**
