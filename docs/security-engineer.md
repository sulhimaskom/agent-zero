# Security Engineer Agent Documentation

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

## 2026-02-25: Proactive Security Scan

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
- ~~Issue #238: Weak password hashing~~ → **FIXED (Issue #266)**
