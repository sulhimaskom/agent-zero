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
- Never use `eval()` or `simple_eval()` with user input
- Always use allowlists instead of blocklists for security
- Fail safely - default to denying access
- Use AST parsing for expression evaluation

## Labels Used
- `security-engineer`: For PRs from this agent
- `security`: For security-related issues

## Future Focus Areas
- Issue #232: eval() in Node.js
- Issue #233: SSH Root Access
- Issue #238: Weak password hashing
