# Security Engineer Agent - Knowledge Base

**Created:** 2026-02-28
**Agent:** security-engineer (autonomous mode)

## Domain Scope

- Docker security hardening
- CORS/CSRF protection
- XSS prevention
- Authentication/authorization
- Input validation
- Secrets management

## Proactive Scan Focus Areas

### Docker Security
- [x] Non-root user in containers - **FIXED (PR #453)**
- [ ] Container capabilities dropping
- [ ] Read-only filesystems
- [ ] Resource limits (CPU/memory)
- [ ] Secrets management in containers

### Web Security
- [x] CORS validation - **SECURE (validate_ws_origin in python/helpers/websocket.py)**
- [ ] XSS prevention (innerHTML usage)
- [ ] CSRF protection
- [ ] Content Security Policy headers

### Authentication
- [ ] Session management
- [ ] Token storage
- [ ] Password handling
- [ ] API key protection

## Active Security Issues

### Issue #417: Docker Missing Security Hardening (HIGH)
- **Status:** Fixed in PR #453
- **Fix:** Added non-root user `agentzero` to Docker containers
- **Files:** `docker/base/Dockerfile`, `docker/run/Dockerfile`

### Issue #416: CORS Permissive Defaults (MEDIUM)
- **Status:** Already secure
- **Implementation:** `validate_ws_origin()` in `python/helpers/websocket.py`
- **Details:** Validates origin matches server host, rejects cross-origin requests

### Issue #421: XSS Risk from innerHTML Usage (MEDIUM)
- **Status:** Acknowledged, needs fix
- **Risk:** Multiple files use innerHTML without proper sanitization
- **Files:** `webui/js/messages.js`, `webui/js/modals.js`, etc.
- **Recommendation:** Add DOMPurify for HTML sanitization

## Security Patterns

### WebSocket Origin Validation
Location: `python/helpers/websocket.py`
- Validates HTTP_ORIGIN and HTTP_REFERER
- Checks against server host, forwarded headers
- Rejects cross-origin requests

### Secrets Handling
Location: `python/helpers/secrets.py`
- Environment variable based
- Masked in logs and UI
- Project-scoped isolation

## Common Vulnerabilities to Check

1. **Path traversal** - `../` in file paths
2. **SQL injection** - Unsanitized DB queries
3. **Command injection** - Unsanitized shell commands
4. **XXE** - XML external entities
5. **Insecure deserialization** - Pickle, YAML
6. **Hardcoded credentials** - Passwords in code

## Testing

- Run security scans: `trivy image agent0ai/agent-zero`
- Check for vulnerabilities: `npm audit`, `pip audit`
- Review CORS: Test cross-origin WebSocket connections
- XSS testing: Inject `<script>alert(1)</script>` in user inputs

## Notes

- WebUI content primarily from trusted LLM sources
- Markdown parsing via `marked` library (consider DOMPurify)
- WebSocket validation already implemented securely
