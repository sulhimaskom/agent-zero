# P1: Security Hardening - Docker SSH Configuration

**Priority:** P1  
**Category:** security  
**Impact:** HIGH - SSH root access is security risk

## Current State
- **SSH root enabled in Docker** (enabled by default)
- `prepare.py` generates random root password
- Production security concern

## Evidence
```dockerfile
# Docker configuration
RUN echo 'root:password' | chpasswd  # or similar
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
```

```python
# prepare.py
# Automatic SSH password generation
```

## Why This Matters
- **Production security risk**
- Container escape vectors
- Unnecessary attack surface
- Violates principle of least privilege

## Acceptance Criteria
- [ ] Disable SSH root login in production Docker image
- [ ] Use non-root user for application
- [ ] Document SSH configuration for development vs production
- [ ] Review prepare.py password generation
- [ ] Add security documentation to docs/

## Implementation Strategy
1. **Phase 1:** Create non-root user in Dockerfile
2. **Phase 2:** Disable root SSH in production variant
3. **Phase 3:** Update prepare.py to use key-based auth
4. **Phase 4:** Document security best practices

## Files to Modify
- `docker/Dockerfile` or `docker/run/Dockerfile`
- `prepare.py`
- `docs/security.md` (create)

## References
- Docker security best practices
- OWASP container security guidelines
- CIS Docker Benchmark

---
*Generated from Audit Report 2026-02-18*
