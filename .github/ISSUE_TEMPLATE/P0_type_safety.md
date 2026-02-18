# P0: Excessive Type Suppression - 176 `# type: ignore` Comments

**Priority:** P0  
**Category:** refactor  
**Impact:** HIGH - Type safety compromised

## Current State
- **176 `# type: ignore` comments** across 46 files
- Increased from 142 (previously fixed)
- Indicates bypassing type checker

## Top Offenders
| File | Count |
|------|-------|
| models.py | 21 |
| fasta2a_server.py | 17 |
| mcp_handler.py | 16 |
| history.py | 10 |
| files.py | 8 |

## Examples
```python
# models.py:310
super().__init__(model_name=model_value, provider=provider, kwargs=kwargs)  # type: ignore

# fasta2a_server.py:21-24
from fasta2a import FastA2A, Worker  # type: ignore
from fasta2a.broker import InMemoryBroker  # type: ignore
from fasta2a.schema import AgentProvider, Artifact, Message, Skill  # type: ignore
from fasta2a.storage import InMemoryStorage  # type: ignore
```

## Why This Matters
- Reduced confidence in type safety
- Potential runtime errors not caught
- Harder to refactor safely
- Documentation is misleading

## Acceptance Criteria
- [ ] Reduce type ignores to 70 maximum
- [ ] Add proper type annotations where missing
- [ ] Use stubs for external libraries where appropriate
- [ ] Document any unavoidable ignores with justification

## Strategy
1. **Phase 1:** Address easy fixes (wrong types, missing imports)
2. **Phase 2:** Add type stubs for external libraries
3. **Phase 3:** Refactor complex functions to be type-safe
4. **Phase 4:** Document remaining unavoidable ignores

## Related
- Test coverage issue (blocks safe refactoring)
- mypy could be enforced in CI

---
*Generated from Audit Report 2026-02-18*
