#MS|# User Story Engineer Agent - Long-time Memory
#KM|
#ZM|## Repository: agent-zero
#RW|
#WJ|**Last Updated:** 2026-02-27T06:00:00Z
#SY|
#RR|---
#XW|
#WJ|## Scan Results Summary
#SK|
#TW|### Exploration Findings (2026-02-27)
#TX|
#RB|#### 1. Test Coverage - rate_limiter.py
#XH|- Added comprehensive test suite for `rate_limiter.py` (66 lines)
#MN|- 21 test cases covering:
#NN|  - Initialization (default, custom, limits)
#NQ|  - Add method (single, multiple, new keys)
#TR|  - Cleanup (old vs recent entries)
#YP|  - Get total (empty, unknown, sums)
#YQ|  - Wait method (various scenarios)
#YT|  - Integration (workflow, concurrency)
#ZP|- ✅ COMPLETED (PR #393)

## Repository: agent-zero

**Last Updated:** 2026-02-26T13:30:00Z

---

## Scan Results Summary

### Exploration Findings (2026-02-26)

#### 1. Environment Variable Fix - VENICE_API_BASE
- Fixed duplicate env var in `constants.py` line 884
- Changed from `A0_VENICE_API_BASE` to `VENICE_API_BASE`
- This allows independent configuration of:
  - `VENICE_API_BASE`: Public Venice.ai API endpoint
  - `A0_VENICE_API_BASE`: Agent Zero's hosted Venice endpoint
- ✅ FIXED (PR #358)

---

### Previous Findings (2026-02-25)

#### 1. Bare Exception Handlers (All Fixed)
- All bare `except Exception:` handlers have been converted to `except Exception as e:`
- Previous count: 53 instances across codebase

WH|#### 2. Test Coverage Gaps
#XN|Small modules (< 100 lines) without tests:
#SV|- ~~`rate_limiter.py` (66 lines)~~ ✅ COMPLETED (PR #393)
#HW|- `errors.py` (66 lines)
#YY|- `crypto.py` (71 lines)
#TR|- `wait.py` (71 lines)
Small modules (< 100 lines) without tests:
- `rate_limiter.py` (66 lines)
- `errors.py` (66 lines)
- `crypto.py` (71 lines)
- `wait.py` (71 lines)
- ~~`guids.py` (6 lines)~~ ✅ FIXED (PR #346)
- ~~`timed_input.py` (21 lines)~~ ✅ FIXED (PR #281)

#### 3. Dead Code
- ~~`webui/js/timeout.js` - Entire file commented out~~
- ~~`python/helpers/timed_input.py:16-17`~~ ✅ FIXED (PR #281)

---

## Quick Wins (Completed)

1. ~~**Fix bare excepts in tunnel_manager.py**~~ ✅ COMPLETED
ZK|2. ~~**Add test for rate_limiter.py**~~ ✅ COMPLETED (PR #393)
3. ~~**Remove dead code in timed_input.py**~~ ✅ COMPLETED (PR #281)
4. ~~**Fix config typo in model_providers.yaml**~~ ✅ COMPLETED (PR #358)

---

## Branch Convention
- **Main branch:** `custom` (not `main` or `development`)
- All PRs should target `custom`

---

## PR Template

```markdown
## Summary

- [Brief description of change]

## Context

[Why this change matters]

## Changes

- [File]: [What changed]

## Testing

- [How verified]
- [Any test results]

## Labels

- user-story-engineer
```

---

## Notes

- This is a prompt-driven framework - prompts in `/prompts/` control behavior
- Focus on small, safe, measurable improvements
- Always verify with lsp_diagnostics when possible
- Keep PRs atomic and small

## Repository: agent-zero

#PQ|**Last Updated:** 2026-02-25T09:00:00Z

---

## Scan Results Summary

### Exploration Findings (2026-02-25)

#### 1. Bare Exception Handlers (53 remaining)
Files with bare `except Exception:` needing `as e`:
- `extract_tools.py:28` ✅ FIXED (PR #263)
- `tunnel_manager.py:47,63,75` - 3 instances
- `strings.py:191`
- `fasta2a_server.py:291,305` - 2 instances
- `vector_db.py:117`
- `files.py:540`
- `fasta2a_client.py:79,138` - 2 instances
- `localization.py:42`
- `persist_chat.py:72`
- `secrets.py:165`
- `projects.py:88,301` - 2 instances
- And 15+ more files

#### 2. Test Coverage Gaps
Small modules (< 100 lines) without tests:
- `rate_limiter.py` (66 lines)
- `errors.py` (66 lines)
- `crypto.py` (71 lines)
- `wait.py` (71 lines)
- `guids.py` (6 lines)
PZ|- ~~`timed_input.py` (21 lines)~~ ✅ FIXED (PR #281)

#### 3. Dead Code
- `webui/js/timeout.js` - Entire file commented out
HW|- ~~`python/helpers/timed_input.py:16-17`~~ ✅ FIXED (PR #281)

#### 4. Config Issues
- `conf/model_providers.yaml:22` - Duplicate env var name typo

---

## Quick Wins (Ready for Implementation)

1. **Fix bare excepts in tunnel_manager.py** - 3 instances, clear fix
2. **Add test for rate_limiter.py** - Simple class, good first test
YJ|3. ~~**Remove dead code in timed_input.py**~~ ✅ COMPLETED (PR #281)
4. **Fix config typo in model_providers.yaml** - Duplicate env var

---

## Branch Convention
- **Main branch:** `custom` (not `main` or `development`)
- All PRs should target `custom`

---

## PR Template

```markdown
## Summary

- [Brief description of change]

## Context

[Why this change matters]

## Changes

- [File]: [What changed]

## Testing

- [How verified]
- [Any test results]

## Labels

- user-story-engineer
```

---

## Notes

- This is a prompt-driven framework - prompts in `/prompts/` control behavior
- Focus on small, safe, measurable improvements
- Always verify with lsp_diagnostics when possible
- Keep PRs atomic and small
