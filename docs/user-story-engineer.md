# User Story Engineer Agent - Long-time Memory

## Repository: agent-zero

> Last Updated: 2026-03-03

---

## Scan Results Summary

### Exploration Findings (2026-03-03)

**Last Updated:** 2026-03-03

#### 1. Dead Code Cleanup - JavaScript Files
- Removed dead commented-out code from `webui/index.js` (14 lines)
- Removed dead commented-out code from `webui/js/messages.js` (6 lines)
- Total: 24 lines of dead code removed
- ✅ COMPLETED (PR #657)

---

### Previous Findings (2026-02-27)

#### 1. JavaScript Dead Code - settings.js
- Removed commented-out dead code in `webui/js/settings.js` (lines 309-323)
- Removed two commented-out blocks:
  - `initSettingsModal()` function
  - `document.addEventListener('alpine:init', ...)` block

#### 2. JavaScript console.log Debugging Remnants
- Investigated Issue #400 about console.log in 78 non-vendor files
- Found only 2 non-vendor files with relevant console.log:
  - `webui/components/chat/speech/speech-store.js` - 9 occurrences (status messages, not pure debugging)
  - `webui/js/settings.js` - 1 commented console.log (included in dead code removal above)
- Most matches are in vendor files (ace-min, katex, transformers) - NOT modifying vendor files

#### 3. Test Coverage - crypto.py
- Added comprehensive test suite for `python/helpers/crypto.py` (71 lines)
- 28 tests covering: hash_data, verify_data, key generation, encrypt_data, decrypt_data
- ✅ COMPLETED (PR #432)

---

### Previous Findings (2026-02-26)

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

#### 2. Test Coverage Gaps
Small modules (< 100 lines) without tests:
- ~~`rate_limiter.py` (66 lines)~~ ✅ COMPLETED (PR #443)
- ~~`errors.py` (73 lines)~~ ✅ COMPLETED
- ~~`wait.py` (71 lines)~~ ✅ COMPLETED
- ~~`crypto.py` (71 lines)~~ ✅ COMPLETED (PR #432)
- ~~`guids.py` (6 lines)~~ ✅ FIXED (PR #346)
- ~~`timed_input.py` (21 lines)~~ ✅ FIXED (PR #281)

#### 3. Dead Code
- ~~`webui/js/timeout.js` - Entire file commented out~~ ✅ FIXED (PR #579)
- ~~`python/helpers/timed_input.py:16-17`~~ ✅ FIXED (PR #281)

#### 4. Config Issues
- ~~`conf/model_providers.yaml:22` - Duplicate env var name typo~~ ✅ FIXED (PR #358)

---

## Quick Wins (Completed)

1. ~~**Fix bare excepts in tunnel_manager.py**~~ ✅ COMPLETED
2. ~~**Add test for rate_limiter.py**~~ ✅ COMPLETED (PR #443)
3. ~~**Remove dead code in timed_input.py**~~ ✅ COMPLETED (PR #281)
4. ~~**Fix config typo in model_providers.yaml**~~ ✅ COMPLETED (PR #358)
5. ~~**Add test for crypto.py**~~ ✅ COMPLETED (PR #432)
6. ~~**Add test for images.py**~~ ✅ COMPLETED (PR #477)
7. ~~**Add test for update_check.py, duckduckgo_search.py, playwright.py**~~ ✅ COMPLETED (PR #541)
8. ~~**Remove dead code in timeout.js**~~ ✅ COMPLETED (PR #579)
9. ~~**Add test for rfc_exchange.py**~~ ✅ COMPLETED (PR #602)
10. ~~**Add test for messages.py**~~ ✅ COMPLETED
11. ~~**Remove dead commented-out code in index.js and messages.js**~~ ✅ COMPLETED (PR #657)

---

## Pending Modules (no tests)

Small modules still needing test coverage:
- `job_loop.py` (70 lines) - Already has tests ✅
- `shell_local.py` (51 lines) - Already has tests ✅
- `tunnel_manager.py` (84 lines) - Already has tests ✅

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
