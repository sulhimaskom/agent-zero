# Technical Writer Agent - Long-time Memory

**Last Updated:** 2026-02-25

---

## Documentation Structure

### Current Docs (28 files in /docs/)

| File | Lines | Purpose |
|------|-------|---------|
| README.md | 69 | Index/TOC |
| installation.md | ~439 | Setup guide |
| usage.md | ~500 | User guide |
| development.md | ~300 | Dev environment |
| extensibility.md | ~400 | Extensions |
| connectivity.md | ~585 | API, MCP, A2A |
| architecture.md | ~407 | System design |
| configuration.md | ~443 | **MERGED** - Configuration guide |
| troubleshooting.md | ~280 | **EXPANDED** - FAQ |
| quickstart.md | 54 | Quick intro |
| contribution.md | 30 | Contributing |
| mcp_setup.md | ~300 | MCP setup |
| notifications.md | ~150 | Notifications |
| blueprint.md | ~200 | Design spec |
| task.md | ~350 | Task system |
| tunnel.md | ~70 | Tunnel setup |
| prompts/README.md | ~185 | **NEW** - Prompts directory guide |

---

## Quick Wins Completed

### 1. MERGED: configuration.md + configuration-guide.md
- **Issue:** Two files with overlapping content
- **Fix:** Combined into single comprehensive guide (443 lines)
- **Status:** ✅ Completed 2026-02-25

### 2. EXPANDED: troubleshooting.md
- **Issue:** Only 44 lines with 8 FAQ items
- **Fix:** Expanded to 280 lines with 32 FAQ items
- **Status:** ✅ Completed 2026-02-25

### 3. DONE: prompts/README.md
- **File:** docs/prompts/README.md
- **Status:** ✅ Created 2026-02-25

### 4. FIXED: AGENTS.md outdated structure (issue #272)
- **Issue:** AGENTS.md generated 2026-01-13 with incorrect structure
- **Problem:** Claimed `default/tools/` exists but only `_context.md` present
- **Fix:** Rewrote with accurate structure for all 7 profiles
- **Changes:**
  - Date: 2026-01-13 → 2026-02-25
  - Commit: a99361d → f7d7f57
  - Added `_context.md` to profiles that have it
  - Added brocula.py, brocula_loop.py, reports/ to brocula
  - Fixed default/ structure (only has `_context.md`)
- **PR:** #303 - ✅ Created 2026-02-25
- **Status:** ✅ Completed 2026-02-25

---

## Future Improvements (Backlog)

### High Priority
1. ~~**Merge configuration.md + configuration-guide.md**~~ ✅ DONE
2. ~~**Add prompts/README.md**~~ ✅ DONE
3. ~~**Expand troubleshooting.md**~~ ✅ DONE
4. ~~**Update AGENTS.md**~~ ✅ DONE (issue #272)

### Medium Priority
5. **Add "last updated" metadata** to doc headers
6. **Create API reference** - Expand connectivity.md into REST docs
7. **Add inline TOCs** for long docs (architecture.md, connectivity.md)

### Low Priority
8. **Security section** - Document SSH root, password changes
9. **Add version numbers** to docs showing which version they apply to

---

## Patterns Used

### Doc Style
- Markdown format
- Use `[!TIP]` and `[!WARNING]` callouts
- Screenshots in `docs/res/`
- Relative links to other docs

### Branch Convention
- **Main branch:** `custom` (not `main` or `development`)
- All PRs should target `custom`

---

## Notes
- This is a prompt-driven framework - prompts in `/prompts/` control behavior
- Documentation is comprehensive but some areas need expansion
- AGENTS.md is auto-generated knowledge base - needs periodic updates
- No "last updated" dates on most docs - hard to identify stale content
- Issue #272 identified AGENTS.md was outdated - now fixed
