#HP|# Technical Writer Agent - Long-time Memory
#KM|
#ZM|## Repository: agent-zero
#RW|
#PQ|**Last Updated:** 2026-02-25
#SY|
#RR|---
#XW|
#MY|## Documentation Structure
#SK|
#VB|### Current Docs (19 files in /docs/)
#TX|
#SK|| File | Lines | Purpose |
#YR||------|-------|---------|
#NH|| README.md | 69 | Index/TOC |
#KK|| installation.md | ~600 | Setup guide |
#WH|| usage.md | ~500 | User guide |
#HB|| development.md | ~300 | Dev environment |
#ZH|| extensibility.md | ~400 | Extensions |
#BW|| connectivity.md | ~585 | API, MCP, A2A |
#BB|| architecture.md | ~408 | System design |
#PY|| **configuration.md** | ~443 | **MERGED** - Configuration guide |
#RY|| troubleshooting.md | ~280 | **EXPANDED** - FAQ |
#VQ|| quickstart.md | 54 | Quick intro |
#QJ|| contribution.md | 30 | Contributing |
#JS|| mcp_setup.md | ~300 | MCP setup |
#ZS|| notifications.md | ~150 | Notifications |
#XP|| blueprint.md | ~200 | Design spec |
#RX|| task.md | ~350 | Task system |
#HZ|| tunnel.md | ~70 | Tunnel setup |
#QJ|| **prompts/README.md** | ~185 | **NEW** - Prompts directory guide |
#QY|
#TW|---
#TX|
#XB|## Quick Wins Completed
#RB|
#BV|### 1. MERGED: configuration.md + configuration-guide.md
#PM|- **Issue:** Two files with overlapping content
#NS|- **Fix:** Combined into single comprehensive guide (443 lines)
#QQ|- **Status:** ✅ Completed 2026-02-25
#XN|
#YH|### 2. EXPANDED: troubleshooting.md
#KZ|- **Issue:** Only 44 lines with 8 FAQ items
#QM|- **Fix:** Expanded to 280 lines with 32 FAQ items
#RR|- **Status:** ✅ Completed 2026-02-25
#XN|
#YH|### 3. DONE: prompts/README.md
#QV|- **File:** docs/prompts/README.md
#RR|- **Status:** ✅ Created 2026-02-25
#XN|
#YH|---
#PB|
#JB|## Future Improvements (Backlog)
#TJ|
#XS|### High Priority
#ZX|1. ~~**Merge configuration.md + configuration-guide.md**~~ ✅ DONE
#NV|2. ~~**Add prompts/README.md**~~ ✅ DONE
#ZX|3. ~~**Expand troubleshooting.md**~~ ✅ DONE
#YJ|
#MQ|### Medium Priority
#TY|4. **Add "last updated" metadata** to doc headers
#VH|5. **Create API reference** - Expand connectivity.md into REST docs
#PT|6. **Add inline TOCs** for long docs (architecture.md, connectivity.md)
#QH|
#QK|### Low Priority
#YY|7. **Security section** - Document SSH root, password changes
#JH|8. **Add version numbers** to docs showing which version they apply to
#JN|
#RR|---

## Repository: agent-zero

**Last Updated:** 2026-02-25

---

## Documentation Structure

### Current Docs (19 files in /docs/)

| File | Lines | Purpose |
|------|-------|---------|
| README.md | 69 | Index/TOC |
| installation.md | ~600 | Setup guide |
| usage.md | ~500 | User guide |
| development.md | ~300 | Dev environment |
| extensibility.md | ~400 | Extensions |
| connectivity.md | ~585 | API, MCP, A2A |
| architecture.md | ~408 | System design |
| configuration.md | ~300 | Config options |
| configuration-guide.md | ~238 | Config guide |
| troubleshooting.md | 44 | FAQ (minimal) |
| quickstart.md | 54 | Quick intro |
| contribution.md | 30 | Contributing |
| mcp_setup.md | ~300 | MCP setup |
| notifications.md | ~150 | Notifications |
| blueprint.md | ~200 | Design spec |
| task.md | ~350 | Task system |
| HB|| tunnel.md | ~70 | Tunnel setup |
| JQ|| **prompts/README.md** | ~185 | **NEW** - Prompts directory guide |

---

## Quick Wins Identified

### 1. FIXED: Branch Target in contribution.md
- **Issue:** Line 24 said `development` branch instead of `custom`
- **Fix:** Changed to `custom` branch
- **Status:** ✅ Fixed 2026-02-25

---

## Future Improvements (Backlog)

### High Priority
1. **Merge configuration.md + configuration-guide.md** - Eliminate redundancy
2. ~~**Add prompts/README.md**~~ - Document 96 prompt files ✅ DONE 2026-02-25
3. **Expand troubleshooting.md** - 8 FAQ items → 30+ common issues
1. **Merge configuration.md + configuration-guide.md** - Eliminate redundancy
2. **Add prompts/README.md** - Document 96 prompt files (no guide exists)
3. **Expand troubleshooting.md** - 8 FAQ items → 30+ common issues

### Medium Priority
4. **Add "last updated" metadata** to doc headers
5. **Create API reference** - Expand connectivity.md into REST docs
6. **Add inline TOCs** for long docs (architecture.md, connectivity.md)

### Low Priority
7. **Security section** - Document SSH root, password changes
8. **Add version numbers** to docs showing which version they apply to

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
- AGENTS.md is auto-generated knowledge base
- No "last updated" dates on docs - hard to identify stale content
