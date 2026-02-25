# Technical Writer Agent - Long-time Memory

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
| tunnel.md | ~70 | Tunnel setup |

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
