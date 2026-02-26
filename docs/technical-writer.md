# Technical Writer Agent - Long-time Memory

## Repository: agent-zero

**Last Updated:** 2026-02-26

---

## Documentation Structure

### Current Docs (20 files in /docs/)

| File | Lines | Purpose |
|------|-------|---------|
| README.md | 69 | Index/TOC |
| installation.md | ~441 | Setup guide (with inline TOC) |
| usage.md | ~366 | User guide (with inline TOC) |
| development.md | ~158 | Dev environment (with metadata) |
| extensibility.md | ~310 | Extensions (with metadata) |
| connectivity.md | ~598 | API, MCP, A2A (with inline TOC) |
| architecture.md | ~427 | System design (with inline TOC) |
| configuration.md | ~446 | Config guide (merged, with metadata) |
| troubleshooting.md | ~281 | FAQ (expanded, with metadata) |
| quickstart.md | 59 | Quick intro (with metadata) |
| contribution.md | 35 | Contributing (with metadata) |
| mcp_setup.md | ~148 | MCP setup (with metadata) |
| notifications.md | ~150 | Notifications |
| blueprint.md | ~200 | Design spec |
| task.md | ~350 | Task system |
| tunnel.md | 62 | Tunnel setup (with metadata) |
| prompts/README.md | ~185 | Prompts directory guide |
| **a2a_protocol.md** | 149 | **NEW** - A2A Protocol docs |

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

### 4. DONE: A2A Protocol Documentation
- **File:** docs/a2a_protocol.md
- **Issue:** #278 - Missing A2A Protocol Documentation
- **Status:** ✅ PR #306 ready to merge

### 5. DONE: connectivity.md inline TOC
- **File:** docs/connectivity.md
- **Issue:** 585-line doc without navigation aid
- **Fix:** Added inline Table of Contents linking to all 7 major sections
- **Status:** ✅ Completed 2026-02-26

### 6. DONE: architecture.md inline TOC
- **File:** docs/architecture.md
- **Issue:** 407-line doc without navigation aid
- **Fix:** Added inline Table of Contents linking to all 4 major sections and 14 subsections
- **Status:** ✅ Completed 2026-02-26

### 7. DONE: Add "Last Updated" metadata to key docs
- **Files:** docs/quickstart.md, docs/contribution.md, docs/tunnel.md
- **Issue:** No timestamp to identify when docs were last updated
- **Fix:** Added "> Last Updated: 2026-02-26" metadata to three key docs
- **Status:** ✅ Completed 2026-02-26

### 8. DONE: Extended "Last Updated" metadata to all user-facing docs
- **Files:** docs/installation.md, docs/usage.md, docs/development.md, docs/extensibility.md, docs/troubleshooting.md, docs/configuration.md, docs/connectivity.md, docs/architecture.md, docs/mcp_setup.md
- **Issue:** Key user-facing docs missing timestamp metadata
- **Fix:** Added "> Last Updated: 2026-02-26" metadata to 9 additional docs
- **Status:** ✅ Completed 2026-02-26

### 9. DONE: installation.md inline TOC
- **File:** docs/installation.md
- **Issue:** 439-line doc without navigation aid
- **Fix:** Added inline Table of Contents linking to all 6 major sections
- **Status:** ✅ Completed 2026-02-26

### 10. DONE: usage.md inline TOC
- **File:** docs/usage.md
- **Issue:** 364-line doc without navigation aid
- **Fix:** Added inline Table of Contents linking to all 7 major sections with subsections
- **Status:** ✅ Completed 2026-02-26

---

## Future Improvements (Backlog)

### High Priority
1. ~~**Merge configuration.md + configuration-guide.md**~~ ✅ DONE
2. ~~**Add prompts/README.md**~~ ✅ DONE
3. ~~**Expand troubleshooting.md**~~ ✅ DONE
4. ~~**Add A2A protocol documentation**~~ ✅ DONE (PR #306)

### Medium Priority
5. ~~**Add "last updated" metadata** to doc headers~~ ✅ All 12 user-facing docs now have metadata
   - quickstart.md, contribution.md, tunnel.md ✅
   - installation.md, usage.md, development.md, extensibility.md ✅
   - troubleshooting.md, configuration.md, connectivity.md, architecture.md, mcp_setup.md ✅
6. **Create API reference** - Expand connectivity.md into REST docs
7. ~~**Add inline TOCs** for long docs~~ ✅ architecture.md, connectivity.md, installation.md, usage.md done

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
- AGENTS.md is auto-generated knowledge base
- **PR Workflow:** Ensure PRs are rebased onto latest `custom` before merging
