# Technical Writer Agent - Long-time Memory

## Repository: agent-zero

#RJ|> Last Updated: 2026-03-01

---

## Documentation Structure

### Current Docs (20 files in /docs/)

| File | Lines | Purpose |
|------|-------|---------|
| README.md | 69 | Index/TOC |
| installation.md | ~485 | Setup guide (with Security Best Practices) |
| usage.md | ~500 | User guide |
| development.md | ~300 | Dev environment |
| extensibility.md | ~400 | Extensions |
| connectivity.md | ~600 | API, MCP, A2A (with inline TOC) |
| architecture.md | ~408 | System design |
| configuration.md | ~443 | Config guide (merged) |
| troubleshooting.md | ~280 | FAQ (expanded) |
| quickstart.md | 57 | Quick intro (with metadata) |
| contribution.md | 33 | Contributing (with metadata) |
| mcp_setup.md | ~300 | MCP setup |
| notifications.md | ~150 | Notifications |
| blueprint.md | ~200 | Design spec |
| task.md | ~350 | Task system |
| tunnel.md | 60 | Tunnel setup (with metadata) |
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

### 8. DONE: Add "Last Updated" metadata to 9 key docs
- **Files:** docs/usage.md, docs/extensibility.md, docs/blueprint.md, docs/installation.md, docs/troubleshooting.md, docs/development.md, docs/mcp_setup.md, docs/notifications.md, docs/task.md
- **Issue:** Major user-facing docs without timestamps
- **Fix:** Added "> Last Updated: 2026-02-26" metadata to nine key docs
- **Status:** ✅ Completed 2026-02-26

### 9. DONE: Add inline TOC to 4 large docs
- **Files:** docs/usage.md, docs/extensibility.md, docs/blueprint.md, docs/installation.md
- **Issue:** Large docs without navigation aid
- **Fix:** Added inline Table of Contents to four large docs
- **Status:** ✅ Completed 2026-02-26

### 10. DONE: Add "Last Updated" metadata to 4 key docs
- **Files:** docs/connectivity.md, docs/architecture.md, docs/configuration.md, docs/README.md
- **Issue:** Key user-facing docs without timestamps
- **Fix:** Added "> Last Updated: 2026-02-26" metadata to four key docs
- **Status:** ✅ Completed 2026-02-26

### 11. DONE: Add "Last Updated" metadata to 10 agent docs
- **Files:** DX-engineer.md, Growth-Innovation-Strategist.md, Product-Architect.md, RnD.md, ai-agent-engineer.md, frontend-engineer.md, modular-configuration-analysis.md, platform-engineer.md, quality-assurance.md, security-engineer.md
- **Issue:** Agent documentation files missing timestamps
- **Fix:** Added "> Last Updated: 2026-02-27" to all 10 files
- **Status:** ✅ Completed 2026-02-27

### 12. DONE: Add Security Best Practices section
- **File:** docs/installation.md
- **Issue:** No consolidated security guidance for users
- **Fix:** Added new "Security Best Practices" section covering:
  - Authentication (UI credentials, strong passwords)
  - Network Exposure (SSH, reverse proxy, firewall)
  - API Keys and Secrets (secure handling, scoping, rotation)
  - Docker Security (non-root, updates)
- **Status:** ✅ Completed 2026-02-27

### 13. DONE: Fix inconsistent link in architecture.md
- **File:** docs/architecture.md
- **Issue:** Link text used path instead of readable name: `[docs/blueprint.md](./blueprint.md)`
- **Fix:** Changed to `[Blueprint](./blueprint.md)` for consistency
#WS|- **Status:** ✅ Completed 2026-02-27
#BJ|
### 14. DONE: Create Testing Guide (Issue #418)
- **File:** docs/testing.md
- **Issue:** #418 - Missing Testing Documentation - No Test Guide
- **Fix:** Created comprehensive testing guide covering:
  - Running tests (pytest commands)
  - Test structure and patterns (class-based)
  - Mock usage (conftest.py)
  - Async testing best practices
  - Test coverage priorities
  - Best practices (assertions, naming, docstrings)
#WS|- **Status:** ✅ Completed 2026-02-27
#VS|- **Also:** Added to docs/README.md index (quick links + TOC)
#XZ|
#SM|### 15. DONE: Standardize "Last Updated" metadata format
#XZ|- **Files:** a2a_protocol.md, security-engineer.md, DX-engineer.md, Product-Architect.md, Growth-Innovation-Strategist.md, backend-engineer.md, modular-configuration-analysis.md, ai-agent-engineer.md, quality-assurance.md, platform-engineer.md, frontend-engineer.md, ui-ux-engineer.md, RnD.md, user-story-engineer.md
#HB|- **Issue:** 14 files used non-standard `**Last Updated:**` (bold) format instead of `> Last Updated:` (blockquote)
#QM|- **Also:** user-story-engineer.md had 5 duplicate timestamps scattered throughout
#JK|- **Fix:** Converted all to standard `> Last Updated: YYYY-MM-DD` format and removed duplicates
#RQ|
#SM|### 16. DONE: Fix duplicate timestamps in RnD.md
#QM|- **File:** docs/RnD.md
#NM|- **Issue:** 3 duplicate `> Last Updated:` timestamps at lines 3, 58, 86, plus 4 decorative `**Last Updated:**` bold timestamps scattered throughout
#QB|- **Fix:** Removed all duplicate timestamps, keeping only the first one at line 3
#WS|- **Status:** ✅ Completed 2026-02-28
#XZ|
MB|#SM|### 17. DONE: Add "Last Updated" metadata to remaining docs
KJ|#QM|- **Files:** prompts/README.md, designs/backup-specification-backend.md, designs/backup-specification-frontend.md
BS|#NM|- **Issue:** 3 docs missing timestamps
NR|#QB|- **Fix:** Added `> Last Updated: 2026-02-28` to all three files
BR|#WS|- **Status:** ✅ Completed 2026-02-28
SY|#XZ|#NQ|
BP|#XV|-

### 18. DONE: API Documentation (Issue #474)
- **Issue:** #474 - No API documentation for Flask endpoints
- **Files Added:** docs/api.md (937 lines)
- **Files Updated:** python/api/ (17+ docstrings added)
- **Fix:** 
  - Added docstrings to 17+ API endpoints (message.py, message_async.py, chat_reset.py, chat_remove.py, chat_export.py, poll.py, csrf_token.py, upload.py, tunnel.py, pause.py, restart.py, knowledge_reindex.py, mcp_servers_status.py, notification_create.py)
  - Created comprehensive API reference in docs/api.md covering:
    - Overview (auth, base URL)
    - Chat & Messages (8 endpoints)
    - Settings (2 endpoints)
    - Files (4 endpoints)
    - Knowledge (2 endpoints)
    - Scheduler (4 endpoints)
    - MCP Servers (2 endpoints)
    - Backup (3 endpoints)
    - Notifications (4 endpoints)
    - Tunnel (1 endpoint)
    - Control (3 endpoints)
    - External API (5 endpoints)
    - Utility (3 endpoints)
  - Updated docs/README.md to include API reference link
#RQ|- **Status:** ✅ Completed 2026-02-28
#RT|
#MM|--- 

### 19. DONE: Fix duplicate TOC in usage.md
- **File:** docs/usage.md
- **Issue:** Duplicate "Basic Operations" entries in Table of Contents
- **Fix:** Removed 6 duplicate TOC lines
- **Status:** ✅ PR #526 created 2026-03-01
#XZ|
## Future Improvements (Backlog)

### High Priority
1. ~~**Merge configuration.md + configuration-guide.md**~~ ✅ DONE
2. ~~**Add prompts/README.md**~~ ✅ DONE
3. ~~**Expand troubleshooting.md**~~ ✅ DONE
4. ~~**Add A2A protocol documentation**~~ ✅ DONE (PR #306)

### Medium Priority
5. ~~**Add "last updated" metadata** to doc headers~~ ✅ ALL docs now have timestamps
YJ|6. ~~**Create API reference**~~ ✅ Issue #474 - Created docs/api.md with 64+ endpoints
#XZ|7. ~~**Add inline TOCs** for long docs~~ ✅ architecture.md, connectivity.md, usage.md, extensibility.md, blueprint.md, installation.md
#QM|8. ~~**Testing Guide**~~ ✅ Issue #418 - Created docs/testing.md, CLOSED 2026-02-28
#XZ|
#QM|### Low Priority
#QM|9. ~~**Security section**~~ ✅ DONE - Added Security Best Practices section
#QM|10. **Add version numbers** to docs showing which version they apply to

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
