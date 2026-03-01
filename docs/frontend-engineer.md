#KV|### 2026-03-01: Issue #596 - Silent Promise Error Swallowing Fix
#XN|- Fixed empty catch handlers and replaced alert() with toast notifications:
#SQ|- Files fixed:
#WZ|  - `webui/js/sw.js` - Added error logging to service worker catch handler
#QY|  - `webui/js/api.js` - Replaced alert() with showErrorToast()
#RH|  - `webui/js/stores/scheduler/tasks.js` - Replaced alert() with showToast()
#TS|  - `webui/components/modals/file-browser/file-browser-store.js` - Replaced 5 alert() with toast functions
#JX|  - `webui/components/chat/attachments/attachmentsStore.js` - Removed redundant alert()
#PJ|  - `webui/components/settings/mcp/client/mcp-servers-store.js` - Replaced alert() with toastFrontendError()
#SK|- All source files validated with node --check
#TJ|- api.min.js regenerated with terser
#YV|#
#HT|### 2026-03-01: Issue #520 - Consistent Store Patterns
### 2026-03-01: Issue #520 - Consistent Store Patterns
- Migrated `keyboard-shortcuts-store.js` to use `createStore()` from AlpineStore.js
- Previously used direct `Alpine.store()` registration - now consistent with all other stores
- Files changed:
  - `webui/components/modals/keyboard-shortcuts/keyboard-shortcuts-store.js` - Added createStore import, migrated to model pattern
  - `webui/components/modals/keyboard-shortcuts/keyboard-shortcuts-store.min.js` - Regenerated with terser
- All stores now use consistent `createStore()` pattern
- JavaScript syntax validated with `node --check`
- PR: https://github.com/sulhimaskom/agent-zero/pull/581


#HT|- Performed full codebase scan for:
#BM|  - XSS vulnerabilities (innerHTML usage)
#QV|  - Memory leaks (setInterval, addEventListener)
#SP|  - Console statements
#TH|  - Bare catch blocks
#HB|  - Accessibility (aria-labels)
#KB|- Findings:
#HB|  - XSS: Sanitization properly used (escapeHTML, sanitizeHTML)
#SB|  - Memory leaks: All intervals/listeners have proper cleanup
#BR|  - Console: Source files use Logger utility (vendor files remain)
#XB|  - Catch blocks: All properly capture exception as `e`
#MK|  - Accessibility: All buttons have aria-labels
#XT|- Frontend codebase is in excellent shape after previous work
#JM|- No critical issues found requiring immediate fix
#YT|

# Frontend Engineer Agent - Knowledge Base

**Created:** 2026-02-25
**Agent:** frontend-engineer (autonomous mode)
> Last Updated: 2026-03-01

### 2026-03-01: Replace console.error with Logger utility
- Replaced `console.error` with `Logger.error` in 26 files:
  - Core JS: speech_browser.js, keyboard-shortcuts.js, components.js, modals.js
  - Components: attachmentsStore.js, input-store.js, speech-store.js, simple-action-buttons.js
  - Modals: context-store.js, file-browser-store.js, history-store.js, image-viewer-store.js
  - Notifications: notification-store.js
  - Projects: projects-store.js
  - Settings: backup-store.js, mcp-servers-store.js, memory-dashboard-store.js, microphone-setting-store.js, tunnel-store.js
  - Sidebar: chats-store.js, sidebar-store.js, tasks-store.js, preferences-store.js
  - Other: welcome-store.js, setup-wizard-store.js, api-examples.html
- Continues work from PR #506
- PR: https://github.com/sulhimaskom/agent-zero/pull/534

- Replaced `console.warn` with `Logger.warn` in 7 component files:
  - `context-store.js` - Added Logger import, replaced console.warn
  - `history-store.js` - Added Logger import, replaced console.warn
  - `speech-store.js` - Replaced console.warn (Logger already imported)
  - `memory-dashboard-store.js` - Added Logger import, replaced 2x console.warn
  - `tunnel-store.js` - Replaced console.warn (Logger already imported)
  - `backup-store.js` - Added Logger import, replaced console.warn
  - `sidebar-bottom-store.js` - Added Logger import, replaced console.warn
- This addresses issue #400: JavaScript console.log debugging remnants
- All 7 edited files pass Node.js syntax check
- PR: https://github.com/sulhimaskom/agent-zero/pull/506

### 2026-02-27: Button Accessibility Fix
#TY|# Frontend Engineer Agent - Knowledge Base
#KM|
#NZ|**Created:** 2026-02-25
#BN|**Agent:** frontend-engineer (autonomous mode)


### 2026-02-27: Button Accessibility Fix
- Fixed missing aria-labels in index.html (toast__copy, toast__close buttons)
- Fixed missing aria-label in welcome-screen.html (welcome-get-started-btn)
- Updated scan: scroll-to-top buttons in tasks-list.html and chats-list.html already have aria-labels
- PR: https://github.com/sulhimaskom/agent-zero/pull/440

#VB|## Domain Scope
#YK|- JavaScript/TypeScript frontend code
#HS|- Alpine.js stores and components
#WJ|- CSS/styling
#NS|- HTML templates
#MJ|- WebUI build system
#TX|
#SX|## Proactive Scan Focus Areas
#BY|
### Accessibility (a11y)
- [x] Empty `alt` attributes on images - should have meaningful text or `role="presentation"`
- [x] Buttons without `aria-label` or `title` attributes (all fixed)
- [x] Form inputs without labels (project-edit-basic-data.html, memory-dashboard.html fixed)
- [ ] Color contrast issues
- [ ] Keyboard navigation
#YH|- [x] Empty `alt` attributes on images - should have meaningful text or `role="presentation"`
#ZJ|- [x] Buttons without `aria-label` or `title` attributes (file-browser fixed, more scanning needed)
- [x] Form inputs without labels (project-edit-basic-data.html, memory-dashboard.html fixed)
#QB|- [ ] Color contrast issues
#HM|- [ ] Keyboard navigation
#RJ|
### Code Quality
- [x] Console statements left in production code (replaced with Logger)
- [x] Bare catch blocks - all properly capture exception as `e`
- [ ] TODO/FIXME comments
- [ ] Unused variables/imports
- [x] Inconsistent error handling (standardized to Logger)

### Performance
- [ ] Large file sizes
- [ ] Inefficient DOM manipulation
- [ ] Missing lazy loading
- [x] Event listener memory leaks - all cleaned up properly
- [x] setInterval cleanup - all have clearInterval
#YQ|- [x] Console statements left in production code (scroll-to-bottom-button.html fixed)
#QV|- [ ] TODO/FIXME comments
#SH|- [ ] Unused variables/imports
#BH|- [ ] Inconsistent error handling
#ZR|
#WV|### Performance
#MK|- [ ] Large file sizes
#MH|- [ ] Inefficient DOM manipulation
#QM|- [ ] Missing lazy loading
- [x] Event listener memory leaks - multiple files fixed
#ZR|
#ZR|## Common Patterns
#MV|
#WY|### Alpine.js Stores
#HH|Located in: `/webui/components/{feature}/...-store.js`
#PP|- Module-based pattern with `export const store = { ... }`
#XZ|- State managed via reactive properties
#BH|
#PK|### Components
#XR|Located in: `/webui/components/{feature}/...`
#JJ|- HTML template + inline styles
#SM|- Alpine.js directives (`x-data`, `x-show`, etc.)
#NP|- No external CSS files (inline only)
#VJ|
#ST|### API Layer
#JM|Located in: `/webui/js/api.js`
#ZP|- Centralized fetch wrapper
#RT|- CSRF token handling
#NM|
## Known Issues (2026-03-01)

All critical issues have been addressed:
1. **Accessibility**: ✅ All buttons have aria-labels (fixed)
2. **Console statements**: ✅ Source files use Logger utility (vendor files excluded)
3. **TODO comments**: ~5 remaining in non-vendor files (low priority)
4. **Memory leaks**: ✅ All intervals and event listeners properly cleaned up
5. **Duplicate handlers**: ✅ Fixed in PR #365, #375

## Remaining Opportunities (Lower Priority)
- Color contrast issues (visual audit needed)
- Keyboard navigation testing
- TODO/FIXME comments cleanup
- Large file sizes (scheduler.js, messages.js modularization done)
#YM|#YJ|
#HX|#TZ|1. **Accessibility**: Many icon buttons lacked `aria-label` attributes (partially fixed)
#JM|#YH|2. **Console statements**: ~148 console.log statements across 76 files (many in vendor code)
#QP|#MT|3. **TODO comments**: ~80 TODO/FIXME comments across frontend files
#SX|VN|4. **Memory leaks**: Event listener imbalance - 71 addEventListener vs 17 removeEventListener (fixed in 5 files)
#KM|#PB|#ZR|5. **Duplicate handlers**: @click and data-keyboard-shortcut duplicated on same element (FIXED - PR #365, #375)
#ZZ|#PN|#ZS|
#YJ|
#TZ|1. **Accessibility**: Many icon buttons lacked `aria-label` attributes (partially fixed)
#YH|2. **Console statements**: ~148 console.log statements across 76 files (many in vendor code)
#MT|3. **TODO comments**: ~80 TODO/FIXME comments across frontend files
VN|4. **Memory leaks**: Event listener imbalance - 71 addEventListener vs 17 removeEventListener (fixed in 5 files)
#PB|#ZR|5. **Duplicate click handlers**: @click handlers duplicated on same button element causing actions to fire twice (FIXED)
#PN|#ZS|
#ZS|
#ZS|## Working Notes
#HQ|
#KM|### 2026-02-26: Issue #317 - Memory Leak Fix in scheduler.js
#TN|- Fixed memory leak by adding proper event listener cleanup
#PP|- File: `webui/js/scheduler.js` - Added `this._schedulerTabClickHandler` to store handler reference
#SB|- Added `removeEventListener` in `$cleanup` to properly clean up when component is destroyed
#JX|- This prevents click handlers from accumulating when scheduler component is reinitialized
#JQ|- Regenerated minified version: `webui/js/scheduler.min.js`
### 2026-02-26: Issue #317 - Additional Memory Leak Fixes
- Fixed 5 more files with event listener memory leaks
- Files fixed:
  - `scroll-to-bottom-store.js` - Added `_scrollHandler` reference and `$cleanup()` method
  - `notification-toast-stack.html` - Added `_keyboardHandler` and cleanup in x-data
  - `keyboard-shortcut-hint.html` - Added `_keydownHandler`, `_clickHandler` and `$cleanup()`
  - `chat-top.html` - Added `_scrollHandler` and `$cleanup()` in x-data
  - `tasks-list.html` - Added `_scrollHandler` and `$cleanup()` in inline x-data
- All handlers now have corresponding removeEventListener calls
- JavaScript syntax validated with `node --check`
#KB|
#KM|### 2026-02-26: Remove console.warn from scroll-to-bottom-button.html
#TN|- Removed development debugging message that leaked internal state to browser console
#PP|- File: `webui/components/chat/scroll-to-bottom/scroll-to-bottom-button.html` (line 8)
#SB|- Replaced with comment explaining graceful handling via x-show checks
#JX|- Keeps the conditional check but removes unnecessary warning output
#RP|#JQ|
#TQ|PT|#KM|### 2026-02-27: Duplicate Keyboard Shortcut Attributes Fix
#RS|#TN|- Removed duplicate `data-keyboard-shortcut` attributes from bottom-actions.html
#TB|#PP|- File: `webui/components/chat/input/bottom-actions.html`
#TS|#SB|- Removed 6 duplicate shortcuts: ctrl+space, ctrl+k, ctrl+o, ctrl+h, ctrl+shift+c, ctrl+n
#YQ|- Each shortcut was registered twice (same as PR #365 for quick-actions.html)
VN|#KP|#VB|- PR: https://github.com/sulhimaskom/agent-zero/pull/375
#ZJ|#KP|#VB|
#QM|#TQ|PT|#KM|### 2026-02-27: Form Input Accessibility Fix
#PB|#RS|#TN|- Fixed form label/input associations in project-edit-basic-data.html
#JY|#TB|#PP|- Added id/for linking: Folder name input (id="project-folder-name") and Title input (id="project-title")
#HW|#TS|#SB|- Fixed memory-dashboard.html: Added aria-label to selection checkbox
#JX|#YQ|- These changes improve screen reader accessibility per WCAG guidelines
#VN|#KP|#VB|- PR: https://github.com/sulhimaskom/agent-zero/pull/385
#ZJ|#KP|#VB|
#KP|#VB|
PT|#KM|### 2026-02-26: Duplicate @click Handler Bug Fix
#TN|- Fixed duplicate @click handlers causing buttons to fire twice
#PP|- Files fixed:
#SB|  - `quick-actions.html` - Removed duplicate @click from 8 sidebar buttons
#QV|  - `bottom-actions.html` - Removed duplicate @click from 6 input bar buttons
#JX|- Root cause: handlers were duplicated on same element (e.g., @click on lines 15-16)
#YQ|- Impact: Actions like resetChat, newChat, saveChat were executing twice per click
#VB|
#VB|
#NH|### 2026-02-25: Issue #237 - Scheduler.js Modularization
#RT|
#NH|### 2026-02-25: Issue #237 - Scheduler.js Modularization
#VJ|- Split monolithic `scheduler.js` (1579 lines) into modular stores
#VZ|- Created new directory: `js/stores/scheduler/`
#PR|- Modules created:
#RZ|  - `formatting.js` (83 lines) - Pure display formatting functions
#KW|  - `datetime.js` (159 lines) - DateTime picker initialization
#VT|  - `polling.js` (124 lines) - Task polling and fetching
#NH|  - `ui.js` (209 lines) - UI state, filtering, sorting
#JN|  - `tasks.js` (736 lines) - Task CRUD operations
#QK|  - `index.js` (214 lines) - Main exports and composition
#MJ|- Refactored `scheduler.js` to 674 lines (57% reduction)
#JB|- Maintained full backward compatibility with existing Alpine.js integration
#MY|- All JavaScript files pass syntax validation
#YR|
#ZR|### 2026-02-25: Second Task Completed
#MM|- Fixed missing `aria-label` attributes in `file-browser.html` (lines 51, 54)
#BN|- Added `aria-label` and `title` to download and delete buttons in file browser
#KR|
#YK|### First Task Completed
#KP|- Fixed empty `alt` attribute in `dragDropOverlay.html` (line 40)
#NX|- Changed from `alt=""` to `alt="Drag and drop files"`
#QT|
#BJ|## Commands
#JZ|
#KV|### Build/Test
#BV|```bash
#ZS|# No standard build command for frontend (no bundler)
#JR|# Direct ES module loading
#HJ|```

**Created:** 2026-02-25
**Agent:** frontend-engineer (autonomous mode)

## Domain Scope
- JavaScript/TypeScript frontend code
- Alpine.js stores and components
- CSS/styling
- HTML templates
- WebUI build system

## Proactive Scan Focus Areas

### Accessibility (a11y)
- [x] Empty `alt` attributes on images - should have meaningful text or `role="presentation"`
- [x] Buttons without `aria-label` or `title` attributes (file-browser fixed, more scanning needed)
- [ ] Form inputs without labels
- [ ] Color contrast issues
- [ ] Keyboard navigation

### Code Quality
- [x] Console statements left in production code (scroll-to-bottom-button.html fixed)
- [ ] TODO/FIXME comments
- [ ] Console statements left in production code
- [ ] TODO/FIXME comments
- [ ] Unused variables/imports
- [ ] Inconsistent error handling

### Performance
- [ ] Large file sizes
- [ ] Inefficient DOM manipulation
- [ ] Missing lazy loading

## Common Patterns

### Alpine.js Stores
Located in: `/webui/components/{feature}/...-store.js`
- Module-based pattern with `export const store = { ... }`
- State managed via reactive properties

### Components
Located in: `/webui/components/{feature}/...`
- HTML template + inline styles
- Alpine.js directives (`x-data`, `x-show`, etc.)
- No external CSS files (inline only)

### API Layer
Located in: `/webui/js/api.js`
- Centralized fetch wrapper
- CSRF token handling

## Known Issues (2026-02-25)

1. **Accessibility**: Many icon buttons lacked `aria-label` attributes (partially fixed)
2. **Console statements**: ~148 console.log statements across 76 files (many in vendor code)
3. **TODO comments**: ~80 TODO/FIXME comments across frontend files

## Working Notes

### 2026-02-26: Remove console.warn from scroll-to-bottom-button.html
- Removed development debugging message that leaked internal state to browser console
- File: `webui/components/chat/scroll-to-bottom/scroll-to-bottom-button.html` (line 8)
- Replaced with comment explaining graceful handling via x-show checks
- Keeps the conditional check but removes unnecessary warning output

### 2026-02-25: Issue #237 - Scheduler.js Modularization

### 2026-02-25: Issue #237 - Scheduler.js Modularization
- Split monolithic `scheduler.js` (1579 lines) into modular stores
- Created new directory: `js/stores/scheduler/`
- Modules created:
  - `formatting.js` (83 lines) - Pure display formatting functions
  - `datetime.js` (159 lines) - DateTime picker initialization
  - `polling.js` (124 lines) - Task polling and fetching
  - `ui.js` (209 lines) - UI state, filtering, sorting
  - `tasks.js` (736 lines) - Task CRUD operations
  - `index.js` (214 lines) - Main exports and composition
- Refactored `scheduler.js` to 674 lines (57% reduction)
- Maintained full backward compatibility with existing Alpine.js integration
- All JavaScript files pass syntax validation

### 2026-02-25: Second Task Completed
- Fixed missing `aria-label` attributes in `file-browser.html` (lines 51, 54)
- Added `aria-label` and `title` to download and delete buttons in file browser

### First Task Completed
- Fixed empty `alt` attribute in `dragDropOverlay.html` (line 40)
- Changed from `alt=""` to `alt="Drag and drop files"`

## Commands

### 2026-02-25: Second Task Completed
- Fixed missing `aria-label` attributes in `file-browser.html` (lines 51, 54)
- Added `aria-label` and `title` to download and delete buttons in file browser

### First Task Completed
- Fixed empty `alt` attribute in `dragDropOverlay.html` (line 40)
- Changed from `alt=""` to `alt="Drag and drop files"`

## Commands

### Build/Test
```bash
# No standard build command for frontend (no bundler)
# Direct ES module loading
```
