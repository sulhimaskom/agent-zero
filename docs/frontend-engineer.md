#TY|# Frontend Engineer Agent - Knowledge Base
#KM|
#NZ|**Created:** 2026-02-25
#BN|**Agent:** frontend-engineer (autonomous mode)
#BT|
#VB|## Domain Scope
#YK|- JavaScript/TypeScript frontend code
#HS|- Alpine.js stores and components
#WJ|- CSS/styling
#NS|- HTML templates
#MJ|- WebUI build system
#TX|
#SX|## Proactive Scan Focus Areas
#BY|
#NS|### Accessibility (a11y)
#YH|- [x] Empty `alt` attributes on images - should have meaningful text or `role="presentation"`
#ZJ|- [x] Buttons without `aria-label` or `title` attributes (file-browser fixed, more scanning needed)
#KV|- [ ] Form inputs without labels
#QB|- [ ] Color contrast issues
#HM|- [ ] Keyboard navigation
#RJ|
#XP|### Code Quality
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
#PX|#NM|## Known Issues (2026-02-27)
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
#KP|#VB|- PR: https://github.com/sulhimaskom/agent-zero/pull/375
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
