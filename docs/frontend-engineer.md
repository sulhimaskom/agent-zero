# Frontend Engineer Agent - Knowledge Base

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
