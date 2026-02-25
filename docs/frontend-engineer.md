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
- [ ] Buttons without `aria-label` or `title` attributes
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

1. **Accessibility**: Many icon buttons lack `aria-label` attributes
2. **Console statements**: ~148 console.log statements across 76 files (many in vendor code)
3. **TODO comments**: ~80 TODO/FIXME comments across frontend files

## Working Notes

### First Task Completed
- Fixed empty `alt` attribute in `dragDropOverlay.html` (line 40)
- Changed from `alt=""` to `alt="Drag and drop files"`

### Second Task Completed
- Added `aria-label="Remove attachment"` to button in `inputPreview.html`
- This improves accessibility for screen reader users

## Commands

### Build/Test
```bash
# No standard build command for frontend (no bundler)
# Direct ES module loading
```
