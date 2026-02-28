# UI/UX Engineer Agent - Knowledge Base

**Created:** 2026-02-28
**Agent:** ui-ux-engineer (autonomous mode)

## Domain Scope
- User Interface (UI) design and implementation
- User Experience (UX) improvements
- Accessibility (a11y) compliance
- Visual consistency across components
- CSS/styling patterns

## Proactive Scan Focus Areas

### Accessibility (a11y)
- [x] Empty `alt` attributes on images - should have meaningful text or `role="presentation"`
- [x] Icon-only buttons with `aria-label` - zoom controls, toolbar buttons
- [ ] Form inputs without labels
- [ ] Color contrast issues
- [ ] Keyboard navigation and focus indicators

### Visual Consistency
- [ ] Inconsistent button styles
- [ ] Missing hover/active states
- [ ] Inconsistent spacing/padding
- [ ] Typography inconsistencies

### Component Patterns
- Modal patterns
- Form patterns
- Card/panel patterns
- Navigation patterns

## Work Completed

### Issue: Image Viewer Zoom Buttons Accessibility (2026-02-28)
**Status:** ✅ COMPLETED

**Problem:** The image viewer modal had three zoom control buttons (zoom out, reset zoom, zoom in) that were icon-only buttons without accessible labels. Screen readers could not properly announce these button functions.

**Solution:** Added `aria-label` attributes to all three zoom buttons in `webui/components/modals/image-viewer/image-viewer.html`:
- Line 47: Added `aria-label="Zoom out"` 
- Line 50: Added `aria-label="Reset zoom"`
- Line 53: Added `aria-label="Zoom in"`

**Impact:** Screen readers will now properly announce the zoom button functions, improving accessibility for visually impaired users.

## Known Issues (Future Work)

1. **Full-screen Input Modal** - Close button and toolbar buttons need aria-labels
2. **Chat Input Bottom Actions** - All 8 icon buttons need aria-labels  
3. **Message Queue** - Action buttons need aria-labels
4. **Notification Components** - Action buttons need aria-labels
5. **Focus Indicators** - Multiple button components lack :focus CSS styles
6. **Form Labels** - Settings pages have inputs without proper label associations
7. **Keyboard Navigation** - No tabindex attributes for enhanced keyboard navigation

## Common Patterns

### Button Accessibility Pattern
```html
<button type="button" @click="action()" aria-label="Descriptive action name">
  <span class="material-symbols-outlined">icon</span>
</button>
```

### Icon Button with Title (Alternative)
```html
<button type="button" @click="action()" title="Descriptive action name">
  <span class="material-symbols-outlined">icon</span>
</button>
```

### Focus Indicator CSS Pattern
```css
.button:focus {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
}
```

## Notes
- PR #455 exists but depends on non-existent files (`webui/js/constants.js`) - needs reimplementation
- The codebase has good alt text coverage on most images
- Login page has proper form label associations
