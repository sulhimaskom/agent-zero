# UI/UX Engineer - Long-term Memory

**Last Updated:** 2026-02-25
**Agent:** ui-ux-engineer

## Overview
This document tracks UI/UX improvements, accessibility standards, and patterns for the Agent Zero frontend.

## Accessibility Standards

### Required Attributes
- **Buttons**: Must have `aria-label` if icon-only (e.g., `&times;`, `+`, `-`)
- **Images**: Must have meaningful `alt` text
- **Interactive elements**: Must have `tabindex="0"`, `role="button"`, and keyboard support
- **Forms**: Must have associated `<label>` elements

### Focus States
- Use `:focus-visible` for keyboard-only focus indicators
- Never remove outline without providing alternative
- Color: Use `var(--color-highlight)` or similar

### Color Contrast
- Minimum 4.5:1 for normal text
- Minimum 3:1 for large text
- Use CSS custom properties from `theme.css`

## Components Checklist

### Modals
- [x] Close button has aria-label (setup-wizard.html - DONE 2026-02-25)
- [x] Close button has aria-label (full-screen-input.html - DONE 2026-02-25)
### Chat Attachments
- [x] Remove attachment button aria-label (inputPreview.html - DONE 2026-02-25)

### Memory Dashboard
- [x] Pagination prev/next buttons aria-label (memory-dashboard.html - DONE 2026-02-25)

- [ ] Other modals need review

### Setup Wizard
- [x] Close button aria-label (line 17)
- [x] Logo alt text (line 50)
- [x] Keyboard navigation (tabindex, role="button")
- [x] aria-pressed for selection states

### Forms
- [x] Labels present
- [x] Required field indicators
- [x] Error messages

## Known Issues

### Priority Fixes
1. **Modal close buttons**: Some modal close buttons missing aria-labels
2. **Focus indicators**: Some interactive elements may lack visible focus states
3. **Screen reader**: Some dynamic content may need `aria-live` regions

### Low Priority
1. **Color contrast**: Some secondary text may have contrast issues
2. **Skip links**: Consider adding skip navigation links

## File Locations
- **Components**: `webui/components/`
- **Styles**: `webui/css/`
- **Stores**: `webui/js/` (Alpine.js stores)

## Common Patterns

### Icon Button
```html
<button class="icon-button" @click="action()" aria-label="Action description">
  <span class="material-symbols-outlined">icon</span>
</button>
```

### Keyboard-Accessible Card
```html
<div class="card" 
     @click="select()"
     @keydown.enter.prevent="select()"
     tabindex="0" 
     role="button" 
     :aria-pressed="selected">
</div>
```

## Action Items (Next Sprint)
- [ ] Audit all modal close buttons
- [ ] Check form validation accessibility
- [ ] Review notification toast accessibility
- [ ] Test keyboard navigation flow

## References
- WCAG 2.1 Guidelines
- MDN Accessibility Documentation
- WAI-ARIA Practices
