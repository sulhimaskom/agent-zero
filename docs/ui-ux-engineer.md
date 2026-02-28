# UI/UX Engineer - Long-term Memory

> Last Updated: 2026-02-26
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
- [x] Audit all modal close buttons (context.html, history.html - DONE 2026-02-25)
- [ ] Check form validation accessibility
- [ ] Review notification toast accessibility
- [ ] Test keyboard navigation flow

## Issue Tracking

### Issue #240 - Silent API Failures
**Status:** ✅ SUBSTANTIALLY ADDRESSED (2026-02-25)
- Toast notification system implemented in notification-store.js
- Main stores (tunnel, projects, memory-dashboard) use `window.toastFrontendError()`
- No empty catch blocks found in webui/components
- Remaining console.error calls are intentional for developer debugging
- Pattern: Both console.error (for devs) AND toast (for users) used together

### Issue #243 - First-Time Setup Wizard
**Status:** ✅ COMPLETED (2026-02-25)
- Setup wizard component exists at setup-wizard-store.js
- Accessibility improvements completed (close button, logo alt, keyboard nav)

### PR #314 - Accessibility Improvements (2026-02-25)
**Status:** ✅ COMPLETED
- Added aria-labels to sidebar quick-actions.html (8 buttons)
- Added aria-labels to chat input bottom-actions.html (6 buttons)
- Added close buttons with aria-labels to context.html and history.html modals
- Added label association to tunnel-section.html select element
- Improves screen reader support and keyboard navigation

## Completed Work

### Scheduler Table Accessibility (2026-02-26)
**Status:** ✅ COMPLETED

Fixed keyboard accessibility issues in the scheduler task table (`webui/index.html`):

1. **Table Headers (th elements)** - Added keyboard support to sortable columns:
   - Name column header (line 1060): Added `@keydown.enter.prevent`, `@keydown.space.prevent`, `tabindex="0"`, `role="button"`, `aria-label="Sort by name"`
   - State column header (line 1065): Added `@keydown.enter.prevent`, `@keydown.space.prevent`, `tabindex="0"`, `role="button"`, `aria-label="Sort by state"`
   - Last Run column header (line 1074): Added `@keydown.enter.prevent`, `@keydown.space.prevent`, `tabindex="0"`, `role="button"`, `aria-label="Sort by last run"`

2. **Table Rows (tr elements)** - Added keyboard support to task rows:
   - Task row (line 1085): Added `@keydown.enter.prevent`, `@keydown.space.prevent`, `tabindex="0"`, `role="button"`, `:aria-label="'View task: ' + task.name"`

**Impact:** Users can now navigate and interact with the scheduler table using keyboard (Tab, Enter, Space) instead of only mouse clicks.

## References
- WCAG 2.1 Guidelines
- MDN Accessibility Documentation
- WAI-ARIA Practices
QQ|**Last Updated:** 2026-02-27
#QZ|
#MR|### Image Viewer Focus States (2026-02-27)
#WS|**Status:** ✅ COMPLETED
#QX|
#QW|Fixed keyboard accessibility issue in image viewer zoom controls (`webui/components/modals/image-viewer/image-viewer.html`):
#QS|
#WS|1. **Zoom Buttons** - Added `:focus-visible` CSS styling:
#MV|   - Added visible focus outline using `var(--color-highlight, #64b5f6)`
#QJ|   - Added `outline-offset: 2px` for better visibility
#TS|   - Added background change on focus for additional visual feedback
#HQ|
#ZW|**Impact:** Keyboard users can now see which zoom button is focused when navigating with Tab key.
#QW|
#YH|### Decorative Icon Accessibility (2026-02-27)
#WS|**Status:** ✅ COMPLETED
#QX|
#QW|Fixed missing `aria-hidden="true"` on decorative material-symbols-outlined icons:
#QS|
#WS|1. **notification-modal.html** - Added aria-hidden to 2 icons:
#MV|   - Line 20: delete icon in "Clear All" button
#QJ|   - Line 74: notifications icon in empty state
#TS|
#ZW|2. **project-list.html** - Added aria-hidden to 4 icons:
#MV|   - Line 34: add icon in "Create project" button (header)
#QJ|   - Line 51: close icon in "Deactivate" button
#TS|   - Line 56: play_arrow icon in "Activate" button
#TW|   - Line 76: add icon in "Create project" button (empty state)
#HQ|
#ZW|**Impact:** Screen readers will now skip decorative icons and only announce the button text, improving the user experience for visually impaired users.

### Image Viewer Focus States (2026-02-27)
**Status:** ✅ COMPLETED

Fixed keyboard accessibility issue in image viewer zoom controls (`webui/components/modals/image-viewer/image-viewer.html`):

1. **Zoom Buttons** - Added `:focus-visible` CSS styling:
   - Added visible focus outline using `var(--color-highlight, #64b5f6)`
   - Added `outline-offset: 2px` for better visibility
   - Added background change on focus for additional visual feedback

**Impact:** Keyboard users can now see which zoom button is focused when navigating with Tab key.

### Welcome Screen Duplicate Content Fix (2026-02-27)
**Status:** ✅ COMPLETED

Fixed duplicate content bug in welcome screen (`webui/components/welcome/welcome-screen.html`):

1. **Removed Duplicate Title and Subtitle** - Lines 33-38 contained duplicate "Welcome to Agent Zero" title and subtitle that was already displayed at lines 19-22.

**Impact:** Eliminates visual redundancy and improves user experience on the welcome screen.

### Memory Dashboard Accessibility (2026-02-27)
**Status:** ✅ COMPLETED

Added missing aria-label to Clear button in memory dashboard (`webui/components/settings/memory/memory-dashboard.html`):

1. **Clear Button** - Added `aria-label="Clear search"` to improve screen reader accessibility.

JY|**Impact:** Screen readers will now properly announce the Clear button function.


## Issue #423 - First-Time Setup Wizard Auto-Trigger (2026-02-28)
WS|**Status:** ✅ COMPLETED

Implemented automatic first-time detection to trigger the setup wizard on first visit:

NW|1. **Backend API** - Created `python/api/settings_status.py`:
   - New endpoint `/api/settings_status` returns `isFirstTime` and `hasApiKey`
   - Checks for settings file existence at `tmp/settings.json`
   - Detects if any API keys are configured

RW|2. **Frontend Integration** - Modified `webui/components/welcome/welcome-store.js`:
   - Added `checkFirstTime()` method called on store initialization
   - Auto-opens setup wizard when `isFirstTime` is true
   - Added `wizardChecked` flag to prevent duplicate checks

JM|3. **API Endpoint** - Added `SETTINGS_STATUS` to `webui/js/constants.js`

TT|**Impact:** First-time users will now see the setup wizard automatically when they first load the application, improving time-to-value and reducing setup friction.

#WH|TT|**Impact:** First-time users will now see the setup wizard automatically when they first load the application, improving time-to-value and reducing setup friction.
#QV|
#KV|## Focus-Visible CSS Improvements (2026-02-28)
#WS|**Status:** ✅ COMPLETED
#QV|
#WY|Fixed keyboard accessibility issues by adding `:focus-visible` styles to interactive elements:
#QT|
#QT|1. **Range Input Focus** - Added `:focus-visible` to modals.css:
#XS|   - Line 386-389: Added visible focus outline for range sliders
#QT|   - Uses `var(--color-highlight, #64b5f6)` with 2px outline and 2px offset
#QT|   - Allows keyboard users to see focus state on range inputs
#QV|
#QT|2. **Form Input Focus** - Added `:focus-visible` to settings.css:
#QT|   - Lines 59-66: Added visible focus outline for text, password, number inputs, textarea, and select
#QT|   - Uses `var(--color-highlight, #64b5f6)` with 2px outline and 2px offset
#QT|   - Improves keyboard accessibility for settings form fields
#QV|
#QV|**Impact:** Keyboard users can now clearly see which element is focused when navigating with Tab key.
