# RnD (Research & Development) Documentation

This document tracks R&D efforts, learnings, and improvements made to Agent Zero.

## 2026-02-25

### Issue Analyzed: #241 - Vision Bytes Sent to Utility LLM

**Problem**: The `Bulk.summarize()` method in `python/helpers/history.py` was sending raw message content containing base64-encoded vision bytes directly to the utility LLM, causing unnecessary bandwidth and token waste.

**Root Cause**: Unlike `Topic.summarize_messages()` which correctly replaced image data URLs with "[Image]" placeholders, `Bulk.summarize()` did not perform this filtering.

**Solution Applied**: 
- Added regex replacement to filter out base64 image data before sending to utility model
- Pattern: `data:image/[^;]+;base64,[A-Za-z0-9+/=]+` → `"[Image]"`
- Moved `import re` to module level for cleaner code

**Files Changed**: `python/helpers/history.py`

**Status**: Fixed in latest commit (issue already resolved in remote)

---

## Notes

- Issue #241 was already addressed in the remote repository
- Minor code quality improvement: moved inline import to module level
- The fix follows the same pattern already used in `Topic.summarize_messages()`
