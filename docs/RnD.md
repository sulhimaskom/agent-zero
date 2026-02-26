# RnD (Research & Development) Documentation

This document tracks R&D efforts, learnings, and improvements made to Agent Zero.

## 2026-02-26

### Issue Analyzed: Bare Exception Handlers in vector_db.py, files.py, and brocula modules

**Problem**: Multiple Python files had bare `except Exception:` handlers that silently swallowed all exceptions without capturing the exception variable, making debugging difficult.

**Root Cause**: Generic exception handlers catch all exceptions but without capturing the exception object, making debugging difficult when issues arise.

**Solution Applied**:
- vector_db.py line 117: Changed `except Exception:` to `except Exception as e:` in safe_eval_node fallback
- files.py line 540: Changed `except Exception:` to `except Exception as e:` in directory reading loop
- lighthouse_auditor.py line 60: Changed `except Exception:` to `except Exception as e:` in Lighthouse availability check
- brocula.py line 173: Changed `except Exception:` to `except Exception as e:` in subprocess execution

**Files Changed**: 
- `python/helpers/vector_db.py`
- `python/helpers/files.py`
- `agents/brocula/tools/lighthouse_auditor.py`
- `agents/brocula/brocula.py`

**Status**: Fixed - Agents directory now has zero bare exception handlers

---

## 2026-02-25

### Issue Analyzed: Bare Exception Handlers in mcp_server.py

**Problem**: The `_run_chat` function in `python/helpers/mcp_server.py` had a bare `except Exception:` handler that silently swallowed all exceptions when processing attachments without capturing the exception variable.

**Root Cause**: Generic exception handlers catch all exceptions but without capturing the exception object, making debugging difficult when attachment processing fails.

**Solution Applied**:
- Line 239: Changed `except Exception:` to `except Exception as e:` to capture the exception and include it in the error message

**Files Changed**: `python/helpers/mcp_server.py`

**Status**: Fixed - Reduced bare exception handlers from 32 to 31 across the codebase

---


### Issue Analyzed: Bare Exception Handlers in login.py

**Problem**: The `verify_password` function in `python/helpers/login.py` had a bare `except Exception:` handler that silently swallowed all exceptions without capturing the exception variable.

**Root Cause**: Generic exception handlers catch all exceptions but without capturing the exception object, making debugging difficult when issues arise.

**Solution Applied**:
- Line 28: Changed `except Exception:` to `except Exception as e:` to capture the exception for potential debugging

**Files Changed**: `python/helpers/login.py`

**Status**: Fixed - Reduced bare exception handlers from 38 to 37 across the codebase

---

### Previous: Issue Analyzed: Bare Exception Handlers in tunnel_manager.py

**Problem**: The `TunnelManager` class in `python/helpers/tunnel_manager.py` had 3 bare `except Exception:` handlers that silently swallowed all exceptions without logging, making debugging difficult.

**Root Cause**: Generic exception handlers catch all exceptions without distinguishing between different error types or providing any diagnostic information.

**Solution Applied**:
- Line 47: Changed `except Exception: pass` to `except Exception as e:` with stderr logging
- Line 63: Changed `except Exception:` to `except (ValueError, RuntimeError) as e:` with stderr logging (more specific)
- Line 75: Changed `except Exception:` to `except Exception as e:` with stderr logging

**Files Changed**: `python/helpers/tunnel_manager.py`

**Status**: Fixed - Reduced bare exception handlers from 38 to 35 across python/ directory

---

### Previous: Issue Analyzed: #241 - Vision Bytes Sent to Utility LLM

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
- Bare exception handlers remaining (37) are mostly defensive fallbacks in defensive code paths
