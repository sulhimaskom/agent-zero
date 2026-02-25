# AI Agent Engineer - Long-term Memory

## Overview
This document serves as the long-term memory for the ai-agent-engineer domain in the Agent Zero project.

## Domain Focus
- Agent behavior and performance optimization
- Multi-agent cooperation patterns
- Agent tool execution and extensions
- Memory and history management for agents

## Implemented Fixes

### 2026-02-25: Bare Exception Handlers Fix in MCP Handler
**Issue**: Bare exception handlers without exception variable capture in `python/helpers/mcp_handler.py`

**Root Cause**: Two locations were using `except Exception:` without capturing the exception variable, making debugging difficult.

**Fix Applied**: Added exception variable capture (`as e`) and logging print statements.

**Code Change**:
```python
# Line 667 - get_server_detail method
try:
    tools = server.get_tools()
except Exception as e:
    print(f"Failed to get tools for server {server_name}: {e}")
    tools = []

# Line 971 - get_log method  
try:
    log = self.log_file.read()
except Exception as e:
    print(f"Failed to read log file: {e}")
    log = ""
```

**Files Modified**:
- `python/helpers/mcp_handler.py` - 2 bare exception handlers fixed

**Verification**:
- Python syntax check: PASSED

---

### 2026-02-25: Secrets and Extensions Bare Exception Fix
**Issue**: Bare exception handlers without exception variable capture in secrets management and agent extensions

**Root Cause**: Multiple locations in the secrets module and extension hooks were using `except Exception:` without capturing the exception variable, making debugging difficult.

**Fix Applied**: Added exception variable capture (`as e`) and logging print statements to 8 critical files.

**Files Modified**:
- `python/helpers/secrets.py` - _read_secrets_raw method (line 165)
- `python/extensions/system_prompt/_10_system_prompt.py` - get_secrets_prompt function (line 71)
- `python/extensions/hist_add_before/_10_mask_content.py` - execute method (line 17)
- `python/extensions/response_stream_chunk/_10_mask_stream.py` - execute method (line 37)
- `python/extensions/reasoning_stream_chunk/_10_mask_stream.py` - execute method (line 37)
- `python/extensions/response_stream_end/_10_mask_end.py` - execute method (line 26)
- `python/extensions/reasoning_stream_end/_10_mask_end.py` - execute method (line 26)

**Verification**:
- All 7 files pass Python syntax check
- Reduced bare exception count from 52 to 39 in codebase (13 fixed)
- Focused on agent domain: extensions (tool execution) and secrets (security)

---

### 2026-02-25: Bare Exception Handlers Fix in Helper Modules (PR #304)
**Issue**: Bare exception handlers without exception variable capture in helper modules

**Root Cause**: Multiple locations in helper modules were using `except Exception:` without capturing the exception variable.

**Fix Applied**: Added exception variable capture (`as e`) to 3 critical files.

**Files Modified**:
- `python/helpers/whisper.py` - Line 104: cleanup in temp file removal
- `python/helpers/print_style.py` - Line 124: secret masking fallback
- `python/helpers/defer.py` - Line 175: async task cleanup

**Verification**:
- Python syntax check: PASSED
- Reduced bare exception count in python/helpers from 21 to 18 (3 fixed)

**Status**: PR #304 ready for merge - creates Issue #309 for remaining 23 files

---

### 2026-02-25: Vision Bytes Filter Fix
**Issue**: [PERFORMANCE] Vision Bytes Sent to Utility LLM - Wastes Tokens (#241)

**Root Cause**: In `python/helpers/history.py`, the `Topic.summarize()` method was sending raw message output (including base64 image data) directly to the utility model without filtering. This wasted bandwidth and tokens.

**Fix Applied**: Added vision bytes filtering using regex substitution to replace base64 image data URLs with "[Image]" placeholder before sending to utility model.

**Code Change**:
```python
async def summarize(self):
    # Get output text and filter out vision bytes
    import re
    output_text = self.output_text()
    # Replace base64 image data URLs with placeholder
    filtered_text = re.sub(r"data:image/[^;]+;base64,[A-Za-z0-9+/=]+", "[Image]", output_text)
    self.summary = await self.history.agent.call_utility_model(...)
```

**Files Modified**:
- `python/helpers/history.py` - Topic.summarize() method

**Verification**:
- Python syntax check passed
- Code follows existing pattern from summarize_messages() method

## Known Issues (Future Work)

1. **Issue #309**: 23 remaining files with bare exception handlers - continuation after PR #304
2. **Issue #234**: Test coverage gap - 5% Python coverage, 0% JS coverage
3. **Issue #235**: settings.py - 1748-Line Monolith Needs Refactoring  
4. **Issue #236**: task_scheduler.py - 1284-Line Mixed Concerns
5. **Issue #237**: scheduler.js - 1579-Line Monolith Needs Splitting

---

## Patterns & Conventions

## Patterns & Conventions
- Use regex substitution to filter vision bytes: `r"data:image/[^;]+;base64,[A-Za-z0-9+/=]+"`
- Replace with "[Image]" placeholder for utility model calls
- Follow existing code patterns in the helpers module

## Agent Profiles
- `agents/agent0/` - Main agent (Agent 0)
- `agents/default/` - Default agent profile
- `agents/developer/` - Developer-focused agent
- `agents/researcher/` - Research agent
- `agents/hacker/` - Security/hacking agent
- `agents/brocula/` - Browser automation agent
- `agents/_example/` - Example extensions and tools
