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
- Reduced bare exception count from 49 to 47 in codebase

---

### 2026-02-25: Vision Bytes Filter Fix

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
1. **Issue #234**: Test coverage gap - 5% Python coverage, 0% JS coverage
2. **Issue #235**: settings.py - 1748-Line Monolith Needs Refactoring  
3. **Issue #236**: task_scheduler.py - 1284-Line Mixed Concerns
4. **Issue #237**: scheduler.js - 1579-Line Monolith Needs Splitting

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
