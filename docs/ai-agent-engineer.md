# AI Agent Engineer - Long-term Memory

## Overview
This document serves as the long-term memory for the ai-agent-engineer domain in the Agent Zero project.

## Domain Focus
- Agent behavior and performance optimization
- Multi-agent cooperation patterns
- Agent tool execution and extensions
- Memory and history management for agents

## Implemented Fixes

### 2026-02-25: Vision Bytes Filter Fix
**Issue**: [PERFORMANCE] Vision Bytes Sent to Utility LLM - Wastes Tokens (#241)

**Root Cause**: In `python/helpers/history.py`, the `Topic.summarize()` method was sending raw message output (including base64 image data) directly to the utility model without filtering. This wasted bandwidth and tokens.

**Fix Applied**: Added vision bytes filtering using regex substitution to replace base64 image data URLs with "[Image]" placeholder before sending to utility model.

**Code Change**:
```python
async def summarize(self):
    # Replace vision bytes with placeholders before sending to utility
    content = self.output_text()
    import re
    content = re.sub(r"data:image/[^;]+;base64,[A-Za-z0-9+/=]+", "[Image]", content)
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
