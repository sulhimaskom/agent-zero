# AGENTS.md

## PROMPTS

### OVERVIEW
96 markdown files controlling entire framework behavior through LLM system prompts. Edit prompts to change agent behavior without code changes.

### STRUCTURE
```
prompts/
├── fw.*.md                 # Framework-level prompts (utility, messages)
├── agent.system.*.md       # Agent system prompts (behavior, tools)
├── agent.system.tool.*.md  # Tool-specific instruction prompts
├── memory.*.md             # Memory system (consolidation, query)
├── behaviour.*.md          # Behavior modification prompts
└── browser_agent.system.md # Browser agent system prompt
```

### WHERE TO LOOK

**Core System**
- `agent.system.main.md` - Master system prompt (includes role, environment, communication, solving, tips)
- `agent.system.main.role.md` - Agent's core role definition
- `agent.system.main.communication.md` - Communication guidelines
- `agent.system.main.solving.md` - Problem-solving approach
- `agent.system.response_tool_tips.md` - Response handling rules (ALWAYS use §§include(), NEVER rewrite subordinate responses)

**Framework-Level Prompts**
- `fw.initial_message.md` - First message template (greeting structure)
- `fw.tool_result.md` - Tool result JSON format
- `fw.error.md` - System error format
- `fw.msg_timeout.md` - Message timeout handling
- `fw.intervention.md` - User intervention prompts

**Tool Instructions**
- `agent.system.tool.memory.md` - Memory tools (load, save, delete, forget)
- `agent.system.tool.call_sub.md` - Subordinate agent creation
- `agent.system.tool.code_exe.md` - Code execution tool
- `agent.system.tool.browser.md` - Browser agent tool
- `agent.system.tool.a2a_chat.md` - Agent-to-Agent communication
- `agent.system.tool.notify_user.md` - User notifications

**Memory System**
- `memory.consolidation.sys.md` - Memory consolidation analysis (merge, replace, keep_separate)
- `memory.memories_filter.sys.md` - AI-based memory filtering
- `memory.memories_query.sys.md` - Memory search queries
- `memory.memories_sum.sys.md` - Memory summarization

**Integration**
- `agent.system.mcp_tools.md` - MCP tool integration placeholder
- `agent.system.main.communication_additions.md` - Communication extensions

### CONVENTIONS

**Prompt Editing**
- Edit markdown files directly - no code changes required
- Changes take effect on next agent message
- Use `{{ include "path.md" }}` for prompt composition
- Substitutions like `{{tools}}` for dynamic content

**Naming Patterns**
- `fw.*.md` - Framework-level utility prompts
- `agent.system.*.md` - Core agent behavior
- `agent.system.tool.*.md` - Tool-specific instructions
- `memory.*.msg.md` / `memory.*.sys.md` - Message vs system prompts

**Response Format**
- Use `~~~json` for code blocks
- `§§include(<path>)` alias includes previous tool results
- Follow JSON structure for tool calls (thoughts, headline, tool_name, tool_args)

**Behavior Modification**
- `behaviour.merge.sys.md` - Merges new behavior into existing ruleset
- `behaviour.search.sys.md` - Searches behavior patterns
- Changes affect agent's approach to tasks

**Prompt Inheritance**
- Agent profiles can override prompts in `/agents/{profile}/prompts/`
- Same filename replaces default prompt
- Subordinate agents inherit from parent unless overridden
