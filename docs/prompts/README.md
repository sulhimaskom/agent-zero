#KM|
#QM|> Last Updated: 2026-02-28
# Prompts Directory

Agent Zero is a **prompt-driven framework** — the entire behavior of the framework is defined by markdown files in this directory. Modifying these prompts changes how agents behave, communicate, and solve problems.

## Overview

| Statistic | Value |
|-----------|-------|
| Total Files | 96 |
| Purpose | Control all agent behavior and system responses |
| Format | Markdown (`.md`) with some Python (`.py`) |

## Naming Conventions

| Prefix | Meaning |
|--------|---------|
| `agent.system.*` | System-level prompts defining agent behavior |
| `agent.extras.*` | Additional context injected into agent prompts |
| `agent.context.*` | Contextual information for specific scenarios |
| `behaviour.*` | Behavior modification prompts |
| `browser_agent.*` | Browser automation agent prompts |
| `fw.*` | Framework-level prompts (messages, errors, hints) |
| `memory.*` | Memory system prompts (recall, consolidation) |

## Prompt Categories

### 1. Agent System Prompts (`agent.system.*`)

Core prompts defining how agents operate.

| File | Purpose |
|------|---------|
| `agent.system.main.md` | Main agent behavior and core instructions |
| `agent.system.main.communication.md` | Communication protocols with superiors/subordinates |
| `agent.system.main.communication_additions.md` | Additional communication rules |
| `agent.system.main.environment.md` | Environment context and working directory |
| `agent.system.main.role.md` | Role definitions for agent hierarchy |
| `agent.system.main.solving.md` | Problem-solving strategies |
| `agent.system.main.tips.md` | Helpful tips for the agent |

### 2. Tool Prompts (`agent.system.tool.*`)

Definitions for built-in tools the agent can use.

| File | Purpose |
|------|---------|
| `agent.system.tools.md` | List of available tools |
| `agent.system.tool.call_sub.md` | Creating and managing subordinate agents |
| `agent.system.tool.code_exe.md` | Code execution in Docker containers |
| `agent.system.tool.memory.md` | Memory storage and retrieval |
| `agent.system.tool.browser.md` | Browser automation |
| `agent.system.tool.search_engine.md` | Web search capabilities |
| `agent.system.tool.scheduler.md` | Scheduled task management |
| `agent.system.tool.wait.md` | Wait/pause functionality |
| `agent.system.tool.notify_user.md` | User notifications |
| `agent.system.tool.input.md` | User input requests |
| `agent.system.tool.a2a_chat.md` | Agent-to-Agent protocol communication |
| `agent.system.tool.document_query.md` | Document Q&A functionality |
| `agent.system.tool.response.md` | Response formatting |
| `agent.system.tool.behaviour.md` | Tool behavior modifications |
| `agent.system.tools_vision.md` | Vision/image processing tools |

**Python Tool Files:**
- `agent.system.tool.call_sub.py` — Subordinate agent implementation
- `agent.system.tools.py` — Tools list implementation

### 3. Project Prompts (`agent.system.projects.*`)

Project-specific behavior.

| File | Purpose |
|------|---------|
| `agent.system.projects.main.md` | Main project management |
| `agent.system.projects.active.md` | Active project context |
| `agent.system.projects.inactive.md` | Inactive project handling |

### 4. Memory Prompts (`memory.*`)

Memory system behavior — how agents remember and recall information.

| File | Purpose |
|------|---------|
| `memory.memories_query.sys.md` | Memory retrieval queries |
| `memory.memories_query.msg.md` | Memory query message format |
| `memory.memories_sum.sys.md` | Memory summarization |
| `memory.memories_filter.sys.md` | AI-based memory filtering |
| `memory.memories_filter.msg.md` | Memory filter message format |
| `memory.keyword_extraction.sys.md` | Keyword extraction for memories |
| `memory.keyword_extraction.msg.md` | Keyword extraction messages |
| `memory.consolidation.sys.md` | Memory consolidation (saving) |
| `memory.consolidation.msg.md` | Consolidation message format |
| `memory.solutions_query.sys.md` | Solution retrieval queries |
| `memory.solutions_sum.sys.md` | Solution summarization |
| `memory.recall_delay_msg.md` | Delayed recall messages |
| `memory.memories_not_found.md` | Memory not found response |
| `memory.memories_deleted.md` | Memory deletion confirmation |

### 5. Framework Prompts (`fw.*`)

System messages, errors, hints, and responses.

| Category | Files | Purpose |
|----------|-------|---------|
| **Messages** | `fw.user_message.md`, `fw.initial_message.md`, `fw.msg_summary.md`, `fw.msg_truncated.md`, `fw.msg_timeout.md`, `fw.msg_cleanup.md`, `fw.msg_misformat.md`, `fw.msg_from_subordinate.md`, `fw.msg_repeat.md` | User and message handling |
| **Code Execution** | `fw.code.running.md`, `fw.code.info.md`, `fw.code.max_time.md`, `fw.code.no_out_time.md`, `fw.code.no_output.md`, `fw.code.pause_dialog.md`, `fw.code.pause_time.md`, `fw.code.reset.md`, `fw.code.runtime_wrong.md` | Code execution states |
| **Memory** | `fw.memory.hist_sum.sys.md`, `fw.memory.hist_suc.sys.md`, `fw.memory_saved.md` | Memory system messages |
| **Document Query** | `fw.document_query.system_prompt.md`, `fw.document_query.optmimize_query.md` | Document Q&A |
| **Knowledge** | `fw.knowledge_tool.response.md` | Knowledge base responses |
| **Utilities** | `fw.rename_chat.sys.md`, `fw.rename_chat.msg.md`, `fw.tool_not_found.md`, `fw.tool_result.md`, `fw.warning.md`, `fw.error.md`, `fw.hint.call_sub.md`, `fw.intervention.md`, `fw.ai_response.md`, `fw.wait_complete.md`, `fw.bulk_summary.sys.md`, `fw.bulk_summary.msg.md`, `fw.topic_summary.sys.md`, `fw.topic_summary.msg.md`, `fw.notify_user.notification_sent.md` | Various utilities |

### 6. Agent Extras (`agent.extras.*`)

Additional context and information.

| File | Purpose |
|------|---------|
| `agent.extras.agent_info.md` | Agent information display |
| `agent.extras.project.file_structure.md` | Project file structure display |

### 7. Behaviour Prompts (`behaviour.*`)

Behavior modification and state tracking.

| File | Purpose |
|------|---------|
| `behaviour.search.sys.md` | Search behavior |
| `behaviour.merge.sys.md`, `behaviour.merge.msg.md` | Merge behavior |
| `behaviour.updated.md` | Update notifications |

### 8. Browser Agent (`browser_agent.*`)

Browser automation specific prompts.

| File | Purpose |
|------|---------|
| `browser_agent.system.md` | Browser agent system prompt |

### 9. Context (`agent.context.*`)

Contextual information.

| File | Purpose |
|------|---------|
| `agent.context.extras.md` | Additional context |

## Modifying Prompts

### How It Works

1. Prompts are loaded at runtime from the `prompts/` directory
2. The framework assembles prompts based on the agent's current context
3. Changes take effect immediately on restart

### Best Practices

1. **Backup before changes** — Copy the original file
2. **Make small changes** — Test incrementally
3. **Use clear naming** — If adding new prompts, follow the existing convention
4. **Document your changes** — Note what you modified and why

### Example: Customizing Agent Behavior

To make agents more cautious about running code:

```markdown
<!-- Edit agent.system.tool.code_exe.md -->
<!-- Add a warning about code execution -->
```

## Key Files to Know

| Priority | File | Why |
|----------|------|-----|
| 🔴 Essential | `agent.system.main.md` | Core agent behavior |
| 🔴 Essential | `agent.system.main.communication.md` | Inter-agent communication |
| 🟠 Important | `agent.system.tool.*` | Tool capabilities |
| 🟡 Useful | `memory.*` | Memory behavior |
| 🟢 Reference | `fw.*` | System messages |

## Related Documentation

- [Architecture Overview](../architecture.md) — System design
- [Extensibility](../extensibility.md) — Extending the framework
- [Usage Guide](../usage.md) — Basic usage
