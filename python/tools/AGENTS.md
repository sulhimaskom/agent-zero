# AGENTS.md - python/tools

## OVERVIEW
18 default tools enabling agents to execute code, search, manage memory, communicate, and delegate to subordinates.

## STRUCTURE
```
python/tools/
├── Core Execution
│   ├── code_execution_tool.py - Python/Node.js/Shell runtime (local + SSH)
│   ├── input.py - Interactive terminal input
│   └── wait.py - Duration or timestamp-based delays
├── Browser & Search
│   ├── browser_agent.py - Headless browser automation (browser-use)
│   ├── search_engine.py - SearXNG search integration
│   └── vision_load.py - Image loading for vision models
├── Memory & Knowledge
│   ├── memory_save.py - Store learnings (main/fragments/solutions/instruments)
│   ├── memory_load.py - Semantic memory search with thresholds
│   ├── memory_delete.py - Delete by memory IDs
│   ├── memory_forget.py - Forget by similarity search
│   └── document_query.py - RAG document Q&A
├── Agent Communication
│   ├── call_subordinate.py - Multi-agent delegation
│   ├── a2a_chat.py - Agent-to-Agent protocol (FastA2A)
│   └── response.py - Final response to user
├── System & Scheduler
│   ├── scheduler.py - Scheduled/adhoc/planned tasks (CronTab)
│   ├── notify_user.py - In-app notifications
│   └── behaviour_adjustment.py - Runtime behavior updates
└── Utilities
    └── unknown.py - Fallback for unrecognized tools
```

## WHERE TO LOOK
| Tool | Purpose |
|------|---------|
| `code_execution_tool.py` | Execute Python (ipython), Node.js, shell commands. Session-based (multiple concurrent). Supports SSH remote execution. Dialog detection for Y/N prompts. |
| `browser_agent.py` | Headless Chromium automation via browser-use library. Screenshot streaming. Max 50 steps per task. Handles secrets via masks. |
| `search_engine.py` | SearXNG search integration. Returns title, URL, content snippets. Configurable result count (default: 10). |
| `call_subordinate.py` | Create subordinate agent with dedicated profile. Subordinate runs monologue, reports result back. Superior-subordinate hierarchy. |
| `memory_save.py` | Insert text into FAISS vector DB. Optional area (main/fragments/solutions/instruments). Returns memory ID. |
| `memory_load.py` | Semantic search with threshold (default 0.7) and limit (default 10). AI-filtered retrieval. |
| `memory_delete.py` | Delete specific memories by comma-separated IDs. |
| `memory_forget.py` | Forget memories by similarity search query. |
| `response.py` | Send final response to user. Breaks agent loop (`break_loop=True`). |
| `document_query.py` | RAG document querying. Supports multiple documents, multiple queries. Returns content or Q&A answers. |
| `input.py` | Interactive keyboard input for terminal sessions. Forwards to code_execution_tool with `allow_running=True`. |
| `wait.py` | Delay by duration (seconds/minutes/hours/days) or until timestamp. Manages intervention during wait. |
| `scheduler.py` | Task scheduling: list_tasks, find_task_by_name, show_task, run_task, delete_task, create_scheduled_task, create_adhoc_task, create_planned_task, wait_for_task. CronTab expressions validated via regex. |
| `notify_user.py` | Display in-app notifications (title, message, detail, type, priority, timeout). |
| `vision_load.py` | Load images for vision-capable LLMs. Compresses to JPEG (max 768k pixels, quality 75). Base64 encoded. Token estimate: 1500 per image. |
| `a2a_chat.py` | Agent-to-Agent communication via FastA2A protocol. Maintains session cache per agent_url. Supports attachments, reset. |
| `behaviour_adjustment.py` | Runtime behavior modification via LLM merging. Writes `behaviour.md` in memory subdir. |
| `unknown.py` | Fallback tool when LLM calls unrecognized tool name. Returns available tools list. |

## CONVENTIONS
- **Base class**: All tools extend `python.helpers.tool.Tool` abstract class
- **Async execution**: `async def execute(self, **kwargs) -> Response:` is required
- **Return type**: Must return `Response(message: str, break_loop: bool, additional: dict | None)`
- **Hook methods**: `before_execution()`, `after_execution()`, `get_log_object()` optional overrides
- **Tool override**: Copy same filename to `/agents/{profile}/tools/` to replace default
- **Tool methods**: Tools can have multiple methods via `self.method` attribute (e.g., `scheduler.py:list_tasks`)
- **Progress updates**: Use `self.set_progress()` / `self.add_progress()` for real-time updates
- **Logging**: `self.log.update()` updates persistent log object
- **Intervention**: Call `await self.agent.handle_intervention()` to pause for user intervention
