# AGENTS.md - python/helpers

## OVERVIEW
70+ utility modules providing core framework functionality for agents, memory, files, scheduling, MCP, and system operations.

## STRUCTURE
```
python/helpers/
├── Core Systems
│   ├── memory.py - FAISS vector DB (main/fragments/solutions/instruments areas)
│   ├── history.py - Message history with summarization (Message, Topic, Bulk)
│   ├── settings.py - Settings management (1758 lines - complexity hotspot)
│   ├── task_scheduler.py - Crontab-based scheduled tasks (adhoc/scheduled/planned)
│   ├── projects.py - Project isolation (usr/projects, .a0proj metadata)
│   └── secrets.py - Secure credential management (placeholder §§secret(KEY))
├── MCP Integration
│   ├── mcp_handler.py - MCP server/client initialization & management
│   ├── mcp_server.py - FastA2A HTTP streaming server
│   └── fasta2a_*.py - A2A protocol client/server
├── File Operations
│   ├── files.py - File I/O helpers (read, write, zip, import plugins)
│   ├── file_tree.py - Directory tree rendering with gitignore support
│   ├── file_browser.py - WebUI file browser (upload/download/preview)
│   └── rfc_files.py - RFC protocol file operations
├── Data & Search
│   ├── document_query.py - Document RAG with embeddings
│   ├── knowledge_import.py - Knowledge base import
│   ├── dirty_json.py - Lenient JSON parser
│   └── searxng.py, duckduckgo_search.py - Search providers
├── Communications
│   ├── email_client.py - Email sending/receiving
│   ├── notification.py - In-app notifications
│   └── persist_chat.py - Chat persistence
├── Browser & Tools
│   ├── browser.py - Browser agent integration
│   ├── playwright.py - Playwright automation
│   ├── tool.py - Tool base class
│   └── extract_tools.py - Tool extraction from files
└── Infrastructure
    ├── runtime.py - Runtime environment detection
    ├── docker.py - Docker operations
    ├── rate_limiter.py - API rate limiting
    ├── localization.py - Timezone/i18n
    └── log.py - Logging system
```

## WHERE TO LOOK
| Task | Module | Notes |
|------|--------|-------|
| Agent memory | `memory.py` | FAISS with areas (main/fragments/solutions/instruments), AI filtering, consolidation |
| Message history | `history.py` | Token-aware compression, topics, bulk merging, langchain conversion |
| Settings | `settings.py` | 1758 lines - needs refactoring to background tasks (5 TODOs) |
| Scheduled tasks | `task_scheduler.py` | CronTab wrapper, task states (idle/running/disabled/error) |
| Projects | `projects.py` | Project isolation with own prompts/files/memory/secrets |
| Secrets | `secrets.py` | StreamingSecretsFilter masks secrets in real-time output |
| MCP servers | `mcp_handler.py` | Initializes local/remote/streamable HTTP MCP servers |
| File trees | `file_tree.py` | PathSpec gitignore, depth/line limits, nested/flat/string output |
| Backup | `backup.py` | JSON metadata patterns, checksum validation, git integration |
| Document RAG | `document_query.py` | Multi-document embedding search with AI filtering |
| Tool loading | `extract_tools.py` | Dynamic tool extraction from Python files |

## CONVENTIONS
- **Numeric prefixes**: Not used in helpers (unlike extensions)
- **Singleton patterns**: `Memory.index`, `MCPConfig.get_instance()`
- **TypedDict**: Heavy use for data structures (Settings, BasicProjectData, etc.)
- **Pydantic models**: Used for config (TaskSchedule, TaskPlan, etc.)
- **FAISS patch**: `faiss_monkey_patch.py` required for Python 3.12 ARM (TODO remove upstream fix)
- **Streaming**: StreamingSecretsFilter for real-time secret masking
- **Context-aware**: Most modules accept `agent` or `AgentContext` parameters
- **Path resolution**: Use `files.get_abs_path()` for consistent paths

## ANTI-PATTERNS
- **Settings blocking**: settings.py has 5 TODOs about replacing blocking operations with background tasks (lines 1558, 1616, 1621, 1631, 1643)
- **Vision inefficiency**: history.py:218 - FIXME: vision bytes sent to utility LLM (send summary instead)
- **FAISS patch**: vector_db.py, memory.py - Monkey patch for Python 3.12 ARM (temporary workaround)
- **Job timing**: job_loop.py:34 - TODO: lowering SLEEP_TIME below 1min causes job duplication
- **MCP prompts**: mcp_handler.py:742-744 - TODO: inline prompts should be external prompt files
