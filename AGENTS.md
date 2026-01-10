# AGENT ZERO PROJECT KNOWLEDGE BASE

**Generated:** 2026-01-10
**Commit:** ee31349
**Branch:** custom

## OVERVIEW
Multi-agent AI framework with Python backend (Flask) + JavaScript frontend (Alpine.js). Prompt-driven behavior - everything controlled by `/prompts/` markdown files. Grows organically through memory, tools, extensions, and agent profiles.

## STRUCTURE
```
./
├── agents/              # Agent profiles (agent0, developer, hacker, researcher) with custom prompts/tools/extensions
├── prompts/             # 90+ system prompts defining framework behavior (fw.* = framework, agent.system.* = agent behavior)
├── python/
│   ├── api/            # 61 Flask API endpoints (auto-registered via ApiHandler base class)
│   ├── helpers/        # 70+ utility modules (memory, history, settings, mcp, scheduler)
│   ├── tools/          # 18 default tools (code_execution, browser_agent, memory_*, call_subordinate)
│   └── extensions/     # 23 lifecycle hook points (message_loop_*, response_stream*, system_prompt)
├── webui/              # Frontend (Alpine.js stores, modular components)
│   ├── components/     # chat/, settings/, sidebar/, modals/, projects/, notifications/
│   ├── js/            # ES modules, stores
│   └── css/           # Styling
├── conf/               # model_providers.yaml (15+ LLM providers), projects.default.gitignore
├── docker/             # base/ (Kali Linux, Python 3.13+3.12) + run/ (runtime container)
├── docs/               # Comprehensive documentation (architecture, extensibility, installation)
├── tests/              # pytest tests (minimal coverage, no CI integration)
├── instruments/        # Custom scripts/procedures for agent use
├── knowledge/          # RAG document storage (separate from agent memory)
└── memory/            # FAISS vector DB for agent's persistent learnings
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Change agent behavior | `/prompts/agent.system.md` | Core system prompt - controls entire framework |
| Add tools | `/python/tools/` or `/agents/{profile}/tools/` | Agent-specific overrides defaults |
| Add extensions | `/python/extensions/{hook}/` or `/agents/{profile}/extensions/{hook}/` | Use numeric prefixes (_10_, _20_) for ordering |
| API endpoints | `/python/api/` | Classes inheriting `ApiHandler` auto-register as Flask routes |
| Memory management | `/python/helpers/memory.py` | FAISS vector DB, semantic search, AI filtering |
| History & context | `/python/helpers/history.py` | Message summarization, context management |
| Settings | `/python/helpers/settings.py` | 1758 lines - needs refactoring to background tasks |
| MCP integration | `/python/helpers/mcp_handler.py` | Server + client for Model Context Protocol |
| Scheduler | `/python/helpers/task_scheduler.py` | Crontab-based scheduled tasks |
| Agent profiles | `/agents/{profile}/` | Each has prompts/, tools/, extensions/ subdirs |
| Model config | `/conf/model_providers.yaml` | LiteLLM provider configurations |
| Docker build | `/docker/` | Two-stage: base (Kali) → runtime (Agent Zero) |
| LLM abstraction | `/models.py` | LiteLLM wrappers for chat/embedding/browser models |
| Core agent loop | `/agent.py` | Agent class, AgentContext, AgentConfig |

## CONVENTIONS

### Agent Profiles
- `/agents/{profile}/prompts/` - Override default prompts
- `/agents/{profile}/tools/` - Override default tools
- `/agents/{profile}/extensions/` - Override default extensions
- Subordinate agents inherit prompts/tools from parent unless overridden

### Extensions
- 23 hook points: `agent_init/`, `before_main_llm_call/`, `message_loop_start/end`, `message_loop_prompts_after`, `system_prompt`, `recall_memories`, `memorize_fragments`, `response_stream_chunk`, `mask_secrets`
- Use numeric prefixes: `_10_*.py`, `_20_*.py` for execution order
- Files in `/agents/{profile}/extensions/` override `/python/extensions/`

### Tools
- Default in `/python/tools/`
- Agent-specific in `/agents/{profile}/tools/`
- Tool override: same filename replaces default

### API Handlers
- Extend `ApiHandler` base class
- Auto-register as Flask route based on class name pattern
- See `/python/api/message.py` for example

### JavaScript
- ES modules in `/webui/js/`
- Alpine.js stores in `/webui/components/{feature}/*-store.js`
- Path mapping: `jsconfig.json` maps `*` to `webui/*`

## ANTI-PATTERNS (THIS PROJECT)

### Forbidden
- **NEVER edit vendor files** (`webui/vendor/` minified libraries)
- **NEVER expose SSH root login** in production (enabled by default in Docker)
- **NEVER use eval/exec** - safe `simple_eval()` only in controlled contexts

### Code Smells (TODOs to address)
- `/python/helpers/settings.py` - Multiple TODOs about replacing with background tasks (lines 1558, 1616, 1621, 1631, 1643)
- `/python/helpers/vector_db.py`, `/python/helpers/memory.py` - FAISS patch for Python 3.12 ARM (remove when fixed upstream)
- `/python/helpers/history.py:218` - FIXME: vision bytes sent to utility LLM (inefficiency)

### Testing
- No pytest.ini, conftest.py, or fixtures - default pytest only
- Tests not run in CI (GitHub workflows use OpenCode AI agent only)
- Mixed naming: `test_*.py` and `*_test.py` both used
- Coverage tool not configured

## UNIQUE STYLES

### Prompt-Driven Architecture
- Entire framework behavior controlled by markdown files in `/prompts/`
- `fw.*.md` files = framework-level prompts
- `agent.system.*.md` files = agent-level prompts
- Edit prompts, not code, to change behavior

### Multi-Agent Hierarchy
- Every agent has a superior (Agent 0's superior is the human user)
- Agents create subordinates via `call_subordinate.py` tool
- Subordinates can have dedicated prompts, tools, extensions
- Communication flows: superior → task → subordinate → report → superior

### MCP & A2A Protocols
- **MCP**: Agent Zero acts as MCP server OR uses external MCP servers as tools
- **A2A**: Agent-to-Agent protocol for inter-agent communication

### Docker-Centric Runtime
- Kali Linux base (unusual for web services)
- Dual Python: 3.13 system-wide + 3.12.4 via pyenv at `/opt/venv-a0`
- Branch-based builds via `ARG BRANCH`
- Preload models in Docker build (`preload.py --dockerized=true`)
- Multi-arch builds: `docker buildx --platform linux/amd64,linux/arm64`

### Memory System
- `/memory/` - Agent's own learnings (FAISS vector DB)
- `/knowledge/` - Reference documents for RAG (separate from memory)
- AI filter for memory retrieval
- Consolidated memories saved automatically

### Projects
- Isolated workspaces with own prompts, files, memory, secrets
- `.a0proj/` directory (gitignored via projects.default.gitignore)

## COMMANDS
```bash
# Run locally (development)
python run_ui.py --development=true -Xfrozen_modules=off

# Run tests
pytest tests/

# Docker build (local)
docker build -f DockerfileLocal -t agent-zero-local --build-arg CACHE_DATE=$(date +%Y-%m-%d:%H:%M:%S) .

# Docker run
docker run -p 50001:80 agent0ai/agent-zero
```

## NOTES
- **No LSP servers installed** - relies on VS Code Python extension for type checking
- **CI is AI-powered** - GitHub workflows use OpenCode agent, not traditional pytest/linting
- **Settings module** (1758 lines) identified as complexity hotspot needing refactoring
- **Large files**: `agent.py` (923 lines), `models.py` (920 lines), `settings.py` (1758 lines)
- **FAISS patch required** for Python 3.12 ARM - temporary workaround
- **56 bare `pass` statements** - mostly in base classes/abstract methods (acceptable)
- **No traditional testing** - CI uses AI code analysis instead of pytest runs
