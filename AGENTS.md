# AGENT ZERO PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-12
**Branch:** custom
**Commit:** 5dfe61f

## OVERVIEW
Multi-agent AI framework with Python backend (Flask) + JavaScript frontend (Alpine.js). Prompt-driven behavior - everything controlled by `/prompts/` markdown files. Grows organically through memory, tools, extensions, and agent profiles.

## STRUCTURE
```
./
├── agents/              # Agent profiles (agent0, developer, hacker, researcher) with custom prompts/tools/extensions
├── prompts/             # 98 system prompts defining framework behavior (fw.* = framework, agent.system.* = agent behavior)
├── python/
│   ├── api/            # 61 Flask API endpoints (auto-registered via ApiHandler base class)
│   ├── helpers/        # 70+ utility modules (memory, history, settings, mcp, scheduler)
│   ├── tools/          # 18 default tools (code_execution, browser_agent, memory_*, call_subordinate)
│   └── extensions/     # 23 lifecycle hook points (message_loop_*, response_stream*, system_prompt)
├── webui/              # Frontend (Alpine.js stores, modular components, 96 code files)
│   ├── components/     # chat/, settings/, sidebar/, modals/, projects/, notifications/
│   ├── js/            # ES modules, stores (scheduler.js 1835 lines, messages.js 1009 lines)
│   └── css/           # Styling
├── conf/               # model_providers.yaml (15+ LLM providers), projects.default.gitignore
├── docker/             # base/ (Debian 13 slim, Python 3.13+3.12) + run/ (runtime container)
├── docs/               # Comprehensive documentation (architecture, extensibility, installation)
├── instruments/        # Custom scripts/procedures for agent use
├── knowledge/          # RAG document storage (separate from agent memory)
├── lib/                # Library dependencies (browser automation, etc.)
├── memory/             # FAISS vector DB for agent's persistent learnings
├── tests/              # pytest tests (minimal coverage, no CI integration)
└── usr/                # User-specific configurations and data
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Change agent behavior | `/prompts/agent.system.main.md` | Core system prompt - controls entire framework |
| Add tools | `/python/tools/` or `/agents/{profile}/tools/` | Agent-specific overrides defaults |
| Add extensions | `/python/extensions/{hook}/` or `/agents/{profile}/extensions/{hook}/` | Use numeric prefixes (_10_, _20_) for ordering |
| API endpoints | `/python/api/` | Classes inheriting `ApiHandler` auto-register as Flask routes |
| Memory management | `/python/helpers/memory.py` | FAISS vector DB, semantic search, AI filtering |
| History & context | `/python/helpers/history.py` | Message summarization, context management |
| Settings | `/python/helpers/settings.py` | 1795 lines - complexity hotspot, needs refactoring to background tasks |
| MCP integration | `/python/helpers/mcp_handler.py` | Server + client for Model Context Protocol |
| Scheduler | `/python/helpers/task_scheduler.py` | Crontab-based scheduled tasks |
| Agent profiles | `/agents/{profile}/` | Each has prompts/, tools/, extensions/ subdirs |
| Model config | `/conf/model_providers.yaml` | LiteLLM provider configurations |
| Docker build | `/docker/` | Two-stage: base (Debian) → runtime (Agent Zero) |
| LLM abstraction | `/models.py` | LiteLLM wrappers for chat/embedding/browser models |
| Core agent loop | `/agent.py` | Agent class, AgentContext, AgentConfig |
| Frontend stores | `/webui/components/{feature}/*-store.js` | Alpine.js component stores |
| Frontend API | `/webui/js/api.js` | Centralized fetch wrapper with CSRF |

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
- No bundler (direct ES module loading)

### Frontend Stores
- Alpine.js Proxy-based reactivity (see `/webui/js/AlpineStore.js`)
- Modular: each feature has its own `-store.js` file
- Centralized API calls via `/webui/js/api.js`

## ANTI-PATTERNS (THIS PROJECT)

### Forbidden
- **NEVER edit vendor files** (`webui/vendor/` minified libraries)
- **NEVER expose SSH root login** in production (enabled by default in Docker)
- **NEVER use eval/exec** - safe `simple_eval()` only in controlled contexts

### Code Smells (TODOs to address)
- `/python/helpers/settings.py` - Multiple TODOs about replacing with background tasks (lines 1558, 1616, 1621, 1631, 1643) - CRITICAL complexity hotspot
- `/python/helpers/task_scheduler.py` - 1384 lines, consider splitting task types from scheduler logic
- `/python/helpers/mcp_handler.py` - 1187 lines, TODO about inline prompts (lines 742-744)
- `/python/helpers/history.py:236` - FIXME: vision bytes sent to utility LLM (inefficiency)
- `/python/helpers/vector_db.py`, `/python/helpers/memory.py` - FAISS patch for Python 3.12 ARM (remove when fixed upstream)
- `/python/helpers/job_loop.py:34` - TODO: lowering SLEEP_TIME below 1min causes job duplication
- 174 `# type: ignore` comments across 47 files - type suppression issues
- 257 `except Exception as e:` handlers - broad exception catching
- 366 print statements across 39 files - should use proper logging

### Testing
- pytest.ini exists and configured (asyncio mode, markers, test paths)
- conftest.py exists with fixtures and mocks
- All 29 tests passing
- Tests not run in CI (GitHub workflows use OpenCode AI agent only)
- Mixed naming: `test_*.py` and `*_test.py` both used
- Coverage tool not configured

### Build/CI Non-Standard Patterns
- **AI-powered CI**: GitHub workflows use OpenCode AI agent (opencode.ai) instead of traditional pytest/linting
- **Debian base**: `debian:13-slim` (minimal, secure base image)
- **Dual Python**: 3.13 system-wide + 3.12.4 via pyenv at `/opt/venv-a0`
- **No pyproject.toml**: Uses requirements.txt only (not installable as package)
- **No frontend bundler**: Direct ES module loading, no webpack/vite

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
- Debian 13 slim base (secure, minimal)
- Optional Kali Linux variant for security tools (`agent0ai/agent-zero:hacking`)
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

### Frontend Architecture
- Alpine.js with Proxy-based reactivity for pre-init stores
- Modular component stores (no monolithic state)
- Direct ES module loading (no bundler)
- Centralized API layer with CSRF management

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
- **Settings module** (1795 lines) identified as complexity hotspot needing refactoring
- **Large files**: `agent.py` (741 lines), `models.py` (919 lines), `settings.py` (1795 lines), `task_scheduler.py` (1384 lines), `mcp_handler.py` (1187 lines)
- **Large frontend files**: `webui/js/scheduler.js` (1835 lines), `webui/js/messages.js` (1009 lines), `webui/components/chat/speech/speech-store.js` (967 lines)
- **FAISS patch required** for Python 3.12 ARM - temporary workaround
- **57 bare `pass` statements** - mostly in base classes/abstract methods (acceptable)
- **No traditional testing** - CI uses AI code analysis instead of pytest runs
- **Automatic SSH password generation** - `prepare.py` generates random root password (security concern for production)
