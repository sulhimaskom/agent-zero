# AGENTS ZERO PROJECT KNOWLEDGE BASE - API DIRECTORY

**Generated:** 2026-01-10
**Commit:** ee31349
**Branch:** custom

## OVERVIEW
61 Flask API endpoint handlers auto-registered via ApiHandler base class.

## STRUCTURE
- **Chat & Messages**: message, message_async, chat_load/create/remove/reset/export, poll, api_message/api_reset_chat/api_terminate_chat
- **Memory & Knowledge**: memory_dashboard, knowledge_reindex, knowledge_path_get, import_knowledge
- **Settings**: settings_get, settings_set
- **Projects**: projects
- **Scheduler**: scheduler_task_create/update/delete/run/tick/tasks_list (7 endpoints)
- **MCP**: mcp_servers_status/apply/get_log/get_detail
- **Backup**: backup_create/restore/inspect/test/preview/preview_grouped/get_defaults
- **Notifications**: notification_create/mark_read/clear/history
- **Files**: upload/download_work_dir_file, get_work_dir_files, delete_work_dir_file, file_info, chat_files_path_get
- **Tunnel**: tunnel, tunnel_proxy
- **Utilities**: health, csrf_token, ctx_window_get, nudge, pause, restart, transcribe, rfc, synthesize, image_get

## WHERE TO LOOK
| Endpoint | Purpose |
|----------|---------|
| message.py | Main chat message handling - multipart/form-data support, file attachments, context management |
| chat_load/create/remove/reset/export.py | Chat persistence operations - load/save/delete/export JSON chat files |
| settings_get/set.py | Settings API - retrieve and modify agent configuration |
| memory_dashboard.py | Memory management UI - search, delete, update, bulk delete, subdirectory support |
| projects.py | Project CRUD - list/create/update/delete, activate/deactivate, file structure |
| knowledge_reindex/import.py | Knowledge base operations - reload memory, import documents for RAG |
| scheduler_task_* | Task scheduler - create/read/update/delete/run tasks, crontab scheduling |
| mcp_servers_status/apply/get_*.py | MCP integration - server status, apply configs, get logs/details |
| backup_create/restore/inspect/test/preview*.py | Backup operations - create/restore backups, inspect contents, pattern filtering |
| notification_create/mark_read/clear/history.py | Notifications - create notifications with priority/type, mark read, clear history |
| files (upload/download/get_work_dir_files/delete*.py) | File browser - upload/download files, browse work directory, delete files |
| tunnel.py, tunnel_proxy.py | Remote access tunnels - create/stop/get tunnels (serveo, localtunnel, ngrok), proxy requests |
| api_message/api_reset_chat/api_terminate_chat/api_files_get/api_log_get.py | External API - auth via API key, optional web auth, message handling |

## CONVENTIONS

### Auto-Registration Pattern
- Extend `ApiHandler` base class from `python.helpers.api`
- Implement async `process(self, input: Input, request: Request) -> Output` method
- Filename determines Flask route: `message.py` → `/message`, `chat_load.py` → `/chat_load`
- All `*.py` files in `python/api/` auto-register at runtime via `run_ui.py`

### Authentication & Authorization
Override class methods:
- `requires_auth()` → `True` (default) requires web authentication
- `requires_api_key()` → `True` requires API key authentication
- `requires_csrf()` → `True` (default) requires CSRF token (mirrors auth)
- `requires_loopback()` → `True` restricts to localhost only
- `get_methods()` → `["GET"]` or `["POST"]` (default) or `["GET", "POST"]`

### Return Types
- Return `dict` for JSON response (auto-serialized to JSON)
- Return `Response` object for custom responses (files, errors, custom status)
- Exceptions return HTTP 500 with error message

### Context Management
- `self.use_context(ctxid)` → Get/create AgentContext by ID
- `self.thread_lock` → Thread-safe context access (inherited from base)
- Context automatically created if `ctxid` is empty or not provided
