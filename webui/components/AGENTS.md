# AGENT ZERO - WEBUI COMPONENTS

**Generated:** 2026-01-13
**Commit:** a99361d
**Branch:** custom

## OVERVIEW
Modular Alpine.js component stores organized by feature (75 files), each with own store, HTML, CSS.

## STRUCTURE
```
webui/components/
├── chat/              # Chat interaction (input, speech, attachments)
│   ├── input/         # Text input, send button
│   ├── speech/         # TTS/STT, speech-store.js (967 lines)
│   ├── attachments/    # File attachments, attachmentsStore.js
│   └── top-section/   # Chat header, context info
├── settings/          # Settings pages (memory, backup, MCP, tunnel, scheduler)
│   ├── memory/        # Memory dashboard, memory-dashboard-store.js (713 lines)
│   ├── backup/        # Backup/restore, backup-store.js (825 lines)
│   ├── mcp/          # MCP server configuration
│   │   ├── client/    # MCP client settings
│   │   └── server/    # MCP server settings
│   ├── tunnel/        # Tunnel configuration, tunnel-store.js (430 lines)
│   └── scheduler/     # Task scheduler settings
├── sidebar/           # Navigation (chats, tasks, projects, preferences)
│   ├── chats/         # Chats list, chats-store.js (334 lines)
│   ├── tasks/         # Task scheduler, sidebar-tasks-store.js
│   ├── projects/      # Project management, projects-store.js (436 lines)
│   ├── top-section/   # Sidebar header
│   └── preferences/  # User preferences
├── modals/            # Modals/overlays
│   ├── history/       # Chat history modal
│   ├── file-browser/  # File browser with directory tree
│   ├── image-viewer/  # Image preview modal
│   └── context/      # Context menu
└── notifications/     # Notification system
    └── notification-store.js (806 lines)
```

## WHERE TO LOOK
| Feature | Location | Notes |
|---------|----------|-------|
| Chat input | `chat/input/` | Text area, send button, formatting |
| Speech TTS/STT | `chat/speech/` | Whisper STT, Kokoro TTS, speech-store.js (967 lines) |
| File attachments | `chat/attachments/` | Upload, preview, delete |
| Memory dashboard | `settings/memory/` | Search, delete, update memories, memory-dashboard-store.js (713 lines) |
| Backup/restore | `settings/backup/` | Backup management, backup-store.js (825 lines) |
| MCP configuration | `settings/mcp/` | Client/server settings, connection status |
| Tunnel management | `settings/tunnel/` | serveo, localtunnel, ngrok, tunnel-store.js (430 lines) |
| Scheduler UI | `settings/scheduler/` | Crontab tasks, scheduled/adhoc/planned |
| Chats list | `sidebar/chats/` | Chat history, switch, delete, rename |
| Task sidebar | `sidebar/tasks/` | Quick task access from scheduler |
| Projects | `sidebar/projects/` | Project switching, creation, deletion |
| File browser | `modals/file-browser/` | Directory tree, upload/download |
| Notifications | `notifications/` | In-app notifications, notification-store.js (806 lines) |

## CONVENTIONS

### Component Structure
- Each feature directory contains: `-store.js`, HTML templates, CSS
- Store file follows `{feature}-store.js` naming
- Uses `AlpineStore()` factory from `js/AlpineStore.js`

### State Management
- Each component manages its own state via Alpine.js reactive object
- Store methods prefixed with actions (e.g., `loadMemories()`, `deleteMemory()`)
- Async actions marked with `async` keyword

### API Calls
- Use centralized `api.callJsonApi()` for JSON endpoints
- File uploads via `FormData` to `api.upload()`
- Long-polling for message streaming

### Modals
- Each modal has its own store with `show` boolean
- Use `x-show` for visibility control
- Close via click outside or escape key

## ANTI-PATTERNS

### Complexity Hotspots
- `chat/speech/speech-store.js` (967 lines) - Extract TTS/STT logic
- `settings/backup/backup-store.js` (825 lines) - Split backup/restore logic
- `notifications/notification-store.js` (806 lines) - Simplify notification handling
- `settings/memory/memory-dashboard-store.js` (713 lines) - Extract search/filter logic

## UNIQUE STYLES

### Modular Stores
- Each feature isolated with own store
- No monolithic state management
- Component communication via Alpine events or direct method calls

### File Browser Modal
- Directory tree with gitignore support
- Upload/download via API
- Integrated with agent's file system

### Notification System
- In-app notifications (not browser notifications)
- Priority levels (low, medium, high)
- Auto-dismiss with timeout
