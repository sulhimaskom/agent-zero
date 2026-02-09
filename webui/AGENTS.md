# AGENT ZERO - WEBUI FRONTEND

**Generated:** 2026-01-13
**Commit:** a99361d
**Branch:** custom

## OVERVIEW
Alpine.js-based frontend with modular component stores, direct ES module loading (no bundler), centralized API layer.

## STRUCTURE
```
webui/
├── index.html          # Main HTML entry point
├── index.js           # Main JS module (691 lines)
├── js/                # Core modules (18 files)
│   ├── api.js         # Centralized API with CSRF
│   ├── messages.js    # Message rendering (1009 lines)
│   ├── scheduler.js   # Scheduler UI (1835 lines - LARGEST JS FILE)
│   ├── settings.js    # Settings management
│   ├── AlpineStore.js # Store factory with Proxy reactivity
│   └── ...          # Other utility modules
├── components/        # Feature-specific Alpine.js stores (75 files)
│   ├── chat/         # Input, speech, attachments
│   ├── settings/     # Memory, backup, MCP, tunnel, scheduler
│   ├── sidebar/      # Chats, tasks, projects, preferences
│   ├── modals/       # History, file-browser, image-viewer
│   ├── notifications/ # Notification system
│   └── messages/    # Message rendering components
├── css/               # Styling
└── vendor/            # Minified libraries (DO NOT EDIT)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Alpine.js store patterns | `js/AlpineStore.js` | Proxy-based reactivity, pre-init support |
| API communication | `js/api.js` | Centralized fetch with CSRF, callJsonApi wrapper |
| Message rendering | `js/messages.js` | 1009 lines, message formatting, streaming |
| Scheduler UI | `js/scheduler.js` | 1835 lines - complexity hotspot |
| Chat input | `components/chat/input/` | Text input, attachments, voice input |
| Speech/TTS | `components/chat/speech/` | speech-store.js (967 lines), Whisper STT, Kokoro TTS |
| Settings pages | `components/settings/` | Modular stores for memory, backup, MCP, tunnel |
| Sidebar navigation | `components/sidebar/` | Chats list, tasks, projects, preferences |
| File browser | `components/modals/` | file-browser-store.js, directory tree |
| Notifications | `components/notifications/` | notification-store.js (806 lines) |

## CONVENTIONS

### Alpine.js Stores
- Each feature has its own `-store.js` file in `components/{feature}/`
- Use `AlpineStore()` factory from `js/AlpineStore.js`
- Proxy-based reactivity works before/after Alpine initialization
- Stores imported via ES modules in HTML

### Component Organization
- Feature-based: `chat/`, `settings/`, `sidebar/`, `modals/`, `notifications/`
- Each feature directory contains: `-store.js`, HTML components, CSS
- Components use `x-component` custom tag (loaded via `js/components.js`)

### API Integration
- Centralized in `js/api.js`
- `fetchApi()` wrapper with CSRF token management
- `callJsonApi()` for JSON endpoints
- File uploads via `FormData` with multipart/form-data

### No Bundler
- Direct ES module loading (no webpack/vite/rollup)
- `jsconfig.json` path mapping: `"*": ["webui/*"]`
- Vendor libraries in `webui/vendor/` (minified, do not edit)

### Message Flow
- `js/messages.js` handles message rendering, streaming, updates
- `sendMessage()` in `index.js` sends to backend
- Streaming responses handled via long-polling (`/poll` endpoint)

## ANTI-PATTERNS

### Complexity Hotspots
- `js/scheduler.js` (1835 lines) - Split into smaller modules
- `js/messages.js` (1009 lines) - Split into rendering/streaming logic
- `components/chat/speech/speech-store.js` (967 lines) - Extract TTS/STT logic

### Console Logging
- 539 `console.*` calls across webui JavaScript files
- Should use proper logging framework

## UNIQUE STYLES

### Pre-Init Stores
- `AlpineStore.js` creates Proxy-based stores that work before Alpine.init()
- Pre-defined stores in `index.html` to avoid initialization race conditions

### Component System
- Custom `x-component` tag for modular components
- Automatic loading via `js/components.js` with caching

### Direct ES Modules
- No build step, no bundler
- Modern browser features only (ES6+)
- Path mapping via `jsconfig.json`

## COMMANDS
```bash
# No build required - static files served directly
# Development: python run_ui.py --development=true
# Production: Docker (see docker/run/)
```

## NOTES
- **No TypeScript** - Pure JavaScript with JSDoc comments
- **No linting config** - No ESLint/Prettier
- **Console logging** - Extensive use for debugging
- **Vendor files** - `webui/vendor/` contains minified libraries (DO NOT EDIT)
