# AGENT ZERO - WEBUI JAVASCRIPT MODULES

**Generated:** 2026-01-13
**Commit:** a99361d
**Branch:** custom

## OVERVIEW
Core JavaScript modules for frontend - ES modules, API layer, message handling, scheduler UI.

## STRUCTURE
```
webui/js/
├── api.js              # Centralized API with CSRF (main entry point)
├── messages.js          # Message rendering (1009 lines)
├── scheduler.js         # Scheduler UI (1835 lines - LARGEST JS FILE)
├── settings.js         # Settings management (591 lines)
├── AlpineStore.js      # Store factory with Proxy reactivity
├── components.js       # Component loader system
├── speech_browser.js   # Speech/TTS for browser (394 lines)
├── modals.js          # Modal management (292 lines)
└── ...                # Other utility modules
```

## WHERE TO LOOK
| Module | Purpose | Notes |
|---------|---------|-------|
| `api.js` | Centralized API layer | CSRF token management, fetchApi wrapper, callJsonApi |
| `messages.js` | Message rendering | 1009 lines, message formatting, streaming, HTML sanitization |
| `scheduler.js` | Scheduler UI | 1835 lines - complexity hotspot, crontab editor, task management |
| `settings.js` | Settings pages | Settings storage, validation, persistence |
| `AlpineStore.js` | Store factory | Proxy-based reactivity, pre-init support |
| `components.js` | Component loader | x-component tag, caching, ES module loading |
| `speech_browser.js` | Browser speech | Whisper STT, Kokoro TTS integration |
| `modals.js` | Modal system | Show/hide modals, escape key handling |

## CONVENTIONS

### ES Modules
- All modules use `export` syntax
- Import via `import { ... } from '...'`
- No bundler (webpack/vite) - direct browser loading

### API Communication
- `api.js` is main entry point
- `fetchApi()` - Generic fetch with CSRF
- `callJsonApi()` - JSON endpoint wrapper
- `api.*` methods for specific endpoints (e.g., `api.sendMessage()`, `api.getSettings()`)

### Store Factory
- `AlpineStore()` in `AlpineStore.js`
- Returns Proxy-based reactive object
- Works before/after Alpine initialization

### Component Loading
- `components.js` handles `x-component` tags
- Caches loaded components
- Dynamic ES module imports

### Message Handling
- `messages.js` renders messages to DOM
- Streaming responses via long-polling
- HTML sanitization for security

## ANTI-PATTERNS

### Complexity Hotspots
- `scheduler.js` (1835 lines) - Split into smaller modules (crontab editor, task list, task detail)
- `messages.js` (1009 lines) - Separate rendering logic from streaming logic

### Console Logging
- Extensive `console.log()` usage for debugging
- Should use proper logging framework

## UNIQUE STYLES

### Proxy-Based Stores
- `AlpineStore.js` creates Proxy objects for reactivity
- Allows stores to work before Alpine.init()
- Enables dynamic property tracking

### Direct ES Module Loading
- No build step
- Browser-native ES6 modules
- `jsconfig.json` path mapping for imports

### Long-Polling
- Message streaming via `/poll` endpoint
- Real-time updates without WebSockets
- Automatic reconnection

## COMMANDS
```bash
# No build required
# Modules loaded directly in browser
# Serve via: python run_ui.py --port=80
```

## NOTES
- **No TypeScript** - Pure JavaScript with JSDoc comments
- **No linting** - No ESLint configuration
- **No bundling** - Direct ES module loading
- **Console debugging** - Extensive console.log usage
