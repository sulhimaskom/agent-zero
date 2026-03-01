# AGENT ZERO - AGENT PROFILES

**Generated:** 2026-02-25
**Commit:** d7c3076
**Branch:** custom

## OVERVIEW
Agent profiles enable different agent personalities with custom prompts, tools, and extensions. Override defaults via same-filename replacement.

## STRUCTURE
```
agents/
├── agent0/              # Default agent profile
│   ├── _context.md     # Agent context configuration
│   └── prompts/         # Override framework prompts
├── brocula/             # Browser console & Lighthouse specialist
│   ├── README.md         # Brocula documentation
│   ├── brocula.py       # Main brocula script
│   ├── brocula_loop.py # Brocula loop script
│   ├── mcp-servers.json # MCP server configuration
│   ├── prompts/         # BroCula system prompts
│   ├── reports/        # Generated reports
│   └── tools/          # Browser monitoring tools
├── developer/          # Developer personality
│   ├── _context.md
│   └── prompts/
├── hacker/             # Security researcher personality
│   ├── _context.md
│   └── prompts/
├── researcher/         # Research analyst personality
│   ├── _context.md
│   └── prompts/
├── default/            # Base profile for agents
│   └── _context.md
└── _example/          # Example profile template
    ├── extensions/
    ├── prompts/
    └── tools/
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Create new profile | `agents/{profile}/` | Copy structure from existing profiles |
| Override agent behavior | `agents/{profile}/prompts/agent.system.main.md` | Core system prompt override |
| Override tools | `agents/{profile}/tools/` | Same filename replaces default |
| Override extensions | `agents/{profile}/extensions/{hook}/` | Same filename replaces default |
| Add profile-specific prompts | `agents/{profile}/prompts/` | Custom .md files |
| Add profile-specific tools | `agents/{profile}/tools/` | Custom .py tools |

## CONVENTIONS

### Profile Structure
- Each profile has optional: `_context.md`, `prompts/`, `tools/`, `extensions/`
- `_context.md`: Agent context configuration file (required for agent behavior)
- `prompts/`: Custom markdown prompts for agent behavior
- `tools/`: Profile-specific tool overrides
- `extensions/`: Profile-specific extension overrides
- Subdirectories mirror default structure: `/prompts/`, `/python/tools/`, `/python/extensions/`
- No subdirectory = uses default framework behavior
- All profiles should have `_context.md` for proper agent initialization

### Override Mechanism
- **Filename matching**: Same filename replaces default (e.g., `call_subordinate.py` in profile overrides default)
- **Inheritance**: Profile inherits from parent unless override exists
- **Cascading**: agent0 → developer/hacker/researcher → subordinate

### Prompts
- Override framework prompts: `agent.system.main.md`, `fw.*.md`
- Add profile-specific prompts: any `.md` file
- Markdown files, edit directly to change behavior

### Tools
- Override: Copy same filename from `/python/tools/`
- Add: New `.py` files extending `Tool` base class
- Async `execute()` method required

### Extensions
- Override in hook directories: `message_loop_start/`, `before_main_llm_call/`, etc.
- Use numeric prefixes for ordering: `_10_*.py`, `_20_*.py`
- Files in profile override defaults in `/python/extensions/`

### Subordinate Agents
- `call_subordinate()` tool creates subordinate agent
- Can specify profile: `profile="hacker"`
- Subordinate inherits prompts/tools/extensions unless overridden

## ANTI-PATTERNS

### Forbidden
- **DO NOT edit vendor files** - Profile overrides only
- **DO NOT modify framework defaults** - Override in profile instead

### Common Mistakes
- Wrong filename for override - Must match default filename exactly
- Missing `__init__.py` - Required for Python package imports

## UNIQUE STYLES

### Prompt-Driven Profiles
- Agent personality defined by markdown files
- No code changes needed for behavior changes
- Framework prompts overridden, not modified

### Hierarchical Inheritance
- Subordinate agents inherit from parent
- Cascading overrides: profile → subordinate
- Flexible multi-agent delegation

### Profile Selection
- Set profile via UI settings
- Subordinate profiles configurable per call
- Dynamic agent switching during conversations

## COMMANDS
```bash
# Create new profile
cp -r agents/_example agents/my-profile
# Edit prompts/agent.system.main.md to define personality
# Add custom tools/tools/ if needed

# Activate profile in UI
# Settings → Agent → Select profile
```

## NOTES
- **No code required** to create new agents - just markdown prompts
- **Inheritance-based** - Profiles build on each other
- **Runtime switching** - Change agent profile without restart
- **Persistent across chats** - Profile setting saved in agent context
