# Agent Zero Configuration Guide

**Flexy's Manifesto**: *No hardcoded values! Everything configurable!*

## Overview

Agent Zero uses a centralized configuration system that allows all important values to be customized via environment variables. This document describes how to configure the framework.

## Configuration Sources (Priority Order)

1. **Environment Variables** (highest priority)
2. **Configuration Files** (`python/helpers/constants.py`)
3. **Default Values** (lowest priority)

## Quick Reference

### Network Ports

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_DEFAULT_PORT` | 5000 | Main Web UI port |
| `A0_SEARXNG_PORT` | 55510 | SearXNG search port |
| `A0_TUNNEL_API_PORT` | 55520 | Tunnel API port |
| `A0_BROCULA_PORT` | 50001 | Brocula agent port |
| `A0_RFC_PORT_HTTP` | 55080 | RFC HTTP port |
| `A0_RFC_PORT_SSH` | 55022 | RFC SSH port |
| `A0_A2A_PORT` | 50101 | A2A protocol port |

### Network Settings

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_DEFAULT_HOSTNAME` | localhost | Default hostname |
| `A0_DEFAULT_LOCALHOST` | 127.0.0.1 | Default localhost IP |
| `A0_DEV_CORS_ORIGINS` | *://localhost:*,*://127.0.0.1:*,*://0.0.0.0:* | CORS origins (comma-separated) |

### File Paths

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_PROJECTS_DIR` | usr/projects | Projects directory |
| `A0_MEMORY_PATH` | memory | Memory storage directory |
| `A0_UPLOAD_FOLDER` | /a0/tmp/uploads | Upload folder path |
| `A0_WHISPER_MODEL_ROOT` | /tmp/models/whisper | Whisper model directory |

### External URLs

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_UPDATE_CHECK_URL` | https://api.agent-zero.ai/a0-update-check | Update check endpoint |
| `A0_PERPLEXITY_API_BASE_URL` | https://api.perplexity.ai | Perplexity API base *(deprecated)* |

> [!WARNING]
> **Perplexity integration is deprecated.** SearXNG is now the primary search provider.
> These variables are maintained for backward compatibility only and may be removed in a future release.
| `A0_VENICE_API_BASE` | https://api.venice.ai/api/v1 | Venice.ai API base |
| `A0_OPENROUTER_API_BASE` | https://openrouter.ai/api/v1 | OpenRouter API base |
| `A0_OPENROUTER_HTTP_REFERER` | https://agent-zero.ai/ | OpenRouter referer header |
| `A0_AGENT_ZERO_REPO_URL` | https://github.com/frdel/agent-zero | Repository URL |

### Timeout Settings

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_CODE_EXEC_TIMEOUT` | 180 | Code execution timeout (seconds) |
| `A0_BROWSER_TIMEOUT` | 300 | Browser operation timeout (seconds) |
| `A0_NOTIFICATION_LIFETIME_HOURS` | 24 | Notification lifetime (hours) |
| `A0_MCP_SERVER_APPLY_DELAY` | 1 | MCP server apply delay (seconds) |
| `A0_TUNNEL_CHECK_DELAY` | 2 | Tunnel check delay (seconds) |

### Memory Settings

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_MAX_MEMORY_RESULTS` | 10 | Maximum memory results |
| `A0_MEMORY_THRESHOLD` | 0.7 | Memory similarity threshold |

### Browser Settings

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_BROWSER_ALLOWED_DOMAINS` | *,http://*,https://* | Allowed domains (comma-separated) |

### Model Defaults

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_CHAT_MODEL_PROVIDER` | openrouter | Default chat model provider |
| `A0_CHAT_MODEL_NAME` | openai/gpt-4.1 | Default chat model |
| `A0_UTIL_MODEL_PROVIDER` | openrouter | Default utility model provider |
| `A0_UTIL_MODEL_NAME` | openai/gpt-4.1-mini | Default utility model |
| `A0_EMBED_MODEL_PROVIDER` | huggingface | Default embedding provider |
| `A0_EMBED_MODEL_NAME` | sentence-transformers/all-MiniLM-L6-v2 | Default embedding model |
| `A0_BROWSER_MODEL_PROVIDER` | openrouter | Default browser model provider |
| `A0_BROWSER_MODEL_NAME` | openai/gpt-4.1 | Default browser model |

## Usage Examples

### Docker Compose

```yaml
services:
  agent-zero:
    image: agent0ai/agent-zero
    environment:
      - A0_DEFAULT_PORT=8080
      - A0_SEARXNG_PORT=55511
      - A0_PROJECTS_DIR=/data/projects
      - A0_MEMORY_PATH=/data/memory
```

### Shell

```bash
export A0_DEFAULT_PORT=8080
export A0_SEARXNG_PORT=55511
python run_ui.py
```

### Systemd Service

```ini
[Service]
Environment=A0_DEFAULT_PORT=8080
Environment=A0_MEMORY_THRESHOLD=0.8
```

## Frontend Configuration

The frontend automatically receives configuration from the backend via `window.ENV_CONFIG`. This is injected into the HTML when the page is served.

### Available Frontend Config

The following values are available in `window.ENV_CONFIG`:

```javascript
{
  WEB_UI_PORT: 5000,
  TUNNEL_API_PORT: 55520,
  SEARXNG_PORT: 55510,
  A2A_PORT: 50101,
  BROCULA_PORT: 50001,
  RFC_PORT_HTTP: 55080,
  RFC_PORT_SSH: 55022,
  HOSTNAME: "localhost",
  LOCALHOST: "127.0.0.1",
  // ... and more
}
```

## Architecture

### Backend Constants (`python/helpers/constants.py`)

The backend uses a class-based constant system:

```python
class Network:
    WEB_UI_PORT_DEFAULT: Final[int] = 5000
    SEARXNG_PORT_DEFAULT: Final[int] = 55510
    # ...

class Config:
    """Runtime configuration with environment variable support"""
    DEFAULT_PORT = get_env_int("A0_DEFAULT_PORT", Network.WEB_UI_PORT_DEFAULT)
    # ...
```

### Frontend Constants (`webui/js/constants.js`)

The frontend uses a modular export system:

```javascript
export const API = {
  WEB_UI_PORT: getEnvConfig('WEB_UI_PORT', 5000),
  // ...
};
```

### Configuration Module (`python/helpers/config.py`)

A dedicated module handles frontend configuration injection:

```python
def get_frontend_config() -> Dict[str, Any]:
    """Get configuration for frontend injection"""
    return {
        "WEB_UI_PORT": ConstConfig.DEFAULT_PORT,
        # ...
    }
```

## Migration Guide

### From Hardcoded to Configurable

**Before (hardcoded):**
```python
port = 5000
```

**After (configurable):**
```python
from python.helpers.constants import Config
port = Config.DEFAULT_PORT  # Uses A0_DEFAULT_PORT env var or defaults to 5000
```

## Best Practices

1. **Always use Config class** - Never hardcode values in new code
2. **Add env var support** - When adding new constants, add corresponding env var
3. **Document changes** - Update this file when adding new configuration options
4. **Use type hints** - All Config class attributes should be typed
5. **Test overrides** - Verify environment variable overrides work correctly

## Troubleshooting

### Changes Not Taking Effect

1. Restart the application after changing environment variables
2. Check for typos in variable names
3. Verify the variable is exported: `echo $A0_DEFAULT_PORT`

### Frontend Not Reflecting Changes

1. Clear browser cache
2. Verify `window.ENV_CONFIG` in browser console
3. Check backend logs for configuration loading errors

## Contributing

When adding new configurable values:

1. Add the constant to the appropriate class in `constants.py`
2. Add environment variable support to `Config` class
3. Update this documentation
4. Add to frontend config in `config.py` if needed
5. Test with and without environment variable override
