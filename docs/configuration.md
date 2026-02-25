# Agent Zero Configuration Guide

Agent Zero uses a centralized configuration system that allows all important values to be customized via environment variables. This guide covers all configuration options and best practices.

> **Flexy's Manifesto**: *No hardcoded values, everything configurable!*

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Sources](#configuration-sources-priority-order)
- [Environment Variables Reference](#environment-variables-reference)
  - [Network Configuration](#network-configuration)
  - [API Endpoints](#api-endpoints)
  - [Model Defaults](#model-defaults)
  - [Security \& Browser](#security--browser)
  - [Timeouts \& Limits](#timeouts--limits)
  - [File Paths](#file-paths)
- [Usage Examples](#usage-examples)
  - [Docker](#docker)
  - [Docker Compose](#docker-compose)
  - [Shell](#shell)
  - [Systemd Service](#systemd-service)
- [Docker Build Arguments](#docker-build-arguments)
- [Frontend Configuration](#frontend-configuration)
- [Architecture](#architecture)
- [Migration Guide](#migration-guide)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Quick Start

Set any configuration value using environment variables with the `A0_` prefix:

```bash
export A0_DEFAULT_HOSTNAME=0.0.0.0
export A0_CHAT_MODEL_NAME=anthropic/claude-3-opus-20240229
export A0_WEB_UI_PORT=8080
python run_ui.py
```

Or with Docker:

```bash
docker run -e A0_DEFAULT_HOSTNAME=0.0.0.0 -e A0_CHAT_MODEL_NAME=gpt-4 -p 50001:80 agent0ai/agent-zero
```

---

## Configuration Sources (Priority Order)

1. **Environment Variables** (highest priority) - Override any setting
2. **Configuration Files** (`python/helpers/constants.py`)
3. **Default Values** (lowest priority)

All changes are non-breaking - if an environment variable is not set, the system falls back to the previous default value.

---

## Environment Variables Reference

### Network Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_DEFAULT_HOSTNAME` | `localhost` | Default hostname for web UI and SSH connections |
| `A0_DEFAULT_LOCALHOST` | `127.0.0.1` | Default localhost IP address |
| `A0_DEFAULT_PORT` | `5000` | Default port for the web UI |
| `A0_SEARXNG_PORT` | `55510` | Port for SearXNG search service |
| `A0_TUNNEL_CHECK_DELAY` | `2` | Delay between tunnel status checks (seconds) |
| `A0_DEV_CORS_ORIGINS` | `*://localhost:*,*://127.0.0.1:*,*://0.0.0.0:*` | Comma-separated list of allowed CORS origins |

#### Network Ports Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_TUNNEL_API_PORT` | `55520` | Tunnel API port |
| `A0_BROCULA_PORT` | `50001` | Brocula agent port |
| `A0_RFC_PORT_HTTP` | `55080` | RFC HTTP port |
| `A0_RFC_PORT_SSH` | `55022` | RFC SSH port |
| `A0_A2A_PORT` | `50101` | A2A protocol port |

#### CORS Configuration Example

```bash
export A0_DEV_CORS_ORIGINS="*://localhost:*,*://127.0.0.1:*,https://mydomain.com"
```

---

### API Endpoints

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_UPDATE_CHECK_URL` | `https://api.agent-zero.ai/a0-update-check` | URL for checking Agent Zero updates |
| `A0_AGENT_ZERO_REPO_URL` | `https://github.com/frdel/agent-zero` | Agent Zero repository URL |
| `A0_VENICE_API_BASE` | `https://api.venice.ai/api/v1` | Venice.ai API base URL |
| `A0_OPENROUTER_API_BASE` | `https://openrouter.ai/api/v1` | OpenRouter API base URL |
| `A0_OPENROUTER_HTTP_REFERER` | `https://agent-zero.ai/` | HTTP Referer header for OpenRouter |
| `A0_OPENROUTER_X_TITLE` | `Agent Zero` | X-Title header for OpenRouter |

> [!WARNING]
> **Perplexity integration is deprecated.** SearXNG is now the primary search provider. These variables are maintained for backward compatibility only:
> - `A0_PERPLEXITY_API_BASE_URL` (default: `https://api.perplexity.ai`)
> - `A0_PERPLEXITY_DEFAULT_MODEL` (default: `llama-3.1-sonar-large-128k-online`)
>
> See [SearXNG Integration](architecture.md#searxng-integration) for the recommended search configuration.

---

### Model Defaults

#### Chat Model

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_CHAT_MODEL_PROVIDER` | `openrouter` | Default chat model provider |
| `A0_CHAT_MODEL_NAME` | `openai/gpt-4.1` | Default chat model name |

#### Utility Model

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_UTIL_MODEL_PROVIDER` | `openrouter` | Default utility model provider |
| `A0_UTIL_MODEL_NAME` | `openai/gpt-4.1-mini` | Default utility model name |

#### Embedding Model

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_EMBED_MODEL_PROVIDER` | `huggingface` | Default embedding model provider |
| `A0_EMBED_MODEL_NAME` | `sentence-transformers/all-MiniLM-L6-v2` | Default embedding model name |

#### Browser Model

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_BROWSER_MODEL_PROVIDER` | `openrouter` | Default browser automation model provider |
| `A0_BROWSER_MODEL_NAME` | `openai/gpt-4.1` | Default browser automation model name |

---

### Security & Browser

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_BROWSER_ALLOWED_DOMAINS` | `*,http://*,https://*` | Comma-separated list of allowed domains for browser agent |
| `CODE_EXEC_SSH_ADDR` | `localhost` | SSH address for code execution |
| `CODE_EXEC_SSH_PORT` | `55022` | SSH port for code execution |
| `CODE_EXEC_SSH_USER` | `root` | SSH user for code execution |
| `CODE_EXEC_SSH_PASS` | (empty) | SSH password for code execution |

#### Browser Allowed Domains Examples

Allow all domains (default):
```bash
export A0_BROWSER_ALLOWED_DOMAINS="*,http://*,https://*"
```

Restrict to specific domains:
```bash
export A0_BROWSER_ALLOWED_DOMAINS="example.com,*.example.com,api.github.com"
```

---

### Timeouts & Limits

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_CODE_EXEC_TIMEOUT` | `180` | Code execution timeout (seconds) |
| `A0_BROWSER_TIMEOUT` | `300` | Browser operation timeout (seconds) |
| `A0_MAX_MEMORY_RESULTS` | `10` | Maximum memory results to return |
| `A0_MEMORY_THRESHOLD` | `0.7` | Memory similarity threshold (0.0-1.0) |
| `A0_NOTIFICATION_LIFETIME_HOURS` | `24` | Notification lifetime (hours) |
| `A0_MCP_SERVER_APPLY_DELAY` | `1` | MCP server apply delay (seconds) |
| `A0_TUNNEL_CHECK_DELAY` | `2` | Tunnel check delay (seconds) |

---

### File Paths

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `A0_PROJECTS_DIR` | `usr/projects` | Directory for projects |
| `A0_MEMORY_PATH` | `memory` | Directory for memory storage |
| `SECRETS_PATH` | `tmp/secrets.env` | Path to secrets file |
| `A0_UPLOAD_FOLDER` | `/a0/tmp/uploads` | Upload folder path |
| `A0_WHISPER_MODEL_ROOT` | `/tmp/models/whisper` | Whisper model directory |
| `WEB_UI_HOST` | `localhost` | Web UI host (also used by run_ui.py) |

---

## Usage Examples

### Docker

```bash
docker run -e A0_DEFAULT_PORT=8080 -e A0_CHAT_MODEL_NAME=gpt-4 -p 50001:80 agent0ai/agent-zero
```

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

---

## Docker Build Arguments

When building Docker images, you can customize:

| Argument | Default | Description |
|----------|---------|-------------|
| `BRANCH` | (required) | Git branch to build from |
| `CACHE_DATE` | `none` | Cache busting date string |
| `LOCALE` | `en_US.UTF-8` | System locale |
| `TZ` | `UTC` | System timezone |

#### Docker Build Examples

Build with specific branch:
```bash
docker build -f docker/run/Dockerfile --build-arg BRANCH=main -t agent-zero .
```

Build with custom locale and timezone:
```bash
docker build -f docker/base/Dockerfile \
  --build-arg LOCALE=de_DE.UTF-8 \
  --build-arg TZ=Europe/Berlin \
  -t agent-zero-base .
```

---

## Frontend Configuration

The frontend supports runtime configuration via `window.ENV_CONFIG`:

```html
<script>
window.ENV_CONFIG = {
  HOSTNAME: 'my-server.local',
  WEB_UI_PORT: 8080,
  TUNNEL_API_PORT: 55521
};
</script>
```

### Available Frontend Config Options

| Key | Default | Description |
|-----|---------|-------------|
| `HOSTNAME` | `localhost` | API hostname |
| `LOCALHOST` | `127.0.0.1` | Localhost IP |
| `WEB_UI_PORT` | `5000` | Web UI port |
| `TUNNEL_API_PORT` | `55520` | Tunnel API port |
| `SEARXNG_PORT` | `55510` | SearXNG port |
| `A2A_PORT` | `50101` | A2A protocol port |
| `BROCULA_PORT` | `50001` | Brocula agent port |
| `RFC_PORT_HTTP` | `55080` | RFC HTTP port |
| `RFC_PORT_SSH` | `55022` | RFC SSH port |

The frontend automatically receives configuration from the backend via `window.ENV_CONFIG`. This is injected into the HTML when the page is served.

---

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

---

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

### From Previous Versions

If you previously modified code to change configuration values:

1. Remove your code changes
2. Set the corresponding environment variable
3. Restart Agent Zero

---

## Best Practices

1. **Always use Config class** - Never hardcode values in new code
2. **Add env var support** - When adding new constants, add corresponding env var with `A0_` prefix
3. **Document changes** - Update this documentation when adding new configuration options
4. **Use type hints** - All Config class attributes should be typed
5. **Test overrides** - Verify environment variable overrides work correctly
6. **Sensible defaults** - Provide sensible defaults for backward compatibility

---

## Troubleshooting

### Changes Not Applied

1. Ensure environment variable names use the `A0_` prefix
2. Check that variables are exported (use `export` in bash)
3. Verify variables are set before starting Agent Zero
4. For Docker, ensure `-e` flags are before the image name
5. Restart the application after changing environment variables
6. Check for typos in variable names
7. Verify the variable is exported: `echo $A0_DEFAULT_PORT`

### Frontend Not Reflecting Changes

1. Clear browser cache
2. Verify `window.ENV_CONFIG` in browser console
3. Check backend logs for configuration loading errors

### Verify Configuration

Check current configuration in Python:

```python
from python.helpers.constants import Config
print(Config.DEFAULT_HOSTNAME)
print(Config.CHAT_MODEL_NAME)
```

### Docker Issues

If Docker containers fail to start:
- Consult the Docker documentation
- Verify your Docker installation and configuration
- On macOS, ensure you've granted Docker access to your project files in Docker Desktop settings
- Verify that the Docker image is updated

### Terminal Commands Not Executing

- Ensure the Docker container is running and properly configured
- Check SSH settings if applicable
- Verify the Docker image is updated

### Performance Issues

If Agent Zero is slow or unresponsive, it might be due to:
- Resource limitations
- Network latency
- Complexity of prompts and tasks (especially when using local models)

---

## Contributing

When adding new configurable values:

1. Add to `python/helpers/constants.py` in the `Config` class
2. Use the `get_env_*` helper functions
3. Prefix with `A0_`
4. Update this documentation
5. Provide sensible defaults for backward compatibility
6. Add to frontend config in `config.py` if needed
7. Test with and without environment variable override

---

*Flexy says: "No hardcoded values, no problems!"*
