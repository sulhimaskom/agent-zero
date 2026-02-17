# Agent Zero Configuration Guide

**Flexy's Modular Configuration System**

This guide documents all environment variables available for configuring Agent Zero without modifying code.

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

## Table of Contents

- [Network Configuration](#network-configuration)
- [API Endpoints](#api-endpoints)
- [Model Defaults](#model-defaults)
- [Security & Browser](#security--browser)
- [Timeouts & Limits](#timeouts--limits)
- [File Paths](#file-paths)
- [Docker Build Arguments](#docker-build-arguments)
- [Frontend Configuration](#frontend-configuration)

---

## Network Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_DEFAULT_HOSTNAME` | `localhost` | Default hostname for web UI and SSH connections |
| `A0_DEFAULT_LOCALHOST` | `127.0.0.1` | Default localhost IP address |
| `A0_DEFAULT_PORT` | `5000` | Default port for the web UI |
| `A0_SEARXNG_PORT` | `55510` | Port for SearXNG search service |
| `A0_TUNNEL_CHECK_DELAY` | `2` | Delay between tunnel status checks (seconds) |

### CORS Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_DEV_CORS_ORIGINS` | `*://localhost:*,*://127.0.0.1:*,*://0.0.0.0:*` | Comma-separated list of allowed CORS origins |

Example:
```bash
export A0_DEV_CORS_ORIGINS="*://localhost:*,*://127.0.0.1:*,https://mydomain.com"
```

---

## API Endpoints

All external API endpoints are fully configurable:

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_UPDATE_CHECK_URL` | `https://api.agent-zero.ai/a0-update-check` | URL for checking Agent Zero updates |
| `A0_PERPLEXITY_API_BASE_URL` | `https://api.perplexity.ai` | Perplexity API base URL *(deprecated)* |
| `A0_PERPLEXITY_DEFAULT_MODEL` | `llama-3.1-sonar-large-128k-online` | Default Perplexity model *(deprecated)* |

> [!WARNING]
> **Perplexity integration is deprecated.** SearXNG is now the primary search provider.
> These variables are maintained for backward compatibility only and may be removed in a future release.
> See [SearXNG Integration](architecture.md#searxng-integration) for the recommended search configuration.
| `A0_AGENT_ZERO_REPO_URL` | `https://github.com/frdel/agent-zero` | Agent Zero repository URL |
| `A0_VENICE_API_BASE` | `https://api.venice.ai/api/v1` | Venice.ai API base URL |
| `A0_VENICE_API_BASE` | `https://api.agent-zero.ai/venice/v1` | Agent Zero Venice proxy URL |
| `A0_OPENROUTER_API_BASE` | `https://openrouter.ai/api/v1` | OpenRouter API base URL |
| `A0_OPENROUTER_HTTP_REFERER` | `https://agent-zero.ai/` | HTTP Referer header for OpenRouter |
| `A0_OPENROUTER_X_TITLE` | `Agent Zero` | X-Title header for OpenRouter |

---

## Model Defaults

Configure default models without changing code:

### Chat Model

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_CHAT_MODEL_PROVIDER` | `openrouter` | Default chat model provider |
| `A0_CHAT_MODEL_NAME` | `openai/gpt-4.1` | Default chat model name |

### Utility Model

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_UTIL_MODEL_PROVIDER` | `openrouter` | Default utility model provider |
| `A0_UTIL_MODEL_NAME` | `openai/gpt-4.1-mini` | Default utility model name |

### Embedding Model

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_EMBED_MODEL_PROVIDER` | `huggingface` | Default embedding model provider |
| `A0_EMBED_MODEL_NAME` | `sentence-transformers/all-MiniLM-L6-v2` | Default embedding model name |

### Browser Model

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_BROWSER_MODEL_PROVIDER` | `openrouter` | Default browser automation model provider |
| `A0_BROWSER_MODEL_NAME` | `openai/gpt-4.1` | Default browser automation model name |

---

## Security & Browser

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_BROWSER_ALLOWED_DOMAINS` | `*,http://*,https://*` | Comma-separated list of allowed domains for browser agent |
| `CODE_EXEC_SSH_ADDR` | `localhost` | SSH address for code execution |
| `CODE_EXEC_SSH_PORT` | `55022` | SSH port for code execution |
| `CODE_EXEC_SSH_USER` | `root` | SSH user for code execution |
| `CODE_EXEC_SSH_PASS` | `` | SSH password for code execution |

### Browser Allowed Domains Examples

Allow all domains (default):
```bash
export A0_BROWSER_ALLOWED_DOMAINS="*,http://*,https://*"
```

Restrict to specific domains:
```bash
export A0_BROWSER_ALLOWED_DOMAINS="example.com,*.example.com,api.github.com"
```

---

## Timeouts & Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_CODE_EXEC_TIMEOUT` | `180` | Code execution timeout (seconds) |
| `A0_BROWSER_TIMEOUT` | `300` | Browser operation timeout (seconds) |
| `A0_MAX_MEMORY_RESULTS` | `10` | Maximum memory results to return |
| `A0_MEMORY_THRESHOLD` | `0.7` | Memory similarity threshold (0.0-1.0) |
| `A0_NOTIFICATION_LIFETIME_HOURS` | `24` | Notification lifetime (hours) |
| `A0_MCP_SERVER_APPLY_DELAY` | `1` | MCP server apply delay (seconds) |

---

## File Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `A0_PROJECTS_DIR` | `usr/projects` | Directory for projects |
| `A0_MEMORY_PATH` | `memory` | Directory for memory storage |
| `SECRETS_PATH` | `tmp/secrets.env` | Path to secrets file |
| `WEB_UI_HOST` | `localhost` | Web UI host (also used by run_ui.py) |

---

## Docker Build Arguments

When building Docker images, you can customize:

| Argument | Default | Description |
|----------|---------|-------------|
| `BRANCH` | (required) | Git branch to build from |
| `CACHE_DATE` | `none` | Cache busting date string |
| `LOCALE` | `en_US.UTF-8` | System locale |
| `TZ` | `UTC` | System timezone |

### Docker Build Examples

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

---

## Complete Configuration Example

```bash
#!/bin/bash
# Agent Zero Configuration Script

# Network
export A0_DEFAULT_HOSTNAME=0.0.0.0
export A0_DEFAULT_PORT=8080
export A0_DEV_CORS_ORIGINS="*://localhost:*,https://mydomain.com"

# Models
export A0_CHAT_MODEL_PROVIDER=anthropic
export A0_CHAT_MODEL_NAME=claude-3-opus-20240229
export A0_UTIL_MODEL_NAME=claude-3-haiku-20240307

# API Endpoints
export A0_OPENROUTER_API_BASE=https://openrouter.ai/api/v1
export A0_PERPLEXITY_API_BASE_URL=https://api.perplexity.ai

# Security
export A0_BROWSER_ALLOWED_DOMAINS="example.com,api.github.com"
export CODE_EXEC_SSH_ADDR=192.168.1.100
export CODE_EXEC_SSH_PORT=22

# Timeouts
export A0_CODE_EXEC_TIMEOUT=300
export A0_BROWSER_TIMEOUT=600

# Run Agent Zero
python run_ui.py
```

---

## Migration from Hardcoded Values

If you previously modified code to change these values, you can now:

1. Remove your code changes
2. Set the corresponding environment variable
3. Restart Agent Zero

All changes are non-breaking - if an environment variable is not set, the system falls back to the previous default value.

---

## Troubleshooting

### Changes Not Applied

1. Ensure environment variable names use the `A0_` prefix
2. Check that variables are exported (use `export` in bash)
3. Verify variables are set before starting Agent Zero
4. For Docker, ensure `-e` flags are before the image name

### Verify Configuration

Check current configuration in Python:

```python
from python.helpers.constants import Config
print(Config.DEFAULT_HOSTNAME)
print(Config.CHAT_MODEL_NAME)
```

---

## Contributing

When adding new configurable values:

1. Add to `python/helpers/constants.py` in the `Config` class
2. Use the `get_env_*` helper functions
3. Prefix with `A0_`
4. Update this documentation
5. Provide sensible defaults for backward compatibility

---

*Flexy says: "No hardcoded values, no problems!"*
