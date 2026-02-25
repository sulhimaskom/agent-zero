# A2A Protocol Documentation

**Last Updated:** 2026-02-25

---

## Overview

The A2A (Agent-to-Agent) protocol enables communication between Agent Zero instances and other agents that support the FastA2A protocol. This allows for distributed multi-agent architectures where agents can collaborate across different instances.

## How A2A Works

A2A protocol provides:
- **Server Mode**: Your Agent Zero instance can accept connections from remote agents
- **Client Mode**: Your Agent Zero can connect to and interact with remote A2A agents

### Protocol Features

- JSON-based message format
- Streaming support for real-time responses
- Authentication via API tokens
- Bidirectional communication

## Setup Instructions

### Enabling A2A Server

1. Open Agent Zero in your browser
2. Navigate to **Settings** → **External Services**
3. Find the **A2A Connection** section
4. Note your A2A connection URL

### Finding Your A2A URL

Your A2A connection URL is displayed in the Settings page under **External Services > A2A Connection**.

```
YOUR_AGENT_ZERO_URL/a2a/t-YOUR_API_TOKEN
```

> [!NOTE]
> The API token is automatically generated from your username and password. The token will change if you update your credentials.

## Connection URL Format

```
https://your-agent-zero-instance.com/a2a/t-YOUR_API_TOKEN
```

### URL Components

| Component | Description |
|-----------|-------------|
| `your-agent-zero-instance.com` | Your Agent Zero deployment URL |
| `a2a` | A2A protocol endpoint |
| `t_YOUR_API_TOKEN` | Your authentication token |

## Usage Examples

### Connecting Another Agent

To connect another agent to your Agent Zero instance:

```javascript
// Example: Connecting a remote agent to Agent Zero
const a2aUrl = 'https://your-agent-zero.com/a2a/t_your_token';

const response = await fetch(a2aUrl, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        message: 'Hello, Agent Zero!',
        context_id: 'optional-context-id'
    })
});

const data = await response.json();
console.log(data.response);
```

### Python Client Example

```python
import requests

def send_to_agent_zero(url, message, api_token):
    response = requests.post(
        url,
        json={"message": message},
        headers={"Authorization": f"Bearer {api_token}"}
    )
    return response.json()

# Usage
result = send_to_agent_zero(
    "https://your-agent-zero.com/a2a/t_token",
    "What is the current system status?"
)
print(result)
```

## Configuration Options

### Server Configuration

A2A server runs on the same port as your Agent Zero instance. No additional configuration is required.

### Client Configuration

When using Agent Zero as an A2A client:

1. **API Token**: Use your Agent Zero credentials to generate a token
2. **Remote URL**: Enter the remote agent's A2A endpoint
3. **Context**: Optionally specify a conversation context ID for continuity

## Security Considerations

- **Token-based authentication**: All A2A connections require authentication
- **Token rotation**: Tokens change when credentials are updated
- **HTTPS recommended**: Always use HTTPS in production environments
- **Network access**: Ensure firewall rules allow A2A port traffic

## Troubleshooting

### Connection Refused

- Verify the remote Agent Zero instance is running
- Check the URL format is correct
- Ensure the API token is valid

### Authentication Errors

- Regenerate your API token in Settings
- Verify the token matches your current credentials
- Check token hasn't expired

### Message Delivery Failures

- Verify network connectivity
- Check remote agent is online
- Ensure message format is correct JSON

## Related Documentation

- [Connectivity Guide](./connectivity.md) - General connectivity options
- [MCP Setup](./mcp_setup.md) - Model Context Protocol setup
- [External API](./connectivity.md#external-api-endpoints) - REST API endpoints
