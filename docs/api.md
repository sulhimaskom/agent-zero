# Agent Zero API Reference

> Last Updated: 2026-02-28

This document provides a comprehensive reference for all Flask API endpoints in Agent Zero.

## Overview

Agent Zero provides 64+ REST API endpoints for external integrations. All endpoints:

- Inherit from the `ApiHandler` base class
- Are auto-registered at runtime based on filename
- Accept JSON input and return JSON responses
- Support CORS for cross-origin requests

### Authentication

Most endpoints require authentication via session or API key:

| Method | Header | Description |
|--------|--------|-------------|
| Session | Cookie | Web UI authentication |
| API Key | `X-API-KEY` | External API access |

### Base URL

```
http://localhost:50001
```

---

## Chat & Messages

### `/message` - Send Chat Message

Send messages to the agent and receive responses.

**Methods:** `POST`

**Request Body:**
```json
{
  "text": "Your message here",
  "context": "optional-context-id",
  "message_id": "optional-message-id"
}
```

**Response:**
```json
{
  "message": "Agent response",
  "context": "context-id"
}
```

**Notes:** Also supports `multipart/form-data` for file attachments.

---

### `/message_async` - Async Message

Acknowledge message receipt without waiting for processing.

**Methods:** `POST`

**Request Body:** Same as `/message`

**Response:**
```json
{
  "message": "Message received.",
  "context": "context-id"
}
```

---

### `/poll` - Long Polling

Poll for agent responses and notifications.

**Methods:** `GET`, `POST`

**Request Body:**
```json
{
  "context": "context-id",
  "log_from": 0,
  "notifications_from": 0
}
```

**Response:**
```json
{
  "messages": [...],
  "notifications": [...],
  "output": "...",
  "done": false
}
```

---

### `/chat_create` - Create Chat

Create a new chat context, optionally copying from existing context.

**Methods:** `POST`

**Request Body:**
```json
{
  "current_context": "existing-context-id",
  "new_context": "optional-new-id"
}
```

**Response:**
```json
{
  "ok": true,
  "ctxid": "new-context-id",
  "message": "Context created."
}
```

---

### `/chat_load` - Load Chats

Load previous chat sessions from JSON files.

**Methods:** `POST`

**Request Body:**
```json
{
  "chats": ["chat1.json", "chat2.json"]
}
```

**Response:**
```json
{
  "message": "Chats loaded.",
  "ctxids": ["ctxid1", "ctxid2"]
}
```

---

### `/chat_reset` - Reset Chat

Clear conversation history and reset agent context.

**Methods:** `POST`

**Request Body:**
```json
{
  "context": "context-id"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Context reset."
}
```

---

### `/chat_remove` - Remove Chat

Permanently delete a chat context and associated files.

**Methods:** `POST`

**Request Body:**
```json
{
  "context": "context-id"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Context removed."
}
```

---

### `/chat_export` - Export Chat

Export chat session to JSON format.

**Methods:** `POST`

**Request Body:**
```json
{
  "ctxid": "context-id"
}
```

**Response:**
```json
{
  "message": "Chats exported.",
  "ctxid": "context-id",
  "content": {...}
}
```

---

## Settings

### `/settings_get` - Get Settings

Retrieve current agent configuration.

**Methods:** `GET`, `POST`

**Response:**
```json
{
  "settings": {
    "key": "value"
  }
}
```

---

### `/settings_set` - Update Settings

Modify agent configuration at runtime.

**Methods:** `POST`

**Request Body:**
```json
{
  "settings": {
    "key": "new-value"
  }
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Settings updated."
}
```

---

## Files

### `/upload` - File Upload

Upload files to the agent's working directory.

**Methods:** `POST`

**Content-Type:** `multipart/form-data`

**Form Data:**
- `file`: File(s) to upload (supports multiple)

**Response:**
```json
{
  "ok": true,
  "files": ["filename1", "filename2"]
}
```

---

### `/get_work_dir_files` - List Files

List files in the working directory.

**Methods:** `POST`

**Request Body:**
```json
{
  "path": "optional/path"
}
```

**Response:**
```json
{
  "files": ["file1", "file2"],
  "directories": ["dir1"]
}
```

---

### `/download_work_dir_file` - Download File

Download a file from the working directory.

**Methods:** `POST`

**Request Body:**
```json
{
  "filename": "file.txt"
}
```

**Response:** Binary file data

---

### `/delete_work_dir_file` - Delete File

Delete a file from the working directory.

**Methods:** `POST`

**Request Body:**
```json
{
  "filename": "file.txt"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "File deleted."
}
```

---

## Knowledge

### `/knowledge_reindex` - Reindex Knowledge Base

Rebuild the knowledge vector index after adding documents.

**Methods:** `POST`

**Request Body:**
```json
{
  "ctxid": "context-id"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Knowledge reindexed."
}
```

---

### `/import_knowledge` - Import Knowledge

Import documents into the knowledge base.

**Methods:** `POST`

**Request Body:**
```json
{
  "ctxid": "context-id",
  "path": "/path/to/documents"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Knowledge imported."
}
```

---

## Scheduler

### `/scheduler_task_create` - Create Scheduled Task

Create a new scheduled task.

**Methods:** `POST`

**Request Body:**
```json
{
  "name": "task-name",
  "schedule": "0 * * * *",
  "command": "task command"
}
```

**Response:**
```json
{
  "ok": true,
  "task_id": "task-id"
}
```

---

### `/scheduler_tasks_list` - List Tasks

List all scheduled tasks.

**Methods:** `POST`

**Response:**
```json
{
  "tasks": [...]
}
```

---

### `/scheduler_task_run` - Run Task Now

Execute a scheduled task immediately.

**Methods:** `POST`

**Request Body:**
```json
{
  "task_id": "task-id"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Task started."
}
```

---

### `/scheduler_task_delete` - Delete Task

Remove a scheduled task.

**Methods:** `POST`

**Request Body:**
```json
{
  "task_id": "task-id"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Task deleted."
}
```

---

## MCP Servers

### `/mcp_servers_status` - MCP Server Status

Get connection status of all MCP servers.

**Methods:** `POST`

**Response:**
```json
{
  "success": true,
  "status": {
    "server-name": {
      "connected": true,
      "error": null
    }
  }
}
```

---

### `/mcp_servers_apply` - Apply MCP Config

Apply MCP server configuration changes.

**Methods:** `POST`

**Request Body:**
```json
{
  "config": {...}
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Configuration applied."
}
```

---

## Backup

### `/backup_create` - Create Backup

Create a backup archive of Agent Zero data.

**Methods:** `POST`

**Request Body:**
```json
{
  "include": ["*"],
  "exclude": ["*.log"]
}
```

**Response:** Binary ZIP file

---

### `/backup_restore` - Restore Backup

Restore from a backup archive.

**Methods:** `POST`

**Request Body:**
```json
{
  "backup_file": "backup.zip"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Backup restored."
}
```

---

### `/backup_inspect` - Inspect Backup

List contents of a backup archive.

**Methods:** `POST`

**Request Body:**
```json
{
  "backup_file": "backup.zip"
}
```

**Response:**
```json
{
  "files": [...],
  "total_size": 12345
}
```

---

## Notifications

### `/notification_create` - Create Notification

Create an in-app notification.

**Methods:** `POST`

**Request Body:**
```json
{
  "message": "Notification text",
  "priority": "normal",
  "type": "info"
}
```

**Response:**
```json
{
  "ok": true,
  "notification_id": "id"
}
```

---

### `/notifications_history` - Get Notifications

Retrieve notification history.

**Methods:** `POST`

**Response:**
```json
{
  "notifications": [...]
}
```

---

### `/notifications_mark_read` - Mark Read

Mark notifications as read.

**Methods:** `POST`

**Request Body:**
```json
{
  "notification_ids": ["id1", "id2"]
}
```

**Response:**
```json
{
  "ok": true
}
```

---

### `/notifications_clear` - Clear Notifications

Clear all notifications.

**Methods:** `POST`

**Response:**
```json
{
  "ok": true,
  "message": "Notifications cleared."
}
```

---

## Tunnel

### `/tunnel` - Manage Tunnel

Create and manage remote access tunnels.

**Methods:** `POST`

**Request Body:**
```json
{
  "action": "get|create|stop",
  "provider": "serveo|localtunnel|ngrok"
}
```

**Response:**
```json
{
  "url": "https://...",
  "ok": true
}
```

---

## Control

### `/pause` - Pause Agent

Pause/resume agent message processing.

**Methods:** `POST`

**Request Body:**
```json
{
  "context": "context-id",
  "paused": true
}
```

**Response:**
```json
{
  "ok": true
}
```

---

### `/restart` - Restart Framework

Trigger a full framework restart.

**Methods:** `POST`

**Response:** HTTP 200 OK

---

### `/nudge` - Nudge Agent

Interrupt agent and request immediate response.

**Methods:** `POST`

**Request Body:**
```json
{
  "context": "context-id"
}
```

**Response:**
```json
{
  "ok": true
}
```

---

## External API

### `/api_message` - External Message

Send message with API key authentication.

**Headers:** `X-API-KEY: your-api-key`

**Request Body:**
```json
{
  "message": "Your message",
  "context_id": "optional-context",
  "lifetime_hours": 24
}
```

**Response:**
```json
{
  "response": "Agent response",
  "context_id": "context-id"
}
```

---

### `/api_log_get` - Get External Logs

Retrieve conversation logs for external API.

**Methods:** `GET`, `POST`

**Headers:** `X-API-KEY: your-api-key`

**Request Body:**
```json
{
  "context_id": "context-id",
  "from": 0
}
```

**Response:**
```json
{
  "logs": [...]
}
```

---

### `/api_reset_chat` - External Reset

Reset chat via external API.

**Methods:** `POST`

**Headers:** `X-API-KEY: your-api-key`

**Request Body:**
```json
{
  "context_id": "context-id"
}
```

**Response:**
```json
{
  "ok": true
}
```

---

### `/api_terminate_chat` - Terminate Chat

Terminate chat via external API.

**Methods:** `POST`

**Headers:** `X-API-KEY: your-api-key`

**Request Body:**
```json
{
  "context_id": "context-id"
}
```

**Response:**
```json
{
  "ok": true
}
```

---

### `/api_files_get` - Get External Files

List files accessible via external API.

**Methods:** `GET`, `POST`

**Headers:** `X-API-KEY: your-api-key`

**Response:**
```json
{
  "files": [...]
}
```

---

## Utility Endpoints

### `/health` - Health Check

System diagnostics and health status.

**Methods:** `POST`

**Response:**
```json
{
  "status": "healthy",
  "checks": {...}
}
```

---

### `/csrf_token` - CSRF Token

Get CSRF token for form submissions.

**Methods:** `GET`

**Response:**
```json
{
  "csrf_token": "token-value"
}
```

---

### `/ctx_window_get` - Context Window

Get current context window information.

**Methods:** `POST`

**Response:**
```json
{
  "max": 128000,
  "current": 5000
}
```

---

## See Also

- [Connectivity Guide](./connectivity.md) - External API and MCP integration
- [Architecture Overview](./architecture.md) - System design
