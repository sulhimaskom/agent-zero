"""User-facing messages and UI text (split from constants.py)."""

from typing import Final


class Messages:
    """User-facing messages and UI text - centralized for consistency."""

    # Tool-related messages
    TOOL_USING: Final[str] = "Using tool '{tool_name}'"
    TOOL_RESPONSE: Final[str] = "Response from tool '{tool_name}'"
    TOOL_FAILED: Final[str] = "Failed to call tool '{tool_name}'"
    TOOL_EMPTY_RESPONSE: Final[str] = "[Tool returned no textual content]"
    TOOL_NO_OUTPUT: Final[str] = "[No direct textual output from tool]"

    # MCP-specific messages
    MCP_TOOL_FAILED: Final[str] = "MCPTool::Failed to call mcp tool {tool_name}:"
    MCP_TOOL_EXCEPTION: Final[str] = "MCP Tool Exception: {error}"
    MCP_CONFIG_ERROR: Final[str] = "Failed to update MCP settings: {error}"
    MCP_SERVER_INIT_ERROR: Final[str] = "MCPConfig::__init__::{error_msg}"
    MCP_SERVER_NOT_FOUND: Final[str] = "Server {server_name} not found"
    MCP_TOOL_NOT_FOUND: Final[str] = "Tool {tool_name} not found"
    MCP_TOOL_NOT_FOUND_REFRESH: Final[str] = (
        "Tool {tool_name} not found after refreshing tool list for server {server_name}."
    )

    # Scheduler messages
    SCHEDULER_TASK_STARTED: Final[str] = "Scheduler Task '{task_name}' started"
    SCHEDULER_TASK_COMPLETED: Final[str] = "Scheduler Task '{task_name}' completed: {result}"
    SCHEDULER_TASK_FAILED: Final[str] = "Scheduler Task '{task_name}' failed: {error}"
    SCHEDULER_TASK_NOT_FOUND: Final[str] = "Scheduler Task with UUID '{task_uuid}' not found"
    SCHEDULER_TASK_RUNNING: Final[str] = "Scheduler Task '{task_name}' already running, skipping"
    SCHEDULER_TASK_DISABLED: Final[str] = (
        "Scheduler Task '{task_name}' state is '{state}', skipping"
    )
    SCHEDULER_CONTEXT_MISMATCH: Final[str] = (
        "Context ID mismatch for task {task_name}: context {context_id} != task {task_id}"
    )

    # Error prefixes
    ERROR_PREFIX: Final[str] = "ERROR:"
    WARNING_PREFIX: Final[str] = "WARNING:"

    # Status messages
    STATUS_INITIALIZED: Final[str] = "initialized"
    STATUS_DISABLED: Final[str] = "Disabled in config"

    # General error messages
    ERROR_VALUE_REQUIRED: Final[str] = "{name} is required"
    ERROR_INVALID_CONFIG: Final[str] = "Invalid configuration: {reason}"
    ERROR_NOT_FOUND: Final[str] = "{resource} not found"
