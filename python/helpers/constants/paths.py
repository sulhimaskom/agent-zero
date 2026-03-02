"""File system paths constants extracted from constants.py."""

from typing import Final


class Paths:
    """File system paths and directories."""

    # Base directories
    PYTHON_DIR: Final[str] = "python"
    AGENTS_DIR: Final[str] = "agents"
    PROMPTS_DIR: Final[str] = "prompts"

    # Extension paths
    EXTENSIONS_DIR: Final[str] = "python/extensions"
    AGENT_EXTENSIONS_DIR: Final[str] = "agents/{profile}/extensions"

    # Tool paths
    TOOLS_DIR: Final[str] = "python/tools"
    AGENT_TOOLS_DIR: Final[str] = "agents/{profile}/tools"
    TOOL_FILE_EXTENSION: Final[str] = ".py"

    # Prompt paths
    DEFAULT_PROMPTS_DIR: Final[str] = "prompts/default"
    AGENT_PROMPTS_DIR: Final[str] = "agents/{profile}/prompts"

    # Project structure
    PROJECTS_PARENT_DIR: Final[str] = "usr/projects"
    PROJECT_META_DIR: Final[str] = ".a0proj"
    PROJECT_INSTRUCTIONS_DIR: Final[str] = "instructions"
    PROJECT_KNOWLEDGE_DIR: Final[str] = "knowledge"
    PROJECT_HEADER_FILE: Final[str] = "project.json"

    # Chat persistence
    CHAT_LOG_SIZE: Final[int] = 1000
    CHAT_FILE_NAME: Final[str] = "chat.json"

    # Settings
    SETTINGS_FILE: Final[str] = "tmp/settings.json"

    # Memory paths
    MEMORY_DIR: Final[str] = "memory"
    MEMORY_EMBEDDINGS_DIR: Final[str] = "memory/embeddings"
    KNOWLEDGE_IMPORT_FILE: Final[str] = "knowledge_import.json"

    # Scheduler
    SCHEDULER_FOLDER: Final[str] = "tmp/scheduler"
    SCHEDULER_TASKS_FILE: Final[str] = "tasks.json"

    # Model downloads
    WHISPER_MODEL_ROOT: Final[str] = "/tmp/models/whisper"

    # API paths
    UPLOAD_FOLDER: Final[str] = "/a0/tmp/uploads"
    WORK_DIR: Final[str] = "/a0"
    ROOT_DIR: Final[str] = "/root"

    # Code execution paths
    NODE_EVAL_SCRIPT: Final[str] = "/exe/node_eval.js"
    EMAIL_INBOX_PATH: Final[str] = "tmp/email/inbox"
    EMAIL_DIR: Final[str] = "tmp/email"

    # Additional tmp directories
    CHATS_FOLDER: Final[str] = "tmp/chats"
    PLAYWRIGHT_DIR: Final[str] = "tmp/playwright"
    DOWNLOADS_DIR: Final[str] = "tmp/downloads"
    UPLOAD_DIR: Final[str] = "tmp/uploads"

    # MCP paths
    MCP_SSE_PATH_PATTERN: Final[str] = "/t-{token}/sse"
    MCP_HTTP_PATH_PATTERN: Final[str] = "/t-{token}/http"
    MCP_MESSAGES_PATH_PATTERN: Final[str] = "/t-{token}/messages/"

    # A2A paths
    A2A_BASE_PATH: Final[str] = "/a2a"
    A2A_TOKEN_PATH_PREFIX: Final[str] = "/t-"

    @staticmethod
    def get_agent_extensions_path(profile: str, extension_point: str) -> str:
        """Get the path to agent-specific extensions."""
        return f"{Paths.AGENTS_DIR}/{profile}/extensions/{extension_point}"

    @staticmethod
    def get_agent_tools_path(profile: str, tool_name: str) -> str:
        """Get the path to agent-specific tool file."""
        return f"{Paths.AGENTS_DIR}/{profile}/tools/{tool_name}{Paths.TOOL_FILE_EXTENSION}"

    @staticmethod
    def get_default_extensions_path(extension_point: str) -> str:
        """Get the path to default extensions."""
        return f"{Paths.EXTENSIONS_DIR}/{extension_point}"

    @staticmethod
    def get_default_tools_path(tool_name: str) -> str:
        """Get the path to default tool file."""
        return f"{Paths.TOOLS_DIR}/{tool_name}{Paths.TOOL_FILE_EXTENSION}"
