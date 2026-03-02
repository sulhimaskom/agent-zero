"""Miscellaneous constants (stream sizes, defaults, and configs) extracted from constants.py."""

from typing import Final


class StreamSizes:
    """Stream and chunk size constants."""

    DEFAULT_CHUNK_SIZE: Final[int] = 8192  # Default chunk size for streaming downloads
    TTY_READ_BUFFER: Final[int] = 1024  # Buffer size for TTY read operations
    MIN_STREAM_LENGTH: Final[int] = 25  # Minimum stream length to process
    BACKUP_TIMESTAMP_PREFIX_LEN: Final[int] = 10  # Length of date prefix in backup names
    ANONYMIZED_ID_LEN: Final[int] = 20  # Length of anonymized ID
    MEMORY_DOC_ID_LEN: Final[int] = 10  # Length of memory document ID
    BROWSER_DISPLAY_TRUNCATE_LEN: Final[int] = 50  # Browser display truncation length
    HEX_BASE: Final[int] = 16  # Base for hex parsing
    MINUTES_PER_HOUR: Final[int] = 60  # Minutes per hour for time conversion
    SECONDS_PER_MINUTE: Final[int] = 60  # Seconds per minute for time conversion
    NORMALIZED_MIN: Final[float] = 0.0  # Minimum normalized value
    NORMALIZED_MAX: Final[float] = 1.0  # Maximum normalized value
    TOTAL_TIMEOUT_MULTIPLIER: Final[int] = 10  # Multiplier for total timeout calculation


class AgentDefaults:
    """Default values for agent configuration."""

    PROFILE: Final[str] = "agent0"
    MEMORY_SUBDIR: Final[str] = "default"
    KNOWLEDGE_SUBDIR: Final[str] = "custom"


class Shell:
    """Shell-related constants."""

    # Shell executables
    SHELL_BASH: Final[str] = "/bin/bash"
    SHELL_POWERSHELL: Final[str] = "powershell.exe"

    # SSH initialization command
    SSH_INIT_COMMAND: Final[str] = "unset PROMPT_COMMAND PS0; stty -echo"

    # Browser arguments
    BROWSER_HEADLESS_ARG: Final[str] = "--headless=new"


class Protocols:
    """Protocol strings for URL construction."""

    HTTP: Final[str] = "http://"
    HTTPS: Final[str] = "https://"


class TmpPaths:
    """Temporary path patterns used throughout the system."""

    # Individual files
    SETTINGS_JSON: Final[str] = "tmp/settings.json"
    SECRETS_ENV: Final[str] = "tmp/secrets.env"

    # Directory patterns (for glob matching)
    CHATS_GLOB: Final[str] = "tmp/chats/**"
    SCHEDULER_GLOB: Final[str] = "tmp/scheduler/**"
    UPLOADS_GLOB: Final[str] = "tmp/uploads/**"


class InternalPaths:
    """Internal path prefixes for file mapping."""

    A0_TMP_UPLOADS: Final[str] = "/a0/tmp/uploads/"


class Browser:
    """Browser agent configuration - All values configurable via environment variables."""

    # Default allowed domains for browser agent (wildcard allows all)
    ALLOWED_DOMAINS: Final[list[str]] = ["*", "http://*", "https://*"]


class Search:
    """Search engine configuration - All values configurable via environment variables."""

    # Default number of search results to return
    DEFAULT_RESULTS_COUNT: Final[int] = 10

    # DuckDuckGo search defaults
    DDG_DEFAULT_RESULTS: Final[int] = 5
    DDG_DEFAULT_REGION: Final[str] = "wt-wt"  # Worldwide
    DDG_DEFAULT_TIME_LIMIT: Final[str] = "y"  # Past year
    DDG_DEFAULT_SAFESEARCH: Final[str] = "off"

    # SearXNG search defaults
    SEARXNG_DEFAULT_RESULTS: Final[int] = 10


class Extensions:
    """Extension-specific configuration constants."""

    # Tool call file saving threshold
    # Minimum length of tool result to save as a file
    TOOL_CALL_FILE_MIN_LENGTH: Final[int] = 500
