"""
Modular constants for Agent Zero framework.
Flexy says: No hardcoded values allowed! Everything configurable.
"""

import os
from typing import Final

# =============================================================================
# TIMEOUT CONSTANTS
# =============================================================================


class Timeouts:
    """Timeout values in seconds"""

    # Code execution timeouts
    CODE_EXEC_FIRST_OUTPUT: Final[int] = 30
    CODE_EXEC_BETWEEN_OUTPUT: Final[int] = 15
    CODE_EXEC_MAX: Final[int] = 180
    CODE_EXEC_DIALOG: Final[int] = 5

    # Extended timeouts for output-heavy operations
    OUTPUT_FIRST_TIMEOUT: Final[int] = 90
    OUTPUT_BETWEEN_TIMEOUT: Final[int] = 45
    OUTPUT_MAX_TIMEOUT: Final[int] = 300

    # Browser agent timeouts
    BROWSER_LLM_TIMEOUT: Final[int] = 3000
    BROWSER_MAX_STEPS: Final[int] = 50
    BROWSER_OPERATION_TIMEOUT: Final[int] = 300
    BROWSER_ASYNC_TIMEOUT: Final[int] = 10
    BROWSER_SCREENSHOT_TIMEOUT: Final[int] = 3000

    # RFC function call timeout
    RFC_FUNCTION_TIMEOUT: Final[int] = 30

    # Email client timeouts
    EMAIL_CONNECTION_TIMEOUT: Final[int] = 30

    # TTY session timeouts
    TTY_READ_TIMEOUT: Final[float] = 1.0
    TTY_TOTAL_TIMEOUT_MULTIPLIER: Final[int] = 10
    IDLE_TIMEOUT: Final[float] = 1.0
    SHORT_IDLE_TIMEOUT: Final[float] = 0.01

    # Scheduler timeouts
    SCHEDULER_DEFAULT_WAIT: Final[int] = 300
    SCHEDULER_CHECK_FREQUENCY: Final[float] = 60.0

    # Input timeouts
    INPUT_DEFAULT_TIMEOUT: Final[int] = 10

    # MCP server apply delay
    MCP_SERVER_APPLY_DELAY: Final[int] = 1

    # Tunnel check delay
    TUNNEL_CHECK_DELAY: Final[int] = 2

    # HTTP cache duration (1 day in seconds)
    HTTP_CACHE_MAX_AGE: Final[int] = 86400

    # Notification default lifetime (hours)
    NOTIFICATION_LIFETIME_HOURS: Final[int] = 24

    # Update check cooldowns
    UPDATE_CHECK_COOLDOWN_SECONDS: Final[int] = 60
    UPDATE_NOTIFICATION_COOLDOWN_SECONDS: Final[int] = 86400  # 24 hours

    # MCP timeouts
    MCP_CLIENT_INIT_TIMEOUT: Final[int] = 10
    MCP_CLIENT_TOOL_TIMEOUT: Final[int] = 120

    # Document query timeouts
    DOCUMENT_DOWNLOAD_TIMEOUT: Final[float] = 10.0
    DOCUMENT_POLL_INTERVAL: Final[int] = 2
    DOCUMENT_MAX_WAIT: Final[int] = 300

    # File browser timeout
    FILE_BROWSER_TIMEOUT: Final[int] = 30

    # Notification default timeouts
    NOTIFICATION_DEFAULT_TIMEOUT: Final[int] = 30
    NOTIFICATION_AGENT_TIMEOUT: Final[int] = 30

    # Docker operation delays
    DOCKER_INIT_DELAY: Final[int] = 5
    DOCKER_RETRY_DELAY: Final[int] = 2
    DOCKER_STARTUP_DELAY: Final[int] = 5

    # Tunnel management
    TUNNEL_STARTUP_ITERATIONS: Final[int] = 150
    TUNNEL_STARTUP_DELAY: Final[float] = 0.1

    # SSH shell delays
    SSH_SHELL_DELAY: Final[float] = 0.1
    SSH_CONNECTION_DELAY: Final[int] = 5

    # Model loading delays
    MODEL_UPDATE_CHECK_DELAY: Final[float] = 0.1

    # Wait function delays
    WAIT_PAUSE_THRESHOLD: Final[float] = 1.5
    WAIT_SLEEP_INTERVAL: Final[float] = 1.0

    # HTTP client timeouts
    HTTP_CLIENT_DEFAULT_TIMEOUT: Final[float] = 30.0

    # Rate limiter timeframe
    RATE_LIMITER_DEFAULT_TIMEFRAME: Final[int] = 60


# =============================================================================
# SIZE LIMITS AND THRESHOLDS
# =============================================================================


class Limits:
    """Size limits, thresholds, and count limits"""

    # Model context lengths (default values)
    DEFAULT_CHAT_MODEL_CTX_LENGTH: Final[int] = 100000
    DEFAULT_UTIL_MODEL_CTX_LENGTH: Final[int] = 100000

    # Memory recall limits
    MEMORY_RECALL_HISTORY_LENGTH: Final[int] = 10000
    MEMORY_RECALL_MAX_SEARCH_MEMORIES: Final[int] = 12
    MEMORY_RECALL_MAX_SEARCH_SOLUTIONS: Final[int] = 8
    MEMORY_RECALL_MAX_RESULT_MEMORIES: Final[int] = 5
    MEMORY_RECALL_MAX_RESULT_SOLUTIONS: Final[int] = 3

    # Memory consolidation
    MEMORY_MAX_SIMILAR: Final[int] = 10
    MEMORY_MAX_LLM_CONTEXT: Final[int] = 5
    MEMORY_PROCESSING_TIMEOUT: Final[int] = 60
    MEMORY_REPLACE_SIMILARITY_THRESHOLD: Final[float] = 0.9
    MEMORY_CONTENT_PREVIEW_TRUNCATION: Final[int] = 200
    MEMORY_CONTENT_PREVIEW_LIMIT: Final[int] = 100
    MEMORY_SEARCH_K: Final[int] = 100
    MEMORY_SIMILARITY_SINGLE_DOC: Final[float] = 1.0
    MEMORY_SIMILARITY_SAFETY_THRESHOLD: Final[float] = 0.9
    MEMORY_SIMILARITY_DEFAULT_ESTIMATE: Final[float] = 0.7

    # Memory extension limits
    MEMORY_EXT_MAX_SIMILAR_MEMORIES: Final[int] = 8
    MEMORY_EXT_MAX_LLM_CONTEXT_MEMORIES: Final[int] = 4
    MEMORY_SOL_MAX_SIMILAR_MEMORIES: Final[int] = 6
    MEMORY_SOL_MAX_LLM_CONTEXT_MEMORIES: Final[int] = 3

    # Default timestamp for sorting
    DEFAULT_TIMESTAMP: Final[str] = "0000-00-00 00:00:00"

    # Document query
    DOCUMENT_DEFAULT_THRESHOLD: Final[float] = 0.5
    DOCUMENT_DEFAULT_CHUNK_SIZE: Final[int] = 1000
    DOCUMENT_DEFAULT_CHUNK_OVERLAP: Final[int] = 100
    DOCUMENT_MAX_LIMIT: Final[int] = 100

    # Memory tool defaults
    MEMORY_DEFAULT_THRESHOLD: Final[float] = 0.7
    MEMORY_DEFAULT_LIMIT: Final[int] = 10

    # Vision/image processing
    VISION_MAX_PIXELS: Final[int] = 768000
    VISION_QUALITY: Final[int] = 75
    VISION_TOKENS_ESTIMATE: Final[int] = 1500
    IMAGE_MAX_PIXELS: Final[int] = 256000
    IMAGE_QUALITY: Final[int] = 50

    # History management
    HISTORY_BULK_MERGE_COUNT: Final[int] = 3
    HISTORY_TOPICS_KEEP_COUNT: Final[int] = 3
    HISTORY_CURRENT_TOPIC_RATIO: Final[float] = 0.5
    HISTORY_TOPIC_RATIO: Final[float] = 0.3
    HISTORY_BULK_RATIO: Final[float] = 0.2
    HISTORY_TOPIC_COMPRESS_RATIO: Final[float] = 0.65
    HISTORY_LARGE_MESSAGE_RATIO: Final[float] = 0.25
    HISTORY_RAW_MESSAGE_TRIM: Final[int] = 100

    # Message truncation
    MESSAGE_TRUNCATE_THRESHOLD: Final[int] = 1000

    # Token calculations
    TOKEN_APPROX_BUFFER: Final[float] = 1.1
    TOKEN_TRIM_BUFFER: Final[float] = 0.8

    # Message truncation ratios (history compression)
    MESSAGE_TRIM_RATIO_UPPER: Final[float] = 1.15
    MESSAGE_TRIM_RATIO_LOWER: Final[float] = 0.85

    # Backup limits
    BACKUP_MAX_FILES_FULL: Final[int] = 50000
    BACKUP_MAX_FILES_PARTIAL: Final[int] = 10000
    BACKUP_MAX_FILES_TEST: Final[int] = 1000

    # File browser limits
    FILE_BROWSER_MAX_FILE_SIZE: Final[int] = 100 * 1024 * 1024  # 100MB
    FILE_BROWSER_MAX_ITEMS: Final[int] = 10000  # Maximum number of files/folders to list
    FILE_READ_MAX_SIZE: Final[int] = 1024 * 1024  # 1MB

    # Project file structure limits
    PROJECT_MAX_DEPTH: Final[int] = 5
    PROJECT_MAX_FILES: Final[int] = 20
    PROJECT_MAX_FOLDERS: Final[int] = 20
    PROJECT_MAX_LINES: Final[int] = 250

    # Notification limits
    NOTIFICATION_MAX_COUNT: Final[int] = 100
    NOTIFICATION_DISPLAY_TIME: Final[int] = 3
    NOTIFICATION_RECENT_SECONDS: Final[int] = 30

    # Fullscreen input modal stack limit
    MODAL_MAX_STACK_SIZE: Final[int] = 100

    # Memory dashboard items per page
    MEMORY_DASHBOARD_ITEMS_PER_PAGE: Final[int] = 10

    # QR Code dimensions
    QR_CODE_WIDTH: Final[int] = 128
    QR_CODE_HEIGHT: Final[int] = 128

    # Sidebar chat retry configuration
    CHAT_MAX_RETRIES: Final[int] = 240
    CHAT_RETRY_INTERVAL_MS: Final[int] = 250
    # RFC ports
    RFC_PORT_HTTP: Final[int] = 55080
    RFC_PORT_SSH: Final[int] = 55022

    # STT settings
    STT_SILENCE_DURATION: Final[int] = 1000
    STT_SILENCE_THRESHOLD: Final[float] = 0.3
    STT_WAITING_TIMEOUT: Final[int] = 2000

    # Command truncation
    COMMAND_TRUNCATION_PRIMARY: Final[int] = 200
    COMMAND_TRUNCATION_SECONDARY: Final[int] = 100
    OUTPUT_TRUNCATION_THRESHOLD: Final[int] = 1000000

    # Browser dimensions
    BROWSER_VIEWPORT_WIDTH: Final[int] = 1024
    BROWSER_VIEWPORT_HEIGHT: Final[int] = 2048
    BROWSER_PAGE_LOAD_MIN: Final[float] = 1.0
    BROWSER_PAGE_LOAD_MED: Final[float] = 2.0
    BROWSER_PAGE_LOAD_MAX: Final[float] = 10.0
    BROWSER_FIRST_LINE_TRUNCATION: Final[int] = 200

    # SSH shell dimensions
    SSH_SHELL_WIDTH: Final[int] = 100
    SSH_SHELL_HEIGHT: Final[int] = 50
    SSH_RECEIVE_BYTES: Final[int] = 1024

    # IMAP settings
    IMAP_DEFAULT_PORT: Final[int] = 993
    IMAP_MAX_LINE_LENGTH: Final[int] = 100000  # Increased from default 10000 to handle large emails

    # TTY settings
    TTY_BUFFER_SIZE: Final[int] = 4096
    TTY_DEFAULT_COLS: Final[int] = 80
    TTY_DEFAULT_ROWS: Final[int] = 25

    # Scheduler token generation
    SCHEDULER_TOKEN_MIN: Final[int] = 10**17  # 18 digits
    SCHEDULER_TOKEN_MAX: Final[int] = 10**18 - 1  # 19 digits

    # Crypto settings
    RSA_PUBLIC_EXPONENT: Final[int] = 65537
    RSA_KEY_SIZE: Final[int] = 2048

    # Audio
    TTS_SAMPLE_RATE: Final[int] = 24000
    TTS_DEFAULT_SPEED: Final[float] = 1.1
    TTS_DEFAULT_VOICE: Final[str] = "am_puck,am_onyx"

    # Job loop
    JOB_LOOP_SLEEP_TIME: Final[int] = 60

    # Agent ID generation
    AGENT_ID_LENGTH: Final[int] = 8

    # Logging limits
    LOG_VALUE_MAX_LEN: Final[int] = 5000
    HEADING_MAX_LEN: Final[int] = 120
    CONTENT_MAX_LEN: Final[int] = 15000
    RESPONSE_CONTENT_MAX_LEN: Final[int] = 250000
    KEY_MAX_LEN: Final[int] = 60
    PROGRESS_MAX_LEN: Final[int] = 120

    # Image/Attachment limits
    IMAGE_PREVIEW_MAX_SIZE: Final[int] = 800
    IMAGE_PREVIEW_QUALITY: Final[int] = 70


# =============================================================================
# NETWORK AND PORTS
# =============================================================================


class Network:
    """Network-related constants"""

    # Default hosts
    DEFAULT_LOCALHOST: Final[str] = "127.0.0.1"
    DEFAULT_HOSTNAME: Final[str] = "localhost"

    # Default ports
    WEB_UI_PORT_DEFAULT: Final[int] = 5000
    TUNNEL_API_PORT_DEFAULT: Final[int] = 55520
    TUNNEL_API_PORT_FALLBACK: Final[int] = 55520
    SEARXNG_PORT_DEFAULT: Final[int] = 55510
    TUNNEL_DEFAULT_PORT: Final[int] = 80

    # Agent-specific ports
    BROCULA_PORT_DEFAULT: Final[int] = 50001

    # CORS allowed origins (development)
    DEV_CORS_ORIGINS: Final[list[str]] = [
        "*://localhost:*",
        "*://127.0.0.1:*",
        "*://0.0.0.0:*",
    ]

    # External API endpoints
    UPDATE_CHECK_URL: Final[str] = "https://api.agent-zero.ai/a0-update-check"
    PERPLEXITY_API_BASE_URL: Final[str] = "https://api.perplexity.ai"
    PERPLEXITY_DEFAULT_MODEL: Final[str] = "llama-3.1-sonar-large-128k-online"


# =============================================================================
# FILE PATHS AND DIRECTORIES
# =============================================================================


class Paths:
    """File system paths and directories"""

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

    # MCP paths
    MCP_SSE_PATH_PATTERN: Final[str] = "/t-{token}/sse"
    MCP_HTTP_PATH_PATTERN: Final[str] = "/t-{token}/http"
    MCP_MESSAGES_PATH_PATTERN: Final[str] = "/t-{token}/messages/"

    # A2A paths
    A2A_BASE_PATH: Final[str] = "/a2a"
    A2A_TOKEN_PATH_PREFIX: Final[str] = "/t-"


# =============================================================================
# FILE EXTENSIONS
# =============================================================================


class FileExtensions:
    """File extensions used throughout the system"""

    MARKDOWN: Final[str] = ".md"
    PYTHON: Final[str] = ".py"
    JSON: Final[str] = ".json"
    YAML: Final[str] = ".yaml"
    YML: Final[str] = ".yml"


# =============================================================================
# AGENT DEFAULTS
# =============================================================================


class AgentDefaults:
    """Default values for agent configuration"""

    PROFILE: Final[str] = "agent0"
    MEMORY_SUBDIR: Final[str] = "default"
    KNOWLEDGE_SUBDIR: Final[str] = "custom"


# =============================================================================
# FILE PATTERNS
# =============================================================================


class FilePatterns:
    """File search patterns used throughout the system"""

    KNOWLEDGE_MARKDOWN: Final[str] = "**/*.md"


# =============================================================================
# SHELL AND COMMANDS
# =============================================================================


class Shell:
    """Shell-related constants"""

    # Shell executables
    SHELL_BASH: Final[str] = "/bin/bash"
    SHELL_POWERSHELL: Final[str] = "powershell.exe"

    # SSH initialization command
    SSH_INIT_COMMAND: Final[str] = "unset PROMPT_COMMAND PS0; stty -echo"

    # Browser arguments
    BROWSER_HEADLESS_ARG: Final[str] = "--headless=new"


# =============================================================================
# HTTP STATUS CODES
# =============================================================================


class HttpStatus:
    """HTTP status codes used in the application"""

    OK: Final[int] = 200
    BAD_REQUEST: Final[int] = 400
    UNAUTHORIZED: Final[int] = 401
    FORBIDDEN: Final[int] = 403
    NOT_FOUND: Final[int] = 404
    ERROR: Final[int] = 500
    SERVICE_UNAVAILABLE: Final[int] = 503


# =============================================================================
# COLOR CONSTANTS (PrintStyle colors)
# =============================================================================


class Colors:
    """Color constants for terminal and UI output"""

    # Primary UI colors
    PRIMARY_BLUE: Final[str] = "#1B4F72"  # Dark blue - tool headers
    PRIMARY_LIGHT_BLUE: Final[str] = "#85C1E9"  # Light blue - tool content

    # Semantic colors
    SUCCESS: Final[str] = "#008000"  # Green - success messages
    WARNING: Final[str] = "#FFA500"  # Orange - warnings
    ERROR: Final[str] = "#E74C3C"  # Red - errors
    INFO: Final[str] = "#0000FF"  # Blue - info messages
    DEBUG: Final[str] = "#808080"  # Gray - debug messages
    HINT: Final[str] = "#6C3483"  # Purple - hints

    # Accent colors
    AGENT_PURPLE: Final[str] = "#6C3483"  # Purple - agent messages
    SETTINGS_PURPLE: Final[str] = "#6734C3"  # Purple - settings UI
    SETTINGS_DARK: Final[str] = "#334455"  # Dark blue-gray
    MCP_MAGENTA: Final[str] = "#CC34C3"  # Magenta - MCP UI
    MCP_ERROR_RED: Final[str] = "#AA4455"  # Reddish - MCP errors
    FILES_GREEN: Final[str] = "#2ECC71"  # Green - file operations
    STREAM_MINT: Final[str] = "#b3ffd9"  # Mint green - stream coordinator
    API_RESET_BLUE: Final[str] = "#3498DB"  # Blue - API reset chat

    # Background colors
    BG_WHITE: Final[str] = "white"


# =============================================================================
# UI TIMING CONSTANTS (Frontend)
# =============================================================================


class UITiming:
    """UI animation and timing constants (in milliseconds)"""

    # Notification display times
    NOTIFICATION_DISPLAY_TIME: Final[int] = 3000
    TOAST_DISPLAY_TIME: Final[int] = 5000

    # Animation delays
    ANIMATION_SHORT: Final[int] = 200
    ANIMATION_MEDIUM: Final[int] = 500
    ANIMATION_LONG: Final[int] = 1000
    ANIMATION_STEP: Final[float] = 0.01  # For string matching animation


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_env_int(key: str, default: int) -> int:
    """Get integer value from environment variable or return default"""
    try:
        return int(os.getenv(key, default))
    except (ValueError, TypeError):
        return default


def get_env_float(key: str, default: float) -> float:
    """Get float value from environment variable or return default"""
    try:
        return float(os.getenv(key, default))
    except (ValueError, TypeError):
        return default


def get_env_str(key: str, default: str) -> str:
    """Get string value from environment variable or return default"""
    return os.getenv(key, default)


# =============================================================================
# PROTOCOL CONSTANTS
# =============================================================================


class Protocols:
    """Protocol strings for URL construction"""

    HTTP: Final[str] = "http://"
    HTTPS: Final[str] = "https://"


# =============================================================================
# TEMPORARY PATH PATTERNS (for backup and file operations)
# =============================================================================


class TmpPaths:
    """Temporary path patterns used throughout the system"""

    # Individual files
    SETTINGS_JSON: Final[str] = "tmp/settings.json"
    SECRETS_ENV: Final[str] = "tmp/secrets.env"

    # Directory patterns (for glob matching)
    CHATS_GLOB: Final[str] = "tmp/chats/**"
    SCHEDULER_GLOB: Final[str] = "tmp/scheduler/**"
    UPLOADS_GLOB: Final[str] = "tmp/uploads/**"


# =============================================================================
# INTERNAL PATH PREFIXES
# =============================================================================


class InternalPaths:
    """Internal path prefixes for file mapping"""

    A0_TMP_UPLOADS: Final[str] = "/a0/tmp/uploads/"


# =============================================================================
# EXTERNAL URLS
# =============================================================================


class ExternalUrls:
    """External URLs used in the application - All configurable via environment variables"""

    # Repository URL
    AGENT_ZERO_REPO: Final[str] = "https://github.com/frdel/agent-zero"

    # API Endpoints - Configurable via environment variables
    UPDATE_CHECK_URL: Final[str] = "https://api.agent-zero.ai/a0-update-check"
    PERPLEXITY_API_BASE_URL: Final[str] = "https://api.perplexity.ai"

    # Default models - Configurable via environment variables
    PERPLEXITY_DEFAULT_MODEL: Final[str] = "llama-3.1-sonar-large-128k-online"

    # Venice.ai endpoints - Configurable via environment variables
    VENICE_API_BASE: Final[str] = "https://api.venice.ai/api/v1"
    A0_VENICE_API_BASE: Final[str] = "https://api.agent-zero.ai/venice/v1"

    # OpenRouter endpoints - Configurable via environment variables
    OPENROUTER_API_BASE: Final[str] = "https://openrouter.ai/api/v1"

    # Default HTTP headers - Configurable via environment variables
    OPENROUTER_HTTP_REFERER: Final[str] = "https://agent-zero.ai/"
    OPENROUTER_X_TITLE: Final[str] = "Agent Zero"


# =============================================================================
# BROWSER CONFIGURATION
# =============================================================================


class Browser:
    """Browser agent configuration - All values configurable via environment variables"""

    # Default allowed domains for browser agent (wildcard allows all)
    ALLOWED_DOMAINS: Final[list[str]] = ["*", "http://*", "https://*"]


# =============================================================================
# SEARCH ENGINE CONFIGURATION
# =============================================================================


class Search:
    """Search engine configuration - All values configurable via environment variables"""

    # Default number of search results to return
    DEFAULT_RESULTS_COUNT: Final[int] = 10

    # DuckDuckGo search defaults
    DDG_DEFAULT_RESULTS: Final[int] = 5
    DDG_DEFAULT_REGION: Final[str] = "wt-wt"  # Worldwide
    DDG_DEFAULT_TIME_LIMIT: Final[str] = "y"  # Past year
    DDG_DEFAULT_SAFESEARCH: Final[str] = "off"

    # SearXNG search defaults
    SEARXNG_DEFAULT_RESULTS: Final[int] = 10


# =============================================================================
# EXTENSION CONFIGURATION
# =============================================================================


class Extensions:
    """Extension-specific configuration constants"""

    # Tool call file saving threshold
    # Minimum length of tool result to save as a file
    TOOL_CALL_FILE_MIN_LENGTH: Final[int] = 500


# =============================================================================
# ENVIRONMENT OVERRIDES
# Allow overriding constants via environment variables
# =============================================================================


class Config:
    """Runtime configuration with environment variable support"""

    # Timeouts
    CODE_EXEC_TIMEOUT = get_env_int("A0_CODE_EXEC_TIMEOUT", Timeouts.CODE_EXEC_MAX)
    BROWSER_TIMEOUT = get_env_int("A0_BROWSER_TIMEOUT", Timeouts.BROWSER_OPERATION_TIMEOUT)

    # Limits
    MAX_MEMORY_RESULTS = get_env_int("A0_MAX_MEMORY_RESULTS", Limits.MEMORY_DEFAULT_LIMIT)
    MEMORY_THRESHOLD = get_env_float("A0_MEMORY_THRESHOLD", Limits.MEMORY_DEFAULT_THRESHOLD)

    # Network
    DEFAULT_PORT = get_env_int("A0_DEFAULT_PORT", Network.WEB_UI_PORT_DEFAULT)
    SEARXNG_PORT = get_env_int("A0_SEARXNG_PORT", Network.SEARXNG_PORT_DEFAULT)
    TUNNEL_API_PORT = get_env_int("A0_TUNNEL_API_PORT", Network.TUNNEL_API_PORT_DEFAULT)
    BROCULA_PORT = get_env_int("A0_BROCULA_PORT", Network.BROCULA_PORT_DEFAULT)

    # RFC Ports
    RFC_PORT_HTTP = get_env_int("A0_RFC_PORT_HTTP", Limits.RFC_PORT_HTTP)
    RFC_PORT_SSH = get_env_int("A0_RFC_PORT_SSH", Limits.RFC_PORT_SSH)

    # Paths (can be overridden via env vars)
    PROJECTS_DIR = get_env_str("A0_PROJECTS_DIR", Paths.PROJECTS_PARENT_DIR)
    MEMORY_PATH = get_env_str("A0_MEMORY_PATH", Paths.MEMORY_DIR)
    UPLOAD_FOLDER = get_env_str("A0_UPLOAD_FOLDER", Paths.UPLOAD_FOLDER)
    WHISPER_MODEL_ROOT = get_env_str("A0_WHISPER_MODEL_ROOT", Paths.WHISPER_MODEL_ROOT)

    # Notification settings
    NOTIFICATION_LIFETIME_HOURS = get_env_int(
        "A0_NOTIFICATION_LIFETIME_HOURS", Timeouts.NOTIFICATION_LIFETIME_HOURS
    )

    # MCP settings
    MCP_SERVER_APPLY_DELAY = get_env_int(
        "A0_MCP_SERVER_APPLY_DELAY", Timeouts.MCP_SERVER_APPLY_DELAY
    )

    # Tunnel settings
    TUNNEL_CHECK_DELAY = get_env_int("A0_TUNNEL_CHECK_DELAY", Timeouts.TUNNEL_CHECK_DELAY)

    # External URLs - Fully configurable via environment variables
    UPDATE_CHECK_URL = get_env_str("A0_UPDATE_CHECK_URL", ExternalUrls.UPDATE_CHECK_URL)
    PERPLEXITY_API_BASE_URL = get_env_str(
        "A0_PERPLEXITY_API_BASE_URL", ExternalUrls.PERPLEXITY_API_BASE_URL
    )
    PERPLEXITY_DEFAULT_MODEL = get_env_str(
        "A0_PERPLEXITY_DEFAULT_MODEL", ExternalUrls.PERPLEXITY_DEFAULT_MODEL
    )
    AGENT_ZERO_REPO_URL = get_env_str("A0_AGENT_ZERO_REPO_URL", ExternalUrls.AGENT_ZERO_REPO)

    # Venice.ai configuration
    VENICE_API_BASE = get_env_str("A0_VENICE_API_BASE", ExternalUrls.VENICE_API_BASE)
    A0_VENICE_API_BASE = get_env_str("A0_A0_VENICE_API_BASE", ExternalUrls.A0_VENICE_API_BASE)

    # OpenRouter configuration
    OPENROUTER_API_BASE = get_env_str("A0_OPENROUTER_API_BASE", ExternalUrls.OPENROUTER_API_BASE)
    OPENROUTER_HTTP_REFERER = get_env_str(
        "A0_OPENROUTER_HTTP_REFERER", ExternalUrls.OPENROUTER_HTTP_REFERER
    )
    OPENROUTER_X_TITLE = get_env_str("A0_OPENROUTER_X_TITLE", ExternalUrls.OPENROUTER_X_TITLE)

    # Hostname defaults
    DEFAULT_HOSTNAME = get_env_str("A0_DEFAULT_HOSTNAME", Network.DEFAULT_HOSTNAME)
    DEFAULT_LOCALHOST = get_env_str("A0_DEFAULT_LOCALHOST", Network.DEFAULT_LOCALHOST)

    # Browser configuration - Allowed domains (comma-separated in env var)
    BROWSER_ALLOWED_DOMAINS = get_env_str(
        "A0_BROWSER_ALLOWED_DOMAINS", ",".join(Browser.ALLOWED_DOMAINS)
    ).split(",")

    # CORS Origins (comma-separated in env var)
    DEV_CORS_ORIGINS = get_env_str("A0_DEV_CORS_ORIGINS", ",".join(Network.DEV_CORS_ORIGINS)).split(
        ","
    )

    # Model defaults - All configurable via environment variables
    DEFAULT_CHAT_MODEL_PROVIDER = get_env_str("A0_CHAT_MODEL_PROVIDER", "openrouter")
    DEFAULT_CHAT_MODEL_NAME = get_env_str("A0_CHAT_MODEL_NAME", "openai/gpt-4.1")
    DEFAULT_UTIL_MODEL_PROVIDER = get_env_str("A0_UTIL_MODEL_PROVIDER", "openrouter")
    DEFAULT_UTIL_MODEL_NAME = get_env_str("A0_UTIL_MODEL_NAME", "openai/gpt-4.1-mini")
    DEFAULT_EMBED_MODEL_PROVIDER = get_env_str("A0_EMBED_MODEL_PROVIDER", "huggingface")
    DEFAULT_EMBED_MODEL_NAME = get_env_str(
        "A0_EMBED_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
    )
    DEFAULT_BROWSER_MODEL_PROVIDER = get_env_str("A0_BROWSER_MODEL_PROVIDER", "openrouter")
    DEFAULT_BROWSER_MODEL_NAME = get_env_str("A0_BROWSER_MODEL_NAME", "openai/gpt-4.1")
