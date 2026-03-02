"""Limits and thresholds extracted from constants.py.

This module was split from the original constants.py to improve modularity.
All values are preserved exactly as in the source.
"""

from typing import Final


class Limits:
    """Size limits, thresholds, and count limits."""

    # Model context lengths (default values)
    DEFAULT_CHAT_MODEL_CTX_LENGTH: Final[int] = 100000
    DEFAULT_UTIL_MODEL_CTX_LENGTH: Final[int] = 100000

    # Context length cap for UI operations (e.g., chat rename)
    CONTEXT_MAX_LEN_DEFAULT: Final[int] = 5000

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

    # Standard SSH port (for local shell interface)
    SSH_DEFAULT_PORT: Final[int] = 22

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

    # Message length limits (for frontend validation)
    MAX_MESSAGE_LENGTH: Final[int] = 10000
