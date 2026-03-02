"""
Timeout constants for Agent Zero framework.

This module was split from constants.py for better modularity.
"""

from typing import Final


class Timeouts:
    """Timeout values in seconds."""

    CODE_EXEC_FIRST_OUTPUT: Final[int] = 30
    CODE_EXEC_BETWEEN_OUTPUT: Final[int] = 15
    CODE_EXEC_MAX: Final[int] = 180
    CODE_EXEC_DIALOG: Final[int] = 5
    OUTPUT_FIRST_TIMEOUT: Final[int] = 90
    OUTPUT_BETWEEN_TIMEOUT: Final[int] = 45
    OUTPUT_MAX_TIMEOUT: Final[int] = 300
    BROWSER_LLM_TIMEOUT: Final[int] = 3000
    BROWSER_MAX_STEPS: Final[int] = 50
    BROWSER_OPERATION_TIMEOUT: Final[int] = 300
    BROWSER_ASYNC_TIMEOUT: Final[int] = 10
    BROWSER_SCREENSHOT_TIMEOUT: Final[int] = 3000
    RFC_FUNCTION_TIMEOUT: Final[int] = 30
    EMAIL_CONNECTION_TIMEOUT: Final[int] = 30
    TTY_READ_TIMEOUT: Final[float] = 1.0
    TTY_TOTAL_TIMEOUT_MULTIPLIER: Final[int] = 10
    IDLE_TIMEOUT: Final[float] = 1.0
    SHORT_IDLE_TIMEOUT: Final[float] = 0.01
    SCHEDULER_DEFAULT_WAIT: Final[int] = 300
    SCHEDULER_CHECK_FREQUENCY: Final[float] = 60.0
    INPUT_DEFAULT_TIMEOUT: Final[int] = 10
    MCP_SERVER_APPLY_DELAY: Final[int] = 1
    TUNNEL_CHECK_DELAY: Final[int] = 2
    HTTP_CACHE_MAX_AGE: Final[int] = 86400
    HTTP_CACHE_DEFAULT: Final[int] = 3600
    HTTP_CACHE_VENDOR: Final[int] = 31536000
    HTTP_CACHE_ASSETS: Final[int] = 86400
    HTTP_CACHE_IMAGES: Final[int] = 604800
    NOTIFICATION_LIFETIME_HOURS: Final[int] = 24
    UPDATE_CHECK_COOLDOWN_SECONDS: Final[int] = 60
    UPDATE_NOTIFICATION_COOLDOWN_SECONDS: Final[int] = 86400
    MCP_CLIENT_INIT_TIMEOUT: Final[int] = 10
    MCP_CLIENT_TOOL_TIMEOUT: Final[int] = 120
    MCP_CLIENT_SESSION_TIMEOUT: Final[int] = 60
    DOCUMENT_DOWNLOAD_TIMEOUT: Final[float] = 10.0
    DOCUMENT_POLL_INTERVAL: Final[int] = 2
    DOCUMENT_MAX_WAIT: Final[int] = 300
    FILE_BROWSER_TIMEOUT: Final[int] = 30
    NOTIFICATION_DEFAULT_TIMEOUT: Final[int] = 30
    NOTIFICATION_AGENT_TIMEOUT: Final[int] = 30
    DOCKER_INIT_DELAY: Final[int] = 5
    DOCKER_RETRY_DELAY: Final[int] = 2
    DOCKER_STARTUP_DELAY: Final[int] = 5
    TUNNEL_STARTUP_ITERATIONS: Final[int] = 150
    TUNNEL_STARTUP_DELAY: Final[float] = 0.1
    SSH_SHELL_DELAY: Final[float] = 0.1
    SSH_CONNECTION_DELAY: Final[int] = 5
    MODEL_UPDATE_CHECK_DELAY: Final[float] = 0.1
    WAIT_PAUSE_THRESHOLD: Final[float] = 1.5
    WAIT_SLEEP_INTERVAL: Final[float] = 1.0
    HTTP_CLIENT_DEFAULT_TIMEOUT: Final[float] = 30.0
    RATE_LIMITER_DEFAULT_TIMEFRAME: Final[int] = 60
    RETRY_DELAY_SHORT: Final[int] = 1
    POLLING_INTERVAL: Final[int] = 1
    AGENT_PAUSE_CHECK_DELAY: Final[float] = 0.1
    LIGHTHOUSE_VERSION_TIMEOUT: Final[int] = 10
    LIGHTHOUSE_AUDIT_TIMEOUT: Final[int] = 120
    BROCULA_COMMAND_TIMEOUT: Final[int] = 60
    BROCULA_LIGHTHOUSE_TIMEOUT: Final[int] = 120
    BROCULA_OPCODE_TIMEOUT: Final[int] = 7200
    BROCULA_PAGE_NAV_TIMEOUT: Final[int] = 30000
    TTY_DRAIN_DELAY: Final[float] = 0
    TTY_WRITE_DELAY: Final[float] = 0.01
    TTY_READ_CHUNK_DELAY: Final[float] = 0.2
    TASK_SCHEDULER_INIT_DELAY: Final[float] = 0.1
