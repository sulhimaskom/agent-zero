"""UI/PrintStyle colors and timing constants."""

from typing import Final


class Colors:
    """Color constants for terminal and UI output."""

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


class UITiming:
    """UI animation and timing constants (in milliseconds)."""

    # Notification display times
    NOTIFICATION_DISPLAY_TIME: Final[int] = 3000
    TOAST_DISPLAY_TIME: Final[int] = 5000

    # Animation delays
    ANIMATION_SHORT: Final[int] = 200
    ANIMATION_MEDIUM: Final[int] = 500
    ANIMATION_LONG: Final[int] = 1000
    ANIMATION_STEP: Final[float] = 0.01  # For string matching animation
