"""Runtime environment helpers and configuration (split from constants.py)."""

import os

from .http import ExternalUrls  # type: ignore
from .limits import Limits  # type: ignore
from .misc import Browser  # type: ignore
from .network import Network  # type: ignore
from .paths import Paths  # type: ignore


def get_env_int(key: str, default: int) -> int:
    """Get integer value from environment variable or return default."""
    try:
        return int(os.getenv(key, default))
    except (ValueError, TypeError):
        return default


def get_env_float(key: str, default: float) -> float:
    """Get float value from environment variable or return default."""
    try:
        return float(os.getenv(key, default))
    except (ValueError, TypeError):
        return default


def get_env_str(key: str, default: str) -> str:
    """Get string value from environment variable or return default."""
    return os.getenv(key, default)


# =============================================================================
# CONFIGURATION
# =============================================================================


class Config:
    """Runtime configuration with environment variable support."""

    # Timeouts
    CODE_EXEC_TIMEOUT = get_env_int("A0_CODE_EXEC_TIMEOUT", 60)  # default to 60s if not defined
    BROWSER_TIMEOUT = get_env_int("A0_BROWSER_TIMEOUT", 3000)

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
    ROOT_DIR = get_env_str("A0_ROOT_DIR", Paths.ROOT_DIR)
    WORK_DIR = get_env_str("A0_WORK_DIR", Paths.WORK_DIR)
    NODE_EVAL_SCRIPT = get_env_str("A0_NODE_EVAL_SCRIPT", Paths.NODE_EVAL_SCRIPT)
    EMAIL_INBOX_PATH = get_env_str("A0_EMAIL_INBOX_PATH", Paths.EMAIL_INBOX_PATH)

    # Notification settings
    NOTIFICATION_LIFETIME_HOURS = get_env_int(
        "A0_NOTIFICATION_LIFETIME_HOURS", 24
    )

    # MCP settings
    MCP_SERVER_APPLY_DELAY = get_env_int("A0_MCP_SERVER_APPLY_DELAY", 1)

    # Tunnel settings
    TUNNEL_CHECK_DELAY = get_env_int("A0_TUNNEL_CHECK_DELAY", 2)
    FILE_BROWSER_TIMEOUT = get_env_int("A0_FILE_BROWSER_TIMEOUT", 30)

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
    VENICE_API_BASE = get_env_str("VENICE_API_BASE", getattr(ExternalUrls, "VENICE_API_BASE", "https://venice.api.local"))
    A0_VENICE_API_BASE = get_env_str("A0_VENICE_API_BASE", getattr(ExternalUrls, "A0_VENICE_API_BASE", "https://api.agent-zero.ai/venice/v1"))

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
    DEV_CORS_ORIGINS = get_env_str("A0_DEV_CORS_ORIGINS", ",".join(Network.DEV_CORS_ORIGINS)).split(",")

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
