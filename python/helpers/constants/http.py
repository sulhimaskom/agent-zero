"""HTTP status codes and external URLs (HTTP-related constants)."""

from typing import Final


class HttpStatus:
    """HTTP status codes used in the application."""

    OK: Final[int] = 200
    BAD_REQUEST: Final[int] = 400
    UNAUTHORIZED: Final[int] = 401
    FORBIDDEN: Final[int] = 403
    NOT_FOUND: Final[int] = 404
    REQUEST_TIMEOUT: Final[int] = 408
    TOO_MANY_REQUESTS: Final[int] = 429
    ERROR: Final[int] = 500
    BAD_GATEWAY: Final[int] = 502
    SERVICE_UNAVAILABLE: Final[int] = 503
    GATEWAY_TIMEOUT: Final[int] = 504


class ExternalUrls:
    """External URLs used in the application - All configurable via environment variables."""

    # Repository URL
    AGENT_ZERO_REPO: Final[str] = "https://github.com/frdel/agent-zero"

    # API Endpoints - Configurable via environment variables
    UPDATE_CHECK_URL: Final[str] = "https://api.agent-zero.ai/a0-update-check"
    PERPLEXITY_API_BASE_URL: Final[str] = "https://api.perplexity.ai"
    PERPLEXITY_DEFAULT_MODEL: Final[str] = "llama-3.1-sonar-large-128k-online"

    # Venice/OpenRouter related endpoints (configurable via env vars)
    VENICE_API_BASE: Final[str] = "https://api.venice.ai/api/v1"
    A0_VENICE_API_BASE: Final[str] = "https://api.agent-zero.ai/venice/v1"
    OPENROUTER_API_BASE: Final[str] = "https://openrouter.ai/api/v1"
    OPENROUTER_HTTP_REFERER: Final[str] = "https://agent-zero.ai/"
    OPENROUTER_X_TITLE: Final[str] = "Agent Zero"
