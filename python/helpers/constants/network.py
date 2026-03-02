"""Network constants extracted from constants.py.

This module was split from the original constants.py to improve modularity.
All values are preserved exactly as in the source.
"""

from typing import Final


class Network:
    """Network-related constants."""

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
    A2A_PORT_DEFAULT: Final[int] = 50101

    STATIC_PORTS: Final[list[str]] = [
        "8080",
        "5002",
        "3000",
        "5000",
        "8000",
        "5500",
        "3001",
        "50001",
    ]

    # CORS allowed origins (development)
    # SECURITY: These defaults are for development only!
    # For production, set A0_DEV_CORS_ORIGINS to your actual domain
    # or empty string to disable CORS (same-origin only)
    DEV_CORS_ORIGINS: Final[list[str]] = [
        "http://localhost:50001",
        "http://127.0.0.1:50001",
    ]

    # Production CORS defaults - more restrictive
    # Empty by default (same-origin only) for production security
    # Set A0_DEV_CORS_ORIGINS env var to configure
    PROD_CORS_ORIGINS: Final[list[str]] = []

    # External API endpoints
    UPDATE_CHECK_URL: Final[str] = "https://api.agent-zero.ai/a0-update-check"
    PERPLEXITY_API_BASE_URL: Final[str] = "https://api.perplexity.ai"
    PERPLEXITY_DEFAULT_MODEL: Final[str] = "llama-3.1-sonar-large-128k-online"


