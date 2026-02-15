"""
Configuration management for Agent Zero.

Flexy says: All configuration centralized, no hardcoded values!
"""

import json
import os
from typing import Any

from python.helpers.constants import (
    Config as ConstConfig,
)
from python.helpers.constants import (
    Limits,
    Network,
)


def get_frontend_config() -> dict[str, Any]:
    """
    Get configuration for frontend injection.

    Returns a dictionary of configuration values that should be exposed to the frontend.
    """
    return {
        # Network configuration
        "WEB_UI_PORT": ConstConfig.DEFAULT_PORT,
        "TUNNEL_API_PORT": ConstConfig.TUNNEL_API_PORT,
        "SEARXNG_PORT": ConstConfig.SEARXNG_PORT,
        "A2A_PORT": int(os.getenv("A0_A2A_PORT", str(Network.A2A_PORT_DEFAULT))),
        "BROCULA_PORT": ConstConfig.BROCULA_PORT,
        "RFC_PORT_HTTP": ConstConfig.RFC_PORT_HTTP,
        "RFC_PORT_SSH": ConstConfig.RFC_PORT_SSH,
        # Host configuration
        "HOSTNAME": ConstConfig.DEFAULT_HOSTNAME,
        "LOCALHOST": ConstConfig.DEFAULT_LOCALHOST,
        # External URLs (safe to expose)
        "AGENT_ZERO_REPO_URL": ConstConfig.AGENT_ZERO_REPO_URL,
        "UPDATE_CHECK_URL": ConstConfig.UPDATE_CHECK_URL,
        # Feature flags
        "FEATURES": {
            "mcp_enabled": True,
            "a2a_enabled": True,
            "tunnel_enabled": True,
            "speech_enabled": True,
        },
        # Limits (for frontend validation)
        "LIMITS": {
            "max_attachment_size": Limits.FILE_BROWSER_MAX_FILE_SIZE,
            "max_file_size": Limits.FILE_READ_MAX_SIZE,
            "max_message_length": 10000,
        },
        "STATIC_PORTS": Network.STATIC_PORTS,
    }


def get_env_config_js() -> str:
    """Generate JavaScript code to inject configuration into window.ENV_CONFIG."""
    config = get_frontend_config()
    config_json = json.dumps(config, indent=2)
    return f"""<script>
    window.ENV_CONFIG = {config_json};
</script>"""


def inject_config_into_html(html_content: str) -> str:
    """Inject ENV_CONFIG script tag into HTML content before the closing </head> tag."""
    config_script = get_env_config_js()

    # Find the </head> tag and insert config before it
    if "</head>" in html_content:
        html_content = html_content.replace("</head>", f"{config_script}\n</head>")

    return html_content
