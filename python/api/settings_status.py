"""Settings status API endpoint.

Returns information about the current settings state:
- isFirstTime: true if no settings file exists (first-time user)
- hasApiKey: true if any API keys are configured
"""

import os

from python.helpers import settings
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import Paths


class GetSettingsStatus(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict | Response:
        # Check if settings file exists
        settings_file = settings.SETTINGS_FILE
        is_first_time = not os.path.exists(settings_file)
        
        # Check if any API keys are configured
        has_api_key = False
        if not is_first_time:
            current_settings = settings.get_settings()
            # Check for any non-empty API keys
            api_keys = current_settings.get("api_keys", {})
            has_api_key = any(bool(v) for v in api_keys.values())
        
        return {
            "isFirstTime": is_first_time,
            "hasApiKey": has_api_key
        }

    @classmethod
    def get_methods(cls) -> list[str]:
        return ["GET", "POST"]
