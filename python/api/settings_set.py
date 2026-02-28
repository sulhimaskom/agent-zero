"""Settings update API endpoint - modifies agent configuration.

Allows runtime modification of agent settings including model providers,
API keys, behavior parameters, and other configuration options.
Settings changes are persisted and applied immediately.
"""

from typing import Any

from python.helpers import settings
from python.helpers.api import ApiHandler, Request, Response


class SetSettings(ApiHandler):
    async def process(self, input: dict[Any, Any], request: Request) -> dict[Any, Any] | Response:
        set = settings.convert_in(input)
        set = settings.set_settings(set)
        return {"settings": set}
