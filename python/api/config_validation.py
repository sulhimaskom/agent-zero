from python.helpers.api import ApiHandler, Request, Response
from python.helpers.config_validator import validate_config


class ConfigValidation(ApiHandler):
    """Configuration validation endpoint."""

    @classmethod
    def requires_auth(cls) -> bool:
        return False

    @classmethod
    def requires_csrf(cls) -> bool:
        return False

    @classmethod
    def get_methods(cls) -> list[str]:
        return ["GET", "POST"]

    async def process(self, input: dict, request: Request) -> dict | Response:
        result = validate_config()
        return result.to_dict()
