"""Health check API endpoint.

Provides system diagnostics and health status information.
"""

from python.helpers import errors, git
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.health_check import Diagnostics, get_health_checker


class HealthCheck(ApiHandler):
    """Health check endpoint with system diagnostics."""

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
        gitinfo = None
        error = None
        health_status = None
        system_info = None

        try:
            gitinfo = git.get_git_info()
        except (ImportError, AttributeError, OSError, ValueError) as e:
            error = errors.error_text(e)

        # Run comprehensive health checks
        try:
            checker = get_health_checker()
            health_status = await checker.run_all_checks()
        except Exception as e:
            error = error or ""
            error += f"; Health check failed: {errors.error_text(e)}"

        # Get system diagnostics
        try:
            system_info = Diagnostics.get_system_info()
        except Exception as e:
            error = error or ""
            error += f"; System info failed: {errors.error_text(e)}"

        return {
            "gitinfo": gitinfo,
            "health": health_status.to_dict() if health_status else None,
            "system_info": system_info,
            "error": error,
        }
