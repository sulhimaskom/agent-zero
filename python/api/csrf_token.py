"""CSRF token retrieval endpoint.

Returns a CSRF token for secure form submissions.
Required for state-changing operations to prevent cross-site requests.
"""

import fnmatch
import secrets
from urllib.parse import urlparse

from flask import Request, session

from python.helpers import dotenv, login, runtime
from python.helpers.api import ApiHandler, Input, Output
from python.helpers.constants import Network
from python.helpers.print_style import PrintStyle


class GetCsrfToken(ApiHandler):
    @classmethod
    def get_methods(cls) -> list[str]:
        return ["GET"]

    @classmethod
    def requires_csrf(cls) -> bool:
        return False

    async def process(self, input: Input, request: Request) -> Output:

        # check for allowed origin to prevent dns rebinding attacks
        origin_check = await self.check_allowed_origin(request)
        if not origin_check["ok"]:
            origin = self.get_origin_from_request(request)
            allowed_list = ",".join(origin_check["allowed_origins"])
            return {
                "ok": False,
                "error": (
                    f"Origin {origin} not allowed when login is disabled. "
                    f"Set login and password or add your URL to ALLOWED_ORIGINS "
                    f"env variable. Currently allowed origins: {allowed_list}"
                ),
            }

        # generate a csrf token if it doesn't exist
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        # Check and log CORS security warning for production
        cors_warning = self.get_cors_security_warning()
        if cors_warning:
            PrintStyle.warning(cors_warning)

        # return the csrf token and runtime id
        response = {
            "ok": True,
            "token": session["csrf_token"],
            "runtime_id": runtime.get_runtime_id(),
        }

        # Add warning to response if present
        if cors_warning:
            response["cors_warning"] = cors_warning

        return response

    def get_cors_security_warning(self) -> str | None:
        """Check if permissive CORS is used in production and return warning."""
        if runtime.is_development():
            return None

        # Check if using default permissive origins in production
        allowed_origins = Network.DEV_CORS_ORIGINS
        permissive_patterns = ["localhost", "127.0.0.1"]

        for origin in allowed_origins:
            for pattern in permissive_patterns:
                if pattern in origin:
                    return (
                        "SECURITY WARNING: Permissive CORS origins detected in production. "
                        "Default origins include localhost which may allow unauthorized cross-origin requests. "
                        "Set A0_DEV_CORS_ORIGINS to your production domain or empty string for same-origin only."
                    )
        return None

    async def check_allowed_origin(self, request: Request):
        # if login is required, this che
        if login.is_login_required():
            return {"ok": True, "origin": "", "allowed_origins": ""}
        # otherwise, check if the origin is allowed
        return await self.is_allowed_origin(request)

    async def is_allowed_origin(self, request: Request):
        # get the origin from the request
        origin = self.get_origin_from_request(request)
        if not origin:
            return {"ok": False, "origin": "", "allowed_origins": ""}

        # list of allowed origins
        allowed_origins = await self.get_allowed_origins()

        # check if the origin is allowed
        match = any(fnmatch.fnmatch(origin, allowed_origin) for allowed_origin in allowed_origins)
        return {
            "ok": match,
            "origin": origin,
            "allowed_origins": allowed_origins,
        }

    def get_origin_from_request(self, request: Request):
        # get from origin
        r = request.headers.get("Origin") or request.environ.get("HTTP_ORIGIN")
        if not r:
            # try referer if origin not present
            r = (
                request.headers.get("Referer")
                or request.referrer
                or request.environ.get("HTTP_REFERER")
            )
        if not r:
            return None
        # parse and normalize
        p = urlparse(r)
        if not p.scheme or not p.hostname:
            return None
        return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")

    async def get_allowed_origins(self) -> list[str]:
        # get the allowed origins from the environment
        allowed_origins = [
            origin.strip()
            for origin in (dotenv.get_dotenv_value("ALLOWED_ORIGINS") or "").split(",")
            if origin.strip()
        ]

        # if there are no allowed origins, allow default localhosts
        if not allowed_origins:
            allowed_origins = self.get_default_allowed_origins()

        # always allow tunnel url if running
        try:
            from python.api.tunnel_proxy import process as tunnel_api_process

            tunnel = await tunnel_api_process({"action": "get"})
            if tunnel and isinstance(tunnel, dict) and tunnel["success"]:
                allowed_origins.append(tunnel["tunnel_url"])
        except Exception:
            pass

        return allowed_origins

    def get_default_allowed_origins(self) -> list[str]:
        return Network.DEV_CORS_ORIGINS
