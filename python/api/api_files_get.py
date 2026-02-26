import base64
import json
import os

from python.helpers import files
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import Colors, HttpStatus, InternalPaths, MimeTypes
from python.helpers.print_style import PrintStyle


class ApiFilesGet(ApiHandler):
    """Handler for retrieving files via API."""

    @classmethod
    def requires_auth(cls) -> bool:
        """Return False as web auth is not required."""
        return False

    @classmethod
    def requires_csrf(cls) -> bool:
        """Return False as CSRF is not required."""
        return False

    @classmethod
    def requires_api_key(cls) -> bool:
        """Return True as API key is required."""
        return True

    @classmethod
    def get_methods(cls) -> list[str]:
        """Return the list of allowed HTTP methods."""
        return ["POST"]

    async def process(self, input: dict, request: Request) -> dict | Response:
        """Process the file retrieval request."""
        try:
            # Get paths from input
            paths = input.get("paths", [])

            if not paths:
                return Response(
                    '{"error": "paths array is required"}',
                    status=HttpStatus.BAD_REQUEST,
                    mimetype=MimeTypes.APPLICATION_JSON,
                )

            if not isinstance(paths, list):
                return Response(
                    '{"error": "paths must be an array"}',
                    status=HttpStatus.BAD_REQUEST,
                    mimetype=MimeTypes.APPLICATION_JSON,
                )

            result = {}

            for path in paths:
                try:
                    # Convert internal paths to external paths
                    if path.startswith(InternalPaths.A0_TMP_UPLOADS):
                        # Internal path - convert to external
                        filename = path.replace(InternalPaths.A0_TMP_UPLOADS, "")
                        external_path = files.get_abs_path("tmp/uploads", filename)
                        filename = os.path.basename(external_path)
                    elif path.startswith("/a0/"):
                        # Other internal Agent Zero paths
                        relative_path = path.replace("/a0/", "")
                        external_path = files.get_abs_path(relative_path)
                        filename = os.path.basename(external_path)
                    else:
                        # Assume it's already an external/absolute path
                        external_path = path
                        filename = os.path.basename(path)

                    # SECURITY: Validate path is within allowed directory (prevents path traversal)
                    if not files.is_in_base_dir(external_path):
                        PrintStyle.warning(f"Path outside allowed directory: {path}")
                        continue

                    # Check if file exists
                    if not os.path.exists(external_path):
                        PrintStyle.warning(f"File not found: {path}")
                        continue

                    # Read and encode file
                    with open(external_path, "rb") as f:
                        file_content = f.read()
                        base64_content = base64.b64encode(file_content).decode("utf-8")
                        result[filename] = base64_content

                    PrintStyle().print(f"Retrieved file: {filename} ({len(file_content)} bytes)")

                except (OSError, ValueError) as e:
                    PrintStyle.error(f"Failed to read file {path}: {e!s}")
                    continue

            # Log the retrieval
            PrintStyle(
                background_color=Colors.FILES_GREEN,
                font_color=Colors.BG_WHITE,
                bold=True,
                padding=True,
            ).print(f"API Files retrieved: {len(result)} files")

            return result

        except (RuntimeError, TypeError) as e:
            PrintStyle.error(f"API files get error: {e!s}")
            return Response(
                json.dumps({"error": f"Internal server error: {e!s}"}),
                status=HttpStatus.ERROR,
                mimetype=MimeTypes.APPLICATION_JSON,
            )
