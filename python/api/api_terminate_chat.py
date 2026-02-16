import json

from agent import AgentContext
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import Colors, HttpStatus, MimeTypes
from python.helpers.persist_chat import remove_chat
from python.helpers.print_style import PrintStyle


class ApiTerminateChat(ApiHandler):
    """Handler for terminating chat via API."""

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
        """Process the chat termination request."""
        try:
            # Get context_id from input
            context_id = input.get("context_id")

            if not context_id:
                return Response(
                    '{"error": "context_id is required"}',
                    status=HttpStatus.BAD_REQUEST,
                    mimetype=MimeTypes.APPLICATION_JSON,
                )

            # Check if context exists
            context = AgentContext.use(context_id)
            if not context:
                return Response(
                    '{"error": "Chat context not found"}',
                    status=HttpStatus.NOT_FOUND,
                    mimetype=MimeTypes.APPLICATION_JSON,
                )

            # Delete the chat context
            AgentContext.remove(context.id)
            remove_chat(context.id)

            # Log the deletion
            PrintStyle(
                background_color=Colors.ERROR,
                font_color=Colors.BG_WHITE,
                bold=True,
                padding=True,
            ).print(f"API Chat deleted: {context_id}")

            # Return success response
            return {
                "success": True,
                "message": "Chat deleted successfully",
                "context_id": context_id,
            }

        except (RuntimeError, KeyError, TypeError) as e:
            PrintStyle.error(f"API terminate chat error: {e!s}")
            return Response(
                json.dumps({"error": f"Internal server error: {e!s}"}),
                status=HttpStatus.ERROR,
                mimetype=MimeTypes.APPLICATION_JSON,
            )
