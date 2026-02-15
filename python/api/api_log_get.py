from agent import AgentContext
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import HttpStatus


class ApiLogGet(ApiHandler):
    """Handler for retrieving chat logs via API."""

    @classmethod
    def get_methods(cls) -> list[str]:
        """Return the list of allowed HTTP methods."""
        return ["GET", "POST"]

    @classmethod
    def requires_auth(cls) -> bool:
        """Return False as web auth is not required."""
        return False  # No web auth required

    @classmethod
    def requires_csrf(cls) -> bool:
        """Return False as CSRF is not required."""
        return False  # No CSRF required

    @classmethod
    def requires_api_key(cls) -> bool:
        """Return True as API key is required."""
        return True  # Require API key

    async def process(self, input: dict, request: Request) -> dict | Response:
        """Process the log retrieval request."""
        # Extract parameters (support both query params for GET and body for POST)
        if request.method == "GET":
            context_id = request.args.get("context_id", "")
            length = int(request.args.get("length", 100))
        else:
            context_id = input.get("context_id", "")
            length = input.get("length", 100)

        if not context_id:
            return Response(
                '{"error": "context_id is required"}',
                status=HttpStatus.BAD_REQUEST,
                mimetype="application/json",
            )

        # Get context
        context = AgentContext.use(context_id)
        if not context:
            return Response(
                '{"error": "Context not found"}',
                status=HttpStatus.NOT_FOUND,
                mimetype="application/json",
            )

        try:
            # Get total number of log items
            total_items = len(context.log.logs)

            # Calculate start position (from newest, so we work backwards)
            start_pos = max(0, total_items - length)

            # Get log items from the calculated start position
            log_items = context.log.output(start=start_pos)

            # Return log data with metadata
            return {
                "context_id": context_id,
                "log": {
                    "guid": context.log.guid,
                    "total_items": total_items,
                    "returned_items": len(log_items),
                    "start_position": start_pos,
                    "progress": context.log.progress,
                    "progress_active": context.log.progress_active,
                    "items": log_items,
                },
            }

        except (AttributeError, RuntimeError) as e:
            return Response(
                f'{{"error": "{e!s}"}}',
                status=HttpStatus.ERROR,
                mimetype="application/json",
            )
