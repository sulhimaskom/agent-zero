"""External API endpoint for agent messaging.

Provides API access for sending messages to agents with support
for file attachments, context management, and authentication.
"""

import base64
import os
import threading
from datetime import datetime, timedelta
from typing import ClassVar

from werkzeug.utils import secure_filename

from agent import AgentContext, AgentContextType, UserMessage
from initialize import initialize_agent
from python.helpers import files
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import Colors, HttpStatus, MimeTypes, Paths, Timeouts
from python.helpers.print_style import PrintStyle


class ApiMessage(ApiHandler):
    """Handler for external API messaging."""

    # Track chat lifetimes for cleanup
    _chat_lifetimes: ClassVar[dict[str, datetime]] = {}
    _cleanup_lock = threading.Lock()

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
        """Process the message request."""
        # Extract parameters
        context_id = input.get("context_id", "")
        message = input.get("message", "")
        attachments = input.get("attachments", [])
        lifetime_hours = input.get(
            "lifetime_hours", Timeouts.NOTIFICATION_LIFETIME_HOURS
        )  # Default from constants

        if not message:
            return Response(
                '{"error": "Message is required"}',
                status=HttpStatus.BAD_REQUEST,
                mimetype=MimeTypes.APPLICATION_JSON,
            )

        # Handle attachments (base64 encoded)
        attachment_paths = []
        if attachments:
            upload_folder_int = Paths.UPLOAD_FOLDER
            upload_folder_ext = files.get_abs_path("tmp/uploads")
            os.makedirs(upload_folder_ext, exist_ok=True)

            for attachment in attachments:
                if (
                    not isinstance(attachment, dict)
                    or "filename" not in attachment
                    or "base64" not in attachment
                ):
                    continue

                try:
                    filename = secure_filename(attachment["filename"])
                    if not filename:
                        continue

                    # Decode base64 content
                    file_content = base64.b64decode(attachment["base64"])

                    # Save to temp file
                    save_path = os.path.join(upload_folder_ext, filename)
                    with open(save_path, "wb") as f:
                        f.write(file_content)

                    attachment_paths.append(os.path.join(upload_folder_int, filename))
                except (ValueError, OSError) as e:
                    PrintStyle.error(
                        f"Failed to process attachment {attachment.get('filename', 'unknown')}: {e}"
                    )
                    continue

        # Get or create context
        if context_id:
            context = AgentContext.use(context_id)
            if not context:
                return Response(
                    '{"error": "Context not found"}',
                    status=HttpStatus.NOT_FOUND,
                    mimetype=MimeTypes.APPLICATION_JSON,
                )
        else:
            config = initialize_agent()
            context = AgentContext(config=config, type=AgentContextType.USER)
            AgentContext.use(context.id)
            context_id = context.id

        # Update chat lifetime
        with self._cleanup_lock:
            self._chat_lifetimes[context_id] = datetime.now() + timedelta(hours=lifetime_hours)

        # Process message
        try:
            # Log the message
            attachment_filenames = (
                [os.path.basename(path) for path in attachment_paths] if attachment_paths else []
            )

            PrintStyle(
                background_color=Colors.AGENT_PURPLE,
                font_color=Colors.BG_WHITE,
                bold=True,
                padding=True,
            ).print("External API message:")
            PrintStyle(font_color=Colors.BG_WHITE, padding=False).print(f"> {message}")
            if attachment_filenames:
                PrintStyle(font_color="white", padding=False).print("Attachments:")
                for filename in attachment_filenames:
                    PrintStyle(font_color="white", padding=False).print(f"- {filename}")

            # Add user message to chat history so it's visible in the UI
            context.log.log(
                type="user",
                heading="User message",
                content=message,
                kvps={"attachments": attachment_filenames},
            )

            # Send message to agent
            task = context.communicate(UserMessage(message, attachment_paths))
            result = await task.result()

            # Clean up expired chats
            self._cleanup_expired_chats()

            return {"context_id": context_id, "response": result}

        except (RuntimeError, ValueError, KeyError) as e:
            PrintStyle.error(f"External API error: {e}")
            return Response(
                f'{{"error": "{e!s}"}}',
                status=HttpStatus.ERROR,
                mimetype=MimeTypes.APPLICATION_JSON,
            )

    @classmethod
    def _cleanup_expired_chats(cls):
        """Clean up expired chats."""
        with cls._cleanup_lock:
            now = datetime.now()
            expired_contexts = [
                context_id for context_id, expiry in cls._chat_lifetimes.items() if now > expiry
            ]

            for context_id in expired_contexts:
                try:
                    context = AgentContext.get(context_id)
                    if context:
                        context.reset()
                        AgentContext.remove(context_id)
                    del cls._chat_lifetimes[context_id]
                    PrintStyle().print(f"Cleaned up expired chat: {context_id}")
                except (RuntimeError, KeyError) as e:
                    PrintStyle.error(f"Failed to cleanup chat {context_id}: {e}")
