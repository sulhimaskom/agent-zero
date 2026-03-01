"""Chat export endpoint.

Exports a chat session to JSON format for backup or migration.
Returns the complete conversation history as a downloadable JSON file.
"""

from python.helpers import persist_chat
from python.helpers.api import ApiHandler, Input, Output, Request


class ExportChat(ApiHandler):
    async def process(self, input: Input, request: Request) -> Output:
        ctxid = input.get("ctxid", "")
        if not ctxid:
            raise ValueError("No context id provided")

        context = self.use_context(ctxid)
        content = persist_chat.export_json_chat(context)
        return {
            "message": "Chats exported.",
            "ctxid": context.id,
            "content": content,
        }
