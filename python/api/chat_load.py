"""Chat load API endpoint - loads chat history from JSON files.

Provides functionality to load previous chat sessions into memory
by reading chat data from JSON files and restoring agent context.
"""

from python.helpers import persist_chat
from python.helpers.api import ApiHandler, Input, Output, Request


class LoadChats(ApiHandler):
    async def process(self, input: Input, request: Request) -> Output:
        chats = input.get("chats", [])
        if not chats:
            raise ValueError("No chats provided")

        ctxids = persist_chat.load_json_chats(chats)

        return {
            "message": "Chats loaded.",
            "ctxids": ctxids,
        }
