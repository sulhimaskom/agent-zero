"""Asynchronous chat message endpoint.

Acknowledges message receipt without waiting for agent processing.
Returns immediately with context ID for polling status updates.
Inherits from Message endpoint but returns instant acknowledgment.
"""

from agent import AgentContext
from python.api.message import Message
from python.helpers.defer import DeferredTask


class MessageAsync(Message):
    async def respond(self, task: DeferredTask, context: AgentContext):
        return {
            "message": "Message received.",
            "context": context.id,
        }
