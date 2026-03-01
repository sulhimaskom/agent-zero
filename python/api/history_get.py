"""Chat history retrieval API endpoint - returns message history and token count.

Provides access to the conversation history for a given context,
including all messages and token usage statistics.
"""

from python.helpers.api import ApiHandler, Request, Response


class GetHistory(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict | Response:
        ctxid = input.get("context", [])
        context = self.use_context(ctxid)
        agent = context.streaming_agent or context.agent0
        history = agent.history.output_text()
        size = agent.history.get_tokens()

        return {"history": history, "tokens": size}
