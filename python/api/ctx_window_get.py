"""Context window retrieval API endpoint - returns current context window content and token count.

Provides access to the agent's context window for display in the UI,
including the full text content and token usage statistics.
"""

from python.helpers.api import ApiHandler, Input, Output, Request


class GetCtxWindow(ApiHandler):
    async def process(self, input: Input, request: Request) -> Output:
        ctxid = input.get("context", [])
        context = self.use_context(ctxid)
        agent = context.streaming_agent or context.agent0
        window = agent.get_data(agent.DATA_NAME_CTX_WINDOW)
        if not window or not isinstance(window, dict):
            return {"content": "", "tokens": 0}

        text = window["text"]
        tokens = window["tokens"]

        return {"content": text, "tokens": tokens}
