from python.helpers.constants import Search
from python.helpers.errors import handle_error
from python.helpers.searxng import search as searxng
from python.helpers.tool import Response, Tool


class SearchEngine(Tool):
    async def execute(self, query="", **kwargs):

        searxng_result = await self.searxng_search(query)

        await self.agent.handle_intervention(
            searxng_result
        )  # wait for intervention and handle it, if paused

        return Response(message=searxng_result, break_loop=False)

    async def searxng_search(self, question):
        results = await searxng(question)
        return self.format_result_searxng(results, "Search Engine")

    def format_result_searxng(self, result, source):
        if isinstance(result, Exception):
            handle_error(result)
            return f"{source} search failed: {result!s}"

        outputs = []
        if not isinstance(result, dict) or "results" not in result:
            return f"{source} search returned invalid result"

        for item in result.get("results", []):
            title = item.get("title", "Untitled")
            url = item.get("url", "")
            content = item.get("content", "")
            outputs.append(f"{title}\n{url}\n{content}")

        return "\n\n".join(outputs[: Search.DEFAULT_RESULTS_COUNT]).strip()
