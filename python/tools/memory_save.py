from python.helpers.memory import Memory
from python.helpers.tool import Response, Tool


class MemorySave(Tool):
    async def execute(self, text="", area="", **kwargs):
        if not text:
            return Response(message="Error: No text provided to save", break_loop=False)

        if not area:
            area = Memory.Area.MAIN.value

        metadata = {"area": area, **kwargs}

        db = await Memory.get(self.agent)
        id = await db.insert_text(text, metadata)

        result = self.agent.read_prompt("fw.memory_saved.md", memory_id=id)
        return Response(message=result, break_loop=False)
