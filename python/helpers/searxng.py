import aiohttp
from python.helpers import runtime
from python.helpers import dotenv

SEARXNG_PORT = int(dotenv.get_dotenv_value("SEARXNG_PORT", 0)) or 55510
SEARXNG_HOST = dotenv.get_dotenv_value("SEARXNG_HOST", "localhost") or "localhost"
URL = f"http://{SEARXNG_HOST}:{SEARXNG_PORT}/search"

async def search(query:str):
    return await runtime.call_development_function(_search, query=query)

async def _search(query:str):
    async with aiohttp.ClientSession() as session:
        async with session.post(URL, data={"q": query, "format": "json"}) as response:
            return await response.json()
