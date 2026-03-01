import aiohttp

from python.helpers import dotenv, runtime
from python.helpers.constants import Network

SEARXNG_PORT = int(dotenv.get_dotenv_value("SEARXNG_PORT", 0)) or Network.SEARXNG_PORT_DEFAULT
SEARXNG_HOST = (
    dotenv.get_dotenv_value("SEARXNG_HOST", Network.DEFAULT_HOSTNAME) or Network.DEFAULT_HOSTNAME
)
URL = f"http://{SEARXNG_HOST}:{SEARXNG_PORT}/search"


async def search(query: str):
    return await runtime.call_development_function(_search, query=query)


async def _search(query: str):
    async with (
        aiohttp.ClientSession() as session,
        session.post(URL, data={"q": query, "format": "json"}) as response,
    ):
        return await response.json()
