import asyncio
from python.helpers.api import ApiHandler, Request, Response
from python.helpers import dotenv, runtime
from python.helpers.tunnel_manager import TunnelManager
import aiohttp


class TunnelProxy(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict | Response:
        # Get configuration from environment
        tunnel_api_port = (
            runtime.get_arg("tunnel_api_port")
            or int(dotenv.get_dotenv_value("TUNNEL_API_PORT", 0))
            or 55520
        )

        # first verify the service is running:
        service_ok = False
        try:
            timeout = aiohttp.ClientTimeout(total=5.0)  # 5 second timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(f"http://localhost:{tunnel_api_port}/", json={"action": "health"}) as response:
                    if response.status == 200:
                        service_ok = True
        except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
            service_ok = False

        # forward this request to the tunnel service if OK
        if service_ok:
            try:
                timeout = aiohttp.ClientTimeout(total=30.0)  # 30 second timeout for main request
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(f"http://localhost:{tunnel_api_port}/", json=input) as response:
                        if response.status == 200:
                            return await response.json()
                        else:
                            return {"error": f"HTTP {response.status}: {await response.text()}"}
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
                return {"error": f"Tunnel service error: {str(e)}"}
            except Exception as e:
                return {"error": f"Unexpected error: {str(e)}"}
        else:
            # forward to API handler directly
            from python.api.tunnel import Tunnel
            return await Tunnel(self.app, self.thread_lock).process(input, request)
