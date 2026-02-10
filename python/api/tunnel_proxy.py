from python.helpers.api import ApiHandler, Request, Response
from python.helpers import dotenv, runtime
from python.helpers.constants import Network, Timeouts
import requests


class TunnelProxy(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict | Response:
        return await process(input)

async def process(input: dict) -> dict | Response:
    # Get configuration from environment
    tunnel_api_port = (
        runtime.get_arg("tunnel_api_port")
        or int(dotenv.get_dotenv_value("TUNNEL_API_PORT", 0))
        or Network.TUNNEL_API_PORT_FALLBACK
    )

    # first verify the service is running:
    service_ok = False
    try:
        response = requests.post(
            f"http://{Network.DEFAULT_HOSTNAME}:{tunnel_api_port}/",
            json={"action": "health"},
            timeout=Timeouts.HTTP_CLIENT_DEFAULT_TIMEOUT
        )
        if response.status_code == 200:
            service_ok = True
    except Exception:
        service_ok = False

    # forward this request to the tunnel service if OK
    if service_ok:
        try:
            response = requests.post(
                f"http://{Network.DEFAULT_HOSTNAME}:{tunnel_api_port}/",
                json=input,
                timeout=Timeouts.HTTP_CLIENT_DEFAULT_TIMEOUT
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    else:
        # forward to API handler directly
        from python.api.tunnel import process as local_process
        return await local_process(input)
