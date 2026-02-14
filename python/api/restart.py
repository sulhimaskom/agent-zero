from python.helpers import process
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import HttpStatus


class Restart(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict | Response:
        process.reload()
        return Response(status=HttpStatus.OK)
