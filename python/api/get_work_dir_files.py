"""Work directory file listing API endpoint - retrieves files and folders in a directory.

Returns the file tree structure for the specified path within the
work directory, supporting navigation and file browsing.
"""

from python.helpers import runtime
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.file_browser import FileBrowser


class GetWorkDirFiles(ApiHandler):
    @classmethod
    def get_methods(cls):
        return ["GET"]

    async def process(self, input: dict, request: Request) -> dict | Response:
        current_path = request.args.get("path", "")
        if current_path == "$WORK_DIR":
            # if runtime.is_development():
            #     current_path = "work_dir"
            # else:
            #     current_path = "root"
            from python.helpers.constants import Paths

            current_path = Paths.WORK_DIR

        # browser = FileBrowser()
        # result = browser.get_files(current_path)
        result = await runtime.call_development_function(get_files, current_path)

        return {"data": result}


async def get_files(path):
    browser = FileBrowser()
    return browser.get_files(path)
