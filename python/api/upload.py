"""File upload endpoint.

Handles file uploads to the agent's working directory.
Supports multiple files in a single request via multipart/form-data.
"""

from werkzeug.utils import secure_filename

from python.helpers import files
from python.helpers.api import ApiHandler, Request, Response
from python.helpers.constants import Paths


class UploadFile(ApiHandler):
    # SECURITY: Whitelist of allowed file extensions
    # Blocks dangerous extensions that could lead to RCE
    ALLOWED_EXTENSIONS = {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "webp",  # Images
        "pdf",  # Documents
        "txt",
        "md",
        "csv",
        "json",
        "xml",
        "yaml",
        "yml",  # Text/Config
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",  # Office
    }

    # SECURITY: Whitelist of allowed MIME type prefixes
    ALLOWED_MIME_PREFIXES = {
        "image/",  # All image types
        "application/pdf",
        "text/",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/json",
        "application/xml",
    }

    async def process(self, input: dict, request: Request) -> dict | Response:
        if "file" not in request.files:
            raise ValueError("No file part")

        file_list = request.files.getlist("file")  # Handle multiple files
        saved_filenames = []
        errors = []

        for file in file_list:
            filename = file.filename if file.filename else ""
            # SECURITY: Validate file extension first
            if not self.allowed_file(filename):
                errors.append(f"File type not allowed: {filename}")
                continue
            # SECURITY: Validate MIME type for extra protection
            if not self.validate_mime_type(file):
                errors.append(f"Invalid MIME type: {filename}")
                continue
            # Save with sanitized filename
            filename = secure_filename(filename)  # type: ignore
            file.save(files.get_abs_path(Paths.UPLOAD_DIR, filename))
            saved_filenames.append(filename)

        if not saved_filenames and errors:
            raise ValueError("; ".join(errors))

        return {"filenames": saved_filenames}  # Return saved filenames

    def allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed.

        SECURITY: Blocks dangerous extensions to prevent RCE.
        """
        if not filename or "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower()
        return ext in self.ALLOWED_EXTENSIONS

    def validate_mime_type(self, file) -> bool:
        """Validate file's MIME type from Content-Type header.

        SECURITY: Uses Content-Type header to validate file type.
        """
        try:
            mime_type = file.content_type
            if not mime_type:
                return False
            # Check if MIME type starts with any allowed prefix
            return any(mime_type.startswith(prefix) for prefix in self.ALLOWED_MIME_PREFIXES)
        except AttributeError:
            return False
