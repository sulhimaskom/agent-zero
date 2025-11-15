import os
import mimetypes
from python.helpers.api import ApiHandler, Request, Response
from python.helpers import files
from werkzeug.utils import secure_filename


class UploadFile(ApiHandler):
    # Configuration constants
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "txt", "pdf", "csv", "html", "json", "md"}
    ALLOWED_MIME_TYPES = {
        'image/png': 'png',
        'image/jpeg': 'jpg', 
        'image/jpeg': 'jpeg',
        'text/plain': 'txt',
        'application/pdf': 'pdf',
        'text/csv': 'csv',
        'text/html': 'html',
        'application/json': 'json',
        'text/markdown': 'md'
    }
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    async def process(self, input: dict, request: Request) -> dict | Response:
        if "file" not in request.files:
            raise Exception("No file part")

        file_list = request.files.getlist("file")  # Handle multiple files
        saved_filenames = []

        for file in file_list:
            if file and self.allowed_file(file):  # Check file type
                filename = secure_filename(file.filename) # type: ignore
                file.save(files.get_abs_path("tmp/upload", filename))
                saved_filenames.append(filename)

        return {"filenames": saved_filenames}  # Return saved filenames


    def allowed_file(self, file):
        """
        Validate file type and size to prevent security vulnerabilities.
        
        Args:
            file: File object with filename attribute
            
        Returns:
            bool: True if file is allowed, False otherwise
        """
        # Check if file and filename are provided
        if not file or not hasattr(file, 'filename') or not file.filename:
            return False
            
        filename = file.filename
        
        # Check file extension
        if not ("." in filename and 
                filename.rsplit(".", 1)[1].lower() in self.ALLOWED_EXTENSIONS):
            return False
            
        # Get file extension
        file_extension = filename.rsplit(".", 1)[1].lower()
        
        # Check file size
        try:
            # Reset file pointer to beginning
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()  # Get size
            file.seek(0)  # Reset to beginning
            
            if file_size > self.MAX_FILE_SIZE:
                return False
        except Exception:
            # If we can't check file size, reject the file for security
            return False
            
        # Check MIME type using mimetypes module
        try:
            file_mime, _ = mimetypes.guess_type(filename)
            if file_mime and file_mime in self.ALLOWED_MIME_TYPES:
                expected_extension = self.ALLOWED_MIME_TYPES[file_mime]
                if file_extension != expected_extension and file_extension not in ['jpg', 'jpeg']:
                    # Special case for jpg/jpeg which both map to image/jpeg
                    return False
        except Exception:
            # If MIME type detection fails, still allow if extension is valid
            # This prevents breaking legitimate uploads due to MIME detection issues
            pass
                
        return True