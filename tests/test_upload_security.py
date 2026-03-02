"""Tests for upload.py security validation.

These tests verify the file upload security fixes:
- Extension whitelist enforcement
- MIME type validation
- Blocking dangerous file types (.php, .py, .exe, etc.)
"""

import unittest
from unittest.mock import MagicMock, Mock

from python.api.upload import UploadFile


class TestUploadFileAllowedFile(unittest.TestCase):
    """Test cases for UploadFile.allowed_file() security validation."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock Flask app and thread_lock
        mock_app = Mock()
        mock_thread_lock = MagicMock()
        self.handler = UploadFile(mock_app, mock_thread_lock)

    # Tests for allowed extensions (should pass)

    def test_allowed_file_images(self):
        """Test allowed image extensions."""
        self.assertTrue(self.handler.allowed_file("photo.jpg"))
        self.assertTrue(self.handler.allowed_file("photo.jpeg"))
        self.assertTrue(self.handler.allowed_file("photo.png"))
        self.assertTrue(self.handler.allowed_file("photo.gif"))
        self.assertTrue(self.handler.allowed_file("photo.bmp"))
        self.assertTrue(self.handler.allowed_file("photo.webp"))

    def test_allowed_file_documents(self):
        """Test allowed document extensions."""
        self.assertTrue(self.handler.allowed_file("doc.pdf"))
        self.assertTrue(self.handler.allowed_file("doc.txt"))
        self.assertTrue(self.handler.allowed_file("doc.md"))
        self.assertTrue(self.handler.allowed_file("data.csv"))
        self.assertTrue(self.handler.allowed_file("config.json"))
        self.assertTrue(self.handler.allowed_file("config.xml"))
        self.assertTrue(self.handler.allowed_file("config.yaml"))
        self.assertTrue(self.handler.allowed_file("config.yml"))

    def test_allowed_file_office(self):
        """Test allowed office document extensions."""
        self.assertTrue(self.handler.allowed_file("doc.doc"))
        self.assertTrue(self.handler.allowed_file("doc.docx"))
        self.assertTrue(self.handler.allowed_file("spreadsheet.xls"))
        self.assertTrue(self.handler.allowed_file("spreadsheet.xlsx"))
        self.assertTrue(self.handler.allowed_file("presentation.ppt"))
        self.assertTrue(self.handler.allowed_file("presentation.pptx"))

    # Tests for disallowed extensions (should fail - SECURITY)

    def test_allowed_file_disallowed_extensions(self):
        """Test disallowed dangerous extensions are blocked."""
        # Executables
        self.assertFalse(self.handler.allowed_file("malware.exe"))
        self.assertFalse(self.handler.allowed_file("malware.dll"))
        self.assertFalse(self.handler.allowed_file("malware.so"))
        self.assertFalse(self.handler.allowed_file("malware.bin"))

        # Web shells
        self.assertFalse(self.handler.allowed_file("shell.php"))
        self.assertFalse(self.handler.allowed_file("shell.jsp"))
        self.assertFalse(self.handler.allowed_file("shell.asp"))
        self.assertFalse(self.handler.allowed_file("shell.aspx"))

        # Scripts
        self.assertFalse(self.handler.allowed_file("script.py"))
        self.assertFalse(self.handler.allowed_file("script.pyw"))
        self.assertFalse(self.handler.allowed_file("script.js"))
        self.assertFalse(self.handler.allowed_file("script.sh"))
        self.assertFalse(self.handler.allowed_file("script.bat"))
        self.assertFalse(self.handler.allowed_file("script.ps1"))

        # Other dangerous
        self.assertFalse(self.handler.allowed_file("file.html"))
        self.assertFalse(self.handler.allowed_file("file.htm"))
        self.assertFalse(self.handler.allowed_file("file.svelte"))
        self.assertFalse(self.handler.allowed_file("file.vue"))

    def test_allowed_file_case_insensitive(self):
        """Test extension validation is case insensitive."""
        self.assertTrue(self.handler.allowed_file("image.JPG"))
        self.assertTrue(self.handler.allowed_file("image.PNG"))
        self.assertTrue(self.handler.allowed_file("doc.PDF"))
        self.assertFalse(self.handler.allowed_file("shell.PHP"))

    def test_allowed_file_no_extension(self):
        """Test file with no extension is blocked."""
        self.assertFalse(self.handler.allowed_file("filename"))
        self.assertFalse(self.handler.allowed_file(""))

    def test_allowed_file_only_extension(self):
        """Test file that is only extension is blocked."""
        self.assertFalse(self.handler.allowed_file(".pdf"))
        self.assertFalse(self.handler.allowed_file(".jpg"))


class TestUploadFileMimeType(unittest.TestCase):
    """Test cases for UploadFile.validate_mime_type() security validation."""

    def setUp(self):
        """Set up test fixtures."""
        mock_app = Mock()
        mock_thread_lock = MagicMock()
        self.handler = UploadFile(mock_app, mock_thread_lock)

    def test_validate_mime_type_image(self):
        """Test allowed image MIME types."""
        mock_file = MagicMock()
        mock_file.content_type = "image/jpeg"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

        mock_file.content_type = "image/png"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

        mock_file.content_type = "image/gif"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_pdf(self):
        """Test allowed PDF MIME type."""
        mock_file = MagicMock()
        mock_file.content_type = "application/pdf"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_text(self):
        """Test allowed text MIME types."""
        mock_file = MagicMock()
        mock_file.content_type = "text/plain"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

        mock_file.content_type = "text/html"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

        mock_file.content_type = "text/csv"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_application(self):
        """Test allowed application MIME types."""
        mock_file = MagicMock()
        mock_file.content_type = "application/json"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

        mock_file.content_type = "application/msword"
        self.assertTrue(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_not_allowed(self):
        """Test disallowed MIME types are blocked."""
        mock_file = MagicMock()

        # Executables
        mock_file.content_type = "application/x-executable"
        self.assertFalse(self.handler.validate_mime_type(mock_file))

        # Java
        mock_file.content_type = "application/x-java-applet"
        self.assertFalse(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_no_content_type(self):
        """Test file without content_type is blocked."""
        mock_file = MagicMock(spec=[])  # No content_type
        self.assertFalse(self.handler.validate_mime_type(mock_file))

    def test_validate_mime_type_empty_content_type(self):
        """Test file with empty content_type is blocked."""
        mock_file = MagicMock()
        mock_file.content_type = ""
        self.assertFalse(self.handler.validate_mime_type(mock_file))


if __name__ == "__main__":
    unittest.main()
