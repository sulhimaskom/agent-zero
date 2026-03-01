"""Tests for attachment_manager.py module."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from python.helpers.attachment_manager import AttachmentManager


class TestAttachmentManager(unittest.TestCase):
    """Test cases for AttachmentManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = AttachmentManager(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    # Tests for is_allowed_file()

    def test_is_allowed_file_jpeg(self):
        """Test allowed JPEG file."""
        self.assertTrue(self.manager.is_allowed_file("image.jpg"))
        self.assertTrue(self.manager.is_allowed_file("image.jpeg"))

    def test_is_allowed_file_png(self):
        """Test allowed PNG file."""
        self.assertTrue(self.manager.is_allowed_file("photo.png"))

    def test_is_allowed_file_bmp(self):
        """Test allowed BMP file."""
        self.assertTrue(self.manager.is_allowed_file("photo.bmp"))

    def test_is_allowed_file_code(self):
        """Test allowed code files."""
        self.assertTrue(self.manager.is_allowed_file("script.py"))
        self.assertTrue(self.manager.is_allowed_file("app.js"))
        self.assertTrue(self.manager.is_allowed_file("run.sh"))
        self.assertTrue(self.manager.is_allowed_file("page.html"))
        self.assertTrue(self.manager.is_allowed_file("style.css"))

    def test_is_allowed_file_document(self):
        """Test allowed document files."""
        self.assertTrue(self.manager.is_allowed_file("readme.md"))
        self.assertTrue(self.manager.is_allowed_file("doc.pdf"))
        self.assertTrue(self.manager.is_allowed_file("data.txt"))
        self.assertTrue(self.manager.is_allowed_file("data.csv"))
        self.assertTrue(self.manager.is_allowed_file("config.json"))

    def test_is_allowed_file_not_allowed(self):
        """Test disallowed file extensions."""
        self.assertFalse(self.manager.is_allowed_file("malicious.exe"))
        self.assertFalse(self.manager.is_allowed_file("script.asp"))
        self.assertFalse(self.manager.is_allowed_file("data.xml"))

    def test_is_allowed_file_no_extension(self):
        """Test file with no extension."""
        self.assertFalse(self.manager.is_allowed_file("filename"))

    # Tests for get_file_type()

    def test_get_file_type_image(self):
        """Test image file type detection."""
        self.assertEqual(self.manager.get_file_type("photo.jpg"), "image")
        self.assertEqual(self.manager.get_file_type("photo.png"), "image")
        self.assertEqual(self.manager.get_file_type("photo.jpeg"), "image")

    def test_get_file_type_code(self):
        """Test code file type detection."""
        self.assertEqual(self.manager.get_file_type("script.py"), "code")
        self.assertEqual(self.manager.get_file_type("app.js"), "code")
        self.assertEqual(self.manager.get_file_type("run.sh"), "code")

    def test_get_file_type_document(self):
        """Test document file type detection."""
        self.assertEqual(self.manager.get_file_type("readme.md"), "document")
        self.assertEqual(self.manager.get_file_type("doc.pdf"), "document")
        self.assertEqual(self.manager.get_file_type("data.txt"), "document")

    def test_get_file_type_unknown(self):
        """Test unknown file type."""
        self.assertEqual(self.manager.get_file_type("file.exe"), "unknown")
        self.assertEqual(self.manager.get_file_type("file"), "unknown")

    # Tests for get_file_extension()

    def test_get_file_extension_jpg(self):
        """Test JPG extension extraction."""
        self.assertEqual(AttachmentManager.get_file_extension("image.jpg"), "jpg")

    def test_get_file_extension_png(self):
        """Test PNG extension extraction."""
        self.assertEqual(AttachmentManager.get_file_extension("photo.png"), "png")

    def test_get_file_extension_uppercase(self):
        """Test uppercase extension is lowercased."""
        self.assertEqual(AttachmentManager.get_file_extension("image.JPG"), "jpg")
        self.assertEqual(AttachmentManager.get_file_extension("image.PNG"), "png")

    def test_get_file_extension_no_extension(self):
        """Test file with no extension returns empty string."""
        self.assertEqual(AttachmentManager.get_file_extension("filename"), "")

    def test_get_file_extension_multiple_dots(self):
        """Test file with multiple dots - should get last extension."""
        self.assertEqual(AttachmentManager.get_file_extension("archive.tar.gz"), "gz")

    # Tests for validate_mime_type()

    def test_validate_mime_type_image(self):
        """Test image MIME type validation."""
        mock_file = MagicMock()
        mock_file.content_type = "image/jpeg"
        self.assertTrue(self.manager.validate_mime_type(mock_file))

    def test_validate_mime_type_text(self):
        """Test text MIME type validation."""
        mock_file = MagicMock()
        mock_file.content_type = "text/plain"
        self.assertTrue(self.manager.validate_mime_type(mock_file))

    def test_validate_mime_type_application(self):
        """Test application MIME type validation."""
        mock_file = MagicMock()
        mock_file.content_type = "application/json"
        self.assertTrue(self.manager.validate_mime_type(mock_file))

    def test_validate_mime_type_not_allowed(self):
        """Test disallowed MIME type."""
        mock_file = MagicMock()
        mock_file.content_type = "video/mp4"
        self.assertFalse(self.manager.validate_mime_type(mock_file))

    def test_validate_mime_type_no_content_type(self):
        """Test file without content_type attribute."""
        mock_file = MagicMock(spec=[])  # No content_type
        self.assertFalse(self.manager.validate_mime_type(mock_file))

    def test_validate_mime_type_empty_content_type(self):
        """Test file with empty content_type."""
        mock_file = MagicMock()
        mock_file.content_type = ""
        self.assertFalse(self.manager.validate_mime_type(mock_file))


class TestAttachmentManagerEdgeCases(unittest.TestCase):
    """Edge case tests for AttachmentManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = AttachmentManager(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_is_allowed_file_uppercase_extension(self):
        """Test uppercase extensions are allowed."""
        self.assertTrue(self.manager.is_allowed_file("image.JPG"))
        self.assertTrue(self.manager.is_allowed_file("script.PY"))

    def test_get_file_type_uppercase_extension(self):
        """Test uppercase extensions return correct type."""
        self.assertEqual(self.manager.get_file_type("image.JPG"), "image")
        self.assertEqual(self.manager.get_file_type("script.PY"), "code")


if __name__ == "__main__":
    unittest.main()
