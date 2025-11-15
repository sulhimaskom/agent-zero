import os
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.api.upload import UploadFile


class TestUploadFileSecurity(unittest.TestCase):
    """Test suite for file upload security validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.upload_handler = UploadFile()
    
    def create_mock_file(self, filename, content_size=1024, content_type=None):
        """Create a mock file object for testing."""
        mock_file = Mock()
        mock_file.filename = filename
        mock_file.content_type = content_type
        
        # Create mock content
        content = b'A' * content_size
        
        # Mock file operations
        mock_file.seek = Mock(side_effect=lambda pos, whence=0: None)
        mock_file.tell = Mock(return_value=content_size)
        mock_file.save = Mock()
        
        return mock_file
    
    def test_allowed_file_extensions(self):
        """Test that allowed file extensions are accepted."""
        allowed_extensions = ['test.png', 'test.jpg', 'test.jpeg', 'test.txt', 
                            'test.pdf', 'test.csv', 'test.html', 'test.json', 'test.md']
        
        for filename in allowed_extensions:
            mock_file = self.create_mock_file(filename)
            self.assertTrue(self.upload_handler.allowed_file(mock_file), 
                          f"File {filename} should be allowed")
    
    def test_blocked_file_extensions(self):
        """Test that dangerous file extensions are blocked."""
        dangerous_extensions = [
            'test.exe', 'test.sh', 'test.bat', 'test.cmd', 'test.com',
            'test.scr', 'test.pif', 'test.vbs', 'test.js', 'test.php',
            'test.py', 'test.pl', 'test.rb', 'test.jar', 'test.app',
            'test.deb', 'test.rpm', 'test.dmg', 'test.iso', 'test.bin'
        ]
        
        for filename in dangerous_extensions:
            mock_file = self.create_mock_file(filename)
            self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                           f"File {filename} should be blocked")
    
    def test_file_size_limit(self):
        """Test that files exceeding size limit are blocked."""
        # Create a file larger than 10MB
        large_file = self.create_mock_file('test.txt', content_size=11 * 1024 * 1024)
        self.assertFalse(self.upload_handler.allowed_file(large_file), 
                        "Large files should be blocked")
        
        # Create a file within size limit
        small_file = self.create_mock_file('test.txt', content_size=1024)
        self.assertTrue(self.upload_handler.allowed_file(small_file), 
                       "Small files should be allowed")
    
    def test_empty_filename(self):
        """Test that files with empty or None filenames are blocked."""
        # None filename
        mock_file = Mock()
        mock_file.filename = None
        self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                        "Files with None filename should be blocked")
        
        # Empty filename
        mock_file.filename = ""
        self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                        "Files with empty filename should be blocked")
        
        # No filename attribute
        mock_file = Mock()
        del mock_file.filename
        self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                        "Files without filename attribute should be blocked")
    
    def test_no_file_object(self):
        """Test that None file objects are blocked."""
        self.assertFalse(self.upload_handler.allowed_file(None), 
                        "None file objects should be blocked")
    
    def test_mime_type_validation(self):
        """Test MIME type validation for common file types."""
        # Test PNG files
        png_file = self.create_mock_file('test.png')
        self.assertTrue(self.upload_handler.allowed_file(png_file), 
                       "PNG files should be allowed")
        
        # Test JPEG files
        jpg_file = self.create_mock_file('test.jpg')
        self.assertTrue(self.upload_handler.allowed_file(jpg_file), 
                       "JPG files should be allowed")
        
        # Test text files
        txt_file = self.create_mock_file('test.txt')
        self.assertTrue(self.upload_handler.allowed_file(txt_file), 
                       "TXT files should be allowed")
    
    def test_extension_case_sensitivity(self):
        """Test that file extensions are case-insensitive."""
        case_variations = ['test.PNG', 'test.JPG', 'test.JPEG', 'test.TXT', 
                          'test.PDF', 'test.CSV', 'test.HTML', 'test.JSON', 'test.MD']
        
        for filename in case_variations:
            mock_file = self.create_mock_file(filename)
            self.assertTrue(self.upload_handler.allowed_file(mock_file), 
                          f"File {filename} should be allowed (case-insensitive)")
    
    def test_files_without_extension(self):
        """Test that files without extensions are blocked."""
        no_extension_files = ['test', 'README', 'Makefile', 'config']
        
        for filename in no_extension_files:
            mock_file = self.create_mock_file(filename)
            self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                           f"File {filename} without extension should be blocked")
    
    def test_double_extension_files(self):
        """Test files with double extensions."""
        # Allowed double extensions
        allowed_double = ['test.config.json', 'backup.data.csv']
        for filename in allowed_double:
            mock_file = self.create_mock_file(filename)
            self.assertTrue(self.upload_handler.allowed_file(mock_file), 
                          f"File {filename} should be allowed")
        
        # Dangerous double extensions
        dangerous_double = ['test.jpg.exe', 'image.png.sh', 'document.pdf.bat']
        for filename in dangerous_double:
            mock_file = self.create_mock_file(filename)
            self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                           f"File {filename} should be blocked")
    
    def test_special_characters_in_filename(self):
        """Test filenames with special characters."""
        special_char_files = [
            'test file.txt',  # space
            'test-file.txt',  # hyphen
            'test_file.txt',  # underscore
            'test(1).txt',    # parentheses
            'test[1].txt',    # brackets
            'test@home.txt',  # at symbol
        ]
        
        for filename in special_char_files:
            mock_file = self.create_mock_file(filename)
            self.assertTrue(self.upload_handler.allowed_file(mock_file), 
                          f"File {filename} with special characters should be allowed")
    
    def test_file_operation_errors(self):
        """Test handling of file operation errors."""
        # Create a mock file that raises exceptions on file operations
        mock_file = Mock()
        mock_file.filename = 'test.txt'
        mock_file.seek.side_effect = Exception("File operation failed")
        
        self.assertFalse(self.upload_handler.allowed_file(mock_file), 
                        "Files with operation errors should be blocked")
    
    def test_configuration_constants(self):
        """Test that configuration constants are properly set."""
        # Check that allowed extensions are defined
        self.assertIn('txt', self.upload_handler.ALLOWED_EXTENSIONS)
        self.assertIn('png', self.upload_handler.ALLOWED_EXTENSIONS)
        self.assertIn('jpg', self.upload_handler.ALLOWED_EXTENSIONS)
        
        # Check that dangerous extensions are not allowed
        self.assertNotIn('exe', self.upload_handler.ALLOWED_EXTENSIONS)
        self.assertNotIn('sh', self.upload_handler.ALLOWED_EXTENSIONS)
        self.assertNotIn('bat', self.upload_handler.ALLOWED_EXTENSIONS)
        
        # Check file size limit
        self.assertEqual(self.upload_handler.MAX_FILE_SIZE, 10 * 1024 * 1024)
        
        # Check MIME types mapping
        self.assertIn('text/plain', self.upload_handler.ALLOWED_MIME_TYPES)
        self.assertIn('image/png', self.upload_handler.ALLOWED_MIME_TYPES)


if __name__ == '__main__':
    unittest.main()