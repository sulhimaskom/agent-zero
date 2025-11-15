#!/usr/bin/env python3
"""
Simple security test for file upload functionality.
Tests the allowed_file method without requiring full Flask setup.
"""

import os
import sys
import tempfile
from unittest.mock import Mock

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock the dependencies that aren't available in test environment
class MockApiHandler:
    pass

class MockRequest:
    pass

class MockResponse:
    pass

# Mock the imports
sys.modules['python.helpers.api'] = Mock()
sys.modules['python.helpers.api'].ApiHandler = MockApiHandler
sys.modules['python.helpers.api'].Request = MockRequest
sys.modules['python.helpers.api'].Response = MockResponse
sys.modules['python.helpers.files'] = Mock()
sys.modules['werkzeug.utils'] = Mock()
sys.modules['werkzeug.utils'].secure_filename = lambda x: x

# Now import the upload module
from python.api.upload import UploadFile


def create_mock_file(filename, content_size=1024):
    """Create a mock file object for testing."""
    mock_file = Mock()
    mock_file.filename = filename
    
    # Mock file operations
    mock_file.seek = Mock(side_effect=lambda pos, whence=0: None)
    mock_file.tell = Mock(return_value=content_size)
    mock_file.save = Mock()
    
    return mock_file


def test_allowed_extensions():
    """Test that allowed file extensions are accepted."""
    print("Testing allowed file extensions...")
    upload_handler = UploadFile()
    
    allowed_extensions = ['test.png', 'test.jpg', 'test.jpeg', 'test.txt', 
                        'test.pdf', 'test.csv', 'test.html', 'test.json', 'test.md']
    
    for filename in allowed_extensions:
        mock_file = create_mock_file(filename)
        result = upload_handler.allowed_file(mock_file)
        assert result == True, f"FAIL: {filename} should be allowed"
        print(f"✓ {filename} allowed")
    
    print("All allowed extensions test passed!\n")


def test_blocked_extensions():
    """Test that dangerous file extensions are blocked."""
    print("Testing blocked file extensions...")
    upload_handler = UploadFile()
    
    dangerous_extensions = [
        'test.exe', 'test.sh', 'test.bat', 'test.cmd', 'test.com',
        'test.scr', 'test.pif', 'test.vbs', 'test.js', 'test.php',
        'test.py', 'test.pl', 'test.rb', 'test.jar', 'test.app'
    ]
    
    for filename in dangerous_extensions:
        mock_file = create_mock_file(filename)
        result = upload_handler.allowed_file(mock_file)
        assert result == False, f"FAIL: {filename} should be blocked"
        print(f"✓ {filename} blocked")
    
    print("All blocked extensions test passed!\n")


def test_file_size_limits():
    """Test file size validation."""
    print("Testing file size limits...")
    upload_handler = UploadFile()
    
    # Test large file (should be blocked)
    large_file = create_mock_file('test.txt', content_size=11 * 1024 * 1024)
    result = upload_handler.allowed_file(large_file)
    assert result == False, "FAIL: Large files should be blocked"
    print("✓ Large file (11MB) blocked")
    
    # Test small file (should be allowed)
    small_file = create_mock_file('test.txt', content_size=1024)
    result = upload_handler.allowed_file(small_file)
    assert result == True, "FAIL: Small files should be allowed"
    print("✓ Small file (1KB) allowed")
    
    print("File size limits test passed!\n")


def test_edge_cases():
    """Test edge cases and error conditions."""
    print("Testing edge cases...")
    upload_handler = UploadFile()
    
    # Test None file
    result = upload_handler.allowed_file(None)
    assert result == False, "FAIL: None file should be blocked"
    print("✓ None file blocked")
    
    # Test empty filename
    mock_file = Mock()
    mock_file.filename = ""
    result = upload_handler.allowed_file(mock_file)
    assert result == False, "FAIL: Empty filename should be blocked"
    print("✓ Empty filename blocked")
    
    # Test no filename attribute
    mock_file = Mock()
    del mock_file.filename
    result = upload_handler.allowed_file(mock_file)
    assert result == False, "FAIL: Missing filename attribute should be blocked"
    print("✓ Missing filename attribute blocked")
    
    print("Edge cases test passed!\n")


def test_case_sensitivity():
    """Test case-insensitive extension handling."""
    print("Testing case sensitivity...")
    upload_handler = UploadFile()
    
    case_variations = ['test.PNG', 'test.JPG', 'test.JPEG', 'test.TXT', 
                      'test.PDF', 'test.CSV', 'test.HTML', 'test.JSON', 'test.MD']
    
    for filename in case_variations:
        mock_file = create_mock_file(filename)
        result = upload_handler.allowed_file(mock_file)
        assert result == True, f"FAIL: {filename} should be allowed (case-insensitive)"
        print(f"✓ {filename} allowed")
    
    print("Case sensitivity test passed!\n")


def test_configuration():
    """Test configuration constants."""
    print("Testing configuration...")
    upload_handler = UploadFile()
    
    # Check allowed extensions
    assert 'txt' in upload_handler.ALLOWED_EXTENSIONS, "FAIL: txt should be allowed"
    assert 'png' in upload_handler.ALLOWED_EXTENSIONS, "FAIL: png should be allowed"
    assert 'exe' not in upload_handler.ALLOWED_EXTENSIONS, "FAIL: exe should not be allowed"
    assert 'sh' not in upload_handler.ALLOWED_EXTENSIONS, "FAIL: sh should not be allowed"
    print("✓ Extension whitelist correct")
    
    # Check file size limit
    assert upload_handler.MAX_FILE_SIZE == 10 * 1024 * 1024, "FAIL: File size limit incorrect"
    print("✓ File size limit correct (10MB)")
    
    # Check MIME types
    assert 'text/plain' in upload_handler.ALLOWED_MIME_TYPES, "FAIL: text/plain MIME type missing"
    assert 'image/png' in upload_handler.ALLOWED_MIME_TYPES, "FAIL: image/png MIME type missing"
    print("✓ MIME type mapping correct")
    
    print("Configuration test passed!\n")


def main():
    """Run all security tests."""
    print("=" * 60)
    print("FILE UPLOAD SECURITY TESTS")
    print("=" * 60)
    print()
    
    try:
        test_allowed_extensions()
        test_blocked_extensions()
        test_file_size_limits()
        test_edge_cases()
        test_case_sensitivity()
        test_configuration()
        
        print("=" * 60)
        print("🎉 ALL SECURITY TESTS PASSED!")
        print("File upload security is working correctly.")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"❌ SECURITY TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())