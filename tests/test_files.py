"""Tests for python.helpers.files utility functions.

Tests pure functions that don't require file system setup:
- remove_code_fences
- is_full_json_template
- basename
- dirname
- safe_file_name
"""
import pytest

from python.helpers.files import (
    basename,
    dirname,
    is_full_json_template,
    remove_code_fences,
    safe_file_name,
)


class TestRemoveCodeFences:
    """Test remove_code_fences function - removes markdown/tilde code fences"""

    def test_no_fences(self):
        """Test text without code fences returns unchanged"""
        text = "Hello, this is plain text without any code fences."
        result = remove_code_fences(text)
        assert result == text

    def test_single_line_fence(self):
        """Test single-line code fence removal"""
        text = "```python\nprint('hello')\n```"
        result = remove_code_fences(text)
        assert result == "print('hello')\n"

    def test_triple_backticks_fence(self):
        """Test triple backticks code fence"""
        text = "```json\n{\"key\": \"value\"}\n```"
        result = remove_code_fences(text)
        assert result == '{"key": "value"}\n'

    def test_tilde_fence(self):
        """Test tilde fence removal"""
        text = "~~~\nSome code\n~~~"
        result = remove_code_fences(text)
        assert result == "Some code\n"

    def test_fence_with_language(self):
        """Test fence with language specifier"""
        text = "```javascript\nconst x = 1;\n```"
        result = remove_code_fences(text)
        assert result == "const x = 1;\n"

    def test_multiple_fences(self):
        """Test text with multiple code fences"""
        text = "Before\n```python\nprint(1)\n```\nMiddle\n```python\nprint(2)\n```\nAfter"
        result = remove_code_fences(text)
        assert "print(1)" in result
        assert "print(2)" in result

    def test_empty_fence(self):
        """Test empty code fence"""
        text = "```\n```"
        result = remove_code_fences(text)
        assert result == ""

    def test_nested_fences(self):
        """Test fence with nested backticks in code"""
        text = "```python\nx = `template`\n```"
        result = remove_code_fences(text)
        assert result == "x = `template`\n"


class TestIsFullJsonTemplate:
    """Test is_full_json_template function - checks if text is full JSON template"""

    def test_json_fence(self):
        """Test text enclosed in json code fence"""
        text = "```json\n{\"key\": \"value\"}\n```"
        result = is_full_json_template(text)
        assert result is True

    def test_tilde_json_fence(self):
        """Test text enclosed in tilde json fence"""
        text = "~~~json\n{\"key\": \"value\"}\n~~~"
        result = is_full_json_template(text)
        assert result is True

    def test_no_fence(self):
        """Test plain JSON without fence returns False"""
        text = '{"key": "value"}'
        result = is_full_json_template(text)
        assert result is False

    def test_with_whitespace(self):
        """Test JSON fence with extra whitespace"""
        text = "  ```json\n{\"key\": \"value\"}\n```  "
        result = is_full_json_template(text)
        assert result is True

    def test_incomplete_fence(self):
        """Test incomplete fence returns False"""
        text = "```json\n{\"key\": \"value\"}"
        result = is_full_json_template(text)
        assert result is False

    def test_empty_json(self):
        """Test empty JSON in fence"""
        text = "```json\n{}\n```"
        result = is_full_json_template(text)
        assert result is True

    def test_nested_json(self):
        """Test nested JSON in fence"""
        text = "```json\n{\"outer\": {\"inner\": 1}}\n```"
        result = is_full_json_template(text)
        assert result is True

    def test_json_array(self):
        """Test JSON array in fence"""
        text = "```json\n[1, 2, 3]\n```"
        result = is_full_json_template(text)
        assert result is True


class TestBasename:
    """Test basename function - extracts filename from path"""

    def test_simple_path(self):
        """Test basic path basename"""
        result = basename("/path/to/file.txt")
        assert result == "file.txt"

    def test_with_suffix(self):
        """Test basename with suffix removal"""
        result = basename("/path/to/file.txt", suffix=".txt")
        assert result == "file"

    def test_no_extension(self):
        """Test basename of file without extension"""
        result = basename("/path/to/README")
        assert result == "README"

    def test_only_filename(self):
        """Test basename when only filename provided"""
        result = basename("file.txt")
        assert result == "file.txt"

    def test_multiple_dots(self):
        """Test basename with multiple dots in filename"""
        result = basename("/path/to/file.name.txt", suffix=".txt")
        assert result == "file.name"

    def test_empty_suffix(self):
        """Test with empty suffix returns full basename"""
        result = basename("/path/to/file.txt", suffix="")
        assert result == "file.txt"


class TestDirname:
    """Test dirname function - extracts directory from path"""

    def test_simple_path(self):
        """Test basic path dirname"""
        result = dirname("/path/to/file.txt")
        assert result == "/path/to"

    def test_deeply_nested(self):
        """Test deeply nested path"""
        result = dirname("/a/b/c/d/file.txt")
        assert result == "/a/b/c/d"

    def test_only_filename(self):
        """Test dirname of filename only returns empty string"""
        result = dirname("file.txt")
        assert result == ""

    def test_root_file(self):
        """Test dirname of file in root"""
        result = dirname("/file.txt")
        assert result == "/"


class TestSafeFileName:
    """Test safe_file_name function - sanitizes filenames"""

    def test_alphanumeric(self):
        """Test alphanumeric characters preserved"""
        result = safe_file_name("file123.txt")
        assert result == "file123.txt"

    def test_special_chars_replaced(self):
        """Test special characters replaced with underscore"""
        result = safe_file_name("file@name#1.txt")
        assert result == "file_name_1.txt"

    def test_spaces_replaced(self):
        """Test spaces replaced with underscore"""
        result = safe_file_name("my file name.txt")
        assert result == "my_file_name.txt"

    def test_allowed_chars_preserved(self):
        """Test allowed special chars (dash, underscore, dot) preserved"""
        result = safe_file_name("file-name_1.2.txt")
        assert result == "file-name_1.2.txt"

    def test_only_special_chars(self):
        """Test filename with only special chars"""
        result = safe_file_name("@#$%")
        assert result == "____"

    def test_unicode_replaced(self):
        """Test unicode characters get replaced by underscore"""
        result = safe_file_name("файл.txt")
        assert result == "____.txt"

    def test_mixed(self):
        """Test mixed allowed and disallowed characters"""
        result = safe_file_name("my file@name.txt")
        assert result == "my_file_name.txt"
