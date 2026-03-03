"""Tests for python.helpers.backup utility functions.

Tests pure functions that don't require file system or async operations:
- _parse_patterns
- _patterns_to_string
- _get_explicit_patterns
- _is_explicitly_included
- _translate_patterns
- _count_directories
- _resolve_path / _unresolve_path
"""

import pytest

# Mock the pathspec module before importing BackupService
# The pathspec import has compatibility issues with newer versions
import sys
from unittest.mock import MagicMock, patch

# Create mock pathspec module
mock_pathspec = MagicMock()
sys.modules['pathspec'] = mock_pathspec
sys.modules['pathspec.patterns'] = MagicMock()
sys.modules['pathspec.patterns.gitwildmatch'] = MagicMock()

from python.helpers.backup import BackupService


class TestParsePatterns:
    """Test _parse_patterns function - parses patterns string into include/exclude arrays."""

    def test_empty_string(self):
        """Test empty patterns string returns empty lists"""
        service = BackupService()
        include, exclude = service._parse_patterns("")
        assert include == []
        assert exclude == []

    def test_only_comments(self):
        """Test comment-only patterns returns empty lists"""
        service = BackupService()
        include, exclude = service._parse_patterns("# Comment line\n# Another comment")
        assert include == []
        assert exclude == []

    def test_single_include_pattern(self):
        """Test single include pattern"""
        service = BackupService()
        include, exclude = service._parse_patterns("/path/to/file")
        assert include == ["/path/to/file"]
        assert exclude == []

    def test_single_exclude_pattern(self):
        """Test single exclude pattern"""
        service = BackupService()
        include, exclude = service._parse_patterns("!/path/to/exclude")
        assert include == []
        assert exclude == ["/path/to/exclude"]

    def test_mixed_include_exclude(self):
        """Test mixed include and exclude patterns"""
        service = BackupService()
        patterns = """/path/to/include1
/path/to/include2
!/path/to/exclude1
!/path/to/exclude2
"""
        include, exclude = service._parse_patterns(patterns)
        assert include == ["/path/to/include1", "/path/to/include2"]
        assert exclude == ["/path/to/exclude1", "/path/to/exclude2"]

    def test_strips_whitespace(self):
        """Test whitespace is stripped from patterns"""
        service = BackupService()
        patterns = "  /path/to/file1  \n  !/path/to/exclude  "
        include, exclude = service._parse_patterns(patterns)
        assert include == ["/path/to/file1"]
        assert exclude == ["/path/to/exclude"]  # Fixed: removed extra =

    def test_exclamation_only_not_exclude(self):
        """Test pattern starting with ! that's just ! becomes empty string"""
        # Empty pattern after ! is included as empty string in exclude
        service = BackupService()
        include, exclude = service._parse_patterns("!")
        assert include == []
        assert exclude == [""]  # Empty pattern after !


class TestPatternsToString:
    """Test _patterns_to_string function - converts patterns arrays back to string."""

    def test_empty_lists(self):
        """Test empty pattern lists returns empty string"""
        service = BackupService()
        result = service._patterns_to_string([], [])
        assert result == ""

    def test_only_include_patterns(self):
        """Test include patterns only"""
        service = BackupService()
        result = service._patterns_to_string(["/path/one", "/path/two"], [])
        assert "/path/one" in result
        assert "/path/two" in result
        assert "!" not in result

    def test_only_exclude_patterns(self):
        """Test exclude patterns only"""
        service = BackupService()
        result = service._patterns_to_string([], ["/exclude/one", "/exclude/two"])
        assert "!/exclude/one" in result
        assert "!/exclude/two" in result

    def test_mixed_patterns(self):
        """Test mixed include and exclude patterns"""
        service = BackupService()
        result = service._patterns_to_string(
            ["/include/one", "/include/two"],
            ["/exclude/one"]
        )
        assert "/include/one" in result
        assert "/include/two" in result
        assert "!/exclude/one" in result


class TestGetExplicitPatterns:
    """Test _get_explicit_patterns function - extracts non-wildcard patterns."""

    def test_empty_list(self):
        """Test empty patterns returns empty set"""
        service = BackupService()
        result = service._get_explicit_patterns([])
        assert result == set()

    def test_no_wildcards(self):
        """Test patterns without wildcards are explicit"""
        service = BackupService()
        result = service._get_explicit_patterns(["/path/to/file", "/another/path"])
        # Note: leading slash is stripped
        assert "path/to/file" in result
        assert "another/path" in result

    def test_with_wildcards(self):
        """Test wildcard patterns are NOT added as explicit"""
        service = BackupService()
        result = service._get_explicit_patterns(["/path/**", "/file*.txt"])
        # Wildcard patterns are explicitly skipped (they have * or ?)
        # So neither the wildcard patterns nor their parents are added
        assert "path" not in result
        assert "path/**" not in result
        assert "file*.txt" not in result

    def test_parent_directories_added(self):
        """Test parent directories are added for hidden file traversal"""
        service = BackupService()
        result = service._get_explicit_patterns(["/home/user/.config/app"])
        # Should include the path itself and all parent directories (without leading slash)
        assert "home/user/.config/app" in result
        assert "home/user/.config" in result
        assert "home/user" in result
        assert "home" in result


class TestIsExplicitlyIncluded:
    """Test _is_explicitly_included function - checks if file is in explicit patterns."""

    def test_explicit_file(self):
        """Test file that matches explicit pattern"""
        service = BackupService()
        explicit = {"path/to/file", "path/to"}  # Note: no leading slash
        result = service._is_explicitly_included("/path/to/file", explicit)
        assert result is True

    def test_non_explicit_file(self):
        """Test file that doesn't match explicit pattern"""
        service = BackupService()
        explicit = {"path/to/other"}  # Note: no leading slash
        result = service._is_explicitly_included("/path/to/file", explicit)
        assert result is False

    def test_directory_traversal(self):
        """Test exact directory match works for traversal"""
        service = BackupService()
        explicit = {"path/to", "path"}  # Note: no leading slash - exact directory matches
        # _is_explicitly_included does exact match, not prefix match
        # So this tests if the exact directory is in explicit patterns
        # The file path is /path/to/file, after strip becomes path/to/file
        # It's not equal to path/to, so it's False
        # This test documents the current behavior (exact match)
        result = service._is_explicitly_included("/path/to/file", explicit)
        assert result is False  # Exact match only, not prefix match

    def test_leading_slash_handling(self):
        """Test leading slash is handled correctly"""
        service = BackupService()
        explicit = {"path/to/file"}  # Note: no leading slash
        # Without leading slash input - should work because _is_explicitly_included strips it
        result = service._is_explicitly_included("path/to/file", explicit)
        assert result is True


class TestTranslatePatterns:
    """Test _translate_patterns function - translates patterns between systems."""

    def test_empty_patterns(self):
        """Test empty patterns returns empty list"""
        service = BackupService()
        result = service._translate_patterns([], {})
        assert result == []

    def test_no_matching_root(self):
        """Test patterns without matching backed up root stay unchanged"""
        service = BackupService()
        patterns = ["/some/other/path", "/another/path"]
        result = service._translate_patterns(patterns, {"environment_info": {}})
        assert result == patterns

    def test_translate_with_matching_root(self):
        """Test patterns are translated when backed up root matches"""
        service = BackupService()
        patterns = ["/old/root/path/file1", "/old/root/path/file2"]
        metadata = {
            "environment_info": {
                "agent_zero_root": "/old/root/path"
            }
        }
        # We can't fully test this without setting agent_zero_root on service
        # But the function logic can be tested
        result = service._translate_patterns(patterns, metadata)
        assert len(result) == 2

    def test_no_environment_info(self):
        """Test patterns without environment info stay unchanged"""
        service = BackupService()
        patterns = ["/path/to/file"]
        result = service._translate_patterns(patterns, {})
        assert result == patterns


class TestCountDirectories:
    """Test _count_directories function - counts unique directories."""

    def test_empty_list(self):
        """Test empty file list returns 0"""
        service = BackupService()
        result = service._count_directories([])
        assert result == 0

    def test_single_file(self):
        """Test single file returns 1 directory"""
        service = BackupService()
        files = [{"path": "/path/to/file.txt"}]
        result = service._count_directories(files)
        assert result == 1

    def test_multiple_files_same_dir(self):
        """Test multiple files in same directory returns 1"""
        service = BackupService()
        files = [
            {"path": "/path/to/file1.txt"},
            {"path": "/path/to/file2.txt"},
        ]
        result = service._count_directories(files)
        assert result == 1

    def test_multiple_files_different_dirs(self):
        """Test files in different directories counts each unique directory"""
        service = BackupService()
        files = [
            {"path": "/path/one/file1.txt"},
            {"path": "/path/two/file2.txt"},
            {"path": "/path/three/file3.txt"},
        ]
        result = service._count_directories(files)
        assert result == 3

    def test_nested_directories(self):
        """Test nested directories are counted correctly"""
        service = BackupService()
        files = [
            {"path": "/a/b/c/file1.txt"},
            {"path": "/a/b/file2.txt"},
            {"path": "/a/file3.txt"},
        ]
        result = service._count_directories(files)
        assert result == 3  # /a/b/c, /a/b, /a

    def test_file_without_directory(self):
        """Test file without directory path returns 0"""
        service = BackupService()
        files = [{"path": "filename.txt"}]  # No directory
        result = service._count_directories(files)
        assert result == 0


class TestPathResolution:
    """Test path resolution and unresolution functions."""

    def test_resolve_path_returns_unchanged(self):
        """Test _resolve_path returns path unchanged"""
        service = BackupService()
        result = service._resolve_path("/some/path")
        assert result == "/some/path"

    def test_unresolve_path_returns_unchanged(self):
        """Test _unresolve_path returns path unchanged"""
        service = BackupService()
        result = service._unresolve_path("/some/path")
        assert result == "/some/path"
