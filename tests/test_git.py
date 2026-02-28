"""Tests for git module - Git repository information utilities."""

import pytest
from unittest.mock import MagicMock, patch

from python.helpers import git


class TestGetGitInfo:
    """Tests for get_git_info function"""

    @patch("python.helpers.git.Repo")
    def test_get_git_info_returns_dict(self, mock_repo_class):
        """Test that get_git_info returns a dictionary"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert isinstance(result, dict)

    @patch("python.helpers.git.Repo")
    def test_get_git_info_has_branch_key(self, mock_repo_class):
        """Test that result contains branch key"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert "branch" in result

    @patch("python.helpers.git.Repo")
    def test_get_git_info_has_commit_hash_key(self, mock_repo_class):
        """Test that result contains commit_hash key"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert "commit_hash" in result

    @patch("python.helpers.git.Repo")
    def test_get_git_info_has_commit_time_key(self, mock_repo_class):
        """Test that result contains commit_time key"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert "commit_time" in result

    @patch("python.helpers.git.Repo")
    def test_get_git_info_has_tag_key(self, mock_repo_class):
        """Test that result contains tag key"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert "tag" in result

    @patch("python.helpers.git.Repo")
    def test_get_git_info_has_version_key(self, mock_repo_class):
        """Test that result contains version key"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_git_info()
        assert "version" in result

    @patch("python.helpers.git.Repo")
    def test_bare_repository_raises_error(self, mock_repo_class):
        """Test that bare repository raises ValueError"""
        mock_repo = MagicMock()
        mock_repo.bare = True
        mock_repo_class.return_value = mock_repo
        
        with pytest.raises(ValueError, match="bare"):
            git.get_git_info()


class TestGetVersion:
    """Tests for get_version function"""

    @patch("python.helpers.git.Repo")
    def test_get_version_returns_string(self, mock_repo_class):
        """Test that get_version returns a string"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_version()
        assert isinstance(result, str)

    @patch("python.helpers.git.Repo")
    def test_get_version_not_empty(self, mock_repo_class):
        """Test that get_version returns a non-empty string"""
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo.active_branch.name = "main"
        mock_repo.head.is_detached = False
        mock_repo.head.commit.hexsha = "a" * 40
        mock_repo.head.commit.committed_date = 1704067200
        mock_repo.git.describe.return_value = "v1.0.0"
        mock_repo_class.return_value = mock_repo
        
        result = git.get_version()
        assert len(result) > 0

    def test_get_version_returns_unknown_on_error(self):
        """Test that get_version returns 'unknown' on error"""
        with patch("python.helpers.git.get_git_info", side_effect=Exception("Test error")):
            result = git.get_version()
            assert result == "unknown"
