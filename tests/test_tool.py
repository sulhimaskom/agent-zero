import pytest
from unittest.mock import MagicMock, AsyncMock

from python.helpers.tool import Tool, Response


class TestResponse:
    """Test Response dataclass"""

    def test_response_creation_basic(self):
        """Test creating Response with required fields"""
        response = Response(message="test message", break_loop=False)
        assert response.message == "test message"
        assert response.break_loop is False

    def test_response_creation_with_break_loop_true(self):
        """Test creating Response with break_loop=True"""
        response = Response(message="stop", break_loop=True)
        assert response.message == "stop"
        assert response.break_loop is True

    def test_response_creation_with_additional(self):
        """Test creating Response with additional dict"""
        additional = {"key": "value", "count": 5}
        response = Response(message="data", break_loop=False, additional=additional)
        assert response.additional == additional
        assert response.additional["key"] == "value"

    def test_response_creation_with_none_additional(self):
        """Test creating Response with None additional"""
        response = Response(message="test", break_loop=False, additional=None)
        assert response.additional is None


class TestToolInit:
    """Test Tool initialization"""

    def _create_mock_agent(self):
        """Create a mock agent for testing"""
        agent = MagicMock()
        agent.agent_name = "test_agent"
        return agent

    def _create_mock_loop_data(self):
        """Create a mock LoopData for testing"""
        loop_data = MagicMock()
        return loop_data

    def test_tool_initialization_full(self):
        """Test Tool initialization with all arguments"""
        agent = self._create_mock_agent()
        loop_data = self._create_mock_loop_data()

        tool = Tool(
            agent=agent,
            name="test_tool",
            method="test_method",
            args={"arg1": "value1", "arg2": "value2"},
            message="test message",
            loop_data=loop_data,
        )

        assert tool.agent == agent
        assert tool.name == "test_tool"
        assert tool.method == "test_method"
        assert tool.args == {"arg1": "value1", "arg2": "value2"}
        assert tool.message == "test message"
        assert tool.loop_data == loop_data
        assert tool.progress == ""

    def test_tool_initialization_minimal(self):
        """Test Tool initialization with minimal arguments"""
        agent = self._create_mock_agent()

        tool = Tool(
            agent=agent,
            name="minimal_tool",
            method=None,
            args={},
            message="",
            loop_data=None,
        )

        assert tool.name == "minimal_tool"
        assert tool.method is None
        assert tool.args == {}
        assert tool.message == ""
        assert tool.loop_data is None
        assert tool.progress == ""


class TestToolProgress:
    """Test Tool progress methods"""

    def _create_mock_tool(self):
        """Create a Tool instance with mocked agent"""
        agent = MagicMock()
        agent.agent_name = "test_agent"
        return Tool(
            agent=agent,
            name="test_tool",
            method=None,
            args={},
            message="",
            loop_data=None,
        )

    def test_set_progress_with_content(self):
        """Test set_progress sets the progress string"""
        tool = self._create_mock_tool()
        tool.set_progress("step1")
        assert tool.progress == "step1"

    def test_set_progress_with_none(self):
        """Test set_progress with None clears progress"""
        tool = self._create_mock_tool()
        tool.set_progress("initial")
        tool.set_progress(None)
        assert tool.progress == ""

    def test_set_progress_with_empty_string(self):
        """Test set_progress with empty string"""
        tool = self._create_mock_tool()
        tool.set_progress("initial")
        tool.set_progress("")
        assert tool.progress == ""

    def test_add_progress_with_content(self):
        """Test add_progress appends to progress string"""
        tool = self._create_mock_tool()
        tool.add_progress("step1")
        tool.add_progress("step2")
        assert tool.progress == "step1step2"

    def test_add_progress_with_none(self):
        """Test add_progress with None does nothing"""
        tool = self._create_mock_tool()
        tool.add_progress("step1")
        tool.add_progress(None)
        assert tool.progress == "step1"

    def test_add_progress_with_empty_string(self):
        """Test add_progress with empty string does nothing"""
        tool = self._create_mock_tool()
        tool.add_progress("step1")
        tool.add_progress("")
        assert tool.progress == "step1"

    def test_add_progress_multiple_calls(self):
        """Test add_progress with multiple sequential calls"""
        tool = self._create_mock_tool()
        tool.add_progress("a")
        tool.add_progress("b")
        tool.add_progress("c")
        assert tool.progress == "abc"


class TestToolNiceKey:
    """Test Tool.nice_key() method - converts snake_case to Title Case"""

    def _create_mock_tool(self):
        """Create a Tool instance with mocked agent"""
        agent = MagicMock()
        agent.agent_name = "test_agent"
        return Tool(
            agent=agent,
            name="test_tool",
            method=None,
            args={},
            message="",
            loop_data=None,
        )

    def test_nice_key_single_word(self):
        """Test nice_key with single word"""
        tool = self._create_mock_tool()
        assert tool.nice_key("name") == "Name"

    def test_nice_key_two_words(self):
        """Test nice_key with two words"""
        tool = self._create_mock_tool()
        assert tool.nice_key("file_name") == "File name"

    def test_nice_key_three_words(self):
        """Test nice_key with three words"""
        tool = self._create_mock_tool()
        assert tool.nice_key("user_id_number") == "User id number"

    def test_nice_key_already_capitalized(self):
        """Test nice_key with already capitalized words"""
        tool = self._create_mock_tool()
        assert tool.nice_key("User_Name") == "User name"

    def test_nice_key_all_caps(self):
        """Test nice_key with all caps words"""
        tool = self._create_mock_tool()
        result = tool.nice_key("API_KEY")
        # First word capitalized, rest lowercased
        assert result.startswith("Api")

    def test_nice_key_mixed_case(self):
        """Test nice_key with mixed case input"""
        tool = self._create_mock_tool()
        result = tool.nice_key("myVAR_nameTEST")
        # All after first should be lowercase
        assert "myvar" in result.lower()

    def test_nice_key_returns_string(self):
        """Test nice_key returns a string"""
        tool = self._create_mock_tool()
        result = tool.nice_key("test_key")
        assert isinstance(result, str)
