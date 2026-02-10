"""Tests for ToolCoordinator"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import Mock, AsyncMock, patch
from python.coordinators.tool_coordinator import ToolCoordinator, IToolExecutor
from python.helpers.tool import Tool, Response


class MockTool(Tool):
    """Mock tool for testing"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = False
        self.before_called = False
        self.after_called = False

    async def before_execution(self, **kwargs):
        self.before_called = True

    async def execute(self, **kwargs) -> Response:
        self.executed = True
        return Response(message="Tool executed successfully", break_loop=False)

    async def after_execution(self, response, **kwargs):
        self.after_called = True


class TestToolCoordinator:
    """Test suite for ToolCoordinator"""
    
    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent"""
        agent = Mock()
        agent.loop_data = Mock()
        agent.loop_data.current_tool = None
        agent.config = Mock()
        agent.config.profile = None
        agent.agent_name = "TestAgent"

        agent.handle_intervention = AsyncMock()
        agent.call_extensions = AsyncMock()
        agent.hist_add_warning = Mock()
        agent.history_coordinator = Mock()
        agent.history_coordinator.add_warning = Mock()
        agent.context = Mock()
        agent.context.log = Mock()
        agent.read_prompt = Mock(return_value="Warning message")

        return agent
    
    @pytest.fixture
    def tool_coordinator(self, mock_agent):
        """Create a ToolCoordinator instance"""
        return ToolCoordinator(mock_agent)
    
    @pytest.fixture
    def valid_tool_request(self):
        """Valid tool request JSON string"""
        return '{"tool_name": "test_tool", "tool_args": {"param1": "value1"}}'
    
    @pytest.fixture
    def tool_with_method(self):
        """Tool request with method"""
        return '{"tool_name": "test_tool:custom_method", "tool_args": {"param1": "value1"}}'
    
    @pytest.mark.asyncio
    async def test_process_tools_executes_tool_successfully(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Valid tool request, mock tool set up"""
        mock_tool = MockTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={"param1": "value1"},
            message=valid_tool_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {"param1": "value1"}
                }
                
                # Act: Process the tool request
                result = await tool_coordinator.process_tools(valid_tool_request)
                
                # Assert: Tool lifecycle executed correctly
                assert mock_tool.before_called is True
                assert mock_tool.executed is True
                assert mock_tool.after_called is True
                assert result is None
                assert mock_agent.call_extensions.called
                assert mock_agent.handle_intervention.called
    
    @pytest.mark.asyncio
    async def test_process_tools_with_break_loop(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Tool configured to break loop"""
        class BreakLoopTool(Tool):
            async def execute(self, **kwargs) -> Response:
                return Response(message="Stopping", break_loop=True)
        
        mock_tool = BreakLoopTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={},
            message=valid_tool_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {}
                }
                
                # Act: Process the tool
                result = await tool_coordinator.process_tools(valid_tool_request)
                
                # Assert: Returns message to break loop
                assert result == "Stopping"
    
    @pytest.mark.asyncio
    async def test_process_tools_with_malformed_request(self, tool_coordinator, mock_agent):
        """Arrange: Malformed tool request"""
        malformed_request = "invalid json"
        
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            mock_extract.json_parse_dirty.return_value = None
            
            # Act: Process malformed request
            result = await tool_coordinator.process_tools(malformed_request)
            
            # Assert: Warning logged, no result
            assert result is None
            assert mock_agent.history_coordinator.add_warning.called
            assert mock_agent.context.log.log.called
    
    @pytest.mark.asyncio
    async def test_process_tools_tool_not_found(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Tool not found, returns Unknown tool"""
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            mock_extract.json_parse_dirty.return_value = {
                "tool_name": "nonexistent_tool",
                "tool_args": {}
            }
            mock_extract.load_classes_from_file.return_value = []

            # Act: Process request for non-existent tool
            result = await tool_coordinator.process_tools(valid_tool_request)

            # Assert: Unknown tool executed, no error
            assert result is None
    
    @pytest.mark.asyncio
    async def test_process_tools_with_tool_method(self, tool_coordinator, mock_agent, tool_with_method):
        """Arrange: Tool request with method specified"""
        mock_tool = MockTool(
            agent=mock_agent,
            name="test_tool",
            method="custom_method",
            args={"param1": "value1"},
            message=tool_with_method,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool:custom_method",
                    "tool_args": {"param1": "value1"}
                }
                
                # Act: Process tool with method
                _ = await tool_coordinator.process_tools(tool_with_method)
                
                # Assert: Tool executed with method
                assert mock_tool.method == "custom_method"
                assert mock_tool.executed is True
    
    @pytest.mark.asyncio
    async def test_process_tools_handles_execution_error(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Tool raises exception during execution"""
        class FailingTool(Tool):
            async def execute(self, **kwargs) -> Response:
                raise ValueError("Tool execution failed")
        
        mock_tool = FailingTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={},
            message=valid_tool_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {}
                }
                
                # Act & Assert: Exception propagated
                with pytest.raises(ValueError, match="Tool execution failed"):
                    await tool_coordinator.process_tools(valid_tool_request)
                
                # Assert: Current tool cleaned up even on error
                assert mock_agent.loop_data.current_tool is None
    
    @pytest.mark.asyncio
    async def test_process_tools_cleanup_current_tool_after_execution(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Tool execution with current_tool tracking"""
        mock_tool = MockTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={},
            message=valid_tool_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {}
                }
                
                # Act: Process tool
                await tool_coordinator.process_tools(valid_tool_request)
                
                # Assert: Current tool cleaned up
                assert mock_agent.loop_data.current_tool is None
    
    @pytest.mark.asyncio
    async def test_process_tools_with_empty_args(self, tool_coordinator, mock_agent):
        """Arrange: Tool request with empty args"""
        empty_args_request = '{"tool_name": "test_tool", "tool_args": {}}'
        mock_tool = MockTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={},
            message=empty_args_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {}
                }
                
                # Act: Process tool with empty args
                result = await tool_coordinator.process_tools(empty_args_request)
                
                # Assert: Tool executed successfully
                assert mock_tool.executed is True
                assert result is None
    
    def test_get_tool_loads_from_profile_directory(self, tool_coordinator, mock_agent):
        """Arrange: Agent with profile, tool exists in profile directory"""
        mock_agent.config.profile = "test_profile"
        
        mock_tool_class = Mock()
        mock_instance = Mock()
        mock_tool_class.return_value = mock_instance
        
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            mock_extract.load_classes_from_file.return_value = [mock_tool_class]
            
            # Act: Get tool from profile directory
            result = tool_coordinator.get_tool(
                name="profile_tool",
                method=None,
                args={},
                message="",
                loop_data=mock_agent.loop_data
            )
            
            # Assert: Tool loaded from profile directory
            assert result == mock_instance
            mock_extract.load_classes_from_file.assert_called_once()
    
    def test_get_tool_falls_back_to_default_directory(self, tool_coordinator, mock_agent):
        """Arrange: Tool not in profile, falls back to default tools directory"""
        mock_agent.config.profile = "test_profile"
        
        mock_tool_class = Mock()
        mock_instance = Mock()
        mock_tool_class.return_value = mock_instance
        
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            def side_effect(path, base):
                if "profile" in path:
                    return []
                else:
                    return [mock_tool_class]
            
            mock_extract.load_classes_from_file.side_effect = side_effect
            
            # Act: Get tool (falls back to default directory)
            result = tool_coordinator.get_tool(
                name="default_tool",
                method=None,
                args={},
                message="",
                loop_data=mock_agent.loop_data
            )
            
            # Assert: Tool loaded from default directory
            assert result == mock_instance
            assert mock_extract.load_classes_from_file.call_count == 2
    
    def test_get_tool_returns_unknown_when_not_found(self, tool_coordinator, mock_agent):
        """Arrange: Tool not found in any directory"""
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            mock_extract.load_classes_from_file.return_value = []
            
            # Act: Get non-existent tool
            result = tool_coordinator.get_tool(
                name="nonexistent_tool",
                method=None,
                args={},
                message="",
                loop_data=mock_agent.loop_data
            )
            
            # Assert: Returns Unknown tool
            assert result is not None
            assert isinstance(result, Tool)
    
    def test_get_tool_passes_correct_parameters(self, tool_coordinator, mock_agent):
        """Arrange: Tool request with all parameters"""
        mock_tool_class = Mock()
        mock_instance = Mock()
        mock_tool_class.return_value = mock_instance
        
        with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
            mock_extract.load_classes_from_file.return_value = [mock_tool_class]
            
            # Act: Get tool with all parameters
            _ = tool_coordinator.get_tool(
                name="test_tool",
                method="custom_method",
                args={"param1": "value1"},
                message="test message",
                loop_data=mock_agent.loop_data,
                extra_param="extra_value"
            )
            
            # Assert: Tool instantiated with correct parameters
            mock_tool_class.assert_called_once_with(
                agent=mock_agent,
                name="test_tool",
                method="custom_method",
                args={"param1": "value1"},
                message="test message",
                loop_data=mock_agent.loop_data,
                extra_param="extra_value"
            )
    
    @pytest.mark.asyncio
    async def test_process_tools_calls_extensions_in_correct_order(self, tool_coordinator, mock_agent, valid_tool_request):
        """Arrange: Tool request with extensions"""
        mock_tool = MockTool(
            agent=mock_agent,
            name="test_tool",
            method=None,
            args={"param1": "value1"},
            message=valid_tool_request,
            loop_data=mock_agent.loop_data
        )
        
        with patch.object(tool_coordinator, 'get_tool', return_value=mock_tool):
            with patch('python.coordinators.tool_coordinator.extract_tools') as mock_extract:
                mock_extract.json_parse_dirty.return_value = {
                    "tool_name": "test_tool",
                    "tool_args": {"param1": "value1"}
                }
                
                # Act: Process tool
                await tool_coordinator.process_tools(valid_tool_request)
                
                # Assert: Extensions called in correct order
                calls = mock_agent.call_extensions.call_args_list
                
                tool_execute_before_call = [c for c in calls if c[0][0] == "tool_execute_before"]
                tool_execute_after_call = [c for c in calls if c[0][0] == "tool_execute_after"]
                
                assert len(tool_execute_before_call) == 1
                assert len(tool_execute_after_call) == 1


class TestIToolExecutorInterface:
    """Test that ToolCoordinator implements IToolExecutor interface"""
    
    def test_tool_coordinator_implements_interface(self):
        """Arrange: IToolExecutor interface defined"""
        # Act: ToolCoordinator should implement IToolExecutor
        # Assert: Interface methods exist
        assert hasattr(ToolCoordinator, 'process_tools')
        assert hasattr(ToolCoordinator, 'get_tool')
    
    @pytest.mark.asyncio
    async def test_process_tools_is_abstract_method(self):
        """Arrange: IToolExecutor defines abstract method"""
        # Act & Assert: Cannot instantiate abstract interface
        with pytest.raises(TypeError):
            IToolExecutor()
