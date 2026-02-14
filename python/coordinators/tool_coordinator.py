from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from python.helpers import extract_tools
from python.helpers.print_style import PrintStyle
from python.helpers.tool import Tool
import contextlib


@dataclass
class ToolResult:
    message: str
    break_loop: bool


class IToolExecutor(ABC):
    """Interface for tool execution"""

    @abstractmethod
    async def process_tools(self, msg: str) -> str | None:
        """Process tool usage requests in agent message"""
        pass

    @abstractmethod
    def get_tool(
        self,
        name: str,
        method: str | None,
        args: dict,
        message: str,
        loop_data: Any,
        **kwargs,
    ) -> Tool:
        """Get tool instance by name"""
        pass


class ToolCoordinator(IToolExecutor):
    """Coordinates tool discovery and execution"""

    def __init__(self, agent):
        self.agent = agent
        self.history_manager = agent.history_coordinator

    async def process_tools(self, msg: str) -> str | None:
        """Process tool usage requests in agent message"""
        tool_request = extract_tools.json_parse_dirty(msg)

        if tool_request is not None:
            raw_tool_name = tool_request.get("tool_name", "")
            tool_args = tool_request.get("tool_args", {})

            tool_name = raw_tool_name
            tool_method = None

            if ":" in raw_tool_name:
                tool_name, tool_method = raw_tool_name.split(":", 1)

            tool = None

            try:
                import python.helpers.mcp_handler as mcp_helper

                mcp_tool_candidate = mcp_helper.MCPConfig.get_instance().get_tool(
                    self.agent, tool_name
                )
                if mcp_tool_candidate:
                    tool = mcp_tool_candidate
            except ImportError:
                PrintStyle(background_color="black", font_color="yellow", padding=True).print(
                    "MCP helper module not found. Skipping MCP tool lookup."
                )
            except (RuntimeError, AttributeError) as e:
                PrintStyle(background_color="black", font_color="red", padding=True).print(
                    f"Failed to get MCP tool '{tool_name}': {e}"
                )

            if not tool:
                tool = self.get_tool(
                    name=tool_name,
                    method=tool_method,
                    args=tool_args,
                    message=msg,
                    loop_data=self.agent.loop_data,
                )

            if tool:
                self.agent.loop_data.current_tool = tool
                try:
                    await self.agent.handle_intervention()

                    await tool.before_execution(**tool_args)
                    await self.agent.handle_intervention()

                    await self.agent.call_extensions(
                        "tool_execute_before",
                        tool_args=tool_args or {},
                        tool_name=tool_name,
                    )

                    response = await tool.execute(**tool_args)
                    await self.agent.handle_intervention()

                    await self.agent.call_extensions(
                        "tool_execute_after",
                        response=response,
                        tool_name=tool_name,
                    )

                    await tool.after_execution(response)
                    await self.agent.handle_intervention()

                    if response.break_loop:
                        return response.message
                finally:
                    self.agent.loop_data.current_tool = None
            else:
                error_detail = f"Tool '{raw_tool_name}' not found or could not be initialized."
                self.history_manager.add_warning(error_detail)
                PrintStyle(font_color="red", padding=True).print(error_detail)
                self.agent.context.log.log(
                    type="error",
                    content=f"{self.agent.agent_name}: {error_detail}",
                )
        else:
            warning_msg_misformat = self.agent.read_prompt("fw.msg_misformat.md")
            self.history_manager.add_warning(warning_msg_misformat)
            PrintStyle(font_color="red", padding=True).print(warning_msg_misformat)
            self.agent.context.log.log(
                type="error",
                content=f"{self.agent.agent_name}: Message misformat, no valid tool request found.",
            )

    def get_tool(
        self,
        name: str,
        method: str | None,
        args: dict,
        message: str,
        loop_data: Any,
        **kwargs,
    ) -> Tool:
        """Get tool instance by name"""
        from python.tools.unknown import Unknown

        classes = []

        if self.agent.config.profile:
            with contextlib.suppress(ImportError, FileNotFoundError):
                classes = extract_tools.load_classes_from_file(
                    "agents/" + self.agent.config.profile + "/tools/" + name + ".py",
                    Tool,
                )

        if not classes:
            with contextlib.suppress(ImportError, FileNotFoundError):
                classes = extract_tools.load_classes_from_file("python/tools/" + name + ".py", Tool)

        tool_class = classes[0] if classes else Unknown
        return tool_class(
            agent=self.agent,
            name=name,
            method=method,
            args=args,
            message=message,
            loop_data=loop_data,
            **kwargs,
        )
