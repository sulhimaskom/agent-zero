from abc import ABC, abstractmethod
from typing import Any, Callable

from python.helpers.print_style import PrintStyle
from python.helpers.dirty_json import DirtyJson


class IStreamHandler(ABC):
    """Interface for stream handling"""

    @abstractmethod
    def create_reasoning_callback(self, loop_data: Any) -> Callable[[str, str], Any]:
        """Create callback for handling reasoning stream chunks"""
        pass

    @abstractmethod
    def create_response_callback(self, loop_data: Any) -> Callable[[str, str], Any]:
        """Create callback for handling response stream chunks"""
        pass

    @abstractmethod
    async def handle_reasoning_stream(self, stream: str):
        """Handle completed reasoning stream"""
        pass

    @abstractmethod
    async def handle_response_stream(self, stream: str):
        """Handle completed response stream"""
        pass

    @abstractmethod
    async def finalize_streams(self, loop_data: Any):
        """Finalize stream processing after LLM call completes"""
        pass


class StreamCoordinator(IStreamHandler):
    """Coordinates stream handling and extension filtering"""

    def __init__(self, agent):
        self.agent = agent
        self.printer = PrintStyle(italic=True, font_color="#b3ffd9", padding=False)

    def create_reasoning_callback(self, loop_data: Any) -> Callable[[str, str], Any]:
        """Create callback for handling reasoning stream chunks"""

        async def reasoning_callback(chunk: str, full: str):
            await self.agent.handle_intervention()
            if chunk == full:
                self.printer.print("Reasoning: ")
            stream_data = {"chunk": chunk, "full": full}
            await self.agent.call_extensions(
                "reasoning_stream_chunk", loop_data=loop_data, stream_data=stream_data
            )
            if stream_data.get("chunk"):
                self.printer.stream(stream_data["chunk"])
            await self.handle_reasoning_stream(stream_data["full"])

        return reasoning_callback

    def create_response_callback(self, loop_data: Any) -> Callable[[str, str], Any]:
        """Create callback for handling response stream chunks"""

        async def stream_callback(chunk: str, full: str):
            await self.agent.handle_intervention()
            if chunk == full:
                self.printer.print("Response: ")
            stream_data = {"chunk": chunk, "full": full}
            await self.agent.call_extensions(
                "response_stream_chunk", loop_data=loop_data, stream_data=stream_data
            )
            if stream_data.get("chunk"):
                self.printer.stream(stream_data["chunk"])
            await self.handle_response_stream(stream_data["full"])

        return stream_callback

    async def handle_reasoning_stream(self, stream: str):
        """Handle completed reasoning stream"""
        await self.agent.handle_intervention()
        await self.agent.call_extensions(
            "reasoning_stream",
            loop_data=self.agent.loop_data,
            text=stream,
        )

    async def handle_response_stream(self, stream: str):
        """Handle completed response stream"""
        await self.agent.handle_intervention()
        try:
            if len(stream) < 25:
                return
            response = DirtyJson.parse_string(stream)
            if isinstance(response, dict):
                await self.agent.call_extensions(
                    "response_stream",
                    loop_data=self.agent.loop_data,
                    text=stream,
                    parsed=response,
                )
        except Exception:
            pass

    async def finalize_streams(self, loop_data: Any):
        """Finalize stream processing after LLM call completes"""
        await self.agent.call_extensions("reasoning_stream_end", loop_data=loop_data)
        await self.agent.call_extensions("response_stream_end", loop_data=loop_data)
