from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING
import asyncio

from python.helpers import history

if TYPE_CHECKING:
    from python.models.agent import UserMessage


class IHistoryManager(ABC):
    """Interface for history management"""

    @abstractmethod
    def hist_add_message(
        self, ai: bool, content: history.MessageContent, tokens: int = 0
    ):
        """Add message to history"""
        pass

    @abstractmethod
    def hist_add_user_message(self, message, intervention: bool = False):
        """Add user message to history"""
        pass

    @abstractmethod
    def hist_add_ai_response(self, message: str):
        """Add AI response to history"""
        pass

    @abstractmethod
    def hist_add_warning(self, message: history.MessageContent):
        """Add warning message to history"""
        pass

    @abstractmethod
    def hist_add_tool_result(self, tool_name: str, tool_result: str, **kwargs):
        """Add tool result to history"""
        pass

    @abstractmethod
    def concat_messages(self, messages):
        """Concatenate messages for display"""
        pass


class HistoryCoordinator(IHistoryManager):
    """Coordinates history operations"""

    def __init__(self, agent):
        self.agent = agent

    def hist_add_message(
        self, ai: bool, content: history.MessageContent, tokens: int = 0
    ):
        """Add message to history"""
        self.agent.last_message = datetime.now(timezone.utc)
        content_data = {"content": content}
        asyncio.run(self.agent.call_extensions("hist_add_before", content_data=content_data, ai=ai))
        return self.agent.history.add_message(ai=ai, content=content_data["content"], tokens=tokens)

    def hist_add_user_message(self, message, intervention: bool = False):
        """Add user message to history"""
        self.agent.history.new_topic()

        if intervention:
            content = self.agent.parse_prompt(
                "fw.intervention.md",
                message=message.message,
                attachments=message.attachments,
                system_message=message.system_message,
            )
        else:
            content = self.agent.parse_prompt(
                "fw.user_message.md",
                message=message.message,
                attachments=message.attachments,
                system_message=message.system_message,
            )

        if isinstance(content, dict):
            content = {k: v for k, v in content.items() if v}

        msg = self.hist_add_message(False, content=content)
        self.agent.last_user_message = msg
        return msg

    def hist_add_ai_response(self, message: str):
        """Add AI response to history"""
        self.agent.loop_data.last_response = message
        content = self.agent.parse_prompt("fw.ai_response.md", message=message)
        return self.hist_add_message(True, content=content)

    def hist_add_warning(self, message: history.MessageContent):
        """Add warning message to history"""
        content = self.agent.parse_prompt("fw.warning.md", message=message)
        return self.hist_add_message(False, content=content)

    def hist_add_tool_result(self, tool_name: str, tool_result: str, **kwargs):
        """Add tool result to history"""
        data = {
            "tool_name": tool_name,
            "tool_result": tool_result,
            **kwargs,
        }
        asyncio.run(self.agent.call_extensions("hist_add_tool_result", data=data))
        return self.hist_add_message(False, content=data)

    def concat_messages(self, messages):
        """Concatenate messages for display"""
        return self.agent.history.output_text(human_label="user", ai_label="assistant")
