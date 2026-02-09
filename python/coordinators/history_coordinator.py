from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone
import asyncio

from python.helpers import history
from python.helpers.localization import Localization
from python.helpers.extension import call_extensions


class IHistoryManager(ABC):
    """Interface for history management"""

    @abstractmethod
    def add_message(
        self, ai: bool, content: history.MessageContent, tokens: int = 0
    ) -> history.Message:
        """Add a message to history"""
        pass

    @abstractmethod
    def add_user_message(self, message: "UserMessage", intervention: bool = False) -> history.Message:
        """Add a user message to history, starting a new topic"""
        pass

    @abstractmethod
    def add_ai_response(self, message: str) -> history.Message:
        """Add an AI response to history"""
        pass

    @abstractmethod
    def add_warning(self, message: history.MessageContent) -> history.Message:
        """Add a warning message to history"""
        pass

    @abstractmethod
    def add_tool_result(self, tool_name: str, tool_result: str, **kwargs) -> history.Message:
        """Add a tool result to history"""
        pass


class HistoryCoordinator(IHistoryManager):
    """Coordinates history management operations"""

    def __init__(self, agent):
        self.agent = agent

    def add_message(
        self, ai: bool, content: history.MessageContent, tokens: int = 0
    ) -> history.Message:
        """Add a message to history"""
        self.agent.context.last_message = datetime.now(timezone.utc)
        content_data = {"content": content}
        asyncio.run(self.agent.call_extensions("hist_add_before", content_data=content_data, ai=ai))
        return self.agent.history.add_message(ai=ai, content=content_data["content"], tokens=tokens)

    def add_user_message(self, message: "UserMessage", intervention: bool = False) -> history.Message:
        """Add a user message to history, starting a new topic"""
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

        msg = self.add_message(False, content=content)
        self.agent.last_user_message = msg
        return msg

    def add_ai_response(self, message: str) -> history.Message:
        """Add an AI response to history"""
        self.agent.loop_data.last_response = message
        content = self.agent.parse_prompt("fw.ai_response.md", message=message)
        return self.add_message(True, content=content)

    def add_warning(self, message: history.MessageContent) -> history.Message:
        """Add a warning message to history"""
        content = self.agent.parse_prompt("fw.warning.md", message=message)
        return self.add_message(False, content=content)

    def add_tool_result(self, tool_name: str, tool_result: str, **kwargs) -> history.Message:
        """Add a tool result to history"""
        data = {
            "tool_name": tool_name,
            "tool_result": tool_result,
            **kwargs,
        }
        asyncio.run(self.agent.call_extensions("hist_add_tool_result", data=data))
        return self.add_message(False, content=data)
