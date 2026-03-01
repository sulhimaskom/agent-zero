"""Tests for call_llm module - core LLM calling utilities

These tests verify the core functionality and structure of the call_llm module.
Due to the complex LangChain dependencies, some tests verify structure and
import behavior while others test the function's behavior with proper mocking.
"""

from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest

# Import the module under test
from python.helpers.call_llm import Example


# Helper to create async iterator
class AsyncChunkIterator:
    """Helper class to create async iterator for testing"""
    def __init__(self, chunks):
        self.chunks = chunks
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index >= len(self.chunks):
            raise StopAsyncIteration
        chunk = self.chunks[self.index]
        self.index += 1
        return chunk


class TestCallLlmFunction:
    """Test call_llm async function"""

    @pytest.mark.asyncio
    async def test_call_llm_basic_response(self):
        """Test basic LLM call - verify function executes without error"""
        chunks = ["Hello", " world", "!"]

        # Create mock chain that returns an async iterator
        mock_chain = MagicMock()

        # Create a proper async iterator
        async def async_streamer():
            for chunk in chunks:
                yield chunk

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            # Import fresh to get patched version
            from python.helpers.call_llm import call_llm as call_llm_func

            # This should execute without raising an exception
            result = await call_llm_func(
                system="You are a helpful assistant.",
                model=model,
                message="Say hello"
            )

    @pytest.mark.asyncio
    async def test_call_llm_with_callback(self):
        """Test LLM call with callback function is invoked"""
        callback = MagicMock(spec=Callable[[str], None])
        chunks = ["Test", " response"]

        mock_chain = MagicMock()

        async def async_streamer():
            for chunk in chunks:
                yield chunk

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            result = await call_llm_func(
                system="You are helpful.",
                model=model,
                message="Test",
                callback=callback
            )

            # Verify callback was called for each chunk
            assert callback.call_count == 2

    @pytest.mark.asyncio
    async def test_call_llm_with_examples(self):
        """Test LLM call with few-shot examples passes examples parameter"""
        examples: list[Example] = [
            {"input": "Hi", "output": "Hello!"},
            {"input": "Bye", "output": "Goodbye!"}
        ]

        mock_chain = MagicMock()

        async def async_streamer():
            yield "Response"

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            # Should not raise - examples are passed
            result = await call_llm_func(
                system="You are helpful.",
                model=model,
                message="Hi there",
                examples=examples
            )

    @pytest.mark.asyncio
    async def test_call_llm_empty_examples_list(self):
        """Test LLM call with empty examples list"""
        mock_chain = MagicMock()

        async def async_streamer():
            yield "Result"

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            result = await call_llm_func(
                system="You are helpful.",
                model=model,
                message="Test",
                examples=[]
            )

    @pytest.mark.asyncio
    async def test_call_llm_none_callback(self):
        """Test LLM call with None callback (default)"""
        mock_chain = MagicMock()

        async def async_streamer():
            yield "Result"

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            # Should not raise - callback is None
            result = await call_llm_func(
                system="You are helpful.",
                model=model,
                message="Test",
                callback=None
            )

    @pytest.mark.asyncio
    async def test_call_llm_single_chunk_response(self):
        """Test with single chunk response"""
        mock_chain = MagicMock()

        async def async_streamer():
            yield "Single response"

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            result = await call_llm_func(
                system="Test",
                model=model,
                message="Test"
            )

    @pytest.mark.asyncio
    async def test_call_llm_ai_message_chunk_handling(self):
        """Test handling of chunk objects with content attribute"""
        mock_chunk = MagicMock()
        mock_chunk.content = "AI response"

        mock_chain = MagicMock()

        async def async_streamer():
            yield mock_chunk

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            result = await call_llm_func(
                system="Test",
                model=model,
                message="Test"
            )

    @pytest.mark.asyncio
    async def test_call_llm_string_chunk_handling(self):
        """Test handling of string chunks"""
        mock_chain = MagicMock()

        async def async_streamer():
            yield "String chunk"

        mock_chain.astream = MagicMock(return_value=async_streamer())

        with patch('python.helpers.call_llm.ChatPromptTemplate') as mock_template:
            mock_prompt = MagicMock()
            mock_prompt.__or__ = MagicMock(return_value=mock_chain)
            mock_template.from_messages.return_value = mock_prompt

            model = MagicMock()

            from python.helpers.call_llm import call_llm as call_llm_func

            result = await call_llm_func(
                system="Test",
                model=model,
                message="Test"
            )


class TestExampleTypedDict:
    """Test Example TypedDict structure"""

    def test_example_creation(self):
        """Test creating Example TypedDict"""
        example: Example = {"input": "Input text", "output": "Output text"}

        assert example["input"] == "Input text"
        assert example["output"] == "Output text"

    def test_example_with_multiple(self):
        """Test list of Examples"""
        examples: list[Example] = [
            {"input": "Q1", "output": "A1"},
            {"input": "Q2", "output": "A2"},
            {"input": "Q3", "output": "A3"}
        ]

        assert len(examples) == 3
        assert examples[0]["input"] == "Q1"
        assert examples[2]["output"] == "A3"

    def test_example_empty_strings(self):
        """Test Example with empty strings"""
        example: Example = {"input": "", "output": ""}

        assert example["input"] == ""
        assert example["output"] == ""

    def test_example_dict_type(self):
        """Test Example is a proper dict"""
        example: Example = {"input": "test", "output": "result"}

        # Verify it's dict-like
        assert isinstance(example, dict)
        assert "input" in example
        assert "output" in example
        assert len(example) == 2

    def test_example_mutation(self):
        """Test Example can be mutated"""
        example: Example = {"input": "original", "output": "original"}

        example["input"] = "modified"
        example["output"] = "modified"

        assert example["input"] == "modified"
        assert example["output"] == "modified"
