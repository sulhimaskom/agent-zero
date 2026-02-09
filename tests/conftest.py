"""Pytest configuration for agent-zero tests"""

import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Create mock modules with submodules to avoid import errors
def create_mock_module(name):
    """Create a mock module that can have attributes assigned to it"""
    module = MagicMock()
    sys.modules[name] = module
    return module

# Mock all heavy ML/AI dependencies
create_mock_module('whisper')
create_mock_module('openai_whisper')
create_mock_module('transformers')
create_mock_module('torch')
create_mock_module('numpy')
create_mock_module('sentence_transformers')
create_mock_module('faiss')
create_mock_module('browser_use')
create_mock_module('mcp')
sys.modules['mcp.client'] = MagicMock()
sys.modules['mcp.client.stdio'] = MagicMock()
sys.modules['mcp.client.sse'] = MagicMock()
sys.modules['mcp.client.streamable_http'] = MagicMock()
sys.modules['mcp.shared'] = MagicMock()
sys.modules['mcp.shared.message'] = MagicMock()
sys.modules['mcp.types'] = MagicMock()

# Mock browser_use submodules
sys.modules['browser_use.llm'] = MagicMock()
sys.modules['browser_use.agent'] = MagicMock()
sys.modules['browser_use.browser'] = MagicMock()

# Mock litellm and all its submodules
litellm_mock = create_mock_module('litellm')

# Create proper async mock for acompletion
async def mock_acompletion(*args, **kwargs):
    """Mock async completion that returns a proper response"""
    
    # Create a proper dict-like choice object
    class Choice:
        def __init__(self):
            self.message = {"content": "Mocked response", "reasoning_content": ""}
            self.delta = {"content": "Mocked response", "reasoning_content": ""}
        
        def get(self, key, default=None):
            return getattr(self, key, default)
    
    # Check if streaming mode
    if kwargs.get('stream'):
        async def stream_generator():
            # Single chunk with all content
            chunk = {"choices": [Choice()]}
            yield chunk
        
        return stream_generator()
    else:
        # Non-streaming response - return a dict-like object
        return {"choices": [Choice()]}

litellm_mock.completion = MagicMock()
litellm_mock.acompletion = mock_acompletion
litellm_mock.embedding = MagicMock()
litellm_mock.utils = MagicMock()
litellm_mock.suppress_debug_info = True

# Mock litellm.types
litellm_mock.types = MagicMock()
sys.modules['litellm.types'] = litellm_mock.types
litellm_mock.types.utils = MagicMock()
sys.modules['litellm.types.utils'] = litellm_mock.types.utils
litellm_mock.types.llms = MagicMock()
sys.modules['litellm.types.llms'] = litellm_mock.types.llms
litellm_mock.types.llms.openai = MagicMock()
sys.modules['litellm.types.llms.openai'] = litellm_mock.types.llms.openai

# Mock openai with proper exception classes
openai_mock = create_mock_module('openai')

# Define proper exception classes for openai
class APITimeoutError(Exception):
    pass

class APIConnectionError(Exception):
    pass

class RateLimitError(Exception):
    pass

class APIError(Exception):
    pass

class InternalServerError(Exception):
    pass

class APIStatusError(Exception):
    pass

openai_mock.APITimeoutError = APITimeoutError
openai_mock.APIConnectionError = APIConnectionError
openai_mock.RateLimitError = RateLimitError
openai_mock.APIError = APIError
openai_mock.InternalServerError = InternalServerError
openai_mock.APIStatusError = APIStatusError

# Mock langchain and langchain_core
sys.modules['langchain'] = MagicMock()
sys.modules['langchain.prompts'] = MagicMock()
sys.modules['langchain.schema'] = MagicMock()
sys.modules['langchain.embeddings'] = MagicMock()
sys.modules['langchain.embeddings.base'] = MagicMock()
