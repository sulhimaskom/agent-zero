"""Pytest configuration for agent-zero tests"""

import sys
import os
from unittest.mock import MagicMock

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

# Mock browser_use submodules
sys.modules['browser_use.llm'] = MagicMock()
sys.modules['browser_use.agent'] = MagicMock()
sys.modules['browser_use.browser'] = MagicMock()

# Mock openai properly to avoid conflicts with litellm
openai_mock = create_mock_module('openai')
openai_mock._models = MagicMock()
sys.modules['openai._models'] = openai_mock._models
openai_mock.types = MagicMock()
sys.modules['openai.types'] = openai_mock.types
openai_mock.types.audio = MagicMock()
sys.modules['openai.types.audio'] = openai_mock.types.audio
sys.modules['openai.types.audio.transcription_create_params'] = MagicMock()
sys.modules['openai.types.completion_create_params'] = MagicMock()
sys.modules['openai.types.chat'] = MagicMock()
