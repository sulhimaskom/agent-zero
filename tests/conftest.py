"""Pytest configuration for agent-zero tests"""

import os
import sys
from unittest.mock import MagicMock

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


# Create mock modules with submodules to avoid import errors
def create_mock_module(name):
    """Create a mock module that can have attributes assigned to it"""
    module = MagicMock()
    sys.modules[name] = module
    return module


# Mock all heavy ML/AI dependencies
create_mock_module("whisper")
create_mock_module("openai_whisper")
create_mock_module("transformers")
create_mock_module("torch")
create_mock_module("numpy")
create_mock_module("sentence_transformers")
create_mock_module("faiss")
create_mock_module("browser_use")

# Mock browser_use submodules
sys.modules["browser_use.llm"] = MagicMock()
sys.modules["browser_use.agent"] = MagicMock()
sys.modules["browser_use.browser"] = MagicMock()

# Mock openai properly to avoid conflicts with litellm
openai_mock = create_mock_module("openai")
openai_mock._models = MagicMock()
sys.modules["openai._models"] = openai_mock._models
openai_mock.types = MagicMock()
sys.modules["openai.types"] = openai_mock.types
openai_mock.types.audio = MagicMock()
sys.modules["openai.types.audio"] = openai_mock.types.audio
sys.modules["openai.types.audio.transcription_create_params"] = MagicMock()
sys.modules["openai.types.completion_create_params"] = MagicMock()
sys.modules["openai.types.chat"] = MagicMock()

# Mock litellm
litellm_mock = create_mock_module("litellm")
sys.modules["litellm.types"] = MagicMock()
sys.modules["litellm.types.utils"] = MagicMock()
sys.modules["litellm.types.utils"].ModelResponse = MagicMock()

# Mock html2text
html2text_mock = create_mock_module("html2text")
html2text_mock.HTML2Text = MagicMock

# Mock other common dependencies
create_mock_module("nest_asyncio")
create_mock_module("docker")
create_mock_module("psutil")
create_mock_module("aiohttp")
create_mock_module("fastmcp")
# Mock mcp module with required classes for tests
mcp_mock = create_mock_module("mcp")
mcp_mock.ClientSession = MagicMock
mcp_mock.StdioServerParameters = MagicMock

# Mock mcp.client submodules
sys.modules["mcp.client"] = MagicMock()
sys.modules["mcp.client.stdio"] = MagicMock()
sys.modules["mcp.client.stdio"].stdio_client = MagicMock()
sys.modules["mcp.client.sse"] = MagicMock()
sys.modules["mcp.client.sse"].sse_client = MagicMock()
sys.modules["mcp.client.streamable_http"] = MagicMock()
sys.modules["mcp.client.streamable_http"].streamablehttp_client = MagicMock()

# Mock mcp.shared submodules
sys.modules["mcp.shared"] = MagicMock()
sys.modules["mcp.shared.message"] = MagicMock()
sys.modules["mcp.shared.message"].SessionMessage = MagicMock()

# Mock mcp.types
sys.modules["mcp.types"] = MagicMock()
sys.modules["mcp.types"].CallToolResult = MagicMock()
sys.modules["mcp.types"].ListToolsResult = MagicMock()

create_mock_module("fasta2a")
create_mock_module("croniter")
create_mock_module("imapclient")
create_mock_module("exchangelib")
create_mock_module("pymupdf")
create_mock_module("fitz")  # PyMuPDF alternative name
create_mock_module("pytesseract")
create_mock_module("pdf2image")
create_mock_module("pypdf")
create_mock_module("kokoro")
create_mock_module("soundfile")
create_mock_module("webcolors")
create_mock_module("crontab")
create_mock_module("markdownify")
create_mock_module("newspaper")
create_mock_module("newspaper3k")
create_mock_module("langchain")
create_mock_module("langchain_core")
create_mock_module("langchain_community")
create_mock_module("langchain_text_splitters")
create_mock_module("langchain_unstructured")
create_mock_module("unstructured")
create_mock_module("duckduckgo_search")
create_mock_module("flaredantic")
create_mock_module("ansio")
create_mock_module("a2wsgi")
create_mock_module("flask_basicauth")
create_mock_module("paramiko")
create_mock_module("GitPython")
create_mock_module("git")
create_mock_module("playwright")
create_mock_module("markdown")
create_mock_module("pytz")
tiktoken_mock = create_mock_module("tiktoken")

# Properly mock get_encoding to return a working encoder
class MockEncoding:
    def encode(self, text, disallowed_special=()):
        if not text:
            return []
        # Simple word-based approximation
        return list(range(len(text.split())))
    
    def encode_batch(self, texts, disallowed_special=()):
        return [self.encode(t, disallowed_special) for t in texts]


def mock_get_encoding(encoding_name):
    return MockEncoding()


tiktoken_mock.get_encoding = mock_get_encoding
tiktoken_mock.encoding_for_model = MagicMock(
    return_value=MockEncoding()
)


def mock_encode(text):
    return [1] * len(text.split()) if hasattr(text, "split") else [1]


def mock_encode_batch(texts):
    return [[1] * len(t.split()) if hasattr(t, "split") else [1] for t in texts]


tiktoken_mock.encoding_for_model = MagicMock(
    return_value=MagicMock(encode=mock_encode, encode_batch=mock_encode_batch)
)
create_mock_module("lxml")
create_mock_module("lxml_html_clean")
create_mock_module("beautifulsoup4")
create_mock_module("bs4")
create_mock_module("inputimeout")
create_mock_module("simpleeval")
create_mock_module("unstructured_client")
create_mock_module("pathspec")
create_mock_module("pywinpty")
create_mock_module("regex")
create_mock_module("httpx")

# Mock anyio for MCP handler
anyio_mock = create_mock_module("anyio")
sys.modules["anyio.streams"] = MagicMock()
sys.modules["anyio.streams.memory"] = MagicMock()
sys.modules["anyio.streams.memory"].MemoryObjectReceiveStream = MagicMock()
sys.modules["anyio.streams.memory"].MemoryObjectSendStream = MagicMock()

# Mock langchain submodules
sys.modules["langchain_core.language_models"] = MagicMock()
sys.modules["langchain_core.language_models.chat_models"] = MagicMock()
sys.modules["langchain_core.language_models.chat_models"].SimpleChatModel = MagicMock
sys.modules["langchain_core.language_models.llms"] = MagicMock()
sys.modules["langchain_core.language_models.llms"].BaseLLM = MagicMock
sys.modules["langchain_core.outputs"] = MagicMock()
sys.modules["langchain_core.outputs.chat_generation"] = MagicMock()
sys.modules["langchain_core.outputs.chat_generation"].ChatGenerationChunk = MagicMock
sys.modules["langchain_core.callbacks"] = MagicMock()
sys.modules["langchain_core.callbacks.manager"] = MagicMock()
sys.modules["langchain_core.callbacks.manager"].CallbackManagerForLLMRun = MagicMock
sys.modules["langchain_core.callbacks.manager"].AsyncCallbackManagerForLLMRun = MagicMock
sys.modules["langchain_core.messages"] = MagicMock()
sys.modules["langchain_core.messages"].BaseMessage = MagicMock
sys.modules["langchain_core.messages"].AIMessageChunk = MagicMock
sys.modules["langchain_core.messages"].HumanMessage = MagicMock
sys.modules["langchain_core.messages"].SystemMessage = MagicMock
sys.modules["langchain_core.prompts"] = MagicMock()
sys.modules["langchain_core.prompts"].PromptTemplate = MagicMock
sys.modules["langchain.embeddings"] = MagicMock()
sys.modules["langchain.embeddings.base"] = MagicMock()
sys.modules["langchain.embeddings.base"].Embeddings = MagicMock
sys.modules["langchain.prompts"] = MagicMock()
sys.modules["langchain.prompts"].PromptTemplate = MagicMock
sys.modules["langchain.schema"] = MagicMock()
sys.modules["langchain.schema"].BaseMessage = MagicMock
sys.modules["langchain.schema"].AIMessage = MagicMock
sys.modules["langchain.schema"].HumanMessage = MagicMock
sys.modules["langchain.schema"].SystemMessage = MagicMock

# Mock yaml
yaml_mock = create_mock_module("yaml")
yaml_mock.safe_load = MagicMock(return_value={})
yaml_mock.dump = MagicMock(return_value="")

# Mock flask
flask_mock = create_mock_module("flask")
flask_mock.Flask = MagicMock
flask_mock.request = MagicMock()
flask_mock.jsonify = MagicMock()
flask_mock.render_template = MagicMock()
flask_mock.send_from_directory = MagicMock()
flask_mock.make_response = MagicMock()
flask_mock.Response = MagicMock

# Mock pydantic for testing - imports will be verified separately
pydantic_mock = create_mock_module("pydantic")
pydantic_mock.BaseModel = MagicMock
pydantic_mock.Field = MagicMock()
pydantic_mock.ConfigDict = MagicMock()
pydantic_mock.validator = MagicMock()
pydantic_mock.ValidationError = Exception
pydantic_mock.RootModel = MagicMock
pydantic_mock.TypeAdapter = MagicMock
pydantic_mock.SerializeAsAny = MagicMock

# Mock dotenv (python-dotenv package)
dotenv_mock = create_mock_module("dotenv")
dotenv_mock.load_dotenv = MagicMock()
dotenv_mock.find_dotenv = MagicMock(return_value=".env")
dotenv_mock.set_key = MagicMock()
dotenv_mock.get_key = MagicMock(return_value=None)
# Mock dotenv.parser submodule
sys.modules["dotenv.parser"] = MagicMock()
sys.modules["dotenv.parser"].parse_stream = MagicMock(return_value={})

# Mock helpers modules used by Tool class
print_style_mock = create_mock_module("python.helpers.print_style")
print_style_class = MagicMock
print_style_mock.PrintStyle = print_style_class

# python.helpers.constants is intentionally not mocked - it has no heavy
# dependencies and is directly tested by test_constants.py

# python.helpers.strings is intentionally not mocked - it has no heavy
# dependencies and is directly tested by test_strings.py
