import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Skip this test in automated runs - it requires actual API keys
pytestmark = pytest.mark.skip(
    reason="Integration test - requires actual API keys and network access"
)

import models  # noqa: E402

provider = "openrouter"
name = "deepseek/deepseek-r1"

model = models.get_chat_model(
    provider=provider,
    name=name,
    model_config=models.ModelConfig(
        type=models.ModelType.CHAT,
        provider=provider,
        name=name,
        limit_requests=5,
        limit_input=15000,
        limit_output=1000,
    ),
)


async def run():
    _response, _reasoning = await model.unified_call(user_message="Tell me a joke")


if __name__ == "__main__":
    import asyncio

    asyncio.run(run())
