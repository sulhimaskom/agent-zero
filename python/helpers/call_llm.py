from typing import Callable, TypedDict, Union, List, Optional, TYPE_CHECKING, Any

# Safe imports for optional LangChain dependencies
from python.helpers.safe_imports import get_langchain_components

# Get LangChain components
langchain = get_langchain_components()

# Import with graceful degradation
ChatPromptTemplate = langchain.get('ChatPromptTemplate')
FewShotChatMessagePromptTemplate = langchain.get('FewShotChatMessagePromptTemplate')
AIMessage = langchain.get('AIMessage')
HumanMessage = langchain.get('HumanMessage')
SystemMessage = langchain.get('SystemMessage')
BaseChatModel = langchain.get('BaseChatModel')
BaseLLM = langchain.get('BaseLLM')

if TYPE_CHECKING:
    from typing import Any


class Example(TypedDict):
    input: str
    output: str

async def call_llm(
    system: str,
    model: Any,  # BaseChatModel | BaseLLM when available
    message: str,
    examples: List[Example] = [],
    callback: Callable[[str], None] | None = None
):

    example_prompt = ChatPromptTemplate.from_messages(
        [
            HumanMessage(content="{input}"),
            AIMessage(content="{output}"),
        ]
    )

    few_shot_prompt = FewShotChatMessagePromptTemplate(
        example_prompt=example_prompt,
        examples=examples,  # type: ignore
        input_variables=[],
    )

    few_shot_prompt.format()

    final_prompt = ChatPromptTemplate.from_messages(
        [
            SystemMessage(content=system),
            few_shot_prompt,
            HumanMessage(content=message),
        ]
    )

    chain = final_prompt | model

    response = ""
    async for chunk in chain.astream({}):
        # await self.handle_intervention()  # wait for intervention and handle it, if paused

        if isinstance(chunk, str):
            content = chunk
        elif hasattr(chunk, "content"):
            content = str(chunk.content)
        else:
            content = str(chunk)

        if callback:
            callback(content)

        response += content

    return response