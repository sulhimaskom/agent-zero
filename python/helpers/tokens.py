from typing import Literal

# Tiktoken with graceful degradation
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError as e:
    TIKTOKEN_AVAILABLE = False
    tiktoken = None
    print(f"Warning: tiktoken not available - token counting will be approximate: {e}")

APPROX_BUFFER = 1.1
TRIM_BUFFER = 0.8


def count_tokens(text: str, encoding_name="cl100k_base") -> int:
    if not text:
        return 0

    if not TIKTOKEN_AVAILABLE:
        # Fallback: approximate token count (roughly 4 characters per token)
        return max(1, len(text) // 4)

    # Get the encoding
    encoding = tiktoken.get_encoding(encoding_name)

    # Encode the text and count the tokens
    tokens = encoding.encode(text)
    token_count = len(tokens)

    return token_count


def approximate_tokens(
    text: str,
) -> int:
    return int(count_tokens(text) * APPROX_BUFFER)


def trim_to_tokens(
    text: str,
    max_tokens: int,
    direction: Literal["start", "end"],
    ellipsis: str = "...",
) -> str:
    chars = len(text)
    tokens = count_tokens(text)

    if tokens <= max_tokens:
        return text

    approx_chars = int(chars * (max_tokens / tokens) * TRIM_BUFFER)

    if direction == "start":
        return text[:approx_chars] + ellipsis
    return ellipsis + text[chars - approx_chars : chars]
