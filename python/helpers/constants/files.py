"""File/IO related constants extracted from constants.py."""

from typing import Final


class FileExtensions:
    """File extensions used throughout the system."""

    MARKDOWN: Final[str] = ".md"
    PYTHON: Final[str] = ".py"
    JSON: Final[str] = ".json"
    YAML: Final[str] = ".yaml"
    YML: Final[str] = ".yml"


class MimeTypes:
    """MIME type constants used throughout the system."""

    APPLICATION_JSON: Final[str] = "application/json"
    TEXT_PLAIN: Final[str] = "text/plain"
    TEXT_HTML: Final[str] = "text/html"
    TEXT_CSS: Final[str] = "text/css"
    TEXT_JAVASCRIPT: Final[str] = "text/javascript"
    IMAGE_PNG: Final[str] = "image/png"
    IMAGE_JPEG: Final[str] = "image/jpeg"
    IMAGE_GIF: Final[str] = "image/gif"
    IMAGE_SVG: Final[str] = "image/svg+xml"
    AUDIO_MPEG: Final[str] = "audio/mpeg"
    AUDIO_WAV: Final[str] = "audio/wav"
    VIDEO_MP4: Final[str] = "video/mp4"
    APPLICATION_PDF: Final[str] = "application/pdf"
    APPLICATION_ZIP: Final[str] = "application/zip"
    MULTIPART_FORM_DATA: Final[str] = "multipart/form-data"
    APPLICATION_OCTET_STREAM: Final[str] = "application/octet-stream"

    # Alias for backward compatibility
    DEFAULT_BINARY: Final[str] = APPLICATION_OCTET_STREAM


class Encodings:
    """Encoding constants used throughout the system."""

    UTF_8: Final[str] = "utf-8"
    ASCII: Final[str] = "ascii"
    LATIN_1: Final[str] = "latin-1"


class FilePatterns:
    """File search patterns used throughout the system."""

    KNOWLEDGE_MARKDOWN: Final[str] = "**/*.md"
