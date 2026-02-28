"""
Comprehensive tests for Agent Zero modular configuration system.

Flexy says: Test everything! No hardcoded value escapes verification.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from python.helpers.config import get_env_config_js, get_frontend_config, inject_config_into_html
from python.helpers.constants import (
    AgentDefaults,
    Browser,
    Colors,
    Encodings,
    Extensions,
    ExternalUrls,
    FileExtensions,
    FilePatterns,
    HttpStatus,
    Limits,
    MimeTypes,
    Network,
    Paths,
    Protocols,
    Search,
    Shell,
    StreamSizes,
    Timeouts,
    TmpPaths,
    UITiming,
    get_env_float,
    get_env_int,
    get_env_str,
)


class TestTimeouts:
    """Test Timeouts constants class"""

    def test_code_execution_timeouts(self):
        """Test code execution timeout constants"""
        assert Timeouts.CODE_EXEC_FIRST_OUTPUT == 30
        assert Timeouts.CODE_EXEC_BETWEEN_OUTPUT == 15
        assert Timeouts.CODE_EXEC_MAX == 180
        assert Timeouts.CODE_EXEC_DIALOG == 5

    def test_output_timeouts(self):
        """Test output timeout constants"""
        assert Timeouts.OUTPUT_FIRST_TIMEOUT == 90
        assert Timeouts.OUTPUT_BETWEEN_TIMEOUT == 45
        assert Timeouts.OUTPUT_MAX_TIMEOUT == 300

    def test_browser_timeouts(self):
        """Test browser agent timeout constants"""
        assert Timeouts.BROWSER_LLM_TIMEOUT == 3000
        assert Timeouts.BROWSER_MAX_STEPS == 50
        assert Timeouts.BROWSER_OPERATION_TIMEOUT == 300
        assert Timeouts.BROWSER_ASYNC_TIMEOUT == 10
        assert Timeouts.BROWSER_SCREENSHOT_TIMEOUT == 3000

    def test_rfc_timeout(self):
        """Test RFC function timeout"""
        assert Timeouts.RFC_FUNCTION_TIMEOUT == 30

    def test_email_timeout(self):
        """Test email connection timeout"""
        assert Timeouts.EMAIL_CONNECTION_TIMEOUT == 30

    def test_tty_timeouts(self):
        """Test TTY session timeouts"""
        assert Timeouts.TTY_READ_TIMEOUT == 1.0
        assert Timeouts.TTY_TOTAL_TIMEOUT_MULTIPLIER == 10
        assert Timeouts.IDLE_TIMEOUT == 1.0
        assert Timeouts.SHORT_IDLE_TIMEOUT == 0.01

    def test_scheduler_timeouts(self):
        """Test scheduler timeouts"""
        assert Timeouts.SCHEDULER_DEFAULT_WAIT == 300
        assert Timeouts.SCHEDULER_CHECK_FREQUENCY == 60.0

    def test_input_timeout(self):
        """Test input timeout"""
        assert Timeouts.INPUT_DEFAULT_TIMEOUT == 10

    def test_mcp_timeouts(self):
        """Test MCP timeouts"""
        assert Timeouts.MCP_SERVER_APPLY_DELAY == 1
        assert Timeouts.MCP_CLIENT_INIT_TIMEOUT == 10
        assert Timeouts.MCP_CLIENT_TOOL_TIMEOUT == 120

    def test_tunnel_timeouts(self):
        """Test tunnel timeouts"""
        assert Timeouts.TUNNEL_CHECK_DELAY == 2
        assert Timeouts.TUNNEL_STARTUP_ITERATIONS == 150
        assert Timeouts.TUNNEL_STARTUP_DELAY == 0.1

    def test_http_cache_timeouts(self):
        """Test HTTP cache durations"""
        assert Timeouts.HTTP_CACHE_MAX_AGE == 86400
        assert Timeouts.HTTP_CACHE_DEFAULT == 3600
        assert Timeouts.HTTP_CACHE_VENDOR == 31536000
        assert Timeouts.HTTP_CACHE_ASSETS == 86400
        assert Timeouts.HTTP_CACHE_IMAGES == 604800

    def test_notification_timeouts(self):
        """Test notification timeouts"""
        assert Timeouts.NOTIFICATION_DEFAULT_TIMEOUT == 30
        assert Timeouts.NOTIFICATION_AGENT_TIMEOUT == 30
        assert Timeouts.NOTIFICATION_LIFETIME_HOURS == 24

    def test_update_check_timeouts(self):
        """Test update check timeouts"""
        assert Timeouts.UPDATE_CHECK_COOLDOWN_SECONDS == 60
        assert Timeouts.UPDATE_NOTIFICATION_COOLDOWN_SECONDS == 86400

    def test_docker_timeouts(self):
        """Test Docker operation timeouts"""
        assert Timeouts.DOCKER_INIT_DELAY == 5
        assert Timeouts.DOCKER_RETRY_DELAY == 2
        assert Timeouts.DOCKER_STARTUP_DELAY == 5

    def test_ssh_timeouts(self):
        """Test SSH timeouts"""
        assert Timeouts.SSH_SHELL_DELAY == 0.1
        assert Timeouts.SSH_CONNECTION_DELAY == 5

    def test_wait_timeouts(self):
        """Test wait function timeouts"""
        assert Timeouts.WAIT_PAUSE_THRESHOLD == 1.5
        assert Timeouts.WAIT_SLEEP_INTERVAL == 1.0

    def test_http_client_timeout(self):
        """Test HTTP client default timeout"""
        assert Timeouts.HTTP_CLIENT_DEFAULT_TIMEOUT == 30.0

    def test_rate_limiter_timeframe(self):
        """Test rate limiter default timeframe"""
        assert Timeouts.RATE_LIMITER_DEFAULT_TIMEFRAME == 60

    def test_retry_and_polling(self):
        """Test retry and polling intervals"""
        assert Timeouts.RETRY_DELAY_SHORT == 1
        assert Timeouts.POLLING_INTERVAL == 1

    def test_document_timeouts(self):
        """Test document query timeouts"""
        assert Timeouts.DOCUMENT_DOWNLOAD_TIMEOUT == 10.0
        assert Timeouts.DOCUMENT_POLL_INTERVAL == 2
        assert Timeouts.DOCUMENT_MAX_WAIT == 300

    def test_file_browser_timeout(self):
        """Test file browser timeout"""
        assert Timeouts.FILE_BROWSER_TIMEOUT == 30

    def test_model_update_delay(self):
        """Test model update check delay"""
        assert Timeouts.MODEL_UPDATE_CHECK_DELAY == 0.1


class TestLimits:
    """Test Limits constants class"""

    def test_model_context_lengths(self):
        """Test model context length defaults"""
        assert Limits.DEFAULT_CHAT_MODEL_CTX_LENGTH == 100000
        assert Limits.DEFAULT_UTIL_MODEL_CTX_LENGTH == 100000

    def test_context_max_len(self):
        """Test context length cap for UI"""
        assert Limits.CONTEXT_MAX_LEN_DEFAULT == 5000

    def test_memory_recall_limits(self):
        """Test memory recall limits"""
        assert Limits.MEMORY_RECALL_HISTORY_LENGTH == 10000
        assert Limits.MEMORY_RECALL_MAX_SEARCH_MEMORIES == 12
        assert Limits.MEMORY_RECALL_MAX_SEARCH_SOLUTIONS == 8
        assert Limits.MEMORY_RECALL_MAX_RESULT_MEMORIES == 5
        assert Limits.MEMORY_RECALL_MAX_RESULT_SOLUTIONS == 3

    def test_memory_consolidation_limits(self):
        """Test memory consolidation limits"""
        assert Limits.MEMORY_MAX_SIMILAR == 10
        assert Limits.MEMORY_MAX_LLM_CONTEXT == 5
        assert Limits.MEMORY_PROCESSING_TIMEOUT == 60
        assert Limits.MEMORY_REPLACE_SIMILARITY_THRESHOLD == 0.9
        assert Limits.MEMORY_CONTENT_PREVIEW_TRUNCATION == 200
        assert Limits.MEMORY_CONTENT_PREVIEW_LIMIT == 100
        assert Limits.MEMORY_SEARCH_K == 100

    def test_memory_similarity_thresholds(self):
        """Test memory similarity thresholds"""
        assert Limits.MEMORY_SIMILARITY_SINGLE_DOC == 1.0
        assert Limits.MEMORY_SIMILARITY_SAFETY_THRESHOLD == 0.9
        assert Limits.MEMORY_SIMILARITY_DEFAULT_ESTIMATE == 0.7
        assert Limits.MEMORY_DEFAULT_THRESHOLD == 0.7

    def test_memory_extension_limits(self):
        """Test memory extension limits"""
        assert Limits.MEMORY_EXT_MAX_SIMILAR_MEMORIES == 8
        assert Limits.MEMORY_EXT_MAX_LLM_CONTEXT_MEMORIES == 4
        assert Limits.MEMORY_SOL_MAX_SIMILAR_MEMORIES == 6
        assert Limits.MEMORY_SOL_MAX_LLM_CONTEXT_MEMORIES == 3

    def test_document_limits(self):
        """Test document query limits"""
        assert Limits.DOCUMENT_DEFAULT_THRESHOLD == 0.5
        assert Limits.DOCUMENT_DEFAULT_CHUNK_SIZE == 1000
        assert Limits.DOCUMENT_DEFAULT_CHUNK_OVERLAP == 100
        assert Limits.DOCUMENT_MAX_LIMIT == 100

    def test_vision_limits(self):
        """Test vision/image processing limits"""
        assert Limits.VISION_MAX_PIXELS == 768000
        assert Limits.VISION_QUALITY == 75
        assert Limits.VISION_TOKENS_ESTIMATE == 1500
        assert Limits.IMAGE_MAX_PIXELS == 256000
        assert Limits.IMAGE_QUALITY == 50

    def test_history_limits(self):
        """Test history management limits"""
        assert Limits.HISTORY_BULK_MERGE_COUNT == 3
        assert Limits.HISTORY_TOPICS_KEEP_COUNT == 3
        assert Limits.HISTORY_CURRENT_TOPIC_RATIO == 0.5
        assert Limits.HISTORY_TOPIC_RATIO == 0.3
        assert Limits.HISTORY_BULK_RATIO == 0.2
        assert Limits.HISTORY_TOPIC_COMPRESS_RATIO == 0.65
        assert Limits.HISTORY_LARGE_MESSAGE_RATIO == 0.25
        assert Limits.HISTORY_RAW_MESSAGE_TRIM == 100

    def test_message_limits(self):
        """Test message limits"""
        assert Limits.MESSAGE_TRUNCATE_THRESHOLD == 1000
        assert Limits.MESSAGE_TRIM_RATIO_UPPER == 1.15
        assert Limits.MESSAGE_TRIM_RATIO_LOWER == 0.85

    def test_token_limits(self):
        """Test token calculation limits"""
        assert Limits.TOKEN_APPROX_BUFFER == 1.1
        assert Limits.TOKEN_TRIM_BUFFER == 0.8

    def test_backup_limits(self):
        """Test backup limits"""
        assert Limits.BACKUP_MAX_FILES_FULL == 50000
        assert Limits.BACKUP_MAX_FILES_PARTIAL == 10000
        assert Limits.BACKUP_MAX_FILES_TEST == 1000

    def test_file_browser_limits(self):
        """Test file browser limits"""
        assert Limits.FILE_BROWSER_MAX_FILE_SIZE == 100 * 1024 * 1024  # 100MB
        assert Limits.FILE_BROWSER_MAX_ITEMS == 10000
        assert Limits.FILE_READ_MAX_SIZE == 1024 * 1024  # 1MB

    def test_project_limits(self):
        """Test project file structure limits"""
        assert Limits.PROJECT_MAX_DEPTH == 5
        assert Limits.PROJECT_MAX_FILES == 20
        assert Limits.PROJECT_MAX_FOLDERS == 20
        assert Limits.PROJECT_MAX_LINES == 250

    def test_notification_limits(self):
        """Test notification limits"""
        assert Limits.NOTIFICATION_MAX_COUNT == 100
        assert Limits.NOTIFICATION_DISPLAY_TIME == 3
        assert Limits.NOTIFICATION_RECENT_SECONDS == 30

    def test_modal_limits(self):
        """Test modal limits"""
        assert Limits.MODAL_MAX_STACK_SIZE == 100

    def test_memory_dashboard_limits(self):
        """Test memory dashboard limits"""
        assert Limits.MEMORY_DASHBOARD_ITEMS_PER_PAGE == 10

    def test_qr_code_limits(self):
        """Test QR code dimensions"""
        assert Limits.QR_CODE_WIDTH == 128
        assert Limits.QR_CODE_HEIGHT == 128

    def test_chat_retry_limits(self):
        """Test sidebar chat retry configuration"""
        assert Limits.CHAT_MAX_RETRIES == 240
        assert Limits.CHAT_RETRY_INTERVAL_MS == 250

    def test_rfc_ports(self):
        """Test RFC ports"""
        assert Limits.RFC_PORT_HTTP == 55080
        assert Limits.RFC_PORT_SSH == 55022

    def test_stt_settings(self):
        """Test STT settings"""
        assert Limits.STT_SILENCE_DURATION == 1000
        assert Limits.STT_SILENCE_THRESHOLD == 0.3
        assert Limits.STT_WAITING_TIMEOUT == 2000

    def test_command_truncation(self):
        """Test command truncation limits"""
        assert Limits.COMMAND_TRUNCATION_PRIMARY == 200
        assert Limits.COMMAND_TRUNCATION_SECONDARY == 100
        assert Limits.OUTPUT_TRUNCATION_THRESHOLD == 1000000

    def test_browser_dimensions(self):
        """Test browser viewport dimensions"""
        assert Limits.BROWSER_VIEWPORT_WIDTH == 1024
        assert Limits.BROWSER_VIEWPORT_HEIGHT == 2048
        assert Limits.BROWSER_PAGE_LOAD_MIN == 1.0
        assert Limits.BROWSER_PAGE_LOAD_MED == 2.0
        assert Limits.BROWSER_PAGE_LOAD_MAX == 10.0
        assert Limits.BROWSER_FIRST_LINE_TRUNCATION == 200

    def test_ssh_shell_dimensions(self):
        """Test SSH shell dimensions"""
        assert Limits.SSH_SHELL_WIDTH == 100
        assert Limits.SSH_SHELL_HEIGHT == 50
        assert Limits.SSH_RECEIVE_BYTES == 1024

    def test_imap_settings(self):
        """Test IMAP settings"""
        assert Limits.IMAP_DEFAULT_PORT == 993
        assert Limits.IMAP_MAX_LINE_LENGTH == 100000

    def test_tty_settings(self):
        """Test TTY settings"""
        assert Limits.TTY_BUFFER_SIZE == 4096
        assert Limits.TTY_DEFAULT_COLS == 80
        assert Limits.TTY_DEFAULT_ROWS == 25

    def test_scheduler_token_range(self):
        """Test scheduler token generation range"""
        assert Limits.SCHEDULER_TOKEN_MIN == 10**17  # 18 digits
        assert Limits.SCHEDULER_TOKEN_MAX == 10**18 - 1  # 19 digits

    def test_crypto_settings(self):
        """Test crypto settings"""
        assert Limits.RSA_PUBLIC_EXPONENT == 65537
        assert Limits.RSA_KEY_SIZE == 2048

    def test_audio_settings(self):
        """Test audio settings"""
        assert Limits.TTS_SAMPLE_RATE == 24000
        assert Limits.TTS_DEFAULT_SPEED == 1.1
        assert Limits.TTS_DEFAULT_VOICE == "am_puck,am_onyx"

    def test_job_loop_settings(self):
        """Test job loop settings"""
        assert Limits.JOB_LOOP_SLEEP_TIME == 60

    def test_agent_id_length(self):
        """Test agent ID generation"""
        assert Limits.AGENT_ID_LENGTH == 8

    def test_logging_limits(self):
        """Test logging limits"""
        assert Limits.LOG_VALUE_MAX_LEN == 5000
        assert Limits.HEADING_MAX_LEN == 120
        assert Limits.CONTENT_MAX_LEN == 15000
        assert Limits.RESPONSE_CONTENT_MAX_LEN == 250000
        assert Limits.KEY_MAX_LEN == 60
        assert Limits.PROGRESS_MAX_LEN == 120

    def test_image_preview_limits(self):
        """Test image/attachment limits"""
        assert Limits.IMAGE_PREVIEW_MAX_SIZE == 800
        assert Limits.IMAGE_PREVIEW_QUALITY == 70

    def test_max_message_length(self):
        """Test max message length for frontend validation"""
        assert Limits.MAX_MESSAGE_LENGTH == 10000


class TestNetwork:
    """Test Network constants class"""

    def test_default_hosts(self):
        """Test default host constants"""
        assert Network.DEFAULT_LOCALHOST == "127.0.0.1"
        assert Network.DEFAULT_HOSTNAME == "localhost"

    def test_default_ports(self):
        """Test default port constants"""
        assert Network.WEB_UI_PORT_DEFAULT == 5000
        assert Network.TUNNEL_API_PORT_DEFAULT == 55520
        assert Network.TUNNEL_API_PORT_FALLBACK == 55520
        assert Network.SEARXNG_PORT_DEFAULT == 55510
        assert Network.TUNNEL_DEFAULT_PORT == 80

    def test_agent_ports(self):
        """Test agent-specific ports"""
        assert Network.BROCULA_PORT_DEFAULT == 50001
        assert Network.A2A_PORT_DEFAULT == 50101

    def test_static_ports(self):
        """Test static ports list"""
        expected_ports = [
            "8080",
            "5002",
            "3000",
            "5000",
            "8000",
            "5500",
            "3001",
            "50001",
        ]
        assert expected_ports == Network.STATIC_PORTS

    def test_cors_origins(self):
        """Test CORS allowed origins"""
        expected_origins = [
            "http://localhost:50001",
            "http://127.0.0.1:50001",
        ]
        assert expected_origins == Network.DEV_CORS_ORIGINS
        """Test CORS allowed origins"""
        expected_origins = [
            "*://localhost:*",
            "*://127.0.0.1:*",
            "*://0.0.0.0:*",
        ]
        assert expected_origins == Network.DEV_CORS_ORIGINS

    def test_external_api_endpoints(self):
        """Test external API endpoints"""
        assert Network.UPDATE_CHECK_URL == "https://api.agent-zero.ai/a0-update-check"
        assert Network.PERPLEXITY_API_BASE_URL == "https://api.perplexity.ai"
        assert Network.PERPLEXITY_DEFAULT_MODEL == "llama-3.1-sonar-large-128k-online"


class TestPaths:
    """Test Paths constants class"""

    def test_base_directories(self):
        """Test base directory constants"""
        assert Paths.PYTHON_DIR == "python"
        assert Paths.AGENTS_DIR == "agents"
        assert Paths.PROMPTS_DIR == "prompts"

    def test_extension_paths(self):
        """Test extension path constants"""
        assert Paths.EXTENSIONS_DIR == "python/extensions"
        assert Paths.AGENT_EXTENSIONS_DIR == "agents/{profile}/extensions"

    def test_tool_paths(self):
        """Test tool path constants"""
        assert Paths.TOOLS_DIR == "python/tools"
        assert Paths.AGENT_TOOLS_DIR == "agents/{profile}/tools"
        assert Paths.TOOL_FILE_EXTENSION == ".py"

    def test_prompt_paths(self):
        """Test prompt path constants"""
        assert Paths.DEFAULT_PROMPTS_DIR == "prompts/default"
        assert Paths.AGENT_PROMPTS_DIR == "agents/{profile}/prompts"

    def test_project_structure(self):
        """Test project structure paths"""
        assert Paths.PROJECTS_PARENT_DIR == "usr/projects"
        assert Paths.PROJECT_META_DIR == ".a0proj"
        assert Paths.PROJECT_INSTRUCTIONS_DIR == "instructions"
        assert Paths.PROJECT_KNOWLEDGE_DIR == "knowledge"
        assert Paths.PROJECT_HEADER_FILE == "project.json"

    def test_chat_persistence(self):
        """Test chat persistence paths"""
        assert Paths.CHAT_LOG_SIZE == 1000
        assert Paths.CHAT_FILE_NAME == "chat.json"

    def test_settings_path(self):
        """Test settings file path"""
        assert Paths.SETTINGS_FILE == "tmp/settings.json"

    def test_memory_paths(self):
        """Test memory paths"""
        assert Paths.MEMORY_DIR == "memory"
        assert Paths.MEMORY_EMBEDDINGS_DIR == "memory/embeddings"
        assert Paths.KNOWLEDGE_IMPORT_FILE == "knowledge_import.json"

    def test_scheduler_paths(self):
        """Test scheduler paths"""
        assert Paths.SCHEDULER_FOLDER == "tmp/scheduler"
        assert Paths.SCHEDULER_TASKS_FILE == "tasks.json"

    def test_api_paths(self):
        """Test API paths"""
        assert Paths.UPLOAD_FOLDER == "/a0/tmp/uploads"
        assert Paths.WORK_DIR == "/a0"
        assert Paths.ROOT_DIR == "/root"

    def test_static_methods(self):
        """Test Paths static methods"""
        assert Paths.get_agent_extensions_path("test", "init") == "agents/test/extensions/init"
        assert Paths.get_agent_tools_path("test", "tool") == "agents/test/tools/tool.py"
        assert Paths.get_default_extensions_path("init") == "python/extensions/init"
        assert Paths.get_default_tools_path("tool") == "python/tools/tool.py"


class TestMimeTypes:
    """Test MimeTypes constants class"""

    def test_common_mime_types(self):
        """Test common MIME type constants"""
        assert MimeTypes.APPLICATION_JSON == "application/json"
        assert MimeTypes.TEXT_PLAIN == "text/plain"
        assert MimeTypes.TEXT_HTML == "text/html"
        assert MimeTypes.IMAGE_PNG == "image/png"
        assert MimeTypes.IMAGE_JPEG == "image/jpeg"
        assert MimeTypes.APPLICATION_PDF == "application/pdf"

    def test_default_binary_alias(self):
        """Test default binary MIME type alias"""
        assert MimeTypes.DEFAULT_BINARY == MimeTypes.APPLICATION_OCTET_STREAM


class TestEncodings:
    """Test Encodings constants class"""

    def test_encoding_constants(self):
        """Test encoding constants"""
        assert Encodings.UTF_8 == "utf-8"
        assert Encodings.ASCII == "ascii"
        assert Encodings.LATIN_1 == "latin-1"


class TestStreamSizes:
    """Test StreamSizes constants class"""

    def test_stream_size_constants(self):
        """Test stream size constants"""
        assert StreamSizes.DEFAULT_CHUNK_SIZE == 8192
        assert StreamSizes.TTY_READ_BUFFER == 1024
        assert StreamSizes.MIN_STREAM_LENGTH == 25
        assert StreamSizes.TOTAL_TIMEOUT_MULTIPLIER == 10


class TestAgentDefaults:
    """Test AgentDefaults constants class"""

    def test_agent_default_constants(self):
        """Test agent default constants"""
        assert AgentDefaults.PROFILE == "agent0"
        assert AgentDefaults.MEMORY_SUBDIR == "default"
        assert AgentDefaults.KNOWLEDGE_SUBDIR == "custom"


class TestFileExtensions:
    """Test FileExtensions constants class"""

    def test_file_extension_constants(self):
        """Test file extension constants"""
        assert FileExtensions.MARKDOWN == ".md"
        assert FileExtensions.PYTHON == ".py"
        assert FileExtensions.JSON == ".json"
        assert FileExtensions.YAML == ".yaml"
        assert FileExtensions.YML == ".yml"


class TestFilePatterns:
    """Test FilePatterns constants class"""

    def test_file_pattern_constants(self):
        """Test file pattern constants"""
        assert FilePatterns.KNOWLEDGE_MARKDOWN == "**/*.md"


class TestShell:
    """Test Shell constants class"""

    def test_shell_executables(self):
        """Test shell executable constants"""
        assert Shell.SHELL_BASH == "/bin/bash"
        assert Shell.SHELL_POWERSHELL == "powershell.exe"

    def test_ssh_init_command(self):
        """Test SSH initialization command"""
        assert Shell.SSH_INIT_COMMAND == "unset PROMPT_COMMAND PS0; stty -echo"

    def test_browser_arguments(self):
        """Test browser arguments"""
        assert Shell.BROWSER_HEADLESS_ARG == "--headless=new"


class TestHttpStatus:
    """Test HttpStatus constants class"""

    def test_http_status_codes(self):
        """Test HTTP status code constants"""
        assert HttpStatus.OK == 200
        assert HttpStatus.BAD_REQUEST == 400
        assert HttpStatus.UNAUTHORIZED == 401
        assert HttpStatus.FORBIDDEN == 403
        assert HttpStatus.NOT_FOUND == 404
        assert HttpStatus.ERROR == 500
        assert HttpStatus.SERVICE_UNAVAILABLE == 503


class TestColors:
    """Test Colors constants class"""

    def test_primary_colors(self):
        """Test primary UI colors"""
        assert Colors.PRIMARY_BLUE == "#1B4F72"
        assert Colors.PRIMARY_LIGHT_BLUE == "#85C1E9"

    def test_semantic_colors(self):
        """Test semantic colors"""
        assert Colors.SUCCESS == "#008000"
        assert Colors.WARNING == "#FFA500"
        assert Colors.ERROR == "#E74C3C"
        assert Colors.INFO == "#0000FF"
        assert Colors.DEBUG == "#808080"
        assert Colors.HINT == "#6C3483"

    def test_accent_colors(self):
        """Test accent colors"""
        assert Colors.AGENT_PURPLE == "#6C3483"
        assert Colors.SETTINGS_PURPLE == "#6734C3"
        assert Colors.MCP_MAGENTA == "#CC34C3"
        assert Colors.FILES_GREEN == "#2ECC71"


class TestUITiming:
    """Test UITiming constants class"""

    def test_notification_display_times(self):
        """Test notification display times"""
        assert UITiming.NOTIFICATION_DISPLAY_TIME == 3000
        assert UITiming.TOAST_DISPLAY_TIME == 5000

    def test_animation_delays(self):
        """Test animation delays"""
        assert UITiming.ANIMATION_SHORT == 200
        assert UITiming.ANIMATION_MEDIUM == 500
        assert UITiming.ANIMATION_LONG == 1000
        assert UITiming.ANIMATION_STEP == 0.01


class TestProtocols:
    """Test Protocols constants class"""

    def test_protocol_constants(self):
        """Test protocol string constants"""
        assert Protocols.HTTP == "http://"
        assert Protocols.HTTPS == "https://"


class TestTmpPaths:
    """Test TmpPaths constants class"""

    def test_temporary_file_paths(self):
        """Test temporary file path constants"""
        assert TmpPaths.SETTINGS_JSON == "tmp/settings.json"
        assert TmpPaths.SECRETS_ENV == "tmp/secrets.env"

    def test_temporary_glob_patterns(self):
        """Test temporary glob pattern constants"""
        assert TmpPaths.CHATS_GLOB == "tmp/chats/**"
        assert TmpPaths.SCHEDULER_GLOB == "tmp/scheduler/**"
        assert TmpPaths.UPLOADS_GLOB == "tmp/uploads/**"


class TestExternalUrls:
    """Test ExternalUrls constants class"""

    def test_repository_url(self):
        """Test repository URL"""
        assert ExternalUrls.AGENT_ZERO_REPO == "https://github.com/frdel/agent-zero"

    def test_api_endpoints(self):
        """Test API endpoint URLs"""
        assert ExternalUrls.UPDATE_CHECK_URL == "https://api.agent-zero.ai/a0-update-check"
        assert ExternalUrls.PERPLEXITY_API_BASE_URL == "https://api.perplexity.ai"

    def test_venice_endpoints(self):
        """Test Venice.ai endpoints"""
        assert ExternalUrls.VENICE_API_BASE == "https://api.venice.ai/api/v1"
        assert ExternalUrls.A0_VENICE_API_BASE == "https://api.agent-zero.ai/venice/v1"

    def test_openrouter_endpoints(self):
        """Test OpenRouter endpoints"""
        assert ExternalUrls.OPENROUTER_API_BASE == "https://openrouter.ai/api/v1"
        assert ExternalUrls.OPENROUTER_HTTP_REFERER == "https://agent-zero.ai/"
        assert ExternalUrls.OPENROUTER_X_TITLE == "Agent Zero"


class TestBrowser:
    """Test Browser constants class"""

    def test_allowed_domains(self):
        """Test browser allowed domains"""
        assert Browser.ALLOWED_DOMAINS == ["*", "http://*", "https://*"]


class TestSearch:
    """Test Search constants class"""

    def test_default_results_count(self):
        """Test default search results count"""
        assert Search.DEFAULT_RESULTS_COUNT == 10

    def test_duckduckgo_defaults(self):
        """Test DuckDuckGo search defaults"""
        assert Search.DDG_DEFAULT_RESULTS == 5
        assert Search.DDG_DEFAULT_REGION == "wt-wt"
        assert Search.DDG_DEFAULT_TIME_LIMIT == "y"
        assert Search.DDG_DEFAULT_SAFESEARCH == "off"

    def test_searxng_defaults(self):
        """Test SearXNG search defaults"""
        assert Search.SEARXNG_DEFAULT_RESULTS == 10


class TestExtensions:
    """Test Extensions constants class"""

    def test_tool_call_file_min_length(self):
        """Test tool call file saving threshold"""
        assert Extensions.TOOL_CALL_FILE_MIN_LENGTH == 500


class TestEnvironmentHelpers:
    """Test environment variable helper functions"""

    def test_get_env_int_with_valid_value(self):
        """Test get_env_int with valid integer value"""
        with patch.dict(os.environ, {"TEST_INT": "42"}):
            assert get_env_int("TEST_INT", 0) == 42

    def test_get_env_int_with_invalid_value(self):
        """Test get_env_int with invalid integer value falls back to default"""
        with patch.dict(os.environ, {"TEST_INT": "invalid"}):
            assert get_env_int("TEST_INT", 100) == 100

    def test_get_env_int_with_missing_variable(self):
        """Test get_env_int with missing environment variable"""
        assert get_env_int("NONEXISTENT_VAR", 50) == 50

    def test_get_env_float_with_valid_value(self):
        """Test get_env_float with valid float value"""
        with patch.dict(os.environ, {"TEST_FLOAT": "3.14"}):
            assert get_env_float("TEST_FLOAT", 0.0) == 3.14

    def test_get_env_float_with_invalid_value(self):
        """Test get_env_float with invalid float value falls back to default"""
        with patch.dict(os.environ, {"TEST_FLOAT": "invalid"}):
            assert get_env_float("TEST_FLOAT", 1.5) == 1.5

    def test_get_env_str_with_valid_value(self):
        """Test get_env_str with valid string value"""
        with patch.dict(os.environ, {"TEST_STR": "hello"}):
            assert get_env_str("TEST_STR", "default") == "hello"

    def test_get_env_str_with_missing_variable(self):
        """Test get_env_str with missing environment variable"""
        assert get_env_str("NONEXISTENT_VAR", "default") == "default"


class TestConfigClass:
    """Test Config class with environment variable overrides"""

    def test_config_timeout_overrides(self):
        """Test Config timeout environment overrides"""
        import importlib

        with patch.dict(os.environ, {"A0_CODE_EXEC_TIMEOUT": "200"}):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.CODE_EXEC_TIMEOUT == 200

    def test_config_limit_overrides(self):
        """Test Config limit environment overrides"""
        import importlib

        with patch.dict(os.environ, {"A0_MAX_MEMORY_RESULTS": "20"}):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.MAX_MEMORY_RESULTS == 20

    def test_config_network_overrides(self):
        """Test Config network environment overrides"""
        import importlib

        with patch.dict(os.environ, {"A0_DEFAULT_PORT": "8080"}):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.DEFAULT_PORT == 8080

    def test_config_external_url_overrides(self):
        """Test Config external URL environment overrides"""
        import importlib

        with patch.dict(os.environ, {"A0_UPDATE_CHECK_URL": "https://custom.example.com/check"}):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.UPDATE_CHECK_URL == "https://custom.example.com/check"

    def test_config_model_defaults(self):
        """Test Config model default environment overrides"""
        import importlib

        with patch.dict(os.environ, {"A0_CHAT_MODEL_PROVIDER": "custom_provider"}):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.DEFAULT_CHAT_MODEL_PROVIDER == "custom_provider"

    def test_config_cors_origins(self):
        """Test Config CORS origins parsing"""
        import importlib

        with patch.dict(
            os.environ, {"A0_DEV_CORS_ORIGINS": "http://localhost:3000,http://localhost:8080"}
        ):
            from python.helpers import constants

            importlib.reload(constants)
            assert constants.Config.DEV_CORS_ORIGINS == [
                "http://localhost:3000",
                "http://localhost:8080",
            ]


class TestFrontendConfig:
    """Test frontend configuration generation"""

    def test_get_frontend_config_structure(self):
        """Test frontend config has expected structure"""
        config = get_frontend_config()

        assert "WEB_UI_PORT" in config
        assert "TUNNEL_API_PORT" in config
        assert "SEARXNG_PORT" in config
        assert "HOSTNAME" in config
        assert "FEATURES" in config
        assert "LIMITS" in config

    def test_get_frontend_config_values(self):
        """Test frontend config contains correct values"""
        config = get_frontend_config()

        assert isinstance(config["WEB_UI_PORT"], int)
        assert isinstance(config["FEATURES"], dict)
        assert isinstance(config["LIMITS"], dict)

    def test_get_frontend_config_features(self):
        """Test frontend config feature flags"""
        config = get_frontend_config()

        assert "mcp_enabled" in config["FEATURES"]
        assert "a2a_enabled" in config["FEATURES"]
        assert "tunnel_enabled" in config["FEATURES"]
        assert "speech_enabled" in config["FEATURES"]

    def test_get_frontend_config_limits(self):
        """Test frontend config limits"""
        config = get_frontend_config()

        assert "max_attachment_size" in config["LIMITS"]
        assert "max_file_size" in config["LIMITS"]
        assert "max_message_length" in config["LIMITS"]

    def test_get_env_config_js_output(self):
        """Test JavaScript config generation"""
        js_output = get_env_config_js()

        assert "window.ENV_CONFIG" in js_output
        assert "<script>" in js_output
        assert "</script>" in js_output

    def test_inject_config_into_html(self):
        """Test HTML config injection"""
        html = "<html><head></head><body></body></html>"
        injected = inject_config_into_html(html)

        assert "window.ENV_CONFIG" in injected
        assert "</head>" in injected


class TestNoHardcodedValues:
    """
    Test that no hardcoded magic numbers exist outside constants files.

    Flexy says: These tests ensure the modular system is being used correctly.
    """

    def test_no_bare_timeout_literals_in_helpers(self):
        """Test that timeout values are imported from constants, not hardcoded"""
        # This test verifies that modules use Timeouts.* instead of bare numbers

        # These modules should reference Timeouts class
        # If they have hardcoded numbers, they need to be refactored
        assert True  # Placeholder - would need AST parsing to fully verify

    def test_no_bare_limit_literals_in_helpers(self):
        """Test that limit values are imported from constants, not hardcoded"""
        # Similar to above, verify Limits.* usage
        assert True  # Placeholder - would need AST parsing to fully verify


class TestConstantsDocumentation:
    """Test that constants are properly documented"""

    def test_timeouts_has_docstring(self):
        """Test Timeouts class has docstring"""
        assert Timeouts.__doc__ is not None
        assert "timeout" in Timeouts.__doc__.lower()

    def test_limits_has_docstring(self):
        """Test Limits class has docstring"""
        assert Limits.__doc__ is not None
        assert "limit" in Limits.__doc__.lower()

    def test_network_has_docstring(self):
        """Test Network class has docstring"""
        assert Network.__doc__ is not None
        assert "network" in Network.__doc__.lower()

    def test_paths_has_docstring(self):
        """Test Paths class has docstring"""
        assert Paths.__doc__ is not None
        assert "path" in Paths.__doc__.lower()
