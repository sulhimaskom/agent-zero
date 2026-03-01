/**
 * Modular constants for Agent Zero WebUI
 * Flexy says: No hardcoded values allowed in JavaScript either!
 */

// =============================================================================
// ENVIRONMENT CONFIGURATION
// Values can be overridden via window.ENV_CONFIG set at runtime
// =============================================================================

const getEnvConfig = (key, defaultValue) => {
  if (typeof window !== 'undefined' && window.ENV_CONFIG && window.ENV_CONFIG[key] !== undefined) {
    return window.ENV_CONFIG[key];
  }
  return defaultValue;
};

// =============================================================================
// API CONFIGURATION
// =============================================================================

export const API = {
  // Default ports
  WEB_UI_PORT: getEnvConfig('WEB_UI_PORT', 5000),
  TUNNEL_API_PORT: getEnvConfig('TUNNEL_API_PORT', 55520),
  SEARXNG_PORT: getEnvConfig('SEARXNG_PORT', 55510),
  A2A_PORT: getEnvConfig('A2A_PORT', 50101),

  // Hosts - Configurable via window.ENV_CONFIG
  LOCALHOST: getEnvConfig('LOCALHOST', '127.0.0.1'),
  HOSTNAME: getEnvConfig('HOSTNAME', 'localhost'),

  // Endpoints
  CSRF_TOKEN_ENDPOINT: getEnvConfig('CSRF_TOKEN_ENDPOINT', '/csrf_token'),
  POLL_ENDPOINT: '/poll',
  LOGIN_ENDPOINT: '/login',

  STATIC_PORTS: getEnvConfig('STATIC_PORTS', ['8080', '5002', '3000', '5000', '8000', '5500', '3001', '50001']),

  // Status codes
  STATUS_OK: 200,
  STATUS_UNAUTHORIZED: 401,
  STATUS_FORBIDDEN: 403,
  STATUS_NOT_FOUND: 404,
  STATUS_ERROR: 500,
};

// =============================================================================
// UI TIMING CONSTANTS (milliseconds)
// =============================================================================

export const TIMING = {
  // Display times
  NOTIFICATION_DISPLAY: 3000,
  TOAST_DISPLAY: 5000,
  SPEECH_DISPLAY: 5000,

  // Animation delays
  ANIMATION_SHORT: 200,
  ANIMATION_MEDIUM: 500,
  ANIMATION_LONG: 1000,

  // Polling intervals
  POLL_INTERVAL: 1000,
  POLL_INTERVAL_FAST: 500,
  SCHEDULER_POLL_INTERVAL: 2000,
  MCP_POLL_INTERVAL: 3000,

  // Debounce delays
  DEBOUNCE_INPUT: 300,
  DEBOUNCE_SEARCH: 500,
  DEBOUNCE_RESIZE: 250,

  // Timeouts
  API_TIMEOUT: 30000,
  STREAM_TIMEOUT: 300000,
  INPUT_DETECT_TIMEOUT: 10000,
  SETUP_DELAY: 100,
  UI_DELAY: 300,
  CHECK_DELAY: 100,
  IMAGE_REFRESH_INTERVAL: 1000,

  // Missing constants (fixes runtime errors)
  WELCOME_ANIMATION_DELAY: 350,
  SLEEP_MAX_TIMEOUT: 1000,

  // UI-specific intervals
  TYPING_INDICATOR_INTERVAL: 500,  // Dot animation interval in typing indicator
  USER_TIME_UPDATE_INTERVAL: 1000,  // User local time update interval
  ANIMATION_OPACITY_DURATION: 200,  // Opacity transition duration
};

// =============================================================================
// SPEECH CONSTANTS
// =============================================================================

export const SPEECH = {
  // Silence detection
  SILENCE_DURATION: 1000,
  WAITING_TIMEOUT: 2000,
  SILENCE_THRESHOLD: 0.15,
  MIN_SPEECH_DURATION: 500,

  // Recorder settings
  RECORDER_CHUNK_SIZE: 1000,

  // Model settings
  DEFAULT_MODEL_SIZE: 'tiny',
  DEFAULT_LANGUAGE: 'en',
};

// =============================================================================
// UI Z-INDEX CONSTANTS
// =============================================================================

export const UI = {
  BASE_Z_INDEX: 3000,
  Z_INDEX_STEP: 20,
  BACKDROP_OFFSET: 10,
};

// =============================================================================
// SIZE LIMITS
// =============================================================================

export const LIMITS = {
  // Message limits
  MAX_MESSAGE_LENGTH: 10000,
  MAX_ATTACHMENT_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB

  // Display limits
  MAX_VISIBLE_MESSAGES: 100,
  MAX_NOTIFICATIONS: 100,

  // Memory limits
  MAX_MEMORY_RESULTS: 10,
  MAX_SEARCH_RESULTS: 50,

  // Image/Preview limits
  IMAGE_MODAL_SIZE: 1000,
  IMAGE_PREVIEW_MAX_SIZE: 800,

  // Recorder chunk size
  RECORDER_CHUNK_SIZE: 1000,
};

// =============================================================================
// FILE EXTENSIONS
// =============================================================================

export const EXTENSIONS = {
  MARKDOWN: '.md',
  PYTHON: '.py',
  JAVASCRIPT: '.js',
  JSON: '.json',
  YAML: '.yaml',
  YML: '.yml',
  TEXT: '.txt',
};

// =============================================================================
// COLOR CONSTANTS (for consistency with Python backend)
// =============================================================================

export const COLORS = {
  // Primary colors
  PRIMARY_BLUE: '#1B4F72',
  PRIMARY_LIGHT_BLUE: '#85C1E9',

  // Semantic colors
  SUCCESS: '#008000',
  WARNING: '#FFA500',
  ERROR: '#E74C3C',
  INFO: '#0000FF',
  DEBUG: '#808080',
  HINT: '#6C3483',

  // Accent colors
  AGENT_PURPLE: '#6C3483',
  SETTINGS_PURPLE: '#6734C3',
  SETTINGS_DARK: '#334455',
  MCP_MAGENTA: '#CC34C3',
  MCP_ERROR_RED: '#AA4455',
  FILES_GREEN: '#2ECC71',
  STREAM_MINT: '#b3ffd9',

  // Background
  BG_WHITE: 'white',
};

// =============================================================================
// STORAGE KEYS
// =============================================================================

export const STORAGE_KEYS = {
  CSRF_TOKEN: 'csrf_token',
  SETTINGS: 'a0_settings',
  THEME: 'a0_theme',
  LANGUAGE: 'a0_language',

  // UI state keys
  DARK_MODE: 'darkMode',
  SPEECH: 'speech',
  LAST_SELECTED_CHAT: 'lastSelectedChat',
  LAST_SELECTED_TASK: 'lastSelectedTask',
  SIDEBAR_SECTIONS: 'sidebarSections',
  SETTINGS_ACTIVE_TAB: 'settingsActiveTab',
  SCHEDULER_VIEW_MODE: 'scheduler_view_mode',
  BACKUP_PREVIEW_MODE: 'backupPreviewMode',

  // Device/Feature keys
  MICROPHONE_SELECTED_DEVICE: 'microphoneSelectedDevice',
  MESSAGE_RESIZE_SETTINGS: 'messageResizeSettings',

  // Feature-specific keys
  TUNNEL_URL: 'agent_zero_tunnel_url',
  MEMORY_DASHBOARD_THRESHOLD: 'memoryDashboard_threshold',
  MEMORY_DASHBOARD_LIMIT: 'memoryDashboard_limit',

  // Debug keys
  DEBUG: 'debug',
};

// =============================================================================
// EVENT NAMES
// =============================================================================

export const EVENTS = {
  // Message events
  MESSAGE_RECEIVED: 'message:received',
  MESSAGE_SENT: 'message:sent',
  MESSAGE_UPDATED: 'message:updated',

  // System events
  CONNECTED: 'system:connected',
  DISCONNECTED: 'system:disconnected',
  ERROR: 'system:error',

  // UI events
  MODAL_OPEN: 'ui:modal:open',
  MODAL_CLOSE: 'ui:modal:close',
  NOTIFICATION_SHOW: 'ui:notification:show',
};

// =============================================================================
// HTTP METHODS
// =============================================================================

export const HTTP_METHODS = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  DELETE: 'DELETE',
  PATCH: 'PATCH',
};

// =============================================================================
// CONTENT TYPES
// =============================================================================

export const CONTENT_TYPES = {
  JSON: 'application/json',
  FORM_DATA: 'multipart/form-data',
  TEXT: 'text/plain',
  HTML: 'text/html',
};

// =============================================================================
// API ENDPOINTS
// =============================================================================

export const API_ENDPOINTS = {
  // Settings endpoints
  SETTINGS_GET: '/api/settings_get',
  SETTINGS_SAVE: '/api/settings_save',
  SETTINGS_STATUS: '/api/settings_status',
  TEST_CONNECTION: '/api/test_connection',

  // Chat endpoints
  MESSAGE_ASYNC: '/message_async',
  CHAT_LOAD: '/chat_load',
  CHAT_FILES_PATH_GET: '/chat_files_path_get',

  // Poll endpoint
  POLL: '/poll',

  // Scheduler endpoints
  SCHEDULER_TASKS_LIST: '/scheduler_tasks_list',

  // Tunnel endpoints
  TUNNEL_PROXY: '/tunnel_proxy',

  // Notification endpoints
  NOTIFICATION_CREATE: '/notification_create',
};

// =============================================================================
// RETRY CONFIGURATION
// =============================================================================

export const RETRY = {
  MAX_RETRIES: 3,
  INTERVAL_MS: 1000,
};

// =============================================================================
// QR CODE CONFIGURATION
// =============================================================================

export const QR_CODE = {
  WIDTH: 128,
  HEIGHT: 128,
};

// =============================================================================
// DEFAULT VALUES
// =============================================================================

export const DEFAULTS = {
  // Scheduler
  SCHEDULER_VIEW_MODE: 'list',
  SETTINGS_TAB: 'agent',
  BACKUP_PREVIEW_MODE: 'grouped',

  // Memory dashboard
  MEMORY_THRESHOLD: '0.6',
  MEMORY_LIMIT: '1000',

  // Notification
  MAX_TOASTS: 5,
  MAX_NOTIFICATIONS: 100,

  // Backup
  BACKUP_MAX_FILES: 10000,
};

// =============================================================================
// DOM SELECTORS
// =============================================================================

export const Selectors = {
  CONTAINER: '.container',
};

// =============================================================================
// TOAST/NOTIFICATION MESSAGES
// =============================================================================

export const MESSAGES = {
  // Success messages
  TUNNEL_CREATED: 'Tunnel created successfully',
  TUNNEL_URL_COPIED: 'Tunnel URL copied to clipboard!',
  CHAT_DELETED: 'Chat deleted successfully',
  CHATS_LOADED: 'Chats loaded.',
  BACKUP_CREATED: 'Backup created and downloaded successfully!',
  COPIED_TO_CLIPBOARD: 'Copied to clipboard!',

  // Progress messages
  CREATING_TUNNEL: 'Creating tunnel...',

  // Button labels
  SAVE: 'Save',
  CANCEL: 'Cancel',
  COPY: 'Copy to clipboard',
};
