/**
 * Modular constants for Agent Zero WebUI
 * Flexy says: No hardcoded values allowed in JavaScript either!
 */

// =============================================================================
// API CONFIGURATION
// =============================================================================

export const API = {
  // Default ports
  WEB_UI_PORT: 5000,
  TUNNEL_API_PORT: 55520,
  SEARXNG_PORT: 55510,
  A2A_PORT: 50101,
  
  // Hosts
  LOCALHOST: "127.0.0.1",
  HOSTNAME: "localhost",
  
  // Endpoints
  CSRF_TOKEN_ENDPOINT: "/csrf_token",
  POLL_ENDPOINT: "/poll",
  LOGIN_ENDPOINT: "/login",
  
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
  
  // Debounce delays
  DEBOUNCE_INPUT: 300,
  DEBOUNCE_SEARCH: 500,
  DEBOUNCE_RESIZE: 250,
  
  // Timeouts
  API_TIMEOUT: 30000,
  STREAM_TIMEOUT: 300000,
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
};

// =============================================================================
// FILE EXTENSIONS
// =============================================================================

export const EXTENSIONS = {
  MARKDOWN: ".md",
  PYTHON: ".py",
  JAVASCRIPT: ".js",
  JSON: ".json",
  YAML: ".yaml",
  YML: ".yml",
  TEXT: ".txt",
};

// =============================================================================
// COLOR CONSTANTS (for consistency with Python backend)
// =============================================================================

export const COLORS = {
  // Primary colors
  PRIMARY_BLUE: "#1B4F72",
  PRIMARY_LIGHT_BLUE: "#85C1E9",
  
  // Semantic colors
  SUCCESS: "#008000",
  WARNING: "#FFA500",
  ERROR: "#E74C3C",
  INFO: "#0000FF",
  DEBUG: "#808080",
  HINT: "#6C3483",
  
  // Accent colors
  AGENT_PURPLE: "#6C3483",
  SETTINGS_PURPLE: "#6734C3",
  SETTINGS_DARK: "#334455",
  MCP_MAGENTA: "#CC34C3",
  MCP_ERROR_RED: "#AA4455",
  FILES_GREEN: "#2ECC71",
  STREAM_MINT: "#b3ffd9",
  
  // Background
  BG_WHITE: "white",
};

// =============================================================================
// STORAGE KEYS
// =============================================================================

export const STORAGE_KEYS = {
  CSRF_TOKEN: "csrf_token",
  SETTINGS: "a0_settings",
  THEME: "a0_theme",
  LANGUAGE: "a0_language",
};

// =============================================================================
// EVENT NAMES
// =============================================================================

export const EVENTS = {
  // Message events
  MESSAGE_RECEIVED: "message:received",
  MESSAGE_SENT: "message:sent",
  MESSAGE_UPDATED: "message:updated",
  
  // System events
  CONNECTED: "system:connected",
  DISCONNECTED: "system:disconnected",
  ERROR: "system:error",
  
  // UI events
  MODAL_OPEN: "ui:modal:open",
  MODAL_CLOSE: "ui:modal:close",
  NOTIFICATION_SHOW: "ui:notification:show",
};

// =============================================================================
// HTTP METHODS
// =============================================================================

export const HTTP_METHODS = {
  GET: "GET",
  POST: "POST",
  PUT: "PUT",
  DELETE: "DELETE",
  PATCH: "PATCH",
};

// =============================================================================
// CONTENT TYPES
// =============================================================================

export const CONTENT_TYPES = {
  JSON: "application/json",
  FORM_DATA: "multipart/form-data",
  TEXT: "text/plain",
  HTML: "text/html",
};
