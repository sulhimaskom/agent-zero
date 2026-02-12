/**
 * Production-safe logging utility
 * Logs are only shown in development mode or when explicitly enabled
 */
const Logger = {
  isDevelopment: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1',
  isDebugEnabled: localStorage.getItem('debug') === 'true',

  /**
   * Check if logging is enabled
   * @returns {boolean}
   */
  shouldLog() {
    return this.isDevelopment || this.isDebugEnabled;
  },

  /**
   * Log debug message (only in development)
   * @param {...any} args
   */
  debug(...args) {
    if (this.shouldLog()) {
      console.log('[DEBUG]', ...args);
    }
  },

  /**
   * Log info message (only in development)
   * @param {...any} args
   */
  info(...args) {
    if (this.shouldLog()) {
      console.info('[INFO]', ...args);
    }
  },

  /**
   * Log warning (always shown, but throttled in production)
   * @param {...any} args
   */
  warn(...args) {
    // Always show warnings, but mark them clearly
    console.warn('[WARN]', ...args);
  },

  /**
   * Log error (always shown)
   * @param {...any} args
   */
  error(...args) {
    console.error('[ERROR]', ...args);
  },

  /**
   * Log once - prevents duplicate messages
   * @param {string} key - Unique key for this message
   * @param {Function} logFn - Logging function to call
   */
  once(key, logFn) {
    if (!this._loggedKeys) this._loggedKeys = new Set();
    if (!this._loggedKeys.has(key)) {
      this._loggedKeys.add(key);
      logFn();
    }
  }
};

// Make available globally
window.Logger = Logger;

export default Logger;
