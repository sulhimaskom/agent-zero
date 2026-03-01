/**
 * Loading State Utility
 *
 * Provides unified loading state management for Alpine.js stores.
 * Addresses Issue #524: Unified Loading State Component
 *
 * Usage in stores:
 *   import { loadingMixin } from '/js/loading.js';
 *   const model = {
 *     ...loadingMixin,
 *     // your store properties
 *   };
 *
 * Usage in templates:
 *   <div x-show="$store.myStore.loading">Loading...</div>
 *   <button :disabled="$store.myStore.loading">Action</button>
 */

/**
 * Creates a loading state mixin for stores
 * @param {string} [initialState='loading'] - Property name for loading state
 * @returns {Object} Mixin object with loading state management
 */
export function loadingMixin(initialState = 'loading') {
  return {
    /**
     * Loading state - set to true during async operations
     * @type {boolean}
     */
    [initialState]: false,

    /**
     * Optional loading message for display
     * @type {string}
     */
    loadingMessage: '',

    /**
     * Set loading state to true with optional message
     * @param {string} [message=''] - Optional loading message
     */
    startLoading(message = '') {
      this[initialState] = true;
      this.loadingMessage = message;
    },

    /**
     * Set loading state to false and clear message
     */
    stopLoading() {
      this[initialState] = false;
      this.loadingMessage = '';
    },

    /**
     * Execute async function with loading state management
     * @param {Function} asyncFn - Async function to execute
     * @param {string} [message=''] - Optional loading message
     * @returns {Promise<any>} Result of the async function
     */
    async withLoading(asyncFn, message = '') {
      this.startLoading(message);
      try {
        return await asyncFn();
      } finally {
        this.stopLoading();
      }
    },
  };
}

/**
 * Creates loading state mixin with isLoading naming convention
 * @returns {Object} Mixin object with isLoading state management
 */
export function isLoadingMixin() {
  return loadingMixin('isLoading');
}

/**
 * Creates loading state mixin with multiple loading states
 * @param {string[]} states - Array of loading state names
 * @returns {Object} Mixin object with multiple loading states
 */
export function multiLoadingMixin(states = []) {
  const mixin = {
    loadingMessage: '',
  };

  for (const state of states) {
    mixin[state] = false;
    mixin[`start${capitalize(state)}`] = function () {
      this[state] = true;
    };
    mixin[`stop${capitalize(state)}`] = function () {
      this[state] = false;
    };
  }

  mixin.startLoading = function (message = '') {
    for (const state of states) {
      this[state] = true;
    }
    this.loadingMessage = message;
  };

  mixin.stopLoading = function () {
    for (const state of states) {
      this[state] = false;
    }
    this.loadingMessage = '';
  };

  return mixin;
}

// Helper function for capitalization
function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Loading Spinner Template
 * Returns HTML string for a loading spinner
 * @param {string} [message='Loading...'] - Optional message to display
 * @returns {string} HTML string for loading spinner
 */
export function loadingSpinner(message = 'Loading...') {
  return `
    <div class="loading-spinner-container">
      <svg class="spin" viewBox="0 0 50 50" width="24" height="24">
        <circle class="spinner-track" cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="4"></circle>
        <circle class="spinner-indicator" cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round"></circle>
      </svg>
      ${message ? `<span class="loading-message">${message}</span>` : ''}
    </div>
  `;
}

/**
 * Show loading indicator in a container element
 * @param {string} elementId - ID of the container element
 * @param {string} [message='Loading...'] - Optional message
 */
export function showLoading(elementId, message = 'Loading...') {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = loadingSpinner(message);
    element.style.display = 'block';
  }
}

/**
 * Hide loading indicator in a container element
 * @param {string} elementId - ID of the container element
 */
export function hideLoading(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = '';
    element.style.display = 'none';
  }
}

export default {
  loadingMixin,
  isLoadingMixin,
  multiLoadingMixin,
  loadingSpinner,
  showLoading,
  hideLoading,
};
