import Logger from './logger.js';
import { API } from './constants.js';

// Track if we're in static file mode (no backend)
let isStaticMode = false;
let staticModeChecked = false;

/**
 * Detect if we're running in static file mode (no backend API available)
 * Checks if the current page is served as a static file without the Flask backend
 * @returns {boolean} True if running in static mode
 */
function detectStaticMode() {
  // Check for indicators that we're in static file mode:
  // 1. URL contains file:// protocol
  // 2. Page is served from common static server ports
  const url = new URL(window.location.href);
  if (url.protocol === 'file:') return true;
  const staticPorts = window.ENV_CONFIG?.STATIC_PORTS || ['8080', '5002', '3000', '5000', '8000', '5500', '3001', '50001'];
  if (staticPorts.includes(url.port)) return true;

  // Check if we're on a static file server by looking at the response headers
  // Static servers typically don't set the same headers as Flask
  return false;
}

/**
 * Get whether we're in static mode (cached)
 * @returns {boolean}
 */
function isStaticFileMode() {
  if (!staticModeChecked) {
    isStaticMode = detectStaticMode();
    staticModeChecked = true;
  }
  return isStaticMode;
}

/**
 * Call a JSON-in JSON-out API endpoint
 * Data is automatically serialized
 * @param {string} endpoint - The API endpoint to call
 * @param {any} data - The data to send to the API
 * @returns {Promise<any>} The JSON response from the API
 */
export async function callJsonApi(endpoint, data) {
  const response = await fetchApi(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    credentials: "same-origin",
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(error);
  }
  const jsonResponse = await response.json();
  return jsonResponse;
}

/**
 * Fetch wrapper for A0 APIs that ensures token exchange
 * Automatically adds CSRF token to request headers
 * @param {string} url - The URL to fetch
 * @param {Object} [request] - The fetch request options
 * @returns {Promise<Response>} The fetch response
 */
export async function fetchApi(url, request) {
  async function _wrap(retry) {
    // get the CSRF token
    const token = await getCsrfToken();

    // create a new request object if none was provided
    const finalRequest = request || {};

    // ensure headers object exists
    finalRequest.headers = finalRequest.headers || {};

    // add the CSRF token to the headers
    finalRequest.headers["X-CSRF-Token"] = token;

    // perform the fetch with the updated request
    const response = await fetch(url, finalRequest);

    // check if there was an CSRF error
    if (response.status === 403 && retry) {
      // retry the request with new token
      csrfToken = null;
      return await _wrap(false);
    } else if (response.redirected && response.url.endsWith("/login")) {
      // redirect to login
      window.location.href = response.url;
      return;
    }

    // return the response
    return response;
  }

  // perform the request
  const response = await _wrap(true);

  // return the response
  return response;
}

// csrf token stored locally
let csrfToken = null;
let csrfTokenFailed = false;
let csrfTokenErrorLogged = false;

/**
 * Get the CSRF token for API requests
 * Caches the token after first request
 * @returns {Promise<string>} The CSRF token
 */
async function getCsrfToken() {
  if (csrfToken) return csrfToken;

  // Prevent repeated failed requests that spam the console
  if (csrfTokenFailed) {
    throw new Error("CSRF token unavailable - backend not running");
  }

  // Check if we're in static file mode to avoid unnecessary network errors
  if (isStaticFileMode()) {
    csrfTokenFailed = true;
    Logger.once('static_mode_skip', () => {
      Logger.debug("Static file mode detected - skipping CSRF token fetch");
    });
    throw new Error("Static file mode - no backend available");
  }

  try {
    const response = await fetch(API.CSRF_TOKEN_ENDPOINT, {
      credentials: "same-origin",
    });

    if (response.redirected && response.url.endsWith("/login")) {
      // redirect to login
      window.location.href = response.url;
      return;
    }

    // Check for 404 or other error status
    if (!response.ok) {
      csrfTokenFailed = true;
      // Log as debug instead of warn to keep console clean in static file mode
      Logger.once('csrf_error', () => {
        Logger.debug("Backend API not available - CSRF token endpoint returned", response.status);
      });
      throw new Error(`CSRF token endpoint returned ${response.status}`);
    }

    // Try to parse JSON, but handle non-JSON responses gracefully
    let json;
    try {
      json = await response.json();
    } catch (parseError) {
      csrfTokenFailed = true;
      Logger.once('csrf_json_error', () => {
        Logger.warn("Backend API not available - CSRF endpoint returned non-JSON response");
      });
      throw new Error("Invalid JSON response from CSRF endpoint");
    }

    if (json.ok) {
      csrfToken = json.token;
      document.cookie = `csrf_token_${json.runtime_id}=${csrfToken}; SameSite=Strict; Path=/`;
      return csrfToken;
    } else {
      if (json.error) alert(json.error);
      throw new Error(json.error || "Failed to get CSRF token");
    }
  } catch (error) {
    csrfTokenFailed = true;
    // Only log the first error to prevent console spam
    // Log as debug instead of warn to keep console clean in static file mode
    Logger.once('backend_connection_error', () => {
      Logger.debug("Backend connection not available - API calls will not work:", error.message);
    });
    throw error;
  }
}
