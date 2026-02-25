// -----------------------------------------------------------------------------
// Imports
// -----------------------------------------------------------------------------
import { formatDateTime, getUserTimezone } from "/js/time-utils.js";

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------
const API = globalThis.fetchApi || globalThis.fetch;
const VIEW_MODE_STORAGE_KEY = "scheduler_view_mode";
const NOTIFICATION_DURATION = {
  success: 3,
  info: 3,
  warning: 4,
  error: 5,
};
const DEFAULT_TASK_STATE = "idle";
const TASK_TYPES = ["scheduled", "adhoc", "planned"];

// -----------------------------------------------------------------------------
// Type Definitions
// -----------------------------------------------------------------------------

/**
 * @typedef {Object} SchedulerPlan
 * @property {string[]} todo
 * @property {string|null} in_progress
 * @property {string[]} done
 */

/**
 * @typedef {Object} SchedulerProject
 * @property {string|null} name
 * @property {string|null} title
 * @property {string} color
 */

/**
 * @typedef {Object} SchedulerTask
 * @property {string} uuid
 * @property {string} name
 * @property {string} type
 * @property {string} state
 * @property {SchedulerPlan} plan
 * @property {Object|string} schedule
 * @property {string} token
 * @property {SchedulerProject|null} project
 * @property {string|null} project_name
 * @property {string} [project_color]
 * @property {string[]} attachments
 * @property {string} [system_prompt]
 * @property {string} [prompt]
 * @property {string} [created_at]
 * @property {string} [updated_at]
 * @property {string} [last_run]
 * @property {string} [last_result]
 */

/**
 * @typedef {Object} EditingTask
 * @property {string} [uuid]
 * @property {string} name
 * @property {string} type
 * @property {string} state
 * @property {SchedulerPlan} plan
 * @property {ReturnType<typeof defaultSchedule>} schedule
 * @property {string} token
 * @property {SchedulerProject|null} project
 * @property {boolean} dedicated_context
 * @property {string[]} attachments
 * @property {string} system_prompt
 * @property {string} prompt
 */

/**
 * @template T
 * @typedef {Object} SchedulerApiResult
 * @property {boolean} ok
 * @property {string} [error]
 * @property {T} [data]
 */

// -----------------------------------------------------------------------------
// Export for use by other modules
// -----------------------------------------------------------------------------
export {
  API,
  VIEW_MODE_STORAGE_KEY,
  NOTIFICATION_DURATION,
  DEFAULT_TASK_STATE,
  TASK_TYPES,
  formatDateTime,
  getUserTimezone,
};

export {
  // Types are for documentation only - they're not runtime values
  // but we export placeholder objects to make JSDoc work
};
