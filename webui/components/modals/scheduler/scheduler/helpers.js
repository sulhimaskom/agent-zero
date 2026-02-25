// -----------------------------------------------------------------------------
// Pure helper functions for scheduler store
// -----------------------------------------------------------------------------
import {
  DEFAULT_TASK_STATE,
  getUserTimezone,
  formatDateTime,
} from "./constants.js";

// -----------------------------------------------------------------------------
// Data Factories
// -----------------------------------------------------------------------------

/**
 * Create default schedule object
 * @returns {Object} Default schedule with cron fields
 */
export const defaultSchedule = () => ({
  minute: "*",
  hour: "*",
  day: "*",
  month: "*",
  weekday: "*",
  timezone: getUserTimezone(),
});

/**
 * Create empty plan object
 * @returns {Object} Empty plan with empty arrays
 */
export const emptyPlan = () => ({
  todo: [],
  in_progress: null,
  done: [],
});

/**
 * Create default editing task
 * @param {Object} overrides - Properties to override defaults
 * @returns {Object} Default editing task
 */
export const defaultEditingTask = (overrides = {}) => ({
  name: "",
  type: "scheduled",
  state: DEFAULT_TASK_STATE,
  schedule: defaultSchedule(),
  token: "",
  plan: emptyPlan(),
  system_prompt: "",
  prompt: "",
  attachments: [],
  project: null,
  dedicated_context: true,
  ...overrides,
});

// -----------------------------------------------------------------------------
// Persistence & Utilities
// -----------------------------------------------------------------------------

/**
 * Read persisted view mode from localStorage
 * @returns {string} View mode ('list' or 'calendar')
 */
export const readPersistedViewMode = () => {
  if (typeof window === "undefined") return "list";
  return window.localStorage?.getItem("scheduler_view_mode") || "list";
};

/**
 * Sleep for specified milliseconds
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
export const sleep = (ms = 0) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

// -----------------------------------------------------------------------------
// Normalization Functions
// -----------------------------------------------------------------------------

/**
 * Safely clone a value using JSON parse/stringify
 * @param {*} value - Value to clone
 * @returns {*} Cloned value
 */
export function safeJsonClone(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return value;
  }
}

/**
 * Normalize attachments to array of strings
 * @param {string|string[]|null} value - Attachments to normalize
 * @returns {string[]} Normalized array
 */
export function normalizeAttachments(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === "string" && item.trim().length > 0);
  }
  if (typeof value === "string") {
    return value
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }
  return [];
}

/**
 * Normalize schedule from various formats to object
 * @param {Object|string|null} schedule - Schedule to normalize
 * @returns {Object} Normalized schedule
 */
export function normalizeSchedule(schedule) {
  if (!schedule) return defaultSchedule();
  if (typeof schedule === "string") {
    const [minute = "*", hour = "*", day = "*", month = "*", weekday = "*"] = schedule
      .split(" ")
      .map((segment) => segment || "*");
    return {
      minute,
      hour,
      day,
      month,
      weekday,
      timezone: getUserTimezone(),
    };
  }
  return {
    minute: schedule.minute || "*",
    hour: schedule.hour || "*",
    day: schedule.day || "*",
    month: schedule.month || "*",
    weekday: schedule.weekday || "*",
    timezone: schedule.timezone || getUserTimezone(),
  };
}

/**
 * Normalize plan structure
 * @param {Object|null} plan - Plan to normalize
 * @returns {Object} Normalized plan
 */
export function normalizePlanStruct(plan) {
  if (!plan) return emptyPlan();
  const clone = {
    todo: Array.isArray(plan.todo) ? [...plan.todo] : [],
    in_progress: plan.in_progress || null,
    done: Array.isArray(plan.done) ? [...plan.done] : [],
  };
  const sanitized = clone.todo
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))
    .map((date) => date.toISOString())
    .sort();
  clone.todo = sanitized;
  clone.done = clone.done
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))
    .map((date) => date.toISOString());
  if (clone.in_progress) {
    const inProgress = new Date(clone.in_progress);
    clone.in_progress = Number.isNaN(inProgress.getTime())
      ? null
      : inProgress.toISOString();
  }
  return clone;
}

// -----------------------------------------------------------------------------
// Validation & Extraction
// -----------------------------------------------------------------------------

/**
 * Ensure task has required fields
 * @param {Object|null} task - Task to validate
 * @returns {boolean} Whether task is valid
 */
export function ensureTaskValidity(task) {
  return Boolean(task && task.uuid && task.name && task.type);
}

/**
 * Extract project info from task
 * @param {Object|null} task - Task to extract from
 * @returns {Object|null} Project info or null
 */
export function extractProjectInfo(task) {
  if (!task) return null;
  const slug = task.project_name || task.project?.name || null;
  const title = task.project?.title || task.project?.name || slug;
  const color = task.project_color || task.project?.color || "";
  if (!slug && !title) return null;
  return {
    name: slug,
    title: title || slug,
    color: color || "",
  };
}

// -----------------------------------------------------------------------------
// Task Composition
// -----------------------------------------------------------------------------

/**
 * Compose editing task with normalization
 * @param {Object} task - Task to compose
 * @returns {Object} Composed editing task
 */
export function composeEditingTask(task = {}) {
  const base = task && task.uuid ? { ...task } : { ...defaultEditingTask(), ...task };
  return {
    ...base,
    schedule: normalizeSchedule(base.schedule),
    plan: normalizePlanStruct(base.plan),
    attachments: normalizeAttachments(base.attachments),
    token: base.token || "",
    project: base.project || extractProjectInfo(base) || null,
    dedicated_context:
      typeof base.dedicated_context === "boolean" ? base.dedicated_context : true,
    state: base.state || DEFAULT_TASK_STATE,
  };
}

/**
 * Normalize task from backend
 * @param {Object|null} task - Task from backend
 * @returns {Object|null} Normalized task or null
 */
export function normalizeTaskFromBackend(task) {
  if (!ensureTaskValidity(task)) return null;
  return composeEditingTask(task);
}

/**
 * Build payload from editing task
 * @param {Object} editingTask - Editing task to build payload from
 * @param {Object} options - Options
 * @param {boolean} options.isCreating - Whether creating new task
 * @returns {Object} Payload for API
 */
export function buildPayloadFromEditingTask(editingTask, { isCreating = false } = {}) {
  const payload = {
    name: editingTask.name.trim(),
    system_prompt: editingTask.system_prompt || "",
    prompt: editingTask.prompt || "",
    state: editingTask.state || DEFAULT_TASK_STATE,
    timezone: getUserTimezone(),
    attachments: normalizeAttachments(editingTask.attachments),
    dedicated_context: editingTask.dedicated_context,
  };

  if (editingTask.type === "scheduled") {
    payload.schedule = normalizeSchedule(editingTask.schedule);
  }

  if (editingTask.type === "planned") {
    payload.plan = normalizePlanStruct(editingTask.plan);
  }

  if (editingTask.type === "adhoc") {
    payload.token = editingTask.token;
  }

  // Only send project fields when creating a new task (project changes are not allowed for existing tasks)
  if (isCreating && editingTask.project && editingTask.project.name) {
    payload.project_name = editingTask.project.name;
    if (editingTask.project.color) {
      payload.project_color = editingTask.project.color;
    }
  }

  if (!isCreating && editingTask.uuid) {
    payload.task_id = editingTask.uuid;
  }

  return payload;
}

// -----------------------------------------------------------------------------
// Sorting
// -----------------------------------------------------------------------------

/**
 * Sort tasks by date
 * @param {string} value - Date string
 * @returns {number} Timestamp
 */
export function sortByDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 0 : date.getTime();
}
