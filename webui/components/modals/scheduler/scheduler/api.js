// -----------------------------------------------------------------------------
// API layer for scheduler store
// -----------------------------------------------------------------------------
import { API, getUserTimezone } from "./constants.js";
import { ensureTaskValidity, normalizeTaskFromBackend } from "./helpers.js";

/**
 * Call a scheduler API endpoint
 * @param {string} endpoint - API endpoint
 * @param {Object} payload - Request payload
 * @param {string} defaultError - Default error message
 * @returns {Promise<Object>} API result
 */
async function callSchedulerEndpoint(endpoint, payload = {}, defaultError) {
  try {
    const response = await API(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return { ok: false, error: data?.error || defaultError || "Scheduler request failed" };
    }
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: error?.message || defaultError || "Scheduler request failed" };
  }
}

/**
 * Scheduler API methods
 */
export const schedulerApi = {
  /**
   * List all scheduler tasks
   * @returns {Promise<Object>} Result with tasks array
   */
  async listTasks() {
    const result = await callSchedulerEndpoint(
      "/scheduler_tasks_list",
      { timezone: getUserTimezone() },
      "Failed to fetch tasks"
    );
    if (!result.ok) return { ok: false, error: result.error };
    const rawTasks = Array.isArray(result.data?.tasks) ? result.data.tasks : [];
    const normalized = rawTasks
      .filter(ensureTaskValidity)
      .map((task) => normalizeTaskFromBackend(task))
      .filter(Boolean);
    return { ok: true, tasks: normalized };
  },

  /**
   * Create a new task
   * @param {Object} payload - Task payload
   * @returns {Promise<Object>} Result with created task
   */
  async createTask(payload) {
    const result = await callSchedulerEndpoint(
      "/scheduler_task_create",
      payload,
      "Failed to create task"
    );
    if (!result.ok) return { ok: false, error: result.error };
    const task = result.data?.task ? normalizeTaskFromBackend(result.data.task) : null;
    return { ok: true, task };
  },

  /**
   * Update an existing task
   * @param {Object} payload - Task payload with task_id
   * @returns {Promise<Object>} Result with updated task
   */
  async updateTask(payload) {
    const result = await callSchedulerEndpoint(
      "/scheduler_task_update",
      payload,
      "Failed to update task"
    );
    if (!result.ok) return { ok: false, error: result.error };
    const task = result.data?.task ? normalizeTaskFromBackend(result.data.task) : null;
    return { ok: true, task };
  },

  /**
   * Run a task immediately
   * @param {string} taskId - Task UUID
   * @returns {Promise<Object>} Result
   */
  async runTask(taskId) {
    return callSchedulerEndpoint(
      "/scheduler_task_run",
      { task_id: taskId, timezone: getUserTimezone() },
      "Failed to run task"
    );
  },

  /**
   * Delete a task
   * @param {string} taskId - Task UUID
   * @returns {Promise<Object>} Result
   */
  async deleteTask(taskId) {
    return callSchedulerEndpoint(
      "/scheduler_task_delete",
      { task_id: taskId, timezone: getUserTimezone() },
      "Failed to delete task"
    );
  },
};
