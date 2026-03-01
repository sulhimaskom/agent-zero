/**
 * Scheduler Formatting Module
 * Pure display formatting functions - no component state dependencies
 */
import { formatDateTime } from '../../time-utils.js';

/**
 * Format date for display
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date or 'Never'
 */
export function formatDate(dateString) {
  if (!dateString) return 'Never';
  return formatDateTime(dateString, 'full');
}

/**
 * Format plan for display
 * @param {Object} task - Task object with plan property
 * @returns {string} Formatted plan string
 */
export function formatPlan(task) {
  if (!task || !task.plan) return 'No plan';

  const todoCount = Array.isArray(task.plan.todo) ? task.plan.todo.length : 0;
  const inProgress = task.plan.in_progress ? 'Yes' : 'No';
  const doneCount = Array.isArray(task.plan.done) ? task.plan.done.length : 0;

  let nextRun = '';
  if (Array.isArray(task.plan.todo) && task.plan.todo.length > 0) {
    try {
      const nextTime = new Date(task.plan.todo[0]);

      // Verify it's a valid date before formatting
      if (!isNaN(nextTime.getTime())) {
        nextRun = formatDateTime(nextTime, 'short');
      } else {
        nextRun = 'Invalid date';
      }
    } catch (_error) {
      nextRun = 'Error';
    }
  } else {
    nextRun = 'None';
  }

  return `Next: ${nextRun}\nTodo: ${todoCount}\nIn Progress: ${inProgress}\nDone: ${doneCount}`;
}

/**
 * Format schedule for display
 * @param {Object|string} task - Task object with schedule property
 * @returns {string} Formatted schedule string
 */
export function formatSchedule(task) {
  if (!task.schedule) return 'None';

  let schedule = '';
  if (typeof task.schedule === 'string') {
    schedule = task.schedule;
  } else if (typeof task.schedule === 'object') {
    // Display only the cron parts, not the timezone
    schedule = `${task.schedule.minute || '*'} ${task.schedule.hour || '*'} ${task.schedule.day || '*'} ${task.schedule.month || '*'} ${task.schedule.weekday || '*'}`;
  }

  return schedule;
}

/**
 * Get CSS class for state badge
 * @param {string} state - Task state
 * @returns {string} CSS class name
 */
export function getStateBadgeClass(state) {
  switch (state) {
  case 'idle': return 'scheduler-status-idle';
  case 'running': return 'scheduler-status-running';
  case 'disabled': return 'scheduler-status-disabled';
  case 'error': return 'scheduler-status-error';
  default: return '';
  }
}
