/**
 * Scheduler Polling Module
 * Task fetching and polling logic
 */
import { getUserTimezone } from '../../time-utils.js';
import Logger from '../../logger.min.js';

/**
 * Show toast notification (imported from parent module)
 */
let showToast = null;

/**
 * Set the showToast function from parent
 * @param {Function} fn - Toast notification function
 */
export function setShowToast(fn) {
    showToast = fn;
}

/**
 * Start polling for task updates
 */
export function startPolling() {
    // Don't start if already polling
    if (this.pollingInterval) {
        Logger.debug('Polling already active, not starting again');
        return;
    }

    Logger.debug('Starting task polling');
    this.pollingActive = true;

    // Fetch immediately, then set up interval for every 2 seconds
    this.fetchTasks();
    this.pollingInterval = setInterval(() => {
        if (this.pollingActive) {
            this.fetchTasks();
        }
    }, 2000); // Poll every 2 seconds as requested
}

/**
 * Stop polling when tab is inactive
 */
export function stopPolling() {
    Logger.debug('Stopping task polling');
    this.pollingActive = false;

    if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
    }
}

/**
 * Fetch tasks from API
 */
export async function fetchTasks() {
    // Don't fetch if polling is inactive (prevents race conditions)
    if (!this.pollingActive && this.pollingInterval) {
        return;
    }

    // Don't fetch while creating/editing a task
    if (this.isCreating || this.isEditing) {
        return;
    }

    this.isLoading = true;
    try {
        const response = await fetchApi('/scheduler_tasks_list', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                timezone: getUserTimezone()
            })
        });

        if (!response.ok) {
            throw new Error('Failed to fetch tasks');
        }

        const data = await response.json();

        // Check if data.tasks exists and is an array
        if (!data || !data.tasks) {
            this.tasks = [];
        } else if (!Array.isArray(data.tasks)) {
            this.tasks = [];
        } else {
            // Verify each task has necessary properties
            const validTasks = data.tasks.filter(task => {
                if (!task || typeof task !== 'object') return false;
                if (!task.uuid) return false;
                if (!task.name) return false;
                if (!task.type) return false;
                return true;
            });

            this.tasks = validTasks;

            // Update UI using the shared function
            this.updateTasksUI();
        }
    } catch (error) {
        // Silently ignore backend unavailable errors - they're expected when server is down
        const isBackendUnavailable = error.message?.includes('CSRF token unavailable') ||
                                     error.message?.includes('CSRF token endpoint returned') ||
                                     error.message?.includes('backend not running') ||
                                     error.message?.includes('Failed to fetch');
        if (!isBackendUnavailable && !this.pollingInterval) {
            // Only show toast for errors on manual refresh, not during polling
            showToast('Failed to fetch tasks: ' + error.message, 'error');
        }
        // Reset tasks to empty array on error
        this.tasks = [];
    } finally {
        this.isLoading = false;
    }
}
