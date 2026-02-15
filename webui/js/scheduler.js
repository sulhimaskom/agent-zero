/**
 * Task Scheduler Component for Settings Modal
 * Manages scheduled and ad-hoc tasks through a dedicated settings tab
 */

import { formatDateTime, getUserTimezone } from './time-utils.js';
import { store as chatsStore } from "/components/sidebar/chats/chats-store.min.js"
import { store as  notificationsStore } from "/components/notifications/notification-store.min.js"
import { store as projectsStore } from "/components/projects/projects-store.min.js"
import { TIMING } from './constants.js';
import Logger from './logger.min.js';

const showToast = function(message, type = 'info') {
    // Use new frontend notification system
    switch (type.toLowerCase()) {
        case 'error':
            return notificationsStore.frontendError(message, "Scheduler", 5);
        case 'success':
            return notificationsStore.frontendInfo(message, "Scheduler", 3);
        case 'warning':
            return notificationsStore.frontendWarning(message, "Scheduler", 4);
        case 'info':
        default:
            return notificationsStore.frontendInfo(message, "Scheduler", 3);
    }
};

// Define the full component implementation
const fullComponentImplementation = function() {
    return {
        tasks: [],
        isLoading: true,
        selectedTask: null,
        expandedTaskId: null,
        sortField: 'name',
        sortDirection: 'asc',
        filterType: 'all',  // all, scheduled, adhoc, planned
        filterState: 'all',  // all, idle, running, disabled, error
        pollingInterval: null,
        pollingActive: false, // Track if polling is currently active
        editingTask: {
            name: '',
            type: 'scheduled',
            state: 'idle',
            schedule: {
                minute: '*',
                hour: '*',
                day: '*',
                month: '*',
                weekday: '*',
                timezone: getUserTimezone()
            },
            token: '',
            plan: {
                todo: [],
                in_progress: null,
                done: []
            },
            system_prompt: '',
            prompt: '',
            attachments: [],
            project: null,
            dedicated_context: true,
        },
        projectOptions: [],
        selectedProjectSlug: '',
        isCreating: false,
        isEditing: false,
        showLoadingState: false,
        viewMode: 'list', // Controls whether to show list or detail view
        selectedTaskForDetail: null, // Task object for detail view
        attachmentsText: '',
        filteredTasks: [],
        hasNoTasks: true, // Add explicit reactive property

        // Initialize the component
        init() {
            // Initialize component data
            this.tasks = [];
            this.isLoading = true;
            this.hasNoTasks = true; // Add explicit reactive property
            this.filterType = 'all';
            this.filterState = 'all';
            this.sortField = 'name';
            this.sortDirection = 'asc';
            this.pollingInterval = null;
            this.pollingActive = false;

            // Start polling for tasks
            this.startPolling();

            // Refresh initial data
            this.fetchTasks();

            // Set up event handler for tab selection to ensure view is refreshed when tab becomes visible
            document.addEventListener('click', (event) => {
                // Check if a tab was clicked
                const clickedTab = event.target.closest('.settings-tab');
                if (clickedTab && clickedTab.getAttribute('data-tab') === 'scheduler') {
                    setTimeout(() => {
                        this.fetchTasks();
                    }, TIMING.SETUP_DELAY);
                }
            });

            // Watch for changes to the tasks array to update UI
            this.$watch('tasks', (newTasks) => {
                this.updateTasksUI();
            });

            this.$watch('filterType', () => {
                this.updateTasksUI();
            });

            this.$watch('filterState', () => {
                this.updateTasksUI();
            });

            // Set up default configuration
            try {
                this.viewMode = localStorage.getItem('scheduler_view_mode') || 'list';
            } catch (e) {
                this.viewMode = 'list';
            }
            this.selectedTask = null;
            this.expandedTaskId = null;
            this.editingTask = {
                name: '',
                type: 'scheduled',
                state: 'idle',
                schedule: {
                    minute: '*',
                    hour: '*',
                    day: '*',
                    month: '*',
                    weekday: '*',
                    timezone: getUserTimezone()
                },
                token: this.generateRandomToken ? this.generateRandomToken() : '',
                plan: {
                    todo: [],
                    in_progress: null,
                    done: []
                },
                system_prompt: '',
                prompt: '',
                attachments: [],
                project: null,
                dedicated_context: true,
            };
            this.refreshProjectOptions();

            // Initialize Flatpickr for date/time pickers after Alpine is fully initialized
            this.$nextTick(() => {
                // Wait until DOM is updated
                setTimeout(() => {
                    if (this.isCreating) {
                        this.initFlatpickr('create');
                    } else if (this.isEditing) {
                        this.initFlatpickr('edit');
                    }
                }, TIMING.SETUP_DELAY);
            });

            // Cleanup on component destruction
            this.$cleanup = () => {
                Logger.debug('Cleaning up schedulerSettings component');
                this.stopPolling();

                // Clean up any Flatpickr instances
                const createInput = document.getElementById('newPlannedTime-create');
                if (createInput && createInput._flatpickr) {
                    createInput._flatpickr.destroy();
                }

                const editInput = document.getElementById('newPlannedTime-edit');
                if (editInput && editInput._flatpickr) {
                    editInput._flatpickr.destroy();
                }
            };
        },

        // Start polling for task updates
        startPolling() {
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
            }, TIMING.SCHEDULER_POLL_INTERVAL); // Poll every 2 seconds as requested
        },

        // Stop polling when tab is inactive
        stopPolling() {
            Logger.debug('Stopping task polling');
            this.pollingActive = false;

            if (this.pollingInterval) {
                clearInterval(this.pollingInterval);
                this.pollingInterval = null;
            }
        },

        // Fetch tasks from API
        async fetchTasks() {
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
        },

        // Change sort field/direction
        changeSort(field) {
            if (this.sortField === field) {
                // Toggle direction if already sorting by this field
                this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                // Set new sort field and default to ascending
                this.sortField = field;
                this.sortDirection = 'asc';
            }
        },

        // Toggle expanded task row
        toggleTaskExpand(taskId) {
            if (this.expandedTaskId === taskId) {
                this.expandedTaskId = null;
            } else {
                this.expandedTaskId = taskId;
            }
        },

        // Show task detail view
        showTaskDetail(taskId) {
            const task = this.tasks.find(t => t.uuid === taskId);
            if (!task) {
                showToast('Task not found', 'error');
                return;
            }

            // Create a copy of the task to avoid modifying the original
            this.selectedTaskForDetail = JSON.parse(JSON.stringify(task));

            // Ensure attachments is always an array
            if (!this.selectedTaskForDetail.attachments) {
                this.selectedTaskForDetail.attachments = [];
            }

            this.viewMode = 'detail';
        },

        // Close detail view and return to list
        closeTaskDetail() {
            this.selectedTaskForDetail = null;
            this.viewMode = 'list';
        },

        // Format date for display
        formatDate(dateString) {
            if (!dateString) return 'Never';
            return formatDateTime(dateString, 'full');
        },

        // Format plan for display
        formatPlan(task) {
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
        },

        // Format schedule for display
        formatSchedule(task) {
            if (!task.schedule) return 'None';

            let schedule = '';
            if (typeof task.schedule === 'string') {
                schedule = task.schedule;
            } else if (typeof task.schedule === 'object') {
                // Display only the cron parts, not the timezone
                schedule = `${task.schedule.minute || '*'} ${task.schedule.hour || '*'} ${task.schedule.day || '*'} ${task.schedule.month || '*'} ${task.schedule.weekday || '*'}`;
            }

            return schedule;
        },

        // Get CSS class for state badge
        getStateBadgeClass(state) {
            switch (state) {
                case 'idle': return 'scheduler-status-idle';
                case 'running': return 'scheduler-status-running';
                case 'disabled': return 'scheduler-status-disabled';
                case 'error': return 'scheduler-status-error';
                default: return '';
            }
        },

        deriveActiveProject() {
            const selected = chatsStore?.selectedContext || null;
            if (!selected || !selected.project) {
                return null;
            }

            const project = selected.project;
            return {
                name: project.name || null,
                title: project.title || project.name || null,
                color: project.color || '',
            };
        },

        formatProjectName(project) {
            if (!project) {
                return 'No Project';
            }
            const title = project.title || project.name;
            return title || 'No Project';
        },

        formatProjectLabel(project) {
            return `Project: ${this.formatProjectName(project)}`;
        },

        async refreshProjectOptions() {
            try {
                if (!Array.isArray(projectsStore.projectList) || !projectsStore.projectList.length) {
                    if (typeof projectsStore.loadProjectsList === 'function') {
                        await projectsStore.loadProjectsList();
                    }
                }
            } catch (_error) {
            }

            const list = Array.isArray(projectsStore.projectList) ? projectsStore.projectList : [];
            this.projectOptions = list.map((proj) => ({
                name: proj.name,
                title: proj.title || proj.name,
                color: proj.color || '',
            }));
        },

        onProjectSelect(slug) {
            this.selectedProjectSlug = slug || '';
            if (!slug) {
                this.editingTask.project = null;
                return;
            }

            const option = this.projectOptions.find((item) => item.name === slug);
            if (option) {
                this.editingTask.project = { ...option };
            } else {
                this.editingTask.project = {
                    name: slug,
                    title: slug,
                    color: '',
                };
            }
        },

        extractTaskProject(task) {
            if (!task) {
                return null;
            }

            const slug = task.project_name || null;
            const project = task.project || {};
            const title = project.name || slug;
            const color = task.project_color || project.color || '';

            if (!slug && !title) {
                return null;
            }

            return {
                name: slug,
                title: title || slug,
                color: color,
            };
        },

        formatTaskProject(task) {
            return this.formatProjectName(this.extractTaskProject(task));
        },

        // Create a new task
        async startCreateTask() {
            this.isCreating = true;
            this.isEditing = false;
            document.querySelector('[x-data="schedulerSettings"]')?.setAttribute('data-editing-state', 'creating');
            await this.refreshProjectOptions();
            const activeProject = this.deriveActiveProject();
            let initialProject = activeProject ? { ...activeProject } : null;
            if (!initialProject && this.projectOptions.length > 0) {
                initialProject = { ...this.projectOptions[0] };
            }

            this.editingTask = {
                name: '',
                type: 'scheduled', // Default to scheduled
                state: 'idle', // Initialize with idle state
                schedule: {
                    minute: '*',
                    hour: '*',
                    day: '*',
                    month: '*',
                    weekday: '*',
                    timezone: getUserTimezone()
                },
                token: this.generateRandomToken(), // Generate token even for scheduled tasks to prevent undefined errors
                plan: { // Initialize plan for all task types to prevent undefined errors
                    todo: [],
                    in_progress: null,
                    done: []
                },
                system_prompt: '',
                prompt: '',
                attachments: [], // Always initialize as an empty array
                project: initialProject,
                dedicated_context: true,
            };
            this.selectedProjectSlug = initialProject && initialProject.name ? initialProject.name : '';

            // Set up Flatpickr after the component is visible
            this.$nextTick(() => {
                this.initFlatpickr('create');
            });
        },

        // Edit an existing task
        async startEditTask(taskId) {
            const task = this.tasks.find(t => t.uuid === taskId);
            if (!task) {
                showToast('Task not found', 'error');
                return;
            }

            this.isCreating = false;
            this.isEditing = true;
            document.querySelector('[x-data="schedulerSettings"]')?.setAttribute('data-editing-state', 'editing');

            // Create a deep copy to avoid modifying the original
            this.editingTask = JSON.parse(JSON.stringify(task));
            const projectSlug = task.project_name || null;
            const projectDisplay = (task.project && task.project.name) || projectSlug;
            const projectColor = task.project_color || (task.project ? task.project.color : '') || '';
            this.editingTask.project = projectSlug || projectDisplay ? {
                name: projectSlug,
                title: projectDisplay,
                color: projectColor,
            } : null;
            this.editingTask.dedicated_context = !!task.dedicated_context;
            this.selectedProjectSlug = this.editingTask.project && this.editingTask.project.name ? this.editingTask.project.name : '';

            // Debug log
            Logger.debug('Task data for editing:', task);
            Logger.debug('Attachments from task:', task.attachments);

            // Ensure state is set with a default if missing
            if (!this.editingTask.state) this.editingTask.state = 'idle';

            // Always initialize schedule to prevent UI errors
            // All task types need this structure for the form to work properly
            if (!this.editingTask.schedule || typeof this.editingTask.schedule === 'string') {
                let scheduleObj = {
                    minute: '*',
                    hour: '*',
                    day: '*',
                    month: '*',
                    weekday: '*',
                    timezone: getUserTimezone()
                };

                // If it's a string, parse it
                if (typeof this.editingTask.schedule === 'string') {
                    const parts = this.editingTask.schedule.split(' ');
                    if (parts.length >= 5) {
                        scheduleObj.minute = parts[0] || '*';
                        scheduleObj.hour = parts[1] || '*';
                        scheduleObj.day = parts[2] || '*';
                        scheduleObj.month = parts[3] || '*';
                        scheduleObj.weekday = parts[4] || '*';
                    }
                }

                this.editingTask.schedule = scheduleObj;
            } else {
                // Ensure timezone exists in the schedule
                if (!this.editingTask.schedule.timezone) {
                    this.editingTask.schedule.timezone = getUserTimezone();
                }
            }

            // Ensure attachments is always an array
            if (!this.editingTask.attachments) {
                this.editingTask.attachments = [];
            } else if (typeof this.editingTask.attachments === 'string') {
                // Handle case where attachments might be stored as a string
                this.editingTask.attachments = this.editingTask.attachments
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line.length > 0);
            } else if (!Array.isArray(this.editingTask.attachments)) {
                // If not an array or string, set to empty array
                this.editingTask.attachments = [];
            }

            // Ensure appropriate properties are initialized based on task type
            if (this.editingTask.type === 'scheduled') {
                // Initialize token for scheduled tasks to prevent undefined errors if UI accesses it
                if (!this.editingTask.token) {
                    this.editingTask.token = '';
                }

                // Initialize plan stub for scheduled tasks to prevent undefined errors
                if (!this.editingTask.plan) {
                    this.editingTask.plan = {
                        todo: [],
                        in_progress: null,
                        done: []
                    };
                }
            } else if (this.editingTask.type === 'adhoc') {
                // Initialize token if it doesn't exist
                if (!this.editingTask.token) {
                    this.editingTask.token = this.generateRandomToken();
                }

                // Initialize plan stub for adhoc tasks to prevent undefined errors
                if (!this.editingTask.plan) {
                    this.editingTask.plan = {
                        todo: [],
                        in_progress: null,
                        done: []
                    };
                }
            } else if (this.editingTask.type === 'planned') {
                // Initialize plan if it doesn't exist
                if (!this.editingTask.plan) {
                    this.editingTask.plan = {
                        todo: [],
                        in_progress: null,
                        done: []
                    };
                }

                // Ensure todo is an array
                if (!Array.isArray(this.editingTask.plan.todo)) {
                    this.editingTask.plan.todo = [];
                }

                // Initialize token to prevent undefined errors
                if (!this.editingTask.token) {
                    this.editingTask.token = '';
                }
            }

            // Set up Flatpickr after the component is visible and task data is loaded
            this.$nextTick(() => {
                this.initFlatpickr('edit');
            });
        },

        // Cancel editing
        cancelEdit() {
            // Clean up Flatpickr instances
            const destroyFlatpickr = (inputId) => {
                const input = document.getElementById(inputId);
                if (input && input._flatpickr) {

                    input._flatpickr.destroy();

                    // Also remove any wrapper elements that might have been created
                    const wrapper = input.closest('.scheduler-flatpickr-wrapper');
                    if (wrapper && wrapper.parentNode) {
                        // Move the input back to its original position
                        wrapper.parentNode.insertBefore(input, wrapper);
                        // Remove the wrapper
                        wrapper.parentNode.removeChild(wrapper);
                    }

                    // Remove any added classes
                    input.classList.remove('scheduler-flatpickr-input');
                }
            };

            if (this.isCreating) {
                destroyFlatpickr('newPlannedTime-create');
            } else if (this.isEditing) {
                destroyFlatpickr('newPlannedTime-edit');
            }

            // Reset to initial state but keep default values to prevent errors
            this.editingTask = {
                name: '',
                type: 'scheduled',
                state: 'idle', // Initialize with idle state
                schedule: {
                    minute: '*',
                    hour: '*',
                    day: '*',
                    month: '*',
                    weekday: '*',
                    timezone: getUserTimezone()
                },
                token: '',
                plan: { // Initialize plan for planned tasks
                    todo: [],
                    in_progress: null,
                    done: []
                },
                system_prompt: '',
                prompt: '',
                attachments: [], // Always initialize as an empty array
                project: null,
                dedicated_context: true,
            };
            this.selectedProjectSlug = '';
            this.isCreating = false;
            this.isEditing = false;
            document.querySelector('[x-data="schedulerSettings"]')?.removeAttribute('data-editing-state');
        },

        // Save task (create new or update existing)
        async saveTask() {
            // Validate task data
            if (!this.editingTask.name.trim() || !this.editingTask.prompt.trim()) {
                // showToast('Task name and prompt are required', 'error');
                alert('Task name and prompt are required');
                return;
            }

            try {
                let apiEndpoint, taskData;

                // Prepare task data
                taskData = {
                    name: this.editingTask.name,
                    system_prompt: this.editingTask.system_prompt || '',
                    prompt: this.editingTask.prompt || '',
                    state: this.editingTask.state || 'idle', // Include state in task data
                    timezone: getUserTimezone()
                };

                if (this.isCreating && this.editingTask.project) {
                    if (this.editingTask.project.name) {
                        taskData.project_name = this.editingTask.project.name;
                    }
                    if (this.editingTask.project.color) {
                        taskData.project_color = this.editingTask.project.color;
                    }
                }

                // Process attachments - now always stored as array
                taskData.attachments = Array.isArray(this.editingTask.attachments)
                    ? this.editingTask.attachments
                        .map(line => typeof line === 'string' ? line.trim() : line)
                        .filter(line => line && line.trim().length > 0)
                    : [];

                // Handle task type specific data
                if (this.editingTask.type === 'scheduled') {
                    // Ensure schedule is properly formatted as an object
                    if (typeof this.editingTask.schedule === 'string') {
                        // Parse string schedule into object
                        const parts = this.editingTask.schedule.split(' ');
                        taskData.schedule = {
                            minute: parts[0] || '*',
                            hour: parts[1] || '*',
                            day: parts[2] || '*',
                            month: parts[3] || '*',
                            weekday: parts[4] || '*',
                            timezone: getUserTimezone() // Add timezone to schedule object
                        };
                    } else {
                        // Use object schedule directly but ensure timezone is included
                        taskData.schedule = {
                            ...this.editingTask.schedule,
                            timezone: this.editingTask.schedule.timezone || getUserTimezone()
                        };
                    }
                    // Don't send token or plan for scheduled tasks
                    delete taskData.token;
                    delete taskData.plan;
                } else if (this.editingTask.type === 'adhoc') {
                    // Ad-hoc task with token
                    // Ensure token is a non-empty string, generate a new one if needed
                    if (!this.editingTask.token) {
                        this.editingTask.token = this.generateRandomToken();
                    }
                    taskData.token = this.editingTask.token;

                    // Don't send schedule or plan for adhoc tasks
                    delete taskData.schedule;
                    delete taskData.plan;
                } else if (this.editingTask.type === 'planned') {
                    // Planned task with plan
                    // Make sure plan exists and has required properties
                    if (!this.editingTask.plan) {
                        this.editingTask.plan = {
                            todo: [],
                            in_progress: null,
                            done: []
                        };
                    }

                    // Ensure todo and done are arrays
                    if (!Array.isArray(this.editingTask.plan.todo)) {
                        this.editingTask.plan.todo = [];
                    }

                    if (!Array.isArray(this.editingTask.plan.done)) {
                        this.editingTask.plan.done = [];
                    }

                    // Validate each date in the todo list to ensure it's a valid ISO string
                    const validatedTodo = [];
                    for (const dateStr of this.editingTask.plan.todo) {
                        try {
                            const date = new Date(dateStr);
                            if (!isNaN(date.getTime())) {
                                validatedTodo.push(date.toISOString());
                            }
                        } catch (_error) {
                        }
                    }

                    // Replace with validated list
                    this.editingTask.plan.todo = validatedTodo;

                    // Sort the todo items by date (earliest first)
                    this.editingTask.plan.todo.sort();

                    // Set the plan in taskData
                    taskData.plan = {
                        todo: this.editingTask.plan.todo,
                        in_progress: this.editingTask.plan.in_progress,
                        done: this.editingTask.plan.done || []
                    };

                    // Don't send schedule or token for planned tasks
                    delete taskData.schedule;
                    delete taskData.token;
                }

                // Determine if creating or updating
                if (this.isCreating) {
                    apiEndpoint = '/scheduler_task_create';
                } else {
                    apiEndpoint = '/scheduler_task_update';
                    taskData.task_id = this.editingTask.uuid;
                }

                // Make API request
                const response = await fetchApi(apiEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(taskData)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Failed to save task');
                }

                // Parse response data to get the created/updated task
                const responseData = await response.json();

                // Show success message
                showToast(this.isCreating ? 'Task created successfully' : 'Task updated successfully', 'success');

                // Immediately update the UI if the response includes the task
                if (responseData && responseData.task) {
                    // Update the tasks array
                    if (this.isCreating) {
                        // For new tasks, add to the array
                        this.tasks = [...this.tasks, responseData.task];
                    } else {
                        // For updated tasks, replace the existing one
                        this.tasks = this.tasks.map(t =>
                            t.uuid === responseData.task.uuid ? responseData.task : t
                        );
                    }

                    // Update UI using the shared function
                    this.updateTasksUI();
                } else {
                    // Fallback to fetching tasks if no task in response
                    await this.fetchTasks();
                }

                // Clean up Flatpickr instances
                const destroyFlatpickr = (inputId) => {
                    const input = document.getElementById(inputId);
                    if (input && input._flatpickr) {
                        input._flatpickr.destroy();
                    }
                };

                if (this.isCreating) {
                    destroyFlatpickr('newPlannedTime-create');
                } else if (this.isEditing) {
                    destroyFlatpickr('newPlannedTime-edit');
                }

                // Reset task data and form state
                this.editingTask = {
                    name: '',
                    type: 'scheduled',
                    state: 'idle',
                    schedule: {
                        minute: '*',
                        hour: '*',
                        day: '*',
                        month: '*',
                        weekday: '*',
                        timezone: getUserTimezone()
                    },
                    token: '',
                    plan: {
                        todo: [],
                        in_progress: null,
                        done: []
                    },
                    system_prompt: '',
                    prompt: '',
                    attachments: [],
                    project: null,
                    dedicated_context: true,
                };
                this.isCreating = false;
                this.isEditing = false;
                document.querySelector('[x-data="schedulerSettings"]')?.removeAttribute('data-editing-state');
            } catch (error) {
                showToast('Failed to save task: ' + error.message, 'error');
            }
        },

        // Run a task
        async runTask(taskId) {
            try {
                const response = await fetchApi('/scheduler_task_run', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        task_id: taskId,
                        timezone: getUserTimezone()
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data?.error || 'Failed to run task');
                }

                const toastMessage = data.warning || data.message || 'Task started successfully';
                const toastType = data.warning ? 'warning' : 'success';
                showToast(toastMessage, toastType);

                // Refresh task list
                this.fetchTasks();
            } catch (error) {
                showToast('Failed to run task: ' + error.message, 'error');
            }
        },

        // Reset a task's state
        async resetTaskState(taskId) {
            try {
                const task = this.tasks.find(t => t.uuid === taskId);
                if (!task) {
                    showToast('Task not found', 'error');
                    return;
                }

                // Check if task is already in idle state
                if (task.state === 'idle') {
                    showToast('Task is already in idle state', 'info');
                    return;
                }

                this.showLoadingState = true;

                // Call API to update the task state
                const response = await fetchApi('/scheduler_task_update', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        task_id: taskId,
                        state: 'idle',  // Always reset to idle state
                        timezone: getUserTimezone()
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Failed to reset task state');
                }

                showToast('Task state reset to idle', 'success');

                // Refresh task list
                await this.fetchTasks();
                this.showLoadingState = false;
            } catch (error) {
                showToast('Failed to reset task state: ' + error.message, 'error');
                this.showLoadingState = false;
            }
        },

        // Delete a task
        async deleteTask(taskId) {
            // Confirm deletion
            if (!confirm('Are you sure you want to delete this task? This action cannot be undone.')) {
                return;
            }

            try {

                // if we delete selected context, switch to another first
                await chatsStore.switchFromContext(taskId);

                const response = await fetchApi('/scheduler_task_delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        task_id: taskId,
                        timezone: getUserTimezone()
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Failed to delete task');
                }

                showToast('Task deleted successfully', 'success');

                // If we were viewing the detail of the deleted task, close the detail view
                if (this.selectedTaskForDetail && this.selectedTaskForDetail.uuid === taskId) {
                    this.closeTaskDetail();
                }

                // Immediately update UI without waiting for polling
                this.tasks = this.tasks.filter(t => t.uuid !== taskId);

                // Update UI using the shared function
                this.updateTasksUI();
            } catch (error) {
                showToast('Failed to delete task: ' + error.message, 'error');
            }
        },

        // Initialize datetime input with default value (30 minutes from now)
        initDateTimeInput(event) {
            if (!event.target.value) {
                const now = new Date();
                now.setMinutes(now.getMinutes() + 30);

                // Format as YYYY-MM-DDThh:mm
                const year = now.getFullYear();
                const month = String(now.getMonth() + 1).padStart(2, '0');
                const day = String(now.getDate()).padStart(2, '0');
                const hours = String(now.getHours()).padStart(2, '0');
                const minutes = String(now.getMinutes()).padStart(2, '0');

                event.target.value = `${year}-${month}-${day}T${hours}:${minutes}`;

                // If using Flatpickr, update it as well
                if (event.target._flatpickr) {
                    event.target._flatpickr.setDate(event.target.value);
                }
            }
        },

        // Generate a random token for ad-hoc tasks
        generateRandomToken() {
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let token = '';
            for (let i = 0; i < 16; i++) {
                token += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            return token;
        },

        // Getter for filtered tasks
        get filteredTasks() {
            // Make sure we have tasks to filter
            if (!Array.isArray(this.tasks)) {
                return [];
            }

            let filtered = [...this.tasks];

            // Apply type filter with case-insensitive comparison
            if (this.filterType && this.filterType !== 'all') {
                filtered = filtered.filter(task => {
                    if (!task.type) return false;
                    return String(task.type).toLowerCase() === this.filterType.toLowerCase();
                });
            }

            // Apply state filter with case-insensitive comparison
            if (this.filterState && this.filterState !== 'all') {
                filtered = filtered.filter(task => {
                    if (!task.state) return false;
                    return String(task.state).toLowerCase() === this.filterState.toLowerCase();
                });
            }

            // Sort the filtered tasks
            return this.sortTasks(filtered);
        },

        // Sort the tasks based on sort field and direction
        sortTasks(tasks) {
            if (!Array.isArray(tasks) || tasks.length === 0) {
                return tasks;
            }

            return [...tasks].sort((a, b) => {
                if (!this.sortField) return 0;

                const fieldA = a[this.sortField];
                const fieldB = b[this.sortField];

                // Handle cases where fields might be undefined
                if (fieldA === undefined && fieldB === undefined) return 0;
                if (fieldA === undefined) return 1;
                if (fieldB === undefined) return -1;

                // For dates, convert to timestamps
                if (this.sortField === 'createdAt' || this.sortField === 'updatedAt') {
                    const dateA = new Date(fieldA).getTime();
                    const dateB = new Date(fieldB).getTime();
                    return this.sortDirection === 'asc' ? dateA - dateB : dateB - dateA;
                }

                // For string comparisons
                if (typeof fieldA === 'string' && typeof fieldB === 'string') {
                    return this.sortDirection === 'asc'
                        ? fieldA.localeCompare(fieldB)
                        : fieldB.localeCompare(fieldA);
                }

                // For numerical comparisons
                return this.sortDirection === 'asc' ? fieldA - fieldB : fieldB - fieldA;
            });
        },

        // Computed property for attachments text representation
        get attachmentsText() {
            // Ensure we always have an array to work with
            const attachments = Array.isArray(this.editingTask.attachments)
                ? this.editingTask.attachments
                : [];

            // Join array items with newlines
            return attachments.join('\n');
        },

        // Setter for attachments text - preserves empty lines during editing
        set attachmentsText(value) {
            if (typeof value === 'string') {
                // Just split by newlines without filtering to preserve editing experience
                this.editingTask.attachments = value.split('\n');
            } else {
                // Fallback to empty array if not a string
                this.editingTask.attachments = [];
            }
        },

        // Debug method to test filtering logic
        testFiltering() {
        },

        // Initialize Flatpickr datetime pickers for both create and edit forms
        /**
         * Initialize Flatpickr date/time pickers for scheduler forms
         *
         * @param {string} mode - Which pickers to initialize: 'all', 'create', or 'edit'
         * @returns {void}
         */
        initFlatpickr(mode = 'all') {
            const initPicker = (inputId, refName, wrapperClass, options = {}) => {
                // Try to get input using Alpine.js x-ref first (more reliable)
                let input = this.$refs[refName];

                // Fall back to getElementById if x-ref is not available
                if (!input) {
                    input = document.getElementById(inputId);
                }

                if (!input) {
                    Logger.warn(`Input element ${inputId} not found by ID or ref`);
                    return null;
                }

                // Create a wrapper around the input
                const wrapper = document.createElement('div');
                wrapper.className = wrapperClass || 'scheduler-flatpickr-wrapper';
                wrapper.style.overflow = 'visible'; // Ensure dropdown can escape container

                // Replace the input with our wrapped version
                input.parentNode.insertBefore(wrapper, input);
                wrapper.appendChild(input);
                input.classList.add('scheduler-flatpickr-input');

                // Default options
                const defaultOptions = {
                    dateFormat: "Y-m-d H:i",
                    enableTime: true,
                    time_24hr: true,
                    static: false, // Not static so it will float
                    appendTo: document.body, // Append to body to avoid overflow issues
                    theme: "scheduler-theme",
                    allowInput: true,
                    positionElement: wrapper, // Position relative to wrapper
                    onOpen: function(selectedDates, dateStr, instance) {
                        // Ensure calendar is properly positioned and visible
                        instance.calendarContainer.style.zIndex = '9999';
                        instance.calendarContainer.style.position = 'absolute';
                        instance.calendarContainer.style.visibility = 'visible';
                        instance.calendarContainer.style.opacity = '1';

                        // Add class to calendar container for our custom styling
                        instance.calendarContainer.classList.add('scheduler-theme');
                    },
                    // Set default date to 30 minutes from now if no date selected
                    onReady: function(selectedDates, dateStr, instance) {
                        if (!dateStr) {
                            const now = new Date();
                            now.setMinutes(now.getMinutes() + 30);
                            instance.setDate(now, true);
                        }
                    }
                };

                // Merge options
                const mergedOptions = {...defaultOptions, ...options};

                // Initialize flatpickr
                const fp = flatpickr(input, mergedOptions);

                // Add a clear button
                const clearButton = document.createElement('button');
                clearButton.className = 'scheduler-flatpickr-clear';
                clearButton.innerHTML = '×';
                clearButton.type = 'button';
                clearButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (fp) {
                        fp.clear();
                    }
                });
                wrapper.appendChild(clearButton);

                return fp;
            };

            // Clear any existing Flatpickr instances to prevent duplication
            if (mode === 'all' || mode === 'create') {
                const createInput = document.getElementById('newPlannedTime-create');
                if (createInput && createInput._flatpickr) {
                    createInput._flatpickr.destroy();
                }
            }

            if (mode === 'all' || mode === 'edit') {
                const editInput = document.getElementById('newPlannedTime-edit');
                if (editInput && editInput._flatpickr) {
                    editInput._flatpickr.destroy();
                }
            }

            // Initialize new instances
            if (mode === 'all' || mode === 'create') {
                initPicker('newPlannedTime-create', 'plannedTimeCreate', 'scheduler-flatpickr-wrapper', {
                    minuteIncrement: 5,
                    defaultHour: new Date().getHours(),
                    defaultMinute: Math.ceil(new Date().getMinutes() / 5) * 5
                });
            }

            if (mode === 'all' || mode === 'edit') {
                initPicker('newPlannedTime-edit', 'plannedTimeEdit', 'scheduler-flatpickr-wrapper', {
                    minuteIncrement: 5,
                    defaultHour: new Date().getHours(),
                    defaultMinute: Math.ceil(new Date().getMinutes() / 5) * 5
                });
            }
        },

        // Update tasks UI
        updateTasksUI() {
            // First update filteredTasks if that method exists
            if (typeof this.updateFilteredTasks === 'function') {
                this.updateFilteredTasks();
            }

            // Wait for UI to update
            this.$nextTick(() => {
                // Get empty state and task list elements
                const emptyElement = document.querySelector('.scheduler-empty');
                const tableElement = document.querySelector('.scheduler-task-list');

                // Calculate visibility state based on filtered tasks
                const hasFilteredTasks = Array.isArray(this.filteredTasks) && this.filteredTasks.length > 0;

                // Update visibility directly
                if (emptyElement) {
                    emptyElement.style.display = !hasFilteredTasks ? '' : 'none';
                }

                if (tableElement) {
                    tableElement.style.display = hasFilteredTasks ? '' : 'none';
                }
            });
        }
    };
};


// Only define the component if it doesn't already exist or extend the existing one
if (!window.schedulerSettings) {

    window.schedulerSettings = fullComponentImplementation;
} else {

    // Store the original function
    const originalSchedulerSettings = window.schedulerSettings;

    // Replace with enhanced version that merges the pre-initialized stub with the full implementation
    window.schedulerSettings = function() {
        // Get the base pre-initialized component
        const baseComponent = originalSchedulerSettings();

        // Create a backup of the original init function
        const originalInit = baseComponent.init || function() {};

        // Create our enhanced init function that adds the missing functionality
        baseComponent.init = function() {
            // Call the original init if it exists
            originalInit.call(this);



            // Get the full implementation
            const fullImpl = fullComponentImplementation();

            // Register all implementation methods (except init) directly
            Object.keys(fullImpl).forEach((key) => {
                if (key === 'init') {
                    return;
                }
                if (typeof fullImpl[key] === 'function') {

                    this[key] = fullImpl[key];
                }
            });

            if (typeof this.refreshProjectOptions === 'function') {
                this.refreshProjectOptions();
            }

            // hack to expose deleteTask
            window.deleteTaskGlobal = this.deleteTask.bind(this);

            // Make sure we have a filteredTasks array initialized
            this.filteredTasks = [];

            // Initialize essential properties if missing
            if (!Array.isArray(this.tasks)) {
                this.tasks = [];
            }

            if (!Array.isArray(this.projectOptions)) {
                this.projectOptions = [];
            }

            if (typeof this.selectedProjectSlug !== 'string') {
                this.selectedProjectSlug = '';
            }

            // Make sure attachmentsText getter/setter are defined
            if (!Object.getOwnPropertyDescriptor(this, 'attachmentsText')?.get) {
                Object.defineProperty(this, 'attachmentsText', {
                    get: function() {
                        // Ensure we always have an array to work with
                        const attachments = Array.isArray(this.editingTask?.attachments)
                            ? this.editingTask.attachments
                            : [];

                        // Join array items with newlines
                        return attachments.join('\n');
                    },
                    set: function(value) {
                        if (!this.editingTask) {
                            this.editingTask = {
                                attachments: [],
                                project: null,
                                dedicated_context: true,
                            };
                        }

                        if (typeof value === 'string') {
                            // Just split by newlines without filtering to preserve editing experience
                            this.editingTask.attachments = value.split('\n');
                        } else {
                            // Fallback to empty array if not a string
                            this.editingTask.attachments = [];
                        }
                    }
                });
            }

            // Add methods for updating filteredTasks directly
            if (typeof this.updateFilteredTasks !== 'function') {
                this.updateFilteredTasks = function() {
                    // Make sure we have tasks to filter
                    if (!Array.isArray(this.tasks)) {
                        this.filteredTasks = [];
                        return;
                    }

                    let filtered = [...this.tasks];

                    // Apply type filter with case-insensitive comparison
                    if (this.filterType && this.filterType !== 'all') {
                        filtered = filtered.filter(task => {
                            if (!task.type) return false;
                            return String(task.type).toLowerCase() === this.filterType.toLowerCase();
                        });
                    }

                    // Apply state filter with case-insensitive comparison
                    if (this.filterState && this.filterState !== 'all') {
                        filtered = filtered.filter(task => {
                            if (!task.state) return false;
                            return String(task.state).toLowerCase() === this.filterState.toLowerCase();
                        });
                    }

                    // Sort the filtered tasks
                    if (typeof this.sortTasks === 'function') {
                        filtered = this.sortTasks(filtered);
                    }

                    // Directly update the filteredTasks property
                    this.filteredTasks = filtered;
                };
            }

            // Set up watchers to update filtered tasks when dependencies change
            this.$nextTick(() => {
                // Update filtered tasks when raw tasks change
                this.$watch('tasks', () => {
                    this.updateFilteredTasks();
                });

                // Update filtered tasks when filter type changes
                this.$watch('filterType', () => {
                    this.updateFilteredTasks();
                });

                // Update filtered tasks when filter state changes
                this.$watch('filterState', () => {
                    this.updateFilteredTasks();
                });

                // Update filtered tasks when sort field or direction changes
                this.$watch('sortField', () => {
                    this.updateFilteredTasks();
                });

                this.$watch('sortDirection', () => {
                    this.updateFilteredTasks();
                });

                // Initial update
                this.updateFilteredTasks();

                // Set up watcher for task type changes to initialize Flatpickr for planned tasks
                this.$watch('editingTask.type', (newType) => {
                    if (newType === 'planned') {
                        this.$nextTick(() => {
                            // Reinitialize Flatpickr when switching to planned task type
                            if (this.isCreating) {
                                this.initFlatpickr('create');
                            } else if (this.isEditing) {
                                this.initFlatpickr('edit');
                            }
                        });
                    }
                });

                // Initialize Flatpickr
                this.$nextTick(() => {
                    if (typeof this.initFlatpickr === 'function') {
                        this.initFlatpickr();
                    }
                });
            });

            // Try fetching tasks after a short delay
            setTimeout(() => {
                if (typeof this.fetchTasks === 'function') {
                    this.fetchTasks();
                }
            }, TIMING.SETUP_DELAY);
        };

        return baseComponent;
    };
}

// Force Alpine.js to register the component immediately
if (window.Alpine) {
    window.Alpine.data('schedulerSettings', window.schedulerSettings);
} else {
    // Wait for Alpine to load
    document.addEventListener('alpine:init', () => {
        Alpine.data('schedulerSettings', window.schedulerSettings);
    });
}

// Add a document ready event handler to ensure the scheduler tab can be clicked on first load
document.addEventListener('DOMContentLoaded', function() {
    // Setup scheduler tab click handling
    const setupSchedulerTab = () => {
        const settingsModal = document.getElementById('settingsModal');
        if (!settingsModal) {
            setTimeout(setupSchedulerTab, TIMING.SETUP_DELAY);
            return;
        }

        // Create a global event listener for clicks on the scheduler tab
        document.addEventListener('click', function(e) {
            // Find if the click was on the scheduler tab or its children
            const schedulerTab = e.target.closest('.settings-tab[title="Task Scheduler"]');
            if (!schedulerTab) return;

            e.preventDefault();
            e.stopPropagation();

            // Get the settings modal data
            try {
                const modalData = Alpine.$data(settingsModal);
                if (modalData.activeTab !== 'scheduler') {
                    // Directly call the modal's switchTab method
                    modalData.switchTab('scheduler');
                }

                // Force start polling and fetch tasks immediately when tab is selected
                setTimeout(() => {
                    // Get the scheduler component data
                    const schedulerElement = document.querySelector('[x-data="schedulerSettings"]');
                    if (schedulerElement) {
                        const schedulerData = Alpine.$data(schedulerElement);

                        // Force fetch tasks and start polling
                        if (typeof schedulerData.fetchTasks === 'function') {
                            schedulerData.fetchTasks();
                        }

                        if (typeof schedulerData.startPolling === 'function') {
                            schedulerData.startPolling();
                        }
                    }
                }, TIMING.SETUP_DELAY);
            } catch (err) {
                Logger.error('Error handling scheduler tab click:', err);
            }
        }, true); // Use capture phase to intercept before Alpine.js handlers
    };

    // Initialize the tab handling
    setupSchedulerTab();
});
