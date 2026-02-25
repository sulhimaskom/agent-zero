/**
 * Task Scheduler Component for Settings Modal
 * Manages scheduled and ad-hoc tasks through a dedicated settings tab
 * 
 * NOTE: This file has been refactored to use modular stores located at:
 * - js/stores/scheduler/formatting.js - Display formatting functions
 * - js/stores/scheduler/datetime.js - DateTime picker logic
 * - js/stores/scheduler/polling.js - Task polling and fetching
 * - js/stores/scheduler/ui.js - UI state, filtering, sorting
 * - js/stores/scheduler/tasks.js - Task CRUD operations
 * - js/stores/scheduler/index.js - Main exports and composition
 * 
 * The original monolithic code has been split into focused modules for
 * better maintainability, testability, and code navigation.
 */

import { formatDateTime, getUserTimezone } from './time-utils.js';
import { store as chatsStore } from "/components/sidebar/chats/chats-store.min.js"
import { store as notificationsStore } from "/components/notifications/notification-store.min.js"
import { store as projectsStore } from "/components/projects/projects-store.min.js"
import { TIMING } from './constants.js';
import Logger from './logger.min.js';

// Import modular functions
import { 
    formatDate, 
    formatPlan, 
    formatSchedule, 
    getStateBadgeClass 
} from './stores/scheduler/formatting.js';

import { 
    generateRandomToken, 
    initDateTimeInput, 
    initFlatpickr as initFlatpickrModule 
} from './stores/scheduler/datetime.js';

import { 
    startPolling as startPollingModule, 
    stopPolling as stopPollingModule, 
    fetchTasks as fetchTasksModule 
} from './stores/scheduler/polling.js';

import { 
    changeSort as changeSortModule, 
    toggleTaskExpand as toggleTaskExpandModule, 
    showTaskDetail as showTaskDetailModule, 
    closeTaskDetail as closeTaskDetailModule, 
    sortTasks as sortTasksModule, 
    getFilteredTasks, 
    testFiltering as testFilteringModule, 
    updateTasksUI as updateTasksUIModule, 
    getAttachmentsText, 
    setAttachmentsText 
} from './stores/scheduler/ui.js';

import { 
    deriveActiveProject as deriveActiveProjectModule,
    formatProjectName as formatProjectNameModule,
    formatProjectLabel as formatProjectLabelModule,
    refreshProjectOptions as refreshProjectOptionsModule,
    onProjectSelect as onProjectSelectModule,
    extractTaskProject as extractTaskProjectModule,
    formatTaskProject as formatTaskProjectModule,
    startCreateTask as startCreateTaskModule,
    startEditTask as startEditTaskModule,
    cancelEdit as cancelEditModule,
    saveTask as saveTaskModule,
    runTask as runTaskModule,
    resetTaskState as resetTaskStateModule,
    deleteTask as deleteTaskModule
} from './stores/scheduler/tasks.js';

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

// Initialize toast functions in modules
import { setShowToast as setPollingToast } from './stores/scheduler/polling.js';
import { setShowToastUi as setUiToast } from './stores/scheduler/ui.js';
import { setShowToast as setTasksToast } from './stores/scheduler/tasks.js';
setPollingToast(showToast);
setUiToast(showToast);
setTasksToast(showToast);

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
            startPollingModule.call(this);
        },

        // Stop polling when tab is inactive
        stopPolling() {
            stopPollingModule.call(this);
        },

        // Fetch tasks from API
        async fetchTasks() {
            await fetchTasksModule.call(this);
        },

        // Change sort field/direction
        changeSort(field) {
            changeSortModule.call(this, field);
        },

        // Toggle expanded task row
        toggleTaskExpand(taskId) {
            toggleTaskExpandModule.call(this, taskId);
        },

        // Show task detail view
        showTaskDetail(taskId) {
            showTaskDetailModule.call(this, taskId);
        },

        // Close detail view and return to list
        closeTaskDetail() {
            closeTaskDetailModule.call(this);
        },

        // Format date for display
        formatDate(dateString) {
            return formatDate(dateString);
        },

        // Format plan for display
        formatPlan(task) {
            return formatPlan(task);
        },

        // Format schedule for display
        formatSchedule(task) {
            return formatSchedule(task);
        },

        // Get CSS class for state badge
        getStateBadgeClass(state) {
            return getStateBadgeClass(state);
        },

        deriveActiveProject() {
            return deriveActiveProjectModule.call(this);
        },

        formatProjectName(project) {
            return formatProjectNameModule.call(this, project);
        },

        formatProjectLabel(project) {
            return formatProjectLabelModule.call(this, project);
        },

        async refreshProjectOptions() {
            await refreshProjectOptionsModule.call(this);
        },

        onProjectSelect(slug) {
            onProjectSelectModule.call(this, slug);
        },

        extractTaskProject(task) {
            return extractTaskProjectModule.call(this, task);
        },

        formatTaskProject(task) {
            return formatTaskProjectModule.call(this, task);
        },

        // Create a new task
        async startCreateTask() {
            await startCreateTaskModule.call(this);
        },

        // Edit an existing task
        async startEditTask(taskId) {
            await startEditTaskModule.call(this, taskId);
        },

        // Cancel editing
        cancelEdit() {
            cancelEditModule.call(this);
        },

        // Save task (create new or update existing)
        async saveTask() {
            await saveTaskModule.call(this);
        },

        // Run a task
        async runTask(taskId) {
            await runTaskModule.call(this, taskId);
        },

        // Reset a task's state
        async resetTaskState(taskId) {
            await resetTaskStateModule.call(this, taskId);
        },

        // Delete a task
        async deleteTask(taskId) {
            await deleteTaskModule.call(this, taskId);
        },

        // Initialize datetime input with default value (30 minutes from now)
        initDateTimeInput(event) {
            initDateTimeInput(event);
        },

        // Generate a random token for ad-hoc tasks
        generateRandomToken() {
            return generateRandomToken();
        },

        // Getter for filtered tasks
        get filteredTasks() {
            return getFilteredTasks.call(this);
        },

        // Sort the tasks based on sort field and direction
        sortTasks(tasks) {
            return sortTasksModule.call(this, tasks);
        },

        // Computed property for attachments text representation
        get attachmentsText() {
            return getAttachmentsText.call(this);
        },

        // Setter for attachments text - preserves empty lines during editing
        set attachmentsText(value) {
            setAttachmentsText.call(this, value);
        },

        // Debug method to test filtering logic
        testFiltering() {
            testFilteringModule();
        },

        // Initialize Flatpickr datetime pickers for both create and edit forms
        initFlatpickr(mode = 'all') {
            initFlatpickrModule.call(this, mode);
        },

        // Update tasks UI
        updateTasksUI() {
            updateTasksUIModule.call(this);
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
