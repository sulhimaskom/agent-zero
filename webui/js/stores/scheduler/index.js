/**
 * Scheduler Store - Modular Store
 * 
 * Split from monolithic scheduler.js for better maintainability and testability.
 * 
 * Module structure:
 * - formatting.js: Pure display formatting functions
 * - datetime.js: DateTime picker initialization
 * - polling.js: Task polling and fetching
 * - ui.js: UI state, filtering, sorting
 * - tasks.js: Task CRUD operations and project management
 * 
 * This index.js provides backward compatibility by re-exporting all functionality
 * in the same structure as the original scheduler.js
 */

// Import all modules
import { 
    formatDate, 
    formatPlan, 
    formatSchedule, 
    getStateBadgeClass 
} from './formatting.js';

import { 
    generateRandomToken, 
    initDateTimeInput, 
    initFlatpickr 
} from './datetime.js';

import { 
    startPolling, 
    stopPolling, 
    fetchTasks, 
    setShowToast as setShowToastPolling 
} from './polling.js';

import { 
    changeSort, 
    toggleTaskExpand, 
    showTaskDetail, 
    closeTaskDetail, 
    sortTasks, 
    getFilteredTasks, 
    testFiltering, 
    updateTasksUI, 
    getAttachmentsText, 
    setAttachmentsText,
    setShowToast as setShowToastUi 
} from './ui.js';

import { 
    deriveActiveProject,
    formatProjectName,
    formatProjectLabel,
    refreshProjectOptions,
    onProjectSelect,
    extractTaskProject,
    formatTaskProject,
    startCreateTask,
    startEditTask,
    cancelEdit,
    saveTask,
    runTask,
    resetTaskState,
    deleteTask,
    setShowToast as setShowToastTasks
} from './tasks.js';

// Re-export formatting functions
export {
    formatDate,
    formatPlan,
    formatSchedule,
    getStateBadgeClass,
    generateRandomToken,
    initDateTimeInput,
    initFlatpickr,
    startPolling,
    stopPolling,
    fetchTasks,
    changeSort,
    toggleTaskExpand,
    showTaskDetail,
    closeTaskDetail,
    sortTasks,
    getFilteredTasks,
    testFiltering,
    updateTasksUI,
    getAttachmentsText,
    setAttachmentsText,
    deriveActiveProject,
    formatProjectName,
    formatProjectLabel,
    refreshProjectOptions,
    onProjectSelect,
    extractTaskProject,
    formatTaskProject,
    startCreateTask,
    startEditTask,
    cancelEdit,
    saveTask,
    runTask,
    resetTaskState,
    deleteTask
};

/**
 * Initialize the showToast function for all modules
 * @param {Function} showToastFn - Toast notification function
 */
export function initializeModules(showToastFn) {
    setShowToastPolling(showToastFn);
    setShowToastUi(showToastFn);
    setShowToastTasks(showToastFn);
}

/**
 * Create the full scheduler component model
 * This is used for backward compatibility with the Alpine.js integration
 * @returns {Object} Full component model
 */
export function createSchedulerModel() {
    return {
        // State
        tasks: [],
        isLoading: true,
        selectedTask: null,
        expandedTaskId: null,
        sortField: 'name',
        sortDirection: 'asc',
        filterType: 'all',
        filterState: 'all',
        pollingInterval: null,
        pollingActive: false,
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
        viewMode: 'list',
        selectedTaskForDetail: null,
        attachmentsText: '',
        filteredTasks: [],
        hasNoTasks: true,
        
        // Methods - bind all imported functions
        formatDate,
        formatPlan,
        formatSchedule,
        getStateBadgeClass,
        generateRandomToken,
        initDateTimeInput,
        initFlatpickr,
        startPolling,
        stopPolling,
        fetchTasks,
        changeSort,
        toggleTaskExpand,
        showTaskDetail,
        closeTaskDetail,
        sortTasks,
        get filteredTasks() {
            return getFilteredTasks.call(this);
        },
        testFiltering,
        updateTasksUI,
        get attachmentsText() {
            return getAttachmentsText.call(this);
        },
        set attachmentsText(value) {
            setAttachmentsText.call(this, value);
        },
        deriveActiveProject,
        formatProjectName,
        formatProjectLabel,
        refreshProjectOptions,
        onProjectSelect,
        extractTaskProject,
        formatTaskProject,
        startCreateTask,
        startEditTask,
        cancelEdit,
        saveTask,
        runTask,
        resetTaskState,
        deleteTask,
    };
}
