/**
 * Scheduler UI Module
 * UI state, filters, sorting, and display logic
 */

/**
 * Show toast notification (imported from parent module)
 */
let showToast = null;

/**
 * Set the showToast function from parent
 * @param {Function} fn - Toast notification function
 */
export function setShowToastUi(fn) {
  showToast = fn;
}

/**
 * Change sort field/direction
 * @param {string} field - Field to sort by
 */
export function changeSort(field) {
  if (this.sortField === field) {
    // Toggle direction if already sorting by this field
    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
  } else {
    // Set new sort field and default to ascending
    this.sortField = field;
    this.sortDirection = 'asc';
  }
}

/**
 * Toggle expanded task row
 * @param {string} taskId - Task UUID
 */
export function toggleTaskExpand(taskId) {
  if (this.expandedTaskId === taskId) {
    this.expandedTaskId = null;
  } else {
    this.expandedTaskId = taskId;
  }
}

/**
 * Show task detail view
 * @param {string} taskId - Task UUID
 */
export function showTaskDetail(taskId) {
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
}

/**
 * Close detail view and return to list
 */
export function closeTaskDetail() {
  this.selectedTaskForDetail = null;
  this.viewMode = 'list';
}

/**
 * Sort the tasks based on sort field and direction
 * @param {Array} tasks - Array of tasks to sort
 * @returns {Array} Sorted tasks
 */
export function sortTasks(tasks) {
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
}

/**
 * Getter for filtered tasks
 */
export function getFilteredTasks() {
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
}

/**
 * Debug method to test filtering logic
 */
export function testFiltering() {
  // Placeholder for debugging
}

/**
 * Update tasks UI - update visibility of empty state and task list
 */
export function updateTasksUI() {
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

/**
 * Computed property for attachments text representation
 */
export function getAttachmentsText() {
  // Ensure we always have an array to work with
  const attachments = Array.isArray(this.editingTask.attachments)
    ? this.editingTask.attachments
    : [];

  // Join array items with newlines
  return attachments.join('\n');
}

/**
 * Setter for attachments text - preserves empty lines during editing
 * @param {string} value - Text value
 */
export function setAttachmentsText(value) {
  if (typeof value === 'string') {
    // Just split by newlines without filtering to preserve editing experience
    this.editingTask.attachments = value.split('\n');
  } else {
    // Fallback to empty array if not a string
    this.editingTask.attachments = [];
  }
}
