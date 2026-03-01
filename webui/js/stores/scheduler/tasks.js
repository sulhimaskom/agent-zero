/**
 * Scheduler Tasks Module
 * Task CRUD operations and project management
 */
import { store as chatsStore } from '/components/sidebar/chats/chats-store.min.js';
import { store as projectsStore } from '/components/projects/projects-store.min.js';
import { getUserTimezone } from '../../time-utils.js';
import { generateRandomToken } from './datetime.js';
import Logger from '../../logger.min.js';

/**
 * Show toast notification (imported from parent module)
 */
let showToast = null;

/**
 * Set the showToast function from parent
 * @param {Function} fn - Toast notification function
 */
export function setShowToastTasks(fn) {
  showToast = fn;
}

/**
 * Derive active project from chats store
 * @returns {Object|null} Project object or null
 */
export function deriveActiveProject() {
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
}

/**
 * Format project name for display
 * @param {Object} project - Project object
 * @returns {string} Formatted project name
 */
export function formatProjectName(project) {
  if (!project) {
    return 'No Project';
  }
  const title = project.title || project.name;
  return title || 'No Project';
}

/**
 * Format project label for display
 * @param {Object} project - Project object
 * @returns {string} Formatted label
 */
export function formatProjectLabel(project) {
  return `Project: ${this.formatProjectName(project)}`;
}

/**
 * Refresh project options from projects store
 */
export async function refreshProjectOptions() {
  try {
    if (!Array.isArray(projectsStore.projectList) || !projectsStore.projectList.length) {
      if (typeof projectsStore.loadProjectsList === 'function') {
        await projectsStore.loadProjectsList();
      }
    }
  } catch (_error) {
    // Silently handle errors
  }

  const list = Array.isArray(projectsStore.projectList) ? projectsStore.projectList : [];
  this.projectOptions = list.map((proj) => ({
    name: proj.name,
    title: proj.title || proj.name,
    color: proj.color || '',
  }));
}

/**
 * Handle project selection
 * @param {string} slug - Project slug/name
 */
export function onProjectSelect(slug) {
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
}

/**
 * Extract project from task
 * @param {Object} task - Task object
 * @returns {Object|null} Project object or null
 */
export function extractTaskProject(task) {
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
    color,
  };
}

/**
 * Format task project for display
 * @param {Object} task - Task object
 * @returns {string} Formatted project name
 */
export function formatTaskProject(task) {
  return this.formatProjectName(this.extractTaskProject(task));
}

/**
 * Create a new task - start creation flow
 */
export async function startCreateTask() {
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
      timezone: getUserTimezone(),
    },
    token: this.generateRandomToken(), // Generate token even for scheduled tasks to prevent undefined errors
    plan: { // Initialize plan for all task types to prevent undefined errors
      todo: [],
      in_progress: null,
      done: [],
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
}

/**
 * Edit an existing task - start edit flow
 * @param {string} taskId - Task UUID
 */
export async function startEditTask(taskId) {
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
    const scheduleObj = {
      minute: '*',
      hour: '*',
      day: '*',
      month: '*',
      weekday: '*',
      timezone: getUserTimezone(),
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
        done: [],
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
        done: [],
      };
    }
  } else if (this.editingTask.type === 'planned') {
    // Initialize plan if it doesn't exist
    if (!this.editingTask.plan) {
      this.editingTask.plan = {
        todo: [],
        in_progress: null,
        done: [],
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
}

/**
 * Cancel editing - reset form state
 */
export function cancelEdit() {
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
      timezone: getUserTimezone(),
    },
    token: '',
    plan: { // Initialize plan for planned tasks
      todo: [],
      in_progress: null,
      done: [],
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
}

/**
 * Save task (create new or update existing)
 */
export async function saveTask() {
  // Validate task data
  if (!this.editingTask.name.trim() || !this.editingTask.prompt.trim()) {
    showToast('Task name and prompt are required', 'error');
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
      timezone: getUserTimezone(),
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
          timezone: getUserTimezone(), // Add timezone to schedule object
        };
      } else {
        // Use object schedule directly but ensure timezone is included
        taskData.schedule = {
          ...this.editingTask.schedule,
          timezone: this.editingTask.schedule.timezone || getUserTimezone(),
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
          done: [],
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
          // Skip invalid dates
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
        done: this.editingTask.plan.done || [],
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
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(taskData),
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
          t.uuid === responseData.task.uuid ? responseData.task : t,
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
        timezone: getUserTimezone(),
      },
      token: '',
      plan: {
        todo: [],
        in_progress: null,
        done: [],
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
    showToast(`Failed to save task: ${  error.message}`, 'error');
  }
}

/**
 * Run a task
 * @param {string} taskId - Task UUID
 */
export async function runTask(taskId) {
  try {
    const response = await fetchApi('/scheduler_task_run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        task_id: taskId,
        timezone: getUserTimezone(),
      }),
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
    showToast(`Failed to run task: ${  error.message}`, 'error');
  }
}

/**
 * Reset a task's state
 * @param {string} taskId - Task UUID
 */
export async function resetTaskState(taskId) {
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
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        task_id: taskId,
        state: 'idle',  // Always reset to idle state
        timezone: getUserTimezone(),
      }),
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
    showToast(`Failed to reset task state: ${  error.message}`, 'error');
    this.showLoadingState = false;
  }
}

/**
 * Delete a task
 * @param {string} taskId - Task UUID
 */
export async function deleteTask(taskId) {
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
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        task_id: taskId,
        timezone: getUserTimezone(),
      }),
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
    showToast(`Failed to delete task: ${  error.message}`, 'error');
  }
}
