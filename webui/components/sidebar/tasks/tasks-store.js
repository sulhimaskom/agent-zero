import { createStore } from '/js/AlpineStore.js';
import Logger from '/js/logger.js';
import { store as chatsStore } from '/components/sidebar/chats/chats-store.js';

// Tasks sidebar store: tasks list and selected task id
const model = {
  tasks: [],
  selected: '',
  isLoading: true,

  init() {
    // No-op: data is driven by poll() in index.js; this store provides a stable target
  },

  // Apply tasks coming from poll() and keep them sorted (newest first)
  applyTasks(tasksList) {
    try {
      const tasks = Array.isArray(tasksList) ? tasksList : [];
      const sorted = [...tasks].sort((a, b) => (b?.created_at || 0) - (a?.created_at || 0));
      this.tasks = sorted;

      // After updating tasks, ensure selection is still valid
      if (this.selected && !this.contains(this.selected)) {
        this.setSelected('');
      }
      this.isLoading = false;
    } catch (e) {
      Logger.error('tasks-store.applyTasks failed', e);
      // Show toast only if this is the first load (tasks were expected)
      if (this.tasks.length === 0 && this.isLoading) {
        window.toastFrontendWarning(
          'Could not load tasks. Will retry on next poll.',
          'Tasks',
          5,
        );
      }
      this.tasks = [];
      this.isLoading = false;
    }
  },

  // Update selected task and persist for tab restore
  setSelected(taskId) {
    this.selected = taskId || '';
    try { localStorage.setItem('lastSelectedTask', this.selected); } catch {}
  },

  // Returns true if a task with the given id exists in the current list
  contains(taskId) {
    return Array.isArray(this.tasks) && this.tasks.some((t) => t?.id === taskId);
  },

  // Convenience: id of the first task in the current list (or empty string)
  firstId() {
    return (Array.isArray(this.tasks) && this.tasks[0]?.id) || '';
  },

  // Action methods for task management
  selectTask(taskId) {
    this.setSelected(taskId);
    chatsStore.selectChat(taskId);
  },

  openDetail(taskId) {
    if (globalThis.openTaskDetail) {
      globalThis.openTaskDetail(taskId);
    }
  },

  reset(taskId) {
    chatsStore.resetChat(taskId);
  },

  deleteTask(taskId) {
    if (globalThis.deleteTaskGlobal) {
      globalThis.deleteTaskGlobal(taskId);
    }
  },
};

export const store = createStore('tasks', model);


