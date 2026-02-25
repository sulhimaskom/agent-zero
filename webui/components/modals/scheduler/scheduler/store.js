// -----------------------------------------------------------------------------
// Main scheduler store - imports modular components
// -----------------------------------------------------------------------------
import { createStore } from "/js/AlpineStore.js";
import { formatDateTime, getUserTimezone, TASK_TYPES, VIEW_MODE_STORAGE_KEY } from "./constants.js";
import {
  defaultEditingTask,
  composeEditingTask,
  buildPayloadFromEditingTask,
  extractProjectInfo,
  safeJsonClone,
  normalizePlanStruct,
  emptyPlan,
  readPersistedViewMode,
  sortByDate,
} from "./helpers.js";
import { schedulerApi } from "./api.js";
import { pushNotification } from "./notifications.js";
import { setupPlannerInput, destroyPlannerInput, readDateFromPlannerInput } from "./flatpickr-utils.js";

// Import other stores for cross-store operations
import { store as chatsStore } from "/components/sidebar/chats/chats-store.js";
import { store as projectsStore } from "/components/projects/projects-store.js";

// -----------------------------------------------------------------------------
// Store Definition
// -----------------------------------------------------------------------------

const schedulerStoreModel = {
  // Core collection state -----------------------------------------------------
  tasks: [],
  isLoading: false,
  showLoadingState: false,
  hasNoTasks: true,

  // Filtering & view ---------------------------------------------------------
  filterType: "all",
  filterState: "all",
  sortField: "name",
  sortDirection: "asc",
  viewMode: readPersistedViewMode(),
  selectedTaskForDetail: null,

  // Pagination ---------------------------------------------------------------
  currentPage: 1,
  pageSize: 10,

  // Editor state -------------------------------------------------------------
  isCreating: false,
  isEditing: false,
  editingTask: defaultEditingTask(),
  selectedProjectSlug: "",
  projectOptions: [],

  // Polling ------------------------------------------------------------------
  pollingInterval: null,
  pollingActive: false,

  // Computed -----------------------------------------------------------------
  get filteredTasks() {
    if (!Array.isArray(this.tasks)) return [];
    let filtered = [...this.tasks];

    if (this.filterType && this.filterType !== "all") {
      filtered = filtered.filter((task) =>
        task.type ? task.type.toLowerCase() === this.filterType.toLowerCase() : false
      );
    }

    if (this.filterState && this.filterState !== "all") {
      filtered = filtered.filter((task) =>
        task.state ? task.state.toLowerCase() === this.filterState.toLowerCase() : false
      );
    }

    return this.sortTasks(filtered);
  },

  get totalPages() {
    if (!Array.isArray(this.filteredTasks) || this.filteredTasks.length === 0) return 1;
    return Math.ceil(this.filteredTasks.length / this.pageSize);
  },

  get paginatedTasks() {
    if (!Array.isArray(this.filteredTasks)) return [];
    // Ensure currentPage is within valid range
    const maxPage = this.totalPages;
    if (this.currentPage > maxPage) {
      this.currentPage = Math.max(1, maxPage);
    }
    const start = (this.currentPage - 1) * this.pageSize;
    const end = start + this.pageSize;
    return this.filteredTasks.slice(start, end);
  },

  get attachmentsText() {
    const attachments = Array.isArray(this.editingTask.attachments)
      ? this.editingTask.attachments
      : [];
    return attachments.join("\n");
  },

  set attachmentsText(value) {
    if (typeof value === "string") {
      this.editingTask.attachments = value.split("\n");
    } else {
      this.editingTask.attachments = [];
    }
  },

  // Lifecycle ----------------------------------------------------------------
  init() {
    this.resetEditingTask();
    this.refreshProjectOptions();
  },

  persistViewMode(mode) {
    this.viewMode = mode;
    try {
      window.localStorage?.setItem(VIEW_MODE_STORAGE_KEY, mode);
    } catch {
      /* ignore storage failures */
    }
  },

  setViewMode(mode) {
    this.persistViewMode(mode);
  },

  onTabActivated() {
    this.pollingActive = true;
    this.startPolling();
  },

  onTabDeactivated() {
    this.stopPolling();
  },

  async onModalClosed() {
    this.stopPolling();
    this.destroyFlatpickr("all");
    this.isCreating = false;
    this.isEditing = false;
    this.resetEditingTask();
    this.selectedTaskForDetail = null;
    this.persistViewMode("list");
  },

  startPolling() {
    if (this.pollingInterval) return;
    this.fetchTasks();
    this.pollingInterval = setInterval(() => {
      if (this.pollingActive) {
        this.fetchTasks();
      }
    }, 2000);
  },

  stopPolling() {
    this.pollingActive = false;
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  },

  // Data fetching -------------------------------------------------------------
  async fetchTasks({ manual = false } = {}) {
    if (this.isCreating || this.isEditing) return;
    if (manual) this.isLoading = true;

    try {
      const { ok, error, tasks } = await schedulerApi.listTasks();
      if (!ok) {
        if (manual) this.notifyError(`Failed to fetch tasks: ${error}`);
        this.tasks = [];
        this.hasNoTasks = true;
        return;
      }

      // Smart merge: preserve object references to prevent UI flickering
      const taskMap = new Map(this.tasks.map((t) => [t.uuid, t]));
      this.tasks = tasks.map((newTask) => {
        const existing = taskMap.get(newTask.uuid);
        if (existing) {
          // Update existing object in-place if different
          if (JSON.stringify(existing) !== JSON.stringify(newTask)) {
            Object.assign(existing, newTask);
          }
          return existing; // Return the SAME object reference
        }
        return newTask; // New object
      });

      this.hasNoTasks = this.tasks.length === 0;
    } catch (error) {
      if (manual) this.notifyError(`Failed to fetch tasks: ${error.message}`);
      this.tasks = [];
      this.hasNoTasks = true;
    } finally {
      this.isLoading = false;
    }
  },

  async saveTask() {
    if (!this.editingTask.name?.trim() || !this.editingTask.prompt?.trim()) {
      window.alert("Task name and prompt are required");
      return;
    }

    if (!TASK_TYPES.includes(this.editingTask.type)) {
      window.alert("Invalid task type");
      return;
    }

    if (this.editingTask.type === "adhoc" && !this.editingTask.token) {
      this.editingTask.token = this.generateRandomToken();
    }

    const payload = buildPayloadFromEditingTask(this.editingTask, {
      isCreating: this.isCreating,
    });

    try {
      const result = this.isCreating
        ? await schedulerApi.createTask(payload)
        : await schedulerApi.updateTask(payload);

      if (!result.ok) {
        throw new Error(result.error);
      }

      const message = this.isCreating
        ? "Task created successfully"
        : "Task updated successfully";
      this.notifySuccess(message);

      if (result.task) {
        if (this.isCreating) {
          this.tasks = [...this.tasks, result.task];
        } else {
          this.tasks = this.tasks.map((task) =>
            task.uuid === result.task.uuid ? result.task : task
          );
        }
      } else {
        await this.fetchTasks({ manual: true });
      }
    } catch (error) {
      this.notifyError(`Failed to save task: ${error.message}`);
      return;
    } finally {
      this.destroyFlatpickr("all");
      this.resetEditingTask();
      this.isCreating = false;
      this.isEditing = false;
    }
  },

  async runTask(taskId) {
    try {
      const result = await schedulerApi.runTask(taskId);
      if (!result.ok) throw new Error(result.error);
      const warning = result.data?.warning;
      const message = result.data?.message || "Task started successfully";
      if (warning) {
        this.notifyWarning(warning);
      } else {
        this.notifySuccess(message);
      }
      this.fetchTasks({ manual: true });
    } catch (error) {
      this.notifyError(`Failed to run task: ${error.message}`);
    }
  },

  async resetTaskState(taskId) {
    const task = this.tasks.find((t) => t.uuid === taskId);
    if (!task) {
      this.notifyError("Task not found");
      return;
    }
    if (task.state === "idle") {
      this.notifyInfo("Task is already in idle state");
      return;
    }

    this.showLoadingState = true;
    try {
      const result = await schedulerApi.updateTask({ task_id: taskId, state: "idle" });
      if (!result.ok) throw new Error(result.error);
      this.notifySuccess("Task state reset to idle");
      await this.fetchTasks({ manual: true });
    } catch (error) {
      this.notifyError(`Failed to reset task state: ${error.message}`);
    } finally {
      this.showLoadingState = false;
    }
  },

  async deleteTask(taskId) {
    try {
      if (typeof chatsStore.switchFromContext === "function") {
        await chatsStore.switchFromContext(taskId);
      }
    } catch (error) {
      console.warn("[scheduler] Failed to switch from context before delete", error);
    }

    try {
      const result = await schedulerApi.deleteTask(taskId);
      if (!result.ok) throw new Error(result.error);
      this.notifySuccess("Task deleted successfully");
      this.tasks = this.tasks.filter((task) => task.uuid !== taskId);
      this.hasNoTasks = this.tasks.length === 0;
      if (this.selectedTaskForDetail?.uuid === taskId) {
        this.closeTaskDetail();
      }
    } catch (error) {
      this.notifyError(`Failed to delete task: ${error.message}`);
    }
  },

  async deleteTaskFromSidebar(taskId) {
    await this.deleteTask(taskId);
  },

  // Domain helpers -----------------------------------------------------------
  resetEditingTask() {
    this.editingTask = defaultEditingTask();
    this.selectedProjectSlug = "";
  },

  setEditingTask(task) {
    const normalized = composeEditingTask(task);
    this.editingTask = normalized;
    this.selectedProjectSlug = normalized.project?.name || "";
  },

  async refreshProjectOptions() {
    try {
      if (
        !Array.isArray(projectsStore.projectList) ||
        projectsStore.projectList.length === 0
      ) {
        if (typeof projectsStore.loadProjectsList === "function") {
          await projectsStore.loadProjectsList();
        }
      }
    } catch (error) {
      console.warn("[scheduler] Failed to load project list", error);
    }

    const list = Array.isArray(projectsStore.projectList)
      ? projectsStore.projectList
      : [];

    this.projectOptions = list.map((proj) => ({
      name: proj.name,
      title: proj.title || proj.name,
      color: proj.color || "",
    }));
  },

  deriveActiveProject() {
    const selected = chatsStore?.selectedContext || null;
    if (!selected || !selected.project) return null;
    const project = selected.project;
    return {
      name: project.name || null,
      title: project.title || project.name || null,
      color: project.color || "",
    };
  },

  onProjectSelect(slug) {
    this.selectedProjectSlug = slug || "";
    if (!slug) {
      this.editingTask.project = null;
      return;
    }

    const option = this.projectOptions.find((item) => item.name === slug);
    if (option) {
      this.editingTask.project = { ...option };
    } else {
      this.editingTask.project = { name: slug, title: slug, color: "" };
    }
  },

  changeSort(field) {
    if (this.sortField === field) {
      this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
    } else {
      this.sortField = field;
      this.sortDirection = "asc";
    }
    // Reset to first page when sorting changes
    this.currentPage = 1;
  },

  // Pagination methods --------------------------------------------------------
  nextPage() {
    if (this.currentPage < this.totalPages) {
      this.currentPage++;
    }
  },

  prevPage() {
    if (this.currentPage > 1) {
      this.currentPage--;
    }
  },

  goToPage(page) {
    const pageNum = parseInt(page, 10);
    if (Number.isNaN(pageNum)) return;
    if (pageNum < 1) {
      this.currentPage = 1;
    } else if (pageNum > this.totalPages) {
      this.currentPage = this.totalPages;
    } else {
      this.currentPage = pageNum;
    }
  },

  sortTasks(tasks) {
    if (!Array.isArray(tasks) || tasks.length === 0) return tasks;
    const direction = this.sortDirection === "asc" ? 1 : -1;
    const field = this.sortField;
    return [...tasks].sort((a, b) => {
      const fieldA = a[field];
      const fieldB = b[field];
      if (fieldA === undefined && fieldB === undefined) return 0;
      if (fieldA === undefined) return 1;
      if (fieldB === undefined) return -1;
      if (["createdAt", "updatedAt", "last_run"].includes(field)) {
        return (sortByDate(fieldA) - sortByDate(fieldB)) * direction;
      }
      if (typeof fieldA === "string" && typeof fieldB === "string") {
        return fieldA.localeCompare(fieldB) * direction;
      }
      return (fieldA - fieldB) * direction;
    });
  },

  formatDate(dateString) {
    if (!dateString) return "Never";
    return formatDateTime(dateString, "full");
  },

  formatPlan(task) {
    if (!task || !task.plan) return "No plan";
    const todoCount = Array.isArray(task.plan.todo) ? task.plan.todo.length : 0;
    const inProgress = task.plan.in_progress ? "Yes" : "No";
    const doneCount = Array.isArray(task.plan.done) ? task.plan.done.length : 0;
    let nextRun = "";
    if (Array.isArray(task.plan.todo) && task.plan.todo.length > 0) {
      const nextTime = new Date(task.plan.todo[0]);
      nextRun = Number.isNaN(nextTime.getTime())
        ? "Invalid date"
        : formatDateTime(nextTime, "short");
    } else {
      nextRun = "None";
    }
    return `Next: ${nextRun}\nTodo: ${todoCount}\nIn Progress: ${inProgress}\nDone: ${doneCount}`;
  },

  formatSchedule(task) {
    if (!task.schedule) return "None";
    if (typeof task.schedule === "string") return task.schedule;
    return `${task.schedule.minute || "*"} ${task.schedule.hour || "*"} ${
      task.schedule.day || "*"
    } ${task.schedule.month || "*"} ${task.schedule.weekday || "*"}`;
  },

  formatTaskType(type) {
    const typeMap = {
      scheduled: "Scheduled",
      adhoc: "Ad-hoc",
      planned: "Planned",
    };
    return typeMap[type] || type;
  },

  getStateBadgeClass(state) {
    switch (state) {
      case "idle":
        return "scheduler-status-idle";
      case "running":
        return "scheduler-status-running";
      case "disabled":
        return "scheduler-status-disabled";
      case "error":
        return "scheduler-status-error";
      default:
        return "";
    }
  },

  extractTaskProject(task) {
    return extractProjectInfo(task);
  },

  formatProjectName(project) {
    if (!project) return "No Project";
    return project.title || project.name || "No Project";
  },

  formatProjectLabel(project) {
    return `Project: ${this.formatProjectName(project)}`;
  },

  formatTaskProject(task) {
    return this.formatProjectName(this.extractTaskProject(task));
  },

  syncTasksFromSidebar(sidebarTasks) {
    // Sync scheduler store with sidebar's poll data for instant access
    if (!Array.isArray(sidebarTasks) || sidebarTasks.length === 0) return;

    // Smart merge: preserve object references to prevent UI flickering
    const taskMap = new Map(this.tasks.map((t) => [t.uuid, t]));
    this.tasks = sidebarTasks.map((sidebarTask) => {
      const taskId = sidebarTask.uuid || sidebarTask.id;
      const existing = taskMap.get(taskId);
      if (existing) {
        // Update existing object in-place if different
        if (JSON.stringify(existing) !== JSON.stringify(sidebarTask)) {
          Object.assign(existing, sidebarTask);
        }
        return existing;
      }
      return sidebarTask;
    });
    this.hasNoTasks = this.tasks.length === 0;
  },

  showTaskDetail(taskId) {
    // Sync with sidebar data if our array is empty (e.g., on page load before modal opened)
    if (this.tasks.length === 0) {
      const tasksStore = globalThis.Alpine?.store?.("tasks");
      if (tasksStore?.tasks?.length > 0) {
        this.syncTasksFromSidebar(tasksStore.tasks);
      }
    }

    const task = this.tasks.find((t) => t.uuid === taskId);
    if (!task) {
      this.notifyError("Task not found");
      return;
    }

    const snapshot = safeJsonClone(task);
    if (!snapshot.attachments) {
      snapshot.attachments = [];
    }

    this.selectedTaskForDetail = snapshot;
    const closePromise = window.openModal("modals/scheduler/scheduler-task-detail.html");
    if (closePromise && typeof closePromise.then === "function") {
      closePromise.then(() => {
        if (this.selectedTaskForDetail?.uuid === snapshot.uuid) {
          this.selectedTaskForDetail = null;
        }
      });
    }
  },

  closeTaskDetail() {
    this.selectedTaskForDetail = null;
    window.closeModal();
  },

  async editFromDetail() {
    const taskId = this.selectedTaskForDetail?.uuid;
    if (!taskId) return;
    this.closeTaskDetail();
    await this.startEditTask(taskId);
    // Open main scheduler modal to show the editor
    window.openModal("modals/scheduler/scheduler-modal.html");
  },

  async deleteFromDetail() {
    const taskId = this.selectedTaskForDetail?.uuid;
    if (!taskId) return;
    await this.deleteTask(taskId);
  },

  async startCreateTask() {
    this.isCreating = true;
    this.isEditing = false;
    await this.refreshProjectOptions();

    let initialProject = this.deriveActiveProject();
    if (!initialProject && this.projectOptions.length > 0) {
      initialProject = { ...this.projectOptions[0] };
    }

    this.editingTask = defaultEditingTask({
      token: this.generateRandomToken(),
      project: initialProject,
    });
    this.selectedProjectSlug = initialProject?.name || "";
    setTimeout(() => this.initFlatpickr("create"), 100);
  },

  async startEditTask(taskId) {
    const task = this.tasks.find((t) => t.uuid === taskId);
    if (!task) {
      this.notifyError("Task not found");
      return;
    }

    this.isCreating = false;
    this.isEditing = true;
    this.setEditingTask(safeJsonClone(task));
    setTimeout(() => this.initFlatpickr("edit"), 100);
  },

  cancelEdit() {
    this.destroyFlatpickr("all");
    this.resetEditingTask();
    this.selectedProjectSlug = "";
    this.isCreating = false;
    this.isEditing = false;
  },

  normalizePlan() {
    this.editingTask.plan = normalizePlanStruct(this.editingTask.plan);
  },

  addPlannedTime(mode = "create") {
    if (!this.editingTask.plan) {
      this.editingTask.plan = emptyPlan();
    }
    if (!Array.isArray(this.editingTask.plan.todo)) {
      this.editingTask.plan.todo = [];
    }

    const inputId = mode === "edit" ? "newPlannedTime-edit" : "newPlannedTime-create";
    const input = document.getElementById(inputId);
    if (!input) {
      console.warn("[scheduler] Input element not found for planned time", inputId);
      return;
    }

    const selectedDate = readDateFromPlannerInput(input);
    if (!selectedDate) {
      window.alert("Please select a valid date and time");
      return;
    }

    this.editingTask.plan.todo.push(selectedDate.toISOString());
    this.editingTask.plan.todo.sort();

    if (input._flatpickr) {
      input._flatpickr.clear();
    } else {
      input.value = "";
    }
  },

  generateRandomToken() {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let token = "";
    for (let i = 0; i < 16; i++) {
      token += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return token;
  },

  // UI bridge helpers --------------------------------------------------------
  initFlatpickr(mode = "all") {
    if (mode === "all" || mode === "create") {
      setupPlannerInput("newPlannedTime-create");
    }
    if (mode === "all" || mode === "edit") {
      setupPlannerInput("newPlannedTime-edit");
    }
  },

  destroyFlatpickr(mode = "all") {
    if (mode === "all" || mode === "create") {
      destroyPlannerInput("newPlannedTime-create");
    }
    if (mode === "all" || mode === "edit") {
      destroyPlannerInput("newPlannedTime-edit");
    }
  },

  // Notifications ------------------------------------------------------------
  notifySuccess(message, options = {}) {
    pushNotification("success", message, options.title, options.duration);
  },

  notifyInfo(message, options = {}) {
    pushNotification("info", message, options.title, options.duration);
  },

  notifyWarning(message, options = {}) {
    pushNotification("warning", message, options.title, options.duration);
  },

  notifyError(message, options = {}) {
    pushNotification("error", message, options.title, options.duration);
  },
};

// -----------------------------------------------------------------------------
// Store Creation and Export
// -----------------------------------------------------------------------------
const store = createStore("schedulerStore", schedulerStoreModel);

export { store };
