import { createStore } from "/js/AlpineStore.js";
import { getContext } from "/index.js";
import { sendJsonData } from "/js/api.js";
import { API_ENDPOINTS } from "/js/constants.js";
import { store as chatsStore } from "/components/sidebar/chats/chats-store.js";
import { store as memoryStore } from "/components/settings/memory/memory-dashboard-store.js";
import { store as projectsStore } from "/components/projects/projects-store.js";
import { TIMING } from "/js/constants.js";
import Logger from '/js/logger.js';

const model = {
  // State
  isVisible: true,
  wizardChecked: false,
  visibilityIntervalId: null,

  init() {
    // Initialize visibility based on current context
    this.updateVisibility();

    // Check for first-time user and auto-open setup wizard
    this.checkFirstTime();

    // Watch for context changes with faster polling for immediate response
    this.visibilityIntervalId = setInterval(() => {
      this.updateVisibility();
    }, TIMING.WELCOME_ANIMATION_DELAY); // Use timing constant for responsive updates
  },

  // Check if first-time user and open setup wizard
  async checkFirstTime() {
    // Only check once
    if (this.wizardChecked) return;
    this.wizardChecked = true;

    try {
      const response = await sendJsonData(API_ENDPOINTS.SETTINGS_STATUS, null);
      if (response && response.isFirstTime) {
        // Auto-open the setup wizard for first-time users
        this.openSetupWizard();
      }
    } catch (e) {
      Logger.error('Failed to check settings status:', e);
    }
  },

  // Open setup wizard
  openSetupWizard() {
    if (window.Alpine && Alpine.store) {
      const wizardStore = Alpine.store('setupWizardStore');
      if (wizardStore) {
        wizardStore.open();
      }
    }
  },

  // Update visibility based on current context
  updateVisibility() {
    const hasContext = !!getContext();
    this.isVisible = !hasContext;
  },

  // Hide welcome screen
  hide() {
    this.isVisible = false;
  },

  // Show welcome screen
  show() {
    this.isVisible = true;
  },

  // Cleanup interval to prevent memory leaks
  cleanup() {
    if (this.visibilityIntervalId) {
      clearInterval(this.visibilityIntervalId);
      this.visibilityIntervalId = null;
    }
  },

  // Execute an action by ID
  executeAction(actionId) {
    switch (actionId) {
      case "new-chat":
        chatsStore.newChat();
        break;
      case "settings":
        // Open settings modal
        const settingsButton = document.getElementById("settings");
        if (settingsButton) {
          settingsButton.click();
        }
        break;
      case "projects":
        projectsStore.openProjectsModal();
        break;
      case "memory":
        memoryStore.openModal();
        break;
      case "website":
        window.open("https://agent-zero.ai", "_blank");
        break;
      case "github":
        window.open("https://github.com/agent0ai/agent-zero", "_blank");
        break;
      case "setup":
        // Open setup wizard
        this.openSetupWizard();
        break;
    }
  },
};

// Create and export the store
const store = createStore("welcomeStore", model);
export { store };
