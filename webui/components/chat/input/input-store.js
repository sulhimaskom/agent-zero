import { createStore } from "/js/AlpineStore.js";
import * as shortcuts from "/js/shortcuts.js";
import { store as fileBrowserStore } from "/components/modals/file-browser/file-browser-store.js";

const model = {
  paused: false,
  isSending: false,

  // Dynamic placeholder system
  placeholderIndex: 0,
  placeholderText: "Type your message here...",
  placeholderTyping: false,
  placeholderInterval: null,

  // Rotating placeholder messages - mix of helpful hints and personality
  placeholderMessages: [
    "Type your message here...",
    "Ask me anything...",
    "What would you like to explore?",
    "Press Ctrl+Shift+F for fullscreen input ✨",
    "Drop files or click the paperclip to attach 📎",
    "Press Enter to send, Shift+Enter for new line",
    "How can I help you today?",
    "Try asking about code, analysis, or creative tasks...",
  ],

  init() {
    console.log("Input store initialized");
    // Event listeners are now handled via Alpine directives in the component
    this.startPlaceholderRotation();
  },

  // Start the placeholder rotation cycle
  startPlaceholderRotation() {
    // Rotate every 6 seconds
    this.placeholderInterval = setInterval(() => {
      this.cyclePlaceholder();
    }, 6000);
  },

  // Stop the placeholder rotation (cleanup)
  stopPlaceholderRotation() {
    if (this.placeholderInterval) {
      clearInterval(this.placeholderInterval);
      this.placeholderInterval = null;
    }
  },

  // Cycle to the next placeholder with typing animation effect
  async cyclePlaceholder() {
    // Don't cycle if user is typing or input has content
    const chatInput = document.getElementById("chat-input");
    if (chatInput && chatInput.value.trim().length > 0) {
      return;
    }

    this.placeholderTyping = true;

    // Fade out effect
    await this.animatePlaceholderChange();

    // Move to next message
    this.placeholderIndex = (this.placeholderIndex + 1) % this.placeholderMessages.length;
    this.placeholderText = this.placeholderMessages[this.placeholderIndex];

    this.placeholderTyping = false;
  },

  // Animate placeholder change with typewriter effect
  animatePlaceholderChange() {
    return new Promise((resolve) => {
      const chatInput = document.getElementById("chat-input");
      if (!chatInput) {
        resolve();
        return;
      }

      // Check for reduced motion preference
      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      if (prefersReducedMotion) {
        // Instant change for accessibility
        resolve();
        return;
      }

      // Subtle fade transition
      chatInput.style.transition = 'opacity 0.2s ease';
      chatInput.style.opacity = '0.7';

      setTimeout(() => {
        chatInput.style.opacity = '1';
        setTimeout(resolve, 200);
      }, 200);
    });
  },

  async sendMessage() {
    if (this.isSending) return;
    this.isSending = true;
    try {
      // Delegate to the global function
      if (globalThis.sendMessage) {
        await globalThis.sendMessage();
      }
      window.dispatchEvent(new CustomEvent('sent-message'));
    } finally {
      this.isSending = false;
    }
  },

  adjustTextareaHeight() {
    const chatInput = document.getElementById("chat-input");
    if (chatInput) {
      chatInput.style.height = "auto";
      chatInput.style.height = chatInput.scrollHeight + "px";
    }
  },

  async pauseAgent(paused) {
    const prev = this.paused;
    this.paused = paused;
    try {
      const context = globalThis.getContext?.();
      if (!globalThis.sendJsonData)
        throw new Error("sendJsonData not available");
      await globalThis.sendJsonData("/pause", { paused, context });
    } catch (e) {
      this.paused = prev;
      if (globalThis.toastFetchError) {
        globalThis.toastFetchError("Error pausing agent", e);
      }
    }
  },

  async nudge() {
    try {
      const context = globalThis.getContext();
      await globalThis.sendJsonData("/nudge", { ctxid: context });
    } catch (e) {
      if (globalThis.toastFetchError) {
        globalThis.toastFetchError("Error nudging agent", e);
      }
    }
  },

  async loadKnowledge() {
    try {
      const resp = await shortcuts.callJsonApi("/knowledge_path_get", {
        ctxid: shortcuts.getCurrentContextId(),
      });
      if (!resp.ok) throw new Error("Error getting knowledge path");
      const path = resp.path;

      // open file browser and wait for it to close
      await fileBrowserStore.open(path);

      // progress notification
      shortcuts.frontendNotification({
        type: shortcuts.NotificationType.PROGRESS,
        message: "Loading knowledge...",
        priority: shortcuts.NotificationPriority.NORMAL,
        displayTime: 999,
        group: "knowledge_load",
        frontendOnly: true,
      });

      // then reindex knowledge
      await globalThis.sendJsonData("/knowledge_reindex", {
        ctxid: shortcuts.getCurrentContextId(),
      });

      // finished notification
      shortcuts.frontendNotification({
        type: shortcuts.NotificationType.SUCCESS,
        message: "Knowledge loaded successfully",
        priority: shortcuts.NotificationPriority.NORMAL,
        displayTime: 2,
        group: "knowledge_load",
        frontendOnly: true,
      });
    } catch (e) {
      // error notification
      shortcuts.frontendNotification({
        type: shortcuts.NotificationType.ERROR,
        message: "Error loading knowledge",
        priority: shortcuts.NotificationPriority.NORMAL,
        displayTime: 5,
        group: "knowledge_load",
        frontendOnly: true,
      });
    }
  },

  // previous implementation without projects
  async _loadKnowledge() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".txt,.pdf,.csv,.html,.json,.md";
    input.multiple = true;

    input.onchange = async () => {
      try {
        const formData = new FormData();
        for (let file of input.files) {
          formData.append("files[]", file);
        }

        formData.append("ctxid", globalThis.getContext());

        const response = await globalThis.fetchApi("/import_knowledge", {
          method: "POST",
          body: formData,
        });

        if (!response.ok) {
          if (globalThis.toast)
            globalThis.toast(await response.text(), "error");
        } else {
          const data = await response.json();
          if (globalThis.toast) {
            globalThis.toast(
              "Knowledge files imported: " + data.filenames.join(", "),
              "success"
            );
          }
        }
      } catch (e) {
        if (globalThis.toastFetchError) {
          globalThis.toastFetchError("Error loading knowledge", e);
        }
      }
    };

    input.click();
  },

  async browseFiles(path) {
    if (!path) {
      try {
        const resp = await shortcuts.callJsonApi("/chat_files_path_get", {
          ctxid: shortcuts.getCurrentContextId(),
        });
        if (resp.ok) path = resp.path;
      } catch (_e) {
        console.error("Error getting chat files path", _e);
      }
    }
    await fileBrowserStore.open(path);
  },
};

const store = createStore("chatInput", model);

export { store };
