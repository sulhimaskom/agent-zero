import { createStore } from "/js/AlpineStore.js";

const model = {
  versionNo: "",
  commitTime: "",

  get versionLabel() {
    return this.versionNo && this.commitTime
      ? `Version ${this.versionNo} ${this.commitTime}`
      : "";
  },

  init() {
    const gi = globalThis.gitinfo;
    if (gi && gi.version && gi.commit_time) {
      this.versionNo = gi.version;
      this.commitTime = gi.commit_time;
    }
  },

  async copyVersion() {
    const textToCopy = this.versionLabel;
    if (!textToCopy) return;

    try {
      await navigator.clipboard.writeText(textToCopy);
    } catch (err) {
      console.warn("Failed to copy version:", err);
    }
  },
};

export const store = createStore("sidebarBottom", model);

