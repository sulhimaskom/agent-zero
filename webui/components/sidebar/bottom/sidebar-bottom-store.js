import { createStore } from '/js/AlpineStore.js';
import Logger from '/js/logger.js';

const model = {
  versionNo: '',
  commitTime: '',

  get versionLabel() {
    return this.versionNo && this.commitTime
      ? `Version ${this.versionNo} ${this.commitTime}`
      : '';
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
    if (!textToCopy) return false;

    try {
      await navigator.clipboard.writeText(textToCopy);
      if (window.toastFrontendInfo) {
        window.toastFrontendInfo('Version info copied to clipboard', 'Copied');
      }
      return true;
    } catch (err) {
      Logger.warn('Failed to copy version:', err);
      if (window.toastFrontendError) {
        window.toastFrontendError('Failed to copy version info', 'Copy Error');
      }
      return false;
    }
  },
};

export const store = createStore('sidebarBottom', model);

