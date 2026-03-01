import { getRegisteredShortcuts } from '/js/keyboard-shortcuts.js';

export const store = {
  isOpen: false,
  shortcuts: [],

  init() {
    this.loadShortcuts();
  },

  loadShortcuts() {
    const registered = getRegisteredShortcuts();
    this.shortcuts = Object.entries(registered).map(([key, description]) => ({
      key,
      description,
    }));
  },

  open() {
    this.loadShortcuts();
    openModal('modals/keyboard-shortcuts/keyboard-shortcuts.html', {
      title: 'Keyboard Shortcuts',
      width: '500px',
      height: 'auto',
    });
    this.isOpen = true;
  },

  close() {
    closeModal();
    this.isOpen = false;
  },
};

if (globalThis.Alpine) {
  globalThis.Alpine.store('keyboardShortcuts', store);
} else {
  document.addEventListener('alpine:init', () => {
    globalThis.Alpine.store('keyboardShortcuts', store);
  });
}
