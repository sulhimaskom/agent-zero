import { createStore } from '/js/AlpineStore.js';
import { getRegisteredShortcuts } from '/js/keyboard-shortcuts.js';

const model = {
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

export const store = createStore('keyboardShortcuts', model);
