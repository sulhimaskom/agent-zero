import { store as chatInputStore } from '/components/chat/input/input-store.min.js';
import Logger from '/js/logger.js';
import { store as historyStore } from '/components/modals/history/history-store.min.js';
import { store as contextStore } from '/components/modals/context/context-store.min.js';

const shortcuts = {
  'ctrl+space': {
    handler: () => {
      if (chatInputStore && typeof chatInputStore.pauseAgent === 'function') {
        chatInputStore.pauseAgent(!chatInputStore.paused);
      }
    },
    description: 'Pause/Resume Agent',
  },
  'ctrl+k': {
    handler: () => {
      if (chatInputStore && typeof chatInputStore.loadKnowledge === 'function') {
        chatInputStore.loadKnowledge();
      }
    },
    description: 'Import Knowledge',
  },
  'ctrl+o': {
    handler: () => {
      if (chatInputStore && typeof chatInputStore.browseFiles === 'function') {
        chatInputStore.browseFiles();
      }
    },
    description: 'Browse Files',
  },
  'ctrl+h': {
    handler: () => {
      if (historyStore && typeof historyStore.open === 'function') {
        historyStore.open();
      }
    },
    description: 'Open History',
  },
  'ctrl+shift+c': {
    handler: () => {
      if (contextStore && typeof contextStore.open === 'function') {
        contextStore.open();
      }
    },
    description: 'Open Context',
  },
  'ctrl+n': {
    handler: () => {
      if (chatInputStore && typeof chatInputStore.nudge === 'function') {
        chatInputStore.nudge();
      }
    },
    description: 'Send Nudge',
  },
  '?': {
    handler: () => {
      const kbStore = globalThis.Alpine?.store('keyboardShortcuts');
      if (kbStore && typeof kbStore.open === 'function') {
        kbStore.open();
      }
    },
    description: 'Show Keyboard Shortcuts',
  },
};

function isInputField(element) {
  if (!element) return false;

  const tagName = element.tagName.toLowerCase();
  const inputTypes = ['input', 'textarea', 'select'];

  if (inputTypes.includes(tagName)) {
    return true;
  }

  if (element.isContentEditable) {
    return true;
  }

  const textInputRoles = ['textbox', 'searchbox', 'combobox'];
  const role = element.getAttribute('role');
  if (role && textInputRoles.includes(role)) {
    return true;
  }

  if (element.classList && element.classList.contains('ace_editor')) {
    return true;
  }

  return false;
}

function getKeyCombo(event) {
  const parts = [];

  if (event.ctrlKey) parts.push('ctrl');
  if (event.altKey) parts.push('alt');
  if (event.shiftKey) parts.push('shift');
  if (event.metaKey) parts.push('meta');

  let key = event.key.toLowerCase();
  if (key === ' ') {
    key = 'space';
  }
  parts.push(key);

  return parts.join('+');
}

function handleKeyDown(event) {
  if (isInputField(event.target)) {
    return;
  }

  const keyCombo = getKeyCombo(event);
  const shortcut = shortcuts[keyCombo];
  if (shortcut) {
    event.preventDefault();
    event.stopPropagation();

    try {
      shortcut.handler();
    } catch (error) {
      Logger.error(`Error executing keyboard shortcut "${keyCombo}":`, error);
    }
  }
}

export function initKeyboardShortcuts() {
  document.addEventListener('keydown', handleKeyDown);
}

export function cleanupKeyboardShortcuts() {
  document.removeEventListener('keydown', handleKeyDown);
}

export function getRegisteredShortcuts() {
  return Object.entries(shortcuts).reduce((acc, [key, value]) => {
    acc[key] = value.description;
    return acc;
  }, {});
}

initKeyboardShortcuts();
