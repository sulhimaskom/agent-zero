import { createStore } from '/js/AlpineStore.min.js';

const model = {
  isVisible: false,
  newMessageCount: 0,
  chatHistory: null,
  lastScrollHeight: 0,

  init() {
    setTimeout(() => {
      this.chatHistory = document.getElementById('chat-history');
      if (this.chatHistory) {
        this.setupScrollListener();
        this.setupMessageObserver();
        this.checkScrollPosition();
      }
    }, 100);
  },

  setupScrollListener() {
    let ticking = false;

    // Store handler reference for cleanup
    this._scrollHandler = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          this.checkScrollPosition();
          ticking = false;
        });
        ticking = true;
      }
    };

    this.chatHistory.addEventListener('scroll', this._scrollHandler, { passive: true });
  },

  $cleanup() {
    // Remove scroll listener to prevent memory leaks
    if (this.chatHistory && this._scrollHandler) {
      this.chatHistory.removeEventListener('scroll', this._scrollHandler);
      this._scrollHandler = null;
    }
    // Cleanup MutationObserver if stored
    if (this._messageObserver) {
      this._messageObserver.disconnect();
      this._messageObserver = null;
    }
  },

  setupMessageObserver() {
    // Store observer reference for cleanup
    this._messageObserver = new MutationObserver((mutations) => {
      let messagesAdded = false;

      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE &&
                            (node.classList.contains('message-container') ||
                             node.querySelector('.message-container'))) {
              messagesAdded = true;
            }
          });
        }
      });

      if (messagesAdded && this.isVisible) {
        this.newMessageCount++;
      }
    });

    this._messageObserver.observe(this.chatHistory, {
      childList: true,
      subtree: true,
    });
  },

  checkScrollPosition() {
    if (!this.chatHistory) return;

    const scrollHeight = this.chatHistory.scrollHeight;
    const scrollTop = this.chatHistory.scrollTop;
    const clientHeight = this.chatHistory.clientHeight;

    const threshold = 100;
    const isScrolledUp = scrollHeight - scrollTop - clientHeight > threshold;

    this.isVisible = isScrolledUp;

    if (!isScrolledUp && this.newMessageCount > 0) {
      this.newMessageCount = 0;
    }

    this.lastScrollHeight = scrollHeight;
  },

  scrollToBottom() {
    if (!this.chatHistory) return;

    this.chatHistory.scrollTo({
      top: this.chatHistory.scrollHeight,
      behavior: 'smooth',
    });

    this.newMessageCount = 0;

    window.dispatchEvent(new CustomEvent('chat-scrolled-to-bottom'));
  },

  reset() {
    this.newMessageCount = 0;
    this.checkScrollPosition();
  },
};

const store = createStore('scrollToBottom', model);
export { store };
