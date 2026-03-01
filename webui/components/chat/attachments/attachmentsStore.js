import { createStore } from '/js/AlpineStore.js';
import { fetchApi } from '/js/api.js';
import { store as imageViewerStore } from '../../modals/image-viewer/image-viewer-store.js';
import Logger from '/js/logger.js';

const model = {
  // State properties
  attachments: [],
  hasAttachments: false,
  dragDropOverlayVisible: false,
  dragFileCount: 0,
  showDropSuccess: false,

  // Stored event handler references for cleanup (prevents memory leaks)
  _eventHandlers: {
    dragenter: null,
    dragover: null,
    dragleave: null,
    drop: null,
    paste: null,
    dragDefaults: [],
  },

  async init() {
    await this.initialize();
  },

  // Initialize the store
  async initialize() {
    // Setup event listeners for drag and drop
    this.setupDragDropHandlers();
    // Setup paste event listener for clipboard images
    this.setupPasteHandler();
  },

  // Basic attachment management methods
  addAttachment(attachment) {
    // Validate for duplicates
    if (this.validateDuplicates(attachment)) {
      this.attachments.push(attachment);
      this.updateAttachmentState();
    }
  },

  removeAttachment(index) {
    if (index >= 0 && index < this.attachments.length) {
      this.attachments.splice(index, 1);
      this.updateAttachmentState();
    }
  },

  clearAttachments() {
    this.attachments = [];
    this.updateAttachmentState();
  },

  validateDuplicates(newAttachment) {
    // Check if attachment already exists based on name and size
    const isDuplicate = this.attachments.some(
      (existing) =>
        existing.name === newAttachment.name &&
        existing.file &&
        newAttachment.file &&
        existing.file.size === newAttachment.file.size,
    );
    return !isDuplicate;
  },

  updateAttachmentState() {
    this.hasAttachments = this.attachments.length > 0;
  },

  // Drag drop overlay control methods
  showDragDropOverlay() {
    this.dragDropOverlayVisible = true;
  },

  hideDragDropOverlay() {
    this.dragDropOverlayVisible = false;
  },

  // Setup drag and drop event handlers
  setupDragDropHandlers() {
    let dragCounter = 0;

    // Store handler references for cleanup
    const dragDefaultsHandler = (e) => {
      e.preventDefault();
      e.stopPropagation();
    };

    // Prevent default drag behaviors - store reference for cleanup
    // Create separate handlers for each event to allow proper removal
    const dragDefaults = {
      dragenter: (e) => { e.preventDefault(); e.stopPropagation(); },
      dragover: (e) => { e.preventDefault(); e.stopPropagation(); },
      dragleave: (e) => { e.preventDefault(); e.stopPropagation(); },
      drop: (e) => { e.preventDefault(); e.stopPropagation(); },
    };
    Object.entries(dragDefaults).forEach(([eventName, handler]) => {
      document.addEventListener(eventName, handler, false);
      this._eventHandlers.dragDefaults.push({ eventName, handler });
    });

    // Store dragenter handler
    const dragenterHandler = (e) => {
      dragCounter++;
      if (dragCounter === 1) {
        let fileCount = 0;
        if (e.dataTransfer) {
          if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
            fileCount = e.dataTransfer.items.length;
          } else if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            fileCount = e.dataTransfer.files.length;
          }
        }
        this.dragFileCount = fileCount;
        this.showDragDropOverlay();
      }
    };
    document.addEventListener('dragenter', dragenterHandler, false);
    this._eventHandlers.dragenter = dragenterHandler;

    // Store dragover handler
    const dragoverHandler = (e) => {
      if (this.dragDropOverlayVisible && e.dataTransfer) {
        let fileCount = 0;
        if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
          for (let i = 0; i < e.dataTransfer.items.length; i++) {
            if (e.dataTransfer.items[i].kind === 'file') {
              fileCount++;
            }
          }
        } else if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          fileCount = e.dataTransfer.files.length;
        }
        if (fileCount !== this.dragFileCount) {
          this.dragFileCount = fileCount;
        }
      }
    };
    document.addEventListener('dragover', dragoverHandler, false);
    this._eventHandlers.dragover = dragoverHandler;

    // Store dragleave handler
    const dragleaveHandler = (e) => {
      dragCounter--;
      if (dragCounter === 0) {
        this.hideDragDropOverlay();
        this.dragFileCount = 0;
      }
    };
    document.addEventListener('dragleave', dragleaveHandler, false);
    this._eventHandlers.dragleave = dragleaveHandler;

    // Store drop handler
    const dropHandler = (e) => {
      dragCounter = 0;
      const files = e.dataTransfer.files;
      const fileCount = files.length;

      this.handleFiles(files);

      if (fileCount > 0) {
        this.showDropSuccess = true;
        setTimeout(() => {
          this.showDropSuccess = false;
          this.hideDragDropOverlay();
          this.dragFileCount = 0;
        }, 1200);
      } else {
        this.hideDragDropOverlay();
        this.dragFileCount = 0;
      }
    };
    document.addEventListener('drop', dropHandler, false);
    this._eventHandlers.drop = dropHandler;
  },

  // Setup paste event handler for clipboard images
  setupPasteHandler() {
    // Store handler reference for cleanup
    const pasteHandler = (e) => {
      const items = e.clipboardData.items;
      let imageFound = false;

      // First, check if there are any images in the clipboard
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.type.indexOf('image') !== -1) {
          imageFound = true;
          const blob = item.getAsFile();
          if (blob) {
            e.preventDefault(); // Prevent default paste behavior for images
            this.handleClipboardImage(blob);
          }
          break; // Only handle the first image found
        }
      }

      // If no images found and we're in an input field, let normal text paste happen
      if (
        !imageFound &&
        (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')
      ) {
        return;
      }
    };
    document.addEventListener('paste', pasteHandler);
    this._eventHandlers.paste = pasteHandler;
  },

  // Handle clipboard image pasting
  async handleClipboardImage(blob) {
    try {
      // Generate unique filename
      const guid = this.generateGUID();
      const filename = `clipboard-${guid}.png`;

      // Create file object from blob
      const file = new File([blob], filename, { type: 'image/png' });

      // Create attachment object
      const attachment = {
        file,
        type: 'image',
        name: filename,
        extension: 'png',
        displayInfo: this.getAttachmentDisplayInfo(file),
      };

      // Read as data URL for preview
      const reader = new FileReader();
      reader.onload = (e) => {
        attachment.url = e.target.result;
        this.addAttachment(attachment);
      };
      reader.onerror = () => {
        Logger.error('Failed to read clipboard image:', reader.error);
        window.toastFrontendError('Failed to load clipboard image. Please try again.', 'Clipboard Error');
      };
      reader.readAsDataURL(file);
    } catch (error) {
      Logger.error('Failed to handle clipboard image:', error);
    }
  },

  // Update handleFileUpload to use the attachments store
  handleFileUpload(event) {
    const files = event.target.files;
    this.handleFiles(files);
    event.target.value = ''; // clear uploader selection to fix issue where same file is ignored the second time
  },

  // File handling logic (moved from index.js)
  handleFiles(files) {
    Array.from(files).forEach((file) => {
      const ext = file.name.split('.').pop().toLowerCase();
      const isImage = ['jpg', 'jpeg', 'png', 'bmp', 'gif', 'webp', 'svg'].includes(
        ext,
      );

      const attachment = {
        file,
        type: isImage ? 'image' : 'file',
        name: file.name,
        extension: ext,
        displayInfo: this.getAttachmentDisplayInfo(file),
      };

      if (isImage) {
        // Read image as data URL for preview
        const reader = new FileReader();
        reader.onload = (e) => {
          attachment.url = e.target.result;
          this.addAttachment(attachment);
        };
        reader.readAsDataURL(file);
      } else {
        // For non-image files, add directly
        this.addAttachment(attachment);
      }
    });
  },

  // Get attachments for sending message
  getAttachmentsForSending() {
    return this.attachments.map((attachment) => {
      if (attachment.type === 'image') {
        return {
          ...attachment,
          url: URL.createObjectURL(attachment.file),
        };
      } else {
        return {
          ...attachment,
        };
      }
    });
  },

  // Generate server-side API URL for file (for device sync)
  getServerImgUrl(filename) {
    return `/image_get?path=/a0/tmp/uploads/${encodeURIComponent(filename)}`;
  },

  getServerFileUrl(filename) {
    return `/a0/tmp/uploads/${encodeURIComponent(filename)}`;
  },

  // Check if file is an image based on extension
  isImageFile(filename) {
    const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'];
    const extension = filename.split('.').pop().toLowerCase();
    return imageExtensions.includes(extension);
  },

  // Get attachment preview URL (server URL for persistence, blob URL for current session)
  getAttachmentPreviewUrl(attachment) {
    // If attachment has a name and we're dealing with a server-stored file
    if (typeof attachment === 'string') {
      // attachment is just a filename (from loaded chat)
      return this.getServerImgUrl(attachment);
    } else if (attachment.name && attachment.file) {
      // attachment is an object from current session
      if (attachment.type === 'image') {
        // For images, use blob URL for current session preview
        return attachment.url || URL.createObjectURL(attachment.file);
      } else {
        // For non-image files, use server URL to get appropriate icon
        return this.getServerImgUrl(attachment.name);
      }
    }
    return null;
  },

  getFilePreviewUrl(filename) {
    const extension = filename.split('.').pop().toLowerCase();
    const types = {
      // Archive files
      zip: 'archive',
      rar: 'archive',
      '7z': 'archive',
      tar: 'archive',
      gz: 'archive',
      // Document files
      pdf: 'document',
      doc: 'document',
      docx: 'document',
      txt: 'document',
      rtf: 'document',
      odt: 'document',
      // Code files
      py: 'code',
      js: 'code',
      html: 'code',
      css: 'code',
      json: 'code',
      xml: 'code',
      md: 'code',
      yml: 'code',
      yaml: 'code',
      sql: 'code',
      sh: 'code',
      bat: 'code',
      // Spreadsheet files
      xls: 'document',
      xlsx: 'document',
      csv: 'document',
      // Presentation files
      ppt: 'document',
      pptx: 'document',
      odp: 'document',
    };
    const type = types[extension] || 'file';
    return `/public/${type}.svg`;
  },

  // Enhanced method to get attachment display info for UI
  getAttachmentDisplayInfo(attachment) {
    if (typeof attachment === 'string') {
      // attachment is filename only (from persistent storage)
      const filename = attachment;
      const extension = filename.split('.').pop();
      const isImage = this.isImageFile(filename);
      const previewUrl = isImage
        ? this.getServerImgUrl(filename)
        : this.getFilePreviewUrl(filename);

      return {
        filename,
        extension: extension.toUpperCase(),
        isImage,
        previewUrl,
        clickHandler: () => {
          if (this.isImageFile(filename)) {
            imageViewerStore.open(this.getServerImgUrl(filename), { name: filename });
          } else {
            this.downloadAttachment(filename);
          }
        },
      };
    } else {
      // attachment is object (from current session)
      const isImage = this.isImageFile(attachment.name);
      const filename = attachment.name;
      const extension = filename.split('.').pop() || '';
      const previewUrl = isImage
        ? this.getServerImgUrl(attachment.name)
        : this.getFilePreviewUrl(attachment.name);
      return {
        filename,
        extension: extension.toUpperCase(),
        isImage: attachment.type === 'image',
        previewUrl,
        clickHandler: () => {
          if (attachment.type === 'image') {
            const imageUrl = this.getServerImgUrl(attachment.name);
            imageViewerStore.open(imageUrl, { name: attachment.name });
          } else {
            this.downloadAttachment(attachment.name);
          }
        },
      };
    }
  },

  async downloadAttachment(filename) {
    try {
      const path = this.getServerFileUrl(filename);
      const response = await fetchApi(`/download_work_dir_file?path=${  path}`);

      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const blob = await response.blob();

      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(link.href);
    } catch (error) {
      window.toastFetchError('Error downloading file', error);
      alert('Error downloading file');
    }
  },

  // Generate GUID for unique filenames
  generateGUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
      /[xy]/g,
      (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c == 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      },
    );
  },

  // Cleanup all event listeners to prevent memory leaks
  cleanup() {
    // Remove drag and drop event listeners
    if (this._eventHandlers.dragenter) {
      document.removeEventListener('dragenter', this._eventHandlers.dragenter);
      this._eventHandlers.dragenter = null;
    }
    if (this._eventHandlers.dragover) {
      document.removeEventListener('dragover', this._eventHandlers.dragover);
      this._eventHandlers.dragover = null;
    }
    if (this._eventHandlers.dragleave) {
      document.removeEventListener('dragleave', this._eventHandlers.dragleave);
      this._eventHandlers.dragleave = null;
    }
    if (this._eventHandlers.drop) {
      document.removeEventListener('drop', this._eventHandlers.drop);
      this._eventHandlers.drop = null;
    }
    if (this._eventHandlers.paste) {
      document.removeEventListener('paste', this._eventHandlers.paste);
      this._eventHandlers.paste = null;
    }
    // Remove drag defaults
    this._eventHandlers.dragDefaults.forEach(({ eventName, handler }) => {
      document.removeEventListener(eventName, handler);
    });
    this._eventHandlers.dragDefaults = [];
  },

};

const store = createStore('chatAttachments', model);

export { store };
