/**
 * Scheduler DateTime Module
 * DateTime picker initialization and utilities
 */
import Logger from '../../logger.min.js';

/**
 * Generate a random token for ad-hoc tasks
 * @returns {string} Random 16-character token
 */
export function generateRandomToken() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 16; i++) {
    token += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return token;
}

/**
 * Initialize datetime input with default value (30 minutes from now)
 * @param {Event} event - Input event
 */
export function initDateTimeInput(event) {
  if (!event.target.value) {
    const now = new Date();
    now.setMinutes(now.getMinutes() + 30);

    // Format as YYYY-MM-DDThh:mm
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');

    event.target.value = `${year}-${month}-${day}T${hours}:${minutes}`;

    // If using Flatpickr, update it as well
    if (event.target._flatpickr) {
      event.target._flatpickr.setDate(event.target.value);
    }
  }
}

/**
 * Initialize Flatpickr datetime pickers for scheduler forms
 * @param {string} mode - Which pickers to initialize: 'all', 'create', or 'edit'
 */
export function initFlatpickr(mode = 'all') {
  const initPicker = (inputId, refName, wrapperClass, options = {}) => {
    // Try to get input using Alpine.js x-ref first (more reliable)
    let input = this.$refs[refName];

    // Fall back to getElementById if x-ref is not available
    if (!input) {
      input = document.getElementById(inputId);
    }

    if (!input) {
      Logger.warn(`Input element ${inputId} not found by ID or ref`);
      return null;
    }

    // Create a wrapper around the input
    const wrapper = document.createElement('div');
    wrapper.className = wrapperClass || 'scheduler-flatpickr-wrapper';
    wrapper.style.overflow = 'visible'; // Ensure dropdown can escape container

    // Replace the input with our wrapped version
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);
    input.classList.add('scheduler-flatpickr-input');

    // Default options
    const defaultOptions = {
      dateFormat: 'Y-m-d H:i',
      enableTime: true,
      time_24hr: true,
      static: false, // Not static so it will float
      appendTo: document.body, // Append to body to avoid overflow issues
      theme: 'scheduler-theme',
      allowInput: true,
      positionElement: wrapper, // Position relative to wrapper
      onOpen(selectedDates, dateStr, instance) {
        // Ensure calendar is properly positioned and visible
        instance.calendarContainer.style.zIndex = '9999';
        instance.calendarContainer.style.position = 'absolute';
        instance.calendarContainer.style.visibility = 'visible';
        instance.calendarContainer.style.opacity = '1';

        // Add class to calendar container for our custom styling
        instance.calendarContainer.classList.add('scheduler-theme');
      },
      // Set default date to 30 minutes from now if no date selected
      onReady(selectedDates, dateStr, instance) {
        if (!dateStr) {
          const now = new Date();
          now.setMinutes(now.getMinutes() + 30);
          instance.setDate(now, true);
        }
      },
    };

    // Merge options
    const mergedOptions = {...defaultOptions, ...options};

    // Initialize flatpickr
    const fp = flatpickr(input, mergedOptions);

    // Add a clear button
    const clearButton = document.createElement('button');
    clearButton.className = 'scheduler-flatpickr-clear';
    clearButton.innerHTML = '×';
    clearButton.type = 'button';
    clearButton.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (fp) {
        fp.clear();
      }
    });
    wrapper.appendChild(clearButton);

    return fp;
  };

  // Clear any existing Flatpickr instances to prevent duplication
  if (mode === 'all' || mode === 'create') {
    const createInput = document.getElementById('newPlannedTime-create');
    if (createInput && createInput._flatpickr) {
      createInput._flatpickr.destroy();
    }
  }

  if (mode === 'all' || mode === 'edit') {
    const editInput = document.getElementById('newPlannedTime-edit');
    if (editInput && editInput._flatpickr) {
      editInput._flatpickr.destroy();
    }
  }

  // Initialize new instances
  if (mode === 'all' || mode === 'create') {
    initPicker('newPlannedTime-create', 'plannedTimeCreate', 'scheduler-flatpickr-wrapper', {
      minuteIncrement: 5,
      defaultHour: new Date().getHours(),
      defaultMinute: Math.ceil(new Date().getMinutes() / 5) * 5,
    });
  }

  if (mode === 'all' || mode === 'edit') {
    initPicker('newPlannedTime-edit', 'plannedTimeEdit', 'scheduler-flatpickr-wrapper', {
      minuteIncrement: 5,
      defaultHour: new Date().getHours(),
      defaultMinute: Math.ceil(new Date().getMinutes() / 5) * 5,
    });
  }
}
