// -----------------------------------------------------------------------------
// Flatpickr date picker utilities for scheduler
// -----------------------------------------------------------------------------
import { sortByDate } from "./helpers.js";

/**
 * Destroy a flatpickr instance and cleanup DOM
 * @param {string} inputId - Input element ID
 */
export function destroyPlannerInput(inputId) {
  const input = typeof document !== "undefined" ? document.getElementById(inputId) : null;
  if (!input || !input._flatpickr) return;
  input._flatpickr.destroy();
  const wrapper = input.closest(".scheduler-flatpickr-wrapper");
  if (wrapper && wrapper.parentNode) {
    wrapper.parentNode.insertBefore(input, wrapper);
    wrapper.parentNode.removeChild(wrapper);
  }
  input.classList.remove("scheduler-flatpickr-input");
}

/**
 * Setup a flatpickr instance for planner input
 * @param {string} inputId - Input element ID
 * @returns {Object|null} Flatpickr instance or null
 */
export function setupPlannerInput(inputId) {
  if (typeof flatpickr === "undefined") {
    return null;
  }
  const input = document.getElementById(inputId);
  if (!input) return null;

  destroyPlannerInput(inputId);

  const wrapper = document.createElement("div");
  wrapper.className = "scheduler-flatpickr-wrapper";
  wrapper.style.overflow = "visible";
  input.parentNode.insertBefore(wrapper, input);
  wrapper.appendChild(input);
  input.classList.add("scheduler-flatpickr-input");

  const options = {
    dateFormat: "Y-m-d H:i",
    enableTime: true,
    time_24hr: true,
    static: false,
    appendTo: document.body,
    allowInput: true,
    positionElement: wrapper,
    theme: "scheduler-theme",
    minuteIncrement: 5,
    defaultHour: new Date().getHours(),
    defaultMinute: Math.ceil(new Date().getMinutes() / 5) * 5,
    onOpen(selectedDates, dateStr, instance) {
      instance.calendarContainer.style.zIndex = "9999";
      instance.calendarContainer.style.position = "absolute";
      instance.calendarContainer.style.visibility = "visible";
      instance.calendarContainer.style.opacity = "1";
      instance.calendarContainer.classList.add("scheduler-theme");
    },
    onReady(selectedDates, dateStr, instance) {
      if (!dateStr) {
        const now = new Date();
        now.setMinutes(now.getMinutes() + 30);
        instance.setDate(now, true);
      }
    },
  };

  const picker = flatpickr(input, options);
  const clearButton = document.createElement("button");
  clearButton.className = "scheduler-flatpickr-clear";
  clearButton.innerHTML = "×";
  clearButton.type = "button";
  clearButton.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (picker) picker.clear();
  });
  wrapper.appendChild(clearButton);

  return picker;
}

/**
 * Read date from planner input
 * @param {HTMLInputElement|null} input - Input element
 * @returns {Date|null} Selected date or null
 */
export function readDateFromPlannerInput(input) {
  if (!input) return null;
  if (input._flatpickr && input._flatpickr.selectedDates.length > 0) {
    return input._flatpickr.selectedDates[0];
  }
  if (input.value) {
    const date = new Date(input.value);
    if (!Number.isNaN(date.getTime())) {
      return date;
    }
  }
  return null;
}
