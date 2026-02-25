// -----------------------------------------------------------------------------
// Scheduler Store - Modular Re-export
// -----------------------------------------------------------------------------
// This file re-exports from the new modular store structure for backward compatibility.
// The new modular stores are located in: /components/modals/scheduler/scheduler/

// Re-export the main store for backward compatibility
export { store } from "./scheduler/store.js";

// Re-export submodules for direct access if needed
export * from "./scheduler/constants.js";
export * from "./scheduler/helpers.js";
export { schedulerApi } from "./scheduler/api.js";
export { pushNotification } from "./scheduler/notifications.js";
export * from "./scheduler/flatpickr-utils.js";
