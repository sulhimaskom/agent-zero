// -----------------------------------------------------------------------------
// Notification helpers for scheduler store
// -----------------------------------------------------------------------------
import { store as notificationsStore } from "/components/notifications/notification-store.js";
import { NOTIFICATION_DURATION } from "./constants.js";

// -----------------------------------------------------------------------------
// Notification Channels
// -----------------------------------------------------------------------------
const notificationChannels = {
  success: "frontendSuccess",
  info: "frontendInfo",
  warning: "frontendWarning",
  error: "frontendError",
};

/**
 * Push a notification to the notification store
 * @param {string} type - Notification type (success, info, warning, error)
 * @param {string} message - Notification message
 * @param {string} title - Notification title
 * @param {number} [duration] - Custom duration in seconds
 */
export function pushNotification(type, message, title = "Scheduler", duration) {
  const channel = notificationChannels[type];
  if (!channel || typeof notificationsStore[channel] !== "function") return;
  const ttl = duration ?? NOTIFICATION_DURATION[type] ?? 4;
  notificationsStore[channel](message, title, ttl);
}
