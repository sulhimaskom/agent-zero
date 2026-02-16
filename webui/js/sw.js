/**
 * Agent Zero Service Worker
 * Provides offline support and caching for PWA functionality
 * @version 1.0.1
 */

const CACHE_NAME = 'agent-zero-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/index.min.css',
  '/css/messages.min.css',
  '/css/buttons.min.css',
  '/css/toast.min.css',
  '/css/settings.min.css',
  '/css/modals.min.css',
  '/css/speech.min.css',
  '/css/scheduler-datepicker.min.css',
  '/css/notification.min.css',
  '/js/api.min.js',
  '/js/messages.min.js',
  '/js/settings.min.js',
  '/js/scheduler.min.js',
  '/js/modals.min.js',
  '/js/components.min.js',
  '/js/constants.min.js',
  '/js/device.min.js',
  '/js/keyboard-shortcuts.min.js',
  '/js/speech_browser.min.js',
  '/js/time-utils.js',
  '/js/initFw.min.js',
  '/js/AlpineStore.min.js',
  '/index.min.js',
  '/vendor/alpine/alpine.min.js',
  '/vendor/flatpickr/flatpickr.min.js',
  '/vendor/flatpickr/flatpickr.min.css',
  '/vendor/katex/katex.min.js',
  '/vendor/katex/katex.min.css',
  '/public/favicon.svg'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(STATIC_ASSETS))
      .catch(() => {})
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) =>
      Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip API requests - let them go to network
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/message') ||
      url.pathname.startsWith('/poll') ||
      url.pathname.startsWith('/settings') ||
      url.pathname.startsWith('/scheduler') ||
      url.pathname.startsWith('/memory') ||
      url.pathname.startsWith('/chat') ||
      url.pathname.startsWith('/project') ||
      url.pathname.startsWith('/tunnel') ||
      url.pathname.startsWith('/backup') ||
      url.pathname.startsWith('/history')) {
    return;
  }

  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          if (networkResponse.ok && networkResponse.status !== 206) {
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, networkResponse.clone());
            });
          }
          return networkResponse;
        })
        .catch(() => cachedResponse);
      return cachedResponse || fetchPromise;
    })
  );
});

// Message event - handle messages from clients
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
});
