/**
 * Agent Zero Service Worker
 * Provides offline support and caching for PWA functionality
 * @version 1.0.0
 */

const CACHE_NAME = 'agent-zero-v1';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/index.css',
  '/css/messages.css',
  '/css/buttons.css',
  '/css/toast.css',
  '/css/settings.css',
  '/css/modals.css',
  '/css/speech.css',
  '/css/scheduler-datepicker.css',
  '/css/notification.css',
  '/js/api.js',
  '/js/messages.js',
  '/js/settings.js',
  '/js/scheduler.js',
  '/js/modals.js',
  '/js/components.js',
  '/js/constants.js',
  '/js/device.js',
  '/js/keyboard-shortcuts.js',
  '/js/speech_browser.js',
  '/js/time-utils.js',
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
      .then((cache) => {
        return cache.addAll(STATIC_ASSETS);
      })
      .catch(() => {
        // Failed to cache static assets - silent fail
      })
  );
  
  // Skip waiting to activate immediately
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => {
            return caches.delete(name);
          })
      );
    })
  );
  
  // Take control of all clients immediately
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
  
  // Stale-while-revalidate strategy for static assets
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          // Update cache with fresh response
          if (networkResponse.ok && networkResponse.status !== 206) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, responseToCache);
            });
          }
          return networkResponse;
        })
        .catch(() => {
          // Return cached response if available
          return cachedResponse;
        });
      
      // Return cached response immediately, or wait for network
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
