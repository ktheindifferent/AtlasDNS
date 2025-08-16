/* eslint-disable no-restricted-globals */

// Service Worker for handling background notifications and offline functionality

const CACHE_NAME = 'atlas-dns-v1';
const urlsToCache = [
  '/',
  '/static/css/main.css',
  '/static/js/bundle.js',
  '/manifest.json',
  '/icon-192x192.png',
  '/icon-512x512.png',
];

// Install event - cache resources
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('Opened cache');
      return cache.addAll(urlsToCache);
    })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - serve from cache when offline
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      // Cache hit - return response
      if (response) {
        return response;
      }

      return fetch(event.request).then((response) => {
        // Check if we received a valid response
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }

        // Clone the response
        const responseToCache = response.clone();

        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });

        return response;
      });
    })
  );
});

// Push event - handle push notifications
self.addEventListener('push', (event) => {
  console.log('Push notification received');

  let notificationData = {
    title: 'Atlas DNS Notification',
    body: 'You have a new notification',
    icon: '/icon-192x192.png',
    badge: '/badge-72x72.png',
    data: {},
  };

  if (event.data) {
    try {
      const data = event.data.json();
      notificationData = {
        title: data.title || notificationData.title,
        body: data.message || data.body || notificationData.body,
        icon: data.icon || notificationData.icon,
        badge: data.badge || notificationData.badge,
        tag: data.id || data.tag,
        requireInteraction: data.priority === 'urgent' || data.priority === 'high',
        data: {
          notificationId: data.id,
          url: data.url || `/notifications/${data.id}`,
          category: data.category,
          priority: data.priority,
          actions: data.actions,
        },
        actions: data.actions?.map(action => ({
          action: action.id,
          title: action.label,
          icon: action.icon,
        })) || [],
        vibrate: data.priority === 'urgent' ? [200, 100, 200] : [200],
        timestamp: data.timestamp || Date.now(),
      };

      // Add priority-based visual indicators
      if (data.priority === 'urgent') {
        notificationData.image = '/urgent-banner.png';
      }
    } catch (error) {
      console.error('Error parsing push data:', error);
    }
  }

  event.waitUntil(
    self.registration.showNotification(notificationData.title, notificationData)
  );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
  console.log('Notification clicked:', event.notification);

  event.notification.close();

  const notificationData = event.notification.data || {};
  const action = event.action;

  if (action) {
    // Handle action button clicks
    handleNotificationAction(action, notificationData);
  } else {
    // Handle notification body click
    event.waitUntil(
      clients.matchAll({ type: 'window' }).then((clientList) => {
        // Check if there's already a window/tab open
        for (const client of clientList) {
          if (client.url === '/' && 'focus' in client) {
            return client.focus().then(() => {
              // Send message to the client
              client.postMessage({
                type: 'notification-clicked',
                notificationId: notificationData.notificationId,
                url: notificationData.url,
              });
            });
          }
        }

        // If no window is open, open a new one
        if (clients.openWindow) {
          return clients.openWindow(notificationData.url || '/');
        }
      })
    );
  }
});

// Handle notification actions
function handleNotificationAction(action, notificationData) {
  switch (action) {
    case 'view-details':
      clients.openWindow(notificationData.url || '/');
      break;
    
    case 'mark-read':
      // Send message to mark notification as read
      sendMessageToClients({
        type: 'mark-notification-read',
        notificationId: notificationData.notificationId,
      });
      break;
    
    case 'snooze':
      // Send message to snooze notification
      sendMessageToClients({
        type: 'snooze-notification',
        notificationId: notificationData.notificationId,
        duration: 3600000, // 1 hour
      });
      break;
    
    case 'block-source':
      // Send message to block source (for security notifications)
      sendMessageToClients({
        type: 'block-source',
        source: notificationData.source,
      });
      break;
    
    default:
      // Handle custom actions
      sendMessageToClients({
        type: 'notification-action',
        action: action,
        notificationId: notificationData.notificationId,
        data: notificationData,
      });
  }
}

// Send message to all clients
function sendMessageToClients(message) {
  clients.matchAll({ type: 'window' }).then((clientList) => {
    clientList.forEach((client) => {
      client.postMessage(message);
    });
  });
}

// Background sync event - sync notifications when back online
self.addEventListener('sync', (event) => {
  console.log('Background sync triggered');

  if (event.tag === 'sync-notifications') {
    event.waitUntil(syncNotifications());
  }
});

async function syncNotifications() {
  try {
    // Fetch latest notifications from server
    const response = await fetch('/api/notifications/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        lastSync: await getLastSyncTime(),
      }),
    });

    if (response.ok) {
      const data = await response.json();
      
      // Store sync time
      await setLastSyncTime(Date.now());
      
      // Send notifications to clients
      sendMessageToClients({
        type: 'notifications-synced',
        notifications: data.notifications,
      });
      
      // Show notifications for urgent ones
      data.notifications
        .filter(n => n.priority === 'urgent' || n.priority === 'high')
        .forEach(notification => {
          self.registration.showNotification(notification.title, {
            body: notification.message,
            icon: '/icon-192x192.png',
            badge: '/badge-72x72.png',
            tag: notification.id,
            data: notification,
          });
        });
    }
  } catch (error) {
    console.error('Error syncing notifications:', error);
  }
}

// Storage helpers for IndexedDB
async function getLastSyncTime() {
  // Implementation would use IndexedDB
  return localStorage.getItem('lastNotificationSync') || 0;
}

async function setLastSyncTime(time) {
  // Implementation would use IndexedDB
  localStorage.setItem('lastNotificationSync', time.toString());
}

// Message event - handle messages from clients
self.addEventListener('message', (event) => {
  console.log('Service worker received message:', event.data);

  switch (event.data.type) {
    case 'skip-waiting':
      self.skipWaiting();
      break;
    
    case 'check-updates':
      checkForUpdates();
      break;
    
    case 'clear-cache':
      caches.delete(CACHE_NAME);
      break;
    
    case 'test-notification':
      self.registration.showNotification('Test Notification', {
        body: 'This is a test notification from the service worker',
        icon: '/icon-192x192.png',
        badge: '/badge-72x72.png',
      });
      break;
  }
});

// Periodic background sync (if supported)
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'check-notifications') {
    event.waitUntil(checkNotifications());
  }
});

async function checkNotifications() {
  // Check for new notifications periodically
  try {
    const response = await fetch('/api/notifications/check');
    if (response.ok) {
      const data = await response.json();
      if (data.hasNew) {
        syncNotifications();
      }
    }
  } catch (error) {
    console.error('Error checking notifications:', error);
  }
}

// Check for service worker updates
async function checkForUpdates() {
  try {
    const response = await fetch('/service-worker.js');
    const newWorker = await response.text();
    const currentWorker = await caches.match('/service-worker.js').then(r => r?.text());
    
    if (newWorker !== currentWorker) {
      sendMessageToClients({
        type: 'update-available',
      });
    }
  } catch (error) {
    console.error('Error checking for updates:', error);
  }
}

console.log('Enhanced Service Worker loaded with notification support');