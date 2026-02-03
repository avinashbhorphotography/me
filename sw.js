// Advanced Service Worker for Image Protection and Performance
// This intercepts image requests and adds protection headers
// Also handles caching for better performance

const CACHE_NAME = 'image-protection-v11';
const STATIC_CACHE = 'static-v11';
const IMAGES_CACHE = 'images-v11';

// Assets to cache immediately
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/favicon.svg',
  '/apple-touch-icon.png',
];

// Allowed origins for the application
const ALLOWED_ORIGINS = [
  'https://avinashbhorphotography.github.io',
  'https://www.abphotostudio.in',
  'http://localhost:8080',
  'http://localhost:5173',
];

// Check if request is for a protected image
function isProtectedImage(url) {
  try {
    const urlObj = new URL(url);
    // Protect external images from specific domains
    const isExternalProtected = ['images.unsplash.com', 'source.unsplash.com'].some(domain =>
      urlObj.hostname.includes(domain)
    );
    // Protect local images
    const isLocalProtected = urlObj.pathname.startsWith('/images/');
    return isExternalProtected || isLocalProtected;
  } catch {
    return false;
  }
}

// Check if the request origin is allowed
function isAllowedOrigin(request) {
  try {
    // For same-origin requests (like localhost), always allow
    if (request.url.startsWith(self.location.origin)) {
      return true;
    }

    // For development, allow localhost variations
    if (request.url.includes('localhost')) {
      return true;
    }

    const url = new URL(request.url);
    const origin = `${url.protocol}//${url.host}`;
    return ALLOWED_ORIGINS.some(allowedOrigin => origin === allowedOrigin);
  } catch {
    return false;
  }
}

// Validate token format and freshness
function validateToken(token) {
  if (!token) return false;
  try {
    const decoded = atob(token);
    const parts = decoded.split('-');
    if (parts.length < 2) return false;

    const timestamp = parseInt(parts[0]);
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes

    // Token should not be older than maxAge and not from future
    return now - timestamp < maxAge && timestamp <= now + 1000;
  } catch {
    return false;
  }
}

// Check if request has proper authentication
function isAuthenticated(request) {
  // In development (localhost), allow all requests
  const isLocalhost =
    self.location.hostname === 'localhost' ||
    self.location.hostname === '127.0.0.1' ||
    self.location.hostname.includes('localhost');

  if (isLocalhost) {
    return true; // Allow all requests in development
  }

  const authHeader = request.headers.get('X-Image-Auth');
  const sessionToken = request.headers.get('X-Session-Token');
  const protectedFlag = request.headers.get('X-Protected-Image');
  const referer = request.headers.get('Referer') || request.headers.get('referer');
  const userAgent = request.headers.get('User-Agent') || '';

  // Check if this looks like a download attempt (based on user agent patterns)
  const isDownloadAttempt =
    userAgent.includes('Wget') ||
    userAgent.includes('curl') ||
    userAgent.includes('Python') ||
    userAgent.includes('bot') ||
    userAgent.includes('spider') ||
    userAgent.includes('crawler') ||
    userAgent.includes('Postman') ||
    userAgent.includes('HTTPie');

  // Block download tools immediately
  if (isDownloadAttempt) {
    console.log('Service Worker: Blocking download tool', {
      url: request.url,
      userAgent: userAgent.substring(0, 100),
    });
    return false;
  }

  // For image requests, allow from app but block direct access
  if (request.url.includes('/images/')) {
    // Check referer to ensure it's from our site
    const hasValidReferer =
      referer &&
      (referer.startsWith(self.location.origin) ||
        referer.includes('localhost') ||
        ALLOWED_ORIGINS.some(origin => referer.startsWith(origin)));

    // Check if request comes from our application (has all required headers)
    const hasValidAuth =
      authHeader === 'protected' &&
      sessionToken &&
      validateToken(sessionToken) &&
      protectedFlag === 'true';

    // Allow image requests (from img tags) from our app pages
    if (request.destination === 'image' && hasValidReferer) {
      console.log('Service Worker: Allowing image request from app', {
        url: request.url.substring(request.url.lastIndexOf('/') + 1),
        referer: referer.substring(0, 50),
      });
      return true;
    }

    // Allow authenticated requests (from fetch with headers)
    if (hasValidAuth && hasValidReferer) {
      console.log('Service Worker: Allowing authenticated request', {
        url: request.url.substring(request.url.lastIndexOf('/') + 1),
        hasAuth: true,
        tokenValid: validateToken(sessionToken),
      });
      return true;
    }

    // Block direct navigation to image URLs
    if (request.mode === 'navigate') {
      console.log('Service Worker: Blocking direct navigation to image');
      return false;
    }

    // Block unauthenticated requests
    console.log('Service Worker: Blocking unauthenticated image request', {
      url: request.url.substring(request.url.lastIndexOf('/') + 1),
      hasAuth: hasValidAuth,
      hasReferer: !!referer,
      destination: request.destination,
      mode: request.mode,
    });
    return false;
  }

  // Allow non-image requests by default
  return true;
}

// Install event - cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(STATIC_CACHE);
      await cache.addAll(STATIC_ASSETS);
      // Force activation of new service worker
      self.skipWaiting();
    })()
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    (async () => {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames.map(cacheName => {
          if (
            cacheName !== CACHE_NAME &&
            cacheName !== STATIC_CACHE &&
            cacheName !== IMAGES_CACHE
          ) {
            return caches.delete(cacheName);
          }
        })
      );
      // Take control of all clients
      self.clients.claim();
    })()
  );
});

// Fetch event - handle requests with caching and protection
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = request.url;

  // Handle static assets with cache-first strategy
  if (STATIC_ASSETS.some(asset => url.endsWith(asset))) {
    event.respondWith(
      caches.match(request).then(response => {
        return (
          response ||
          fetch(request).then(response => {
            const responseClone = response.clone();
            caches.open(STATIC_CACHE).then(cache => {
              cache.put(request, responseClone);
            });
            return response;
          })
        );
      })
    );
    return;
  }

  // Handle images with cache-first strategy
  if (request.destination === 'image' || url.includes('/images/')) {
    event.respondWith(
      caches.match(request).then(response => {
        if (response) {
          return response;
        }

        // Detect direct navigation (URL typed in browser)
        const isDirectNavigation =
          request.mode === 'navigate' ||
          (!request.headers.get('X-Protected-Image') && request.destination === '');

        // Block direct navigation to image URLs
        if (isDirectNavigation && url.includes('/images/')) {
          console.log('Service Worker: Blocking direct navigation to image');
          return new Response(
            '<!DOCTYPE html><html><head><title>403 Forbidden</title><style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}div{text-align:center;padding:2rem;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);}h1{color:#e74c3c;margin:0 0 1rem;}p{color:#666;}</style></head><body><div><h1>&#x1F512; Access Denied</h1><p>Direct access to images is not allowed.</p><p>Please view images through the portfolio.</p></div></body></html>',
            {
              status: 403,
              statusText: 'Forbidden',
              headers: {
                'Content-Type': 'text/html',
                'X-Protection-Reason': 'Direct navigation blocked',
              },
            }
          );
        }

        // Check authentication for protected images
        const protectedFlag = request.headers.get('X-Protected-Image');
        const referer = request.headers.get('Referer') || request.headers.get('referer');
        console.log('Service Worker: Image request', {
          url,
          mode: request.mode,
          destination: request.destination,
          protectedFlag,
          hasAuth: !!request.headers.get('X-Image-Auth'),
          hasSession: !!request.headers.get('X-Session-Token'),
          referer: referer ? referer.substring(0, 100) : 'none',
        });

        // Enhanced authentication check
        if (!isAuthenticated(request)) {
          console.log('Service Worker: Blocking unauthorized image request');
          return new Response('403 Forbidden - Image Protection Active', {
            status: 403,
            statusText: 'Forbidden',
            headers: {
              'Content-Type': 'text/plain',
              'X-Protection-Reason': 'Unauthorized access attempt detected',
            },
          });
        }

        return fetch(request)
          .then(response => {
            console.log('Service Worker: Image fetch response', response.status, url);
            if (response.ok) {
              const responseClone = response.clone();
              caches.open(IMAGES_CACHE).then(cache => {
                cache.put(request, responseClone);
              });
            }
            return response;
          })
          .catch(error => {
            console.error('Service Worker: Image fetch failed', error, url);
            // Return cached placeholder for failed image requests
            return caches.match('/images/placeholder.jpeg') || new Response('', { status: 404 });
          });
      })
    );
    return;
  }

  // Handle API requests and other dynamic content with network-first strategy
  if (url.includes('/api/') || request.method !== 'GET') {
    event.respondWith(
      fetch(request).catch(() => {
        return new Response(JSON.stringify({ error: 'Network unavailable' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      })
    );
    return;
  }

  // Default network-first strategy for other requests
  event.respondWith(
    fetch(request)
      .then(response => {
        // Cache successful responses
        if (response.ok && response.type === 'basic') {
          const responseClone = response.clone();
          caches.open(STATIC_CACHE).then(cache => {
            cache.put(request, responseClone);
          });
        }
        return response;
      })
      .catch(() => {
        // Return cached version if available
        return caches.match(request).then(response => {
          return (
            response ||
            new Response('Offline - Content not available', {
              status: 503,
              headers: { 'Content-Type': 'text/plain' },
            })
          );
        });
      })
  );
});

// Message event - handle messages from the main thread
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// Push event - handle incoming push notifications
self.addEventListener('push', event => {
  if (!event.data) return;

  try {
    const data = event.data.json();
    const options = {
      body: data.body || 'New update from AB Photo Studio',
      icon: data.icon || '/web-app-manifest-192x192.png',
      badge: data.badge || '/web-app-manifest-192x192.png',
      image: data.image,
      tag: data.tag || 'general',
      requireInteraction: data.requireInteraction || false,
      actions: data.actions || [],
      data: data.data || {},
      silent: false,
    };

    event.waitUntil(self.registration.showNotification(data.title || 'AB Photo Studio', options));
  } catch (error) {
    // Fallback for non-JSON payloads
    const title = event.data.text() || 'AB Photo Studio';
    event.waitUntil(
      self.registration.showNotification(title, {
        body: 'New update available',
        icon: '/web-app-manifest-192x192.png',
        tag: 'general',
      })
    );
  }
});

// Notification click event - handle notification interactions
self.addEventListener('notificationclick', event => {
  event.notification.close();

  const notificationData = event.notification.data || {};
  let url = '/';

  // Handle different notification types
  if (event.action) {
    // Handle action button clicks
    switch (event.action) {
      case 'view-portfolio':
        url = '/portfolio';
        break;
      case 'contact':
        url = '/?section=contact';
        break;
      case 'dismiss':
        return; // Just close, don't navigate
      default:
        url = notificationData.url || '/';
    }
  } else {
    // Handle main notification click
    url = notificationData.url || '/';
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      // Check if there's already a window/tab open with the target URL
      for (const client of clientList) {
        if (client.url.includes(url) && 'focus' in client) {
          return client.focus();
        }
      }

      // If no suitable window is found, open a new one
      if (clients.openWindow) {
        return clients.openWindow(url);
      }
    })
  );
});

// Background sync for offline actions
self.addEventListener('sync', event => {
  if (event.tag === 'background-sync-contact') {
    event.waitUntil(syncContactForm());
  } else if (event.tag === 'background-sync-analytics') {
    event.waitUntil(syncAnalyticsData());
  }
});

// Background sync for contact form submissions
async function syncContactForm() {
  try {
    const cache = await caches.open('contact-form-cache');
    const requests = await cache.keys();

    for (const request of requests) {
      if (request.url.includes('/api/contact')) {
        try {
          const response = await fetch(request);
          if (response.ok) {
            await cache.delete(request);
          }
        } catch (error) {
          console.error('Failed to sync contact form:', error);
        }
      }
    }
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}

// Background sync for analytics data
async function syncAnalyticsData() {
  try {
    const cache = await caches.open('analytics-cache');
    const requests = await cache.keys();

    for (const request of requests) {
      if (request.url.includes('/api/analytics')) {
        try {
          const response = await fetch(request);
          if (response.ok) {
            await cache.delete(request);
          }
        } catch (error) {
          console.error('Failed to sync analytics:', error);
        }
      }
    }
  } catch (error) {
    console.error('Analytics sync failed:', error);
  }
}
