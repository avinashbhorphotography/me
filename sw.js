// Caching + image deterrent: photos are cache-first, opening a photo URL directly in a tab is
// refused, everything else is network-first with an offline fallback to the cache.

const STATIC_CACHE = 'static-v12';
const IMAGES_CACHE = 'images-v12';
const STATIC_ASSETS = ['/', '/site.webmanifest', '/favicon.ico', '/apple-touch-icon.png'];
const PHOTO_PATH = /\/(images|thumbs)\//;
const IS_LOCALHOST = ['localhost', '127.0.0.1'].includes(self.location.hostname);

const blockedPage = () =>
  new Response(
    '<!DOCTYPE html><html><head><title>403 Forbidden</title><style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}div{text-align:center;padding:2rem;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);}h1{color:#e74c3c;margin:0 0 1rem;}p{color:#666;}</style></head><body><div><h1>&#x1F512; Access Denied</h1><p>Direct access to images is not allowed.</p><p>Please view images through the portfolio.</p></div></body></html>',
    { status: 403, statusText: 'Forbidden', headers: { 'Content-Type': 'text/html' } }
  );

const putInCache = (cacheName, request, response) => {
  const copy = response.clone();
  caches.open(cacheName).then(cache => cache.put(request, copy));
};

self.addEventListener('install', event => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches
      .keys()
      .then(names =>
        Promise.all(
          names
            .filter(name => name !== STATIC_CACHE && name !== IMAGES_CACHE)
            .map(name => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = request.url;

  if (request.mode !== 'navigate' && STATIC_ASSETS.includes(new URL(url).pathname)) {
    event.respondWith(
      caches.match(request).then(
        cached =>
          cached ||
          fetch(request).then(response => {
            putInCache(STATIC_CACHE, request, response);
            return response;
          })
      )
    );
    return;
  }

  if (request.destination === 'image' || PHOTO_PATH.test(url)) {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        if (PHOTO_PATH.test(url) && request.destination !== 'image') {
          // Typed/opened in a tab, or fetched by script rather than shown by an <img>.
          if (request.mode === 'navigate' || request.destination === '') return blockedPage();
          if (!IS_LOCALHOST) {
            return new Response('403 Forbidden - Image Protection Active', {
              status: 403,
              headers: { 'Content-Type': 'text/plain' },
            });
          }
        }
        return fetch(request)
          .then(response => {
            if (response.ok) putInCache(IMAGES_CACHE, request, response);
            return response;
          })
          .catch(
            async () =>
              (await caches.match('/images/placeholder.jpeg')) || new Response('', { status: 404 })
          );
      })
    );
    return;
  }

  if (url.includes('/api/') || request.method !== 'GET') {
    event.respondWith(
      fetch(request).catch(
        () =>
          new Response(JSON.stringify({ error: 'Network unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          })
      )
    );
    return;
  }

  event.respondWith(
    fetch(request)
      .then(response => {
        if (response.ok && response.type === 'basic') putInCache(STATIC_CACHE, request, response);
        return response;
      })
      .catch(
        async () =>
          (await caches.match(request)) ||
          new Response('Offline - Content not available', {
            status: 503,
            headers: { 'Content-Type': 'text/plain' },
          })
      )
  );
});
