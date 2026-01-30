// Service Worker for Image Protection
// This intercepts image requests and adds protection headers

const CACHE_NAME = 'image-protection-v1';
const PROTECTED_IMAGE_DOMAINS = [
  'images.unsplash.com',
  'source.unsplash.com',
  // Add other domains as needed
];

// Allowed origins for the application
const ALLOWED_ORIGINS = [
  'https://avinashbhorphotography.github.io',
  'https://www.abphotostudio.in',
  'http://localhost:8080', // For Vite dev server
];

// Generate a simple session token
function generateSessionToken() {
  return btoa(Date.now().toString() + Math.random().toString());
}

// Check if request is for a protected image
function isProtectedImage(url) {
  try {
    const urlObj = new URL(url);
    // Protect external images from specific domains
    const isExternalProtected = PROTECTED_IMAGE_DOMAINS.some(domain => urlObj.hostname.includes(domain));
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
    const url = new URL(request.url);
    const origin = `${url.protocol}//${url.host}`;
    return ALLOWED_ORIGINS.some(allowedOrigin => origin === allowedOrigin);
  } catch {
    return false;
  }
}

// Check if request has proper authentication
function isAuthenticated(request) {
  const authHeader = request.headers.get('X-Image-Auth');
  const sessionToken = request.headers.get('X-Session-Token');
  const protectedFlag = request.headers.get('X-Protected-Image');

  // For local images from allowed origins, require all authentication headers
  if (isAllowedOrigin(request) && request.url.includes('/images/')) {
    return authHeader === 'protected' && sessionToken && protectedFlag === 'true';
  }

  // For external images, just check the protected flag
  return protectedFlag === 'true';
}

// Handle fetch events
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = request.url;

  // Only intercept GET requests for protected images
  if (request.method !== 'GET' || !isProtectedImage(url)) {
    return;
  }

  // Check authentication for local images - return 404 if not authenticated
  if (isAllowedOrigin(request) && url.includes('/images/') && !isAuthenticated(request)) {
    event.respondWith(
      new Response('404 Not Found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain' },
      })
    );
    return;
  }

  event.respondWith(
    (async () => {
      try {
        // Create a new request with protection headers
        const protectedRequest = new Request(url, {
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers.entries()),
            'X-Requested-With': 'XMLHttpRequest',
            'X-Session-Token': generateSessionToken(),
            'X-Protected-Image': 'true',
            'Referer': self.location.origin,
          },
          mode: 'cors',
          credentials: 'omit',
        });

        // Try to fetch with protection headers
        const response = await fetch(protectedRequest);

        // Add additional security headers to the response
        const newHeaders = new Headers(response.headers);
        newHeaders.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
        newHeaders.set('Pragma', 'no-cache');
        newHeaders.set('Expires', '0');
        newHeaders.set('X-Content-Type-Options', 'nosniff');
        newHeaders.set('X-Frame-Options', 'DENY');

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
      } catch (error) {
        console.error('Service Worker: Failed to fetch protected image:', error);
        // Return a placeholder response
        return new Response('Image access denied', {
          status: 403,
          headers: { 'Content-Type': 'text/plain' },
        });
      }
    })()
  );
});

// Handle messages from the main thread
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});