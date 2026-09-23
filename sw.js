const CACHE_NAME = 'indl-v2-cache-v1';
const urlsToCache = [
  '/',
  '/index.html',
  '/css/main.css',
  '/css/animations.css',
  '/css/responsive.css',
  '/js/app.js',
  '/js/auth.js',
  '/js/cache.js',
  '/js/downloader.js',
  '/js/ui.js',
  '/my.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  // We only cache GET requests
  if (event.request.method !== 'GET') {
    return;
  }
  // Don't cache API calls
  if (event.request.url.includes('/api/')) {
    return;
  }
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});

self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
