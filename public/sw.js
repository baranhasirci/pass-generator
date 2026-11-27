// PassGen service worker: cache-first app shell so the app opens instantly and
// works offline. Bump CACHE on every deploy that changes any file below;
// users then get a "new version available" prompt.
const CACHE = 'passgen-v2.0.1';
const ASSETS = [
    './index.html',
    './styles.css',
    './theme.js',
    './app.js',
    './core.js',
    './manifest.json',
    './icon-192.png',
    './icon-512.png',
    './icon-maskable-512.png',
    './apple-touch-icon.png'
];

const SCOPE_PATH = new URL('./', self.location).pathname;

// Versioned cache names. Anything else ('passgen-v1', 'passgen-v2') belongs to
// the pre-v2 service worker.
const VERSIONED = /^passgen-v\d+\.\d+\.\d+$/;

self.addEventListener('install', (event) => {
    event.waitUntil((async () => {
        const cache = await caches.open(CACHE);
        // Bypass the HTTP cache so a new version never caches stale files.
        await cache.addAll(ASSETS.map((url) => new Request(url, { cache: 'reload' })));
        // Pages of the pre-v2 app have no "new version" prompt, so a waiting worker
        // would never be activated while one is open: take over from it right away.
        const keys = await caches.keys();
        if (keys.some((key) => !VERSIONED.test(key))) await self.skipWaiting();
    })());
});

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)));
        await self.clients.claim();
    })());
});

// The page asks the waiting worker to take over when the user clicks "Reload".
self.addEventListener('message', (event) => {
    if (event.data === 'skipWaiting') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.method !== 'GET') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;

    if (request.mode === 'navigate') {
        // Any visit to the app's start page (with or without ?query) gets the cached shell.
        if (url.pathname === SCOPE_PATH || url.pathname === SCOPE_PATH + 'index.html') {
            event.respondWith(fromCache('./index.html').then((cached) => cached || fetch(request)));
        }
        return;
    }

    event.respondWith(fromCache(request).then((cached) => cached || fetch(request)));
});

async function fromCache(request) {
    const cache = await caches.open(CACHE);
    return cache.match(request, { ignoreSearch: true });
}
