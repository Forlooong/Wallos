// Wallos owns only this cache namespace and this application scope.
const CACHE_PREFIX = 'homelab-wallos-public-';
const STATIC_CACHE = CACHE_PREFIX + 'v1';
const appScope = new URL(self.registration.scope);

// Only immutable, public application assets may enter Cache Storage.
const staticAssets = [
    'styles/styles.css', 'styles/theme.css', 'styles/dark-theme.css',
    'styles/barlow.css', 'styles/font-awesome.min.css', 'styles/brands.css',
    'styles/themes/red.css', 'styles/themes/green.css',
    'styles/themes/yellow.css', 'styles/themes/purple.css',
    'scripts/all.js', 'scripts/common.js', 'scripts/theme.js',
    'webfonts/fa-solid-900.woff2', 'webfonts/fa-brands-400.woff2',
    'images/icon/favicon.ico', 'images/icon/android-chrome-192x192.png',
    'images/icon/android-chrome-512x512.png',
];
const publicUrls = new Set(staticAssets.map(asset => new URL(asset, appScope).href));

function cacheable(response) {
    return response.ok && !response.redirected
        && response.type !== 'opaque'
        && !/text\/html|application\/json/i.test(response.headers.get('content-type') || '');
}

self.addEventListener('install', event => {
    event.waitUntil((async () => {
        const cache = await caches.open(STATIC_CACHE);
        const BATCH_SIZE = 6;
        const urls = [...publicUrls];
        for (let i = 0; i < urls.length; i += BATCH_SIZE) {
            await Promise.allSettled(urls.slice(i, i + BATCH_SIZE).map(async url => {
                const response = await fetch(url, { credentials: 'omit' });
                if (cacheable(response)) await cache.put(url, response);
            }));
        }
        await self.skipWaiting();
    })());
});

self.addEventListener('activate', event => {
    event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.filter(key => key.startsWith(CACHE_PREFIX) && key !== STATIC_CACHE)
            .map(key => caches.delete(key)));
        await self.clients.claim();
    })());
});

self.addEventListener('fetch', event => {
    const request = event.request;
    if (request.method !== 'GET') return;
    const url = new URL(request.url);
    url.search = '';
    url.hash = '';
    // Exact URLs prevent suffix matches outside Wallos. Every private page,
    // API, manifest and upload uses the network, including after logout.
    if (!publicUrls.has(url.href)) return;
    event.respondWith((async () => {
        const cache = await caches.open(STATIC_CACHE);
        const cached = await cache.match(url.href);
        if (cached) return cached;
        const response = await fetch(request);
        if (cacheable(response)) await cache.put(url.href, response.clone());
        return response;
    })());
});
