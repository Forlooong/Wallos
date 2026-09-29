// Execute the real worker with browser API doubles; no private data or network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const events = new Map();
const entries = new Map();
const deleted = [];
const fetched = [];
const scope = 'https://site.test/apps/wallos/';
let mime = 'text/css';
const response = () => ({ ok: true, redirected: false, type: 'basic', headers: { get: () => mime }, clone: response });
const cache = { match: async key => entries.get(key), put: async (key, value) => entries.set(key, value) };
const context = {
    URL, Set, Promise,
    self: { registration: { scope }, addEventListener: (type, fn) => events.set(type, fn),
        skipWaiting: async () => {}, clients: { claim: async () => {} } },
    caches: { open: async name => { assert.equal(name, 'homelab-wallos-public-v1'); return cache; },
        keys: async () => ['homelab-wallos-public-v0', 'homelab-wallos-public-v1', 'notes-cache', 'static-cache-v8'],
        delete: async name => deleted.push(name) },
    fetch: async request => { fetched.push(typeof request === 'string' ? request : request.url); return response(); },
};
vm.runInNewContext(fs.readFileSync(path.join(root, 'service-worker.js'), 'utf8'), context);
async function dispatch(type) {
    let pending;
    events.get(type)({ waitUntil: value => { pending = value; } });
    await pending;
}
function request(url, method = 'GET') {
    let intercepted = false;
    let pending;
    events.get('fetch')({ request: { url, method }, respondWith: value => { intercepted = true; pending = value; } });
    return { intercepted, pending };
}
(async () => {
    await dispatch('install');
    assert.equal(entries.size, 18);
    for (const url of entries.keys()) {
        assert.ok(url.startsWith(scope));
        assert.ok(fs.existsSync(path.join(root, new URL(url).pathname.slice('/apps/wallos/'.length))));
        assert.ok(!url.includes('.php') && !url.includes('/uploads/'));
    }
    await dispatch('activate');
    assert.deepEqual(deleted, ['homelab-wallos-public-v0']);
    for (const url of [
        scope, scope + 'profile.php', scope + 'manifest.php',
        scope + 'endpoints/subscriptions/export.php', scope + 'images/uploads/logos/secret.png',
        scope + 'private_file.php?file=secret.png',
        'https://site.test/apps/notes/styles/styles.css', 'https://evil.test/apps/wallos/styles/styles.css',
        scope + 'nested/styles/styles.css',
    ]) {
        assert.equal(request(url).intercepted, false, 'private and out-of-scope requests never use cache: ' + url);
    }
    assert.equal(request(scope + 'styles/styles.css', 'POST').intercepted, false);
    const cached = request(scope + 'styles/styles.css?v=5.8.2');
    assert.equal(cached.intercepted, true);
    const count = fetched.length;
    await cached.pending;
    assert.equal(fetched.length, count, 'versioned public asset can reuse explicit cache entry');
    entries.clear(); mime = 'text/html';
    await request(scope + 'styles/styles.css').pending;
    assert.equal(entries.size, 0, 'a login/error HTML response must never enter the public cache');
    console.log('Wallos service worker: public allowlist, private bypass, scope and cache ownership passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
