const PREFIX = 'pso-viewer-' + encodeURIComponent(new URL('./', self.location).pathname) + '-shell-';
const CACHE = PREFIX + 'github-v5-message-captions';
const SHELL = ['./','./index.html','./styles.css','./app.mjs','./crypto.mjs','./exchange.mjs','./storage.mjs','./sharing.mjs','./manifest.webmanifest','./icon-pso-v2-192.png','./icon-pso-v2-512.png','./apple-touch-icon-pso-v2.png','./favicon-pso-v2.png','./icon-192.png','./icon-512.png','./apple-touch-icon.png'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL))));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith(PREFIX) && k !== CACHE).map(k => caches.delete(k))))));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || url.search) return;
  const allowed = SHELL.map(item => new URL(item, self.location).pathname);
  if (!allowed.includes(url.pathname)) return;
  event.respondWith(caches.open(CACHE).then(async cache => {
    const cached = await cache.match(event.request);
    return cached || fetch(event.request);
  }));
});
