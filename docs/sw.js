const PREFIX = 'pso-viewer-' + encodeURIComponent(new URL('./', self.location).pathname) + '-shell-';
const CACHE = PREFIX + 'github-v7-web-push';
const SHELL = ['./','./index.html','./styles.css','./app.mjs','./crypto.mjs','./exchange.mjs','./storage.mjs','./sharing.mjs','./push.mjs','./shortlinks.mjs','./shortlink-config.mjs','./manifest.webmanifest','./icon-pso-v2-192.png','./icon-pso-v2-512.png','./apple-touch-icon-pso-v2.png','./favicon-pso-v2.png','./icon-192.png','./icon-512.png','./apple-touch-icon.png'];
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


// Notifications carry only a random lookup ID and expiry. Patient data is never
// resolved or decrypted by this worker and never written to its shell cache.
const APP = new URL('./', self.location);
function notificationPayload(value, now = Date.now()) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'expires,id,v' || value.v !== 1 ||
      !Number.isSafeInteger(value.expires) || value.expires <= now ||
      value.expires > now + 86430000 ||
      !(value.id === null || (typeof value.id === 'string' && /^[A-Za-z0-9_-]{21}[AQgw]$/.test(value.id)))) return null;
  return {v:1, id:value.id, expires:value.expires};
}
self.addEventListener('push', event => {
  let payload = null;
  try { payload = notificationPayload(event.data?.json()); } catch {}
  // Even malformed or expired pushes remain user-visible as required by Apple.
  // They can only open the app home page, never an unvalidated destination.
  event.waitUntil(self.registration.showNotification('ПСО', {
    body:payload?.id === null ? 'Проверка уведомлений' : 'Новое сообщение ПСО',
    icon:new URL('./icon-pso-v2-192.png', APP).href,
    tag:payload?.id ? 'pso-' + payload.id : 'pso-notification',
    data:payload || {v:1,id:null,expires:0}
  }));
});
async function openNotification(data) {
  const payload = notificationPayload(data);
  const target = new URL(APP.href);
  if (payload?.id) target.hash = 'r=' + payload.id;
  let windows = [];
  try { windows = await self.clients.matchAll({type:'window',includeUncontrolled:true}); } catch {}
  for (const client of windows) {
    let current;
    try { current = new URL(client.url); } catch { continue; }
    if (current.origin !== APP.origin || current.username || current.password ||
        ![APP.pathname,APP.pathname+'index.html'].includes(current.pathname)) continue;
    try {
      const navigated = await client.navigate(target.href);
      if (navigated) { await navigated.focus(); return; }
    } catch {}
  }
  await self.clients.openWindow(target.href);
}
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(openNotification(event.notification.data));
});
