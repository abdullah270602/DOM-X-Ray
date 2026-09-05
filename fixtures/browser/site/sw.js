self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname !== '/sw/worker-data') return;
  event.respondWith(new Response('w'.repeat(4096), {
    status: 200,
    headers: { 'Content-Type': 'application/octet-stream' },
  }));
});
