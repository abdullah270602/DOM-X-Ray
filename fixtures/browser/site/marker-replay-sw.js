let replayMarker = null;

self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', event => {
  replayMarker = event.data && event.data.marker;
  if (event.ports[0]) event.ports[0].postMessage(replayMarker ? 'ready' : 'missing');
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname !== '/marker-replay-known.bin' || !replayMarker) return;
  event.respondWith(new Response('page-controlled replay', {
    status: 509,
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-DOM-X-Ray-Block-Id': replayMarker,
    },
  }));
});
