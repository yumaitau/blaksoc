const CACHE = "blaksoc-portal-v1";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  const path = url.pathname;
  const cacheable = path === "/portal" || path.startsWith("/portal/incidents/");
  if (!cacheable) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const res = await fetch(req);
      if (res.ok && res.type === "basic") await cache.put(req, res.clone());
      return res;
    } catch {
      const hit = await cache.match(req) || await cache.match("/portal");
      if (hit) return hit;
      return new Response("You are offline. Open the portal once while you have coverage to keep the last incident status on this phone.", {
        status: 503,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  })());
});
