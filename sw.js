const CACHE_NAME = 'lotuscyber-pwa-v5';

const APP_ASSETS = [
'./',
'./index.html',
'./manifest.json',
'./icon-192.png',
'./icon-512.png'
];

const CDN_ASSETS = [
'https://cdn.tailwindcss.com',
'https://unpkg.com/lucide@latest',
'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js'
];

// INSTALL
self.addEventListener('install', (event) => {
event.waitUntil(
(async () => {
const cache = await caches.open(CACHE_NAME);

  // Fail utama wajib berjaya dicache.
  await cache.addAll(APP_ASSETS);
  // CDN pilihan: kegagalan satu CDN tidak membatalkan pemasangan.
  await Promise.allSettled(
    CDN_ASSETS.map(async (url) => {
      const response = await fetch(url, { mode: 'no-cors' });
      await cache.put(url, response);
    })
  );
  await self.skipWaiting();
})()

);
});

// ACTIVATE
self.addEventListener('activate', (event) => {
event.waitUntil(
(async () => {
const keys = await caches.keys();

  await Promise.all(
    keys
      .filter((key) => key.startsWith('lotuscyber-pwa-') && key !== CACHE_NAME)
      .map((key) => caches.delete(key))
  );
  await self.clients.claim();
})()

);
});

// FETCH
self.addEventListener('fetch', (event) => {
const request = event.request;

if (request.method !== 'GET') return;

const url = new URL(request.url);

// API mesti menggunakan rangkaian, bukan cache.
if (url.pathname.startsWith('/api/')) return;

event.respondWith(
(async () => {
const cached = await caches.match(request);

  if (cached) {
    return cached;
  }
  try {
    const response = await fetch(request);
    if (response && (response.ok || response.type === 'opaque')) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone()).catch(() => {});
    }
    return response;
  } catch (error) {
    if (request.mode === 'navigate') {
      return (
        await caches.match('./index.html') ||
        new Response('LotusCyber tidak tersedia ketika offline.', {
          status: 503,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        })
      );
    }
    return new Response('Sumber tidak tersedia ketika offline.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
})()

);
});
