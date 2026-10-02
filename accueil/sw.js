// Service Worker minimal de la page d'accueil — même principe que celui de
// Bilan de Passage : rend la page installable sur l'écran d'accueil, sans
// cache offline, pour toujours servir la dernière version publiée.
const SW_VERSION = '2026.10.02-3';
self.addEventListener('install', (event) => {
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
