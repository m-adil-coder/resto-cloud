const CACHE_NAME = 'restopos-app-v10'
const STATIC_ASSETS = [
  '/',
  '/app.html',
  '/index.html',
  '/manifest.json',
  '/favicon.png',
  '/icon-192.png',
  '/icon-512.png'
]

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('PWA Precache warning:', err)
      })
    })
  )
  self.skipWaiting()
})

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((k) => {
          if (k !== CACHE_NAME) return caches.delete(k)
        })
      )
    })
  )
  self.clients.claim()
})

self.addEventListener('fetch', (e) => {
  const req = e.request
  const url = new URL(req.url)

  // API calls: Network first, with graceful offline JSON fallback
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(req).catch(() => {
        return new Response(
          JSON.stringify({ ok: false, offline: true, message: 'Offline mode: You are working without internet.' }),
          { headers: { 'Content-Type': 'application/json' } }
        )
      })
    )
    return
  }

  // HTML page navigations (opening installed PWA from home screen)
  if (req.mode === 'navigate' || req.destination === 'document' || url.pathname.endsWith('.html') || url.pathname === '/') {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.status === 200) {
            const clone = res.clone()
            caches.open(CACHE_NAME).then((cache) => cache.put(req, clone))
          }
          return res
        })
        .catch(async () => {
          const cached = await caches.match(req)
          if (cached) return cached
          const appCached = await caches.match('/app.html')
          if (appCached) return appCached
          return caches.match('/')
        })
    )
    return
  }

  // Static files: Cache first, fallback to network
  e.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached
      return fetch(req).then((res) => {
        if (res && res.status === 200 && req.method === 'GET') {
          const clone = res.clone()
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone))
        }
        return res
      }).catch(() => cached)
    })
  )
})
