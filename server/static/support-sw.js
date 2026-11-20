// Installable portal. Never cache API responses, credentials, or customer data.
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{if(event.request.mode==='navigate')event.respondWith(fetch(event.request).catch(()=>new Response('Pulse Support is offline. Reconnect to view requests or contact your support team.',{headers:{'Content-Type':'text/plain;charset=utf-8'}})))});
