const CACHE_NAME='pulse-shell-v1';
const APP_SHELL=['/','/index.html','/manifest.webmanifest','/pulse-logo.png','/icon.png','/icon-192.png','/icon-512.png','/apple-touch-icon.png','/favicon.ico'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE_NAME).then(cache=>cache.addAll(APP_SHELL)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('pulse-shell-')&&key!==CACHE_NAME).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  const request=event.request,url=new URL(request.url);
  if(request.method!=='GET'||url.origin!==self.location.origin)return;
  if(url.pathname==='/api'||url.pathname.startsWith('/api/')||url.pathname.startsWith('/downloads/'))return;
  if(request.mode==='navigate'&&(url.pathname==='/'||url.pathname==='/index.html')){
    event.respondWith((async()=>{try{const response=await fetch(request);if(response.ok){const cache=await caches.open(CACHE_NAME);await cache.put('/index.html',response.clone())}return response}catch{const cache=await caches.open(CACHE_NAME);return (await cache.match('/index.html'))||(await cache.match('/'))||Response.error()}})());
    return;
  }
  if(APP_SHELL.includes(url.pathname))event.respondWith(caches.match(request).then(cached=>cached||fetch(request)));
});
