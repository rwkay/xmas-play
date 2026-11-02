// Service worker of the published (GitHub Pages) build: every game file is stored encrypted (pages/deploy.js);
// this decrypts each one as the page asks for it. The key is kept by the pages, not here: the browser can stop this
// worker at any time (phones do, often) and it then forgets it. The password page and the game page hand it over
// (a 'raw-key' message); a restarted worker that has none asks the page whose request it is answering ('need-key').
// IndexedDB isn't used: iOS can leave it hanging. The pages themselves, this file and lock.json are not encrypted.

const PLAIN = new Set([ '', 'index.html', 'game.html', 'sw.js', 'lock.json' ]);
const TYPES = { js: 'text/javascript', wasm: 'application/wasm', html: 'text/html', json: 'application/json',
                ttf: 'font/ttf', png: 'image/png', mp3: 'audio/mpeg', wav: 'audio/wav' };
const ASK_TIME_LIMIT = 5000;

let keyPromise = null;

function fromBase64(text) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}

function importKey(raw) {
  return crypto.subtle.importKey('raw', fromBase64(raw), 'AES-GCM', false, [ 'decrypt' ]);
}

// the key, from the page that made the request (by its client id), else from any open page of the site
async function askPage(clientId) {
  const client = clientId ? await self.clients.get(clientId) : null;
  const clients = client ? [ client ] : await self.clients.matchAll({ type: 'window' });
  for (const c of clients) {
    const channel = new MessageChannel();
    const answer = new Promise(resolve => { channel.port1.onmessage = event => resolve(event.data); });
    c.postMessage({ type: 'need-key' }, [ channel.port2 ]);
    const raw = await Promise.race([ answer, new Promise(resolve => setTimeout(() => resolve(null), ASK_TIME_LIMIT)) ]);
    if (raw)
      return importKey(raw);
  }
  return null;
}

function getKey(clientId) {
  if (!keyPromise) {
    keyPromise = askPage(clientId).then(key => {
      if (!key)
        keyPromise = null;      // no page had it: ask again next time
      return key;
    }, () => {
      keyPromise = null;
      return null;
    });
  }
  return keyPromise;
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  if (event.data && (event.data.type === 'raw-key') && event.data.raw)
    keyPromise = importKey(event.data.raw).catch(() => null);
  // (answered, so the password page knows the key has arrived before it opens the game)
  if (event.ports && event.ports[0])
    event.ports[0].postMessage('ok');
});

async function decrypted(request, name, clientId) {
  const key = await getKey(clientId);
  if (!key)
    return new Response('locked', { status: 403 });
  // revalidate, so a new deployment's files aren't mixed with cached ones from the last
  const response = await fetch(request.url, { cache: 'no-cache' });
  if (!response.ok)
    return response;
  const data = new Uint8Array(await response.arrayBuffer());
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
  } catch (e) {
    return new Response('this file could not be decrypted', { status: 500 });
  }
  const extension = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  return new Response(plain, { status: 200, headers: {
    'Content-Type': TYPES[extension] || 'application/octet-stream',
    'Content-Length': String(plain.byteLength),
  } });
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  const scope = new URL(self.registration.scope);
  if ((event.request.method !== 'GET') || (url.origin !== scope.origin) || !url.pathname.startsWith(scope.pathname))
    return;
  const name = decodeURIComponent(url.pathname.slice(scope.pathname.length));
  if (PLAIN.has(name))
    return;
  event.respondWith(decrypted(event.request, name, event.clientId));
});
