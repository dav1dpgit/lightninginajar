// LiJ service worker — v400 (S30): wake notifications (push +
// notificationclick). Base: v395 (S29) PRECACHE-AT-INSTALL + network-first.
// One online open arms offline: install caches the shell, styles, the
// wasm decryptor pair, and fonts. Runtime stays NETWORK-FIRST for every
// same-origin GET (online behavior identical to having no worker; ?v=
// busters unaffected). Offline: exact match → ignore-search match →
// navigation shell fallback. Cross-origin never intercepted.
// RITUAL: buster flips must update PRECACHE versions below.
const CACHE = 'lij-offline-v710';  // v468 RITUAL: bump with EVERY page build — a changed sw.js re-runs install, refreshing the precached shell (the SW sat unchanged since v400, freezing iOS's offline-served index at v400-era)
// v687 (S45, DP): UPDATES DIAL. The mode lives in a settings cache that
// survives CACHE bumps, so a freshly installed sw.js can read it in its own
// install event. Under 'ask' the new build precaches, describes itself (page
// and engine versions from the page text; sha256 of the engine glue + wasm)
// and WAITS; the page shows a card and the user's tap sends lij-skip-waiting.
// Under 'auto' nothing changes from before. Honest limit, stated on the dial:
// the browser replaces this worker from its origin unconditionally, so a
// hostile build could ignore the setting — this stops silent replacement and
// lets the engine hashes be checked; it cannot pin against the origin.
const SETTINGS_CACHE = 'lij-settings';
const MODE_KEY = '/__lij_update_mode';
const PENDING_KEY = '/__lij_pending_build';
async function readMode() {
  try { const c = await caches.open(SETTINGS_CACHE); const r = await c.match(MODE_KEY); if (!r) return 'auto'; const j = await r.json(); return (j && j.mode === 'ask') ? 'ask' : 'auto'; }
  catch (e) { return 'auto'; }
}
async function writeSetting(key, obj) {
  try { const c = await caches.open(SETTINGS_CACHE); await c.put(key, new Response(JSON.stringify(obj), { headers: { 'Content-Type': 'application/json' } })); } catch (e) {}
}
async function sha256Hex(buf) {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
const PRECACHE = [
  '/wallet/',
  '/wallet/index.html',
  '/styles.css?v=326',
  '/wood-hinoki.jpg?v=1',   // v623: hinoki wood-motif plane image \u2014 a future buster flip updates the page token, the tile, and this line together (parity law)   // v579: styles buster flip — precache moves in lockstep (the parity lesson generalized)
  '/pkg/lij_wasm.js?v=239',   // v567 (S37 ROOT-CAUSE): precache pinned at v214 since S34 while the page moved to v218 (S36 flips v215-218 never updated this list) — with the v472 exact-or-nothing /pkg law, OFFLINE ENGINE LOAD was impossible on every device. The sanity pass now asserts page-buster == precache version, permanently.
  '/pkg/lij_wasm_bg.wasm?v=239',
  '/fonts/geist-sans-400.woff2',
  '/fonts/geist-sans-500.woff2',
  '/fonts/geist-mono-400.woff2',
  '/vendor/qrcode.min.js',
  '/vendor/qr-scanner.min.js',
  '/vendor/qr-scanner-worker.min.js',
  '/vendor/bc-ur.min.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    const fetched = {};   // v687: keep the bytes to describe this build
    await Promise.allSettled(PRECACHE.map((u) => fetch(new Request(u, { cache: 'reload' })).then(async (r) => {
      if (r && r.ok) {
        try { fetched[u] = await r.clone().arrayBuffer(); } catch (e) {}
        return c.put(u, r);
      }
    }).catch(() => {})));
    try {
      const pageBuf = fetched['/wallet/index.html'] || fetched['/wallet/'];
      const pageTxt = pageBuf ? new TextDecoder().decode(pageBuf) : '';
      const pv = (pageTxt.match(/LIJ_FRONTEND_VERSION = 'phase11-(v\d+)'/) || [])[1] || null;
      const ev = (pageTxt.match(/LIJ_WASM_EXPECTED = 'phase11-(v\d+)'/) || [])[1] || null;
      const glueKey = PRECACHE.find((u) => u.indexOf('/pkg/lij_wasm.js') === 0);
      const wasmKey = PRECACHE.find((u) => u.indexOf('/pkg/lij_wasm_bg.wasm') === 0);
      const glue = fetched[glueKey] ? await sha256Hex(fetched[glueKey]) : null;
      const wasm = fetched[wasmKey] ? await sha256Hex(fetched[wasmKey]) : null;
      await writeSetting(PENDING_KEY, { cache: CACHE, page: pv, engine: ev, glue_sha256: glue, wasm_sha256: wasm, at: Date.now() });
    } catch (err) {}
    const mode = await readMode();
    if (mode !== 'ask') await self.skipWaiting();   // v687: under Ask me this build waits for the user's tap
  })());
});

// v687: the page posts the dial's mode (at every load and on change) and the
// card's tap; the waiting worker receives the tap directly.
self.addEventListener('message', (e) => {
  const d = (e && e.data) || {};
  if (d.type === 'lij-update-mode') { e.waitUntil(writeSetting(MODE_KEY, { mode: d.mode === 'ask' ? 'ask' : 'auto' })); }
  else if (d.type === 'lij-skip-waiting') { self.skipWaiting(); }
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE && k !== SETTINGS_CACHE).map((k) => caches.delete(k)));   // v687: the settings cache survives
    await self.clients.claim();
  })());
});

// v399 (S30): WAKE NOTIFICATIONS. The adapter's web-push ({t:'wake'}) reached
// the device but this worker had NO push handler — nothing was ever displayed,
// and iOS throttles subscriptions whose pushes show nothing. Field-found by DP
// on the offline zero-JIT run. Tapping the notification focuses or opens the
// wallet, which is exactly the wake the held payment needs.
// v543 (S36, DP UX fix): (1) the time-to-open line renders ONLY when the app
// is backgrounded/closed — a visible client settles the payment itself, and
// telling a foregrounded user to "open within N minutes" was nonsense; (2) the
// window is now the VARIABLE the adapter sends (hold_s, adapter 0.55.6 — the
// wallet's own hold-dial choice), never the v400-era hardcoded "3 minutes"; an
// older adapter payload without hold_s gets honest wording with NO invented
// number. Never say "jar" (lock-screen context has no brand surround).
self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (err) {}
  e.waitUntil((async () => {
    let foreground = false;
    try {
      const cs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      foreground = cs.some((c) => c.visibilityState === 'visible');
    } catch (err) {}
    let body, title = 'Payment waiting';
    if (data.t === 'wake') {
      if (foreground) {
        title = 'Payment arriving';
        body = 'A payment is arriving in your open wallet now.';
      } else {
        const s = Number(data.hold_s);
        if (Number.isFinite(s) && s > 0) {
          const w = (s >= 3600 && s % 3600 === 0)
            ? (s / 3600) + ' hour' + (s === 3600 ? '' : 's')
            : Math.max(1, Math.round(s / 60)) + ' minute' + (Math.round(s / 60) === 1 ? '' : 's');
          body = 'Open the LiJ app within ' + w + ' to receive it.';
        } else {
          body = 'Open the LiJ app to receive it.';
        }
      }
    } else {
      body = 'Open the LiJ app.';
    }
    await self.registration.showNotification(title, {
      body: body,
      tag: 'lij-wake',
      // v546: renotify — a repeat wake RE-ALERTS instead of silently
      // replacing the same-tag notification; vibrate strengthens Android
      // (heads-up banners remain governed by the site's Android
      // notification-channel importance, a device setting).
      renotify: true,
      vibrate: [180, 90, 180],
      icon: '/icon-maskable-192.png',
      badge: '/icon-maskable-192.png'
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if ('focus' in c) return c.focus();
    }
    return self.clients.openWindow('/wallet/');
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (err) { return; }
  if (url.origin !== self.location.origin) return;
  if (url.pathname === '/__lij_net_probe') return;  // v568: the reachability probe is a RAW network question — the SW never answers it (no cache can exist for it today, _redirects-verified; this removes the class forever and takes the probe out of the SW timing envelope)
  e.respondWith((async () => {
    // v471: BOUNDED network-first. A VPN blackhole (Tailscale up during
    // airplane/flaky states — DP field find, iPhone XS) hangs fetches for
    // ~50s at the OS layer instead of failing fast; a present cache must
    // not lose to a hung network. When a cached fallback exists, the
    // network races a 3.5s timer and the cache serves on timeout — the
    // late network response still lands in cache for next load. First-ever
    // loads (no fallback) keep the full network wait, unchanged.
    const c = await caches.open(CACHE);
    // v687: under Ask me the shell, the engine pair and the stylesheet are
    // served CACHE-FIRST from the installed build — never refreshed from the
    // network here, or the pin would leak. A new build lands only through its
    // own worker's install + the user's tap. Everything else stays as below.
    if (await readMode() === 'ask') {
      const isPkgA = url.pathname.indexOf('/pkg/') === 0;
      const pinned = isPkgA || url.pathname === '/wallet/' || url.pathname === '/wallet/index.html' || url.pathname.endsWith('.css');
      if (pinned) {
        const hit = (await c.match(req))
          || (isPkgA ? null : (await c.match(req, { ignoreSearch: true })))
          || (req.mode === 'navigate' ? ((await c.match('/wallet/index.html', { ignoreSearch: true })) || (await c.match('/wallet/', { ignoreSearch: true }))) : null);
        if (hit) return hit;
      }
    }
    // v472: /pkg is EXACT-VERSION ONLY — the glue js and the wasm binary are
    // an atomic pair; ignoreSearch resolved each independently and could hand
    // the page js from one engine build and wasm from another (ABI trap at
    // unwrap, mis-read as a bad passphrase — DP field case). Exact or nothing:
    // an absent exact pair fails fast into the page's honest loading guard.
    const isPkg = url.pathname.indexOf('/pkg/') === 0;
    let fallback = (await c.match(req)) || (isPkg ? null : (await c.match(req, { ignoreSearch: true })));
    if (!fallback && req.mode === 'navigate') {
      fallback = (await c.match('/wallet/index.html', { ignoreSearch: true }))
        || (await c.match('/wallet/', { ignoreSearch: true }));
    }
    const netReq = isPkg ? new Request(req, { cache: 'reload' }) : req;  // v486: /pkg always revalidates at origin — the laundering loop dies here
    const netP = fetch(netReq).then((net) => {
      if (net && net.ok) c.put(req, net.clone()).catch(() => {});
      return net;
    });
    if (!fallback) return netP;
    const bound569 = navigator.onLine === false ? 800 : (req.mode === 'navigate' ? 4000 : 3500);  // v569: onLine=false is a HINT, not a verdict (the flag sticks false on old-iOS PWAs after airplane toggles — DP road case) — an 800ms bound keeps offline near-instant while a lying flag self-heals within a second
    const timer = new Promise((res) => setTimeout(() => res(null), bound569));
    const net = await Promise.race([netP.catch(() => null), timer]);
    if (net) return net;
    return fallback;
  })());
});
