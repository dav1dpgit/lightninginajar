// LiJ service worker — v400 (S30): wake notifications (push +
// notificationclick). Base: v395 (S29) PRECACHE-AT-INSTALL + network-first.
// One online open arms offline: install caches the shell, styles, the
// wasm decryptor pair, and fonts. Runtime stays NETWORK-FIRST for every
// same-origin GET (online behavior identical to having no worker; ?v=
// busters unaffected). Offline: exact match → ignore-search match →
// navigation shell fallback. Cross-origin never intercepted.
// RITUAL: buster flips must update PRECACHE versions below.
// v880 (S51, DP — S6): the page shell (/wallet/, /wallet/index.html, any navigation in scope) is served CACHE-FIRST from
// the installed build; a new build shows at the next open, through its own worker's install. Reversible: one block.
// v873 (S51, DP): /pkg/ is served CACHE-FIRST on an exact-version hit (the pair is ?v= keyed) — the network only
// for a version this cache does not hold; the install copies an exact-version engine file from an earlier
// build's cache instead of re-fetching it. Everything else stays network-first as described above.
const CACHE = 'lij-offline-v1074';  // v468 RITUAL: bump with EVERY page build — a changed sw.js re-runs install, refreshing the precached shell (the SW sat unchanged since v400, freezing iOS's offline-served index at v400-era)
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
// v1057 (S62 Wed, DP 2026-10-21 "B.2 could be following the dial … Add it in"): WHERE AN UPDATE'S FILES COME FROM follows the
// Reach dial (docs/design/routes/phase-b2-r1.md). The browser's own check of this file is always at the origin; the
// install's downloads go to the host the dial names — lightninginajar.xyz itself, or Cloudflare's copy of the site (the
// Pages project, the same deploy branch). A file from the copy is kept only when its sha256 equals the stamp this worker
// carries (LIJ_EXPECTED, one per PRECACHE entry, written from the final bytes by ops/frontend/sw_stamp.py — the cut and
// CI's flip); otherwise it is taken from the origin and the record names it. The preference reaches here as the Updates
// mode does (the page posts lij-reach-pref at every load and on change); a test may seed /__lij_files_copy before the
// first install to point the copy at a stand-in — the page has no code path that writes it.
const REACH_KEY = '/__lij_reach';
const COPY_KEY = '/__lij_files_copy';
const FILES_COPY = 'https://lij-git.pages.dev';   // v1058: the Pages project is lij-git (v1057 named a host that does not exist)
/* LIJ_EXPECTED_BEGIN */ const LIJ_EXPECTED = { '/wallet/': '72dccaa982aae63ba35868c41cfce45371a551f6f514009ee1dc53fe3a5b67ff', '/wallet/index.html': '72dccaa982aae63ba35868c41cfce45371a551f6f514009ee1dc53fe3a5b67ff', '/styles.css?v=328': '2d3af7a0cf38d26ae46ef9e74424ca059fbfd4c042f3ac308f85043a6e4fa993', '/wood-hinoki.jpg?v=1': 'a4fe645c952c1ea59c9a6f40b0a59b1420aa4252c065bc7118a0d22a1053bc63', '/pkg/lij_wasm.js?v=358': 'da664c949d131faf0e8b2e21f604e2348968a7f488cebfaf0cb2b548e6c77e1b', '/pkg/lij_wasm_bg.wasm?v=358': '934281c2502d85cf9e6141c1f188ad5cc6524577535197057bbd9a191416de9b', '/fonts/geist-sans-400.woff2': 'faed18848df4a6e1b5503b589bbbc055fbdab0e1780781edf5105457395e1e5d', '/fonts/geist-sans-500.woff2': '0b50074337a05ed834a1474d3d13fc6bd8480e2ce3075d02f1d38c017a8ac2a4', '/fonts/geist-mono-400.woff2': 'c88d20967768754cbdca230acd74ecb25de78d0dc47e31694aa8bd2c528fec26', '/fonts/geist-mono-500.woff2': '7b0d8cbf68357ade96d7d7d7721578ac6e8935aab14da68b89d31cc5816c323c', '/vendor/qrcode.min.js': 'c541ef06327885a8415bca8df6071e14189b4855336def4f36db54bde8484f36', '/vendor/qr-scanner.min.js': '0564e4cf84b94cac80213b4f779bd215bb0876a91c19df28baf97766f4fd5484', '/vendor/qr-scanner-worker.min.js': 'f4d8445f5a15c4e5f71a8c8c062c6443f09db370b8d3fe1fbdc7fe7889630d14', '/vendor/bc-ur.min.js': 'af24ecc278152f563077058574b8ef7556f071eb0b04e4c1e0b0f263620dcc14' }; /* LIJ_EXPECTED_END */
async function readSetting(key) { try { const c = await caches.open(SETTINGS_CACHE); const r = await c.match(key); return r ? await r.json() : null; } catch (e) { return null; } }
async function readReach() { const j = await readSetting(REACH_KEY); const v = j && j.pref; return (v === 'never-cloudflare' || v === 'cloudflare-first') ? v : 'direct-first'; }
async function copyBase() { const j = await readSetting(COPY_KEY); return (j && typeof j.url === 'string' && /^https?:\/\//.test(j.url)) ? j.url.replace(/\/+$/, '') : FILES_COPY; }
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
  '/styles.css?v=328',
  '/wood-hinoki.jpg?v=1',   // v623: hinoki wood-motif plane image \u2014 a future buster flip updates the page token, the tile, and this line together (parity law)   // v579: styles buster flip — precache moves in lockstep (the parity lesson generalized)
  '/pkg/lij_wasm.js?v=358',   // v567 (S37 ROOT-CAUSE): precache pinned at v214 since S34 while the page moved to v218 (S36 flips v215-218 never updated this list) — with the v472 exact-or-nothing /pkg law, OFFLINE ENGINE LOAD was impossible on every device. The sanity pass now asserts page-buster == precache version, permanently.
  '/pkg/lij_wasm_bg.wasm?v=358',
  '/fonts/geist-sans-400.woff2',
  '/fonts/geist-sans-500.woff2',
  '/fonts/geist-mono-400.woff2',
  '/fonts/geist-mono-500.woff2',   /* v1053: the opening's name */
  '/vendor/qrcode.min.js',
  '/vendor/qr-scanner.min.js',
  '/vendor/qr-scanner-worker.min.js',
  '/vendor/bc-ur.min.js'
];

// v934 (S54, DP 2026-10-04 10:41 — the Push Key link: "This site can't be reached … ERR_FAILED"): the host answers
// /wallet/index.html with a redirect to /wallet/, so its stored copy carried the redirect mark — and a browser refuses a
// redirected response as the answer to a page load (Chrome ERR_FAILED; Safari "Response served by service worker has
// redirections"). Every response is stored, and every cached answer served, without the mark: the same bytes, status
// and headers in a fresh Response. A response that was not redirected passes through untouched.
async function unredirected(r) {
  if (!r || !r.redirected) return r;
  const body = await r.blob();
  return new Response(body, { status: r.status, statusText: r.statusText, headers: r.headers });
}

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    const fetched = {};   // v687: keep the bytes to describe this build
    const pref = await readReach(); const copy = await copyBase();   // v1057: the dial's value and Cloudflare's copy
    const order = pref === 'never-cloudflare' ? ['origin'] : (pref === 'cloudflare-first' ? ['copy', 'origin'] : ['origin', 'copy']);
    const rec = { origin: 0, copy: 0, held: 0, verified: 0, mismatch: [], stale: [], failed: [] };
    await Promise.allSettled(PRECACHE.map(async (u) => {
      // v873 (S51, DP): the engine pair is exact-version keyed — an earlier build's cache holding this exact URL
      // has the right bytes; copy them instead of downloading 8.4 MB again for a page-only build
      if (u.indexOf('/pkg/') === 0) {
        try { const prev = await caches.match(u); if (prev && prev.ok) { try { fetched[u] = await prev.clone().arrayBuffer(); } catch (e) {} await c.put(u, prev); rec.held++; return; } } catch (e) {}
      }
      // v1057: each source in the dial's order; a copy file must match its stamp; the stored response is rebuilt from the
      // bytes — never the copy's address, never the redirect mark (v934)
      for (const src of order) {
        let r = null;
        try { r = await fetch(src === 'copy' ? new Request(copy + u, { cache: 'reload', mode: 'cors' }) : new Request(u, { cache: 'reload' })); } catch (e) { r = null; }
        if (!r || !r.ok) continue;
        let buf; try { buf = await r.arrayBuffer(); } catch (e) { continue; }
        const want = LIJ_EXPECTED[u] || null;
        const got = want ? await sha256Hex(buf) : null;
        if (src === 'copy' && (!want || got !== want)) { rec.mismatch.push(u); continue; }
        if (src === 'origin' && want && got !== want) rec.stale.push(u);   // the origin is the trust root: kept, and the stamp named as stale
        fetched[u] = buf;
        await c.put(u, new Response(buf, { status: r.status, statusText: r.statusText, headers: r.headers }));
        rec[src]++; if (want && got === want) rec.verified++;
        return;
      }
      rec.failed.push(u);
    }));
    try {
      const pageBuf = fetched['/wallet/index.html'] || fetched['/wallet/'];
      const pageTxt = pageBuf ? new TextDecoder().decode(pageBuf) : '';
      const pv = (pageTxt.match(/LIJ_FRONTEND_VERSION = 'phase11-(v\d+)'/) || [])[1] || null;
      const ev = (pageTxt.match(/LIJ_WASM_EXPECTED = 'phase11-(v\d+)'/) || [])[1] || null;
      const glueKey = PRECACHE.find((u) => u.indexOf('/pkg/lij_wasm.js') === 0);
      const wasmKey = PRECACHE.find((u) => u.indexOf('/pkg/lij_wasm_bg.wasm') === 0);
      const glue = fetched[glueKey] ? await sha256Hex(fetched[glueKey]) : null;
      const wasm = fetched[wasmKey] ? await sha256Hex(fetched[wasmKey]) : null;
      await writeSetting(PENDING_KEY, { cache: CACHE, page: pv, engine: ev, glue_sha256: glue, wasm_sha256: wasm, at: Date.now(), pref: pref, copy_url: copy, source: rec });   // v1057: where the files came from
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
  else if (d.type === 'lij-reach-pref') { e.waitUntil(writeSetting(REACH_KEY, { pref: (d.pref === 'never-cloudflare' || d.pref === 'cloudflare-first') ? d.pref : 'direct-first' })); }   // v1057
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
// v914 (S54, DP 2026-10-02 11:17 "make sure the push alert is accurate to the actual time it will be held"): THE WORDS,
// in one place. Adapter 0.88.1 sends the window actually held (hold_s, rounded down) and when it ends (until_ms), or
// neither when nothing is held. Never more time than is left: an hour or more → the clock time it ends (seconds dropped,
// so never later than the end; still true while the alert waits in the tray); under an hour → the whole minutes left
// and the clock time; under a minute → now; after the end → it may have gone back. A phone clock more than 2 minutes
// behind the provider's → the window alone. An older provider (hold_s only) → its hours and minutes, rounded down.
function lijWakeWords(data, nowMs) {
  const dur = (ms) => {
    const m = Math.floor(ms / 60000);
    if (m < 60) return m + ' minute' + (m === 1 ? '' : 's');
    const h = Math.floor(m / 60), mm = m % 60;
    return h + ' hour' + (h === 1 ? '' : 's') + (mm ? ' ' + mm + ' minute' + (mm === 1 ? '' : 's') : '');
  };
  const clock = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); } catch (err) { return ''; } };
  const s = Number(data && data.hold_s), u = Number(data && data.until_ms);
  const haveS = Number.isFinite(s) && s > 0;
  if (Number.isFinite(u) && u > 0) {
    const rem = u - nowMs;
    if (!(haveS && rem > s * 1000 + 120000)) {
      if (rem <= 0) return 'Open the LiJ app \u2014 this payment may already have gone back to the sender.';
      if (rem < 60000) return 'Open the LiJ app now to receive it.';
      const c = clock(u);
      if (rem >= 3600000 && c) return 'Open the LiJ app by ' + c + ' to receive it.';
      return 'Open the LiJ app within ' + dur(rem) + (c ? ' (by ' + c + ')' : '') + ' to receive it.';
    }
  }
  if (haveS) return (s < 60) ? 'Open the LiJ app now to receive it.' : 'Open the LiJ app within ' + dur(s * 1000) + ' to receive it.';
  return 'Open the LiJ app to receive it.';
}
// v1065 (S63, DP 2026-10-26 — adapter 0.113.0 (1)): the SENDER's wake when a Push Key is taken (push_taken) or comes
// back untaken (push_returned): the lock on this phone's channel settles or returns only while LiJ is online, and one
// left hanging past the time the provider gives (until_ms = the HTLC's expiry) can close the channel. The same
// never-more-time-than-is-left rule as lijWakeWords. Self-contained (the gate evaluates it as written).
function lijPushKeyWords(data, nowMs) {
  const dur = (ms) => {
    const m = Math.floor(ms / 60000);
    if (m < 60) return m + ' minute' + (m === 1 ? '' : 's');
    const h = Math.floor(m / 60), mm = m % 60;
    return h + ' hour' + (h === 1 ? '' : 's') + (mm ? ' ' + mm + ' minute' + (mm === 1 ? '' : 's') : '');
  };
  const clock = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); } catch (err) { return ''; } };
  const taken = data && data.t === 'push_taken';
  const what = taken ? 'to finish the send' : 'to take your sats back';
  const s = Number(data && data.hold_s), u = Number(data && data.until_ms);
  const haveS = Number.isFinite(s) && s > 0;
  let when = '';
  if (Number.isFinite(u) && u > 0) {
    const rem = u - nowMs;
    if (!(haveS && rem > s * 1000 + 120000)) {
      if (rem <= 0) return 'Open the LiJ app now ' + what + ' — the lock is past its time and your channel could close.';
      if (rem < 60000) return 'Open the LiJ app now ' + what + '.';
      const c = clock(u);
      when = (rem >= 3600000 && c) ? ' by ' + c : ' within ' + dur(rem) + (c ? ' (by ' + c + ')' : '');
    }
  }
  if (!when && haveS) when = (s < 60) ? ' now' : ' within ' + dur(s * 1000);
  return 'Open the LiJ app' + when + ' ' + what + '. Left closed past then, your channel could close.';
}
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
    if (data.t === 'nwc') {   // v855 (S50, NWC): a Nostr app's request waits at the provider — content-free; the wallet fetches it on open
      title = 'NWC request waiting';
      body = foreground ? 'A Nostr app is asking your open wallet to pay.' : 'Open the LiJ app to see it.';
    } else if (data.t === 'tatara') {   // v990 (S58): the Mix — a pool this phone has a seat in is starting
      title = 'Your Mix pool is starting';
      body = 'Open LiJ within 3 minutes and keep it open while the pool sets up.';
    } else if (data.t === 'push_taken' || data.t === 'push_returned') {   // v1065 (adapter 0.113.0): the sender's wake
      title = data.t === 'push_taken' ? 'Your Push Key was taken' : 'Your Push Key came back';
      body = foreground ? (data.t === 'push_taken' ? 'Someone took your Push Key — your open wallet is finishing the send.' : 'Nobody took your Push Key — your open wallet is taking the sats back.') : lijPushKeyWords(data, Date.now());
    } else if (data.t === 'wake') {
      if (foreground) {
        title = 'Payment arriving';
        body = 'A payment is arriving in your open wallet now.';
      } else {
        body = lijWakeWords(data, Date.now());   // v914 (S54): the time actually held, never more
      }
    } else {
      body = 'Open the LiJ app.';
    }
    await self.registration.showNotification(title, {
      body: body,
      tag: data.t === 'tatara' ? 'lij-mix' : 'lij-wake',   // v990: a Mix start is its own notification
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
    const mix = e.notification && e.notification.tag === 'lij-mix';   // v990 (S58): a Mix start opens the wallet on Mix
    for (const c of list) {
      if ('focus' in c) { if (mix) { try { c.postMessage({ lij: 'open-mix' }); } catch (err) {} } return c.focus(); }
    }
    return self.clients.openWindow(mix ? '/wallet/#mix' : '/wallet/');
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
        if (hit) return await unredirected(hit);   // v934
      }
    }
    // v472: /pkg is EXACT-VERSION ONLY — the glue js and the wasm binary are
    // an atomic pair; ignoreSearch resolved each independently and could hand
    // the page js from one engine build and wasm from another (ABI trap at
    // unwrap, mis-read as a bad passphrase — DP field case). Exact or nothing:
    // an absent exact pair fails fast into the page's honest loading guard.
    const isPkg = url.pathname.indexOf('/pkg/') === 0;
    if (isPkg) {
      // v873 (S51, DP): exact-version keyed (?v=) — a hit is the right bytes by construction; serve it and never
      // re-download the engine per open. A miss (a version this cache lacks) takes the network path below.
      const hit = await c.match(req);
      if (hit) return hit;
    }
    // v880 (S51, DP 22:57 — S6, "be ready to reverse it"): THE PAGE SHELL IS CACHE-FIRST. The page was fetched from the
    // network first on every open (a 4 s race, the cache only on timeout), so between the launch screen and the first
    // paint nothing of ours was on screen — iOS shows its own empty view there — and 1.9 MB came down per open. An
    // installed build's page is served from its cache at once; a new build lands through its own worker's install
    // (sw.js is checked at every online open) and shows at the next open, as the Updates row says. No cache yet (a
    // first-ever open) → the network below, as before. Ask-me keeps its pin above. REVERSE: delete this block.
    if (req.mode === 'navigate' || url.pathname === '/wallet/' || url.pathname === '/wallet/index.html') {
      const shell = (await c.match(req, { ignoreSearch: true }))
        || (await c.match('/wallet/index.html', { ignoreSearch: true }))
        || (await c.match('/wallet/', { ignoreSearch: true }));
      if (shell) return await unredirected(shell);   // v934: a cache an older worker filled may still carry the mark
    }
    let fallback = (await c.match(req)) || (isPkg ? null : (await c.match(req, { ignoreSearch: true })));
    if (!fallback && req.mode === 'navigate') {
      fallback = (await c.match('/wallet/index.html', { ignoreSearch: true }))
        || (await c.match('/wallet/', { ignoreSearch: true }));
    }
    const netReq = isPkg ? new Request(req, { cache: 'reload' }) : req;  // v486: /pkg always revalidates at origin — the laundering loop dies here
    const netP = fetch(netReq).then((net) => {
      if (net && net.ok) unredirected(net.clone()).then((x) => c.put(req, x)).catch(() => {});   // v934
      return net;
    });
    if (!fallback) return netP;
    const bound569 = navigator.onLine === false ? 800 : (req.mode === 'navigate' ? 4000 : 3500);  // v569: onLine=false is a HINT, not a verdict (the flag sticks false on old-iOS PWAs after airplane toggles — DP road case) — an 800ms bound keeps offline near-instant while a lying flag self-heals within a second
    const timer = new Promise((res) => setTimeout(() => res(null), bound569));
    const net = await Promise.race([netP.catch(() => null), timer]);
    if (net) return net;
    return await unredirected(fallback);   // v934
  })());
});
