# Update prompt — Dials row spec (DP asked 2026-09-03; not built)

## What it is
A Dials row "Updates" with two chips: **Automatic** (default, today's
behaviour) and **Ask me**. Under Ask me the wallet keeps running the page
and engine it already has until the user taps Update on a card that shows
the new versions and their sha256 hashes.

## What it protects and what it cannot
Protects: no silent replacement of running code; the user sees version +
hash before new code runs and can compare the hash with the one CI prints
in the commit; the wallet's "runs the code it was running" property holds
online as well as offline.
Cannot: stop a hostile origin. The browser replaces sw.js from the origin
unconditionally; a malicious sw.js ignores the setting. The origin is the
root of trust of any web wallet. Say so on the row's det text.

## Mechanics
- Key `lij_update_mode` = 'auto' | 'ask'. Boot-applied; posted to the SW
  (`{type:'lij-update-mode', mode}`) at every load and on change. The SW
  persists it in a small settings cache (`caches.open('lij-settings')`,
  `/__lij_update_mode`) so a freshly installed sw.js can read it in its own
  install event before any page has messaged it.
- sw.js install: precache as today into the new CACHE name; call
  `skipWaiting()` only when mode is auto. Under ask, the new SW stays
  waiting; the old SW keeps serving.
- sw.js fetch under ask: /wallet, /pkg and css become CACHE-FIRST from the
  installed version (revalidate in the background only to detect the next
  build); network-first stays for everything else. This is what keeps the
  running version pinned — network-first would fetch the new page anyway.
  Side effect: opens are instant under ask.
- Detection: the browser's own SW update check (each navigation, at most
  once per 24 h) installs the new SW → `registration.waiting` → the page
  shows the card.
- Hashes: in install, the new SW computes sha256 (`crypto.subtle.digest`)
  of the fetched page, glue js and wasm and stores them beside the mode;
  the page reads them from the waiting SW by message. Versions come from a
  `/wallet/version.json` the cut script writes (page v, engine v, styles v,
  hashes); CI prints the same hashes in the commit comment so the card's
  numbers can be checked against the record.
- Card: "Update available — page v681 · engine v233 · sha256 …" with
  Update now (posts `lij-skip-waiting` → SW `skipWaiting()` →
  `controllerchange` → reload) and Later (once per session).
- Activate: delete old caches only after activation, as today.

## Companions (cheaper, worth more against injection)
`_headers` gains: Strict-Transport-Security (max-age 1 year,
includeSubDomains), X-Frame-Options DENY / CSP frame-ancestors 'none',
Permissions-Policy (camera=(self), everything else off), X-Content-Type-
Options nosniff, Referrer-Policy no-referrer, and a CSP:
default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src
'self'; connect-src https: wss:; frame-ancestors 'none'; object-src 'none';
base-uri 'self'; form-action 'none'. 'unsafe-inline' is forced by the
page's 255 inline onclick attributes and 10 inline script blocks; a strict
script-src needs those moved to files first (a refactor, not a header).

## Size
sw.js ~60 lines; page ~80 lines (row + card); cut script writes
version.json; CI prints hashes. One page build plus one sw.js change.
