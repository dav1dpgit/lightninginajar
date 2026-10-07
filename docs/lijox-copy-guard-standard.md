# LIJOX — one wallet, one open copy: the provider's part (v1, 2026-10-07, S57)

Status: adopted by DP 2026-10-07 ("Go" on Proposals 1, 3 and 4; the 60-s window and "a line in the LIJOX standard",
14:15 and 15:10). Reference code: lijox-adapter 0.92.1 (my-channels) and 0.93.0 (copies.js); LiJ page v956/v960.
Why: on 2026-10-06 a copy of a wallet with no record of a channel connected to its provider; its engine answered the
provider's re-establish for that unknown channel with LDK's "bogus" re-establish, and the provider's LND force-closed
the channel. The provider is the one party that always
knows which channels a wallet has, and the one place two open copies of one wallet meet.

## 1. My channels (every LIJOX provider MUST answer it)

`GET /lsps/registry/challenge` → `{ nonce }` (single use, as recover-close).

`POST /lsps/registry/my-channels` with `{ node_pubkey, nonce, signature, session? }`, where `signature` is an
LND-style signmessage (zbase32) by the wallet's NODE key over `"lij-my-channels-v1:" + nonce`. The provider checks
the signature (the recovered key must equal `node_pubkey`), then uses up the nonce, then answers ONLY for that key:

```
200 { "ok": true,
      "channels":     [{ "chan_point", "capacity_sats", "wallet_side_sats", "active", "pending_htlcs", "commitment_type" }],
      "pending_open": [{ "chan_point", "capacity_sats", "commitment_type" }],
      "other_copy_seen_s": n | null }            // only when a session was sent (§2)
```

Read-only: the route closes and changes nothing. `chan_point` is `txid:vout` in display order. `commitment_type` is the
provider's name for the channel type (`STATIC_REMOTE_KEY` = the wallet's share pays its plain m/84 address on a
close). Errors: 400 (malformed, used nonce), 401 `bad_signature`, 503 `verify_unavailable` / `lnd_unavailable`.

**What a wallet does with it.** Before its first connection to the provider, a wallet compares the list with the
channel records it holds (live and archived). A channel it has no record of means another copy of the wallet opened it
(or the wallet was restored from its words): the wallet does not connect until its person chooses — stay offline, load
a backup, close the channels through recover-close, or connect anyway (the provider will close them). No answer within
about 5 s, or a provider without the route: the wallet connects as always. The check never stops a wallet from
starting.

## 2. One open copy at a time (every LIJOX provider MUST keep it)

- A wallet copy makes a random 128-bit session number when it opens (kept for its browser tab — a reload is the same
  copy) and sends it as `session` in its signed my-channels request. The provider registers a session ONLY there,
  after the signature and the nonce are checked — nobody without the wallet's key can make a copy appear.
- The copy's heartbeat (`GET /health?client=<node pubkey>&session=<s>&known=<n>&bn=<b>`, every 15 s while it is open)
  marks it alive. `known` = how many of the provider's channels this copy has a record of; `bn` = its backup number.
  Unregistered sessions are ignored.
- **The window is 60 s.** Another registered session of the same wallet is OPEN AT THE SAME TIME when its last
  heartbeat came within the last 60 s AND after this session registered (a copy that was closed and reopened as a new
  session never overlaps itself). The heartbeat answer then carries
  `copies: { me: { known, bn }, others: [{ known, bn, seen_s }] }`.
- my-channels answers `other_copy_seen_s`: seconds since any other session of this wallet last showed life, or null.
- Sessions are held in memory and forgotten 10 minutes after their last sign of life. Nothing about sessions is
  written to disk, logged with the session number, or shared with anyone.

**What a wallet does with it.** When another copy is named, the wallet pauses: it stops reconnecting to the provider
and stops cloud uploads, and says: "This wallet appears to be open on another device. Close the least-current one —
You risk force closures of channels by having the same seed on multiple devices with different channel information."
with which copy is less current (fewer of the provider's channels known, else the lower backup number; "They look the
same — close either"). It carries on by itself once the provider stops naming the other copy. At boot, when
`other_copy_seen_s` is small, the wallet waits — at most until 20 s after that copy's last sign of life — before its
first connection, so it never knocks a live copy off the provider.

## 3. Versioning

This text is v1. A provider declares it with the standard's version and capabilities in its signed registration when
the baseline/versioning work lands (S56 plan); until then a wallet finds out by asking (a 404 is "not offered").
