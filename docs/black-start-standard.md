# LIJOX Black Start — the standard (BS1)

DP 2026-09-22 21:41: in user-facing copy the feature is "Black start" (the LiJ sentence case) and the kit is the
"Black start kit" everywhere — the wallet (the Offline room's card included), /recover, the website. "escape kit"
remains the engine's and this document's name for the export (escape_export, v211).

DP rulings 2026-09-22 (S48): remote storage first — the escape kit, sealed under a key only the
12 words can make, held by the user's own LSP plus 20 others from the LIJOX directory and by public
Nostr relays; recovered with the words alone through a single-file page that needs no LiJ install.
Script expiry (the funding-script leaf) comes with splicing; LSPS7 leases are pricing, not exit.
This document is the cut copy: engine v275, adapter 0.79.0, the page and /recover are built from it.

## 0. What is being solved

The stranded corner: device gone, cloud copy gone, LSP dark, only the 12 words. A channel is a
2-of-2; the words re-derive the user's keys but not the channel's state — above all not the LSP's
signature on the user's latest commitment, which no key can produce. So the exit must be a
transaction someone kept: THE CLOSE (the fully signed latest holder commitment) and THE COLLECT
(the pre-signed sweep of its delayed output to the seed's m/84 tree), which the engine already
exports offline as the escape kit (v211). BS1 is: seal that kit, fan it out, get it back with the
words, broadcast it — and never against a living LSP.

## 1. Keys from the words

- `seed` = BIP39 seed of the 12 words, empty passphrase (as the wallet has always done).
- `root` = the BIP32 master private key = left 32 bytes of HMAC-SHA512(key = "Bitcoin seed", seed).
- **Kit key** `K` = HKDF-SHA256(ikm = root, salt = "lijox-black-start", info = "escape-kit-v1", 32 bytes).
  Used for AES-256-GCM only. Distinct from the cloud copy's key (m/525h family): a kit holder can
  never open a cloud copy, and vice versa.
- **Identity** = the NIP-06 key: BIP32 path m/44'/1237'/0'/0/0 on secp256k1. `pubkey` = the 33-byte
  compressed public key; `npub` = its x coordinate, 32 bytes hex (the Nostr public key). The npub
  names the user at every holder and every relay. Nothing about it is secret; the kit is ciphertext.

Both are recomputable by any LIJOX wallet and by the /recover page from the words alone.

## 2. The kit

Plaintext = the engine's escape export (v211) plus three fields:

```
{ "v": 1, "made_at": <unix ms>, "seq": <unix ms of the export>,
  "lsp": { "pubkey": <the user's LSP node pubkey hex>, "endpoint": <its adapter URL> },
  "sweep_destination_index": n, "sweep_destination_address": "bc1q…",
  "feerate_normal_sat_vb": 10, "feerate_high_sat_vb": 40,
  "channels": [ { "channel_id", "open", "claimable_sats", "funding_txo", "counterparty",
                  "commitment_txid", "commitment_hex", "htlc_tx_hexes": [], "to_self_delay",
                  "our_to_local_sats", "has_to_local",
                  "sweep_txid_normal", "sweep_hex_normal", "sweep_txid_high", "sweep_hex_high" } ] }
```

Envelope (what holders and relays store, opaque to them):

```
{ "v": 1, "alg": "A256GCM", "kdf": "hkdf-sha256:lijox-black-start:escape-kit-v1",
  "npub": <hex>, "seq": <same as inside>, "nonce": <hex, 12 bytes>, "ct": <hex> }
```

AES-256-GCM, fresh random nonce per seal, AAD = the UTF-8 bytes of `"lijox-kit-v1:" + npub`
(a kit cannot be re-labelled to another npub). `seq` is the freshness order: a holder keeps the
highest it has seen; a relay keeps the newest event. Size cap 64 KB (a kit is a few KB per channel).

A wallet with no channels seals and pushes an EMPTY kit (`channels: []`) so a later /recover can
tell "nothing to close" from "nothing found".

### 2.1 The silent-payment leg (engine v291, 2026-09-28; DP's ruling of the same day)

Coins received at the wallet's silent-payment address (BIP-352, chain 352 on the coin ledger) are
not reachable from the 12 words in an ordinary BIP-84 wallet. So the kit carries, for every
UNSPENT silent-payment coin, one pre-signed transaction that moves that coin ALONE (never
combined) to a fresh m/84 receive address of the wallet's own — index `sweep_destination_index
+ 1 + i` for the i-th coin, so every coin lands on its own address — at the same two rates:

```
"silent_payments": [ { "txid", "vout", "value_sats", "height",
                       "destination": "bc1q…", "destination_index": n,
                       "sweep_txid_normal", "sweep_hex_normal", "sweep_fee_normal",
                       "sweep_txid_high",   "sweep_hex_high",   "sweep_fee_high" } ],
"silent_payments_note": ""      // set when the coin ledger could not be read; the leg is then empty
```

A coin too small to pay a rate (value ≤ fee + dust) has `null` at that rate. The sweeps are
Schnorr-signed on the taproot key path by the wallet's one signer, signal RBF (the high variant
replaces the normal one), and are valid the moment they are broadcast — no delay, unlike a
channel's collect. ≈ 350 bytes per coin; the 64 KB cap holds ~120 coins beside a few channels
(the holder's cap rises in a later adapter release).

The kit's fingerprint (what makes a push due, §6) includes the set of unspent silent-payment
outpoints: a coin arriving or leaving is a fresh push. The Black start switch off still means only
"not sent to holders" — the kit always carries the leg. On /recover the coins are listed under the
channels with Sweep this coin (normal / high) and Sweep all, which broadcasts them one at a time,
20 seconds apart, each watched to confirmation.

### 2.2 Across copies (BS1.1 — engine v313, page v966, adapter 0.94.0; DP 2026-10-07 17:55)

DP: "it's not just fewer channels, it is where anything is different." A push is never blind. Before every push the
wallet reads the kits it can reach (every holder and relay at the first push of a page session; its own provider and
two others after that) and the engine merges them with this copy's kit, entry by entry
(docs/design/black-start/kit-merge-r1.md has the full table):

- every channel entry carries `commitment_number` (BOLT 3, plain; an older entry without it is decoded with the
  channel's factor by a copy that knows the channel);
- a channel only a held kit has is **carried** unchanged (`carried`, `carried_since`, `carried_from_seq`) while its
  funding output is unspent, or spent by that entry's own CLOSE with the delayed output unspent; unknown keeps it;
- a channel this copy holds at an older commitment number keeps the held entry (`kept_newer`,
  `this_copy_commitment_number`): a revoked CLOSE never enters the kit; the wallet tells its person;
- silent-payment coins only a held kit has are carried while unspent;
- `seq` = max(the wallet's clock, the highest held seq + 1);
- no holder answering at all = no push; "not found" everywhere = push;
- over the cap, carried silent-payment coins go first (oldest first); channels never.

## 3. Holders — the adapter API

Every LIJOX adapter is a holder. Manifest / getinfo capability: `"kit_holder": { "v": 1, "max_bytes": 65536 }`.

**PUT** `POST /v1/kit` — body:
```
{ "pubkey": <33-byte hex>, "seq": <int>, "kit": <envelope object>, "sig": <64-byte hex> }
```
`sig` = ECDSA (secp256k1, compact r‖s, low-S) over SHA-256 of
`"lijox-kit-put-v1" ‖ pubkey_bytes ‖ seq as 8-byte big-endian ‖ SHA-256(canonical envelope)`,
where the canonical envelope is the seven fields in the order written above, compact, no
whitespace — `{"v":1,"alg":"A256GCM","kdf":"…","npub":"…","seq":N,"nonce":"…","ct":"…"}`. The
engine emits exactly that string; a holder REBUILDS it from the parsed fields before hashing
(never trusts the transport's key order or whitespace).
The holder checks: pubkey parses; `envelope.npub` equals pubkey's x; seq equals `envelope.seq`;
signature verifies; seq is strictly greater than the stored one (else 409 `STALE`); size ≤ cap.
Stores `DATA_DIR/kits/<npub>.json` = `{ "seq", "at", "pubkey", "kit" }`. Rate limit per IP; total
store cap with oldest-untouched eviction, never evicting a record touched in the last 90 days.
ECDSA is used here — not Schnorr — so a holder verifies with platform crypto (Node's own
`crypto.verify`) and carries no third-party signature code; the relay event (§5) is Schnorr
because Nostr requires it. One key signs both.

**GET** `GET /v1/kit?npub=<hex>` → `{ "ok": true, "seq", "at", "pubkey", "kit" }` or 404. Open read:
the record is ciphertext; presence reveals only that an npub has used LIJOX.

**Writers (adapter 0.94.0, BS1.1).** A PUT may carry `w` — 16 hex, the writing install, random, outside the signed
envelope (absent = the legacy writer). Beside the newest kit the holder keeps `others`: the newest kit of each of the
last two OTHER writers — including a validly signed kit refused as `STALE` when it comes from another writer. GET adds
`"w"` and `"others": [{ "seq", "at", "w", "kit" }]`; its earlier fields are unchanged. One device pushing again and
again can never erase another device's last kit. The holder still reads nothing; it learns that more than one device
writes for the npub.

## 4. Which holders — the 20

Let `D` = the LIJOX directory (`/lsps` from the registry worker), each entry with `pubkey` and
`endpoint`, sorted by pubkey. The user's own LSP is always a holder. Then, for i = 0, 1, 2, …:
`j = SHA-256(npub_bytes ‖ i as 4-byte big-endian) mod |D|`; take D[j] unless it is the own LSP or
already chosen; stop at 20 others or when D is exhausted. Deterministic from the words and the
directory, so /recover recomputes it — and in any case /recover asks every directory entry; the
selection bounds the WRITES, not the search. DP: "my LSP plus 20 others is the easily-remembered
number."

## 5. Relays — the second rung

Nostr, NIP-78 application data: kind **30078**, tags `[["d", "lijox-kit-v1"]]`, `content` = the
envelope JSON string, signed BIP-340 with the NIP-06 key. Parameterized-replaceable: a relay keeps
the newest per (npub, d). Default relay list, editable in Privacy, 6–10 long-lived public relays;
relays are best-effort (they may prune) — holders first, relays second.

## 6. Cadence

Pushed by the wallet on the existing backup tick (the same moment the cloud copy is refreshed —
a kit must be as fresh as the blob), debounced 10 s so a burst of payments is one push; and once at
unlock when the last push is older than 24 h or the holder set changed. Failures are retried on
the next tick; the Dials group shows the last push, the holder count reached and the relay count.
From v291 the fingerprint that decides "changed" covers the channels' latest commitments AND the
unspent silent-payment coins (§2.1).

## 7. /recover — one file, no install

`lightninginajar.xyz/recover` (the same file in the public repo; also the wallet's Offline room):
1. Enter the 12 words → seed → root → K and the NIP-06 key, in the browser (WebCrypto + a small
   inlined secp256k1). Nothing leaves the page but signed requests and, at the end, transactions.
2. Fetch the directory; ask every entry `GET /v1/kit?npub=` (with its `others`, BS1.1); query the relays for kind
   30078, author npub, `#d lijox-kit-v1`. Every kit that decrypts is merged (BS1.1, page v966): per channel the higher
   `commitment_number` (an entry without one keeps the newer kit's), coins united; a channel from another copy's kit is
   marked.
3. **The LSP first.** Read `lsp` from the kit — and, from v966, each channel's own `counterparty` in the directory. Try
   each adapter. If one answers, stop:
   tell the user their LSP is alive — restore the wallet normally (the cloud copy) or reconnect and
   let the LSP close; broadcasting a kit against a living LSP invites the penalty. The user may
   override only after that warning, in writing.
4. Otherwise show each channel (a channel whose funding output another transaction already spent reads "Already
   closed" and offers no close — v966): the close, the sweep, the delay, the m/84 destination; broadcast
   THE CLOSE through the public Esplora quorum; after `to_self_delay` confirmations broadcast THE
   COLLECT (normal or high feerate, the user's pick); funds land at the shown address, visible to
   any BIP84 wallet on the words (gap-limit caveat as documented).

The words on that page (DP 2026-09-22 21:56, "erase after use and verified copy, no split mode"):
- The words are used once, to make K and the identity, and erased — the textarea is cleared, the seed
  and the master key are zeroed; the page holds only K as a non-extractable WebCrypto key (decrypt
  only, cannot be read out) and the public name. Nothing the page keeps can spend. "Forget" drops
  the two. A second search reuses them without the words.
- The page is one file and runs from disk: the "Keep your own copy" card offers it for download
  (`lij-black-start.html`), and the user checks its SHA-256 against the `recover/index.html` hash in
  `docs/releases.md` (CI writes it into every release row from page v817, with the page's build
  stamp). A saved, checked copy takes the web server out of the trust set on the day it is needed.
- Not done, by ruling: the offline ceremony (it cannot be enforced by the page and does not defend
  against a hostile page) and a split mode (K from another device).

## 8. Honest limits (copy for the page and the card)

- A kit is only as fresh as its last push. A close from an older kit pays the balances of that
  moment; a dead LSP cannot punish it, a living one can — hence rule 7.3.
- The commitment feerate is what it was; in a fee spike the close confirms late, not never.
- The CSV delay is physics.
- Relays may prune; holders may vanish; the words plus one surviving copy anywhere is enough.

## 9. Not in BS1

The full state blob (brings channels back OPEN) to the user's LSP + 1 — same key family as the
cloud copy, larger cap — is a second standard (BS2) after the kit is in the field. Script expiry
rides splicing.
