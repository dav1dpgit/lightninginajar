# LIJOX — the watch duties: towers for both sides (r2, 2026-11-15, S70)

Status. This round is the whole text and is the one to read; r1 (2026-11-13) is kept as written. Since r1 the
provider's tower, the wallet's side, the record and the drill have all been built and run, a wallet's key is now let
in by a VOUCHER (§2, new), and the duties have their checks (§5, new). The rulings are DP's of 2026-11-13, 11-14 and
11-15. §6 says what has run; §7 says what this round leaves out. Read and agreed by DP on 2026-11-15.

Why. A Lightning channel is protected by a rule: whoever publishes an OLD STATE of the channel can lose their whole
side of it — if the other side answers inside the delay. LiJ's delay is one day (DP's ruling: it stays). A wallet
is closed most of the time; a provider's node can be down. A tower answers for the one who is away. LIJOX makes that
a duty of the providers toward each other and toward each other's wallets, because the party to be watched is never
the right watcher: a wallet's channel is with its own provider. In DP's words: "The watchtowers are providing
protection for both sides, for the wallet users channels and all channels of the LSP owners, public and private."

Words. "Old state": a channel balance both sides have replaced. "Penalty transaction": the transaction that takes
the publisher's side of an old state. "Hint": 16 bytes that let a tower notice an old state without knowing it.
"Tower key": the key a wallet signs in to one tower with. "Voucher": a provider's signature that lets one of its
wallets into the towers.

## 1. A provider keeps penalty data and watches (W1 — MUST at full conformance)

A provider that keeps a tower says so on its registry record: `tower: { offered, quota_bytes, keep_days_silent,
form }`, signed with the rest of the record. `offered` is true only while the box can read blocks; the record is
sent again when that changes. `form` is `teos-v1`.

**The bytes** (`teos-v1`, the form of The Eye of Satoshi, so that a wallet's data suits more than one kind of
tower). For each replaced state the wallet makes one or more ITEMS:
- `hint` — the first 16 bytes of the old state's transaction id, in the id's own byte order (the reverse of how an
  id is written);
- `blob` — the penalty transaction in Bitcoin's serialization, encrypted with ChaCha20-Poly1305 under the key
  SHA-256(the 32 id bytes), an all-zero nonce (each key is used once), the 16-byte tag at the end.
A tower can read nothing from an item until that old state is published: the key needs the whole id.

**The tower key.** A wallet signs in to a tower with a key it makes for THAT TOWER from its 12 words (BIP-340, 32
bytes) — never its node key. A tower is named by its provider's node key. Every request carries `key`, `ts` (within
10 minutes of the tower's clock) and `signature`: BIP-340 over SHA-256 of the text
`lijox-tower-v1|<action>|<key>|<group>|<ts>` and, for a put, `|<items fingerprint>`; the fingerprint is SHA-256 over
`hint ‖ SHA-256(blob)` for each item in the order sent. `group` is empty for `status`.

**The routes.**
- `POST /v1/tower/put` `{ key, group, items: [{ hint, blob }], ts, signature }` — `group` is 16 random bytes the
  wallet picks per channel (never the channel's id). Up to 64 items a request, 2,048 bytes an item. Items already
  held are kept once. Over the wallet's quota: refused whole (413). Over the tower's room in all: refused (507).
- `POST /v1/tower/drop` `{ key, group, ts, signature }` — the channel is closed; its items are deleted.
- `POST /v1/tower/status` `{ key, ts, signature }` → the items and bytes held, the quota, the last upload's time,
  whether the box is watching, and how this key stands (§2).
`key`, `group`, `hint` and `signature` are lowercase hex; `blob` is base64; `ts` is the time in seconds.
A put or a status may carry a `voucher` (§2). A tower that is not watching takes nothing (503).

**The watch.** On every new block the provider compares the hint of each transaction id in the block with what it
holds. On a match it decrypts each item with the full id and publishes the result ONLY IF it is a transaction whose
every input spends that transaction. A provider MUST NOT publish anything else it is handed, and MUST keep the
items until the penalty has six blocks. A wallet silent for longer than `keep_days_silent` may be cleared. The
reference code publishes the penalty that pays the higher fee first and again on every new block for 144 blocks,
believes a block only when its header hashes to the hash asked for, reads a height again when its hash changes, and
after a stop reads the blocks it missed.

**The room.** Defaults in the reference code, all the operator's settings: 5 MB a wallet key, 400 silent days,
20,000 keys and 20 GB in all, 1,200 requests an hour from one internet address and 600 for one key. The whole tower
is off until the operator turns it on.

**What a tower learns.** A wallet's tower key, its internet address, how often its channel changes state, and which
provider vouched for it (§2). Nothing of the channel, the amounts or the other side, unless an old state is
published. Both towers of a channel hold the same items, so two towers can tell that they serve the same wallet.
A tower SHOULD keep its lists to itself: a provider knows its own channels' old states and could work out from a
tower's hints which of them are guarded there.

## 2. Who may use a tower: the voucher

Without this a tower takes any key, and somebody with no wallet at all can take every key slot. The one thing such
a person cannot make for free is a funded channel at a real provider. So the wallet's OWN provider vouches for it,
once, and that is what a tower checks.

**The voucher key.** The wallet makes ONE more key from its 12 words (BIP-340, 32 bytes): the voucher key. It is
not the node key and not a tower key.

**Given once (a provider that keeps a tower MUST do this).** When a provider has earned its first fee from a wallet
— the funding of a just-in-time channel, or a first payment that paid the provider — the wallet asks it for its
voucher: `POST /v1/tower/voucher` `{ node_pubkey, nonce, signature, voucher_key }`, the ask proven by the wallet's
node key over the provider's one-use challenge (action `tower-voucher`, record `voucher:<voucher key>`). The
provider signs the text `lijox-voucher-v1|tower|<voucher key>` with its NODE key (its node software's message
signature: LND `signmessage`) and answers `{ ok, issuer, voucher_key, issuer_sig }`. ONE voucher a wallet, for the
wallet's life: the same key asked again gets the same signature; another key for the same wallet is refused (409).
A wallet that has paid no fee yet is refused with the reason (403 `not_yet`). EVERY wallet asks, whether or not it
uses a tower — so the ask tells the provider nothing about which of its wallets are watched.

**Shown at a tower.** With a put or a status the wallet sends `voucher: { key, issuer, issuer_sig, use_sig }`:
the voucher key, the provider's node key and its signature, and a USE LINE signed by the voucher key (BIP-340 over
SHA-256 of the text) — `lijox-voucher-use-v1|<this tower's node key>|<the wallet's tower key here>`.

**The tower checks**, once for a key:
1. the use line is signed by the voucher key and names THIS tower and the very key that signs the request;
2. this voucher key has no other tower key here;
3. the provider is on the registry list and offers a tower itself (the same duty both ways);
4. the signature on the voucher is that provider's node key's (the tower's own node software: LND `verifymessage`);
5. the provider is inside what this tower allows one provider (below).
Then the key is ADMITTED. It stays admitted for as long as it keeps coming (the silent-days rule ends it). The
provider is never asked again and can take nothing back: the provider is the party the tower watches.

**A copied voucher is useless.** At another tower the use line names the wrong tower; a new use line needs the
secret half of the voucher key. So nothing a tower holds has to be secret from a spammer.

**Per vouching provider.** The registry is open, so anybody can list a provider and vouch for itself. A tower
therefore counts per provider — defaults: 2,000 admitted keys, 50 new ones a day — and takes another provider's
vouchers only if its OWN node sees that provider in the public Lightning graph with at least 2,000,000 sats of
channels (LND `GetNodeInfo`), or its operator has named that provider. A tower's own provider's vouchers need
neither.

**The answers.** A put and a status say `admitted`: `voucher`, or `open` (taken without one). A voucher that was
not taken is named in `voucher_refused`. A key that is not let in gets 403 with one of: `voucher_needed`,
`bad_voucher`, `voucher_used`, `use_signature`, `issuer_unknown`, `issuer_no_tower`, `issuer_full`, `issuer_rate`,
`issuer_signature`, `issuer_unproven`, `not_ready`.

**Open, or by voucher.** A tower says on its capability line (`/health`: `tower.admit`) whether it still takes a
key without a voucher (`open`) or requires one (`voucher`). Keys a tower held before it required one stay admitted.

**The keys, for another wallet with the same 12 words.** LiJ makes both keys by HKDF-SHA256 over the BIP32 master
private key: the tower key with the salt `LiJ-Tower-key-v1` and, as info, the tower's node key (33 bytes) followed
by a 4-byte counter; the voucher key with the salt `LiJ-Voucher-key-v1` and the counter alone. The counter starts
at 0 and moves on only if an output is not a valid secp256k1 secret. A wallet that makes the same keys is the same
wallet to every tower and to its provider's voucher record.

## 3. A wallet uploads after every change (W2)

A conforming wallet MUST be able to do this. Whether it does is the user's switch: a tower learns a key, the
phone's internet address and how often the channel changes, and that is the user's to turn on. In LiJ the switch is
off by default (DP's ruling).

- Each time its provider replaces a state, the wallet builds the penalty transaction for the state just replaced,
  paying to an address of its own that a plain wallet restored from the 12 words would find, signs it at TWO fee
  rates (2× and 5× the next-block rate at that moment — it cannot be raised afterwards, and it must confirm inside
  the one-day delay), and uploads both as items under one hint.
- To TWO towers a channel, picked at random among the listed providers that offer one, once, and then kept — never
  the tower of that channel's own provider. A wallet with one provider uploads to other listed providers' towers,
  with or without a channel there. A tower that has been off, or unlisted, for a day is replaced.
- A tower that is full for the wallet (413), or does not let it in (403), gives its place to another tower when
  there is one. The full tower keeps the older balances and is told when the channel closes.
- The upload never holds up a payment. Until it has reached a tower, that state is unguarded. The wallet says, per
  channel, which providers watch it now — and when none does.
- On a channel's close the wallet sends `drop` to every tower that holds its items, also when the switch has been
  turned off since.
- Not covered, said plainly: payments that were in flight in the old state (the penalty takes the provider's main
  balance of that state); balances replaced before the switch was turned on or while it was off; and, at a tower
  that took another tower's place, the balances replaced before it did — the wallet keeps no copy of what it has
  uploaded, so a new tower holds what is replaced from then on (§7).

## 4. Providers guard each other (W3 — MUST at joining)

Every channel a provider has — public and private — is backed up to another provider's tower with the tower and
tower client its node software already carries (LND: `watchtower.active`, `wtclient.active`, `lncli wtclient add`).
Read in LND 0.21.8: the tower client registers every channel; anchor channels use the anchor kind of data, all
others the plain kind; main outputs only. Each provider runs a tower and is the client of at least one other
provider's tower. The steps, as run: the adapter repository's `docs/tower-between-providers.md`.

Not covered: states a channel replaced before the provider's tower client was turned on. LND backs up a state at
the moment it is replaced and does not go back over older ones.

## 5. Joining, and how the duties are checked

**At joining.**
- §4 is set up before a provider serves wallets.
- §1 and §2: the provider turns its tower on, or joins with it not yet on and says by when it will be (DP's ruling
  2026-11-13: the first two providers keep one from the start; a new provider may join so).
- **One drill.** An existing provider proves that the joining provider's tower publishes. With its own coins it
  signs a small transaction (T1) to a one-time script and does not publish it; it signs the transaction that takes
  T1's coins back (T2), encrypts T2 under T1's id and puts it at the joining tower exactly as a wallet would, under
  a one-time key it vouches for itself; then it publishes T1. PASS: T2 is in a block at most six above T1's and was
  not published by the drilling box. Otherwise the drilling box publishes T2 itself and the drill has FAILED. A
  drill costs the drilling provider two on-chain fees and is started by its operator's own command, never by a
  screen that can be reached over a network. Once, at joining (DP's ruling: a monthly drill is "overkill, as wallets
  are already doing this and should alert when it fails").

**All the time.**
- The record says `offered` only while the box is watching, and is sent again when that changes and every six hours.
- A box that cannot read blocks takes nothing and says so (`/health`: `tower.offered: false`).
- Every wallet that uses a tower asks it — whether it still offers, and how the wallet's key stands — and shows a
  tower that is off as off, not as watching. After a day it puts another tower in its place.
- A provider whose record offers no tower loses the way in for its own wallets: other towers do not take its
  vouchers (`issuer_no_tower`). Keys already admitted are not put out.

## 6. Reference code, and what has run

Reference code: the adapter's `tower.js` (the holder), `tower-watch.js` (the watch), `tower-admit.js` (the voucher's
two sides), `tower-drill.js` (the drill); the wallet engine's `tower.rs` and `key.rs`; the wallet page's tower
module.

On LiJ-Node 1 and LiJ-Node 2:
- §4 set on both nodes 2026-11-13. On 2026-11-15 LiJ-Node 1's backups were read as acknowledged by LiJ-Node 2's
  tower: 434 states, none waiting. LiJ-Node 2 has put 20,960 states into sessions at LiJ-Node 1's tower; that
  tower's acknowledgement of them is still to be recorded here.
- §1 since 2026-11-13; the tower on the registry record since 2026-11-14.
- §3: a wallet's first items kept by another provider's tower on 2026-11-14; two towers a channel since the same day.
- The drill: the first real ones on 2026-11-14. LiJ-Node 1 → LiJ-Node 2 PASSED — T1 in block 975,762, the answer in
  block 975,763, published by the tower by itself.
- §2: the first wallet key admitted by a voucher at another provider's tower on 2026-11-15. Both towers require a
  voucher since the same day (added 2026-11-15, after both boxes' journals were read).
The bytes of §1 are checked against The Eye of Satoshi's own test value on both sides.

## 7. What r2 leaves out

- A tower that stops: the notice it gives, and how the tower that takes its place is given a channel's older
  states. Today a wallet replaces a tower that has been off or unlisted for a day, and the new tower holds the
  states replaced from then on.
- A standing check of one provider's tower BY the other providers, and what a failed drill — or a tower found not
  publishing — does to a provider's record. Today a failed drill is seen by the drilling provider only.
- A field on the record for the date by which a joining provider's tower will be on.
- A paid way in, and paid room above the free quota: for a wallet whose provider gives no voucher, and for a
  wallet that fills its quota at every tower it can reach.
- The public proof that a provider took a just-in-time payment and did not fund the channel (ThomasV's fraud
  proofs). The holder of §1 is written so a second kind of item can be added without changing the first.
- Payments in flight in an old state.
