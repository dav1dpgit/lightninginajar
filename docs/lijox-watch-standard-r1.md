# LIJOX — the watch duties: towers for both sides (r1, 2026-11-13, S69)

Status: the rulings are DP's of 2026-11-13 ("Agree with all" on docs/design/watchtower/watchtower-r1.md; "Go on
suggestions — a unique Tower Public Key" on watchtower-r2.md; "The watchtowers are providing protection for both
sides, for the wallet users channels and all channels of the LSP owners, public and private"). In operation: §3, on
LiJ-Node 1 and LiJ-Node 2 since 2026-11-13. Reference code for §1: lijox-adapter `tower.js` (the holder and its 27
checks; its routes and block watch are not yet in a release). §2 is not built. This text is r1: it will be revised
when §1 and §2 run, and is not edited over.

Why. A Lightning channel is protected by a rule: whoever publishes an OLD STATE of the channel can lose their whole
side of it — if the other side answers inside the delay. LiJ's delay is one day (DP's ruling: it stays). A wallet
is closed most of the time; a provider's node can be down. A tower answers for the one who is away. LIJOX makes that
a duty of the providers toward each other and toward each other's wallets, because the party to be watched is never
the right watcher: a wallet's channel is with its own provider.

Words. "Old state": a channel balance both sides have replaced. "Penalty transaction": the transaction that takes
the publisher's side of an old state. "Hint": 16 bytes that let a tower notice an old state without knowing it.

## 1. A provider keeps penalty data for other providers' wallets (W1 — MUST at full conformance)

A provider that offers the tower says so on its record: `tower: { offered, quota_bytes, keep_days_silent, form }`.
`form` is `teos-v1`. Defaults in the reference code: 5 MB per wallet, 400 days, and the whole tower off until the
operator turns it on.

**The bytes** (`teos-v1`, the form of The Eye of Satoshi, so that a wallet's data suits more than one kind of
tower). For each replaced state the wallet makes one or more ITEMS:
- `hint` — the first 16 bytes of the old state's transaction id, in the id's own byte order (the reverse of how an
  id is written);
- `blob` — the penalty transaction in Bitcoin's serialization, encrypted with ChaCha20-Poly1305 under the key
  SHA-256(the 32 id bytes), an all-zero nonce (each key is used once), the 16-byte tag at the end.
A tower can read nothing from an item until that old state is published: the key needs the whole id.

**The sign-in.** A wallet signs in to a tower with a key it makes for THAT TOWER ALONE from its 12 words (BIP-340,
32 bytes) — never its node key. The tower knows "a wallet", not which one. Every request carries `key`, `ts` (within
10 minutes of the tower's clock) and `signature`: BIP-340 over SHA-256 of the text
`lijox-tower-v1|<action>|<key>|<group>|<ts>` and, for a put, `|<items fingerprint>`; the fingerprint is SHA-256 over
`hint ‖ SHA-256(blob)` for each item in the order sent. `group` is empty for `status`.

**The routes.**
- `POST /v1/tower/put` `{ key, group, items: [{ hint, blob }], ts, signature }` — `group` is 16 random bytes the
  wallet picks per channel (never the channel's id). Up to 64 items a request, 2,048 bytes an item. Items already
  held are kept once. Over the wallet's quota: refused whole.
- `POST /v1/tower/drop` `{ key, group, ts, signature }` — the channel is closed; its items are deleted.
- `POST /v1/tower/status` `{ key, ts, signature }` → the items and bytes held, the quota, the last upload's time.

**The watch.** On every new block the provider compares the hint of each transaction id in the block with what it
holds. On a match it decrypts each item with the full id and publishes the result ONLY IF it is a transaction whose
every input spends that transaction. A provider MUST NOT publish anything else it is handed, and MUST keep the
items until the penalty has six blocks. A wallet silent for longer than `keep_days_silent` may be cleared.

**What a tower learns.** A wallet's tower key, its internet address, and how often its channel changes state.
Nothing of the channel, the amounts or the other side, unless an old state is published.

## 2. A wallet uploads after every change (W2 — SHOULD; MUST once two providers offer §1)

- Each time its provider replaces a state, the wallet builds the penalty transaction for the state just replaced,
  paying to an address of its own that a plain wallet restored from the 12 words would find, signs it at TWO fee
  rates (DP's ruling: 2× and 5× the next-block rate at that moment — it cannot be raised afterwards, and it must
  confirm inside the one-day delay), and uploads both as items under one hint.
- To the tower of at least one provider that is NOT the provider of that channel. Never to its own provider alone.
  A wallet with one provider uploads to another listed provider's tower, with or without a channel there.
- The upload never holds up a payment. Until it has reached a tower, that state is unguarded, and the wallet's
  Safety screen says which provider watches it, or that none does.
- On a channel's close the wallet sends `drop`.
- Not covered, said plainly: payments that were in flight in the old state. The penalty takes the provider's main
  balance of that state.

## 3. Providers guard each other (W3 — MUST at joining)

Every channel a provider has — public and private — is backed up to another provider's tower with the tower and
tower client its node software already carries (LND: `watchtower.active`, `wtclient.active`, `lncli wtclient add`).
Read in LND 0.21.8: the tower client registers every channel; anchor channels use the anchor kind of data, all
others the plain kind; main outputs only. Each provider runs a tower and is the client of at least one other
provider's tower. The steps, as run: the adapter repository's `docs/tower-between-providers.md`.

## 4. What is not in r1

- The public proof that a provider took a JIT payment and did not fund the channel (ThomasV's fraud proofs;
  docs/design/lijox-standard/considerations.md 1b). DP: "we may or may not proceed". The holder of §1 is written so
  a second kind of item can be added without changing the first.
- Towers that are paid.
- A live breach drill: it needs a node willing to publish an old state; the proof today is the engine's own test
  harness and the adapter's checks on those bytes.
