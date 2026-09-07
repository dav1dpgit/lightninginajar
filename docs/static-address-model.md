# Static addresses (LNURLp) — the model after S43

Written 2026-09-02 after the 30-day-cliff / registry-first incident. This is
the contract between the wallet (engine v229+, page v666+) and any LIJOX
adapter (0.67.1+). Read it before touching lnurlp_* in the engine, the
LNURLp block in the page, or the LNURLP section of the adapter.

## The four rules

1. **Preimages come from the seed.** `RootKey::lnurlp_preimage(index)` =
   HKDF-SHA256(master secret, salt "LiJ-LNURLp-preimage-v1", info = index).
   The local pool (`lij_lnurlp_preimages`) is a cache only. A claim that
   misses the cache searches indices 0..max(next_index+1024, 8192) before
   failing the HTLC back. A wallet restored from its 12 words can claim every
   payment ever sent to its address. Never store a random preimage again.

2. **A hash carries its own expiry, set by the wallet.** The engine registers
   each hash for `LNURLP_HASH_EXPIRY_SECS` (30 years) and hands the same
   `expires` (unix s) and `index` to the LSP. The LSP never mints an expired
   hash, counts only live free hashes as `pool_size`, and answers `register`
   with `added` and `next_index`. The wallet's ordinary top-up (fires after
   open when `pool_size < 20`) therefore refreshes a stale pool by itself, and
   passes `next_index` back as the derivation start hint so a restored wallet
   continues its sequence. Hashes registered by older engines carry no expiry
   and get 30 days; pre-0.67.0 random hashes were retired once at 0.67.1 boot.

3. **A pay code belongs to the engine's peer.** Every LNURLp call in the page
   (create/rotate, top-up, auto-provision, pool readout, address rebuild)
   resolves the LSP with `lijLnurlpLsp()`: the engine's active peer
   (`getActiveLsp().pubkey`) matched to the LIJOX registry by pubkey. On a
   mismatch it returns null and the call does nothing. Never use the
   registry's first entry (`walletState.activeLsp` at boot) for anything
   that registers, mints, or builds an address. A stored address whose host
   is not the engine's LSP is re-homed at open.

4. **A definitive refusal ends the payment.** When the wallet rejects an
   inbound HTLC as unknown (INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, invalid
   onion), the LSP cancels the held original at once — the sender's sats
   return in seconds. Retrying a permanent refusal is never correct.

## In-flight truth (adapter)

After a SendToRoute deadline, a hard timeout, or LND's "attempted value
exceeds payment amount" (= a prior attempt for the SAME hash is still in
flight; two payments to one address are two hashes and never collide), the
delivery belt does not re-send. It asks LND via ListPayments: SUCCEEDED ⇒
settle the outer with the preimage; FAILED with a permanent reason ⇒ cancel
the outer; IN_FLIGHT ⇒ wait. Without ListPayments in the macaroon it re-sends
at most once a minute and says so once per boot.

## Numbers

- Hash life: 30 years (engine `LNURLP_HASH_EXPIRY_SECS = 946_080_000`).
- Pool: 50 per registration; top-up when live < 20.
- Unpaid reservation (hold invoice): 20 min; watcher gives up at 25.
- Mint ceiling: 60 per IP per rolling minute.
- Derive search bound: max(next_index + 1024, 8192).

## What the incident looked like, for recognition

- Sender: "held by your LSP — waiting for the recipient (no verdict in 30s)".
- LSP journal: `sendToRouteV2 rejected: attempted value exceeds payment
  amount` every 4 s (belt re-sending against its own in-flight HTLC), or
  `inner leg did not succeed code=INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS`.
- LND: the payment as a pending OUTGOING HTLC on the wallet's channel.
- A 21,000-sat minimum on a wallet that has a channel = the pay code lives at
  an LSP that holds no channel to it (check the LNURL's host).

## Still open

- The rotation/create screen should name the LSP it is about to register at.
- The Umbrel's delegate-free macaroon lacks ListPayments: in-flight truth is
  blind there (once-a-minute re-send fallback).
