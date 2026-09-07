# LSPS2 Payment State Machine — design v0.1

Status: DRAFT for DP ratification · S21 · supersedes scattered-conditional
architecture of lij-adapter.js payment path (B-1 … B-13 era).

## 1. Why

Thirteen B-patches have landed on one pipeline: intercept → aggregate →
hold → open → forward → settle. Each was locally correct; the class of
failure keeps returning because the pipeline's invariants live implicitly
across ~3,000 lines of conditionals and three side-tables
(pendingHtlcsForOfflineWallets, promise._shards, in-flight opens), mutated
from four independent contexts (interceptor stream, WS liveness events,
timers, reconnect poll). The S21 ladder made the cost concrete:

- open-without-sats (M2b2, REPEAT offender): channel opened on-chain,
  no forward completed, recipient never credited.
- hold that promised "refunds ~18:23" with no wall-clock timer behind it
  (M3a1): UI ETA derived from the 180 s cap; the only scheduled failure
  path keyed to auto_fail_height (blocks ≈ hours).
- first-attempt no-routes, second attempt succeeds (M2b1): readiness race
  between promise/alias creation and send.
- three different "spendable" truths shown to one user in one flow
  (M2b2b), including a NEGATIVE lsp_spendable in our own flight panel.

A state machine doesn't make bugs impossible; it makes *this class*
impossible: every mutation flows through one dispatch, every transition
asserts invariants, and an invariant violation is a loud log line instead
of a silent wrong channel on mainnet.

## 2. Core model

One `PaymentIntent` per payment_hash. It OWNS everything about that
payment: all shards, the promise binding, timers, the channel (if JIT),
and the resolution. Nothing about a payment exists outside its intent.

```
PaymentIntent {
  payment_hash                 // identity
  promise_scid, client_pubkey  // binding
  total_msat_expected          // from promise
  shards: [ { circuit_key, amount_msat, received_at, resolution } ]
  state                        // exactly one of §3
  state_entered_at
  timers: { agg_deadline?, hold_cap_deadline?, watchdog_height? }
  channel: { funding_txid?, scid?, broadcast_state? }   // JIT only
  journal_seq                  // persistence ordering
  history: [ (event, from_state, to_state, ts) ]        // capped ring
}
```

## 3. States

```
INTERCEPTED   first shard arrived; intent created
AGGREGATING   MPP window open; shards accumulating (single-path skips)
GATED         all preconditions being checked before commitment
HOLDING       recipient not live; HTLCs parked under cap + CLTV budget
OPENING       JIT only: channel negotiate/open in flight
FORWARDING    outgoing HTLC(s) dispatched toward recipient
SETTLING      preimage received; applying to every inbound shard
SETTLED       terminal ✓  — every shard resolved with the preimage
FAILING       failing all shards back (reason recorded)
FAILED        terminal ✗  — every shard resolved with a failure
EXPIRED       terminal ✗  — cap or CLTV budget exhausted (subset of FAILED
              with reason=expiry; kept distinct for UX honesty)
ABANDONED     terminal ✗  — operator/conflict retirement; loud by definition
```

Legal transitions (anything else is an invariant violation, logged
[SM-VIOLATION] and refused):

```
INTERCEPTED → AGGREGATING | GATED
AGGREGATING → GATED | FAILING(agg_timeout|shard_invalid)
GATED       → HOLDING | OPENING | FORWARDING | FAILING(gate_reason)
HOLDING     → GATED (recipient live again; re-gate from scratch)
            → FAILING(cap_expired | cltv_low)
OPENING     → FORWARDING | HOLDING (B-13 disconnect mid-open)
            → FAILING(open_failed)
FORWARDING  → SETTLING | FAILING(forward_failed) | HOLDING(recipient lost
              AND no HTLC yet irrevocably out — else must ride to failure)
SETTLING    → SETTLED
FAILING     → FAILED | EXPIRED
```

## 4. Events (the ONLY way state changes)

`htlc_intercepted, agg_window_elapsed, gate_evaluated, recipient_live,
recipient_lost, open_succeeded, open_disconnected, open_failed,
forward_result, preimage_received, cap_timer_fired, watchdog_height_hit,
operator_abandon, adapter_restarted`

Interceptor callbacks, WS liveness, timers, and the reconnect poll are
*event emitters*. They never touch intent fields. `dispatch(intent, event)`
is the single writer; effects (LND calls, interceptor writes, pushes) are
issued by transition handlers and their results come back as events.

## 5. Invariants — each one is an observed failure, made structural

I1  OPENING requires: every expected shard present, Σ shard msat ==
    total_msat_expected, promise unexpired, recipient liveness confirmed
    ≤ 2 s before the open call.            → kills open-without-sats (M2b2)
I2  Entering HOLDING atomically creates BOTH a wall-clock cap timer AND a
    height watchdog; an intent in HOLDING without both is a violation.
    The UX refund ETA is *read from the cap timer*, never computed
    separately.                             → kills refunds-~18:23-that-never-came (M3a1)
I3  SETTLED requires the preimage applied to EVERY shard's circuit key;
    partial application is a violation, and FAILED requires every shard
    explicitly failed.                      → kills half-settled aggregates
I4  No openChannelSync call site exists outside the OPENING transition
    handler.                                → kills orphan/duplicate opens
I5  One intent per payment_hash; a second intercept for a hash in a
    terminal state re-opens NOTHING and fails the shard with a distinct
    reason.                                 → kills replay double-opens
I6  Timer/watchdog handles are owned by the intent and cancelled on every
    exit from the state that created them.  → kills zombie timers
I7  Every field the UX shows (ETA, amount, state word) is read from the
    intent, not recomputed at the display site.
I8  All capacity/limit checks call the ONE capacity module (see companion
    doc, S21 item "capacity lockdown"); no inline reserve math.

## 6. Persistence — restartable holds

Every transition appends the intent (full snapshot, journal_seq++) to a
disk journal (append-only JSONL, fsync'd; compaction on boot). On
`adapter_restarted`, intents are replayed: terminal → dropped after
retention; HOLDING → timers re-armed from persisted deadlines (wall-clock
deltas honored); OPENING/FORWARDING → re-verified against LND reality
(channel exists? HTLC out?) and re-dispatched or failed honestly.

This line is the 72-hour receiver-set hold's prerequisite. A 3-minute
hold can live in a Map; a 3-day hold that dies with systemctl restart is
not a feature. Persistence, sender-chosen CLTV budgets (~450+ blocks),
LSP policy caps, and re-notification cadence are the remaining deltas —
all of them intents-first. The state machine and the 72 h hold are one
road.

## 7. Deferred funding (atomic open-and-pay) — phase 2

OPENING splits: negotiate the channel via LND's PSBT funding flow
(fundingShim), hold the signed funding tx UNBROADCAST, forward zero-conf
over the negotiated channel, and broadcast funding only on
preimage_received. On failure, abandon the pending channel — nothing ever
hit the chain. This retires the open-without-sats class *permanently*
(I1 shrinks the window; deferred funding closes it). Requires: client
trusts zero-conf from us already (existing model), LND ≥ funding-shim
support (present), and abort-path hygiene. Ships after the machine is
absorbed, as its first native feature.

## 8. Migration — strangler pattern

Phase 0  SHADOW: machine runs alongside current code, fed by the same
         events, writes nothing. Every divergence between its computed
         state and the live tables logs [SM-SHADOW-DIVERGE]; every
         violated invariant logs [SM-VIOLATION]. The ladder is run once
         in shadow — the violation log IS the migration worklist.
Phase 1  Absorb resolution: settle/fail writes move into dispatch
         (I3 enforced for real). Old paths call dispatch.
Phase 2  Absorb hold + timers (I2, I6). pendingHtlcsForOfflineWallets
         deleted; journal becomes the truth. Restartable holds live.
Phase 3  Absorb gate + open (I1, I4, I5). B-13 becomes the
         open_disconnected → HOLDING transition it always wanted to be.
Phase 4  Deferred funding (§7). 72 h hold surface (§6) behind it.

Each phase is one adapter patch, shippable and revertable; B-1…B-13
logic transplants as transition handlers, not rewrites.

## 9. Acceptance

The restructured ladder (session21.md, DP's M1a–M4 with single/MPP
splits) run green twice consecutively, PLUS: adapter restarted mid-HOLD
with the payment completing correctly on resume (new rung M5), and a
forced open_failed after gate (new rung M6) leaving zero on-chain
footprint once §7 lands.
