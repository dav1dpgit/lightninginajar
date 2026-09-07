# Recovery Classes — the canonical taxonomy
Drafted Session 22 (2026-07-10), DP + Claude. THIS DOCUMENT IS MASTER for
recovery; docs/recovery-outcomes.md is its mechanics appendix.

## Governing principle — the intermediary-free terminus
Recovery is not complete when funds are merely SAFE at the user's keys.
It is complete when they sit where ANY ordinary wallet, holding only the
12 words, can see and spend them: the seed's standard tree (m/84). No
LSP, no LiJ, no sweep software, no intermediary in the DELIVERY path —
not just the custody path. Every class below is measured against this.

## The Waterfall (DP-ratified, 2026-07-10)
Inside the Lightning LIJOX standard...
...if you lose or erase your device: your 12 words + your encrypted
channel-state auto-backup bring back everything — channels included.
...if you have only your 12 words: channels close on the open, and your
money comes home on-chain within a few confirmations.

If you never touch LIJOX again: lightning channels close on your timer.
Every sat waits at your seed.

No one — not even your LSP — can redirect a single sat.
Your keys...your bitcoin.

## Naming: the Lines
DP-ratified shorthand: Line 1 = 1st class (Continuity), Line 2 = 2nd
class (Prompt Exit), Line 3 = 3rd class (Timed Exit) — matching the
Waterfall's stanzas.

## The three classes
### 1st class — Continuity
GUARANTEE: full on-chain access AND all channels remain open and usable.
MECHANISM: seed + CURRENT channel state. Two rails:
  (a) Same device — Layer-1 localStorage; the seed re-entry restore path
      preserves channel_manager + monitors. SHIPPED, session-verified.
  (b) Cross device — Layer-2 encrypted state blob: pushed automatically
      after every state write to the user-owned Cloudflare KV Worker
      (client-side AES-GCM, key derived from the mnemonic; versioned
      against rollback; indexed by a portable BIP32 pubkey; challenge-
      signature auth, no shared secret; multi-sink architecture — email/
      file sinks slot in later). PUSH SHIPPED + AUTO. PULL is engine-
      complete (KvBackupClient::pull, wasm pull_backup) but NOT YET
      WIRED into the restore UI — the one remaining build for (b).
SAFETY: only safe with CURRENT state. A stale blob restored and used
degrades AUTOMATICALLY to 2nd class via LDK data-loss protection (the
peer refuses old state; the LSP closes from ITS commitment) — funds
land on-chain, never lost. Wallet-side stale-state guard ships with the
pull wiring.

### 2nd class — Prompt Exit
GUARANTEE: full on-chain access immediately; channels close promptly;
every sat on the user's side (balance + honesty deposit) returns to the
seed's m/84 tree.
MECHANISM (today): seed-only restore into a LIJOX-compatible wallet →
LSP closes on reconnect → user output carries no delay (the delay binds
the broadcaster) → OutputSweeper claims to the recovery key, ~1 conf,
typically within the hour. SHIPPED (Outcome 2).
TERMINUS STATUS (corrected Session 22, DP caught it): ALREADY SHIPPED.
signer.rs get_shutdown_scriptpubkey() derives m/84h/{coin}h/0h/0/{n}
and node.rs commits it UPFRONT at channel open — every cooperative
close pays the seed's standard tree DIRECTLY: plain-wallet visible,
sweep-free, no software in the delivery path. (Edge: coop closes fee-
bumped/RBF'd by one side — DP caveat, verify behavior at desk.) Desk
item reduces to an on-chain eyeball of one real coop-close output.

### 3rd class — Timed Exit
GUARANTEE: full on-chain access; channels auto-close to m/84 at a
user-set deadline if the wallet never returns — protecting the user who
loses the habit, the device, or the ability to return (inheritance).
DP DESIGN RULES: opt-in per user; deadline refreshed to the full preset
on EVERY wallet touch (open / action / close); zero usability impact;
denominated in blocks, displayed in days.
ENFORCEMENT — two flavors on the board:
  (A) Enforced-by-transaction (DP's instinct; strongest): a co-signed
      nLockTime'd close, invalid before height H, broadcastable by
      anyone after — no liveness trust at all. COST: must be re-signed
      on every channel state change or a stale copy pays outdated
      balances (itself a theft vector). Real protocol work. v2 target.
  (B) Enforced-by-lease (lighter, ships first): the LSP commits at open
      to close by height H; every authenticated reestablish resets H.
      With the upfront m/84 pin, the LSP has ZERO power over where or
      how much — only WHETHER it acts on time. Non-performance can never
      cost a sat: the user's own signed commitment remains broadcastable
      forever (worst case: funds waited, then user/heir force-closed).
      Lease performance is attestable → LIJOX manifest capability +
      market discipline.
SEQUENCING: pin + lease first; locktime hardening second.
TTL (DP-RATIFIED): default 60 days = 8,640 blocks; min 1 day; max 364
days; per-channel; adjustable while online. "Heard from" = any
authenticated peer reestablish. ONBOARDING (DP-ratified): explained and
OFFERED at wallet establishment AND re-establishment; if enabled, user
chooses days; if declined, a warning screen states they may not survive
Line-3 recovery in the rare event of an LSP disappearance.
FLAVOR (C) — WITHDRAWN for third parties (DP stress-test, 2026-07-11):
a holder of the user's signed commitment who broadcasts a STALE version
triggers the LSP's revocation penalty — the user's entire channel
balance is confiscated as justice — and non-retention of old versions
is unenforceable. Third-party C = a new intermediary with a burn
weapon: rejected. Survives ONLY as self-custodied infrastructure (the
user's own second device / personal node), which is no intermediary at
all. NO COMMON POOL in any case — LIJOX never federates.
LEASE, REFRAMED: the lease is a COURTESY TIMER, not a load-bearing
member. Security is carried by the pin + the vault blob + independent
broadcast + (now) the direct-to-m/84 force-close; the lease carries
only punctuality, disciplined by LIJOX reputation. Its worst failure is
waiting — never loss, never a new trust.
IN-CHANNEL ENFORCEMENT: not expressible on today's Bitcoin without
covenant-class script or LN-symmetry; flavor (A) is the nearest and
carries the stale-version option flaw (an old split is broadcastable
after H by whichever side it favors) — documented research, not a ship
target.

THE TERMINUS FIX (DP-ratified 2026-07-11) — direct-to-m/84 force-close:
New channels default to NO-ANCHORS / static-remotekey commitments with
the to_remote payment_point pinned at open to a FRESH m/84 index drawn
from the shared PersistedCounter allocator. Consequence: every LSP-
broadcast force close (lease fire, LSP death, seed-only restore) pays
the seed's standard tree DIRECTLY, pre-signed — plain P2WPKH any BIP84
wallet auto-discovers, no sweeper, no return, no LIJOX ever required.
This is the pre-v0.2.0 pubkeys() override matured: the two recorded
reasons it was abandoned (custom m/525 path ≠ normie; ANCHORS wrapped
to_remote in unreadable P2WSH) are both removed by design (standard
path; no anchors). Collision was NOT the abandonment reason — the
persisted counter already exists precisely to prevent m/84 reuse, and
the pin draws from that same allocator: one counter, one chain,
collisions structurally impossible.
ANCHORS INVERSION: anchors become the PER-CHANNEL OPT-IN ("fee-boost
insurance — advanced"), not the default. What anchors buy is speed
insurance on emergency exits, never money: 2 × 330-sat fixed outputs;
without them a force close during a fee spike confirms LATE, not never
(update_fee keeps the frozen rate current in life; the absent-user case
is by definition an idle channel with nothing in flight). An anchors
channel's absent-user force close falls back to today's sweeper world —
stated to the user in one honest sentence.
ADDRESS MODES: per-channel fresh m/84 index = DEFAULT (gap-limit auto-
discovery, zero reuse); SINGLE-ADDRESS mode (index 0, deliberate reuse,
"one jar, one address") = user opt-in with the reuse trade stated.
SWEEPER RETAINED: still required for legacy m/525 residue and for the
self-broadcast to_local path (which only occurs when the user is
PRESENT — the absent-user case never touches it).
END STATE: every close where the user is absent lands on m/84 with no
machinery at all; the Waterfall is mechanically true in every branch.

IMPLEMENTATION STATUS (Session 23, 2026-07-12):
- SHIPPED engine v176: keys_id v2 marker gates a pubkeys()
  payment_point pin to m/84 at the channel's shared-allocator index;
  outbound opens propose no-anchors + pin (LIVE); inbound marks itself
  iff the proposed channel_type is non-anchors (truth-driven, read from
  the open request at accept time); sweep exemption for pinned outputs
  (already home; inside the tier2 watch window by construction);
  pre-v176 channels are unmarked ⇒ structurally untouchable.
- VERIFY (i) RESOLVED FROM LND SOURCE (answer: NO, then FIXED BY
  PATCH): stock LND 0.20.1's explicit channel-type whitelist has no
  zero-conf case without anchors — LSP-initiated zero-conf JIT could
  not negotiate no-anchors, and flipping the wallet's anchors support
  off would have failed JIT opens outright. LND's own fundee path
  accepts zero-conf without anchors ("for compatibility with LDK"),
  proving the internals support the combination; only the whitelist
  blocks it. DP RULING: patch LND (~64 added lines, 2 files —
  ops/lnd-terminus/) adding the missing whitelist rows + RPC support;
  upstream PR queued. Desk: build+swap lnd (additive, no behavior
  change), adapter T1 env flip, one labeled test open (M1b), then JIT
  ladder re-run. LDK sidecar LSP acknowledged as the long-term LIJOX
  reference architecture (SuperScalar era) — roadmap, not this track.
- Anchors JIT channels opened before the desk flip remain sweeper-world
  (the doctrine's stated fallback) until closed and reopened.

## Sweep actuation & broadcast independence (DP-ratified wording)
Every channel close sweeps to the seed's m/84 tree. The actuator is
OutputSweeper inside the user's own wallet — the signer mints the m/84
destination; the sweeper builds, fee-bumps, and broadcasts. Broadcast
is LSP-independent: cooperative relay first, then direct POST to a
public Esplora quorum, retried forever, failures visible. A hostile or
dead LSP can neither block the close nor censor the sweep. Residual: if
no LIJOX wallet ever opens again, matured force-close outputs wait —
safe, seed-and-state recoverable. (The terminus fix above removes even
this residual for new no-anchors channels.)

## The fail-safe ladder (the spine)
Stale 1st → automatic 2nd (LDK DLP). Dead/ignoring LSP in 3rd → slower
2nd (user force-close; delayed output matures ~144 blocks; claim to
m/84). THE FLOOR: the seed alone always recovers all value on-chain.
With the m/84 pin, DELIVERY joins custody in being intermediary-free on
all cooperative paths. RESIDUAL against the terminus: force-close
outputs still require LIJOX software to claim once — closing that gap
(force-close destination on the standard tree) is the remaining engine
design item for full terminus compliance.

## Morning hole-poke refinements (DP, 2026-07-11)
- VAULT ≠ LSP: the blob lives in the USER'S OWN vault; changing LSPs
  never touches it. Words-only scenarios = VAULT-LOSS (deleted/lapsed/
  unreachable/undiscovered endpoint), never LSP-change.
- LIJOX SPEC GAP (found by DP's Q1) — EXPANDED (DP-ratified): the
  encrypted backup vault is STANDARDIZED — blob format, seed-based
  derivation (m/525h identity + mnemonic-derived AES-GCM key),
  challenge auth, and endpoint discovery (`backup_vault` manifest
  field + user-supplied endpoint fallback) — so ANY LIJOX wallet opens
  the blob and lets the user reestablish or close the channels.
- LIJOX BOND (DP-ratified 2026-07-11): OPTIONAL `bond` manifest field —
  a Joinmarket-style timelocked self-bond: a UTXO locked to the LSP's
  own key, verifiable on-chain by anyone, custodied by no one, slashed
  by no one — pure burned-opportunity-cost signal, weighted by wallets/
  reputation as they please. MANDATORY bonds REJECTED on constitutional
  grounds (an enforcer is a federation; capital-gated entry betrays the
  hobbyist-LSP ethos; the terminus stack already strips the LSP of
  everything but punctuality, which reputation prices). Symmetry note
  for product copy: the in-protocol BOLT-2 channel reserve already
  means "your LSP posts an honesty deposit too, in every channel."
- m/525 VERDICT (DP challenged; code ruled): portable blob identity is
  m/525h's ONLY live role (key.rs header). The force-close association
  is LEGACY — static_remotekey_xpriv removed in v0.2.0; residue
  read-path only. wallet.rs:95 still says "m/535h" (stale comment,
  queued for the next engine bump).
- THIRD-PARTY CHANNELS (future feature): ride the SAME blob (LDK state
  is snapshotted wholesale) and get the terminus pin (our signer,
  peer-agnostic). Line-2 nuance: a words-only wallet cannot dial peers
  it does not remember — third-party closes fire on the PEER'S
  reestablish/timeout policy, not "on the open"; with the pin, even
  that eventual close pays m/84.
- AUTO-SPEND: no such primitive can exist — a payment requires the
  sender signing NEW state at send time; an absent wallet cannot sign,
  and pre-signed workarounds are flavor A with its stale-copy flaw.
- MALICIOUS-BUT-ALIVE LSP: costs the user a DELAY only — blob-holding
  user broadcasts their own commitment (broadcaster is LSP-
  independent), waits CSV, sweeps to m/84.
- THE ONE STRANDED CORNER, named: LSP-DEAD + VAULT-DEAD + WORDS-ONLY.
  A 2-of-2 with no living counterparty and no stored commitment is
  physics, not design. Mitigations: vault redundancy via the existing
  multi-sink architecture (second KV region / email sink — distinct
  from the PARKED state-card) + self-custodied flavor C. Comparison
  that grounds it: today's Lightning strands seed-only users in
  expert tooling even when peers DO close; our pinned to_remote pays
  plain m/84 whenever a dead LSP's channels ever get closed — our
  floor beats today's normal.

## Open issues — status
1. Who sweeps (class 3)? RESOLVED for cooperative paths by the upfront
   m/84 pin; force-close residual = engine item above.
2. "Heard from" definition: RESOLVED — any authenticated reestablish.
3. Lease trust honesty: STATED — a promise, custody-trustless, liveness
   fail-safe; not a protocol guarantee until flavor (A).
4. TTL bounds: PROPOSED above, DP override pending.
5. Stale-state guard: doc note now; wallet guard ships with pull wiring.
6. Doc authority: RESOLVED — this doc is master.

## Build queue (ordered)
1. ~~Wire pull_backup into restore~~ ALREADY WIRED (Session-22 find #3):
   LijWallet::restore pulls the blob on fresh devices (portable pubkey
   m/525h — seed-only recoverable by design), decrypts, injects
   monitors, rehydrates channels; the DP-ratified conflict rule is
   implemented verbatim (local present = at least as fresh = skip).
   REMAINING: (a) restore-announce UX (surface channels_recovered +
   vault version once, at unlock); (b) live round-trip verification —
   DP's next erase-and-restore IS the test.
2. ~~upfront_shutdown_script → m/84~~ SHIPPED (verified in code this
   session; desk: eyeball one real coop-close output on-chain).
3. TERMINUS ENGINE WORK (new centerpiece): signer pubkeys() override v2
   — payment_point → fresh m/84 index from the shared allocator; channel
   -open posture: no-anchors/static-remotekey DEFAULT, anchors per-
   channel opt-in flag; wallet UX: single-address opt-in + anchors
   "advanced" toggle. Verifies attached: (i) zero-conf JIT × no-anchors
   negotiability on the UM890's LND; (ii) one-allocator invariant —
   receive-address minting shares the persisted counter.
4. Lease protocol (punctuality layer): wallet TTL picker + onboarding
   offer/decline-warning per DP rulings + adapter lease table + LIJOX
   manifest `lease_ttl` capability.
5. Locktime'd close (flavor A): documented research only (stale-option
   flaw); superseded in practice by the terminus fix.
6. ~~Force-close terminus study~~ RESOLVED by the terminus fix (item 3).

## Verify at the desk
- Blob CONTENTS enumeration (exactly what prepare_backup snapshots).
- Pull round-trip test against the live Worker.
- LND stale-reestablish behavior on the UM890 (auto-close vs error-wait).
- LSP-close user-output script today (channel key vs direct address) —
  grounds the 2nd-class "sweep vs direct" sentences.
- Different-seed-over-surviving-monitors behavior (queued earlier).

## S26 AMENDMENT (2026-07-16) — the gap-limit caveat
The "gap-limit auto-discovery" claim in ADDRESS MODES above was
FALSIFIED by DP's live test (S25 pre-departure finding #2): the shared
m/84 allocator (shutdown scripts + sweeps + receive floors, burned
indices designed-in) spreads indices past third-party scanners'
default gap limits — a real 3-conf coop close landed at an address
BlueWallet never derives (~80 shown, 41 closed channels of history).
LiJ itself is CORRECT (derives from the persisted counter; funds
owned, visible, spendable). The Waterfall's terminus claim stays TRUE
with this caveat: seed-only recovery in a THIRD-PARTY wallet requires
raising its gap limit to >=500 first (Sparrow: Settings -> Advanced;
Electrum: wallet.change_gap_limit(500)). The wallet's Waterfall copy
carries the caveat on both surfaces as of frontend v345 (gate page +
the v283 recovery guide). Allocator-density / recovery-hints-export
design conversation remains queued (handoff §7.4.5b).
