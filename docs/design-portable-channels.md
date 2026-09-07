# Portable channels — LIJOX-PORT (design discussion v0)
Status: DISCUSSION. Written S21-close at DP's request; awaiting DP
ratification before an extension-spec draft.

## The promise being completed
LIJOX already makes the RELATIONSHIP portable: rebind the wallet to
any advertising LSP (the eSIM move). But today the CHANNELS don't
follow — switching means closing at A and reopening at B: two on-chain
events, an inbound rebuild, and a UX cliff. Lock-in survives at the
channel layer. LIJOX-PORT removes it.

## What cannot port (honesty first)
Raw channel STATE cannot move: a channel is a two-party contract with
a specific peer; its commitment secrets are meaningless to a third
party. Any "portability" is therefore a coordinated CLOSE+OPEN — the
design question is how many on-chain transactions and how much trust
that takes.

## Three grades
G1 — RELATIONSHIP PORT (exists today): rebind via LIJOX URI; old
channels close normally; new capacity via JIT at B. Cost: 2 on-chain
events (close + B's JIT open), inbound rebuilt from zero. Fine, but
clunky.
G2 — SINGLE-TRANSACTION PORT (the proposal): user and LSP-A negotiate
a COOPERATIVE CLOSE whose user-side output script IS the funding
script of a pre-negotiated 2-of-2 with LSP-B. The close transaction
IS the new channel's funding transaction. One on-chain event; the
balance moves A→B with the user co-signing both edges; at no block is
the money under any single party's key. LSP-B accepts the pre-existing
outpoint as an externally funded channel (LND funding-shim — the same
machinery our deferred-funding plan uses) and may extend zero-conf
usability immediately (same trust class as JIT today).
G3 — FACTORY-GRADE (SuperScalar future): within one LSP's factory,
"porting" is off-chain leaf reassignment; ACROSS factories/LSPs it
reduces to G2 on the leaf.

## Protocol sketch (G2)
1. Wallet → LSP-B: PORT_INTENT (desired capacity = current balance,
   user pubkey, optional zero-conf request). LSP-B → PORT_ACCEPT
   (its funding pubkey, reserve/fee terms, funding-script template),
   BIP-340-signed under its LIJOX manifest identity.
2. Wallet computes the 2-of-2(user, B) script; initiates shutdown with
   LSP-A using that script as its close address.
3. Close confirms (or B extends zero-conf on the unconfirmed close);
   B registers the outpoint via funding-shim; channel(user,B) live.
4. Inbound at B starts at 0 → B's JIT/promise machinery refills on the
   user's next receive, or B splices later.

## Requirements
• LSP-A: permit an arbitrary (any-segwit) shutdown script — i.e., the
  wallet must NOT pin upfront_shutdown to a fixed key at open time
  (action item: audit our open path for upfront_shutdown usage).
• LSP-B: external-funding acceptance (funding-shim ✓ in our stack) +
  a PORT_ACCEPT endpoint (adapter addition).
• Wallet: orchestrate the two negotiations; treat the port as one
  user action ("Move my jar to <provider>").

## Economics & incentives
User pays ONE close-tx fee (+ B's optional port/zero-conf fee — a
healthy price signal in the LIJOX market). A loses a customer with no
hostage mechanics — which is the point: exit costs one transaction,
so providers compete on service, not switching pain.

## Risks / open questions
• Griefing by A (stalled shutdown) → fallback is the standard force-
  close (degrades to G1; user's funds ride the no-delay output).
• Fee spikes mid-negotiation → wallet re-quotes before signing.
• B's zero-conf window on the unconfirmed close = exactly today's JIT
  trust class; confirmed-first mode always available.
• Privacy: A learns you left (unavoidable); B learns the prior close
  outpoint (acceptable; note in spec).
• Reserve/fee-cushion continuity: the new channel's honesty deposit
  and (if user-funded — it isn't; B is funder? NO: the USER's balance
  funds it, making the USER the funder of channel(user,B)) → the
  funder fence would sit on the USER again. COUNTER-DESIGN OPTION:
  B contributes a dual-funding-style token amount or the port opens as
  anchors-only so the fence is negligible. FLAG for the spec: ports
  SHOULD be anchor channels from day one.

═══════════════════════════════════════════════════════════════════
## AXIS 2 — WALLET-TO-WALLET PORT (DP, S21 close): switch wallet
## software WITHOUT ever closing a channel
═══════════════════════════════════════════════════════════════════
The insight: LSP-to-LSP (Axis 1) needs an on-chain event because the
COUNTERPARTY changes. Wallet-to-wallet keeps the same counterparty —
only the CLIENT changes. A channel is (funding outpoint + keys + state);
if the new software derives the same keys from the same seed and
imports the same state, the LSP sees the same peer reconnect with
valid latest state and the channels simply CONTINUE. This is recovery
Outcome 1, generalized across implementations — the recovery process
already laid the rails (DP's observation, correct).

W1 — SAME-ENGINE PORT (true today): LiJ → LiJ on a new device/browser
= seed + state backup = channels alive in minutes. The "port" framing
adds only a clean HANDOVER: the old instance must STOP (the
two-live-copies red line). 
W2 — CROSS-IMPLEMENTATION PORT (the standardization target): any
LIJOX wallet in the LDK family imports a SPECIFIED state container.
The LIJOX Wallet-State Portability profile =
  (a) container: LDK-serialized ChannelManager+Monitors, versioned,
      inside our existing envelope (Argon2id + AES-256-GCM — the
      vault's own cryptography, already shipped);
  (b) key profile: the seed → node-key derivation, documented and
      pinned (conformance vectors);
  (c) the LSP as the HANDOVER RAIL WITHOUT CUSTODY: the adapter gains
      GET/PUT /lijox/state — the encrypted blob hosted BY the LSP,
      pullable only with a possession-proof signature from the node
      key. New wallet flow: install → enter seed → point at LSP →
      auto-pull → channels alive. No close, no on-chain event, and the
      LSP never learns the brand changed OR the blob's contents
      (ciphertext; secrets ≠ custody, as always).
  HONEST SCOPE: cross-ENGINE (non-LDK: CLN/LND-based wallets) cannot
  import monitors — for them, portability degrades to Axis-1 grades.
  W2's addressable market = the LDK family (most of mobile).
W3 — LIVE HANDOVER (the horizon): old and new instance coordinate an
atomic session transfer (old signs a release at state N; new resumes;
LSP referees ordering). UX polish over W2.

THE DRAGON, named: same-seed-two-live-copies. The port protocol's
core job is making the unsafe state UNREPRESENTABLE, not punished:
release-marker in the container + adapter-side single-active-session
fencing per node pubkey (refuse a second concurrent identity; the
protocol's own data-loss protection remains the backstop, but UX must
prevent, never rely on punishment).
STATUS: deep-think queued per DP; W1 shippable as a documented flow
now; W2 = spec work on the LIJOX doc line; the /lijox/state sink
doubles as a first-class backup destination (manual §3's "sinks"
question and this feature are the same build).
