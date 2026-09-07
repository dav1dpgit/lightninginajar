# Internal transaction-fee cap — design record (PARKED)

DP, 2026-09-03: cap the per-transaction fee on payments internal to one LSP
(LiJ → LiJ, both wallets on the same LSP; channel opens excluded) at
"something like 9 sats". Talked through, agreed, PARKED behind the public
release and to-do #6. Not ruled: min(0.1 %, 9 sats) vs a flat 9; the 9 itself.

## Where the fee comes from today
A → LSP → B pays the LSP's channel policy on the LSP→B channel (0 + 0.1 %).
LND enforces it at forward time (htlcswitch/link.go CheckHtlcForward) and has
no cap primitive. The LSP→B channel also carries outside-in payments to B,
so a policy change cannot be internal-only.

## The design (two parts that must agree)
1. Sender side. The adapter's route answer already dictates the wallet's
   LSP-hop fee via `lsp_first_hop_policy` (engine: node.rs Phase 10b computes
   base + ppm × amount from it). For a destination the adapter recognises as
   one of its own wallets it answers min(policy fee, cap) for that route.
   Engine change needed (small): the engine RECORDS that policy as the LSP's
   general fee policy (v216 record_lsp_fee_policy) — an internal-only quote
   must not be recorded. Add a separate exact-fee field the engine uses for
   the route and does not record. Engine bump → page bump.
2. LSP side. LND would fail the cheaper HTLC ("insufficient fee"). LND ≥ 0.18
   interceptor action RESUME_MODIFIED with `in_amount_msat`: read from LND
   v0.20.1 source — interceptable_switch.go ResumeModified sets
   packet.incomingAmount; switch.go passes it to CheckHtlcForward; it also
   feeds the dust-exposure check; the real HTLC and channel balances are
   untouched. Adapter rule: incoming channel's peer is a registered wallet
   here AND outgoing channel's peer is a registered wallet here AND
   (in − out) ≥ min(cap, policy fee) → RESUME_MODIFIED with
   in_amount_msat = out + policy fee. Otherwise plain RESUME (LND's own fee
   check decides). Identification is entirely LSP-side; wallets need nothing.
   The repo's trimmed router.proto lacks RESUME_MODIFIED = 3 and response
   fields 6/7 — add them (wire-compatible with LND 0.20.1).

## Side effects (told to DP)
- LND's forwarding history records the substituted incoming amount
  (circuit.go IncomingAmount ← pkt.incomingAmount): `fwdinghistory` will show
  the policy fee earned, not the capped one. The adapter must keep its own
  internal-forward log for the LSP monitor (#10).
- Requires LND ≥ 0.18 on the LSP (UM890 0.20.1 ✓; Umbrel version to check).
  The adapter advertises the cap only when its node supports it — an
  OPTIONAL LIJOX manifest field (e.g. internal_fee_cap_msat).
- Revenue: at 0.1 % the cap bites above 9,000 sats (500k internal send:
  500 → 9 sats). Internal forwards cost the LSP nothing upstream; this is
  margin given back for a selling point.
