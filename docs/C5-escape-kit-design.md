# C-5 — DARK-LSP ESCAPE KIT · DESIGN (S33)

Goal: if the LSP goes permanently dark, the user exits with time,
never money. Two artifacts, produced in the offline room on the
read-only engine instance (B2 rail), delivered through the proven
QR/UR/copy rails.

## Code facts (read this session)
- Patched LDK 0.0.123 in-tree (`lij/patches/lightning`). The exact
  API exists at channelmonitor.rs:1641 —
  `unsafe_get_latest_holder_commitment_txn()` returns the fully
  signed holder commitment + HTLC txs — but is cfg-gated
  `test | unsafe_revoked_tx_signing`.
- The adjacent "safe" path (`queue_latest_holder_commitment_txn_for_
  broadcast`) MUTATES monitor state (broadcast lockdown) — wrong for
  an export-only kit.
- Monitors decrypt+deserialize cleanly in restore (node.rs 656-676);
  the offline instance already holds them.
- Channels negotiate `anchors_zero_fee_htlc_tx` (node.rs 708).
- Sweep signing: LDK `KeysManager::spend_spendable_outputs` over a
  manually built `SpendableOutputDescriptor::DelayedPaymentOutput`
  (all fields present in the monitor: per_commitment_point, channel
  keys id, to_self_delay, output index/value).

## Engine (one rebuild, v208)
- Patch: add an UNGATED read-only twin,
  `lij_export_latest_holder_commitment_txn()` — same body as the
  unsafe getter, zero state mutation, zero broadcast queuing.
- New wasm export `escape_export()` on the current (offline)
  instance. Per channel returns:
  channel_id · counterparty · commitment_txid · commitment_hex ·
  htlc_tx_hexes[] · to_self_delay · our_to_local_sats ·
  sweep_hex_normal · sweep_hex_high · sweep_destination (m/84 via
  the persisted-counter allocator, Terminus class).
- Sweep is PRE-SIGNED at export: nSequence = to_self_delay makes it
  valid automatically once the commitment has that many confs. No
  post-CSV return trip. Broadcasting early is rejected by the
  network, never harmful.
- Two feerate variants because there is no RBF later (~10 and ~40
  sat/vB; exact numbers at build).

## Page (rides after the engine lands)
- Room card in KEYS: "ESCAPE KIT — if the LSP disappears." Reveal →
  per-channel rows → each artifact: copy (canonical rail) + QR/UR
  out (encoder self-test guards corrupt output).
- Copy states, per channel: broadcast the commitment anywhere (any
  explorer's broadcast page, any node); after N confirmations
  (shown per channel) broadcast the sweep; funds land at the shown
  m/84 address, visible to any BIP84 wallet on the 12 words.

## Honest limits (shipped in the card copy + ledger)
- FRESHNESS: the persisted monitor is the newest state this device
  ever signed. Exporting from an OLD restored backup and
  broadcasting it invites the penalty path — the card says: export
  only from the device you actually use.
- ANCHORS: commitment feerate is low by design; in high-fee weather
  it may confirm slowly. Anchor CPFP export = v2, not this build.
- CSV wait is physics; the card shows the per-channel block count.

## Sequence
- Engine v208: patch method + escape_export → CI build.
- Page: room card + rails.
- Field: export-only first (decode artifacts in Sparrow, verify
  txids/outputs); a real force-close drill only on a small
  sacrificial channel, DP's call.
