# LDK patches — the full diff against upstream `lightning` 0.2.7 (refreshed 2026-11-26, engine v393: one read-only accessor, `lij_holder_csv()`, in `chain/channelmonitor.rs` — see (9) there, 8 lines; before that refreshed 2026-11-18, engine v376: the hunk LIJ PATCH v376 in `chain/channelmonitor.rs`, its test file and the one line that registers it — see `src/chain/channelmonitor.rs` (8) and `src/ln/lij_own_send_tests.rs` below; before that refreshed 2026-11-17, engine v375, the move from 0.2.6 to 0.2.7; the previous refresh 2026-10-15 at v347 lacked v360's `LijHtlcLeg` / `lij_htlc_legs` hunks — 88 lines)

The engine (`lij/lij-core`, `lij/lij-wasm`) builds against `lij/patches/lightning`, a copy of the `lightning` crate at 0.2.7 with local changes (`lij/Cargo.toml`: `lightning = { path = "patches/lightning" }`). This document is the complete diff, hunk by hunk, with the purpose of each. It supersedes the 0.0.123 edition of this file (engine ≤ v240); the engine moved to 0.2.6 at v241 (2026-09-12) and to 0.2.7 at v375 (2026-11-17: the same hunks, applied to the 0.2.7 source unchanged — no hunk rejected, the sorted change lines identical), and every hunk below is the re-port of a 0.0.123 hunk except one, the re-exposed `force_close_without_broadcasting_txn` (removed upstream in 0.1). To reproduce the diff yourself:

```
curl -sLO https://static.crates.io/crates/lightning/lightning-0.2.7.crate
sha256sum lightning-0.2.7.crate     # 982ffb82e8362ea95e03a5de8a6004bceb7a577fc1f07d5b02cfc3fc7c930a90
tar xzf lightning-0.2.7.crate
diff -ru lightning-0.2.7/src lij/patches/lightning/src
diff -u  lightning-0.2.7/Cargo.toml lij/patches/lightning/Cargo.toml
```

## Summary

| file | added | removed |
|---|---:|---:|
| `src/chain/chaininterface.rs` | 12 | 0 |
| `src/chain/channelmonitor.rs` | 232 | 0 |
| `src/ln/channel.rs` | 11 | 4 |
| `src/ln/channel_state.rs` | 10 | 0 |
| `src/ln/channelmanager.rs` | 32 | 6 |
| `src/ln/lij_own_send_tests.rs` (new file, tests only — v376) | 207 | 0 |
| `src/ln/mod.rs` (v376: registers the test file under `cfg(test)`) | 4 | 0 |
| `src/ln/outbound_payment.rs` | 2 | 2 |
| `src/ln/peer_handler.rs` | 1 | 1 |
| `src/offers/flow.rs` | 2 | 2 |
| `src/offers/invoice.rs` | 1 | 1 |
| `src/offers/invoice_request.rs` | 4 | 4 |
| `src/offers/refund.rs` | 5 | 5 |
| `src/onion_message/dns_resolution.rs` | 1 | 1 |
| `src/routing/gossip.rs` | 10 | 10 |
| `src/routing/router.rs` | 2 | 1 |
| `src/util/sweep.rs` | 11 | 0 |
| `src/util/time.rs` | 50 | 1 |
| `Cargo.toml` | 4 | 0 |
| **total, 19 files** | **601** | **38** |

Two kinds of change. (a) **Behavioural** — five files: `chain/chaininterface.rs`, `chain/channelmonitor.rs`, `ln/channel.rs`, `ln/channelmanager.rs`, `util/sweep.rs`; plus one **read-only field** (engine v269, 2026-09-21): `ln/channel_state.rs` adds `ChannelDetails::lij_value_to_self_msat`, LDK's own `value_to_self_msat` carried out unchanged (TLV 49, odd, default 0), and `routing/router.rs` sets it to 0 in two test/bench constructors. Each is read-only or narrows LDK's behaviour toward not broadcasting; none touches signing, key derivation, routing or gossip. One of them, since engine v376, is about HTLC handling: `chain/channelmonitor.rs` (8) changes WHEN the wallet goes on-chain over an HTLC it sent itself (3 blocks past its expiry → 4,032) — it delays a broadcast and adds none; the two v376 files under `ln/` are tests and compile into no build of the engine. (b) **Wall-clock substitutions** — `SystemTime` / `Instant` do not exist on `wasm32-unknown-unknown`, so every wall-clock call in the crate goes through `util/time.rs` (`lij_now`, `lij_since_epoch`, a browser-clock `Instant`), which reads `js_sys::Date` on wasm32 and the standard clock on every other target. Ten files carry only these substitutions; native builds are unchanged in behaviour. (The 0.0.123 edition had the same two kinds; 0.2.6 calls the clock in more places, which is why the file list grew.)

Files NOT touched, for the avoidance of doubt (identical to upstream byte for byte): `ln/onion_utils.rs`, `chain/chainmonitor.rs`, `chain/onchaintx.rs`, `chain/package.rs`, `sign/mod.rs`, `ln/msgs.rs`, `ln/features.rs`, and every file not listed in the table above.

Kept deliberately from the 0.0.123 engine (these are in `lij-core`, not in this crate, but a reviewer will look for them): the ChannelMonitor persistence keys are byte-identical to the 0.0.123 ones so restored state finds its monitors; the KeysManager's remote-key derivation stays the pre-0.1 form (LiJ pins `to_remote` to the wallet's own m/84 key itself); inbound splices are rejected at both `UserConfig` sites (`docs/ldk-0.2-splice-readiness.md` lists what must change before that is switched on).

## `src/chain/chaininterface.rs`

Adds `unbounded_sat_per_1000_weight`, an accessor that returns the fee estimator's own number for a target WITHOUT LDK's 253 sat/kW relay floor. Called from exactly one place (channel.rs below): the cooperative-close MINIMUM feerate, so the wallet accepts a sub-1-sat/vB close fee from its LSP instead of force-closing. Behavioural; identical in purpose to the 0.0.123 hunk.

```diff
@@ -209,6 +209,18 @@
 	pub fn bounded_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
 		cmp::max(self.0.get_est_sat_per_1000_weight(confirmation_target), FEERATE_FLOOR_SATS_PER_KW)
 	}
+
+	/// LiJ Option B (re-ported to 0.2.6): the underlying estimate WITHOUT the 253 sat/kW relay
+	/// floor. Used only for the cooperative-close MINIMUM feerate (ChannelCloseMinimum) in
+	/// `Channel::calculate_closing_fee_limits`. LiJ's FeeEstimator returns a deliberately
+	/// sub-relay value for that target so the wallet will ACCEPT a low coop-close fee from its
+	/// LSP (LND nodes routinely propose sub-1-sat/vB close fees). The normal `bounded_*` path
+	/// re-floored it and force-closed instead ("Unable to come to consensus about closing
+	/// feerate"). The close MAXIMUM keeps the floor via `bounded_*`; every other fee path is
+	/// untouched. The final fee paid is the negotiated value, not this floor.
+	pub fn unbounded_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
+		self.0.get_est_sat_per_1000_weight(confirmation_target)
+	}
 }
 
 #[cfg(test)]
```

## `src/chain/channelmonitor.rs`

Eight read-only additions and one hold, all behavioural, re-ported from 0.0.123 (the fifth added at v276, the sixth at v313, the seventh at v360, the eighth at v393 — see (6), (7) and (9) below), and since v376 one change to a rule (8): (1) `channel_keys_id()` — the 32-byte key id the registry channel record and the escape kit need to re-derive channel keys from the seed; (2) `lij_export_escape` + the private `lij_to_local_descriptor` — a signed copy of the latest holder commitment and its `to_local` descriptor for the offline escape kit (never broadcast by this code); (3) `lij_is_resolved_awaiting_archive()` — true when every balance is claimed and the funding spend has confirmed, so the wallet's archiver can retire the monitor; (5) `lij_latest_holder_commitment_txid()` — the txid of the latest holder commitment, read without building or signing anything, so the wallet can fingerprint its Black start kit every tick and re-push it only when a channel's state moved (engine v276); (4) the `lij_coop_hold` module and its one check at monitor load — LDK's rule is "a monitor without a manager channel broadcasts the holder commitment"; a cooperative close this wallet signed and that is still unconfirmed at the next boot must not be turned into a force close, so the wallet marks those funding txids before the manager is read and the broadcast is held; (6) `lij_commitment_obscure_factor()` — the channel's BOLT 3 commitment-number obscure factor, read only; the Black start kit's merge across copies of the wallet (engine v313) uses it to order another copy's kit entry against this copy's state, so a revoked CLOSE never replaces a newer one in the kit; (7) `LijHtlcLeg` and `lij_htlc_legs()` (engine v360, Black start — the in-flight payment collect), with its private twin on `ChannelMonitorImpl` — for each signed HTLC transaction `lij_export_escape` returns, which HTLC it belongs to and a `DelayedPaymentOutput` descriptor for its one output, so the wallet pre-signs a collect of it for the kit as it does for `to_local`; matched by the HTLC transaction's input, never by position; nothing is queued, signed or changed; (8) **LIJ PATCH v376** (engine v376, 2026-11-18, DP "Go" — `docs/design/htlc/offline-sender-r1.md` §4 B and `-r2.md`), the one change here to a rule LDK acts on: in `should_broadcast_holder_commitment_txn`, an outbound HTLC whose source is `HTLCSource::OutboundRoute` — a payment this node sent itself — is given the grace upstream already gives an async payment (`ASYNC_PAYMENT_GRACE_PERIOD_BLOCKS`, 4,032 blocks) before the node closes the channel on-chain over it, where upstream closes 3 blocks past the HTLC's expiry (`LATENCY_GRACE_PERIOD_BLOCKS`). Upstream's own comment gives the reason for that close as claiming the corresponding inbound HTLC on another channel; a LiJ wallet never forwards, so no HTLC it sends has one. A forwarded HTLC (`HTLCSource::PreviousHopData`) keeps the 3-block rule; the third line of the test (an inbound HTLC this node holds the preimage for) is untouched; no stored field changes. Its tests are `src/ln/lij_own_send_tests.rs` (below). **Fourteen of upstream's own tests assert the 3-block close for a sender's own payment and fail by design with (8) in place** (each read at its failing line: the node expected to close is the node that sent the payment): `async_signer_tests::test_async_holder_signatures_keyed_anchors`, `…_no_anchors`, `…_p2a_anchor`; `chanmon_update_fail_tests::test_monitor_and_persister_update_fail`; `functional_tests::channel_monitor_network_test`, `htlc_claim_single_commitment_only_a`, `htlc_claim_single_commitment_only_b`, `test_concurrent_monitor_claim`, `test_manual_broadcast_skips_commitment_until_funding`, `test_update_err_monitor_lockdown`; `monitor_tests::test_revoked_counterparty_commitment_balances`, `test_yield_anchors_events`; `reorg_tests::test_retries_own_commitment_broadcast_after_reorg`, `test_set_outpoints_partial_claiming`. All fourteen pass on the same tree without the hunk (run 2026-11-18). They are left as upstream wrote them. (9) `lij_holder_csv()` (engine v393, 2026-11-26) — read only: it returns the stored number `on_holder_tx_csv`, the delay in blocks the counterparty set on this wallet's own `to_local` output (`to_self_delay`). The wallet shows it on a channel closed by force ("available N blocks after the close transaction is in a block"). Nothing is built, signed, queued or changed.

```diff
@@ -1058,6 +1058,29 @@
 	}
 }
 
+/// LiJ v360 (S66 2026-11-02, Black start — the in-flight payment collect): one payment in flight
+/// on the latest holder commitment, as the kit records it — which of the exported transactions
+/// is its HTLC transaction, what it is, and the descriptor the collect is pre-signed from.
+/// See [`ChannelMonitor::lij_htlc_legs`].
+#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
+#[derive(Clone, Debug)]
+pub struct LijHtlcLeg {
+	/// Index into the transactions `lij_export_escape` returned (0 is the commitment itself).
+	pub tx_index: usize,
+	/// `true`: a payment going OUT — its transaction is the HTLC-timeout ("the return"), valid
+	/// from `cltv_expiry`. `false`: a payment coming IN whose preimage this wallet knows — its
+	/// transaction is the HTLC-success ("the claim"), valid at once.
+	pub offered: bool,
+	/// The HTLC's amount, in satoshis (its transaction's output carries this less the fee).
+	pub amount_sat: u64,
+	/// The block number from which a return is valid; carried for a claim too, unused there.
+	pub cltv_expiry: u32,
+	/// The payment's hash, so the kit can name the row.
+	pub payment_hash: PaymentHash,
+	/// A `DelayedPaymentOutput` at (the HTLC transaction's txid, 0).
+	pub descriptor: SpendableOutputDescriptor,
+}
+
 /// A ChannelMonitor handles chain events (blocks connected and disconnected) and generates
 /// on-chain transactions to ensure no loss of funds occurs.
 ///
@@ -2370,6 +2393,83 @@
 		);
 	}
 
+	/// LIJ PATCH (re-ported to 0.2.6): exposes the 32-byte `channel_keys_id` used to derive
+	/// this channel's signer, so the wallet can build registry records for seed-only recovery.
+	/// Additive, no behaviour change.
+	pub fn channel_keys_id(&self) -> [u8; 32] {
+		self.inner.lock().unwrap().channel_keys_id
+	}
+
+	/// LiJ v393 (read-only): the delay on THIS wallet's own `to_local` output when its own commitment
+	/// transaction closes the channel — the number of blocks the counterparty set (`to_self_delay`).
+	/// For the wallet's words "available N blocks after the close transaction is in a block".
+	/// Additive, no behaviour change.
+	pub fn lij_holder_csv(&self) -> u16 {
+		self.inner.lock().unwrap().on_holder_tx_csv
+	}
+
+	/// LiJ (escape kit, re-ported to 0.2.6; read-only): a signed copy of the latest holder
+	/// commitment transaction(s) plus a manually assembled
+	/// [`SpendableOutputDescriptor::DelayedPaymentOutput`] for our `to_local` output when it
+	/// exists on the commitment. Nothing is queued for broadcast and no lockdown flag is set —
+	/// export only. The descriptor is assembled here because
+	/// `broadcasted_holder_revokable_script` is `None` until a holder commitment is SEEN
+	/// on-chain, which is exactly the pre-broadcast situation the escape kit exists for.
+	/// Returns (transactions, to_local descriptor, to_self_delay).
+	#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
+	pub fn lij_export_escape<L: Deref>(&self, logger: &L)
+	 -> (Vec<Transaction>, Option<SpendableOutputDescriptor>, u16)
+	where L::Target: Logger {
+		let mut inner = self.inner.lock().unwrap();
+		let logger = WithChannelMonitor::from_impl(logger, &*inner, None);
+		let txs = inner.unsafe_get_latest_holder_commitment_txn(&logger);
+		let to_local = inner.lij_to_local_descriptor(&txs);
+		(txs, to_local, inner.on_holder_tx_csv)
+	}
+
+	/// LiJ v360 (S66 2026-11-02, Black start — the in-flight payment collect; read-only): for each
+	/// fully signed HTLC transaction `lij_export_escape` returned (its `txs[1..]`), which HTLC it
+	/// belongs to and a hand-assembled [`SpendableOutputDescriptor::DelayedPaymentOutput`] for its
+	/// single output — the same shape `lij_to_local_descriptor` builds for `to_local`, because
+	/// BOLT 3 gives the HTLC-timeout and HTLC-success outputs that very script
+	/// (`chan_utils::build_htlc_output` → `get_revokeable_redeemscript(..).to_p2wsh()`), and the
+	/// signed transaction's txid is fixed before broadcast. The wallet pre-signs a collect of it
+	/// for the kit exactly as it pre-signs the `to_local` collect. Matched by the HTLC
+	/// transaction's input (the commitment txid and the HTLC's output index), never by position;
+	/// a transaction whose output script is not the expected one is skipped with a warning — never
+	/// a wrong collect. Nothing is queued, signed or changed here.
+	#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
+	pub fn lij_htlc_legs<L: Deref>(&self, txs: &[Transaction], logger: &L) -> Vec<LijHtlcLeg>
+	where L::Target: Logger {
+		let inner = self.inner.lock().unwrap();
+		let logger = WithChannelMonitor::from_impl(logger, &*inner, None);
+		inner.lij_htlc_legs(txs, &logger)
+	}
+
+	/// LiJ v276 (Black Start, read-only): the txid of the latest holder commitment — what the
+	/// escape kit would export — without building or signing anything. The wallet fingerprints
+	/// its kit with this every tick and re-pushes only when a channel's state moved.
+	pub fn lij_latest_holder_commitment_txid(&self) -> Txid {
+		let inner = self.inner.lock().unwrap();
+		inner.funding.current_holder_commitment_tx.trust().txid()
+	}
+
+	/// LiJ v313 (Black start kit across copies, read-only): the factor that obscures this channel's commitment numbers
+	/// in its commitment transactions (BOLT 3). With it the wallet orders a kit entry made by another copy of itself
+	/// against its own state — a revoked CLOSE never replaces a newer one in the kit.
+	pub fn lij_commitment_obscure_factor(&self) -> u64 {
+		self.inner.lock().unwrap().commitment_transaction_number_obscure_factor
+	}
+
+	/// LiJ v223 (re-ported to 0.2.6): true when every balance is claimed AND the funding spend
+	/// was seen — the monitor is only waiting out the archive threshold. Read-only twin of
+	/// `is_fully_resolved` with no height latch and no threshold test; the spend walker uses it
+	/// to drop settled monitors from its all-must-answer chain pass.
+	pub fn lij_is_resolved_awaiting_archive(&self) -> bool {
+		if !self.get_claimable_balances().is_empty() { return false; }
+		self.inner.lock().unwrap().funding_spend_seen
+	}
+
 	/// Unsafe test-only version of `broadcast_latest_holder_commitment_txn` used by our test framework
 	/// to bypass HolderCommitmentTransaction state update lockdown after signature and generate
 	/// revoked commitment transaction.
@@ -4345,6 +4445,18 @@
 							log_trace!(logger, "Avoiding commitment broadcast, already detected confirmed spend onchain");
 							continue;
 						}
+						// LiJ (S45, re-ported to 0.2.6): a cooperative close this wallet signed may still be
+						// waiting in the mempool when the ChannelManager is re-read at boot. The startup rule
+						// queues this update for every monitor whose channel is gone from the manager, and
+						// the check above stands down only on a CONFIRMED spend — so a plain app restart
+						// broadcast the holder commitment over a pending cooperative close (2026-09-03,
+						// REMOTE_FORCE_CLOSE at 965353). The wallet registers such channels in
+						// `lij_coop_hold` before the manager read; hold the commitment for them. The wallet
+						// owns the ceiling and the fallback.
+						if lij_coop_hold::contains(&self.funding.funding_txid()) {
+							log_info!(logger, "LiJ: holding the holder-commitment broadcast for channel {} - a cooperative close this wallet signed is still pending", &self.channel_id());
+							continue;
+						}
 						self.queue_latest_holder_commitment_txn_for_broadcast(broadcaster, &bounded_fee_estimator, logger, true);
 					} else if !self.holder_tx_signed {
 						log_error!(logger, "WARNING: You have a potentially-unsafe holder commitment transaction available to broadcast");
@@ -5326,6 +5438,82 @@
 	#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
 	/// Note that this includes possibly-locktimed-in-the-future transactions!
 	#[rustfmt::skip]
+	/// LiJ escape-kit helper (re-ported to 0.2.6): the `to_local` descriptor for the holder
+	/// commitment in `txs[0]`, assembled from exactly the fields `get_broadcasted_holder_claims`
+	/// uses to build `broadcasted_holder_revokable_script`. Read-only.
+	fn lij_to_local_descriptor(&self, txs: &[Transaction]) -> Option<SpendableOutputDescriptor> {
+		let commitment = txs.first()?;
+		let holder_tx = &self.funding.current_holder_commitment_tx;
+		let trusted = holder_tx.trust();
+		let keys = trusted.keys();
+		let redeem_script = chan_utils::get_revokeable_redeemscript(
+			&keys.revocation_key, self.on_holder_tx_csv, &keys.broadcaster_delayed_payment_key,
+		);
+		let to_local_spk = redeem_script.to_p2wsh();
+		let txid = commitment.compute_txid();
+		for (i, outp) in commitment.output.iter().enumerate() {
+			if outp.script_pubkey == to_local_spk {
+				return Some(SpendableOutputDescriptor::DelayedPaymentOutput(DelayedPaymentOutputDescriptor {
+					outpoint: OutPoint { txid, index: i as u16 },
+					per_commitment_point: holder_tx.per_commitment_point(),
+					to_self_delay: self.on_holder_tx_csv,
+					output: outp.clone(),
+					revocation_pubkey: keys.revocation_key.clone(),
+					channel_keys_id: self.channel_keys_id,
+					channel_value_satoshis: self.funding.channel_parameters.channel_value_satoshis,
+					channel_transaction_parameters: Some(self.funding.channel_parameters.clone()),
+				}));
+			}
+		}
+		None
+	}
+
+	/// LiJ v360 (the in-flight payment collect): see `ChannelMonitor::lij_htlc_legs`.
+	fn lij_htlc_legs<L: Deref>(&self, txs: &[Transaction], logger: &WithContext<L>) -> Vec<LijHtlcLeg>
+	where L::Target: Logger {
+		let holder_tx = &self.funding.current_holder_commitment_tx;
+		let trusted = holder_tx.trust();
+		let keys = trusted.keys();
+		let commitment_txid = trusted.txid();
+		let redeem_script = chan_utils::get_revokeable_redeemscript(
+			&keys.revocation_key, self.on_holder_tx_csv, &keys.broadcaster_delayed_payment_key,
+		);
+		let expected_spk = redeem_script.to_p2wsh();
+		let mut legs = Vec::new();
+		for (tx_index, tx) in txs.iter().enumerate().skip(1) {
+			let input = match tx.input.first() { Some(i) => i, None => continue };
+			if input.previous_output.txid != commitment_txid { continue; }
+			let htlc = match holder_tx.nondust_htlcs().iter()
+				.find(|h| h.transaction_output_index == Some(input.previous_output.vout)) {
+				Some(h) => h,
+				None => continue,
+			};
+			let output = match tx.output.first() { Some(o) => o, None => continue };
+			if tx.output.len() != 1 || output.script_pubkey != expected_spk {
+				log_warn!(logger, "LiJ in-flight collect: HTLC transaction {} has an unexpected output — leg skipped", tx.compute_txid());
+				continue;
+			}
+			legs.push(LijHtlcLeg {
+				tx_index,
+				offered: htlc.offered,
+				amount_sat: htlc.amount_msat / 1000,
+				cltv_expiry: htlc.cltv_expiry,
+				payment_hash: htlc.payment_hash,
+				descriptor: SpendableOutputDescriptor::DelayedPaymentOutput(DelayedPaymentOutputDescriptor {
+					outpoint: OutPoint { txid: tx.compute_txid(), index: 0 },
+					per_commitment_point: holder_tx.per_commitment_point(),
+					to_self_delay: self.on_holder_tx_csv,
+					output: output.clone(),
+					revocation_pubkey: keys.revocation_key.clone(),
+					channel_keys_id: self.channel_keys_id,
+					channel_value_satoshis: self.funding.channel_parameters.channel_value_satoshis,
+					channel_transaction_parameters: Some(self.funding.channel_parameters.clone()),
+				}),
+			});
+		}
+		legs
+	}
+
 	fn unsafe_get_latest_holder_commitment_txn<L: Deref>(
 		&mut self, logger: &WithContext<L>
 	) -> Vec<Transaction> where L::Target: Logger {
@@ -6157,6 +6345,21 @@
 							..
 						}
 					);
+					// ── LIJ PATCH v376 (S70, DP 2026-11-18 "Go"; docs/design/htlc/offline-sender-r1.md §4 B) ──
+					// A payment this node sent itself (`HTLCSource::OutboundRoute`) has no inbound HTLC
+					// on another channel to protect by going on-chain — the reason given above for
+					// closing over an expired outbound HTLC. A LiJ wallet never forwards, so that is
+					// every HTLC it sends. Each such HTLC gets the grace upstream gives an async
+					// payment: a wallet that was offline while its provider failed (or settled) the
+					// HTLC lets the reconnect deliver that answer instead of closing the channel.
+					// A forwarded HTLC (`HTLCSource::PreviousHopData`) keeps the
+					// `LATENCY_GRACE_PERIOD_BLOCKS` rule, and so does the inbound-with-preimage rule
+					// in the third line of the test below.
+					let async_payment = async_payment || (htlc_outbound && matches!(
+						source.as_deref().expect("Every outbound HTLC should have a corresponding source"),
+						HTLCSource::OutboundRoute { .. }
+					));
+					// ── END LIJ PATCH v376 ──
 					if ( htlc_outbound && htlc.cltv_expiry + LATENCY_GRACE_PERIOD_BLOCKS <= height && !async_payment) ||
 					   ( htlc_outbound && htlc.cltv_expiry + ASYNC_PAYMENT_GRACE_PERIOD_BLOCKS <= height && async_payment) ||
 					   (!htlc_outbound && htlc.cltv_expiry <= height + CLTV_CLAIM_BUFFER && self.payment_preimages.contains_key(&htlc.payment_hash)) {
@@ -7471,3 +7674,32 @@
 	}
 	// Further testing is done in the ChannelManager integration tests.
 }
+
+/// LiJ (S45, re-ported to 0.2.6): the cooperative-close hold. See the note at the
+/// `ChannelForceClosed { should_broadcast: true }` handler in `ChannelMonitorImpl::update_monitor`.
+/// The wallet inserts the funding txid of every cooperative close it signed and broadcast that
+/// has not yet confirmed, BEFORE the ChannelManager is re-read at boot; the handler then holds
+/// the holder-commitment broadcast for those channels instead of double-spending the pending
+/// cooperative transaction. Additive; the wallet removes entries as closes confirm or when it
+/// falls back to the commitment itself.
+pub mod lij_coop_hold {
+	use bitcoin::Txid;
+	use std::collections::HashSet;
+	use std::sync::Mutex;
+
+	static HOLD: Mutex<Option<HashSet<Txid>>> = Mutex::new(None);
+
+	/// Register a funding txid whose cooperative close is pending.
+	pub fn insert(funding_txid: &Txid) {
+		let mut g = HOLD.lock().unwrap();
+		g.get_or_insert_with(HashSet::new).insert(*funding_txid);
+	}
+	/// Release a hold (the cooperative close confirmed, or the wallet fell back).
+	pub fn remove(funding_txid: &Txid) {
+		if let Some(set) = HOLD.lock().unwrap().as_mut() { set.remove(funding_txid); }
+	}
+	/// Is a hold registered for this funding txid?
+	pub fn contains(funding_txid: &Txid) -> bool {
+		HOLD.lock().unwrap().as_ref().map(|s| s.contains(funding_txid)).unwrap_or(false)
+	}
+}
```

## `src/ln/lij_own_send_tests.rs` and `src/ln/mod.rs` (engine v376 — tests only)

A new file, compiled only under `cfg(test)`: the five tests of `chain/channelmonitor.rs` (8), written with upstream's own test tools (`functional_test_utils`), node 0 as the wallet and node 1 as its provider. `lij_own_send_past_expiry_takes_the_late_fail` and its dust twin: the provider fails the payment back while the wallet is away; the wallet's chain goes 3 and then 1,003 blocks past the expiry and it closes nothing; the reconnect delivers the fail, the payment reads as failed, the channel stays open and carries the next payment. `lij_own_send_past_expiry_takes_the_late_settle`: the same with a settle — the payment reads as sent. `lij_own_send_closes_when_the_grace_has_run`: the provider never answers — nothing one block short of expiry + 4,032, the on-chain close (`HTLCsTimedOut`) at it. `lij_forwarded_htlc_keeps_the_three_block_rule`: a node that forwards still closes 3 blocks past the expiry. RUN 2026-11-18 on a copy of this tree outside the repo: with (8) 5 of 5 pass; with the hunk taken out 4 fail (the wallet has already broadcast at expiry + 3) and the forward test passes. `src/ln/mod.rs` gains the registration:

```diff
@@ -89,6 +89,10 @@
 #[cfg(test)]
 #[allow(unused_mut)]
 mod monitor_tests;
+// LiJ (engine v376): the tests of LIJ PATCH v376 in chain/channelmonitor.rs — own sends wait 4,032 blocks
+#[cfg(test)]
+#[allow(unused_mut)]
+mod lij_own_send_tests;
 #[cfg(test)]
 #[allow(unused_mut)]
 mod offers_tests;
```

The test file in full (all of it is new):

```rust
// LiJ (engine v376, S70 — DP 2026-11-18 "Go"; docs/design/htlc/offline-sender-r1.md §4 B and r2).
//
// Tests for the LIJ PATCH v376 in `chain/channelmonitor.rs`
// (`ChannelMonitorImpl::should_broadcast_holder_commitment_txn`): a payment this node sent itself
// (`HTLCSource::OutboundRoute`) gets the grace upstream gives an async payment — 4,032 blocks —
// before the node closes the channel on-chain over it. Upstream closes 3 blocks past the HTLC's
// expiry (`LATENCY_GRACE_PERIOD_BLOCKS`).
//
// In these tests node 0 is the wallet and node 1 is its provider.
//
// Without the patch `lij_own_send_past_expiry_takes_the_late_fail`,
// `lij_own_dust_send_past_expiry_takes_the_late_fail` and
// `lij_own_send_past_expiry_takes_the_late_settle` fail (the wallet has closed the channel before
// the reconnect), and `lij_own_send_closes_when_the_grace_has_run` fails (the close comes 4,029
// blocks sooner). `lij_forwarded_htlc_keeps_the_three_block_rule` passes with and without it.

use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::events::{ClosureReason, HTLCHandlingFailureType};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ErrorAction, MessageSendEvent};
use crate::types::payment::PaymentHash;

/// The grace the patch gives a payment this node sent: upstream's
/// `ASYNC_PAYMENT_GRACE_PERIOD_BLOCKS`, which is private to the function it is used in.
const LIJ_OWN_SEND_GRACE_BLOCKS: u32 = 4032;

/// The expiry block of the HTLC `node` sent for `payment_hash`, read from its own channel.
fn sent_htlc_expiry(node: &Node, payment_hash: PaymentHash) -> u32 {
	node.node
		.list_channels()
		.iter()
		.flat_map(|c| c.pending_outbound_htlcs.clone())
		.find(|htlc| htlc.payment_hash == payment_hash)
		.expect("the HTLC is on a channel")
		.cltv_expiry
}

/// Nothing was broadcast, nothing was closed, nothing is waiting to be sent or stored.
fn assert_quiet(node: &Node) {
	assert!(node.tx_broadcaster.txn_broadcast().is_empty());
	assert!(node.node.get_and_clear_pending_events().is_empty());
	assert!(node.node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(node, 0);
}

fn do_own_send_past_expiry_takes_the_late_fail(dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// The wallet sends; the provider holds the payment.
	let amt_msat = if dust { 50_000 } else { 3_000_000 };
	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], amt_msat);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	// The wallet goes offline. The provider fails the payment back while it is away: the fail
	// cannot leave the provider until the wallet is there to sign.
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);

	// The wallet's chain reaches 3 blocks past the expiry — where upstream closes — and then goes
	// 1,000 blocks further. It closes nothing.
	connect_blocks(&nodes[0], expiry + LATENCY_GRACE_PERIOD_BLOCKS - nodes[0].best_block_info().1);
	assert_eq!(nodes[0].best_block_info().1, expiry + LATENCY_GRACE_PERIOD_BLOCKS);
	assert_quiet(&nodes[0]);
	connect_blocks(&nodes[0], 1000);
	assert_quiet(&nodes[0]);

	// The provider sees the same chain and closes nothing either: it has nothing to claim.
	connect_blocks(&nodes[1], nodes[0].best_block_info().1 - nodes[1].best_block_info().1);
	assert_quiet(&nodes[1]);

	// The wallet reconnects. The provider's fail is delivered, the payment reads as failed, the
	// HTLC is gone and the channel is open.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_fails.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_failed!(nodes[0], payment_hash, true);
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.is_empty());
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	assert!(nodes[1].tx_broadcaster.txn_broadcast().is_empty());

	// ... and the same channel carries the next payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn lij_own_send_past_expiry_takes_the_late_fail() {
	do_own_send_past_expiry_takes_the_late_fail(false);
}

#[test]
fn lij_own_dust_send_past_expiry_takes_the_late_fail() {
	// Upstream counts an HTLC below the dust limit in the same rule (its own comment in
	// `should_broadcast_holder_commitment_txn`), so the patch must cover it too.
	do_own_send_past_expiry_takes_the_late_fail(true);
}

#[test]
fn lij_own_send_past_expiry_takes_the_late_settle() {
	// The provider has the preimage while the wallet is away. (A real provider collects on-chain
	// before the expiry if the wallet stays away — that rule is the provider's and is not changed;
	// here the provider's own chain is held back so that only the wallet's rule is in play.) The
	// wallet returns 3 blocks and more past the expiry: it does not close, and the reconnect
	// delivers the settle — the payment reads as sent.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	nodes[1].node.claim_funds(preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[0], expiry + LATENCY_GRACE_PERIOD_BLOCKS + 500 - nodes[0].best_block_info().1);
	assert_quiet(&nodes[0]);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_sent(&nodes[0], preimage, None, true, true);
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.is_empty());
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
}

#[test]
fn lij_own_send_closes_when_the_grace_has_run() {
	// The provider never answers. One block short of the grace the wallet has closed nothing; at
	// the grace it closes the channel on-chain over the payment, as upstream does at 3 blocks.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	connect_blocks(&nodes[0], expiry + LIJ_OWN_SEND_GRACE_BLOCKS - 1 - nodes[0].best_block_info().1);
	assert_eq!(nodes[0].best_block_info().1, expiry + LIJ_OWN_SEND_GRACE_BLOCKS - 1);
	assert_quiet(&nodes[0]);

	connect_blocks(&nodes[0], 1);
	assert!(!nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(msg_events.iter().any(|ev| matches!(
		ev,
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { .. }, .. }
			| MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, .. }
	)));
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event!(nodes[0], 1, reason, [node_b_id], 100000);
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn lij_forwarded_htlc_keeps_the_three_block_rule() {
	// Node 1 forwards a payment from node 0 to node 2, and node 2 never answers. A forwarded HTLC
	// has an inbound HTLC behind it, so node 1 still closes its channel with node 2 on-chain 3
	// blocks past the HTLC's expiry — the patch does not reach it.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_c_id = nodes[2].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[1], payment_hash);

	connect_blocks(&nodes[1], expiry + LATENCY_GRACE_PERIOD_BLOCKS - 1 - nodes[1].best_block_info().1);
	assert!(nodes[1].tx_broadcaster.txn_broadcast().is_empty());
	assert_eq!(nodes[1].node.list_channels().len(), 2);

	connect_blocks(&nodes[1], 1);
	assert!(!nodes[1].tx_broadcaster.txn_broadcast().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event!(nodes[1], 1, reason, [node_c_id], 100000);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
}
```

## `src/ln/channel.rs`

Three hunks: `force_shutdown` consults `lij_no_broadcast` so a channel marked for the stale-state abandon is closed locally without queueing the holder commitment (a revoked commitment must never hit the chain; the counterparty's close pays the wallet's pinned m/84 address directly); the cooperative-close MINIMUM reads the un-floored estimate (the chaininterface.rs accessor); one wall-clock call goes through `lij_now()`.

```diff
@@ -5998,7 +5998,11 @@
 		// be delayed in being processed! See the docs for `ChannelManagerReadArgs` for more.
 		assert!(!matches!(self.channel_state, ChannelState::ShutdownComplete));
 
-		let broadcast = self.is_funding_broadcastable();
+		// LiJ (re-port of the 0.0.123 `force_close_without_broadcasting_txn`, removed upstream in
+		// 0.1): a channel registered in `lij_no_broadcast` is closed locally WITHOUT queueing the
+		// holder commitment — the stale-state recovery move (a revoked commitment must never be
+		// broadcast; the counterparty's close pays the wallet's pinned m/84 directly).
+		let broadcast = self.is_funding_broadcastable() && !crate::ln::channelmanager::lij_no_broadcast::contains(&self.channel_id());
 
 		// We go ahead and "free" any holding cell HTLCs or HTLCs we haven't yet committed to and
 		// return them to fail the payment.
@@ -10195,8 +10199,11 @@
 		// Propose a range from our current Background feerate to our Normal feerate plus our
 		// force_close_avoidance_max_fee_satoshis.
 		// If we fail to come to consensus, we'll have to force-close.
+		// LiJ Option B (re-ported to 0.2.6): read the close MINIMUM un-floored — see
+		// LowerBoundedFeeEstimator::unbounded_sat_per_1000_weight. The MAXIMUM below keeps
+		// the relay floor via `bounded_*`.
 		let mut proposed_feerate =
-			fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
+			fee_estimator.unbounded_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
 		// Use NonAnchorChannelFee because this should be an estimate for a channel close
 		// that we don't expect to need fee bumping
 		let normal_feerate =
@@ -15727,9 +15734,9 @@
 
 	#[cfg(feature = "std")]
 	let now = Some(
-		std::time::SystemTime::now()
+		crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH"),
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH"),
 	);
 
 	now
```

## `src/ln/channelmanager.rs`

Re-exposes `force_close_without_broadcasting_txn`, which upstream removed in 0.1. LiJ's stale-state recovery move needs it (a wallet restored from an older state must never broadcast). Implemented as a process-local registry `lij_no_broadcast` (never persisted) that `Channel::force_shutdown` consults, set and cleared around one `force_close_sending_error` call. The other hunks are wall-clock calls redirected to `lij_now()`.

```diff
@@ -4684,6 +4684,16 @@
 		self.force_close_channel_with_peer(channel_id, &counterparty_node_id, reason)
 	}
 
+	/// LiJ (re-port; upstream removed it in 0.1): force-close a channel WITHOUT broadcasting our
+	/// commitment. Only for provably-stale state, where our commitment may be revoked and the
+	/// counterparty's close pays our pinned m/84 directly. The wallet owns the decision.
+	pub fn force_close_without_broadcasting_txn(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, error_message: String) -> Result<(), APIError> {
+		lij_no_broadcast::insert(channel_id);
+		let r = self.force_close_sending_error(channel_id, counterparty_node_id, error_message);
+		lij_no_broadcast::remove(channel_id);
+		r
+	}
+
 	/// Force closes a channel, immediately broadcasting the latest local transaction(s),
 	/// rejecting new HTLCs.
 	///
@@ -8418,9 +8428,9 @@
 			}
 
 			#[cfg(feature = "std")]
-			let duration_since_epoch = std::time::SystemTime::now()
+			let duration_since_epoch = crate::util::time::lij_now()
 				.duration_since(std::time::SystemTime::UNIX_EPOCH)
-				.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+				.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 			#[cfg(not(feature = "std"))]
 			let duration_since_epoch = Duration::from_secs(
 				self.highest_seen_timestamp.load(Ordering::Acquire).saturating_sub(7200) as u64,
@@ -12585,8 +12595,8 @@
 		#[cfg(feature = "std")]
 		let duration_since_epoch = {
 			use std::time::SystemTime;
-			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
-				.expect("SystemTime::now() should be after SystemTime::UNIX_EPOCH")
+			crate::util::time::lij_now().duration_since(SystemTime::UNIX_EPOCH)
+				.expect("crate::util::time::lij_now() should be after SystemTime::UNIX_EPOCH")
 		};
 
 		// This may be up to 2 hours in the future because of bitcoin's block time rule or about
@@ -13403,9 +13413,9 @@
 		#[cfg(not(feature = "std"))]
 		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
 		#[cfg(feature = "std")]
-		let now = std::time::SystemTime::now()
+		let now = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 
 		now
 	}
@@ -19879,3 +19889,19 @@
 		}));
 	}
 }
+
+/// LiJ: channel ids whose force-close must NOT broadcast the holder commitment — consulted by
+/// `Channel::force_shutdown`. Set and cleared around one call of
+/// `ChannelManager::force_close_without_broadcasting_txn`; never persisted.
+pub mod lij_no_broadcast {
+	use crate::ln::types::ChannelId;
+	use std::collections::HashSet;
+	use std::sync::Mutex;
+	static SET: Mutex<Option<HashSet<ChannelId>>> = Mutex::new(None);
+	/// Mark a channel: its next force-close must not broadcast.
+	pub fn insert(id: &ChannelId) { SET.lock().unwrap().get_or_insert_with(HashSet::new).insert(*id); }
+	/// Clear the mark.
+	pub fn remove(id: &ChannelId) { if let Some(s) = SET.lock().unwrap().as_mut() { s.remove(id); } }
+	/// Is the channel marked?
+	pub fn contains(id: &ChannelId) -> bool { SET.lock().unwrap().as_ref().map(|s| s.contains(id)).unwrap_or(false) }
+}
```

## `src/ln/outbound_payment.rs`

Wall-clock substitution only (`lij_since_epoch()` at the two `UNIX_EPOCH.elapsed()` sites). No behavioural change.

```diff
@@ -455,7 +455,7 @@
 #[rustfmt::skip]
 pub(super) fn has_expired(route_params: &RouteParameters) -> bool {
 	if let Some(expiry_time) = route_params.payment_params.expiry_time {
-		if let Ok(elapsed) = std::time::SystemTime::UNIX_EPOCH.elapsed() {
+		if let Ok(elapsed) = crate::util::time::lij_since_epoch() {
 			return elapsed > core::time::Duration::from_secs(expiry_time)
 		}
 	}
@@ -2914,7 +2914,7 @@
 		let secp_ctx = Secp256k1::new();
 		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);
 
-		let past_expiry_time = std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 2;
+		let past_expiry_time = crate::util::time::lij_since_epoch().unwrap().as_secs() - 2;
 		let payment_params = PaymentParameters::from_node_id(
 				PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap()),
 				0
```

## `src/ln/peer_handler.rs`

Wall-clock substitution only (the gossip full-sync threshold). No behavioural change.

```diff
@@ -2370,7 +2370,7 @@
 					// Forward ad-hoc gossip if the timestamp range is less than six hours ago.
 					// Otherwise, do a full sync.
 					use std::time::{SystemTime, UNIX_EPOCH};
-					let full_sync_threshold = SystemTime::now()
+					let full_sync_threshold = crate::util::time::lij_now()
 						.duration_since(UNIX_EPOCH)
 						.expect("Time must be > 1970")
 						.as_secs() - 6 * 3600;
```

## `src/offers/flow.rs`

Wall-clock substitution only. No behavioural change.

```diff
@@ -197,9 +197,9 @@
 		#[cfg(not(feature = "std"))]
 		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
 		#[cfg(feature = "std")]
-		let now = std::time::SystemTime::now()
+		let now = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 		now
 	}
 
```

## `src/offers/invoice.rs`

Wall-clock substitution only. No behavioural change.

```diff
@@ -1341,7 +1341,7 @@
 pub(super) fn is_expired(created_at: Duration, relative_expiry: Duration) -> bool {
 	let absolute_expiry = created_at.checked_add(relative_expiry);
 	match absolute_expiry {
-		Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
+		Some(seconds_from_epoch) => match crate::util::time::lij_since_epoch() {
 			Ok(elapsed) => elapsed > seconds_from_epoch,
 			Err(_) => false,
 		},
```

## `src/offers/invoice_request.rs`

Wall-clock substitution only. No behavioural change.

```diff
@@ -727,9 +727,9 @@
 	pub fn respond_with(
 		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 
 		$contents.respond_with_no_std(payment_paths, payment_hash, created_at)
 	}
@@ -932,9 +932,9 @@
 	pub fn respond_using_derived_keys(
 		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 
 		$self.respond_using_derived_keys_no_std(payment_paths, payment_hash, created_at)
 	}
```

## `src/offers/refund.rs`

Wall-clock substitution only (one of the lines is inside a doc comment). No behavioural change.

```diff
@@ -47,7 +47,7 @@
 //! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
 //! let pubkey = PublicKey::from(keys);
 //!
-//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
+//! let expiration = crate::util::time::lij_now() + Duration::from_secs(24 * 60 * 60);
 //! let refund = RefundBuilder::new(vec![1; 32], pubkey, 20_000)?
 //!     .description("coffee, large".to_string())
 //!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
@@ -573,9 +573,9 @@
 		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
 		signing_pubkey: PublicKey,
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 
 		$self.respond_with_no_std(payment_paths, payment_hash, signing_pubkey, created_at)
 	}
@@ -631,9 +631,9 @@
 	where
 		ES::Target: EntropySource,
 	{
-		let created_at = std::time::SystemTime::now()
+		let created_at = crate::util::time::lij_now()
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
-			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
+			.expect("crate::util::time::lij_now() should come after SystemTime::UNIX_EPOCH");
 
 		$self.respond_using_derived_keys_no_std(
 			payment_paths, payment_hash, created_at, expanded_key, entropy_source
```

## `src/onion_message/dns_resolution.rs`

Wall-clock substitution only. No behavioural change.

```diff
@@ -488,7 +488,7 @@
 				#[cfg(feature = "std")]
 				{
 					use std::time::{SystemTime, UNIX_EPOCH};
-					let now = SystemTime::now().duration_since(UNIX_EPOCH);
+					let now = crate::util::time::lij_now().duration_since(UNIX_EPOCH);
 					time = now.expect("Time must be > 1970").as_secs();
 				}
 				if time != 0 {
```

## `src/routing/gossip.rs`

Wall-clock substitution only (ten sites). No behavioural change.

```diff
@@ -843,7 +843,7 @@
 		let should_sync = self.should_request_full_sync();
 		#[cfg(feature = "std")]
 		{
-			gossip_start_time = SystemTime::now()
+			gossip_start_time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -2202,7 +2202,7 @@
 		let mut announcement_received_time = 0;
 		#[cfg(feature = "std")]
 		{
-			announcement_received_time = SystemTime::now()
+			announcement_received_time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -2242,7 +2242,7 @@
 	pub fn channel_failed_permanent(&self, short_channel_id: u64) {
 		#[cfg(feature = "std")]
 		let current_time_unix = Some(
-			SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs(),
+			crate::util::time::lij_now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs(),
 		);
 		#[cfg(not(feature = "std"))]
 		let current_time_unix = None;
@@ -2269,7 +2269,7 @@
 	pub fn node_failed_permanent(&self, node_id: &PublicKey) {
 		#[cfg(feature = "std")]
 		let current_time_unix = Some(
-			SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs(),
+			crate::util::time::lij_now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs(),
 		);
 		#[cfg(not(feature = "std"))]
 		let current_time_unix = None;
@@ -2327,7 +2327,7 @@
 	/// [`NetworkGraph::remove_stale_channels_and_tracking_with_time`] for non-`std` use.
 	pub fn remove_stale_channels_and_tracking(&self) {
 		let time =
-			SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			crate::util::time::lij_now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 		self.remove_stale_channels_and_tracking_with_time(time);
 	}
 
@@ -2478,7 +2478,7 @@
 		{
 			// Note that many tests rely on being able to set arbitrarily old timestamps, thus we
 			// disable this check during tests!
-			let time = SystemTime::now()
+			let time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -3055,7 +3055,7 @@
 		{
 			use std::time::{SystemTime, UNIX_EPOCH};
 
-			let tracking_time = SystemTime::now()
+			let tracking_time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -3470,7 +3470,7 @@
 			// so we should add it with a recent timestamp.
 			assert!(network_graph.read_only().channels().get(&scid).unwrap().one_to_two.is_none());
 			use std::time::{SystemTime, UNIX_EPOCH};
-			let announcement_time = SystemTime::now()
+			let announcement_time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -3507,7 +3507,7 @@
 		{
 			use std::time::{SystemTime, UNIX_EPOCH};
 
-			let tracking_time = SystemTime::now()
+			let tracking_time = crate::util::time::lij_now()
 				.duration_since(UNIX_EPOCH)
 				.expect("Time must be > 1970")
 				.as_secs();
@@ -3844,7 +3844,7 @@
 				MessageSendEvent::SendGossipTimestampFilter { node_id, msg } => {
 					assert_eq!(node_id, &node_id_1);
 					assert_eq!(msg.chain_hash, chain_hash);
-					let expected_timestamp = SystemTime::now()
+					let expected_timestamp = crate::util::time::lij_now()
 						.duration_since(UNIX_EPOCH)
 						.expect("Time must be > 1970")
 						.as_secs();
```

## `src/util/sweep.rs`

Behavioural, unchanged in purpose since the 0.0.123 patch (v150): a `StaticOutput` is never put in a sweep batch. In LiJ those are cooperative-close outputs at an m/84 address the wallet already controls — spendable as ordinary UTXOs with no sweep — and the KeysManager cannot sign them, so one in a batch fails `spend_spendable_outputs()` for the whole batch.

```diff
@@ -490,6 +490,17 @@
 	/// Regenerates and broadcasts the spending transaction for any outputs that are pending
 	async fn regenerate_and_broadcast_spend_if_necessary_internal(&self) -> Result<(), ()> {
 		let filter_fn = |o: &TrackedSpendableOutput, cur_height: u32| {
+			// ── LIJ PATCH v150 (re-ported to 0.2.6) ──
+			// Never include a StaticOutput in a sweep batch: in LiJ they are coop-close
+			// shutdown/destination outputs at an m/84 address the wallet already controls,
+			// spendable as a normal UTXO with no sweep; the KeysManager cannot sign them
+			// (no channel key), so one in a batch fails spend_spendable_outputs() for the
+			// ENTIRE batch. New ones are excluded at track time; an old one persisted in
+			// state would poison every batch. TO REVERT: delete this block only.
+			if matches!(o.descriptor, SpendableOutputDescriptor::StaticOutput { .. }) {
+				return false;
+			}
+			// ── END LIJ PATCH v150 ──
 			if o.status.is_confirmed() {
 				// Don't rebroadcast confirmed txs.
 				return false;
```

## `src/util/time.rs`

The clock shims. `wasm32-unknown-unknown` has no wall clock: `std::time::SystemTime::now()` and `Instant::now()` panic with "time not implemented on this platform". `lij_now()` and `lij_since_epoch()` read `js_sys::Date::now()` on wasm32 and the standard clock everywhere else; a browser-clock `Instant` type covers the two calls the crate makes on it. Every wall-clock call site in the crate goes through these (the substitutions listed above). Native builds are byte-for-byte upstream behaviour.

```diff
@@ -7,8 +7,37 @@
 //! A simple module which either re-exports [`std::time::Instant`] or a mocked version of it for
 //! tests.
 
-#[cfg(not(test))]
+#[cfg(all(not(test), not(target_arch = "wasm32")))]
 pub use std::time::Instant;
+
+// LiJ (re-port): on wasm32 `std::time::Instant::now()` panics ("time not implemented");
+// `outbound_payment` keeps a `first_attempted_at` for `Retry::Timeout`, which LiJ never uses
+// (Retry::Attempts(0)). A browser-clock Instant satisfies the two calls the crate makes.
+#[cfg(all(not(test), target_arch = "wasm32"))]
+pub use wasm_instant::Instant;
+#[cfg(all(not(test), target_arch = "wasm32"))]
+mod wasm_instant {
+	use core::time::Duration;
+	/// Monotonic-enough time on wasm32: milliseconds from the browser clock.
+	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+	pub struct Instant(Duration);
+	impl Instant {
+		/// Now, per the browser.
+		pub fn now() -> Self { Self(Duration::from_millis(js_sys::Date::now() as u64)) }
+		/// Time since `earlier` (saturating).
+		pub fn duration_since(&self, earlier: Self) -> Duration { self.0.saturating_sub(earlier.0) }
+		/// Time since this instant.
+		pub fn elapsed(&self) -> Duration { Self::now().duration_since(*self) }
+	}
+	impl core::ops::Sub<Duration> for Instant {
+		type Output = Self;
+		fn sub(self, other: Duration) -> Self { Self(self.0.saturating_sub(other)) }
+	}
+	impl core::ops::Add<Duration> for Instant {
+		type Output = Self;
+		fn add(self, other: Duration) -> Self { Self(self.0 + other) }
+	}
+}
 #[cfg(test)]
 pub use test::Instant;
 
@@ -60,3 +89,23 @@
 		assert_eq!(now.0 + Duration::from_secs(2), later.0);
 	}
 }
+
+// ── LiJ wasm32 clock shims (re-ported to 0.2.6) ─────────────────────────────────────
+// wasm32-unknown-unknown has no wall clock: `std::time::SystemTime::now()` panics with
+// "time not implemented on this platform" (2026-09-12: the first v241 tick did exactly
+// that and left the engine's lock held). Every wall-clock read in this crate goes through
+// these two helpers; on wasm32 they read the browser clock, elsewhere they are std.
+/// Wall-clock now.
+pub fn lij_now() -> std::time::SystemTime {
+	#[cfg(target_arch = "wasm32")]
+	{ std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64) }
+	#[cfg(not(target_arch = "wasm32"))]
+	{ std::time::SystemTime::now() }
+}
+/// Time since the Unix epoch (what `SystemTime::UNIX_EPOCH.elapsed()` returns).
+pub fn lij_since_epoch() -> Result<std::time::Duration, std::time::SystemTimeError> {
+	#[cfg(target_arch = "wasm32")]
+	{ Ok(std::time::Duration::from_millis(js_sys::Date::now() as u64)) }
+	#[cfg(not(target_arch = "wasm32"))]
+	{ std::time::SystemTime::UNIX_EPOCH.elapsed() }
+}
```

## `src/ln/channel_state.rs`

Engine v269 (2026-09-21, running totals): `ChannelDetails` carries the channel's exact local balance, `lij_value_to_self_msat` — LDK's own `FundingScope::value_to_self_msat`, the figure it reports as `last_local_balance_msat` when a channel closes — so the wallet's Lightning book has one exact number to foot against (the previous approximation, outbound capacity + reserve, undercounts a channel the wallet funded by the funder's commitment-fee buffer). Read-only: an odd TLV (49, default 0) on a struct that nothing in the state machine, persistence or signing reads back.

```diff
@@ -440,6 +440,13 @@
 	pub force_close_spend_delay: Option<u16>,
 	/// True if the channel was initiated (and thus funded) by us.
 	pub is_outbound: bool,
+	/// LiJ (engine v269, running totals): our side of the channel in millisatoshis, exact —
+	/// LDK's own `value_to_self_msat`: what this node owns on the channel, before the
+	/// commitment fee, the anchors and the reserve are carved out of it, and excluding HTLCs in
+	/// flight in either direction (an outbound HTLC has already left it; an inbound one has not
+	/// yet arrived). `value_to_self + value_to_remote + pending HTLCs = channel_value`. This is the
+	/// figure LDK reports as `last_local_balance_msat` when the channel closes. Read-only.
+	pub lij_value_to_self_msat: u64,
 	/// True if the channel is confirmed, channel_ready messages have been exchanged, and the
 	/// channel is not currently being shut down. `channel_ready` message exchange implies the
 	/// required confirmation count has been reached (and we were connected to the peer at some
@@ -587,6 +594,7 @@
 			confirmations: Some(funding.get_funding_tx_confirmations(best_block_height)),
 			force_close_spend_delay: funding.get_counterparty_selected_contest_delay(),
 			is_outbound: funding.is_outbound(),
+			lij_value_to_self_msat: funding.get_value_to_self_msat(),
 			is_channel_ready: context.is_usable(),
 			is_usable: context.is_live(),
 			is_announced: context.should_announce(),
@@ -636,6 +644,7 @@
 	(43, pending_inbound_htlcs, optional_vec),
 	(45, pending_outbound_htlcs, optional_vec),
 	(47, funding_redeem_script, option),
+	(49, lij_value_to_self_msat, (default_value, 0)),
 	(_unused, user_channel_id, (static_value,
 		_user_channel_id_low.unwrap_or(0) as u128 | ((_user_channel_id_high.unwrap_or(0) as u128) << 64)
 	)),
@@ -731,6 +740,7 @@
 			confirmations: Some(73),
 			force_close_spend_delay: Some(10),
 			is_outbound: true,
+			lij_value_to_self_msat: 0,
 			is_channel_ready: false,
 			is_usable: true,
 			is_announced: false,
```

## `src/routing/router.rs`

The two test/bench constructors of `ChannelDetails` set the new field to 0; nothing else.

```diff
@@ -4045,7 +4045,7 @@
 			confirmations_required: None,
 			confirmations: None,
 			force_close_spend_delay: None,
-			is_outbound: true, is_channel_ready: true,
+			is_outbound: true, lij_value_to_self_msat: 0, is_channel_ready: true,
 			is_usable: true, is_announced: true,
 			inbound_htlc_minimum_msat: None,
 			inbound_htlc_maximum_msat: None,
@@ -9507,6 +9507,7 @@
 			confirmations: None,
 			force_close_spend_delay: None,
 			is_outbound: true,
+			lij_value_to_self_msat: 0,
 			is_channel_ready: true,
 			is_usable: true,
 			is_announced: true,
```

## `Cargo.toml`

The wasm32-only `js-sys` dependency the shims read the browser clock through.

```diff
@@ -125,3 +125,7 @@
 version = "0.4"
 optional = true
 default-features = false
+
+# LiJ (re-port): the wasm32 clock shims read the browser clock through js-sys.
+[target."cfg(target_arch = \"wasm32\")".dependencies.js-sys]
+version = "0.3"
```
