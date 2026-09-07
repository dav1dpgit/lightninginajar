# LDK patches — the full diff against upstream `lightning` 0.0.123

The engine (`lij/lij-core`, `lij/lij-wasm`) builds against `lij/patches/lightning`, a copy of the `lightning` crate at 0.0.123 with local changes (`lij/Cargo.toml`: `lightning = { path = "patches/lightning" }`). The pristine crate is the crates.io tarball `https://static.crates.io/crates/lightning/lightning-0.0.123.crate`, sha256 `5fd92d4aa159374be430c7590e169b4a6c0fb79018f5bc4ea1bffde536384db3`. This document is `diff -ru` of the two, hunk by hunk, with the purpose of each change stated above its hunks. Regenerate it with:

```
curl -sLO https://static.crates.io/crates/lightning/lightning-0.0.123.crate
sha256sum lightning-0.0.123.crate     # 5fd92d4aa159374b…
tar xzf lightning-0.0.123.crate
diff -ru lightning-0.0.123/src lij/patches/lightning/src
```

## Summary

| file | added | removed |
|---|---:|---:|
| `src/chain/chaininterface.rs` | 19 | 0 |
| `src/chain/channelmonitor.rs` | 141 | 0 |
| `src/ln/channel.rs` | 8 | 1 |
| `src/ln/channelmanager.rs` | 6 | 8 |
| `src/ln/outbound_payment.rs` | 20 | 4 |
| `src/offers/invoice.rs` | 1 | 1 |
| `src/offers/invoice_request.rs` | 2 | 2 |
| `src/offers/refund.rs` | 3 | 3 |
| `src/routing/gossip.rs` | 10 | 10 |
| `src/util/sweep.rs` | 19 | 0 |
| **total, 10 files** | **229** | **29** |

Files NOT touched, for the avoidance of doubt (identical to upstream byte for byte): `ln/peer_handler.rs`, `ln/onion_utils.rs`, `chain/chainmonitor.rs`, `chain/onchaintx.rs`, `routing/router.rs`, `sign/mod.rs`, and every other file not listed above.

Three kinds of change: (a) wasm32 clock substitutions — `SystemTime` / `Instant` do not exist on `wasm32-unknown-unknown`, so the wall clock comes from `js_sys::Date` there and native builds are untouched (channelmanager, outbound_payment, the three offers files, gossip); (b) the cooperative-close fee floor (chaininterface + channel); (c) additive accessors and one boot-time hold in the channel monitor, plus the sweeper's StaticOutput skip. Nothing changes commitment, revocation, HTLC or penalty logic.

## `src/chain/chaininterface.rs`

Adds `unbounded_sat_per_1000_weight`, an accessor that returns the fee estimator's own number for a target WITHOUT LDK's 253 sat/kW relay floor. It is called from exactly one place (channel.rs below) — the cooperative-close MINIMUM. Reason: LND nodes routinely propose sub-1-sat/vB cooperative closes; upstream re-floored the wallet's deliberately low accept floor to 253 sat/kW, rejected the LSP's proposal ("Unable to come to consensus about closing feerate") and force-closed. Every other fee path (opens, sweeps, HTLC transactions, the close MAXIMUM) still uses the floored `bounded_*` call. Additive.

```diff
@@ -189,6 +189,25 @@
 			FEERATE_FLOOR_SATS_PER_KW,
 		)
 	}
+
+	/// LiJ Option B: the underlying estimate WITHOUT the 253 sat/kW relay floor.
+	///
+	/// Used only for the cooperative-close MINIMUM feerate (ChannelCloseMinimum)
+	/// in `Channel::calculate_closing_fee_limits`. LiJ's FeeEstimator returns a
+	/// deliberately sub-relay value (COOP_CLOSE_ACCEPT_FLOOR_SAT_PER_KW = 25
+	/// sat/kW ≈ 0.1 sat/vB) for that target so the wallet will ACCEPT a low
+	/// coop-close fee from its trusted LSP (LND nodes routinely propose
+	/// sub-1-sat/vB close fees, e.g. 139 sat ≈ 0.77 sat/vB). The normal
+	/// `bounded_*` path re-floored that 25 back up to 253 (≈182 sat on a ~720-wu
+	/// close tx), which rejected the LSP's 139 and force-closed instead — the
+	/// exact "Unable to come to consensus about closing feerate" failure. This
+	/// accessor lets the close MINIMUM pass through un-floored. The close MAXIMUM
+	/// (NonAnchorChannelFee) keeps the floor via `bounded_*`, and every other
+	/// fee path (opens, sweeps, HTLC txs) is untouched. The final fee paid is
+	/// the negotiated value, not this floor.
+	pub fn unbounded_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
+		self.0.get_est_sat_per_1000_weight(confirmation_target)
+	}
 }
 
 #[cfg(test)]
```

## `src/chain/channelmonitor.rs`

Four additive pieces, none of which changes what LDK does with its own state: (1) `channel_keys_id()` — a stable accessor for the 32-byte id that derives the channel signer (upstream only exposes it behind a test-gated call); used to build seed-only-recovery registry records. (2) `lij_export_escape` / `lij_export_escape_kit` — a READ-ONLY export of the latest holder commitment transaction(s) plus a `DelayedPaymentOutput` descriptor for our `to_local` output, so the escape kit can be written before anything is broadcast; unlike `queue_latest_holder_commitment_txn_for_broadcast` it queues nothing and sets no lockdown flag. (3) `lij_is_resolved_awaiting_archive()` — a read-only twin of `is_fully_resolved` without the height latch, used to drop settled monitors from the wallet's chain-spend walker. (4) `lij_coop_hold` — a set of funding txids the wallet fills BEFORE the ChannelManager is re-read at boot with every cooperative close it signed and broadcast that has not yet confirmed. Upstream's startup rule queues `ChannelForceClosed { should_broadcast: true }` for every monitor whose channel is gone from the manager and stands down only on a CONFIRMED funding spend, so a plain app restart broadcast the holder commitment over a pending cooperative close (2026-09-03). The handler now holds the commitment for channels in the set; the wallet removes entries as closes confirm or gives up after a bounded wait.

```diff
@@ -1446,6 +1446,15 @@
 		self.inner.lock().unwrap().channel_id()
 	}
 
+	/// LIJ PATCH (Phase 1c-write): exposes the 32-byte `channel_keys_id` used
+	/// to derive this channel's [`ChannelSigner`]. Upstream LDK 0.0.123 only
+	/// exposes the signer via the test-gated `do_signer_call`; we add this
+	/// stable accessor so `registry_client` can build registry records for
+	/// seed-only recovery. Additive, no behavior change. Reapply on LDK bump.
+	pub fn channel_keys_id(&self) -> [u8; 32] {
+		self.inner.lock().unwrap().channel_keys_id
+	}
+
 	/// Gets a list of txids, with their output scripts (in the order they appear in the
 	/// transaction), which we must learn about spends of via block_connected().
 	pub fn get_outputs_to_watch(&self) -> Vec<(Txid, Vec<(u32, ScriptBuf)>)> {
@@ -1636,6 +1645,23 @@
 		inner.unsafe_get_latest_holder_commitment_txn(&logger)
 	}
 
+	/// LiJ (escape kit, ungated, read-only): signed copy of the latest holder
+	/// commitment transaction(s) plus a manually assembled
+	/// [`SpendableOutputDescriptor::DelayedPaymentOutput`] for our `to_local`
+	/// output when it exists on the commitment. Nothing is queued for
+	/// broadcast and no lockdown flag is set — export only. The descriptor is
+	/// assembled here because `broadcasted_holder_revokable_script` is `None`
+	/// until a holder commitment is actually SEEN on-chain, which is exactly
+	/// the pre-broadcast situation the escape kit exists for. Returns
+	/// (transactions, to_local descriptor, to_self_delay).
+	pub fn lij_export_escape<L: Deref>(&self, logger: &L)
+	 -> (Vec<Transaction>, Option<SpendableOutputDescriptor>, u16)
+	where L::Target: Logger {
+		let mut inner = self.inner.lock().unwrap();
+		let logger = WithChannelMonitor::from_impl(logger, &*inner);
+		inner.lij_export_escape(&logger)
+	}
+
 	/// Processes transactions in a newly connected block, which may result in any of the following:
 	/// - update the monitor's state against resolved HTLCs
 	/// - punish the counterparty in the case of seeing a revoked commitment transaction
@@ -1910,6 +1936,16 @@
 		}
 	}
 
+	/// LiJ v223 (S39): true when every balance is claimed AND the funding
+	/// spend was seen — the monitor is only waiting out the archive
+	/// threshold above. Read-only twin of `is_fully_resolved` with no
+	/// height latch and no threshold test; the spend walker uses it to
+	/// drop settled monitors from its all-must-answer Esplora pass.
+	pub fn lij_is_resolved_awaiting_archive(&self) -> bool {
+		if !self.get_claimable_balances().is_empty() { return false; }
+		self.inner.lock().unwrap().funding_spend_seen
+	}
+
 	#[cfg(test)]
 	pub fn get_counterparty_payment_script(&self) -> ScriptBuf {
 		self.inner.lock().unwrap().counterparty_payment_script.clone()
@@ -2973,6 +3009,22 @@
 							log_trace!(logger, "Avoiding commitment broadcast, already detected confirmed spend onchain");
 							continue;
 						}
+						// LiJ (S45, 2026-09-06): a cooperative close this wallet signed may still be
+						// waiting in the mempool when the ChannelManager is re-read at boot. The
+						// startup rule queues this update for every monitor whose channel is gone
+						// from the manager, and the check above stands down only on a CONFIRMED
+						// spend — so a plain app restart broadcast the holder commitment over a
+						// pending cooperative close (2026-09-03, channel 4c99…, REMOTE_FORCE_CLOSE
+						// at 965353). The wallet registers such channels in `lij_coop_hold` before
+						// the manager read; hold the commitment for them. The wallet owns the
+						// ceiling and the fallback (it releases the hold, or broadcasts the
+						// commitment itself via `broadcast_latest_holder_commitment_txn`).
+						{
+							if lij_coop_hold::contains(&self.funding_info.0.txid) {
+								log_info!(logger, "LiJ: holding the holder-commitment broadcast for channel {} - a cooperative close this wallet signed is still pending confirmation", &self.channel_id());
+								continue;
+							}
+						}
 						self.queue_latest_holder_commitment_txn_for_broadcast(broadcaster, &bounded_fee_estimator, logger);
 					} else if !self.holder_tx_signed {
 						log_error!(logger, "WARNING: You have a potentially-unsafe holder commitment transaction available to broadcast");
@@ -3658,6 +3710,64 @@
 		holder_transactions
 	}
 
+	/// LiJ escape-kit body — see the outer method on [`ChannelMonitor`].
+	/// Read-only apart from the signer's copy-signing, which sets no state
+	/// and queues nothing for broadcast (unlike
+	/// `queue_latest_holder_commitment_txn_for_broadcast`).
+	fn lij_export_escape<L: Deref>(
+		&mut self, logger: &WithChannelMonitor<L>
+	) -> (Vec<Transaction>, Option<SpendableOutputDescriptor>, u16) where L::Target: Logger {
+		log_debug!(logger, "LiJ escape export: signing copy of latest holder commitment transaction");
+		let commitment_tx = self.onchain_tx_handler.get_fully_signed_copy_holder_tx(&self.funding_redeemscript);
+		let txid = commitment_tx.txid();
+		let mut holder_transactions = vec![commitment_tx];
+		// HTLC transactions ride only for non-anchor channels — with anchors
+		// they are CSV-1 encumbered on the commitment and not final here.
+		// Same policy as `unsafe_get_latest_holder_commitment_txn` above.
+		if !self.onchain_tx_handler.channel_type_features().supports_anchors_zero_fee_htlc_tx() {
+			for htlc in self.current_holder_commitment_tx.htlc_outputs.iter() {
+				if let Some(vout) = htlc.0.transaction_output_index {
+					let preimage = if !htlc.0.offered {
+						if let Some(preimage) = self.payment_preimages.get(&htlc.0.payment_hash) { Some(preimage.clone()) } else {
+							// No HTLC-Success without the preimage.
+							continue;
+						}
+					} else { None };
+					if let Some(htlc_tx) = self.onchain_tx_handler.get_maybe_signed_htlc_tx(
+						&::bitcoin::OutPoint { txid, vout }, &preimage
+					) {
+						if htlc_tx.is_fully_signed() {
+							holder_transactions.push(htlc_tx.0);
+						}
+					}
+				}
+			}
+		}
+		// to_local descriptor, assembled from exactly the fields
+		// `get_broadcasted_holder_claims` uses to build
+		// `broadcasted_holder_revokable_script`.
+		let holder_tx = &self.current_holder_commitment_tx;
+		let redeemscript = chan_utils::get_revokeable_redeemscript(&holder_tx.revocation_key, self.on_holder_tx_csv, &holder_tx.delayed_payment_key);
+		let to_local_spk = redeemscript.to_v0_p2wsh();
+		let mut to_local = None;
+		for (i, outp) in holder_transactions[0].output.iter().enumerate() {
+			if outp.script_pubkey == to_local_spk {
+				to_local = Some(SpendableOutputDescriptor::DelayedPaymentOutput(DelayedPaymentOutputDescriptor {
+					outpoint: OutPoint { txid, index: i as u16 },
+					per_commitment_point: holder_tx.per_commitment_point.clone(),
+					to_self_delay: self.on_holder_tx_csv,
+					output: outp.clone(),
+					revocation_pubkey: holder_tx.revocation_key.clone(),
+					channel_keys_id: self.channel_keys_id,
+					channel_value_satoshis: self.channel_value_satoshis,
+					channel_transaction_parameters: Some(self.onchain_tx_handler.channel_transaction_parameters.clone()),
+				}));
+				break;
+			}
+		}
+		(holder_transactions, to_local, self.on_holder_tx_csv)
+	}
+
 	fn block_connected<B: Deref, F: Deref, L: Deref>(
 		&mut self, header: &Header, txdata: &TransactionData, height: u32, broadcaster: B,
 		fee_estimator: F, logger: &WithChannelMonitor<L>,
@@ -5271,3 +5381,34 @@
 	}
 	// Further testing is done in the ChannelManager integration tests.
 }
+
+/// LiJ (S45, 2026-09-06): the cooperative-close hold. See the note at the
+/// `ChannelForceClosed { should_broadcast: true }` handler in
+/// `ChannelMonitorImpl::update_monitor`. The wallet inserts the funding txid
+/// of every cooperative close it signed and broadcast that has not yet
+/// confirmed, BEFORE the ChannelManager is re-read at boot; the handler then
+/// holds the holder-commitment broadcast for those channels instead of
+/// double-spending the pending cooperative transaction. Additive, read-only
+/// for LDK's own state; the wallet removes entries as closes confirm or when
+/// it falls back to the commitment itself.
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

## `src/ln/channel.rs`

One call site: the cooperative-close minimum feerate reads the un-floored value from the accessor above. The maximum is unchanged. This is what lets the wallet accept its LSP's low cooperative-close fee instead of force-closing.

```diff
@@ -5655,7 +5655,14 @@
 		// Propose a range from our current Background feerate to our Normal feerate plus our
 		// force_close_avoidance_max_fee_satoshis.
 		// If we fail to come to consensus, we'll have to force-close.
-		let mut proposed_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
+		// LiJ Option B: read the close MINIMUM un-floored. LiJ's FeeEstimator
+		// returns 25 sat/kW for ChannelCloseMinimum (a deliberate sub-relay
+		// accept floor) so the wallet defers to its trusted LSP's low coop-close
+		// fee. The default `bounded_*` call re-floored that to 253 sat/kW (≈182
+		// sat), rejecting the LSP's 139-sat proposal and force-closing. Using
+		// the un-floored value lets consensus succeed. The MAXIMUM below keeps
+		// the relay floor via `bounded_*`.
+		let mut proposed_feerate = fee_estimator.unbounded_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
 		// Use NonAnchorChannelFee because this should be an estimate for a channel close
 		// that we don't expect to need fee bumping
 		let normal_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
```

## `src/ln/channelmanager.rs`

wasm32 time source. Upstream reads `SystemTime::now()` under `feature = "std"` and a timestamp-derived estimate otherwise; on wasm32-unknown-unknown `SystemTime::now()` panics, so the wall clock comes from `js_sys::Date::now()`. Used only by `remove_stale_payments` (pruning of stale pending outbound payments). Native builds are unchanged.

```diff
@@ -6017,14 +6017,12 @@
 				self.finish_close_channel(shutdown_res);
 			}
 
-			#[cfg(feature = "std")]
-			let duration_since_epoch = std::time::SystemTime::now()
-				.duration_since(std::time::SystemTime::UNIX_EPOCH)
-				.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
-			#[cfg(not(feature = "std"))]
-			let duration_since_epoch = Duration::from_secs(
-				self.highest_seen_timestamp.load(Ordering::Acquire).saturating_sub(7200) as u64
-			);
+				#[cfg(target_arch = "wasm32")]
+				let duration_since_epoch = std::time::Duration::from_millis(js_sys::Date::now() as u64);
+				#[cfg(not(target_arch = "wasm32"))]
+				let duration_since_epoch = std::time::SystemTime::now()
+					.duration_since(std::time::SystemTime::UNIX_EPOCH)
+					.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
 
 			self.pending_outbound_payments.remove_stale_payments(
 				duration_since_epoch, &self.pending_events
```

## `src/ln/outbound_payment.rs`

wasm32 time source for `PaymentAttempts.first_attempted_at`: `std::time::Instant` panics on wasm32, so the type alias becomes a no-op "Eternity" clock there. That field is consulted only by `Retry::Timeout`, which this wallet never uses (it uses `Retry::Attempts(0)`), and by `Display`. If a timeout retry strategy were ever introduced on wasm32 this would need a real clock — the comment in the code says so.

```diff
@@ -314,9 +314,17 @@
 			(Retry::Attempts(max_retry_count), PaymentAttempts { count, .. }) => {
 				max_retry_count > count
 			},
-			#[cfg(all(feature = "std", not(test)))]
+			#[cfg(all(feature = "std", not(test), not(target_arch = "wasm32")))]
 			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
 				*max_duration >= crate::util::time::MonotonicTime::now().duration_since(*first_attempted_at),
+			// Phase 3.8.C v2 (LiJ): wasm32 PaymentAttempts.first_attempted_at is
+			// Eternity (see ConfiguredTime alias, patched by v1). This arm is
+			// unreachable for LiJ's current Retry::Attempts(0) usage, but must
+			// type-check against Eternity. If Retry::Timeout is ever introduced
+			// on wasm32, Eternity::duration_since returns 0 → "always retryable".
+			#[cfg(all(feature = "std", not(test), target_arch = "wasm32"))]
+			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
+				*max_duration >= crate::util::time::Eternity::now().duration_since(*first_attempted_at),
 			#[cfg(all(feature = "std", test))]
 			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
 				*max_duration >= SinceEpoch::now().duration_since(*first_attempted_at),
@@ -327,7 +335,7 @@
 #[cfg(feature = "std")]
 pub(super) fn has_expired(route_params: &RouteParameters) -> bool {
 	if let Some(expiry_time) = route_params.payment_params.expiry_time {
-		if let Ok(elapsed) = std::time::SystemTime::UNIX_EPOCH.elapsed() {
+		if let Ok(elapsed) = { #[cfg(target_arch = "wasm32")] { Ok::<std::time::Duration, std::time::SystemTimeError>(std::time::Duration::from_millis(js_sys::Date::now() as u64)) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::UNIX_EPOCH.elapsed() } } {
 			return elapsed > core::time::Duration::from_secs(expiry_time)
 		}
 	}
@@ -352,7 +360,15 @@
 
 #[cfg(not(feature = "std"))]
 type ConfiguredTime = crate::util::time::Eternity;
-#[cfg(all(feature = "std", not(test)))]
+// Phase 3.8.C (LiJ): WASM target uses Eternity (no-op time) because
+// std::time::Instant panics on wasm32-unknown-unknown. PaymentAttempts'
+// first_attempted_at is only consulted by Retry::Timeout (which LiJ does
+// not use; LiJ uses Retry::Attempts(0)), and by Display, which becomes
+// "duration: 0s". If a Retry::Timeout strategy is ever introduced in LiJ,
+// this needs a real time source.
+#[cfg(all(feature = "std", not(test), target_arch = "wasm32"))]
+type ConfiguredTime = crate::util::time::Eternity;
+#[cfg(all(feature = "std", not(test), not(target_arch = "wasm32")))]
 type ConfiguredTime = crate::util::time::MonotonicTime;
 #[cfg(all(feature = "std", test))]
 type ConfiguredTime = SinceEpoch;
@@ -1892,7 +1908,7 @@
 		let secp_ctx = Secp256k1::new();
 		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);
 
-		let past_expiry_time = std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 2;
+		let past_expiry_time = { #[cfg(target_arch = "wasm32")] { Ok::<std::time::Duration, std::time::SystemTimeError>(std::time::Duration::from_millis(js_sys::Date::now() as u64)) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::UNIX_EPOCH.elapsed() } }.unwrap().as_secs() - 2;
 		let payment_params = PaymentParameters::from_node_id(
 				PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap()),
 				0
```

## `src/offers/invoice.rs`

wasm32 time source for BOLT12 invoice expiry checks (`SystemTime::UNIX_EPOCH.elapsed()` → `js_sys::Date::now()` on wasm32). Native unchanged.

```diff
@@ -1057,7 +1057,7 @@
 	fn is_expired(&self) -> bool {
 		let absolute_expiry = self.created_at().checked_add(self.relative_expiry());
 		match absolute_expiry {
-			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
+			Some(seconds_from_epoch) => match { #[cfg(target_arch = "wasm32")] { Ok::<std::time::Duration, std::time::SystemTimeError>(std::time::Duration::from_millis(js_sys::Date::now() as u64)) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::UNIX_EPOCH.elapsed() } } {
 				Ok(elapsed) => elapsed > seconds_from_epoch,
 				Err(_) => false,
 			},
```

## `src/offers/invoice_request.rs`

Same wasm32 time substitution for invoice-request expiry.

```diff
@@ -709,7 +709,7 @@
 	pub fn respond_with(
 		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::now() } }
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
 			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
 
@@ -848,7 +848,7 @@
 	pub fn respond_using_derived_keys(
 		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::now() } }
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
 			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
```

## `src/offers/refund.rs`

Same wasm32 time substitution for refund expiry.

```diff
@@ -47,7 +47,7 @@
 //! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
 //! let pubkey = PublicKey::from(keys);
 //!
-//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
+//! let expiration = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } } + Duration::from_secs(24 * 60 * 60);
 //! let refund = RefundBuilder::new(vec![1; 32], pubkey, 20_000)?
 //!     .description("coffee, large".to_string())
 //!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
@@ -525,7 +525,7 @@
 		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
 		signing_pubkey: PublicKey,
 	) -> Result<$builder, Bolt12SemanticError> {
-		let created_at = std::time::SystemTime::now()
+		let created_at = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::now() } }
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
 			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
 
@@ -583,7 +583,7 @@
 	where
 		ES::Target: EntropySource,
 	{
-		let created_at = std::time::SystemTime::now()
+		let created_at = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { std::time::SystemTime::now() } }
 			.duration_since(std::time::SystemTime::UNIX_EPOCH)
 			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
```

## `src/routing/gossip.rs`

Ten sites where gossip timestamps are read from `SystemTime::now()`; each becomes `js_sys::Date` on wasm32 and is unchanged natively. No change to what is accepted or pruned — only where the clock comes from.

```diff
@@ -589,7 +589,7 @@
 		let mut gossip_start_time = 0;
 		#[cfg(feature = "std")]
 		{
-			gossip_start_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			gossip_start_time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 			if self.should_request_full_sync(&their_node_id) {
 				gossip_start_time -= 60 * 60 * 24 * 7 * 2; // 2 weeks ago
 			} else {
@@ -1705,7 +1705,7 @@
 		let mut announcement_received_time = 0;
 		#[cfg(feature = "std")]
 		{
-			announcement_received_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			announcement_received_time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 		}
 
 		let chan_info = ChannelInfo {
@@ -1731,7 +1731,7 @@
 	/// The channel and any node for which this was their last channel are removed from the graph.
 	pub fn channel_failed_permanent(&self, short_channel_id: u64) {
 		#[cfg(feature = "std")]
-		let current_time_unix = Some(SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
+		let current_time_unix = Some({ #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
 		#[cfg(not(feature = "std"))]
 		let current_time_unix = None;
 
@@ -1754,7 +1754,7 @@
 	/// from local storage.
 	pub fn node_failed_permanent(&self, node_id: &PublicKey) {
 		#[cfg(feature = "std")]
-		let current_time_unix = Some(SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
+		let current_time_unix = Some({ #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
 		#[cfg(not(feature = "std"))]
 		let current_time_unix = None;
 
@@ -1801,7 +1801,7 @@
 	/// This method is only available with the `std` feature. See
 	/// [`NetworkGraph::remove_stale_channels_and_tracking_with_time`] for `no-std` use.
 	pub fn remove_stale_channels_and_tracking(&self) {
-		let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+		let time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 		self.remove_stale_channels_and_tracking_with_time(time);
 	}
 
@@ -1930,7 +1930,7 @@
 		{
 			// Note that many tests rely on being able to set arbitrarily old timestamps, thus we
 			// disable this check during tests!
-			let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			let time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 			if (msg.timestamp as u64) < time - STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS {
 				return Err(LightningError{err: "channel_update is older than two weeks old".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Gossip)});
 			}
@@ -2382,7 +2382,7 @@
 		{
 			use std::time::{SystemTime, UNIX_EPOCH};
 
-			let tracking_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			let tracking_time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 			// Mark a node as permanently failed so it's tracked as removed.
 			gossip_sync.network_graph().node_failed_permanent(&PublicKey::from_secret_key(&secp_ctx, node_1_privkey));
 
@@ -2706,7 +2706,7 @@
 			// so we should add it with a recent timestamp.
 			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_none());
 			use std::time::{SystemTime, UNIX_EPOCH};
-			let announcement_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			let announcement_time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 			let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
 				unsigned_channel_update.timestamp = (announcement_time + 1 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS) as u32;
 			}, node_1_privkey, &secp_ctx);
@@ -2728,7 +2728,7 @@
 		{
 			use std::time::{SystemTime, UNIX_EPOCH};
 
-			let tracking_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+			let tracking_time = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 
 			// Clear tracked nodes and channels for clean slate
 			network_graph.removed_channels.lock().unwrap().clear();
@@ -3007,7 +3007,7 @@
 				MessageSendEvent::SendGossipTimestampFilter{ node_id, msg } => {
 					assert_eq!(node_id, &node_id_1);
 					assert_eq!(msg.chain_hash, chain_hash);
-					let expected_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
+					let expected_timestamp = { #[cfg(target_arch = "wasm32")] { use js_sys::Date; std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(Date::now() as u64) } #[cfg(not(target_arch = "wasm32"))] { SystemTime::now() } }.duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
 					assert!((msg.first_timestamp as u64) >= expected_timestamp - 60*60*24*7*2);
 					assert!((msg.first_timestamp as u64) < expected_timestamp - 60*60*24*7*2 + 10);
 					assert_eq!(msg.timestamp_range, u32::max_value());
```

## `src/util/sweep.rs`

The OutputSweeper never includes a `StaticOutput` in a sweep batch. In this wallet a `StaticOutput` descriptor is only ever a cooperative-close `shutdown_script` / `destination_script` output at an m/84 address the wallet already controls and spends as an ordinary UTXO; the LDK `KeysManager` cannot sign it (no channel key), and one such output in a batch made `spend_spendable_outputs()` fail for the whole all-or-nothing batch, stranding the legitimate `DelayedPaymentOutput` / `StaticPaymentOutput` sweeps beside it. New `StaticOutput`s are already excluded at track time; this skips any tracked earlier. Marked revertable in the code.

```diff
@@ -469,6 +469,25 @@
 		let cur_height = sweeper_state.best_block.height;
 		let cur_hash = sweeper_state.best_block.block_hash;
 		let filter_fn = |o: &TrackedSpendableOutput| {
+			// ─── LIJ PATCH v150 (REVERTABLE) ─────────────────────────────────
+			// Never include a StaticOutput in a sweep batch. In LiJ, StaticOutput
+			// descriptors are emitted only for coop-close shutdown_script /
+			// destination_script — both at an m/84 address LiJ already controls,
+			// already spendable as a normal wallet UTXO, with NO sweep needed.
+			// The KeysManager cannot sign them (no channel key), so including one
+			// makes spend_spendable_outputs() fail for the ENTIRE batch (it is
+			// all-or-nothing), stranding the legitimate DelayedPaymentOutput /
+			// StaticPaymentOutput sweeps batched alongside it. New StaticOutputs
+			// are already excluded at track time (exclude_static_outputs=true,
+			// v128), but a StaticOutput tracked BEFORE that flap persists in the
+			// state and poisons every batch. Skipping it here is safe (LiJ never
+			// sweeps StaticOutputs) and unblocks the real sweeps.
+			// TO REVERT: delete this block only.
+			if matches!(o.descriptor, SpendableOutputDescriptor::StaticOutput { .. }) {
+				return false;
+			}
+			// ─── END LIJ PATCH v150 ──────────────────────────────────────────
+
 			if o.status.is_confirmed() {
 				// Don't rebroadcast confirmed txs.
 				return false;
```
