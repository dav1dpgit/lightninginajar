#![allow(deprecated)]

// closed_channel_watcher.rs
// Background polling watcher that resolves closing_txid_hex and
// destination_address for ClosedChannelRecord entries.
//
// Invoked from background_tick at 60s intervals via spawn_local. For each
// pending record (where closing_txid_hex is None), the watcher:
//   1. Parses funding_txo_hex into (funding_txid, vout)
//   2. Queries Esplora /tx/{funding_txid}/outspends to find what spent vout
//   3. If spent: parses the spending tx outputs and matches against the
//      wallet's BIP84 (m/84'/{coin}h/0'/0/n) and m/525h/0/0/0/n derivation
//      chains to identify the destination address. The m/525h chain is
//      checked under TWO output forms — P2WPKH (STATIC_REMOTE_KEY commit
//      type, e.g. LSPS1) AND P2WSH-anchor wrapping
//      (<pubkey> CHECKSIGVERIFY 1 CSV, anchor commit type, e.g. LSPS2 JIT) —
//      so the same scan catches force-closes of either commitment variant.
//   4. Updates the ClosedChannelRecord via log.update_by_channel_id
//
// Cadence per record: at most once per 60 seconds. Per-record poll state
// (last_polled, consecutive_failures) lives in-memory only — restart
// re-polls all pending records once and stabilizes.
//
// Failure handling: silent (log only). Each pending record gets up to
// MAX_CONSECUTIVE_FAILURES failures before backing off to once-per-hour.
// Eventually consistent — the record stays in the log forever, the
// watcher will eventually find the closing tx if it ever appears
// on-chain via independent path.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    blockdata::{opcodes, script::Builder},
    secp256k1::Secp256k1,
    Address, Network,
};

use crate::{
    closed_channel_log::{ClosedChannelLog, ClosedChannelRecord, CloseKind},
    error::{LijError, LijResult},
    independent::IndependentClient,
    key::RootKey,
};

/// Minimum seconds between polls for a single record under normal operation.
pub const POLL_INTERVAL_SECS: u64 = 60;

/// After this many consecutive failures, back off to BACKOFF_INTERVAL_SECS.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Backoff cadence for records that have repeatedly failed to resolve.
pub const BACKOFF_INTERVAL_SECS: u64 = 3600;

/// In-memory state about a record's polling history.
#[derive(Clone, Debug, Default)]
struct PollState {
    last_polled_unix_secs: u64,
    consecutive_failures: u32,
}

/// Closed-channel watcher. Cloneable across spawn_local calls.
///
/// **Deprecated as of v0.2.0**: superseded by `lightning::util::sweep::OutputSweeper`
/// wired into `LijNode` (see `crate::sweeper`). The OutputSweeper consumes
/// `Event::SpendableOutputs` directly from `ChainMonitor` and sweeps to
/// BIP84 destinations at `m/84'/0'/0'/0/n` without needing the on-chain
/// address-walk this watcher performs.
///
/// Kept compiling for one release cycle as a safety net for any pre-v0.2.0
/// channel state that may still resolve via the m/525 chain. Scheduled for
/// removal in v0.3.0 once Phase 1c (seed-only recovery via LSP registry)
/// covers the offline-recovery scenarios this watcher previously addressed.
#[derive(Clone)]
#[deprecated(
    since = "0.2.0",
    note = "Replaced by lightning::util::sweep::OutputSweeper (see crate::sweeper). \
            Will be removed in v0.3.0 after Phase 1c lands."
)]
pub struct ClosedChannelWatcher {
    poll_state: Arc<Mutex<HashMap<String, PollState>>>,
}

impl ClosedChannelWatcher {
    pub fn new() -> Self {
        Self {
            poll_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Poll all pending records once. Records that were polled in the last
    /// POLL_INTERVAL_SECS (or BACKOFF_INTERVAL_SECS for failing records) are
    /// skipped.
    ///
    /// `current_counter` is the SignerProvider's current counter value —
    /// used as the upper bound for address-matching index walks.
    pub async fn poll_pending_closes(
        &self,
        log: ClosedChannelLog,
        independent: Arc<IndependentClient>,
        root_key: &RootKey,
        network: Network,
        current_counter: u32,
        now_unix_secs: u64,
    ) -> LijResult<()> {
        let records = log.list()?;
        let pending: Vec<ClosedChannelRecord> = records
            .into_iter()
            // S45: keep polling until a spend has CONFIRMED — a txid seen in the
            // mempool is the INTENDED close; the confirmed one is the ACTUAL close
            // and may differ (a commitment overtaking a cooperative tx).
            .filter(|r| (r.closing_txid_hex.is_none() || !r.closing_confirmed) && r.funding_txo_hex.is_some())
            .collect();

        if pending.is_empty() {
            return Ok(());
        }

        // Pre-derive both xprivs and the per-index addresses up to current
        // counter. Reused for every record being polled in this round.
        let shutdown_xpriv = root_key.shutdown_xpriv()?;
        let static_remotekey_xpriv = root_key.static_remotekey_xpriv()?;
        let address_table = build_address_table(
            &shutdown_xpriv,
            &static_remotekey_xpriv,
            current_counter,
            network,
        )?;

        for record in pending {
            // Skip if recently polled
            if !self.should_poll(&record.channel_id_hex, now_unix_secs) {
                continue;
            }

            self.set_polled(&record.channel_id_hex, now_unix_secs);

            let result = self
                .resolve_record(&record, &independent, &address_table, &log, network)
                .await;

            match result {
                Ok(()) => self.clear_failures(&record.channel_id_hex),
                Err(e) => {
                    let failures = self.increment_failures(&record.channel_id_hex);
                    if failures <= MAX_CONSECUTIVE_FAILURES {
                        log::warn!(
                            "closed_channel_watcher: poll failed for {}: {} (failure {}/{})",
                            record.channel_id_hex,
                            e,
                            failures,
                            MAX_CONSECUTIVE_FAILURES
                        );
                    }
                    // After MAX_CONSECUTIVE_FAILURES, log.warn is suppressed.
                    // The record stays pending; next poll attempt happens
                    // after BACKOFF_INTERVAL_SECS.
                }
            }
        }

        Ok(())
    }

    /// Resolve a single record. Returns Ok if either:
    ///   - Resolution succeeded (record updated)
    ///   - The funding output has not been spent yet (no error, just pending)
    /// Returns Err for actual failures (network, parse, etc).
    async fn resolve_record(
        &self,
        record: &ClosedChannelRecord,
        independent: &Arc<IndependentClient>,
        address_table: &AddressTable,
        log: &ClosedChannelLog,
        network: Network,
    ) -> LijResult<()> {
        let funding_txo_hex = record.funding_txo_hex.as_ref().ok_or_else(|| {
            LijError::Storage("Record has no funding_txo_hex".into())
        })?;

        let (funding_txid, funding_vout) = parse_outpoint(funding_txo_hex)?;

        // Query outspends for the funding tx
        let outspends = independent
            .fetch_tx_outspends(&funding_txid)
            .await?;

        let spend_info = outspends
            .into_iter()
            .nth(funding_vout as usize)
            .ok_or_else(|| {
                LijError::Lsp(format!(
                    "outspends array shorter than funding vout index {}",
                    funding_vout
                ))
            })?;

        if !spend_info.spent {
            // Funding output not yet spent — closing tx hasn't confirmed.
            return Ok(());
        }

        let spending_txid = spend_info.txid.ok_or_else(|| {
            LijError::Lsp("outspends reports spent=true but no txid".into())
        })?;
        // S45: mempool spend = intended; confirmed spend = actual.
        let confirmed = spend_info.status.as_ref().map(|s| s.confirmed).unwrap_or(false);
        // A cooperative record whose CONFIRMED spend is not the tx it intended
        // lost the race to a commitment.
        let lost_race = confirmed
            && matches!(record.kind, CloseKind::Cooperative)
            && record
                .closing_txid_hex
                .as_deref()
                .map(|t| t != spending_txid.as_str())
                .unwrap_or(false);

        // Fetch the spending tx so we can read its outputs.
        let spending_tx = independent.fetch_tx(&spending_txid).await?;

        // Walk outputs and find the one that matches our derivation chains.
        let mut matched_address: Option<String> = None;
        for vout in &spending_tx.vouts {
            if let Some(addr) = address_table.match_script(&vout.scriptpubkey, network) {
                matched_address = Some(addr);
                break;
            }
        }

        // S45: is the confirmed close OUR commitment? Exact when the record
        // carries the holder commitment txid (v233+). For older records under
        // Terminus the shape decides: the LSP's commitment pays our side to
        // m/84 directly (an address of ours matches), ours pays through the
        // timelocked script (nothing matches).
        let ours_commitment = confirmed
            && (record.holder_commitment_txid_hex.as_deref() == Some(spending_txid.as_str())
                || (lost_race && matched_address.is_none()));

        let final_destination = matched_address
            .unwrap_or_else(|| "unmatched - check on-chain".to_string());

        // S45: when our own commitment closed the channel, follow its timelocked
        // output to the sweep that landed the money — the output(s) that match
        // none of our addresses are the to_local / HTLC scripts; their spender
        // paying one of our addresses is the sweep.
        let mut sweep_txid: Option<String> = None;
        if ours_commitment {
            if let Ok(spends) = independent.fetch_tx_outspends(&spending_txid).await {
                for (i, vout) in spending_tx.vouts.iter().enumerate() {
                    if address_table.match_script(&vout.scriptpubkey, network).is_some() {
                        continue;
                    }
                    if let Some(sp) = spends.get(i) {
                        if sp.spent {
                            if let Some(t) = sp.txid.as_ref() {
                                sweep_txid = Some(t.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        log.update_by_channel_id(&record.channel_id_hex, |r| {
            r.closing_txid_hex = Some(spending_txid.clone());
            r.closing_confirmed = confirmed;
            if r.destination_address.is_none() || confirmed {
                r.destination_address = Some(final_destination.clone());
            }
            if ours_commitment && !matches!(r.kind, CloseKind::Force) {
                r.kind = CloseKind::Force;
                r.reason_description = format!(
                    "force close from this wallet: the cooperative close did not confirm and the wallet's commitment took its place (was: {})",
                    r.reason_description
                );
            }
            if sweep_txid.is_some() && r.sweep_txid_hex.is_none() {
                r.sweep_txid_hex = sweep_txid.clone();
            }
        })?;

        log::info!(
            "closed_channel_watcher: {} {} → closing_txid={} confirmed={} ours_commitment={} sweep={} dest={}",
            if confirmed { "resolved" } else { "pending" },
            record.channel_id_hex, spending_txid, confirmed, ours_commitment,
            sweep_txid.as_deref().unwrap_or("-"), final_destination
        );

        Ok(())
    }

    fn should_poll(&self, channel_id_hex: &str, now: u64) -> bool {
        let state = self.poll_state.lock().unwrap();
        match state.get(channel_id_hex) {
            None => true,
            Some(ps) => {
                let interval = if ps.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    BACKOFF_INTERVAL_SECS
                } else {
                    POLL_INTERVAL_SECS
                };
                now.saturating_sub(ps.last_polled_unix_secs) >= interval
            }
        }
    }

    fn set_polled(&self, channel_id_hex: &str, now: u64) {
        let mut state = self.poll_state.lock().unwrap();
        let entry = state
            .entry(channel_id_hex.to_string())
            .or_default();
        entry.last_polled_unix_secs = now;
    }

    fn increment_failures(&self, channel_id_hex: &str) -> u32 {
        let mut state = self.poll_state.lock().unwrap();
        let entry = state
            .entry(channel_id_hex.to_string())
            .or_default();
        entry.consecutive_failures += 1;
        entry.consecutive_failures
    }

    fn clear_failures(&self, channel_id_hex: &str) {
        let mut state = self.poll_state.lock().unwrap();
        if let Some(entry) = state.get_mut(channel_id_hex) {
            entry.consecutive_failures = 0;
        }
    }
}

impl Default for ClosedChannelWatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── Address matching ────────────────────────────────────────────────────────

/// Pre-computed table mapping P2WPKH scriptpubkey hex → (path_kind, index, address).
/// Built once per poll round to avoid re-deriving for every output of every
/// closing tx of every record.
struct AddressTable {
    /// Map from script pubkey hex (40 hex chars: OP_0 + 20-byte hash) to address.
    by_script_hex: HashMap<String, String>,
}

impl AddressTable {
    fn match_script(&self, script_hex: &str, _network: Network) -> Option<String> {
        self.by_script_hex.get(script_hex).cloned()
    }
}

fn build_address_table(
    shutdown_xpriv: &ExtendedPrivKey,
    static_remotekey_xpriv: &ExtendedPrivKey,
    max_index: u32,
    network: Network,
) -> LijResult<AddressTable> {
    let secp = Secp256k1::new();
    let mut by_script_hex = HashMap::new();

    for n in 0..=max_index {
        // BIP84 cooperative path
        let coop_child = shutdown_xpriv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![ChildNumber::from_normal_idx(n)
                    .map_err(|e| LijError::Key(format!("Bad child {n}: {e}")))?]),
            )
            .map_err(|e| LijError::Key(format!("coop derive {n}: {e}")))?;
        let coop_pubkey = bitcoin::PublicKey::new(coop_child.private_key.public_key(&secp));
        let coop_address = Address::p2wpkh(&coop_pubkey, network)
            .map_err(|e| LijError::Key(format!("coop p2wpkh: {e}")))?;
        let coop_script_hex = hex::encode(coop_address.script_pubkey().as_bytes());
        by_script_hex.insert(coop_script_hex, coop_address.to_string());

        // m/525h force-close path — P2WPKH variant (STATIC_REMOTE_KEY channels, e.g. LSPS1)
        let fc_child = static_remotekey_xpriv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![ChildNumber::from_normal_idx(n)
                    .map_err(|e| LijError::Key(format!("Bad child {n}: {e}")))?]),
            )
            .map_err(|e| LijError::Key(format!("fc derive {n}: {e}")))?;
        let fc_pubkey = bitcoin::PublicKey::new(fc_child.private_key.public_key(&secp));
        let fc_address = Address::p2wpkh(&fc_pubkey, network)
            .map_err(|e| LijError::Key(format!("fc p2wpkh: {e}")))?;
        let fc_script_hex = hex::encode(fc_address.script_pubkey().as_bytes());
        by_script_hex.insert(fc_script_hex, fc_address.to_string());

        // m/525h force-close path — P2WSH-anchor variant (ANCHORS channels, e.g. LSPS2)
        //
        // Same private key as the P2WPKH variant above, but the to_remote
        // output on an ANCHORS commitment is wrapped behind a witness script:
        //
        //   <payment_point> OP_CHECKSIGVERIFY 1 OP_CSV
        //
        // and then P2WSH'd. See BOLT 3 (option_anchors_zero_fee_htlc_tx).
        // We scan for both variants so the watcher detects either commit type
        // without needing to know which was used per-channel. Cheap insurance:
        // one extra address per index, no risk of collision since P2WPKH and
        // P2WSH script hashes can't coincide.
        let anchor_redeem = Builder::new()
            .push_slice(fc_pubkey.inner.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_int(1)
            .push_opcode(opcodes::all::OP_CSV)
            .into_script();
        let fc_anchor_address = Address::p2wsh(&anchor_redeem, network);
        let fc_anchor_script_hex = hex::encode(fc_anchor_address.script_pubkey().as_bytes());
        by_script_hex.insert(fc_anchor_script_hex, fc_anchor_address.to_string());
    }

    Ok(AddressTable { by_script_hex })
}

// ── Outpoint parsing ────────────────────────────────────────────────────────

fn parse_outpoint(outpoint_hex: &str) -> LijResult<(String, u32)> {
    let mut parts = outpoint_hex.split(':');
    let txid = parts
        .next()
        .ok_or_else(|| LijError::Storage("Empty outpoint".into()))?
        .to_string();
    let vout_str = parts
        .next()
        .ok_or_else(|| LijError::Storage("Outpoint missing vout".into()))?;
    let vout: u32 = vout_str
        .parse()
        .map_err(|e| LijError::Storage(format!("Bad vout: {e}")))?;
    Ok((txid, vout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    fn test_root() -> RootKey {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse()
                .unwrap();
        RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap()
    }

    #[test]
    fn parse_outpoint_works() {
        let (txid, vout) = parse_outpoint("abc123:5").unwrap();
        assert_eq!(txid, "abc123");
        assert_eq!(vout, 5);
    }

    #[test]
    fn parse_outpoint_rejects_bad_vout() {
        assert!(parse_outpoint("abc123:notanumber").is_err());
    }

    #[test]
    fn parse_outpoint_rejects_no_separator() {
        assert!(parse_outpoint("abc123").is_err());
    }

    #[test]
    fn address_table_includes_known_pinned_address() {
        let root = test_root();
        let shutdown_xpriv = root.shutdown_xpriv().unwrap();
        let static_remotekey_xpriv = root.static_remotekey_xpriv().unwrap();
        let table = build_address_table(
            &shutdown_xpriv,
            &static_remotekey_xpriv,
            5,
            Network::Bitcoin,
        )
        .unwrap();

        // Known coop address at index 0 (verified against BlueWallet)
        let coop_addr_0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let coop_script = bitcoin::Address::from_str(coop_addr_0)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        let coop_script_hex = hex::encode(coop_script.as_bytes());
        let matched = table.match_script(&coop_script_hex, Network::Bitcoin);
        assert_eq!(matched.as_deref(), Some(coop_addr_0));

        // Known fc address at index 0
        let fc_addr_0 = "bc1qrffjk8zt6uqsv376pfeqkz524llh425m96neru";
        let fc_script = bitcoin::Address::from_str(fc_addr_0)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        let fc_script_hex = hex::encode(fc_script.as_bytes());
        let matched = table.match_script(&fc_script_hex, Network::Bitcoin);
        assert_eq!(matched.as_deref(), Some(fc_addr_0));
    }

    #[test]
    fn address_table_returns_none_for_unknown_script() {
        let root = test_root();
        let shutdown_xpriv = root.shutdown_xpriv().unwrap();
        let static_remotekey_xpriv = root.static_remotekey_xpriv().unwrap();
        let table = build_address_table(
            &shutdown_xpriv,
            &static_remotekey_xpriv,
            5,
            Network::Bitcoin,
        )
        .unwrap();
        // Random unrelated script
        let unrelated_hex = "0014000102030405060708090a0b0c0d0e0f1011121314";
        assert_eq!(table.match_script(unrelated_hex, Network::Bitcoin), None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn watcher_should_poll_initially() {
        let watcher = ClosedChannelWatcher::new();
        assert!(watcher.should_poll("abc", 1000));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn watcher_skips_recently_polled() {
        let watcher = ClosedChannelWatcher::new();
        watcher.set_polled("abc", 1000);
        assert!(!watcher.should_poll("abc", 1030)); // 30s < 60s interval
        assert!(watcher.should_poll("abc", 1061)); // 61s > 60s interval
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn watcher_backs_off_after_max_failures() {
        let watcher = ClosedChannelWatcher::new();
        watcher.set_polled("abc", 1000);
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            watcher.increment_failures("abc");
        }
        // Within backoff window — should NOT poll
        assert!(!watcher.should_poll("abc", 1000 + POLL_INTERVAL_SECS + 1));
        // After backoff interval — should poll
        assert!(watcher.should_poll("abc", 1000 + BACKOFF_INTERVAL_SECS + 1));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn watcher_clear_failures_resets_to_normal_cadence() {
        let watcher = ClosedChannelWatcher::new();
        watcher.set_polled("abc", 1000);
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            watcher.increment_failures("abc");
        }
        watcher.clear_failures("abc");
        // Should be back to normal POLL_INTERVAL_SECS
        assert!(watcher.should_poll("abc", 1000 + POLL_INTERVAL_SECS + 1));
    }

    use std::str::FromStr;
}
