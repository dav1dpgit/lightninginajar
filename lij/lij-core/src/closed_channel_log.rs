// closed_channel_log.rs
// Persistent log of closed channels, stored in localStorage.
//
// Used by:
//   - background_tick (8c.2): appends a record when Event::ChannelClosed fires
//   - Channel Management UI (8d): displays the closed-channels list
//   - Future onchain watch (8c.2b): polls funding_txo to find closing tx
//
// Storage: a single localStorage key holds a JSON array of records.
// Append-only — we do not delete records (user retains a complete history
// for tax / audit / privacy reasons). User can clear via dev tools if needed.
//
// Per-record cost: ~300 bytes JSON. localStorage typically allows 5-10 MB,
// so we can store ~30,000 records before any size concern. In practice users
// will have < 100 records over the wallet's lifetime.
//
// Resolution of closing txid + destination address:
//   The Event::ChannelClosed payload from LDK does NOT include the closing
//   txid. We persist the channel_funding_txo so the closing tx can be
//   located later via the independent path (8c.2b — onchain watch). The
//   destination address is recoverable via the same path: scan the closing
//   tx outputs and match against known BIP84 / m/525h addresses. Stored
//   separately when 8c.2b resolves them.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    error::{LijError, LijResult},
    storage::LijStorage,
};

/// localStorage key for the closed-channel log.
pub const KEY_CLOSED_CHANNELS: &str = "lij_closed_channels";

/// How a channel was closed, from LiJ's perspective.
/// Maps from LDK's ClosureReason + our outstanding_close_attempts state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseKind {
    /// User cooperatively closed (or LSP cooperatively closed and we
    /// auto-accepted). Funds at BIP84 destination, BlueWallet recovers.
    Cooperative,
    /// User force-closed (or counterparty force-closed).
    ///
    /// to_remote address depends on the channel's commitment type — both
    /// share the m/525h/0/0/0/n derivation but differ in script wrapping:
    ///   - STATIC_REMOTE_KEY (LSPS1, non-zero-conf):
    ///       P2WPKH(payment_point), 42-char address.
    ///       BlueWallet custom-path (m/525'/0/0, BIP84) recovers.
    ///   - ANCHORS (LSPS2, all zero-conf JIT):
    ///       P2WSH(<payment_point> CHECKSIGVERIFY 1 CSV), 62-char address.
    ///       NOT BlueWallet-recoverable — needs descriptor sweep
    ///       (Sparrow miniscript wsh(and_v(v:pk(K),older(1)))) or
    ///       LiJ recover_anchor tool, with nSequence>=1.
    /// closed_channel_watcher scans both variants automatically.
    Force,
    /// LDK reported a closure type we don't categorize as either of the
    /// above (e.g. FundingTimedOut, DisconnectedPeer pre-funding).
    /// No funds at risk in these cases.
    Other,
}

/// A single record of a closed channel.
/// JSON-serialized in localStorage. Forward compatible — new fields added as
/// Option<T> so older records deserialize cleanly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClosedChannelRecord {
    /// Hex-encoded LDK channel_id (32 bytes → 64 hex chars).
    pub channel_id_hex: String,
    /// Hex-encoded counterparty pubkey. Used to group records by LSP in UI.
    /// Optional because some closure reasons (e.g. DisconnectedPeer pre-funding)
    /// may not have a counterparty resolved.
    pub counterparty_pubkey_hex: Option<String>,
    /// Plain-language description of the close reason. Survived from LDK's
    /// ClosureReason via Display, plus our user-/LSP-initiated context.
    pub reason_description: String,
    /// Categorized for UI grouping and recovery hints.
    pub kind: CloseKind,
    /// Unix seconds when the close event arrived (NOT when it was initiated).
    pub closed_at_unix_secs: u64,
    /// Channel capacity in satoshis, if LDK reported it (None for very old
    /// LDK serialization formats).
    pub channel_capacity_sats: Option<u64>,
    /// v178: whether the channel was terminus-pinned (to_remote pays m/84
    /// directly — closes DELIVER rather than sweep). Option for backward
    /// deserialization of pre-v178 records (None = unknown/legacy).
    #[serde(default)]
    pub terminus_pinned: Option<bool>,
    /// Hex-encoded funding outpoint (txid:vout). Used to locate the
    /// closing tx via onchain watch (8c.2b).
    pub funding_txo_hex: Option<String>,
    /// Resolved closing txid, if onchain watch has located it.
    /// None until 8c.2b finds the tx that spent funding_txo_hex.
    pub closing_txid_hex: Option<String>,
    /// Destination address where funds will/did land. Resolved by onchain
    /// watch in 8c.2b. Format depends on close kind and (for Force)
    /// the channel's commitment type:
    ///   - Cooperative: P2WPKH at m/84'/0'/0'/0/n (42 chars)
    ///   - Force, STATIC_REMOTE_KEY: P2WPKH at m/525'/0/0/0/n (42 chars)
    ///   - Force, ANCHORS:           P2WSH-anchor at m/525'/0/0/0/n
    ///       (62 chars; script = <K> CHECKSIGVERIFY 1 CSV)
    /// None until resolved.
    pub destination_address: Option<String>,
    /// Resolved sweep txid — the tx that spent our to_local output of the
    /// closing tx (the force-close CSV sweep to BIP84). Resolved by the
    /// background sweep walker: the outspend of the closing-tx output paying
    /// `destination_address`. None until that sweep confirms; stays None for
    /// cooperative closes (which pay BIP84 directly, with no separate sweep).
    /// Forward-compatible Option (older records deserialize to None).
    pub sweep_txid_hex: Option<String>,
    /// S45: raw hex of the cooperative closing transaction THIS wallet signed
    /// and broadcast (taken from the broadcaster's ring at ChannelClosed time),
    /// so a restart can hold LDK's commitment broadcast and rebroadcast this.
    #[serde(default)]
    pub coop_close_tx_hex: Option<String>,
    /// S45: txid of the latest holder commitment at close time (monitor's
    /// read-only escape export). The watcher compares the CONFIRMED spend to
    /// it and relabels a cooperative record that lost the race as Force.
    #[serde(default)]
    pub holder_commitment_txid_hex: Option<String>,
    /// S45: true once a spend of the funding output has CONFIRMED. Before that
    /// `closing_txid_hex` is the INTENDED closing tx (seen in the mempool);
    /// after, the ACTUAL one.
    #[serde(default)]
    pub closing_confirmed: bool,
    /// S45: chain tip when the close was recorded; the hold's 144-block
    /// ceiling counts from here.
    #[serde(default)]
    pub close_seen_height: Option<u32>,
    /// S45: the wallet released the hold (ceiling or mempool eviction) and
    /// broadcast the holder commitment itself.
    #[serde(default)]
    pub hold_released: bool,
    /// S45: txid of the CPFP child the wallet broadcast to pull a slow
    /// cooperative close in (spends the coop tx's output to our address).
    #[serde(default)]
    pub cpfp_txid_hex: Option<String>,
    /// S45: tip at the last CPFP attempt (success or failure) — retries are
    /// spaced, never per tick.
    #[serde(default)]
    pub cpfp_last_height: Option<u32>,
}

/// Append-only log of closed channels.
pub struct ClosedChannelLog {
    storage: Arc<dyn LijStorage>,
}

impl ClosedChannelLog {
    pub fn new(storage: Arc<dyn LijStorage>) -> Self {
        Self { storage }
    }

    /// Append a record to the log. Reads the current array, appends, writes
    /// back. Not concurrency-safe across multiple ClosedChannelLog instances —
    /// but that doesn't happen in our architecture (single instance per node).
    pub fn append(&self, record: ClosedChannelRecord) -> LijResult<()> {
        let mut records = self.list()?;
        records.push(record);
        let json = serde_json::to_string(&records)
            .map_err(|e| LijError::Storage(format!("Closed log serialize: {e}")))?;
        self.storage.set(KEY_CLOSED_CHANNELS, json.as_bytes())?;
        Ok(())
    }

    /// Read all records. Returns empty vec if no records yet or if storage
    /// returned None.
    pub fn list(&self) -> LijResult<Vec<ClosedChannelRecord>> {
        match self.storage.get(KEY_CLOSED_CHANNELS)? {
            Some(bytes) => {
                let s = std::str::from_utf8(&bytes).map_err(|e| {
                    LijError::Storage(format!("Closed log not valid UTF-8: {e}"))
                })?;
                serde_json::from_str(s)
                    .map_err(|e| LijError::Storage(format!("Closed log parse: {e}")))
            }
            None => Ok(Vec::new()),
        }
    }

    /// Closing txids of every logged close — used to tag on-chain receives that
    /// are capacity returning from a channel close. Best-effort: returns an
    /// empty set on any storage/parse miss so tagging never blocks a sync.
    pub fn closing_txids(storage: &dyn LijStorage) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        if let Ok(Some(bytes)) = storage.get(KEY_CLOSED_CHANNELS) {
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if let Ok(records) = serde_json::from_str::<Vec<ClosedChannelRecord>>(s) {
                    for r in records {
                        if let Some(t) = r.closing_txid_hex {
                            set.insert(t);
                        }
                    }
                }
            }
        }
        set
    }

    /// v180: funding outpoints ("txid:vout") of records that are still BLIND —
    /// closed, but with no closing txid recorded. These are healable from the
    /// chain: whatever spent the funding outpoint IS the closing tx.
    pub fn blind_funding_txos(storage: &dyn LijStorage) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(Some(bytes)) = storage.get(KEY_CLOSED_CHANNELS) {
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if let Ok(records) = serde_json::from_str::<Vec<ClosedChannelRecord>>(s) {
                    for r in records {
                        if r.closing_txid_hex.is_none() {
                            if let Some(txo) = r.funding_txo_hex {
                                out.push(txo);
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// v180: storage-level heal (no Arc needed — mirrors closing_txids' idiom)
    /// so the tier2 sync can fill a blind record's closing txid. None-only fill;
    /// never overwrites a value the close watcher already set.
    pub fn heal_closing_txid(
        storage: &dyn LijStorage,
        funding_txo: &str,
        closing_txid: &str,
    ) -> bool {
        if let Ok(Some(bytes)) = storage.get(KEY_CLOSED_CHANNELS) {
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if let Ok(mut records) = serde_json::from_str::<Vec<ClosedChannelRecord>>(s) {
                    let mut changed = false;
                    for r in records.iter_mut() {
                        if r.funding_txo_hex.as_deref() == Some(funding_txo)
                            && r.closing_txid_hex.is_none()
                        {
                            r.closing_txid_hex = Some(closing_txid.to_string());
                            changed = true;
                        }
                    }
                    if changed {
                        if let Ok(json) = serde_json::to_string(&records) {
                            let _ = storage.set(KEY_CLOSED_CHANNELS, json.as_bytes());
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Update an existing record by channel_id_hex. Used by onchain watch
    /// (8c.2b) to fill in closing_txid and destination_address once
    /// resolved on-chain. Returns Ok(true) if updated, Ok(false) if no
    /// matching record found.
    /// v179: fill a record's closing_txid_hex by funding outpoint
    /// ("txid:vout"), ONLY when currently unset — the funding-spend walker
    /// calls this on every pass where it knows the spending txid, so records
    /// created blind (wallet offline through the mempool window; LSP force
    /// close) heal as soon as the walker runs. Never overwrites a value the
    /// close watcher already set. Returns true when a record was updated.
    pub fn set_closing_txid_by_funding_txo(
        &self,
        funding_txo: &str,
        closing_txid: &str,
    ) -> LijResult<bool> {
        let mut records = self.list()?;
        let idx = records.iter().position(|r| {
            r.funding_txo_hex.as_deref() == Some(funding_txo) && r.closing_txid_hex.is_none()
        });
        match idx {
            Some(i) => {
                records[i].closing_txid_hex = Some(closing_txid.to_string());
                let json = serde_json::to_string(&records)
                    .map_err(|e| LijError::Storage(format!("Closed log serialize: {e}")))?;
                self.storage.set(KEY_CLOSED_CHANNELS, json.as_bytes())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn update_by_channel_id(
        &self,
        channel_id_hex: &str,
        f: impl FnOnce(&mut ClosedChannelRecord),
    ) -> LijResult<bool> {
        let mut records = self.list()?;
        let idx = records
            .iter()
            .position(|r| r.channel_id_hex == channel_id_hex);
        match idx {
            Some(i) => {
                f(&mut records[i]);
                let json = serde_json::to_string(&records)
                    .map_err(|e| LijError::Storage(format!("Closed log serialize: {e}")))?;
                self.storage.set(KEY_CLOSED_CHANNELS, json.as_bytes())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    use crate::storage::native_storage::MemoryStorage;

    fn sample_record() -> ClosedChannelRecord {
        ClosedChannelRecord {
            channel_id_hex: "a".repeat(64),
            counterparty_pubkey_hex: Some("b".repeat(66)),
            reason_description: "user-initiated cooperative close".into(),
            kind: CloseKind::Cooperative,
            closed_at_unix_secs: 1_700_000_000,
            channel_capacity_sats: Some(100_000),
            terminus_pinned: None,
            funding_txo_hex: Some("c".repeat(64) + ":0"),
            closing_txid_hex: None,
            destination_address: None,
            sweep_txid_hex: None,
            coop_close_tx_hex: None,
            holder_commitment_txid_hex: None,
            closing_confirmed: false,
            close_seen_height: None,
            hold_released: false,
            cpfp_txid_hex: None,
            cpfp_last_height: None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fresh_log_returns_empty() {
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let log = ClosedChannelLog::new(storage);
        assert_eq!(log.list().unwrap().len(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn append_and_read_roundtrip() {
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let log = ClosedChannelLog::new(storage);
        log.append(sample_record()).unwrap();
        let records = log.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, CloseKind::Cooperative);
        assert_eq!(records[0].channel_capacity_sats, Some(100_000));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn multiple_appends_preserve_order() {
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let log = ClosedChannelLog::new(storage);
        for i in 0..5 {
            let mut r = sample_record();
            r.channel_id_hex = format!("{:0>64}", i);
            r.closed_at_unix_secs = 1_700_000_000 + i;
            log.append(r).unwrap();
        }
        let records = log.list().unwrap();
        assert_eq!(records.len(), 5);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.closed_at_unix_secs, 1_700_000_000 + i as u64);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn update_by_channel_id_modifies_record() {
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let log = ClosedChannelLog::new(storage);
        log.append(sample_record()).unwrap();

        let updated = log
            .update_by_channel_id(&"a".repeat(64), |r| {
                r.closing_txid_hex = Some("d".repeat(64));
                r.destination_address = Some("bc1qexample".into());
            })
            .unwrap();
        assert!(updated);

        let records = log.list().unwrap();
        assert_eq!(records[0].closing_txid_hex.as_deref(), Some(&*"d".repeat(64)));
        assert_eq!(records[0].destination_address.as_deref(), Some("bc1qexample"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn update_by_channel_id_returns_false_when_not_found() {
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let log = ClosedChannelLog::new(storage);
        log.append(sample_record()).unwrap();
        let updated = log
            .update_by_channel_id("nonexistent", |r| {
                r.closing_txid_hex = Some("x".into());
            })
            .unwrap();
        assert!(!updated);
    }
}
