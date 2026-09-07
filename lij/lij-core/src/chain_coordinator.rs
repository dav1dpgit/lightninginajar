//! Chain Coordinator — single authoritative path for chain data flowing into LDK.
//!
//! Phase 3.7.A — addresses the race condition where multiple chain sources
//! (cooperative bridge from LSP + independent Esplora monitor) can disagree
//! and call LDK's `Confirm` interface in incompatible orders, triggering
//! unwanted unconfirmation events.
//!
//! ## Safety invariants enforced here
//!
//! 1. **Only `ingest_bridge_*` methods produce LDK chain actions on the
//!    normal path.** The independent path's verify-only entry point
//!    (`ingest_independent_tx_status`) never produces a `PendingLdkAction`.
//!    The single explicit exception is the admin-only recovery path
//!    `ingest_independent_confirmation`, used when the cooperative bridge
//!    has no protocol message for the situation (today: offline force-close
//!    detection, where no `ClosingTxObserved` message exists). That path
//!    is gated to recovery callers in `node.rs` and is logged at WARN.
//!
//! 2. **`transaction_unconfirmed` is never automatic.** Only via the
//!    explicit `force_unconfirm(txid, reason)` admin path. Yesterday's
//!    bug was an automatic unconfirm; this invariant prevents recurrence.
//!
//! 3. **`best_block_updated` is monotonic.** Stale tips are dropped silently
//!    with a `BridgeTipStaleDropped` event for diagnostics.
//!
//! 4. **Once a tx is confirmed, it stays confirmed** (in coordinator state)
//!    unless `force_unconfirm` is called. Independent disagreements log a
//!    warning but never override a bridge confirmation.
//!
//! 5. **Independent verify-only observations log at WARN when they disagree**
//!    with authoritative state, but never act on LDK. The recovery path in
//!    invariant #1 is the only exception and tracks its own audit reason.
//!
//! ## Lock duration discipline
//!
//! `ingest_*` methods do *not* call LDK. They return `PendingLdkAction`
//! describing what call to make. The caller is expected to drop the
//! coordinator's mutex before invoking `action.apply(...)`. This keeps the
//! coordinator's lock held only for synchronous internal state updates.
//!
//! ## Hydration (Option B from design)
//!
//! At construction, `hydrate_from_channels` is called with confirmed-channel
//! metadata derived from existing LDK state (channel `short_channel_id`s
//! decompose to height and tx_index). This populates `confirmed_txs` so
//! that any independent observation about those txs cannot trigger a
//! warning that escalates to action — the bridge confirmation is treated
//! as pre-existing.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Replaces std::time::Instant::now() — Instant panics on wasm32-unknown-unknown
/// (no platform time impl). Uses js_sys::Date::now() on wasm32, SystemTime math
/// on native. Established LiJ pattern (see vendored LDK files patched in be35931).
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    }
}

use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};

use lightning::chain::Confirm;

/// Source attribution for confirmation data and chain events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSource {
    /// Bridge events delivered via the cooperative chain protocol from LSP.
    CooperativeBridge,
    /// Esplora HTTP polling from the wallet's independent path.
    /// Verify-only on the standard path (`ingest_independent_tx_status`).
    /// On the recovery admin path (`ingest_independent_confirmation`,
    /// used today only for offline force-close detection), independent
    /// observations are promoted to authoritative — see invariant #1
    /// in the module-level docs.
    IndependentEsplora,
    /// Self-originated (broadcast tx).
    Local,
    /// Recovered from persisted LDK state at coordinator construction.
    /// Treated as authoritative-by-precedent and protected against unconfirm.
    Hydrated,
}

/// Authoritative confirmation record for a watched transaction.
#[derive(Debug, Clone)]
pub struct ConfirmationData {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    pub tx_index: u32,
    /// Raw serialized tx bytes. Empty for hydrated entries (we don't
    /// re-fetch the raw tx at startup).
    pub raw_tx: Vec<u8>,
    pub source: ChainSource,
}

/// Bridge-delivered confirmation payload (decoded from `FundingTxConfirmed`).
#[derive(Debug, Clone)]
pub struct BridgeConfirmation {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    pub tx_index: u32,
    pub raw_tx: Vec<u8>,
    pub block_header: BlockHeader,
    pub confirmations: u32,
}

/// Independent-path confirmation payload. Mirrors `BridgeConfirmation` but
/// sources the data from the wallet's Esplora quorum rather than the LSP.
///
/// Used in the offline force-close recovery path: when the wallet comes
/// back online and detects via outspends that one of its funding outpoints
/// has been spent, it assembles this struct and calls
/// `ingest_independent_confirmation` to feed the spending tx into LDK so
/// the channel can transition to closed. The cooperative bridge protocol
/// has no `ClosingTxObserved` message today, so this is the only path that
/// can resolve offline force-closes automatically (option 1 from the
/// 2026-05-20 handoff).
#[derive(Debug, Clone)]
pub struct IndependentConfirmation {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    pub tx_index: u32,
    pub raw_tx: Vec<u8>,
    pub block_header: BlockHeader,
    /// Free-form audit string explaining why this independent observation
    /// is being promoted to authoritative. Logged and recorded in the
    /// coordinator's event ring so the decision is reviewable later.
    pub reason: String,
}

/// Tx status as observed by an external source (used by independent path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Confirmed { height: u32 },
    Unconfirmed,
    NotFound,
}

/// Diagnostic event recorded in the coordinator's ring buffer.
#[derive(Debug, Clone)]
pub enum ChainEvent {
    /// v200 (DP ratchet ruling, 29 Jul): a BestBlockUpdated candidate
    /// arrived BELOW the wallet-level floor and was dropped at the mint.
    /// Source-agnostic — this is why two individually-monotonic lanes can
    /// no longer be jointly non-monotonic toward LDK.
    BestBlockRatchetDropped { source: String, height: u32, floor: u32 },
    Hydrated { txid_count: usize },
    BridgeTipAdvanced { from_height: u32, to_height: u32, hash: BlockHash },
    BridgeTipStaleDropped { received_height: u32, current_height: u32 },
    BridgeConfirmation { txid: Txid, height: u32, tx_index: u32 },
    BridgeBlockHeader { height: u32 },
    IndependentTipObserved { height: u32, hash: BlockHash, agrees_with_bridge: bool },
    IndependentTxStatusObserved { txid: Txid, status: TxStatus, conflicts_with_authoritative: bool },
    /// Independent observation promoted to authoritative confirmation
    /// (offline force-close recovery path). Distinct from
    /// `IndependentTxStatusObserved` which is verify-only.
    IndependentConfirmation { txid: Txid, height: u32, reason: String },
    AdminForceUnconfirm { txid: Txid, reason: String },
    WatchTxRegistered { txid: Txid },
    WatchOutputRegistered { txid: Txid, vout: u32 },
}

/// Action that the caller must apply to LDK after dropping the
/// coordinator's mutex. Use [`PendingLdkAction::apply`].
#[derive(Debug, Clone)]
pub enum PendingLdkAction {
    /// No LDK call required.
    None,
    /// Call `transactions_confirmed` on both monitor and manager.
    TransactionsConfirmed {
        header: BlockHeader,
        txdata: Vec<(usize, Transaction)>,
        height: u32,
    },
    /// Call `best_block_updated` on both monitor and manager.
    BestBlockUpdated {
        header: BlockHeader,
        height: u32,
    },
    /// Call `transaction_unconfirmed` on both monitor and manager.
    /// Only emitted via [`ChainCoordinator::force_unconfirm`].
    TransactionUnconfirmed {
        txid: Txid,
    },
}

impl PendingLdkAction {
    /// Apply the action to LDK targets. Caller must NOT hold the
    /// coordinator's mutex during this call.
    ///
    /// `output_sweeper` is optional. When `Some`, the action is also applied
    /// to the sweeper — required so OutputSweeper's internal
    /// `regenerate_spend_if_necessary` fires on every block update (it only
    /// runs from `best_block_updated_internal`, so without this wiring the
    /// sweeper never builds a sweep transaction). `None` is accepted to
    /// support legacy / test callers that don't have a sweeper attached.
    pub fn apply<C1, C2>(
        &self,
        chain_monitor: &C1,
        channel_manager: &C2,
        output_sweeper: Option<&dyn Confirm>,
    )
    where
        C1: Confirm + ?Sized,
        C2: Confirm + ?Sized,
    {
        match self {
            Self::None => {}
            Self::TransactionsConfirmed { header, txdata, height } => {
                let tx_refs: Vec<(usize, &Transaction)> =
                    txdata.iter().map(|(i, t)| (*i, t)).collect();
                chain_monitor.transactions_confirmed(header, &tx_refs, *height);
                channel_manager.transactions_confirmed(header, &tx_refs, *height);
                if let Some(s) = output_sweeper {
                    s.transactions_confirmed(header, &tx_refs, *height);
                }
            }
            Self::BestBlockUpdated { header, height } => {
                chain_monitor.best_block_updated(header, *height);
                channel_manager.best_block_updated(header, *height);
                if let Some(s) = output_sweeper {
                    s.best_block_updated(header, *height);
                }
            }
            Self::TransactionUnconfirmed { txid } => {
                chain_monitor.transaction_unconfirmed(txid);
                channel_manager.transaction_unconfirmed(txid);
                if let Some(s) = output_sweeper {
                    s.transaction_unconfirmed(txid);
                }
            }
        }
    }

    /// True when no LDK call is required.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// Snapshot of coordinator state for diagnostics / dump endpoints.
#[derive(Debug, Clone)]
pub struct ChainStateSnapshot {
    pub tip_height: u32,
    pub tip_hash: BlockHash,
    pub confirmed_tx_count: usize,
    pub watched_tx_count: usize,
    pub watched_output_count: usize,
    pub last_bridge_update_secs_ago: Option<u64>,
    pub last_independent_update_secs_ago: Option<u64>,
    /// Phase 3.7.L: Bridge-observed tip (real LSP-claimed chain tip). None
    /// until first cooperative dispatch.
    pub bridge_observed_tip: Option<(u32, BlockHash)>,
}

const MAX_EVENT_LOG_SIZE: usize = 256;

/// The single authoritative chain data router.
pub struct ChainCoordinator {
    // Authoritative chain state. Only mutated by `ingest_bridge_*` and
    // by hydration at construction.
    tip_height: u32,
    tip_hash: BlockHash,
    confirmed_txs: HashMap<Txid, ConfirmationData>,

    // Watch list — mirror of LDK chain_filter registrations.
    watched_txs: HashMap<Txid, ScriptBuf>,
    watched_outputs: HashMap<(Txid, u32), ScriptBuf>,

    // Source health.
    last_bridge_update: Option<f64>,
    last_independent_update: Option<f64>,

    // Phase 3.7.L: Bridge-observed tip from cooperative ChainDataBundle /
    // BlockHeightUpdate dispatches. Verification-only — does NOT drive LDK's
    // best_block_updated and is kept separate from `tip_height`/`tip_hash`,
    // which are the synthetic-header FundingTxConfirmed +6 path that 3.7.G's
    // monotonic floor logic operates on. The two paths must not interact.
    bridge_observed_tip: Option<(u32, BlockHash)>,

    // v200 (DP ruling): THE WALLET-LEVEL RATCHET. Every BestBlockUpdated
    // action — regardless of which lane mints it — must be >= this floor.
    // Seeded from LDK's persisted best at boot; advanced by every emitted
    // action. Strictly-lower candidates are dropped with a recorder event;
    // EQUAL height passes (same-height reorg hashes must still propagate).
    // Root cause of record: the tip lane and the header lane each guarded
    // against their OWN floor (bridge_observed_tip vs tip_height) — each
    // monotonic alone, jointly non-monotonic, stepping LDK backward one
    // block and reading 1-conf fundings as 0 confs.
    ldk_best_floor: Option<u32>,

    // Diagnostic ring buffer.
    event_log: VecDeque<ChainEvent>,
}

impl ChainCoordinator {
    /// Construct an empty coordinator at the given chain tip.
    /// Hydration is a separate step: see [`hydrate_from_channels`].
    pub fn new(initial_tip_height: u32, initial_tip_hash: BlockHash) -> Self {
        Self {
            tip_height: initial_tip_height,
            tip_hash: initial_tip_hash,
            confirmed_txs: HashMap::new(),
            watched_txs: HashMap::new(),
            watched_outputs: HashMap::new(),
            last_bridge_update: None,
            last_independent_update: None,
            bridge_observed_tip: None,
            ldk_best_floor: None,
            event_log: VecDeque::with_capacity(MAX_EVENT_LOG_SIZE),
        }
    }

    /// Hydrate confirmed-tx state from existing LDK channel data.
    /// Each tuple is `(funding_txid, height_from_scid, tx_index_from_scid)`.
    /// This is Option B from the design — defensive hydration so that
    /// existing channels' funding-tx confirmations are protected from
    /// accidental unconfirm via independent disagreement.
    pub fn hydrate_from_channels(&mut self, channels: Vec<(Txid, u32, u32)>) {
        let count = channels.len();
        for (txid, height, tx_index) in channels {
            let data = ConfirmationData {
                txid,
                height,
                // We don't have the block hash from SCID alone. Placeholder
                // is acceptable here: this entry's role is to *prevent*
                // unconfirm, not to be re-fed to LDK.
                block_hash: BlockHash::all_zeros(),
                tx_index,
                raw_tx: Vec::new(),
                source: ChainSource::Hydrated,
            };
            self.confirmed_txs.insert(txid, data);
        }
        self.push_event(ChainEvent::Hydrated { txid_count: count });
        log::info!("[ChainCoordinator] hydrated with {count} confirmed funding txs");
    }

    // ── Bridge ingestion (authoritative) ────────────────────────────────

    /// Bridge advanced the chain tip. Returns the LDK action to apply.
    /// Stale (lower or equal) heights are dropped silently.
    pub fn ingest_bridge_tip(
        &mut self,
        height: u32,
        hash: BlockHash,
        header: BlockHeader,
    ) -> PendingLdkAction {
        self.last_bridge_update = Some(now_ms());

        if height <= self.tip_height {
            self.push_event(ChainEvent::BridgeTipStaleDropped {
                received_height: height,
                current_height: self.tip_height,
            });
            return PendingLdkAction::None;
        }

        let from_height = self.tip_height;
        self.tip_height = height;
        self.tip_hash = hash;
        self.push_event(ChainEvent::BridgeTipAdvanced {
            from_height,
            to_height: height,
            hash,
        });

        self.emit_best_block("bridge_tip", header, height)
    }

    /// Bridge delivered a confirmation event for a watched tx.
    /// Returns the LDK action to apply.
    pub fn ingest_bridge_conf(&mut self, conf: BridgeConfirmation) -> PendingLdkAction {
        self.last_bridge_update = Some(now_ms());

        // Update authoritative state.
        let data = ConfirmationData {
            txid: conf.txid,
            height: conf.height,
            block_hash: conf.block_hash,
            tx_index: conf.tx_index,
            raw_tx: conf.raw_tx.clone(),
            source: ChainSource::CooperativeBridge,
        };
        self.confirmed_txs.insert(conf.txid, data);

        self.push_event(ChainEvent::BridgeConfirmation {
            txid: conf.txid,
            height: conf.height,
            tx_index: conf.tx_index,
        });

        // Build LDK action.
        let tx: Transaction = match bitcoin::consensus::deserialize(&conf.raw_tx) {
            Ok(t) => t,
            Err(e) => {
                log::error!(
                    "[ChainCoordinator] bridge conf tx deserialize failed for {}: {e}",
                    conf.txid
                );
                return PendingLdkAction::None;
            }
        };

        let txdata = vec![(conf.tx_index as usize, tx)];
        PendingLdkAction::TransactionsConfirmed {
            header: conf.block_header,
            txdata,
            height: conf.height,
        }
    }

    /// Bridge delivered a block header (informational — no tx confirmation).
    /// Use this when the bridge says a new block exists but doesn't include
    /// any of our watched txs.
    pub fn ingest_bridge_block_header(
        &mut self,
        header: BlockHeader,
        height: u32,
    ) -> PendingLdkAction {
        self.last_bridge_update = Some(now_ms());
        self.push_event(ChainEvent::BridgeBlockHeader { height });

        if height <= self.tip_height {
            return PendingLdkAction::None;
        }

        self.tip_height = height;
        self.tip_hash = header.block_hash();

        self.emit_best_block("bridge_header", header, height)
    }

    // ── Bridge tip observation (verify-only, no LDK action) ─────────────

    /// Phase 3.7.L: Record the chain tip the LSP claims via cooperative
    /// path (ChainDataBundle, BlockHeightUpdate). Updates `bridge_observed_tip`
    /// only — does NOT touch `tip_height`/`tip_hash` (driven by the
    /// synthetic-header FundingTxConfirmed path) and does NOT produce a
    /// PendingLdkAction. Used solely as the comparison reference for
    /// independent-path verification.
    ///
    /// Monotonic floor: backward observations are dropped silently.
    pub fn ingest_bridge_tip_observed(&mut self, height: u32, hash: BlockHash) {
        self.last_bridge_update = Some(now_ms());

        let prior_height = self.bridge_observed_tip.map(|(h, _)| h).unwrap_or(0);
        if height < prior_height {
            log::debug!(
                "[ChainCoordinator] bridge_observed_tip backward observation dropped: height={height} prior={prior_height}"
            );
            return;
        }

        self.bridge_observed_tip = Some((height, hash));
    }

    // ── Independent ingestion (verify-only) ─────────────────────────────

    /// Independent monitor observed the chain tip. Verified against the
    /// LSP's claimed `bridge_observed_tip`. Disagreements are logged but
    /// never acted on. Never returns a PendingLdkAction.
    ///
    /// Phase 3.7.L: comparison reference is `bridge_observed_tip` (the real
    /// LSP-claimed tip), NOT `tip_height`/`tip_hash` (which may be a
    /// synthetic +6 buffer set by the FundingTxConfirmed path). When no
    /// bridge observation has been recorded yet, the comparison is skipped
    /// entirely — there's nothing meaningful to disagree against.
    pub fn ingest_independent_tip(&mut self, height: u32, hash: BlockHash) {
        self.last_independent_update = Some(now_ms());

        let agrees = match self.bridge_observed_tip {
            Some((bh, bhash)) => height == bh && hash == bhash,
            None => true, // No bridge observation → nothing to disagree against.
        };

        self.push_event(ChainEvent::IndependentTipObserved {
            height,
            hash,
            agrees_with_bridge: agrees,
        });

        if !agrees {
            if let Some((bh, bhash)) = self.bridge_observed_tip {
                log::warn!(
                    "[ChainCoordinator] independent tip observation disagrees with bridge: \
                     independent={height}/{hash} bridge={bh}/{bhash}"
                );
            }
        }
    }

    /// S30 (v199): the flight recorder, readable. Serializes the last
    /// `limit` events (Debug-formatted; serde_json does all quoting) plus
    /// the authoritative header (bridge tip, confirmed-tx count).
    /// Read-only; the source of truth diagnosis consults when things fall
    /// apart, per DP's standing order.
    pub fn events_snapshot_json(&self, limit: usize) -> String {
        let n = self.event_log.len();
        let start = n.saturating_sub(limit);
        let events: Vec<String> = self
            .event_log
            .iter()
            .skip(start)
            .map(|e| format!("{:?}", e))
            .collect();
        let tip = self
            .bridge_observed_tip
            .map(|(h, hash)| serde_json::json!({ "height": h, "hash": hash.to_string() }));
        serde_json::json!({
            "bridge_tip": tip,
            "confirmed_count": self.confirmed_txs.len(),
            "events_total": n,
            "events": events,
        })
        .to_string()
    }

    /// v200: the single mint for BestBlockUpdated actions — both lanes
    /// route here. Drops strictly-lower candidates (ratchet), advances the
    /// floor on every emit, records drops.
    fn emit_best_block(
        &mut self,
        source: &str,
        header: BlockHeader,
        height: u32,
    ) -> PendingLdkAction {
        let floor = self.ldk_best_floor.unwrap_or(0);
        if height < floor {
            self.push_event(ChainEvent::BestBlockRatchetDropped {
                source: source.to_string(),
                height,
                floor,
            });
            log::warn!(
                "[ChainCoordinator] best-block RATCHET drop: {source} offered {height} below floor {floor}"
            );
            return PendingLdkAction::None;
        }
        self.ldk_best_floor = Some(height);
        PendingLdkAction::BestBlockUpdated { header, height }
    }

    /// S30 (v198): seed the monotonic best-block floor from LDK's own
    /// persisted best block at boot. The coordinator's baseline is
    /// in-memory (0 after every reload), so the FIRST bridge tip could sit
    /// below the deserialized ChannelManager's best — LDK then reads a
    /// low-conf funding as regressed ("Locked at 1 confs, now have 0
    /// confs") and force-closes a healthy channel. Seeding lets invariant
    /// #3's existing stale-drop do the rest. Monotonic: never lowers an
    /// observed tip; no-ops once observations meet or pass the floor —
    /// safe to call every tick, logs only on the actual seed.
    pub fn seed_floor(&mut self, height: u32, hash: BlockHash) {
        let prior = self.bridge_observed_tip.map(|(h, _)| h).unwrap_or(0);
        if height > prior {
            self.bridge_observed_tip = Some((height, hash));
            log::info!("[ChainCoordinator] best-block floor seeded from LDK: {height}");
        }
        // v200: the universal ratchet seeds from the same truth.
        if self.ldk_best_floor.map_or(true, |f| height > f) {
            self.ldk_best_floor = Some(height);
        }
    }

    /// Independent monitor observed a tx's status. Logs a warning if the
    /// observation conflicts with authoritative state. Never returns a
    /// PendingLdkAction. Specifically: an "unconfirmed" observation does
    /// NOT trigger `transaction_unconfirmed` — that's the bug from yesterday.
    pub fn ingest_independent_tx_status(&mut self, txid: Txid, status: TxStatus) {
        self.last_independent_update = Some(now_ms());

        let conflicts = match (self.confirmed_txs.get(&txid), status) {
            (Some(_), TxStatus::Unconfirmed) => true,
            (Some(_), TxStatus::NotFound) => true,
            (Some(c), TxStatus::Confirmed { height: h }) if h != c.height => true,
            _ => false,
        };

        self.push_event(ChainEvent::IndependentTxStatusObserved {
            txid,
            status,
            conflicts_with_authoritative: conflicts,
        });

        if conflicts {
            log::warn!(
                "[ChainCoordinator] independent tx status conflicts with authoritative: \
                 txid={txid} status={status:?} authoritative={:?}",
                self.confirmed_txs.get(&txid).map(|c| c.height)
            );
        }
    }

    /// Promote an independent-path observation of a confirmed transaction
    /// to authoritative state and produce a `TransactionsConfirmed` LDK
    /// action.
    ///
    /// Bypasses the verify-only policy of [`ingest_independent_tx_status`].
    /// Use **only** in recovery scenarios where the cooperative bridge has
    /// no path to deliver this confirmation — currently the only such case
    /// is offline force-close detection, since the cooperative protocol
    /// has no `ClosingTxObserved` message and the wallet would otherwise
    /// never learn that its channel was closed while offline.
    ///
    /// Idempotent: if the txid is already authoritatively confirmed at the
    /// same height, returns [`PendingLdkAction::None`] without re-firing.
    /// At a different height, the new height takes precedence (caller
    /// vetted via Esplora quorum) and re-fires the LDK action.
    pub fn ingest_independent_confirmation(
        &mut self,
        conf: IndependentConfirmation,
    ) -> PendingLdkAction {
        self.last_independent_update = Some(now_ms());

        if let Some(existing) = self.confirmed_txs.get(&conf.txid) {
            if existing.height == conf.height {
                log::debug!(
                    "[ChainCoordinator] ingest_independent_confirmation: txid={} already confirmed at height={} — no-op",
                    conf.txid, conf.height
                );
                return PendingLdkAction::None;
            }
            log::warn!(
                "[ChainCoordinator] ingest_independent_confirmation: txid={} re-confirming at height={} (was {}) — reason: {}",
                conf.txid, conf.height, existing.height, conf.reason
            );
        } else {
            log::warn!(
                "[ChainCoordinator] ingest_independent_confirmation: txid={} at height={} (independent path, reason: {})",
                conf.txid, conf.height, conf.reason
            );
        }

        let data = ConfirmationData {
            txid: conf.txid,
            height: conf.height,
            block_hash: conf.block_hash,
            tx_index: conf.tx_index,
            raw_tx: conf.raw_tx.clone(),
            source: ChainSource::IndependentEsplora,
        };
        self.confirmed_txs.insert(conf.txid, data);

        self.push_event(ChainEvent::IndependentConfirmation {
            txid: conf.txid,
            height: conf.height,
            reason: conf.reason.clone(),
        });

        let tx: Transaction = match bitcoin::consensus::deserialize(&conf.raw_tx) {
            Ok(t) => t,
            Err(e) => {
                log::error!(
                    "[ChainCoordinator] independent conf tx deserialize failed for {}: {e}",
                    conf.txid
                );
                return PendingLdkAction::None;
            }
        };

        let txdata = vec![(conf.tx_index as usize, tx)];
        PendingLdkAction::TransactionsConfirmed {
            header: conf.block_header,
            txdata,
            height: conf.height,
        }
    }

    // ── Watch list registration ─────────────────────────────────────────

    /// Mirror an LDK chain_filter `register_tx` call.
    pub fn register_tx(&mut self, txid: Txid, script: ScriptBuf) {
        self.watched_txs.insert(txid, script);
        self.push_event(ChainEvent::WatchTxRegistered { txid });
    }

    /// Mirror an LDK chain_filter `register_output` call.
    pub fn register_output(&mut self, txid: Txid, vout: u32, script: ScriptBuf) {
        self.watched_outputs.insert((txid, vout), script);
        self.push_event(ChainEvent::WatchOutputRegistered { txid, vout });
    }

    // ── Admin ───────────────────────────────────────────────────────────

    /// Explicitly unconfirm a tx. The ONLY way to produce a
    /// `TransactionUnconfirmed` action. Use only in recovery scenarios
    /// (manual reorg handling, etc.). Logs the reason.
    pub fn force_unconfirm(&mut self, txid: Txid, reason: String) -> PendingLdkAction {
        self.confirmed_txs.remove(&txid);
        log::warn!(
            "[ChainCoordinator] admin force_unconfirm: txid={txid} reason={reason}"
        );
        self.push_event(ChainEvent::AdminForceUnconfirm {
            txid,
            reason,
        });
        PendingLdkAction::TransactionUnconfirmed { txid }
    }

    // ── Diagnostics ─────────────────────────────────────────────────────

    pub fn snapshot_state(&self) -> ChainStateSnapshot {
        let now = now_ms();
        ChainStateSnapshot {
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            confirmed_tx_count: self.confirmed_txs.len(),
            watched_tx_count: self.watched_txs.len(),
            watched_output_count: self.watched_outputs.len(),
            last_bridge_update_secs_ago: self
                .last_bridge_update
                .map(|t| ((now - t).max(0.0) / 1000.0) as u64),
            last_independent_update_secs_ago: self
                .last_independent_update
                .map(|t| ((now - t).max(0.0) / 1000.0) as u64),
            bridge_observed_tip: self.bridge_observed_tip,
        }
    }

    pub fn recent_events(&self, n: usize) -> Vec<ChainEvent> {
        let take = n.min(self.event_log.len());
        self.event_log.iter().rev().take(take).cloned().collect()
    }

    pub fn is_confirmed(&self, txid: &Txid) -> bool {
        self.confirmed_txs.contains_key(txid)
    }

    pub fn confirmed_tx_count(&self) -> usize {
        self.confirmed_txs.len()
    }

    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    /// Phase 3.7.L: Most recent (height, hash) the LSP has claimed via
    /// cooperative bridge. None until first ChainDataBundle / BlockHeightUpdate
    /// dispatch has populated it.
    pub fn bridge_observed_tip(&self) -> Option<(u32, BlockHash)> {
        self.bridge_observed_tip
    }

    // ── Internal ────────────────────────────────────────────────────────

    fn push_event(&mut self, event: ChainEvent) {
        if self.event_log.len() == MAX_EVENT_LOG_SIZE {
            self.event_log.pop_front();
        }
        self.event_log.push_back(event);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;

    fn dummy_header(height: u32) -> BlockHeader {
        // Construct via consensus deserialize so we don't depend on the
        // bitcoin crate's internal type paths (Version, CompactTarget,
        // TxMerkleNode each moved across crate versions).
        let mut bytes = [0u8; 80];
        // Set version field (bytes 0-4) and time field (bytes 68-72) to vary
        // per height so each call yields a distinct block_hash.
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&height.to_le_bytes());
        bitcoin::consensus::deserialize(&bytes)
            .expect("dummy header bytes must decode")
    }

    fn dummy_txid(seed: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Txid::from_byte_array(bytes)
    }

    fn dummy_blockhash(seed: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        BlockHash::from_byte_array(bytes)
    }

    #[test]
    fn new_coordinator_empty() {
        let c = ChainCoordinator::new(948000, dummy_blockhash(0xaa));
        assert_eq!(c.tip_height(), 948000);
        assert_eq!(c.confirmed_tx_count(), 0);
    }

    #[test]
    fn hydration_populates_confirmed_txs() {
        let mut c = ChainCoordinator::new(948000, dummy_blockhash(0xaa));
        let txid = dummy_txid(0x01);
        c.hydrate_from_channels(vec![(txid, 947968, 814)]);
        assert_eq!(c.confirmed_tx_count(), 1);
        assert!(c.is_confirmed(&txid));
    }

    #[test]
    fn bridge_tip_advance_returns_action() {
        let mut c = ChainCoordinator::new(948000, dummy_blockhash(0xaa));
        let header = dummy_header(948001);
        let action = c.ingest_bridge_tip(948001, header.block_hash(), header);
        assert!(matches!(action, PendingLdkAction::BestBlockUpdated { .. }));
        assert_eq!(c.tip_height(), 948001);
    }

    #[test]
    fn bridge_tip_stale_drops_silently() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let header = dummy_header(948005);
        let action = c.ingest_bridge_tip(948005, header.block_hash(), header);
        assert!(action.is_none(), "stale tip must produce no LDK action");
        assert_eq!(c.tip_height(), 948010, "tip must not regress");
    }

    #[test]
    fn bridge_tip_equal_drops_silently() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let header = dummy_header(948010);
        let action = c.ingest_bridge_tip(948010, header.block_hash(), header);
        assert!(action.is_none());
    }

    #[test]
    fn independent_tip_agreement_does_not_warn() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        c.ingest_independent_tip(948010, dummy_blockhash(0xaa));
        let events = c.recent_events(10);
        let last = events.first().expect("event recorded");
        match last {
            ChainEvent::IndependentTipObserved { agrees_with_bridge, .. } => {
                assert!(*agrees_with_bridge);
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn independent_tip_disagreement_logs_no_action() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        // Phase 3.7.L: independent disagreement is now relative to the
        // bridge_observed_tip (set explicitly here), not to the synthetic
        // tip_height/tip_hash supplied at construction.
        c.ingest_bridge_tip_observed(948010, dummy_blockhash(0xaa));
        // Independent says different hash at same height
        c.ingest_independent_tip(948010, dummy_blockhash(0xff));
        // No LDK action returned (return type is unit) — implicit assertion
        let events = c.recent_events(10);
        let last = events.first().expect("event recorded");
        match last {
            ChainEvent::IndependentTipObserved { agrees_with_bridge, .. } => {
                assert!(!*agrees_with_bridge);
            }
            _ => panic!("wrong event"),
        }
    }

    /// The regression test for yesterday's bug: even when independent says
    /// a confirmed tx is "unconfirmed", the coordinator must NOT produce
    /// an LDK unconfirm action.
    #[test]
    fn independent_unconfirmed_observation_does_not_unconfirm() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let txid = dummy_txid(0x01);
        c.hydrate_from_channels(vec![(txid, 948005, 100)]);
        assert!(c.is_confirmed(&txid));

        // Simulate yesterday's failure trigger: independent reports tx not found.
        c.ingest_independent_tx_status(txid, TxStatus::NotFound);

        // Coordinator must still consider the tx confirmed.
        assert!(c.is_confirmed(&txid), "hydrated confirmation must survive independent NotFound");

        // Verify a conflict was logged.
        let events = c.recent_events(10);
        let conflict = events.iter().find_map(|e| match e {
            ChainEvent::IndependentTxStatusObserved {
                conflicts_with_authoritative, ..
            } => Some(*conflicts_with_authoritative),
            _ => None,
        });
        assert_eq!(conflict, Some(true), "conflict must be flagged in event log");
    }

    #[test]
    fn force_unconfirm_admin_produces_ldk_action() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let txid = dummy_txid(0x01);
        c.hydrate_from_channels(vec![(txid, 948005, 100)]);

        let action = c.force_unconfirm(txid, "manual reorg handling".to_string());
        assert!(matches!(action, PendingLdkAction::TransactionUnconfirmed { .. }));
        assert!(!c.is_confirmed(&txid), "force_unconfirm must remove from state");
    }

    #[test]
    fn watch_list_registration_mirrors() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let txid = dummy_txid(0x01);
        let script = ScriptBuf::new();
        c.register_tx(txid, script.clone());
        c.register_output(txid, 0, script);

        let snap = c.snapshot_state();
        assert_eq!(snap.watched_tx_count, 1);
        assert_eq!(snap.watched_output_count, 1);
    }

    #[test]
    fn event_log_bounded_to_max_size() {
        let mut c = ChainCoordinator::new(0, dummy_blockhash(0));
        for i in 0..(MAX_EVENT_LOG_SIZE as u32 + 50) {
            let header = dummy_header(i);
            // Use unique hashes so each tip advance is recorded.
            let hash = header.block_hash();
            let _ = c.ingest_bridge_tip(i + 1, hash, header);
        }
        let events = c.recent_events(MAX_EVENT_LOG_SIZE + 100);
        assert!(
            events.len() <= MAX_EVENT_LOG_SIZE,
            "event log must not exceed cap"
        );
    }

    #[test]
    fn pending_ldk_action_is_none_helper() {
        assert!(PendingLdkAction::None.is_none());
        assert!(!PendingLdkAction::TransactionUnconfirmed { txid: dummy_txid(0) }.is_none());
    }

    /// Catches any Duration import drift — ensures snapshot logic compiles
    /// even when no source has reported yet.
    #[test]
    fn snapshot_handles_no_updates() {
        let c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        let snap = c.snapshot_state();
        assert!(snap.last_bridge_update_secs_ago.is_none());
        assert!(snap.last_independent_update_secs_ago.is_none());
        let _ = std::time::Duration::from_secs(0); // ensure Duration is in scope
    }

    /// Phase 3.7.L: independent observation must NOT flag disagreement when
    /// no bridge observation exists yet. This is the regression test for the
    /// pre-funding WARN spam discovered in Session 11.
    #[test]
    fn independent_skips_warn_without_bridge_observation() {
        let mut c = ChainCoordinator::new(948010, dummy_blockhash(0xaa));
        // No call to ingest_bridge_tip_observed — bridge_observed_tip stays None.
        c.ingest_independent_tip(948722, dummy_blockhash(0xff));
        let events = c.recent_events(10);
        let last = events.first().expect("event recorded");
        match last {
            ChainEvent::IndependentTipObserved { agrees_with_bridge, .. } => {
                assert!(
                    *agrees_with_bridge,
                    "no bridge tip → must report agreement (skip-flag semantics)"
                );
            }
            _ => panic!("wrong event"),
        }
    }

    /// Phase 3.7.L: bridge_observed_tip must enforce a monotonic floor —
    /// backward observations are dropped silently to avoid LSP-side regress
    /// (e.g. brief LSP reorg below our floor) corrupting verification state.
    #[test]
    fn bridge_observed_tip_monotonic_floor() {
        let mut c = ChainCoordinator::new(0, dummy_blockhash(0));

        c.ingest_bridge_tip_observed(948010, dummy_blockhash(0xaa));
        assert_eq!(
            c.bridge_observed_tip(),
            Some((948010, dummy_blockhash(0xaa))),
        );

        // Backward observation must be dropped.
        c.ingest_bridge_tip_observed(948005, dummy_blockhash(0xbb));
        assert_eq!(
            c.bridge_observed_tip(),
            Some((948010, dummy_blockhash(0xaa))),
            "backward observation must not regress bridge_observed_tip",
        );

        // Forward observation must be accepted.
        c.ingest_bridge_tip_observed(948015, dummy_blockhash(0xcc));
        assert_eq!(
            c.bridge_observed_tip(),
            Some((948015, dummy_blockhash(0xcc))),
        );
    }
}
