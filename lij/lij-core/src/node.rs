// node.rs — LDK 0.0.123 verified API
// ChannelManager fully wired for invoice creation and payment sending.

use std::sync::{Arc, Mutex};
#[cfg(target_arch = "wasm32")]
use wasm_timer::SystemTime;

use bitcoin::{
    block::{Header, Version as BlockVersion},
    consensus::deserialize as consensus_deserialize,
    hash_types::TxMerkleNode,
    hashes::{Hash, sha256},
    pow::CompactTarget,
    BlockHash, Network,
};
use lightning::{
    chain::{
        BestBlock, Confirm, Watch,
        chainmonitor::ChainMonitor,
        chaininterface::{BroadcasterInterface, FeeEstimator},
        channelmonitor::ChannelMonitor,
    },
    events::EventsProvider,
    ln::{
        channelmanager::{ChainParameters, ChannelManager, ChannelManagerReadArgs, Retry},
        peer_handler::{IgnoringMessageHandler, PeerManager},
    },
    routing::{
        gossip::NetworkGraph,
        router::DefaultRouter,
        scoring::{
            ProbabilisticScorer,
            ProbabilisticScoringDecayParameters,
            ProbabilisticScoringFeeParameters,
        },
    },
    ln::ChannelId,
    sign::KeysManager,
    util::{
        config::UserConfig,
        logger::{Logger, Level, Record},
        ser::{ReadableArgs, Writeable},
    },
};
use lightning::routing::router::{Route, RouteHop, Path};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use lightning::ln::features::{NodeFeatures, ChannelFeatures};

/// v195 (S30): wallet-storage key for the LNURLp preimage pool (JSON map
/// hash_hex -> preimage_hex). Never leaves the device.
const KEY_LNURLP_PREIMAGES: &str = "lij_lnurlp_preimages";
/// v229: the next derivation index for seed-derived LNURLp preimages.
const KEY_LNURLP_NEXT_INDEX: &str = "lij_lnurlp_next_index";
/// v229 (DP: "decades"): how long a registered static-address hash stays
/// valid in the wallet's own engine — 30 years. The same number is handed
/// to the LSP as `expires`, so the two sides can never disagree again.
const LNURLP_HASH_EXPIRY_SECS: u32 = 946_080_000;
/// v229: how far the claim path searches derived indices when the local
/// cache lacks a hash (a restore, a wiped pool): ~25 ms of hashing in WASM.
const LNURLP_DERIVE_SEARCH_BOUND: u32 = 8192;
/// v224 (S41, DP RULED): the user's EXPLICIT provider choice — a full LspInfo
/// snapshot, so a registry outage cannot strand boot. Written ONLY by
/// wallet.switch_lsp (a user action). Distinct from KEY_LSP_CONFIG, which is
/// "last connected" and gets overwritten by every boot's selection — the very
/// record that could not serve as memory of a choice.
const KEY_CHOSEN_LSP: &str = "lij_chosen_lsp";
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder,
    RouteHint, RouteHintHop, RoutingFees,
};

use crate::{
    broadcaster::LijBroadcaster,
    chain_filter::LijChainFilter,
    cooperative_chain_bridge::CooperativeChainBridge,
    cooperative_chain_handler::CooperativeChainHandler,
    fee_estimator::LijFeeEstimator,
    http_stub::StubEsploraHttp,
    independent::IndependentClient,
    cold_start::ColdStartOrchestrator,
    sync_state::{require_can_receive, require_can_send, SyncState, SyncStateTracker},
    error::{LijError, LijResult},
    key::RootKey,
    lsp::{ActiveLsp, LspClient, LspInfo},
    peer::{build_message_handler, ephemeral_bytes, LijPeerManagerType, LijSocketDescriptor},
    persist::{
        self, LijChannelMonitorPersister, CHANNEL_MANAGER_KEY, MONITOR_KEY_PREFIX,
    },
    close_attempt::{CloseAttemptKind, CloseAttemptRecord},
    closed_channel_log::{ClosedChannelLog, ClosedChannelRecord, CloseKind},
    persisted_counter::PersistedCounter,
    signer::LijSignerProvider,
    storage::{LijStorage, KEY_LSP_CONFIG},
    types::{Balance, ChannelInfo, InvoiceResult, InvoiceWithJitResult, InvoiceJitInfo, PaymentResult, WalletConfig},
};

/// Ceiling knob for cooperative-close fee negotiation, applied as
/// `ChannelConfig.force_close_avoidance_max_fee_satoshis` on every channel we
/// configure. The wallet (when it is the funder, and thus pays the close fee)
/// will accept a negotiated coop-close fee up to `NonAnchorChannelFee + this`;
/// anything higher is rejected and the close falls back to a force close. This
/// bounds a devious LSP from griefing the funder by negotiating an inflated
/// close fee (the fee is burned to miners, not paid to the LSP).
///
/// v75: RAISED from 250 to 3000. The 250 ceiling (v41) was far too tight — two
/// independent nodes (LiJ vs the LSP's LND) routinely disagree on a closing-tx
/// fee by more than 250 sats just from honest fee-estimator divergence, so
/// normal cooperative closes were being rejected and force-closed. That trade
/// was backwards: avoiding a few hundred sats of *miner* fee (which the LSP
/// never receives) cost us a force close + CSV lock + fragile sweep recovery.
/// At 3000 we strongly prefer a clean coop close (funds land directly at the
/// m/84 shutdown script, no CSV, no sweep). A devious LSP still can't profit —
/// the worst it can do is make us overpay miners up to this cap, which is far
/// cheaper than a force close. LDK's default is 1000; we sit above it on
/// purpose. Ignored by LDK on channels where the LSP is the funder.
const COOP_CLOSE_MAX_FEE_OVERAGE_SAT: u64 = 3000;

// ── Logger ────────────────────────────────────────────────────────────────────

pub struct LijLogger;
impl Logger for LijLogger {
    fn log(&self, record: Record) {
        match record.level {
            Level::Error => log::error!("[LDK] {}", record.args),
            Level::Warn  => log::warn!("[LDK] {}", record.args),
            Level::Info  => log::info!("[LDK] {}", record.args),
            _            => log::debug!("[LDK] {}", record.args),
        }
    }
}

// ── Chain interfaces ──────────────────────────────────────────────────────────

// NoopBroadcaster removed in Phase 4 step 1 — replaced by LijBroadcaster
// (see broadcaster.rs). Cooperative + independent paths wired in steps 4 & 5.

// StaticFeeEstimator removed in Phase 4 step 2 — replaced by LijFeeEstimator
// (see fee_estimator.rs). Cooperative + independent paths wired in steps 4 & 5.

// ── Concrete LDK types ────────────────────────────────────────────────────────

pub type DynLogger      = Arc<dyn Logger + Send + Sync>;
pub type DynBroadcaster = Arc<dyn BroadcasterInterface + Send + Sync>;
pub type DynFeeEst      = Arc<dyn FeeEstimator + Send + Sync>;
type DynFilter      = Arc<dyn lightning::chain::Filter + Send + Sync>;

type LijNetworkGraph = Arc<NetworkGraph<DynLogger>>;

type LijChainMonitor = ChainMonitor<
    crate::signer::LijChannelSigner,
    DynFilter,
    DynBroadcaster,
    DynFeeEst,
    DynLogger,
    Arc<LijChannelMonitorPersister>,
>;

type LijRouter = Arc<DefaultRouter<
    LijNetworkGraph,
    DynLogger,
    Arc<KeysManager>,
    Arc<Mutex<ProbabilisticScorer<LijNetworkGraph, DynLogger>>>,
    ProbabilisticScoringFeeParameters,
    ProbabilisticScorer<LijNetworkGraph, DynLogger>,
>>;

pub type LijChannelManager = ChannelManager<
    Arc<LijChainMonitor>,
    DynBroadcaster,
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<LijSignerProvider>,
    DynFeeEst,
    LijRouter,
    DynLogger,
>;

// ── SpendableOutputs diagnostic log (temp) ──────────────────────────────────
// Records every SpendableOutputDescriptor as it arrives at the event handler —
// INCLUDING ones excluded from the sweeper by the v128 exclude_static_outputs
// rule — so we can confirm what variant + destination an anchors coop close
// emits (the m/525 P2WSH-anchor exclusion diagnosis). WASM is single-threaded,
// so a thread_local ring buffer is safe and avoids threading a field through
// the Node constructor. Remove with the rest of the temp diagnostics.
thread_local! {
    static SPENDABLE_OUTPUTS_LOG: std::cell::RefCell<Vec<String>> =
        std::cell::RefCell::new(Vec::new());
    // Companion log: every ChannelClosed event + force-close invocation, with
    // timestamps, so we can see the SEQUENCE for a channel (e.g. did a coop
    // ChannelClosed fire AND a force close, and in what order?). Resolves the
    // contradiction where the record says LocallyInitiatedCooperativeClosure but
    // a force-close-shaped tx confirmed on-chain. Temp; remove with the rest.
    static CLOSE_EVENT_LOG: std::cell::RefCell<Vec<String>> =
        std::cell::RefCell::new(Vec::new());
}

pub fn spendable_log_record(line: String) {
    SPENDABLE_OUTPUTS_LOG.with(|l| {
        let mut v = l.borrow_mut();
        v.push(line);
        // Cap so it can't grow unbounded; keep the most recent 50.
        let len = v.len();
        if len > 50 { v.drain(0..len - 50); }
    });
}

pub fn spendable_log_dump() -> Vec<String> {
    SPENDABLE_OUTPUTS_LOG.with(|l| l.borrow().clone())
}

pub fn close_event_record(line: String) {
    CLOSE_EVENT_LOG.with(|l| {
        let mut v = l.borrow_mut();
        v.push(line);
        let len = v.len();
        if len > 50 { v.drain(0..len - 50); }
    });
}

pub fn close_event_dump() -> Vec<String> {
    CLOSE_EVENT_LOG.with(|l| l.borrow().clone())
}

// v149 TEMP diagnostic helpers: read a SpendableOutputDescriptor's output value
// and a short kind label. Remove with the spend-attempt diagnostic.
fn descriptor_value_sats(d: &lightning::sign::SpendableOutputDescriptor) -> u64 {
    use lightning::sign::SpendableOutputDescriptor as SOD;
    match d {
        SOD::StaticOutput { output, .. } => output.value,
        SOD::DelayedPaymentOutput(o) => o.output.value,
        SOD::StaticPaymentOutput(o) => o.output.value,
    }
}
fn descriptor_kind(d: &lightning::sign::SpendableOutputDescriptor) -> &'static str {
    use lightning::sign::SpendableOutputDescriptor as SOD;
    match d {
        SOD::StaticOutput { .. } => "StaticOutput",
        SOD::DelayedPaymentOutput(_) => "DelayedPaymentOutput",
        SOD::StaticPaymentOutput(_) => "StaticPaymentOutput",
    }
}

// ── Node ──────────────────────────────────────────────────────────────────────

/// v213 (DP: "evil-LSP reserve"): the reserve the WALLET USER demands the LSP
/// maintain on its side, in proportional millionths — the user's priced
/// distrust of a business counterparty. Applied to NEW channels only (BOLT2:
/// fixed at handshake). ppm 0 rides LDK's MIN_THEIR_CHAN_RESERVE_SATOSHIS
/// clamp = exactly 1,000 sats on any channel. Default 10_000 ppm = 1%.
/// Page persists the choice and re-applies at boot (quorum pattern).
/// v214 (DP): default = 0 ppm — LDK's MIN_THEIR_CHAN_RESERVE clamp makes that
/// exactly 1,000 sats on any channel, matching the dial's shipped default.
/// Engine and page now agree with no boot-apply dependency.
pub static LSP_RESERVE_PPM: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// ── v216 (S36, O6 fee headroom → exact-fee, DP GREEN) ────────────────────────
// The 2% blanket shave is retired. These statics carry the LIVE-SEEN LSP
// first-hop fee policy (fee_base_msat, fee_proportional_millionths), cached
// from every route-build response that passes through the wallet — the scan-
// time quote and the send path both feed it. Until the first sighting the
// UNSEEN defaults are deliberately conservative (base 1,000 msat, 0.1% ppm —
// still ~20× tighter than the old 2%); the first quote replaces them.
pub static LSP_FEE_BASE_MSAT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static LSP_FEE_PPM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static LSP_FEE_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// O6 fee-rate race margin (sats), user-dialable (page persists + boot-applies;
/// WALLET → Controls). Subtracted ONCE, at the aggregate, inside
/// max_sendable_sats — covers a fee-policy move between quote and dispatch.
/// Default 10; dial down to Zero (exact) is honest when the policy is pinned.
pub static FEE_MARGIN_SATS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10);

/// The policy in force right now: live-seen values, else the unseen defaults.
pub fn lsp_fee_policy_now() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    if LSP_FEE_SEEN.load(Relaxed) {
        (LSP_FEE_BASE_MSAT.load(Relaxed), LSP_FEE_PPM.load(Relaxed))
    } else {
        (1_000, 1_000)
    }
}

/// Record a sighted LSP first-hop policy (from lsp_first_hop_policy in any
/// route-build response). Every sighting refreshes the cache.
pub fn record_lsp_fee_policy(base_msat: u64, ppm: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    LSP_FEE_BASE_MSAT.store(base_msat, Relaxed);
    LSP_FEE_PPM.store(ppm.min(1_000_000), Relaxed);
    LSP_FEE_SEEN.store(true, Relaxed);
    log::info!("[O6-fee] LSP first-hop policy recorded: base={} msat, ppm={}", base_msat, ppm);
}

/// v216 THE ONE LAW (replaces every ×98/100 site — change NOTHING here
/// without changing max_sendable_sats + mpp_plan + the ExceedsTotal fallback
/// together): the largest amount DELIVERABLE through a capacity of cap_msat
/// once the LSP forward fee rides on top —
///   amt + base + amt·ppm/1e6 ≤ cap  ⇒  amt = (cap − base)·1e6/(1e6 + ppm)
/// u128 interim so a multi-BTC cap cannot overflow.
pub fn fee_adjusted_deliverable_msat(cap_msat: u64) -> u64 {
    let (base, ppm) = lsp_fee_policy_now();
    if cap_msat <= base { return 0; }
    (((cap_msat - base) as u128) * 1_000_000u128 / (1_000_000u128 + ppm as u128)) as u64
}

/// v216: the exact sender-side fee for delivering `amount_msat` (self-hop on
/// amount + downstream fees), given `downstream_fees_msat` from LND's
/// QueryRoutes total (0 on the common one-hop/synth path). Ceil'd to msat.
pub fn quote_self_hop_fee_msat(amount_msat: u64, downstream_fees_msat: u64) -> u64 {
    let (base, ppm) = lsp_fee_policy_now();
    let forwarded = (amount_msat as u128) + (downstream_fees_msat as u128);
    let prop = (forwarded * ppm as u128 + 999_999) / 1_000_000;
    (base as u128 + prop) as u64
}

/// v216: parse a /v1/route/build response for quoting — records any
/// lsp_first_hop_policy sighting, reads routes[0].total_fees_msat (LND emits
/// int64s as strings), and returns the TOTAL sender fee in msat for
/// delivering amount_msat: downstream + self-hop-on-(amount+downstream).
/// v216: invoice amount in msat — invoice-fixed, else the override (sats),
/// else an error naming the open-invoice case. Core-side so lij-wasm needs
/// no lightning-invoice dependency of its own.
pub fn invoice_amount_msat(bolt11: &str, amount_sats_override: Option<u64>) -> Result<u64, crate::error::LijError> {
    let inv = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|e| crate::error::LijError::Payment(format!("invoice decode: {:?}", e)))?;
    match inv.amount_milli_satoshis() {
        Some(m) => Ok(m),
        None => amount_sats_override
            .map(|s| s.saturating_mul(1000))
            .ok_or_else(|| crate::error::LijError::Payment(
                "open invoice — amount_sats_override required".into())),
    }
}

/// S45 (DP): the route-build request for a PUBKEY destination (no invoice) —
/// the same body prepare_lsp_route_request builds from a bolt11, minus the
/// hints. Lets Max price a route to another LSP's node before any invoice
/// exists (an LNURL address served by that LSP). Returns (url, body).
pub fn prepare_route_quote_to_pubkey(dest_pubkey_hex: &str, route_endpoint: &str, amount_sats: u64) -> LijResult<(String, String)> {
    let pk = dest_pubkey_hex.trim().to_lowercase();
    if pk.len() != 66 || !pk.chars().all(|c| c.is_ascii_hexdigit()) || !(pk.starts_with("02") || pk.starts_with("03")) {
        return Err(LijError::Payment("destination must be a 33-byte hex node key".into()));
    }
    if amount_sats == 0 {
        return Err(LijError::Payment("amount must be positive".into()));
    }
    let url = format!("{}/v1/route/build", route_endpoint.trim_end_matches('/'));
    let body = serde_json::json!({
        "destination": pk,
        "amount_sat": amount_sats,
        "route_hints": [],
    }).to_string();
    Ok((url, body))
}

pub fn quote_total_fee_msat_from_response(response_text: &str, amount_msat: u64) -> u64 {    let parsed: Option<serde_json::Value> = serde_json::from_str(response_text).ok();
    let mut downstream: u64 = 0;
    if let Some(v) = parsed.as_ref() {
        if let Some(policy) = v.get("lsp_first_hop_policy") {
            let base = policy.get("fee_base_msat").and_then(|x| x.as_str()).and_then(|s| s.parse().ok());
            let ppm = policy.get("fee_proportional_millionths").and_then(|x| x.as_u64());
            if let (Some(b), Some(p)) = (base, ppm) { record_lsp_fee_policy(b, p); }
        }
        downstream = v.get("routes")
            .and_then(|r| r.get(0))
            .and_then(|r0| r0.get("total_fees_msat"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
    }
    downstream + quote_self_hop_fee_msat(amount_msat, downstream)
}

/// v219 (DEFECT B): realm-global socket-id sequence — see next_socket_id().
static NEXT_SOCKET_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct LijNode {
    pub config: WalletConfig,
    pub network: Network,
    root_key: Arc<RootKey>,
    active_lsp: Option<ActiveLsp>,
    keys_manager: Arc<KeysManager>,
    signer_provider: Arc<LijSignerProvider>,
    outstanding_close_attempts: Arc<Mutex<std::collections::HashMap<ChannelId, CloseAttemptRecord>>>,
    /// v178 (close-awareness): funding outpoints ("txid:vout") the walker has
    /// seen spent by a still-UNCONFIRMED tx, mapped to the spending txid.
    /// Written by check_funding_outpoints_for_spends; read by get_channels to
    /// surface "closing — in the mempool" to the display layer. Entries clear
    /// when the spend confirms (eviction takes over) or evaporates (RBF).
    funding_spend_sightings: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// v8: Per-payment outcome tracking for Phase 10b retry mechanism.
    /// Populated by the event handler when PaymentSent / PaymentPathFailed / PaymentFailed
    /// events fire. Keyed by PaymentId (not PaymentHash) so retries with a
    /// freshly-generated PaymentId can be distinguished from prior attempts'
    /// outcomes (PaymentHash is constant across retries of the same invoice).
    /// Drained by send_payment_with_retries after each attempt.
    payment_outcomes: Arc<Mutex<std::collections::HashMap<lightning::ln::channelmanager::PaymentId, PaymentOutcome>>>,
    /// v206: hashes of inbound payments the engine has actually CLAIMED this
    /// session (PaymentClaimed fired) -> sats. The frontend ledger completes a
    /// pending receive only when its payment_hash appears here, replacing the
    /// unsound balance-delta heuristic that could fabricate "received" rows from
    /// a resync balance blip. In-memory / per-session by design.
    claimed_payments: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    #[allow(deprecated)]
    closed_channel_watcher: crate::closed_channel_watcher::ClosedChannelWatcher,
    network_graph: LijNetworkGraph,
    scorer: Arc<Mutex<ProbabilisticScorer<LijNetworkGraph, DynLogger>>>,
    storage: Arc<dyn LijStorage>,
    chain_monitor: Option<Arc<LijChainMonitor>>,
    /// LDK's [`lightning::util::sweep::OutputSweeper`], wired to sweep all
    /// `SpendableOutputDescriptor`s emitted by ChannelMonitor to BIP84
    /// destinations at `m/84'/0'/0'/0/n`. Set during `restore()` or
    /// `init_channel_manager()` (immediately after chain_monitor). `None`
    /// before init completes. Event hookup lands in sub-step 2.3.
    output_sweeper: Option<Arc<crate::sweeper::LijOutputSweeper>>,
    channel_manager: Option<Arc<LijChannelManager>>,
    peer_manager: Option<Arc<LijPeerManagerType>>,
    broadcaster: Arc<LijBroadcaster>,
    fee_estimator: Arc<LijFeeEstimator>,
    chain_filter: Arc<LijChainFilter>,
    cooperative_chain: Arc<CooperativeChainHandler>,
    cooperative_bridge: Arc<CooperativeChainBridge>,
    chain_coordinator: Arc<Mutex<crate::chain_coordinator::ChainCoordinator>>,
    independent: Arc<IndependentClient>,
    sync_state: Arc<SyncStateTracker>,
    cold_start: Arc<ColdStartOrchestrator>,
    last_independent_fetch_tick: std::sync::atomic::AtomicU64,
    /// FLAP FIX: false until the funding-outpoint reconcile has completed one
    /// full pass (every live funding outpoint definitively queried against the
    /// Esplora quorum, every confirmed spend evicted). While false,
    /// background_tick runs the spend-walker eagerly so a channel the LSP
    /// force-closed while we were offline is evicted before LDK's reestablish
    /// loop can flap the peer. After first success we drop to maintenance cadence.
    #[allow(dead_code)]
    funding_reconcile_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Guards against launching overlapping reconcile passes while a slow or
    /// rate-limited (429) Esplora query is still in flight.
    #[allow(dead_code)]
    funding_reconcile_inflight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// FLAP FIX: consecutive incomplete reconcile passes. After
    /// EAGER_FAIL_THRESHOLD, the eager cadence widens (see background_tick) so a
    /// persistently rate-limited (429) Esplora isn't hammered every 3 ticks.
    #[allow(dead_code)]
    funding_reconcile_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// AUTO-BACKUP: set true whenever channel state is persisted. The frontend's
    /// slow backup tick snapshots + pushes the encrypted state to enabled sinks
    /// and clears it. Cleared at snapshot time, so any change during the push
    /// re-dirties it; re-set on push failure to retry next tick.
    backup_dirty: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// S21 item 2: flipped by the monitor persister on every monitor write so
    /// the tick persists the manager promptly (never trails a commitment).
    manager_dirty: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// S21 item 2: monotonic stamp shared with the monitor persister.
    persist_seq: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// S21 item 2: set at load when stamps show the manager stale vs monitors.
    persist_skew: std::sync::atomic::AtomicBool,
    /// DIAGNOSTICS: increments once per spend-walk pass (bumped in
    /// background_tick after each `check_funding_outpoints_for_spends`). The
    /// frontend reads this via `diagnostics_json` to confirm the background
    /// loop is actually running on the device — notably on iOS, where Safari
    /// throttles/suspends background JS. A stale seq while the wallet is
    /// foregrounded means the loop is suspended.
    walk_seq: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Tick of the last funding-spend walk we committed to. The cadence gate
    /// fires when `tick_count - walk_last_tick >= interval`, which self-corrects
    /// across skipped/throttled ticks instead of relying on an exact modulo
    /// window a backgrounded tab will silently miss.
    walk_last_tick: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Set by note_foreground() so the next background_tick forces a walk
    /// regardless of cadence phase (re-scan the instant the app is foregrounded).
    funding_walk_force: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// D-1 (JIT safety): true only while the app is foreground. The
    /// OpenChannelRequest handler refuses inbound JIT opens when this is false,
    /// so a backgrounded/offline wallet never accepts a channel it can't claim
    /// into. Set by note_foreground(), cleared by note_background(); defaults
    /// false so a cold start won't accept until the frontend signals foreground.
    accepting_channels: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// v8: Per-payment outcome recorded by LDK event handler.
/// Used by send_payment_with_retries to detect failure, extract the failed
/// channel edge, and decide whether to retry with that edge excluded.
#[derive(Debug, Clone)]
pub enum PaymentOutcome {
    /// PaymentSent fired — payment succeeded end-to-end.
    Sent {
        preimage_hex: Option<String>,
        fee_paid_msat: Option<u64>,
    },
    /// PaymentPathFailed fired — this attempt's path failed, but the payment
    /// itself may still be retryable. `failed_pair` is the (from, to) pubkey
    /// pair of the failed channel edge, ready to be passed to the adapter's
    /// `ignored_pairs` parameter on the next /v1/route/build call.
    PathFailed {
        failed_scid: Option<u64>,
        failed_from_pubkey: Option<Vec<u8>>, // 33-byte compressed
        failed_to_pubkey: Option<Vec<u8>>,   // 33-byte compressed
        is_permanent: bool,
    },
    /// PaymentFailed fired — payment is terminally failed, retries exhausted
    /// from LDK's perspective (which is always immediately for us since we use
    /// Retry::Attempts(0)).
    Failed {
        reason: String,
    },
}

/// v8: Extract (from_pubkey, to_pubkey) compressed bytes for the failed channel
/// edge in a PaymentPathFailed event, given the route path and the failed scid.
/// Returns None if the scid isn't found in the path (shouldn't happen but is
/// handled defensively).
fn extract_failed_pair_from_path(
    path: &lightning::routing::router::Path,
    failed_scid: u64,
) -> Option<(Vec<u8>, Vec<u8>)> {
    // Each hop.short_channel_id is the channel USED TO REACH hop.pubkey.
    // So the channel goes from hop[i-1].pubkey (or self, if i=0) to hop[i].pubkey.
    // We don't have self's pubkey here, so for i=0 we return None and let the
    // caller decide (self→LSP channel shouldn't be excluded anyway).
    for (i, hop) in path.hops.iter().enumerate() {
        if hop.short_channel_id == failed_scid {
            if i == 0 {
                // Failed channel is wallet→LSP — can't exclude, that's our only outbound.
                return None;
            }
            let from = path.hops[i - 1].pubkey.serialize().to_vec();
            let to = hop.pubkey.serialize().to_vec();
            return Some((from, to));
        }
    }
    None
}

/// v8: Output of prepare_lsp_route_request, consumed by apply_lsp_route_and_send
/// (after an HTTP fetch between them). Carries everything the apply step needs
/// to build and submit the HTLC, plus the payment_hash so the caller can later
/// poll payment_outcomes for the result.
///
/// Lives across the await boundary in send_payment_with_retries — all fields
/// are Send + 'static (RecipientOnionFields, PaymentId, PaymentHash are all
/// plain data; no references back into the Node).
#[cfg(target_arch = "wasm32")]
pub struct LspRoutePreparation {
    /// URL for the adapter's /v1/route/build endpoint.
    pub url: String,
    /// Serialized JSON body to POST.
    pub request_body: String,
    /// PaymentHash extracted from the invoice — also the key for the outcome map.
    pub payment_hash: lightning::ln::PaymentHash,
    /// Recipient onion fields needed by cm.send_payment_with_route.
    pub recipient_onion: lightning::ln::channelmanager::RecipientOnionFields,
    /// LDK PaymentId — used to correlate the HTLC with PaymentSent / PaymentFailed.
    pub payment_id: lightning::ln::channelmanager::PaymentId,
    /// Final CLTV delta from the invoice (passed to parse_lnd_route_response).
    pub final_cltv_delta: u32,
    /// Amount in msat from the invoice — for logging.
    pub amount_msat: u64,
    /// Destination pubkey hex — for logging.
    pub dest_pubkey_hex: String,
}

/// MPP (v158): one shard of a multipath payment — which wallet→LSP channel
/// carries it (`scid`) and how many msat it delivers toward the destination.
#[derive(Debug, Clone)]
pub struct MppPart {
    pub scid: u64,
    pub part_msat: u64,
}

/// MPP (v158): the routing strategy chosen for a send, decided up front from the
/// invoice amount and the wallet's channel topology.
///   - `Single`        : amount fits the largest single channel → existing path.
///   - `Multi(parts)`  : split across channels (greedy largest-first).
///   - `NoMppSupport`  : split needed but the recipient's invoice lacks
///                       basic_mpp → cannot split.
///   - `ExceedsTotal`  : amount exceeds the wallet's total sendable.
#[derive(Debug, Clone)]
pub enum MppDecision {
    Single,
    Multi(Vec<MppPart>),
    NoMppSupport,
    ExceedsTotal { sendable_msat: u64 },
}

impl LijNode {
    pub async fn new(
        root_key: RootKey,
        config: WalletConfig,
        storage: Arc<dyn LijStorage>,
    ) -> LijResult<Self> {
        let network = parse_network(&config.network)?;
        let root_key = Arc::new(root_key);
        let seed = root_key.lightning_node_key()?.private_key.secret_bytes();
        let ts = current_time_secs();
        let keys_manager = Arc::new(KeysManager::new(&seed, ts, (ts * 1000) as u32));
        let counter = PersistedCounter::new(storage.clone())?;
        let signer_provider = Arc::new(LijSignerProvider::new(
            keys_manager.clone(),
            root_key.shutdown_xpriv()?,
            counter,
            network,
        ));
        let logger: DynLogger = Arc::new(LijLogger);
        let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
        let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
            ProbabilisticScoringDecayParameters::default(),
            network_graph.clone(),
            logger.clone(),
        )));
        let broadcaster = Arc::new(LijBroadcaster::new());
        let fee_estimator = Arc::new(LijFeeEstimator::new());
        // v182 (S25, the 510): boot-seed the fee cache from the last
        // persisted quote — a prior between the live sources and the
        // relay floor. Live sources overrule it the moment they land.
        if let Ok(Some(bytes)) = storage.get("fee_quote_v1") {
            if let Ok(q) = serde_json::from_slice::<crate::fee_estimator::FeeQuote>(&bytes) {
                fee_estimator.seed_persisted(q);
            }
        }
        let chain_filter = Arc::new(LijChainFilter::new());
        let cooperative_chain = Arc::new(CooperativeChainHandler::new());
        let independent = Arc::new(IndependentClient::with_defaults(Arc::new(StubEsploraHttp::new())));
        broadcaster.set_independent(independent.clone());
        fee_estimator.set_independent(independent.clone());
        let sync_state = Arc::new(SyncStateTracker::new());
        let cold_start = Arc::new(ColdStartOrchestrator::new());
        let cooperative_bridge = CooperativeChainBridge::new(
            cooperative_chain.clone(),
            chain_filter.clone(),
            fee_estimator.clone(),
            broadcaster.clone(),
        );

        let chain_coordinator = Arc::new(Mutex::new(
            crate::chain_coordinator::ChainCoordinator::new(
                0,
                bitcoin::BlockHash::all_zeros(),
            )
        ));

        let mut node = Self {
            config, network, root_key, active_lsp: None,
            keys_manager, signer_provider,
            outstanding_close_attempts: Arc::new(Mutex::new(std::collections::HashMap::new())),
            funding_spend_sightings: Arc::new(Mutex::new(std::collections::HashMap::new())),
            payment_outcomes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            claimed_payments: Arc::new(Mutex::new(std::collections::HashMap::new())),
            #[allow(deprecated)]
            closed_channel_watcher: crate::closed_channel_watcher::ClosedChannelWatcher::new(),
            network_graph, scorer, storage,
            chain_monitor: None,
            output_sweeper: None,
            channel_manager: None,
            peer_manager: None,
            broadcaster,
            fee_estimator,
            chain_filter,
            cooperative_chain,
            cooperative_bridge,
            chain_coordinator,
            independent,
            sync_state,
            cold_start,
            last_independent_fetch_tick: std::sync::atomic::AtomicU64::new(0),
            funding_reconcile_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            funding_reconcile_inflight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            funding_reconcile_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            walk_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            walk_last_tick: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            funding_walk_force: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            accepting_channels: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            backup_dirty: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            manager_dirty: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            persist_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            persist_skew: std::sync::atomic::AtomicBool::new(false),
        };
        node.init_channel_manager()?;
        node.init_peer_manager()?;
        node.hydrate_chain_coordinator()?;
        Ok(node)
    }

    /// Restore a previously persisted node from storage.
    ///
    /// Reads encrypted ChannelMonitor blobs and the ChannelManager blob,
    /// rehydrates them via `ChannelManagerReadArgs`, then re-watches each
    /// monitor in the freshly built ChainMonitor. Falls back to `Self::new`
    /// if no persisted state is found (first-run or post-clear).
    pub async fn restore(
        root_key: RootKey,
        config: WalletConfig,
        storage: Arc<dyn LijStorage>,
    ) -> LijResult<Self> {
        let cm_blob_opt = storage.get(CHANNEL_MANAGER_KEY)?;
        let monitor_keys = storage.list_with_prefix(MONITOR_KEY_PREFIX)?;

        if cm_blob_opt.is_none() && monitor_keys.is_empty() {
            log::info!("restore: no persisted state — creating fresh node");
            return Self::new(root_key, config, storage).await;
        }
        if cm_blob_opt.is_none() {
            return Err(LijError::Storage(format!(
                "restore: {} monitor(s) present but no ChannelManager blob",
                monitor_keys.len()
            )));
        }
        log::info!(
            "restore: rehydrating {} monitor(s) + ChannelManager",
            monitor_keys.len(),
        );

        let network = parse_network(&config.network)?;
        let root_key = Arc::new(root_key);
        let enc_key = root_key.encryption_key();
        let seed = root_key.lightning_node_key()?.private_key.secret_bytes();
        let ts = current_time_secs();
        let keys_manager = Arc::new(KeysManager::new(&seed, ts, (ts * 1000) as u32));
        let counter = PersistedCounter::new(storage.clone())?;
        let signer_provider = Arc::new(LijSignerProvider::new(
            keys_manager.clone(),
            root_key.shutdown_xpriv()?,
            counter,
            network,
        ));

        let logger: DynLogger = Arc::new(LijLogger);
        let network_graph: LijNetworkGraph = Arc::new(NetworkGraph::new(network, logger.clone()));
        let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
            ProbabilisticScoringDecayParameters::default(),
            network_graph.clone(),
            logger.clone(),
        )));
        let broadcaster_typed = Arc::new(LijBroadcaster::new());
        let broadcaster: DynBroadcaster = broadcaster_typed.clone();
        let fee_estimator_typed = Arc::new(LijFeeEstimator::new());
        // v182 (S25, the 510): boot-seed the fee cache from the last
        // persisted quote — a prior between the live sources and the
        // relay floor. Live sources overrule it the moment they land.
        if let Ok(Some(bytes)) = storage.get("fee_quote_v1") {
            if let Ok(q) = serde_json::from_slice::<crate::fee_estimator::FeeQuote>(&bytes) {
                fee_estimator_typed.seed_persisted(q);
            }
        }
        let fee_estimator: DynFeeEst = fee_estimator_typed.clone();
        let chain_filter_typed = Arc::new(LijChainFilter::new());
        let chain_filter: DynFilter = chain_filter_typed.clone();
        let cooperative_chain = Arc::new(CooperativeChainHandler::new());
        let independent = Arc::new(IndependentClient::with_defaults(Arc::new(StubEsploraHttp::new())));
        broadcaster_typed.set_independent(independent.clone());
        fee_estimator_typed.set_independent(independent.clone());
        let sync_state = Arc::new(SyncStateTracker::new());
        let cold_start = Arc::new(ColdStartOrchestrator::new());
        let cooperative_bridge = CooperativeChainBridge::new(
            cooperative_chain.clone(),
            chain_filter_typed.clone(),
            fee_estimator_typed.clone(),
            broadcaster_typed.clone(),
        );
        // Shared with the node struct below so monitor persists (the
        // per-commitment, security-critical writes) flag the cloud backup dirty.
        let backup_dirty = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // S21 item 2: manager-dirty + stamp counter, shared with the persister.
        let manager_dirty = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let persist_seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let persister = Arc::new(LijChannelMonitorPersister::new(
            storage.clone(),
            enc_key,
            backup_dirty.clone(),
            manager_dirty.clone(),
            persist_seq.clone(),
        ));
        let chain_monitor: Arc<LijChainMonitor> = Arc::new(ChainMonitor::new(
            Some(chain_filter.clone()),
            broadcaster.clone(),
            logger.clone(),
            fee_estimator.clone(),
            persister,
        ));
        // OutputSweeper: restores from persisted KVStore state if present,
        // otherwise initializes fresh against BestBlock::from_network. Event
        // hookup (ChannelMonitor::Event::SpendableOutputs → sweeper) is wired
        // separately in background_tick (sub-step 2.3).
        let output_sweeper = crate::sweeper::build_output_sweeper(
            storage.clone(),
            broadcaster_typed.clone(),
            fee_estimator_typed.clone(),
            keys_manager.clone(),
            signer_provider.clone(),
            logger.clone(),
            network,
        )?;
        let router: LijRouter = Arc::new(DefaultRouter::new(
            network_graph.clone(),
            logger.clone(),
            keys_manager.clone(),
            scorer.clone(),
            ProbabilisticScoringFeeParameters::default(),
        ));

        // Decrypt + deserialize each ChannelMonitor.
        let mut monitors: Vec<(BlockHash, ChannelMonitor<crate::signer::LijChannelSigner>)> =
            Vec::with_capacity(monitor_keys.len());
        for key in &monitor_keys {
            let ct = storage.get(key)?.ok_or_else(|| {
                LijError::Storage(format!("monitor key {key} disappeared mid-restore"))
            })?;
            let pt = persist::decrypt(&enc_key, &ct).map_err(|e| {
                LijError::Storage(format!("monitor decrypt failed for {key}: {e}"))
            })?;
            let mut cursor = std::io::Cursor::new(&pt);
            let read = <(BlockHash, ChannelMonitor<crate::signer::LijChannelSigner>)>::read(
                &mut cursor,
                (&*keys_manager, &*signer_provider),
            )
            .map_err(|e| {
                LijError::Storage(format!("monitor deser failed for {key}: {:?}", e))
            })?;
            monitors.push(read);
        }

        // Decrypt + deserialize ChannelManager via ChannelManagerReadArgs.
        let cm_ct = cm_blob_opt.expect("checked above");
        let cm_pt = persist::decrypt(&enc_key, &cm_ct)
            .map_err(|e| LijError::Storage(format!("CM decrypt: {e}")))?;
        let user_config = {
            let mut c = UserConfig::default();
            // Step C.2: minimum_depth=1 for fast UX. Reorg risk at depth 1 is
            // minimal on modern Bitcoin; channel funds are not at risk on
            // reorg, only channel state (which can be re-established). Matches
            // the channelpolicy daemon on UM890 which sets min_accept_depth=1
            // for wallet-class peers. Both directions now converge at 1 conf.
            c.channel_handshake_config.minimum_depth = 1;
            c.channel_handshake_config.their_channel_reserve_proportional_millionths = LSP_RESERVE_PPM.load(std::sync::atomic::Ordering::Relaxed); // v213 evil-LSP reserve dial
            // JIT receive: the LSP forwards the full net amount as a SINGLE
            // inbound HTLC. LDK's default inbound in-flight cap is 10% of
            // channel capacity, which rejects any JIT receive above ~10% of the
            // (payment+buffer) channel (e.g. a 17,001-sat receive over a 67,001
            // channel: cap 6,700 < 17,001 -> HTLC never traverses, LSP strands
            // an empty channel, payer times out). Raise to 100% so a single
            // HTLC up to the full channel value is accepted. Inbound-only; no
            // sender risk (we only claim with the preimage). Matches Phoenix/
            // Breez. Affects newly accepted channels only.
            c.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
            // Bound coop-close fee a devious LSP could negotiate (v41).
            c.channel_config.force_close_avoidance_max_fee_satoshis = COOP_CLOSE_MAX_FEE_OVERAGE_SAT;
            // Phase F-2 (LSPS2): zero-conf channels per LND require ANCHORS
            // commitment type, which LDK refuses by default. Flip the flag so
            // LDK will negotiate anchors_zero_fee_htlc_tx when proposed. Note:
            // anchor outputs (330 sats each side) lock briefly in commitment
            // outputs. On force-close they'd require on-chain fee-bumping to
            // sweep — currently handled manually via OutputSweeper backlog
            // (item #8). Acceptable tradeoff for zero-conf JIT receive.
            c.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
            log::info!("[Phase F-2 diag] restore-path UserConfig.negotiate_anchors_zero_fee_htlc_tx = {}", c.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx);
            // Phase F-3 (LSPS2): zero-conf channels require option_scid_alias per
            // BOLT-2 ("If option_zeroconf is negotiated, the sender MUST set
            // option_scid_alias to negotiated/required"). LDK advertises the
            // scid_alias feature only when negotiate_scid_privacy is true; the
            // flag name is misleading — it controls advertisement of both
            // option_scid_alias and the privacy mode built on top of it.
            c.channel_handshake_config.negotiate_scid_privacy = true;
            log::info!("[Phase F-2 diag] restore-path UserConfig.negotiate_scid_privacy = {}", c.channel_handshake_config.negotiate_scid_privacy);
            // Phase E (LSPS2): manually_accept_inbound_channels=true gates
            // every inbound open through Event::OpenChannelRequest, where
            // we accept only zero-conf private channels from the active LSP.
            // Without this, LDK auto-accepts all conformant channels — which
            // would let any peer open inbound (and we'd reject browser-wallet
            // unfriendly defaults like announced channels at handshake time).
            c.manually_accept_inbound_channels = true;
            c
        };
        // Phase F-3 diagnostic: log what LDK considers its supported channel_type
        // features given our UserConfig. Cross-reference with what LND sends in
        // open_channel (enable LND PEER=debug logging to capture LND's side).
        // Diagnostic-only — no behavioral change.
        let monitor_refs: Vec<&mut ChannelMonitor<crate::signer::LijChannelSigner>> =
            monitors.iter_mut().map(|(_, m)| m).collect();
        let read_args = ChannelManagerReadArgs::new(
            keys_manager.clone(),
            keys_manager.clone(),
            signer_provider.clone(),
            fee_estimator.clone(),
            chain_monitor.clone(),
            broadcaster.clone(),
            router.clone(),
            logger.clone(),
            user_config,
            monitor_refs,
        );
        // S45: register pending cooperative closes so LDK's startup rule (a
        // monitor whose channel is missing from the manager → broadcast the holder
        // commitment) HOLDS for them instead of double-spending the cooperative
        // transaction still waiting in the mempool. Must precede the manager read.
        {
            let clog = ClosedChannelLog::new(storage.clone());
            if let Ok(records) = clog.list() {
                for r in records.iter().filter(|r| {
                    matches!(r.kind, CloseKind::Cooperative)
                        && r.coop_close_tx_hex.is_some()
                        && !r.closing_confirmed
                        && !r.hold_released
                }) {
                    if let Some(txid) = r
                        .funding_txo_hex
                        .as_deref()
                        .and_then(|f| f.split(':').next())
                        .and_then(|t| t.parse::<bitcoin::Txid>().ok())
                    {
                        lightning::chain::channelmonitor::lij_coop_hold::insert(&txid);
                        log::info!(
                            "restore: holding LDK's commitment broadcast for {} — cooperative close {} pending",
                            &r.channel_id_hex[..12.min(r.channel_id_hex.len())],
                            r.closing_txid_hex.as_deref().unwrap_or("?")
                        );
                    }
                }
            }
        }
        let mut cursor = std::io::Cursor::new(&cm_pt);
        let (_block_hash, channel_manager): (BlockHash, LijChannelManager) =
            ReadableArgs::read(&mut cursor, read_args)
                .map_err(|e| LijError::Storage(format!("CM deser failed: {:?}", e)))?;
        let channel_manager = Arc::new(channel_manager);

        // Re-watch each monitor in the chain monitor (consumes the monitor).
        for (_block_hash, monitor) in monitors {
            let outpoint = monitor.get_funding_txo().0;
            chain_monitor
                .watch_channel(outpoint, monitor)
                .map_err(|e| LijError::Storage(format!("watch_channel failed: {:?}", e)))?;
        }

        log::info!(
            "restore: ChannelManager has {} channel(s)",
            channel_manager.list_channels().len()
        );

        let chain_coordinator = Arc::new(Mutex::new(
            crate::chain_coordinator::ChainCoordinator::new(
                0,
                bitcoin::BlockHash::all_zeros(),
            )
        ));
        // Hydrate from existing channels — protects each channel's funding-tx
        // confirmation against accidental unconfirm by independent observations.
        {
            let mut hydration: Vec<(bitcoin::Txid, u32, u32)> = Vec::new();
            for ch in channel_manager.list_channels() {
                if let Some(scid) = ch.short_channel_id {
                    let height = (scid >> 40) as u32;
                    let tx_index = ((scid >> 16) & 0xFFFFFF) as u32;
                    if let Some(funding) = ch.funding_txo {
                        hydration.push((funding.txid, height, tx_index));
                    }
                }
            }
            chain_coordinator
                .lock()
                .expect("ChainCoordinator mutex poisoned at hydration")
                .hydrate_from_channels(hydration);
        }

        let mut node = Self {
            config,
            network,
            root_key,
            active_lsp: None,
            keys_manager,
            signer_provider,
            outstanding_close_attempts: Arc::new(Mutex::new(std::collections::HashMap::new())),
            funding_spend_sightings: Arc::new(Mutex::new(std::collections::HashMap::new())),
            payment_outcomes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            claimed_payments: Arc::new(Mutex::new(std::collections::HashMap::new())),
            #[allow(deprecated)]
            closed_channel_watcher: crate::closed_channel_watcher::ClosedChannelWatcher::new(),
            network_graph,
            scorer,
            storage,
            chain_monitor: Some(chain_monitor),
            output_sweeper: Some(output_sweeper),
            channel_manager: Some(channel_manager),
            peer_manager: None,
            broadcaster: broadcaster_typed,
            fee_estimator: fee_estimator_typed,
            chain_filter: chain_filter_typed,
            cooperative_chain: cooperative_chain.clone(),
            cooperative_bridge,
            chain_coordinator,
            independent,
            sync_state,
            cold_start,
            last_independent_fetch_tick: std::sync::atomic::AtomicU64::new(0),
            funding_reconcile_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            funding_reconcile_inflight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            funding_reconcile_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            walk_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            walk_last_tick: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            funding_walk_force: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            accepting_channels: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            backup_dirty,
            manager_dirty,
            persist_seq,
            persist_skew: std::sync::atomic::AtomicBool::new(false),
        };
        node.init_peer_manager()?;
        Ok(node)
    }

    /// Hydrate the chain coordinator from existing channels' SCID-encoded
    /// confirmation data. Protects each existing channel's funding-tx
    /// confirmation against accidental unconfirm by independent observations.
    /// Called from `new()` after init (no-op for fresh wallets) and from
    /// `restore()` inline (when channels are loaded).
    fn hydrate_chain_coordinator(&self) -> LijResult<()> {
        let cm = match self.channel_manager.as_ref() {
            Some(cm) => cm,
            None => return Ok(()),
        };
        let mut hydration: Vec<(bitcoin::Txid, u32, u32)> = Vec::new();
        for ch in cm.list_channels() {
            if let Some(scid) = ch.short_channel_id {
                let height = (scid >> 40) as u32;
                let tx_index = ((scid >> 16) & 0xFFFFFF) as u32;
                if let Some(funding) = ch.funding_txo {
                    hydration.push((funding.txid, height, tx_index));
                }
            }
        }
        let mut coord = self.chain_coordinator.lock()
            .map_err(|e| LijError::Node(format!("Coordinator lock poisoned: {e}")))?;
        coord.hydrate_from_channels(hydration);
        Ok(())
    }

    fn init_channel_manager(&mut self) -> LijResult<()> {
        let logger: DynLogger           = Arc::new(LijLogger);
        let broadcaster: DynBroadcaster = self.broadcaster.clone();
        let fee_estimator: DynFeeEst    = self.fee_estimator.clone();
        let chain_filter: DynFilter     = self.chain_filter.clone();
        // S21 item 2: load-time skew detect. mon > cm at load means an
        // interrupted save left the manager stale — LDK will protectively FC
        // (the SAFE direction; the reverse would be critical). Surface it
        // honestly instead of letting the close be silent. The counter
        // reseeds at max so stamps stay monotonic across restarts.
        let seq_cm = self.storage.get(persist::SEQ_CM_KEY).ok().flatten()
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes).unwrap_or(0);
        let seq_mon = self.storage.get(persist::SEQ_MON_KEY).ok().flatten()
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes).unwrap_or(0);
        if seq_mon > seq_cm {
            log::warn!("[PERSIST-SKEW] monitor stamp {seq_mon} > manager stamp {seq_cm} at load — interrupted save; a protective force-close may follow");
            self.persist_skew.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.persist_seq.store(seq_cm.max(seq_mon), std::sync::atomic::Ordering::Relaxed);
        let persister = Arc::new(LijChannelMonitorPersister::new(
            self.storage.clone(),
            self.root_key.encryption_key(),
            self.backup_dirty.clone(),
            self.manager_dirty.clone(),
            self.persist_seq.clone(),
        ));

        let chain_monitor: Arc<LijChainMonitor> = Arc::new(ChainMonitor::new(
            Some(chain_filter), broadcaster.clone(), logger.clone(), fee_estimator.clone(), persister,
        ));
        self.chain_monitor = Some(chain_monitor.clone());

        // OutputSweeper: restores from persisted KVStore state if present,
        // otherwise initializes fresh against BestBlock::from_network. See
        // crate::sweeper::build_output_sweeper for details. Event hookup
        // (ChannelMonitor::Event::SpendableOutputs → sweeper) is wired
        // separately in background_tick (sub-step 2.3).
        let output_sweeper = crate::sweeper::build_output_sweeper(
            self.storage.clone(),
            self.broadcaster.clone(),
            self.fee_estimator.clone(),
            self.keys_manager.clone(),
            self.signer_provider.clone(),
            logger.clone(),
            self.network,
        )?;
        self.output_sweeper = Some(output_sweeper);

        let router: LijRouter = Arc::new(DefaultRouter::new(
            self.network_graph.clone(),
            logger.clone(),
            self.keys_manager.clone(),
            self.scorer.clone(),
            ProbabilisticScoringFeeParameters::default(),
        ));

        let best_block = BestBlock::from_network(self.network);
        let chain_params = ChainParameters { network: self.network, best_block };

        let cm = ChannelManager::new(
            fee_estimator,
            chain_monitor,
            broadcaster,
            router,
            logger,
            self.keys_manager.clone(),
            self.keys_manager.clone(),
            self.signer_provider.clone(),
            {
                let mut config = UserConfig::default();
                // Step C.2: minimum_depth=1 for fast UX. Reorg risk at depth 1
                // is minimal on modern Bitcoin; channel funds are not at risk
                // on reorg, only channel state (which can be re-established).
                // Matches the channelpolicy daemon on UM890 which sets
                // min_accept_depth=1 for wallet-class peers. Step C.4 will
                // delete the synthetic-tip block in background_tick now that
                // depth=1 makes it provably unnecessary.
                config.channel_handshake_config.minimum_depth = 1;
                config.channel_handshake_config.their_channel_reserve_proportional_millionths = LSP_RESERVE_PPM.load(std::sync::atomic::Ordering::Relaxed); // v213 evil-LSP reserve dial
                // JIT receive single-HTLC fix — see restore-path comment.
                // Raise inbound in-flight cap from LDK default 10% to 100% so a
                // full-net-amount JIT HTLC is accepted (inbound-only; safe).
                config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
                // Bound coop-close fee a devious LSP could negotiate (v41).
                config.channel_config.force_close_avoidance_max_fee_satoshis = COOP_CLOSE_MAX_FEE_OVERAGE_SAT;
                // Phase F-2 (LSPS2): see restore-path config — anchors required
                // for zero-conf JIT receive.
                config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
                log::info!("[Phase F-2 diag] create-path UserConfig.negotiate_anchors_zero_fee_htlc_tx = {}", config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx);
                // Phase F-3 (LSPS2): see restore-path comment — required for
                // option_zeroconf per BOLT-2.
                config.channel_handshake_config.negotiate_scid_privacy = true;
                log::info!("[Phase F-2 diag] create-path UserConfig.negotiate_scid_privacy = {}", config.channel_handshake_config.negotiate_scid_privacy);
                // Phase E (LSPS2): see restore-path config — same reasoning.
                config.manually_accept_inbound_channels = true;
                // Phase F-3 diagnostic: see restore-path block.
                config
            },
            chain_params,
            current_time_secs() as u32,
        );

        self.channel_manager = Some(Arc::new(cm));
        log::info!("ChannelManager ready");
        Ok(())
    }

    fn init_peer_manager(&mut self) -> LijResult<()> {
        let channel_manager = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager must be initialized before PeerManager".into()))?
            .clone();

        let logger: DynLogger = Arc::new(LijLogger);
        let ignoring = Arc::new(IgnoringMessageHandler {});

        let message_handler = build_message_handler(channel_manager, ignoring, self.cooperative_chain.clone());

        let peer_manager = PeerManager::new(
            message_handler,
            current_time_secs() as u32,
            &ephemeral_bytes(),
            logger,
            self.keys_manager.clone(),
        );

        self.peer_manager = Some(Arc::new(peer_manager));
        log::info!("PeerManager ready");
        Ok(())
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /// v221 (device-file import): read-only accessors for the import path.
    pub fn storage_ref(&self) -> &dyn LijStorage { self.storage.as_ref() }
    pub fn root_key_ref(&self) -> &RootKey { self.root_key.as_ref() }

    /// Allocate a new socket id. Called by lij-wasm when opening a new WebSocket.
    /// v219 (DEFECT B, F1 root-kill): REALM-GLOBAL, not per-instance. The old
    /// per-node counter restarted at 1 on every wallet construction while
    /// lij-wasm's WS_MAP static outlives instances — a second construction in
    /// one page load (boot-retry paths) collided with the first instance's
    /// live entries and dropped closures whose socket events were still in
    /// flight: the "closure invoked recursively or after being dropped" boot
    /// throw (lij_wasm.js:1893). A process-static sequence makes collision
    /// impossible by construction; LDK needs only per-PeerManager uniqueness,
    /// which global uniqueness satisfies.
    pub fn next_socket_id(&self) -> u64 {
        NEXT_SOCKET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn signer_provider(&self) -> &Arc<crate::signer::LijSignerProvider> {
    &self.signer_provider
}

    /// Access the OutputSweeper. `None` only during the narrow window before
    /// init_channel_manager() or restore() completes. After init the
    /// sweeper is the destination for SpendableOutputDescriptor events and
    /// builds + broadcasts sweep transactions to BIP84 destinations at
    /// m/84'/0'/0'/0/n. Used by background_tick (sub-step 2.3) and by any
    /// future seed-only recovery code that wants to inject descriptors
    /// directly (Phase 1c).
    pub fn output_sweeper(&self) -> Option<&Arc<crate::sweeper::LijOutputSweeper>> {
        self.output_sweeper.as_ref()
    }

    /// Convert the optional OutputSweeper Arc into the `Option<&dyn Confirm>`
    /// shape that `PendingLdkAction::apply` expects. Used at every call site
    /// where chain coordinator actions get applied to LDK, so the sweeper
    /// receives `transactions_confirmed` / `best_block_updated` /
    /// `transaction_unconfirmed` notifications in lockstep with chain_monitor
    /// and channel_manager. Without these notifications the sweeper's
    /// `regenerate_spend_if_necessary` never fires and no sweep tx is built.
    fn output_sweeper_as_confirm(&self) -> Option<&dyn lightning::chain::Confirm> {
        self.output_sweeper
            .as_ref()
            .map(|s| s.as_ref() as &dyn lightning::chain::Confirm)
    }

    /// v102: how many tracked sweeper outputs are still awaiting their first
    /// confirmation (status "sweeping")? The Tier-2 sync uses this to decide
    /// whether the sweeper-confirmation reconcile is worth a block fetch — it is
    /// a no-op on the overwhelmingly common path (no closes maturing).
    pub fn sweeper_pending_first_count(&self) -> usize {
        self.output_sweeper
            .as_ref()
            .map(|s| {
                s.tracked_spendable_outputs()
                    .iter()
                    .filter(|o| {
                        matches!(
                            o.status,
                            lightning::util::sweep::OutputSpendStatus::PendingFirstConfirmation { .. }
                        )
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// TEMP diagnostic: why aren't matured sweeps broadcasting? Returns JSON with
    /// the broadcaster queue depth + recorded broadcast failures (did a sweep get
    /// enqueued and hard-fail?), and the sweeper's INTERNAL best-block height
    /// (if it's behind the real tip, matured outputs won't trigger). Plus a
    /// per-tracked-output dump of status + maturity vs the sweeper's own height.
    /// Remove with the other temp diagnostics.
    pub fn sweeper_broadcast_diag(&self, real_tip: u32) -> String {
        let queue_depth = self.broadcaster.queue_depth();
        let failures = self.broadcaster.peek_failures();
        let fail_json: Vec<String> = failures.iter().map(|f| format!(
            "{{\"txid\":\"{}\",\"attempts\":{},\"error\":\"{}\"}}",
            f.txid_hex, f.attempts,
            f.last_error.replace('\\', "\\\\").replace('"', "\\\"")
        )).collect();

        let (sweeper_height, outs_json): (i64, Vec<String>) = match self.output_sweeper.as_ref() {
            Some(s) => {
                let h = s.current_best_block().height as i64;
                let outs = s.tracked_spendable_outputs().iter().map(|o| {
                    use lightning::util::sweep::OutputSpendStatus as St;
                    let (status, delay): (&str, i64) = match &o.status {
                        St::PendingInitialBroadcast { delayed_until_height } =>
                            ("pending_broadcast", delayed_until_height.map(|x| x as i64).unwrap_or(-1)),
                        St::PendingFirstConfirmation { .. } => ("sweeping", -1),
                        St::PendingThresholdConfirmations { .. } => ("confirming", -1),
                    };
                    format!("{{\"status\":\"{}\",\"delayed_until_height\":{}}}", status, delay)
                }).collect::<Vec<_>>();
                (h, outs)
            }
            None => (-1, vec![]),
        };

        format!(
            "{{\"real_tip\":{},\"sweeper_height\":{},\"sweeper_behind_by\":{},\"queue_depth\":{},\"failures\":[{}],\"tracked\":[{}]}}",
            real_tip, sweeper_height,
            if sweeper_height >= 0 { real_tip as i64 - sweeper_height } else { -1 },
            queue_depth, fail_json.join(","), outs_json.join(",")
        )
    }

    /// v149 TEMP diagnostic: faithfully REPLICATE the OutputSweeper's internal
    /// spend_outputs() to find why matured sweeps fail (spend_outputs returns a
    /// bare Err(()) -> regenerate_spend_if_necessary returns None -> nothing
    /// broadcast, nothing queued, no failure recorded). Mirrors sweep.rs
    /// spend_outputs line-for-line, but split into steps with full detail:
    ///   1. fee rate (OutputSpendingFee) — is the 3x-fast multiplier too high?
    ///   2. change-destination script (m/84) — does derivation succeed?
    ///   3. the spend itself — try ALL matured descriptors batched (faithful to
    ///      the sweeper), then if that fails, EACH individually to isolate which
    ///      output the signer can't spend.
    /// Reports total sats vs fee so the small-output-vs-fee hypothesis is testable.
    pub fn sweeper_spend_attempt_diag(&self, real_tip: u32) -> String {
        use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
        use lightning::sign::{OutputSpender, ChangeDestinationSource};
        use lightning::util::sweep::OutputSpendStatus as St;

        let sweeper = match self.output_sweeper.as_ref() {
            Some(s) => s,
            None => return "{\"err\":\"no sweeper\"}".to_string(),
        };
        let fee_rate = self.fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::OutputSpendingFee);

        // Change-destination script (step 2). LijChangeDestinationSource wraps the
        // signer_provider; call the same path it uses.
        let change_src = crate::sweeper::LijChangeDestinationSource::new(self.signer_provider.clone());
        let (change_ok, change_spk) = match change_src.get_change_destination_script() {
            Ok(spk) => (true, hex::encode(spk.as_bytes())),
            Err(()) => (false, String::new()),
        };

        // Collect matured (filter-passing) descriptors: not confirmed, not delayed.
        let tracked = sweeper.tracked_spendable_outputs();
        let mut matured: Vec<&lightning::sign::SpendableOutputDescriptor> = Vec::new();
        let mut total_sats: u64 = 0;
        let mut per_desc: Vec<String> = Vec::new();
        for o in tracked.iter() {
            let is_pending = matches!(o.status, St::PendingInitialBroadcast { .. });
            let delayed = match &o.status {
                St::PendingInitialBroadcast { delayed_until_height } =>
                    delayed_until_height.map_or(false, |h| real_tip < h),
                _ => false,
            };
            let val = descriptor_value_sats(&o.descriptor);
            let kind = descriptor_kind(&o.descriptor);
            if is_pending && !delayed {
                matured.push(&o.descriptor);
                total_sats += val;
            }
            per_desc.push(format!(
                "{{\"kind\":\"{}\",\"sats\":{},\"pending\":{},\"delayed\":{}}}",
                kind, val, is_pending, delayed
            ));
        }

        let cur_height = real_tip;
        let locktime = Some(bitcoin::blockdata::locktime::absolute::LockTime::from_height(cur_height)
            .unwrap_or(bitcoin::blockdata::locktime::absolute::LockTime::ZERO));
        let secp = bitcoin::secp256k1::Secp256k1::new();

        // Step 3a: batched spend of ALL matured descriptors (what the sweeper does).
        let change_spk_buf = match change_src.get_change_destination_script() {
            Ok(s) => Some(s),
            Err(()) => None,
        };
        let mut batched_result = String::from("\"skipped (no change script)\"");
        let mut individual: Vec<String> = Vec::new();
        if let Some(spk) = change_spk_buf.clone() {
            let batched = self.keys_manager.spend_spendable_outputs(
                &matured, Vec::new(), spk, fee_rate, locktime, &secp,
            );
            batched_result = match &batched {
                Ok(tx) => format!("\"OK txid={} vbytes~={}\"", tx.txid(), tx.vsize()),
                Err(()) => "\"ERR (signer rejected the batch)\"".to_string(),
            };
            // Step 3b: if batched failed, isolate per-descriptor.
            if batched.is_err() {
                for o in tracked.iter() {
                    if !matches!(o.status, St::PendingInitialBroadcast { delayed_until_height } if delayed_until_height.map_or(true, |h| real_tip >= h)) {
                        continue;
                    }
                    if let Some(spk2) = change_spk_buf.clone() {
                        let one = [&o.descriptor];
                        let r = self.keys_manager.spend_spendable_outputs(
                            &one, Vec::new(), spk2, fee_rate, locktime, &secp,
                        );
                        individual.push(format!(
                            "{{\"kind\":\"{}\",\"sats\":{},\"result\":\"{}\"}}",
                            descriptor_kind(&o.descriptor),
                            descriptor_value_sats(&o.descriptor),
                            match r { Ok(tx) => format!("OK txid={}", tx.txid()), Err(()) => "ERR".to_string() }
                        ));
                    }
                }
            }
        }

        format!(
            "{{\"fee_rate_sat_per_kw\":{},\"fee_rate_sat_per_vb_approx\":{:.2},\"matured_count\":{},\"matured_total_sats\":{},\"change_script_ok\":{},\"change_spk\":\"{}\",\"batched_spend\":{},\"per_descriptor\":[{}],\"individual_spend\":[{}]}}",
            fee_rate, (fee_rate as f64) / 250.0, matured.len(), total_sats,
            change_ok, change_spk, batched_result,
            per_desc.join(","), individual.join(",")
        )
    }

    /// v102: hand the OutputSweeper the REAL confirmed sweep txs (fetched from the
    /// blocks the Tier-2 scan already covers) so it advances sweeping -> confirming.
    ///
    /// Why this is needed: the sweeper rebuilds each unconfirmed sweep every block
    /// (locktime = current height -> new txid each time), so its own
    /// `latest_spending_tx` drifts away from the tx that actually confirmed and it
    /// never recognizes its sweep landing — it sits at "sweeping" forever while the
    /// scan independently records the swept output into spendable (a double-count
    /// in the maturing alert). Feeding the real confirmed tx fixes this at the
    /// source: `is_spent_in()` matches each tx to the source descriptor it spends
    /// (NOT by txid or value), so the right tracked output advances and any
    /// non-sweep txs fed alongside (genuine receives/change) match nothing and are
    /// harmless. Synthetic header mirrors the cooperative-tip pattern (Confirm has
    /// no chain-order assertion; the caller's txid filter against the validated
    /// view is the integrity guard). Caller passes txs sorted by height ascending.
    /// Returns how many txs were fed.
    pub fn reconcile_sweeper_confirmations(&self, txs: &[(u32, bitcoin::Transaction)]) -> usize {
        let confirm = match self.output_sweeper_as_confirm() {
            Some(c) => c,
            None => return 0,
        };
        for (height, tx) in txs {
            let merkle_root = TxMerkleNode::from_byte_array(tx.txid().to_byte_array());
            let header = Header {
                version: BlockVersion::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 0,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            let tx_refs: Vec<(usize, &bitcoin::Transaction)> = vec![(0usize, tx)];
            confirm.transactions_confirmed(&header, &tx_refs, *height);
        }
        if !txs.is_empty() {
            log::info!(
                "reconcile_sweeper_confirmations: fed {} confirmed tx(s) to the sweeper",
                txs.len()
            );
        }
        txs.len()
    }

    pub fn storage_clone(&self) -> Arc<dyn LijStorage> {
    self.storage.clone()
}

    /// Access the PeerManager. Used by lij-wasm to invoke read_event, timer_tick,
    /// and process_events when WebSocket callbacks fire.
    pub fn peer_manager(&self) -> LijResult<Arc<LijPeerManagerType>> {
        self.peer_manager.as_ref()
            .cloned()
            .ok_or_else(|| LijError::Node("PeerManager not initialized".into()))
    }

    /// Initiate an outbound connection to a Lightning peer.
    /// Called after a WebSocket is opened; returns the first bytes to send
    /// (Noise handshake act one). lij-wasm writes these to the WebSocket.
    pub fn new_outbound_connection(
        &self,
        peer_pubkey: bitcoin::secp256k1::PublicKey,
        socket_id: u64,
    ) -> LijResult<Vec<u8>> {
        let pm = self.peer_manager()?;
        let descriptor = LijSocketDescriptor::new(socket_id);

        // remote_network_address=None: browser behind NAT, no public address to announce
        pm.new_outbound_connection(peer_pubkey, descriptor, None)
            .map_err(|e| LijError::Node(format!("new_outbound_connection: {:?}", e)))
    }

    /// Phase 1c-write: build a [`ChannelRecord`] for a newly-ready channel and
    /// fire-and-forget upload it to the active LSP's registry.
    ///
    /// Called from the `Event::ChannelReady` arm in `background_tick`'s event
    /// closure. Silently no-ops when:
    ///   - No active LSP is set (rare — wallet has never connected to one).
    ///   - The channel isn't found in `list_channels()` (race with close).
    ///   - The funding outpoint isn't yet known (extremely rare; would mean
    ///     `ChannelReady` fired before funding TX confirmed, which the LDK
    ///     state machine doesn't permit).
    ///   - `chain_monitor` doesn't have a matching `ChannelMonitor`.
    ///
    /// Logs at WARN level for each of these so operators can spot a wallet
    /// running without registry coverage. Step 3 of Phase 1c-write will add
    /// a KV-backed retry queue so transient HTTP failures (LSP down) don't
    /// lose the upload.
    /// Register a Web Push wake subscription for offline-receive (D-1 2c).
    /// Signs the `push-subscribe` challenge with the node identity key (same
    /// auth as the channel registry) and POSTs to the active LSP. Awaitable so
    /// the frontend learns success/failure.
    pub async fn register_push_subscription(&self, subscription_json: &str) -> LijResult<()> {
        let endpoint = match self.active_lsp.as_ref() {
            Some(lsp) => lsp.info.endpoint.clone(),
            None => {
                return Err(crate::error::LijError::Lsp(
                    "no active LSP — cannot register push subscription".into(),
                ));
            }
        };
        crate::registry_client::register_push_subscription(
            &self.keys_manager,
            &endpoint,
            subscription_json,
        )
        .await
    }

    fn upload_channel_record_for_ready(&self, channel_id: ChannelId) {
        // Active LSP endpoint (the only place we know to POST to).
        let endpoint = match self.active_lsp.as_ref() {
            Some(lsp) => lsp.info.endpoint.clone(),
            None => {
                log::warn!(
                    "Registry: ChannelReady fired but no active LSP — skipping upload for {:?}",
                    channel_id
                );
                return;
            }
        };

        let cm = match self.channel_manager.as_ref() {
            Some(cm) => cm,
            None => {
                log::warn!("Registry: ChannelManager not initialized — skipping upload");
                return;
            }
        };
        let chain_monitor = match self.chain_monitor.as_ref() {
            Some(cm) => cm,
            None => {
                log::warn!("Registry: ChainMonitor not initialized — skipping upload");
                return;
            }
        };

        // Find the channel in the live list.
        let details = match cm.list_channels().into_iter().find(|d| d.channel_id == channel_id) {
            Some(d) => d,
            None => {
                log::warn!(
                    "Registry: channel {:?} not in list_channels() at ChannelReady — skipping",
                    channel_id
                );
                return;
            }
        };

        let funding_outpoint = match details.funding_txo {
            Some(o) => o,
            None => {
                log::warn!(
                    "Registry: channel {:?} has no funding_txo at ChannelReady — skipping",
                    channel_id
                );
                return;
            }
        };

        // commit_type from negotiated channel_type. Anchors (either flavor) = ANCHORS;
        // else legacy static_remote_key. Mirrors the LSP-side hardcoded "ANCHORS"
        // for current LSPS2 channels but stays correct if LSPS1 (STATIC_REMOTE_KEY)
        // ever ships.
        let commit_type = match details.channel_type.as_ref() {
            Some(ct) if ct.requires_anchors_zero_fee_htlc_tx()
                     || ct.requires_anchors_nonzero_fee_htlc_tx() => "ANCHORS",
            Some(_) => "STATIC_REMOTE_KEY",
            None => {
                // Should be impossible for a Ready channel — but if it happens,
                // default to ANCHORS (current LSPS2 norm) and log.
                log::warn!(
                    "Registry: channel {:?} has no channel_type at ChannelReady — defaulting to ANCHORS",
                    channel_id
                );
                "ANCHORS"
            }
        };

        // channel_keys_id read via our LDK patch (see channelmonitor.rs:1450).
        // The upstream `do_signer_call` API is #[cfg(test)] gated and not
        // usable from production code.
        let channel_keys_id: [u8; 32] = match chain_monitor.get_monitor(funding_outpoint) {
            Ok(monitor) => monitor.channel_keys_id(),
            Err(()) => {
                log::warn!(
                    "Registry: no ChannelMonitor for {:?} (funding {:?}) — skipping upload",
                    channel_id, funding_outpoint
                );
                return;
            }
        };

        let record = crate::registry_client::ChannelRecord {
            channel_id: hex::encode(channel_id.0),
            // Display-format txid (big-endian, matches Esplora and explorers).
            // Phase 1c-recover will look up the funding TX in chain APIs using
            // this string so it MUST be the display format, not raw bytes.
            funding_txid: funding_outpoint.txid.to_string(),
            funding_vout: funding_outpoint.index as u32,
            channel_value_sat: details.channel_value_satoshis,
            commit_type: commit_type.to_string(),
            channel_keys_id_hex: hex::encode(channel_keys_id),
            close_height: None,
            closing_txid: None,
        };

        log::info!(
            "Registry: scheduling upload — channel_id={} funding={}:{} value={} type={}",
            record.channel_id, record.funding_txid, record.funding_vout,
            record.channel_value_sat, record.commit_type
        );

        // Phase 1c-write Step 3: persist to KV BEFORE attempting upload. If
        // the wallet crashes mid-upload or the LSP returns an error, the
        // record stays in storage and process_registry_retries() will retry
        // on the next 30-second tick. On successful upload we delete the KV
        // entry from inside the spawned future.
        let pending_key = format!("{}{}", Self::REGISTRY_PENDING_PREFIX, record.channel_id);
        let record_bytes = match serde_json::to_vec(&record) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Registry: serialize for KV failed: {e} — upload skipped");
                return;
            }
        };
        if let Err(e) = self.storage.set(&pending_key, &record_bytes) {
            log::error!("Registry: KV persist of pending entry failed: {e} — upload skipped");
            return;
        }

        // Fire-and-forget the async upload. KeysManager is cloned (Arc), so
        // the future is 'static. wasm32 only — native test builds skip.
        #[cfg(target_arch = "wasm32")]
        {
            let km = self.keys_manager.clone();
            let storage = self.storage.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match crate::registry_client::upload_channel_record(
                    &km, &endpoint, &record,
                ).await {
                    Ok(()) => {
                        log::info!("Registry: upload OK channel_id={}", record.channel_id);
                        if let Err(e) = storage.delete(&pending_key) {
                            log::warn!(
                                "Registry: failed to clear pending KV after success: {e} \
                                 — retry will re-upload (idempotent at LSP)"
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Registry: upload FAIL channel_id={} — {} (will retry every 30s)",
                            record.channel_id, e
                        );
                    }
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Native target (test builds): no async runtime / no spawn_local.
            // Touch the variables to silence unused-variable warnings.
            let _ = (endpoint, record, pending_key);
        }
    }

    /// KV key prefix for pending registry uploads. Phase 1c-write Step 3.
    const REGISTRY_PENDING_PREFIX: &'static str = "lij_registry_pending:";

    /// Phase 1c-write Step 3: drain the pending registry-upload queue.
    ///
    /// Called every 30 seconds from `background_tick`. Enumerates KV entries
    /// with the `lij_registry_pending:` prefix, parses each as a
    /// [`ChannelRecord`], and spawns an upload attempt. Successful uploads
    /// delete the KV entry from inside the spawned future. Failures stay
    /// queued for the next 30-second tick.
    ///
    /// Silently returns if no active LSP (e.g. wallet running cold without
    /// having connected yet) — the queue stays intact for when an LSP gets
    /// configured.
    ///
    /// The LSP's POST endpoint is idempotent (upsert by channel_id), so
    /// concurrent retries from this path and `upload_channel_record_for_ready`
    /// are harmless. Worst case: a duplicate upload that the LSP echoes back
    /// with `replaced: true`.
    fn process_registry_retries(&self) {
        let endpoint = match self.active_lsp.as_ref() {
            Some(lsp) => lsp.info.endpoint.clone(),
            None => return,
        };

        let keys = match self.storage.list_with_prefix(Self::REGISTRY_PENDING_PREFIX) {
            Ok(k) => k,
            Err(e) => {
                log::warn!("Registry retry: list_with_prefix failed: {e}");
                return;
            }
        };

        if keys.is_empty() {
            return;
        }

        log::info!("Registry retry: {} pending upload(s) to drain", keys.len());

        for key in keys {
            let bytes = match self.storage.get(&key) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    // Race: entry vanished between list and get. Harmless.
                    continue;
                }
                Err(e) => {
                    log::warn!("Registry retry: get '{}' failed: {e}", key);
                    continue;
                }
            };
            let record: crate::registry_client::ChannelRecord =
                match serde_json::from_slice(&bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        // Bad entry. Delete it so it doesn't poison every
                        // retry tick. The wallet will never get that channel
                        // into the registry now, but the original upload
                        // already failed too — same loss either way, just
                        // not amplified into a persistent error.
                        log::warn!(
                            "Registry retry: parse '{}' failed: {e} — deleting bad entry",
                            key
                        );
                        let _ = self.storage.delete(&key);
                        continue;
                    }
                };

            #[cfg(target_arch = "wasm32")]
            {
                let km = self.keys_manager.clone();
                let storage = self.storage.clone();
                let endpoint = endpoint.clone();
                let key = key.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match crate::registry_client::upload_channel_record(
                        &km, &endpoint, &record,
                    ).await {
                        Ok(()) => {
                            log::info!(
                                "Registry retry: OK channel_id={}", record.channel_id
                            );
                            if let Err(e) = storage.delete(&key) {
                                log::warn!(
                                    "Registry retry: clear KV after success failed: {e}"
                                );
                            }
                        }
                        Err(e) => {
                            log::debug!(
                                "Registry retry: FAIL channel_id={} — {} (stays queued)",
                                record.channel_id, e
                            );
                        }
                    }
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = (endpoint.clone(), record, key);
            }
        }
    }

    /// v227 (S43, DP GO — same-LSP speed): the ChannelManager EVENT PASS,
    /// extracted VERBATIM from background_tick (it ran only on the 1-second
    /// tick, so a receiver's claim and a sender's "paid" each waited up to a
    /// second — and a just-arrived HTLC waited for process_pending_htlc_forwards
    /// on one tick and its PaymentClaimable on the next). background_tick still
    /// calls it every tick; lij-wasm also runs it on the turn after inbound
    /// bytes. Returns whether any event was seen (the tick folds that into its
    /// persistence decision; an early caller flags manager_dirty instead).
    pub fn process_channel_events(&self) -> LijResult<bool> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let event_seen = AtomicBool::new(false);
        // Collect preimages from PaymentClaimable events so we can call
        // claim_funds() AFTER the closure exits (can't re-borrow cm inside it).
        let preimages_to_claim: std::sync::Mutex<Vec<lightning::ln::PaymentPreimage>> =
            std::sync::Mutex::new(Vec::new());
        // v228: hashes we provably hold no preimage for — failed back after the
        // closure so the sender learns in a second instead of after expiry.
        let hashes_to_fail: std::sync::Mutex<Vec<lightning::ln::PaymentHash>> =
            std::sync::Mutex::new(Vec::new());
        cm.process_pending_events(&|event| {
            log::info!("[Event] {:?}", event);
            event_seen.store(true, Ordering::Relaxed);
            match event {
                lightning::events::Event::PaymentClaimable { payment_hash, amount_msat, purpose, .. } => {
                    log::info!(
                        "PaymentClaimable: hash={:?} amount_msat={}",
                        payment_hash, amount_msat
                    );
                    // Extract preimage from purpose
                    match purpose {
                        lightning::events::PaymentPurpose::Bolt11InvoicePayment { payment_preimage: Some(preimage), .. }
                        | lightning::events::PaymentPurpose::Bolt12OfferPayment { payment_preimage: Some(preimage), .. }
                        | lightning::events::PaymentPurpose::Bolt12RefundPayment { payment_preimage: Some(preimage), .. }
                        | lightning::events::PaymentPurpose::SpontaneousPayment(preimage) => {
                            preimages_to_claim.lock().unwrap().push(preimage);
                        }
                        _ => {
                            // v195 (S30): LNURLp held-claim pool — for_hash
                            // payments carry no preimage in `purpose`; ours
                            // live in wallet storage. Look up, claim, burn.
                            let hash_hex = hex::encode(payment_hash.0);
                            // v228: a readable pool that lacks the hash means the
                            // preimage lives on another device (a restore without
                            // it) or was burned — fail back now. An unreadable pool
                            // keeps holding: the next pass will look again.
                            let pool_checked = self.lnurlp_load_pool_checked();
                            let pool_readable = pool_checked.is_some();
                            let mut pool = pool_checked.unwrap_or_default();
                            if let Some(pre_hex) = pool.remove(&hash_hex) {
                                match hex::decode(&pre_hex) {
                                    Ok(bytes) if bytes.len() == 32 => {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        log::info!(
                                            "LNURLp pool claim: hash={} — preimage found, claiming",
                                            hash_hex
                                        );
                                        preimages_to_claim
                                            .lock()
                                            .unwrap()
                                            .push(lightning::ln::PaymentPreimage(arr));
                                        self.lnurlp_save_pool(&pool);
                                    }
                                    _ => log::warn!(
                                        "LNURLp pool entry for {} is malformed — cannot claim",
                                        hash_hex
                                    ),
                                }
                            } else if let Some((idx, pre)) = self.lnurlp_derive_search(&hash_hex) {
                                // v229: not in the cache but ours by derivation — a
                                // restore, a wiped pool, or a pre-v229 cache miss.
                                log::info!(
                                    "LNURLp derived claim: hash={} index={} — claiming and caching",
                                    hash_hex, idx
                                );
                                preimages_to_claim
                                    .lock()
                                    .unwrap()
                                    .push(lightning::ln::PaymentPreimage(pre));
                                if idx.saturating_add(1) > self.lnurlp_next_index() {
                                    self.lnurlp_set_next_index(idx.saturating_add(1));
                                }
                            } else if pool_readable {
                                log::warn!(
                                    "PaymentClaimable for {} but this device holds no preimage and derivation finds none — failing back so the sender is not left hanging",
                                    hash_hex
                                );
                                hashes_to_fail.lock().unwrap().push(payment_hash);
                            } else {
                                log::warn!(
                                    "PaymentClaimable received but the preimage pool could not be read — holding; will look again"
                                );
                            }
                        }
                    }
                }
                lightning::events::Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
                    log::info!(
                        "PaymentClaimed: hash={:?} amount_msat={} — funds settled into balance",
                        payment_hash, amount_msat
                    );
                    // v206: record the claimed hash so the frontend ledger can
                    // complete the matching pending receive authoritatively
                    // (replaces the unsound balance-delta heuristic).
                    self.claimed_payments
                        .lock()
                        .unwrap()
                        .insert(hex::encode(payment_hash.0), amount_msat / 1000);
                }
                lightning::events::Event::PaymentSent { payment_id, payment_hash, fee_paid_msat, payment_preimage, .. } => {
                    log::info!(
                        "PaymentSent: id={:?} hash={:?} fee_paid_msat={:?}",
                        payment_id, payment_hash, fee_paid_msat
                    );
                    // v8: record outcome for send_payment_with_retries polling.
                    // Keyed by payment_id — every attempt has a fresh PaymentId.
                    if let Some(pid) = payment_id {
                        let preimage_hex = hex::encode(payment_preimage.0);
                        self.payment_outcomes.lock().unwrap().insert(
                            pid,
                            PaymentOutcome::Sent {
                                preimage_hex: Some(preimage_hex),
                                fee_paid_msat,
                            },
                        );
                    }
                }
                lightning::events::Event::PaymentPathFailed {
                    payment_id,
                    payment_hash,
                    payment_failed_permanently,
                    failure: _,
                    path,
                    short_channel_id,
                    ..
                } => {
                    log::warn!(
                        "PaymentPathFailed: id={:?} hash={:?} scid={:?} permanent={} path_len={}",
                        payment_id, payment_hash, short_channel_id,
                        payment_failed_permanently, path.hops.len()
                    );
                    // v8: extract failed channel pair for retry exclusion
                    let failed_pair = short_channel_id
                        .and_then(|scid| extract_failed_pair_from_path(&path, scid));
                    let (failed_from, failed_to) = match failed_pair {
                        Some((f, t)) => (Some(f), Some(t)),
                        None => (None, None),
                    };
                    // Only record if no terminal outcome already there (Sent or
                    // Failed). PathFailed is non-terminal — record only on a
                    // vacant slot so a later Sent for the same id wins.
                    if let Some(pid) = payment_id {
                        let mut map = self.payment_outcomes.lock().unwrap();
                        if !map.contains_key(&pid) {
                            map.insert(
                                pid,
                                PaymentOutcome::PathFailed {
                                    failed_scid: short_channel_id,
                                    failed_from_pubkey: failed_from,
                                    failed_to_pubkey: failed_to,
                                    is_permanent: payment_failed_permanently,
                                },
                            );
                        }
                    }
                }
                lightning::events::Event::PaymentFailed { payment_id, payment_hash, reason, .. } => {
                    log::warn!(
                        "PaymentFailed: id={:?} hash={:?} reason={:?}",
                        payment_id, payment_hash, reason
                    );
                    // v9: preserve PathFailed when reason is RetriesExhausted.
                    // LDK's internal retry budget (Retry::Attempts(0) for our
                    // routed sends) being "exhausted" does NOT mean the payment
                    // is terminally unrecoverable — our outer
                    // send_payment_with_retries loop should still try with the
                    // failed pair excluded. Overwriting PathFailed with
                    // Failed{RetriesExhausted} loses the exclusion data and
                    // forces the retry loop to bail after one attempt. Only
                    // overwrite for genuinely terminal reasons (PaymentExpired,
                    // UserAbandoned, UnexpectedError, etc).
                    let reason_str = format!("{:?}", reason);
                    let mut map = self.payment_outcomes.lock().unwrap();
                    let preserve_path_failed = reason_str.contains("RetriesExhausted")
                        && matches!(map.get(&payment_id), Some(PaymentOutcome::PathFailed { .. }));
                    if !preserve_path_failed {
                        map.insert(
                            payment_id,
                            PaymentOutcome::Failed { reason: reason_str },
                        );
                    }
                }
                // Outbound channel we initiated (open_channel_to_lsp). LDK has
                // negotiated and now needs the funding transaction. We build +
                // sign it from the Tier-2 on-chain view and hand it back; LDK
                // broadcasts it once it has the counterparty's commitment — we
                // must NOT broadcast it ourselves. The funding fee rate (sat/kw)
                // is carried in the low 32 bits of user_channel_id.
                lightning::events::Event::FundingGenerationReady {
                    temporary_channel_id,
                    counterparty_node_id,
                    channel_value_satoshis,
                    output_script,
                    user_channel_id,
                } => {
                    let fee_rate_sat_per_kw = (user_channel_id & 0xFFFF_FFFF) as u32;
                    log::info!(
                        "[Event] FundingGenerationReady: fund {} sat to peer {}… (fee {} sat/kw, temp_chan {:?})",
                        channel_value_satoshis,
                        &hex::encode(counterparty_node_id.serialize())[..16],
                        fee_rate_sat_per_kw,
                        temporary_channel_id
                    );
                    match crate::channel_open::build_funding_tx(
                        &*self.root_key,
                        &*self.storage,
                        self.network,
                        output_script,
                        channel_value_satoshis,
                        fee_rate_sat_per_kw,
                    ) {
                        Ok(funding) => {
                            let funding_txid = funding.tx.txid().to_string();
                            let fee_sats = funding.fee_sats;
                            let spent = funding.spent_outpoints.clone();
                            // Build #4: keep the raw bytes — LDK take()s the
                            // tx at broadcast; this copy backs
                            // rebroadcast-until-seen.
                            let raw_hex = hex::encode(bitcoin::consensus::encode::serialize(&funding.tx));
                            log::info!(
                                "Funding tx built: {} input(s), fee {} sat, change {} sat — handing to LDK (it will broadcast)",
                                funding.inputs, funding.fee_sats, funding.change_sats
                            );
                            match cm.funding_transaction_generated(
                                &temporary_channel_id,
                                &counterparty_node_id,
                                funding.tx,
                            ) {
                                Ok(()) => {
                                    // Reflect the open immediately: reserve the
                                    // inputs (spendable drops now) and show an
                                    // "Adding Lightning capacity" pending row.
                                    // Written to the dedicated pending key so the
                                    // on-chain sync can't clobber it; reconciled
                                    // when Tier-2 sees it confirmed.
                                    let delta = -((channel_value_satoshis as i64)
                                        + (fee_sats as i64));
                                    let n_reserved = spent.len();
                                    match crate::tier2_wallet::record_pending(
                                        &*self.storage,
                                        crate::tier2_wallet::PendingTx {
                                            txid: funding_txid.clone(),
                                            spent_outpoints: spent,
                                            delta_sats: delta,
                                            direction: crate::tier2_wallet::TxDirection::Sent,
                                            kind: crate::tier2_wallet::TxKind::ChannelOpen,
                                            created_at_ms: crate::tier2_wallet::now_ms(),
                                            change_outpoint: funding.change_outpoint.clone(),
                                            change_value_sats: funding.change_sats,
                                            change_index: funding.change_index,
                                            broadcast_seen: false,
                                            raw_tx_hex: Some(raw_hex.clone()),
                                            // v166 (#29-4b): bump metadata is a
                                            // plain-send concept; a funding tx is
                                            // the LSP's to replace, never ours.
                                            dest_addr: None,
                                            dest_sats: None,
                                            fee_sats: None,
                                            fee_rate_sat_per_kw: None,
                                        },
                                    ) {
                                        Ok(()) => log::info!(
                                            "Recorded pending ChannelOpen txid={} delta={} reserving {} input(s)",
                                            funding_txid, delta, n_reserved
                                        ),
                                        Err(e) => log::error!(
                                            "record pending ChannelOpen failed (txid={}): {}",
                                            funding_txid, e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    log::error!("funding_transaction_generated failed: {:?}", e)
                                }
                            }
                        }
                        Err(e) => {
                            // Leave the temp channel to time out; surfaced via logs.
                            log::error!("Failed to build funding tx for outbound channel: {e}");
                        }
                    }
                }
                // Phase E (LSPS2): with manually_accept_inbound_channels=true,
                // every inbound open hits this handler. Accept zero-conf channels
                // from the active LSP only; reject everyone else.
                lightning::events::Event::OpenChannelRequest {
                    temporary_channel_id,
                    counterparty_node_id,
                    funding_satoshis,
                    push_msat,
                    channel_type,
                    ..
                } => {
                    let counterparty_hex = hex::encode(counterparty_node_id.serialize());
                    let active_lsp_pubkey = self.active_lsp
                        .as_ref()
                        .map(|lsp| lsp.info.pubkey.to_lowercase());

                    let is_active_lsp = active_lsp_pubkey
                        .as_ref()
                        .map(|pk| pk == &counterparty_hex.to_lowercase())
                        .unwrap_or(false);

                    if is_active_lsp && !self.accepting_channels.load(std::sync::atomic::Ordering::Relaxed) {
                        // D-1: app is backgrounded/offline, so we can't reliably claim
                        // the JIT HTLC. Refuse the open rather than leave an empty
                        // channel; the sender just sees a normal payment failure.
                        log::warn!(
                            "OpenChannelRequest from active LSP {}…: REJECTING — app not foreground (D-1 gate)",
                            &counterparty_hex[..16]
                        );
                        if let Some(ref cm) = self.channel_manager {
                            let _ = cm.force_close_broadcasting_latest_txn(
                                &temporary_channel_id,
                                &counterparty_node_id,
                            );
                        }
                    } else if is_active_lsp {
                        log::info!(
                            "OpenChannelRequest from active LSP {}…: accepting as 0-conf private (funding={} sat push={} msat)",
                            &counterparty_hex[..16], funding_satoshis, push_msat
                        );
                        if let Some(ref cm) = self.channel_manager {
                            // Terminus v2 (Session 23): in manual-accept mode,
                            // keys generation runs INSIDE the accept call with
                            // the user_channel_id we pass here — and the event
                            // carries the PROPOSED channel_type. Truth-driven
                            // marking: request the m/84 pin iff the type is
                            // non-anchors (a pinned point inside an anchors
                            // P2WSH would break the descriptor sweep). Today's
                            // LND proposes anchors, so JIT channels stay
                            // unmarked/unchanged until the patched LND at the
                            // desk proposes STATIC_REMOTE_KEY — at which point
                            // inbound pins turn on with zero further code.
                            let non_anchors =
                                !channel_type.supports_anchors_zero_fee_htlc_tx();
                            let ucid: u128 = if non_anchors {
                                log::info!(
                                    "[terminus] inbound open is NON-ANCHORS — requesting m/84 pin"
                                );
                                crate::signer::UCID_TERMINUS_PIN_BIT
                            } else {
                                log::info!(
                                    "[terminus] inbound open proposes ANCHORS — no pin (sweeper world)"
                                );
                                0u128
                            };
                            match cm.accept_inbound_channel_from_trusted_peer_0conf(
                                &temporary_channel_id,
                                &counterparty_node_id,
                                ucid,
                            ) {
                                Ok(()) => log::info!(
                                    "Accepted 0-conf channel from LSP (temp_chan={:?})",
                                    temporary_channel_id
                                ),
                                Err(e) => log::error!(
                                    "Accept 0-conf failed (temp_chan={:?}): {:?}",
                                    temporary_channel_id, e
                                ),
                            }
                        } else {
                            log::error!("OpenChannelRequest: no channel_manager — cannot accept");
                        }
                    } else {
                        log::warn!(
                            "OpenChannelRequest from non-LSP peer {}…: rejecting (active_lsp={:?})",
                            &counterparty_hex[..16],
                            active_lsp_pubkey.as_ref().map(|p| &p[..16])
                        );
                        if let Some(ref cm) = self.channel_manager {
                            // Use same signature as existing force_close path at line ~2106.
                            // For an unaccepted channel there's no funding tx to broadcast — this
                            // just sends an error_channel message to the peer.
                            let _ = cm.force_close_broadcasting_latest_txn(
                                &temporary_channel_id,
                                &counterparty_node_id,
                            );
                        }
                    }
                }
                lightning::events::Event::ChannelReady { channel_id, counterparty_node_id, .. } => {
                    log::info!(
                        "ChannelReady: channel_id={:?} counterparty={}",
                        channel_id, counterparty_node_id
                    );
                    // Phase 1c-write Step 1+2: upload signed record to LSP
                    // registry so Phase 1c-recover has data to recover from.
                    // Fire-and-forget; transient failure retry lands in Step 3.
                    self.upload_channel_record_for_ready(channel_id);
                }
                lightning::events::Event::ChannelClosed {
                    channel_id,
                    reason,
                    counterparty_node_id,
                    channel_capacity_sats,
                    channel_funding_txo,
                    user_channel_id,
                    ..
                } => {
                    // Phase 1c-write Step 1+2 SCOPE: we intentionally do NOT
                    // re-upload here. The event doesn't carry closing_txid or
                    // close_height (those need chain-spend observation), so a
                    // re-write would add no information vs the record already
                    // posted on ChannelReady. A follow-up that watches the
                    // closing TX confirm and then updates the registry with
                    // close_height + closing_txid is its own self-contained
                    // piece — tracked as a Step-3+ followup.
                    let channel_id_hex = hex::encode(channel_id.0);
                    log::warn!(
                        "ChannelClosed: channel_id={} reason={:?}",
                        channel_id_hex, reason
                    );
                    // TEMP diagnostic: record the ChannelClosed event with reason +
                    // timestamp so the close SEQUENCE for a channel is visible.
                    close_event_record(format!(
                        "{{\"ts\":{},\"event\":\"ChannelClosed\",\"channel\":\"{}\",\"reason\":\"{:?}\"}}",
                        current_time_secs(), channel_id_hex, reason
                    ));

                    // Look up our outstanding attempt record (if any) to
                    // distinguish user-initiated from LSP-initiated closes.
                    let attempt = {
                        let mut attempts = self.outstanding_close_attempts.lock().unwrap();
                        attempts.remove(&channel_id)
                    };

                    // Categorize by combining LDK's reason with our attempt record.
                    use lightning::events::ClosureReason::*;
                    let kind = match (&reason, &attempt) {
                        // We force-closed.
                        (HolderForceClosed, Some(a)) if a.kind == CloseAttemptKind::Force => {
                            CloseKind::Force
                        }
                        // We force-closed without an attempt record (restart loss).
                        (HolderForceClosed, _) => CloseKind::Force,
                        // Counterparty force-closed (their commitment hit chain).
                        (CounterpartyForceClosed { .. }, _) => CloseKind::Force,
                        (CommitmentTxConfirmed, _) => CloseKind::Force,
                        // Cooperative close — either side initiated.
                        (LocallyInitiatedCooperativeClosure, _) => CloseKind::Cooperative,
                        (CounterpartyInitiatedCooperativeClosure, _) => {
                            CloseKind::Cooperative
                        }
                        (LegacyCooperativeClosure, _) => CloseKind::Cooperative,
                        (CounterpartyCoopClosedUnfundedChannel, _) => {
                            CloseKind::Cooperative
                        }
                        // v232 (S43, DP): a ProcessingError closure IS a force-close — LDK
                        // force-closes the channel on it (the 0a80ac8d case). Filed as
                        // Other, the page's close-inbound bridge skipped it and the
                        // returning sats had no mempool row.
                        (ProcessingError { .. }, _) => CloseKind::Force,
                        // Closures where no funds are at risk (pre-funding etc).
                        _ => CloseKind::Other,
                    };

                    let counterparty_pubkey_hex = counterparty_node_id
                        .as_ref()
                        .map(|pk| hex::encode(pk.serialize()))
                        .or_else(|| attempt.as_ref().map(|a| a.counterparty_pubkey_hex.clone()));

                    let funding_txo_hex = channel_funding_txo.as_ref().map(|outpoint| {
                        format!("{}:{}", outpoint.txid, outpoint.index)
                    });

                    let reason_description = match attempt.as_ref() {
                        Some(a) => format!(
                            "{}-initiated {}: LDK reason {:?}",
                            "user", a.kind.description(), reason
                        ),
                        None => format!("LSP-initiated or external: LDK reason {:?}", reason),
                    };

                    // A channel that never had a funding tx — e.g. an open the
                    // peer rejected (below-min size, see the retry/force-close
                    // storm in logs) — is a FAILED OPEN, not a close. No funds
                    // ever moved on-chain. Recording it would create a phantom
                    // "Force close · Pending" row, so skip closed-history.
                    if channel_funding_txo.is_none() {
                        log::info!(
                            "ChannelClosed with no funding txo (open never funded, no funds moved) — not recording as a close: {}",
                            channel_id_hex
                        );
                    } else {
                        // S45: capture what the record needs to survive a restart and to be
                        // relabelled truthfully later — the cooperative closing tx we just
                        // broadcast (from the broadcaster's ring, by its funding input) and the
                        // txid of our latest holder commitment (the monitor is still present).
                        let (coop_close_tx_hex, holder_commitment_txid_hex) = {
                            let mut coop: Option<String> = None;
                            let mut holder: Option<String> = None;
                            if let Some(outpoint) = channel_funding_txo.as_ref() {
                                if matches!(kind, CloseKind::Cooperative) {
                                    coop = self
                                        .broadcaster
                                        .recent_spending(&outpoint.txid.to_string(), outpoint.index as u32)
                                        .map(|raw| hex::encode(raw));
                                }
                                if let Some(cm) = self.chain_monitor.as_ref() {
                                    if let Ok(monitor) = cm.get_monitor(*outpoint) {
                                        let logger = std::sync::Arc::new(LijLogger);
                                        let (txs, _to_local, _delay) = monitor.lij_export_escape(&logger);
                                        holder = txs.first().map(|t| t.txid().to_string());
                                    }
                                }
                            }
                            (coop, holder)
                        };
                        let close_seen_height = self
                            .chain_coordinator
                            .lock()
                            .map(|c| c.tip_height())
                            .ok()
                            .filter(|h| *h > 0);
                        if matches!(kind, CloseKind::Cooperative) {
                            log::info!(
                                "ChannelClosed: cooperative — coop tx captured={} holder_commitment={}",
                                coop_close_tx_hex.is_some(),
                                holder_commitment_txid_hex.as_deref().unwrap_or("?")
                            );
                        }
                        let record = ClosedChannelRecord {
                            channel_id_hex: channel_id_hex.clone(),
                            counterparty_pubkey_hex,
                            reason_description,
                            kind,
                            closed_at_unix_secs: current_time_secs(),
                            channel_capacity_sats,
                            funding_txo_hex,
                            closing_txid_hex: None,
                            destination_address: None,
                            sweep_txid_hex: None,
                            coop_close_tx_hex,
                            holder_commitment_txid_hex,
                            closing_confirmed: false,
                            close_seen_height,
                            hold_released: false,
                            cpfp_txid_hex: None,
                            cpfp_last_height: None,
                            // v178: closes of pinned channels DELIVER to m/84
                            // directly (no sweep) — closed-history copy keys
                            // off this.
                            terminus_pinned: Some(
                                (user_channel_id & crate::signer::UCID_TERMINUS_PIN_BIT) != 0,
                            ),
                        };
                        let log = ClosedChannelLog::new(self.storage.clone());
                        if let Err(e) = log.append(record) {
                            log::error!(
                                "Failed to persist closed-channel record for {}: {}",
                                channel_id_hex, e
                            );
                        } else {
                            log::info!("Closed-channel record persisted: {}", channel_id_hex);
                        }
                    }
                }
                _ => {
                    // Other events logged generically above; no specific action needed.
                }
            }
        });
        // Now claim any payments outside the event-handling closure.
        for preimage in preimages_to_claim.into_inner().unwrap() {
            log::info!("Claiming preimage {:?}", preimage);
            cm.claim_funds(preimage);
        }
        // v228: give the unclaimable ones back at once.
        for hash in hashes_to_fail.into_inner().unwrap() {
            log::warn!("Failing back unclaimable HTLC {}", hex::encode(hash.0));
            cm.fail_htlc_backwards(&hash);
        }
        cm.process_pending_htlc_forwards();
        Ok(event_seen.load(Ordering::Relaxed))
    }

    /// v227: an early event pass (after inbound bytes) that saw events marks the
    /// manager dirty so the next tick's persistence fires as if the tick had
    /// seen them itself.
    pub fn mark_manager_dirty(&self) {
        self.manager_dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// v227 (S43, speed): write queued outbound messages NOW. Until v227 a
    /// freshly dispatched HTLC (update_add_htlc) sat in LDK's queue until the
    /// next process_events — inbound bytes, a disconnect, or the 1-second tick
    /// (avg 0.5 s of pure wait on every send). Same call the tick makes; the
    /// v197 pump_peer does this for channel opens.
    pub fn pump_outbound(&self) {
        if let Ok(pm) = self.peer_manager() {
            pm.process_events();
        }
    }

    /// Full background tick — call every second from JS.
    /// Handles peer keepalives (every 10s), channel state (every 60s),
    /// event draining (every tick), HTLC forwarding (every tick),
    /// and ChannelManager persistence (after events + every 10s safety net).
    pub fn background_tick(&self, tick_count: u64) -> LijResult<()> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pm = self.peer_manager()?;
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        // v227 (S43, speed): the event pass lives in process_channel_events
        // (extracted verbatim; also run right after inbound bytes). The
        // persistence decision at the end of this tick reads event_seen exactly
        // as before.
        let event_seen = AtomicBool::new(self.process_channel_events()?);

        // Drain ChainMonitor events. Event::SpendableOutputs originates here
        // (from ChannelMonitor; ChainMonitor aggregates and exposes via
        // EventsProvider). Without this drain, SpendableOutputs events stay
        // queued forever and no force-close residue ever gets swept. This
        // call closes the latent gap that existed prior to v0.2.0.
        if let Some(chain_monitor) = self.chain_monitor.as_ref() {
            let sweeper_opt = self.output_sweeper.as_ref();
            chain_monitor.process_pending_events(&|event| {
                match event {
                    lightning::events::Event::SpendableOutputs { outputs, channel_id } => {
                        log::info!(
                            "[Event/ChainMonitor] SpendableOutputs from channel {:?}: {} descriptor(s)",
                            channel_id, outputs.len()
                        );
                        // TEMP diagnostic: record each descriptor's variant + value +
                        // destination script BEFORE tracking (outputs is consumed below).
                        // Confirms whether an anchors coop close emits a StaticOutput
                        // paying the m/525 P2WSH (which v128 wrongly excludes) vs m/84.
                        {
                            use lightning::sign::SpendableOutputDescriptor as SOD;
                            let cid_hex = channel_id.as_ref().map(|c| hex::encode(c.0)).unwrap_or_default();
                            let now = current_time_secs();
                            for d in outputs.iter() {
                                let (variant, value, spk) = match d {
                                    SOD::StaticOutput { output, .. } =>
                                        ("StaticOutput", output.value, hex::encode(output.script_pubkey.as_bytes())),
                                    SOD::DelayedPaymentOutput(x) =>
                                        ("DelayedPaymentOutput", x.output.value, hex::encode(x.output.script_pubkey.as_bytes())),
                                    SOD::StaticPaymentOutput(x) =>
                                        ("StaticPaymentOutput", x.output.value, hex::encode(x.output.script_pubkey.as_bytes())),
                                };
                                // excluded = StaticOutput under the current v128 rule.
                                let excluded = matches!(d, SOD::StaticOutput { .. });
                                spendable_log_record(format!(
                                    "{{\"ts\":{},\"channel\":\"{}\",\"variant\":\"{}\",\"value_sats\":{},\"dest_spk\":\"{}\",\"excluded_by_v128\":{}}}",
                                    now, cid_hex, variant, value, spk, excluded
                                ));
                            }
                        }
                        match sweeper_opt {
                            Some(sweeper) => {
                                // Terminus v2 (Session 23, S6): a MARKED channel's
                                // StaticPaymentOutput is the pinned to_remote — a
                                // plain P2WPKH on the seed's m/84 tree, ALREADY
                                // spendable by any BIP84 wallet and already inside
                                // the tier2 watch window (the pin index came from
                                // the shared counter, which the scan frontier
                                // covers). Tracking it would repeat the v128
                                // StaticOutput failure: the sweeper cannot spend
                                // it (KeysManager re-derives the ORIGINAL HKDF
                                // payment key, not the pin) and would error-loop.
                                // Filter it out; it is home. Belt-and-braces: a
                                // marked descriptor that is NOT plain P2WPKH
                                // should be impossible (marking requires
                                // non-anchors) — log loudly and still track it
                                // so nothing silently strands.
                                let outputs: Vec<_> = outputs
                                    .into_iter()
                                    .filter(|d| {
                                        use lightning::sign::SpendableOutputDescriptor as SOD;
                                        if let SOD::StaticPaymentOutput(x) = d {
                                            if crate::signer::keys_id_has_terminus_marker(
                                                x.channel_keys_id,
                                            ) {
                                                if x.output.script_pubkey.is_v0_p2wpkh() {
                                                    log::info!(
                                                        "[terminus] pinned to_remote already home at m/84 — {} sats, no sweep needed",
                                                        x.output.value
                                                    );
                                                    return false; // drop: already home
                                                }
                                                log::error!(
                                                    "[terminus] marked StaticPaymentOutput is NOT plain P2WPKH ({} sats) — \
                                                     invariant breach, tracking for visibility",
                                                    x.output.value
                                                );
                                            }
                                        }
                                        true
                                    })
                                    .collect();
                                if outputs.is_empty() {
                                    // Nothing left to track — all descriptors in this
                                    // event were pinned outputs already home.
                                } else
                                if sweeper
                                    .track_spendable_outputs(
                                        outputs,
                                        channel_id,
                                        // v128: exclude StaticOutput descriptors. Per the vendored
                                        // LDK get_spendable_outputs (channelmonitor.rs ~4380/4410),
                                        // StaticOutput is emitted ONLY for shutdown_script (coop
                                        // to_local) and destination_script — both already at an
                                        // address WE control (m/84), spendable with no sweep. The
                                        // confirmed on-chain scanner finds them as normal UTXOs.
                                        // Tracking them (the old `false`) put cooperative closes into
                                        // the sweeper's pending_broadcast database forever — there is
                                        // no sweep to broadcast — surfacing as a permanent phantom
                                        // "withdrawal from N closes · in the mempool" alert. Force
                                        // outputs that DO need sweeping are distinct variants and
                                        // still tracked: DelayedPaymentOutput (force to_local, CSV)
                                        // and StaticPaymentOutput (static-remote to_remote).
                                        /*exclude_static_outputs=*/ true,
                                        /*delay_until_height=*/ None,
                                    )
                                    .is_err()
                                {
                                    // OutputSweeper returns Err only on persistence failure.
                                    // The outputs are NOT tracked — they will be re-emitted
                                    // on a subsequent event drain (LDK keeps them until
                                    // explicitly acked), so this is recoverable but loud.
                                    log::error!(
                                        "OutputSweeper::track_spendable_outputs persistence failure — \
                                         outputs not tracked; will retry on next event drain"
                                    );
                                }
                            }
                            None => {
                                // Should be unreachable post-init. If it fires, something
                                // re-entered background_tick before init_channel_manager
                                // finished. Loud error so we catch it in dev.
                                log::error!(
                                    "[Event/ChainMonitor] SpendableOutputs received but \
                                     OutputSweeper not initialized — funds may be at risk if \
                                     this persists. Outputs lost from this event drain."
                                );
                            }
                        }
                    }
                    other => {
                        // Other events from ChainMonitor are rare; log and ignore. The
                        // event spec evolves with LDK versions, so a forward-compatible
                        // ignore is correct here rather than a hard match.
                        log::debug!("[Event/ChainMonitor] {:?} (no handler)", other);
                    }
                }
            });
        }

        // Every 10 seconds: peer keepalive
        if tick_count % 10 == 0 {
            pm.timer_tick_occurred();
        }

        // Phase 1c-write Step 3: every 30 seconds, retry any registry uploads
        // that are still pending in localStorage (LSP was down, network blip,
        // wallet crashed mid-upload, etc.). POST is idempotent at the LSP
        // (upsert by channel_id), so concurrent retries from this path and
        // upload_channel_record_for_ready are harmless. Successful retries
        // delete the KV entry; failures stay queued for the next attempt.
        if tick_count % 30 == 0 {
            self.process_registry_retries();
        }

        // Every 60 seconds: channel state maintenance
        if tick_count % 60 == 0 {
            cm.timer_tick_occurred();
        }

        // Always pump outbound message queue
        pm.process_events();

        // Process cooperative chain inbound messages and forward new chain-filter
        // registrations to the LSP. Both are sync — no spawn_local needed.
        self.cooperative_bridge.process_inbound_tick(tick_count);
        self.cooperative_bridge.process_new_registrations_tick();

        // Phase 3.7.L: Sync the chain coordinator's bridge_observed_tip from
        // the cooperative bridge state populated by process_inbound_tick above.
        // Verification-only — no LDK action produced. This makes the
        // independent-vs-bridge comparison meaningful and stops the WARN spam
        // when the independent path observes a tip while the coordinator's
        // bridge tip was still default. Coord's monotonic floor handles
        // repeat-observations cleanly.
        // S30 (v198): seed the coordinator's monotonic floor from LDK's own
        // persisted best block BEFORE bridge tips land — a reload while a
        // 1-conf channel is live must never hand LDK a regressed tip (the
        // "Locked at 1 confs, now have 0 confs" force-close). Idempotent
        // every tick; the seed itself happens once per boot.
        if let Some(cm) = self.channel_manager.as_ref() {
            let bb = cm.current_best_block();
            if let Ok(mut coord) = self.chain_coordinator.lock() {
                coord.seed_floor(bb.height, bb.block_hash);
            }
        }
        if let (Some(coop_height), Some(coop_hash)) = (
            self.cooperative_bridge.cooperative_block_height(),
            self.cooperative_bridge.cooperative_block_hash(),
        ) {
            match self.chain_coordinator.lock() {
                Ok(mut coord) => coord.ingest_bridge_tip_observed(coop_height, coop_hash),
                Err(_) => log::warn!(
                    "chain_coordinator: lock poisoned during bridge_observed_tip ingest"
                ),
            }
        }

        // If we have a target LSP but haven't received its ChainDataBundle yet,
        // check whether the BOLT peer connection has come up since the last
        // attempt. LDK silently drops custom messages enqueued for not-yet-
        // connected peers, so the initial send_subscribe call in connect_lsp
        // typically vanishes — we have to re-issue once the peer is actually
        // in PeerManager's connected-peers map. v113: checked EVERY tick until
        // subscribed — the old %5 throttle made tick 5 the first eligible
        // re-issue, costing ~4s of every cold boot (lsp/chain dots amber).
        // The check is a cheap list_peers scan; it only SENDS once the peer is
        // actually connected, and it self-terminates when the ChainDataBundle
        // arrives and dispatch() sets subscribed=true — worst case a couple of
        // duplicate subscribe messages during the one-RTT bundle window.
        if !self.cooperative_bridge.cooperative_subscribed() {
            if let Some(lsp_pubkey) = self.cooperative_bridge.target_lsp() {
                let peer_connected = pm.list_peers().iter()
                    .any(|p| p.counterparty_node_id == lsp_pubkey);
                if peer_connected {
                    log::info!(
                        "background_tick: peer {} connected but cooperative not subscribed — re-issuing SubscribeChainData",
                        lsp_pubkey
                    );
                    if let Err(e) = self.cooperative_bridge.send_subscribe(lsp_pubkey) {
                        log::warn!("background_tick: send_subscribe retry failed: {}", e);
                    }
                }
            }
        }

        // v231 (S43, DP field 2026-09-02): TIP BEFORE CONFIRMATIONS. This block moved up from
        // below the Step-8c drain. Until v231 each tick handed LDK the LSP's confirmations first
        // and the tip second, and persisted right after a confirmation; a funding confirmed in
        // block M was therefore saved next to a newest block M-1 whenever the app closed within
        // the next ten seconds. LDK's transactions_confirmed re-checks every channel against
        // its stored best block, so the next boot's replay of an older funding block found
        // 0 confirmations for that channel and force-closed it. Order now: tip, then only the
        // confirmations at or below it; the rest wait in the bridge for the tip to arrive.
        if let (Some(coop_height), Some(chain_monitor), Some(cm)) = (
            self.cooperative_bridge.cooperative_block_height(),
            self.chain_monitor.as_ref(),
            self.channel_manager.as_ref(),
        ) {
            let ldk_current_tip = cm.current_best_block().height;
            if coop_height > ldk_current_tip {
                // Synthetic header. LDK uses header.block_hash() for its
                // stored BestBlock hash. The real tip_blockhash from the
                // bundle cannot be reconstructed into a header that
                // hashes to that value (would require the real block's
                // PoW), so LDK records a synthetic hash. The coordinator's
                // tip_hash field stores the real bundle hash for event
                // and audit purposes. Height is what drives LDK behavior;
                // hash mismatch is harmless because no reorg path at our
                // level uses LDK's stored hash for comparison.
                let coop_header = Header {
                    version: BlockVersion::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 0,
                };
                // Prefer the real bundle hash for the coordinator's
                // record-keeping. Falls back to synthetic header hash if
                // the bridge somehow has height-without-hash (defensive;
                // bridge stores both together so should not occur).
                let coop_hash = self.cooperative_bridge
                    .cooperative_block_hash()
                    .unwrap_or_else(|| coop_header.block_hash());
                let coop_action = {
                    let mut coord = self.chain_coordinator.lock()
                        .map_err(|e| LijError::Node(format!(
                            "Coordinator lock poisoned (cooperative tip): {e}"
                        )))?;
                    coord.ingest_bridge_tip(coop_height, coop_hash, coop_header)
                };
                if !coop_action.is_none() {
                    log::info!(
                        "background_tick: cooperative tip ingested -- LDK best_block {} -> {} (+{} blocks)",
                        ldk_current_tip, coop_height, coop_height - ldk_current_tip
                    );
                    coop_action.apply(&**chain_monitor, &**cm, self.output_sweeper_as_confirm());
                    // v231 (S43, DP field 2026-09-02): the tip advance is persisted at the end of THIS
                    // tick (manager_dirty), so LDK's newest block and a funding's block can never be saved
                    // one apart — the state that made the next boot's replay force-close 0a80ac8d.
                    self.manager_dirty.store(true, std::sync::atomic::Ordering::Relaxed);
                } else {
                    // Coordinator monotonic guard rejected. Possible if a
                    // future independent-tip ingestion path already
                    // advanced coord past coop_height while LDK lagged.
                    // Edge case; LDK does not advance this tick, will
                    // retry next.
                    log::debug!(
                        "background_tick: cooperative tip {} dropped by coordinator monotonic guard",
                        coop_height
                    );
                }
            }
            // Quiet on the common no-advance path. Frontend status panel
            // surfaces the wallet's notion of cooperative tip vs LDK tip.
        }

        // Step 8c: drain pending FundingTxConfirmed and route into LDK's
        // Confirm trait via transactions_confirmed. Synthetic header (i.e.
        // a fabricated Header struct) is used because the cooperative path
        // does not carry full block headers; LDK only needs a header it
        // can hash for BestBlock bookkeeping, not a valid-PoW header.
        let mut pending = self.cooperative_bridge.take_pending_confirmations();
        // Sort pending by confirmed_at_height ascending so transactions_confirmed
        // calls reach LDK in monotonic block-height order, as LDK's Confirm
        // trait expects. Out-of-order replays (e.g. cooperative bridge cache
        // after wallet reconnect with multiple pending channels) would
        // otherwise trigger spurious reorgs that force-close healthy
        // channels with "Funding transaction was un-confirmed".
        pending.sort_by_key(|c| c.confirmed_at_height);
        // v231: a confirmation from a block ABOVE the tip the coordinator has accepted waits
        // in the bridge until the tip reaches it — LDK never records a transaction in a block
        // newer than the newest block it knows.
        {
            let tip_now = self.chain_coordinator.lock().map(|c| c.tip_height()).unwrap_or(0);
            let (ready, held): (Vec<_>, Vec<_>) = pending.into_iter().partition(|c| c.confirmed_at_height <= tip_now);
            if !held.is_empty() {
                log::info!("background_tick: holding {} confirmation(s) above tip {} until the tip arrives", held.len(), tip_now);
                self.cooperative_bridge.requeue_pending_confirmations(held);
            }
            pending = ready;
        }
        if !pending.is_empty() {
            let chain_monitor = self.chain_monitor.as_ref().ok_or_else(||
                LijError::Node("ChainMonitor not initialized".into())
            )?;
            for confirmed in pending {
                use bitcoin::consensus::encode::deserialize as consensus_deserialize;
                let tx: bitcoin::Transaction = match consensus_deserialize(&confirmed.raw_tx_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        log::warn!(
                            "background_tick: pending FundingTxConfirmed re-parse failed (already validated by bridge?): {}",
                            e
                        );
                        continue;
                    }
                };
                let txid = tx.txid();
                log::info!(
                    "background_tick: routing cooperative FundingTxConfirmed txid={} to LDK at height {}",
                    txid, confirmed.confirmed_at_height
                );
                let merkle_root = TxMerkleNode::from_byte_array(txid.to_byte_array());
                let conf_header = Header {
                    version: BlockVersion::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root,
                    time: 0,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 0,
                };
                // Step 3.6 (SCID fix): use real tx position from cooperative
                // bridge instead of hardcoded 0. LDK uses tx_index to compute
                // the channel's on-chain SCID; with the placeholder 0, the
                // SCID didn't match LSP's view and route hints failed.
                // Phase 3.7.B — route bridge confirmation through ChainCoordinator.
                // Lock held only for synchronous internal state update; LDK call
                // happens lock-free via PendingLdkAction::apply.
                let conf_action = {
                    let mut coord = self.chain_coordinator.lock()
                        .map_err(|e| LijError::Node(format!("Coordinator lock poisoned: {e}")))?;
                    coord.ingest_bridge_conf(crate::chain_coordinator::BridgeConfirmation {
                        txid,
                        height: confirmed.confirmed_at_height,
                        block_hash: conf_header.block_hash(),
                        tx_index: confirmed.tx_index as u32,
                        raw_tx: confirmed.raw_tx_bytes.clone(),
                        block_header: conf_header,
                        confirmations: confirmed.confirmations,
                    })
                };
                conf_action.apply(&**chain_monitor, &**cm, self.output_sweeper_as_confirm());

                // Step C.4: synthetic-tip emission removed. ChannelReady
                // now fires after the transactions_confirmed call above
                // lands, on the next cooperative-tip ingestion below
                // (Phase 3.9.A), with minimum_depth=1 from Step C.2 --
                // no synthetic jump to funding_height + 6 needed.
            }
            // Persist channel manager since channel state advanced.
            self.persist_channel_manager()?;
        }

        // Phase 3.9.A (+ Step C.4): ingest cooperative chain tip into LDK.
        //
        // Sole driver of LDK's BestBlock advancement. Keeps LDK aligned
        // with the real chain head for ChannelReady (with minimum_depth=1
        // from Step C.2), HTLC math, CLTV expiry checks, sweep timing,
        // and confirmation-depth tracking. The synthetic-tip-per-
        // confirmation emission that previously handled fast ChannelReady
        // by jumping LDK to funding_height+6 was removed in Step C.4
        // once minimum_depth=1 made the jump unnecessary.
        //
        // Without this path, LDK's BestBlock would stay frozen at whatever
        // height transactions_confirmed last reported -- typically the
        // most recent funding_height across all channels -- far behind
        // the real chain head on a wallet with established channels.
        // That would cause CLTV computations to underflow on outgoing
        // HTLCs and manifest as expiry_too_soon failures at intermediate
        // hops.
        //
        // Runs every tick. Cheap on the no-advance path: tuple destructure
        // plus one comparison. Header construction and coordinator lock
        // only happen when there is actual advancement to do. Monotonic
        // guard in coord.ingest_bridge_tip drops stale heights silently.
        //
        // Defensive: skips silently if cooperative tip, chain_monitor, or
        // channel_manager is not yet initialized. These can be absent
        // during cold-start and should not generate spurious errors.

        // ── Sweeper-tip floor (belt-and-suspenders) ──────────────────────────
        // The "missed starting block" failures (which previously forced a manual
        // sweep-block restart) happen when the OutputSweeper's best_block is left
        // behind the real chain — e.g. on a restored state the sweeper inits at
        // BestBlock::from_network and, if the cooperative-tip advance path above
        // has a gap or never delivers an early update, its delayed_until_height /
        // maturity math is computed against a stale tip, so it never starts (or
        // mis-times) a sweep. This guard makes that unrecoverable-by-design state
        // impossible: every tick, if the sweeper is behind the authoritative
        // height we already hold (the same coop tip LDK uses), drive
        // best_block_updated to catch it up. Idempotent and cheap on the
        // no-lag path (one height read + compare); the sweeper's own
        // best_block_updated_internal is monotonic so a redundant call is a
        // no-op. This is independent of the LDK coop-advance above: even if that
        // path is skipped (monotonic guard, missing handles), the sweeper still
        // gets floored here.
        if let (Some(sweeper), Some(authoritative_height)) = (
            self.output_sweeper(),
            self.cooperative_bridge.cooperative_block_height(),
        ) {
            let sweeper_height = sweeper.current_best_block().height;
            if authoritative_height > sweeper_height {
                let floor_header = Header {
                    version: BlockVersion::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 0,
                };
                use lightning::chain::Confirm;
                sweeper.best_block_updated(&floor_header, authoritative_height);
                log::info!(
                    "background_tick: sweeper-tip floor advanced sweeper {} -> {} (+{} blocks) [belt-and-suspenders]",
                    sweeper_height, authoritative_height, authoritative_height - sweeper_height
                );
            }
        }

        // ── v185 sweep-memo release (Session 27) ────────────────────────
        // The signer pins ONE m/84 destination across a pending sweep's
        // per-block rebroadcasts (LijSignerProvider::sweep_destination_
        // script). Release it the moment nothing can rebroadcast to it —
        // no tracked output pending broadcast or first confirmation — so
        // a LATER sweep epoch can never fund the same address twice (the
        // binding per-epoch rule; docs/session27.md privacy analysis).
        // O(n_tracked) once per tick, only when a sweeper exists.
        if let Some(sweeper) = self.output_sweeper() {
            use lightning::util::sweep::OutputSpendStatus as SwSt;
            let any_rebroadcastable =
                sweeper.tracked_spendable_outputs().iter().any(|o| {
                    matches!(
                        o.status,
                        SwSt::PendingInitialBroadcast { .. }
                            | SwSt::PendingFirstConfirmation { .. }
                    )
                });
            if !any_rebroadcastable {
                self.signer_provider.clear_sweep_memo();
            }
        }

        // Cold-start orchestrator: read cache state, decide sync transitions.
        self.cold_start.tick(
            tick_count,
            &self.sync_state,
            self.cooperative_bridge.cooperative_subscribed(),
            self.cooperative_bridge.cooperative_block_height(),
            &self.independent,
        );

        // Fire independent fetch periodically so the orchestrator has fresh
        // data to read on its next tick. Cadence: every 5 ticks (5 seconds)
        // until Ready, then every 30 ticks (30s) once Ready. Per design doc §3.
        //
        // TODO(scale): The current cadence works for development but does not
        // scale. At 10k active wallets, the 30s post-Ready cadence puts ~333
        // requests/sec on each healthy Esplora endpoint — above free public
        // Esplora rate limits. Before public launch:
        //   1. Jitter the polling window (±50% randomization) so wallets
        //      don't hit the same boundary simultaneously.
        //   2. Apply success-backoff: after 3 consecutive fetches return
        //      identical heights, slow to 60s or 120s. Chain blocks come
        //      every ~10 minutes; we're polling far faster than necessary.
        //   3. Skip independent polling when cooperative path has produced
        //      a fresh BlockHeightUpdate within the cadence window — the
        //      data is redundant.
        //   4. Stand up own LIJOX-served Esplora endpoint as the primary
        //      so traffic doesn't hit Blockstream/mempool.space at all
        //      under nominal conditions.
        let last_fetch = self.last_independent_fetch_tick.load(std::sync::atomic::Ordering::Relaxed);
        let cadence = if matches!(self.sync_state.current(), crate::sync_state::SyncState::Ready) { 30 } else { 5 };
        // v113: the first fetch fires on the FIRST tick (last_fetch == 0 is
        // the never-fetched sentinel) — the cadence math previously delayed
        // the boot's first quorum round to tick 5, holding the quorum dot and
        // the LSP dot's speed-sample gate amber for ~4s of every cold start.
        // Steady-state cadences (5s pre-Ready / 30s Ready) are unchanged.
        if last_fetch == 0 || tick_count.saturating_sub(last_fetch) >= cadence {
            self.last_independent_fetch_tick.store(tick_count, std::sync::atomic::Ordering::Relaxed);
            #[cfg(target_arch = "wasm32")]
            {
                let independent = self.independent.clone();
                let cold_start = self.cold_start.clone();
                // Phase 3.7.C - verify-only telemetry: coordinator never
                // produces LDK actions from independent data.
                let chain_coordinator = self.chain_coordinator.clone();
                // v226 (S43, speed item 0): the FIRST endpoint to answer marks
                // the round queried (independent.rs early report), so the next
                // tick can go Ready on one source agreeing with the LSP's feed
                // (the v225 floor) instead of waiting for the slowest endpoint.
                // Idempotent: the post-round mark below still runs.
                {
                    let cs = cold_start.clone();
                    independent.set_first_height_hook(Arc::new(move |h: u32| cs.mark_independent_queried(Some(h))));
                }
                wasm_bindgen_futures::spawn_local(async move {
                    match independent.fetch_tip_height().await {
                        Ok(height) => {
                            log::debug!("independent: fetch_tip_height returned {}", height);
                            cold_start.mark_independent_queried(Some(height));
                            match independent.fetch_tip_hash().await {
                                Ok(hash) => {
                                    if let Ok(mut coord) = chain_coordinator.lock() {
                                        coord.ingest_independent_tip(height, hash);
                                    } else {
                                        log::warn!("chain_coordinator: lock poisoned during independent tip ingest");
                                    }
                                }
                                Err(e) => {
                                    log::debug!("independent: fetch_tip_hash failed (telemetry skipped): {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!("independent: fetch_tip_height failed: {}", e);
                            cold_start.mark_independent_queried(None);
                        }
                    }
                });
            }
        }

        // Refresh the cooperative fee cache from the bridge's latest quote.
        // KEYSTONE FIX: refresh_cooperative() had only ever been called from
        // tests, so in production the FeeEstimator's cooperative cache was never
        // populated — get_est_sat_per_1000_weight fell through to
        // FeeQuote::floor(), pinning EVERY LDK fee (sweeps, closes, anchor CPFP)
        // at ~1 sat/vB regardless of the real market rate the bridge already had.
        // That is why matured sweeps went out at the floor and LND bounced them
        // with "insufficient fee". BridgeFeeSource::fetch is a local read of
        // last_fee_quote (no network), so this is cheap to run every tick; once
        // the bridge has a quote, OutputSpendingFee becomes fast*3 and the next
        // sweep rebuild clears LND's relay floor.
        #[cfg(target_arch = "wasm32")]
        {
            let fe = self.fee_estimator.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = fe.refresh_cooperative(tick_count).await {
                    log::warn!("fee_estimator refresh_cooperative: {e}");
                }
            });
        }

        // v182: persist the fee quote when it changes — the next boot's
        // prior. Change-gated so storage writes (which ride the KV
        // auto-backup) happen on market movement only.
        if let Some(q) = self.fee_estimator.snapshot_if_changed() {
            match serde_json::to_vec(&q) {
                Ok(json) => {
                    if let Err(e) = self.storage.set("fee_quote_v1", &json) {
                        log::warn!("fee quote persist: {e}");
                    }
                }
                Err(e) => log::warn!("fee quote serialize: {e}"),
            }
        }

        // Drain broadcast queue asynchronously — fire-and-forget.
        // process_queue handles its own errors; we don't await because
        // background_tick must remain sync for the JS caller.
        #[cfg(target_arch = "wasm32")]
        {
            let bc = self.broadcaster.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = bc.process_queue().await {
                    log::warn!("broadcaster process_queue: {e}");
                }
            });
        }

        // Closed-channel watcher: every 60 ticks, poll pending closes
        // for onchain resolution of closing_txid_hex and destination_address.
        // Watcher itself enforces per-record cadence (60s normal,
        // backoff after max failures). spawn_local — fire-and-forget.
        #[cfg(target_arch = "wasm32")]
        if tick_count % 60 == 0 {
            let watcher = self.closed_channel_watcher.clone();
            let storage = self.storage.clone();
            let independent = self.independent.clone();
            let root_key = self.root_key.clone();
            let network = self.network;
            let counter = match self.signer_provider.peek_counter() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("closed_channel_watcher: peek_counter failed: {e}");
                    0
                }
            };
            let now = current_time_secs();
            wasm_bindgen_futures::spawn_local(async move {
                let log = crate::closed_channel_log::ClosedChannelLog::new(storage);
                if let Err(e) = watcher
                    .poll_pending_closes(log, independent, &root_key, network, counter, now)
                    .await
                {
                    log::warn!("closed_channel_watcher poll failed: {e}");
                }
            });
        }

        // Sweep-tx surfacing: one hop past the closing-tx watcher. For a resolved
        // force close, find what spent the closing tx's to_local output (the CSV
        // sweep to BIP84) and persist sweep_txid_hex. Independent observation
        // only — no chain mutation. Shares the 60-tick cadence. Coops are skipped
        // (they pay BIP84 directly in the closing tx, with no separate sweep).
        #[cfg(target_arch = "wasm32")]
        if tick_count % 60 == 0 {
            let storage = self.storage.clone();
            let independent = self.independent.clone();
            let network = self.network;
            wasm_bindgen_futures::spawn_local(async move {
                use std::str::FromStr;
                let log = crate::closed_channel_log::ClosedChannelLog::new(storage);
                let records = match log.list() {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("[sweep_resolve] list failed: {e}");
                        return;
                    }
                };
                for r in records.into_iter().filter(|r| {
                    r.sweep_txid_hex.is_none()
                        && r.closing_txid_hex.is_some()
                        && r.destination_address.is_some()
                        && r.kind == crate::closed_channel_log::CloseKind::Force
                }) {
                    let closing_txid = match r.closing_txid_hex.as_ref() {
                        Some(t) => t.clone(),
                        None => continue,
                    };
                    let dest = match r.destination_address.as_ref() {
                        Some(d) => d.clone(),
                        None => continue,
                    };
                    // Our to_local scriptpubkey (hex), from the resolved dest
                    // address. Unresolved sentinels (e.g. "unmatched - check
                    // on-chain") fail to parse and are skipped.
                    let our_spk_hex = match bitcoin::Address::from_str(&dest) {
                        Ok(a) => match a.require_network(network) {
                            Ok(a) => hex::encode(a.script_pubkey().as_bytes()),
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    };
                    // Locate the to_local vout in the closing tx by scriptpubkey.
                    let closing_tx = match independent.fetch_tx(&closing_txid).await {
                        Ok(t) => t,
                        Err(e) => {
                            log::debug!("[sweep_resolve] fetch_tx({closing_txid}) failed: {e}");
                            continue;
                        }
                    };
                    let vout = match closing_tx
                        .vouts
                        .iter()
                        .position(|v| v.scriptpubkey == our_spk_hex)
                    {
                        Some(i) => i,
                        None => continue,
                    };
                    // Whatever spent that output is the sweep.
                    let outspends = match independent.fetch_tx_outspends(&closing_txid).await {
                        Ok(o) => o,
                        Err(e) => {
                            log::debug!("[sweep_resolve] outspends({closing_txid}) failed: {e}");
                            continue;
                        }
                    };
                    let spend = match outspends.get(vout) {
                        Some(s) => s,
                        None => continue,
                    };
                    if !spend.spent {
                        continue;
                    }
                    let sweep_txid = match spend.txid.as_ref() {
                        Some(t) => t.clone(),
                        None => continue,
                    };
                    // Wait for a confirmation before recording — a mempool sweep
                    // can still be replaced.
                    if !spend.status.as_ref().map(|s| s.confirmed).unwrap_or(false) {
                        continue;
                    }
                    match log.update_by_channel_id(&r.channel_id_hex, |rec| {
                        rec.sweep_txid_hex = Some(sweep_txid.clone());
                    }) {
                        Ok(true) => log::info!(
                            "[sweep_resolve] {} sweep_txid={}",
                            r.channel_id_hex, sweep_txid
                        ),
                        Ok(false) => {}
                        Err(e) => log::warn!(
                            "[sweep_resolve] update {} failed: {e}",
                            r.channel_id_hex
                        ),
                    }
                }
            });
        }

        // Funding-outpoint spend walker. FLAP FIX (2026-06-02): formerly ran
        // first at tick 30 then every 600 ticks (~10 min), which left a cold
        // start reestablishing a channel the LSP force-closed while we were
        // offline — LND can't summarize it, tears down the peer, and we flap on
        // a ~10s loop until the walker finally ran. Now we run EAGERLY (every
        // EAGER_INTERVAL ticks) until the first full reconcile pass completes,
        // then drop to MAINTENANCE_INTERVAL. If Esplora keeps failing (429), the
        // cadence widens to EAGER_BACKOFF_INTERVAL after EAGER_FAIL_THRESHOLD
        // incomplete passes so we don't hammer it — mirrors
        // closed_channel_watcher's MAX_FAILURES -> slow-down. The in-flight
        // guard prevents overlapping passes. Cooperative bridge has no
        // `ClosingTxObserved`, so this is still the only path to learn of an
        // offline force-close.
        #[cfg(target_arch = "wasm32")]
        {
            const EAGER_INTERVAL: u64 = 3;
            const EAGER_BACKOFF_INTERVAL: u64 = 30;
            const EAGER_FAIL_THRESHOLD: u32 = 5;
            const MAINTENANCE_INTERVAL: u64 = 180;

            let reconcile_done = self.funding_reconcile_done.load(Ordering::Relaxed);
            let failures = self.funding_reconcile_failures.load(Ordering::Relaxed);
            let interval = if reconcile_done {
                MAINTENANCE_INTERVAL
            } else if failures >= EAGER_FAIL_THRESHOLD {
                EAGER_BACKOFF_INTERVAL
            } else {
                EAGER_INTERVAL
            };
            let forced = self.funding_walk_force.swap(false, Ordering::AcqRel);
            let last = self.walk_last_tick.load(Ordering::Relaxed);
            let due = forced
                || (tick_count >= EAGER_INTERVAL
                    && tick_count.saturating_sub(last) >= interval);

            // Prune fully-resolved closed monitors (all outputs claimed past
            // ANTI_REORG_DELAY) so the closed-monitor count drops instead of
            // lingering forever. v223 (S39): UNGATED from reconcile_done —
            // is_fully_resolved() demands empty claimables + funding spend
            // seen + LDK's 4032-block threshold, all monitor-internal facts,
            // so the call is safe regardless of walk completeness. Gating it
            // also delayed the latch of balances_empty_height (the four-week
            // clock STARTS at the first post-resolution archive attempt), so
            // walk starvation stacked ON TOP of the threshold. `due` keeps
            // the cadence cheap. Pre-maturity closes are NOT fully resolved,
            // so this can't archive funds still owed to us.
            if due {
                if let Some(cm) = self.chain_monitor.as_ref() {
                    cm.archive_fully_resolved_channel_monitors();
                }
            }

            if due
                && self
                    .funding_reconcile_inflight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                self.walk_last_tick.store(tick_count, Ordering::Relaxed);
                match (self.channel_manager.as_ref(), self.chain_monitor.as_ref()) {
                    (Some(cm_ref), Some(chain_monitor_ref)) => {
                        let cm_clone = cm_ref.clone();
                        let chain_monitor_clone = chain_monitor_ref.clone();
                        let chain_coordinator_clone = self.chain_coordinator.clone();
                        let independent_clone = self.independent.clone();
                        let sightings_clone = self.funding_spend_sightings.clone();
                        let storage_clone = self.storage.clone();
                        let done_flag = self.funding_reconcile_done.clone();
                        let inflight_flag = self.funding_reconcile_inflight.clone();
                        let failures_flag = self.funding_reconcile_failures.clone();
                        let walk_seq_flag = self.walk_seq.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            let complete = check_funding_outpoints_for_spends(
                                cm_clone,
                                chain_monitor_clone,
                                chain_coordinator_clone,
                                independent_clone,
                                sightings_clone,
                                storage_clone,
                            )
                            .await;
                            if complete {
                                done_flag.store(true, Ordering::Relaxed);
                                failures_flag.store(0, Ordering::Relaxed);
                            } else {
                                failures_flag.fetch_add(1, Ordering::Relaxed);
                            }
                            walk_seq_flag.fetch_add(1, Ordering::Relaxed);
                            inflight_flag.store(false, Ordering::Relaxed);
                        });
                    }
                    _ => {
                        // cm/chain_monitor not ready yet — release the guard so a
                        // later tick can retry.
                        self.funding_reconcile_inflight.store(false, Ordering::Relaxed);
                        log::debug!(
                            "[funding_spend_check] cm/chain_monitor not yet initialized at tick {tick_count} -- skipping"
                        );
                    }
                }
            }
        }


        // Build #4 (open-broadcast regression): the sweeper's regeneration
        // property, ported to opens — rebroadcast-until-seen for pending
        // ChannelOpen txs, plus release of dead pre-fix records. Network I/O
        // runs off-lock in a spawned task.
        // v186 (S27, alert-family fix 2): LIVE FUNDING-CONFIRMATION HEAL.
        // The cooperative bridge is the only live funding-conf feed; when
        // any link drops, a pending channel sits not-ready until a reload
        // replays cold-start's independent reconcile. This block IS that
        // reconcile, live: for channels LDK reports not-ready, probe the
        // quorum's merkle-proof (confirmed?, height, REAL pos — SCID needs
        // it, Step 3.6). Raw tx from the v166 PendingTx record, quorum
        // fallback. Coordinator ingest is idempotent; bridge stays
        // primary; no-op when nothing is pending. Sweeper handle None
        // (funding confs don't concern it). CM persistence rides the next
        // event-driven persist; a pre-persist reload just replays today's
        // cold-start heal.
        // v189 (S29): STALE-INTENT SWEEP — with ZERO channels, an
        // LDK-'pending' outbound is unresolvable by definition; abandon it
        // so the UI's ghost rows die at the root instead of on a timer.
        // (The with-channels >4h case is root-killed by the frontend via
        // abandon_payment_by_id at retirement.)
        // v192 (S29): CANCELLED-OPEN SWEEP — DP ruling on vocabulary:
        // "cancelled — funds never left." A channel with zero
        // confirmations that never became ready, whose funding txid is
        // tracked by NOTHING on-chain (absent from confirmed history AND
        // pending records), is a dead attempt: real fresh opens always
        // hold a pending record, confirmed ones live in history, and
        // zero-conf JIT channels are ready immediately. Discard without
        // broadcasting — the funding never existed, so there is nothing
        // on-chain to close, no timelock, no sweep.
        #[cfg(target_arch = "wasm32")]
        if tick_count % 30 == 29 {
            if let Some(cm) = self.channel_manager.as_ref() {
                let mut dead: Vec<(lightning::ln::ChannelId, bitcoin::secp256k1::PublicKey, String)> = Vec::new();
                if let Ok(view) = crate::tier2_wallet::load_view(&*self.storage) {
                    let pending = crate::tier2_wallet::load_pending(&*self.storage);
                    let tracked: std::collections::HashSet<String> = view
                        .history
                        .iter()
                        .map(|h| h.txid.clone())
                        .chain(pending.iter().map(|p| p.txid.clone()))
                        .collect();
                    for c in cm.list_channels() {
                        // v193 (S29) — DP ruling "harden for outbound now":
                        // the untracked-test only proves death for spends WE
                        // authored; inbound is categorically outside the
                        // sweep's jurisdiction.
                        if !c.is_outbound || c.is_channel_ready || c.confirmations.unwrap_or(0) > 0 {
                            continue;
                        }
                        if let Some(f) = c.funding_txo {
                            let ftx = f.txid.to_string();
                            if !tracked.contains(&ftx) {
                                dead.push((c.channel_id, c.counterparty.node_id, ftx));
                            }
                        }
                    }
                }
                for (chan_id, peer, ftx) in dead {
                    log::info!(
                        "[CONFLICT-AUDIT] cancelled unfunded open {} — funding never reached the chain; funds never left",
                        &ftx[..16.min(ftx.len())]
                    );
                    let _ = cm.force_close_without_broadcasting_txn(&chan_id, &peer);
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        if tick_count % 30 == 23 {
            if let Some(cm) = self.channel_manager.as_ref() {
                if cm.list_channels().is_empty() {
                    use lightning::ln::channelmanager::RecentPaymentDetails as RPD;
                    for p in cm.list_recent_payments() {
                        if let RPD::Pending { payment_id, payment_hash, .. } = p {
                            log::info!(
                                "[stale-intent] zero-channel abandon {} (hash {})",
                                hex::encode(payment_id.0),
                                hex::encode(payment_hash.0)
                            );
                            cm.abandon_payment(payment_id);
                        }
                    }
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        if tick_count % 30 == 17 {
            if let (Some(chain_monitor), Some(cm_arc)) =
                (self.chain_monitor.clone(), self.channel_manager.clone())
            {
                let pending_fundings: Vec<String> = cm_arc
                    .list_channels()
                    .iter()
                    .filter(|c| !c.is_channel_ready)
                    .filter_map(|c| c.funding_txo.map(|o| o.txid.to_string()))
                    .collect();
                if !pending_fundings.is_empty() {
                    let indep = self.independent.clone();
                    let storage = self.storage.clone();
                    let coordinator = self.chain_coordinator.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        for txid_str in pending_fundings.into_iter().take(4) {
                            let (height, pos) = match indep.fetch_tx_merkle_pos(&txid_str).await {
                                Ok(v) => v,
                                Err(_) => continue, // unconfirmed / quorum down — retry next round
                            };
                            let parsed_txid: bitcoin::Txid = match txid_str.parse() {
                                Ok(t) => t,
                                Err(_) => continue,
                            };
                            let raw_tx: Vec<u8> = {
                                let from_record = crate::tier2_wallet::load_pending(&*storage)
                                    .into_iter()
                                    .find(|p| p.txid == txid_str)
                                    .and_then(|p| p.raw_tx_hex)
                                    .and_then(|h| hex::decode(h).ok());
                                match from_record {
                                    Some(b) => b,
                                    None => match indep.fetch_tx_hex(&txid_str).await {
                                        Ok(b) => b,
                                        Err(_) => continue,
                                    },
                                }
                            };
                            let merkle_root = TxMerkleNode::from_byte_array(parsed_txid.to_byte_array());
                            let heal_header = Header {
                                version: BlockVersion::TWO,
                                prev_blockhash: BlockHash::all_zeros(),
                                merkle_root,
                                time: 0,
                                bits: CompactTarget::from_consensus(0x207fffff),
                                nonce: 0,
                            };
                            let action = {
                                let mut coord = match coordinator.lock() {
                                    Ok(c) => c,
                                    Err(_) => continue,
                                };
                                coord.ingest_independent_confirmation(
                                    crate::chain_coordinator::IndependentConfirmation {
                                        txid: parsed_txid,
                                        height,
                                        block_hash: heal_header.block_hash(),
                                        tx_index: pos,
                                        raw_tx,
                                        block_header: heal_header,
                                        reason: format!(
                                            "live funding heal: bridge FundingTxConfirmed missing for {} (merkle pos {})",
                                            txid_str, pos
                                        ),
                                    },
                                )
                            };
                            log::info!(
                                "[funding_heal] independent confirmation for pending funding {} at height {} pos {} — routing to LDK",
                                txid_str, height, pos
                            );
                            action.apply(&*chain_monitor, &*cm_arc, None);
                        }
                    });
                }
            }
        }

        // v185: OPEN-AUDIT is wasm-only (spawn_local + quorum fetch); the
        // native test lane resurrected by CI exposed it as an un-gated
        // E0433. Gated, not rewritten — behavior on wasm32 is unchanged.
        // S45: cooperative-close hold maintenance — confirm, keep, rebroadcast,
        // or release (ceiling / eviction → the wallet broadcasts the commitment).
        #[cfg(target_arch = "wasm32")]
        if tick_count % 30 == 19 {
            let storage = self.storage.clone();
            let indep = self.independent.clone();
            let bc = self.broadcaster.clone();
            let fee = self.fee_estimator.clone();
            let cm = self.chain_monitor.clone();
            let tip = self.chain_coordinator.lock().map(|c| c.tip_height()).unwrap_or(0);
            let root_key = self.root_key.clone();
            let network = self.network;
            let counter = self.signer_provider.peek_counter().unwrap_or(0);
            wasm_bindgen_futures::spawn_local(async move {
                coop_hold_maintain(storage, indep, bc, fee, cm, tip, root_key, network, counter).await;
            });
        }
        #[cfg(target_arch = "wasm32")]
        if tick_count % 30 == 7 {
            let storage = self.storage.clone();
            let indep = self.independent.clone();
            let bc = self.broadcaster.clone();
            let live_funding_txids: Vec<String> = self
                .channel_manager
                .as_ref()
                .map(|cm| cm.list_channels().iter()
                    .filter_map(|c| c.funding_txo.map(|o| o.txid.to_string()))
                    .collect())
                .unwrap_or_default();
            wasm_bindgen_futures::spawn_local(async move {
                let pending = crate::tier2_wallet::load_pending(&*storage);
                let now = crate::tier2_wallet::now_ms();
                for p in pending.iter().filter(|p| {
                    matches!(p.kind, crate::tier2_wallet::TxKind::ChannelOpen)
                        && !p.broadcast_seen
                }) {
                    let age_s = now.saturating_sub(p.created_at_ms) / 1000;
                    if age_s < 60 {
                        continue;
                    }
                    let short = &p.txid[..16.min(p.txid.len())];
                    if indep.fetch_tx(&p.txid).await.is_ok() {
                        log::info!("[OPEN-AUDIT] funding {short}… visible to the quorum — marking seen");
                        let _ = crate::tier2_wallet::mark_broadcast_seen(&*storage, &p.txid);
                        continue;
                    }
                    if let Some(hex_raw) = &p.raw_tx_hex {
                        if let Ok(bytes) = hex::decode(hex_raw) {
                            if let Ok(tx) = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&bytes) {
                                log::warn!("[OPEN-AUDIT] funding {short}… unseen after {age_s}s — rebroadcasting");
                                bc.broadcast_transactions(&[&tx]);
                                continue;
                            }
                        }
                    }
                    // Pre-fix record (no bytes): once its channel is gone and
                    // it has aged out, release the reservation it holds.
                    if age_s > 3600 && !live_funding_txids.contains(&p.txid) {
                        log::warn!("[OPEN-AUDIT] dead open {short}… (no bytes, no channel, {age_s}s) — releasing reserved inputs");
                        let _ = crate::tier2_wallet::remove_pending_by_txid(&*storage, &p.txid);
                    }
                }
            });
        }

        // Persist ChannelManager after any event fires, whenever a monitor
        // write flagged it dirty (S21 item 2 — the manager on disk must never
        // trail a commitment across a force-quit), and every 10s as a safety
        // net. ChannelMonitors persist on every update via the
        // chainmonitor::Persist trait.
        let cm_dirty = self.manager_dirty.swap(false, Ordering::Relaxed);
        if event_seen.load(Ordering::Relaxed) || cm_dirty || tick_count % 10 == 0 {
            if let Err(e) = self.persist_channel_manager() {
                log::warn!("ChannelManager persist failed: {e}");
                if cm_dirty {
                    // Don't drop dirtiness on a failed write.
                    self.manager_dirty.store(true, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    /// Access the currently active LSP, if any.
    pub fn active_lsp(&self) -> Option<&ActiveLsp> {
        self.active_lsp.as_ref()
    }

    /// Access the Worker URL from config (used for HTTP calls that go through the proxy).
    pub fn worker_url(&self) -> &str {
        &self.config.worker_url
    }

    /// List currently connected peers by hex pubkey.
    pub fn list_peers(&self) -> LijResult<Vec<String>> {
        let pm = self.peer_manager()?;
        Ok(pm.list_peers()
            .into_iter()
            .map(|p| hex::encode(p.counterparty_node_id.serialize()))
            .collect())
    }

    /// Open an outbound channel to the active LSP, funded from our on-chain
    /// (Tier-2) balance. Initiates the BOLT2 handshake via `create_channel`;
    /// the funding transaction is built + submitted asynchronously when LDK
    /// emits `FundingGenerationReady` (drained in `background_tick`).
    ///
    /// `fee_rate_sat_per_vb` is the on-chain fee rate for the funding tx; it is
    /// converted to sat/kw and carried to the funding step encoded in the low
    /// 32 bits of `user_channel_id` (the high bits hold a per-open nonce, so the
    /// id is always non-zero and never aliases the JIT inbound path, id = 0).
    ///
    /// Returns a small status JSON immediately. Requires an active LSP peer
    /// connection (the wallet maintains one for JIT).
    pub fn open_channel_to_lsp(
        &self,
        amount_sats: u64,
        fee_rate_sat_per_vb: f64,
    ) -> LijResult<String> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static OPEN_NONCE: AtomicU32 = AtomicU32::new(1);

        let cm = self
            .channel_manager
            .as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let lsp = self
            .active_lsp()
            .ok_or_else(|| LijError::Lsp("No active LSP — select one first".into()))?;
        let lsp_pubkey =
            <bitcoin::secp256k1::PublicKey as std::str::FromStr>::from_str(&lsp.info.pubkey)
                .map_err(|e| LijError::Lsp(format!("bad LSP pubkey {}: {e}", lsp.info.pubkey)))?;

        // create_channel requires an active peer connection to the LSP.
        let connected = self
            .list_peers()?
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&lsp.info.pubkey));
        if !connected {
            return Err(LijError::Node(
                "not connected to the LSP peer yet — wait for the connection, then retry".into(),
            ));
        }

        // sat/vB -> sat/kw (1 vbyte = 4 weight units; sat/kw = sat/vB * 250).
        let fee_rate_sat_per_kw = ((fee_rate_sat_per_vb * 250.0).round() as u32).max(250);
        let nonce = OPEN_NONCE.fetch_add(1, Ordering::Relaxed) as u128;
        // Terminus v2 (Session 23, S5): this open proposes a no-anchors
        // commitment (below), so the channel qualifies for the m/84
        // payment_point pin — request it via the UCID high bit. Fee rate
        // stays in the low 32 bits (FundingGenerationReady reads them);
        // nonce in bits 32..96. Explicit-type negotiation is
        // take-it-or-leave-it, so a marked outbound channel can never
        // silently end up anchors.
        let user_channel_id: u128 = crate::signer::UCID_TERMINUS_PIN_BIT
            | (nonce << 32)
            | (fee_rate_sat_per_kw as u128);

        let mut config = UserConfig::default();
        config.channel_handshake_config.minimum_depth = 1;
        config.channel_config.force_close_avoidance_max_fee_satoshis = COOP_CLOSE_MAX_FEE_OVERAGE_SAT; // v41 coop-close fee ceiling
        config.channel_handshake_config.their_channel_reserve_proportional_millionths = LSP_RESERVE_PPM.load(std::sync::atomic::Ordering::Relaxed); // v213 evil-LSP reserve dial
        // Accept a single inbound HTLC up to full channel value (LDK default is
        // 10%) so large LSPS1 receives over wallet-opened channels also work.
        config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
        // Terminus v2 (Session 23, S5): wallet-initiated opens default to
        // NO-ANCHORS / static-remotekey — with the pinned payment_point,
        // an LSP force-close pays a plain m/84 P2WPKH any BIP84 wallet
        // reads. Anchors ("fee-boost insurance on emergency exits, never
        // money") becomes per-channel OPT-IN; its UX toggle ships in a
        // later page build. NODE-level anchors support (init features)
        // stays ON so inbound JIT keeps negotiating exactly as today
        // until the patched LND lands at the desk.
        config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
        config.channel_handshake_config.negotiate_scid_privacy = true;
        // Private / non-routing: do not announce the channel to the gossip network.
        config.channel_handshake_config.announced_channel = false;

        cm.create_channel(lsp_pubkey, amount_sats, 0, user_channel_id, None, Some(config))
            .map(|chan_id| {
                log::info!(
                    "create_channel -> LSP ok: temp_chan={:?} value={amount_sats} sat fee={fee_rate_sat_per_kw} sat/kw",
                    chan_id
                );
                format!("{{\"status\":\"opening\",\"channel_value_sats\":{amount_sats}}}")
            })
            .map_err(|e| LijError::Node(format!("create_channel failed: {e:?}")))
    }

    // ── LSP ───────────────────────────────────────────────────────────────────

    pub async fn connect_lsp(&mut self, lsp: LspInfo) -> LijResult<()> {
        log::info!("Connecting to LSP: {} at {}", lsp.name, lsp.endpoint);
        let client = LspClient::new(lsp.clone());
        if !client.health_check().await {
            return Err(LijError::Lsp(format!("LSP {} unreachable", lsp.name)));
        }
        // Parse LSP pubkey for cooperative chain-data subscribe.
        let lsp_pubkey_bytes = hex::decode(&lsp.pubkey)
            .map_err(|e| LijError::Lsp(format!("LSP pubkey hex decode: {e}")))?;
        let lsp_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&lsp_pubkey_bytes)
            .map_err(|e| LijError::Lsp(format!("LSP pubkey parse: {e}")))?;
        self.active_lsp = Some(ActiveLsp { info: lsp, channel_ids: vec![] });
        let json = serde_json::to_vec(self.active_lsp.as_ref().unwrap())
            .map_err(|e| LijError::Storage(format!("LSP serialize: {e}")))?;
        self.storage.set(KEY_LSP_CONFIG, &json)?;
        // Send initial cooperative chain-data subscribe.
        if let Err(e) = self.cooperative_bridge.send_subscribe(lsp_pubkey) {
            log::warn!("cooperative subscribe failed (non-fatal): {e}");
        }
        log::info!("LSP connected and persisted");
        Ok(())
    }

    pub async fn switch_lsp(&mut self, new_lsp: LspInfo) -> LijResult<()> {
        self.connect_lsp(new_lsp).await
    }

    /// v224: persist the user's explicit provider choice. Only
    /// wallet.switch_lsp calls this — boot selection reads, never writes.
    pub fn persist_chosen_lsp(&self, lsp: &LspInfo) -> LijResult<()> {
        let json = serde_json::to_vec(lsp)
            .map_err(|e| LijError::Storage(format!("chosen-lsp serialize: {e}")))?;
        self.storage.set(KEY_CHOSEN_LSP, &json)
    }

    /// v224: the user's persisted explicit choice, if any.
    pub fn load_chosen_lsp(&self) -> Option<LspInfo> {
        match self.storage.get(KEY_CHOSEN_LSP) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        }
    }

    // ── Balance ───────────────────────────────────────────────────────────────

    pub fn get_balance(&self) -> LijResult<Balance> {
        let lightning_sats = self.channel_manager.as_ref().map(|cm| {
            cm.list_usable_channels().iter()
                .map(|c| c.outbound_capacity_msat / 1000)
                .sum::<u64>()
        }).unwrap_or(0);
        Ok(Balance {
            lightning_sats,
            onchain_sats: 0,
            pending_inbound_sats: 0,
            pending_outbound_sats: 0,
        })
    }

    // ── Invoice ───────────────────────────────────────────────────────────────

    // Step 3.6 (route hints fix): rewritten to manually construct route
    // hints from list_usable_channels() and build the invoice via
    // InvoiceBuilder. LDK's auto-route-hint helper filters out our
    // private channel because LSP hasn't sent us a channel_update
    // (counterparty.forwarding_info is None). We supply LiJ-Node's
    // confirmed default LND fees as fallback.
    // ── LNURLp hash pool (v195, S30 — "held-claim" static receive) ──────
    // The wallet pre-generates preimages LOCALLY, registers only the HASHES
    // (plus LDK payment_secrets) with the LSP, and claims incoming HTLCs
    // locked to those hashes when they arrive. Preimages persist in wallet
    // storage and NEVER leave the device: the LSP literally cannot claim
    // what it holds. Design ledgered docs/session30.md (Option 1).
    fn lnurlp_load_pool(&self) -> std::collections::HashMap<String, String> {
        self.lnurlp_load_pool_checked().unwrap_or_default()
    }

    /// v228: the same load, but honest about failure — `None` when storage
    /// could not be read or the pool did not parse, `Some(empty)` when there
    /// simply is no pool yet. The claim path uses this to tell "I truly do not
    /// hold this preimage" (fail the HTLC back at once) from "I could not look"
    /// (keep holding; the next pass retries).
    fn lnurlp_load_pool_checked(&self) -> Option<std::collections::HashMap<String, String>> {
        match self.storage.get(KEY_LNURLP_PREIMAGES) {
            Ok(Some(bytes)) => {
                let s = std::str::from_utf8(&bytes).ok()?;
                serde_json::from_str(s).ok()
            }
            Ok(None) => Some(std::collections::HashMap::new()),
            Err(_) => None,
        }
    }

    /// v229: the stored next index (0 when absent).
    fn lnurlp_next_index(&self) -> u32 {
        match self.storage.get(KEY_LNURLP_NEXT_INDEX) {
            Ok(Some(b)) => std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0),
            _ => 0,
        }
    }

    fn lnurlp_set_next_index(&self, next: u32) {
        if let Err(e) = self.storage.set(KEY_LNURLP_NEXT_INDEX, next.to_string().as_bytes()) {
            log::error!("LNURLp next-index persist failed: {e}");
        }
    }

    /// v229: find the derived index whose hash is `hash_hex`, searching
    /// 0..bound. Used when the local cache lacks a preimage (restore, wiped
    /// pool). Returns (index, preimage).
    fn lnurlp_derive_search(&self, hash_hex: &str) -> Option<(u32, [u8; 32])> {
        use bitcoin::hashes::Hash as _;
        let bound = self.lnurlp_next_index().saturating_add(1024).max(LNURLP_DERIVE_SEARCH_BOUND);
        for i in 0..bound {
            let pre = self.root_key.lnurlp_preimage(i);
            let h = bitcoin::hashes::sha256::Hash::hash(&pre);
            if hex::encode(h.to_byte_array()) == hash_hex {
                return Some((i, pre));
            }
        }
        None
    }

    fn lnurlp_save_pool(&self, m: &std::collections::HashMap<String, String>) {
        match serde_json::to_string(m) {
            Ok(json) => {
                if let Err(e) = self.storage.set(KEY_LNURLP_PREIMAGES, json.as_bytes()) {
                    log::error!("LNURLp pool persist failed: {e}");
                }
            }
            Err(e) => log::error!("LNURLp pool serialize failed: {e}"),
        }
    }

    /// Generate `count` fresh (preimage, hash, payment_secret) triples,
    /// persist the preimages, register the hashes with LDK
    /// (create_inbound_payment_for_hash, any-amount, 30-day expiry), and
    /// return JSON `[{hash, secret}]` for LSP registration. Preimages are
    /// NOT in the return value by design.
    /// v229 (S43, DP — the robust design): preimages are DERIVED from the
    /// master key by index (RootKey::lnurlp_preimage), never random; the local
    /// pool is only a cache. Each hash is registered in this engine for
    /// LNURLP_HASH_EXPIRY_SECS (30 years) and the same `expires` (unix s) is
    /// handed to the LSP in the JSON, so the LSP retires what this engine
    /// would refuse. `start_hint` is the LSP's own `next_index` for this name
    /// (the page passes it from the register probe) so a wallet restored from
    /// its words continues the sequence instead of re-offering hashes the LSP
    /// already holds. Returns JSON `[{hash, secret, expires, index}]`.
    pub fn lnurlp_prepare_hashes(&self, count: u32, start_hint: Option<u32>) -> LijResult<String> {
        use bitcoin::hashes::Hash as _;
        let n = count.clamp(1, 50);
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let mut pool = self.lnurlp_load_pool();
        let mut next = self.lnurlp_next_index().max(start_hint.unwrap_or(0));
        let expires = current_time_secs().saturating_add(LNURLP_HASH_EXPIRY_SECS as u64);
        let mut out: Vec<serde_json::Value> = Vec::new();
        for _ in 0..n {
            let index = next;
            next = next.saturating_add(1);
            let pre: [u8; 32] = self.root_key.lnurlp_preimage(index);
            let hash = bitcoin::hashes::sha256::Hash::hash(&pre);
            let payment_hash = lightning::ln::PaymentHash(hash.to_byte_array());
            let secret = cm
                .create_inbound_payment_for_hash(payment_hash, None, LNURLP_HASH_EXPIRY_SECS, None)
                .map_err(|()| {
                    LijError::Invoice("create_inbound_payment_for_hash failed".into())
                })?;
            let hash_hex = hex::encode(payment_hash.0);
            pool.insert(hash_hex.clone(), hex::encode(pre));
            out.push(serde_json::json!({
                "hash": hash_hex,
                "secret": hex::encode(secret.0),
                "expires": expires,
                "index": index,
            }));
        }
        self.lnurlp_set_next_index(next);
        self.lnurlp_save_pool(&pool);
        log::info!("LNURLp pool: prepared {} derived hash(es) (indices up to {}); cache size now {}", n, next.saturating_sub(1), pool.len());
        Ok(serde_json::to_string(&out).unwrap_or_else(|_| "[]".into()))
    }

    pub fn create_invoice(
        &self,
        amount_sats: Option<u64>,
        memo: &str,
        expiry_seconds: u64,
    ) -> LijResult<InvoiceResult> {
        require_can_receive(self.sync_state.current())?;
        log::info!("Creating invoice: {:?} sats, memo={}", amount_sats, memo);
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let amt_msat = amount_sats.map(|s| s * 1000);

        let (payment_hash, payment_secret) = cm
            .create_inbound_payment(amt_msat, expiry_seconds as u32, None)
            .map_err(|()| LijError::Invoice("create_inbound_payment failed".into()))?;

        // v168: capture the secret (hex) before it is moved into the builder.
        // Registered with the LSP out-of-band (hash-keyed) for trampoline
        // settles of held forwards.
        let payment_secret_hex = hex::encode(payment_secret.0);

        let currency = match self.network {
            Network::Bitcoin => Currency::Bitcoin,
            Network::Testnet => Currency::BitcoinTestnet,
            Network::Signet  => Currency::Signet,
            Network::Regtest => Currency::Regtest,
            _                => Currency::Bitcoin,
        };

        let duration_since_epoch = std::time::Duration::from_secs(current_time_secs());

        // LSP fallback fees if counterparty.forwarding_info is None.
        // Verified from `lncli feereport` on UM890: LiJ-Node uses LND
        // defaults (1 sat base, 1 ppm, 80 blocks CLTV delta).
        let lsp_default_fee_base_msat: u32     = 1000;
        let lsp_default_fee_proportional: u32  = 1;
        let lsp_default_cltv_expiry_delta: u16 = 80;

        let route_hints: Vec<RouteHint> = cm.list_usable_channels().into_iter()
            .filter(|ch| !ch.is_public)
            .filter(|ch| ch.inbound_capacity_msat >= amt_msat.unwrap_or(0))
            .filter_map(|ch| {
                let scid = ch.inbound_scid_alias.or(ch.short_channel_id)?;
                let (fee_base, fee_ppm, cltv_delta) = ch.counterparty.forwarding_info
                    .as_ref()
                    .map(|f| (f.fee_base_msat, f.fee_proportional_millionths, f.cltv_expiry_delta))
                    .unwrap_or((
                        lsp_default_fee_base_msat,
                        lsp_default_fee_proportional,
                        lsp_default_cltv_expiry_delta,
                    ));
                Some(RouteHint(vec![RouteHintHop {
                    src_node_id: ch.counterparty.node_id,
                    short_channel_id: scid,
                    fees: RoutingFees {
                        base_msat: fee_base,
                        proportional_millionths: fee_ppm,
                    },
                    cltv_expiry_delta: cltv_delta,
                    htlc_minimum_msat: None,
                    htlc_maximum_msat: None,
                }]))
            })
            .collect();

        log::info!("Built {} route hint(s) for invoice", route_hints.len());

        let payment_hash_obj = sha256::Hash::from_slice(&payment_hash.0)
            .map_err(|e| LijError::Invoice(format!("payment_hash hash: {:?}", e)))?;

        let mut builder = InvoiceBuilder::new(currency)
            .description(memo.to_string())
            .duration_since_epoch(duration_since_epoch)
            .payee_pub_key(cm.get_our_node_id())
            .payment_hash(payment_hash_obj)
            .payment_secret(payment_secret)
            .basic_mpp()
            .min_final_cltv_expiry_delta(24)
            .expiry_time(std::time::Duration::from_secs(expiry_seconds));

        if let Some(amt) = amt_msat {
            builder = builder.amount_milli_satoshis(amt);
        }
        for hint in route_hints {
            builder = builder.private_route(hint);
        }

        let raw_invoice = builder.build_raw()
            .map_err(|e| LijError::Invoice(format!("build_raw: {:?}", e)))?;

        // Sign by directly hashing+signing the &Message that LDK provides.
        // Avoids needing bech32::ToBase32 trait (would require adding
        // bech32 to Cargo.toml as a direct dep).
        let secret_key = self.keys_manager.get_node_secret_key();
        let signed_raw = raw_invoice
            .sign::<_, ()>(|message| {
                let secp = bitcoin::secp256k1::Secp256k1::signing_only();
                Ok(secp.sign_ecdsa_recoverable(message, &secret_key))
            })
            .map_err(|_| LijError::Invoice("sign failed".into()))?;

        let invoice = Bolt11Invoice::from_signed(signed_raw)
            .map_err(|e| LijError::Invoice(format!("from_signed: {:?}", e)))?;

        let bolt11 = invoice.to_string();
        let payment_hash_hex = hex::encode(&invoice.payment_hash()[..]);
        self.persist_channel_manager()?;
        log::info!("Invoice created: {}…", &bolt11[..30.min(bolt11.len())]);
        Ok(InvoiceResult { bolt11, payment_hash: payment_hash_hex, amount_sats, expiry_seconds, payment_secret: payment_secret_hex })
    }

    /// v0.16 Phase C: Build a Lightning invoice with an LSPS2 JIT channel
    /// route_hint, using a promise the caller already obtained from the LSP.
    ///
    /// SYNCHRONOUS — caller must have already called the LSP's get_info and
    /// /lsps2/buy before invoking this. Splitting the flow this way lets the
    /// WASM layer hold the wallet mutex only during this sync build, not
    /// across the network round-trips. Matches the v8 send-path discipline
    /// that fixed mutex_no_threads panics on long fetches.
    ///
    /// The invoice's sole route_hint uses:
    ///   - src_node_id      = LSP pubkey from the buy response
    ///   - short_channel_id = JIT alias from the buy response (16 hex → u64)
    ///   - fees             = from get_info (base_fee_msat, fee_ppm)
    ///   - cltv_expiry_delta = 80 (LiJ-Node LND policy. TODO: surface in get_info.)
    ///
    /// When the payer's HTLC arrives at the LSP carrying this SCID, Phase D's
    /// htlc-interceptor will recognize the promise, open a zero-conf channel
    /// to this wallet, and forward the HTLC over it.
    pub fn build_invoice_with_jit_promise(
        &self,
        amount_sats: u64,
        memo: &str,
        expiry_seconds: u64,
        info: &crate::lsps2::Lsps2GetInfoResponse,
        buy: crate::lsps2::Lsps2BuyResponse,
    ) -> LijResult<InvoiceWithJitResult> {
        require_can_receive(self.sync_state.current())?;
        log::info!(
            "Building JIT invoice: {} sats, memo={}, scid={}",
            amount_sats, memo, buy.jit_channel_scid
        );

        // Validate payment size is within LSP's range (cheap; sub-microsecond).
        let amount_msat = amount_sats * 1000;
        let min_msat = info.min_payment_size_msat_u64()?;
        let max_msat = info.max_payment_size_msat_u64()?;
        if amount_msat < min_msat {
            return Err(LijError::Lsp(format!(
                "JIT payment too small: {} msat (LSP minimum {})", amount_msat, min_msat
            )));
        }
        if amount_msat > max_msat {
            return Err(LijError::Lsp(format!(
                "JIT payment too large: {} msat (LSP maximum {})", amount_msat, max_msat
            )));
        }

        // Parse SCID alias (16 hex chars → u64) and LSP pubkey.
        let jit_scid_u64 = u64::from_str_radix(&buy.jit_channel_scid, 16)
            .map_err(|e| LijError::Invoice(format!("Invalid jit_channel_scid hex: {e}")))?;
        let lsp_pubkey_bytes = hex::decode(&buy.lsp_pubkey)
            .map_err(|e| LijError::Invoice(format!("Invalid lsp_pubkey hex: {e}")))?;
        let lsp_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&lsp_pubkey_bytes)
            .map_err(|e| LijError::Invoice(format!("Invalid lsp_pubkey: {e}")))?;

        // JIT (channel-opening) invoice: the LSP's compensation is the one-time
        // channel-open fee (buy.fee_msat), collected by INFLATING the invoice
        // amount (see amount_milli_satoshis below) and deducted by the LSP from
        // the forwarded HTLC. The route_hint therefore charges ZERO routing fee:
        // if it also charged the ongoing base/ppm, that spread would be taken on
        // top of the open-fee deduction, so the forward would land BELOW what
        // create_inbound_payment expects -> the wallet rejects as underpayment.
        // (Ongoing per-payment routing fees apply to LATER receives over the
        // established channel via create_invoice -- not to this opening payment.)
        // If channel_open_fee_sats is ever 0 (collect-via-flow model), gross ==
        // net, nothing is deducted, and this still settles cleanly.
        let jit_hint_base_msat: u32 = 0;
        let jit_hint_ppm: u32 = 0;
        let cltv_expiry_delta: u16 = 80;  // LiJ-Node LND policy. TODO: surface in get_info.

        let jit_hint = RouteHint(vec![RouteHintHop {
            src_node_id: lsp_pubkey,
            short_channel_id: jit_scid_u64,
            fees: RoutingFees {
                base_msat: jit_hint_base_msat,
                proportional_millionths: jit_hint_ppm,
            },
            cltv_expiry_delta,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        }]);

        log::info!(
            "JIT route_hint: scid={} lsp_pubkey={}... base={} ppm={} cltv={} (open fee charged via invoice inflation, not the route hint)",
            buy.jit_channel_scid, &buy.lsp_pubkey[..16], jit_hint_base_msat, jit_hint_ppm, cltv_expiry_delta
        );

        // Build the invoice — pattern mirrors create_invoice() above.
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        // v217 (S36, O5 full balance availability): the payer-funds-the-floor
        // prefund rides INSIDE the expected amount — the three coupled numbers
        // (buy payment_size, this expected amount, the registered secret total)
        // all equal amount + prefund, so the adapter's completeness gross, its
        // final-hop mpp total, and LDK's claim check agree to the msat. The
        // forward (gross − open_fee) then settles EXACTLY at net_expected.
        let prefund_msat = buy.prefund_msat_u64();
        let net_expected_msat = amount_msat.saturating_add(prefund_msat);
        let (payment_hash, payment_secret) = cm
            .create_inbound_payment(Some(net_expected_msat), expiry_seconds as u32, None)
            .map_err(|()| LijError::Invoice("create_inbound_payment failed".into()))?;

        let currency = match self.network {
            Network::Bitcoin => Currency::Bitcoin,
            Network::Testnet => Currency::BitcoinTestnet,
            Network::Signet  => Currency::Signet,
            Network::Regtest => Currency::Regtest,
            _                => Currency::Bitcoin,
        };

        let duration_since_epoch = std::time::Duration::from_secs(current_time_secs());
        let payment_hash_obj = sha256::Hash::from_slice(&payment_hash.0)
            .map_err(|e| LijError::Invoice(format!("payment_hash hash: {:?}", e)))?;

        // Capture the payment_secret (hex) before it is moved into the builder.
        // Sent to the LSP out-of-band via /lsps2/register_secret (Option B) so it
        // can rebuild the final hop in sendToRouteV2. NOT the preimage.
        let payment_secret_hex = hex::encode(payment_secret.0);

        // Inflate the invoice by the LSP's one-time channel-open fee so the PAYER
        // covers it and the wallet still receives the full requested amount.
        // amount_msat (net) was registered as the create_inbound_payment minimum
        // above; the LSP deducts open_fee_msat from the forward, so the net
        // forward of (gross - open_fee) == amount_msat and settles exactly.
        let open_fee_msat = buy.fee_msat_u64()?;
        // v217 (O5): gross = amount + prefund + open fee — the payer funds the
        // floor; the 400 lands on the USER'S side and leaves with them at close.
        let gross_msat = net_expected_msat.saturating_add(open_fee_msat);
        log::info!("JIT invoice math (O5): requested={} + prefund={} + open_fee={} = gross={} msat",
            amount_msat, prefund_msat, open_fee_msat, gross_msat);

        let builder = InvoiceBuilder::new(currency)
            .description(memo.to_string())
            .duration_since_epoch(duration_since_epoch)
            .payee_pub_key(cm.get_our_node_id())
            .payment_hash(payment_hash_obj)
            .payment_secret(payment_secret)
            .basic_mpp()
            .min_final_cltv_expiry_delta(24)
            .expiry_time(std::time::Duration::from_secs(expiry_seconds))
            .amount_milli_satoshis(gross_msat)
            .private_route(jit_hint);

        let raw_invoice = builder.build_raw()
            .map_err(|e| LijError::Invoice(format!("build_raw: {:?}", e)))?;

        let secret_key = self.keys_manager.get_node_secret_key();
        let signed_raw = raw_invoice
            .sign::<_, ()>(|message| {
                let secp = bitcoin::secp256k1::Secp256k1::signing_only();
                Ok(secp.sign_ecdsa_recoverable(message, &secret_key))
            })
            .map_err(|_| LijError::Invoice("sign failed".into()))?;

        let invoice = Bolt11Invoice::from_signed(signed_raw)
            .map_err(|e| LijError::Invoice(format!("from_signed: {:?}", e)))?;

        let bolt11 = invoice.to_string();
        let payment_hash_hex = hex::encode(&invoice.payment_hash()[..]);
        self.persist_channel_manager()?;
        log::info!("JIT invoice created: {}…", &bolt11[..30.min(bolt11.len())]);

        Ok(InvoiceWithJitResult {
            invoice: InvoiceResult {
                payment_secret: payment_secret_hex.clone(),
                bolt11,
                payment_hash: payment_hash_hex,
                amount_sats: Some(amount_sats),
                expiry_seconds,
            },
            jit: InvoiceJitInfo {
                jit_channel_scid:   buy.jit_channel_scid,
                lsp_pubkey:         buy.lsp_pubkey,
                fee_msat:           buy.fee_msat,
                prefund_msat:       buy.prefund_msat.clone().unwrap_or_else(|| "0".into()),   // v217 (O5)
                promise_expires_at: buy.promise_expires_at,
                human_summary:      buy.human_summary,
            },
            payment_secret_hex,
        })
    }

    /// v188 (S27): OPEN-AMOUNT JIT invoice — the zero-amount sibling of
    /// build_invoice_with_jit_promise. Differences, each deliberate:
    ///   - no payment-size validation (there is no size; the adapter's
    ///     per-shard floor + ceiling env govern at forward time);
    ///   - create_inbound_payment(None): LDK claims WHATEVER total the
    ///     payer's final hop declares — which the adapter sets to
    ///     (observed sum − fee) at quiescence flush, so the deduction can
    ///     never break claim equality (design final v2);
    ///   - NO invoice inflation (nothing to inflate); the LSP's
    ///     compensation is the variable deduction, priced to senders via
    ///     the route hint: base=0, ppm = info.variable.fee_ppm;
    ///   - amountless InvoiceBuilder — basic_mpp KEPT (essential: this
    ///     whole arc exists so zero-amount invoices can shard).
    /// Fixed-mode builder above is byte-untouched (prime directive).
    pub fn build_open_invoice_with_jit_promise(
        &self,
        memo: &str,
        expiry_seconds: u64,
        info: &crate::lsps2::Lsps2GetInfoResponse,
        buy: crate::lsps2::Lsps2BuyResponse,
    ) -> LijResult<InvoiceWithJitResult> {
        require_can_receive(self.sync_state.current())?;

        let variable = info.variable.as_ref()
            .filter(|v| v.enabled)
            .ok_or_else(|| LijError::Lsp(
                "This LSP does not support open-amount JIT invoices yet — \
                 enter an amount, or wait for the LSP to enable variable mode".into()))?;

        log::info!(
            "Building OPEN JIT invoice (zero-amount): memo={}, scid={}, hint ppm={} (variable mode)",
            memo, buy.jit_channel_scid, variable.fee_ppm
        );

        let jit_scid_u64 = u64::from_str_radix(&buy.jit_channel_scid, 16)
            .map_err(|e| LijError::Invoice(format!("Invalid jit_channel_scid hex: {e}")))?;
        let lsp_pubkey_bytes = hex::decode(&buy.lsp_pubkey)
            .map_err(|e| LijError::Invoice(format!("Invalid lsp_pubkey hex: {e}")))?;
        let lsp_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&lsp_pubkey_bytes)
            .map_err(|e| LijError::Invoice(format!("Invalid lsp_pubkey: {e}")))?;

        // Variable-mode hint: senders price the LSP's deduction as an
        // ordinary routing fee. base=0 (a per-shard base would multiply by
        // shard count); min_fee is enforced adapter-side at flush — safe
        // with an amountless claim (see doc above).
        let cltv_expiry_delta: u16 = 80;  // LiJ-Node LND policy, same as fixed.
        let ppm_u32: u32 = u32::try_from(variable.fee_ppm)
            .map_err(|_| LijError::Lsp("variable.fee_ppm exceeds u32".into()))?;
        let jit_hint = RouteHint(vec![RouteHintHop {
            src_node_id: lsp_pubkey,
            short_channel_id: jit_scid_u64,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: ppm_u32,
            },
            cltv_expiry_delta,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        }]);

        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let (payment_hash, payment_secret) = cm
            .create_inbound_payment(None, expiry_seconds as u32, None)
            .map_err(|()| LijError::Invoice("create_inbound_payment failed".into()))?;

        let currency = match self.network {
            Network::Bitcoin => Currency::Bitcoin,
            Network::Testnet => Currency::BitcoinTestnet,
            Network::Signet  => Currency::Signet,
            Network::Regtest => Currency::Regtest,
            _                => Currency::Bitcoin,
        };

        let duration_since_epoch = std::time::Duration::from_secs(current_time_secs());
        let payment_hash_obj = sha256::Hash::from_slice(&payment_hash.0)
            .map_err(|e| LijError::Invoice(format!("payment_hash hash: {:?}", e)))?;

        // Registered out-of-band via /lsps2/register_secret with total_msat=0
        // — the VARIABLE SENTINEL. The adapter fills the real total at flush.
        let payment_secret_hex = hex::encode(payment_secret.0);

        let builder = InvoiceBuilder::new(currency)
            .description(memo.to_string())
            .duration_since_epoch(duration_since_epoch)
            .payee_pub_key(cm.get_our_node_id())
            .payment_hash(payment_hash_obj)
            .payment_secret(payment_secret)
            .basic_mpp()
            .min_final_cltv_expiry_delta(24)
            .expiry_time(std::time::Duration::from_secs(expiry_seconds))
            .private_route(jit_hint);

        let raw_invoice = builder.build_raw()
            .map_err(|e| LijError::Invoice(format!("build_raw: {:?}", e)))?;

        let secret_key = self.keys_manager.get_node_secret_key();
        let signed_raw = raw_invoice
            .sign::<_, ()>(|message| {
                let secp = bitcoin::secp256k1::Secp256k1::signing_only();
                Ok(secp.sign_ecdsa_recoverable(message, &secret_key))
            })
            .map_err(|_| LijError::Invoice("sign failed".into()))?;

        let invoice = Bolt11Invoice::from_signed(signed_raw)
            .map_err(|e| LijError::Invoice(format!("from_signed: {:?}", e)))?;

        let bolt11 = invoice.to_string();
        let payment_hash_hex = hex::encode(&invoice.payment_hash()[..]);
        self.persist_channel_manager()?;
        log::info!("OPEN JIT invoice created: {}…", &bolt11[..30.min(bolt11.len())]);

        Ok(InvoiceWithJitResult {
            invoice: InvoiceResult {
                payment_secret: payment_secret_hex.clone(),
                bolt11,
                payment_hash: payment_hash_hex,
                amount_sats: None,
                expiry_seconds,
            },
            jit: InvoiceJitInfo {
                jit_channel_scid:   buy.jit_channel_scid,
                lsp_pubkey:         buy.lsp_pubkey,
                fee_msat:           buy.fee_msat,
                // v217 (O5): open-amount invoices CANNOT charge a payer-funds
                // prefund (no amount to inflate) — honest zero by design; the
                // adapter's stamp on variable buys goes deliberately unused.
                prefund_msat:       "0".to_string(),
                promise_expires_at: buy.promise_expires_at,
                human_summary:      buy.human_summary,
            },
            payment_secret_hex,
        })
    }

    // ── Payment ───────────────────────────────────────────────────────────────

    pub async fn send_payment(&self, bolt11: &str) -> LijResult<PaymentResult> {
    require_can_send(self.sync_state.current())?;
    log::info!("Sending: {}…", &bolt11[..20.min(bolt11.len())]);
    let cm = self.channel_manager.as_ref()
        .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

    let invoice = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|e| LijError::Payment(format!("Invalid invoice: {:?}", e)))?;

    // v194 (S29): this legacy direct-send path has no amount parameter —
    // an amountless invoice cannot work here; say so in words instead of
    // LDK's unit error.
    if invoice.amount_milli_satoshis().is_none() {
        return Err(LijError::Payment(
            "Invoice has no amount \u{2014} this send path needs an amount-bearing invoice".into(),
        ));
    }

    let (payment_hash, recipient_onion, route_params) =
        lightning_invoice::payment::payment_parameters_from_invoice(&invoice)
        .map_err(|e| LijError::Payment(format!("Invoice params error: {:?}", e)))?;

    let payment_id = lightning::ln::channelmanager::PaymentId(payment_hash.0);

    // Use send_payment directly — avoids internal SystemTime::now() calls
    // that panic on WASM target
    match cm.send_payment(
        payment_hash,
        recipient_onion,
        payment_id,
        route_params,
        Retry::Attempts(0), // No retries — avoids stale payment cleanup timer
    ) {
        Ok(_) => {
            log::info!("Payment initiated");
            Ok(PaymentResult { success: true, preimage: None, fee_sats: None, error: None })
        }
        Err(e) => {
            let msg = format!("{:?}", e);
            log::warn!("Payment failed: {}", msg);
            Ok(PaymentResult { success: false, preimage: None, fee_sats: None, error: Some(msg) })
        }
    }
}

    /// Phase 10b — Send a Lightning payment using a route obtained from the LSP.
    ///
    /// Architecture:
    ///   1. Decode invoice → extract payment_hash, amount, dest pubkey, payment_secret
    ///   2. Look up active LSP's route_endpoint + route_macaroon
    ///   3. HTTP fetch route from LSP's QueryRoutes endpoint (LND-format)
    ///   4. Convert LND-format route → LDK Route struct
    ///   5. Call cm.send_payment_with_route() — bypasses LDK path-finding
    ///
    /// FUTURE: failover to alternate LSPs (Path B fallback to wallet-side
    /// path-finding) is deferred until LIJOX spec defines the fallback
    /// ordering and until no-std migration unblocks client-side RGS.
    #[cfg(target_arch = "wasm32")]
    pub async fn send_payment_via_lsp_route(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
    ) -> LijResult<PaymentResult> {
        // v8: thin compat wrapper. The real work is split into prepare + apply
        // so the WASM-side wrapper can release the wallet mutex during the HTTP
        // fetch. This wrapper, kept for backwards compatibility with v7's
        // doSend(), still holds the lock across the await — callers using the
        // new retry mechanism should call send_payment_with_retries instead.
        let prep = self.prepare_lsp_route_request(bolt11, route_endpoint, &[], None)?;
        let response_text = fetch_post_with_macaroon(
            &prep.url, route_macaroon_hex, &prep.request_body,
        ).await?;
        self.apply_lsp_route_and_send(&response_text, &prep)
    }

    /// v8 (Phase 10b prep step, sync, lock-friendly): Build the adapter
    /// /v1/route/build POST request from the invoice. Returns everything the
    /// downstream apply step needs after the HTTP round-trip — including the
    /// payment_hash so callers can poll for an outcome.
    ///
    /// `excluded_pairs` is a list of (from_pubkey, to_pubkey) compressed-33-byte
    /// channel edges that should be EXCLUDED from path-finding on this attempt.
    /// Used by send_payment_with_retries to retry around a hop that failed on
    /// a prior attempt. Empty for first attempt.
    #[cfg(target_arch = "wasm32")]
    pub fn prepare_lsp_route_request(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        excluded_pairs: &[(Vec<u8>, Vec<u8>)],
        // MPP (v158): when Some(sats), request a route for THIS part amount
        // instead of the invoice's full amount. Single-path callers pass None
        // (unchanged behaviour). Identity fields (payment_hash, recipient_onion,
        // final_cltv_delta) are invoice-derived and identical across parts; only
        // the request body's amount_sat differs per part.
        override_amount_sat: Option<u64>,
    ) -> LijResult<LspRoutePreparation> {
        self.prepare_lsp_route_request_msat(bolt11, route_endpoint, excluded_pairs, override_amount_sat.map(|s| s.saturating_mul(1000)))
    }

    /// S45 (DP, "truly 0"): the same preparation with a MILLISAT override, so a
    /// Max send can carry the exact sub-sat amount. The route request to the
    /// LSP still says whole sats (its API); LND prices the hop fee with integer
    /// division, so the quoted fee for floor(sats) is never below what LND
    /// requires for the exact msat amount.
    #[cfg(target_arch = "wasm32")]
    pub fn prepare_lsp_route_request_msat(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        excluded_pairs: &[(Vec<u8>, Vec<u8>)],
        override_amount_msat: Option<u64>,
    ) -> LijResult<LspRoutePreparation> {
        let override_amount_sat: Option<u64> = override_amount_msat.map(|m| m / 1000);
        require_can_send(self.sync_state.current())?;
        log::info!("Phase10b: prepare request for {}…", &bolt11[..20.min(bolt11.len())]);

        // Channel manager must exist at apply time too, but we don't need a
        // borrow now — only confirm it's initialized.
        let _ = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let invoice = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| LijError::Payment(format!("Invalid invoice: {:?}", e)))?;

        // v194 (S29): the v187 treatment, applied to the Phase10b prepare —
        // payment_parameters_from_invoice ERRORS on amountless invoices, and
        // only the identity pair is used here (route_params was already
        // discarded; the B1 override below supplies the user amount).
        // Amount-ful invoices take the ORIGINAL call, byte-identical
        // (prime directive: working sends are untouchable).
        let (payment_hash, recipient_onion) = if invoice.amount_milli_satoshis().is_some() {
            let (h, o, _route_params) =
                lightning_invoice::payment::payment_parameters_from_invoice(&invoice)
                .map_err(|e| LijError::Payment(format!("Invoice params error: {:?}", e)))?;
            (h, o)
        } else {
            use bitcoin::hashes::Hash as _;
            (
                lightning::ln::PaymentHash(invoice.payment_hash().to_byte_array()),
                lightning::ln::channelmanager::RecipientOnionFields::secret_only(
                    *invoice.payment_secret(),
                ),
            )
        };

        // v8: generate a FRESH PaymentId per prepare call. We can't reuse the
        // same PaymentId across retries because LDK keeps Retryable state for
        // any previously-submitted payment_id (send_payment_with_route never
        // auto-retries on user-routes — only the LDK router does). PaymentHash
        // is the constant across retries; PaymentId differs.
        // 32 random bytes from the KeysManager's entropy source.
        use lightning::sign::EntropySource;
        let payment_id_bytes = self.keys_manager.get_secure_random_bytes();
        let payment_id = lightning::ln::channelmanager::PaymentId(payment_id_bytes);
        let dest_pubkey_hex = hex::encode(invoice.recover_payee_pub_key().serialize());
        let invoice_amount_msat = invoice.amount_milli_satoshis()
            // B1 (S25): open invoices — the caller's override carries the
            // user amount; the match below then selects the same value.
            .or(override_amount_sat.map(|s| s.saturating_mul(1000)))
            .ok_or_else(|| LijError::Payment("Invoice has no amount \u{2014} enter one to pay this open invoice".into()))?;
        // MPP (v158): route-build uses the part amount when overridden, else the
        // invoice's full amount. Identity (hash/secret/cltv) is unaffected.
        let amount_msat = match override_amount_msat {
            Some(m) => m,
            None => invoice_amount_msat,
        };
        let amount_sats = amount_msat / 1000;
        let final_cltv_delta = invoice.min_final_cltv_expiry_delta() as u32;

        // Build route_hints JSON from invoice's BOLT11 hint set (see v7 comments
        // above for LDK→LND field mapping). Empty array = no hints.
        let route_hints_json: Vec<serde_json::Value> = invoice.route_hints().iter().map(|hint| {
            serde_json::json!({
                "hop_hints": hint.0.iter().map(|hop| {
                    serde_json::json!({
                        "node_id": hex::encode(hop.src_node_id.serialize()),
                        "chan_id": hop.short_channel_id.to_string(),
                        "fee_base_msat": hop.fees.base_msat,
                        "fee_proportional_millionths": hop.fees.proportional_millionths,
                        "cltv_expiry_delta": hop.cltv_expiry_delta as u32,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect();

        // v8: build ignored_pairs JSON. Adapter v0.13+ accepts this and passes
        // through to LND's QueryRoutes ignored_pairs field for retry-with-
        // exclusion. Hex pubkeys go on the wire; adapter does the hex→base64
        // conversion for LND REST.
        let ignored_pairs_json: Vec<serde_json::Value> = excluded_pairs.iter().map(|(from, to)| {
            serde_json::json!({
                "from": hex::encode(from),
                "to":   hex::encode(to),
            })
        }).collect();

        let url = format!("{}/v1/route/build", route_endpoint.trim_end_matches('/'));
        let mut body_map = serde_json::Map::new();
        body_map.insert("destination".to_string(), serde_json::Value::String(dest_pubkey_hex.clone()));
        body_map.insert("amount_sat".to_string(), serde_json::Value::from(amount_sats));
        body_map.insert("route_hints".to_string(), serde_json::Value::Array(route_hints_json.clone()));
        if !ignored_pairs_json.is_empty() {
            body_map.insert("ignored_pairs".to_string(),
                serde_json::Value::Array(ignored_pairs_json));
        }
        let request_body = serde_json::Value::Object(body_map).to_string();

        log::info!("Phase10b: POST {} with {} route_hint(s), {} excluded pair(s)",
            url, route_hints_json.len(), excluded_pairs.len());

        Ok(LspRoutePreparation {
            url,
            request_body,
            payment_hash,
            recipient_onion,
            payment_id,
            final_cltv_delta,
            amount_msat,
            dest_pubkey_hex,
        })
    }

    /// v8 (Phase 10b apply step, sync, lock-required): Parse the LND response,
    /// extract adapter v0.12+ first-hop policy, prepend the wallet→LSP self-hop,
    /// and call send_payment_with_route. This is the part that must hold the
    /// wallet lock (touches channel_manager.list_channels and submits the HTLC).
    #[cfg(target_arch = "wasm32")]
    pub fn apply_lsp_route_and_send(
        &self,
        response_text: &str,
        prep: &LspRoutePreparation,
    ) -> LijResult<PaymentResult> {
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        // ── v222 (S38, DP GO — INTERNAL LNURLp): when the destination IS the
        // active LSP (held-claim invoices mint on the LSP's own node), the
        // correct route is the prepended self-hop and NOTHING ELSE. Asked to
        // route from itself to itself while honoring the invoice's PUBLIC
        // hints, LND can only answer out-and-back over the same channel —
        // which LDK rightly rejects ("Path went through the same channel
        // twice"; DP field, 5/5 deterministic). The adapter round-trip result
        // is IGNORED here; channel selection mirrors the prepend block.
        let v222_self_dest = self.active_lsp.as_ref()
            .map(|a| a.info.pubkey.eq_ignore_ascii_case(&prep.dest_pubkey_hex))
            .unwrap_or(false);
        if v222_self_dest {
            use bitcoin::secp256k1::PublicKey;
            let lsp_pubkey_hex = self.active_lsp.as_ref()
                .map(|a| a.info.pubkey.clone())
                .ok_or_else(|| LijError::Payment("No active LSP — internal route".into()))?;
            let lsp_pubkey_bytes = hex::decode(&lsp_pubkey_hex)
                .map_err(|e| LijError::Payment(format!("LSP pubkey hex: {:?}", e)))?;
            let lsp_pubkey = PublicKey::from_slice(&lsp_pubkey_bytes)
                .map_err(|e| LijError::Payment(format!("LSP PublicKey: {:?}", e)))?;
            let channels = cm.list_channels();
            let (v222_scid,) = {
                let lsp_chan = channels.iter()
                    .filter(|c| c.counterparty.node_id == lsp_pubkey)
                    .filter(|c| c.is_usable)
                    .max_by_key(|c| c.outbound_capacity_msat)
                    .ok_or_else(|| LijError::Payment(format!(
                        "No usable channel to LSP {}…", &lsp_pubkey_hex[..16.min(lsp_pubkey_hex.len())]
                    )))?;
                let scid = lsp_chan.short_channel_id
                    .or(lsp_chan.outbound_scid_alias)
                    .ok_or_else(|| LijError::Payment(
                        "LSP channel has no short_channel_id or outbound_scid_alias".into()))?;
                (scid,)
            };
            log::info!("Phase10b v222: internal dest==LSP — single-hop route scid={} amount_msat={} final_cltv={} (LND response ignored)",
                v222_scid, prep.amount_msat, prep.final_cltv_delta);
            let route = Route {
                paths: vec![Path {
                    hops: vec![RouteHop {
                        pubkey: lsp_pubkey,
                        node_features: NodeFeatures::empty(),
                        short_channel_id: v222_scid,
                        channel_features: ChannelFeatures::empty(),
                        fee_msat: prep.amount_msat,
                        cltv_expiry_delta: prep.final_cltv_delta,
                        maybe_announced_channel: false,
                    }],
                    blinded_tail: None,
                }],
                route_params: None,
            };
            return match cm.send_payment_with_route(
                &route,
                prep.payment_hash,
                prep.recipient_onion.clone(),
                prep.payment_id,
            ) {
                Ok(_) => {
                    log::info!("Phase10b v222: internal payment initiated (hash={:?} amount_msat={})",
                        prep.payment_hash, prep.amount_msat);
                    self.pump_outbound();   // v227: the HTLC leaves now, not on the next tick
                    Ok(PaymentResult { success: true, preimage: None, fee_sats: None, error: None })
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    log::warn!("Phase10b v222: internal payment failed (synchronous): {}", msg);
                    Ok(PaymentResult { success: false, preimage: None, fee_sats: None, error: Some(msg) })
                }
            };
        }

        let mut route = parse_lnd_route_response(response_text, prep.final_cltv_delta)?;
        log::info!("Phase10b: route from LSP has {} path(s), {} hop(s) before prepend",
            route.paths.len(),
            route.paths.first().map(|p| p.hops.len()).unwrap_or(0));

        // Extract adapter v0.12+ lsp_first_hop_policy (see v7 doc above).
        let lsp_first_hop_policy_from_adapter: Option<(u64, u64, u32)> = (|| {
            let parsed: serde_json::Value = serde_json::from_str(response_text).ok()?;
            let policy = parsed.get("lsp_first_hop_policy")?;
            let base: u64 = policy.get("fee_base_msat")?.as_str()?.parse().ok()?;
            let ppm = policy.get("fee_proportional_millionths")?.as_u64()?;
            let cltv = policy.get("cltv_expiry_delta")?.as_u64()? as u32;
            Some((base, ppm, cltv))
        })();
        // v216 (O6 exact-fee): every route-build sighting refreshes the policy
        // cache the quote/estimator/planner all read.
        if let Some((b, p, _)) = lsp_first_hop_policy_from_adapter {
            record_lsp_fee_policy(b, p);
        }

        // Prepend wallet→LSP self-hop (see v7 doc above for full rationale).
        {
            use bitcoin::secp256k1::PublicKey;

            let lsp_pubkey_hex = self.active_lsp.as_ref()
                .map(|a| a.info.pubkey.clone())
                .ok_or_else(|| LijError::Payment(
                    "No active LSP — cannot prepend LSP hop".into()))?;
            let lsp_pubkey_bytes = hex::decode(&lsp_pubkey_hex)
                .map_err(|e| LijError::Payment(format!("LSP pubkey hex: {:?}", e)))?;
            let lsp_pubkey = PublicKey::from_slice(&lsp_pubkey_bytes)
                .map_err(|e| LijError::Payment(format!("LSP PublicKey: {:?}", e)))?;

            let channels = cm.list_channels();
            let (lsp_scid, base_msat, ppm, cltv_delta) = {
                let lsp_chan = channels.iter()
                    .filter(|c| c.counterparty.node_id == lsp_pubkey)
                    .filter(|c| c.is_usable)
                    .max_by_key(|c| c.outbound_capacity_msat)
                    .ok_or_else(|| LijError::Payment(format!(
                        "No usable channel to LSP {}…", &lsp_pubkey_hex[..16.min(lsp_pubkey_hex.len())]
                    )))?;
                let scid = lsp_chan.short_channel_id
                    .or(lsp_chan.outbound_scid_alias)
                    .ok_or_else(|| LijError::Payment(
                        "LSP channel has no short_channel_id or outbound_scid_alias".into()))?;
                let (base, ppm, cltv) = if let Some((b, p, c)) = lsp_first_hop_policy_from_adapter {
                    log::info!("Phase10b (3.8.h): using LSP-advertised first-hop policy: base={} ppm={} cltv={}", b, p, c);
                    (b, p, c)
                } else {
                    log::warn!("Phase10b: no lsp_first_hop_policy from adapter (pre-v0.12 adapter or lookup failed); falling back to counterparty.forwarding_info — this describes the LSP→wallet direction, NOT wallet→peer-via-LSP, and may underpay the LSP causing fee_insufficient");
                    match &lsp_chan.counterparty.forwarding_info {
                    Some(fwd) => (
                        fwd.fee_base_msat as u64,
                        fwd.fee_proportional_millionths as u64,
                        fwd.cltv_expiry_delta as u32,
                    ),
                    None => {
                        log::warn!("Phase10b: LSP channel missing counterparty.forwarding_info;                                     using fallback (0 base, 0 ppm, 40 cltv). If LSP actually                                     charges, LND will reject downstream with fee_insufficient.");
                        (0u64, 0u64, 40u32)
                    }
                    }
                };
                (scid, base, ppm, cltv)
            };

            let path = route.paths.get_mut(0)
                .ok_or_else(|| LijError::Payment("Parsed route has no path[0]".into()))?;
            let amount_forwarded_msat: u64 = path.hops.iter()
                .map(|h| h.fee_msat)
                .sum();
            let lsp_fee_msat = base_msat
                + (amount_forwarded_msat.saturating_mul(ppm)) / 1_000_000;

            log::info!("Phase10b: LSP self-hop: pubkey={}… scid={} fwd_msat={} fee_msat={} (base={} ppm={}) cltv_delta={}",
                &lsp_pubkey_hex[..16.min(lsp_pubkey_hex.len())],
                lsp_scid, amount_forwarded_msat, lsp_fee_msat, base_msat, ppm, cltv_delta);

            path.hops.insert(0, RouteHop {
                pubkey: lsp_pubkey,
                node_features: NodeFeatures::empty(),
                short_channel_id: lsp_scid,
                channel_features: ChannelFeatures::empty(),
                fee_msat: lsp_fee_msat,
                cltv_expiry_delta: cltv_delta,
                maybe_announced_channel: false,
            });

            log::info!("Phase10b: route after LSP prepend: {} hop(s), total_payment_msat = {}",
                path.hops.len(),
                path.hops.iter().map(|h| h.fee_msat).sum::<u64>()
            );
        }

        // Clone recipient_onion since send_payment_with_route consumes it and
        // we want to keep prep usable for the retry caller's record-keeping.
        match cm.send_payment_with_route(
            &route,
            prep.payment_hash,
            prep.recipient_onion.clone(),
            prep.payment_id,
        ) {
            Ok(_) => {
                log::info!("Phase10b: payment initiated (hash={:?} amount_msat={})",
                    prep.payment_hash, prep.amount_msat);
                self.pump_outbound();   // v227: the HTLC leaves now, not on the next tick
                Ok(PaymentResult { success: true, preimage: None, fee_sats: None, error: None })
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                log::warn!("Phase10b: payment failed (synchronous): {}", msg);
                Ok(PaymentResult { success: false, preimage: None, fee_sats: None, error: Some(msg) })
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MPP (v158): multipath send across the wallet's multiple channels to the
    // LSP. Engaged ONLY when the amount exceeds the largest single channel; the
    // single-path apply path above is untouched. Orchestration (lib.rs) calls:
    //   1. mpp_decision(bolt11)                  → Single | Multi(parts) | …
    //   2. prepare_lsp_route_request(.., Some(part_sats)) per shard → body+url
    //   3. (HTTP fetch per shard, lock released)
    //   4. send_mpp_from_responses(responses,bolt11) → assemble + send ONCE
    // One payment_hash / payment_secret / payment_id across all shards, so the
    // recipient sees ONE payment and reassembles it via MPP.
    // ─────────────────────────────────────────────────────────────────────────

    /// Decide single-path vs multipath for `bolt11`, from the invoice amount and
    /// the wallet's usable channels to the active LSP. Single-path when the amount
    /// fits the largest channel's full outbound (pre-MPP behaviour preserved);
    /// otherwise split, where a 2% per-channel headroom (in mpp_plan) reserves
    /// room for the LSP first-hop fee + downstream routing fees.
    #[cfg(target_arch = "wasm32")]
    pub fn mpp_decision(&self, bolt11: &str, user_amount_sat: Option<u64>) -> LijResult<MppDecision> {
        use bitcoin::secp256k1::PublicKey;
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let invoice = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| LijError::Payment(format!("Invalid invoice: {:?}", e)))?;
        // B1 (S25): an open (zero-amount) invoice takes the user's typed
        // amount. The invoice amount always wins when present (v263
        // doctrine: a BOLT11 amount is not a suggestion).
        let amount_msat = invoice.amount_milli_satoshis()
            .or(user_amount_sat.map(|s| s.saturating_mul(1000)))
            .ok_or_else(|| LijError::Payment("Invoice has no amount \u{2014} enter one to pay this open invoice".into()))?;
        // v187 (S27, DP-approved): the S25 B1 containment is RETIRED. The
        // shard machinery's only invoice-amount dependency was the identity
        // extraction in send_mpp_from_responses (now gated there); every
        // other stage already runs on the resolved amount above — shard
        // sizes ride the LSP route responses, the delivered total is summed
        // from the paths. Amountless invoices now flow through the SAME
        // threshold / basic_mpp / plan checks below as amount-ful ones.

        let lsp_pubkey_hex = self.active_lsp.as_ref()
            .map(|a| a.info.pubkey.clone())
            .ok_or_else(|| LijError::Payment("No active LSP".into()))?;
        let lsp_pubkey = PublicKey::from_slice(&hex::decode(&lsp_pubkey_hex)
            .map_err(|e| LijError::Payment(format!("LSP pubkey hex: {:?}", e)))?)
            .map_err(|e| LijError::Payment(format!("LSP PublicKey: {:?}", e)))?;

        // v159: bound by the per-HTLC ceiling, not just balance. A single-path
        // send or an MPP shard is ONE HTLC, and LDK enforces
        // next_outbound_htlc_limit_msat (commitment-fee buffer + in-flight
        // headroom) strictly below outbound_capacity_msat.
        let outbounds: Vec<u64> = cm.list_channels().iter()
            .filter(|c| c.counterparty.node_id == lsp_pubkey)
            .filter(|c| c.is_usable)
            .map(|c| c.outbound_capacity_msat.min(c.next_outbound_htlc_limit_msat))
            .collect();
        let largest = outbounds.iter().copied().max().unwrap_or(0);

        // Single-path threshold = the largest channel's PER-HTLC ceiling (v159,
        // amends the original full-outbound threshold with DP approval): the band
        // between the HTLC ceiling and raw outbound could never succeed
        // single-path (LDK rejects the HTLC at submission), so diverting only
        // that band into MPP strictly adds successes. Sends that previously
        // worked single-path still go Single. Fee headroom still lives only in
        // the split math (mpp_plan).
        if amount_msat <= largest {
            return Ok(MppDecision::Single);
        }

        // Split needed. The recipient must support MPP (basic_mpp feature bit in
        // the BOLT11 invoice) — otherwise we cannot legally split the payment.
        let supports_mpp = invoice.features()
            .map(|f| f.supports_basic_mpp())
            .unwrap_or(false);
        if !supports_mpp {
            log::warn!("MPP needed ({} msat > largest {} msat) but invoice lacks basic_mpp",
                amount_msat, largest);
            return Ok(MppDecision::NoMppSupport);
        }

        match self.mpp_plan(amount_msat) {
            Ok(parts) => Ok(MppDecision::Multi(parts)),
            Err(e) => {
                if format!("{}", e).contains("exceeds_total") {
                    // v216 (O6 exact-fee): same law as max_sendable_sats —
                    // fee-adjusted deliverable minus the race margin, so the
                    // number in this message always equals the field line.
                    let sendable: u64 = outbounds.iter()
                        .map(|o| fee_adjusted_deliverable_msat(*o)).sum::<u64>()
                        .saturating_sub(FEE_MARGIN_SATS.load(std::sync::atomic::Ordering::Relaxed) * 1000);
                    Ok(MppDecision::ExceedsTotal { sendable_msat: sendable })
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Greedy largest-outbound-first split of `total_amount_msat` across usable
    /// LSP channels, per-channel EXACT-FEE deliverable (v216). Errors
    /// ("exceeds_total") if the amount exceeds the fee-adjusted aggregate.
    #[cfg(target_arch = "wasm32")]
    /// v173 (capacity harmonization) → v216 (S36, O6 exact-fee, DP GREEN):
    /// the planner's OWN answer to "how much can I send right now" — per LSP
    /// channel fee_adjusted_deliverable_msat(min(outbound, per-HTLC ceiling))
    /// (the exact base+ppm law, replacing the 2% blanket that idled ~20K sats
    /// per 1M), floored to whole sats, zero-channels excluded, summed, MINUS
    /// the user's fee-race margin (FEE_MARGIN_SATS, Controls dial) once at
    /// the aggregate. Every display/gate surface quotes THIS number;
    /// mpp_plan enforces the identical per-channel math below (change them
    /// together — and change fee_adjusted_deliverable_msat with BOTH).
    pub fn max_sendable_sats(&self) -> u64 {
        let cm = match self.channel_manager.as_ref() {
            Some(c) => c,
            None => return 0,
        };
        let lsp_hex = match self.active_lsp.as_ref() {
            Some(a) => a.info.pubkey.clone(),
            None => return 0,
        };
        let lsp_pk = match hex::decode(&lsp_hex)
            .ok()
            .and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok())
        {
            Some(p) => p,
            None => return 0,
        };
        let sum: u64 = cm.list_channels()
            .iter()
            .filter(|c| c.counterparty.node_id == lsp_pk)
            .filter(|c| c.is_usable)
            .map(|c| {
                let cap = c.outbound_capacity_msat.min(c.next_outbound_htlc_limit_msat);
                fee_adjusted_deliverable_msat(cap) / 1000
            })
            .sum();
        sum.saturating_sub(FEE_MARGIN_SATS.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn mpp_plan(&self, total_amount_msat: u64) -> LijResult<Vec<MppPart>> {
        use bitcoin::secp256k1::PublicKey;
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let lsp_pubkey_hex = self.active_lsp.as_ref()
            .map(|a| a.info.pubkey.clone())
            .ok_or_else(|| LijError::Payment("No active LSP — cannot plan MPP".into()))?;
        let lsp_pubkey = PublicKey::from_slice(&hex::decode(&lsp_pubkey_hex)
            .map_err(|e| LijError::Payment(format!("LSP pubkey hex: {:?}", e)))?)
            .map_err(|e| LijError::Payment(format!("LSP PublicKey: {:?}", e)))?;

        // (scid, fee-buffered usable outbound SATS), largest first.
        // v161: plan in WHOLE SATS. Shard route requests are sat-denominated,
        // so msat-granular parts got floored at request time and the delivered
        // total undershot the invoice (e.g. 8,443+2,559=11,002 delivered vs
        // 11,003 invoiced) — the recipient rejects the whole set
        // (RecipientRejected). Sat-aligned parts make the sum exact.
        let mut chans: Vec<(u64, u64)> = cm.list_channels().iter()
            .filter(|c| c.counterparty.node_id == lsp_pubkey)
            .filter(|c| c.is_usable)
            .filter_map(|c| {
                let scid = c.short_channel_id.or(c.outbound_scid_alias)?;
                // v159: a shard is one HTLC — cap at the per-HTLC ceiling too.
                // v216 (O6 exact-fee): per-shard deliverable via the one law —
                // each shard is a forwarded HTLC paying base+ppm on itself, so
                // the exact per-channel room is fee_adjusted_deliverable_msat.
                let cap = c.outbound_capacity_msat.min(c.next_outbound_htlc_limit_msat);
                let usable_sats = fee_adjusted_deliverable_msat(cap) / 1000;
                if usable_sats == 0 { None } else { Some((scid, usable_sats)) }
            })
            .collect();
        chans.sort_by(|a, b| b.1.cmp(&a.1));

        if chans.is_empty() {
            return Err(LijError::Payment("No usable channel to LSP for MPP".into()));
        }
        // Deliver at least the invoice amount: round the total UP to whole
        // sats — overpaying ≤999 msat is spec-legal; undershooting is fatal.
        let total_sats = (total_amount_msat + 999) / 1000;
        // LDK caps MPP at 10 parts; we never produce more than the channel count.
        let total_usable_sats: u64 = chans.iter().map(|(_, o)| *o).sum();
        if total_sats > total_usable_sats {
            return Err(LijError::Payment(format!(
                "exceeds_total: {} sats exceeds sendable {} sats across {} channel(s)",
                total_sats, total_usable_sats, chans.len())));
        }

        let mut parts: Vec<MppPart> = Vec::new();
        let mut remaining = total_sats;
        for (scid, usable_sats) in chans {
            if remaining == 0 { break; }
            let take = remaining.min(usable_sats);
            if take == 0 { continue; }
            parts.push(MppPart { scid, part_msat: take * 1000 });
            remaining = remaining.saturating_sub(take);
        }
        if remaining > 0 {
            return Err(LijError::Payment(format!(
                "MPP split incomplete: {} sats unassigned", remaining)));
        }
        log::info!("MPP plan: {} shard(s) for {} sats total", parts.len(), total_sats);
        Ok(parts)
    }

    /// Parse one shard's LSP route response and prepend the wallet→LSP self-hop
    /// over the SPECIFIC channel `part_scid` (vs apply's largest-channel pick).
    /// Mirrors apply_lsp_route_and_send's prepend logic exactly. Returns one Path.
    #[cfg(target_arch = "wasm32")]
    fn build_mpp_path(
        &self,
        response_text: &str,
        part_scid: u64,
        final_cltv_delta: u32,
    ) -> LijResult<Path> {
        use bitcoin::secp256k1::PublicKey;
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let mut route = parse_lnd_route_response(response_text, final_cltv_delta)?;

        let lsp_first_hop_policy_from_adapter: Option<(u64, u64, u32)> = (|| {
            let parsed: serde_json::Value = serde_json::from_str(response_text).ok()?;
            let policy = parsed.get("lsp_first_hop_policy")?;
            let base: u64 = policy.get("fee_base_msat")?.as_str()?.parse().ok()?;
            let ppm = policy.get("fee_proportional_millionths")?.as_u64()?;
            let cltv = policy.get("cltv_expiry_delta")?.as_u64()? as u32;
            Some((base, ppm, cltv))
        })();
        // v216 (O6 exact-fee): every route-build sighting refreshes the policy
        // cache the quote/estimator/planner all read.
        if let Some((b, p, _)) = lsp_first_hop_policy_from_adapter {
            record_lsp_fee_policy(b, p);
        }

        let lsp_pubkey_hex = self.active_lsp.as_ref()
            .map(|a| a.info.pubkey.clone())
            .ok_or_else(|| LijError::Payment("No active LSP — cannot prepend LSP hop".into()))?;
        let lsp_pubkey = PublicKey::from_slice(&hex::decode(&lsp_pubkey_hex)
            .map_err(|e| LijError::Payment(format!("LSP pubkey hex: {:?}", e)))?)
            .map_err(|e| LijError::Payment(format!("LSP PublicKey: {:?}", e)))?;

        // Resolve the SPECIFIC channel for this shard by its scid.
        let channels = cm.list_channels();
        let lsp_chan = channels.iter()
            .filter(|c| c.counterparty.node_id == lsp_pubkey && c.is_usable)
            .find(|c| c.short_channel_id == Some(part_scid)
                   || c.outbound_scid_alias == Some(part_scid))
            .ok_or_else(|| LijError::Payment(format!(
                "MPP shard channel scid={} not found/usable", part_scid)))?;

        let (base_msat, ppm, cltv_delta) = if let Some((b, p, c)) = lsp_first_hop_policy_from_adapter {
            (b, p, c)
        } else {
            match &lsp_chan.counterparty.forwarding_info {
                Some(fwd) => (
                    fwd.fee_base_msat as u64,
                    fwd.fee_proportional_millionths as u64,
                    fwd.cltv_expiry_delta as u32,
                ),
                None => (0u64, 0u64, 40u32),
            }
        };

        let path = route.paths.get_mut(0)
            .ok_or_else(|| LijError::Payment("MPP shard route has no path[0]".into()))?;
        let amount_forwarded_msat: u64 = path.hops.iter().map(|h| h.fee_msat).sum();
        let lsp_fee_msat = base_msat + (amount_forwarded_msat.saturating_mul(ppm)) / 1_000_000;

        log::info!("MPP shard: scid={} fwd_msat={} lsp_fee_msat={} (base={} ppm={}) cltv_delta={}",
            part_scid, amount_forwarded_msat, lsp_fee_msat, base_msat, ppm, cltv_delta);

        path.hops.insert(0, RouteHop {
            pubkey: lsp_pubkey,
            node_features: NodeFeatures::empty(),
            short_channel_id: part_scid,
            channel_features: ChannelFeatures::empty(),
            fee_msat: lsp_fee_msat,
            cltv_expiry_delta: cltv_delta,
            maybe_announced_channel: false,
        });

        Ok(route.paths.remove(0))
    }

    /// Assemble shard Paths into one multipath Route and submit ONE
    /// send_payment_with_route. The shared payment_secret (in recipient_onion)
    /// makes this a single MPP payment the recipient reassembles.
    #[cfg(target_arch = "wasm32")]
    fn send_assembled_mpp(
        &self,
        paths: Vec<Path>,
        payment_hash: lightning::ln::PaymentHash,
        recipient_onion: lightning::ln::channelmanager::RecipientOnionFields,
        payment_id: lightning::ln::channelmanager::PaymentId,
    ) -> LijResult<PaymentResult> {
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        if paths.is_empty() {
            return Err(LijError::Payment("MPP: no shard paths to send".into()));
        }
        let total_msat: u64 = paths.iter()
            .map(|p| p.hops.last().map(|h| h.fee_msat).unwrap_or(0))
            .sum();
        let route = Route { paths, route_params: None };
        log::info!("MPP send: {} shard(s), ~{} msat delivered total",
            route.paths.len(), total_msat);

        match cm.send_payment_with_route(&route, payment_hash, recipient_onion, payment_id) {
            Ok(_) => {
                log::info!("MPP: multipath payment initiated (hash={:?})", payment_hash);
                self.pump_outbound();   // v227: every shard leaves now, not on the next tick
                Ok(PaymentResult { success: true, preimage: None, fee_sats: None, error: None })
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                log::warn!("MPP: send failed (synchronous): {}", msg);
                // v159: clear stale outbound-payment state. Safe even with a
                // partially-sent shard (PartialFailure): LDK marks the payment
                // abandoned and fires the failure event once any in-flight
                // HTLCs resolve back.
                cm.abandon_payment(payment_id);
                Ok(PaymentResult { success: false, preimage: None, fee_sats: None, error: Some(msg) })
            }
        }
    }

    /// Orchestration entry point called by lib.rs once all shard route responses
    /// are collected. Derives ONE payment identity from the invoice (hash +
    /// secret + a fresh payment_id), builds a Path per (response, scid), and
    /// sends the assembled multipath Route once.
    #[cfg(target_arch = "wasm32")]
    pub fn send_mpp_from_responses(
        &self,
        responses: Vec<(String, u64)>,
        bolt11: &str,
    ) -> LijResult<(PaymentResult, lightning::ln::channelmanager::PaymentId)> {
        let invoice = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| LijError::Payment(format!("Invalid invoice: {:?}", e)))?;
        // v187 (S27, DP-approved): payment_parameters_from_invoice ERRORS on
        // amountless invoices, and the identity pair (hash + secret-only
        // onion) is all this call provided here — route_params was already
        // discarded. Amount-ful invoices take the ORIGINAL call, byte-
        // identical (prime directive: working MPP is untouchable);
        // amountless constructs the same pair directly. Shard amounts and
        // the delivered total never touched the invoice in this chain.
        let (payment_hash, recipient_onion) = if invoice.amount_milli_satoshis().is_some() {
            let (h, o, _route_params) =
                lightning_invoice::payment::payment_parameters_from_invoice(&invoice)
                .map_err(|e| LijError::Payment(format!("Invoice params error: {:?}", e)))?;
            (h, o)
        } else {
            use bitcoin::hashes::Hash as _;
            (
                lightning::ln::PaymentHash(invoice.payment_hash().to_byte_array()),
                lightning::ln::channelmanager::RecipientOnionFields::secret_only(
                    *invoice.payment_secret(),
                ),
            )
        };
        use lightning::sign::EntropySource;
        let payment_id = lightning::ln::channelmanager::PaymentId(
            self.keys_manager.get_secure_random_bytes());
        let final_cltv_delta = invoice.min_final_cltv_expiry_delta() as u32;

        let mut paths: Vec<Path> = Vec::with_capacity(responses.len());
        for (resp, scid) in &responses {
            let path = self.build_mpp_path(resp, *scid, final_cltv_delta)?;
            paths.push(path);
        }
        log::info!("MPP: assembled {} shard path(s); submitting as one payment", paths.len());
        // v160: hand the payment_id back so lib.rs can poll settlement —
        // submission alone is NOT success (review 1.1).
        self.send_assembled_mpp(paths, payment_hash, recipient_onion, payment_id)
            .map(|r| (r, payment_id))
    }


    // ── Channels ──────────────────────────────────────────────────────────────

    pub fn get_channels(&self) -> LijResult<Vec<ChannelInfo>> {
        Ok(self.channel_manager.as_ref().map(|cm| {
            cm.list_channels().iter().map(|c| ChannelInfo {
                channel_id: hex::encode(c.channel_id.0),
                counterparty_pubkey: hex::encode(c.counterparty.node_id.serialize()),
                balance_sats: c.outbound_capacity_msat / 1000,
                spendable_sats: c.outbound_capacity_msat.min(c.next_outbound_htlc_limit_msat) / 1000,
                spendable_msat: c.outbound_capacity_msat.min(c.next_outbound_htlc_limit_msat),
                inbound_capacity_sats: c.inbound_capacity_msat / 1000,
                is_usable: c.is_usable,
                is_public: c.is_public,
                // v178 (close-awareness): unconfirmed funding-spend sighting
                // from the walker — "a close is in the mempool". Display-only.
                closing_seen_mempool: c
                    .funding_txo
                    .and_then(|o| {
                        self.funding_spend_sightings
                            .lock()
                            .ok()
                            .map(|m| m.contains_key(&format!("{}:{}", o.txid, o.index)))
                    })
                    .unwrap_or(false),
                closing_txid: c.funding_txo.and_then(|o| {
                    self.funding_spend_sightings
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&format!("{}:{}", o.txid, o.index)).cloned())
                }),
                terminus_pinned: (c.user_channel_id & crate::signer::UCID_TERMINUS_PIN_BIT) != 0,
                funding_txid: c.funding_txo.map(|o| o.txid.to_string()),
                confirmations: c.confirmations,
                is_channel_ready: c.is_channel_ready,
                // Holder-side reserve (sats). LDK reports this already excluded
                // from outbound_capacity_msat, so it's purely informational.
                our_reserve_sats: c.unspendable_punishment_reserve,
                // v212: full our-side balance incl. reserve — the ledger's
                // "built up so far" reads min(gross, reserve).
                our_balance_gross_sats: c.balance_msat / 1000,
                their_reserve_sats: c.counterparty.unspendable_punishment_reserve,
                inbound_unlock_after_sats: {
                    // remote_total = capacity − our full balance (balance_msat
                    // already includes our reserve). The deficit vs THEIR
                    // reserve is what our sends must fill before inbound can
                    // exceed zero (verified to the msat, session 19).
                    let remote_msat = (c.channel_value_satoshis * 1000)
                        .saturating_sub(c.balance_msat);
                    let deficit_msat = (c.counterparty.unspendable_punishment_reserve * 1000)
                        .saturating_sub(remote_msat);
                    if c.inbound_capacity_msat == 0 && deficit_msat > 0 {
                        Some((deficit_msat + 999) / 1000)
                    } else { None }
                },
                // R3 (v174): authoritative shutdown discriminator. None (field
                // absent) is treated as not-shutting-down.
                is_shutting_down: !matches!(
                    c.channel_shutdown_state,
                    None | Some(lightning::ln::channelmanager::ChannelShutdownState::NotShuttingDown)
                ),
            }).collect()
        }).unwrap_or_default())
    }

    /// Step 3.6 diagnostic: dump full LDK ChannelDetails as JSON.
    /// The slim ChannelInfo struct only surfaces a handful of fields;
    /// this exposes the rest (inbound_scid_alias, short_channel_id,
    /// counterparty.forwarding_info, htlc_min/max, etc.) for use when
    /// LDK does something unexpected with channels.
    pub fn dump_channel_details_json(&self) -> LijResult<String> {
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;

        let details: Vec<serde_json::Value> = cm.list_channels().iter().map(|c| {
            serde_json::json!({
                "channel_id":               hex::encode(c.channel_id.0),
                // Terminus v2 (Session 23): negotiated commitment posture +
                // pin state, so channel types are verifiable from the wallet
                // itself (no lncli needed). channel_type is None until
                // negotiation completes.
                "channel_type": c.channel_type.as_ref().map(|t| serde_json::json!({
                    "anchors":            t.supports_anchors_zero_fee_htlc_tx(),
                    "static_remote_key":  t.supports_static_remote_key(),
                    "zero_conf":          t.supports_zero_conf(),
                    "scid_privacy":       t.supports_scid_privacy(),
                })),
                "terminus_pinned": (c.user_channel_id & crate::signer::UCID_TERMINUS_PIN_BIT) != 0,
                "is_shutting_down":         !matches!(c.channel_shutdown_state, None | Some(lightning::ln::channelmanager::ChannelShutdownState::NotShuttingDown)),
                "counterparty_pubkey":      hex::encode(c.counterparty.node_id.serialize()),
                "short_channel_id":         c.short_channel_id,
                "outbound_scid_alias":      c.outbound_scid_alias,
                "inbound_scid_alias":       c.inbound_scid_alias,
                "is_usable":                c.is_usable,
                "is_public":                c.is_public,
                "channel_value_satoshis":   c.channel_value_satoshis,
                "outbound_capacity_msat":   c.outbound_capacity_msat,
                "next_outbound_htlc_limit_msat":   c.next_outbound_htlc_limit_msat,
                "next_outbound_htlc_minimum_msat": c.next_outbound_htlc_minimum_msat,
                "inbound_capacity_msat":    c.inbound_capacity_msat,
                // v162: reserve + balance visibility — inbound_capacity is
                // remote_balance minus THEIR reserve minus (when they funded,
                // e.g. LSPS1) the funder's commit-fee/anchor obligation. These
                // make the zero-inbound arithmetic exact instead of inferred.
                "balance_msat":             c.balance_msat,
                "our_reserve_sats":         c.unspendable_punishment_reserve,
                "their_reserve_sats":       c.counterparty.unspendable_punishment_reserve,
                "inbound_htlc_minimum_msat": c.inbound_htlc_minimum_msat,
                "inbound_htlc_maximum_msat": c.inbound_htlc_maximum_msat,
                "counterparty_forwarding_info": c.counterparty.forwarding_info.as_ref().map(|f| {
                    serde_json::json!({
                        "fee_base_msat":             f.fee_base_msat,
                        "fee_proportional_millionths": f.fee_proportional_millionths,
                        "cltv_expiry_delta":         f.cltv_expiry_delta,
                    })
                }),
            })
        }).collect();

        serde_json::to_string_pretty(&details)
            .map_err(|e| LijError::Node(format!("serialize: {:?}", e)))
    }

    /// Read-only access to outstanding close attempts. Used by the
    /// background_tick event handler (8c.2) and the Channel Management
    /// UI (8d) to surface negotiation status.
    pub fn outstanding_close_attempts(
        &self,
    ) -> Arc<Mutex<std::collections::HashMap<ChannelId, CloseAttemptRecord>>> {
        self.outstanding_close_attempts.clone()
    }

    /// v8: Access to per-payment outcomes recorded by the LDK event handler.
    /// Used by send_payment_with_retries to poll for PaymentSent / PaymentPathFailed
    /// / PaymentFailed events after submitting an HTLC, and to extract the failed
    /// channel pair for retry exclusion. Keyed by PaymentId.
    pub fn payment_outcomes_handle(
        &self,
    ) -> Arc<Mutex<std::collections::HashMap<lightning::ln::channelmanager::PaymentId, PaymentOutcome>>> {
        self.payment_outcomes.clone()
    }

    /// v8: Abandon an outbound payment in LDK's OutboundPayments state.
    /// Used by send_payment_with_retries to clean up a payment_id after a
    /// PathFailed outcome before starting the next attempt — prevents the
    /// stale Retryable state from accumulating and lets us recycle the
    /// payment slot. Abandoning fires PaymentFailed for the id (which our
    /// event handler records, then the retry caller drains).
    pub fn abandon_payment(&self, payment_id: lightning::ln::channelmanager::PaymentId) -> LijResult<()> {
        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        cm.abandon_payment(payment_id);
        Ok(())
    }

    /// v215 (S36, 6a sender concurrent-retry redesign): the pre-dispatch
    /// in-flight probe. Returns Some(payment_id_hex) if LDK still tracks a
    /// PENDING outbound payment whose payment_hash matches this bolt11 —
    /// i.e. an HTLC for this invoice is (or may still be) in flight and a
    /// new dispatch would create a same-hash duplicate (the S35 stacking
    /// class: one revealed preimage claims EVERY sibling). Cross-PaymentId
    /// and persisted in ChannelManager, so it survives page reloads.
    /// Decode failures return None — the send path surfaces those itself.
    pub fn pending_payment_for_bolt11(&self, bolt11: &str) -> Option<String> {
        use lightning::ln::channelmanager::RecentPaymentDetails as RPD;
        let cm = self.channel_manager.as_ref()?;
        let invoice = bolt11.trim().parse::<lightning_invoice::Bolt11Invoice>().ok()?;
        let want: [u8; 32] = invoice.payment_hash().to_byte_array();
        for p in cm.list_recent_payments() {
            if let RPD::Pending { payment_id, payment_hash, .. } = p {
                if payment_hash.0 == want {
                    return Some(hex::encode(payment_id.0));
                }
            }
        }
        None
    }

    /// v189 (S29): abandon a stuck outbound by its PaymentId hex (32 bytes,
    /// exactly as reported by recent_payments_json). Root fix for the
    /// 'Tokyo −2,003' family: send_payment_with_retries never abandons on
    /// terminal validation failure, so such intents sit LDK-'pending'
    /// forever. Safe by LDK semantics — abandon never cancels in-flight
    /// HTLCs; it only stops retries and lets the terminal failure surface.
    pub fn abandon_payment_by_id_hex(&self, payment_id_hex: &str) -> LijResult<()> {
        let bytes = hex::decode(payment_id_hex.trim())
            .map_err(|_| LijError::Node("bad payment_id hex".into()))?;
        let arr: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| LijError::Node("payment_id must be 32 bytes".into()))?;
        self.abandon_payment(lightning::ln::channelmanager::PaymentId(arr))
    }

    /// Initiate a cooperative close on a single channel.
    ///
    /// Synchronously sends `shutdown` to the peer and returns Ok if the
    /// initiation succeeded. The actual close transaction broadcast and
    /// Event::ChannelClosed arrive asynchronously — caller must monitor
    /// outstanding_close_attempts() and the ChannelClosed event handler.
    ///
    /// Uses the upfront shutdown_script that was committed at channel
    /// open time (BIP84 path m/84'/0'/0'/0/n). The destination is locked
    /// in the channel's permanent state — neither party can redirect.
    /// v165 (#29-4a): fee-rate tiers for the UI speed picker, from the live
    /// estimator (cooperative-first). Tiering mirrors
    /// FeeQuote::from_fast_sat_per_vb's philosophy: normal = fast/2,
    /// slow = fast/4, all floored at 1 sat/vB.
    pub fn fee_rates_json(&self) -> String {
        let (fast_kw, source, escalation) = self.fee_estimator.picker_summary();
        let fast_vb = ((fast_kw as f64) / 250.0).max(1.0);
        let normal_vb = (fast_vb / 2.0).max(1.0);
        let slow_vb = (fast_vb / 4.0).max(1.0);
        format!(
            "{{\"fast_vb\":{:.2},\"normal_vb\":{:.2},\"slow_vb\":{:.2},\"source\":\"{}\",\"escalation\":{}}}",
            fast_vb, normal_vb, slow_vb, source, escalation
        )
    }

    pub fn close_channel(&self, channel_id_hex: &str) -> LijResult<()> {
        let channel_id = parse_channel_id_hex(channel_id_hex)?;
        let cm = self.channel_manager.as_ref().ok_or_else(|| {
            LijError::Node("close_channel: channel_manager not initialized".into())
        })?;

        // Resolve counterparty pubkey from the channel list.
        let counterparty = cm
            .list_channels()
            .into_iter()
            .find(|c| c.channel_id == channel_id)
            .map(|c| c.counterparty.node_id)
            .ok_or_else(|| {
                LijError::Node(format!(
                    "close_channel: channel {} not found",
                    channel_id_hex
                ))
            })?;

        // Record the attempt BEFORE calling LDK so that if Event::ChannelClosed
        // fires before this method returns (extremely unlikely but possible
        // in test harnesses), the handler sees the attempt record.
        let counterparty_hex = hex::encode(counterparty.serialize());
        {
            let mut attempts = self
                .outstanding_close_attempts
                .lock()
                .map_err(|e| LijError::Node(format!("Mutex poisoned: {e}")))?;
            attempts.insert(
                channel_id,
                CloseAttemptRecord {
                    kind: CloseAttemptKind::Cooperative,
                    started_at_unix_secs: current_time_secs(),
                    counterparty_pubkey_hex: counterparty_hex.clone(),
                },
            );
        }

        log::info!(
            "Initiating cooperative close: channel={} counterparty={}",
            channel_id_hex, counterparty_hex
        );
        close_event_record(format!(
            "{{\"ts\":{},\"event\":\"invoke_coop_close\",\"channel\":\"{}\"}}",
            current_time_secs(), channel_id_hex
        ));
        cm.close_channel(&channel_id, &counterparty)
            .map_err(|e| LijError::Node(format!("close_channel: LDK error {:?}", e)))?;
        Ok(())
    }

    /// Initiate a unilateral force close on a single channel.
    ///
    /// Broadcasts the latest holder commitment transaction. The to_remote
    /// output is encumbered by static_remotekey at m/525'/0/0/0/n
    /// (recoverable in BlueWallet via custom-path import). The to_local
    /// output is timelocked by to_self_delay (typically 144 blocks ≈ 24
    /// hours) before being spendable.
    ///
    /// This is destructive — there is no way to recall it. UI must
    /// confirm with the user before calling.
    pub fn force_close(&self, channel_id_hex: &str) -> LijResult<()> {
        let channel_id = parse_channel_id_hex(channel_id_hex)?;
        let cm = self.channel_manager.as_ref().ok_or_else(|| {
            LijError::Node("force_close: channel_manager not initialized".into())
        })?;

        let counterparty = cm
            .list_channels()
            .into_iter()
            .find(|c| c.channel_id == channel_id)
            .map(|c| c.counterparty.node_id)
            .ok_or_else(|| {
                LijError::Node(format!(
                    "force_close: channel {} not found",
                    channel_id_hex
                ))
            })?;

        let counterparty_hex = hex::encode(counterparty.serialize());
        {
            let mut attempts = self
                .outstanding_close_attempts
                .lock()
                .map_err(|e| LijError::Node(format!("Mutex poisoned: {e}")))?;
            attempts.insert(
                channel_id,
                CloseAttemptRecord {
                    kind: CloseAttemptKind::Force,
                    started_at_unix_secs: current_time_secs(),
                    counterparty_pubkey_hex: counterparty_hex.clone(),
                },
            );
        }

        log::info!(
            "Initiating force close: channel={} counterparty={}",
            channel_id_hex, counterparty_hex
        );
        close_event_record(format!(
            "{{\"ts\":{},\"event\":\"invoke_force_close\",\"channel\":\"{}\"}}",
            current_time_secs(), channel_id_hex
        ));
        cm.force_close_broadcasting_latest_txn(&channel_id, &counterparty)
            .map_err(|e| LijError::Node(format!("force_close: LDK error {:?}", e)))?;
        Ok(())
    }

    /// Force-close a SINGLE channel WITHOUT broadcasting any transaction.
    /// For a channel whose funding never confirmed (e.g. a stranded open that
    /// LDK keeps disconnecting the peer over via its no-progress watchdog),
    /// this drops it from LDK's active set so the watchdog stops firing,
    /// releases the reserved funding inputs back to spendable, and — critically
    /// — broadcasts NOTHING, so there is no path by which the unconfirmed
    /// funding tx could be pushed on-chain. Targeted counterpart to
    /// force_close_all_without_broadcasting (which would also drop good
    /// channels and orphan them).
    /// S30 (v199): drain-free read of the chain flight recorder.
    pub fn chain_events_json(&self, limit: usize) -> LijResult<String> {
        let coord = self.chain_coordinator.lock().map_err(|_| {
            LijError::Node("chain_events_json: coordinator lock poisoned".into())
        })?;
        Ok(coord.events_snapshot_json(limit))
    }

    pub fn force_close_without_broadcasting(&self, channel_id_hex: &str) -> LijResult<()> {
        let channel_id = parse_channel_id_hex(channel_id_hex)?;
        let cm = self.channel_manager.as_ref().ok_or_else(|| {
            LijError::Node(
                "force_close_without_broadcasting: channel_manager not initialized".into(),
            )
        })?;

        let counterparty = cm
            .list_channels()
            .into_iter()
            .find(|c| c.channel_id == channel_id)
            .map(|c| c.counterparty.node_id)
            .ok_or_else(|| {
                LijError::Node(format!(
                    "force_close_without_broadcasting: channel {} not found",
                    channel_id_hex
                ))
            })?;

        log::info!(
            "Force-close WITHOUT broadcast: channel={} counterparty={}",
            channel_id_hex,
            hex::encode(counterparty.serialize())
        );
        close_event_record(format!(
            "{{\"ts\":{},\"event\":\"invoke_force_close_no_broadcast\",\"channel\":\"{}\"}}",
            current_time_secs(),
            channel_id_hex
        ));
        cm.force_close_without_broadcasting_txn(&channel_id, &counterparty)
            .map_err(|e| {
                LijError::Node(format!(
                    "force_close_without_broadcasting: LDK error {:?}",
                    e
                ))
            })?;
        Ok(())
    }

    /// End the relationship with a specific LSP by cooperatively closing
    /// every channel with that counterparty.
    ///
    /// Channels are closed in parallel (all `cm.close_channel` calls fire
    /// rapidly). Each individual close is recorded in
    /// outstanding_close_attempts so the event handler resolves them as
    /// they complete. If any individual close fails, others continue —
    /// returns a vec of (channel_id_hex, Result) pairs so the UI can
    /// show partial-success state.
    pub fn end_lsp_relationship(
        &self,
        lsp_pubkey_hex: &str,
    ) -> LijResult<Vec<(String, LijResult<()>)>> {
        let cm = self.channel_manager.as_ref().ok_or_else(|| {
            LijError::Node("end_lsp_relationship: channel_manager not initialized".into())
        })?;

        let target_channels: Vec<(ChannelId, String)> = cm
            .list_channels()
            .into_iter()
            .filter(|c| hex::encode(c.counterparty.node_id.serialize()) == lsp_pubkey_hex)
            .map(|c| (c.channel_id, hex::encode(c.channel_id.0)))
            .collect();

        if target_channels.is_empty() {
            log::info!(
                "end_lsp_relationship: no channels with {}",
                lsp_pubkey_hex
            );
            return Ok(Vec::new());
        }

        log::info!(
            "Ending LSP relationship: {} channels with {}",
            target_channels.len(),
            lsp_pubkey_hex
        );

        let mut results = Vec::with_capacity(target_channels.len());
        for (_channel_id, channel_id_hex) in target_channels {
            let r = self.close_channel(&channel_id_hex);
            results.push((channel_id_hex, r));
        }
        Ok(results)
    }

    /// Manually mark a funding transaction as confirmed at a given height.
    /// Bypasses normal chain sync — pre-Neutrino dev tool to unblock the
    /// ChannelReady event when no chain backend is wired up.
    ///
    /// Synthesizes a single-tx pseudo-block whose merkle root is the funding
    /// txid, notifies both ChainMonitor and ChannelManager via the Confirm
    /// trait, then advances the chain tip past the configured minimum_depth
    /// so the channel can transition to ready.
    pub fn mark_funding_confirmed(
        &self,
        funding_tx_hex: &str,
        confirmed_at_height: u32,
    ) -> LijResult<()> {
        let tx_bytes = hex::decode(funding_tx_hex.trim())
            .map_err(|e| LijError::InvalidArgument(format!("Bad tx hex: {e}")))?;
        let tx: bitcoin::Transaction = consensus_deserialize(&tx_bytes)
            .map_err(|e| LijError::InvalidArgument(format!("Bad tx bytes: {e}")))?;
        let txid = tx.txid();
        log::info!(
            "mark_funding_confirmed: txid={} at height={}",
            txid, confirmed_at_height
        );

        let cm = self.channel_manager.as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let chain_monitor = self.chain_monitor.as_ref()
            .ok_or_else(|| LijError::Node("ChainMonitor not initialized".into()))?;

        let merkle_root = TxMerkleNode::from_byte_array(txid.to_byte_array());
        let conf_header = Header {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        // Phase 3.7.B — route through ChainCoordinator (dev tool path).
        // tx_index defaults to 0 here (this is a manual dev tool, not from
        // the cooperative bridge which carries real tx_index data).
        let conf_action = {
            let mut coord = self.chain_coordinator.lock()
                .map_err(|e| LijError::Node(format!("Coordinator lock poisoned: {e}")))?;
            coord.ingest_bridge_conf(crate::chain_coordinator::BridgeConfirmation {
                txid,
                height: confirmed_at_height,
                block_hash: conf_header.block_hash(),
                tx_index: 0,
                raw_tx: bitcoin::consensus::serialize(&tx),
                block_header: conf_header,
                confirmations: 1,
            })
        };
        conf_action.apply(&**chain_monitor, &**cm, self.output_sweeper_as_confirm());

        // Step C.4: synthetic-tip emission removed. With minimum_depth=1
        // from Step C.2, ChannelReady fires on the next background_tick
        // cooperative-tip ingestion (Phase 3.9.A) after the
        // transactions_confirmed call above lands -- no synthetic jump
        // to confirmed_at_height + 6 needed.

        cm.process_pending_events(&|event| {
            log::info!("[Event after mark_funding_confirmed] {:?}", event);
        });
        self.persist_channel_manager()?;
        Ok(())
    }

    pub fn get_sync_state(&self) -> SyncState {
        self.sync_state.current()
    }

    /// Set sync state directly. Used by step 6d's cold-start orchestrator and
    /// by tests. Production state changes go through that orchestrator.
    pub(crate) fn set_sync_state(&self, state: SyncState) {
        self.sync_state.set(state);
    }

    /// Whether the cooperative chain-data path is subscribed to an LSP and
    /// has received its initial ChainDataBundle.
    pub fn cooperative_subscribed(&self) -> bool {
        self.cooperative_bridge.cooperative_subscribed()
    }

    /// Last cooperative-cached block height. None until first ChainDataBundle.
    pub fn cooperative_block_height(&self) -> Option<u32> {
        self.cooperative_bridge.cooperative_block_height()
    }

    /// Step 3.6 (F7): Unix epoch seconds of the last cooperative chain
    /// message received. None until the first ChainDataBundle arrives.
    pub fn cooperative_last_update_ts(&self) -> Option<u64> {
        self.cooperative_bridge.cooperative_last_update_ts()
    }

    /// v210: passthrough for the runtime quorum endpoint set.
    pub fn set_independent_endpoints(&self, urls: Vec<String>) {
        self.independent.set_endpoints(urls);
    }

    /// v223 (S39, 0.57.0 item h): whether a payment destination is the
    /// active LSP itself — the held-claim internal-payment shape. Read-only;
    /// stamped onto the send progress events so the page's silence copy can
    /// say "held by your LSP" instead of implying a network search.
    pub fn dest_is_active_lsp(&self, dest_pubkey_hex: &str) -> bool {
        self.active_lsp.as_ref()
            .map(|a| a.info.pubkey.eq_ignore_ascii_case(dest_pubkey_hex))
            .unwrap_or(false)
    }

    /// v211 — ESCAPE KIT export (read-only). For every retained channel
    /// monitor: the fully signed latest holder commitment ("THE CLOSE") and,
    /// when a to_local output exists, a pre-signed sweep of it ("THE
    /// COLLECT") to a PEEKED m/84 allocator destination, at two feerates
    /// (no RBF exists after the fact). The sweep input carries
    /// nSequence = to_self_delay, so it becomes valid on its own once the
    /// commitment has that many confirmations — sign once offline, publish
    /// twice online, no return trip to this device. Zero state change:
    /// nothing broadcast, nothing queued, counter not advanced.
    pub fn escape_export(&self) -> LijResult<String> {
        use bitcoin::consensus::encode::serialize_hex;
        use lightning::sign::{OutputSpender, SpendableOutputDescriptor as SOD};
        let chain_monitor = self
            .chain_monitor
            .as_ref()
            .ok_or_else(|| LijError::Node("escape export: chain monitor not ready".into()))?;
        let (dest_index, dest_script) = self.signer_provider.peek_destination_script()?;
        let dest_address = bitcoin::Address::from_script(dest_script.as_script(), self.network)
            .map_err(|e| LijError::Node(format!("escape export: destination address render: {e}")))?
            .to_string();
        let logger = std::sync::Arc::new(LijLogger);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        // sat per 1000 weight: 10 sat/vB and 40 sat/vB.
        const FEERATE_NORMAL: u32 = 2_500;
        const FEERATE_HIGH: u32 = 10_000;
        // v223 (S39): the kit stops quoting dead commitments as "yours".
        // `open` = the monitor's channel is in the manager's live list;
        // `claimable_sats` = LDK's own answer to what is still claimable
        // here (same walk the Balance card's maturing/close-value lines
        // ride). The page splits CLOSING / OPEN / SETTLED on these.
        let open_txos: std::collections::HashSet<lightning::chain::transaction::OutPoint> = self
            .channel_manager
            .as_ref()
            .map(|cmgr| {
                cmgr.list_channels()
                    .into_iter()
                    .filter_map(|ch| ch.funding_txo)
                    .collect()
            })
            .unwrap_or_default();
        let mut channels = Vec::new();
        for (funding_txo, channel_id) in chain_monitor.list_monitors() {
            let monitor = match chain_monitor.get_monitor(funding_txo) {
                Ok(m) => m,
                Err(()) => continue, // monitor evicted between list and get
            };
            let (txs, to_local, to_self_delay) = monitor.lij_export_escape(&logger);
            let claimable_sats: u64 = monitor
                .get_claimable_balances()
                .iter()
                .map(|b| b.claimable_amount_satoshis())
                .sum();
            let counterparty = monitor
                .get_counterparty_node_id()
                .map(|pk| pk.to_string());
            let commitment_txid = txs
                .get(0)
                .map(|tx| tx.txid().to_string())
                .unwrap_or_default();
            let commitment_hex = txs.get(0).map(|tx| serialize_hex(tx)).unwrap_or_default();
            let htlc_tx_hexes: Vec<String> =
                txs.iter().skip(1).map(|tx| serialize_hex(tx)).collect();
            let (our_to_local_sats, sweeps) = match &to_local {
                Some(desc) => {
                    let value = match desc {
                        SOD::DelayedPaymentOutput(d) => d.output.value,
                        _ => 0,
                    };
                    // Per-variant degradation: a to_local too small to pay a
                    // given feerate yields an honest null for that variant
                    // only, never a failed export.
                    let variant = |feerate: u32| -> Option<(String, String)> {
                        self.keys_manager
                            .spend_spendable_outputs(
                                &[desc],
                                Vec::new(),
                                dest_script.clone(),
                                feerate,
                                None,
                                &secp,
                            )
                            .ok()
                            .map(|tx| (tx.txid().to_string(), serialize_hex(&tx)))
                    };
                    (value, (variant(FEERATE_NORMAL), variant(FEERATE_HIGH)))
                }
                None => (0, (None, None)),
            };
            let (sweep_normal, sweep_high) = sweeps;
            channels.push(serde_json::json!({
                "channel_id": channel_id.to_string(),
                "open": open_txos.contains(&funding_txo),
                "claimable_sats": claimable_sats,
                "funding_txo": format!("{}:{}", funding_txo.txid, funding_txo.index),
                "counterparty": counterparty,
                "commitment_txid": commitment_txid,
                "commitment_hex": commitment_hex,
                "htlc_tx_hexes": htlc_tx_hexes,
                "to_self_delay": to_self_delay,
                "our_to_local_sats": our_to_local_sats,
                "has_to_local": to_local.is_some(),
                "sweep_txid_normal": sweep_normal.as_ref().map(|s| s.0.clone()),
                "sweep_hex_normal": sweep_normal.as_ref().map(|s| s.1.clone()),
                "sweep_txid_high": sweep_high.as_ref().map(|s| s.0.clone()),
                "sweep_hex_high": sweep_high.as_ref().map(|s| s.1.clone()),
            }));
        }
        let kit = serde_json::json!({
            "version": 1,
            "sweep_destination_index": dest_index,
            "sweep_destination_address": dest_address,
            "feerate_normal_sat_vb": 10,
            "feerate_high_sat_vb": 40,
            "channels": channels,
        });
        serde_json::to_string(&kit)
            .map_err(|e| LijError::Node(format!("escape export: serialize: {e}")))
    }

    /// Number of currently-healthy independent Esplora endpoints.
    pub fn independent_healthy_count(&self) -> usize {
        self.independent.healthy_count()
    }

    /// DIAGNOSTICS: monitor census + spend-walker liveness, surfaced in the
    /// on-device status pane (iOS gives us no console). `monitors` compares
    /// `list_monitors()` against `list_channels()` to split open vs
    /// closed-but-retained (a present closed monitor is what the walker needs
    /// to detect an offline close). `walk.seq` advancing confirms the
    /// background loop is actually running on the device.
    /// Pre-maturity closing funds straight from the ChannelMonitors: CSV-locked
    /// to_local awaiting confirmations after a force-close. Unlike the
    /// OutputSweeper's maturing_outputs (post-maturity SpendableOutputs only),
    /// this surfaces funds still locked so the UI can count them down, and it
    /// self-clears once swept (the monitor stops reporting the balance). Works
    /// on a freshly-restored wallet the moment its monitors load. JSON:
    /// [{"amount_sats":N,"confirmation_height":H,"channel_id":"hex"}].
    pub fn maturing_balances_json(&self) -> String {
        use lightning::chain::channelmonitor::Balance;
        let cm = match self.chain_monitor.as_ref() {
            Some(c) => c,
            None => return "[]".to_string(),
        };
        let mut items: Vec<String> = Vec::new();
        for (funding_outpoint, channel_id) in cm.list_monitors() {
            if let Ok(monitor) = cm.get_monitor(funding_outpoint) {
                for bal in monitor.get_claimable_balances() {
                    if let Balance::ClaimableAwaitingConfirmations {
                        amount_satoshis,
                        confirmation_height,
                    } = bal
                    {
                        items.push(format!(
                            "{{\"amount_sats\":{},\"confirmation_height\":{},\"channel_id\":\"{}\"}}",
                            amount_satoshis,
                            confirmation_height,
                            hex::encode(channel_id.0)
                        ));
                    }
                }
            }
        }
        format!("[{}]", items.join(","))
    }

    /// S24 Build 13 (the bubble, v181): per-channel close values — LDK’s own
    /// "what you’d claim were this channel closed now", which for
    /// wallet-funded channels already subtracts the commitment-tx fee
    /// (chain-verified in S23: 10,006 gross → 9,282 delivered, Δ724 = the
    /// funder fee). The frontend joins by channel_id against
    /// dump_channel_details_json to derive the Closing-fees line and the
    /// honest Total owned. Same monitor walk as maturing_balances_json.
    pub fn close_values_json(&self) -> String {
        use lightning::chain::channelmonitor::Balance;
        let cm = match self.chain_monitor.as_ref() {
            Some(c) => c,
            None => return "[]".to_string(),
        };
        let mut items: Vec<String> = Vec::new();
        for (funding_outpoint, channel_id) in cm.list_monitors() {
            if let Ok(monitor) = cm.get_monitor(funding_outpoint) {
                let mut close_sats: u64 = 0;
                let mut seen = false;
                for bal in monitor.get_claimable_balances() {
                    if let Balance::ClaimableOnChannelClose { amount_satoshis, .. } = bal {
                        close_sats += amount_satoshis;
                        seen = true;
                    }
                }
                if seen {
                    items.push(format!(
                        "{{\"channel_id\":\"{}\",\"close_value_sats\":{}}}",
                        hex::encode(channel_id.0),
                        close_sats
                    ));
                }
            }
        }
        format!("[{}]", items.join(","))
    }

    /// v206: JSON array of payments CLAIMED this session —
    /// `[{"hash":"<hex>","sats":N}]`. The frontend matches pending receive
    /// ledger entries by payment_hash to complete them only on a real claim,
    /// never on a balance delta (which a resync blip could fake).
    pub fn claimed_payments_json(&self) -> String {
        let map = self.claimed_payments.lock().unwrap();
        let items: Vec<String> = map
            .iter()
            .map(|(hash, sats)| format!("{{\"hash\":\"{}\",\"sats\":{}}}", hash, sats))
            .collect();
        format!("[{}]", items.join(","))
    }

    /// S21 build #1 (ledger reconciler): LDK's own outbound-payment tracking,
    /// serialized for the frontend's startup RECENT backfill. States:
    /// awaiting_invoice | pending | fulfilled | abandoned. In this LDK
    /// vintage Fulfilled carries NO amount (hash only, and Optional at that);
    /// Pending carries total_msat. Purge caveat: fulfilled entries leave
    /// LDK's tracking ~7 timer ticks after their HTLCs resolve — a backfill
    /// window, not an archive. Rows the frontend writes persist regardless.
    pub fn recent_payments_json(&self) -> String {
        use lightning::ln::channelmanager::RecentPaymentDetails as RPD;
        let cm = match self.channel_manager.as_ref() {
            Some(cm) => cm,
            None => return "[]".to_string(),
        };
        let items: Vec<String> = cm
            .list_recent_payments()
            .iter()
            .map(|p| match p {
                RPD::AwaitingInvoice { payment_id } => format!(
                    "{{\"state\":\"awaiting_invoice\",\"payment_id\":\"{}\"}}",
                    hex::encode(payment_id.0)
                ),
                RPD::Pending { payment_id, payment_hash, total_msat } => format!(
                    "{{\"state\":\"pending\",\"payment_id\":\"{}\",\"payment_hash\":\"{}\",\"total_msat\":{}}}",
                    hex::encode(payment_id.0),
                    hex::encode(payment_hash.0),
                    total_msat
                ),
                RPD::Fulfilled { payment_id, payment_hash } => format!(
                    "{{\"state\":\"fulfilled\",\"payment_id\":\"{}\",\"payment_hash\":{}}}",
                    hex::encode(payment_id.0),
                    match payment_hash {
                        Some(h) => format!("\"{}\"", hex::encode(h.0)),
                        None => "null".to_string(),
                    }
                ),
                RPD::Abandoned { payment_id, payment_hash } => format!(
                    "{{\"state\":\"abandoned\",\"payment_id\":\"{}\",\"payment_hash\":\"{}\"}}",
                    hex::encode(payment_id.0),
                    hex::encode(payment_hash.0)
                ),
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Force the next background_tick to run a funding-spend walk regardless of
    /// cadence phase. Called on app foreground so a wallet whose tick loop was
    /// throttled while backgrounded re-scans for closes immediately.
    pub fn note_foreground(&self) {
        self.funding_walk_force
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // D-1: foreground means we can claim a JIT HTLC, so allow inbound opens.
        self.accepting_channels
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// D-1 (JIT safety): called when the app is backgrounded/hidden. Clears the
    /// acceptance gate so the OpenChannelRequest handler refuses inbound JIT
    /// opens we couldn't reliably claim into while throttled.
    pub fn note_background(&self) {
        self.accepting_channels
            .store(false, std::sync::atomic::Ordering::Relaxed);
        // S21 item 2: hidden precedes nearly every force-quit — one
        // synchronous manager persist here closes most of the skew window.
        if let Err(e) = self.persist_channel_manager() {
            log::warn!("[note_background] ChannelManager persist failed: {e}");
        }
    }

    /// S21 item 2: true when load-time stamps showed the manager stale vs
    /// monitors (interrupted save). The protective FC LDK performs in this
    /// state is expected; the frontend uses this to say so honestly.
    pub fn persist_skew_at_load(&self) -> bool {
        self.persist_skew.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Build #4: cheap Arc handles for the async pending-audit getter — the
    /// wasm layer drops the wallet lock before any network I/O.
    pub fn audit_handles(
        &self,
    ) -> (
        Arc<dyn crate::storage::LijStorage>,
        Arc<crate::independent::IndependentClient>,
    ) {
        (self.storage.clone(), self.independent.clone())
    }

    pub fn diagnostics_json(&self) -> String {
        let (total, open) = match (self.chain_monitor.as_ref(), self.channel_manager.as_ref()) {
            (Some(mon), Some(mgr)) => {
                let live: Vec<(bitcoin::Txid, u16)> = mgr
                    .list_channels()
                    .iter()
                    .filter_map(|c| c.funding_txo.map(|o| (o.txid, o.index)))
                    .collect();
                let monitors = mon.list_monitors();
                let total = monitors.len();
                let open = monitors
                    .iter()
                    .filter(|(op, _)| live.contains(&(op.txid, op.index)))
                    .count();
                (total, open)
            }
            _ => (0usize, 0usize),
        };
        let closed = total.saturating_sub(open);
        let seq = self.walk_seq.load(std::sync::atomic::Ordering::Relaxed);
        let done = self
            .funding_reconcile_done
            .load(std::sync::atomic::Ordering::Relaxed);
        let inflight = self
            .funding_reconcile_inflight
            .load(std::sync::atomic::Ordering::Relaxed);
        let failures = self
            .funding_reconcile_failures
            .load(std::sync::atomic::Ordering::Relaxed);
        format!(
            r#"{{"monitors":{{"total":{},"open":{},"closed":{}}},"walk":{{"seq":{},"done":{},"inflight":{},"failures":{}}}}}"#,
            total, open, closed, seq, done, inflight, failures
        )
    }

    /// Total configured independent Esplora endpoints (healthy + demoted).
    pub fn independent_total_count(&self) -> usize {
        self.independent.endpoint_status().len()
    }

    /// Last quorum decision state.
    pub fn independent_quorum_state(&self) -> crate::independent::QuorumState {
        self.independent.last_quorum_state()
    }

    /// Per-endpoint health snapshot for status panel drilldown.
    /// Step 3.6 (F5): consensus tip from the last successful independent
    /// fetch_tip_height. None until the first quorum-validated tip arrives.
    pub fn independent_block_height(&self) -> Option<u32> {
        self.independent.last_block_height()
    }

    pub fn independent_endpoint_status(&self) -> Vec<(String, bool, u32, Option<u64>)> {
        self.independent.endpoint_status()
    }

    /// Replace the IndependentClient's HTTP backend with a real one.
    /// Called from lij-wasm after wallet construction to swap from
    /// StubEsploraHttp to the real WasmEsploraHttp.
    pub fn set_independent_http(&self, http: std::sync::Arc<dyn crate::independent::EsploraHttp>) {
        self.independent.replace_http(http);
    }

    pub fn node_pubkey(&self) -> LijResult<String> {
        use lightning::sign::{NodeSigner, Recipient};
        let pubkey = self.keys_manager
            .get_node_id(Recipient::Node)
            .map_err(|_| LijError::Node("Failed to get node ID from KeysManager".into()))?;
        Ok(hex::encode(pubkey.serialize()))
    }

    /// v184: sign an arbitrary message with the NODE key using the Lightning
    /// message-signing convention (LND `signmessage`-compatible: zbase32 of a
    /// recoverable sig over sha256d("Lightning Signed Message:" + msg)).
    /// Serves the LIJOX delegate slip digests (register/void); the LSP
    /// verifies via LND /v1/verifymessage and requires the recovered key to
    /// equal this wallet's node_pubkey(). Sync, no I/O.
    pub fn sign_message(&self, msg: &str) -> LijResult<String> {
        lightning::util::message_signing::sign(
            msg.as_bytes(),
            &self.keys_manager.get_node_secret_key(),
        )
        .map_err(|e| LijError::Node(format!("message signing failed: {:?}", e)))
    }

    /// Gather the full local channel state — the ChannelManager blob plus every
    /// live ChannelMonitor — into one encrypted StateBlob for any BackupSink.
    /// The storage keys (which embed funding outpoints) and their values are
    /// JSON-bundled and encrypted in a SINGLE pass, so a backup destination
    /// never sees a funding outpoint. Returns Ok(None) when there is no
    /// ChannelManager yet (nothing to back up).
    pub fn gather_state_blob(&self) -> LijResult<Option<crate::storage::StateBlob>> {
        let cm = match self.storage.get(CHANNEL_MANAGER_KEY)? {
            Some(cm) => cm,
            None => return Ok(None),
        };
        let mut bundle: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        bundle.insert(CHANNEL_MANAGER_KEY.to_string(), hex::encode(&cm));
        for key in self.storage.list_with_prefix(MONITOR_KEY_PREFIX)? {
            if let Some(v) = self.storage.get(&key)? {
                bundle.insert(key, hex::encode(&v));
            }
        }
        // OutputSweeper state (pending sweeps, RBF/bump tracking, best-block
        // cursor). Without this a recovered device re-initializes the sweeper
        // from genesis and loses in-flight sweep tracking after a force-close.
        let sweeper_prefix = format!("{}:", crate::sweeper::SWEEPER_KEY_PREFIX);
        for key in self.storage.list_with_prefix(&sweeper_prefix)? {
            if let Some(v) = self.storage.get(&key)? {
                bundle.insert(key, hex::encode(&v));
            }
        }
        // v220 (D3, recovery arc): the on-chain state rides the blob — view
        // (cursor with the TRUE birthday, UTXO set, history, address
        // frontiers), pendings, and the destination-index counters — so a blob
        // restore rehydrates on-chain balances instantly instead of re-walking
        // filters from the epoch. inject_state_blob writes every bundle key
        // generically, so old blobs restore unchanged and new keys flow with
        // zero unpack changes: two-way compatible by construction.
        // v228 (S43, DP field 2026-09-02): the LNURLp preimage pool rides
        // in the bundle. It never did — a wallet restored on another device
        // (cloud or sealed file) got its channels and the registered hashes
        // but NOT the preimages, so every payment to its static address
        // arrived as PaymentClaimable it could not claim and hung until LDK's
        // own expiry. The key restores through the same generic inject path.
        for key in [
            crate::tier2_wallet::VIEW_KEY,
            crate::tier2_wallet::PENDING_KEY,
            crate::persisted_counter::KEY_NEXT_CHANNEL_INDEX,
            crate::persisted_counter::KEY_COUNTER_UPWARD_RATCHET,
            KEY_LNURLP_PREIMAGES,
            KEY_LNURLP_NEXT_INDEX,   // v229
        ] {
            if let Some(v) = self.storage.get(key)? {
                bundle.insert(key.to_string(), hex::encode(&v));
            }
        }
        let plaintext = serde_json::to_vec(&bundle)
            .map_err(|e| LijError::Backup(format!("backup bundle serialize: {e}")))?;
        let enc_key = self.root_key.encryption_key();
        let encrypted_data = persist::encrypt(&enc_key, &plaintext)
            .map_err(|e| LijError::Backup(format!("backup bundle encrypt: {e}")))?;
        let version = self.next_backup_version()?;
        let pubkey_hex = self.root_key.portable_pubkey_hex()?;
        Ok(Some(crate::storage::StateBlob {
            version,
            encrypted_data,
            nonce: Vec::new(), // persist::encrypt embeds its own AES-GCM nonce
            pubkey_hex,
        }))
    }

    /// Monotonic, persisted backup version so a stale push can never roll back a
    /// newer one — the Worker rejects a version lower than what it holds.
    fn next_backup_version(&self) -> LijResult<u64> {
        let cur = match self.storage.get(crate::storage::KEY_BACKUP_VERSION)? {
            Some(b) if b.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b);
                u64::from_be_bytes(a)
            }
            _ => 0,
        };
        let next = cur + 1;
        self.storage
            .set(crate::storage::KEY_BACKUP_VERSION, &next.to_be_bytes())?;
        Ok(next)
    }

    /// The portable-key signer used to authenticate backup pushes/reads.
    /// (RootKey implements BackupSigner.)
    pub fn portable_signer(&self) -> &crate::key::RootKey {
        &self.root_key
    }

    /// An owned (Arc) handle to the portable-key signer, so a backup push can run
    /// WITHOUT holding the wallet lock across its `.await` — which would let a
    /// background tick re-enter and panic the single-threaded WASM mutex.
    pub fn portable_signer_arc(&self) -> std::sync::Arc<crate::key::RootKey> {
        self.root_key.clone()
    }

    /// Take the auto-backup dirty flag: returns its value and clears it. True
    /// means channel state changed since the last snapshot and should be pushed.
    pub fn take_backup_dirty(&self) -> bool {
        self.backup_dirty.swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// Clonable handle to the dirty flag, so a push running outside the wallet
    /// lock can re-mark dirty on failure to retry on the next tick.
    pub fn backup_dirty_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.backup_dirty.clone()
    }

    /// On-chain wallet (D): clonable handle to the independent Esplora client
    /// for UTXO scanning and broadcast.
    pub fn independent_client(&self) -> std::sync::Arc<crate::independent::IndependentClient> {
        self.independent.clone()
    }

    /// Clonable handle to the root key, for on-chain address derivation/signing.
    /// S45: handles for the CPFP work (runs outside the wallet lock).
    pub fn coop_cpfp_handles(&self) -> CoopCpfpHandles {
        CoopCpfpHandles {
            root_key: self.root_key.clone(),
            independent: self.independent.clone(),
            network: self.network,
            fee_estimator: self.fee_estimator.clone(),
            tip: self.chain_coordinator.lock().map(|c| c.tip_height()).unwrap_or(0),
            counter: self.signer_provider.peek_counter().unwrap_or(0),
        }
    }
    pub fn root_key_arc(&self) -> std::sync::Arc<crate::key::RootKey> {
        self.root_key.clone()
    }

    /// Abandon ALL channels WITHOUT broadcasting our commitment transaction.
    /// This is the safe recovery move after restoring stale channel state:
    /// broadcasting our (revoked) commitment would let the counterparty take
    /// everything via the penalty mechanism, so instead we drop the channel
    /// locally and rely on the counterparty / on-chain monitor to resolve it.
    /// Must be called BEFORE reconnecting to peers, since channel_reestablish on
    /// a stale channel triggers LDK's data-loss-protect panic. Returns the count
    /// of channels abandoned.
    pub fn force_close_all_without_broadcasting(&self) -> LijResult<u32> {
        let cm = self
            .channel_manager
            .as_ref()
            .ok_or_else(|| LijError::Node("ChannelManager not initialized".into()))?;
        let mut closed = 0u32;
        for ch in cm.list_channels() {
            match cm.force_close_without_broadcasting_txn(
                &ch.channel_id,
                &ch.counterparty.node_id,
            ) {
                Ok(()) => {
                    closed += 1;
                    log::info!(
                        "force-close WITHOUT broadcast: channel {} counterparty {}",
                        ch.channel_id, ch.counterparty.node_id
                    );
                }
                Err(e) => log::warn!(
                    "force_close_without_broadcasting_txn failed for {}: {e:?}",
                    ch.channel_id
                ),
            }
        }
        Ok(closed)
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    fn persist_channel_manager(&self) -> LijResult<()> {
        if let Some(ref cm) = self.channel_manager {
            let mut buf = vec![];
            cm.write(&mut buf)
                .map_err(|e| LijError::Storage(format!("CM serialize: {:?}", e)))?;
            let enc_key = self.root_key.encryption_key();
            let ciphertext = persist::encrypt(&enc_key, &buf)
                .map_err(|e| LijError::Storage(format!("CM encrypt: {e}")))?;
            self.storage.set(CHANNEL_MANAGER_KEY, &ciphertext)?;
            // S21 item 2: manager stamp for load-time skew detection.
            let s = self.persist_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let _ = self.storage.set(persist::SEQ_CM_KEY, &s.to_be_bytes());
            // AUTO-BACKUP: state changed -> flag for the next backup tick (debounced).
            self.backup_dirty.store(true, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "ChannelManager persisted ({} bytes plaintext, {} bytes encrypted)",
                buf.len(),
                ciphertext.len()
            );
        }
        Ok(())
    }
}

/// Build #4 confirmation instrument: audit every pending record against the
/// independent quorum — is the tx itself visible, and what is the live status
/// of each recorded input (unspent / spent-by / parent unseen). Pure network
/// reads; call with cloned Arcs, never under the wallet lock.
pub async fn pending_onchain_audit(
    storage: Arc<dyn crate::storage::LijStorage>,
    indep: Arc<crate::independent::IndependentClient>,
) -> String {
    let pending = crate::tier2_wallet::load_pending(&*storage);
    let now = crate::tier2_wallet::now_ms();
    let mut rows: Vec<String> = Vec::new();
    for p in pending.iter() {
        let age_s = now.saturating_sub(p.created_at_ms) / 1000;
        let tx_seen = indep.fetch_tx(&p.txid).await.is_ok();
        let kind_str = match p.kind {
            crate::tier2_wallet::TxKind::ChannelOpen => "ChannelOpen",
            _ => "Other",
        };
        let mut inputs: Vec<String> = Vec::new();
        for (in_txid, vout) in p.spent_outpoints.iter() {
            let status = match indep.fetch_tx_outspends(in_txid).await {
                Ok(outs) => match outs.get(*vout as usize) {
                    Some(o) if o.spent => format!(
                        "spent_by:{}",
                        o.txid.clone().unwrap_or_else(|| "?".into())
                    ),
                    Some(_) => "unspent".to_string(),
                    None => "vout_out_of_range".to_string(),
                },
                Err(_) => "parent_unseen".to_string(),
            };
            inputs.push(format!(
                "{{\"outpoint\":\"{}:{}\",\"status\":\"{}\"}}",
                in_txid, vout, status
            ));
        }
        rows.push(format!(
            "{{\"txid\":\"{}\",\"kind\":\"{}\",\"delta_sats\":{},\"broadcast_seen\":{},\"tx_seen_now\":{},\"age_s\":{},\"has_raw_bytes\":{},\"inputs\":[{}]}}",
            p.txid, kind_str, p.delta_sats, p.broadcast_seen, tx_seen, age_s,
            p.raw_tx_hex.is_some(), inputs.join(",")
        ));
    }
    format!("[{}]", rows.join(","))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn parse_network(s: &str) -> LijResult<Network> {
    match s {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet"  => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(LijError::InvalidArgument(format!("Unknown network: {other}"))),
    }
}

fn parse_channel_id_hex(hex_str: &str) -> LijResult<ChannelId> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| LijError::InvalidArgument(format!("Bad channel_id hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(LijError::InvalidArgument(format!(
            "channel_id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ChannelId(arr))
}

fn current_time_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    { (js_sys::Date::now() / 1000.0) as u64 }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Offline force-close detection (option 1, 2026-05-20 handoff)
// ─────────────────────────────────────────────────────────────────────────────

/// Walk every channel monitor's funding outpoint (including closed-but-
/// retained monitors, not just live channels) and verify via the independent
/// Esplora quorum that it is still unspent. If any funding outpoint has been
/// spent on-chain in a confirmed block, fetch the spending tx bytes, build a
/// synthetic header (mirroring the cooperative-bridge confirmation pattern at
/// node.rs `take_pending_confirmations`), and route the closure through the
/// chain coordinator's `ingest_independent_confirmation` admin path so LDK
/// processes the channel close.
///
/// Recovery path for offline force-closes: while the wallet is offline, the
/// LSP may force-close a channel and sweep the funding output, but the
/// cooperative chain protocol has no `ClosingTxObserved` message type. Without
/// this walker, the channel stays `is_usable: true` in LDK state until a
/// payment attempt fails — and even then LDK may keep retrying since the
/// monitor never saw the closing tx.
///
/// All HTTP failures are logged at debug or warn level and skipped (no
/// retries here — `background_tick` re-invokes this on a periodic cadence).
/// Idempotent: `ingest_independent_confirmation` no-ops if the spending tx
/// is already in the coordinator's authoritative set at the same height.
#[cfg(target_arch = "wasm32")]
async fn check_funding_outpoints_for_spends(
    cm: Arc<LijChannelManager>,
    chain_monitor: Arc<LijChainMonitor>,
    chain_coordinator: Arc<Mutex<crate::chain_coordinator::ChainCoordinator>>,
    independent: Arc<IndependentClient>,
    sightings: Arc<Mutex<std::collections::HashMap<String, String>>>,
    storage: Arc<dyn crate::storage::LijStorage>,
) -> bool {
    // Snapshot funding outpoints from the MONITORS, not from live channels.
    //
    // list_channels() returns only channels LDK still considers open. The
    // instant a channel force-closes, LDK drops it from that list — but its
    // ChannelMonitor is retained until the to_local/to_remote outputs are
    // swept and the monitor is archived. Sourcing from list_channels() meant
    // this walker stopped checking exactly the channels that had just closed,
    // so their closing-tx confirmation was never fed to the monitor, the
    // monitor never emitted SpendableOutputs, and the OutputSweeper sat idle
    // (funds stranded on-chain at hundreds of confirmations). list_monitors()
    // is a superset of the live set — live channels still have monitors, so
    // flap detection is unchanged — and it additionally covers closed-but-
    // retained monitors, which is precisely the offline-force-close case.
    // Resolved spends dedup via the coordinator's already_confirmed check;
    // fully-swept monitors get archived and drop off this list, so it
    // converges rather than re-checking forever.
    // v223 (S39): fully-resolved monitors (claimables empty, funding spend
    // seen) LEAVE the walk — nothing on-chain can change for them; they are
    // only waiting out LDK's 4032-block archive threshold. Dropping them
    // shrinks the all-must-answer Esplora pass (18 outpoints on the field
    // Android) to the live few, which is what lets reconcile_done actually
    // latch on a phone network — the corpses no longer lengthen the walk
    // that would bury them.
    let outpoints: Vec<(bitcoin::Txid, u16)> = chain_monitor
        .list_monitors()
        .into_iter()
        .filter(|(op, _cid)| match chain_monitor.get_monitor(*op) {
            Ok(m) => !m.lij_is_resolved_awaiting_archive(),
            Err(()) => false, // evicted between list and get — nothing to walk
        })
        .map(|(op, _cid)| (op.txid, op.index))
        .collect();

    if outpoints.is_empty() {
        return true;
    }

    // FLAP FIX: true only if this pass got a definitive on-chain answer for
    // every outpoint AND evicted every confirmed spend. The scheduler latches
    // funding_reconcile_done only on true, so a 429/partial pass keeps us in
    // eager-retry mode rather than dropping to the 10-min cadence with a dead
    // channel still flapping.
    let mut complete = true;

    log::debug!(
        "[funding_spend_check] walking {} live channel funding outpoint(s)",
        outpoints.len()
    );

    for (funding_txid, funding_vout) in outpoints {
        let outspends = match independent
            .fetch_tx_outspends(&funding_txid.to_string())
            .await
        {
            Ok(o) => o,
            Err(e) => {
                log::debug!(
                    "[funding_spend_check] fetch_tx_outspends({}) failed: {}",
                    funding_txid, e
                );
                complete = false; // no on-chain answer for this outpoint -- retry
                continue;
            }
        };

        let outspend = match outspends.get(funding_vout as usize) {
            Some(o) => o,
            None => {
                log::debug!(
                    "[funding_spend_check] {}:{} -- outspends had no entry at vout {}",
                    funding_txid, funding_vout, funding_vout
                );
                continue;
            }
        };

        if !outspend.spent {
            // v178: an earlier mempool sighting that evaporated (RBF/mempool
            // eviction) must not keep painting "closing".
            if let Ok(mut m) = sightings.lock() {
                m.remove(&format!("{}:{}", funding_txid, funding_vout));
            }
            continue; // Channel still alive on-chain.
        }

        let spending_txid_str = match outspend.txid.as_ref() {
            Some(t) => t.clone(),
            None => {
                log::warn!(
                    "[funding_spend_check] {}:{} marked spent but no spending txid",
                    funding_txid, funding_vout
                );
                continue;
            }
        };

        // v179: heal blind closed records — the walker knows the spending
        // (closing) txid; records created while the wallet slept through the
        // mempool window carry closing_txid_hex=None, which blinds the tier2
        // ChannelClose reclassifier and every surface downstream (Lightning
        // RECENTS "returned to on-chain" row, on-chain row labeling, the v132
        // alert clear). None-only fill; record may not exist yet pre-eviction
        // (Ok(false)) — retried every pass, heals within one walker cycle of
        // the record's birth. Retro-heals T-CLOSE-1 (monitor still retained).
        {
            let log = ClosedChannelLog::new(storage.clone());
            let key = format!("{}:{}", funding_txid, funding_vout);
            if let Ok(true) = log.set_closing_txid_by_funding_txo(&key, &spending_txid_str) {
                log::info!(
                    "[funding_spend_check] closed record for {} healed with closing txid {}",
                    key, spending_txid_str
                );
            }
        }

        let status = match outspend.status.as_ref() {
            Some(s) => s,
            None => {
                log::debug!(
                    "[funding_spend_check] {}:{} spent by {} -- spending tx still in mempool",
                    funding_txid, funding_vout, spending_txid_str
                );
                // v178 (close-awareness): non-destructive display signal —
                // a close is in flight. Eviction stays confirmation-gated.
                if let Ok(mut m) = sightings.lock() {
                    m.insert(format!("{}:{}", funding_txid, funding_vout), spending_txid_str.clone());
                }
                continue;
            }
        };

        if !status.confirmed {
            log::debug!(
                "[funding_spend_check] {}:{} spent by {} -- status not yet confirmed",
                funding_txid, funding_vout, spending_txid_str
            );
            // v178 (close-awareness): same display signal — see above.
            if let Ok(mut m) = sightings.lock() {
                m.insert(format!("{}:{}", funding_txid, funding_vout), spending_txid_str.clone());
            }
            continue;
        }

        // v178: confirmed — the display signal hands off to eviction/monitor.
        if let Ok(mut m) = sightings.lock() {
            m.remove(&format!("{}:{}", funding_txid, funding_vout));
        }
        let height = match status.block_height {
            Some(h) => h,
            None => {
                log::warn!(
                    "[funding_spend_check] {}:{} confirmed but no block_height in status",
                    funding_txid, funding_vout
                );
                continue;
            }
        };

        let spending_txid = match spending_txid_str.parse::<bitcoin::Txid>() {
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "[funding_spend_check] {}:{} spending txid parse error: {}",
                    funding_txid, funding_vout, e
                );
                continue;
            }
        };

        // Dedup: skip if coordinator already authoritatively knows this
        // spending tx confirmation. Cheap check before fetching tx bytes.
        let already_confirmed = chain_coordinator
            .lock()
            .map(|c| c.is_confirmed(&spending_txid))
            .unwrap_or(false);
        if already_confirmed {
            log::debug!(
                "[funding_spend_check] {}:{} spending tx {} already authoritative — skipping",
                funding_txid, funding_vout, spending_txid
            );
            continue;
        }

        // Fetch raw spending-tx bytes.
        let raw_tx = match independent.fetch_tx_hex(&spending_txid_str).await {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "[funding_spend_check] fetch_tx_hex({}) failed: {}",
                    spending_txid_str, e
                );
                complete = false; // confirmed spend not yet evicted -- retry
                continue;
            }
        };

        // Sanity: verify the bytes hash to the claimed txid (defense in
        // depth against a single Esplora endpoint returning bogus data
        // past the quorum's healthy_count gate).
        match bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_tx) {
            Ok(tx) => {
                if tx.txid() != spending_txid {
                    log::warn!(
                        "[funding_spend_check] spending tx bytes hash mismatch: claimed={} computed={} -- dropping",
                        spending_txid, tx.txid()
                    );
                    complete = false; // confirmed spend not evicted -- retry
                    continue;
                }
            }
            Err(e) => {
                log::warn!(
                    "[funding_spend_check] spending tx bytes deserialize failed for {}: {}",
                    spending_txid, e
                );
                complete = false; // confirmed spend not evicted -- retry
                continue;
            }
        }

        // Build synthetic header. Mirror of the cooperative-bridge pattern
        // at node.rs `take_pending_confirmations` -- LDK only needs a header
        // it can hash for BestBlock bookkeeping, not a valid-PoW header.
        // tx_index=0 is safe here: LDK uses tx_index for SCID computation
        // on funding confirmations, not on closing-tx confirmations (SCID
        // was already established at channel open).
        let merkle_root = TxMerkleNode::from_byte_array(spending_txid.to_byte_array());
        let synthetic_header = Header {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };

        log::warn!(
            "[funding_spend_check] funding outpoint {}:{} was spent by {} at height {} -- promoting independent observation to authoritative confirmation",
            funding_txid, funding_vout, spending_txid, height
        );

        let action = {
            let mut coord = match chain_coordinator.lock() {
                Ok(c) => c,
                Err(_) => {
                    log::error!(
                        "[funding_spend_check] chain_coordinator lock poisoned -- aborting walk"
                    );
                    return false;
                }
            };
            coord.ingest_independent_confirmation(
                crate::chain_coordinator::IndependentConfirmation {
                    txid: spending_txid,
                    height,
                    block_hash: synthetic_header.block_hash(),
                    tx_index: 0,
                    raw_tx,
                    block_header: synthetic_header,
                    reason: format!(
                        "offline force-close: funding {}:{} spent by {}",
                        funding_txid, funding_vout, spending_txid
                    ),
                },
            )
        };
        action.apply(&*chain_monitor, &*cm, None);
        // Event::ChannelClosed will fire on the next background_tick's
        // process_pending_events call; the existing handler at the
        // ChannelClosed match arm above persists the ClosedChannelRecord
        // and the closed_channel_watcher takes over from there.
    }

    complete
}



// ─────────────────────────────────────────────────────────────────────────────
// Phase 10b — LSP routing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch a URL via web_sys::fetch with a Grpc-Metadata-macaroon header.
/// Returns response body as String. Returns LijError::Lsp on any HTTP failure.
#[cfg(target_arch = "wasm32")]
async fn fetch_with_macaroon(url: &str, macaroon_hex: &str) -> LijResult<String> {
    use wasm_bindgen::JsValue;
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use wasm_bindgen_futures::JsFuture;

    let mut opts = RequestInit::new();
    #[allow(deprecated)]
    opts.method("GET");
    #[allow(deprecated)]
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Lsp(format!("Failed to build request: {:?}", e)))?;
    request.headers().set("Grpc-Metadata-macaroon", macaroon_hex)
        .map_err(|e| LijError::Lsp(format!("Failed to set macaroon header: {:?}", e)))?;

    let window = web_sys::window()
        .ok_or_else(|| LijError::Lsp("No window object available".into()))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
        .map_err(|e| LijError::Lsp(format!("Fetch failed: {:?}", e)))?;
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| LijError::Lsp("Response cast failed".into()))?;

    if !resp.ok() {
        return Err(LijError::Lsp(format!("HTTP {}: {}", resp.status(), resp.status_text())));
    }

    let text_promise = resp.text()
        .map_err(|e| LijError::Lsp(format!("text() failed: {:?}", e)))?;
    let text_value = JsFuture::from(text_promise).await
        .map_err(|e| LijError::Lsp(format!("text await failed: {:?}", e)))?;
    text_value.as_string()
        .ok_or_else(|| LijError::Lsp("Response not a string".into()))
}

/// POST variant of fetch_with_macaroon. Sends a JSON body with the macaroon
/// header and Content-Type: application/json. Used by Phase 10b's
/// send_payment_via_lsp_route to call the adapter's /v1/route/build endpoint
/// (introduced in lij-adapter v0.11).
///
/// Identical error-handling and response shape as the GET helper above —
/// caller gets the response body text or a LijError::Lsp on any failure.
#[cfg(target_arch = "wasm32")]
pub async fn fetch_post_with_macaroon(url: &str, macaroon_hex: &str, body: &str) -> LijResult<String> {
    use wasm_bindgen::JsValue;
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use wasm_bindgen_futures::JsFuture;
    let mut opts = RequestInit::new();
    #[allow(deprecated)]
    opts.method("POST");
    #[allow(deprecated)]
    opts.mode(RequestMode::Cors);
    #[allow(deprecated)]
    opts.body(Some(&JsValue::from_str(body)));
    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Lsp(format!("Failed to build request: {:?}", e)))?;
    request.headers().set("Grpc-Metadata-macaroon", macaroon_hex)
        .map_err(|e| LijError::Lsp(format!("Failed to set macaroon header: {:?}", e)))?;
    request.headers().set("Content-Type", "application/json")
        .map_err(|e| LijError::Lsp(format!("Failed to set content-type header: {:?}", e)))?;
    let window = web_sys::window()
        .ok_or_else(|| LijError::Lsp("No window object available".into()))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
        .map_err(|e| LijError::Lsp(format!("Fetch failed: {:?}", e)))?;
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| LijError::Lsp("Response cast failed".into()))?;
    if !resp.ok() {
        return Err(LijError::Lsp(format!("HTTP {}: {}", resp.status(), resp.status_text())));
    }
    let text_promise = resp.text()
        .map_err(|e| LijError::Lsp(format!("text() failed: {:?}", e)))?;
    let text_value = JsFuture::from(text_promise).await
        .map_err(|e| LijError::Lsp(format!("text await failed: {:?}", e)))?;
    text_value.as_string()
        .ok_or_else(|| LijError::Lsp("Response not a string".into()))
}

/// Parse LND QueryRoutes JSON response and convert to LDK Route.
///
/// LND format (relevant fields):
///   { "routes": [{ "hops": [{ "pub_key": "...", "chan_id": "...",
///     "amt_to_forward_msat": "...", "fee_msat": "...", "expiry": ... }] }] }
///
/// LDK Route requires Path with RouteHops carrying:
///   pubkey, node_features, short_channel_id, channel_features,
///   fee_msat, cltv_expiry_delta, maybe_announced_channel
///
/// Conversion notes:
///   - LND `chan_id` is a stringified u64 → parse to short_channel_id
///   - LND gives absolute `expiry` per hop (block height); LDK wants
///     `cltv_expiry_delta` as the difference between successive hops.
///     For the last hop, delta is `final_cltv_delta` from the invoice (already
///     baked into LND's response per its routing logic).
///   - node_features and channel_features → empty (LDK accepts known-good routes
///     with empty features when routes come from a trusted source like our LSP)
///   - maybe_announced_channel → true (LSP's routes go through public channels;
///     LSP would not return private channels unless via blinded paths which
///     we don't yet handle)
fn parse_lnd_route_response(json: &str, final_cltv_delta: u32) -> LijResult<Route> {
    use bitcoin::secp256k1::PublicKey;

    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| LijError::Payment(format!("LND response parse: {:?}", e)))?;

    // v218 (S36, 6e payer-visible A1 refusal — DP-confirmed, additive on the
    // ALREADY-FAILING path only): when the adapter refused route synthesis
    // (hint-faithful A1: stale jit-pinned hint), it labels the routeless
    // response with lijox_refusal.code. Surface the token so the page can
    // speak one honest sentence. Successful sends (routes present) never
    // reach these lines; failure timing is unchanged, only the STRING gains
    // meaning. Absent label (older adapter) = the original errors verbatim.
    let refusal_code: Option<String> = parsed.get("lijox_refusal")
        .and_then(|r| r.get("code"))
        .and_then(|c| c.as_str())
        .map(|c| c.to_string());

    let routes = parsed.get("routes").and_then(|v| v.as_array())
        .ok_or_else(|| match &refusal_code {
            Some(code) => LijError::Payment(format!("lsp_refusal:{}", code)),
            None => LijError::Payment("No 'routes' in LND response".into()),
        })?;

    if routes.is_empty() {
        return Err(match refusal_code {
            Some(code) => LijError::Payment(format!("lsp_refusal:{}", code)),
            None => LijError::Payment("LND returned no routes".into()),
        });
    }

    let lnd_route = &routes[0];
    let hops_json = lnd_route.get("hops").and_then(|v| v.as_array())
        .ok_or_else(|| LijError::Payment("No 'hops' in route".into()))?;

    if hops_json.is_empty() {
        return Err(LijError::Payment("LND route has no hops".into()));
    }

    // First pass: collect hop expiry block heights and other fields.
    //
    // Note on amt_to_forward_msat (added in 3.8.g):
    // LND returns this per hop = the amount arriving at that hop. For the
    // LAST hop in the route, this equals the delivery amount to the
    // destination, which LDK requires as the last hop's fee_msat
    // (LDK convention: last-hop fee_msat = full path value, not a fee).
    struct HopRaw {
        pubkey: PublicKey,
        short_channel_id: u64,
        fee_msat: u64,
        amt_to_forward_msat: u64,
        expiry: u32,
    }

    let mut raws: Vec<HopRaw> = Vec::with_capacity(hops_json.len());
    for hop in hops_json {
        let pubkey_hex = hop.get("pub_key").and_then(|v| v.as_str())
            .ok_or_else(|| LijError::Payment("Hop missing pub_key".into()))?;
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| LijError::Payment(format!("pub_key hex: {:?}", e)))?;
        let pubkey = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| LijError::Payment(format!("PublicKey parse: {:?}", e)))?;

        let chan_id_str = hop.get("chan_id").and_then(|v| v.as_str())
            .ok_or_else(|| LijError::Payment("Hop missing chan_id".into()))?;
        let short_channel_id: u64 = chan_id_str.parse()
            .map_err(|e| LijError::Payment(format!("chan_id parse: {:?}", e)))?;

        // LND returns msat fields as strings sometimes, sometimes numbers
        let fee_msat = parse_lnd_msat(hop.get("fee_msat"))?;
        let amt_to_forward_msat = parse_lnd_msat(hop.get("amt_to_forward_msat"))?;

        let expiry = hop.get("expiry").and_then(|v| v.as_u64())
            .ok_or_else(|| LijError::Payment("Hop missing expiry".into()))? as u32;

        raws.push(HopRaw { pubkey, short_channel_id, fee_msat, amt_to_forward_msat, expiry });
    }

    // Second pass: compute cltv_expiry_delta from successive expiries.
    // For hop i (0-indexed): delta = expiry[i-1] - expiry[i] for i > 0
    // For hop 0: delta = total_time_lock - expiry[0]
    // Actually, LDK's convention: cltv_expiry_delta on hop N is the delta
    // *added* by that hop. So delta[0] = our_block_height + delta_to_hop_1, etc.
    //
    // Simpler approach: LND's `total_time_lock` is the topmost CLTV; each hop's
    // `expiry` is the CLTV for that hop's outgoing HTLC. So:
    //   hop[0]'s outgoing expiry = total_time_lock - hop[0]'s cltv_expiry_delta
    // Working backward:
    //   hop[N-1].cltv_expiry_delta = invoice's min_final_cltv_expiry (we don't
    //     have direct access here; LND has already accounted for it)
    //   hop[i].cltv_expiry_delta = hop[i].expiry - hop[i+1].expiry
    //                              for i < N-1
    //
    // For the last hop, delta is what's left between the last hop's expiry
    // and the destination. LND encodes this implicitly.
    // We approximate: last hop delta = expiry[N-1] - expiry[N-1] would be 0,
    // which is wrong. Use a sane default of 40 (LDK default min_final_cltv).
    let total_time_lock = lnd_route.get("total_time_lock").and_then(|v| v.as_u64())
        .ok_or_else(|| LijError::Payment("Route missing total_time_lock".into()))? as u32;

    let mut hops: Vec<RouteHop> = Vec::with_capacity(raws.len());
    for (i, raw) in raws.iter().enumerate() {
        let cltv_expiry_delta = if i == 0 {
            // First hop: delta is total - first hop's expiry
            total_time_lock.saturating_sub(raw.expiry)
        } else if i < raws.len() - 1 {
            // Middle hops: delta is previous - current
            raws[i - 1].expiry.saturating_sub(raw.expiry)
        } else {
            // Last hop: use the invoice's min_final_cltv_expiry_delta.
            // This is what the destination requires us to lock for, encoded
            // in the BOLT11 invoice itself (per BOLT 11 spec, default 18 if
            // not specified). Using the invoice's value is correct for
            // any-length route (1 hop or 8+ hops) since this represents the
            // destination's requirement, not a routing hop's.
            final_cltv_delta
        };

        // 3.8.g: LDK convention for RouteHop.fee_msat differs for the last hop:
        //   - Non-last hops: fee taken BY this hop for forwarding to the next
        //     (= LND's fee_msat field, what this node keeps).
        //   - Last hop: the FULL VALUE delivered to the destination. LND's
        //     fee_msat for the last hop is 0 (destinations don't charge), but
        //     LDK uses this field as the delivery amount. Use LND's
        //     amt_to_forward_msat for the last hop — that's the amount
        //     arriving at (= delivered to) the destination.
        let ldk_fee_msat = if i == raws.len() - 1 {
            raw.amt_to_forward_msat
        } else {
            raw.fee_msat
        };

        hops.push(RouteHop {
            pubkey: raw.pubkey,
            node_features: NodeFeatures::empty(),
            short_channel_id: raw.short_channel_id,
            channel_features: ChannelFeatures::empty(),
            fee_msat: ldk_fee_msat,
            cltv_expiry_delta,
            maybe_announced_channel: true,
        });
    }

    let path = Path {
        hops,
        blinded_tail: None,
    };

    Ok(Route {
        paths: vec![path],
        route_params: None,
    })
}

/// LND returns msat fields sometimes as numbers, sometimes as strings.
/// Handle both.
fn parse_lnd_msat(v: Option<&serde_json::Value>) -> LijResult<u64> {
    let val = v.ok_or_else(|| LijError::Payment("Missing msat field".into()))?;
    if let Some(n) = val.as_u64() {
        return Ok(n);
    }
    if let Some(s) = val.as_str() {
        return s.parse::<u64>()
            .map_err(|e| LijError::Payment(format!("msat parse: {:?}", e)));
    }
    Err(LijError::Payment("msat field has unexpected type".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;

    #[test]
    fn test_parse_network() {
        assert!(matches!(parse_network("bitcoin"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_network("testnet"), Ok(Network::Testnet)));
        assert!(parse_network("invalid").is_err());
    }

    fn test_config() -> WalletConfig {
        WalletConfig {
            network: "regtest".into(),
            worker_url: "http://localhost".into(),
            backup_auth_token: "".into(),
            esplora_url: "http://localhost".into(),
            preferred_lsp_pubkey: None,
        }
    }

    #[tokio::test]
    async fn restore_with_empty_storage_creates_fresh_node() {
        let (root_key, _mnemonic) = RootKey::generate(Network::Regtest).unwrap();
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let node = LijNode::restore(root_key, test_config(), storage)
            .await
            .expect("restore from empty storage should fall back to fresh node");
        assert_eq!(node.get_channels().unwrap().len(), 0);
        assert!(node.channel_manager.is_some());
        assert!(node.peer_manager.is_some());
    }

    #[tokio::test]
    async fn restore_errors_when_monitors_present_but_no_channel_manager() {
        let (root_key, _mnemonic) = RootKey::generate(Network::Regtest).unwrap();
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        // Plant an orphan monitor key (content irrelevant — restore should
        // bail before attempting to decrypt).
        storage
            .set("lij:monitor:abc:0", b"opaque")
            .unwrap();
        match LijNode::restore(root_key, test_config(), storage).await {
            Err(e) => assert!(
                format!("{e}").contains("no ChannelManager"),
                "expected ChannelManager-missing error, got: {e}"
            ),
            Ok(_) => panic!("monitors-without-CM should error"),
        }
    }

    #[tokio::test]
    async fn fresh_node_persists_channel_manager_on_invoice_creation() {
        let (root_key, _mnemonic) = RootKey::generate(Network::Regtest).unwrap();
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let node = LijNode::new(root_key, test_config(), storage.clone())
            .await
            .unwrap();
        assert_eq!(storage.get(CHANNEL_MANAGER_KEY).unwrap(), None);

        // Phase 4 step 6b: gate sync state to Ready so create_invoice doesn't bail.
        node.set_sync_state(SyncState::Ready);

        // create_invoice() calls persist_channel_manager() internally.
        let _ = node.create_invoice(Some(1_000), "test", 3600);

        let blob = storage
            .get(CHANNEL_MANAGER_KEY)
            .unwrap()
            .expect("CM should be persisted after invoice creation");
        // Ciphertext = 12-byte nonce + AES-GCM payload (≥ 16-byte tag).
        assert!(blob.len() > 12 + 16, "ciphertext too short: {} bytes", blob.len());
    }
}

// ============================================================================
// Phase 3.7.H — Zombie monitor cleanup
// ============================================================================
//
// Methods for manually archiving force-closed ChannelMonitor entries from
// browser persistence storage. Used to clean up zombies — monitors whose
// underlying channels are fully resolved on chain but which LDK keeps
// re-engaging with on every wallet restart (causing chain_filter
// re-registration, broadcaster claim re-attempts, and noisy logs).
//
// Storage scheme (defined in persist.rs):
//   active key:   lij:monitor:{funding_txid}:{vout}
//   archived key: lij:monitor-archived:{funding_txid}:{vout}
//
// Archiving moves the encrypted blob from active to archived; the next
// wallet restart will not load archived monitors, eliminating their
// downstream effects.
impl LijNode {
    /// Archive a stored ChannelMonitor by funding outpoint, removing it from
    /// the active monitor set. Used for cleaning up zombies — force-closed
    /// channels whose claim outputs were already swept (e.g. via BIP84) but
    /// which LDK keeps re-engaging with on each wallet restart.
    ///
    /// Returns Ok(true) if a monitor was archived, Ok(false) if no active
    /// monitor existed at the given outpoint, Err on storage failure.
    ///
    /// Note: this only modifies persistence. The chain_filter state for the
    /// current wallet session remains; a wallet restart picks up the cleaned
    /// state. For zombie cleanup, this is sufficient because the noise only
    /// manifests at restart-time (monitor reload triggers chain_filter
    /// re-registration and broadcaster re-arming).
    pub fn purge_force_closed_monitor(
        &self,
        funding_txid: bitcoin::Txid,
        output_index: u32,
    ) -> LijResult<bool> {
        let outpoint = lightning::chain::transaction::OutPoint {
            txid: funding_txid,
            index: u16::try_from(output_index).map_err(|_| {
                LijError::Node(format!(
                    "purge_force_closed_monitor: output_index {output_index} exceeds u16"
                ))
            })?,
        };
        let active_key = crate::persist::LijChannelMonitorPersister::monitor_key(&outpoint);
        let archived_key = crate::persist::LijChannelMonitorPersister::archived_key(&outpoint);

        let storage = self.storage_clone();
        let blob_opt = storage.get(&active_key).map_err(|e| {
            LijError::Node(format!(
                "purge_force_closed_monitor: storage.get({active_key}) failed: {e}"
            ))
        })?;

        match blob_opt {
            Some(blob) => {
                storage.set(&archived_key, &blob).map_err(|e| {
                    LijError::Node(format!(
                        "purge_force_closed_monitor: storage.set({archived_key}) failed: {e}"
                    ))
                })?;
                storage.delete(&active_key).map_err(|e| {
                    LijError::Node(format!(
                        "purge_force_closed_monitor: storage.delete({active_key}) failed: {e}"
                    ))
                })?;
                log::info!(
                    "purge_force_closed_monitor: archived {} -> {}",
                    active_key, archived_key
                );
                Ok(true)
            }
            None => {
                log::warn!(
                    "purge_force_closed_monitor: no active monitor at {}",
                    active_key
                );
                Ok(false)
            }
        }
    }
}

/// S45: blocks a pending cooperative close may wait before the wallet stops
/// holding LDK's commitment broadcast and lets the commitment go.
pub const COOP_HOLD_CEILING_BLOCKS: u32 = 144;

/// S45: blocks a cooperative close may sit in the mempool before the wallet
/// tries to pull it in with a CPFP child.
pub const COOP_CPFP_AFTER_BLOCKS: u32 = 3;

/// S45 (DP): the AUTOMATIC CPFP is a user dial (Dials → Speed up slow closes:
/// Off / Automatic), default OFF — a wallet action that spends the user's
/// coins is the user's decision. The manual Speed up button is always
/// available. Set from the page via `set_coop_cpfp_auto`.
pub static COOP_CPFP_AUTO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// S45: everything the CPFP needs, handed out so the work runs OUTSIDE the
/// wallet lock (network I/O).
pub struct CoopCpfpHandles {
    pub root_key: Arc<RootKey>,
    pub independent: Arc<IndependentClient>,
    pub network: Network,
    pub fee_estimator: Arc<LijFeeEstimator>,
    pub tip: u32,
    pub counter: u32,
}

/// S45: plan or send a CPFP child for one pending cooperative close.
/// `send == false` only computes (the button shows the fee before the tap);
/// `send == true` broadcasts. `force` skips the automatic mode's age and
/// spacing gates (the user's tap). Returns JSON:
/// {ok, can, reason, child_fee_sats, parent_rate_vb, target_vb, txid}.
pub async fn coop_cpfp(
    storage: Arc<dyn LijStorage>,
    h: CoopCpfpHandles,
    channel_id_hex: &str,
    send: bool,
    force: bool,
) -> LijResult<String> {
    let log = ClosedChannelLog::new(storage.clone());
    let r = log
        .list()?
        .into_iter()
        .find(|r| r.channel_id_hex == channel_id_hex)
        .ok_or_else(|| LijError::Node("no closed-channel record with that id".into()))?;
    let done = |ok: bool, can: bool, reason: &str, fee: u64, prate: u64, target: u64, txid: Option<String>| -> String {
        format!(
            "{{\"ok\":{},\"can\":{},\"reason\":\"{}\",\"child_fee_sats\":{},\"parent_rate_vb\":{},\"target_vb\":{},\"txid\":{}}}",
            ok, can, reason.replace('"', "'"), fee, prate, target,
            txid.map(|t| format!("\"{}\"", t)).unwrap_or_else(|| "null".to_string())
        )
    };
    if !matches!(r.kind, CloseKind::Cooperative) || r.coop_close_tx_hex.is_none() {
        return Ok(done(true, false, "not a cooperative close this wallet signed", 0, 0, 0, None));
    }
    if r.closing_confirmed {
        return Ok(done(true, false, "already confirmed", 0, 0, 0, None));
    }
    if let Some(t) = r.cpfp_txid_hex.clone() {
        return Ok(done(true, false, "a speed-up child was already sent", 0, 0, 0, Some(t)));
    }
    let age = h.tip.saturating_sub(r.close_seen_height.unwrap_or(h.tip));
    if !force {
        if !COOP_CPFP_AUTO.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(done(true, false, "automatic speed-up is off", 0, 0, 0, None));
        }
        if age < COOP_CPFP_AFTER_BLOCKS {
            return Ok(done(true, false, "too early", 0, 0, 0, None));
        }
        let last = r.cpfp_last_height.unwrap_or(0);
        if last != 0 && h.tip.saturating_sub(last) < 6 {
            return Ok(done(true, false, "spacing", 0, 0, 0, None));
        }
    }
    let parent = r
        .coop_close_tx_hex
        .as_deref()
        .and_then(|x| hex::decode(x).ok())
        .and_then(|b| bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&b).ok())
        .ok_or_else(|| LijError::Node("stored cooperative tx does not parse".into()))?;
    let mut found: Option<(u32, u32)> = None;
    if let Ok(scripts) = crate::onchain_send::receive_scripts(&h.root_key, h.network, h.counter.saturating_add(20)) {
        'outer: for (vi, o) in parent.output.iter().enumerate() {
            for (idx, spk) in scripts.iter() {
                if *spk == o.script_pubkey {
                    found = Some((vi as u32, *idx));
                    break 'outer;
                }
            }
        }
    }
    let out_sum: u64 = parent.output.iter().map(|o| o.value).sum();
    let parent_fee = r.channel_capacity_sats.unwrap_or(out_sum).saturating_sub(out_sum);
    let parent_vsize = parent.vsize() as u64;
    let parent_rate_vb = if parent_vsize > 0 { parent_fee / parent_vsize } else { 0 };
    let target_kw = h.fee_estimator.get_est_sat_per_1000_weight(lightning::chain::chaininterface::ConfirmationTarget::OnChainSweep);
    let target_vb = ((target_kw as u64) + 249) / 250;
    let Some((vout, idx)) = found else {
        return Ok(done(true, false, "no output of ours in the cooperative tx", 0, parent_rate_vb, target_vb, None));
    };
    let out_value = parent.output[vout as usize].value;
    let child_vsize: u64 = 11 + 68 + 31;
    let child_fee = (target_vb * (parent_vsize + child_vsize))
        .saturating_sub(parent_fee)
        .max(child_vsize * target_vb);
    if out_value <= child_fee + crate::onchain_send::DUST_THRESHOLD_SATS {
        return Ok(done(true, false, "the output is too small to fund a speed-up", child_fee, parent_rate_vb, target_vb, None));
    }
    if !force && target_vb <= parent_rate_vb + parent_rate_vb / 4 + 1 {
        return Ok(done(true, false, "not needed at the current fee rate", child_fee, parent_rate_vb, target_vb, None));
    }
    if !send {
        return Ok(done(true, true, "ready", child_fee, parent_rate_vb, target_vb, None));
    }
    let _ = log.update_by_channel_id(&r.channel_id_hex, |rec| { rec.cpfp_last_height = Some(h.tip); });
    match crate::onchain_send::build_and_send_cpfp(&h.root_key, h.independent.clone(), &parent, vout, parent_fee, idx, target_kw).await {
        Ok((child, fee)) => {
            let child_c = child.clone();
            let _ = log.update_by_channel_id(&r.channel_id_hex, |rec| { rec.cpfp_txid_hex = Some(child_c.clone()); });
            log::info!("coop-cpfp: {} child {} sent (fee {fee}; parent {parent_rate_vb} sat/vB, target {target_vb}, forced={force})", &r.channel_id_hex[..12.min(r.channel_id_hex.len())], &child[..12.min(child.len())]);
            Ok(done(true, true, "sent", fee, parent_rate_vb, target_vb, Some(child)))
        }
        Err(e) => Ok(done(false, true, &format!("send failed: {e}"), child_fee, parent_rate_vb, target_vb, None)),
    }
}

/// S45: maintenance of the cooperative-close hold (see `lij_coop_hold` in the
/// vendored LDK). For every Cooperative record whose closing tx has not
/// confirmed: confirmed spend → record the ACTUAL closing txid (relabel Force
/// if it is our own commitment) and release; spend pending in the mempool →
/// keep holding; no spend visible → rebroadcast our cooperative tx; past the
/// ceiling → release the hold and broadcast the holder commitment ourselves.
#[cfg(target_arch = "wasm32")]
async fn coop_hold_maintain(
    storage: Arc<dyn LijStorage>,
    indep: Arc<IndependentClient>,
    bc: Arc<LijBroadcaster>,
    fee: Arc<LijFeeEstimator>,
    cm: Option<Arc<LijChainMonitor>>,
    tip: u32,
    root_key: Arc<RootKey>,
    network: Network,
    counter: u32,
) {
    use lightning::chain::channelmonitor::lij_coop_hold;
    let log = ClosedChannelLog::new(storage.clone());
    let records = match log.list() {
        Ok(r) => r,
        Err(_) => return,
    };
    for r in records.into_iter().filter(|r| {
        matches!(r.kind, CloseKind::Cooperative)
            && r.coop_close_tx_hex.is_some()
            && !r.closing_confirmed
            && !r.hold_released
    }) {
        let Some(ftxo) = r.funding_txo_hex.clone() else { continue };
        let mut parts = ftxo.split(':');
        let Some(ftxid_hex) = parts.next() else { continue };
        let vout: u32 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let Ok(funding_txid) = ftxid_hex.parse::<bitcoin::Txid>() else { continue };
        let short = &r.channel_id_hex[..12.min(r.channel_id_hex.len())];
        let age = tip.saturating_sub(r.close_seen_height.unwrap_or(tip));
        let spends = match indep.fetch_tx_outspends(ftxid_hex).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("coop-hold: {short}: outspends unavailable ({e}); keeping the hold");
                continue;
            }
        };
        let spend = spends.get(vout as usize).cloned();
        let (spent_by, confirmed) = match spend {
            Some(sp) if sp.spent => (
                sp.txid.clone(),
                sp.status.as_ref().map(|st| st.confirmed).unwrap_or(false),
            ),
            _ => (None, false),
        };
        if let (Some(stxid), true) = (spent_by.as_ref(), confirmed) {
            // ACTUAL: a spend confirmed. Record it, relabel if it is our commitment, release.
            let ours = r.holder_commitment_txid_hex.as_deref() == Some(stxid.as_str());
            let stxid_c = stxid.clone();
            let _ = log.update_by_channel_id(&r.channel_id_hex, |rec| {
                rec.closing_txid_hex = Some(stxid_c.clone());
                rec.closing_confirmed = true;
                if ours {
                    rec.kind = CloseKind::Force;
                    rec.reason_description = format!(
                        "force close from this wallet: the cooperative close did not confirm and the wallet's commitment took its place (was: {})",
                        rec.reason_description
                    );
                }
            });
            lij_coop_hold::remove(&funding_txid);
            log::info!("coop-hold: {short}: funding spent by {} (confirmed, ours_commitment={ours}); hold released", &stxid[..12.min(stxid.len())]);
            continue;
        }
        if age >= COOP_HOLD_CEILING_BLOCKS {
            // Ceiling: stop waiting. Release the hold and let the commitment go.
            let outpoint = lightning::chain::transaction::OutPoint { txid: funding_txid, index: vout as u16 };
            let mut broadcast = false;
            if let Some(cm) = cm.as_ref() {
                if let Ok(monitor) = cm.get_monitor(outpoint) {
                    let logger = std::sync::Arc::new(LijLogger);
                    monitor.broadcast_latest_holder_commitment_txn(&bc, &fee, &logger);
                    broadcast = true;
                }
            }
            lij_coop_hold::remove(&funding_txid);
            let _ = log.update_by_channel_id(&r.channel_id_hex, |rec| {
                rec.hold_released = true;
            });
            log::warn!("coop-hold: {short}: cooperative close unconfirmed after {age} blocks (ceiling {COOP_HOLD_CEILING_BLOCKS}); hold released, commitment broadcast={broadcast}");
            continue;
        }
        match spent_by {
            Some(stxid) => {
                // INTENDED: pending in the mempool. Keep holding; make sure the record names it.
                if r.closing_txid_hex.as_deref() != Some(stxid.as_str()) {
                    let stxid_c = stxid.clone();
                    let _ = log.update_by_channel_id(&r.channel_id_hex, |rec| {
                        rec.closing_txid_hex = Some(stxid_c.clone());
                    });
                }
                log::info!("coop-hold: {short}: cooperative close {} pending in the mempool ({age} blocks); holding", &stxid[..12.min(stxid.len())]);
                // S45 CPFP (DP: a user dial, default OFF; the manual Speed up lives on the
                // on-chain face): the shared coop_cpfp() applies the automatic gates.
                let h = CoopCpfpHandles { root_key: root_key.clone(), independent: indep.clone(), network, fee_estimator: fee.clone(), tip, counter };
                match coop_cpfp(storage.clone(), h, &r.channel_id_hex, true, false).await {
                    Ok(j) => log::info!("coop-hold: {short}: automatic speed-up → {j}"),
                    Err(e) => log::warn!("coop-hold: {short}: automatic speed-up errored: {e}"),
                }
            }
            None => {
                // Not visible: rebroadcast our cooperative tx.
                if let Ok(raw) = hex::decode(r.coop_close_tx_hex.as_deref().unwrap_or("")) {
                    let txid_hex = r.closing_txid_hex.clone().unwrap_or_default();
                    bc.enqueue_raw(raw, txid_hex);
                    log::warn!("coop-hold: {short}: cooperative close not visible on-chain or in the mempool ({age} blocks); rebroadcast");
                }
            }
        }
    }
}
