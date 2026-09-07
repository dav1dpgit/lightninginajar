// fee_estimator.rs
// Replaces StaticFeeEstimator. Implements LDK's FeeEstimator interface.
//
// Architecture (per Phase4_chain_data_trust_model_v1.md §7):
//   - Cooperative path PRIMARY: LSP-quoted fee rates. Fast, accurate to
//     what the LSP will actually charge. LDK reads from cache.
//   - Independent path CROSS-CHECK: Esplora-quorum median at jittered
//     30–45 min cadence. Compared to cooperative; persistent disagreement
//     beyond tolerance window → soft escalation (flag for status panel).
//   - Tolerance window: 25% deviation triggers escalation.
//   - SOFT escalation only — fee disagreement is often legitimate
//     (different mempool views), unlike block-height disagreement which
//     is adversarial.
//
// LDK interface constraint:
//   FeeEstimator::get_est_sat_per_1000_weight is SYNCHRONOUS. We can't
//   await network calls inside it. Resolution: cache last-known values
//   per ConfirmationTarget; refresh cycle runs in background_tick.
//
// Step 2 status:
//   - Cache + read path: REAL.
//   - Cooperative refresh: TRAIT DEFINED, implementation deferred to step 4.
//   - Independent refresh: TRAIT DEFINED, implementation deferred to step 5.
//   - Cross-check + escalation flag: REAL (logic verified by tests).
//   - Pre-payment force-refresh hook: REAL (`force_refresh_independent`).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use serde::{Deserialize, Serialize};

use crate::error::LijResult;

/// Type alias matching the one in broadcaster.rs. Defined locally to
/// avoid cross-module coupling for a 1-line type.
type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Floor used when no source has ever reported. 253 sat/1000-weight ≈ 1 sat/vB,
/// the network minimum. LDK can build txs but they won't confirm fast.
/// Better than 0 (which would cause LDK to construct unconfirmable txs).
const FEE_FLOOR_SAT_PER_KW: u32 = 253;

/// Cooperative-close ACCEPT floor — deliberately BELOW relay min.
///
/// This governs only the lowest counter the wallet will accept (and the floor
/// of the range it proposes) during coop-close fee negotiation; it does NOT
/// set the fee the close actually pays — that is the negotiated value, which
/// in the LiJ topology is the LSP's. LND-based LSPs routinely propose
/// sub-1-sat/vB coop-close fees (observed: 139 sat ≈ 0.77 sat/vB). With the
/// old FEE_FLOOR-pinned min (253 sat/kW ≈ 182 sat on a ~720-wu close tx) the
/// wallet rejected anything under 1 sat/vB and LDK fell back to a force close.
/// A LiJ wallet trusts its single LSP and treats coop closes as non-urgent, so
/// it DEFERS: accept whatever the LSP negotiates. The LSP broadcasts the close
/// via the cooperative path and will not propose an unconfirmable fee, so a
/// sub-relay-min accept floor here is safe. Non-zero to avoid a degenerate
/// 0-fee initial proposal. (v40 — fixes the 182-vs-139 force-close fallback.)
const COOP_CLOSE_ACCEPT_FLOOR_SAT_PER_KW: u32 = 25;

/// Tolerance window for soft escalation. If independent's median is more
/// than this fraction BELOW cooperative's quote, the LSP is plausibly
/// overcharging and we flag it. Above-cooperative independent answers
/// are normal (different mempool views) and don't escalate.
const ESCALATION_THRESHOLD_PCT: u32 = 25;

/// How long before a cached value is considered stale enough to warrant
/// fresh refresh on payment. Per §7c, payments larger than 1M sats OR
/// cache older than this trigger force-refresh.
pub const CACHE_FRESH_DURATION: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Fee rates indexed by ConfirmationTarget. Stored as sat per 1000 weight
/// (LDK's native unit). Mirrors LDK's enum variants.
///
/// LDK 0.0.123 ConfirmationTarget variants we care about:
///   MinAllowedAnchorChannelRemoteFee
///   MinAllowedNonAnchorChannelRemoteFee
///   AnchorChannelFee
///   NonAnchorChannelFee
///   ChannelCloseMinimum
///   OnChainSweep
///   OutputSpendingFee
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub min_allowed_anchor_channel_remote: u32,
    pub min_allowed_non_anchor_channel_remote: u32,
    pub anchor_channel: u32,
    pub non_anchor_channel: u32,
    pub channel_close_minimum: u32,
    pub on_chain_sweep: u32,
    pub output_spending: u32,
}

impl FeeQuote {
    /// Build a FeeQuote from a single sat-per-vbyte fast-rate value.
    /// Used when the source returns one number rather than a per-target schedule.
    /// Conservative scaling: faster targets get higher fees, slower ones get lower.
    pub fn from_fast_sat_per_vb(fast_sat_per_vb: u32) -> Self {
        let kw = |sat_per_vb: u32| sat_per_vb.saturating_mul(250);
        let fast_kw = kw(fast_sat_per_vb);
        // Scale down for slower confirmations. These ratios are reasonable
        // defaults; an LSP that wants finer control can return its own
        // FeeQuote directly.
        Self {
            // v177 (T-OPEN-1 root cause): the two MinAllowed*RemoteFee
            // targets are ACCEPT THRESHOLDS for the counterparty's proposed
            // commitment feerate — never a fee we pay. Scaling them off the
            // fast rate (old: fast/4 and fast/2) turned a dormant sub-1-sat
            // mempool into a rejection: LND honestly proposed the 253 sat/kw
            // relay floor for the first no-anchors JIT open and LDK's
            // check_remote_fee refused it ("Actual: 253. Our expected lower
            // limit: 3750" — desk evidence, 2026-07-12). Same class of bug
            // as v40's coop-close accept floor. A trusted-LSP wallet accepts
            // any relay-valid commitment feerate: in life update_fee keeps
            // the rate current; a low initial rate only slows a hypothetical
            // day-one force close, never loses funds. LDK lower-bounds reads
            // at 253 anyway, so the floor is the minimum expressible.
            min_allowed_anchor_channel_remote: FEE_FLOOR_SAT_PER_KW,
            min_allowed_non_anchor_channel_remote: FEE_FLOOR_SAT_PER_KW,
            anchor_channel: kw(fast_sat_per_vb / 4).max(FEE_FLOOR_SAT_PER_KW),
            non_anchor_channel: kw(fast_sat_per_vb).max(FEE_FLOOR_SAT_PER_KW),
            // Coop-close accept floor. Sub-relay-min so the wallet accepts the
            // LSP's negotiated close fee (e.g. ~139 sat ≈ 0.77 sat/vB) instead
            // of rejecting it and force-closing. The final fee is the
            // negotiated (LSP) value, not this floor. (v40 — supersedes the
            // v39 no-op, which set this to FEE_FLOOR where .max() already
            // pinned it, leaving the 182-sat min that rejected 139.)
            channel_close_minimum: COOP_CLOSE_ACCEPT_FLOOR_SAT_PER_KW,
            on_chain_sweep: fast_kw.max(FEE_FLOOR_SAT_PER_KW),
            output_spending: fast_kw.saturating_mul(3).max(FEE_FLOOR_SAT_PER_KW),
        }
    }

    fn floor() -> Self {
        Self {
            min_allowed_anchor_channel_remote: FEE_FLOOR_SAT_PER_KW,
            min_allowed_non_anchor_channel_remote: FEE_FLOOR_SAT_PER_KW,
            anchor_channel: FEE_FLOOR_SAT_PER_KW,
            non_anchor_channel: FEE_FLOOR_SAT_PER_KW,
            channel_close_minimum: COOP_CLOSE_ACCEPT_FLOOR_SAT_PER_KW,
            on_chain_sweep: FEE_FLOOR_SAT_PER_KW,
            output_spending: FEE_FLOOR_SAT_PER_KW,
        }
    }

    /// Look up the rate for a given LDK ConfirmationTarget.
    pub fn get(&self, target: ConfirmationTarget) -> u32 {
        match target {
            ConfirmationTarget::MinAllowedAnchorChannelRemoteFee => {
                self.min_allowed_anchor_channel_remote
            }
            ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => {
                self.min_allowed_non_anchor_channel_remote
            }
            ConfirmationTarget::AnchorChannelFee => self.anchor_channel,
            ConfirmationTarget::NonAnchorChannelFee => self.non_anchor_channel,
            ConfirmationTarget::ChannelCloseMinimum => self.channel_close_minimum,
            ConfirmationTarget::OnChainSweep => self.on_chain_sweep,
            ConfirmationTarget::OutputSpendingFee => self.output_spending,
        }
    }
}

/// Cooperative fee source — LSP-quoted. Implementation deferred to step 4.
pub trait CooperativeFeeSource {
    /// Fetch the current fee schedule from the LSP. Wallet calls this on
    /// connect and in response to LSP-pushed fee updates over BOLT 8.
    fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>>;

    fn is_available(&self) -> bool;
}

/// Independent fee source — Esplora-quorum median. Implementation deferred to step 5.
///
/// Quorum semantics for fee estimation:
/// - Query all configured Esplora endpoints in parallel
/// - Take the median across responding endpoints (robust to outliers)
/// - Tolerance window applies between cooperative and this median
pub trait IndependentFeeSource {
    /// Fetch median fee schedule across the Esplora quorum.
    fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>>;

    fn is_available(&self) -> bool;
}

/// Internal cache state — what LDK reads from synchronously.
struct CachedQuotes {
    /// Last cooperative-path response. None = never received.
    cooperative: Option<FeeQuote>,
    /// Last independent-path response. None = never received.
    independent: Option<FeeQuote>,
    /// Tick at which cooperative was last refreshed. Used to gauge staleness.
    cooperative_refreshed_at_tick: Option<u64>,
    /// Tick at which independent was last refreshed.
    independent_refreshed_at_tick: Option<u64>,
    /// v182: last persisted quote, loaded at boot — a prior served after
    /// live sources and before the floor. Closes the boot window where a
    /// floor read clamped capacity on any channel whose negotiated
    /// feerate exceeded 253 (the Sendable-opens-low symptom).
    persisted: Option<FeeQuote>,
    /// v182: memo of the last snapshot handed to the persister; writes
    /// happen only when the live quote differs from this.
    last_persist_snapshot: Option<FeeQuote>,
    /// Set when cooperative quote exceeds independent median by more than
    /// ESCALATION_THRESHOLD_PCT. Read by status panel; cleared on agreement.
    soft_escalation_active: bool,
}

impl CachedQuotes {
    fn new() -> Self {
        Self {
            cooperative: None,
            independent: None,
            cooperative_refreshed_at_tick: None,
            independent_refreshed_at_tick: None,
            persisted: None,
            last_persist_snapshot: None,
            soft_escalation_active: false,
        }
    }
}

/// LDK-facing fee estimator with cooperative-primary + independent-cross-check.
pub struct LijFeeEstimator {
    cache: Mutex<CachedQuotes>,
    cooperative: Mutex<Option<Arc<dyn CooperativeFeeSource + Send + Sync>>>,
    independent: Mutex<Option<Arc<dyn IndependentFeeSource + Send + Sync>>>,
}

impl LijFeeEstimator {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(CachedQuotes::new()),
            cooperative: Mutex::new(None),
            independent: Mutex::new(None),
        }
    }

    pub fn set_cooperative(
        &self,
        cooperative: Arc<dyn CooperativeFeeSource + Send + Sync>,
    ) {
        *self.cooperative.lock().unwrap() = Some(cooperative);
    }

    pub fn set_independent(
        &self,
        independent: Arc<dyn IndependentFeeSource + Send + Sync>,
    ) {
        *self.independent.lock().unwrap() = Some(independent);
    }

    /// Refresh from cooperative path. Called on LSP connect, after BOLT 8
    /// fee_update push, and on every cooperative spot-check tick.
    pub async fn refresh_cooperative(&self, current_tick: u64) -> LijResult<()> {
        let coop_opt = self.cooperative.lock().unwrap().clone();
        let coop = match coop_opt {
            Some(c) if c.is_available() => c,
            _ => return Ok(()), // no source wired or unavailable
        };
        match coop.fetch().await {
            Ok(quote) => {
                let mut cache = self.cache.lock().unwrap();
                cache.cooperative = Some(quote);
                cache.cooperative_refreshed_at_tick = Some(current_tick);
                Self::reevaluate_escalation(&mut cache);
                log::debug!("fee_estimator: cooperative refreshed at tick {current_tick}");
                Ok(())
            }
            Err(e) => {
                log::warn!("fee_estimator: cooperative refresh failed: {e}");
                Err(e)
            }
        }
    }

    /// Refresh from independent path. Called at jittered 30–45 min cadence
    /// and on force_refresh_independent().
    pub async fn refresh_independent(&self, current_tick: u64) -> LijResult<()> {
        let indep_opt = self.independent.lock().unwrap().clone();
        let indep = match indep_opt {
            Some(i) if i.is_available() => i,
            _ => return Ok(()),
        };
        match indep.fetch().await {
            Ok(quote) => {
                let mut cache = self.cache.lock().unwrap();
                cache.independent = Some(quote);
                cache.independent_refreshed_at_tick = Some(current_tick);
                Self::reevaluate_escalation(&mut cache);
                log::debug!("fee_estimator: independent refreshed at tick {current_tick}");
                Ok(())
            }
            Err(e) => {
                log::warn!("fee_estimator: independent refresh failed: {e}");
                Err(e)
            }
        }
    }

    /// Force fresh independent check. Called by send-payment path when
    /// payment > 1M sats OR cooperative cache > 1h old. Non-blocking from
    /// LDK's perspective — the FeeEstimator interface still reads cached
    /// cooperative; this just triggers a background refresh whose result
    /// will be available on the next call.
    pub async fn force_refresh_independent(&self, current_tick: u64) -> LijResult<()> {
        self.refresh_independent(current_tick).await
    }

    /// v182: boot-seed from the persisted quote (the node loads it from
    /// storage at construction). Live sources always win over this.
    pub fn seed_persisted(&self, quote: FeeQuote) {
        self.cache.lock().unwrap().persisted = Some(quote);
    }

    /// v182: the current best live quote (cooperative else independent),
    /// returned only when it differs from the last snapshot handed out —
    /// the node persists exactly these, so storage writes (which ride
    /// the KV auto-backup) happen on market movement only.
    pub fn snapshot_if_changed(&self) -> Option<FeeQuote> {
        let mut cache = self.cache.lock().unwrap();
        let cur = cache.cooperative.clone().or_else(|| cache.independent.clone())?;
        if cache.last_persist_snapshot.as_ref() == Some(&cur) {
            return None;
        }
        cache.last_persist_snapshot = Some(cur.clone());
        Some(cur)
    }

    /// Read whether soft escalation is currently active. Status panel
    /// uses this to color the fee-row dot.
    pub fn is_soft_escalation_active(&self) -> bool {
        self.cache.lock().unwrap().soft_escalation_active
    }

    /// Cooperative cache age in ticks. None if never refreshed.
    pub fn cooperative_age_ticks(&self, current_tick: u64) -> Option<u64> {
        self.cache
            .lock()
            .unwrap()
            .cooperative_refreshed_at_tick
            .map(|t| current_tick.saturating_sub(t))
    }

    /// Recompute soft_escalation_active from current cache contents.
    /// Called whenever either cooperative or independent updates.
    fn reevaluate_escalation(cache: &mut CachedQuotes) {
        let (coop, indep) = match (&cache.cooperative, &cache.independent) {
            (Some(c), Some(i)) => (c, i),
            _ => {
                // Need both sources to compare; clear any prior flag
                cache.soft_escalation_active = false;
                return;
            }
        };
        // Use NonAnchorChannelFee as the comparison target — it's the
        // "normal payment" fee and most representative of routine ops.
        let coop_rate = coop.non_anchor_channel;
        let indep_rate = indep.non_anchor_channel;
        if coop_rate == 0 {
            cache.soft_escalation_active = false;
            return;
        }
        // Escalate if cooperative is meaningfully ABOVE independent.
        // Below or equal is fine — LSP isn't overcharging.
        if coop_rate > indep_rate {
            let pct_above = ((coop_rate - indep_rate) as u64 * 100) / coop_rate as u64;
            let threshold = ESCALATION_THRESHOLD_PCT as u64;
            let new_state = pct_above >= threshold;
            if new_state != cache.soft_escalation_active {
                if new_state {
                    log::warn!(
                        "fee_estimator: SOFT ESCALATION — cooperative {} sat/kw vs independent median {} sat/kw ({pct_above}% above)",
                        coop_rate, indep_rate
                    );
                } else {
                    log::info!(
                        "fee_estimator: escalation cleared — cooperative {} sat/kw vs independent median {} sat/kw",
                        coop_rate, indep_rate
                    );
                }
            }
            cache.soft_escalation_active = new_state;
        } else {
            cache.soft_escalation_active = false;
        }
    }
}

impl LijFeeEstimator {
    /// v165 (#29-4a): one-shot summary for the wallet's fee speed picker.
    /// `fast` is the NonAnchorChannelFee read — cooperative-first, i.e. the
    /// exact number LDK itself pays — so the picker can never disagree with
    /// the engine. Source names which cache answered; escalation mirrors the
    /// status-panel flag (LSP quote >25% above the independent median).
    pub fn picker_summary(&self) -> (u32, &'static str, bool) {
        let cache = self.cache.lock().unwrap();
        let (kw, src) = if let Some(ref c) = cache.cooperative {
            (c.get(ConfirmationTarget::NonAnchorChannelFee), "lsp")
        } else if let Some(ref i) = cache.independent {
            (i.get(ConfirmationTarget::NonAnchorChannelFee), "esplora")
        } else if let Some(ref s) = cache.persisted {
            (s.get(ConfirmationTarget::NonAnchorChannelFee), "seed")
        } else {
            (FeeQuote::floor().get(ConfirmationTarget::NonAnchorChannelFee), "floor")
        };
        (kw, src, cache.soft_escalation_active)
    }
}

impl FeeEstimator for LijFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        let cache = self.cache.lock().unwrap();
        // Cooperative is authoritative for what LDK reads. Independent is
        // a cross-check, not a substitute. If cooperative is missing, fall
        // through to independent. If both missing, floor.
        if let Some(ref coop) = cache.cooperative {
            return coop.get(target);
        }
        if let Some(ref indep) = cache.independent {
            return indep.get(target);
        }
        // v182: the persisted prior — yesterday's ambient beats the relay
        // floor; live sources above overrule it the moment they land.
        if let Some(ref seed) = cache.persisted {
            return seed.get(target);
        }
        FeeQuote::floor().get(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LijError;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct StaticCoop {
        quote: FeeQuote,
    }
    impl CooperativeFeeSource for StaticCoop {
        fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>> {
            let q = self.quote.clone();
            Box::pin(async move { Ok(q) })
        }
        fn is_available(&self) -> bool { true }
    }

    struct StaticIndep {
        quote: FeeQuote,
    }
    impl IndependentFeeSource for StaticIndep {
        fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>> {
            let q = self.quote.clone();
            Box::pin(async move { Ok(q) })
        }
        fn is_available(&self) -> bool { true }
    }

    struct FailingIndep {
        calls: AtomicU32,
    }
    impl IndependentFeeSource for FailingIndep {
        fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Err(LijError::Storage("indep down".into())) })
        }
        fn is_available(&self) -> bool { true }
    }

    #[tokio::test]
    async fn no_sources_returns_floor() {
        let fe = LijFeeEstimator::new();
        let rate = fe.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
        assert_eq!(rate, FEE_FLOOR_SAT_PER_KW);
        assert!(!fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn cooperative_only_drives_ldk_reads() {
        let fe = LijFeeEstimator::new();
        // 32 sat/vB fast → 32 * 250 = 8000 sat/kw for non-anchor channel
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(32),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        let rate = fe.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
        assert_eq!(rate, 32 * 250);
        // No independent → no escalation possible
        assert!(!fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn independent_below_cooperative_within_tolerance_no_escalation() {
        let fe = LijFeeEstimator::new();
        // Cooperative 32, independent 28 → 12.5% above → below 25% threshold
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(32),
        }));
        fe.set_independent(Arc::new(StaticIndep {
            quote: FeeQuote::from_fast_sat_per_vb(28),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        fe.refresh_independent(1).await.unwrap();
        assert!(!fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn independent_well_below_cooperative_triggers_escalation() {
        let fe = LijFeeEstimator::new();
        // Cooperative 40, independent 20 → 50% above → above 25% threshold
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(40),
        }));
        fe.set_independent(Arc::new(StaticIndep {
            quote: FeeQuote::from_fast_sat_per_vb(20),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        fe.refresh_independent(1).await.unwrap();
        assert!(fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn independent_above_cooperative_no_escalation() {
        let fe = LijFeeEstimator::new();
        // LSP charging 20, network thinks 40 — LSP under-charging is fine,
        // not a reason to escalate. Could even be marketplace competition.
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(20),
        }));
        fe.set_independent(Arc::new(StaticIndep {
            quote: FeeQuote::from_fast_sat_per_vb(40),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        fe.refresh_independent(1).await.unwrap();
        assert!(!fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn escalation_clears_when_independent_recovers() {
        let fe = LijFeeEstimator::new();
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(40),
        }));
        // Start with bad independent → escalation
        fe.set_independent(Arc::new(StaticIndep {
            quote: FeeQuote::from_fast_sat_per_vb(20),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        fe.refresh_independent(1).await.unwrap();
        assert!(fe.is_soft_escalation_active());
        // Replace independent source with one in tolerance
        fe.set_independent(Arc::new(StaticIndep {
            quote: FeeQuote::from_fast_sat_per_vb(35),
        }));
        fe.refresh_independent(2).await.unwrap();
        assert!(!fe.is_soft_escalation_active());
    }

    #[tokio::test]
    async fn cache_age_tracking_works() {
        let fe = LijFeeEstimator::new();
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(20),
        }));
        assert_eq!(fe.cooperative_age_ticks(100), None);
        fe.refresh_cooperative(50).await.unwrap();
        assert_eq!(fe.cooperative_age_ticks(100), Some(50));
        assert_eq!(fe.cooperative_age_ticks(50), Some(0));
    }

    #[tokio::test]
    async fn independent_failure_does_not_corrupt_cache() {
        let fe = LijFeeEstimator::new();
        fe.set_cooperative(Arc::new(StaticCoop {
            quote: FeeQuote::from_fast_sat_per_vb(20),
        }));
        fe.set_independent(Arc::new(FailingIndep {
            calls: AtomicU32::new(0),
        }));
        fe.refresh_cooperative(1).await.unwrap();
        let _ = fe.refresh_independent(1).await; // intentionally fails
        // Cooperative still drives LDK reads
        let rate = fe.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
        assert_eq!(rate, 20 * 250);
        assert!(!fe.is_soft_escalation_active()); // no independent data to compare against
    }
}
