// cold_start.rs
//
// Step 6d — Cold-start orchestrator.
// Per Phase4_chain_data_trust_model_v1.md §6.
//
// Runs the t=0 → t=30s cold-start sequence:
//   t=0:    Initializing — local state read, no chain data yet
//   t=0-2s: cooperative path subscribes (handled by node.rs::connect_lsp)
//   t=0-5s: wait for ChainDataBundle from LSP
//   t=5-30s: independent path queries tip-height + priority scan
//   t=30s:  decide Ready / ReadOnly / Frozen
//
// Architecture:
//   The orchestrator is a function called from background_tick once per
//   second. On each call it inspects:
//     - Cooperative cache (is subscribed? last_block_height?)
//     - Independent client state (healthy_count, last_quorum_state)
//     - Priority scan results (any unresolved critical funding txids?)
//   And decides whether to advance state.
//
// State transitions (forward):
//   Initializing → Syncing       (when first tick happens)
//   Syncing → Ready              (cooperative + independent agree, no critical)
//   Syncing → ReadOnly           (independent unavailable past timeout)
//   Syncing → Frozen             (both paths broken past timeout)
//
// State transitions (degradation, can happen any time after Ready):
//   Ready → ReadOnly             (independent path becomes unavailable)
//   Ready → Frozen               (both paths broken)
//   ReadOnly → Ready             (independent recovers)
//   ReadOnly → Frozen            (cooperative also fails)
//   Frozen → Ready / ReadOnly    (paths recover)
//
// What this file does NOT do:
//   - Wire LSP-served funding-tx confirmations into LDK's Confirm trait.
//     The cooperative bridge already records FundingTxConfirmed messages
//     but routing them to cm.transactions_confirmed() is a step 8
//     concern (when send/receive needs working channels).
//   - Independent verification of priority funding txids actually returning
//     real data — the stub HTTP backend returns errors, so independent
//     verification will report "insufficient endpoints" until step 8 lands.
//     The orchestrator handles this gracefully: with stub HTTP, it will
//     converge to ReadOnly state, which is the architecturally-correct
//     answer ("we have cooperative chain data but no independent verify").

use std::sync::Mutex;

use crate::cooperative_chain_bridge::CooperativeChainBridge;
use crate::independent::{IndependentClient, QuorumState};
use crate::sync_state::{SyncState, SyncStateTracker};

/// Cold-start budget windows in ticks (seconds).
/// Per design doc §6 timeline.
mod timing {
    /// After this many ticks of Initializing, transition to Syncing automatically.
    pub const INITIALIZING_GRACE_TICKS: u64 = 1;
    /// Target for cooperative-path completion. Past this, log warning.
    pub const COOPERATIVE_TARGET_TICKS: u64 = 5;
    /// Target for independent-path completion. Past this without success,
    /// transition to ReadOnly.
    pub const INDEPENDENT_TARGET_TICKS: u64 = 30;
    /// Past this with both paths broken, transition to Frozen.
    pub const BOTH_BROKEN_TIMEOUT_TICKS: u64 = 60;
}

/// How close cooperative and independent block heights need to be to count
/// as "agreement" per design doc §6 ("within 2 blocks of actual tip").
pub const HEIGHT_AGREEMENT_TOLERANCE: u32 = 2;

/// Orchestrator state. Tracked separately from SyncStateTracker because
/// the orchestrator needs to know when sync started (for budget timeouts).
pub struct ColdStartOrchestrator {
    /// Tick at which cold-start began. None = not started.
    started_at_tick: Mutex<Option<u64>>,
    /// Last cooperative-cache tip height we observed (for change detection).
    last_seen_cooperative_height: Mutex<Option<u32>>,
    /// Last independent tip height we observed.
    last_seen_independent_height: Mutex<Option<u32>>,
    /// Whether we've completed at least one full evaluation cycle.
    /// Used to avoid declaring Ready on a tick where independent hasn't
    /// even been queried yet.
    independent_queried_once: Mutex<bool>,
}

impl ColdStartOrchestrator {
    pub fn new() -> Self {
        Self {
            started_at_tick: Mutex::new(None),
            last_seen_cooperative_height: Mutex::new(None),
            last_seen_independent_height: Mutex::new(None),
            independent_queried_once: Mutex::new(false),
        }
    }

    /// Reset orchestrator state. Called when the wallet reconnects after
    /// an extended disconnect, so cold-start budgets restart.
    pub fn reset(&self, current_tick: u64) {
        *self.started_at_tick.lock().unwrap() = Some(current_tick);
        *self.last_seen_cooperative_height.lock().unwrap() = None;
        *self.last_seen_independent_height.lock().unwrap() = None;
        *self.independent_queried_once.lock().unwrap() = false;
        log::info!("cold_start: orchestrator reset at tick {current_tick}");
    }

    /// One tick of orchestration. Called from background_tick.
    ///
    /// This is the state machine. It reads current cache contents and
    /// quorum state, decides whether to transition, and posts the new
    /// state to the SyncStateTracker.
    ///
    /// `current_tick`: the wallet's monotonic tick counter.
    /// `cooperative`: bridge holding the cooperative-cache state.
    /// `independent`: independent client for quorum state inspection.
    /// `cooperative_height`: current cooperative-cached block height (read
    ///                       from bridge; passed in to keep the orchestrator
    ///                       free of bridge-internals details).
    pub fn tick(
        &self,
        current_tick: u64,
        sync_state: &SyncStateTracker,
        cooperative_subscribed: bool,
        cooperative_height: Option<u32>,
        independent: &IndependentClient,
    ) {
        // Lazy-initialize started_at on first tick
        let started_at = {
            let mut s = self.started_at_tick.lock().unwrap();
            if s.is_none() {
                *s = Some(current_tick);
            }
            s.unwrap()
        };
        let elapsed = current_tick.saturating_sub(started_at);

        let current_state = sync_state.current();

        // Update height-tracking caches for change detection.
        if let Some(h) = cooperative_height {
            *self.last_seen_cooperative_height.lock().unwrap() = Some(h);
        }

        let healthy = independent.healthy_count();
        let quorum = independent.last_quorum_state();
        let independent_queried = *self.independent_queried_once.lock().unwrap();

        // Decide transitions
        let new_state = self.decide_state(
            current_state,
            elapsed,
            cooperative_subscribed,
            cooperative_height,
            healthy,
            quorum,
            independent_queried,
        );

        // v115: evaluate to a FIXPOINT within this tick. The machine used to
        // advance at most one state per 1s tick, so a fully-ready boot still
        // walked Initializing → Syncing → Ready across two tick boundaries
        // (~2s of chain-amber with every condition already true — measured on
        // device, boot-profile tables, Session 17). Inputs are fixed within
        // the tick and decide_state is deterministic on fixed inputs, so the
        // loop reaches a stable state in ≤3 hops; the guard is belt-and-
        // braces. Grace periods are elapsed-based and unaffected.
        let mut state = current_state;
        for _ in 0..4 {
            let next = self.decide_state(
                state,
                elapsed,
                cooperative_subscribed,
                cooperative_height,
                healthy,
                quorum,
                independent_queried,
            );
            if next == state { break; }
            log::info!(
                "cold_start: tick={} elapsed={} {} → {} (coop_sub={}, coop_h={:?}, healthy={}, quorum={:?})",
                current_tick,
                elapsed,
                state.display(),
                next.display(),
                cooperative_subscribed,
                cooperative_height,
                healthy,
                quorum,
            );
            sync_state.set(next);
            state = next;
        }
    }

    /// Mark that the independent path has been queried at least once this
    /// cold-start cycle. Called from the orchestrator's tick caller when
    /// it actually fires off an independent fetch (so we know at next tick
    /// whether to wait or transition).
    pub fn mark_independent_queried(&self, height_returned: Option<u32>) {
        *self.independent_queried_once.lock().unwrap() = true;
        if let Some(h) = height_returned {
            *self.last_seen_independent_height.lock().unwrap() = Some(h);
        }
    }

    /// Pure decision function. Given a state snapshot, what state should
    /// the wallet be in? Tested independently from the orchestrator.
    fn decide_state(
        &self,
        current: SyncState,
        elapsed: u64,
        cooperative_subscribed: bool,
        cooperative_height: Option<u32>,
        healthy_endpoints: usize,
        quorum: QuorumState,
        independent_queried: bool,
    ) -> SyncState {
        decide_state_pure(
            current,
            elapsed,
            cooperative_subscribed,
            cooperative_height,
            self.last_seen_independent_height.lock().unwrap().clone(),
            healthy_endpoints,
            quorum,
            independent_queried,
        )
    }
}

/// Pure decision function extracted for testing. The argument list is
/// long but every input is observable in real operation.
#[allow(clippy::too_many_arguments)]
pub fn decide_state_pure(
    current: SyncState,
    elapsed: u64,
    cooperative_subscribed: bool,
    cooperative_height: Option<u32>,
    independent_height: Option<u32>,
    healthy_endpoints: usize,
    quorum: QuorumState,
    independent_queried: bool,
) -> SyncState {
    // Compute "available" status of each path
    let cooperative_available = cooperative_subscribed && cooperative_height.is_some();

    // Heights agreement check (only meaningful when both available)
    let heights_agree = match (cooperative_height, independent_height) {
        (Some(c), Some(i)) => c.abs_diff(i) <= HEIGHT_AGREEMENT_TOLERANCE,
        _ => false,
    };

    // Independent verification needs >= 3 confirming sources for BFT correctness
    // when one source might lie. Cooperative path counts as one of those sources
    // when subscribed and agreeing on tip height — so 2 healthy independent +
    // cooperative gives equivalent trust to 3 healthy independent standalone.
    // (Phase 3.8.A: relaxes original >= 3 threshold to allow cooperative bridging.)
    // 2-of-4 unconditional threshold (May 2026). Endpoint count is 4 after
    // zeusln + getalbypro lost CORS; 2/4 = 50%. The if/else structure is
    // preserved (both branches return 2) so an asymmetric policy can be
    // reintroduced later when a 5th endpoint slot (e.g. LIJOX) is added.
    // v225 (S42, DP RULED — the v476 floor lands in the engine): ONE healthy
    // independent source is the Lightning floor. Ready additionally requires
    // heights_agree, i.e. the LSP's cooperative height matches that source —
    // two agreeing sources, the same agreement standard as before. The
    // on-chain face keeps its 2-of-4 gate on the page (indepOk).
    let min_independent = 1;
    let independent_available =
        healthy_endpoints >= min_independent
        && matches!(quorum, QuorumState::Healthy | QuorumState::SlightDisagreement | QuorumState::SingleSource);

    // ── Initializing → first move
    if matches!(current, SyncState::Initializing) {
        if elapsed >= timing::INITIALIZING_GRACE_TICKS {
            return SyncState::Syncing;
        }
        return SyncState::Initializing;
    }

    // ── Both paths broken for too long → Frozen
    if !cooperative_available && !independent_available && elapsed >= timing::BOTH_BROKEN_TIMEOUT_TICKS {
        return SyncState::Frozen;
    }

    // ── Successful sync: cooperative + independent agreement → Ready
    if cooperative_available && independent_available && independent_queried && heights_agree {
        return SyncState::Ready;
    }

    // ── Cooperative only, independent path unavailable past target → ReadOnly
    if cooperative_available && !independent_available && elapsed >= timing::INDEPENDENT_TARGET_TICKS {
        return SyncState::ReadOnly;
    }

    // ── Independent only (cooperative dropped), still inside grace → ReadOnly
    if !cooperative_available && independent_available {
        // Cooperative dropped but independent works — read-only is the right
        // posture. Send/receive blocked because we want LSP cooperation for
        // routing.
        return SyncState::ReadOnly;
    }

    // ── Nothing ready yet, still within budgets → Syncing
    if matches!(current, SyncState::Syncing | SyncState::Ready | SyncState::ReadOnly) {
        // If we were Ready and something dropped, fall back appropriately.
        if matches!(current, SyncState::Ready) && !cooperative_available {
            return SyncState::ReadOnly;
        }
        if matches!(current, SyncState::Ready) && !independent_available {
            return SyncState::ReadOnly;
        }
        if matches!(current, SyncState::ReadOnly) && cooperative_available && independent_available && heights_agree {
            return SyncState::Ready;
        }
        // Frozen recovery
        if matches!(current, SyncState::Frozen) && (cooperative_available || independent_available) {
            return SyncState::Syncing;
        }
        return current;
    }

    // ── Frozen recovery
    if matches!(current, SyncState::Frozen) && (cooperative_available || independent_available) {
        return SyncState::Syncing;
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        elapsed: u64,
        coop_sub: bool,
        coop_h: Option<u32>,
        indep_h: Option<u32>,
        healthy: usize,
        quorum: QuorumState,
        indep_queried: bool,
    ) -> (u64, bool, Option<u32>, Option<u32>, usize, QuorumState, bool) {
        (elapsed, coop_sub, coop_h, indep_h, healthy, quorum, indep_queried)
    }

    fn decide(
        current: SyncState,
        s: (u64, bool, Option<u32>, Option<u32>, usize, QuorumState, bool),
    ) -> SyncState {
        decide_state_pure(current, s.0, s.1, s.2, s.3, s.4, s.5, s.6)
    }

    #[test]
    fn initializing_advances_to_syncing_after_grace() {
        let s = snapshot(0, false, None, None, 0, QuorumState::Healthy, false);
        assert_eq!(decide(SyncState::Initializing, s), SyncState::Initializing);
        let s = snapshot(1, false, None, None, 0, QuorumState::Healthy, false);
        assert_eq!(decide(SyncState::Initializing, s), SyncState::Syncing);
    }

    #[test]
    fn syncing_advances_to_ready_when_both_paths_agree() {
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            3,
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn ready_requires_independent_to_have_been_queried() {
        // Both paths look fine but independent_queried=false (haven't run yet)
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            3,
            QuorumState::Healthy,
            false, // not yet queried
        );
        // Should NOT advance to Ready — wait until independent has run
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Syncing);
    }

    #[test]
    fn syncing_advances_to_ready_within_height_tolerance() {
        // Heights differ by 2 — exactly at tolerance, should still agree
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_098),
            3,
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
        // Heights differ by 3 — outside tolerance, do not advance
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_097),
            3,
            QuorumState::Healthy,
            true,
        );
        assert_ne!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn single_source_agreeing_with_cooperative_is_ready() {
        // v225 (DP v476 floor): one healthy independent source whose height
        // agrees with the cooperative height unlocks Ready.
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            1,
            QuorumState::SingleSource,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn single_source_disagreeing_with_cooperative_is_not_ready() {
        // v225: the lone source must AGREE with the LSP's feed; a 5-block gap
        // is outside tolerance, so no Ready on a single dissenting source.
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_095),
            1,
            QuorumState::SingleSource,
            true,
        );
        assert_ne!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn syncing_falls_to_readonly_when_independent_unavailable_past_target() {
        // Cooperative is fine; independent has 0 healthy, well past target
        let s = snapshot(
            timing::INDEPENDENT_TARGET_TICKS + 1,
            true,
            Some(880_100),
            None,
            0,
            QuorumState::InsufficientEndpoints,
            false,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::ReadOnly);
    }

    #[test]
    fn frozen_when_both_paths_broken_past_timeout() {
        let s = snapshot(
            timing::BOTH_BROKEN_TIMEOUT_TICKS + 1,
            false,
            None,
            None,
            0,
            QuorumState::InsufficientEndpoints,
            false,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Frozen);
    }

    #[test]
    fn ready_degrades_to_readonly_on_independent_loss() {
        let s = snapshot(
            100,
            true,
            Some(880_100),
            None,
            0,
            QuorumState::InsufficientEndpoints,
            true,
        );
        assert_eq!(decide(SyncState::Ready, s), SyncState::ReadOnly);
    }

    #[test]
    fn ready_degrades_to_readonly_on_cooperative_loss() {
        let s = snapshot(
            100,
            false,
            None,
            Some(880_100),
            3,
            QuorumState::Healthy,
            true,
        );
        // No cooperative + working independent → ReadOnly
        assert_eq!(decide(SyncState::Ready, s), SyncState::ReadOnly);
    }

    #[test]
    fn readonly_recovers_to_ready_when_both_agree_again() {
        let s = snapshot(
            120,
            true,
            Some(880_200),
            Some(880_200),
            3,
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::ReadOnly, s), SyncState::Ready);
    }

    #[test]
    fn frozen_recovers_to_readonly_when_only_cooperative_returns() {
        // From Frozen, if cooperative comes back but independent doesn't,
        // we land in ReadOnly directly — no point pretending we're still Syncing.
        let s = snapshot(
            200,
            true,
            Some(880_100),
            None,
            0,
            QuorumState::InsufficientEndpoints,
            false,
        );
        assert_eq!(decide(SyncState::Frozen, s), SyncState::ReadOnly);
    }

    #[test]
    fn frozen_recovers_to_ready_when_both_paths_return_and_agree() {
        // Both paths back, agreement → straight to Ready.
        let s = snapshot(
            200,
            true,
            Some(880_200),
            Some(880_200),
            3,
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::Frozen, s), SyncState::Ready);
    }

    #[test]
    fn cooperative_only_inside_budget_stays_syncing() {
        // Cooperative subscribed and has height; independent not yet ready;
        // still within INDEPENDENT_TARGET_TICKS — wait it out
        let s = snapshot(
            10, // well below INDEPENDENT_TARGET_TICKS=30
            true,
            Some(880_100),
            None,
            0,
            QuorumState::InsufficientEndpoints,
            false,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Syncing);
    }

    #[test]
    fn slight_disagreement_quorum_still_counts_as_available() {
        // §5: SlightDisagreement is a healthy state with one demoted dissenter.
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            3,
            QuorumState::SlightDisagreement,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn no_quorum_does_not_count_as_independent_available() {
        // §5: NoQuorum means even split, no decision possible
        let s = snapshot(
            timing::INDEPENDENT_TARGET_TICKS + 1,
            true,
            Some(880_100),
            Some(880_100),
            3,
            QuorumState::NoQuorum,
            true,
        );
        // With independent unavailable past target, fall to ReadOnly
        assert_eq!(decide(SyncState::Syncing, s), SyncState::ReadOnly);
    }

    #[test]
    fn total_disagreement_blocks_ready() {
        // §5: TotalDisagreement is a hard-stop signal
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            3,
            QuorumState::TotalDisagreement,
            true,
        );
        // Should not advance to Ready when quorum is in disagreement state
        assert_ne!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn cooperative_bridges_low_independent_count() {
        // Phase 3.8.A: 2 healthy independent endpoints + cooperative agrees on
        // tip → Ready. Previously stuck at Syncing/ReadOnly because the >= 3
        // threshold rejected even when cooperative was a valid third source.
        let s = snapshot(
            10,
            true,
            Some(880_100),
            Some(880_100),
            2, // only 2 healthy
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn cooperative_rescues_one_endpoint_when_heights_agree() {
        // v225 (S42, DP RULED — the v476 floor): a single healthy source whose
        // height agrees with the cooperative feed is Ready. This test used to
        // assert the opposite (Phase 3.8.A: floor at 2); the floor is now 1 —
        // agreement, not headcount, is the standard.
        let s = snapshot(
            timing::INDEPENDENT_TARGET_TICKS + 1,
            true,
            Some(880_100),
            Some(880_100),
            1,
            QuorumState::Healthy,
            true,
        );
        assert_eq!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn cooperative_does_not_rescue_disagreeing_heights() {
        // Phase 3.8.A: cooperative bridge requires heights to actually agree.
        // 2 healthy + cooperative present but heights disagree → not Ready.
        let s = snapshot(
            timing::INDEPENDENT_TARGET_TICKS + 1,
            true,
            Some(880_100),
            Some(880_050), // 50-block disagreement, well past tolerance
            2,
            QuorumState::Healthy,
            true,
        );
        assert_ne!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn cooperative_unavailable_preserves_strict_threshold() {
        // Phase 3.8.A: when cooperative is missing, the original >= 3
        // threshold is preserved. 2 healthy independent alone is insufficient.
        let s = snapshot(
            timing::INDEPENDENT_TARGET_TICKS + 1,
            false, // cooperative unavailable
            None,
            Some(880_100),
            2, // 2 healthy independent
            QuorumState::Healthy,
            true,
        );
        // No cooperative + only 2 independent → not Ready (preserves
        // original BFT floor; falls to ReadOnly via independent-only branch).
        assert_ne!(decide(SyncState::Syncing, s), SyncState::Ready);
    }

    #[test]
    fn orchestrator_starts_recording_first_tick() {
        let orch = ColdStartOrchestrator::new();
        let tracker = SyncStateTracker::new();
        let http = std::sync::Arc::new(crate::http_stub::StubEsploraHttp::new());
        let independent = IndependentClient::with_defaults(http);
        // First tick records the start time
        orch.tick(100, &tracker, false, None, &independent);
        // started_at should now be 100
        let started = orch.started_at_tick.lock().unwrap();
        assert_eq!(*started, Some(100));
    }
}
