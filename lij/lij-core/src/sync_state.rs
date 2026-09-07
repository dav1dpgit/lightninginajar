// sync_state.rs
//
// Step 6b — Cold-start state machine.
// Per Phase4_chain_data_trust_model_v1.md §6 and §8.
//
// The wallet's operational state regarding chain data freshness. The state
// gates which operations are allowed:
//
//   Initializing  → wallet just created, no chain data fetched yet.
//                   Most ops blocked (no chain data to base them on).
//   Syncing       → fetching chain data, may be partial.
//                   Read-only ops OK; send/receive blocked.
//   Ready         → cooperative + independent agree within tolerance,
//                   send/receive unlocked. Normal operation.
//   ReadOnly      → independent path degraded (Rung 3 from §8).
//                   Show balance/history with staleness indicator;
//                   send blocked, but receive (invoice generation +
//                   HTLC claim) is allowed — cooperative chain feed
//                   is sufficient. (Step 3.6 receive gate review.)
//   Frozen        → both paths broken (Rung 4 from §8).
//                   No chain-dependent operations allowed.
//                   User sees an OFFLINE banner; manual reconnect possible.
//
// State transitions are driven by step 6d's cold-start orchestrator and by
// the trigger logic from §3 of the design doc (force-close suspicion, LSP
// unreachable, etc.). Step 6b just defines the type and the gating logic.

use std::sync::Mutex;
use std::time::Duration;

use crate::error::{LijError, LijResult};

/// Operational state regarding chain data freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Wallet just created or restored; no chain data yet.
    Initializing,
    /// Actively fetching chain data; may be partial.
    Syncing,
    /// Both cooperative + independent agree; send/receive unlocked.
    Ready,
    /// Independent path degraded; balance/history viewable, send/receive blocked.
    ReadOnly,
    /// Both paths broken; no chain-dependent ops allowed.
    Frozen,
}

impl SyncState {
    /// Whether the wallet is allowed to send payments in this state.
    pub fn can_send(&self) -> bool {
        matches!(self, SyncState::Ready)
    }

    /// Whether the wallet is allowed to create invoices (receive) in this state.
    // Step 3.6 receive gate: cooperative chain data is sufficient to safely
    // generate invoices and claim incoming HTLCs. Independent quorum
    // degradation alone (ReadOnly) does NOT block receive, since invoices
    // are signed metadata and HTLC claim only needs cooperative chain
    // visibility (the LSP's chain feed). Frozen still blocks because
    // cooperative is also broken in that state.
    pub fn can_receive(&self) -> bool {
        matches!(self, SyncState::Ready | SyncState::ReadOnly)
    }

    /// Whether the wallet is allowed to open or close channels in this state.
    /// Hard gate per §6: channel ops require full sync.
    pub fn can_manage_channels(&self) -> bool {
        matches!(self, SyncState::Ready)
    }

    /// Whether read-only views (balance, history, channel list) are valid.
    /// True except in Initializing where we have no data at all.
    pub fn can_read_state(&self) -> bool {
        !matches!(self, SyncState::Initializing)
    }

    /// User-facing display string, plain language per the LiJ_Instructions doc.
    pub fn display(&self) -> &'static str {
        match self {
            SyncState::Initializing => "Starting up",
            SyncState::Syncing => "Syncing with the network",
            SyncState::Ready => "Ready",
            SyncState::ReadOnly => "View only — chain verification incomplete",
            SyncState::Frozen => "Offline — last verified state shown",
        }
    }

    /// Dot color for the dashboard grid per §9.
    /// Green = healthy (Ready), Yellow = degraded (Syncing/ReadOnly), Red = broken (Frozen).
    /// Initializing is yellow because we don't yet know.
    pub fn dot_color(&self) -> DotColor {
        match self {
            SyncState::Ready => DotColor::Green,
            SyncState::Initializing | SyncState::Syncing | SyncState::ReadOnly => DotColor::Yellow,
            SyncState::Frozen => DotColor::Red,
        }
    }
}

/// Dot grid color, surfaced to the frontend dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DotColor {
    Green,
    Yellow,
    Red,
}

impl DotColor {
    pub fn as_str(&self) -> &'static str {
        match self {
            DotColor::Green => "green",
            DotColor::Yellow => "yellow",
            DotColor::Red => "red",
        }
    }
}

/// Tracks sync state plus the timestamps needed to compute staleness.
pub struct SyncStateTracker {
    state: Mutex<SyncState>,
    /// Tick at which we last successfully refreshed cooperative chain data.
    last_cooperative_refresh_tick: Mutex<Option<u64>>,
    /// Tick at which we last successfully refreshed independent chain data.
    last_independent_refresh_tick: Mutex<Option<u64>>,
}

impl SyncStateTracker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SyncState::Initializing),
            last_cooperative_refresh_tick: Mutex::new(None),
            last_independent_refresh_tick: Mutex::new(None),
        }
    }

    pub fn current(&self) -> SyncState {
        *self.state.lock().unwrap()
    }

    pub fn set(&self, new_state: SyncState) {
        let mut s = self.state.lock().unwrap();
        if *s != new_state {
            log::info!("sync_state: {:?} → {:?}", *s, new_state);
            *s = new_state;
        }
    }

    pub fn note_cooperative_refresh(&self, tick: u64) {
        *self.last_cooperative_refresh_tick.lock().unwrap() = Some(tick);
    }

    pub fn note_independent_refresh(&self, tick: u64) {
        *self.last_independent_refresh_tick.lock().unwrap() = Some(tick);
    }

    pub fn cooperative_age_ticks(&self, current_tick: u64) -> Option<u64> {
        self.last_cooperative_refresh_tick
            .lock()
            .unwrap()
            .map(|t| current_tick.saturating_sub(t))
    }

    pub fn independent_age_ticks(&self, current_tick: u64) -> Option<u64> {
        self.last_independent_refresh_tick
            .lock()
            .unwrap()
            .map(|t| current_tick.saturating_sub(t))
    }
}

// ── Operation gating helpers ────────────────────────────────────────────────
// These return `LijError::SyncStateNotReady` if the state forbids the op.
// The error variant is added to error.rs in this same step.

pub fn require_can_send(state: SyncState) -> LijResult<()> {
    if state.can_send() {
        Ok(())
    } else {
        Err(LijError::SyncStateNotReady(format!(
            "send blocked: state is {:?} ({})",
            state,
            state.display()
        )))
    }
}

pub fn require_can_receive(state: SyncState) -> LijResult<()> {
    if state.can_receive() {
        Ok(())
    } else {
        Err(LijError::SyncStateNotReady(format!(
            "receive blocked: state is {:?} ({})",
            state,
            state.display()
        )))
    }
}

pub fn require_can_manage_channels(state: SyncState) -> LijResult<()> {
    if state.can_manage_channels() {
        Ok(())
    } else {
        Err(LijError::SyncStateNotReady(format!(
            "channel ops blocked: state is {:?} ({})",
            state,
            state.display()
        )))
    }
}

/// Per §6: cooperative cache freshness for fee/payment decisions.
/// Reused from fee_estimator.rs's threshold for symmetry.
pub const COOPERATIVE_FRESH_DURATION: Duration = Duration::from_secs(60 * 60); // 1 hour

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_unlocks_everything() {
        let s = SyncState::Ready;
        assert!(s.can_send());
        assert!(s.can_receive());
        assert!(s.can_manage_channels());
        assert!(s.can_read_state());
        assert_eq!(s.dot_color(), DotColor::Green);
    }

    #[test]
    fn frozen_blocks_active_ops_allows_read() {
        let s = SyncState::Frozen;
        assert!(!s.can_send());
        assert!(!s.can_receive());
        assert!(!s.can_manage_channels());
        assert!(s.can_read_state(), "frozen should still allow viewing last-known state");
        assert_eq!(s.dot_color(), DotColor::Red);
    }

    #[test]
    fn read_only_blocks_send_allows_receive_and_read() {
        let s = SyncState::ReadOnly;
        assert!(!s.can_send());
        assert!(s.can_receive(), "Step 3.6 receive gate: ReadOnly allows receive (cooperative path is sufficient)");
        assert!(!s.can_manage_channels());
        assert!(s.can_read_state());
        assert_eq!(s.dot_color(), DotColor::Yellow);
    }

    #[test]
    fn require_can_receive_allows_ready_and_readonly_blocks_others() {
        // Step 3.6 receive gate: Ready and ReadOnly both have cooperative
        // chain visibility; receive OK in both. Initializing/Syncing have
        // no/partial chain data; Frozen has neither path working.
        assert!(require_can_receive(SyncState::Ready).is_ok());
        assert!(require_can_receive(SyncState::ReadOnly).is_ok());

        for s in [
            SyncState::Initializing,
            SyncState::Syncing,
            SyncState::Frozen,
        ] {
            assert!(require_can_receive(s).is_err(), "should error in {:?}", s);
        }
    }

    #[test]
    fn syncing_blocks_active_ops() {
        let s = SyncState::Syncing;
        assert!(!s.can_send());
        assert!(!s.can_receive());
        assert!(s.can_read_state());
        assert_eq!(s.dot_color(), DotColor::Yellow);
    }

    #[test]
    fn initializing_blocks_everything_including_read() {
        let s = SyncState::Initializing;
        assert!(!s.can_send());
        assert!(!s.can_read_state());
    }

    #[test]
    fn require_can_send_returns_err_in_non_ready_states() {
        for s in [
            SyncState::Initializing,
            SyncState::Syncing,
            SyncState::ReadOnly,
            SyncState::Frozen,
        ] {
            assert!(require_can_send(s).is_err(), "should error in {:?}", s);
        }
        assert!(require_can_send(SyncState::Ready).is_ok());
    }

    #[test]
    fn tracker_records_state_transitions() {
        let t = SyncStateTracker::new();
        assert_eq!(t.current(), SyncState::Initializing);
        t.set(SyncState::Syncing);
        assert_eq!(t.current(), SyncState::Syncing);
        t.set(SyncState::Ready);
        assert_eq!(t.current(), SyncState::Ready);
    }

    #[test]
    fn tracker_age_ticks_tracking() {
        let t = SyncStateTracker::new();
        assert_eq!(t.cooperative_age_ticks(100), None);
        t.note_cooperative_refresh(50);
        assert_eq!(t.cooperative_age_ticks(100), Some(50));
        assert_eq!(t.cooperative_age_ticks(50), Some(0));
    }

    #[test]
    fn display_strings_are_plain_language() {
        // Per LiJ_Instructions: plain language for user-facing text
        for s in [
            SyncState::Initializing,
            SyncState::Syncing,
            SyncState::Ready,
            SyncState::ReadOnly,
            SyncState::Frozen,
        ] {
            let display = s.display();
            // No technical terms in display strings
            for jargon in ["LSP", "BOLT", "HTLC", "channel_ready", "Esplora"] {
                assert!(
                    !display.contains(jargon),
                    "{:?} display '{}' contains jargon '{}'",
                    s, display, jargon
                );
            }
        }
    }
}
