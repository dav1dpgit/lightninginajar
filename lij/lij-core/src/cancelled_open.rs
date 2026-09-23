//! v277 (S48, DP 2026-09-22 23:37 — "fix the proof, don't delete the janitor"): the CANCELLED-OPEN
//! SWEEP's decision, made honest.
//!
//! History. S29's zombie episode: failed opens left channel objects whose funding could never
//! confirm, and the Lightning face counted their value for as long as LDK keeps such a channel
//! (2016 blocks). v191 closed the root cause (one owner per coin); v192 added this sweep as the
//! janitor: a not-ready outbound channel with zero confirmations whose funding is tracked by nothing
//! is a dead attempt — discard it without broadcasting (nothing exists on chain to close). v257
//! dropped the confirmed-history half of "tracked by nothing" as never load-bearing. It was: on
//! 2026-09-22 the wallet's scanner confirmed a real funding (the record left the pending list) some
//! tens of seconds before the LSP's node reported the same block, LDK still counted zero, and the
//! sweep abandoned a funded channel — 35,000 sats stranded in a 2-of-2 until the LSP closed it.
//!
//! The proof now. A channel is discarded only when ALL of these hold at the sweep's tick:
//!   1. outbound, not ready, LDK counts zero confirmations, and it carries a funding txid;
//!   2. the funding txid is in neither the pending list nor the confirmed history;
//!   3. the chain-server quorum answers, definitively, that it has never seen the transaction
//!      (an HTTP 404 from a reachable server — a transport failure or a dark quorum proves nothing);
//!   4. it has looked that way, at every check, for at least two hours.
//! A single sighting anywhere — the wallet's own books, LDK, or one server — resets the clock.
//! The clock is persisted, so reloads do not restart it; a true zombie still disappears in hours
//! instead of weeks, and a momentary lag can never trigger it.
//!
//! The ratified vocabulary (DP, S29): "cancelled — funds never left."

use std::collections::HashMap;

use crate::storage::LijStorage;

/// How long a funding must look dead, at every check, before the channel is discarded.
pub const DEAD_FLOOR_MS: u64 = 2 * 3600 * 1000;

/// Storage key of the first-seen-dead clock, by funding txid.
pub const DEAD_MAP_KEY: &str = "lij_dead_opens_v1";

/// The message LDK records on the closed-channel record.
pub const ABANDON_MESSAGE: &str = "LiJ: cancelled unfunded open — funding never reached the chain; funds never left";

/// What the sweep should do with one candidate channel this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Something knows the funding: the pending list, the history, or a chain server. Not dead;
    /// any clock for it is cleared.
    Alive,
    /// Nothing knows it, and the quorum said so definitively — but not for long enough yet.
    /// The clock runs (starting now when `first_dead_ms` is None).
    Watching,
    /// Nothing has known it for at least the floor: a dead attempt. Discard without broadcasting.
    Dead,
    /// The quorum could not answer (dark, or only transport failures): no conclusion, the clock
    /// is left as it is.
    Unknown,
}

/// The pure decision. `quorum_knows`: Some(true) a server has the tx; Some(false) a reachable server
/// answered 404 and none has it; None the quorum could not answer.
pub fn verdict(
    in_pending: bool,
    in_history: bool,
    quorum_knows: Option<bool>,
    first_dead_ms: Option<u64>,
    now_ms: u64,
) -> Verdict {
    if in_pending || in_history {
        return Verdict::Alive;
    }
    match quorum_knows {
        Some(true) => Verdict::Alive,
        None => Verdict::Unknown,
        Some(false) => match first_dead_ms {
            Some(t0) if now_ms.saturating_sub(t0) >= DEAD_FLOOR_MS => Verdict::Dead,
            _ => Verdict::Watching,
        },
    }
}

pub fn load_dead_map(storage: &dyn LijStorage) -> HashMap<String, u64> {
    match storage.get(DEAD_MAP_KEY) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => HashMap::new(),
    }
}

pub fn save_dead_map(storage: &dyn LijStorage, m: &HashMap<String, u64>) {
    if m.is_empty() {
        let _ = storage.delete(DEAD_MAP_KEY);
        return;
    }
    if let Ok(b) = serde_json::to_vec(m) {
        let _ = storage.set(DEAD_MAP_KEY, &b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600 * 1000;

    #[test]
    fn the_dp_case_a_funding_the_scanner_confirmed_is_alive() {
        // 2026-09-22: left the pending list (the scanner saw the block), LDK still at 0 confs.
        // History has it → alive, whatever the quorum says and however long the clock ran.
        assert_eq!(verdict(false, true, Some(false), Some(0), 10 * H), Verdict::Alive);
        assert_eq!(verdict(false, true, None, None, 10 * H), Verdict::Alive);
    }

    #[test]
    fn a_pending_record_is_alive() {
        assert_eq!(verdict(true, false, Some(false), Some(0), 10 * H), Verdict::Alive);
    }

    #[test]
    fn a_server_that_has_the_tx_is_alive_and_resets_nothing_else() {
        assert_eq!(verdict(false, false, Some(true), Some(0), 10 * H), Verdict::Alive);
    }

    #[test]
    fn a_dark_or_failing_quorum_proves_nothing() {
        assert_eq!(verdict(false, false, None, None, 10 * H), Verdict::Unknown);
        assert_eq!(verdict(false, false, None, Some(0), 10 * H), Verdict::Unknown);
    }

    #[test]
    fn unknown_everywhere_starts_the_clock_and_waits_the_floor() {
        assert_eq!(verdict(false, false, Some(false), None, 10 * H), Verdict::Watching);
        assert_eq!(verdict(false, false, Some(false), Some(10 * H), 10 * H + DEAD_FLOOR_MS - 1), Verdict::Watching);
        assert_eq!(verdict(false, false, Some(false), Some(10 * H), 10 * H + DEAD_FLOOR_MS), Verdict::Dead);
    }

    #[test]
    fn the_floor_is_two_hours() {
        assert_eq!(DEAD_FLOOR_MS, 2 * H);
    }
}
