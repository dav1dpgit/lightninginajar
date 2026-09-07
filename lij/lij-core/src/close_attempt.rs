// close_attempt.rs
// In-memory record of an outstanding channel-close attempt.
//
// LijNode tracks these records in a HashMap<ChannelId, CloseAttemptRecord>
// so that when Event::ChannelClosed fires on the LDK event queue, the
// background_tick handler can:
//   - Distinguish user-initiated closes from LSP-initiated closes
//   - Compute elapsed time for the negotiation
//   - Determine which kind of close was attempted (cooperative vs force)
//   - Resolve the LSP pubkey for relationship-level operations
//
// Records are stored at attempt time (synchronously, in close_channel /
// force_close) and removed when the matching ChannelClosed event arrives
// (in 8c.2). Records older than COOPERATIVE_TIMEOUT_SECS without resolution
// are surfaced to the UI as candidates for force-close escalation.
//
// Persistence: not persisted across wallet restarts. If the wallet
// restarts mid-close, we lose the attempt record but LDK has its own
// state (the shutdown was sent, the channel is in pending-close state).
// On restart, the ChannelClosed event still arrives correctly; we just
// can't tell whether the close was user-initiated. Fall back to
// "treat as LSP-initiated" — safe default per Phase 4 design (auto-accept
// LSP-initiated closes anyway).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseAttemptKind {
    /// User clicked Close cooperatively, or wallet auto-accepted LSP-initiated.
    Cooperative,
    /// User clicked Force close, or escalated from cooperative.
    Force,
}

impl CloseAttemptKind {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative close",
            Self::Force => "force close",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CloseAttemptRecord {
    pub kind: CloseAttemptKind,
    /// Unix seconds when close was initiated. Used to compute elapsed
    /// time for the UI ("Negotiating... 12s") and to detect cooperative-
    /// close timeout candidates.
    pub started_at_unix_secs: u64,
    /// LSP pubkey hex of the counterparty. Used for relationship-level
    /// queries ("end LSP relationship") and for grouping closed channels
    /// in the Channel Management screen by LSP.
    pub counterparty_pubkey_hex: String,
}

/// Cooperative-close negotiations that exceed this duration without an
/// Event::ChannelClosed are surfaced to the UI as candidates for
/// force-close escalation. Per Phase 4 design.
pub const COOPERATIVE_TIMEOUT_SECS: u64 = 30;
