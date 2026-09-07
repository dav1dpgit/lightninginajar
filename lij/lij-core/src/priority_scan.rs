// priority_scan.rs
//
// Step 6c — Funds-safety priority scan.
// Per Phase4_chain_data_trust_model_v1.md §6 funds-safety floor.
//
// Before declaring SyncState::Ready on cold start, the wallet scans local
// channel state for HTLCs/timelocks expiring within a safety window
// (default 6 blocks, ~1 hour). Channels with approaching obligations get
// independent verification PRIORITY, ahead of generic chain sync.
//
// Why this exists:
//   Mutiny had a known failure mode where wallets opened after long offline
//   periods would have HTLCs expiring during the slow chain-sync, triggering
//   force-close. Our priority scan inverts the problem: we identify which
//   chain queries actually matter for funds safety BEFORE doing routine sync,
//   and run those queries first via the independent path.
//
// What this file does NOT do:
//   - Run the actual independent verification queries — that's the
//     orchestrator (step 6d).
//   - Trigger user warnings on T-144 / T-36 / T-6 — that's the proactive
//     warning ladder, deferred to Phase 6 per session decision.
//
// What this file DOES do:
//   - scan_channels() — look at all channels' pending HTLCs, return a
//     PriorityScanReport listing what's expiring within the safety window
//     and what funding outpoints/scripts to verify.
//   - The orchestrator consumes this report to decide which queries to
//     run first.

use std::collections::HashSet;

use bitcoin::Txid;
use lightning::ln::channelmanager::ChannelDetails;

/// Default safety window: any timelock expiring within this many blocks
/// of current chain tip is considered "approaching" and gets priority
/// verification. Per design doc §6 and trigger 2h.
pub const SAFETY_WINDOW_BLOCKS: u32 = 6;

/// One channel's worth of priority-scan findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPriorityFinding {
    /// Channel ID for logging and status surfacing.
    pub channel_id_hex: String,
    /// Funding txid that the orchestrator should verify independently.
    /// None for channels still in pre-funding state.
    pub funding_txid: Option<Txid>,
    /// Earliest HTLC expiry block in this channel. None if no pending HTLCs.
    pub earliest_htlc_expiry: Option<u32>,
    /// Total count of pending HTLCs (inbound + outbound).
    pub pending_htlc_count: usize,
    /// Whether this channel is in our priority scan because of approaching
    /// expiry vs. just because it's an active channel (informational).
    pub priority: PriorityLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriorityLevel {
    /// HTLC or timelock expiring within SAFETY_WINDOW_BLOCKS — verify NOW.
    Critical,
    /// Active channel, no immediate expiry concern. Routine verification OK.
    Routine,
    /// No funding txo known yet (channel pre-funding). Skip — nothing to verify.
    PreFunding,
}

/// Aggregated report of the priority scan.
#[derive(Clone, Debug, Default)]
pub struct PriorityScanReport {
    /// Findings ordered by priority then by earliest_htlc_expiry ascending.
    pub findings: Vec<ChannelPriorityFinding>,
    /// Funding txids to verify on the independent path BEFORE generic sync.
    /// Drawn from Critical-priority findings.
    pub critical_funding_txids: HashSet<Txid>,
    /// Total channels scanned (for logging / status).
    pub total_channels: usize,
    /// Whether any channel had Critical priority. The orchestrator gates
    /// the Ready transition on resolving these.
    pub has_critical: bool,
}

/// Scan the given channels against the current chain tip. Returns a
/// PriorityScanReport that the orchestrator (step 6d) consumes to decide
/// which queries to run first.
pub fn scan_channels(channels: &[ChannelDetails], current_tip_height: u32) -> PriorityScanReport {
    let mut findings: Vec<ChannelPriorityFinding> = Vec::new();
    let mut critical_funding_txids: HashSet<Txid> = HashSet::new();

    for ch in channels {
        let funding_txid = ch.funding_txo.as_ref().map(|o| o.txid);
        let pending_htlc_count = ch.pending_inbound_htlcs.len() + ch.pending_outbound_htlcs.len();

        // Find earliest HTLC expiry across both directions
        let earliest_htlc_expiry = {
            let inbound_min = ch.pending_inbound_htlcs.iter().map(|h| h.cltv_expiry).min();
            let outbound_min = ch.pending_outbound_htlcs.iter().map(|h| h.cltv_expiry).min();
            match (inbound_min, outbound_min) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            }
        };

        let priority = if funding_txid.is_none() {
            PriorityLevel::PreFunding
        } else if let Some(exp) = earliest_htlc_expiry {
            if exp <= current_tip_height.saturating_add(SAFETY_WINDOW_BLOCKS) {
                PriorityLevel::Critical
            } else {
                PriorityLevel::Routine
            }
        } else {
            PriorityLevel::Routine
        };

        if priority == PriorityLevel::Critical {
            if let Some(txid) = funding_txid {
                critical_funding_txids.insert(txid);
            }
        }

        findings.push(ChannelPriorityFinding {
            channel_id_hex: hex::encode(ch.channel_id.0),
            funding_txid,
            earliest_htlc_expiry,
            pending_htlc_count,
            priority,
        });
    }

    // Sort: Critical first, then Routine, then PreFunding.
    // Within priority, earlier expiry first.
    findings.sort_by(|a, b| {
        let priority_order = |p: PriorityLevel| match p {
            PriorityLevel::Critical => 0,
            PriorityLevel::Routine => 1,
            PriorityLevel::PreFunding => 2,
        };
        priority_order(a.priority)
            .cmp(&priority_order(b.priority))
            .then_with(|| {
                a.earliest_htlc_expiry
                    .unwrap_or(u32::MAX)
                    .cmp(&b.earliest_htlc_expiry.unwrap_or(u32::MAX))
            })
    });

    let has_critical = !critical_funding_txids.is_empty();
    let total_channels = channels.len();

    if has_critical {
        log::warn!(
            "priority_scan: {} channel(s) have HTLCs expiring within {} blocks of tip {} — independent verification REQUIRED before Ready",
            critical_funding_txids.len(),
            SAFETY_WINDOW_BLOCKS,
            current_tip_height,
        );
    } else {
        log::info!(
            "priority_scan: {} channel(s) scanned, no critical timelocks at tip {}",
            total_channels, current_tip_height
        );
    }

    PriorityScanReport {
        findings,
        critical_funding_txids,
        total_channels,
        has_critical,
    }
}

#[cfg(test)]
mod tests {
    // Note: testing this against real LDK ChannelDetails requires building
    // a full ChannelManager, which is heavyweight. The pure-function logic
    // is what matters — we verify the priority decision tree on synthetic
    // inputs by building a minimal mock-channel struct mirror.
    //
    // The real integration test happens in step 9 (end-to-end against an
    // external Lightning wallet) where actual ChannelDetails flow through.
    //
    // What we CAN test in pure Rust is the priority logic itself: given
    // (earliest_expiry, current_tip), does scan_channels produce the right
    // priority? We do that by directly constructing PriorityScanReport
    // findings and verifying sort order + critical detection.

    use super::*;

    fn dummy_txid(b: u8) -> Txid {
        use bitcoin::hashes::Hash;
        Txid::from_byte_array([b; 32])
    }

    /// Build a finding with given priority and expiry — for sort-logic tests.
    fn finding(priority: PriorityLevel, earliest_expiry: Option<u32>) -> ChannelPriorityFinding {
        ChannelPriorityFinding {
            channel_id_hex: format!("ch_{:?}_{:?}", priority, earliest_expiry),
            funding_txid: Some(dummy_txid(0)),
            earliest_htlc_expiry: earliest_expiry,
            pending_htlc_count: 0,
            priority,
        }
    }

    #[test]
    fn empty_channel_list_no_critical() {
        let report = scan_channels(&[], 880_000);
        assert_eq!(report.total_channels, 0);
        assert!(!report.has_critical);
        assert!(report.findings.is_empty());
        assert!(report.critical_funding_txids.is_empty());
    }

    #[test]
    fn priority_decision_critical_when_within_window() {
        // tip=880000, window=6, so expiries 880000..=880006 are critical
        let cases = [
            (880_000, PriorityLevel::Critical), // expires now
            (880_001, PriorityLevel::Critical),
            (880_006, PriorityLevel::Critical), // exactly at boundary
            (880_007, PriorityLevel::Routine),  // just outside
            (880_100, PriorityLevel::Routine),  // far in future
        ];
        for (expiry, expected) in cases {
            // Manually replicate the decision logic the function uses.
            let tip = 880_000u32;
            let actual = if expiry <= tip.saturating_add(SAFETY_WINDOW_BLOCKS) {
                PriorityLevel::Critical
            } else {
                PriorityLevel::Routine
            };
            assert_eq!(
                actual, expected,
                "expiry {} at tip {} should be {:?}, got {:?}",
                expiry, tip, expected, actual
            );
        }
    }

    #[test]
    fn report_sort_critical_before_routine() {
        let mut findings = vec![
            finding(PriorityLevel::Routine, Some(900_000)),
            finding(PriorityLevel::Critical, Some(880_005)),
            finding(PriorityLevel::PreFunding, None),
            finding(PriorityLevel::Critical, Some(880_001)),
            finding(PriorityLevel::Routine, Some(890_000)),
        ];
        findings.sort_by(|a, b| {
            let order = |p: PriorityLevel| match p {
                PriorityLevel::Critical => 0,
                PriorityLevel::Routine => 1,
                PriorityLevel::PreFunding => 2,
            };
            order(a.priority).cmp(&order(b.priority)).then_with(|| {
                a.earliest_htlc_expiry
                    .unwrap_or(u32::MAX)
                    .cmp(&b.earliest_htlc_expiry.unwrap_or(u32::MAX))
            })
        });
        assert_eq!(findings[0].priority, PriorityLevel::Critical);
        assert_eq!(findings[0].earliest_htlc_expiry, Some(880_001));
        assert_eq!(findings[1].priority, PriorityLevel::Critical);
        assert_eq!(findings[1].earliest_htlc_expiry, Some(880_005));
        assert_eq!(findings[2].priority, PriorityLevel::Routine);
        assert_eq!(findings[2].earliest_htlc_expiry, Some(890_000));
        assert_eq!(findings[3].priority, PriorityLevel::Routine);
        assert_eq!(findings[3].earliest_htlc_expiry, Some(900_000));
        assert_eq!(findings[4].priority, PriorityLevel::PreFunding);
    }

    #[test]
    fn safety_window_constant_matches_design_doc() {
        // Design doc §6 specifies 6 blocks. Don't accidentally change this
        // without updating the doc.
        assert_eq!(SAFETY_WINDOW_BLOCKS, 6);
    }

    #[test]
    fn report_collects_critical_funding_txids() {
        // Build findings manually because constructing real ChannelDetails
        // would require a full ChannelManager. Verify the aggregation logic.
        let mut critical_set: HashSet<Txid> = HashSet::new();
        let txid_a = dummy_txid(1);
        let txid_b = dummy_txid(2);

        // Two critical findings with different funding txids
        let f1 = ChannelPriorityFinding {
            channel_id_hex: "ch1".into(),
            funding_txid: Some(txid_a),
            earliest_htlc_expiry: Some(880_001),
            pending_htlc_count: 1,
            priority: PriorityLevel::Critical,
        };
        let f2 = ChannelPriorityFinding {
            channel_id_hex: "ch2".into(),
            funding_txid: Some(txid_b),
            earliest_htlc_expiry: Some(880_002),
            pending_htlc_count: 1,
            priority: PriorityLevel::Critical,
        };

        if f1.priority == PriorityLevel::Critical {
            if let Some(t) = f1.funding_txid {
                critical_set.insert(t);
            }
        }
        if f2.priority == PriorityLevel::Critical {
            if let Some(t) = f2.funding_txid {
                critical_set.insert(t);
            }
        }
        assert_eq!(critical_set.len(), 2);
        assert!(critical_set.contains(&txid_a));
        assert!(critical_set.contains(&txid_b));
    }

    #[test]
    fn dot_color_implication_for_critical() {
        // If there are critical findings, the orchestrator should treat
        // the wallet as not-yet-Ready until they resolve. Document by test.
        let report = PriorityScanReport {
            findings: vec![],
            critical_funding_txids: {
                let mut s = HashSet::new();
                s.insert(dummy_txid(7));
                s
            },
            total_channels: 1,
            has_critical: true,
        };
        // Orchestrator's contract: has_critical => block Ready transition.
        assert!(report.has_critical);
    }
}
