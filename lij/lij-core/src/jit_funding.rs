//! v363 (S67, DP 2026-11-04 "Go on all" — docs/design/jit-trust/wallet-trusts-lsp-v0.1.md §6): the wallet's half of
//! WALLET TRUSTS LSP.
//!
//! The provider (adapter 0.124.0+) holds a JIT channel's funding transaction back until this wallet has claimed the
//! payment. When the payment is refused instead, the provider abandons the channel on its side and tells the wallet
//! so (`JitFundingAbandoned`, type 32823). LND sends the wallet nothing on its own for an abandoned channel, and LDK
//! never times out an inbound zero-conf channel on its funding (channel.rs: the funding timeout applies only before
//! channel_ready), so without this module the wallet would keep a ghost channel for ever — one LDK's own archiving
//! never removes either (its monitor, once the channel advanced, keeps a 0-sat balance for good).
//!
//! THE RULE (the only thing that lets a wallet drop a channel on a provider's word): the wallet owns NOTHING in it.
//!   1. the message's sender is the channel's counterparty AND the active provider;
//!   2. the channel is inbound and zero-conf (`confirmations_required == Some(0)`), with no confirmation counted;
//!   3. the monitor's claimable balance for us is zero and no HTLC is pending in either direction;
//!   4. the funding txid is unknown to the wallet's own books (the tier-2 walk's pending list and history).
//! Then the wallet can lose nothing whatever the provider later does with the funding — it could only lose its own
//! coins. Any check failing → the message is logged and ignored. A provider cannot talk a wallet out of money.
//!
//! THE AUDIT (the wallet was offline when the provider abandoned, so the message never came): the same drop when an
//! inbound zero-conf channel with our balance zero and no HTLCs has a funding unknown to the books AND the chain-server
//! quorum for two hours — the outbound CONFLICT-AUDIT's clock (crate::cancelled_open), the same persisted map.
//!
//! THE WATCH (the trust the wallet extends): an inbound zero-conf channel in which we DO own sats whose funding stays
//! unknown to books and quorum for `WATCH_FLOOR_MS` — the provider took the payment and has not published. Nothing is
//! dropped (dropping would lose the sats); a tape line and the health report say so.
//!
//! WHAT A DROP DOES: the channel id and funding outpoint go into the persisted `never_funded` map FIRST; then
//! `force_close_without_broadcasting_txn` (no transaction can spend a funding that does not exist); the ChannelClosed
//! handler sees the map and files no close record; every reader of `list_monitors()` skips the entry; at the NEXT boot
//! the monitor's storage key is archived before loading (archiving in-session would race the persister's own writes).

use std::collections::HashMap;

use crate::storage::LijStorage;

/// Storage key of the never-funded channels (JSON map: "txid:vout" of the funding → the record). An engine key —
/// the page never takes this name (ops/frontend/gate-storage-keys.mjs).
pub const NEVER_FUNDED_KEY: &str = "lij_never_funded_v1";

/// The message LDK records on the closed-channel record (never shown as a close — the handler skips it).
pub const ABANDON_MESSAGE: &str = "LiJ: JIT channel never funded — the provider held the funding back and abandoned the channel; nothing was owned in it";

/// How long a funded (our balance > 0) inbound zero-conf channel's funding may stay unknown to books and quorum before
/// the watch speaks: 30 minutes. A publishing provider's funding is in the mempool within seconds of the claim.
pub const WATCH_FLOOR_MS: u64 = 30 * 60 * 1000;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct NeverFunded {
    /// The channel id, hex (LDK's 32 bytes).
    pub channel_id: String,
    /// The counterparty's node pubkey, hex.
    pub counterparty: String,
    /// When the wallet dropped it (ms since the epoch).
    pub at_ms: u64,
    /// "message" (the provider said so) or "audit" (two hours unknown, our balance zero).
    pub how: String,
    /// Whether the monitor's storage key has been archived (done at a boot after the drop).
    #[serde(default)]
    pub archived: bool,
    /// v364 (the review, finding 5): true once the force close returned Ok AND the channel manager was persisted
    /// without the channel. Only a `closed` entry's monitor is archived at boot, and only a `closed` entry hides its
    /// monitor from the kit, the balances and the sweeps — a manager that still holds the channel needs that monitor
    /// to load at all (LDK refuses a manager whose channel has no monitor). An entry found `closed: false` at boot
    /// is reconciled after the manager loads: channel still there → the entry is removed (the drop never completed;
    /// the audit may do it again); channel gone → `closed: true`.
    #[serde(default)]
    pub closed: bool,
}

/// v364: the outpoint keys whose monitors THIS boot archived, written before the manager loads and cleared after. If
/// the load then fails, `unarchive_after_failed_load` puts those monitors back and the boot is tried once more.
pub const ARCHIVED_THIS_BOOT_KEY: &str = "lij_never_funded_archived_boot_v1";

pub fn note_archived_this_boot(storage: &dyn LijStorage, op_keys: &[String]) {
    if op_keys.is_empty() { let _ = storage.delete(ARCHIVED_THIS_BOOT_KEY); return; }
    if let Ok(b) = serde_json::to_vec(op_keys) { let _ = storage.set(ARCHIVED_THIS_BOOT_KEY, &b); }
}

pub fn clear_archived_this_boot(storage: &dyn LijStorage) {
    let _ = storage.delete(ARCHIVED_THIS_BOOT_KEY);
}

/// After a failed manager load: every monitor this boot archived for a never-funded entry goes back to its active key,
/// and the entry is marked neither archived nor closed (the post-load reconciliation decides). Returns true when any
/// monitor was put back — the caller then loads once more.
pub fn unarchive_after_failed_load(storage: &dyn LijStorage, monitor_prefix: &str, archived_prefix: &str) -> bool {
    let keys: Vec<String> = match storage.get(ARCHIVED_THIS_BOOT_KEY) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Vec::new(),
    };
    if keys.is_empty() { return false; }
    let mut map = load_never_funded(storage);
    let mut moved = 0usize;
    for op_key in &keys {
        let archived_key = format!("{archived_prefix}{op_key}");
        let active_key = format!("{monitor_prefix}{op_key}");
        if let Ok(Some(blob)) = storage.get(&archived_key) {
            if storage.set(&active_key, &blob).is_ok() {
                let _ = storage.delete(&archived_key);
                moved += 1;
                log::error!("[jit-trust] boot: the manager did not load — the monitor of never-funded channel (funding {op_key}) archived this boot is PUT BACK ({archived_key} -> {active_key})");
            }
        }
        if let Some(r) = map.get_mut(op_key) { r.archived = false; r.closed = false; }
    }
    save_never_funded(storage, &map);
    clear_archived_this_boot(storage);
    moved > 0
}

pub fn load_never_funded(storage: &dyn LijStorage) -> HashMap<String, NeverFunded> {
    match storage.get(NEVER_FUNDED_KEY) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => HashMap::new(),
    }
}

pub fn save_never_funded(storage: &dyn LijStorage, m: &HashMap<String, NeverFunded>) {
    if m.is_empty() {
        let _ = storage.delete(NEVER_FUNDED_KEY);
        return;
    }
    if let Ok(b) = serde_json::to_vec(m) {
        let _ = storage.set(NEVER_FUNDED_KEY, &b);
    }
}

/// The funding outpoint as the map's key and as the monitor key's tail: display-hex txid, colon, index.
pub fn outpoint_key(txid_display_hex: &str, index: u32) -> String {
    format!("{txid_display_hex}:{index}")
}

/// What one channel looks like to the rule, read from LDK's `ChannelDetails`, its monitor and the wallet's books.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelView {
    pub is_outbound: bool,
    pub confirmations_required: Option<u32>,
    pub confirmations: Option<u32>,
    /// The monitor's claimable balance for us, sats (`get_claimable_balances` summed) — the figure the wallet owns.
    pub our_claimable_sats: u64,
    pub pending_inbound_htlcs: usize,
    pub pending_outbound_htlcs: usize,
    /// The funding txid is in the tier-2 walk's pending list or confirmed history.
    pub funding_known_to_books: bool,
}

/// Why the rule refused — a plain sentence for the log.
pub fn refuse_reason(sender_is_counterparty: bool, sender_is_active_lsp: bool, v: &ChannelView) -> Option<&'static str> {
    if !sender_is_counterparty {
        return Some("the sender is not the channel's counterparty");
    }
    if !sender_is_active_lsp {
        return Some("the sender is not this wallet's active provider");
    }
    if let Some(r) = refuse_reason_channel(v) {
        return Some(r);
    }
    None
}

/// The channel-side checks alone (shared by the message rule and the audit).
pub fn refuse_reason_channel(v: &ChannelView) -> Option<&'static str> {
    if v.is_outbound {
        return Some("the channel is outbound — this wallet funded it");
    }
    if v.confirmations_required != Some(0) {
        return Some("the channel is not zero-conf");
    }
    if v.confirmations.unwrap_or(0) > 0 {
        return Some("the funding has confirmations — it exists on chain");
    }
    if v.our_claimable_sats > 0 {
        return Some("this wallet owns sats in the channel");
    }
    if v.pending_inbound_htlcs > 0 || v.pending_outbound_htlcs > 0 {
        return Some("a payment is pending in the channel");
    }
    if v.funding_known_to_books {
        return Some("the funding is known to this wallet's own books");
    }
    None
}

/// Ask the provider what became of a held JIT funding: GET {endpoint}/v1/jit-funding/status?client_pubkey=…&funding=txid:vout
/// (adapter 0.124.0+, the route token as every wallet route). Answers the record's `state` — "funded" | "held" | "paid"
/// | "published" | "confirmed" | "abandoned" | "cancelled" | "orphan" — or None when the provider has no record, runs an
/// older adapter, or cannot be reached. The caller treats None as "nothing known": never a reason to act.
#[cfg(target_arch = "wasm32")]
pub async fn fetch_funding_status(endpoint: &str, route_macaroon: &str, client_pubkey_hex: &str, funding_key: &str) -> Option<String> {
    let url = format!("{}/v1/jit-funding/status?client_pubkey={}&funding={}", endpoint.trim_end_matches('/'), client_pubkey_hex, funding_key);
    match crate::node::fetch_get_with_macaroon(&url, route_macaroon).await {
        Ok(text) => parse_funding_status(&text),
        Err(e) => { log::debug!("[jit-trust] funding status not answered for {funding_key}: {e}"); None }
    }
}

/// The `state` field of the provider's answer; None when absent or not a string.
pub fn parse_funding_status(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get("state").and_then(|x| x.as_str()).map(|x| x.to_string())
}

/// The watch's question: does this channel hold our sats on a funding nobody has seen?
pub fn watch_applies(v: &ChannelView) -> bool {
    !v.is_outbound
        && v.confirmations_required == Some(0)
        && v.confirmations.unwrap_or(0) == 0
        && v.our_claimable_sats > 0
        && !v.funding_known_to_books
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> ChannelView {
        ChannelView {
            is_outbound: false,
            confirmations_required: Some(0),
            confirmations: Some(0),
            our_claimable_sats: 0,
            pending_inbound_htlcs: 0,
            pending_outbound_htlcs: 0,
            funding_known_to_books: false,
        }
    }

    #[test]
    fn the_clean_case_is_dropped() {
        assert_eq!(refuse_reason(true, true, &clean()), None);
    }

    #[test]
    fn a_stranger_or_another_provider_is_refused() {
        assert_eq!(refuse_reason(false, true, &clean()), Some("the sender is not the channel's counterparty"));
        assert_eq!(refuse_reason(true, false, &clean()), Some("the sender is not this wallet's active provider"));
    }

    #[test]
    fn a_channel_with_our_money_is_never_dropped() {
        let mut v = clean(); v.our_claimable_sats = 1;
        assert_eq!(refuse_reason(true, true, &v), Some("this wallet owns sats in the channel"));
        let mut v = clean(); v.pending_inbound_htlcs = 1;
        assert_eq!(refuse_reason(true, true, &v), Some("a payment is pending in the channel"));
        let mut v = clean(); v.pending_outbound_htlcs = 1;
        assert_eq!(refuse_reason(true, true, &v), Some("a payment is pending in the channel"));
    }

    #[test]
    fn a_funding_that_exists_is_never_dropped() {
        let mut v = clean(); v.confirmations = Some(1);
        assert_eq!(refuse_reason(true, true, &v), Some("the funding has confirmations — it exists on chain"));
        let mut v = clean(); v.funding_known_to_books = true;
        assert_eq!(refuse_reason(true, true, &v), Some("the funding is known to this wallet's own books"));
    }

    #[test]
    fn only_inbound_zero_conf_channels_qualify() {
        let mut v = clean(); v.is_outbound = true;
        assert_eq!(refuse_reason(true, true, &v), Some("the channel is outbound — this wallet funded it"));
        let mut v = clean(); v.confirmations_required = Some(1);
        assert_eq!(refuse_reason(true, true, &v), Some("the channel is not zero-conf"));
        let mut v = clean(); v.confirmations_required = None;
        assert_eq!(refuse_reason(true, true, &v), Some("the channel is not zero-conf"));
    }

    #[test]
    fn the_watch_speaks_only_for_our_sats_on_an_unseen_funding() {
        assert!(!watch_applies(&clean()), "nothing owned — the audit's case, not the watch's");
        let mut v = clean(); v.our_claimable_sats = 50_000;
        assert!(watch_applies(&v));
        v.funding_known_to_books = true;
        assert!(!watch_applies(&v), "the books know the funding — the provider published");
        let mut v = clean(); v.our_claimable_sats = 50_000; v.confirmations = Some(1);
        assert!(!watch_applies(&v));
        let mut v = clean(); v.our_claimable_sats = 50_000; v.is_outbound = true;
        assert!(!watch_applies(&v));
    }

    #[test]
    fn the_providers_answer_is_read_by_its_state_field_alone() {
        assert_eq!(parse_funding_status(r#"{"ok":true,"state":"abandoned","txid":"aa"}"#), Some("abandoned".to_string()));
        assert_eq!(parse_funding_status(r#"{"ok":true,"state":"published"}"#), Some("published".to_string()));
        assert_eq!(parse_funding_status(r#"{"ok":false,"error":"not found"}"#), None, "no record — nothing known");
        assert_eq!(parse_funding_status("<html>404</html>"), None, "an older adapter's 404 page — nothing known");
        assert_eq!(parse_funding_status(r#"{"state":7}"#), None);
    }

    #[test]
    fn the_map_round_trips_and_an_empty_map_deletes_its_key() {
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut m = HashMap::new();
        m.insert(outpoint_key("aa", 1), NeverFunded { channel_id: "cc".into(), counterparty: "02ab".into(), at_ms: 7, how: "message".into(), archived: false, closed: true });
        save_never_funded(&storage, &m);
        assert_eq!(load_never_funded(&storage), m);
        save_never_funded(&storage, &HashMap::new());
        assert!(load_never_funded(&storage).is_empty());
        assert!(storage.get(NEVER_FUNDED_KEY).unwrap().is_none());
    }

    #[test]
    fn a_v363_entry_without_the_closed_flag_reads_as_not_closed() {
        // v364 (the review, finding 5): an entry written by v363 has no `closed`; it must NOT lose its monitor at boot on
        // the strength of that — the post-load reconciliation decides (channel gone → closed; still there → removed)
        let storage = crate::storage::native_storage::MemoryStorage::new();
        storage.set(NEVER_FUNDED_KEY, br#"{"aa:1":{"channel_id":"cc","counterparty":"02ab","at_ms":7,"how":"message","archived":false}}"#).unwrap();
        let m = load_never_funded(&storage);
        assert_eq!(m.len(), 1);
        assert!(!m["aa:1"].closed);
        assert!(!m["aa:1"].archived);
    }

    #[test]
    fn a_failed_load_puts_this_boots_archived_monitors_back_once() {
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut m = HashMap::new();
        m.insert("aa:1".to_string(), NeverFunded { channel_id: "cc".into(), counterparty: "02ab".into(), at_ms: 7, how: "audit".into(), archived: true, closed: true });
        m.insert("bb:0".to_string(), NeverFunded { channel_id: "dd".into(), counterparty: "02ab".into(), at_ms: 8, how: "message".into(), archived: true, closed: true });
        save_never_funded(&storage, &m);
        // the boot archived aa:1 (its blob moved) and noted it; bb:0 was archived at an earlier boot (not noted)
        storage.set("m:bb:0", b"old").unwrap(); storage.set("a:bb:0", b"old-archived").unwrap(); storage.delete("m:bb:0").unwrap();
        storage.set("a:aa:1", b"monitor-bytes").unwrap();
        note_archived_this_boot(&storage, &["aa:1".to_string()]);
        assert!(storage.get(ARCHIVED_THIS_BOOT_KEY).unwrap().is_some());
        // the manager did not load
        assert!(unarchive_after_failed_load(&storage, "m:", "a:"), "one monitor put back");
        assert_eq!(storage.get("m:aa:1").unwrap().as_deref(), Some(&b"monitor-bytes"[..]), "the active key is back");
        assert!(storage.get("a:aa:1").unwrap().is_none(), "the archived copy is gone");
        assert!(storage.get("m:bb:0").unwrap().is_none(), "an earlier boot's archive is not touched");
        assert_eq!(storage.get("a:bb:0").unwrap().as_deref(), Some(&b"old-archived"[..]));
        let after = load_never_funded(&storage);
        assert!(!after["aa:1"].archived && !after["aa:1"].closed, "the entry is open again — the next load reconciles it");
        assert!(after["bb:0"].archived && after["bb:0"].closed, "the other entry untouched");
        assert!(storage.get(ARCHIVED_THIS_BOOT_KEY).unwrap().is_none(), "the note is cleared");
        // a second failure with nothing noted does nothing — no endless retry
        assert!(!unarchive_after_failed_load(&storage, "m:", "a:"));
        // a successful load clears the note
        note_archived_this_boot(&storage, &["aa:1".to_string()]);
        clear_archived_this_boot(&storage);
        assert!(storage.get(ARCHIVED_THIS_BOOT_KEY).unwrap().is_none());
        // an empty list clears too
        note_archived_this_boot(&storage, &[]);
        assert!(storage.get(ARCHIVED_THIS_BOOT_KEY).unwrap().is_none());
    }

    #[test]
    fn the_outpoint_key_matches_the_monitor_key_tail() {
        // persist.rs monitor_key = MONITOR_KEY_PREFIX + "{txid}:{index}" with the txid's Display (reversed hex)
        assert_eq!(outpoint_key("0a15", 1), "0a15:1");
    }
}
