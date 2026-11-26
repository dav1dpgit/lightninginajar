//! sent_log.rs — v386 (S72, DP 2026-11-25 03:03 "Let's figure out why that happened and why it wasn't caught, and put
//! in a proper fix so it doesn't happen again"): THE END OF EVERY SENT LIGHTNING PAYMENT, WRITTEN DOWN BY THE ENGINE
//! AT THE MOMENT IT LEARNS IT.
//!
//! THE FIELD CASE. A Lightning payment of 5,088 sats was held by the recipient's provider, then came back while the
//! phone was closed. Afterwards the balance was right and the row in RECENT still read "Held on the way".
//!
//! THE CAUSE, READ IN THE CODE. The engine kept a sent payment's end in memory only (`payment_outcomes`, for the send
//! that is waiting on it). LDK drops its own record of a payment the moment its last HTLC fails back, and of a paid
//! one a few timer ticks later. So a payment that ended when no send was waiting on it — the wallet was closed, or
//! the send had already returned "held" — left nothing behind: the page found no record and could not tell paid from
//! returned. It then waited on a clock (24 hours for a hold at another provider) before asking the provider, which
//! cannot answer for a payment to an outside node.
//!
//! THE REPAIR. Push Keys and on-chain pays already have this (`push_latch`, `onchain_pay_latch`: their records are
//! written when the payment's end arrives, whoever is watching). This file is the same for every sent payment: one
//! small record per payment hash — paid (with the preimage and the fee) or failed (with LDK's reason) — kept in the
//! engine's own storage, so it is there after a restart and whenever the page comes to look.
//!
//! "paid" is final: a later "failed" for the same hash never replaces it (a further try of the same invoice under a
//! new payment id can fail after an earlier one was paid; the preimage is the evidence). A "failed" IS replaced by a
//! later "paid" (the send's own further tries).
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Records kept at most.
pub const KEEP: usize = 200;
/// A record older than this is dropped (30 days — longer than any HTLC can stay out).
pub const KEEP_SECS: u64 = 30 * 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SentEnd {
    /// "sent" (paid — the preimage came back) or "failed" (every HTLC came back unpaid).
    pub state: String,
    /// When the engine learned it, unix seconds.
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_msat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Write one end down. → true when the map changed (the caller then saves it).
pub fn record(map: &mut HashMap<String, SentEnd>, hash_hex: &str, end: SentEnd) -> bool {
    let key = hash_hex.to_ascii_lowercase();
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) { return false; }
    if end.state != "sent" && end.state != "failed" { return false; }
    if let Some(had) = map.get(&key) {
        if had.state == "sent" { return false; }                       // paid is final
        if end.state == "failed" && had.state == "failed" { return false; }   // the first time it came back is the time kept
    }
    let now = end.at;
    map.insert(key, end);
    prune(map, now);
    true
}

/// Drop what is older than KEEP_SECS, then the oldest beyond KEEP.
pub fn prune(map: &mut HashMap<String, SentEnd>, now: u64) {
    map.retain(|_, e| now.saturating_sub(e.at) <= KEEP_SECS);
    if map.len() > KEEP {
        let mut by_age: Vec<(String, u64)> = map.iter().map(|(k, e)| (k.clone(), e.at)).collect();
        by_age.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let cut = map.len() - KEEP;
        for (k, _) in by_age.into_iter().take(cut) { map.remove(&k); }
    }
}

/// For the page: `[{"hash","state","at",…}]`, newest first.
pub fn to_json(map: &HashMap<String, SentEnd>) -> String {
    let mut rows: Vec<(&String, &SentEnd)> = map.iter().collect();
    rows.sort_by(|a, b| b.1.at.cmp(&a.1.at).then_with(|| a.0.cmp(b.0)));
    let items: Vec<serde_json::Value> = rows.into_iter().map(|(h, e)| {
        let mut v = serde_json::to_value(e).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(o) = v.as_object_mut() { o.insert("hash".to_string(), serde_json::Value::String(h.clone())); }
        v
    }).collect();
    serde_json::Value::Array(items).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(c: char) -> String { std::iter::repeat(c).take(64).collect() }
    fn sent(at: u64) -> SentEnd { SentEnd { state: "sent".into(), at, preimage: Some("ab".repeat(32)), fee_msat: Some(1200), reason: None } }
    fn failed(at: u64) -> SentEnd { SentEnd { state: "failed".into(), at, preimage: None, fee_msat: None, reason: Some("UserAbandoned".into()) } }

    #[test]
    fn v386_a_payment_that_came_back_is_written_down_and_read_back() {
        let mut m = HashMap::new();
        assert!(record(&mut m, &h('a'), failed(100)));
        let j: serde_json::Value = serde_json::from_str(&to_json(&m)).unwrap();
        assert_eq!(j[0]["hash"], h('a'));
        assert_eq!(j[0]["state"], "failed");
        assert_eq!(j[0]["at"], 100);
        assert_eq!(j[0]["reason"], "UserAbandoned");
        assert!(j[0].get("preimage").is_none());
        // the same text read back gives the same map (it is what the engine stores)
        let stored = serde_json::to_string(&m).unwrap();
        let back: HashMap<String, SentEnd> = serde_json::from_str(&stored).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn v386_paid_is_final_and_a_failed_try_is_replaced_by_a_paid_one() {
        let mut m = HashMap::new();
        assert!(record(&mut m, &h('b'), failed(100)));          // the first try came back
        assert!(!record(&mut m, &h('b'), failed(150)));         // a further failed try changes nothing: the first time stands
        assert_eq!(m[&h('b')].at, 100);
        assert!(record(&mut m, &h('b'), sent(200)));            // a further try was paid
        assert_eq!(m[&h('b')].state, "sent");
        assert_eq!(m[&h('b')].fee_msat, Some(1200));
        assert!(!record(&mut m, &h('b'), failed(300)));         // nothing after "paid" replaces it
        assert!(!record(&mut m, &h('b'), sent(400)));
        assert_eq!(m[&h('b')].at, 200);
    }

    #[test]
    fn v386_only_a_payment_hash_and_the_two_states_are_taken() {
        let mut m = HashMap::new();
        assert!(!record(&mut m, "abc", failed(1)));
        assert!(!record(&mut m, &"zz".repeat(32), failed(1)));
        assert!(!record(&mut m, &h('c'), SentEnd { state: "pending".into(), at: 1, preimage: None, fee_msat: None, reason: None }));
        assert!(m.is_empty());
        assert!(record(&mut m, &h('C'), failed(1)));            // upper case is the same hash
        assert!(m.contains_key(&h('c')));
    }

    #[test]
    fn v386_old_records_go_and_the_newest_are_kept() {
        let mut m = HashMap::new();
        assert!(record(&mut m, &h('d'), failed(1_000)));
        assert!(record(&mut m, &h('e'), sent(1_000 + KEEP_SECS + 5)));   // KEEP_SECS and 5 s later
        assert!(!m.contains_key(&h('d')));
        assert!(m.contains_key(&h('e')));
        let mut big = HashMap::new();
        for i in 0..(KEEP as u64 + 20) { big.insert(format!("{:064x}", i), failed(10_000 + i)); }
        prune(&mut big, 20_000);
        assert_eq!(big.len(), KEEP);
        assert!(!big.contains_key(&format!("{:064x}", 0u64)));           // the oldest went
        assert!(big.contains_key(&format!("{:064x}", KEEP as u64 + 19)));
        let j: serde_json::Value = serde_json::from_str(&to_json(&big)).unwrap();
        assert_eq!(j[0]["at"], 10_000 + KEEP as u64 + 19);               // newest first
    }
}
