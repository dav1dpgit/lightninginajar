//! v382 (S71 Fri 2026-11-20, DP 09:45 "'The choices are: catch up, or close on purpose.' Agreed. Carry on and go beyond
//! A-E — approved." · 11:30 "Let's go and fold in." — docs/incidents/2026-11-20-channel-close-r2.md §4.1):
//! THE WALLET'S STATEMENT OF ITS CHANNEL RECORDS.
//!
//! A provider's node (LND) closes a channel by force the moment a wallet reconnects with an older state. On 2026-11-20
//! a phone did exactly that with both its channels. The provider cannot read the wallet's reconnect message (it is
//! encrypted between the wallet and LND), and LND's API gives out one of the two numbers it compares. What can decide
//! is the wallet's own record: each channel record's update number rises with every change and never falls. The
//! wallet STATES those numbers to its provider, signed with its node key; the provider (lijox-adapter 0.136.0,
//! state-marks.js) keeps the highest stated per channel; a wallet that states a lower number than its own high mark is
//! behind, and is given no pass for its Lightning connection.
//!
//! This file is the statement's fixed form and the text the node key signs — the twin of the adapter's
//! state-marks.js (`canonical`, `signedText`). No network here: the page sends the statement (POST /v1/state).

use std::collections::BTreeMap;

/// What every signed statement begins with.
pub const DOMAIN: &str = "lijox-state-v1:";
/// At most this many channel records in one statement (the adapter refuses more).
pub const MAX_CHANNELS: usize = 64;

/// The statement in one fixed form: "txid:vout=number" for each channel record, sorted by name, joined by commas.
/// "" for a wallet that holds no channel record.
pub fn canonical(ids: &BTreeMap<String, u64>) -> String {
    ids.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}

/// What the node key signs: the wallet's node key (hex), the statement's own time (unix ms) and the sha256 (hex) of
/// the statement in its fixed form.
pub fn signed_text(node_pubkey_hex: &str, at_ms: u64, ids: &BTreeMap<String, u64>) -> String {
    use bitcoin::hashes::{sha256, Hash};
    let h = sha256::Hash::hash(canonical(ids).as_bytes());
    format!("{DOMAIN}{}:{at_ms}:{}", node_pubkey_hex.to_ascii_lowercase(), hex::encode(h.as_byte_array()))
}

/// The request's body as the page sends it: {"node_pubkey","at","channels":{…},"signature"}. The page adds
/// "want_pass". `sign` is the node key's message signature (LND SignMessage form).
pub fn body_json(node_pubkey_hex: &str, at_ms: u64, ids: &BTreeMap<String, u64>, signature: &str) -> String {
    serde_json::json!({
        "node_pubkey": node_pubkey_hex.to_ascii_lowercase(),
        "at": at_ms,
        "channels": ids,
        "signature": signature,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4:0";

    fn ids(v: &[(&str, u64)]) -> BTreeMap<String, u64> { v.iter().map(|(k, n)| (k.to_string(), *n)).collect() }

    #[test]
    fn v382_the_fixed_form_is_the_adapters() {
        // state-marks.test.js m1: canonical({ [B]: 707, [A]: 1788 }) === A + '=1788,' + B + '=707'; canonical({}) === ''
        let b = format!("{}:1", "b6".repeat(32));
        assert_eq!(canonical(&ids(&[(&b, 707), (A, 1788)])), format!("{A}=1788,{b}=707"), "sorted by name, name=number, commas");
        assert_eq!(canonical(&ids(&[])), "", "no channel record: the empty text");
    }

    #[test]
    fn v382_the_signed_text_is_the_adapters_pinned() {
        // state-marks.test.js m1: signedText(PK, 5, { [A]: 1 }) === 'lijox-state-v1:' + PK + ':5:' + sha256hex(A + '=1')
        use bitcoin::hashes::{sha256, Hash};
        let pk = format!("02{}", "aa".repeat(32));
        let want = format!("lijox-state-v1:{pk}:5:{}", hex::encode(sha256::Hash::hash(format!("{A}=1").as_bytes()).as_byte_array()));
        assert_eq!(signed_text(&pk, 5, &ids(&[(A, 1)])), want);
        assert_eq!(signed_text(&pk.to_uppercase().replace("AA", "aa").replace("02", "02"), 5, &ids(&[(A, 1)])), want, "the key is written in lowercase hex");
        // the empty statement signs the hash of the empty text
        assert!(signed_text(&pk, 7, &ids(&[])).ends_with(":7:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    #[test]
    fn v382_the_body_carries_the_statement_as_signed() {
        let pk = format!("02{}", "aa".repeat(32));
        let v: serde_json::Value = serde_json::from_str(&body_json(&pk, 1795000000000, &ids(&[(A, 1788)]), "sig")).unwrap();
        assert_eq!(v["node_pubkey"], pk);
        assert_eq!(v["at"], 1795000000000u64);
        assert_eq!(v["channels"][A], 1788);
        assert_eq!(v["signature"], "sig");
    }
}
