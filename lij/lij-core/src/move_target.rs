//! move_target.rs — v394 (S73, DP 2026-11-26: "Maybe we make it so the wallet can handle having a channel open from
//! the new provider during a switch only"; the eight rulings of 12:11; 13:08 "Work to finish Way 1" —
//! docs/design/balance-transfer/balance-transfer-r2.md): THE PROVIDER THIS WALLET IS MOVING TO.
//!
//! A wallet has one provider in use. A balance transfer ("pay across") sends everything the wallet can send from
//! its channel with that provider to a NEW provider, which opens a channel to the wallet and passes the payment on
//! over it. For the length of that move — and for nothing else — the engine has to deal with a second provider:
//!
//!   1. it takes a channel that provider opens, under the same rules as a channel from the provider in use
//!      (node.rs, OpenChannelRequest);
//!   2. it acts on that provider's "the funding was given up" message, and asks that provider — not the provider
//!      in use — what became of a held funding (node.rs, the JIT trust rule and its audit);
//!   3. it sends the new channel's record to that provider (node.rs, upload_channel_record_for_ready);
//!   4. it takes the move's own payment only when at least the agreed amount arrives (node.rs, PaymentClaimable):
//!      the wallet sent a known amount and the new provider stated its fee before the send, so less than
//!      `min_msat` on the move's hash goes back, and the wallet's own payment returns with it.
//!
//! The record is ONE: a wallet moves to one provider at a time. It is kept in storage (a reload in the middle of a
//! move must not turn the new provider's channel away), it ends by itself after `MOVE_LIFE_MS`, and it is cleared
//! when the move ends — by the page, or by the engine the moment that provider becomes the provider in use.
//! Nothing here sends a payment, closes a channel or changes the provider in use.

use serde::{Deserialize, Serialize};

use crate::{
    error::{LijError, LijResult},
    lsp::LspInfo,
    storage::LijStorage,
};

/// The storage key of the one move record.
pub const KEY_MOVE_TARGET: &str = "lij_move_target_v1";

/// A move that has not ended after this long is over: nothing more is taken from its provider on its account.
/// (A provider holds an address-rail payment for hours at most; a day covers a phone that was put away.)
pub const MOVE_LIFE_MS: u64 = 24 * 3600 * 1000;

/// The provider this wallet is moving to, and the one payment of the move.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveTarget {
    /// The provider's record, as the page checked it (its signature included) before the move began.
    pub info: LspInfo,
    /// The move's payment hash, 64 hex characters, lower case.
    pub payment_hash: String,
    /// The least this wallet takes on that hash, in millisats: what it sends less the provider's stated fee.
    pub min_msat: u64,
    /// When the move was named (unix ms).
    pub set_at_ms: u64,
    /// What arrived on the move's hash and was taken (millisats) — written by the engine.
    #[serde(default)]
    pub arrived_msat: Option<u64>,
    /// What arrived on the move's hash and was sent back as too little (millisats) — written by the engine.
    #[serde(default)]
    pub refused_msat: Option<u64>,
}

/// What the engine does with a payment that arrives while a move is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    /// Not the move's hash: every other rule of the engine decides, as before.
    NotTheMove,
    /// The move's hash and at least the agreed amount.
    Take,
    /// The move's hash and less than the agreed amount: it goes back.
    TooLittle,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Checks a move before it is named. `active_pubkey` is the provider in use (hex), when there is one.
pub fn validate(info: &LspInfo, payment_hash: &str, min_msat: u64, active_pubkey: Option<&str>) -> LijResult<()> {
    if !is_hex(&info.pubkey, 66) {
        return Err(LijError::Lsp("the provider to move to has no valid node key in its record".into()));
    }
    if !is_hex(payment_hash, 64) {
        return Err(LijError::Lsp("the move's payment hash is not 64 hex characters".into()));
    }
    if min_msat == 0 {
        return Err(LijError::Lsp("the move names no least amount: nothing could be checked when the payment arrives".into()));
    }
    if let Some(a) = active_pubkey {
        if a.eq_ignore_ascii_case(&info.pubkey) {
            return Err(LijError::Lsp("that provider is already the provider in use: there is nothing to move".into()));
        }
    }
    Ok(())
}

/// A move record is live from the moment it is named until `MOVE_LIFE_MS` later.
pub fn is_live(t: &MoveTarget, now_ms: u64) -> bool {
    now_ms < t.set_at_ms.saturating_add(MOVE_LIFE_MS)
}

/// The stored move record, live or not. A record that cannot be read is no record.
pub fn load(storage: &dyn LijStorage) -> Option<MoveTarget> {
    match storage.get(KEY_MOVE_TARGET) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    }
}

/// The stored move record when it is still live.
pub fn load_live(storage: &dyn LijStorage, now_ms: u64) -> Option<MoveTarget> {
    load(storage).filter(|t| is_live(t, now_ms))
}

pub fn save(storage: &dyn LijStorage, t: &MoveTarget) -> LijResult<()> {
    let json = serde_json::to_vec(t).map_err(|e| LijError::Storage(format!("move record serialize: {e}")))?;
    storage.set(KEY_MOVE_TARGET, &json)
}

pub fn clear(storage: &dyn LijStorage) -> LijResult<()> {
    storage.delete(KEY_MOVE_TARGET)
}

/// True when `peer_hex` is the provider of a live move.
pub fn is_target(t: Option<&MoveTarget>, peer_hex: &str) -> bool {
    t.map(|t| t.info.pubkey.eq_ignore_ascii_case(peer_hex)).unwrap_or(false)
}

/// THE RULE for a payment that arrives while a move is named.
pub fn take_rule(t: &MoveTarget, payment_hash_hex: &str, amount_msat: u64) -> Take {
    if !t.payment_hash.eq_ignore_ascii_case(payment_hash_hex) {
        return Take::NotTheMove;
    }
    if amount_msat >= t.min_msat {
        Take::Take
    } else {
        Take::TooLittle
    }
}

/// The move record for the page: `null` when none is stored, else what was named, whether it is still live, and
/// what the engine has seen arrive. No secret is in it.
pub fn status_json(t: Option<&MoveTarget>, now_ms: u64) -> String {
    match t {
        None => "null".to_string(),
        Some(t) => serde_json::json!({
            "pubkey": t.info.pubkey.to_lowercase(),
            "name": t.info.name,
            "payment_hash": t.payment_hash.to_lowercase(),
            "min_msat": t.min_msat,
            "set_at_ms": t.set_at_ms,
            "live": is_live(t, now_ms),
            "ends_at_ms": t.set_at_ms.saturating_add(MOVE_LIFE_MS),
            "arrived_msat": t.arrived_msat,
            "refused_msat": t.refused_msat,
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;

    const KEY_A: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH: &str = "7373737373737373737373737373737373737373737373737373737373737373";

    fn provider(pubkey: &str) -> LspInfo {
        serde_json::from_value(serde_json::json!({
            "name": "New provider", "pubkey": pubkey, "endpoint": "https://new.example",
            "fee_ppm": 1000, "fee_base_sats": 0, "channel_open_fee_sats": 100,
            "max_channel_size_sats": 2000000, "uptime": 99, "supports_jit": true
        }))
        .expect("a provider record as the registry serves it")
    }

    fn target(set_at_ms: u64) -> MoveTarget {
        MoveTarget { info: provider(KEY_B), payment_hash: HASH.to_string(), min_msat: 889_899_000, set_at_ms, arrived_msat: None, refused_msat: None }
    }

    #[test]
    fn v394_a_move_is_checked_before_it_is_named() {
        assert!(validate(&provider(KEY_B), HASH, 1, Some(KEY_A)).is_ok());
        assert!(validate(&provider(KEY_B), HASH, 1, None).is_ok(), "a wallet with no provider in use may still name one");
        assert!(validate(&provider(KEY_A), HASH, 1, Some(KEY_A)).is_err(), "the provider in use is not a provider to move to");
        assert!(validate(&provider(KEY_A), HASH, 1, Some(&KEY_A.to_uppercase())).is_err(), "letter case does not hide it");
        assert!(validate(&provider("02abc"), HASH, 1, Some(KEY_A)).is_err(), "a short node key");
        assert!(validate(&provider(KEY_B), "73", 1, Some(KEY_A)).is_err(), "a short payment hash");
        assert!(validate(&provider(KEY_B), &HASH.replace('7', "z"), 1, Some(KEY_A)).is_err(), "not hex");
        assert!(validate(&provider(KEY_B), HASH, 0, Some(KEY_A)).is_err(), "no least amount");
    }

    #[test]
    fn v394_a_move_ends_by_itself() {
        let t = target(1_000);
        assert!(is_live(&t, 1_000));
        assert!(is_live(&t, 1_000 + MOVE_LIFE_MS - 1));
        assert!(!is_live(&t, 1_000 + MOVE_LIFE_MS), "one day later it is over");
        assert!(!is_live(&t, u64::MAX));
    }

    #[test]
    fn v394_only_the_named_provider_is_the_target() {
        let t = target(0);
        assert!(is_target(Some(&t), KEY_B));
        assert!(is_target(Some(&t), &KEY_B.to_uppercase()));
        assert!(!is_target(Some(&t), KEY_A));
        assert!(!is_target(None, KEY_B), "no move, no target");
    }

    #[test]
    fn v394_the_moves_payment_is_taken_only_whole() {
        let t = target(0);
        assert_eq!(take_rule(&t, HASH, 889_899_000), Take::Take, "exactly the agreed amount");
        assert_eq!(take_rule(&t, HASH, 889_899_001), Take::Take, "more is taken");
        assert_eq!(take_rule(&t, HASH, 889_898_999), Take::TooLittle, "one millisat short goes back");
        assert_eq!(take_rule(&t, HASH, 0), Take::TooLittle);
        assert_eq!(take_rule(&t, &HASH.to_uppercase(), 889_899_000), Take::Take, "letter case of the hash");
        let other = "1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(take_rule(&t, other, 1), Take::NotTheMove, "another payment is not judged by the move's amount");
    }

    #[test]
    fn v394_the_record_is_kept_read_back_and_cleared() {
        let s = MemoryStorage::new();
        assert!(load(&s).is_none());
        assert_eq!(status_json(load(&s).as_ref(), 5), "null");
        let mut t = target(1_000);
        save(&s, &t).unwrap();
        let back = load(&s).expect("the record is stored");
        assert_eq!(back.info.pubkey, KEY_B);
        assert_eq!(back.payment_hash, HASH);
        assert_eq!(back.min_msat, 889_899_000);
        assert!(load_live(&s, 2_000).is_some());
        assert!(load_live(&s, 1_000 + MOVE_LIFE_MS).is_none(), "a record past its day is not live");
        assert!(load(&s).is_some(), "but it is still there to be read and cleared");
        t.arrived_msat = Some(889_899_000);
        save(&s, &t).unwrap();
        let v: serde_json::Value = serde_json::from_str(&status_json(load(&s).as_ref(), 2_000)).unwrap();
        assert_eq!(v["pubkey"], KEY_B);
        assert_eq!(v["live"], true);
        assert_eq!(v["arrived_msat"], 889_899_000u64);
        assert!(v["refused_msat"].is_null());
        assert_eq!(v["ends_at_ms"], 1_000 + MOVE_LIFE_MS);
        clear(&s).unwrap();
        assert!(load(&s).is_none());
        // a record that cannot be read is no record
        s.set(KEY_MOVE_TARGET, b"not json").unwrap();
        assert!(load(&s).is_none());
    }
}
