//! v361 (S66 Mon 2026-11-02, DP 23:12 "Go on Phase 1" — LIGHTNING PAYS ON-CHAIN, the wallet's half; the design, every
//! ruling and the words: docs/design/onchain-pay/lightning-paying-onchain-v0.6.md). In one paragraph: the wallet pays
//! its provider two Lightning hold payments (A, the provider's fee and the lock's miner fee; B, the recipient's amount
//! plus the release's fee and a speed-up reserve, locked to this wallet's own hash H); the provider sends THE LOCK to a
//! HAND-OVER ADDRESS built from H, the wallet's release key W, the provider's take-back key L and the take-back block T;
//! after one confirmation the wallet builds and signs THE RELEASE from the hand-over address to the recipient (the unused
//! reserve back to its own m/84 address), publishing the secret in the witness — which is how the provider collects B.
//! A wallet that never releases loses only A: at T the provider takes its coins back and B returns.
//!
//! This module is the pure half: the hand-over script and address (the SAME bytes as the adapter's btc-tx.js —
//! pinned here against its vector), the release built and signed (SIGHASH_ALL over the whole transaction, so nothing
//! can rewrite the recipient; nSequence replaceable, so a faster release can replace it), the record and its states.
//! `node.rs` keeps the records, feeds the hand-over scripts to the block-filter walk (tier2::CHAIN_HANDOVER) and reads
//! the walk's events; `lib.rs` hands the page what it shows.
use bitcoin::{
    absolute::LockTime,
    hashes::{sha256, Hash},
    opcodes::all as op,
    script::{Builder, PushBytesBuf},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};

/// The states of a record, in the order they happen. `quoted` → `paying` (A and B sent) → `locked` (the provider says
/// the lock went; T known) → `lock_seen` (the walk saw the lock in a block) → `released` (the release sent) → `done`
/// (the release in a block). Side exits: `returned` (A and B came back; nothing locked), `taken_back` (the provider
/// took its coins back at T; B came back), `failed` (a send failed before anything was held).
pub const STATES: &[&str] = &["quoted", "paying", "locked", "lock_seen", "released", "done", "returned", "taken_back", "failed"];
pub const OPEN_STATES: &[&str] = &["quoted", "paying", "locked", "lock_seen", "released"];

/// One on-chain pay as this wallet records it (the secret and the release key are never stored — derived by `index`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OnchainPayRecord {
    pub index: u32,
    pub hash: String,              // H, hex — the record's key and payment B's hash
    pub state: String,
    pub provider: String,          // the provider's node key, hex
    pub endpoint: String,          // the provider's https base
    pub recipient: String,         // the on-chain address paid
    pub amount_sats: u64,          // to the recipient
    pub release_fee_sats: u64,     // the release's miner fee as quoted (the wallet's rate)
    pub reserve_sats: u64,         // the speed-up reserve
    pub lock_sats: u64,            // amount + release fee + reserve = what the lock carries
    pub provider_fee_sats: u64,    // the flat fee (A's first part)
    pub lock_fee_sats: u64,        // the lock's miner fee (A's second part)
    pub a_hash: String,            // A's hash (the provider's)
    pub a_bolt11: String,
    pub b_bolt11: String,
    pub l_pubkey: String,          // L, hex — the provider's take-back key
    pub w_pubkey: String,          // W, hex — this wallet's release key (derived; kept for the record's own check)
    pub refund_blocks: u32,        // T = the lock's block + this
    pub stop_release_blocks: u32,  // the wallet stops releasing this many blocks before T
    pub reserve_index: u32,        // the m/84 receive index the unused reserve returns to
    pub created: u64,              // unix seconds
    pub updated: u64,
    #[serde(default)] pub t: Option<u32>,                 // the take-back block, once the provider reports the lock
    #[serde(default)] pub lock_block: Option<u32>,        // the block the provider sent the lock at
    #[serde(default)] pub handover_address: Option<String>,
    #[serde(default)] pub lock_txid: Option<String>,      // as the provider reported it (bumps change it)
    #[serde(default)] pub lock_vout: Option<u32>,
    #[serde(default)] pub lock_seen_txid: Option<String>, // as the walk saw it
    #[serde(default)] pub lock_seen_height: Option<u32>,
    #[serde(default)] pub release_txid: Option<String>,
    #[serde(default)] pub release_hex: Option<String>,
    #[serde(default)] pub release_rate_sat_vb: Option<u64>,
    #[serde(default)] pub release_height: Option<u32>,
    #[serde(default)] pub a_payment_id: Option<String>,
    #[serde(default)] pub b_payment_id: Option<String>,
    #[serde(default)] pub ended: Option<u64>,
    #[serde(default)] pub end_reason: Option<String>,
    #[serde(default)] pub paid_block: Option<u32>,        // LDK's height when A and B went out (the T bound's anchor)
    #[serde(default)] pub walk_from: Option<u32>,         // set by the lock report: the walk re-reads from here once
    // v362 (Phase 2 — fractional rates, design v0.7; Phase 3 — the speed-up): the rates in sat per kilo-vbyte (a whole
    // number of thousandths of a sat/vB), the provider's six-block suggestion for the release, the fast copy of the
    // release at twice the rate (the whole reserve — the Black start page's "send the faster one"), the block the
    // first release went out at, and how many times it was replaced
    #[serde(default)] pub lock_rate_sat_kvb: Option<u64>,
    #[serde(default)] pub release_rate_suggested_sat_kvb: Option<u64>,
    #[serde(default)] pub release_rate_sat_kvb: Option<u64>,
    #[serde(default)] pub release_hex_fast: Option<String>,
    #[serde(default)] pub release_txid_fast: Option<String>,
    #[serde(default)] pub released_at_block: Option<u32>,
    #[serde(default)] pub release_replacements: u32,
}

impl OnchainPayRecord {
    pub fn is_open(&self) -> bool { OPEN_STATES.contains(&self.state.as_str()) }
    /// The last block at which this wallet will still release (v0.6 §7: 12 blocks before T).
    pub fn stop_release_block(&self) -> Option<u32> { self.t.map(|t| t.saturating_sub(self.stop_release_blocks)) }
}

/// SHA-256 of the secret — H.
pub fn hash_of(secret: &[u8; 32]) -> [u8; 32] { sha256::Hash::hash(secret).to_byte_array() }

/// The hand-over script (v0.6 §6) — byte for byte the adapter's `btc-tx.js handoverScript`:
/// `OP_SIZE <32> OP_EQUAL OP_IF OP_SHA256 <H> OP_EQUALVERIFY <W> OP_ELSE OP_DROP <T> OP_CHECKLOCKTIMEVERIFY OP_DROP <L> OP_ENDIF OP_CHECKSIG`
/// W and L are the 33-byte compressed keys as bytes (the script embeds them; the adapter hands L over as hex).
pub fn handover_script(h: &[u8; 32], w: &[u8; 33], l: &[u8; 33], t: u32) -> ScriptBuf {
    let hp = PushBytesBuf::try_from(h.to_vec()).expect("32 bytes push");
    let wp = PushBytesBuf::try_from(w.to_vec()).expect("33 bytes push");
    let lp = PushBytesBuf::try_from(l.to_vec()).expect("33 bytes push");
    Builder::new()
        .push_opcode(op::OP_SIZE)
        .push_int(32)
        .push_opcode(op::OP_EQUAL)
        .push_opcode(op::OP_IF)
        .push_opcode(op::OP_SHA256)
        .push_slice(hp)
        .push_opcode(op::OP_EQUALVERIFY)
        .push_slice(wp)
        .push_opcode(op::OP_ELSE)
        .push_opcode(op::OP_DROP)
        .push_int(t as i64)
        .push_opcode(op::OP_CLTV)
        .push_opcode(op::OP_DROP)
        .push_slice(lp)
        .push_opcode(op::OP_ENDIF)
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}
/// The hand-over address — P2WSH of the script.
pub fn handover_address(script: &ScriptBuf, network: Network) -> Address { Address::p2wsh(script, network) }

/// The release's size in vbytes (an estimate for the fee): one P2WSH input whose witness is a 72-byte signature, the
/// 32-byte secret and the script (about 180 bytes), one P2WPKH or P2WSH-sized output to the recipient, and the reserve
/// output back when there is one.
pub fn release_vbytes(script_len: usize, recipient_spk_len: usize, with_reserve: bool) -> u64 {
    let witness = 1 + 1 + 72 + 1 + 32 + 3 + script_len as u64;   // count, sig, secret, script (a 2-byte length)
    let base = 10 + 41 + (8 + 1 + recipient_spk_len as u64) + if with_reserve { 31 } else { 0 };
    (base * 4 + 2 + witness + 3) / 4
}

/// THE RELEASE: from the lock's output (`lock`, `lock_value` sats) at the hand-over `script` to `recipient_spk` with
/// `amount_sats`; the rest, less a fee at `rate_sat_vb`, back to `reserve_spk` — or into the fee when it would be dust.
/// Signed by `w_key` with SIGHASH_ALL; the secret is the second witness item. `None` when the lock cannot pay the
/// amount and the fee. v362: the rate is in sat per KILO-vbyte (1 sat/vB = 1000; 0.2 sat/vB = 200), floored at 100
/// (0.1 sat/vB, Core 30+'s relay floor); the fee is rounded up once.
pub const MIN_RATE_SAT_KVB: u64 = 100;
pub fn fee_at(vbytes: u64, rate_sat_kvb: u64) -> u64 { (vbytes * rate_sat_kvb.max(MIN_RATE_SAT_KVB) + 999) / 1000 }
pub fn build_release(
    lock: OutPoint, lock_value: u64, script: &ScriptBuf, w_key: &SecretKey, secret: &[u8; 32],
    recipient_spk: &ScriptBuf, amount_sats: u64, reserve_spk: &ScriptBuf, rate_sat_kvb: u64,
) -> LijResult<Transaction> {
    const DUST: u64 = 294;
    if lock_value < amount_sats { return Err(LijError::Node("the lock carries less than the amount".into())); }
    let vb_with = release_vbytes(script.len(), recipient_spk.len(), true);
    let vb_without = release_vbytes(script.len(), recipient_spk.len(), false);
    let rest = lock_value - amount_sats;
    let fee_with = fee_at(vb_with, rate_sat_kvb);
    let (outputs, _fee) = if rest >= fee_with + DUST {
        (vec![TxOut { value: Amount::from_sat(amount_sats), script_pubkey: recipient_spk.clone() }, TxOut { value: Amount::from_sat(rest - fee_with), script_pubkey: reserve_spk.clone() }], fee_with)
    } else {
        let fee_without = fee_at(vb_without, rate_sat_kvb);
        if rest < fee_without { return Err(LijError::Node(format!("the lock cannot pay the amount and a fee of {fee_without} sats at {} sat/vB", (rate_sat_kvb.max(MIN_RATE_SAT_KVB) as f64) / 1000.0))); }
        (vec![TxOut { value: Amount::from_sat(amount_sats), script_pubkey: recipient_spk.clone() }], rest)
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: lock, script_sig: ScriptBuf::new(), sequence: Sequence(0xffff_fffd), witness: Witness::new() }],
        output: outputs,
    };
    let secp = Secp256k1::new();
    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(0, script, Amount::from_sat(lock_value), EcdsaSighashType::All)
        .map_err(|e| LijError::Node(format!("release sighash: {e}")))?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, w_key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut w = Witness::new();
    w.push(sig_bytes);
    w.push(secret.to_vec());
    w.push(script.to_bytes());
    tx.input[0].witness = w;
    Ok(tx)
}

/// The record's check of the provider's word (v0.6 §3 step 6): the address the provider reports must be the script's
/// own, and T must sit inside the agreed bounds — at least the lock's block + refund_blocks − 4, at most the block B
/// was paid at + b_expiry − 40 (the provider's collection margin). Returns the script on success.
pub fn check_lock_report(
    h: &[u8; 32], w: &[u8; 33], l: &[u8; 33], t: u32, lock_block: u32, refund_blocks: u32, paid_block: u32, b_expiry_blocks: u32, reported_address: &str, network: Network,
) -> LijResult<ScriptBuf> {
    let t_min = lock_block.saturating_add(refund_blocks.saturating_sub(4));
    let t_max = paid_block.saturating_add(b_expiry_blocks.saturating_sub(40));
    if t < t_min || t > t_max { return Err(LijError::Node(format!("the take-back block {t} is outside the agreed bounds {t_min}..{t_max}"))); }
    let script = handover_script(h, w, l, t);
    let addr = handover_address(&script, network).to_string();
    if addr != reported_address.trim() { return Err(LijError::Node("the provider's hand-over address is not the one H, W, L and T make".into())); }
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn pk(hex_s: &str) -> [u8; 33] { hex::decode(hex_s).unwrap().try_into().unwrap() }
    fn h32(b: u8) -> [u8; 32] { [b; 32] }

    /// THE SAME BYTES AS THE ADAPTER: btc-tx.test.js pins this exact hex for H = 11…, W = 02aa…, L = 03bb…, T = 975,123.
    #[test]
    fn v361_the_handover_script_is_byte_for_byte_the_adapters() {
        let s = handover_script(&h32(0x11), &pk(&format!("02{}", "aa".repeat(32))), &pk(&format!("03{}", "bb".repeat(32))), 975_123);
        let want = format!("82012087{}{}{}{}{}{}", "63a820", "11".repeat(32), format!("8821{}", format!("02{}", "aa".repeat(32))), "67750313e10eb175", format!("21{}", format!("03{}", "bb".repeat(32))), "68ac");
        assert_eq!(hex::encode(s.as_bytes()), want);
        assert_eq!(s.len(), 118);
        let a = handover_address(&s, Network::Bitcoin);
        assert!(a.to_string().starts_with("bc1q") && a.to_string().len() == 62, "{a}");
        assert_eq!(a.script_pubkey(), ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(s.as_bytes())));
    }

    #[test]
    fn v361_the_release_pays_the_recipient_returns_the_reserve_and_verifies_under_w() {
        let secp = Secp256k1::new();
        let w_key = SecretKey::from_slice(&sha256::Hash::hash(b"wallet release key").to_byte_array()).unwrap();
        let w = PublicKey::from_secret_key(&secp, &w_key);
        let secret = sha256::Hash::hash(b"the payment secret").to_byte_array();
        let h = hash_of(&secret);
        let l = pk(&format!("03{}", "bb".repeat(32)));
        let script = handover_script(&h, &w.serialize(), &l, 975_123);
        let recipient = Address::from_str("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3").unwrap().assume_checked().script_pubkey();
        let reserve = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap().assume_checked().script_pubkey();
        let lock = OutPoint::from_str(&format!("{}:1", "ab".repeat(32))).unwrap();
        for rate in [1u64, 5, 10] {   // whole sat/vB — the rate goes in as sat/kvB (v362)
            let tx = build_release(lock, 101_700, &script, &w_key, &secret, &recipient, 100_000, &reserve, rate * 1000).unwrap();
            assert_eq!(tx.input.len(), 1); assert_eq!(tx.input[0].previous_output, lock);
            assert_eq!(tx.input[0].sequence, Sequence(0xffff_fffd), "replaceable");
            assert_eq!(tx.lock_time, LockTime::ZERO);
            assert_eq!(tx.output[0].value.to_sat(), 100_000); assert_eq!(tx.output[0].script_pubkey, recipient);
            let fee = 101_700 - tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
            let vb = (tx.weight().to_wu() + 3) / 4;
            if tx.output.len() == 2 {
                assert_eq!(tx.output[1].script_pubkey, reserve);
                assert!(fee >= vb * rate && fee <= vb * rate + 12, "rate {rate}: fee {fee} for {vb} vB");
            } else {
                assert_eq!(rate, 10, "the release at twice the starting rate eats the whole reserve (no dust output)");
                assert_eq!(fee, 1_700);
            }
            // the witness, by hand: [signature, secret, script]; the signature is W's over the BIP-143 hash of the script
            let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
            assert_eq!(items.len(), 3); assert_eq!(items[1], &secret[..]); assert_eq!(items[2], script.as_bytes());
            let sighash = SighashCache::new(&tx).p2wsh_signature_hash(0, &script, Amount::from_sat(101_700), EcdsaSighashType::All).unwrap();
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&items[0][..items[0].len() - 1]).unwrap();
            secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sig, &w).expect("W's signature");
            assert_eq!(items[0][items[0].len() - 1], 0x01);
            let again = build_release(lock, 101_700, &script, &w_key, &secret, &recipient, 100_000, &reserve, rate * 1000).unwrap();
            assert_eq!(again, tx, "the same bytes every time");
        }
        assert!(build_release(lock, 100_050, &script, &w_key, &secret, &recipient, 100_000, &reserve, 5_000).is_err(), "a lock that cannot pay the fee is refused");
        assert!(build_release(lock, 101_700, &script, &w_key, &secret, &recipient, 100_000, &reserve, 40_000).is_err(), "40 sat/vB needs more than the reserve holds — refused, the amount is never touched");
        assert!(build_release(lock, 90_000, &script, &w_key, &secret, &recipient, 100_000, &reserve, 5_000).is_err(), "a lock below the amount is refused");
        // v362 (Phase 2): a fractional rate — 0.2 sat/vB on a 170-vB release is 34 sats, rounded up once; 0.05 is floored at 0.1
        let frac = build_release(lock, 101_700, &script, &w_key, &secret, &recipient, 100_000, &reserve, 200).unwrap();
        let fee_frac = 101_700 - frac.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
        let vb_frac = (frac.weight().to_wu() + 3) / 4;
        assert!(fee_frac >= (vb_frac * 200 + 999) / 1000 && fee_frac <= (vb_frac * 200 + 999) / 1000 + 3, "0.2 sat/vB: fee {fee_frac} for {vb_frac} vB");
        assert_eq!(fee_at(170, 200), 34); assert_eq!(fee_at(170, 50), fee_at(170, 100)); assert_eq!(fee_at(170, 1_000), 170); assert_eq!(fee_at(170, 1_234), 210);
    }

    #[test]
    fn v361_the_lock_report_check_rebuilds_the_address_and_bounds_t() {
        let w = pk(&format!("02{}", "aa".repeat(32))); let l = pk(&format!("03{}", "bb".repeat(32))); let h = h32(0x11);
        let t = 975_000 + 144;
        let addr = handover_address(&handover_script(&h, &w, &l, t), Network::Bitcoin).to_string();
        assert!(check_lock_report(&h, &w, &l, t, 975_000, 144, 974_999, 200, &addr, Network::Bitcoin).is_ok());
        assert!(check_lock_report(&h, &w, &l, t, 975_000, 144, 974_999, 200, &format!("{}x", &addr[..addr.len() - 1]), Network::Bitcoin).is_err(), "another address");
        assert!(check_lock_report(&h, &w, &l, 975_000 + 139, 975_000, 144, 974_999, 200, &addr, Network::Bitcoin).is_err(), "T too low");
        assert!(check_lock_report(&h, &w, &l, 975_000 + 170, 975_000, 144, 974_999, 200, &addr, Network::Bitcoin).is_err(), "T past B's margin (974,999 + 160)");
        let t2 = 975_000 + 150; let addr2 = handover_address(&handover_script(&h, &w, &l, t2), Network::Bitcoin).to_string();
        assert!(check_lock_report(&h, &w, &l, t2, 975_000, 144, 974_999, 200, &addr2, Network::Bitcoin).is_ok(), "a later T inside the bounds, with its own address");
    }

    #[test]
    fn v361_the_secret_and_the_release_key_come_from_the_words_apart_from_everything_else() {
        let root = crate::key::RootKey::from_mnemonic(&"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(), Network::Bitcoin).unwrap();
        let s0 = root.onchain_pay_secret(0); let s1 = root.onchain_pay_secret(1);
        assert_ne!(s0, s1); assert_ne!(s0, root.push_preimage(0)); assert_ne!(s0, root.lnurlp_preimage(0));
        assert_eq!(s0, root.onchain_pay_secret(0), "stable");
        let k0 = root.onchain_pay_release_key(0).unwrap(); let k1 = root.onchain_pay_release_key(1).unwrap();
        assert_ne!(k0, k1);
        assert_ne!(k0.secret_bytes(), root.lightning_node_key().unwrap().private_key.secret_bytes(), "not the identity at m/525h");
        assert_eq!(k0, root.onchain_pay_release_key(0).unwrap(), "stable");
        assert_eq!(release_vbytes(118, 34, true), release_vbytes(118, 34, false) + 31);
        assert!(release_vbytes(118, 34, true) > 140 && release_vbytes(118, 34, true) < 200, "{}", release_vbytes(118, 34, true));
    }
}
