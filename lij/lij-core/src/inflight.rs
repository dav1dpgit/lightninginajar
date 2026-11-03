//! v360 (S66 Mon 2026-11-02, DP 21:28 "Go" — Black start, THE IN-FLIGHT PAYMENT COLLECT; the plan is
//! docs/design/black-start/in-flight-collect-v0.1.md). Phase 0 of Lightning pays on-chain and the fix for Push
//! Key's exposure today: sats locked in a channel for a payment that has neither settled nor failed (an HTLC —
//! a Push Key's lock for up to 72 hours, a Lightning-pays-on-chain payment B for about a day) could not be
//! brought back through /recover's steps. The kit carried the signed HTLC transaction (the "return" of a payment
//! going out, the "claim" of a payment coming in whose secret the wallet knows) only as raw hex, and no
//! pre-signed sweep of its output.
//!
//! The fact that makes the fix small (checked in the bytes, `chan_utils::build_htlc_output`): BOLT 3 gives the
//! HTLC-timeout and HTLC-success transactions' single output THE SAME SCRIPT as the commitment's `to_local`
//! output — the revocation key, `to_self_delay`, the delayed payment key — and LDK's own `get_spendable_outputs`
//! treats any output carrying that script as a `DelayedPaymentOutput`. A fully signed HTLC transaction's txid is
//! fixed before broadcast (a witness never changes a txid). So its output's collect can be pre-signed now by the
//! very call that pre-signs the `to_local` collect (`spend_spendable_outputs`), with nSequence = `to_self_delay`,
//! valid on its own once the HTLC transaction has that many confirmations.
//!
//! This module is the pure half: the destination address of a leg's collect, the two collects, and the kit's
//! record of a leg. The channel monitor's walk (`lij_htlc_legs`, the LiJ patch to LDK's `channelmonitor.rs`)
//! hands over each leg's HTLC and descriptor; `node.rs`'s `escape_export` calls here.

use bitcoin::{
    bip32::{ChildNumber, DerivationPath},
    consensus::encode::serialize_hex,
    secp256k1::{All, Secp256k1},
    Address, Network, Transaction,
};
use lightning::chain::channelmonitor::LijHtlcLeg;
use lightning::sign::{OutputSpender, SpendableOutputDescriptor};

use crate::{
    error::{LijError, LijResult},
    key::RootKey,
};

/// The kit's two rates, in sat per 1000 weight: 10 sat/vB and 40 sat/vB — the `to_local` collect's.
pub const FEERATE_NORMAL_SAT_PER_KW: u32 = 2_500;
pub const FEERATE_HIGH_SAT_PER_KW: u32 = 10_000;

/// The wallet's m/84 receive address at `index` — where a kit sweep lands. The same derivation the
/// silent-payment and taproot legs use (`onchain_send::kit_sweeps_where`): any BIP84 wallet on the 12 words
/// finds it.
pub fn kit_destination(root_key: &RootKey, network: Network, index: u32) -> LijResult<Address> {
    let secp = Secp256k1::new();
    let parent = root_key.shutdown_xpriv()?;   // m/84'/{coin}'/0'/0
    let child = parent
        .derive_priv(&secp, &DerivationPath::from(vec![ChildNumber::from_normal_idx(index).map_err(|e| LijError::Key(format!("kit destination index: {e}")))?]))
        .map_err(|e| LijError::Key(format!("kit destination: {e}")))?;
    let pk = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    Ok(Address::p2wpkh(&bitcoin::CompressedPublicKey(pk.inner), network))
}

/// One collect: (txid, hex), or `None` when the output is too small to pay that rate — the `to_local`
/// collect's per-variant degradation, never a failed export.
fn collect<S: OutputSpender>(spender: &S, desc: &SpendableOutputDescriptor, dest: &Address, feerate: u32, secp: &Secp256k1<All>) -> Option<(String, String)> {
    spender
        .spend_spendable_outputs(&[desc], Vec::new(), dest.script_pubkey(), feerate, None, secp)
        .ok()
        .map(|tx| (tx.compute_txid().to_string(), serialize_hex(&tx)))
}

/// The kit's record of one payment in flight (the design's §3.2): the HTLC transaction itself, what it is,
/// when it is valid, how long its output then waits, and the two pre-signed collects to `dest`.
pub fn leg_json<S: OutputSpender>(spender: &S, leg: &LijHtlcLeg, tx: &Transaction, dest: &Address, dest_index: u32, secp: &Secp256k1<All>) -> serde_json::Value {
    let (returns_sats, collect_after_blocks) = match &leg.descriptor {
        SpendableOutputDescriptor::DelayedPaymentOutput(d) => (d.output.value.to_sat(), d.to_self_delay),
        _ => (0, 0),
    };
    let normal = collect(spender, &leg.descriptor, dest, FEERATE_NORMAL_SAT_PER_KW, secp);
    let high = collect(spender, &leg.descriptor, dest, FEERATE_HIGH_SAT_PER_KW, secp);
    serde_json::json!({
        "kind": if leg.offered { "return" } else { "claim" },
        "txid": tx.compute_txid().to_string(),
        "hex": serialize_hex(tx),
        "amount_sats": leg.amount_sat,
        "returns_sats": returns_sats,
        "valid_from_block": if leg.offered { leg.cltv_expiry } else { 0 },
        "collect_after_blocks": collect_after_blocks,
        "payment_hash": hex::encode(leg.payment_hash.0),
        "collect_address": dest.to_string(),
        "collect_index": dest_index,
        "collect_txid_normal": normal.as_ref().map(|v| v.0.clone()),
        "collect_hex_normal": normal.as_ref().map(|v| v.1.clone()),
        "collect_txid_high": high.as_ref().map(|v| v.0.clone()),
        "collect_hex_high": high.as_ref().map(|v| v.1.clone()),
    })
}

#[cfg(test)]
mod tests {
    //! A synthetic channel — two KeysManagers, the holder's commitment keys at one commitment number, one offered
    //! HTLC — and the exact calls the production path makes: `build_htlc_transaction` for the return,
    //! a `DelayedPaymentOutput` at its output, `spend_spendable_outputs` for the collect. The collect's witness
    //! is then checked by hand: the BIP-143 signature hash over the revokable script, the ECDSA signature
    //! against the delayed payment key, the sequence, the destination and the fee.
    use super::*;
    use bitcoin::{
        hashes::Hash,
        secp256k1::{ecdsa::Signature, Message},
        sighash::{EcdsaSighashType, SighashCache},
        OutPoint as BtcOutPoint, Txid,
    };
    use lightning::chain::transaction::OutPoint;
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_revokeable_redeemscript, ChannelTransactionParameters,
        CounterpartyChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning::ln::channel_keys::DelayedPaymentKey;
    use lightning::sign::{ChannelSigner, DelayedPaymentOutputDescriptor, KeysManager, SignerProvider};
    use lightning::types::features::ChannelTypeFeatures;
    use lightning::types::payment::PaymentHash;

    const CSV: u16 = 144;
    const CHANNEL_SATS: u64 = 1_000_000;
    const HTLC_MSAT: u64 = 100_000_000;   // 100,000 sats
    const EXPIRY: u32 = 975_123;
    const COMMITMENT_FEERATE: u32 = 253;

    struct Synthetic {
        holder: KeysManager,
        channel_keys_id: [u8; 32],
        keys: TxCreationKeys,
        per_commitment_point: bitcoin::secp256k1::PublicKey,
        params: ChannelTransactionParameters,
        htlc: HTLCOutputInCommitment,
        commitment_txid: Txid,
    }

    fn synthetic(offered: bool) -> Synthetic {
        let secp = Secp256k1::new();
        let holder = KeysManager::new(&[7u8; 32], 0, 0, false);
        let counterparty = KeysManager::new(&[9u8; 32], 0, 0, false);
        let channel_keys_id = holder.generate_channel_keys_id(false, 1);
        let holder_signer = holder.derive_channel_signer(channel_keys_id);
        let cp_signer = counterparty.derive_channel_signer(counterparty.generate_channel_keys_id(true, 2));
        let holder_pubkeys = holder_signer.pubkeys(&secp);
        let cp_pubkeys = cp_signer.pubkeys(&secp);
        let per_commitment_point = holder_signer.get_per_commitment_point(0xffff_ffff_ffff - 3, &secp).unwrap();
        let keys = TxCreationKeys::derive_new(
            &secp, &per_commitment_point,
            &holder_pubkeys.delayed_payment_basepoint, &holder_pubkeys.htlc_basepoint,
            &cp_pubkeys.revocation_basepoint, &cp_pubkeys.htlc_basepoint,
        );
        let commitment_txid = Txid::from_byte_array([0xab; 32]);
        let params = ChannelTransactionParameters {
            holder_pubkeys: holder_pubkeys.clone(),
            holder_selected_contest_delay: CSV,
            is_outbound_from_holder: true,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters { pubkeys: cp_pubkeys, selected_contest_delay: CSV }),
            funding_outpoint: Some(OutPoint { txid: Txid::from_byte_array([0xf0; 32]), index: 0 }),
            splice_parent_funding_txid: None,
            channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
            channel_value_satoshis: CHANNEL_SATS,
        };
        let htlc = HTLCOutputInCommitment { offered, amount_msat: HTLC_MSAT, cltv_expiry: EXPIRY, payment_hash: PaymentHash([0x11; 32]), transaction_output_index: Some(2) };
        Synthetic { holder, channel_keys_id, keys, per_commitment_point, params, htlc, commitment_txid }
    }

    fn return_tx(s: &Synthetic) -> Transaction {
        build_htlc_transaction(&s.commitment_txid, COMMITMENT_FEERATE, CSV, &s.htlc, &s.params.channel_type_features, &s.keys.broadcaster_delayed_payment_key, &s.keys.revocation_key)
    }

    fn leg_of(s: &Synthetic, tx: &Transaction) -> LijHtlcLeg {
        LijHtlcLeg {
            tx_index: 1,
            offered: s.htlc.offered,
            amount_sat: s.htlc.amount_msat / 1000,
            cltv_expiry: s.htlc.cltv_expiry,
            payment_hash: s.htlc.payment_hash,
            descriptor: SpendableOutputDescriptor::DelayedPaymentOutput(DelayedPaymentOutputDescriptor {
                outpoint: OutPoint { txid: tx.compute_txid(), index: 0 },
                per_commitment_point: s.per_commitment_point,
                to_self_delay: CSV,
                output: tx.output[0].clone(),
                revocation_pubkey: s.keys.revocation_key.clone(),
                channel_keys_id: s.channel_keys_id,
                channel_value_satoshis: CHANNEL_SATS,
                channel_transaction_parameters: Some(s.params.clone()),
            }),
        }
    }

    fn dest() -> Address {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[5u8; 32]).unwrap();
        Address::p2wpkh(&bitcoin::CompressedPublicKey(sk.public_key(&secp)), Network::Bitcoin)
    }

    /// THE FACT: the return's single output carries the to_local script — the revokable redeem script's P2WSH.
    #[test]
    fn the_returns_output_is_the_to_local_script_and_its_locktime_is_the_expiry() {
        let s = synthetic(true);
        let tx = return_tx(&s);
        let to_local_spk = get_revokeable_redeemscript(&s.keys.revocation_key, CSV, &s.keys.broadcaster_delayed_payment_key).to_p2wsh();
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].script_pubkey, to_local_spk);
        assert_eq!(tx.lock_time.to_consensus_u32(), EXPIRY, "a return is valid from the HTLC's expiry");
        assert_eq!(tx.input[0].previous_output, BtcOutPoint { txid: s.commitment_txid, vout: 2 });
        assert!(tx.output[0].value.to_sat() < HTLC_MSAT / 1000 && tx.output[0].value.to_sat() > HTLC_MSAT / 1000 - 1000, "the output is the amount less the HTLC-timeout fee");
        // a claim (a payment coming in) has no block rule
        let c = synthetic(false);
        let ctx = return_tx(&c);
        assert_eq!(ctx.lock_time.to_consensus_u32(), 0);
        assert_eq!(ctx.output[0].script_pubkey, get_revokeable_redeemscript(&c.keys.revocation_key, CSV, &c.keys.broadcaster_delayed_payment_key).to_p2wsh());
    }

    /// THE COLLECT: pre-signed by the production call, and valid — the witness is [signature, empty, script],
    /// the signature verifies against the delayed payment key over the BIP-143 hash of the revokable script,
    /// the input waits to_self_delay, the one output is the destination, the fee is the rate times the weight.
    #[test]
    fn the_collect_is_signed_by_the_delayed_key_waits_csv_and_pays_the_destination() {
        let secp = Secp256k1::new();
        let s = synthetic(true);
        let tx = return_tx(&s);
        let leg = leg_of(&s, &tx);
        let d = dest();
        for (rate, name) in [(FEERATE_NORMAL_SAT_PER_KW, "normal"), (FEERATE_HIGH_SAT_PER_KW, "high")] {
            let (txid, hex) = collect(&s.holder, &leg.descriptor, &d, rate, &secp).unwrap_or_else(|| panic!("{name} collect not built"));
            let col: Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
            assert_eq!(col.compute_txid().to_string(), txid);
            assert_eq!(col.input.len(), 1);
            assert_eq!(col.input[0].previous_output, BtcOutPoint { txid: tx.compute_txid(), vout: 0 }, "spends the return's output");
            assert_eq!(col.input[0].sequence.0, CSV as u32, "waits to_self_delay blocks");
            assert_eq!(col.output.len(), 1);
            assert_eq!(col.output[0].script_pubkey, d.script_pubkey(), "pays the destination");
            // the fee
            let fee = tx.output[0].value.to_sat() - col.output[0].value.to_sat();
            let want = (col.weight().to_wu() * rate as u64 + 999) / 1000;
            assert!(fee >= want && fee <= want + 50, "{name}: fee {fee} for weight {} at {rate} sat/kw (want ≈ {want})", col.weight().to_wu());
            // the witness, by hand
            let w: Vec<Vec<u8>> = col.input[0].witness.iter().map(|x| x.to_vec()).collect();
            assert_eq!(w.len(), 3, "[signature, empty, script]");
            assert!(w[1].is_empty(), "the empty element takes the ELSE (delayed) branch");
            let script = get_revokeable_redeemscript(&s.keys.revocation_key, CSV, &s.keys.broadcaster_delayed_payment_key);
            assert_eq!(w[2], script.as_bytes(), "the revokable script");
            let (sig_der, ty) = w[0].split_at(w[0].len() - 1);
            assert_eq!(ty[0], EcdsaSighashType::All as u8);
            let sighash = SighashCache::new(&col).p2wsh_signature_hash(0, &script, tx.output[0].value, EcdsaSighashType::All).unwrap();
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = Signature::from_der(sig_der).unwrap();
            let delayed: &DelayedPaymentKey = &s.keys.broadcaster_delayed_payment_key;
            secp.verify_ecdsa(&msg, &sig, &delayed.to_public_key()).expect("the signature is the delayed payment key's");
        }
    }

    /// THE RECORD: what the kit carries for a leg — and a kit without legs is unchanged elsewhere.
    #[test]
    fn the_legs_record_names_kind_block_wait_destination_and_both_collects() {
        let secp = Secp256k1::new();
        let s = synthetic(true);
        let tx = return_tx(&s);
        let leg = leg_of(&s, &tx);
        let d = dest();
        let j = leg_json(&s.holder, &leg, &tx, &d, 9, &secp);
        assert_eq!(j["kind"], "return");
        assert_eq!(j["txid"], tx.compute_txid().to_string());
        assert_eq!(j["hex"], serialize_hex(&tx));
        assert_eq!(j["amount_sats"], HTLC_MSAT / 1000);
        assert_eq!(j["returns_sats"], tx.output[0].value.to_sat());
        assert_eq!(j["valid_from_block"], EXPIRY);
        assert_eq!(j["collect_after_blocks"], CSV);
        assert_eq!(j["payment_hash"], "11".repeat(32));
        assert_eq!(j["collect_address"], d.to_string());
        assert_eq!(j["collect_index"], 9);
        for k in ["collect_txid_normal", "collect_hex_normal", "collect_txid_high", "collect_hex_high"] {
            assert!(j[k].is_string() && !j[k].as_str().unwrap().is_empty(), "{k}");
        }
        assert_ne!(j["collect_hex_normal"], j["collect_hex_high"]);
        // a claim: valid at once
        let c = synthetic(false);
        let ctx = return_tx(&c);
        let cj = leg_json(&c.holder, &leg_of(&c, &ctx), &ctx, &d, 10, &secp);
        assert_eq!(cj["kind"], "claim");
        assert_eq!(cj["valid_from_block"], 0);
    }

    /// Too small for a rate → that collect is null, the other stands (the to_local rule).
    #[test]
    fn a_tiny_leg_degrades_per_rate_never_fails() {
        let secp = Secp256k1::new();
        let mut s = synthetic(true);
        s.htlc.amount_msat = 2_000_000;   // 2,000 sats: the return's output ≈ 1,300 sats; the high collect (≈ 1,300+ sats of fee) cannot be built
        let tx = return_tx(&s);
        let leg = leg_of(&s, &tx);
        let j = leg_json(&s.holder, &leg, &tx, &dest(), 3, &secp);
        assert!(j["collect_hex_normal"].is_string() || j["collect_hex_normal"].is_null());
        assert!(j["collect_hex_high"].is_null(), "40 sat/vB cannot be paid from ≈1,300 sats");
        assert_eq!(j["kind"], "return");
    }

    /// The destination derivation is the m/84 receive chain the coin legs use.
    #[test]
    fn kit_destination_is_the_m84_receive_address_at_the_index() {
        let root = RootKey::from_mnemonic(&"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(), Network::Bitcoin).unwrap();
        let a0 = kit_destination(&root, Network::Bitcoin, 0).unwrap();
        let a1 = kit_destination(&root, Network::Bitcoin, 1).unwrap();
        assert_ne!(a0, a1);
        assert_eq!(a0.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "BIP84's first receive address of the test words");
    }
}
