// onchain_send.rs
// Hand-rolled P2WPKH send for the on-chain wallet (option D, increment 2).
//
// No BDK: builds, signs (BIP143 segwit v0), and broadcasts directly on
// rust-bitcoin 0.30 — the same bitcoin version LDK links, so types interoperate
// and there's no second crate stack. Spends the m/84'/{coin}'/0'/0/n
// (Cooperative) chain — receives + LDK sweep/coop-close destinations — and sends
// change to a dedicated m/84'/{coin}'/0'/1/0 change address.
//
// Scope (increment 2): m/84 spend only. Legacy m/525 force-close residue is
// recovered by the a1 sweep flow, which reuses this signing machinery with
// static_remotekey_xpriv-derived keys.

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath},
    consensus::encode::serialize,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
// `to_byte_array()` on the sighash is a method of the hashes `Hash` trait.
use bitcoin::hashes::Hash;

use crate::{
    error::{LijError, LijResult},
    independent::IndependentClient,
    key::RootKey,
};

/// Drop P2WPKH change below this (sats) into the fee rather than create a dust
/// output (P2WPKH dust limit is ~294 sats at the relay default).
pub(crate) const DUST_THRESHOLD_SATS: u64 = 294;

/// Result of a broadcast send, surfaced to the UI.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SendResult {
    pub txid: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub inputs: usize,
    pub change_sats: u64,
    /// Our outpoints this send spends, so the caller can reserve them as a
    /// pending tx (immediate debit before confirmation): (txid, vout).
    pub spent_outpoints: Vec<(String, u32)>,
    /// If this send created a change output (vout 1), its (txid, vout).
    pub change_outpoint: Option<(String, u32)>,
    /// Change-chain index this send's change went to (rotates per use).
    pub change_index: u32,
}

impl SendResult {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self)
            .map_err(|e| LijError::Storage(format!("send result serialize: {e}")))
    }
}

/// Rough fee in sats for a P2WPKH tx with `n_in` inputs and `n_out` outputs.
/// vsize ≈ 11 (overhead) + 68/input + 31/output vbytes. `fee_rate_sat_per_kw`
/// is LDK-style sat/kilo-weight (FeeQuote::on_chain_sweep); 1 vbyte = 4 weight,
/// so sat/vB = sat_per_kw / 250. Rounded up, floored at 1 sat/vB.
pub(crate) fn estimate_fee(n_in: usize, n_out: usize, fee_rate_sat_per_kw: u32) -> u64 {
    let vsize = 11 + 68 * n_in as u64 + 31 * n_out as u64;
    let sat_per_vb = (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1);
    vsize * sat_per_vb
}

/// A spendable UTXO with everything needed to sign it.
struct SpendableUtxo {
    chain: u32, // 0=receive, 1=change, 525=legacy
    index: u32,
    txid: String,
    vout: u32,
    value_sats: u64,
}

/// Spendable coins for a plain send, read from the canonical Tier-2 view — the
/// SAME source channel funding and the displayed balance use. Unspent receive +
/// change (chain 0/1), minus any input already reserved by a pending tx. Legacy
/// m/525 force-close residue is excluded (it's surfaced as legacy residue and
/// recovered via the documented BlueWallet custom-path), matching funding +
/// display. Replaces the old live Esplora scan: one source of truth, no chain-1
/// divergence, and confirmed change is counted everywhere it is spent or shown.
fn gather_spendable(
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
) -> Vec<SpendableUtxo> {
    let reserved: std::collections::HashSet<(String, u32)> = pending
        .iter()
        .flat_map(|p| p.spent_outpoints.iter().cloned())
        .collect();
    let mut out: Vec<SpendableUtxo> = view
        .utxos
        .iter()
        .filter(|u| {
            u.spent_height.is_none()
                && (u.chain == crate::tier2::CHAIN_RECEIVE || u.chain == crate::tier2::CHAIN_CHANGE)
                && !reserved.contains(&(u.txid.clone(), u.vout))
        })
        .map(|u| SpendableUtxo {
            chain: u.chain,
            index: u.index,
            txid: u.txid.clone(),
            vout: u.vout,
            value_sats: u.value_sats,
        })
        .collect();
    // Also spend our own unconfirmed change — the SAME source as the optimistic
    // balance, so what shows as spendable actually is. Chains off the pending
    // parent (doubles as CPFP); signed at chain 1 / change_index by
    // signing_secret. unconfirmed_change_utxos already skips reserved and
    // already-confirmed change, so there is no overlap with the view UTXOs above.
    for u in crate::tier2_wallet::unconfirmed_change_utxos(view, pending) {
        out.push(SpendableUtxo {
            chain: u.chain,
            index: u.index,
            txid: u.txid,
            vout: u.vout,
            value_sats: u.value_sats,
        });
    }
    out
}

/// Derive the signing secret key for a spendable UTXO by (chain, index).
pub(crate) fn signing_secret(
    root_key: &RootKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    chain: u32,
    index: u32,
) -> LijResult<bitcoin::secp256k1::SecretKey> {
    let parent = match chain {
        0 => root_key.shutdown_xpriv()?, // m/84'/{coin}'/0'/0
        1 => root_key
            .onchain_key()?
            .derive_priv(
                secp,
                &DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(1).map_err(|e| LijError::Key(format!("{e}")))?
                ]),
            )
            .map_err(|e| LijError::Key(format!("change parent derivation: {e}")))?,
        525 =>
        {
            #[allow(deprecated)]
            root_key.static_remotekey_xpriv()?
        }
        other => return Err(LijError::Key(format!("unknown chain {other}"))),
    };
    let child = parent
        .derive_priv(
            secp,
            &DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
                .map_err(|e| LijError::Key(format!("{e}")))?]),
        )
        .map_err(|e| LijError::Key(format!("signing key derivation at {chain}/{index}: {e}")))?;
    Ok(child.private_key)
}

/// Build, sign, and broadcast a P2WPKH send from the m/84 spendable chain.
/// Must run OUTSIDE any wallet lock (awaits network I/O).
pub async fn build_and_send(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    dest: &str,
    amount_sats: u64,
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
) -> LijResult<SendResult> {
    if amount_sats == 0 {
        return Err(LijError::Node("amount must be greater than zero".into()));
    }

    // Parse + network-check the destination address.
    let dest_addr = Address::from_str(dest)
        .map_err(|e| LijError::Node(format!("invalid address: {e}")))?
        .require_network(network)
        .map_err(|e| LijError::Node(format!("address is for the wrong network: {e}")))?;
    let dest_spk = dest_addr.script_pubkey();

    let secp = Secp256k1::new();

    // Gather spendable UTXOs (receive + change), preferring the trusted node.
    let mut spendable = gather_spendable(view, pending);
    if spendable.is_empty() {
        return Err(LijError::Node("no spendable on-chain funds found".into()));
    }
    // Largest-first selection (simple, deterministic).
    spendable.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));

    // Select inputs until amount + fee (for 2 outputs) is covered.
    let mut selected: Vec<&SpendableUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    for u in &spendable {
        selected.push(u);
        total_in += u.value_sats;
        if total_in >= amount_sats + estimate_fee(selected.len(), 2, fee_rate_sat_per_kw) {
            break;
        }
    }
    let n_in = selected.len();
    let mut fee_sats = estimate_fee(n_in, 2, fee_rate_sat_per_kw);
    if total_in < amount_sats + fee_sats {
        return Err(LijError::Node(format!(
            "insufficient funds: have {total_in} sats, need {} (amount {amount_sats} + fee {fee_sats})",
            amount_sats + fee_sats
        )));
    }
    let mut change_sats = total_in - amount_sats - fee_sats;

    // Change address: m/84'/{coin}'/0'/1/n — ROTATED per send (fresh address) so
    // change isn't linkable by reuse. Index chosen by the caller from the Tier-2
    // view + pending; the gap-limited scan re-discovers it.
    let account_xpriv = root_key.onchain_key()?; // m/84'/{coin}'/0'
    let change_xpriv = account_xpriv
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(|e| LijError::Key(format!("{e}")))?,
                ChildNumber::from_normal_idx(change_index)
                    .map_err(|e| LijError::Key(format!("{e}")))?,
            ]),
        )
        .map_err(|e| LijError::Key(format!("change key derivation: {e}")))?;
    let change_pubkey = bitcoin::PublicKey::new(change_xpriv.private_key.public_key(&secp));
    let change_spk = Address::p2wpkh(&change_pubkey, network)
        .map_err(|e| LijError::Key(format!("change p2wpkh encoding: {e}")))?
        .script_pubkey();

    // Outputs: destination, plus change unless it's dust (then it goes to fee).
    let mut outputs = vec![TxOut {
        value: amount_sats,
        script_pubkey: dest_spk,
    }];
    if change_sats >= DUST_THRESHOLD_SATS {
        outputs.push(TxOut {
            value: change_sats,
            script_pubkey: change_spk,
        });
    } else {
        fee_sats += change_sats;
        change_sats = 0;
    }

    // Inputs (witnesses filled in after we build the tx for sighashing).
    let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(n_in);
    for u in &selected {
        tx_inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&u.txid)
                    .map_err(|e| LijError::Node(format!("bad utxo txid {}: {e}", u.txid)))?,
                vout: u.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    // Sign each P2WPKH input (BIP143). Collect witnesses while the cache holds an
    // immutable borrow of tx, then assign them after dropping the cache.
    let mut witnesses: Vec<Witness> = Vec::with_capacity(n_in);
    {
        let cache_tx = tx.clone();
        let mut cache = SighashCache::new(&cache_tx);
        for (i, u) in selected.iter().enumerate() {
            let sk = signing_secret(root_key, &secp, u.chain, u.index)?;
            let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
            // BIP143 scriptCode for P2WPKH is the corresponding p2pkh script.
            let script_code = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
            let sighash = cache
                .segwit_signature_hash(i, &script_code, u.value_sats, EcdsaSighashType::All)
                .map_err(|e| LijError::Node(format!("segwit sighash at input {i}: {e}")))?;
            let msg = Message::from_slice(&sighash.to_byte_array())
                .map_err(|e| LijError::Node(format!("sighash->message: {e}")))?;
            let sig = secp.sign_ecdsa(&msg, &sk);
            let mut sig_with_type = sig.serialize_der().to_vec();
            sig_with_type.push(EcdsaSighashType::All as u8);
            let mut w = Witness::new();
            w.push(sig_with_type);
            w.push(pk.to_bytes());
            witnesses.push(w);
        }
    }
    for (i, w) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = w;
    }

    // Broadcast through the Esplora quorum.
    let raw = serialize(&tx);
    independent.broadcast_raw_tx(&raw).await?;
    let txid = tx.txid().to_string();
    log::info!(
        "onchain send: broadcast {txid} ({amount_sats} sats to {dest}, fee {fee_sats}, {n_in} input(s), change {change_sats})"
    );

    let change_outpoint = if change_sats > 0 {
        // Outputs are [dest (vout 0), change (vout 1)].
        Some((txid.clone(), 1u32))
    } else {
        None
    };

    Ok(SendResult {
        txid,
        amount_sats,
        fee_sats,
        inputs: n_in,
        change_sats,
        spent_outpoints: selected
            .iter()
            .map(|u| (u.txid.clone(), u.vout))
            .collect(),
        change_outpoint,
        change_index,
    })
}

/// v166 (#29-4b): RBF replacement of one of OUR pending sends. Same inputs,
/// same destination; the fee delta comes out of the change output (v1 —
/// declines with an actionable message when change can't fund it). Inputs
/// are reconstructed from the Tier-2 view; an input that was itself
/// unconfirmed change is recovered from the sibling PendingTx that created
/// it. BIP-125 economics enforced: new absolute fee >= old + 1 sat/vB *
/// vsize, and the rate must exceed the original's.
pub async fn build_and_send_bump(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    prev: &crate::tier2_wallet::PendingTx,
    new_fee_rate_sat_per_kw: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
) -> LijResult<SendResult> {
    let dest = prev.dest_addr.as_deref().ok_or_else(|| {
        LijError::Node("this send predates fee-bump support (no destination on record)".into())
    })?;
    let amount_sats = prev.dest_sats.ok_or_else(|| {
        LijError::Node("this send predates fee-bump support (no amount on record)".into())
    })?;
    let old_fee = prev.fee_sats.ok_or_else(|| {
        LijError::Node("this send predates fee-bump support (no fee on record)".into())
    })?;
    let old_rate = prev.fee_rate_sat_per_kw.unwrap_or(0);
    if new_fee_rate_sat_per_kw <= old_rate {
        return Err(LijError::Node(format!(
            "bump rate must exceed the original (≈{} sat/vB)",
            (((old_rate as f64) / 250.0).ceil()).max(1.0) as u64
        )));
    }
    if prev.change_outpoint.is_none() {
        return Err(LijError::Node(
            "the original send has no change output to draw the higher fee from — wait for confirmation or spend again"
                .into(),
        ));
    }

    let dest_addr = Address::from_str(dest)
        .map_err(|e| LijError::Node(format!("recorded destination unparseable: {e}")))?
        .require_network(network)
        .map_err(|e| LijError::Node(format!("recorded destination wrong network: {e}")))?;
    let dest_spk = dest_addr.script_pubkey();
    let secp = Secp256k1::new();

    // Reconstruct the ORIGINAL inputs with signing info.
    let mut selected: Vec<SpendableUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    'op: for (otxid, ovout) in prev.spent_outpoints.iter() {
        for u in view.utxos.iter() {
            if &u.txid == otxid && u.vout == *ovout {
                if u.spent_height.is_some() {
                    return Err(LijError::Node(
                        "that send looks confirmed already — refresh and check the list".into(),
                    ));
                }
                selected.push(SpendableUtxo {
                    chain: u.chain,
                    index: u.index,
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value_sats: u.value_sats,
                });
                total_in += u.value_sats;
                continue 'op;
            }
        }
        for pp in pending.iter() {
            if let Some((ctxid, cvout)) = &pp.change_outpoint {
                if ctxid == otxid && *cvout == *ovout {
                    selected.push(SpendableUtxo {
                        chain: 1,
                        index: pp.change_index,
                        txid: otxid.clone(),
                        vout: *ovout,
                        value_sats: pp.change_value_sats,
                    });
                    total_in += pp.change_value_sats;
                    continue 'op;
                }
            }
        }
        return Err(LijError::Node(format!(
            "input {otxid}:{ovout} is no longer visible — the original may have confirmed; refresh and retry"
        )));
    }

    let n_in = selected.len();
    let vsize = 11 + 68 * n_in as u64 + 31 * 2;
    let mut new_fee = estimate_fee(n_in, 2, new_fee_rate_sat_per_kw);
    let bip125_min = old_fee + vsize; // old absolute fee + 1 sat/vB incremental relay
    if new_fee < bip125_min {
        let min_vb = (bip125_min + vsize - 1) / vsize;
        return Err(LijError::Node(format!(
            "bump too small for relay replacement — use at least {min_vb} sat/vB"
        )));
    }
    if total_in < amount_sats + new_fee {
        let max_fee = total_in.saturating_sub(amount_sats);
        let max_vb = (max_fee / vsize).max(1);
        return Err(LijError::Node(format!(
            "change too small to fund this bump — max ≈ {max_vb} sat/vB on this send"
        )));
    }
    let mut change_sats = total_in - amount_sats - new_fee;

    // Change goes back to the SAME index as the original: identical outputs,
    // minus fee — textbook BIP-125 replacement, no fresh-address burn.
    let account_xpriv = root_key.onchain_key()?;
    let change_xpriv = account_xpriv
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(|e| LijError::Key(format!("{e}")))?,
                ChildNumber::from_normal_idx(prev.change_index)
                    .map_err(|e| LijError::Key(format!("{e}")))?,
            ]),
        )
        .map_err(|e| LijError::Key(format!("change key derivation: {e}")))?;
    let change_pubkey = bitcoin::PublicKey::new(change_xpriv.private_key.public_key(&secp));
    let change_spk = Address::p2wpkh(&change_pubkey, network)
        .map_err(|e| LijError::Key(format!("change p2wpkh encoding: {e}")))?
        .script_pubkey();

    let mut outputs = vec![TxOut {
        value: amount_sats,
        script_pubkey: dest_spk,
    }];
    if change_sats >= DUST_THRESHOLD_SATS {
        outputs.push(TxOut {
            value: change_sats,
            script_pubkey: change_spk,
        });
    } else {
        new_fee += change_sats;
        change_sats = 0;
    }

    let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(n_in);
    for u in &selected {
        tx_inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&u.txid)
                    .map_err(|e| LijError::Node(format!("bad utxo txid {}: {e}", u.txid)))?,
                vout: u.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    let mut witnesses: Vec<Witness> = Vec::with_capacity(n_in);
    {
        let cache_tx = tx.clone();
        let mut cache = SighashCache::new(&cache_tx);
        for (i, u) in selected.iter().enumerate() {
            let sk = signing_secret(root_key, &secp, u.chain, u.index)?;
            let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
            let script_code = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
            let sighash = cache
                .segwit_signature_hash(i, &script_code, u.value_sats, EcdsaSighashType::All)
                .map_err(|e| LijError::Node(format!("segwit sighash at input {i}: {e}")))?;
            let msg = Message::from_slice(&sighash.to_byte_array())
                .map_err(|e| LijError::Node(format!("sighash->message: {e}")))?;
            let sig = secp.sign_ecdsa(&msg, &sk);
            let mut sig_with_type = sig.serialize_der().to_vec();
            sig_with_type.push(EcdsaSighashType::All as u8);
            let mut w = Witness::new();
            w.push(sig_with_type);
            w.push(pk.to_bytes());
            witnesses.push(w);
        }
    }
    for (i, w) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = w;
    }

    let raw = serialize(&tx);
    independent.broadcast_raw_tx(&raw).await?;
    let txid = tx.txid().to_string();
    log::info!(
        "onchain bump: {txid} replaces {} ({amount_sats} sats, fee {old_fee} -> {new_fee}, {n_in} input(s), change {change_sats})",
        prev.txid
    );

    let change_outpoint = if change_sats > 0 { Some((txid.clone(), 1u32)) } else { None };
    Ok(SendResult {
        txid,
        amount_sats,
        fee_sats: new_fee,
        inputs: n_in,
        change_sats,
        spent_outpoints: prev.spent_outpoints.clone(),
        change_outpoint,
        change_index: prev.change_index,
    })
}

/// S45: CPFP child for a pending cooperative close. `parent` is our own
/// cooperative closing tx (in the mempool); `parent_vout` is its output to our
/// m/84 receive address at `dest_index`. The child spends that output back to
/// the SAME address (no allocator involvement, the scan already knows it) with
/// a fee that lifts the parent+child package to `target_sat_per_kw`. Returns
/// (child txid, child fee). Refuses when the output cannot fund the child.
pub async fn build_and_send_cpfp(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    parent: &Transaction,
    parent_vout: u32,
    parent_fee_sats: u64,
    dest_index: u32,
    target_sat_per_kw: u32,
) -> LijResult<(String, u64)> {
    let out = parent
        .output
        .get(parent_vout as usize)
        .ok_or_else(|| LijError::Node(format!("cpfp: parent has no output {parent_vout}")))?;
    let parent_value_sats = out.value;
    let parent_vsize = parent.vsize() as u64;
    let sat_per_vb = (((target_sat_per_kw as u64) + 249) / 250).max(1);
    let child_vsize: u64 = 11 + 68 + 31;
    let package_fee = sat_per_vb * (parent_vsize + child_vsize);
    let child_fee = package_fee
        .saturating_sub(parent_fee_sats)
        .max(child_vsize * sat_per_vb);
    if parent_value_sats <= child_fee + DUST_THRESHOLD_SATS {
        return Err(LijError::Node(format!(
            "cpfp: output of {parent_value_sats} sats cannot fund a {child_fee}-sat child"
        )));
    }
    let secp = Secp256k1::new();
    let sk = signing_secret(root_key, &secp, crate::tier2::CHAIN_RECEIVE, dest_index)?;
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: parent.txid(), vout: parent_vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: parent_value_sats - child_fee,
            script_pubkey: out.script_pubkey.clone(),
        }],
    };
    let w = {
        let cache_tx = tx.clone();
        let mut cache = SighashCache::new(&cache_tx);
        let script_code = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        let sighash = cache
            .segwit_signature_hash(0, &script_code, parent_value_sats, EcdsaSighashType::All)
            .map_err(|e| LijError::Node(format!("cpfp sighash: {e}")))?;
        let msg = Message::from_slice(&sighash.to_byte_array())
            .map_err(|e| LijError::Node(format!("cpfp sighash->message: {e}")))?;
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_with_type = sig.serialize_der().to_vec();
        sig_with_type.push(EcdsaSighashType::All as u8);
        let mut w = Witness::new();
        w.push(sig_with_type);
        w.push(pk.to_bytes());
        w
    };
    tx.input[0].witness = w;
    let raw = serialize(&tx);
    independent.broadcast_raw_tx(&raw).await?;
    let txid = tx.txid().to_string();
    log::info!(
        "cpfp: child {txid} broadcast — parent {} ({parent_vsize} vB, fee {parent_fee_sats}) + child fee {child_fee} = package at {sat_per_vb} sat/vB",
        parent.txid()
    );
    Ok((txid, child_fee))
}

/// S45: the receive-chain P2WPKH scripts m/84'/{coin}'/0'/0/0..=max_index, so
/// a caller can find which output of a transaction pays one of our receive
/// addresses (and at which index) without touching the allocator.
pub(crate) fn receive_scripts(
    root_key: &RootKey,
    network: Network,
    max_index: u32,
) -> LijResult<Vec<(u32, ScriptBuf)>> {
    let secp = Secp256k1::new();
    let account_xpriv = root_key.onchain_key()?;
    let mut v: Vec<(u32, ScriptBuf)> = Vec::with_capacity(max_index as usize + 1);
    for i in 0..=max_index {
        let xpriv = account_xpriv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(crate::tier2::CHAIN_RECEIVE).map_err(|e| LijError::Key(format!("{e}")))?,
                    ChildNumber::from_normal_idx(i).map_err(|e| LijError::Key(format!("{e}")))?,
                ]),
            )
            .map_err(|e| LijError::Key(format!("receive key derivation: {e}")))?;
        let pk = bitcoin::PublicKey::new(xpriv.private_key.public_key(&secp));
        let spk = Address::p2wpkh(&pk, network)
            .map_err(|e| LijError::Key(format!("receive p2wpkh encoding: {e}")))?
            .script_pubkey();
        v.push((i, spk));
    }
    Ok(v)
}
