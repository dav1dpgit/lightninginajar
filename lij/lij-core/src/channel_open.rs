// channel_open.rs
// Outbound channel funding: build + sign the funding transaction that pays
// LDK's funding output script from the wallet's Tier-2 on-chain UTXOs.
//
// Flow (the node-side orchestration in node.rs drives this):
//   1. ChannelManager::create_channel(lsp_pubkey, value, ...) is called.
//   2. LDK negotiates, then emits Event::FundingGenerationReady carrying the
//      exact `output_script` (the 2-of-2 funding P2WSH) and `channel_value`.
//   3. We build + sign a funding tx here that pays `output_script` exactly
//      `channel_value`, with change back to the m/84 change chain.
//   4. The signed tx is handed to ChannelManager::funding_transaction_generated.
//      LDK broadcasts it once it has the counterparty's signed commitment — we
//      MUST NOT broadcast it ourselves.
//
// Inputs are selected from the Tier-2 view (the same spendable set the wallet
// displays): receive chain 0 + change chain 1, unspent only. The legacy m/525
// force-close residue (chain 525) is intentionally excluded — that belongs to
// the separate sweep flow, not to funding new channels.
//
// Signing mirrors onchain_send::build_and_send exactly (BIP143 P2WPKH), reusing
// its signing_secret / estimate_fee / dust helpers so the two paths can never
// drift in how they derive keys or size fees.

use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath},
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin::hashes::Hash;

use crate::{
    error::{LijError, LijResult},
    key::RootKey,
    onchain_send::{estimate_fee, signing_secret, DUST_THRESHOLD_SATS},
    storage::LijStorage,
    tier2_wallet,
};

/// Smallest channel the wallet will ATTEMPT to open. This is NOT LDK's bare
/// protocol minimum — it's the smallest *structurally openable* channel against
/// an LND-class peer. LDK hardcodes the counterparty reserve it requests at
/// `max(1% * capacity, MIN_THEIR_CHAN_RESERVE_SATOSHIS=1000)`, with no config
/// override below 1000. LND (and the BOLT default) caps the reserve a peer may
/// impose at ~20% of capacity. Those reconcile only at capacity >= 1000 / 0.20
/// = 5000: below that, LDK's 1000-sat reserve exceeds the 20% cap and the open
/// is rejected ("channel reserve is too large"), no matter what minchansize the
/// LSP advertises. Enforcing 5000 here means the wallet never attempts an open
/// that is doomed by reserve math, independent of any LSP-advertised minimum.
pub const LDK_MIN_CHANNEL_SATS: u64 = 5_000;

/// On-chain headroom (sats) we keep OUT of the channel as a pre-staged CPFP
/// buffer for force-closing an anchor channel later.
///
/// Set to 0 for LiJ's NON-ROUTING model. The large reserve only earns its keep
/// on a routing node, where in-flight HTLCs have hard timeout deadlines and a
/// missed CPFP can lose money. LiJ forwards nothing, so a force close has no
/// deadline: the funding LSP normally confirms the close itself (it CPFPs its
/// own anchor, which confirms the shared tx), and the user can otherwise wait
/// for fees to fall or fee-bump manually from any wallet holding the seed.
/// Holding 10k against every open was over-conservative and blocked small opens
/// (a 10k wallet couldn't open at all). NOT a hard LDK requirement at open time.
pub const ANCHOR_FEE_RESERVE_SATS: u64 = 0;

/// A built, signed funding transaction ready to hand to LDK. NOT broadcast.
pub struct FundingTx {
    pub tx: Transaction,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub inputs: usize,
    /// Our outpoints this tx spends, so the caller can reserve them as pending.
    pub spent_outpoints: Vec<(String, u32)>,
    /// If this funding tx created a change output (vout 1), its (txid, vout) —
    /// so the caller records it and the next open can spend it pre-confirmation.
    pub change_outpoint: Option<(String, u32)>,
    /// Change-chain index this funding tx's change went to (rotates per use).
    pub change_index: u32,
}

/// Collect the spendable Tier-2 UTXOs eligible to fund a channel: unspent,
/// receive (chain 0) or change (chain 1). Largest-first for deterministic,
/// low-input-count selection.
/// v230 (S43, DP field 2026-09-02): the ESTIMATE must see the same funds the
/// funding path sees. Until v230 this filter ignored outpoints already
/// committed by a pending (mempool) open or send — the v191 reserved exclusion
/// lived only in build_funding_tx — so after one "Add to Lightning" at Max the
/// sheet still offered the same Max, a second open sailed through the page and
/// died later in the event pass for lack of funds (a phantom "opening").
fn spendable_utxos<'a>(
    storage: &dyn LijStorage,
    view: &'a tier2_wallet::Tier2View,
) -> Vec<&'a tier2_wallet::OnchainUtxo> {
    let reserved: std::collections::HashSet<(String, u32)> = tier2_wallet::load_pending(storage)
        .iter()
        .flat_map(|p| p.spent_outpoints.iter().cloned())
        .collect();
    let mut v: Vec<&tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| {
            u.spent_height.is_none()
                && (u.chain == 0 || u.chain == 1)
                && !reserved.contains(&(u.txid.clone(), u.vout))
        })
        .collect();
    v.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));
    v
}

/// Total spendable balance (chain 0 + 1, unspent) from the Tier-2 view.
pub fn spendable_total(storage: &dyn LijStorage) -> LijResult<u64> {
    let view = tier2_wallet::load_view(storage)?;
    let confirmed: u64 = spendable_utxos(storage, &view).iter().map(|u| u.value_sats).sum();
    let unconfirmed: u64 = unconfirmed_change_candidates(storage, &view)
        .iter()
        .map(|u| u.value_sats)
        .sum();
    Ok(confirmed.saturating_add(unconfirmed))
}

/// Largest channel value openable at this fee rate:
///   spendable − funding_fee(all_inputs, 2 outputs) − anchor reserve
/// Returns 0 (not an error) when nothing is openable, so the UI can show a
/// disabled MAX rather than an exception.
pub fn max_channel_value(storage: &dyn LijStorage, fee_rate_sat_per_kw: u32) -> LijResult<u64> {
    let view = tier2_wallet::load_view(storage)?;
    let mut utxos: Vec<tier2_wallet::OnchainUtxo> =
        spendable_utxos(storage, &view).into_iter().cloned().collect();
    utxos.extend(unconfirmed_change_candidates(storage, &view));
    if utxos.is_empty() {
        return Ok(0);
    }
    let total: u64 = utxos.iter().map(|u| u.value_sats).sum();
    // Worst case fee assumes every UTXO is consumed (the MAX path spends all).
    let fee = estimate_fee(utxos.len(), 2, fee_rate_sat_per_kw);
    let overhead = fee.saturating_add(ANCHOR_FEE_RESERVE_SATS);
    Ok(total.saturating_sub(overhead))
}

/// Unconfirmed wallet change recorded by still-pending txs (opens/sends we've
/// broadcast but not yet seen confirmed). Returned as synthetic chain-1 UTXOs so
/// a channel can be funded from the change of a just-broadcast funding tx without
/// waiting a block. Capped to the 3 most recent. Skips change already reserved by
/// another pending tx (no double-spend) or already confirmed into the view (no
/// double-count). Evicted/replaced change is pruned by the reconciliation scan; a
/// stale entry here at worst makes a broadcast fail, never a double-spend.
fn unconfirmed_change_candidates(
    storage: &dyn LijStorage,
    view: &tier2_wallet::Tier2View,
) -> Vec<tier2_wallet::OnchainUtxo> {
    // One source of truth (tier2_wallet::unconfirmed_change_utxos); capped to the
    // 3 most-recent for funding to bound how deep a single open chains off
    // still-unconfirmed change.
    let pending = tier2_wallet::load_pending(storage);
    tier2_wallet::unconfirmed_change_utxos(view, &pending)
        .into_iter()
        .take(3)
        .collect()
}

/// Build + sign the funding transaction. Pays `output_script` exactly
/// `channel_value_sats`; sends change to m/84'/{coin}'/0'/1/0. Sources inputs
/// from the Tier-2 view (chain 0/1). Does NOT broadcast — the caller hands the
/// returned tx to ChannelManager::funding_transaction_generated.
pub fn build_funding_tx(
    root_key: &RootKey,
    storage: &dyn LijStorage,
    network: Network,
    output_script: ScriptBuf,
    channel_value_sats: u64,
    fee_rate_sat_per_kw: u32,
) -> LijResult<FundingTx> {
    if channel_value_sats < LDK_MIN_CHANNEL_SATS {
        return Err(LijError::Node(format!(
            "channel value {channel_value_sats} below LDK minimum {LDK_MIN_CHANNEL_SATS} sats"
        )));
    }

    let secp = Secp256k1::new();
    let view = tier2_wallet::load_view(storage)?;
    // Confirmed receive/change (chain 0/1) from the Tier-2 view PLUS unconfirmed
    // change recorded by still-pending txs (capped 3, deduped) — owned so the two
    // sources mix. This is what lets a channel be funded from the change of a
    // just-broadcast funding tx without waiting a block.
    // v191 (S29): RESERVED EXCLUSION — the missing half of the pending
    // integration. The confirmed pool must not offer coins already
    // committed by a pending tx (open or send); without this, a second
    // open while the first pends re-selects the same largest coin and
    // mints an unbroadcastable double-spend (the S29 zombie opens).
    let pending_res = tier2_wallet::load_pending(storage);
    let reserved: std::collections::HashSet<(String, u32)> = pending_res
        .iter()
        .flat_map(|p| p.spent_outpoints.iter().cloned())
        .collect();
    let mut candidates: Vec<tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| {
            u.spent_height.is_none()
                && (u.chain == 0 || u.chain == 1)
                && !reserved.contains(&(u.txid.clone(), u.vout))
        })
        .cloned()
        .collect();
    candidates.extend(unconfirmed_change_candidates(storage, &view));
    candidates.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));
    if candidates.is_empty() {
        return Err(LijError::Node(
            "no spendable on-chain funds to open a channel".into(),
        ));
    }

    // Select inputs until channel value + fee (2 outputs) is covered.
    let mut selected: Vec<&tier2_wallet::OnchainUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    for u in &candidates {
        selected.push(u);
        total_in += u.value_sats;
        if total_in >= channel_value_sats + estimate_fee(selected.len(), 2, fee_rate_sat_per_kw) {
            break;
        }
    }
    // v191 (S29): belt — impossible by construction post-exclusion; if it
    // ever fires, refuse loudly instead of minting a double-spend.
    if selected
        .iter()
        .any(|u| reserved.contains(&(u.txid.clone(), u.vout)))
    {
        return Err(LijError::Node(
            "coin already committed to a pending transaction — wait one sync".into(),
        ));
    }
    let n_in = selected.len();
    let mut fee_sats = estimate_fee(n_in, 2, fee_rate_sat_per_kw);
    if total_in < channel_value_sats + fee_sats {
        return Err(LijError::Node(format!(
            "insufficient funds for channel: have {total_in} sats, need {} (channel {channel_value_sats} + fee {fee_sats})",
            channel_value_sats + fee_sats
        )));
    }
    let mut change_sats = total_in - channel_value_sats - fee_sats;

    // Change address: m/84'/{coin}'/0'/1/n — ROTATED per use (fresh address each
    // time) so change isn't linkable by reuse. The gap-limited Tier-2 scan
    // (chain 1, 0..gap) re-discovers it.
    let change_idx =
        tier2_wallet::next_change_index(&view, &tier2_wallet::load_pending(storage));
    let account_xpriv = root_key.onchain_key()?; // m/84'/{coin}'/0'
    let change_xpriv = account_xpriv
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(|e| LijError::Key(format!("{e}")))?,
                ChildNumber::from_normal_idx(change_idx)
                    .map_err(|e| LijError::Key(format!("{e}")))?,
            ]),
        )
        .map_err(|e| LijError::Key(format!("change key derivation: {e}")))?;
    let change_pubkey = bitcoin::PublicKey::new(change_xpriv.private_key.public_key(&secp));
    let change_spk = Address::p2wpkh(&change_pubkey, network)
        .map_err(|e| LijError::Key(format!("change p2wpkh encoding: {e}")))?
        .script_pubkey();

    // Outputs: funding (LDK's 2-of-2 script), plus change unless it's dust.
    let mut outputs = vec![TxOut {
        value: channel_value_sats,
        script_pubkey: output_script,
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

    // Sign each P2WPKH input (BIP143), identical to onchain_send::build_and_send.
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

    // Outputs are [funding (vout 0), change (vout 1)]; change present only when it
    // cleared the dust threshold (change_sats set to 0 above otherwise).
    let change_outpoint = if change_sats > 0 {
        Some((tx.txid().to_string(), 1u32))
    } else {
        None
    };

    Ok(FundingTx {
        tx,
        fee_sats,
        change_sats,
        inputs: n_in,
        spent_outpoints: selected
            .iter()
            .map(|u| (u.txid.clone(), u.vout))
            .collect(),
        change_outpoint,
        change_index: change_idx,
    })
}
