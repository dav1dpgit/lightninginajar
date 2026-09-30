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
// v285: signing goes through onchain_send::sign_inputs (BIP143 P2WPKH for m/84 coins, taproot
// key-path Schnorr for silent-payment coins) — one signer for every spend; the note below is history:
// Signing mirrors onchain_send::build_and_send exactly (BIP143 P2WPKH), reusing
// its signing_secret / estimate_fee / dust helpers so the two paths can never
// drift in how they derive keys or size fees.

use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath},
    secp256k1::Secp256k1,
    Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::{
    error::{LijError, LijResult},
    key::RootKey,
    onchain_send::{estimate_fee, DUST_THRESHOLD_SATS},
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
/// v281 (S50, coin control): the user's freezes — read from the same encrypted store the
/// view lives in; a frozen coin is never a candidate for an open (nor for its Max).
fn frozen_set(storage: &dyn LijStorage) -> std::collections::HashSet<(String, u32)> {
    tier2_wallet::load_marks(storage).map(|m| m.frozen_set()).unwrap_or_default()
}

fn spendable_utxos<'a>(
    storage: &dyn LijStorage,
    view: &'a tier2_wallet::Tier2View,
) -> Vec<&'a tier2_wallet::OnchainUtxo> {
    let reserved: std::collections::HashSet<(String, u32)> = tier2_wallet::load_pending(storage)
        .iter()
        .flat_map(|p| p.spent_outpoints.iter().cloned())
        .collect();
    let frozen = frozen_set(storage);
    let mut v: Vec<&tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| {
            u.spent_height.is_none()
                && crate::onchain_send::is_signable(u)   // v285: m/84 receive + change, and a silent-payment coin with its t_k
                && !reserved.contains(&(u.txid.clone(), u.vout))
                && !frozen.contains(&(u.txid.clone(), u.vout))
        })
        .collect();
    v.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));
    v
}

/// v285: the funding fee for exactly these coins (their real sizes — a silent-payment coin is
/// a 58-vB taproot input, an m/84 coin 68) and two outputs (funding + change).
fn funding_fee(utxos: &[&tier2_wallet::OnchainUtxo], fee_rate_sat_per_kw: u32) -> u64 {
    crate::onchain_send::estimate_fee_chains(utxos.iter().map(|u| u.chain), 0, 2, 0, fee_rate_sat_per_kw)
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
    max_channel_value_with(storage, fee_rate_sat_per_kw, None)
}

/// v282 (S50, coin control cut 3): the largest channel the CHOSEN coins can open (exactly
/// those coins, one change output, the anchor reserve) — or every sendable coin when none
/// are chosen. A frozen or unknown choice is an error the page shows.
pub fn max_channel_value_with(storage: &dyn LijStorage, fee_rate_sat_per_kw: u32, pins: Option<&[(String, u32)]>) -> LijResult<u64> {
    let view = tier2_wallet::load_view(storage)?;
    let mut utxos: Vec<tier2_wallet::OnchainUtxo> =
        spendable_utxos(storage, &view).into_iter().cloned().collect();
    utxos.extend(unconfirmed_change_candidates(storage, &view));
    if let Some(p) = pins {
        utxos = pick_pinned(&utxos, &frozen_set(storage), p)?;
    }
    if utxos.is_empty() {
        return Ok(0);
    }
    let total: u64 = utxos.iter().map(|u| u.value_sats).sum();
    // Worst case fee assumes every UTXO is consumed (the MAX path spends all).
    let refs: Vec<&tier2_wallet::OnchainUtxo> = utxos.iter().collect();
    let fee = funding_fee(&refs, fee_rate_sat_per_kw);   // v285: real input sizes
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
    let frozen = frozen_set(storage);   // v281: a frozen unconfirmed change coin stays out
    tier2_wallet::unconfirmed_change_utxos(view, &pending)
        .into_iter()
        .filter(|u| !frozen.contains(&(u.txid.clone(), u.vout)))
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
    build_funding_tx_with(root_key, storage, network, output_script, channel_value_sats, fee_rate_sat_per_kw, None)
}

/// v282 (S50, coin control cut 3): the user's chosen coins for an open. The page hands them to
/// open_channel_to_lsp_with, which parks them under the open's nonce (the low half of the
/// user_channel_id's middle 64 bits); LDK's FundingGenerationReady, seconds later, takes them
/// back by that nonce and builds the funding transaction from EXACTLY those coins.
static PARKED_PINS: std::sync::Mutex<Vec<(u32, Vec<(String, u32)>)>> = std::sync::Mutex::new(Vec::new());

pub fn park_pins(nonce: u32, pins: Vec<(String, u32)>) {
    if let Ok(mut g) = PARKED_PINS.lock() {
        g.retain(|(n, _)| *n != nonce);
        g.push((nonce, pins));
        // an open that never reached its event leaves a stale entry; keep the list short
        while g.len() > 8 { g.remove(0); }
    }
}

pub fn take_pins(nonce: u32) -> Option<Vec<(String, u32)>> {
    let mut g = PARKED_PINS.lock().ok()?;
    let i = g.iter().position(|(n, _)| *n == nonce)?;
    Some(g.remove(i).1)
}

/// v282: resolve chosen coins against the candidates — exactly those, in the order given.
fn pick_pinned(
    candidates: &[tier2_wallet::OnchainUtxo],
    frozen: &std::collections::HashSet<(String, u32)>,
    pins: &[(String, u32)],
) -> LijResult<Vec<tier2_wallet::OnchainUtxo>> {
    if pins.is_empty() {
        return Err(LijError::Node("no coins chosen".into()));
    }
    let mut out = Vec::with_capacity(pins.len());
    let mut seen: std::collections::HashSet<(String, u32)> = std::collections::HashSet::new();
    for (txid, vout) in pins {
        let key = (txid.to_ascii_lowercase(), *vout);
        if !seen.insert(key.clone()) { continue; }
        if frozen.contains(&key) {
            return Err(LijError::Node(format!("a chosen coin is frozen ({}…:{vout}) — unfreeze it first", &txid[..8.min(txid.len())])));
        }
        match candidates.iter().find(|u| u.txid.eq_ignore_ascii_case(txid) && u.vout == *vout) {
            Some(u) => out.push(u.clone()),
            None => return Err(LijError::Node(format!(
                "a chosen coin is not spendable ({}…:{vout}) — already spent, reserved by a send still confirming, or unknown",
                &txid[..8.min(txid.len())]
            ))),
        }
    }
    Ok(out)
}

pub fn build_funding_tx_with(
    root_key: &RootKey,
    storage: &dyn LijStorage,
    network: Network,
    output_script: ScriptBuf,
    channel_value_sats: u64,
    fee_rate_sat_per_kw: u32,
    pins: Option<&[(String, u32)]>,
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
    let frozen = frozen_set(storage);   // v281: the user's freezes are never funding
    let mut candidates: Vec<tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| {
            u.spent_height.is_none()
                && crate::onchain_send::is_signable(u)   // v285: m/84 coins, and a silent-payment coin with its t_k
                && !reserved.contains(&(u.txid.clone(), u.vout))
                && !frozen.contains(&(u.txid.clone(), u.vout))
        })
        .cloned()
        .collect();
    candidates.extend(unconfirmed_change_candidates(storage, &view));
    if candidates.is_empty() {
        return Err(LijError::Node(
            "no spendable on-chain funds to open a channel".into(),
        ));
    }

    // v282 (S50): the user's chosen coins — exactly those; short = an error in plain words.
    let pinned: Option<Vec<tier2_wallet::OnchainUtxo>> = match pins {
        Some(p) => Some(pick_pinned(&candidates, &frozen, p)?),
        None => None,
    };
    let candidates: Vec<tier2_wallet::OnchainUtxo> = match pinned { Some(c) => c, None => candidates };
    // v281 (S50): DP's pick rule — the smallest single coin that covers channel value +
    // fee, else largest first (coin_select::pick; was largest-first always). With chosen
    // coins the set IS the selection (v282).
    let values: Vec<u64> = candidates.iter().map(|u| u.value_sats).collect();
    let all_refs: Vec<&tier2_wallet::OnchainUtxo> = candidates.iter().collect();
    let picked = if pins.is_some() {
        let fee = funding_fee(&all_refs, fee_rate_sat_per_kw);   // v285: the chosen coins' real sizes
        let have: u64 = values.iter().sum();
        if have >= channel_value_sats.saturating_add(fee) { Some((0..values.len()).collect::<Vec<usize>>()) } else {
            return Err(LijError::Node(format!(
                "your chosen coins cover {have} sats; this channel needs {} (channel {channel_value_sats} + fee {fee}) — add coins or lower the size",
                channel_value_sats.saturating_add(fee)
            )));
        }
    } else {
        // v285 (DP's silent-payment design, 2026-09-28: "SP coins are prioritized as inputs to
        // self-funded channel opens"): the automatic pick tries the silent-payment coins alone
        // first — by the same rule — and falls back to the rule over every coin when they cannot
        // cover. The pick counts every coin at the larger 68-vB size (never short); the fee the
        // transaction pays is the selected coins' real sizes, below.
        let sp_idx: Vec<usize> = (0..candidates.len()).filter(|&i| candidates[i].chain == crate::tier2::CHAIN_SP).collect();
        let sp_first = if sp_idx.is_empty() { None } else {
            let sp_values: Vec<u64> = sp_idx.iter().map(|&i| values[i]).collect();
            crate::coin_select::pick(&sp_values, |n| {
                channel_value_sats.saturating_add(estimate_fee(n, 2, fee_rate_sat_per_kw))
            }).map(|idx| idx.into_iter().map(|j| sp_idx[j]).collect::<Vec<usize>>())
        };
        match sp_first {
            Some(idx) => Some(idx),
            None => crate::coin_select::pick(&values, |n| {
                channel_value_sats.saturating_add(estimate_fee(n, 2, fee_rate_sat_per_kw))
            }),
        }
    };
    let selected: Vec<&tier2_wallet::OnchainUtxo> = match picked {
        Some(idx) => idx.into_iter().map(|i| &candidates[i]).collect(),
        None => {
            let have: u64 = values.iter().sum();
            let fee = funding_fee(&all_refs, fee_rate_sat_per_kw);
            return Err(LijError::Node(format!(
                "insufficient funds for channel: have {have} sats, need {} (channel {channel_value_sats} + fee {fee}){}",
                channel_value_sats + fee,
                if frozen.is_empty() { "" } else { " — frozen coins are not counted" }
            )));
        }
    };
    let total_in: u64 = selected.iter().map(|u| u.value_sats).sum();
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
    let mut fee_sats = funding_fee(&selected, fee_rate_sat_per_kw);   // v285: the selected coins' real sizes
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
    let change_spk = Address::p2wpkh(&bitcoin::CompressedPublicKey(change_pubkey.inner), network)
        .script_pubkey();

    // Outputs: funding (LDK's 2-of-2 script), plus change unless it's dust.
    let mut outputs = vec![TxOut {
        value: bitcoin::Amount::from_sat(channel_value_sats),
        script_pubkey: output_script,
    }];
    if change_sats >= DUST_THRESHOLD_SATS {
        outputs.push(TxOut {
            value: bitcoin::Amount::from_sat(change_sats),
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
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    // v285: the one signer every spend shares (onchain_send::sign_inputs) — an m/84 coin signs
    // BIP143 ECDSA as ever; a silent-payment coin signs Schnorr on the taproot key-path sighash.
    let signable: Vec<crate::onchain_send::SpendableUtxo> = selected.iter().map(|u| crate::onchain_send::SpendableUtxo::from_utxo(u)).collect();
    let signable_refs: Vec<&crate::onchain_send::SpendableUtxo> = signable.iter().collect();
    let witnesses: Vec<Witness> = crate::onchain_send::sign_inputs(root_key, &secp, &tx, &signable_refs)?;
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

#[cfg(test)]
mod coin_control_tests {
    // v282 (S50): the parked pins by nonce, and the exact-set resolver.
    use super::*;

    fn coin(txid: &str, vout: u32, value: u64) -> tier2_wallet::OnchainUtxo {
        tier2_wallet::OnchainUtxo { chain: 0, index: 0, txid: txid.into(), vout, value_sats: value, height: 1, spent_height: None, spent_txid: None, sp_tweak: None }
    }

    #[test]
    fn park_and_take_by_nonce_once() {
        park_pins(7, vec![("aa".into(), 0)]);
        park_pins(8, vec![("bb".into(), 1)]);
        assert_eq!(take_pins(9), None);
        assert_eq!(take_pins(7), Some(vec![("aa".to_string(), 0u32)]));
        assert_eq!(take_pins(7), None, "taken once");
        assert_eq!(take_pins(8), Some(vec![("bb".to_string(), 1u32)]));
    }

    #[test]
    fn pinned_set_is_exact_and_refuses_frozen_or_unknown() {
        let cands = vec![coin("aa", 0, 10), coin("bb", 0, 20)];
        let mut frozen = std::collections::HashSet::new();
        let got = pick_pinned(&cands, &frozen, &[("BB".into(), 0)]).unwrap();
        assert_eq!(got.len(), 1); assert_eq!(got[0].txid, "bb");
        assert!(pick_pinned(&cands, &frozen, &[("zz".into(), 0)]).is_err());
        assert!(pick_pinned(&cands, &frozen, &[]).is_err());
        frozen.insert(("aa".to_string(), 0));
        assert!(pick_pinned(&cands, &frozen, &[("aa".into(), 0)]).unwrap_err().to_string().contains("frozen"));
    }

    fn root() -> RootKey {
        RootKey::from_mnemonic(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            Network::Bitcoin,
        ).unwrap()
    }

    /// A ledger with one m/84 receive coin (60k) and one silent-payment coin (50k, its t_k on
    /// the record) in an in-memory store; returns the store and the SP coin's script.
    fn ledger_with_sp() -> (crate::storage::native_storage::MemoryStorage, ScriptBuf, [u8; 32]) {
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let secp = Secp256k1::new();
        let keys = crate::silent_payment::SpKeys::from_root(&root()).unwrap();
        let t_k = [0x77u8; 32];
        let sp_script = keys.script_for(&secp, &t_k).unwrap();
        let mut view = tier2_wallet::Tier2View::default();
        let mut sp = coin(&"11".repeat(32), 0, 50_000);
        sp.chain = crate::tier2::CHAIN_SP; sp.sp_tweak = Some(hex::encode(t_k));
        let mut plain = coin(&"22".repeat(32), 1, 60_000);
        plain.index = 2;
        view.utxos = vec![plain, sp];
        tier2_wallet::save_view(&storage, &view).unwrap();
        (storage, sp_script, t_k)
    }

    #[test]
    fn open_takes_the_silent_payment_coin_first_and_signs_it_schnorr() {
        // v285 (DP: "SP coins are prioritized as inputs to self-funded channel opens"): 40k
        // channel at 2 sat/vB — the 50k SP coin covers alone, so it is the one spent even though
        // the 60k m/84 coin is larger; the funding tx's one input carries a 64-byte Schnorr
        // signature that verifies against the coin's taproot key.
        use bitcoin::sighash::{Prevouts, TapSighashType, SighashCache};
        use bitcoin::hashes::Hash;
        let (storage, sp_script, t_k) = ledger_with_sp();
        let secp = Secp256k1::new();
        let funding_spk = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0xab; 32]));
        let f = build_funding_tx(&root(), &storage, Network::Bitcoin, funding_spk, 40_000, 2 * 250).unwrap();
        assert_eq!(f.inputs, 1);
        assert_eq!(f.spent_outpoints, vec![("11".repeat(32), 0u32)]);
        assert_eq!(f.fee_sats, (11 + 58 + 31 * 2) * 2, "a taproot input is 58 vB");
        assert_eq!(f.change_sats, 50_000 - 40_000 - f.fee_sats);
        let w = &f.tx.input[0].witness;
        assert_eq!(w.len(), 1);
        assert_eq!(w.nth(0).unwrap().len(), 64);
        let prevouts = vec![TxOut { value: bitcoin::Amount::from_sat(50_000), script_pubkey: sp_script.clone() }];
        let mut unsigned = f.tx.clone(); unsigned.input[0].witness = Witness::new();
        let mut cache = SighashCache::new(&unsigned);
        let sh = cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&sp_script.as_bytes()[2..34]).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(w.nth(0).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &xonly).expect("Schnorr verifies");
        let _ = t_k;
        // the SP coin cannot cover 55k alone → the rule over every coin: the 60k m/84 coin alone
        let funding_spk = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0xab; 32]));
        let f2 = build_funding_tx(&root(), &storage, Network::Bitcoin, funding_spk, 55_000, 2 * 250).unwrap();
        assert_eq!(f2.spent_outpoints, vec![("22".repeat(32), 1u32)]);
        assert_eq!(f2.fee_sats, (11 + 68 + 31 * 2) * 2);
        assert_eq!(f2.tx.input[0].witness.len(), 2, "an m/84 coin signs ECDSA (sig + key)");
        // Max counts both coins at their real sizes
        assert_eq!(max_channel_value(&storage, 2 * 250).unwrap(), 110_000 - (11 + 58 + 68 + 62) * 2);
    }

    #[test]
    fn chosen_coins_mix_a_silent_payment_coin_and_an_m84_coin() {
        // v285: both chosen for a 100k channel — exactly those two, each signed its own way.
        use bitcoin::hashes::Hash;
        let (storage, _sp_script, _) = ledger_with_sp();
        let funding_spk = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0xcd; 32]));
        let pins = vec![("11".repeat(32), 0u32), ("22".repeat(32), 1u32)];
        let f = build_funding_tx_with(&root(), &storage, Network::Bitcoin, funding_spk, 100_000, 2 * 250, Some(&pins)).unwrap();
        assert_eq!(f.inputs, 2);
        assert_eq!(f.fee_sats, (11 + 58 + 68 + 62) * 2);
        assert_eq!(f.tx.input[0].witness.len(), 1, "the SP coin: one Schnorr signature");
        assert_eq!(f.tx.input[1].witness.len(), 2, "the m/84 coin: DER signature + key");
        assert_eq!(f.change_sats, 110_000 - 100_000 - f.fee_sats);
    }
}
