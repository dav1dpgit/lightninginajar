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
    estimate_fee_with(n_in, n_out, 0, fee_rate_sat_per_kw)
}

/// v240: `extra_vbytes` covers outputs larger than P2WPKH — a silent-payment
/// destination is a P2TR output, 43 vB instead of 31.
pub(crate) fn estimate_fee_with(n_in: usize, n_out: usize, extra_vbytes: u64, fee_rate_sat_per_kw: u32) -> u64 {
    let vsize = 11 + 68 * n_in as u64 + 31 * n_out as u64 + extra_vbytes;
    let sat_per_vb = (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1);
    vsize * sat_per_vb
}

/// v240 (BIP-352): the destination is either an ordinary address (script known
/// up front) or a silent-payment address (script derived from the inputs that
/// end up selected). `Deferred` carries the parsed keys until then.
enum Dest {
    Script(ScriptBuf),
    SilentPayment(crate::silent_payment::SpAddress),
}

fn parse_dest(dest: &str, network: Network) -> LijResult<Dest> {
    if crate::silent_payment::looks_like(dest, network) {
        return Ok(Dest::SilentPayment(crate::silent_payment::parse(dest, network)?));
    }
    let dest_addr = Address::from_str(dest)
        .map_err(|e| LijError::Node(format!("invalid address: {e}")))?
        .require_network(network)
        .map_err(|e| LijError::Node(format!("address is for the wrong network: {e}")))?;
    Ok(Dest::Script(dest_addr.script_pubkey()))
}

/// The output script for `dest` given the inputs finally selected — for a
/// silent-payment address this is where the one-time taproot key is derived.
fn resolve_dest_script(
    dest: &Dest,
    root_key: &RootKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    selected: &[&SpendableUtxo],
) -> LijResult<ScriptBuf> {
    match dest {
        Dest::Script(spk) => Ok(spk.clone()),
        Dest::SilentPayment(addr) => {
            let mut inputs = Vec::with_capacity(selected.len());
            let mut sp_keys: Option<crate::silent_payment::SpKeys> = None;
            for u in selected {
                let (secret, taproot) = match u.sp_tweak {
                    Some(t) if u.chain == crate::tier2::CHAIN_SP => {
                        // v284: a silent-payment coin spends with b_spend + t_k and counts as a taproot input
                        if sp_keys.is_none() { sp_keys = Some(crate::silent_payment::SpKeys::from_root(root_key)?); }
                        (sp_keys.as_ref().unwrap().spend_secret(secp, &t)?, true)
                    }
                    _ => (signing_secret(root_key, secp, u.chain, u.index)?, false),
                };
                inputs.push(crate::silent_payment::SpInput {
                    secret,
                    outpoint: OutPoint {
                        txid: Txid::from_str(&u.txid)
                            .map_err(|e| LijError::Node(format!("bad utxo txid {}: {e}", u.txid)))?,
                        vout: u.vout,
                    },
                    taproot,
                });
            }
            crate::silent_payment::derive_output_script(secp, &inputs, addr)
        }
    }
}

fn dest_extra_vbytes(dest: &Dest) -> u64 {
    match dest {
        Dest::Script(_) => 0,
        Dest::SilentPayment(_) => 12,
    }
}

// ── v291 (S50, DP 23:04 "Go on Black start v291"): THE BLACK START KIT'S SILENT-PAYMENT SWEEPS ──
// For every unspent silent-payment coin, ONE pre-signed transaction that moves that coin alone (never combined —
// DP's ruling) to a fresh m/84 address of the wallet's own (one address per coin: the kit's destination index + 1 + i,
// on the receive chain any BIP-84 wallet derives from the 12 words), at the kit's two fee rates. A coin too small to
// pay a rate gets nothing at that rate. Signed by the one signer every spend shares (sign_inputs). Valid the moment it
// is broadcast (no delay, unlike a channel's sweep); signals RBF so the high-rate variant can replace the normal one.

/// One coin's kit entry.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SpKitSweep {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub height: u32,
    /// The fresh m/84 receive address this coin's sweep pays, and its index.
    pub destination: String,
    pub destination_index: u32,
    pub sweep_txid_normal: Option<String>,
    pub sweep_hex_normal: Option<String>,
    pub sweep_fee_normal: Option<u64>,
    pub sweep_txid_high: Option<String>,
    pub sweep_hex_high: Option<String>,
    pub sweep_fee_high: Option<u64>,
}

/// The kit's silent-payment sweeps for `view`'s unspent chain-352 coins (sorted by outpoint, so the kit is stable).
/// `first_dest_index` is the first free m/84 receive index the kit may use (the coins take consecutive ones).
pub fn sp_kit_sweeps(
    root_key: &RootKey,
    view: &crate::tier2_wallet::Tier2View,
    network: Network,
    first_dest_index: u32,
    rates_sat_vb: (u64, u64),
) -> LijResult<Vec<SpKitSweep>> {
    let secp = Secp256k1::new();
    let mut coins: Vec<&crate::tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| u.chain == crate::tier2::CHAIN_SP && u.spent_height.is_none() && is_signable(u))
        .collect();
    coins.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    let receive_parent = root_key.shutdown_xpriv()?;   // m/84'/{coin}'/0'/0
    let mut out = Vec::with_capacity(coins.len());
    for (i, u) in coins.iter().enumerate() {
        let dest_index = first_dest_index.saturating_add(i as u32);
        let child = receive_parent
            .derive_priv(&secp, &DerivationPath::from(vec![ChildNumber::from_normal_idx(dest_index).map_err(|e| LijError::Key(format!("kit sweep index: {e}")))?]))
            .map_err(|e| LijError::Key(format!("kit sweep destination: {e}")))?;
        let pk = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
        let dest = Address::p2wpkh(&bitcoin::CompressedPublicKey(pk.inner), network);
        let spend = SpendableUtxo::from_utxo(u);
        let outpoint = OutPoint { txid: Txid::from_str(&u.txid).map_err(|e| LijError::Node(format!("kit sweep txid: {e}")))?, vout: u.vout };
        let vbytes = 11 + input_vbytes(u.chain) + 31;   // one input, one P2WPKH output
        let variant = |rate: u64| -> LijResult<Option<(String, String, u64)>> {
            let fee = vbytes * rate;
            if u.value_sats <= fee + DUST_THRESHOLD_SATS {
                return Ok(None);
            }
            let mut tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn { previous_output: outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }],
                output: vec![TxOut { value: bitcoin::Amount::from_sat(u.value_sats - fee), script_pubkey: dest.script_pubkey() }],
            };
            let w = sign_inputs(root_key, &secp, &tx, &[&spend])?;
            tx.input[0].witness = w.into_iter().next().unwrap_or_default();
            Ok(Some((tx.compute_txid().to_string(), hex::encode(serialize(&tx)), fee)))
        };
        let normal = variant(rates_sat_vb.0)?;
        let high = variant(rates_sat_vb.1)?;
        out.push(SpKitSweep {
            txid: u.txid.clone(),
            vout: u.vout,
            value_sats: u.value_sats,
            height: u.height,
            destination: dest.to_string(),
            destination_index: dest_index,
            sweep_txid_normal: normal.as_ref().map(|v| v.0.clone()),
            sweep_hex_normal: normal.as_ref().map(|v| v.1.clone()),
            sweep_fee_normal: normal.as_ref().map(|v| v.2),
            sweep_txid_high: high.as_ref().map(|v| v.0.clone()),
            sweep_hex_high: high.as_ref().map(|v| v.1.clone()),
            sweep_fee_high: high.as_ref().map(|v| v.2),
        });
    }
    Ok(out)
}

/// A spendable UTXO with everything needed to sign it.
/// v285: shared with channel_open (a funding transaction signs through the same signer).
pub(crate) struct SpendableUtxo {
    pub(crate) chain: u32, // 0=receive, 1=change, 525=legacy, 352=silent payment (v284)
    pub(crate) index: u32,
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) value_sats: u64,
    /// v284: a silent-payment coin's t_k — the key and the script come from it.
    pub(crate) sp_tweak: Option<[u8; 32]>,
}

impl SpendableUtxo {
    /// v285: a ledger record as a signable input (the tweak parsed when the record has one).
    pub(crate) fn from_utxo(u: &crate::tier2_wallet::OnchainUtxo) -> SpendableUtxo {
        SpendableUtxo { chain: u.chain, index: u.index, txid: u.txid.clone(), vout: u.vout, value_sats: u.value_sats, sp_tweak: sp_tweak_of(u) }
    }
}

/// v284: the t_k on a ledger record, parsed (None when absent or malformed).
pub(crate) fn sp_tweak_of(u: &crate::tier2_wallet::OnchainUtxo) -> Option<[u8; 32]> {
    let h = u.sp_tweak.as_deref()?;
    let b = hex::decode(h).ok()?;
    if b.len() != 32 { return None; }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

/// v285: is this ledger record a coin the wallet can sign for? Receive and change (m/84) always;
/// a silent-payment coin (chain 352) when its t_k is on the record. Legacy (m/525) never here.
pub(crate) fn is_signable(u: &crate::tier2_wallet::OnchainUtxo) -> bool {
    u.chain == crate::tier2::CHAIN_RECEIVE
        || u.chain == crate::tier2::CHAIN_CHANGE
        || (u.chain == crate::tier2::CHAIN_SP && sp_tweak_of(u).is_some())
}

/// v284: an input's size in the fee estimate — a taproot key-path input (a silent-payment coin)
/// is 57.5 vB, a P2WPKH input 68.
pub(crate) fn input_vbytes(chain: u32) -> u64 {
    if chain == crate::tier2::CHAIN_SP { 58 } else { 68 }
}

/// v284: the fee for exactly these inputs (their real sizes) and `n_out` outputs.
fn estimate_fee_inputs(selected: &[&SpendableUtxo], n_out: usize, extra_vbytes: u64, fee_rate_sat_per_kw: u32) -> u64 {
    estimate_fee_mixed(selected, 0, n_out, extra_vbytes, fee_rate_sat_per_kw)
}

/// v284: the fee for these inputs (real sizes) plus `extra_inputs` not yet chosen, counted at the
/// P2WPKH size (68 vB — the larger, so a pick over unknown coins never comes up short).
fn estimate_fee_mixed(selected: &[&SpendableUtxo], extra_inputs: usize, n_out: usize, extra_vbytes: u64, fee_rate_sat_per_kw: u32) -> u64 {
    estimate_fee_chains(selected.iter().map(|u| u.chain), extra_inputs, n_out, extra_vbytes, fee_rate_sat_per_kw)
}

/// v285: the same estimate from the inputs' chains alone (channel_open works on ledger records).
pub(crate) fn estimate_fee_chains(chains: impl Iterator<Item = u32>, extra_inputs: usize, n_out: usize, extra_vbytes: u64, fee_rate_sat_per_kw: u32) -> u64 {
    let vsize = 11
        + chains.map(input_vbytes).sum::<u64>()
        + 68 * extra_inputs as u64
        + 31 * n_out as u64
        + extra_vbytes;
    let sat_per_vb = (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1);
    vsize * sat_per_vb
}

/// Spendable coins for a plain send, read from the canonical Tier-2 view — the
/// SAME source channel funding and the displayed balance use. Unspent receive +
/// change (chain 0/1), minus any input already reserved by a pending tx. Legacy
/// m/525 force-close residue is excluded (it's surfaced as legacy residue and
/// recovered via the documented BlueWallet custom-path), matching funding +
/// display. Replaces the old live Esplora scan: one source of truth, no chain-1
/// divergence, and confirmed change is counted everywhere it is spent or shown.
/// v281 (S50, coin control): `frozen` — the outpoints the user froze (CoinMarks::frozen_set);
/// a frozen coin is never a candidate, confirmed or unconfirmed change alike.
fn gather_spendable(
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    frozen: &std::collections::HashSet<(String, u32)>,
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
                && is_signable(u)   // v284: m/84 receive + change, and a silent-payment coin with its t_k
                && !reserved.contains(&(u.txid.clone(), u.vout))
                && !frozen.contains(&(u.txid.clone(), u.vout))
        })
        .map(SpendableUtxo::from_utxo)
        .collect();
    // Also spend our own unconfirmed change — the SAME source as the optimistic
    // balance, so what shows as spendable actually is. Chains off the pending
    // parent (doubles as CPFP); signed at chain 1 / change_index by
    // signing_secret. unconfirmed_change_utxos already skips reserved and
    // already-confirmed change, so there is no overlap with the view UTXOs above.
    for u in crate::tier2_wallet::unconfirmed_change_utxos(view, pending) {
        if frozen.contains(&(u.txid.clone(), u.vout)) {
            continue;   // v281: a frozen unconfirmed change coin stays out too
        }
        out.push(SpendableUtxo {
            chain: u.chain,
            index: u.index,
            txid: u.txid,
            vout: u.vout,
            value_sats: u.value_sats,
            sp_tweak: None,
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
    marks: &crate::tier2_wallet::CoinMarks,
) -> LijResult<SendResult> {
    build_and_send_pinned(root_key, independent, network, dest, amount_sats, fee_rate_sat_per_kw, change_index, view, pending, marks, None).await
}

/// v282 (S50, coin control cut 3 — chosen coins): an exact amount from EXACTLY the chosen coins
/// (`pins`, as (txid, vout)); change to m/84 as ever. None = the automatic pick.
pub async fn build_and_send_pinned(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    dest: &str,
    amount_sats: u64,
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
) -> LijResult<SendResult> {
    if amount_sats == 0 {
        return Err(LijError::Node("amount must be greater than zero".into()));
    }
    build_and_send_inner(root_key, independent, network, dest, SendAmount::Exact(amount_sats), fee_rate_sat_per_kw, change_index, view, pending, marks, pins).await
}

/// v281 (S50, coin control — Max): send EVERYTHING sendable (every unfrozen, unreserved
/// coin) to `dest` in ONE output: amount = total − the fee for that one-output shape. No
/// change output, no leftover coin. The page's old Max reserved a two-output fee and let
/// the builder fold the ~0 change into the fee; this is the exact form, sized for one
/// output, and the one the page calls from v845 on.
pub async fn build_and_send_all(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    dest: &str,
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
) -> LijResult<SendResult> {
    build_and_send_inner(root_key, independent, network, dest, SendAmount::All, fee_rate_sat_per_kw, change_index, view, pending, marks, None).await
}

/// v282 (S50, coin control cut 3): everything in the CHOSEN coins to `dest` in one output.
pub async fn build_and_send_all_pinned(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    dest: &str,
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: &[(String, u32)],
) -> LijResult<SendResult> {
    build_and_send_inner(root_key, independent, network, dest, SendAmount::All, fee_rate_sat_per_kw, change_index, view, pending, marks, Some(pins)).await
}

/// v282: resolve the user's chosen coins against the sendable set — exactly those, in the
/// order given. A frozen or unknown choice is an error the page shows in plain words.
fn resolve_pins<'a>(
    spendable: &'a [SpendableUtxo],
    frozen: &std::collections::HashSet<(String, u32)>,
    pins: &[(String, u32)],
) -> LijResult<Vec<&'a SpendableUtxo>> {
    if pins.is_empty() {
        return Err(LijError::Node("no coins chosen".into()));
    }
    let mut out: Vec<&SpendableUtxo> = Vec::with_capacity(pins.len());
    let mut seen: std::collections::HashSet<(String, u32)> = std::collections::HashSet::new();
    for (txid, vout) in pins {
        let key = (txid.to_ascii_lowercase(), *vout);
        if !seen.insert(key.clone()) {
            continue;   // the same coin twice is one coin
        }
        if frozen.contains(&key) {
            return Err(LijError::Node(format!("a chosen coin is frozen ({}…:{vout}) — unfreeze it first", &txid[..8.min(txid.len())])));
        }
        match spendable.iter().find(|u| u.txid.eq_ignore_ascii_case(txid) && u.vout == *vout) {
            Some(u) => out.push(u),
            None => {
                return Err(LijError::Node(format!(
                    "a chosen coin is not spendable ({}…:{vout}) — already spent, reserved by a send still confirming, or unknown",
                    &txid[..8.min(txid.len())]
                )))
            }
        }
    }
    Ok(out)
}

/// v281: what a send asks for — an exact amount (change back to m/84), or everything.
#[derive(Clone, Copy, Debug)]
enum SendAmount {
    Exact(u64),
    All,
}

/// v281 (S50, coin control): the exact Max for the page — what a one-output send of every
/// sendable coin delivers at this fee rate, from the same candidate set and the same fee
/// arithmetic the builder uses, so the number on the screen is the number that goes out.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MaxQuote {
    /// What the recipient gets (0 when the coins do not cover the fee).
    pub max_sats: u64,
    pub fee_sats: u64,
    pub inputs: usize,
    /// The coins' total before the fee.
    pub total_sats: u64,
    /// What a freeze keeps out of this Max.
    pub frozen_sats: u64,
    pub frozen_count: usize,
    pub sat_per_vb: u64,
}

impl MaxQuote {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self)
            .map_err(|e| LijError::Storage(format!("max quote serialize: {e}")))
    }
}

/// v281: the Max quote. `dest` may be empty or not yet valid (the user is still typing)
/// — then the ordinary-output size is assumed; a silent-payment address adds its 12 vB.
pub fn max_sendable(
    dest: &str,
    network: Network,
    fee_rate_sat_per_kw: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
) -> MaxQuote {
    let extra_vb = match parse_dest(dest, network) {
        Ok(d) => dest_extra_vbytes(&d),
        Err(_) => 0,
    };
    let frozen = marks.frozen_set();
    let spendable = gather_spendable(view, pending, &frozen);
    let total_sats: u64 = spendable.iter().map(|u| u.value_sats).sum();
    let inputs = spendable.len();
    let refs: Vec<&SpendableUtxo> = spendable.iter().collect();
    let fee_sats = if inputs == 0 { 0 } else { estimate_fee_inputs(&refs, 1, extra_vb, fee_rate_sat_per_kw) };   // v284: real input sizes
    let max_sats = total_sats.saturating_sub(fee_sats);
    // The frozen figure: unspent, unreserved coins the user froze (the same set the
    // summary reports), so the page can say "Max leaves out N frozen sats".
    let reserved: std::collections::HashSet<(String, u32)> = pending
        .iter()
        .flat_map(|p| p.spent_outpoints.iter().cloned())
        .collect();
    let mut frozen_sats = 0u64;
    let mut frozen_count = 0usize;
    for u in view.utxos.iter().filter(|u| u.spent_height.is_none() && u.chain != crate::tier2::CHAIN_LEGACY) {
        if frozen.contains(&(u.txid.clone(), u.vout)) && !reserved.contains(&(u.txid.clone(), u.vout)) {
            frozen_sats = frozen_sats.saturating_add(u.value_sats);
            frozen_count += 1;
        }
    }
    for u in crate::tier2_wallet::unconfirmed_change_utxos(view, pending) {
        if frozen.contains(&(u.txid.clone(), u.vout)) {
            frozen_sats = frozen_sats.saturating_add(u.value_sats);
            frozen_count += 1;
        }
    }
    MaxQuote {
        max_sats,
        fee_sats,
        inputs,
        total_sats,
        frozen_sats,
        frozen_count,
        sat_per_vb: (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1),
    }
}

/// v282 (S50, coin control cut 3): the picker's quote. For the chosen coins (or every sendable
/// coin when none are chosen): the one-output Max, and — with an amount — what the send needs
/// (amount + the fee for those inputs and two outputs), whether the choice covers it, and how
/// short it is. `fill` asks the engine to pick, by DP's rule, the extra coins that would cover
/// the shortfall ("Fill the rest for me"): the page shows them ticked; nothing is spent here.
/// A frozen or unknown choice is reported in `problem` — the page shows it, the button greys.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CoinQuote {
    pub chosen: Vec<(String, u32)>,
    pub chosen_sats: u64,
    pub chosen_count: usize,
    pub max_sats: u64,
    pub max_fee_sats: u64,
    pub amount_sats: Option<u64>,
    pub need_sats: Option<u64>,
    pub fee_sats: Option<u64>,
    pub covered: Option<bool>,
    pub short_sats: Option<u64>,
    pub fill: Vec<(String, u32)>,
    pub fill_sats: u64,
    pub fill_covers: Option<bool>,
    /// v283: the coins the send WOULD spend for this amount — the chosen set, or the automatic
    /// pick — and the change it would leave. `tiny_change` = a change coin that is worth
    /// keeping out: at or above the dust floor (below it the builder folds it into the fee)
    /// but under max(1,000 sats, five times what one input costs to spend at this rate).
    pub spend: Vec<(String, u32)>,
    pub spend_sats: u64,
    pub change_sats: Option<u64>,
    pub tiny_change: bool,
    pub tiny_below_sats: u64,
    pub dust_sats: u64,
    pub sendable_sats: u64,
    pub frozen_sats: u64,
    pub frozen_count: usize,
    pub sat_per_vb: u64,
    pub problem: Option<String>,
}

impl CoinQuote {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self)
            .map_err(|e| LijError::Storage(format!("coin quote serialize: {e}")))
    }
}

pub fn coin_quote(
    dest: &str,
    network: Network,
    fee_rate_sat_per_kw: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
    amount_sats: Option<u64>,
    fill: bool,
) -> CoinQuote {
    let extra_vb = match parse_dest(dest, network) {
        Ok(d) => dest_extra_vbytes(&d),
        Err(_) => 0,
    };
    let base = max_sendable(dest, network, fee_rate_sat_per_kw, view, pending, marks);
    let frozen = marks.frozen_set();
    let spendable = gather_spendable(view, pending, &frozen);
    let mut problem: Option<String> = None;
    let chosen: Vec<&SpendableUtxo> = match pins {
        Some(p) if !p.is_empty() => match resolve_pins(&spendable, &frozen, p) {
            Ok(c) => c,
            Err(e) => { problem = Some(e.to_string()); Vec::new() }
        },
        _ => spendable.iter().collect(),
    };
    let chosen_sats: u64 = chosen.iter().map(|u| u.value_sats).sum();
    let n = chosen.len();
    // v284: the chosen coins' real sizes (a silent-payment coin is the smaller taproot input)
    let max_fee_sats = if n == 0 { 0 } else { estimate_fee_inputs(&chosen, 1, extra_vb, fee_rate_sat_per_kw) };
    let max_sats = chosen_sats.saturating_sub(max_fee_sats);
    let (need_sats, fee_sats, covered, short_sats) = match amount_sats {
        Some(a) => {
            let fee = estimate_fee_mixed(&chosen, if n == 0 { 1 } else { 0 }, 2, extra_vb, fee_rate_sat_per_kw);
            let need = a.saturating_add(fee);
            (Some(need), Some(fee), Some(chosen_sats >= need), Some(need.saturating_sub(chosen_sats)))
        }
        None => (None, None, None, None),
    };
    // Fill the rest for me: DP's rule over the coins NOT chosen, the chosen ones counted in.
    let mut fill_out: Vec<(String, u32)> = Vec::new();
    let mut fill_sats = 0u64;
    let mut fill_covers: Option<bool> = None;
    if fill && problem.is_none() {
        if let (Some(a), Some(false)) = (amount_sats, covered) {
            let chosen_keys: std::collections::HashSet<(String, u32)> = chosen.iter().map(|u| (u.txid.clone(), u.vout)).collect();
            let rest: Vec<&SpendableUtxo> = spendable.iter().filter(|u| !chosen_keys.contains(&(u.txid.clone(), u.vout))).collect();
            let values: Vec<u64> = rest.iter().map(|u| u.value_sats).collect();
            let picked = crate::coin_select::pick(&values, |k| {
                a.saturating_add(estimate_fee_mixed(&chosen, k, 2, extra_vb, fee_rate_sat_per_kw)).saturating_sub(chosen_sats)
            });
            match picked {
                Some(idx) => {
                    for i in idx { fill_out.push((rest[i].txid.clone(), rest[i].vout)); fill_sats = fill_sats.saturating_add(rest[i].value_sats); }
                    fill_covers = Some(true);
                }
                None => { fill_covers = Some(false); }
            }
        }
    }
    // v283: what the send would spend and leave — the chosen set as is, or the automatic pick.
    let sat_per_vb = (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1);
    let tiny_below_sats = 1_000u64.max(5 * 68 * sat_per_vb);
    let mut spend: Vec<(String, u32)> = Vec::new();
    let mut spend_sats = 0u64;
    let mut change_sats: Option<u64> = None;
    if let Some(a) = amount_sats {
        if problem.is_none() {
            let set: Option<Vec<&SpendableUtxo>> = match pins {
                Some(p) if !p.is_empty() => if covered == Some(true) { Some(chosen.clone()) } else { None },
                _ => {
                    let values: Vec<u64> = spendable.iter().map(|u| u.value_sats).collect();
                    crate::coin_select::pick(&values, |k| a.saturating_add(estimate_fee_with(k, 2, extra_vb, fee_rate_sat_per_kw)))
                        .map(|idx| idx.into_iter().map(|i| &spendable[i]).collect())
                }
            };
            if let Some(set) = set {
                spend_sats = set.iter().map(|u| u.value_sats).sum();
                spend = set.iter().map(|u| (u.txid.clone(), u.vout)).collect();
                let fee = estimate_fee_inputs(&set, 2, extra_vb, fee_rate_sat_per_kw);   // v284: the set's real sizes — what the send pays
                change_sats = Some(spend_sats.saturating_sub(a).saturating_sub(fee));
            }
        }
    }
    let tiny_change = matches!(change_sats, Some(c) if c >= DUST_THRESHOLD_SATS && c < tiny_below_sats);
    CoinQuote {
        chosen: chosen.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
        chosen_sats,
        chosen_count: n,
        max_sats,
        max_fee_sats,
        amount_sats,
        need_sats,
        fee_sats,
        covered,
        short_sats,
        fill: fill_out,
        fill_sats,
        fill_covers,
        spend,
        spend_sats,
        change_sats,
        tiny_change,
        tiny_below_sats,
        dust_sats: DUST_THRESHOLD_SATS,
        sendable_sats: base.total_sats,
        frozen_sats: base.frozen_sats,
        frozen_count: base.frozen_count,
        sat_per_vb: base.sat_per_vb,
        problem,
    }
}

/// v284: the witnesses for `tx`'s inputs, in order. Each input's (key, prevout) comes from the
/// ledger record; a silent-payment coin signs Schnorr on the taproot key-path sighash
/// (SIGHASH_DEFAULT), everything else ECDSA on the BIP143 sighash.
pub(crate) fn sign_inputs(
    root_key: &RootKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
    selected: &[&SpendableUtxo],
) -> LijResult<Vec<Witness>> {
    use bitcoin::sighash::{Prevouts, TapSighashType};
    // every input's key and prevout script first (the taproot sighash needs them all)
    let mut sp_keys: Option<crate::silent_payment::SpKeys> = None;
    let mut keys: Vec<(bitcoin::secp256k1::SecretKey, ScriptBuf, bool)> = Vec::with_capacity(selected.len());
    for u in selected {
        match u.sp_tweak {
            Some(t) if u.chain == crate::tier2::CHAIN_SP => {
                if sp_keys.is_none() { sp_keys = Some(crate::silent_payment::SpKeys::from_root(root_key)?); }
                let k = sp_keys.as_ref().unwrap();
                keys.push((k.spend_secret(secp, &t)?, k.script_for(secp, &t)?, true));
            }
            _ => {
                let sk = signing_secret(root_key, secp, u.chain, u.index)?;
                let pk = bitcoin::PublicKey::new(sk.public_key(secp));
                keys.push((sk, ScriptBuf::new_p2wpkh(&bitcoin::CompressedPublicKey(pk.inner).wpubkey_hash()), false));
            }
        }
    }
    let prevouts: Vec<TxOut> = selected.iter().zip(keys.iter()).map(|(u, (_, spk, _))| TxOut { value: bitcoin::Amount::from_sat(u.value_sats), script_pubkey: spk.clone() }).collect();
    let mut witnesses: Vec<Witness> = Vec::with_capacity(selected.len());
    let mut cache = SighashCache::new(tx);
    for (i, (sk, spk, taproot)) in keys.iter().enumerate() {
        if *taproot {
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                .map_err(|e| LijError::Node(format!("taproot sighash at input {i}: {e}")))?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let kp = bitcoin::secp256k1::Keypair::from_secret_key(secp, sk);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            let mut w = Witness::new();
            w.push(sig.as_ref());   // 64 bytes, SIGHASH_DEFAULT: no type byte
            witnesses.push(w);
        } else {
            let sighash = cache
                .p2wpkh_signature_hash(i, spk, prevouts[i].value, EcdsaSighashType::All)
                .map_err(|e| LijError::Node(format!("segwit sighash at input {i}: {e}")))?;
            let msg = Message::from_slice(&sighash.to_byte_array())
                .map_err(|e| LijError::Node(format!("sighash->message: {e}")))?;
            let sig = secp.sign_ecdsa(&msg, sk);
            let mut sig_with_type = sig.serialize_der().to_vec();
            sig_with_type.push(EcdsaSighashType::All as u8);
            let pk = bitcoin::PublicKey::new(sk.public_key(secp));
            let mut w = Witness::new();
            w.push(sig_with_type);
            w.push(pk.to_bytes());
            witnesses.push(w);
        }
    }
    Ok(witnesses)
}

/// v281: the one builder behind build_and_send (an exact amount, change to m/84) and
/// build_and_send_all (everything, one output). Coins come from the ledger minus the
/// pending reserve minus the user's freezes; an exact amount picks by DP's rule
/// (coin_select::pick); everything takes every candidate.
async fn build_and_send_inner(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    dest: &str,
    what: SendAmount,
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
) -> LijResult<SendResult> {
    // Parse + network-check the destination (v240: or a silent-payment address).
    let dest_parsed = parse_dest(dest, network)?;
    let extra_vb = dest_extra_vbytes(&dest_parsed);

    let secp = Secp256k1::new();

    // Gather spendable UTXOs (receive + change) from the ledger; v281: minus the freezes.
    let frozen = marks.frozen_set();
    let spendable = gather_spendable(view, pending, &frozen);
    if spendable.is_empty() {
        return Err(LijError::Node(if frozen.is_empty() {
            "no spendable on-chain funds found".into()
        } else {
            "no spendable on-chain funds found — every coin is frozen".into()
        }));
    }
    // v282: chosen coins are EXACTLY the set the transaction spends (DP 2026-09-28: chosen
    // = exact; a top-up is the user's explicit "Fill the rest for me", never silent).
    let chosen: Option<Vec<&SpendableUtxo>> = match pins {
        Some(p) => Some(resolve_pins(&spendable, &frozen, p)?),
        None => None,
    };

    // v281: the pick (DP's rule) or everything; v282: or the chosen set.
    let (selected, amount_sats, mut fee_sats, total_in): (Vec<&SpendableUtxo>, u64, u64, u64) = match what {
        SendAmount::Exact(amount_sats) => {
            let selected: Vec<&SpendableUtxo> = match chosen {
                Some(c) => {
                    let total: u64 = c.iter().map(|u| u.value_sats).sum();
                    let fee = estimate_fee_inputs(&c, 2, extra_vb, fee_rate_sat_per_kw);   // v284: the chosen coins' real sizes — the quote's number
                    if total < amount_sats.saturating_add(fee) {
                        return Err(LijError::Node(format!(
                            "your chosen coins cover {total} sats; this send needs {} (amount {amount_sats} + fee {fee}) — add coins or lower the amount",
                            amount_sats.saturating_add(fee)
                        )));
                    }
                    c
                }
                None => {
                    let values: Vec<u64> = spendable.iter().map(|u| u.value_sats).collect();
                    let picked = crate::coin_select::pick(&values, |n| {
                        amount_sats.saturating_add(estimate_fee_with(n, 2, extra_vb, fee_rate_sat_per_kw))
                    });
                    match picked {
                        Some(idx) => idx.into_iter().map(|i| &spendable[i]).collect(),
                        None => {
                            let have: u64 = values.iter().sum();
                            let fee = estimate_fee_with(values.len(), 2, extra_vb, fee_rate_sat_per_kw);
                            return Err(LijError::Node(format!(
                                "insufficient funds: have {have} sats, need {} (amount {amount_sats} + fee {fee}){}",
                                amount_sats + fee,
                                if frozen.is_empty() { "" } else { " — frozen coins are not counted" }
                            )));
                        }
                    }
                }
            };
            let total_in: u64 = selected.iter().map(|u| u.value_sats).sum();
            let fee_sats = estimate_fee_inputs(&selected, 2, extra_vb, fee_rate_sat_per_kw);   // v284: real input sizes
            (selected, amount_sats, fee_sats, total_in)
        }
        SendAmount::All => {
            let selected: Vec<&SpendableUtxo> = match chosen { Some(c) => c, None => spendable.iter().collect() };
            let total_in: u64 = selected.iter().map(|u| u.value_sats).sum();
            let fee_sats = estimate_fee_inputs(&selected, 1, extra_vb, fee_rate_sat_per_kw);
            if total_in <= fee_sats + DUST_THRESHOLD_SATS {
                return Err(LijError::Node(format!(
                    "nothing left to send after the fee: {total_in} sats of coins, fee {fee_sats}"
                )));
            }
            (selected, total_in - fee_sats, fee_sats, total_in)
        }
    };
    let n_in = selected.len();
    // v240: a silent-payment output key depends on the inputs just chosen.
    let dest_spk = resolve_dest_script(&dest_parsed, root_key, &secp, &selected)?;
    if total_in < amount_sats + fee_sats {
        return Err(LijError::Node(format!(
            "insufficient funds: have {total_in} sats, need {} (amount {amount_sats} + fee {fee_sats})",
            amount_sats + fee_sats
        )));
    }
    let mut change_sats = total_in - amount_sats - fee_sats;   // 0 by construction for All

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
    let change_spk = Address::p2wpkh(&bitcoin::CompressedPublicKey(change_pubkey.inner), network)
        .script_pubkey();

    // Outputs: destination, plus change unless it's dust (then it goes to fee).
    let mut outputs = vec![TxOut {
        value: bitcoin::Amount::from_sat(amount_sats),
        script_pubkey: dest_spk,
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
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    // Sign each input. P2WPKH (BIP143, ECDSA) as ever; v284: a silent-payment coin (chain 352) is a
    // taproot key-path input — a Schnorr signature over the BIP-341 sighash, which commits to EVERY
    // input's prevout, so the prevouts are gathered first. Witnesses are collected while the cache
    // holds an immutable borrow of tx, then assigned after dropping the cache.
    let witnesses: Vec<Witness> = sign_inputs(root_key, &secp, &tx, &selected)?;
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

    let dest_parsed = parse_dest(dest, network)
        .map_err(|e| LijError::Node(format!("recorded destination unusable: {e}")))?;
    let extra_vb = dest_extra_vbytes(&dest_parsed);
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
                    sp_tweak: sp_tweak_of(u),
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
                        sp_tweak: None,
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
    let selected_refs: Vec<&SpendableUtxo> = selected.iter().collect();
    // v284: the inputs' real sizes (a silent-payment coin is a 58-vB taproot input, not 68)
    let vsize = 11 + selected_refs.iter().map(|u| input_vbytes(u.chain)).sum::<u64>() + 31 * 2 + extra_vb;
    let mut new_fee = estimate_fee_inputs(&selected_refs, 2, extra_vb, new_fee_rate_sat_per_kw);
    // v240: the same inputs re-derive the same silent-payment output — RBF keeps the output.
    let dest_spk = resolve_dest_script(&dest_parsed, root_key, &secp, &selected_refs)?;
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
    let change_spk = Address::p2wpkh(&bitcoin::CompressedPublicKey(change_pubkey.inner), network)
        .script_pubkey();

    let mut outputs = vec![TxOut {
        value: bitcoin::Amount::from_sat(amount_sats),
        script_pubkey: dest_spk,
    }];
    if change_sats >= DUST_THRESHOLD_SATS {
        outputs.push(TxOut {
            value: bitcoin::Amount::from_sat(change_sats),
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
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    // v284: one signer for every path — a silent-payment coin in the original signs Schnorr here too
    let witnesses: Vec<Witness> = sign_inputs(root_key, &secp, &tx, &selected_refs)?;
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
    let parent_value_sats = out.value.to_sat();
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
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: parent.txid(), vout: parent_vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(parent_value_sats - child_fee),
            script_pubkey: out.script_pubkey.clone(),
        }],
    };
    let w = {
        let cache_tx = tx.clone();
        let mut cache = SighashCache::new(&cache_tx);
        let spk = ScriptBuf::new_p2wpkh(&bitcoin::CompressedPublicKey(pk.inner).wpubkey_hash());   // 0.32: the sighash helper takes the scriptPubKey
        let sighash = cache
            .p2wpkh_signature_hash(0, &spk, bitcoin::Amount::from_sat(parent_value_sats), EcdsaSighashType::All)
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
        let spk = Address::p2wpkh(&bitcoin::CompressedPublicKey(pk.inner), network)
            .script_pubkey();
        v.push((i, spk));
    }
    Ok(v)
}

#[cfg(test)]
mod coin_control_tests {
    // v281 (S50, coin control): the Max quote and the frozen exclusion, from a ledger
    // built by hand (no network, no keys).
    use super::*;
    use crate::tier2_wallet::{CoinMarks, OnchainUtxo, Tier2View};

    fn coin(txid: &str, vout: u32, chain: u32, value: u64) -> OnchainUtxo {
        OnchainUtxo { chain, index: 0, txid: txid.into(), vout, value_sats: value, height: 900_000, spent_height: None, spent_txid: None, sp_tweak: None }
    }

    #[test]
    fn max_is_total_minus_a_one_output_fee_and_skips_frozen_and_legacy() {
        let mut view = Tier2View::default();
        view.utxos = vec![coin("aa", 0, 0, 50_000), coin("bb", 0, 1, 20_000), coin("cc", 0, 525, 9_000)];
        let rate_kw = 2 * 250;   // 2 sat/vB
        let q = max_sendable("", Network::Bitcoin, rate_kw, &view, &[], &CoinMarks::default());
        assert_eq!(q.inputs, 2, "legacy is never a candidate");
        assert_eq!(q.total_sats, 70_000);
        assert_eq!(q.fee_sats, (11 + 68 * 2 + 31) * 2);
        assert_eq!(q.max_sats, 70_000 - q.fee_sats);
        assert_eq!(q.frozen_sats, 0);
        assert_eq!(q.sat_per_vb, 2);
        let mut marks = CoinMarks::default();
        marks.set_frozen("aa", 0, true, 1);
        let q2 = max_sendable("", Network::Bitcoin, rate_kw, &view, &[], &marks);
        assert_eq!(q2.inputs, 1);
        assert_eq!(q2.total_sats, 20_000);
        assert_eq!(q2.max_sats, 20_000 - (11 + 68 + 31) * 2);
        assert_eq!(q2.frozen_sats, 50_000);
        assert_eq!(q2.frozen_count, 1);
        // a silent-payment destination costs 12 vB more on the output
        let sp = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
        let q3 = max_sendable(sp, Network::Bitcoin, rate_kw, &view, &[], &marks);
        assert_eq!(q3.fee_sats, q2.fee_sats + 12 * 2);
        // nothing sendable → zeros, no error
        marks.set_frozen("bb", 0, true, 1);
        let q4 = max_sendable("", Network::Bitcoin, rate_kw, &view, &[], &marks);
        assert_eq!((q4.inputs, q4.max_sats, q4.fee_sats, q4.frozen_sats), (0, 0, 0, 70_000));
    }

    #[test]
    fn coin_quote_chosen_needed_short_and_fill_the_rest() {
        // v282: the picker's numbers. Coins 50k, 20k, 5k (all unfrozen), 2 sat/vB.
        let mut view = Tier2View::default();
        view.utxos = vec![coin("aa", 0, 0, 50_000), coin("bb", 0, 0, 20_000), coin("cc", 0, 1, 5_000)];
        let kw = 2 * 250;
        let marks = CoinMarks::default();
        // nothing chosen, no amount: Max over every coin, one output
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, None, None, false);
        assert_eq!((q.chosen_count, q.chosen_sats, q.max_sats), (3, 75_000, 75_000 - (11 + 68 * 3 + 31) * 2));
        assert!(q.problem.is_none() && q.need_sats.is_none());
        // 5k chosen, amount 4,000: needs 4,000 + fee(1 in, 2 out) = 4,000 + 282 → covered
        let pins = vec![("cc".to_string(), 0u32)];
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(4_000), false);
        assert_eq!((q.chosen_sats, q.need_sats, q.covered, q.short_sats), (5_000, Some(4_282), Some(true), Some(0)));
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(4_800), false);
        assert_eq!((q.covered, q.short_sats), (Some(false), Some(82)));
        assert!(q.fill.is_empty() && q.fill_covers.is_none(), "no fill unless asked");
        // Fill the rest for me: the smallest single extra coin that covers the shortfall (20k, not 50k)
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(4_800), true);
        assert_eq!((q.fill, q.fill_sats, q.fill_covers), (vec![("bb".to_string(), 0u32)], 20_000, Some(true)));
        // a shortfall no coin can fill
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(90_000), true);
        assert_eq!(q.fill_covers, Some(false));
        // a frozen choice is a problem, not a crash; an unknown one too
        let mut marks2 = CoinMarks::default();
        marks2.set_frozen("cc", 0, true, 1);
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks2, Some(&pins), Some(1_000), false);
        assert!(q.problem.as_deref().unwrap_or("").contains("frozen"));
        assert_eq!(q.chosen_count, 0);
        let bad = vec![("zz".to_string(), 9u32)];
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&bad), None, false);
        assert!(q.problem.as_deref().unwrap_or("").contains("not spendable"));
        // the same coin twice is one coin
        let twice = vec![("bb".to_string(), 0u32), ("bb".to_string(), 0u32)];
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&twice), None, false);
        assert_eq!((q.chosen_count, q.chosen_sats), (1, 20_000));
        // v283: the automatic pick for an amount and the change it leaves — 4,000 from the 5k coin
        // (the smallest that covers): change = 5,000 − 4,000 − 282 = 718 → tiny (under 1,000)
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, None, Some(4_000), false);
        assert_eq!((q.spend, q.spend_sats, q.change_sats), (vec![("cc".to_string(), 0u32)], 5_000, Some(718)));
        assert!(q.tiny_change && q.tiny_below_sats == 1_000 && q.dust_sats == 294);
        // 4,600: change 118 < dust → folded into the fee, not a coin → not tiny
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, None, Some(4_600), false);
        assert_eq!((q.change_sats, q.tiny_change), (Some(118), false));
        // 15,000: the 20k coin, change 4,718 → fine
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, None, Some(15_000), false);
        assert_eq!((q.spend_sats, q.change_sats, q.tiny_change), (20_000, Some(4_718), false));
        // at 30 sat/vB the "tiny" line rises to 5 × 68 × 30 = 10,200
        let q = coin_quote("", Network::Bitcoin, 30 * 250, &view, &[], &marks, None, Some(15_000), false);
        assert_eq!(q.tiny_below_sats, 10_200);
        assert_eq!(q.change_sats, Some(20_000 - 15_000 - (11 + 68 + 62) * 30));
        assert!(q.tiny_change);
        // chosen coins that cover: the change is theirs
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(4_000), false);
        assert_eq!((q.spend_sats, q.change_sats), (5_000, Some(718)));
    }

    #[test]
    fn gather_spendable_honours_the_freeze_and_the_pending_reserve() {
        let mut view = Tier2View::default();
        view.utxos = vec![coin("aa", 0, 0, 50_000), coin("bb", 1, 0, 20_000), coin("cc", 0, 0, 5_000)];
        let mut frozen = std::collections::HashSet::new();
        frozen.insert(("aa".to_string(), 0u32));
        let pending = vec![crate::tier2_wallet::PendingTx {
            txid: "dd".into(), spent_outpoints: vec![("bb".into(), 1)], delta_sats: -1, direction: crate::tier2_wallet::TxDirection::Sent,
            kind: crate::tier2_wallet::TxKind::Onchain, created_at_ms: 0, change_outpoint: None, change_value_sats: 0, change_index: 0,
            broadcast_seen: false, raw_tx_hex: None, dest_addr: None, dest_sats: None, fee_sats: None, fee_rate_sat_per_kw: None,
        }];
        let got = gather_spendable(&view, &pending, &frozen);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].txid.as_str(), got[0].value_sats), ("cc", 5_000));
    }

    #[test]
    fn sp_coins_are_gathered_with_their_tweak_and_sized_as_taproot() {
        // v284: a chain-352 coin is a candidate (with its t_k), and the fee counts it at 58 vB
        let mut view = Tier2View::default();
        let mut sp = coin("ee", 0, crate::tier2::CHAIN_SP, 30_000);
        sp.sp_tweak = Some("11".repeat(32));
        let mut bad = coin("ff", 0, crate::tier2::CHAIN_SP, 30_000);   // a malformed tweak → not spendable
        bad.sp_tweak = Some("zz".into());
        view.utxos = vec![coin("aa", 0, 0, 50_000), sp, bad];
        let got = gather_spendable(&view, &[], &std::collections::HashSet::new());
        assert_eq!(got.len(), 2);
        let sp_row = got.iter().find(|u| u.txid == "ee").expect("the silent-payment coin is a candidate");
        assert_eq!(sp_row.sp_tweak, Some([0x11u8; 32]));
        assert!(got.iter().all(|u| u.txid != "ff"), "a coin whose tweak cannot be read is left alone");
        let refs: Vec<&SpendableUtxo> = got.iter().collect();
        assert_eq!(estimate_fee_inputs(&refs, 1, 0, 2 * 250), (11 + 68 + 58 + 31) * 2);
        let q = max_sendable("", Network::Bitcoin, 2 * 250, &view, &[], &CoinMarks::default());
        assert_eq!(q.inputs, 2);
        assert_eq!(q.fee_sats, (11 + 68 + 58 + 31) * 2);
    }

    #[test]
    fn the_kits_silent_payment_sweeps_are_one_per_coin_to_fresh_m84_addresses_and_verify() {
        // v291: two SP coins (50k and a 1,500-sat one) → two entries, each its own transaction to its own m/84
        // receive address (index 7 and 8); the small coin has a normal-rate sweep but none at the high rate; the
        // Schnorr signature of the big coin's sweep verifies against the coin's taproot key.
        use bitcoin::sighash::{Prevouts, TapSighashType};
        let root = crate::key::RootKey::from_mnemonic(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            Network::Bitcoin,
        ).unwrap();
        let secp = Secp256k1::new();
        let keys = crate::silent_payment::SpKeys::from_root(&root).unwrap();
        let mut view = crate::tier2_wallet::Tier2View::default();
        let mk = |txid: &str, vout: u32, sats: u64, t: u8| crate::tier2_wallet::OnchainUtxo { sp_tweak: Some(hex::encode([t; 32])), chain: crate::tier2::CHAIN_SP, index: 0, txid: txid.to_string(), vout, value_sats: sats, height: 900_000, spent_height: None, spent_txid: None };
        view.utxos = vec![mk(&"bb".repeat(32), 0, 1_500, 0x55), mk(&"aa".repeat(32), 1, 50_000, 0x42)];
        // a spent SP coin and an m/84 coin are not in the kit
        let mut spent = mk(&"cc".repeat(32), 0, 9_000, 0x66); spent.spent_height = Some(900_001);
        view.utxos.push(spent);
        view.utxos.push(crate::tier2_wallet::OnchainUtxo { sp_tweak: None, chain: 0, index: 2, txid: "dd".repeat(32), vout: 0, value_sats: 70_000, height: 1, spent_height: None, spent_txid: None });
        let kit = sp_kit_sweeps(&root, &view, Network::Bitcoin, 7, (10, 40)).unwrap();
        assert_eq!(kit.len(), 2);
        assert_eq!((kit[0].txid.as_str(), kit[0].destination_index, kit[1].txid.as_str(), kit[1].destination_index), ("aa".repeat(32).as_str(), 7, "bb".repeat(32).as_str(), 8), "sorted by outpoint; consecutive destinations");
        assert!(kit[0].destination.starts_with("bc1q") && kit[1].destination.starts_with("bc1q") && kit[0].destination != kit[1].destination);
        // the big coin: both rates; 100 vB → 1,000 and 4,000 sats
        assert_eq!((kit[0].sweep_fee_normal, kit[0].sweep_fee_high), (Some(1_000), Some(4_000)));
        // the small coin: normal only (1,500 − 1,000 = 500 > dust; the high rate would leave nothing)
        assert_eq!((kit[1].sweep_fee_normal, kit[1].sweep_hex_high.is_none()), (Some(1_000), true));
        // the big coin's sweep: one input, one output paying the destination, RBF signalled, Schnorr verifies
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(kit[0].sweep_hex_normal.as_ref().unwrap()).unwrap()).unwrap();
        assert_eq!((tx.input.len(), tx.output.len(), tx.output[0].value.to_sat()), (1, 1, 49_000));
        assert_eq!(tx.output[0].script_pubkey, Address::from_str(&kit[0].destination).unwrap().assume_checked().script_pubkey());
        assert_eq!(tx.input[0].sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
        assert_eq!(tx.compute_txid().to_string(), *kit[0].sweep_txid_normal.as_ref().unwrap());
        let sp_script = keys.script_for(&secp, &[0x42u8; 32]).unwrap();
        let prevouts = vec![TxOut { value: bitcoin::Amount::from_sat(50_000), script_pubkey: sp_script.clone() }];
        let mut unsigned = tx.clone(); unsigned.input[0].witness = Witness::new();
        let mut cache = SighashCache::new(&unsigned);
        let sh = cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&sp_script.as_bytes()[2..34]).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(tx.input[0].witness.nth(0).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sh.to_byte_array()), &xonly).expect("the kit sweep's Schnorr signature verifies");
        // the high variant is a different transaction spending the same coin (a replacement)
        let hi: Transaction = bitcoin::consensus::deserialize(&hex::decode(kit[0].sweep_hex_high.as_ref().unwrap()).unwrap()).unwrap();
        assert_eq!((hi.input[0].previous_output, hi.output[0].value.to_sat()), (tx.input[0].previous_output, 46_000));
        // no SP coins → an empty kit leg
        assert!(sp_kit_sweeps(&root, &crate::tier2_wallet::Tier2View::default(), Network::Bitcoin, 7, (10, 40)).unwrap().is_empty());
    }

    #[test]
    fn sign_inputs_signs_a_silent_payment_coin_schnorr_and_a_p2wpkh_coin_ecdsa() {
        // v284: one transaction spending an SP coin (taproot key-path, Schnorr) and an ordinary
        // coin (BIP143 ECDSA); both signatures verify against the scripts the keys derive.
        use bitcoin::sighash::{Prevouts, TapSighashType};
        let root = crate::key::RootKey::from_mnemonic(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            Network::Bitcoin,
        ).unwrap();
        let secp = Secp256k1::new();
        let keys = crate::silent_payment::SpKeys::from_root(&root).unwrap();
        let t_k = [0x42u8; 32];
        let sp_script = keys.script_for(&secp, &t_k).unwrap();
        let sp = SpendableUtxo { chain: crate::tier2::CHAIN_SP, index: 0, txid: "11".repeat(32), vout: 1, value_sats: 40_000, sp_tweak: Some(t_k) };
        let plain = SpendableUtxo { chain: 0, index: 3, txid: "22".repeat(32), vout: 0, value_sats: 10_000, sp_tweak: None };
        let plain_sk = signing_secret(&root, &secp, 0, 3).unwrap();
        let plain_pk = bitcoin::PublicKey::new(plain_sk.public_key(&secp));
        let plain_script = ScriptBuf::new_p2wpkh(&bitcoin::CompressedPublicKey(plain_pk.inner).wpubkey_hash());
        let selected = vec![&sp, &plain];
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: selected.iter().map(|u| TxIn {
                previous_output: OutPoint { txid: Txid::from_str(&u.txid).unwrap(), vout: u.vout },
                script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new(),
            }).collect(),
            output: vec![TxOut { value: bitcoin::Amount::from_sat(49_000), script_pubkey: plain_script.clone() }],
        };
        let w = sign_inputs(&root, &secp, &tx, &selected).unwrap();
        assert_eq!(w.len(), 2);
        // the SP input: one 64-byte Schnorr signature, valid for the x-only key in its script
        assert_eq!(w[0].len(), 1);
        assert_eq!(w[0].nth(0).unwrap().len(), 64);
        let prevouts = vec![
            TxOut { value: bitcoin::Amount::from_sat(40_000), script_pubkey: sp_script.clone() },
            TxOut { value: bitcoin::Amount::from_sat(10_000), script_pubkey: plain_script.clone() },
        ];
        let mut cache = SighashCache::new(&tx);
        let sh = cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&sp_script.as_bytes()[2..34]).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(w[0].nth(0).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sh.to_byte_array()), &xonly).expect("the Schnorr signature verifies against P_k");
        // the ordinary input: DER signature + SIGHASH_ALL byte, then the compressed key
        assert_eq!(w[1].len(), 2);
        assert_eq!(w[1].nth(1).unwrap(), &plain_pk.to_bytes()[..]);
        let sh2 = cache.p2wpkh_signature_hash(1, &plain_script, bitcoin::Amount::from_sat(10_000), EcdsaSighashType::All).unwrap();
        let der = w[1].nth(0).unwrap();
        assert_eq!(*der.last().unwrap(), EcdsaSighashType::All as u8);
        let sig2 = bitcoin::secp256k1::ecdsa::Signature::from_der(&der[..der.len() - 1]).unwrap();
        secp.verify_ecdsa(&Message::from_digest(sh2.to_byte_array()), &sig2, &plain_pk.inner).expect("the ECDSA signature verifies");
        // and the spend key really is b_spend + t_k (even-y form): its x-only key is the script's
        let sk = keys.spend_secret(&secp, &t_k).unwrap();
        assert_eq!(sk.x_only_public_key(&secp).0, xonly);
    }
}
