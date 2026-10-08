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
    /// v298 (S52, DP #2): the broadcast transaction's raw bytes, hex — kept in the tx store for the drill-down;
    /// never sent to the page.
    #[serde(skip)]
    pub raw_hex: String,
    /// v305 (S54): what each recipient was paid, in output order (one entry for a one-recipient send).
    pub recipients: Vec<SentTo>,
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
/// v308 (S54, DP 2026-10-04 00:03 "Go."): what is left after the recipients and the fee — the change, or, under the
/// 294-sat output minimum (DUST_THRESHOLD_SATS: Bitcoin does not relay a smaller output), part of the fee. Returns
/// (fee paid, change output, leftover added to the fee). One rule for the builder (plan_send) and the quote (coin_quote).
pub(crate) fn settle_change(total_in: u64, paid: u64, fee: u64) -> (u64, u64, u64) {
    let left = total_in.saturating_sub(paid).saturating_sub(fee);
    if left < DUST_THRESHOLD_SATS { (fee.saturating_add(left), 0, left) } else { (fee, left, 0) }
}

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
    kit_sweeps_where(root_key, view, network, first_dest_index, rates_sat_vb, &|u| u.chain == crate::tier2::CHAIN_SP && is_signable(u))
}

/// v318 (S57, DP 2026-10-07 22:58 "Add the ability to sweep coin-by-coin to the Black start kit so everything comes back
/// to m/84. In the Black start kit the user can decide whether to sweep or not."): the same leg for the wallet's
/// taproot coins (both BIP86 branches — today the Mix's exits). Any BIP86 wallet on the 12 words finds these as they
/// are; the sweeps let one BIP84 wallet show everything. Each coin alone (never combined — a mixed coin beside another
/// links them), to its own fresh m/84 address; /recover offers each one, nothing moves unless it is tapped.
pub fn tr_kit_sweeps(
    root_key: &RootKey,
    view: &crate::tier2_wallet::Tier2View,
    network: Network,
    first_dest_index: u32,
    rates_sat_vb: (u64, u64),
) -> LijResult<Vec<SpKitSweep>> {
    kit_sweeps_where(root_key, view, network, first_dest_index, rates_sat_vb, &|u| crate::tier2::bip86_branch(u.chain).is_some())
}

/// v318: one pre-signed sweep per unspent coin `pick` takes (v291's rule, any key-path coin the signer knows).
fn kit_sweeps_where(
    root_key: &RootKey,
    view: &crate::tier2_wallet::Tier2View,
    network: Network,
    first_dest_index: u32,
    rates_sat_vb: (u64, u64),
    pick: &dyn Fn(&crate::tier2_wallet::OnchainUtxo) -> bool,
) -> LijResult<Vec<SpKitSweep>> {
    let secp = Secp256k1::new();
    let mut coins: Vec<&crate::tier2_wallet::OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| u.spent_height.is_none() && pick(u))
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
    pub(crate) chain: u32, // 0=receive, 1=change, 525=legacy, 352=silent payment (v284), 86/87=BIP86 /0 and /1 (v316/v317)
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
/// v316: a BIP86 coin (chains 86/87 — today only Mix coins) is NOT here yet, though sign_inputs signs it: whether the
/// automatic pick may put a mixed coin beside the wallet's other coins (which links them and undoes the mix) waits for
/// DP's postmix rule (CoinMarks::is_mix tells a Mix coin from a plain taproot one).
pub(crate) fn is_signable(u: &crate::tier2_wallet::OnchainUtxo) -> bool {
    u.chain == crate::tier2::CHAIN_RECEIVE
        || u.chain == crate::tier2::CHAIN_CHANGE
        || (u.chain == crate::tier2::CHAIN_SP && sp_tweak_of(u).is_some())
}

/// v284: an input's size in the fee estimate — a taproot key-path input (a silent-payment coin;
/// v316: a Mix coin) is 57.5 vB, a P2WPKH input 68.
pub(crate) fn input_vbytes(chain: u32) -> u64 {
    if chain == crate::tier2::CHAIN_SP || crate::tier2::bip86_branch(chain).is_some() { 58 } else { 68 }
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
    /// v308: the change OUTPUT the send would make — 0 when the leftover is under the dust floor (see folded_sats).
    pub change_sats: Option<u64>,
    /// v308 (S54, DP 2026-10-04 00:03): the fee the send pays for `spend` — exactly what goes out, any leftover under the
    /// dust floor included. `fee_sats` is NOT this when no coins are chosen: it is what every coin would need.
    pub send_fee_sats: Option<u64>,
    /// v308: the leftover too small to keep as change, added to the fee (0 = none).
    pub folded_sats: u64,
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
    let mut send_fee_sats: Option<u64> = None;
    let mut folded_sats = 0u64;
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
                let (paid_fee, change, folded) = settle_change(spend_sats, a, fee);   // v308: the builder's own rule
                change_sats = Some(change);
                send_fee_sats = Some(paid_fee);
                folded_sats = folded;
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
        send_fee_sats,
        folded_sats,
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
            // v316 (step 1b): a coin at a BIP86 address (a Mix coin) — the key-path secret and its P2TR script
            _ if crate::tier2::bip86_branch(u.chain).is_some() => {
                let (sk, spk) = crate::bip86::secret_and_script(root_key, crate::tier2::bip86_branch(u.chain).unwrap_or(0), u.index)?;
                keys.push((sk, spk, true));
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

/// v305 (S54, DP 2026-10-02 13:50 "Go ahead" — SEVERAL RECIPIENTS IN ONE SEND): one recipient — an address (or an sp1
/// silent-payment address) and an amount, or `None` = everything left after the other recipients and the fee ("Max",
/// on the LAST recipient only — DP's rule).
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Recipient {
    pub dest: String,
    #[serde(default)]
    pub amount_sats: Option<u64>,
}

/// v305: what a send paid each recipient, in output order (vout 0, 1, …; the change, if any, comes after them).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SentTo {
    pub dest: String,
    pub amount_sats: u64,
}

/// v305: the most recipients in one send.
pub const MAX_RECIPIENTS: usize = 20;

/// v305: the plan of a send — the coins, each recipient's amount, the fee and the change — made before any key is
/// touched. The quote and the builder share it, so the figures on the screen are the figures that go out.
struct Plan<'a> {
    dests: Vec<Dest>,
    selected: Vec<&'a SpendableUtxo>,
    amounts: Vec<u64>,
    /// Includes change too small to keep (folded in).
    fee_sats: u64,
    change_sats: u64,
    /// v308: that change too small to keep, added to the fee (0 = none).
    folded_sats: u64,
    total_in: u64,
}

fn plan_send<'a>(
    recipients: &[Recipient],
    network: Network,
    fee_rate_sat_per_kw: u32,
    spendable: &'a [SpendableUtxo],
    frozen: &std::collections::HashSet<(String, u32)>,
    pins: Option<&[(String, u32)]>,
) -> LijResult<Plan<'a>> {
    let n_dest = recipients.len();
    if n_dest == 0 {
        return Err(LijError::Node("add who you are paying".into()));
    }
    if n_dest > MAX_RECIPIENTS {
        return Err(LijError::Node(format!("one send pays at most {MAX_RECIPIENTS} recipients")));
    }
    let mut dests = Vec::with_capacity(n_dest);
    for (i, r) in recipients.iter().enumerate() {
        let d = parse_dest(&r.dest, network).map_err(|e| if n_dest > 1 {
            let m = match e { LijError::Node(m) => m, other => other.to_string() };
            LijError::Node(format!("recipient {}: {m}", i + 1))
        } else { e })?;
        dests.push(d);
        match r.amount_sats {
            None if i + 1 != n_dest => return Err(LijError::Node("only the last recipient can take everything left (Max)".into())),
            Some(0) => return Err(LijError::Node(if n_dest > 1 { format!("recipient {}: the amount must be greater than zero", i + 1) } else { "amount must be greater than zero".into() })),
            Some(a) if n_dest > 1 && a < DUST_THRESHOLD_SATS => return Err(LijError::Node(format!("recipient {}: {a} sats is below the {DUST_THRESHOLD_SATS}-sat minimum an output can carry", i + 1))),
            _ => {}
        }
    }
    let extra_vb: u64 = dests.iter().map(dest_extra_vbytes).sum();
    if spendable.is_empty() {
        return Err(LijError::Node(if frozen.is_empty() {
            "no spendable on-chain funds found".into()
        } else {
            "no spendable on-chain funds found — every coin is frozen".into()
        }));
    }
    // v282: chosen coins are EXACTLY the set the transaction spends (DP 2026-09-28: chosen = exact; a top-up is the
    // user's explicit "Fill the rest for me", never silent).
    let chosen: Option<Vec<&SpendableUtxo>> = match pins {
        Some(p) => Some(resolve_pins(spendable, frozen, p)?),
        None => None,
    };
    let fixed: u64 = recipients.iter().filter_map(|r| r.amount_sats).sum();
    let rest = recipients.last().map(|r| r.amount_sats.is_none()).unwrap_or(false);
    if rest {
        // everything left goes to the last recipient: every candidate (or the chosen set), no change output
        let selected: Vec<&SpendableUtxo> = match chosen { Some(c) => c, None => spendable.iter().collect() };
        let total_in: u64 = selected.iter().map(|u| u.value_sats).sum();
        let fee_sats = estimate_fee_inputs(&selected, n_dest, extra_vb, fee_rate_sat_per_kw);
        if total_in <= fixed + fee_sats + DUST_THRESHOLD_SATS {
            return Err(LijError::Node(if n_dest == 1 {
                format!("nothing left to send after the fee: {total_in} sats of coins, fee {fee_sats}")
            } else {
                format!("nothing left for the last recipient: the others take {fixed} sats and the fee {fee_sats} of {total_in}")
            }));
        }
        let mut amounts: Vec<u64> = recipients[..n_dest - 1].iter().filter_map(|r| r.amount_sats).collect();
        amounts.push(total_in - fixed - fee_sats);
        return Ok(Plan { dests, selected, amounts, fee_sats, change_sats: 0, folded_sats: 0, total_in });
    }
    // exact amounts: DP's pick rule (coin_select::pick) or the chosen set; change back to m/84
    let selected: Vec<&SpendableUtxo> = match chosen {
        Some(c) => {
            let total: u64 = c.iter().map(|u| u.value_sats).sum();
            let fee = estimate_fee_inputs(&c, n_dest + 1, extra_vb, fee_rate_sat_per_kw);   // v284: the chosen coins' real sizes — the quote's number
            if total < fixed.saturating_add(fee) {
                return Err(LijError::Node(format!(
                    "your chosen coins cover {total} sats; this send needs {} (amount {fixed} + fee {fee}) — add coins or lower the amount",
                    fixed.saturating_add(fee)
                )));
            }
            c
        }
        None => {
            let values: Vec<u64> = spendable.iter().map(|u| u.value_sats).collect();
            let picked = crate::coin_select::pick(&values, |n| fixed.saturating_add(estimate_fee_with(n, n_dest + 1, extra_vb, fee_rate_sat_per_kw)));
            match picked {
                Some(idx) => idx.into_iter().map(|i| &spendable[i]).collect(),
                None => {
                    let have: u64 = values.iter().sum();
                    let fee = estimate_fee_with(values.len(), n_dest + 1, extra_vb, fee_rate_sat_per_kw);
                    return Err(LijError::Node(format!(
                        "insufficient funds: have {have} sats, need {} (amount {fixed} + fee {fee}){}",
                        fixed + fee,
                        if frozen.is_empty() { "" } else { " — frozen coins are not counted" }
                    )));
                }
            }
        }
    };
    let total_in: u64 = selected.iter().map(|u| u.value_sats).sum();
    let fee_sats = estimate_fee_inputs(&selected, n_dest + 1, extra_vb, fee_rate_sat_per_kw);   // v284: real input sizes
    if total_in < fixed + fee_sats {
        return Err(LijError::Node(format!("insufficient funds: have {total_in} sats, need {} (amount {fixed} + fee {fee_sats})", fixed + fee_sats)));
    }
    let (fee_sats, change_sats, folded_sats) = settle_change(total_in, fixed, fee_sats);   // v308: too small to keep → the fee
    let amounts = recipients.iter().filter_map(|r| r.amount_sats).collect();
    Ok(Plan { dests, selected, amounts, fee_sats, change_sats, folded_sats, total_in })
}

/// v305: the silent-payment inputs of a selection (each coin's key and outpoint; a silent-payment coin counts as a
/// taproot input).
fn sp_inputs(root_key: &RootKey, secp: &Secp256k1<bitcoin::secp256k1::All>, selected: &[&SpendableUtxo]) -> LijResult<Vec<crate::silent_payment::SpInput>> {
    let mut inputs = Vec::with_capacity(selected.len());
    let mut sp_keys: Option<crate::silent_payment::SpKeys> = None;
    for u in selected {
        let (secret, taproot) = match u.sp_tweak {
            Some(t) if u.chain == crate::tier2::CHAIN_SP => {
                if sp_keys.is_none() { sp_keys = Some(crate::silent_payment::SpKeys::from_root(root_key)?); }
                (sp_keys.as_ref().unwrap().spend_secret(secp, &t)?, true)
            }
            _ if crate::tier2::bip86_branch(u.chain).is_some() => (crate::bip86::secret_and_script(root_key, crate::tier2::bip86_branch(u.chain).unwrap_or(0), u.index)?.0, true),   // v316
            _ => (signing_secret(root_key, secp, u.chain, u.index)?, false),
        };
        inputs.push(crate::silent_payment::SpInput {
            secret,
            outpoint: OutPoint { txid: Txid::from_str(&u.txid).map_err(|e| LijError::Node(format!("bad utxo txid {}: {e}", u.txid)))?, vout: u.vout },
            taproot,
        });
    }
    Ok(inputs)
}

/// v305: every recipient's output script for the inputs finally selected — the silent-payment ones derived together
/// (one group per scan key, k = 0, 1, … in recipient order), the others as given.
fn resolve_dest_scripts(dests: &[Dest], root_key: &RootKey, secp: &Secp256k1<bitcoin::secp256k1::All>, selected: &[&SpendableUtxo]) -> LijResult<Vec<ScriptBuf>> {
    let sp: Vec<crate::silent_payment::SpAddress> = dests.iter().filter_map(|d| match d { Dest::SilentPayment(a) => Some(a.clone()), _ => None }).collect();
    let mut derived = if sp.is_empty() { Vec::new() } else { crate::silent_payment::derive_output_scripts(secp, &sp_inputs(root_key, secp, selected)?, &sp)? }.into_iter();
    dests.iter().map(|d| match d {
        Dest::Script(spk) => Ok(spk.clone()),
        Dest::SilentPayment(_) => derived.next().ok_or_else(|| LijError::Node("silent payment: an output was not derived".into())),
    }).collect()
}

/// v305: the change script at m/84'/{coin}'/0'/1/`change_index` — rotated per send so change is not linked by reuse.
fn change_script(root_key: &RootKey, secp: &Secp256k1<bitcoin::secp256k1::All>, network: Network, change_index: u32) -> LijResult<ScriptBuf> {
    let change_xpriv = root_key.onchain_key()?   // m/84'/{coin}'/0'
        .derive_priv(
            secp,
            &DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(|e| LijError::Key(format!("{e}")))?,
                ChildNumber::from_normal_idx(change_index).map_err(|e| LijError::Key(format!("{e}")))?,
            ]),
        )
        .map_err(|e| LijError::Key(format!("change key derivation: {e}")))?;
    let change_pubkey = bitcoin::PublicKey::new(change_xpriv.private_key.public_key(secp));
    Ok(Address::p2wpkh(&bitcoin::CompressedPublicKey(change_pubkey.inner), network).script_pubkey())
}

/// v305: a built, signed send — not yet broadcast.
pub(crate) struct BuiltSend {
    pub(crate) tx: Transaction,
    pub(crate) paid: Vec<SentTo>,
    pub(crate) fee_sats: u64,
    pub(crate) change_sats: u64,
    pub(crate) spent_outpoints: Vec<(String, u32)>,
}

/// v305: THE one builder — every on-chain send (one recipient or several; an exact amount or Max on the last) is
/// planned by plan_send, its outputs derived (silent payments together), signed by the one signer. Outputs: the
/// recipients in order (vout 0 …), then the change. No network.
pub(crate) fn build_send_tx(
    root_key: &RootKey,
    network: Network,
    recipients: &[Recipient],
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
) -> LijResult<BuiltSend> {
    let secp = Secp256k1::new();
    let frozen = marks.frozen_set();
    let spendable = gather_spendable(view, pending, &frozen);
    let plan = plan_send(recipients, network, fee_rate_sat_per_kw, &spendable, &frozen, pins)?;
    let scripts = resolve_dest_scripts(&plan.dests, root_key, &secp, &plan.selected)?;
    let mut outputs: Vec<TxOut> = scripts.into_iter().zip(plan.amounts.iter()).map(|(spk, a)| TxOut { value: bitcoin::Amount::from_sat(*a), script_pubkey: spk }).collect();
    if plan.change_sats > 0 {
        outputs.push(TxOut { value: bitcoin::Amount::from_sat(plan.change_sats), script_pubkey: change_script(root_key, &secp, network, change_index)? });
    }
    let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(plan.selected.len());
    for u in &plan.selected {
        tx_inputs.push(TxIn {
            previous_output: OutPoint { txid: Txid::from_str(&u.txid).map_err(|e| LijError::Node(format!("bad utxo txid {}: {e}", u.txid)))?, vout: u.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }
    let mut tx = Transaction { version: bitcoin::transaction::Version::TWO, lock_time: LockTime::ZERO, input: tx_inputs, output: outputs };
    // P2WPKH (BIP143, ECDSA) as ever; v284: a silent-payment coin is a taproot key-path input (Schnorr, BIP-341)
    let witnesses: Vec<Witness> = sign_inputs(root_key, &secp, &tx, &plan.selected)?;
    for (i, w) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = w;
    }
    debug_assert_eq!(plan.total_in, plan.amounts.iter().sum::<u64>() + plan.fee_sats + plan.change_sats);
    Ok(BuiltSend {
        paid: recipients.iter().zip(plan.amounts.iter()).map(|(r, a)| SentTo { dest: r.dest.trim().to_string(), amount_sats: *a }).collect(),
        fee_sats: plan.fee_sats,
        change_sats: plan.change_sats,
        spent_outpoints: plan.selected.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
        tx,
    })
}

/// v305: build, sign and broadcast a send to one or several recipients. Must run OUTSIDE any wallet lock.
pub async fn build_and_send_multi(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
    recipients: &[Recipient],
    fee_rate_sat_per_kw: u32,
    change_index: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
) -> LijResult<SendResult> {
    let b = build_send_tx(root_key, network, recipients, fee_rate_sat_per_kw, change_index, view, pending, marks, pins)?;
    let raw = serialize(&b.tx);
    independent.broadcast_raw_tx(&raw).await?;
    let txid = b.tx.compute_txid().to_string();
    let amount_sats: u64 = b.paid.iter().map(|p| p.amount_sats).sum();
    let n_in = b.tx.input.len();
    log::info!(
        "onchain send: broadcast {txid} ({amount_sats} sats to {} recipient(s){}, fee {}, {n_in} input(s), change {})",
        b.paid.len(),
        if b.paid.len() == 1 { format!(" — {}", b.paid[0].dest) } else { String::new() },
        b.fee_sats,
        b.change_sats
    );
    let change_outpoint = if b.change_sats > 0 { Some((txid.clone(), b.paid.len() as u32)) } else { None };   // after the recipients
    Ok(SendResult {
        txid,
        amount_sats,
        fee_sats: b.fee_sats,
        inputs: n_in,
        change_sats: b.change_sats,
        spent_outpoints: b.spent_outpoints,
        change_outpoint,
        change_index,
        raw_hex: hex::encode(&raw),   // v298
        recipients: b.paid,
    })
}

/// v281: the builder behind build_and_send (an exact amount, change to m/84) and build_and_send_all (everything, one
/// output) — since v305 the one-recipient case of build_and_send_multi.
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
    let r = Recipient { dest: dest.to_string(), amount_sats: match what { SendAmount::Exact(a) => Some(a), SendAmount::All => None } };
    build_and_send_multi(root_key, independent, network, std::slice::from_ref(&r), fee_rate_sat_per_kw, change_index, view, pending, marks, pins).await
}

/// v305: the quote for a send to several recipients (or one) — the same plan the builder makes. With Max on the last
/// recipient, `amounts`' last entry is what it gets. `problem` carries the builder's own refusal in plain words.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MultiQuote {
    pub amounts: Vec<u64>,
    pub total_sats: u64,
    pub fee_sats: u64,
    pub change_sats: u64,
    /// v308: the leftover too small to keep as change, inside fee_sats (0 = none).
    pub folded_sats: u64,
    pub inputs: usize,
    pub spend: Vec<(String, u32)>,
    pub sat_per_vb: u64,
    pub problem: Option<String>,
}

impl MultiQuote {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self).map_err(|e| LijError::Storage(format!("multi quote serialize: {e}")))
    }
}

pub fn multi_quote(
    recipients: &[Recipient],
    network: Network,
    fee_rate_sat_per_kw: u32,
    view: &crate::tier2_wallet::Tier2View,
    pending: &[crate::tier2_wallet::PendingTx],
    marks: &crate::tier2_wallet::CoinMarks,
    pins: Option<&[(String, u32)]>,
) -> MultiQuote {
    let frozen = marks.frozen_set();
    let spendable = gather_spendable(view, pending, &frozen);
    let sat_per_vb = (((fee_rate_sat_per_kw as u64) + 249) / 250).max(1);
    match plan_send(recipients, network, fee_rate_sat_per_kw, &spendable, &frozen, pins) {
        Ok(p) => MultiQuote {
            total_sats: p.amounts.iter().sum(),
            amounts: p.amounts,
            fee_sats: p.fee_sats,
            change_sats: p.change_sats,
            folded_sats: p.folded_sats,
            inputs: p.selected.len(),
            spend: p.selected.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
            sat_per_vb,
            problem: None,
        },
        Err(e) => MultiQuote { sat_per_vb, problem: Some(e.to_string()), ..Default::default() },
    }
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
    // v305: every recipient the send paid (one for a send recorded before v305 — its dest_addr and dest_sats)
    let dests: Vec<(String, u64)> = if !prev.dests.is_empty() {
        prev.dests.clone()
    } else {
        let dest = prev.dest_addr.clone().ok_or_else(|| {
            LijError::Node("this send predates fee-bump support (no destination on record)".into())
        })?;
        let amount = prev.dest_sats.ok_or_else(|| {
            LijError::Node("this send predates fee-bump support (no amount on record)".into())
        })?;
        vec![(dest, amount)]
    };
    let amount_sats: u64 = dests.iter().map(|d| d.1).sum();
    let n_dest = dests.len();
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

    let mut dests_parsed: Vec<Dest> = Vec::with_capacity(n_dest);
    for (d, _) in &dests {
        dests_parsed.push(parse_dest(d, network).map_err(|e| LijError::Node(format!("recorded destination unusable: {e}")))?);
    }
    let extra_vb: u64 = dests_parsed.iter().map(dest_extra_vbytes).sum();
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
    let vsize = 11 + selected_refs.iter().map(|u| input_vbytes(u.chain)).sum::<u64>() + 31 * (n_dest as u64 + 1) + extra_vb;
    let mut new_fee = estimate_fee_inputs(&selected_refs, n_dest + 1, extra_vb, new_fee_rate_sat_per_kw);
    // v240: the same inputs re-derive the same silent-payment outputs — RBF keeps every output (v305: every recipient,
    // in the same order, so a silent payment's k is the same too).
    let dest_spks = resolve_dest_scripts(&dests_parsed, root_key, &secp, &selected_refs)?;
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

    let mut outputs: Vec<TxOut> = dest_spks.into_iter().zip(dests.iter()).map(|(spk, (_, a))| TxOut {
        value: bitcoin::Amount::from_sat(*a),
        script_pubkey: spk,
    }).collect();
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

    let change_outpoint = if change_sats > 0 { Some((txid.clone(), n_dest as u32)) } else { None };   // v305: after the recipients
    Ok(SendResult {
        txid,
        amount_sats,
        fee_sats: new_fee,
        inputs: n_in,
        change_sats,
        spent_outpoints: prev.spent_outpoints.clone(),
        change_outpoint,
        change_index: prev.change_index,
        raw_hex: hex::encode(&raw),   // v298
        recipients: dests.iter().map(|(d, a)| SentTo { dest: d.clone(), amount_sats: *a }).collect(),   // v305
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
        OnchainUtxo { chain, index: 0, txid: txid.into(), vout, value_sats: value, height: 900_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None }
    }

    // ── v305 (S54): several recipients in one send ──
    const SP_EX: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const BC1_EX: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    fn root305() -> RootKey {
        RootKey::from_mnemonic(&"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(), Network::Bitcoin).unwrap()
    }
    /// the BIP example address's own keys (the first receiving vector) — the receiver of SP_EX
    fn sp_ex_keys() -> crate::silent_payment::SpKeys {
        let secp = Secp256k1::new();
        let scan = bitcoin::secp256k1::SecretKey::from_slice(&hex::decode("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c").unwrap()).unwrap();
        let spend = bitcoin::secp256k1::SecretKey::from_slice(&hex::decode("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3").unwrap()).unwrap();
        let k = crate::silent_payment::SpKeys { scan, spend, scan_pub: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &scan), spend_pub: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &spend), network: Network::Bitcoin };
        assert_eq!(k.address(), SP_EX);
        k
    }
    fn view305() -> Tier2View {
        let mut view = Tier2View::default();
        let mut a = coin(&"aa".repeat(32), 0, 0, 100_000); a.index = 1;
        let mut b = coin(&"bb".repeat(32), 1, 0, 80_000); b.index = 2;
        view.utxos = vec![a, b];
        view
    }
    fn rcpt(dest: &str, a: Option<u64>) -> Recipient { Recipient { dest: dest.into(), amount_sats: a } }
    /// what the receiver of SP_EX finds in a built transaction, from the box's tweak of its inputs
    fn sp_ex_finds(tx: &Transaction, root: &RootKey) -> Vec<(u32, u64)> {
        let secp = Secp256k1::new();
        let keys: Vec<bitcoin::secp256k1::PublicKey> = tx.input.iter().map(|i| {
            let idx = if i.previous_output.txid.to_string() == "aa".repeat(32) { 1 } else { 2 };
            signing_secret(root, &secp, 0, idx).unwrap().public_key(&secp)
        }).collect();
        let ops: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        let tweak = crate::silent_payment::tweak_from_inputs(&secp, &keys, &ops).unwrap();
        let outs: Vec<(u32, [u8; 32], u64)> = tx.output.iter().enumerate().filter(|(_, o)| o.script_pubkey.is_p2tr()).map(|(i, o)| {
            let mut k = [0u8; 32]; k.copy_from_slice(&o.script_pubkey.as_bytes()[2..34]); (i as u32, k, o.value.to_sat())
        }).collect();
        let mut f: Vec<(u32, u64)> = sp_ex_keys().find_in_outputs(&secp, &tweak, tx.compute_txid(), &outs, &[]).iter().map(|f| (f.vout, f.value_sats)).collect();
        f.sort();
        f
    }

    #[test]
    fn v305_two_recipients_exact_amounts_change_last_and_the_silent_payment_found() {
        let root = root305();
        let view = view305();
        let rate = 500;   // 2 sat/vB
        let rs = vec![rcpt(BC1_EX, Some(50_000)), rcpt(SP_EX, Some(30_000))];
        let b = build_send_tx(&root, Network::Bitcoin, &rs, rate, 7, &view, &[], &CoinMarks::default(), None).unwrap();
        // DP's pick: the smallest single coin covering 80,000 + the fee for three outputs (one of them taproot)
        assert_eq!(b.spent_outpoints, vec![("aa".repeat(32), 0)]);
        let fee = (11 + 68 + 31 * 3 + 12) * 2;
        assert_eq!((b.fee_sats, b.change_sats), (fee, 100_000 - 80_000 - fee));
        assert_eq!(b.tx.output.len(), 3);
        assert_eq!(b.tx.output[0].script_pubkey, Address::from_str(BC1_EX).unwrap().assume_checked().script_pubkey());
        assert_eq!(b.tx.output[0].value.to_sat(), 50_000);
        assert!(b.tx.output[1].script_pubkey.is_p2tr());
        assert_eq!(b.tx.output[1].value.to_sat(), 30_000);
        assert_eq!(b.tx.output[2].value.to_sat(), b.change_sats, "change after the recipients");
        assert_eq!(b.paid, vec![SentTo { dest: BC1_EX.into(), amount_sats: 50_000 }, SentTo { dest: SP_EX.into(), amount_sats: 30_000 }]);
        assert_eq!(sp_ex_finds(&b.tx, &root), vec![(1, 30_000)], "the silent-payment recipient finds its output");
        // the quote is the same plan
        let q = multi_quote(&rs, Network::Bitcoin, rate, &view, &[], &CoinMarks::default(), None);
        assert_eq!((q.amounts.clone(), q.total_sats, q.fee_sats, q.change_sats, q.inputs, q.problem.clone()), (vec![50_000, 30_000], 80_000, fee, b.change_sats, 1, None));
    }

    #[test]
    fn v305_two_payments_to_one_silent_payment_wallet_are_k0_and_k1_and_both_found() {
        let root = root305();
        let b = build_send_tx(&root, Network::Bitcoin, &[rcpt(SP_EX, Some(10_000)), rcpt(SP_EX, Some(20_000))], 500, 7, &view305(), &[], &CoinMarks::default(), None).unwrap();
        assert_ne!(b.tx.output[0].script_pubkey, b.tx.output[1].script_pubkey, "two distinct one-time outputs");
        assert_eq!(sp_ex_finds(&b.tx, &root), vec![(0, 10_000), (1, 20_000)]);
    }

    #[test]
    fn v305_max_on_the_last_recipient_takes_what_is_left_with_no_change() {
        let root = root305();
        let view = view305();
        let rs = vec![rcpt(BC1_EX, Some(50_000)), rcpt(SP_EX, None)];
        let b = build_send_tx(&root, Network::Bitcoin, &rs, 500, 7, &view, &[], &CoinMarks::default(), None).unwrap();
        let fee = (11 + 68 * 2 + 31 * 2 + 12) * 2;
        assert_eq!((b.spent_outpoints.len(), b.fee_sats, b.change_sats, b.tx.output.len()), (2, fee, 0, 2), "every coin, no change output");
        assert_eq!(b.paid[1].amount_sats, 180_000 - 50_000 - fee);
        assert_eq!(sp_ex_finds(&b.tx, &root), vec![(1, 180_000 - 50_000 - fee)]);
        let q = multi_quote(&rs, Network::Bitcoin, 500, &view, &[], &CoinMarks::default(), None);
        assert_eq!(q.amounts, vec![50_000, 180_000 - 50_000 - fee], "the quote shows the Max the send pays");
        // chosen coins: Max takes exactly those
        let pins = vec![("bb".repeat(32), 1u32)];
        let b2 = build_send_tx(&root, Network::Bitcoin, &[rcpt(BC1_EX, Some(10_000)), rcpt(SP_EX, None)], 500, 7, &view, &[], &CoinMarks::default(), Some(&pins)).unwrap();
        assert_eq!((b2.spent_outpoints.clone(), b2.paid[1].amount_sats), (pins.clone(), 80_000 - 10_000 - (11 + 68 + 31 * 2 + 12) * 2));
    }

    #[test]
    fn v305_refusals_in_plain_words() {
        let root = root305();
        let view = view305();
        let m = CoinMarks::default();
        let err = |rs: Vec<Recipient>| build_send_tx(&root, Network::Bitcoin, &rs, 500, 7, &view, &[], &m, None).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err(vec![rcpt(SP_EX, None), rcpt(BC1_EX, Some(1_000))]).contains("only the last recipient"));
        assert!(err(vec![rcpt(BC1_EX, Some(1_000)), rcpt(SP_EX, Some(0))]).contains("recipient 2: the amount must be greater than zero"));
        assert!(err(vec![rcpt(BC1_EX, Some(1_000)), rcpt(SP_EX, Some(200))]).contains("recipient 2: 200 sats is below"));
        let bad = err(vec![rcpt(BC1_EX, Some(1_000)), rcpt("bc1qnotanaddress", Some(1_000))]);
        assert!(bad.starts_with("Node error: recipient 2: invalid address"), "{bad}");
        assert!(err(vec![]).contains("add who you are paying"));
        assert!(err((0..21).map(|_| rcpt(BC1_EX, Some(1_000))).collect()).contains("at most 20"));
        assert!(err(vec![rcpt(BC1_EX, Some(100_000)), rcpt(SP_EX, Some(90_000))]).contains("insufficient funds"));
        assert!(err(vec![rcpt(BC1_EX, Some(179_700)), rcpt(SP_EX, None)]).contains("nothing left for the last recipient"));
        // one recipient keeps its old words
        assert_eq!(err(vec![rcpt(BC1_EX, Some(0))]), "Node error: amount must be greater than zero");
    }

    #[test]
    fn v305_one_recipient_is_the_send_it_always_was() {
        let root = root305();
        let view = view305();
        let b = build_send_tx(&root, Network::Bitcoin, &[rcpt(BC1_EX, Some(50_000))], 500, 7, &view, &[], &CoinMarks::default(), None).unwrap();
        let fee = (11 + 68 + 31 * 2) * 2;
        assert_eq!((b.tx.output.len(), b.tx.output[0].value.to_sat(), b.fee_sats, b.change_sats), (2, 50_000, fee, 80_000 - 50_000 - fee), "dest at vout 0, change at vout 1, the two-output fee");
        let all = build_send_tx(&root, Network::Bitcoin, &[rcpt(BC1_EX, None)], 500, 7, &view, &[], &CoinMarks::default(), None).unwrap();
        let fee1 = (11 + 68 * 2 + 31) * 2;
        assert_eq!((all.tx.output.len(), all.paid[0].amount_sats, all.fee_sats), (1, 180_000 - fee1, fee1));
        assert_eq!(max_sendable(BC1_EX, Network::Bitcoin, 500, &view, &[], &CoinMarks::default()).max_sats, all.paid[0].amount_sats, "Max on the screen = Max sent");
    }

    #[test]
    fn v305_the_bump_rebuilds_every_recipient_output_in_order() {
        // the bump re-derives the outputs from the SAME inputs and the recorded recipients, in order — so every
        // silent payment keeps its k and its output; this is the derivation the bump calls
        let root = root305();
        let secp = Secp256k1::new();
        let rs = vec![rcpt(SP_EX, Some(10_000)), rcpt(BC1_EX, Some(20_000)), rcpt(SP_EX, Some(30_000))];
        let b = build_send_tx(&root, Network::Bitcoin, &rs, 500, 7, &view305(), &[], &CoinMarks::default(), None).unwrap();
        let view = view305();
        let frozen = std::collections::HashSet::new();
        let sp = gather_spendable(&view, &[], &frozen);
        let selected: Vec<&SpendableUtxo> = sp.iter().filter(|u| b.spent_outpoints.contains(&(u.txid.clone(), u.vout))).collect();
        let dests: Vec<Dest> = rs.iter().map(|r| parse_dest(&r.dest, Network::Bitcoin).unwrap()).collect();
        let again = resolve_dest_scripts(&dests, &root, &secp, &selected).unwrap();
        assert_eq!(again, b.tx.output[..3].iter().map(|o| o.script_pubkey.clone()).collect::<Vec<_>>());
        assert_eq!(sp_ex_finds(&b.tx, &root), vec![(0, 10_000), (2, 30_000)]);
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
        // 4,600: change 118 < dust → folded into the fee, not a coin → not tiny (v308: no change output; the fee carries it)
        let q = coin_quote("", Network::Bitcoin, kw, &view, &[], &marks, None, Some(4_600), false);
        assert_eq!((q.change_sats, q.folded_sats, q.send_fee_sats, q.tiny_change), (Some(0), 118, Some(282 + 118), false));
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

    /// v308 (S54, DP 2026-10-04 00:03): DP's send 1fffda67… replayed — coins 1,501 and 5,555 and 62,015, 1,002 to an address
    /// at 2 sat/vB. The pick is the 1,501 coin (1,002 + 282 = 1,284 covers); 217 is left, under 294 → the fee: 499, no
    /// change. The quote says exactly that, and the builder pays exactly that. Before v308 the quote's only fee was what
    /// EVERY coin would need.
    #[test]
    fn v308_the_quote_shows_the_fee_the_send_pays_and_the_leftover_it_adds() {
        let root = root305();
        let mut view = Tier2View::default();
        let mut a = coin(&"a1".repeat(32), 0, 0, 1_501); a.index = 1;
        let mut b = coin(&"b2".repeat(32), 0, 0, 5_555); b.index = 2;
        let mut c = coin(&"c3".repeat(32), 1, 0, 62_015); c.index = 3;
        view.utxos = vec![a, b, c];
        let kw = 2 * 250;
        let marks = CoinMarks::default();
        let q = coin_quote(BC1_EX, Network::Bitcoin, kw, &view, &[], &marks, None, Some(1_002), false);
        assert_eq!(q.spend, vec![("a1".repeat(32), 0u32)], "the smallest coin that covers");
        assert_eq!((q.send_fee_sats, q.folded_sats, q.change_sats), (Some(499), 217, Some(0)));
        assert_eq!(q.fee_sats, Some((11 + 68 * 3 + 31 * 2) * 2), "fee_sats keeps its meaning: every coin, two outputs");
        assert!(!q.tiny_change);
        let built = build_send_tx(&root, Network::Bitcoin, &[rcpt(BC1_EX, Some(1_002))], kw, 7, &view, &[], &marks, None).unwrap();
        assert_eq!((built.fee_sats, built.change_sats, built.tx.output.len()), (499, 0, 1), "what goes out is what the quote said");
        // DP's second send 32dd5e31…: the 5,555 coin, change kept, the fee exactly 282, nothing folded
        let q = coin_quote(BC1_EX, Network::Bitcoin, kw, &view, &[], &marks, None, Some(3_519), false);
        assert_eq!((q.spend_sats, q.send_fee_sats, q.folded_sats, q.change_sats), (5_555, Some(282), 0, Some(5_555 - 3_519 - 282)));
        let built = build_send_tx(&root, Network::Bitcoin, &[rcpt(BC1_EX, Some(3_519))], kw, 7, &view, &[], &marks, None).unwrap();
        assert_eq!((built.fee_sats, built.change_sats), (282, 1_754));
        // chosen coins: the same rule — the 1,501 coin chosen for 1,100 leaves 119 → the fee 401
        let pins = vec![("a1".repeat(32), 0u32)];
        let q = coin_quote(BC1_EX, Network::Bitcoin, kw, &view, &[], &marks, Some(&pins), Some(1_100), false);
        assert_eq!((q.send_fee_sats, q.folded_sats, q.change_sats), (Some(401), 119, Some(0)));
        // no amount: nothing to settle
        let q = coin_quote(BC1_EX, Network::Bitcoin, kw, &view, &[], &marks, None, None, false);
        assert_eq!((q.send_fee_sats, q.folded_sats), (None, 0));
    }

    #[test]
    fn v308_the_several_recipients_quote_names_the_leftover_too() {
        let mut view = Tier2View::default();
        let mut a = coin(&"a1".repeat(32), 0, 0, 2_000); a.index = 1;
        view.utxos = vec![a];
        let kw = 2 * 250;
        // 700 + 600 = 1,300; fee for 1 in, 3 out = (11 + 68 + 93) × 2 = 344; left 356 → kept as change
        let q = multi_quote(&[rcpt(BC1_EX, Some(700)), rcpt(BC1_EX, Some(600))], Network::Bitcoin, kw, &view, &[], &CoinMarks::default(), None);
        assert_eq!((q.fee_sats, q.change_sats, q.folded_sats), (344, 356, 0));
        // 800 + 600 = 1,400; left 256 → the fee: 600, no change
        let q = multi_quote(&[rcpt(BC1_EX, Some(800)), rcpt(BC1_EX, Some(600))], Network::Bitcoin, kw, &view, &[], &CoinMarks::default(), None);
        assert_eq!((q.fee_sats, q.change_sats, q.folded_sats), (600, 0, 256));
        assert_eq!(q.total_sats + q.fee_sats, 2_000);
    }

    #[test]
    fn v308_settle_change_is_one_rule() {
        assert_eq!(settle_change(1_501, 1_002, 282), (499, 0, 217));
        assert_eq!(settle_change(5_555, 3_519, 282), (282, 1_754, 0));
        assert_eq!(settle_change(1_578, 1_002, 282), (282, 294, 0), "294 itself is kept");
        assert_eq!(settle_change(1_577, 1_002, 282), (575, 0, 293));
        assert_eq!(settle_change(1_284, 1_002, 282), (282, 0, 0), "nothing left, nothing folded");
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
            broadcast_seen: false, raw_tx_hex: None, dest_addr: None, dest_sats: None, fee_sats: None, fee_rate_sat_per_kw: None, dests: Vec::new(),
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
        let mk = |txid: &str, vout: u32, sats: u64, t: u8| crate::tier2_wallet::OnchainUtxo { sp_tweak: Some(hex::encode([t; 32])), chain: crate::tier2::CHAIN_SP, index: 0, txid: txid.to_string(), vout, value_sats: sats, height: 900_000, spent_height: None, spent_txid: None, sp_label: None };
        view.utxos = vec![mk(&"bb".repeat(32), 0, 1_500, 0x55), mk(&"aa".repeat(32), 1, 50_000, 0x42)];
        // a spent SP coin and an m/84 coin are not in the kit
        let mut spent = mk(&"cc".repeat(32), 0, 9_000, 0x66); spent.spent_height = Some(900_001);
        view.utxos.push(spent);
        view.utxos.push(crate::tier2_wallet::OnchainUtxo { sp_tweak: None, chain: 0, index: 2, txid: "dd".repeat(32), vout: 0, value_sats: 70_000, height: 1, spent_height: None, spent_txid: None, sp_label: None });
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
        // v318: and the taproot leg takes none of these coins
        assert!(tr_kit_sweeps(&root, &view, Network::Bitcoin, 9, (10, 40)).unwrap().is_empty());
    }

    #[test]
    fn v318_the_kit_sweeps_each_taproot_coin_alone_to_its_own_bip84_address() {
        use bitcoin::sighash::{Prevouts, TapSighashType};
        let root = crate::key::RootKey::from_mnemonic(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            Network::Bitcoin,
        ).unwrap();
        let secp = Secp256k1::new();
        let mk = |txid: &str, chain: u32, index: u32, sats: u64| crate::tier2_wallet::OnchainUtxo { sp_tweak: None, chain, index, txid: txid.to_string(), vout: 0, value_sats: sats, height: 900_000, spent_height: None, spent_txid: None, sp_label: None };
        let mut view = crate::tier2_wallet::Tier2View::default();
        view.utxos = vec![
            mk(&"bb".repeat(32), crate::tier2::CHAIN_BIP86_INTERNAL, 0, 100_000),   // BIP86 change 0: bc1p3qkhfews…
            mk(&"aa".repeat(32), crate::tier2::CHAIN_BIP86, 1, 50_000),             // BIP86 receive 1: bc1p4qhjn9…
            mk(&"cc".repeat(32), 0, 2, 70_000),                                     // an m/84 coin: not in this leg
        ];
        let mut spent = mk(&"dd".repeat(32), crate::tier2::CHAIN_BIP86, 2, 9_000); spent.spent_height = Some(900_001);
        view.utxos.push(spent);
        let kit = tr_kit_sweeps(&root, &view, Network::Bitcoin, 12, (10, 40)).unwrap();
        assert_eq!(kit.iter().map(|k| (k.txid.clone(), k.destination_index)).collect::<Vec<_>>(), vec![("aa".repeat(32), 12), ("bb".repeat(32), 13)]);
        // one input, one output, to the m/84 receive address at its index; the 100 vB rule as the silent-payment leg
        let want_dest = |i: u32| {
            let sk = signing_secret(&root, &secp, 0, i).unwrap();
            Address::p2wpkh(&bitcoin::CompressedPublicKey(sk.public_key(&secp)), Network::Bitcoin).to_string()
        };
        assert_eq!((kit[0].destination.clone(), kit[1].destination.clone()), (want_dest(12), want_dest(13)));
        assert_eq!((kit[0].sweep_fee_normal, kit[0].sweep_fee_high), (Some(1_000), Some(4_000)));
        for (k, spk_addr, sats) in [(&kit[0], "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", 50_000u64), (&kit[1], "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", 100_000)] {
            let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(k.sweep_hex_normal.as_ref().unwrap()).unwrap()).unwrap();
            assert_eq!((tx.input.len(), tx.output.len(), tx.output[0].value.to_sat()), (1, 1, sats - 1_000));
            let spk = Address::from_str(spk_addr).unwrap().assume_checked().script_pubkey();
            let prevouts = vec![TxOut { value: bitcoin::Amount::from_sat(sats), script_pubkey: spk.clone() }];
            let mut unsigned = tx.clone(); unsigned.input[0].witness = Witness::new();
            let mut cache = SighashCache::new(&unsigned);
            let sh = cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
            let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(tx.input[0].witness.nth(0).unwrap()).unwrap();
            secp.verify_schnorr(&sig, &Message::from_digest(sh.to_byte_array()), &xonly).expect("the taproot sweep verifies against the BIP86 output key");
        }
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

    #[test]
    fn v316_sign_inputs_signs_a_mix_coin_on_the_bip86_key_path() {
        // v316 (step 1b): a Mix coin at m/86'/0'/0'/0/1 (BIP86's own vector address) beside an ordinary m/84 coin;
        // the Schnorr signature verifies against the address's output key, with every prevout committed.
        use bitcoin::sighash::{Prevouts, TapSighashType};
        let root = crate::key::RootKey::from_mnemonic(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            Network::Bitcoin,
        ).unwrap();
        let secp = Secp256k1::new();
        let mix_script = Address::from_str("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh").unwrap().assume_checked().script_pubkey();
        let mix = SpendableUtxo { chain: crate::tier2::CHAIN_BIP86, index: 1, txid: "33".repeat(32), vout: 2, value_sats: 100_000, sp_tweak: None };
        let plain = SpendableUtxo { chain: 0, index: 3, txid: "22".repeat(32), vout: 0, value_sats: 10_000, sp_tweak: None };
        let plain_sk = signing_secret(&root, &secp, 0, 3).unwrap();
        let plain_pk = bitcoin::PublicKey::new(plain_sk.public_key(&secp));
        let plain_script = ScriptBuf::new_p2wpkh(&bitcoin::CompressedPublicKey(plain_pk.inner).wpubkey_hash());
        let selected = vec![&plain, &mix];
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: selected.iter().map(|u| TxIn {
                previous_output: OutPoint { txid: Txid::from_str(&u.txid).unwrap(), vout: u.vout },
                script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new(),
            }).collect(),
            output: vec![TxOut { value: bitcoin::Amount::from_sat(109_000), script_pubkey: plain_script.clone() }],
        };
        let w = sign_inputs(&root, &secp, &tx, &selected).unwrap();
        assert_eq!((w[0].len(), w[1].len()), (2, 1), "P2WPKH: signature + key; the Mix coin: one Schnorr signature");
        assert_eq!(w[1].nth(0).unwrap().len(), 64, "SIGHASH_DEFAULT: no type byte");
        let prevouts = vec![
            TxOut { value: bitcoin::Amount::from_sat(10_000), script_pubkey: plain_script.clone() },
            TxOut { value: bitcoin::Amount::from_sat(100_000), script_pubkey: mix_script.clone() },
        ];
        let mut cache = SighashCache::new(&tx);
        let sh = cache.taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&mix_script.as_bytes()[2..34]).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(w[1].nth(0).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sh.to_byte_array()), &xonly).expect("the Mix coin's signature verifies against the BIP86 output key");
        // its size in every fee figure is the taproot input's
        assert_eq!(input_vbytes(crate::tier2::CHAIN_BIP86), 58);
        // and toward a silent-payment address it counts as a taproot input whose key is the output key
        let ins = sp_inputs(&root, &secp, &[&mix]).unwrap();
        assert!(ins[0].taproot);
        assert_eq!(ins[0].secret.x_only_public_key(&secp).0, xonly);
    }

    #[test]
    fn v316_a_mix_coin_is_not_in_the_automatic_pick_until_dps_rule() {
        let mut view = Tier2View::default();
        view.utxos = vec![coin("aa", 0, 0, 50_000), coin("bb", 0, crate::tier2::CHAIN_BIP86, 100_000)];
        assert!(!is_signable(&view.utxos[1]), "held: a mixed coin beside the others links them");
        let got = gather_spendable(&view, &[], &std::collections::HashSet::new());
        assert_eq!(got.iter().map(|u| u.txid.as_str()).collect::<Vec<_>>(), vec!["aa"]);
        let mut marks = crate::tier2_wallet::CoinMarks::default();
        marks.mix_exits.insert(0);
        assert_eq!(crate::tier2_wallet::coin_tag(&view, &marks, &view.utxos[1]), "mix");
    }
}
