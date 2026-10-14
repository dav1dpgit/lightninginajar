//! S10 (review r1 §5, finding 22): our own re-derivation of a LiJ pool's transactions — the funding transaction and
//! every exit — from the registrations and the payouts, written from the NIP's text ("Amounts", "Transactions",
//! "Keys"), not through joinstr's builder. It covers the Phase 1 options only (`caps::phase1_pool`): one denomination,
//! a chain, equal fee split, one fee rate, no anchor, the default exit plan. The phone compares joinstr's build with
//! this before it signs anything (`checks::same_as_rederived`), so a bug in the builder no longer passes its own check.
//!
//! Keys: BIP-327 KeySort + KeyAgg (the musig2 crate), BIP-328's synthetic xpub, the BIP-32 children 0 and i, the BIP-86
//! tweak — through the bitcoin crate's BIP-32 and taproot code, not joinstr's keys.rs.

use anyhow::{bail, ensure, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::consensus::serialize;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, NetworkKind, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use super::tagged;

/// BIP-328's chain code for the synthetic xpub of an aggregate key.
const BIP328_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76, 0x2d, 0x32, 0xcb,
    0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];
const SEQUENCE: Sequence = Sequence(0xffff_fffd);
const MAX_LOCKTIME_LAG: u32 = 100;

/// One member's input registration, as the NIP has it.
#[derive(Clone, Debug)]
pub struct Member {
    pub musig: [u8; 33],
    pub inputs: Vec<(OutPoint, TxOut)>,
    pub change: Option<TxOut>,
    pub height: u32,
}

/// The pool, as re-derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rederived {
    pub funding: Transaction,
    pub pool_vout: u32,
    /// The exits in signing order (a chain: exit k spends pool output k−1).
    pub exits: Vec<Transaction>,
    /// pool_0 … pool_(m−1).
    pub pools: Vec<u64>,
    pub exit_share: u64,
    /// Every pool output's script, index 0 … m−1.
    pub pool_scripts: Vec<ScriptBuf>,
}

/// `fee(w, r) = ceil(w · r / 4)` with r in thousandths of a sat/vB.
fn fee(weight: u64, rate_milli: u64) -> Result<u64> {
    let x = weight.checked_mul(rate_milli).context("fee overflow")?;
    Ok(x.div_ceil(4000))
}

fn input_weight(spk: &Script) -> Result<u64> {
    if spk.is_p2wpkh() {
        Ok(272)
    } else if spk.is_p2tr() {
        Ok(230)
    } else {
        bail!("an input is neither P2WPKH nor P2TR")
    }
}

/// Step 8 (S58): what each member pays for the exits — their fees summed and split equally, rounded up (the NIP's
/// "Amounts", the default plan, one rate, no anchor). The same arithmetic `rederive` checks every member against.
pub fn exit_share(peers: usize, fee_rate_milli: u64) -> Result<u64> {
    ensure!((3..=6).contains(&peers), "a LiJ pool has 3 to 6 members");
    let plan = default_plan(peers);
    let m = plan.len();
    let mut total = 0u64;
    for (k, g) in plan.iter().enumerate() {
        let outputs = *g as u64 + if k + 1 < m { 1 } else { 0 };
        total = total.checked_add(fee(42 + 230 + 172 * outputs, fee_rate_milli)?).context("overflow")?;
    }
    Ok(total.div_ceil(peers as u64))
}

/// Step 8 (S58; v0.10 §5.3): what one member must put in — the pool size (its payout is exactly that), its equal share
/// of the exits' fees, and its own part of the funding's fee (its inputs, its change output if any, its share of the
/// transaction's fixed part). `rederive` refuses a member whose inputs less its change fall short of this.
pub fn member_need(denomination: u64, peers: usize, fee_rate_milli: u64, input_spks: &[&Script], change_spk: Option<&Script>) -> Result<u64> {
    ensure!(!input_spks.is_empty(), "no input");
    let mut w = 214u64.div_ceil(peers as u64);
    for spk in input_spks {
        w += input_weight(spk)?;
    }
    if let Some(c) = change_spk {
        w += 4 * (9 + c.len() as u64);
    }
    denomination
        .checked_add(exit_share(peers, fee_rate_milli)?)
        .and_then(|v| v.checked_add(fee(w, fee_rate_milli).ok()?))
        .context("overflow")
}

/// Step 8 (S58; v0.10 §5.3): this member's change for these inputs — what is left over what it must put in, when that is
/// worth an output of its own (at least `dust` and more than the output costs at this rate); else None, and the rest goes
/// to the miners. Err when the inputs do not cover even the need without a change output.
pub fn my_change(total_in: u64, denomination: u64, peers: usize, fee_rate_milli: u64, input_spks: &[&Script], change_spk: &Script, dust: u64) -> Result<Option<u64>> {
    let bare = member_need(denomination, peers, fee_rate_milli, input_spks, None)?;
    ensure!(total_in >= bare, "the coin covers {total_in} sats; the pool needs {bare}");
    let with = member_need(denomination, peers, fee_rate_milli, input_spks, Some(change_spk))?;
    let out_cost = with - bare;
    match total_in.checked_sub(with) {
        Some(c) if c >= dust && c > out_cost => Ok(Some(c)),
        _ => Ok(None),
    }
}

/// The P2TR script of pool output `index`: KeySort + KeyAgg of every member's musig key, BIP-328, child 0/index,
/// BIP-86 tweak.
pub fn pool_script(musig_keys: &[[u8; 33]], index: u32) -> Result<ScriptBuf> {
    ensure!(!musig_keys.is_empty(), "no keys");
    let mut sorted: Vec<musig2::secp::Point> = musig_keys
        .iter()
        .map(|k| musig2::secp::Point::from_slice(k).map_err(|_| anyhow::anyhow!("bad musig key")))
        .collect::<Result<_>>()?;
    sorted.sort_by_key(|p| p.serialize());
    let ctx = musig2::KeyAggContext::new(sorted).map_err(|e| anyhow::anyhow!("key aggregation: {e}"))?;
    let agg: musig2::secp::Point = ctx.aggregated_pubkey();
    let secp = Secp256k1::verification_only();
    let xpub = Xpub {
        network: NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_normal_idx(0)?,
        public_key: PublicKey::from_slice(&agg.serialize())?,
        chain_code: ChainCode::from(BIP328_CHAIN_CODE),
    };
    let child = xpub
        .ckd_pub(&secp, ChildNumber::from_normal_idx(0)?)?
        .ckd_pub(&secp, ChildNumber::from_normal_idx(index)?)?;
    let (internal, _) = child.public_key.x_only_public_key();
    let (tweaked, _) = internal.tap_tweak(&secp, None);
    Ok(ScriptBuf::new_p2tr_tweaked(tweaked))
}

/// The default exit plan: one payout per exit and two in the final exit.
fn default_plan(n: usize) -> Vec<usize> {
    let mut g = vec![1; n.saturating_sub(2)];
    g.push(2);
    g
}

fn txin(previous_output: OutPoint) -> TxIn {
    TxIn { previous_output, script_sig: ScriptBuf::new(), sequence: SEQUENCE, witness: Witness::new() }
}

/// Re-derive a Phase 1 pool. `payouts` are the registered payout scripts with their priorities (Phase 1: 0).
/// `my_tip` is this phone's chain tip: the funding's locktime (the smallest registered height) may lag it by at most
/// 100 blocks (the NIP's rule).
pub fn rederive(
    id: &str,
    denomination: u64,
    fee_rate_milli: u64,
    members: &[Member],
    payouts: &[(ScriptBuf, u8)],
    my_tip: u32,
) -> Result<Rederived> {
    let n = members.len();
    ensure!((3..=6).contains(&n), "a LiJ pool has 3 to 6 members");
    ensure!(payouts.len() == n, "{} payouts for {n} members", payouts.len());
    let plan = default_plan(n);
    let m = plan.len();
    let d = denomination;

    // Amounts — exit costs (no anchor, one rate: r_k = fee_rate), the equal share, the pool values
    let mut exit_fees = Vec::with_capacity(m);
    for (k, g) in plan.iter().enumerate() {
        let outputs = *g as u64 + if k + 1 < m { 1 } else { 0 };
        exit_fees.push(fee(42 + 230 + 172 * outputs, fee_rate_milli)?);
    }
    let exit_share = exit_share(n, fee_rate_milli)?;   // step 8: one function for this arithmetic
    let mut pools = vec![(d.checked_add(exit_share).context("overflow")?).checked_mul(n as u64).context("overflow")?];
    for k in 0..m - 1 {
        let prev = pools[k];
        let next = prev
            .checked_sub(plan[k] as u64 * d)
            .and_then(|v| v.checked_sub(exit_fees[k]))
            .context("a pool value runs out")?;
        pools.push(next);
    }
    // the final exit pays its payouts; its fee is what is left, at least F_m
    let last_fee = pools[m - 1].checked_sub(plan[m - 1] as u64 * d).context("the final exit runs out")?;
    ensure!(last_fee >= exit_fees[m - 1], "the final exit pays less than its fee");

    // every member's contribution covers denomination + exit share + its funding fee (step 8: member_need, the one rule)
    for (i, mb) in members.iter().enumerate() {
        ensure!(!mb.inputs.is_empty(), "member {i} has no input");
        let mut total_in: u64 = 0;
        for (_, out) in &mb.inputs {
            total_in = total_in.checked_add(out.value.to_sat()).context("overflow")?;
        }
        let change = mb.change.as_ref().map_or(0, |c| c.value.to_sat());
        let spks: Vec<&Script> = mb.inputs.iter().map(|(_, o)| o.script_pubkey.as_script()).collect();
        let need = member_need(d, n, fee_rate_milli, &spks, mb.change.as_ref().map(|c| c.script_pubkey.as_script()))?;
        let contribution = total_in.checked_sub(change).context("change larger than the inputs")?;
        ensure!(contribution >= need, "member {i} contributes {contribution} sats, needs {need}");
    }

    // keys
    let keys: Vec<[u8; 33]> = members.iter().map(|mb| mb.musig).collect();
    let pool_scripts: Vec<ScriptBuf> = (0..m as u32).map(|i| pool_script(&keys, i)).collect::<Result<_>>()?;

    // locktime: the smallest registered height, no more than 100 blocks behind this phone's tip
    let h = members.iter().map(|mb| mb.height).min().context("no members")?;
    ensure!(h.saturating_add(MAX_LOCKTIME_LAG) >= my_tip, "the locktime is more than {MAX_LOCKTIME_LAG} blocks behind");
    let lock_time = LockTime::from_height(h).map_err(|_| anyhow::anyhow!("bad locktime"))?;

    // the funding transaction — inputs by H(input_order, id ‖ outpoint), outputs by H(output_order, id ‖ txout)
    let mut inputs: Vec<OutPoint> = members.iter().flat_map(|mb| mb.inputs.iter().map(|(op, _)| *op)).collect();
    inputs.sort_by_key(|op| tagged("joinstr/v2/input_order", &[id.as_bytes(), &serialize(op)]));
    let mut outputs = vec![TxOut { value: Amount::from_sat(pools[0]), script_pubkey: pool_scripts[0].clone() }];
    outputs.extend(members.iter().filter_map(|mb| mb.change.clone()));
    outputs.sort_by_key(|o| tagged("joinstr/v2/output_order", &[id.as_bytes(), &serialize(o)]));
    let pool_vout = outputs.iter().position(|o| o.script_pubkey == pool_scripts[0]).context("pool output")? as u32;
    let funding = Transaction { version: Version::TWO, lock_time, input: inputs.into_iter().map(txin).collect(), output: outputs };

    // payout order: priority (highest first), then H(payout_order, id ‖ script)
    let mut order: Vec<(ScriptBuf, u8)> = payouts.to_vec();
    order.sort_by_key(|(s, pr)| (std::cmp::Reverse(*pr), tagged("joinstr/v2/payout_order", &[id.as_bytes(), s.as_bytes()])));

    // the exits — a chain: exit k (1-based) spends pool output k−1 and, unless final, creates pool output k
    let mut exits = Vec::with_capacity(m);
    let mut prev = OutPoint::new(funding.compute_txid(), pool_vout);
    let mut next_payout = 0usize;
    for k in 1..=m {
        let g = plan[k - 1];
        let mut outs: Vec<TxOut> = order[next_payout..next_payout + g]
            .iter()
            .map(|(s, _)| TxOut { value: Amount::from_sat(d), script_pubkey: s.clone() })
            .collect();
        next_payout += g;
        if k < m {
            outs.push(TxOut { value: Amount::from_sat(pools[k]), script_pubkey: pool_scripts[k].clone() });
        }
        let kb = (k as u32).to_le_bytes();
        outs.sort_by_key(|o| tagged("joinstr/v2/exit_output_order", &[id.as_bytes(), &kb, &serialize(o)]));
        let tx = Transaction { version: Version::TWO, lock_time, input: vec![txin(prev)], output: outs };
        if k < m {
            let vout = tx.output.iter().position(|o| o.script_pubkey == pool_scripts[k]).context("pool output")? as u32;
            prev = OutPoint::new(tx.compute_txid(), vout);
        }
        exits.push(tx);
    }
    Ok(Rederived { funding, pool_vout, exits, pools, exit_share, pool_scripts })
}
