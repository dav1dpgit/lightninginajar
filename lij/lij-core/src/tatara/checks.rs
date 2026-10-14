//! S4 and S5 (review r1 §5; the NIP's "Signing the funding"): what the phone checks before it signs its coin into a
//! pool. The independent re-derivation (S10) is `rederive`; here it is compared with joinstr's build.

use std::collections::HashSet;

use anyhow::{ensure, Result};
use bitcoin::{ScriptBuf, Transaction};
use joinstr_v2::pool::PoolTxs;

use super::rederive::{Member, Rederived};

/// S4: no payout equal to any pool output's script, any change script or any input script; no change equal to the
/// pool-0 script; no payout twice.
pub fn scripts_apart(r: &Rederived, members: &[Member], payouts: &[ScriptBuf]) -> Result<()> {
    let pools: HashSet<&ScriptBuf> = r.pool_scripts.iter().collect();
    let changes: HashSet<&ScriptBuf> = members.iter().filter_map(|m| m.change.as_ref().map(|c| &c.script_pubkey)).collect();
    let inputs: HashSet<&ScriptBuf> = members.iter().flat_map(|m| m.inputs.iter().map(|(_, o)| &o.script_pubkey)).collect();
    let mut seen = HashSet::new();
    for p in payouts {
        ensure!(seen.insert(p), "a payout is registered twice");
        ensure!(!pools.contains(p), "a payout equals a pool output's script");
        ensure!(!changes.contains(p), "a payout equals a change script");
        ensure!(!inputs.contains(p), "a payout equals an input's script");
    }
    for c in &changes {
        ensure!(!pools.contains(c), "a change equals a pool output's script");
    }
    Ok(())
}

/// S10 + S5 (1–5): joinstr's build is exactly our re-derivation — the funding (inputs exactly the registered ones, in the
/// NIP's order, empty script sigs; the pool output's key and value; every change exactly as registered; version,
/// locktime, sequences) and every exit (what it spends, its outputs and values, its fee). Witnesses are compared too:
/// at this point nothing is signed.
pub fn same_as_rederived(built: &PoolTxs, r: &Rederived) -> Result<()> {
    ensure!(built.funding == r.funding, "the funding transaction differs from the re-derivation");
    ensure!(built.pool_vout == r.pool_vout, "the pool output's place differs");
    ensure!(built.exits.len() == r.exits.len(), "{} exits, re-derived {}", built.exits.len(), r.exits.len());
    for (k, (a, b)) in built.exits.iter().zip(&r.exits).enumerate() {
        ensure!(a == b, "exit {} differs from the re-derivation", k + 1);
    }
    for i in &built.funding.input {
        ensure!(i.script_sig.is_empty(), "a funding input has a script sig");
    }
    Ok(())
}

/// S5 (6): this phone's payout is paid exactly once, by exactly the denomination, across all exits.
pub fn my_payout_once(exits: &[Transaction], mine: &ScriptBuf, denomination: u64) -> Result<()> {
    let hits: Vec<u64> = exits
        .iter()
        .flat_map(|t| t.output.iter())
        .filter(|o| &o.script_pubkey == mine)
        .map(|o| o.value.to_sat())
        .collect();
    ensure!(hits.len() == 1, "my payout appears {} times", hits.len());
    ensure!(hits[0] == denomination, "my payout is {} sats, not {denomination}", hits[0]);
    Ok(())
}

/// S5 (2): this phone's own inputs and change are in the funding transaction exactly as it registered them.
pub fn mine_in_funding(funding: &Transaction, me: &Member) -> Result<()> {
    for (op, _) in &me.inputs {
        ensure!(funding.input.iter().filter(|i| &i.previous_output == op).count() == 1, "my input {op} is not in the funding once");
    }
    if let Some(c) = &me.change {
        ensure!(funding.output.iter().filter(|o| *o == c).count() == 1, "my change is not in the funding exactly once");
    }
    Ok(())
}
