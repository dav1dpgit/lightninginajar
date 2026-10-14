//! Amounts and the deterministic funding transaction and pre-signed exits of a pool.

use std::collections::HashSet;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use secp::Point;
use serde::{Deserialize, Serialize};

use crate::keys::PoolKeys;
use crate::util::tagged_hash;

/// One key path input and two P2TR outputs.
pub const EXIT_WEIGHT: u64 = 616;
/// Version, locktime, counts, segwit marker and the pool output of the funding transaction.
pub const SHARED_WEIGHT: u64 = 214;
const TX_OVERHEAD_WEIGHT: u64 = 42;
const KEY_PATH_INPUT_WEIGHT: u64 = 230;
const P2TR_OUTPUT_WEIGHT: u64 = 172;
const P2A_OUTPUT_WEIGHT: u64 = 52;
pub const MAX_PEERS: usize = 100;
/// Most payouts in one exit, so that output counts stay one byte.
pub const MAX_GROUP: usize = 250;
/// Most transactions of a pool that are broadcast before earlier ones confirm.
pub const MAX_UNCONFIRMED: usize = 20;
pub const ANCHOR_VALUE: u64 = 240;
pub const SEQUENCE: Sequence = Sequence(0xfffffffd);
pub const MAX_LOCKTIME_LAG: u32 = 100;
/// Largest pool that pre-signs every order of exits, 6139 transactions for 7 peers.
pub const MAX_ANY_ORDER: usize = 7;
/// LiJ P6: caps that keep every sum and product below in range (no overflow: our release build has no overflow
/// checks). 21 M BTC in sats; 1,000 sat/vB in thousandths; inputs per peer (LiJ's own pools allow 4 — Tatara S6).
pub const MAX_MONEY_SAT: u64 = 2_100_000_000_000_000;
pub const MAX_FEE_RATE_MILLI: u64 = 1_000_000;
pub const MAX_INPUTS_PER_PEER: usize = 100;

pub fn p2a_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSplit {
    /// Every payout is exactly the denomination and all peers share the exit fees.
    #[default]
    Equal,
    /// Every peer puts the denomination in, and the payouts of each exit pay for that exit.
    ByExit,
}

/// How the pre-signed exits leave the pool.
/// P1 (LiJ, Tatara v0.10 §6.1): what every payout of the pool is. P2TR (joinstr's) or — a channel pool — P2WSH, a
/// channel's 2-of-2, so a payout can be a channel's funding. A P2WSH output weighs what a P2TR output weighs (172 WU),
/// so the fee rules are unchanged; a pool declares one type and every payout is checked against it by the peers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutType {
    #[default]
    P2tr,
    P2wsh,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Structure {
    /// One chain in a fixed order. A peer who leaves early also pays out everyone before it.
    #[default]
    Chain,
    /// An exit for every peer from every state the pool can reach, so peers leave in any order.
    AnyOrder,
    /// A binary tree. A peer leaves by broadcasting its branch, the others stay pooled below.
    Tree,
}

/// One denomination of a pool and how many peers use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Class {
    pub amount: u64,
    pub peers: usize,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub id: String,
    pub peers: usize,
    /// One or more denominations; the peers of all of them share the funding and the exits.
    pub classes: Vec<Class>,
    /// sat/kvB, so that `fee_rate` in sat/vB with three decimals is exact.
    pub fee_rate_milli: u64,
    /// Payouts per exit, in chain order.
    pub exits: Vec<usize>,
    /// Fee rate of the first and the last exit in sat/kvB, linear in between.
    pub exit_rates_milli: (u64, u64),
    pub fee_split: FeeSplit,
    pub anchor: bool,
    pub structure: Structure,
    /// P1: what every payout is (P2TR, or P2WSH for a channel pool).
    pub payout_type: PayoutType,
}

pub fn fee(weight: u64, rate_milli: u64) -> u64 {
    (weight * rate_milli).div_ceil(4000)
}

pub fn input_weight(spk: &Script) -> Result<u64> {
    if spk.is_p2wpkh() {
        Ok(272)
    } else if spk.is_p2tr() {
        Ok(230)
    } else {
        bail!("only P2WPKH and P2TR inputs are allowed")
    }
}

pub fn dust_limit(spk: &Script) -> u64 {
    spk.minimal_non_dust().to_sat()
}

/// One payout per exit and two in the final exit.
pub fn default_exits(peers: usize) -> Vec<usize> {
    let mut v = vec![1; peers.saturating_sub(2)];
    v.push(peers.min(2));
    v
}

/// Size and fee of an exit, which do not depend on the amounts it pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitCost {
    pub payouts: usize,
    pub weight: u64,
    pub rate_milli: u64,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitAmounts {
    /// Value of each payout of this exit, in payout order.
    pub payouts: Vec<u64>,
    pub weight: u64,
    pub rate_milli: u64,
    /// Fee actually paid, rounding included.
    pub fee: u64,
    /// The pool output this exit creates, none for the final exit.
    pub pool: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Amounts {
    /// `pool_0` to `pool_(m-1)`.
    pub pools: Vec<u64>,
    pub exits: Vec<ExitAmounts>,
}

/// An output of a pre-signed exit before it has a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanOut {
    /// The payout at this position of the payout order.
    Payout { position: usize, value: u64 },
    /// Pool output `index`, with key `0/index`.
    Pool { index: u32, value: u64 },
}

impl PlanOut {
    pub fn value(&self) -> u64 {
        match self {
            PlanOut::Payout { value, .. } | PlanOut::Pool { value, .. } => *value,
        }
    }
}

/// One pre-signed exit: the pool output it spends and what it pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitPlan {
    /// Pool output this exit spends, 0 is the one of the funding transaction.
    pub from: u32,
    pub outs: Vec<PlanOut>,
    pub fee: u64,
    pub weight: u64,
    pub rate_milli: u64,
    /// Exits before this one on its path.
    pub depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitSet {
    pub plans: Vec<ExitPlan>,
    /// Value of every pool output by index.
    pub pools: Vec<u64>,
}

/// A child of a tree node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Child {
    Payout(usize),
    Node(u32),
}

/// An inner node of the exit tree, covering payouts `lo..hi` of the payout order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    pub lo: usize,
    pub hi: usize,
    pub depth: usize,
    pub children: [Child; 2],
}

/// The inner nodes of the exit tree in breadth first order, node 0 spends the funding's pool
/// output. A node of `n` payouts splits them into the first `ceil(n / 2)` and the rest.
pub fn tree_nodes(peers: usize) -> Vec<TreeNode> {
    let mut nodes: Vec<TreeNode> = Vec::new();
    let mut queue = std::collections::VecDeque::from([(0usize, peers, 0usize)]);
    let mut next = 1u32;
    while let Some((lo, hi, depth)) = queue.pop_front() {
        let mid = lo + (hi - lo).div_ceil(2);
        let mut child = |a: usize, b: usize| {
            if b - a == 1 {
                Child::Payout(a)
            } else {
                queue.push_back((a, b, depth + 1));
                next += 1;
                Child::Node(next - 1)
            }
        };
        let children = [child(lo, mid), child(mid, hi)];
        nodes.push(TreeNode {
            lo,
            hi,
            depth,
            children,
        });
    }
    nodes
}

/// Every state of a pool with exits in any order, breadth first: the order in which payouts
/// left, from none up to all but two. State 0 is the funding's pool output.
pub fn any_order_states(peers: usize) -> Vec<Vec<usize>> {
    let mut states = vec![Vec::new()];
    let mut level = vec![Vec::new()];
    for _ in 0..peers.saturating_sub(2) {
        let mut next = Vec::new();
        for path in &level {
            for p in 0..peers {
                if !path.contains(&p) {
                    let mut q: Vec<usize> = path.clone();
                    q.push(p);
                    next.push(q);
                }
            }
        }
        states.extend(next.iter().cloned());
        level = next;
    }
    states
}

impl Params {
    pub fn new(id: &str, denomination: u64, peers: usize, fee_rate_milli: u64) -> Self {
        Self::with_classes(
            id,
            vec![Class {
                amount: denomination,
                peers,
            }],
            fee_rate_milli,
        )
    }

    pub fn with_classes(id: &str, classes: Vec<Class>, fee_rate_milli: u64) -> Self {
        let peers = classes.iter().map(|c| c.peers).sum();
        Params {
            id: id.to_string(),
            peers,
            classes,
            fee_rate_milli,
            exits: default_exits(peers),
            exit_rates_milli: (fee_rate_milli, fee_rate_milli),
            fee_split: FeeSplit::Equal,
            anchor: false,
            structure: Structure::Chain,
            payout_type: PayoutType::P2tr,
        }
    }

    pub fn class(&self, amount: u64) -> Option<&Class> {
        self.classes.iter().find(|c| c.amount == amount)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (2..=MAX_PEERS).contains(&self.peers),
            "peers must be from 2 to {MAX_PEERS}"
        );
        ensure!(!self.classes.is_empty(), "no denomination");
        // LiJ P6: each class bounded before anything sums them (a class of usize::MAX peers wrapped the sum)
        ensure!(self.classes.len() <= MAX_PEERS, "too many denominations");
        ensure!(
            self.classes
                .iter()
                .all(|c| (1..=MAX_PEERS).contains(&c.peers) && (1..=MAX_MONEY_SAT).contains(&c.amount)),
            "a denomination is out of range"
        );
        ensure!(
            self.fee_rate_milli <= MAX_FEE_RATE_MILLI
                && self.exit_rates_milli.0 <= MAX_FEE_RATE_MILLI
                && self.exit_rates_milli.1 <= MAX_FEE_RATE_MILLI,
            "fee rate above {} sat/vB",
            MAX_FEE_RATE_MILLI / 1000
        );
        ensure!(self.exits.len() <= MAX_PEERS, "too many exits");
        ensure!(
            self.classes.iter().map(|c| c.peers).sum::<usize>() == self.peers,
            "the denominations must add up to the number of peers"
        );
        let amounts: HashSet<u64> = self.classes.iter().map(|c| c.amount).collect();
        ensure!(
            amounts.len() == self.classes.len(),
            "denominations must be different"
        );
        if self.classes.len() > 1 {
            ensure!(
                self.classes.iter().all(|c| c.peers >= 2),
                "every denomination needs at least 2 peers"
            );
        }
        ensure!(self.fee_rate_milli > 0, "fee rate must be positive");
        ensure!(
            self.exit_rates_milli.0 > 0 && self.exit_rates_milli.1 > 0,
            "exit fee rates must be positive"
        );
        ensure!(!self.exits.is_empty(), "no exits");
        ensure!(
            self.exits.iter().all(|g| (1..=MAX_GROUP).contains(g)),
            "every exit pays 1 to {MAX_GROUP} peers"
        );
        ensure!(
            self.exits.iter().sum::<usize>() == self.peers,
            "the exits must pay every peer once"
        );
        match self.structure {
            Structure::Chain => {}
            Structure::AnyOrder => {
                ensure!(
                    (3..=MAX_ANY_ORDER).contains(&self.peers),
                    "a pool with exits in any order has 3 to {MAX_ANY_ORDER} peers"
                );
                ensure!(
                    self.exits == default_exits(self.peers),
                    "a pool with exits in any order pays one peer per exit"
                );
            }
            Structure::Tree => {
                ensure!(
                    self.exits == default_exits(self.peers),
                    "a tree has no exit groups"
                );
                ensure!(
                    self.fee_split == FeeSplit::Equal,
                    "in a tree every peer shares the fees"
                );
            }
        }
        let smallest = self.classes.iter().map(|c| c.amount).min().unwrap_or(0);
        let anchor = if self.anchor { ANCHOR_VALUE } else { 0 };
        let worst = match self.fee_split {
            FeeSplit::Equal => 0,
            FeeSplit::ByExit => self
                .exit_costs()
                .iter()
                .map(|e| (e.fee + anchor).div_ceil(e.payouts as u64))
                .max()
                .unwrap_or(0),
        };
        ensure!(smallest >= 330 + worst, "payouts would be below dust");
        Ok(())
    }

    fn exit_rate(&self, j: usize) -> u64 {
        let m = self.exits.len() as u64;
        let (first, last) = self.exit_rates_milli;
        if m == 1 {
            return first;
        }
        let j = j as u64;
        (first * (m - 1 - j) + last * j) / (m - 1)
    }

    pub fn exit_costs(&self) -> Vec<ExitCost> {
        let m = self.exits.len();
        self.exits
            .iter()
            .enumerate()
            .map(|(j, &g)| {
                let outputs = g as u64 + u64::from(j + 1 < m);
                let weight = TX_OVERHEAD_WEIGHT
                    + KEY_PATH_INPUT_WEIGHT
                    + P2TR_OUTPUT_WEIGHT * outputs
                    + if self.anchor { P2A_OUTPUT_WEIGHT } else { 0 };
                let rate_milli = self.exit_rate(j);
                ExitCost {
                    payouts: g,
                    weight,
                    rate_milli,
                    fee: fee(weight, rate_milli),
                }
            })
            .collect()
    }

    /// What every peer adds to the pool for the exits on top of its denomination. In a pool
    /// with exits in any order every path has the same exits, so the share is that of the chain.
    pub fn exit_share(&self) -> u64 {
        match self.fee_split {
            FeeSplit::Equal => {
                let anchor = if self.anchor { ANCHOR_VALUE } else { 0 };
                let costs: u64 = match self.structure {
                    Structure::Tree => tree_nodes(self.peers)
                        .iter()
                        .map(|t| self.tree_cost(t).fee + anchor)
                        .sum(),
                    _ => self.exit_costs().iter().map(|e| e.fee + anchor).sum(),
                };
                costs.div_ceil(self.peers as u64)
            }
            FeeSplit::ByExit => 0,
        }
    }

    /// Weight, rate and fee of a tree node. Rates go from the first exit rate at the root to
    /// the last one at the deepest node.
    pub fn tree_cost(&self, node: &TreeNode) -> ExitCost {
        let deepest = tree_nodes(self.peers)
            .iter()
            .map(|t| t.depth)
            .max()
            .unwrap_or(0) as u64;
        let (first, last) = self.exit_rates_milli;
        let d = node.depth as u64;
        let rate_milli = (first * deepest.saturating_sub(d) + last * d)
            .checked_div(deepest)
            .unwrap_or(first);
        let weight = TX_OVERHEAD_WEIGHT
            + KEY_PATH_INPUT_WEIGHT
            + P2TR_OUTPUT_WEIGHT * 2
            + if self.anchor { P2A_OUTPUT_WEIGHT } else { 0 };
        ExitCost {
            payouts: node
                .children
                .iter()
                .filter(|c| matches!(c, Child::Payout(_)))
                .count(),
            weight,
            rate_milli,
            fee: fee(weight, rate_milli),
        }
    }

    /// Values of the pool outputs and the exits for payouts of these denominations, in chain order.
    pub fn amounts(&self, ordered: &[u64]) -> Amounts {
        let anchor = if self.anchor { ANCHOR_VALUE } else { 0 };
        let share = self.exit_share();
        let costs = self.exit_costs();
        let m = costs.len();
        let mut pools = vec![ordered.iter().map(|a| a + share).sum::<u64>()];
        let mut exits = Vec::with_capacity(m);
        let mut next = 0;
        for (j, c) in costs.into_iter().enumerate() {
            let group = &ordered[next.min(ordered.len())..(next + c.payouts).min(ordered.len())];
            next += c.payouts;
            let per_payout = (c.fee + anchor).div_ceil(c.payouts as u64);
            let payouts: Vec<u64> = group
                .iter()
                .map(|&a| match self.fee_split {
                    FeeSplit::Equal => a,
                    FeeSplit::ByExit => a.saturating_sub(per_payout),
                })
                .collect();
            let before = pools[j];
            let paid = payouts.iter().sum::<u64>() + anchor;
            // Only invalid plans, which `validate` rejects, can run short here.
            let (fee, pool) = if j + 1 < m {
                let after = before.saturating_sub(paid + c.fee);
                pools.push(after);
                (c.fee, Some(after))
            } else {
                (before.saturating_sub(paid), None)
            };
            exits.push(ExitAmounts {
                payouts,
                weight: c.weight,
                rate_milli: c.rate_milli,
                fee,
                pool,
            });
        }
        Amounts { pools, exits }
    }

    /// Amounts of a pool with a single denomination.
    pub fn amounts_single(&self) -> Amounts {
        self.amounts(&vec![self.classes[0].amount; self.peers])
    }

    /// Every pre-signed exit of the pool, in signing order, for payouts of these denominations
    /// in payout order.
    pub fn exit_set(&self, ordered: &[u64]) -> ExitSet {
        match self.structure {
            Structure::Chain => self.chain_set(ordered),
            Structure::AnyOrder => self.any_order_set(ordered),
            Structure::Tree => self.tree_set(ordered),
        }
    }

    fn chain_set(&self, ordered: &[u64]) -> ExitSet {
        let amounts = self.amounts(ordered);
        let mut plans = Vec::new();
        let mut first = 0;
        for (j, e) in amounts.exits.iter().enumerate() {
            let mut outs: Vec<PlanOut> = e
                .payouts
                .iter()
                .enumerate()
                .map(|(i, &value)| PlanOut::Payout {
                    position: first + i,
                    value,
                })
                .collect();
            first += e.payouts.len();
            if let Some(value) = e.pool {
                outs.push(PlanOut::Pool {
                    index: j as u32 + 1,
                    value,
                });
            }
            plans.push(ExitPlan {
                from: j as u32,
                outs,
                fee: e.fee,
                weight: e.weight,
                rate_milli: e.rate_milli,
                depth: j,
            });
        }
        ExitSet {
            plans,
            pools: amounts.pools,
        }
    }

    /// One exit for every payout from every state, where a state is the order in which
    /// payouts already left. Signatures commit to the transaction they spend, so the same
    /// set of departed payouts reached in two orders is two states.
    fn any_order_set(&self, ordered: &[u64]) -> ExitSet {
        let n = self.peers;
        let anchor = if self.anchor { ANCHOR_VALUE } else { 0 };
        let costs = self.exit_costs();
        let states = any_order_states(n);
        let index_of = |path: &[usize]| -> u32 {
            states.iter().position(|s| s == path).expect("known state") as u32
        };
        let mut pools = vec![0u64; states.len()];
        pools[0] = ordered.iter().sum::<u64>() + n as u64 * self.exit_share();
        let mut plans = Vec::new();
        for (si, path) in states.iter().enumerate() {
            let depth = path.len();
            let left: Vec<usize> = (0..n).filter(|p| !path.contains(p)).collect();
            let c = &costs[depth];
            if left.len() >= 3 {
                for &p in &left {
                    let value = match self.fee_split {
                        FeeSplit::Equal => ordered[p],
                        FeeSplit::ByExit => ordered[p].saturating_sub(c.fee + anchor),
                    };
                    let mut next = path.clone();
                    next.push(p);
                    let to = index_of(&next);
                    pools[to as usize] = pools[si].saturating_sub(value + anchor + c.fee);
                    plans.push(ExitPlan {
                        from: si as u32,
                        outs: vec![
                            PlanOut::Payout { position: p, value },
                            PlanOut::Pool {
                                index: to,
                                value: pools[to as usize],
                            },
                        ],
                        fee: c.fee,
                        weight: c.weight,
                        rate_milli: c.rate_milli,
                        depth,
                    });
                }
            } else {
                let per_payout = (c.fee + anchor).div_ceil(2);
                let outs: Vec<PlanOut> = left
                    .iter()
                    .map(|&p| PlanOut::Payout {
                        position: p,
                        value: match self.fee_split {
                            FeeSplit::Equal => ordered[p],
                            FeeSplit::ByExit => ordered[p].saturating_sub(per_payout),
                        },
                    })
                    .collect();
                let paid: u64 = outs.iter().map(PlanOut::value).sum::<u64>() + anchor;
                plans.push(ExitPlan {
                    from: si as u32,
                    outs,
                    fee: pools[si].saturating_sub(paid),
                    weight: c.weight,
                    rate_milli: c.rate_milli,
                    depth,
                });
            }
        }
        ExitSet { plans, pools }
    }

    /// One transaction per inner node of a binary tree over the payouts in payout order. The
    /// rounding of the shares goes to the fee of the root.
    fn tree_set(&self, ordered: &[u64]) -> ExitSet {
        let anchor = if self.anchor { ANCHOR_VALUE } else { 0 };
        let nodes = tree_nodes(self.peers);
        let costs: Vec<ExitCost> = nodes.iter().map(|t| self.tree_cost(t)).collect();
        // value of each node's pool output: its payouts and the exits below it
        let mut pools = vec![0u64; nodes.len()];
        for (i, t) in nodes.iter().enumerate().rev() {
            let mut v = costs[i].fee + anchor;
            for c in &t.children {
                v += match *c {
                    Child::Payout(p) => ordered[p],
                    Child::Node(j) => pools[j as usize],
                };
            }
            pools[i] = v;
        }
        pools[0] = ordered.iter().sum::<u64>() + self.peers as u64 * self.exit_share();
        let plans = nodes
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let outs: Vec<PlanOut> = t
                    .children
                    .iter()
                    .map(|c| match *c {
                        Child::Payout(p) => PlanOut::Payout {
                            position: p,
                            value: ordered[p],
                        },
                        Child::Node(j) => PlanOut::Pool {
                            index: j,
                            value: pools[j as usize],
                        },
                    })
                    .collect();
                let paid: u64 = outs.iter().map(PlanOut::value).sum::<u64>() + anchor;
                ExitPlan {
                    from: i as u32,
                    outs,
                    fee: pools[i].saturating_sub(paid),
                    weight: costs[i].weight,
                    rate_milli: costs[i].rate_milli,
                    depth: t.depth,
                }
            })
            .collect();
        ExitSet { plans, pools }
    }

    pub fn funding_fee(&self, inputs: &[TxOut], change: Option<&TxOut>) -> Result<u64> {
        let mut weight = SHARED_WEIGHT.div_ceil(self.peers as u64);
        for i in inputs {
            weight += input_weight(&i.script_pubkey)?;
        }
        if let Some(c) = change {
            weight += c.weight().to_wu();
        }
        Ok(fee(weight, self.fee_rate_milli))
    }

    /// What a peer of denomination `amount` with these inputs and change must contribute.
    pub fn required(&self, amount: u64, inputs: &[TxOut], change: Option<&TxOut>) -> Result<u64> {
        Ok(amount + self.exit_share() + self.funding_fee(inputs, change)?)
    }
}

#[derive(Clone, Debug)]
pub struct InputRegistration {
    pub session: [u8; 32],
    /// The denomination this peer joins.
    pub amount: u64,
    pub musig: Point,
    pub ring: Point,
    pub inputs: Vec<(OutPoint, TxOut)>,
    pub change: Option<TxOut>,
    pub height: u32,
}

impl InputRegistration {
    pub fn input_total(&self) -> u64 {
        self.inputs.iter().map(|(_, o)| o.value.to_sat()).sum()
    }

    pub fn contribution(&self) -> u64 {
        self.input_total() - self.change.as_ref().map_or(0, |c| c.value.to_sat())
    }

    pub fn prevouts(&self) -> Vec<TxOut> {
        self.inputs.iter().map(|(_, o)| o.clone()).collect()
    }
}

/// Checks that only need the registrations themselves.
pub fn check_input_registrations(params: &Params, regs: &[InputRegistration]) -> Result<()> {
    ensure!(regs.len() == params.peers, "wrong number of registrations");
    for c in &params.classes {
        ensure!(
            regs.iter().filter(|r| r.amount == c.amount).count() == c.peers,
            "denomination {} needs {} peers",
            c.amount,
            c.peers
        );
    }
    let mut sessions = HashSet::new();
    let mut keys = HashSet::new();
    let mut outpoints = HashSet::new();
    let mut scripts = HashSet::new();
    for r in regs {
        ensure!(
            params.class(r.amount).is_some(),
            "unknown denomination {}",
            r.amount
        );
        ensure!(sessions.insert(r.session), "duplicate session key");
        ensure!(keys.insert(r.musig.serialize()), "duplicate musig key");
        ensure!(keys.insert(r.ring.serialize()), "duplicate ring key");
        ensure!(!r.inputs.is_empty(), "registration without inputs");
        // LiJ P6: bounded inputs and values, so the sums below cannot overflow
        ensure!(
            r.inputs.len() <= MAX_INPUTS_PER_PEER,
            "more than {MAX_INPUTS_PER_PEER} inputs from one peer"
        );
        for (op, out) in &r.inputs {
            ensure!(outpoints.insert(*op), "input {op} registered twice");
            ensure!(out.value.to_sat() <= MAX_MONEY_SAT, "input {op} is larger than all bitcoin");
            input_weight(&out.script_pubkey)?;
        }
        if let Some(c) = &r.change {
            ensure!(c.value.to_sat() <= MAX_MONEY_SAT, "change larger than all bitcoin");
            ensure!(
                scripts.insert(c.script_pubkey.clone()),
                "duplicate change script"
            );
            ensure!(
                c.value.to_sat() >= dust_limit(&c.script_pubkey),
                "dust change"
            );
            ensure!(
                c.value.to_sat() <= r.input_total(),
                "change larger than inputs"
            );
        }
        let need = params.required(r.amount, &r.prevouts(), r.change.as_ref())?;
        ensure!(
            r.input_total() >= need && r.contribution() >= need,
            "a peer contributes {} sats but must contribute {need}",
            r.contribution().min(r.input_total())
        );
    }
    Ok(())
}

pub fn locktime(regs: &[InputRegistration]) -> u32 {
    regs.iter().map(|r| r.height).min().unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct PoolTxs {
    pub funding: Transaction,
    /// Prevouts of the funding inputs, in input order.
    pub funding_prevouts: Vec<TxOut>,
    pub pool_vout: u32,
    /// Every pre-signed exit, in signing order.
    pub exits: Vec<Transaction>,
    /// The pool output spent by each exit.
    pub spent: Vec<TxOut>,
    /// Where each exit sits in the structure.
    pub links: Vec<ExitLink>,
    /// Payout scripts in payout order.
    pub payouts: Vec<ScriptBuf>,
    /// The denomination of each payout, in payout order.
    pub payout_amounts: Vec<u64>,
}

/// The pool output an exit spends, the pool outputs it creates and the payouts it pays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitLink {
    pub from: u32,
    /// Pool output index and vout of each pool output it creates.
    pub to: Vec<(u32, u32)>,
    /// Position in the payout order and vout of each payout it pays.
    pub pays: Vec<(usize, u32)>,
    pub depth: usize,
}

/// A registered payout, its denomination and the priority its owner asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub script: ScriptBuf,
    pub amount: u64,
    pub priority: u8,
}

fn order_key(tag: &str, id: &str, data: &[u8]) -> [u8; 32] {
    tagged_hash(tag, &[id.as_bytes(), data])
}

/// The message a payout's ring signature signs.
pub fn payout_msg(id: &str, priority: u8, amount: u64, script: &Script) -> [u8; 32] {
    tagged_hash(
        "joinstr/v2/payout",
        &[
            id.as_bytes(),
            &[priority],
            &amount.to_le_bytes(),
            script.as_bytes(),
        ],
    )
}

/// Higher priority first, then the tagged hash of the script.
pub fn payout_order(id: &str, payouts: &[Payout]) -> Vec<Payout> {
    let mut v = payouts.to_vec();
    v.sort_by_key(|p| {
        (
            std::cmp::Reverse(p.priority),
            order_key("joinstr/v2/payout_order", id, p.script.as_bytes()),
        )
    });
    v
}

fn txin(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: SEQUENCE,
        witness: Witness::new(),
    }
}

/// The outputs of exit number `k` (from 1, in signing order), in transaction order.
fn exit_outputs(
    params: &Params,
    plan: &ExitPlan,
    keys: &PoolKeys,
    order: &[ScriptBuf],
    k: usize,
) -> Result<Vec<TxOut>> {
    let mut outputs = Vec::with_capacity(plan.outs.len() + 1);
    for o in &plan.outs {
        outputs.push(match *o {
            PlanOut::Payout { position, value } => TxOut {
                value: Amount::from_sat(value),
                script_pubkey: order[position].clone(),
            },
            PlanOut::Pool { index, value } => TxOut {
                value: Amount::from_sat(value),
                script_pubkey: keys.script_pubkey(index)?,
            },
        });
    }
    if params.anchor {
        outputs.push(TxOut {
            value: Amount::from_sat(ANCHOR_VALUE),
            script_pubkey: p2a_script(),
        });
    }
    let tag = (k as u32).to_le_bytes();
    outputs.sort_by_key(|o| {
        tagged_hash(
            "joinstr/v2/exit_output_order",
            &[params.id.as_bytes(), &tag, &serialize(o)],
        )
    });
    Ok(outputs)
}

/// Where the planned outputs ended up after sorting.
fn link_of(
    plan: &ExitPlan,
    outputs: &[TxOut],
    keys: &PoolKeys,
    order: &[ScriptBuf],
) -> Result<ExitLink> {
    let vout_of = |spk: &ScriptBuf| -> Result<u32> {
        Ok(outputs
            .iter()
            .position(|o| &o.script_pubkey == spk)
            .context("planned output missing")? as u32)
    };
    let mut to = Vec::new();
    let mut pays = Vec::new();
    for o in &plan.outs {
        match *o {
            PlanOut::Payout { position, .. } => pays.push((position, vout_of(&order[position])?)),
            PlanOut::Pool { index, .. } => to.push((index, vout_of(&keys.script_pubkey(index)?)?)),
        }
    }
    Ok(ExitLink {
        from: plan.from,
        to,
        pays,
        depth: plan.depth,
    })
}

pub fn build(
    params: &Params,
    regs: &[InputRegistration],
    payouts: &[Payout],
    keys: &PoolKeys,
) -> Result<PoolTxs> {
    let n = params.peers;
    ensure!(regs.len() == n && payouts.len() == n, "incomplete pool");
    let lock_time = LockTime::from_height(locktime(regs)).context("locktime")?;
    let id = params.id.as_str();
    let ordered = payout_order(id, payouts);
    let payout_amounts: Vec<u64> = ordered.iter().map(|p| p.amount).collect();
    let order: Vec<ScriptBuf> = ordered.into_iter().map(|p| p.script).collect();
    let set = params.exit_set(&payout_amounts);

    let mut inputs: Vec<(OutPoint, TxOut)> = regs.iter().flat_map(|r| r.inputs.clone()).collect();
    inputs.sort_by_key(|(op, _)| order_key("joinstr/v2/input_order", id, &serialize(op)));

    let pool_spk = keys.script_pubkey(0)?;
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(set.pools[0]),
        script_pubkey: pool_spk.clone(),
    }];
    outputs.extend(regs.iter().filter_map(|r| r.change.clone()));
    outputs.sort_by_key(|o| order_key("joinstr/v2/output_order", id, &serialize(o)));
    let pool_vout = outputs
        .iter()
        .position(|o| o.script_pubkey == pool_spk)
        .expect("pool output") as u32;

    let funding = Transaction {
        version: Version::TWO,
        lock_time,
        input: inputs.iter().map(|(op, _)| txin(*op)).collect(),
        output: outputs,
    };
    let funding_prevouts = inputs.into_iter().map(|(_, o)| o).collect();

    // every pool output, by index, once the transaction creating it is built
    let mut created: Vec<Option<(OutPoint, TxOut)>> = vec![None; set.pools.len()];
    created[0] = Some((
        OutPoint::new(funding.compute_txid(), pool_vout),
        funding.output[pool_vout as usize].clone(),
    ));
    let mut exits = Vec::with_capacity(set.plans.len());
    let mut spent = Vec::with_capacity(set.plans.len());
    let mut links = Vec::with_capacity(set.plans.len());
    for (t, plan) in set.plans.iter().enumerate() {
        let (prev, prev_out) = created[plan.from as usize]
            .clone()
            .context("an exit spends a pool output that is not built yet")?;
        let output = exit_outputs(params, plan, keys, &order, t + 1)?;
        let link = link_of(plan, &output, keys, &order)?;
        let tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![txin(prev)],
            output,
        };
        let txid = tx.compute_txid();
        for &(index, vout) in &link.to {
            created[index as usize] =
                Some((OutPoint::new(txid, vout), tx.output[vout as usize].clone()));
        }
        spent.push(prev_out);
        links.push(link);
        exits.push(tx);
    }

    Ok(PoolTxs {
        funding,
        funding_prevouts,
        pool_vout,
        exits,
        spent,
        links,
        payouts: order,
        payout_amounts,
    })
}

pub fn exit_sighash(tx: &Transaction, spent: &TxOut) -> [u8; 32] {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[spent]), TapSighashType::Default)
        .expect("one input with its prevout")
        .to_byte_array()
}

/// Structural checks of the funding transaction and the exit chain, see "Signing the funding".
pub fn check_txs(params: &Params, txs: &PoolTxs, keys: &PoolKeys) -> Result<()> {
    ensure!(txs.payouts.len() == params.peers, "wrong number of payouts");
    ensure!(
        txs.payout_amounts.len() == params.peers,
        "wrong number of payouts"
    );
    let distinct: HashSet<&ScriptBuf> = txs.payouts.iter().collect();
    ensure!(distinct.len() == params.peers, "a payout is listed twice");
    for c in &params.classes {
        ensure!(
            txs.payout_amounts
                .iter()
                .filter(|a| **a == c.amount)
                .count()
                == c.peers,
            "wrong number of payouts of {}",
            c.amount
        );
    }
    let set = params.exit_set(&txs.payout_amounts);
    // LiJ P9: every index below is checked — a short or out-of-range list from a peer is an Err, never a panic
    // (our release build aborts on a panic).
    let pool = txs
        .funding
        .output
        .get(txs.pool_vout as usize)
        .context("the pool output index is outside the funding")?;
    ensure!(
        pool.script_pubkey == keys.script_pubkey(0)?,
        "funding pays the wrong pool key"
    );
    ensure!(
        pool.value.to_sat() == set.pools[0],
        "pool output has the wrong value"
    );
    for i in &txs.funding.input {
        ensure!(i.script_sig.is_empty(), "funding input with a script sig");
    }
    let total_in = txs
        .funding_prevouts
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
        .context("funding inputs overflow")?;
    let total_out = txs
        .funding
        .output
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
        .context("funding outputs overflow")?;
    ensure!(total_in > total_out, "funding pays no fee");

    ensure!(txs.exits.len() == set.plans.len(), "wrong number of exits");
    ensure!(
        txs.spent.len() == txs.exits.len() && txs.links.len() == txs.exits.len(),
        "wrong number of spent outputs or links"
    );
    let mut created: Vec<Option<(OutPoint, u64)>> = vec![None; set.pools.len()];
    created[0] = Some((
        OutPoint::new(txs.funding.compute_txid(), txs.pool_vout),
        pool.value.to_sat(),
    ));
    for (t, (tx, plan)) in txs.exits.iter().zip(&set.plans).enumerate() {
        let k = t + 1;
        let (prev, prev_value) = created
            .get(plan.from as usize)
            .copied()
            .flatten()
            .context("exit spends an unknown pool output")?;
        ensure!(
            tx.input.len() == 1 && tx.input[0].previous_output == prev,
            "exit {k} does not spend pool output {}",
            plan.from
        );
        ensure!(
            txs.spent[t].value.to_sat() == prev_value,
            "exit {k} spends the wrong amount"
        );
        let expected = exit_outputs(params, plan, keys, &txs.payouts, k)?;
        ensure!(tx.output == expected, "exit {k} has the wrong outputs");
        ensure!(
            txs.links[t] == link_of(plan, &expected, keys, &txs.payouts)?,
            "exit {k} is in the wrong place"
        );
        let out = tx
            .output
            .iter()
            .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
            .context("exit outputs overflow")?;
        ensure!(
            prev_value.checked_sub(out) == Some(plan.fee),
            "exit {k} pays the wrong fee"
        );
        let txid = tx.compute_txid();
        for &(index, vout) in &txs.links[t].to {
            let value = tx
                .output
                .get(vout as usize)
                .context("exit link names an output the exit does not have")?
                .value
                .to_sat();
            *created
                .get_mut(index as usize)
                .context("exit link names an unknown pool output")? = Some((OutPoint::new(txid, vout), value));
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests_support {
    use super::*;
    use crate::util::random_scalar;
    use bitcoin::Txid;
    use std::str::FromStr;

    pub fn params(peers: usize) -> Params {
        Params::new("test-pool", 10_000, peers, 2_000)
    }

    pub fn fake_pool(n: usize) -> (Params, Vec<InputRegistration>, Vec<Payout>, PoolKeys) {
        pool_with(params(n), |i| i % 2 == 0, |_| true)
    }

    /// A pool whose peer `i` has a P2TR coin if `taproot(i)` (P2WPKH otherwise)
    /// and change if `change(i)`; peers without change contribute exactly what they owe.
    pub fn pool_with(
        p: Params,
        taproot: impl Fn(usize) -> bool,
        change: impl Fn(usize) -> bool,
    ) -> (Params, Vec<InputRegistration>, Vec<Payout>, PoolKeys) {
        let mut regs = Vec::new();
        let mut payouts = Vec::new();
        let mut class_of = Vec::new();
        for c in &p.classes {
            class_of.extend(std::iter::repeat_n(c.amount, c.peers));
        }
        for (i, &amount) in class_of.iter().enumerate() {
            let spk = if taproot(i) {
                ScriptBuf::from_hex(&format!("5120{:02x}{}", i, "33".repeat(31))).unwrap()
            } else {
                ScriptBuf::from_hex(&format!("0014{:02x}{}", i, "77".repeat(19))).unwrap()
            };
            let change_out = TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_hex(&format!("0014{:02x}{}", i, "44".repeat(19)))
                    .unwrap(),
            };
            let mut input = TxOut {
                value: Amount::ZERO,
                script_pubkey: spk.clone(),
            };
            let (value, change_out) = if change(i) {
                let need = p
                    .required(amount, std::slice::from_ref(&input), Some(&change_out))
                    .unwrap();
                let value = need + 20_000;
                (
                    value,
                    Some(TxOut {
                        value: Amount::from_sat(value - need),
                        ..change_out
                    }),
                )
            } else {
                (
                    p.required(amount, std::slice::from_ref(&input), None)
                        .unwrap(),
                    None,
                )
            };
            input.value = Amount::from_sat(value);
            regs.push(InputRegistration {
                session: [i as u8; 32],
                amount,
                musig: random_scalar().base_point_mul(),
                ring: random_scalar().base_point_mul(),
                inputs: vec![(
                    OutPoint::new(
                        Txid::from_str(&format!("{:02x}{}", i, "55".repeat(31))).unwrap(),
                        i as u32,
                    ),
                    input,
                )],
                change: change_out,
                height: 1000 + i as u32,
            });
            let xonly = bitcoin::key::XOnlyPublicKey::from_slice(
                &random_scalar().base_point_mul().serialize_xonly(),
            )
            .unwrap();
            payouts.push(Payout {
                script: ScriptBuf::new_p2tr_tweaked(
                    bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
                ),
                amount,
                priority: 0,
            });
        }
        let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
        (p, regs, payouts, keys)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    fn signed_weight(tx: &Transaction, prevouts: &[TxOut]) -> u64 {
        let mut tx = tx.clone();
        for (i, p) in tx.input.iter_mut().zip(prevouts) {
            if p.script_pubkey.is_p2tr() {
                i.witness.push([0u8; 64]);
            } else {
                i.witness.push([0u8; 72]);
                i.witness.push([0u8; 33]);
            }
        }
        tx.weight().to_wu()
    }

    fn exit_weight(tx: &Transaction) -> u64 {
        let mut tx = tx.clone();
        tx.input[0].witness.push([0u8; 64]);
        tx.weight().to_wu()
    }

    fn structured(structure: Structure, peers: usize, anchor: bool) -> (Params, PoolTxs, PoolKeys) {
        let mut p = params(peers);
        p.structure = structure;
        p.anchor = anchor;
        p.validate().unwrap();
        let (p, regs, payouts, keys) = pool_with(p, |i| i % 3 != 1, |i| i % 2 == 0);
        let txs = build(&p, &regs, &payouts, &keys).unwrap();
        check_txs(&p, &txs, &keys).unwrap();
        (p, txs, keys)
    }

    #[test]
    fn any_order_presigns_every_order() {
        for (n, count) in [(3, 6), (4, 28), (5, 145)] {
            let (p, txs, _) = structured(Structure::AnyOrder, n, n == 4);
            assert_eq!(txs.exits.len(), count, "{n} peers");
            // every path pays every payout exactly once and conserves value
            let set = p.exit_set(&txs.payout_amounts);
            let mut stack = vec![(0u32, Vec::<usize>::new())];
            let mut paths = 0;
            while let Some((from, paid)) = stack.pop() {
                let next: Vec<usize> = (0..txs.links.len())
                    .filter(|&t| txs.links[t].from == from)
                    .collect();
                if next.is_empty() {
                    let mut all = paid.clone();
                    all.sort();
                    assert_eq!(all, (0..n).collect::<Vec<_>>());
                    paths += 1;
                    continue;
                }
                for t in next {
                    let mut more = paid.clone();
                    more.extend(txs.links[t].pays.iter().map(|x| x.0));
                    let to = txs.links[t].to.first().map_or(u32::MAX, |x| x.0);
                    stack.push((to, more));
                }
            }
            let orders: usize = (1..=n).product::<usize>() / 2;
            assert_eq!(paths, orders, "one path per order of the first n - 2 exits");
            assert_eq!(set.plans.len(), count);
        }
    }

    #[test]
    fn any_order_matches_the_chain_amounts() {
        let (p, txs, _) = structured(Structure::AnyOrder, 5, false);
        let mut chain = p.clone();
        chain.structure = Structure::Chain;
        let amounts = chain.amounts(&txs.payout_amounts);
        // the path in payout order has the values of the chain
        let mut from = 0u32;
        for (j, e) in amounts.exits.iter().enumerate() {
            let t = (0..txs.links.len())
                .find(|&t| txs.links[t].from == from && txs.links[t].pays.iter().any(|x| x.0 == j))
                .unwrap();
            let tx = &txs.exits[t];
            let paid: Vec<u64> = txs.links[t]
                .pays
                .iter()
                .map(|&(_, v)| tx.output[v as usize].value.to_sat())
                .collect();
            assert_eq!(paid, e.payouts);
            if let Some(&(to, vout)) = txs.links[t].to.first() {
                assert_eq!(Some(tx.output[vout as usize].value.to_sat()), e.pool);
                from = to;
            }
        }
    }

    #[test]
    fn tree_lets_every_payout_leave_on_its_own_branch() {
        for n in [2, 3, 5, 8, 13, 100] {
            let (_, txs, _) = structured(Structure::Tree, n, n == 13);
            assert_eq!(txs.exits.len(), n - 1, "{n} peers");
            let depth = txs.links.iter().map(|l| l.depth).max().unwrap();
            assert_eq!(
                depth + 1,
                (n as f64).log2().ceil() as usize,
                "branches of {n} peers"
            );
            for position in 0..n {
                let paying: Vec<usize> = (0..n - 1)
                    .filter(|&t| txs.links[t].pays.iter().any(|x| x.0 == position))
                    .collect();
                assert_eq!(paying.len(), 1, "one exit pays payout {position}");
            }
            // each pool output is spent by exactly one exit
            for index in 0..(n - 1) as u32 {
                assert_eq!(txs.links.iter().filter(|l| l.from == index).count(), 1);
            }
        }
    }

    #[test]
    fn tree_conserves_value() {
        let (p, txs, _) = structured(Structure::Tree, 13, true);
        let set = p.exit_set(&txs.payout_amounts);
        let payouts: u64 = txs.payout_amounts.iter().sum();
        let fees: u64 = set.plans.iter().map(|x| x.fee).sum();
        let anchors = (p.peers as u64 - 1) * ANCHOR_VALUE;
        assert_eq!(set.pools[0], payouts + fees + anchors);
        for plan in &set.plans {
            assert!(plan.fee >= fee(plan.weight, plan.rate_milli));
        }
    }

    #[test]
    fn any_order_counts() {
        // sum over j < n - 2 of n! / (n - j)!, plus n! / 2 final exits
        for (n, count) in [(3, 6), (4, 28), (5, 145), (6, 876), (7, 6139)] {
            let mut p = params(n);
            p.structure = Structure::AnyOrder;
            p.validate().unwrap();
            let set = p.exit_set(&vec![10_000; n]);
            assert_eq!(set.plans.len(), count, "{n} peers");
            let finals = set
                .plans
                .iter()
                .filter(|x| {
                    x.outs.len() == 2 && x.outs.iter().all(|o| matches!(o, PlanOut::Payout { .. }))
                })
                .count();
            assert_eq!(finals, (1..=n).product::<usize>() / 2);
        }
    }

    #[test]
    fn structures_are_validated() {
        let mut p = params(8);
        p.structure = Structure::AnyOrder;
        assert!(
            p.validate().is_err(),
            "8 peers would need 49120 transactions"
        );
        let mut p = params(5);
        p.structure = Structure::AnyOrder;
        p.exits = vec![1, 2, 2];
        assert!(p.validate().is_err());
        let mut p = params(8);
        p.structure = Structure::Tree;
        p.fee_split = FeeSplit::ByExit;
        assert!(p.validate().is_err());
    }

    #[test]
    fn spec_example_amounts() {
        let a = params(5).amounts_single();
        assert_eq!(params(5).exit_share(), 247);
        assert_eq!(a.pools, vec![51235, 40927, 30619, 20311]);
        let fees: Vec<u64> = a.exits.iter().map(|e| e.fee).collect();
        assert_eq!(fees, vec![308, 308, 308, 311]);
        assert!(a
            .exits
            .iter()
            .all(|e| e.payouts.iter().all(|v| *v == 10_000)));
        let p2tr = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_hex(&format!("5120{}", "11".repeat(32))).unwrap(),
        };
        assert_eq!(
            params(5)
                .required(10_000, std::slice::from_ref(&p2tr), Some(&p2tr))
                .unwrap(),
            10470
        );
    }

    #[test]
    fn exit_weight_constant() {
        let spk = ScriptBuf::from_hex(&format!("5120{}", "22".repeat(32))).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin(OutPoint::null())],
            output: vec![
                TxOut {
                    value: Amount::ONE_SAT,
                    script_pubkey: spk.clone()
                };
                2
            ],
        };
        assert_eq!(exit_weight(&tx), EXIT_WEIGHT);
    }

    #[test]
    fn default_plan() {
        assert_eq!(default_exits(2), vec![2]);
        assert_eq!(default_exits(3), vec![1, 2]);
        assert_eq!(default_exits(5), vec![1, 1, 1, 2]);
    }

    fn plans() -> Vec<Params> {
        let mut v = Vec::new();
        for peers in [2, 3, 5, 8, 20, 100] {
            for (exits, split, anchor, rates) in [
                (default_exits(peers), FeeSplit::Equal, false, (2_000, 2_000)),
                (
                    default_exits(peers),
                    FeeSplit::ByExit,
                    true,
                    (10_000, 1_000),
                ),
                (vec![peers], FeeSplit::Equal, true, (1_500, 1_500)),
                (
                    {
                        let mut e = vec![1; peers / 3];
                        e.push(peers - peers / 3);
                        e
                    },
                    FeeSplit::ByExit,
                    false,
                    (3_000, 1_000),
                ),
            ] {
                let mut p = Params::new("plan", 50_000, peers, 2_000);
                p.exits = exits;
                p.fee_split = split;
                p.anchor = anchor;
                p.exit_rates_milli = rates;
                p.validate().unwrap();
                v.push(p);
            }
        }
        v
    }

    #[test]
    fn amounts_conserve_value_for_every_plan() {
        for p in plans() {
            let a = p.amounts_single();
            let anchor = if p.anchor { ANCHOR_VALUE } else { 0 };
            let out: u64 = a
                .exits
                .iter()
                .map(|e| e.payouts.iter().sum::<u64>() + anchor + e.fee)
                .sum();
            assert_eq!(out, a.pools[0], "{:?}", p.exits);
            assert_eq!(
                a.pools[0],
                p.peers as u64 * (p.classes[0].amount + p.exit_share())
            );
            for (j, e) in a.exits.iter().enumerate() {
                assert!(e.fee * 4000 >= e.weight * e.rate_milli);
                assert_eq!(e.pool.is_some(), j + 1 < a.exits.len());
                assert_eq!(e.payouts.len(), p.exits[j]);
                if p.fee_split == FeeSplit::Equal {
                    assert!(e.payouts.iter().all(|v| *v == p.classes[0].amount));
                }
            }
        }
    }

    #[test]
    fn by_exit_makes_earlier_exits_pay_more() {
        let mut p = Params::new("fees", 50_000, 6, 2_000);
        p.fee_split = FeeSplit::ByExit;
        p.exit_rates_milli = (10_000, 2_000);
        let a = p.amounts_single();
        let payouts: Vec<u64> = a.exits.iter().map(|e| e.payouts[0]).collect();
        assert!(payouts.windows(2).all(|w| w[0] <= w[1]), "{payouts:?}");
        assert!(payouts[0] < payouts[payouts.len() - 1]);
        assert_eq!(p.exit_share(), 0);
        assert_eq!(a.pools[0], 6 * 50_000);
        let rates: Vec<u64> = a.exits.iter().map(|e| e.rate_milli).collect();
        assert_eq!(rates, vec![10_000, 8_000, 6_000, 4_000, 2_000]);
    }

    #[test]
    fn every_plan_builds_and_checks() {
        for p in plans().into_iter().filter(|p| p.peers <= 20) {
            let (p, regs, payouts, keys) = pool_with(p, |i| i % 3 != 0, |i| i % 2 == 0);
            check_input_registrations(&p, &regs).unwrap();
            let txs = build(&p, &regs, &payouts, &keys).unwrap();
            check_txs(&p, &txs, &keys).unwrap();
            let a = p.amounts(&txs.payout_amounts);
            assert_eq!(txs.exits.len(), p.exits.len());
            for (j, tx) in txs.exits.iter().enumerate() {
                assert_eq!(exit_weight(tx), a.exits[j].weight);
                let anchors = tx
                    .output
                    .iter()
                    .filter(|o| o.script_pubkey == p2a_script())
                    .count();
                assert_eq!(anchors, usize::from(p.anchor));
                let paid = tx
                    .output
                    .iter()
                    .filter(|o| txs.payouts.contains(&o.script_pubkey))
                    .count();
                assert_eq!(paid, p.exits[j]);
            }
            let total_in: u64 = txs.funding_prevouts.iter().map(|o| o.value.to_sat()).sum();
            let total_out: u64 = txs.funding.output.iter().map(|o| o.value.to_sat()).sum();
            let weight = signed_weight(&txs.funding, &txs.funding_prevouts);
            assert!((total_in - total_out) * 4000 >= weight * p.fee_rate_milli);
        }
    }

    #[test]
    fn priority_comes_first() {
        let (p, _, mut payouts, _) = fake_pool(5);
        payouts[3].priority = 2;
        payouts[1].priority = 1;
        let order = payout_order(&p.id, &payouts);
        assert_eq!(order[0], payouts[3]);
        assert_eq!(order[1], payouts[1]);
        let mut shuffled = payouts.clone();
        shuffled.reverse();
        assert_eq!(payout_order(&p.id, &shuffled), order);
    }

    #[test]
    fn invalid_plans_are_rejected() {
        let mut p = Params::new("bad", 10_000, 5, 2_000);
        p.exits = vec![1, 1, 1];
        assert!(p.validate().is_err());
        p.exits = vec![0, 5];
        assert!(p.validate().is_err());
        p.exits = vec![5];
        assert!(p.validate().is_ok());
        let mut p = Params::new("bad", 1_000, 5, 2_000);
        p.fee_split = FeeSplit::ByExit;
        p.exit_rates_milli = (20_000, 20_000);
        assert!(p.validate().is_err(), "payouts would be dust");
    }

    #[test]
    fn build_is_deterministic_and_consistent() {
        for n in 2..=7 {
            let (p, regs, payouts, keys) = fake_pool(n);
            check_input_registrations(&p, &regs).unwrap();
            let a = build(&p, &regs, &payouts, &keys).unwrap();
            let mut shuffled = regs.clone();
            shuffled.reverse();
            let mut payouts2 = payouts.clone();
            payouts2.rotate_left(1);
            let b = build(&p, &shuffled, &payouts2, &keys).unwrap();
            assert_eq!(a.funding, b.funding);
            assert_eq!(a.exits, b.exits);
            check_txs(&p, &a, &keys).unwrap();
            assert_eq!(a.funding.lock_time, LockTime::from_height(1000).unwrap());
            assert_eq!(a.exits.len(), n - 1);
            for tx in &a.exits {
                assert_eq!(tx.version, Version::TWO);
                assert_eq!(tx.input[0].sequence, SEQUENCE);
                assert_eq!(exit_weight(tx), EXIT_WEIGHT);
            }
        }
    }

    #[test]
    fn no_change_funding_has_one_output() {
        let (p, regs, payouts, keys) = pool_with(params(4), |_| true, |_| false);
        check_input_registrations(&p, &regs).unwrap();
        let txs = build(&p, &regs, &payouts, &keys).unwrap();
        assert_eq!(txs.funding.output.len(), 1);
        assert_eq!(txs.funding.input.len(), 4);
    }

    #[test]
    fn check_txs_catches_tampering() {
        let (p, regs, payouts, keys) = fake_pool(4);
        let good = build(&p, &regs, &payouts, &keys).unwrap();
        check_txs(&p, &good, &keys).unwrap();
        let payout_vout = |tx: &Transaction| {
            tx.output
                .iter()
                .position(|o| good.payouts.contains(&o.script_pubkey))
                .unwrap()
        };
        let mut cases: Vec<(&str, PoolTxs)> = Vec::new();

        let mut t = good.clone();
        let v = payout_vout(&t.exits[0]);
        t.exits[0].output[v].value = Amount::from_sat(p.classes[0].amount - 1);
        cases.push(("payout below the denomination", t));

        let mut t = good.clone();
        let first = t.exits[0].output[payout_vout(&t.exits[0])]
            .script_pubkey
            .clone();
        let v = payout_vout(&t.exits[2]);
        t.exits[2].output[v].script_pubkey = first;
        cases.push(("one payout paid twice", t));

        let mut t = good.clone();
        t.funding.output[t.pool_vout as usize].script_pubkey = payouts[0].script.clone();
        cases.push(("funding pays someone else", t));

        let mut t = good.clone();
        let v = t.pool_vout as usize;
        t.funding.output[v].value = Amount::from_sat(good.funding.output[v].value.to_sat() - 1);
        cases.push(("pool output too small", t));

        let mut t = good.clone();
        t.exits.pop();
        t.spent.pop();
        cases.push(("missing final exit", t));

        let mut t = good.clone();
        t.exits[1].input[0].previous_output.vout ^= 1;
        cases.push(("exit spends the wrong output", t));

        let mut t = good.clone();
        t.funding.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        cases.push(("funding input with a script sig", t));

        let mut t = good.clone();
        t.exits[0].output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: payouts[1].script.clone(),
        });
        cases.push(("exit with a third output", t));

        let mut t = good.clone();
        t.exits[0].output.swap(0, 1);
        cases.push(("outputs out of order", t));

        let mut t = good.clone();
        t.payouts[1] = t.payouts[0].clone();
        cases.push(("payout list with a duplicate", t));

        for (name, t) in cases {
            assert!(check_txs(&p, &t, &keys).is_err(), "not caught: {name}");
        }
    }

    #[test]
    fn params_bounds() {
        let ok = |peers, rate, d| Params::new("b", d, peers, rate).validate().is_ok();
        assert!(ok(2, 1000, 330) && ok(MAX_PEERS, 1000, 330));
        assert!(!ok(1, 1000, 10_000));
        assert!(!ok(MAX_PEERS + 1, 1000, 10_000));
        assert!(!ok(3, 0, 10_000));
        assert!(!ok(3, 1000, 329));
    }

    #[test]
    fn registrations_must_be_distinct() {
        let (p, regs, _, _) = fake_pool(3);
        let mut r = regs.clone();
        r[1].musig = r[0].musig;
        assert!(check_input_registrations(&p, &r).is_err());
        let mut r = regs.clone();
        r[1].inputs = r[0].inputs.clone();
        assert!(check_input_registrations(&p, &r).is_err());
        let mut r = regs.clone();
        r[2].session = r[0].session;
        assert!(check_input_registrations(&p, &r).is_err());
        let mut r = regs.clone();
        r[1].change = r[0].change.clone();
        assert!(check_input_registrations(&p, &r).is_err());
        let mut r = regs.clone();
        r.pop();
        assert!(check_input_registrations(&p, &r).is_err());
        let mut r = regs;
        r[0].change.as_mut().unwrap().value = Amount::from_sat(100);
        assert!(check_input_registrations(&p, &r).is_err());
    }

    #[test]
    fn rejects_underpaying_peer() {
        let (p, mut regs, _, _) = fake_pool(3);
        let c = regs[1].change.as_mut().unwrap();
        c.value = Amount::from_sat(c.value.to_sat() + 1);
        assert!(check_input_registrations(&p, &regs).is_err());
    }

    #[test]
    fn rejects_legacy_input() {
        let (p, mut regs, _, _) = fake_pool(3);
        regs[0].inputs[0].1.script_pubkey =
            ScriptBuf::from_hex(&format!("76a914{}88ac", "66".repeat(20))).unwrap();
        assert!(check_input_registrations(&p, &regs).is_err());
    }

    #[test]
    fn locktime_is_the_smallest_height() {
        let (_, mut regs, _, _) = fake_pool(3);
        regs[1].height = 900;
        assert_eq!(locktime(&regs), 900);
    }

    fn two_classes(split: FeeSplit) -> Params {
        let mut p = Params::with_classes(
            "classes",
            vec![
                Class {
                    amount: 100_000,
                    peers: 3,
                },
                Class {
                    amount: 50_000,
                    peers: 4,
                },
            ],
            2_000,
        );
        p.fee_split = split;
        p.exit_rates_milli = (6_000, 2_000);
        p.validate().unwrap();
        p
    }

    #[test]
    fn classes_pay_their_own_denomination() {
        for split in [FeeSplit::Equal, FeeSplit::ByExit] {
            let (p, regs, payouts, keys) = pool_with(two_classes(split), |i| i % 2 == 0, |_| true);
            check_input_registrations(&p, &regs).unwrap();
            let txs = build(&p, &regs, &payouts, &keys).unwrap();
            check_txs(&p, &txs, &keys).unwrap();
            let a = p.amounts(&txs.payout_amounts);
            let mut j = 0;
            for e in &a.exits {
                for v in &e.payouts {
                    let class = txs.payout_amounts[j];
                    match split {
                        FeeSplit::Equal => assert_eq!(*v, class),
                        FeeSplit::ByExit => assert!(*v < class && *v > class - 5_000),
                    }
                    j += 1;
                }
            }
            let total: u64 = p.classes.iter().map(|c| c.amount * c.peers as u64).sum();
            assert_eq!(a.pools[0], total + p.peers as u64 * p.exit_share());
        }
    }

    #[test]
    fn classes_need_their_counts() {
        let (p, mut regs, _, _) = pool_with(two_classes(FeeSplit::Equal), |_| true, |_| true);
        check_input_registrations(&p, &regs).unwrap();
        regs[0].amount = 50_000;
        assert!(check_input_registrations(&p, &regs).is_err());
        let mut bad = Params::with_classes(
            "bad",
            vec![
                Class {
                    amount: 100_000,
                    peers: 4,
                },
                Class {
                    amount: 50_000,
                    peers: 1,
                },
            ],
            2_000,
        );
        assert!(
            bad.validate().is_err(),
            "a denomination of one peer has no privacy"
        );
        bad.classes[1].peers = 2;
        bad.peers = 6;
        bad.exits = default_exits(6);
        assert!(bad.validate().is_ok());
        bad.classes[1].amount = 100_000;
        assert!(bad.validate().is_err(), "denominations must differ");
    }
}
