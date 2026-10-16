//! S6 (review r1 §5; Tatara v0.10 §5.4, §8.7, §15.5): the limits, checked before a message is parsed further, and the
//! Phase 1 pool options — the phone refuses any other pool.

use anyhow::{bail, ensure, Result};
use joinstr_v2::msg::{Broadcast, PoolEvent};
use joinstr_v2::pool::{FeeSplit, Params, Structure};

/// LiJ pools: 3 to 6 people (DP 2026-10-12).
pub const MIN_PEOPLE: usize = 3;
pub const MAX_PEOPLE: usize = 6;
/// Inputs one member may register (a coin, or a few small ones).
pub const MAX_INPUTS_PER_MEMBER: usize = 4;
/// Bytes of one pool message before it is parsed. A Tatara pool's largest message (a registration of 4 inputs, or the
/// nonces of 5 exits) is a few kilobytes.
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024;
/// The lowest fee rate nodes relay (sat/vB).
pub const RELAY_MIN_SAT_VB: u64 = 1;
/// The most standard weight of a transaction nodes relay (400,000 WU); a LiJ funding of 6 × 4 inputs is far below it.
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// What the provider declared upfront in its signed registry record (v0.10 §11.2) and its start message.
#[derive(Clone, Debug)]
pub struct Declared {
    /// Pool sizes offered (sats).
    pub sizes: Vec<u64>,
    /// Fee-rate cap (sat/vB).
    pub max_fee_sat_vb: u64,
    /// The pool's relay, as named in the provider's start message.
    pub relay: String,
    /// The network's wire name as the public joinstr v2 code writes it (peer.rs network_name): "mainnet", "signet",
    /// "testnet", "regtest". v347: the engine named mainnet "bitcoin" (rust-bitcoin's word) and the public code's
    /// "mainnet" pools were refused as "another network", and ours by them; `wire_network` maps either spelling.
    pub network: String,
    /// The latest a pool may run to, in seconds from now.
    pub max_timeout_s: u64,
}

/// A raw pool message is refused before parsing when it is larger than any honest Tatara message.
pub fn message_size(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_MESSAGE_BYTES, "pool message of {} bytes (cap {MAX_MESSAGE_BYTES})", bytes.len());
    Ok(())
}

/// v347 (S59 Thu, DP 2026-10-15 17:56 — the relay listing that named no network of ours): the network's WIRE NAME. The
/// public joinstr v2 code writes "mainnet" for Bitcoin (its peer.rs network_name) and refuses a pool whose `network`
/// differs; this engine and the adapter wrote rust-bitcoin's "bitcoin" — so a Joinstr user's mainnet pool was
/// "another network" to us and our rooms to them. Either spelling of mainnet reads as "mainnet"; the rest unchanged.
pub fn wire_network(name: &str) -> &str {
    match name { "bitcoin" | "mainnet" | "main" => "mainnet", other => other }
}

/// The Phase 1 pool options (v0.10 §5.4): one denomination among the declared sizes; a chain; equal fee split; one fee
/// rate, whole sat/vB, between the relay minimum and the declared cap; broadcast now; no anchor; the default exit plan;
/// no Tor or VPN transport; the declared network and relay; 3–6 people; a timeout within the declared window. Anything
/// else: not a LiJ pool, the phone does not join. `ev` comes from `PoolEvent::parse_strict` (P8).
pub fn phase1_pool(ev: &PoolEvent, d: &Declared, now_s: u64) -> Result<Params> {
    ensure!(ev.versions == vec!["2".to_string()], "versions must be [\"2\"]");
    ensure!(ev.kind == "new_pool", "not a new pool");
    ensure!(wire_network(&ev.network) == wire_network(&d.network), "pool for another network");
    ensure!((MIN_PEOPLE..=MAX_PEOPLE).contains(&ev.peers), "a LiJ pool has 3 to 6 people");
    ensure!(d.sizes.contains(&ev.denomination), "pool size {} not declared", ev.denomination);
    ensure!(ev.denominations.is_none(), "one denomination only");
    ensure!(ev.exits.is_none(), "the default exit plan only");
    ensure!(ev.exit_fee_rates.is_none(), "one fee rate for the funding and every exit");
    ensure!(ev.fee_split == FeeSplit::Equal, "equal fee split only");
    ensure!(ev.structure == Structure::Chain, "a chain only");
    ensure!(ev.broadcast == Broadcast::Now, "broadcast now only");
    ensure!(ev.anchor.is_none(), "no anchor (v0.10 §6.4)");
    ensure!(!ev.transport.tor.enable && !ev.transport.vpn.enable, "no Tor or VPN transport in Phase 1");
    ensure!(ev.relays == vec![d.relay.clone()], "the pool must use the declared relay");
    // v335 (S59, DP 2026-10-14 11:50 "why are we limiting to integer fee rates if we already have sub-integer fee rates in
    // practice in the wallet"): a fraction is a pool option like any other — the builders work in thousandths of a
    // sat/vB (P6 milli), the public code's pools carry fractions (its default demo runs at 1.5); the limit is the cap,
    // the floor the relay minimum.
    let rate = ev.fee_rate;
    ensure!(rate.is_finite() && ((rate * 1000.0) - (rate * 1000.0).round()).abs() < 1e-6, "fee rate must be a whole number of thousandths of a sat/vB");
    ensure!(
        rate >= RELAY_MIN_SAT_VB as f64 && rate <= d.max_fee_sat_vb as f64,
        "fee rate {rate} outside {RELAY_MIN_SAT_VB}..={} sat/vB",
        d.max_fee_sat_vb
    );
    ensure!(ev.timeout > now_s && ev.timeout <= now_s.saturating_add(d.max_timeout_s), "timeout outside the window");
    let p = ev.params()?;
    // the parse must have given exactly the options above
    if p.peers != ev.peers || p.classes.len() != 1 || p.exit_rates_milli.0 != p.fee_rate_milli || p.exit_rates_milli.1 != p.fee_rate_milli || p.anchor {
        bail!("pool options parsed to something else");
    }
    Ok(p)
}

/// v335: the same limit for a pool's rate with a fraction — compared in thousandths.
pub fn within_fee_limit_milli(pool_rate_milli: u64, shown_at_join_sat_vb: u64, cap_sat_vb: u64) -> bool {
    let limit = shown_at_join_sat_vb.saturating_mul(1500);
    pool_rate_milli <= limit && pool_rate_milli <= cap_sat_vb.saturating_mul(1000)
}

/// The fee limit (v0.10 §8.7, D6): the pool's rate may be at most 1.5 × the rate shown when the person joined, and
/// never above the declared cap.
pub fn within_fee_limit(pool_rate_sat_vb: u64, shown_at_join_sat_vb: u64, cap_sat_vb: u64) -> bool {
    let limit = shown_at_join_sat_vb.saturating_mul(3) / 2;
    pool_rate_sat_vb <= limit.max(shown_at_join_sat_vb) && pool_rate_sat_vb <= cap_sat_vb
}

/// A registration's inputs: 1 to `MAX_INPUTS_PER_MEMBER`.
pub fn registration_inputs(count: usize) -> Result<()> {
    ensure!((1..=MAX_INPUTS_PER_MEMBER).contains(&count), "a member registers 1 to {MAX_INPUTS_PER_MEMBER} inputs");
    Ok(())
}

/// One nonce and one partial signature per exit, exactly.
pub fn one_per_exit(got: usize, exits: usize) -> Result<()> {
    ensure!(got == exits, "{got} items for {exits} exits");
    Ok(())
}
