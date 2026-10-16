//! Whole pools of 3–6 phones running the machine against each other through an in-memory relay (tatara-engine-r1
//! "Tests"), and the stops the rules require.

use std::collections::VecDeque;

use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut, Txid, Witness};
use joinstr_v2::funding::verify_input;
use joinstr_v2::msg::{Envelope, Msg};
use joinstr_v2::pool::Params;
use musig2::secp::Scalar;

use super::machine::{Action, Attempt, Input, MyPart, Phase, Timeouts};
use super::tagged;

fn sk(label: &str, i: u32) -> SecretKey {
    SecretKey::from_slice(&tagged("lij/test/machine", &[label.as_bytes(), &i.to_le_bytes()])).unwrap()
}
fn scalar(label: &str, i: u32) -> Scalar {
    Scalar::from_slice(&sk(label, i).secret_bytes()).unwrap()
}
fn p2tr_of(k: &SecretKey) -> ScriptBuf {
    let secp = Secp256k1::new();
    let (x, _) = k.public_key(&secp).x_only_public_key();
    Address::p2tr(&secp, x, None, Network::Bitcoin).script_pubkey()
}
fn p2wpkh_of(k: &SecretKey) -> ScriptBuf {
    let secp = Secp256k1::new();
    Address::p2wpkh(&CompressedPublicKey(k.public_key(&secp)), Network::Bitcoin).script_pubkey()
}
/// A channel's funding script: the 2-of-2 of this phone's funding key and the provider's (BOLT 3), as P2WSH.
fn p2wsh_of(i: u32) -> ScriptBuf {
    let secp = Secp256k1::new();
    let mut keys = [sk("fund-phone", i).public_key(&secp), sk("fund-provider", i).public_key(&secp)];
    keys.sort_by_key(|k| k.serialize());
    let redeem = bitcoin::blockdata::script::Builder::new()
        .push_int(2)
        .push_key(&bitcoin::PublicKey::new(keys[0]))
        .push_key(&bitcoin::PublicKey::new(keys[1]))
        .push_int(2)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    ScriptBuf::new_p2wsh(&redeem.wscript_hash())
}

const D: u64 = 100_000;
const RATE: u64 = 2;

fn session(i: u32) -> [u8; 32] {
    tagged("lij/test/session", &[&i.to_le_bytes()])
}

pub(super) fn my_part(i: u32) -> MyPart {
    let coin_key = sk("coin", i);
    let spk = if i % 2 == 0 { p2tr_of(&coin_key) } else { p2wpkh_of(&coin_key) };
    let op = OutPoint::new(Txid::from_byte_array(tagged("lij/test/coin", &[&i.to_le_bytes()])), i % 2);
    MyPart {
        coins: vec![(op, TxOut { value: Amount::from_sat(D + 20_000), script_pubkey: spk }, coin_key)],
        change: Some(TxOut { value: Amount::from_sat(15_000 + i as u64), script_pubkey: p2wpkh_of(&sk("change", i)) }),
        tip: 970_000 + i % 3,
        payout: Some(p2tr_of(&sk("payout", i))),
        session: session(i),
        musig: scalar("musig", i),
        ring: scalar("ring", i),
        entropy: tagged("lij/test/entropy", &[&i.to_le_bytes()]),
        rate_at_join: RATE,
    }
}

/// A test relay: what each phone posts reaches every phone; a payout arrives under a one-time key; coin checks and
/// record saves are answered at once (unless a test says otherwise).
struct Net {
    phones: Vec<Attempt>,
    queue: VecDeque<(usize, Input)>,
    funding_sigs: Vec<String>,
    stops: Vec<(usize, String, Vec<[u8; 32]>)>,
    signed: Vec<usize>,
    /// Rewrite a phone's outgoing post (by phone index) — the tests' dishonest member.
    tamper: Option<Box<dyn Fn(usize, &str) -> Option<Vec<String>>>>,
    bad_coins: Vec<OutPoint>,
    one_time: u32,
    /// Answer every coin check and record save twice (a page that repeats itself).
    double: bool,
    /// Phase 1b: the channel pool's page — which phones opened a channel, which exits fund them; a page that never
    /// opens the channel, or a provider whose signature never comes.
    opened: Vec<usize>,
    funded: Vec<(usize, String, u32)>,
    /// The pool's exits, from the records the phones save (every phone saves the same).
    exits: Vec<bitcoin::Transaction>,
    no_channel: bool,
    no_signature: bool,
}

impl Net {
    fn new(n: usize) -> Net {
        let id = hex::encode(&tagged("lij/test/pool", &[&(n as u32).to_le_bytes()])[..16]);
        let params = Params::new(&id, D, n, RATE * 1000);
        Net::with(n, false)
    }

    /// `channel`: a channel pool (P1 payout_type p2wsh; every phone's payout comes from the page's channel open).
    fn with(n: usize, channel: bool) -> Net {
        let id = hex::encode(&tagged("lij/test/pool", &[&(n as u32).to_le_bytes()])[..16]);
        let mut params = Params::new(&id, D, n, RATE * 1000);
        if channel { params.payout_type = joinstr_v2::pool::PayoutType::P2wsh; }
        let mut net = Net { phones: vec![], queue: VecDeque::new(), funding_sigs: vec![], stops: vec![], signed: vec![], tamper: None, bad_coins: vec![], one_time: 0, double: false, opened: vec![], funded: vec![], exits: vec![], no_channel: false, no_signature: false };
        let mut first = Vec::new();
        for i in 0..n {
            let mut me = my_part(i as u32);
            if channel { me.payout = None; }
            let (a, acts) = Attempt::new(params.clone(), Network::Bitcoin, me, 1_000, Timeouts { phase_s: 600 }).unwrap();
            net.phones.push(a);
            first.push((i, acts));
        }
        for (i, acts) in first {
            net.act(i, acts);
        }
        net
    }

    fn deliver_all(&mut self, from: [u8; 32], json: &str) {
        for j in 0..self.phones.len() {
            self.queue.push_back((j, Input::Msg { from, json: json.to_string() }));
        }
    }

    fn act(&mut self, i: usize, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Post(json) => {
                    let outs = match &self.tamper {
                        Some(t) => t(i, &json).unwrap_or_else(|| vec![json.clone()]),
                        None => vec![json.clone()],
                    };
                    for o in outs {
                        if o.contains("\"funding_sigs\"") {
                            self.funding_sigs.push(o.clone());
                        }
                        self.deliver_all(session(i as u32), &o);
                    }
                }
                Action::PostPayout(json) => {
                    let outs = match &self.tamper {
                        Some(t) => t(i, &json).unwrap_or_else(|| vec![json.clone()]),
                        None => vec![json.clone()],
                    };
                    for o in outs {
                        self.one_time += 1;
                        let k = tagged("lij/test/one-time", &[&self.one_time.to_le_bytes()]);
                        self.deliver_all(k, &o);
                    }
                }
                Action::CheckCoins(coins) => {
                    let bad: Vec<OutPoint> = coins.iter().map(|(op, _)| *op).filter(|op| self.bad_coins.contains(op)).collect();
                    if self.double {
                        self.queue.push_back((i, Input::CoinsChecked { bad: bad.clone(), unanswered: vec![] }));
                    }
                    self.queue.push_back((i, Input::CoinsChecked { bad, unanswered: vec![] }));
                }
                Action::SaveRecord(rec) => {
                    if self.exits.is_empty() { self.exits = rec.exits.clone(); }
                    if self.double {
                        self.queue.push_back((i, Input::RecordSaved));
                    }
                    self.queue.push_back((i, Input::RecordSaved));
                }
                Action::FundingSigned => self.signed.push(i),
                Action::Stopped { reason, named } => self.stops.push((i, reason, named)),
                Action::OpenChannel { sats } => {
                    // the channel pool's page: a channel of the pool size opened with the provider; its 2-of-2 is the payout
                    assert_eq!(sats, D);
                    self.opened.push(i);
                    if !self.no_channel {
                        self.queue.push_back((i, Input::PayoutGiven(p2wsh_of(i as u32))));
                    }
                }
                Action::FundChannel { txid, vout } => {
                    self.funded.push((i, txid, vout));
                    if !self.no_signature {
                        self.queue.push_back((i, Input::ChannelSaved));
                    }
                }
            }
        }
    }

    /// v335: every phone takes the pool as public (other joinstr clients at the table — machine.rs `public`).
    fn public(mut self) -> Net {
        self.phones = self.phones.drain(..).map(|p| p.public(true)).collect();
        self
    }

    fn run(&mut self) {
        let mut steps = 0;
        while let Some((j, input)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 100_000, "the pool does not settle");
            let acts = self.phones[j].on(input);
            self.act(j, acts);
        }
    }
}

#[test]
fn whole_pools_of_3_to_6_reach_funding_signed_and_the_funding_is_valid() {
    for n in 3..=6 {
        let mut net = Net::new(n);
        net.run();
        assert!(net.stops.is_empty(), "n={n}: stops {:?}", net.stops);
        assert_eq!(net.signed.len(), n, "n={n}: every phone signed its funding");
        assert!(net.phones.iter().all(|p| *p.phase() == Phase::FundingSigned));
        // assemble the funding transaction from every member's witnesses and check every input's signature
        let hexes: Vec<String> = net.phones.iter().map(|p| p.funding_hex().unwrap()).collect();
        assert!(hexes.windows(2).all(|w| w[0] == w[1]), "n={n}: every phone built the same funding");
        let mut tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hexes[0]).unwrap();
        let mut prevouts = Vec::new();
        for i in &tx.input {
            let owner = (0..n as u32).find(|k| my_part(*k).coins[0].0 == i.previous_output).unwrap();
            prevouts.push(my_part(owner).coins[0].1.clone());
        }
        for js in &net.funding_sigs {
            let env = Envelope::parse_strict(js).unwrap();
            let Msg::FundingSigs { witnesses } = env.msg else { panic!() };
            for w in witnesses {
                let idx = tx.input.iter().position(|i| i.previous_output.txid.to_string() == w.txid && i.previous_output.vout == w.vout).unwrap();
                tx.input[idx].witness = Witness::from_slice(&w.witness.iter().map(|h| hex::decode(h).unwrap()).collect::<Vec<_>>());
            }
        }
        for idx in 0..tx.input.len() {
            verify_input(&tx, idx, &prevouts, &tx.input[idx].witness.clone()).unwrap();
        }
    }
}

/// Phase 1b (v0.10 §6.2, P1): a channel pool of 3–6 — every phone is asked to open a channel of the pool size once
/// registration is complete, registers the channel's 2-of-2 (P2WSH) as its payout, is told the exit and output that
/// fund its channel (exactly its script, exactly the size), and signs its coin only after the channel is saved.
#[test]
fn c1_a_channel_pool_opens_a_channel_per_phone_funds_it_from_its_exit_and_signs_after_the_channel_is_saved() {
    for n in 3..=6 {
        let mut net = Net::with(n, true);
        net.run();
        assert!(net.stops.is_empty(), "n={n}: stops {:?}", net.stops);
        assert_eq!(net.signed.len(), n, "n={n}: every phone signed its funding");
        let mut opened = net.opened.clone(); opened.sort();
        assert_eq!(opened, (0..n).collect::<Vec<_>>(), "n={n}: every phone opened one channel");
        assert_eq!(net.funded.len(), n, "n={n}: every phone was told the exit that funds its channel");
        // the exit named for each phone pays its 2-of-2 exactly the pool size at that output
        let hexes: Vec<String> = net.phones.iter().map(|p| p.funding_hex().unwrap()).collect();
        assert!(hexes.windows(2).all(|w| w[0] == w[1]), "n={n}: every phone built the same funding");
        let funding: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hexes[0]).unwrap();
        for (i, txid, vout) in &net.funded {
            let exit = net.exits.iter().find(|e| e.compute_txid().to_string() == *txid).unwrap_or_else(|| panic!("n={n}: phone {i}'s exit {txid} is one of the pool's"));
            let o = &exit.output[*vout as usize];
            assert_eq!((o.script_pubkey.clone(), o.value.to_sat()), (p2wsh_of(*i as u32), D), "n={n}: phone {i}'s channel is paid exactly the pool size");
        }
        // the first exit spends the funding's pool output: the channels are funded from the pool, not from anyone's coin
        let pool_vout = funding.output.iter().position(|o| o.value.to_sat() > D).unwrap();
        assert!(net.exits.iter().any(|e| e.input[0].previous_output == OutPoint::new(funding.compute_txid(), pool_vout as u32)), "n={n}: an exit spends the pool output");
    }
}

/// §6.2.4: the provider's first-commitment signature never arrives — the phone stops before its coin signature;
/// nothing moved; the stop says so and names no one.
#[test]
fn c2_a_channel_whose_provider_signature_never_comes_stops_before_the_coin_signature() {
    let mut net = Net::with(3, true);
    net.no_signature = true;
    net.run();
    assert!(net.signed.is_empty(), "no phone signed its coin");
    assert!(net.stops.is_empty(), "nothing stopped yet: every phone waits at Funding");
    assert!(net.phones.iter().all(|p| *p.phase() == Phase::Funding));
    // the clock: past the phase's deadline every phone stops with the channel's words, blaming nobody
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 2_000 })); }
    net.run();
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 3_000 })); }
    net.run();
    assert_eq!(net.stops.len(), 3);
    assert!(net.stops.iter().all(|(_, r, named)| r == "the provider's channel signature did not arrive in time" && named.is_empty()), "{:?}", net.stops);
    assert!(net.signed.is_empty());
}

/// P1: the payout's type is the pool's — a P2TR payout in a channel pool, or a P2WSH one in an on-chain pool, stops
/// the pool; a page that never opens the channel stops at the Channel phase's deadline.
#[test]
fn c3_a_payout_of_the_wrong_type_stops_the_pool_and_an_unopened_channel_times_out() {
    // a channel pool whose phone 1 registers a P2TR payout
    let mut net = Net::with(3, true);
    let wrong = p2tr_of(&sk("payout", 1));
    net.tamper = Some(Box::new(move |i, json| {
        if i != 1 || !json.contains("\"output\"") { return None; }
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["address"] = serde_json::Value::String(Address::from_script(&wrong, Network::Bitcoin).unwrap().to_string());
        Some(vec![v.to_string()])
    }));
    net.run();
    // v340 (finding 1): a wrong-type payout comes under an anonymous one-time key — it is IGNORED (not a stop anyone could
    // trigger at will); the pool then waits out the Payouts clock with nobody named
    assert!(net.stops.is_empty() && net.signed.is_empty(), "the wrong payout is ignored: {:?}", net.stops);
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 2_000 })); }
    net.run();
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 3_000 })); }
    net.run();
    assert!(net.stops.len() == 3 && net.stops.iter().all(|(_, r, named)| r.contains("timed out at Payouts") && named.is_empty()), "{:?}", net.stops);
    assert!(net.signed.is_empty());
    // an on-chain pool whose phone 1 registers a P2WSH payout
    let mut net = Net::new(3);
    let wrong = p2wsh_of(1);
    net.tamper = Some(Box::new(move |i, json| {
        if i != 1 || !json.contains("\"output\"") { return None; }
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["address"] = serde_json::Value::String(Address::from_script(&wrong, Network::Bitcoin).unwrap().to_string());
        Some(vec![v.to_string()])
    }));
    net.run();
    assert!(net.stops.is_empty(), "ignored, as above: {:?}", net.stops);
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 2_000 })); }
    net.run();
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 3_000 })); }
    net.run();
    assert!(net.stops.iter().all(|(_, r, named)| r.contains("timed out at Payouts") && named.is_empty()) && net.stops.len() == 3, "{:?}", net.stops);
    // a page that never opens the channel
    let mut net = Net::with(3, true);
    net.no_channel = true;
    net.run();
    assert!(net.phones.iter().all(|p| *p.phase() == Phase::Channel), "every phone waits for its channel");
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 2_000 })); }
    net.run();
    for j in 0..3 { net.queue.push_back((j, Input::Tick { now: 3_000 })); }
    net.run();
    assert!(net.stops.len() == 3 && net.stops.iter().all(|(_, r, named)| r == "the channel could not be opened in time" && named.is_empty()), "{:?}", net.stops);
    // a channel pool must take its payout from the channel, an on-chain pool must bring one
    let id = "ab".repeat(8);
    let mut params = Params::new(&id, D, 3, RATE * 1000);
    params.payout_type = joinstr_v2::pool::PayoutType::P2wsh;
    assert!(Attempt::new(params.clone(), Network::Bitcoin, my_part(0), 1_000, Timeouts { phase_s: 600 }).is_err(), "a channel pool with a brought payout");
    let mut me = my_part(0); me.payout = None;
    assert!(Attempt::new(Params::new(&id, D, 3, RATE * 1000), Network::Bitcoin, me, 1_000, Timeouts { phase_s: 600 }).is_err(), "an on-chain pool without a payout");
}

#[test]
fn s2_two_payouts_under_one_key_image_stop_everyone_and_name_no_one() {
    let mut net = Net::new(4);
    // member 1 registers a second, different payout under its own ring key
    net.tamper = Some(Box::new(|i, json| {
        if i != 1 || !json.contains("\"output\"") {
            return None;
        }
        let env = Envelope::parse_strict(json).unwrap();
        let Msg::Output { ring_sig: _, .. } = env.msg else { return None };
        // sign a second payout with member 1's ring key over the same ring: rebuild from the registrations' ring keys
        let mut ring: Vec<musig2::secp::Point> = (0..4).map(|k| scalar("ring", k).base_point_mul()).collect();
        ring.sort_by_key(|p| p.serialize());
        let other = p2tr_of(&sk("payout-b", 1));
        let id = hex::encode(&tagged("lij/test/pool", &[&4u32.to_le_bytes()])[..16]);
        let sig = joinstr_v2::ring::sign(&ring, scalar("ring", 1), &joinstr_v2::pool::payout_msg(&id, 0, D, &other), &[9u8; 32]).unwrap();
        let second = Envelope::json(Msg::Output { address: Address::from_script(&other, Network::Bitcoin).unwrap().to_string(), ring_sig: sig, priority: 0, denomination: Some(D) });
        Some(vec![json.to_string(), second])
    }));
    net.run();
    assert!(net.signed.is_empty(), "nobody signs");
    assert!(!net.stops.is_empty() && net.stops.iter().all(|(_, r, named)| r.contains("key image") && named.is_empty()), "{:?}", net.stops);
}

#[test]
fn s3_a_member_whose_view_differs_stops_the_pool_and_is_not_named() {
    let mut net = Net::new(3);
    net.tamper = Some(Box::new(|i, json| {
        if i == 2 && json.contains("\"lij_view\"") {
            Some(vec![serde_json::json!({ "version": "2", "type": "lij_view", "hash": "ab".repeat(32) }).to_string()])
        } else {
            None
        }
    }));
    net.run();
    assert!(net.signed.is_empty());
    let others: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(!others.is_empty() && others.iter().all(|(_, r, named)| r.contains("same pool") && named.is_empty()), "{:?}", net.stops);
}

// ── v335 (S59, Phase 2): public pools — members who send no `lij_view` ──────────────────────────────────────────────

/// Member 2 is a public joinstr client: it never sends a view. A LiJ pool waits for it (nobody signs); a public pool
/// signs on every member's nonces, with S3 covering the views that came.
#[test]
fn s3_a_public_pool_signs_without_a_view_from_its_public_members_a_lij_pool_waits() {
    let drop_view = || -> Box<dyn Fn(usize, &str) -> Option<Vec<String>>> { Box::new(|i, json| if i == 2 && json.contains("\"lij_view\"") { Some(vec![]) } else { None }) };
    let mut lij = Net::new(3);
    lij.tamper = Some(drop_view());
    lij.run();
    assert!(lij.signed.is_empty() && lij.stops.is_empty(), "a LiJ pool waits at View for member 2's view: {:?}", lij.stops);
    let mut pub_ = Net::new(3).public();
    pub_.tamper = Some(drop_view());
    pub_.run();
    assert_eq!(pub_.signed.len(), 3, "every member signs the funding: {:?}", pub_.stops);
    assert!(pub_.stops.is_empty());
}

/// v338: a public room's registration phase lasts until the deadline it was given (the announcement's timeout + one
/// step), not PHASE_S; the later phases keep the phase clock.
#[test]
fn s3_a_public_rooms_registration_phase_waits_until_its_own_deadline() {
    let id = hex::encode(&tagged("lij/test/pool", &[&7u32.to_le_bytes()])[..16]);
    let params = Params::new(&id, D, 3, RATE * 1000);
    let (lone, _) = Attempt::new(params.clone(), Network::Bitcoin, my_part(0), 1_000, Timeouts { phase_s: 600 }).unwrap();
    let mut lone = lone.public(true).first_phase_until(5_000);
    assert!(lone.on(Input::Tick { now: 1_700 }).is_empty(), "past PHASE_S, still waiting");
    assert!(lone.on(Input::Tick { now: 4_900 }).is_empty());
    let acts = lone.on(Input::Tick { now: 5_001 });
    assert!(acts.iter().any(|a| matches!(a, Action::Stopped { reason, .. } if reason.contains("timed out at Inputs"))), "{acts:?}");
    // a shorter deadline than the phase clock changes nothing
    let (lone2, _) = Attempt::new(params, Network::Bitcoin, my_part(0), 1_000, Timeouts { phase_s: 600 }).unwrap();
    let mut lone2 = lone2.public(true).first_phase_until(1_100);
    assert!(lone2.on(Input::Tick { now: 1_500 }).is_empty(), "the phase clock (1_600) still stands");
}

/// v339: a member leaves on purpose — before its signature the others hear an abort and stop (no one named); after the
/// funding signature a leave does nothing.
#[test]
fn a_member_who_leaves_stops_the_pool_for_everyone_and_names_no_one_but_cannot_leave_once_signed() {
    let mut net = Net::new(3).public();
    net.tamper = Some(Box::new(|i, json| if i == 2 && json.contains("\"nonces\"") { Some(vec![]) } else { None }));   // member 2 holds the pool at View
    net.run();
    assert!(net.signed.is_empty() && net.stops.is_empty());
    let acts = net.phones[2].on(Input::Leave);
    assert!(acts.iter().any(|a| matches!(a, Action::Post(j) if j.contains("\"abort\""))), "the abort goes out: {acts:?}");
    assert!(acts.iter().any(|a| matches!(a, Action::Stopped { reason, named } if reason.contains("left") && named.is_empty())));
    net.act(2, acts); net.run();
    let others: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(others.len() == 2 && others.iter().all(|(_, r, n)| r.contains("a member stopped the pool") && n.is_empty()), "{:?}", net.stops);
    // once signed: a leave is nothing
    let mut done = Net::new(3);
    done.run();
    assert_eq!(done.signed.len(), 3);
    assert!(done.phones[0].on(Input::Leave).is_empty(), "no leaving after the coin signature");
}

/// v340 (S59 security review, finding 1): a malformed message from a key that is not a registered session is ignored,
/// never a stop; a registered member's malformed message stops the pool naming THAT member.
#[test]
fn a_malformed_message_from_a_stranger_is_ignored_and_from_a_member_is_named() {
    let mut net = Net::new(3).public();
    net.run();
    assert_eq!(net.signed.len(), 3);
    let mut fresh = Net::new(3);
    fresh.tamper = Some(Box::new(|i, json| if i == 2 && json.contains("\"nonces\"") { Some(vec![]) } else { None }));
    fresh.run();   // everyone waits at View
    assert!(fresh.stops.is_empty());
    // a stranger (not registered) with the pool key: garbage of every kind
    for bad in ["{\"version\":\"9\"}", "not json", "{\"version\":\"2\",\"type\":\"nonces\",\"nonces\":[\"zz\"]}"] {
        for j in 0..3 { let acts = fresh.phones[j].on(Input::Msg { from: session(77), json: bad.into() }); assert!(acts.is_empty(), "ignored: {acts:?}"); }
    }
    assert!(fresh.stops.is_empty(), "a stranger cannot stop the pool");
    // a registered member's garbage names that member
    let acts = fresh.phones[0].on(Input::Msg { from: session(2), json: "{\"version\":\"9\"}".into() });
    assert!(acts.iter().any(|a| matches!(a, Action::Stopped { named, .. } if *named == vec![session(2)])), "{acts:?}");
}

/// v340 (finding 2): funding signatures are taken only from the member that registered the input and only when they
/// verify against the funding we built; an outsider's, or a wrong one, never reaches the complete funding.
#[test]
fn funding_signatures_are_verified_and_bound_to_their_owner() {
    // the phone-level test lives in phone.rs (p6_…); here: the machine's owns()
    let mut net = Net::new(3);
    net.run();
    assert_eq!(net.signed.len(), 3);
    let p0 = &net.phones[0];
    let my = my_part(0).coins[0].0;
    assert!(p0.owns(&session(0), &my));
    assert!(!p0.owns(&session(1), &my), "another member does not own my input");
    assert!(!p0.owns(&session(77), &my), "a stranger owns nothing");
}

/// A LiJ member's view still counts in a public pool: a different hash stops the pool, no one named.
#[test]
fn s3_a_public_pool_still_stops_on_a_lij_members_differing_view() {
    let mut net = Net::new(3).public();
    net.tamper = Some(Box::new(|i, json| {
        if i == 2 && json.contains("\"lij_view\"") {
            Some(vec![serde_json::json!({ "version": "2", "type": "lij_view", "hash": "ab".repeat(32) }).to_string()])
        } else {
            None
        }
    }));
    net.run();
    assert!(net.signed.is_empty());
    let others: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(!others.is_empty() && others.iter().all(|(_, r, named)| r.contains("same pool") && named.is_empty()), "{:?}", net.stops);
}

/// In a public pool a partial signature that does not verify stops the pool and names no one (the public members
/// never confirmed their view, so a bad signature cannot be told from a different view); a View timeout names only
/// the members whose nonces are missing.
#[test]
fn s3_a_public_pools_bad_partial_signature_names_no_one() {
    let mut net = Net::new(4).public();
    net.tamper = Some(Box::new(|i, json| {
        if json.contains("\"lij_view\"") && i != 0 {
            return Some(vec![]);   // members 1–3 are public clients
        }
        if i != 3 || !json.contains("\"partial_sigs\"") {
            return None;
        }
        let env = Envelope::parse_strict(json).unwrap();
        let Msg::PartialSigs { offset, mut sigs } = env.msg else { return None };
        sigs.swap(0, 1);
        Some(vec![Envelope::json(Msg::PartialSigs { offset, sigs })])
    }));
    net.run();
    assert!(net.signed.is_empty(), "nobody signs the funding");
    let stops: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 3).collect();
    assert!(!stops.is_empty() && stops.iter().all(|(_, r, n)| r.contains("partial signature") && n.is_empty()), "{:?}", net.stops);
    // the timeout: a public member that withheld its nonces is still named; one that sent them but no view is not
    let mut late = Net::new(3).public();
    late.tamper = Some(Box::new(|i, json| if (i == 2 && json.contains("\"nonces\"")) || (i == 1 && json.contains("\"lij_view\"")) { Some(vec![]) } else { None }));
    late.run();
    assert!(late.signed.is_empty() && late.stops.is_empty());
    for j in 0..3 {
        let acts = late.phones[j].on(Input::Tick { now: 5_000 });
        late.act(j, acts);
        let acts = late.phones[j].on(Input::Tick { now: 5_700 });
        late.act(j, acts);
    }
    let others: Vec<_> = late.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(others.len() == 2 && others.iter().all(|(_, r, n)| r.contains("timed out at View") && *n == vec![session(2)]), "{:?}", late.stops);
}

#[test]
fn p7_a_bad_partial_signature_is_named() {
    let mut net = Net::new(4);
    // member 3 sends member 3's own signatures for exit 1 twice over (the second list's first entry replaced)
    net.tamper = Some(Box::new(|i, json| {
        if i != 3 || !json.contains("\"partial_sigs\"") {
            return None;
        }
        let env = Envelope::parse_strict(json).unwrap();
        let Msg::PartialSigs { offset, mut sigs } = env.msg else { return None };
        sigs.swap(0, 1);
        Some(vec![Envelope::json(Msg::PartialSigs { offset, sigs })])
    }));
    net.run();
    assert!(net.signed.is_empty(), "nobody signs the funding");
    let named: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 3).collect();
    assert!(!named.is_empty() && named.iter().all(|(_, r, n)| r.contains("partial signature") && *n == vec![session(3)]), "{:?}", net.stops);
}

#[test]
fn s1_an_outsiders_messages_are_ignored() {
    let mut net = Net::new(3);
    let outsider = tagged("lij/test/outsider", &[]);
    // before anything: an outsider's nonces, partial signatures and abort
    net.deliver_all(outsider, &Envelope::json(Msg::Nonces { offset: 0, nonces: vec!["02".repeat(66)] }));
    net.deliver_all(outsider, &Envelope::json(Msg::Abort { reason: "<script>".into() }));
    net.run();
    assert!(net.stops.is_empty(), "{:?}", net.stops);
    assert_eq!(net.signed.len(), 3, "the pool still completes");
}

#[test]
fn a_coin_that_fails_the_check_stops_the_pool_and_names_its_owner() {
    let mut net = Net::new(3);
    // mark member 2's coin bad before the coin checks are answered
    net.bad_coins.push(my_part(2).coins[0].0);
    net.run();
    assert!(net.signed.is_empty());
    let others: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(!others.is_empty() && others.iter().all(|(_, _, named)| *named == vec![session(2)]), "{:?}", net.stops);
}

#[test]
fn a_second_different_registration_and_a_timeout_stop_the_attempt() {
    let mut net = Net::new(3);
    let id = hex::encode(&tagged("lij/test/pool", &[&3u32.to_le_bytes()])[..16]);
    let params = Params::new(&id, D, 3, RATE * 1000);
    // a second phone using member 0's session posts a different registration
    let (_, acts) = Attempt::new(params.clone(), Network::Bitcoin, MyPart { tip: 970_001, ..my_part(0) }, 1_000, Timeouts { phase_s: 600 }).unwrap();
    for a in acts {
        if let Action::Post(j) = a {
            net.deliver_all(session(0), &j);
        }
    }
    net.run();
    assert!(net.signed.is_empty() && net.stops.iter().any(|(_, r, _)| r.contains("two different registrations")), "{:?}", net.stops);
    // a phone left alone times out
    let (mut lone, _) = Attempt::new(params, Network::Bitcoin, my_part(1), 1_000, Timeouts { phase_s: 600 }).unwrap();
    assert!(lone.on(Input::Tick { now: 1_500 }).is_empty());
    let acts = lone.on(Input::Tick { now: 2_200 });
    assert!(acts.iter().any(|a| matches!(a, Action::Stopped { reason, .. } if reason.contains("timed out"))), "{acts:?}");
    assert_eq!(*lone.phase(), Phase::Stopped);
}

#[test]
fn repeated_answers_from_the_page_change_nothing() {
    let mut net = Net::new(3);
    net.double = true;
    net.run();
    assert!(net.stops.is_empty(), "{:?}", net.stops);
    assert_eq!(net.signed.len(), 3);
}

#[test]
fn a_member_who_withholds_its_nonces_is_named_at_the_timeout_and_its_coin_is_refused_next_time() {
    let mut net = Net::new(3);
    net.tamper = Some(Box::new(|i, json| if i == 2 && json.contains("\"nonces\"") { Some(vec![]) } else { None }));
    net.run();
    assert!(net.signed.is_empty() && net.stops.is_empty(), "everyone waits at View");
    for j in 0..3 {
        let acts = net.phones[j].on(Input::Tick { now: 5_000 }); // the View phase's clock starts
        net.act(j, acts);
        let acts = net.phones[j].on(Input::Tick { now: 5_700 }); // 700 s later: past the 600-s phase
        net.act(j, acts);
    }
    let others: Vec<_> = net.stops.iter().filter(|(i, _, _)| *i != 2).collect();
    assert!(others.len() == 2 && others.iter().all(|(_, r, n)| r.contains("timed out at View") && *n == vec![session(2)]), "{:?}", net.stops);
    let refused = net.phones[0].coins_of(&[session(2)]);
    assert_eq!(refused, vec![my_part(2).coins[0].0]);
    // the next attempt: member 2's coin is refused
    let id = hex::encode(&tagged("lij/test/pool", &[&3u32.to_le_bytes()])[..16]);
    let params = Params::new(&id, D, 3, RATE * 1000);
    let (mut fresh, _) = Attempt::new(params.clone(), Network::Bitcoin, my_part(0), 1_000, Timeouts { phase_s: 600 }).unwrap();
    fresh = fresh.refusing(refused);
    let (_, acts2) = Attempt::new(params, Network::Bitcoin, my_part(2), 1_000, Timeouts { phase_s: 600 }).unwrap();
    let mut stopped = None;
    for a in acts2 {
        if let Action::Post(j) = a {
            for out in fresh.on(Input::Msg { from: session(2), json: j }) {
                if let Action::Stopped { reason, named } = out {
                    stopped = Some((reason, named));
                }
            }
        }
    }
    let (reason, named) = stopped.expect("refused");
    assert!(reason.contains("refused") && named == vec![session(2)]);
}
