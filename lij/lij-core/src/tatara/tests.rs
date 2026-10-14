//! Tests of the Tatara pool core (plan r3 step 3). The re-derivation is checked against joinstr's builder over many
//! pools, and against the NIP's worked example; every check is shown to refuse what it must.

use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut, Txid};
use joinstr_v2::keys::PoolKeys;
use joinstr_v2::msg::PoolEvent;
use joinstr_v2::pool::{build, check_input_registrations, InputRegistration, Params, Payout};
use musig2::secp::{Point, Scalar};

use super::caps::{self, Declared};
use super::checks::{mine_in_funding, my_payout_once, same_as_rederived, scripts_apart};
use super::rederive::{pool_script, rederive, Member};
use super::tagged;

fn sk(label: &str, i: u32) -> SecretKey {
    SecretKey::from_slice(&tagged("lij/test/tatara", &[label.as_bytes(), &i.to_le_bytes()])).unwrap()
}
fn scalar(label: &str, i: u32) -> Scalar {
    Scalar::from_slice(&sk(label, i).secret_bytes()).unwrap()
}
fn p2tr(label: &str, i: u32) -> ScriptBuf {
    let secp = Secp256k1::new();
    let (x, _) = sk(label, i).public_key(&secp).x_only_public_key();
    Address::p2tr(&secp, x, None, Network::Bitcoin).script_pubkey()
}
fn p2wpkh(label: &str, i: u32) -> ScriptBuf {
    let secp = Secp256k1::new();
    Address::p2wpkh(&CompressedPublicKey(sk(label, i).public_key(&secp)), Network::Bitcoin).script_pubkey()
}
fn op(i: u32, j: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array(tagged("lij/test/txid", &[&i.to_le_bytes(), &j.to_le_bytes()])), i % 3)
}

struct Pool {
    params: Params,
    regs: Vec<InputRegistration>,
    members: Vec<Member>,
    payouts: Vec<(ScriptBuf, u8)>,
    keys: PoolKeys,
}

/// A pool of `n`: member i has 1–2 inputs (P2TR or P2WPKH by i), change on some, registered heights near 970,000.
fn pool(n: usize, d: u64, rate_milli: u64, seed: u32) -> Pool {
    let id = hex::encode(&tagged("lij/test/id", &[&seed.to_le_bytes()])[..16]);
    let params = Params::new(&id, d, n, rate_milli);
    let mut regs = Vec::new();
    let mut members = Vec::new();
    let mut payouts = Vec::new();
    for i in 0..n as u32 {
        let s = seed * 100 + i;
        let musig = scalar("musig", s).base_point_mul();
        let ring = scalar("ring", s).base_point_mul();
        let ins = 1 + (s % 2);
        let per = d / ins as u64 + 20_000;
        let inputs: Vec<(OutPoint, TxOut)> = (0..ins)
            .map(|j| (op(s, j), TxOut { value: Amount::from_sat(per), script_pubkey: if (s + j) % 2 == 0 { p2tr("coin", s * 10 + j) } else { p2wpkh("coin", s * 10 + j) } }))
            .collect();
        let change = if s % 3 != 0 { Some(TxOut { value: Amount::from_sat(7_000 + (s % 1_000) as u64), script_pubkey: if s % 2 == 0 { p2wpkh("change", s) } else { p2tr("change", s) } }) } else { None };
        let height = 970_000 + (s % 5);
        regs.push(InputRegistration { session: tagged("lij/test/session", &[&s.to_le_bytes()]), amount: d, musig, ring, inputs: inputs.clone(), change: change.clone(), height });
        members.push(Member { musig: musig.serialize(), inputs, change, height });
        payouts.push((p2tr("payout", s), 0u8));
    }
    check_input_registrations(&params, &regs).unwrap();
    let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
    Pool { params, regs, members, payouts, keys }
}

fn joinstr_payouts(p: &Pool) -> Vec<Payout> {
    p.payouts.iter().map(|(s, pr)| Payout { script: s.clone(), amount: p.params.classes[0].amount, priority: *pr }).collect()
}

// ── S10: the re-derivation is joinstr's build, byte for byte ──────────────────────────────────────────────────────────

#[test]
fn rederive_matches_joinstrs_build_for_3_to_6_members() {
    let mut seed = 1;
    for n in 3..=6 {
        for &d in &[50_000u64, 100_000, 1_000_000] {
            for &rate in &[1_000u64, 2_000, 20_000] {
                let p = pool(n, d, rate, seed);
                seed += 1;
                let built = build(&p.params, &p.regs, &joinstr_payouts(&p), &p.keys).unwrap();
                let ours = rederive(&p.params.id, d, rate, &p.members, &p.payouts, 970_050).unwrap();
                same_as_rederived(&built, &ours).unwrap();
                for (i, s) in ours.pool_scripts.iter().enumerate() {
                    assert_eq!(s, &p.keys.script_pubkey(i as u32).unwrap(), "pool output {i}'s key");
                }
            }
        }
    }
}

#[test]
fn the_nips_worked_example() {
    // NIP "Amounts": N = 5, d = 10,000, fee_rate = 2 — exit share 247, pools 51235 / 40927 / 30619 / 20311, final fee 311
    let p = pool(5, 10_000, 2_000, 900);
    let r = rederive(&p.params.id, 10_000, 2_000, &p.members, &p.payouts, 970_000).unwrap();
    assert_eq!(r.exit_share, 247);
    assert_eq!(r.pools, vec![51_235, 40_927, 30_619, 20_311]);
    let last = r.exits.last().unwrap();
    assert_eq!(r.pools[3] - last.output.iter().map(|o| o.value.to_sat()).sum::<u64>(), 311);
}

#[test]
fn pool_scripts_follow_bip328_and_bip86() {
    let keys: Vec<[u8; 33]> = (0..4).map(|i| scalar("k", i).base_point_mul().serialize()).collect();
    let pk = PoolKeys::new(keys.iter().map(|k| Point::from_slice(k).unwrap()).collect()).unwrap();
    for i in 0..5 {
        assert_eq!(pool_script(&keys, i).unwrap(), pk.script_pubkey(i).unwrap());
    }
    // the order the keys come in does not matter (KeySort)
    let mut rev = keys.clone();
    rev.reverse();
    assert_eq!(pool_script(&rev, 2).unwrap(), pool_script(&keys, 2).unwrap());
}

#[test]
fn a_build_that_differs_anywhere_is_caught() {
    let p = pool(4, 100_000, 2_000, 7);
    let ours = rederive(&p.params.id, 100_000, 2_000, &p.members, &p.payouts, 970_050).unwrap();
    let good = build(&p.params, &p.regs, &joinstr_payouts(&p), &p.keys).unwrap();
    // a redirected change (the probe of review finding 4)
    let mut t = good.clone();
    let ci = t.funding.output.iter().position(|o| o.script_pubkey != ours.pool_scripts[0]).unwrap();
    t.funding.output[ci].script_pubkey = p2wpkh("thief", 1);
    assert!(same_as_rederived(&t, &ours).is_err());
    // an exit paying one sat less to a payout
    let mut t = good.clone();
    let o = t.exits[0].output.iter_mut().find(|o| o.value.to_sat() == 100_000).unwrap();
    o.value = Amount::from_sat(99_999);
    assert!(same_as_rederived(&t, &ours).is_err());
    // another locktime, another sequence, a script sig
    let mut t = good.clone();
    t.funding.lock_time = bitcoin::absolute::LockTime::from_height(969_000).unwrap();
    assert!(same_as_rederived(&t, &ours).is_err());
    let mut t = good.clone();
    t.exits[1].input[0].sequence = bitcoin::Sequence::MAX;
    assert!(same_as_rederived(&t, &ours).is_err());
    let mut t = good.clone();
    t.funding.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    assert!(same_as_rederived(&t, &ours).is_err());
    // an extra input someone slipped in
    let mut t = good.clone();
    t.funding.input.push(t.funding.input[0].clone());
    assert!(same_as_rederived(&t, &ours).is_err());
}

#[test]
fn contributions_and_locktime_are_checked() {
    let mut p = pool(3, 50_000, 2_000, 11);
    // a member one sat short: its inputs exactly cover d + share + fee, minus one
    let ours = rederive(&p.params.id, 50_000, 2_000, &p.members, &p.payouts, 970_050).unwrap();
    let mb = &mut p.members[0];
    mb.change = Some(TxOut {
        value: Amount::from_sat(mb.inputs.iter().map(|(_, o)| o.value.to_sat()).sum::<u64>() - 50_000 - ours.exit_share),
        script_pubkey: p2wpkh("change", 9_999),
    });
    assert!(rederive(&p.params.id, 50_000, 2_000, &p.members, &p.payouts, 970_050).is_err(), "short by its funding fee");
    // the locktime more than 100 blocks behind my tip
    let p = pool(3, 50_000, 2_000, 12);
    assert!(rederive(&p.params.id, 50_000, 2_000, &p.members, &p.payouts, 970_000 + 101).is_err());
    assert!(rederive(&p.params.id, 50_000, 2_000, &p.members, &p.payouts, 970_000 + 100).is_ok());
    // 2 or 7 members, or a payout missing
    assert!(rederive(&p.params.id, 50_000, 2_000, &p.members[..2], &p.payouts[..2], 970_000).is_err());
    assert!(rederive(&p.params.id, 50_000, 2_000, &p.members, &p.payouts[..2], 970_000).is_err());
}

// ── S4: scripts kept apart ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn s4_a_payout_equal_to_a_pool_change_or_input_script_is_refused() {
    let p = pool(4, 100_000, 2_000, 21);
    let r = rederive(&p.params.id, 100_000, 2_000, &p.members, &p.payouts, 970_050).unwrap();
    let pay: Vec<ScriptBuf> = p.payouts.iter().map(|(s, _)| s.clone()).collect();
    scripts_apart(&r, &p.members, &pay).unwrap();
    for bad in [
        r.pool_scripts[0].clone(),
        r.pool_scripts[2].clone(),
        p.members.iter().find_map(|m| m.change.as_ref()).unwrap().script_pubkey.clone(),
        p.members[1].inputs[0].1.script_pubkey.clone(),
        pay[0].clone(),
    ] {
        let mut x = pay.clone();
        x[3] = bad;
        assert!(scripts_apart(&r, &p.members, &x).is_err());
    }
    let mut m = p.members.clone();
    m[0].change = Some(TxOut { value: Amount::from_sat(5_000), script_pubkey: r.pool_scripts[0].clone() });
    assert!(scripts_apart(&r, &m, &pay).is_err(), "a change equal to pool 0");
}

// ── S5: mine, exactly once ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn s5_my_payout_once_and_my_coins_as_registered() {
    let p = pool(5, 100_000, 2_000, 31);
    let r = rederive(&p.params.id, 100_000, 2_000, &p.members, &p.payouts, 970_050).unwrap();
    let mine = p.payouts[2].0.clone();
    my_payout_once(&r.exits, &mine, 100_000).unwrap();
    assert!(my_payout_once(&r.exits, &p2tr("stranger", 1), 100_000).is_err(), "not paid");
    let mut twice = r.exits.clone();
    twice[0].output.push(TxOut { value: Amount::from_sat(100_000), script_pubkey: mine.clone() });
    assert!(my_payout_once(&twice, &mine, 100_000).is_err(), "paid twice");
    assert!(my_payout_once(&r.exits, &mine, 99_999).is_err(), "the wrong amount");
    for m in &p.members {
        mine_in_funding(&r.funding, m).unwrap();
    }
    let mut f = r.funding.clone();
    f.input.retain(|i| i.previous_output != p.members[1].inputs[0].0);
    assert!(mine_in_funding(&f, &p.members[1]).is_err(), "my input missing");
}

// ── S6: the Phase 1 options and the caps ──────────────────────────────────────────────────────────────────────────────

fn declared() -> Declared {
    Declared { sizes: vec![50_000, 100_000, 250_000, 1_000_000], max_fee_sat_vb: 20, relay: "wss://relay.lsp.example".into(), network: "bitcoin".into(), max_timeout_s: 3_600 }
}

fn event(changes: &[(&str, serde_json::Value)], drop: &[&str]) -> String {
    let mut v = serde_json::json!({
        "versions": ["2"], "id": "0123456789abcdef0123456789abcdef", "network": "bitcoin", "type": "new_pool",
        "public_key": hex::encode(scalar("poolkey", 1).base_point_mul().serialize()),
        "denomination": 100_000, "peers": 4, "timeout": 1_000_600, "relays": ["wss://relay.lsp.example"], "fee_rate": 3,
        "transport": {"vpn": {"enable": false, "vpn_gateway": null}, "tor": {"enable": false}}
    });
    for (k, val) in changes {
        v[*k] = val.clone();
    }
    for k in drop {
        v.as_object_mut().unwrap().remove(*k);
    }
    v.to_string()
}

#[test]
fn s6_the_phase1_options_and_nothing_else() {
    let d = declared();
    let now = 1_000_000;
    let ok = PoolEvent::parse_strict(&event(&[], &[])).unwrap();
    let p = caps::phase1_pool(&ok, &d, now).unwrap();
    assert_eq!((p.peers, p.classes[0].amount, p.fee_rate_milli), (4, 100_000, 3_000));
    use serde_json::json;
    let refused: Vec<(&str, serde_json::Value)> = vec![
        ("versions", json!(["1", "2"])),
        ("network", json!("signet")),
        ("peers", json!(2)),
        ("peers", json!(7)),
        ("denomination", json!(75_000)),
        ("denominations", json!([{"amount": 100_000, "peers": 2}, {"amount": 50_000, "peers": 2}])),
        ("exits", json!([2, 2])),
        ("exit_fee_rates", json!([3, 2])),
        ("fee_split", json!("by_exit")),
        ("structure", json!("any_order")),
        ("broadcast", json!("hold")),
        ("anchor", json!("p2a")),
        ("transport", json!({"vpn": {"enable": false, "vpn_gateway": null}, "tor": {"enable": true}})),
        ("relays", json!(["wss://elsewhere.example"])),
        ("relays", json!(["wss://relay.lsp.example", "wss://elsewhere.example"])),
        ("fee_rate", json!(21)),
        ("timeout", json!(999_999)),
        ("timeout", json!(1_003_601)),
    ];
    for (k, v) in refused {
        let s = event(&[(k, v.clone())], &[]);
        let refused_here = match PoolEvent::parse_strict(&s) {
            Err(_) => true, // refused already by the strict parse (P8)
            Ok(ev) => caps::phase1_pool(&ev, &d, now).is_err(),
        };
        assert!(refused_here, "{k} = {v} must be refused");
    }
    // v332 (P1, Phase 1b): a channel pool's event carries payout_type "p2wsh" — the strict parse takes it (DP's first
    // channel pool stopped at every create with "unknown field in the pool event"); any other payout type is refused
    let ch = PoolEvent::parse_strict(&event(&[("payout_type", json!("p2wsh"))], &[])).unwrap();
    assert_eq!(caps::phase1_pool(&ch, &d, now).unwrap().payout_type, joinstr_v2::pool::PayoutType::P2wsh);
    assert!(PoolEvent::parse_strict(&event(&[("payout_type", json!("p2pkh"))], &[])).is_err());
    assert!(PoolEvent::parse_strict(&event(&[("payout_type", json!("p2tr"))], &[])).is_ok());
}

#[test]
fn s6_limits() {
    assert!(caps::message_size(&vec![0u8; caps::MAX_MESSAGE_BYTES]).is_ok());
    assert!(caps::message_size(&vec![0u8; caps::MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(caps::registration_inputs(0).is_err());
    assert!(caps::registration_inputs(4).is_ok());
    assert!(caps::registration_inputs(5).is_err());
    assert!(caps::one_per_exit(3, 3).is_ok());
    assert!(caps::one_per_exit(2, 3).is_err());
    // the fee limit: 1.5 × the rate shown at Join, never above the cap
    assert!(caps::within_fee_limit(6, 4, 20));
    assert!(!caps::within_fee_limit(7, 4, 20));
    assert!(!caps::within_fee_limit(21, 20, 20));
    assert!(caps::within_fee_limit(1, 1, 20));
}
