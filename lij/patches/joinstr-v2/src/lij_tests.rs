//! LiJ's tests for our patches to joinstr v2 (docs/joinstr-patches.md). Ours, not upstream's; compiled for tests only.
//! Each test names its patch. Upstream's own tests stay in their modules and keep passing.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use secp::Scalar;

use crate::funding::{ownership_msg, prove, verify_proof};
use crate::keys::PoolKeys;
use crate::pool::{build, check_input_registrations, tests_support::fake_pool};
use crate::ring::{sign as ring_sign, verify as ring_verify};
use crate::sign::{exit_messages, make_nonces};
use crate::util::{derive_scalar, random_scalar};

fn ring_of(n: usize) -> (Vec<Scalar>, Vec<secp::Point>) {
    let xs: Vec<Scalar> = (0..n).map(|_| random_scalar()).collect();
    let mut ring: Vec<secp::Point> = xs.iter().map(|x| x.base_point_mul()).collect();
    ring.sort_by_key(|p| p.serialize());
    (xs, ring)
}

// ── P4: every random byte from the caller ──────────────────────────────────────────────────────────────────────────

#[test]
fn p4_ring_sig_is_fixed_by_the_callers_bytes_and_still_verifies() {
    let (xs, ring) = ring_of(5);
    let aux = [7u8; 32];
    let a = ring_sign(&ring, xs[2], &[1u8; 32], &aux).unwrap();
    let b = ring_sign(&ring, xs[2], &[1u8; 32], &aux).unwrap();
    assert_eq!((a.c0.clone(), a.s.clone()), (b.c0.clone(), b.s.clone()), "same key, message and aux: the same signature");
    ring_verify(&ring, &[1u8; 32], &a).unwrap();
    let c = ring_sign(&ring, xs[2], &[1u8; 32], &[8u8; 32]).unwrap();
    assert_ne!(a.s, c.s, "other aux bytes: other responses");
    ring_verify(&ring, &[1u8; 32], &c).unwrap();
}

#[test]
fn p4_ring_commitment_is_hedged_with_key_and_message() {
    // the same (weak, repeated) aux bytes on two messages or two keys never give the same commitment
    let (xs, ring) = ring_of(4);
    let aux = [0u8; 32];
    let m1 = ring_sign(&ring, xs[0], &[1u8; 32], &aux).unwrap();
    let m2 = ring_sign(&ring, xs[0], &[2u8; 32], &aux).unwrap();
    let k2 = ring_sign(&ring, xs[1], &[1u8; 32], &aux).unwrap();
    assert_ne!(m1.s, m2.s);
    assert_ne!(m1.s, k2.s);
    ring_verify(&ring, &[2u8; 32], &m2).unwrap();
    ring_verify(&ring, &[1u8; 32], &k2).unwrap();
}

#[test]
fn p4_derive_scalar_is_deterministic_and_tag_separated() {
    let a = derive_scalar("t1", &[b"x"]);
    assert_eq!(a, derive_scalar("t1", &[b"x"]));
    assert_ne!(a, derive_scalar("t2", &[b"x"]));
    assert_ne!(a, derive_scalar("t1", &[b"y"]));
}

#[test]
fn p4_ownership_proof_uses_the_callers_aux() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    // P2TR: BIP-340 aux bytes decide the signature
    let (xonly, _) = sk.public_key(&secp).x_only_public_key();
    let tr = Address::p2tr(&secp, xonly, None, Network::Bitcoin).script_pubkey();
    let op = bitcoin::OutPoint::null();
    let m = ownership_msg("pool", &[3; 32], &op);
    let a = prove(&sk, &tr, m, &[1u8; 32]).unwrap();
    let b = prove(&sk, &tr, m, &[1u8; 32]).unwrap();
    let c = prove(&sk, &tr, m, &[2u8; 32]).unwrap();
    assert_eq!(a.sig, b.sig);
    assert_ne!(a.sig, c.sig);
    verify_proof(&tr, m, &a).unwrap();
    verify_proof(&tr, m, &c).unwrap();
    // P2WPKH: ECDSA (RFC 6979) needs no aux bytes and ignores them
    let wpkh = Address::p2wpkh(&CompressedPublicKey(pk.inner), Network::Bitcoin).script_pubkey();
    let d = prove(&sk, &wpkh, m, &[1u8; 32]).unwrap();
    let e = prove(&sk, &wpkh, m, &[2u8; 32]).unwrap();
    assert_eq!(d.sig, e.sig);
    verify_proof(&wpkh, m, &d).unwrap();
}

#[test]
fn p4_exit_nonces_come_from_the_callers_bytes() {
    let (p, mut regs, payouts, _) = fake_pool(3);
    let seckeys: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
    for (r, sk) in regs.iter_mut().zip(&seckeys) {
        r.musig = sk.base_point_mul();
    }
    check_input_registrations(&p, &regs).unwrap();
    let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
    let txs = build(&p, &regs, &payouts, &keys).unwrap();
    let msgs = exit_messages(&keys, &txs).unwrap();
    let (_, a) = make_nonces(seckeys[0], &keys, &msgs, &p.id, &[5u8; 32]).unwrap();
    let (_, b) = make_nonces(seckeys[0], &keys, &msgs, &p.id, &[5u8; 32]).unwrap();
    let (_, c) = make_nonces(seckeys[0], &keys, &msgs, &p.id, &[6u8; 32]).unwrap();
    assert_eq!(a, b, "same bytes: same nonces");
    assert_ne!(a, c, "other bytes: other nonces");
    // one exit's nonce never equals another's under the same bytes
    for i in 0..a.len() {
        for j in (i + 1)..a.len() {
            assert_ne!(a[i], a[j]);
        }
    }
    // another member's key under the same bytes: other nonces (NonceGen mixes in the secret key)
    let (_, d) = make_nonces(seckeys[1], &keys, &msgs, &p.id, &[5u8; 32]).unwrap();
    assert_ne!(a, d);
}

// ── P9: check_txs never panics on a short or out-of-range list ───────────────────────────────────────────────────────

fn built_pool() -> (crate::pool::Params, crate::pool::PoolTxs, PoolKeys) {
    let (p, regs, payouts, keys) = fake_pool(4);
    let txs = build(&p, &regs, &payouts, &keys).unwrap();
    crate::pool::check_txs(&p, &txs, &keys).unwrap();
    (p, txs, keys)
}

#[test]
fn p9_pool_output_index_outside_the_funding_is_an_error() {
    let (p, mut txs, keys) = built_pool();
    txs.pool_vout = 99;
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
}

#[test]
fn p9_short_spent_or_links_lists_are_errors() {
    let (p, mut txs, keys) = built_pool();
    txs.spent.pop();
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
    let (p, mut txs, keys) = built_pool();
    txs.links.truncate(1);
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
    let (p, mut txs, keys) = built_pool();
    txs.spent.clear();
    txs.links.clear();
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
}

#[test]
fn p9_a_link_to_an_output_or_pool_that_does_not_exist_is_an_error() {
    let (p, mut txs, keys) = built_pool();
    if let Some(l) = txs.links.iter_mut().find(|l| !l.to.is_empty()) {
        l.to[0].1 = 99;
    }
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
    let (p, mut txs, keys) = built_pool();
    if let Some(l) = txs.links.iter_mut().find(|l| !l.to.is_empty()) {
        l.to[0].0 = 99;
    }
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
}

#[test]
fn p9_values_that_overflow_are_an_error() {
    let (p, mut txs, keys) = built_pool();
    for o in txs.funding_prevouts.iter_mut() {
        o.value = bitcoin::Amount::from_sat(u64::MAX / 2 + 1);
    }
    assert!(crate::pool::check_txs(&p, &txs, &keys).is_err());
}

// ── P6: caps keep every sum in range ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn p6_a_class_of_impossible_size_or_amount_is_refused() {
    use crate::pool::{Class, Params, MAX_MONEY_SAT};
    let mut p = Params::new("p6", 100_000, 4, 2_000);
    p.validate().unwrap();
    // a class of usize::MAX peers next to one of 3: the sum wraps to 2 in a release build
    p.classes = vec![Class { amount: 100_000, peers: usize::MAX }, Class { amount: 200_000, peers: 3 }];
    p.peers = 2;
    assert!(p.validate().is_err());
    let mut q = Params::new("p6", MAX_MONEY_SAT + 1, 4, 2_000);
    assert!(q.validate().is_err());
    q = Params::new("p6", 0, 4, 2_000);
    assert!(q.validate().is_err());
}

#[test]
fn p6_fee_rates_above_the_cap_are_refused() {
    use crate::pool::{Params, MAX_FEE_RATE_MILLI};
    let p = Params::new("p6", 100_000, 4, MAX_FEE_RATE_MILLI + 1);
    assert!(p.validate().is_err());
    let mut q = Params::new("p6", 100_000, 4, 2_000);
    q.exit_rates_milli = (2_000, u64::MAX);
    assert!(q.validate().is_err());
    assert!(Params::new("p6", 100_000, 4, MAX_FEE_RATE_MILLI).validate().is_ok());
}

#[test]
fn p6_too_many_or_too_large_inputs_are_refused() {
    use crate::pool::MAX_INPUTS_PER_PEER;
    let (p, regs, _, _) = fake_pool(3);
    check_input_registrations(&p, &regs).unwrap();
    let mut big = regs.clone();
    big[0].inputs[0].1.value = bitcoin::Amount::from_sat(u64::MAX);
    assert!(check_input_registrations(&p, &big).is_err());
    let mut many = regs.clone();
    let (op0, out0) = many[0].inputs[0].clone();
    many[0].inputs = (0..=MAX_INPUTS_PER_PEER as u32)
        .map(|i| (bitcoin::OutPoint::new(op0.txid, op0.vout + 1000 + i), out0.clone()))
        .collect();
    assert!(check_input_registrations(&p, &many).is_err());
}

#[test]
fn p6_a_pool_events_fee_rate_must_be_finite_positive_and_capped() {
    let ev = |rate: &str| -> serde_json::Value {
        serde_json::from_str(&format!(
            r#"{{"versions":["2"],"id":"{id}","network":"bitcoin","type":"new_pool","public_key":"{pk}","denomination":100000,"peers":3,"timeout":1900000000,"relays":["wss://r.example"],"fee_rate":{rate},"transport":{{"vpn":{{"enable":false,"vpn_gateway":null}},"tor":{{"enable":false}}}}}}"#,
            id = "ab".repeat(16),
            pk = "02".to_string() + &"11".repeat(32),
        ))
        .unwrap()
    };
    let ok: crate::msg::PoolEvent = serde_json::from_value(ev("2")).unwrap();
    assert!(ok.params().is_ok(), "2 sat/vB is fine");
    for bad in ["1e300", "-1", "0", "1000.001"] {
        let e: crate::msg::PoolEvent = serde_json::from_value(ev(bad)).unwrap();
        assert!(e.params().is_err(), "fee rate {bad} must be refused");
    }
}

// ── P7: lengths, signers and secret nonces ────────────────────────────────────────────────────────────────────────────

struct Signed {
    keys: PoolKeys,
    msgs: Vec<crate::sign::ExitMessage>,
    seckeys: Vec<Scalar>,
    pubnonces: Vec<Vec<musig2::PubNonce>>,
    psigs: Vec<Vec<musig2::PartialSignature>>,
}

fn signed_pool(n: usize) -> Signed {
    use crate::sign::partial_sign;
    let (p, mut regs, payouts, _) = fake_pool(n);
    let seckeys: Vec<Scalar> = (0..n).map(|_| random_scalar()).collect();
    for (r, sk) in regs.iter_mut().zip(&seckeys) {
        r.musig = sk.base_point_mul();
    }
    let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
    let txs = build(&p, &regs, &payouts, &keys).unwrap();
    let msgs = exit_messages(&keys, &txs).unwrap();
    let mut secs = Vec::new();
    let mut pubnonces = Vec::new();
    for sk in &seckeys {
        let (s, pn) = make_nonces(*sk, &keys, &msgs, &p.id, &crate::util::random_bytes()).unwrap();
        secs.push(s);
        pubnonces.push(pn);
    }
    let pubs: Vec<&[musig2::PubNonce]> = pubnonces.iter().map(|v| v.as_slice()).collect();
    let psigs = seckeys.iter().zip(secs).map(|(sk, s)| partial_sign(*sk, &keys, &msgs, s, &pubs).unwrap()).collect();
    Signed { keys, msgs, seckeys, pubnonces, psigs }
}

#[test]
fn p7_short_lists_are_errors_not_panics() {
    use crate::sign::{aggregate, partial_sign};
    let s = signed_pool(3);
    // a signer with one partial signature short
    let short: Vec<_> = s.psigs[1][..s.psigs[1].len() - 1].to_vec();
    let signers: Vec<_> = (0..3)
        .map(|i| (s.seckeys[i].base_point_mul(), s.pubnonces[i].as_slice(), if i == 1 { short.as_slice() } else { s.psigs[i].as_slice() }))
        .collect();
    assert!(aggregate(&s.keys, &s.msgs, &signers).is_err());
    // a nonce list one short when signing
    let (p, _, _, _) = fake_pool(3);
    let (mine, _) = make_nonces(s.seckeys[0], &s.keys, &s.msgs, &p.id, &[1u8; 32]).unwrap();
    let mut pn: Vec<Vec<musig2::PubNonce>> = s.pubnonces.clone();
    pn[2].pop();
    let pubs: Vec<&[musig2::PubNonce]> = pn.iter().map(|v| v.as_slice()).collect();
    assert!(partial_sign(s.seckeys[0], &s.keys, &s.msgs, mine, &pubs).is_err());
}

#[test]
fn p7_the_signers_must_be_exactly_the_pools_keys() {
    use crate::sign::aggregate;
    let s = signed_pool(3);
    let all: Vec<_> = (0..3).map(|i| (s.seckeys[i].base_point_mul(), s.pubnonces[i].as_slice(), s.psigs[i].as_slice())).collect();
    aggregate(&s.keys, &s.msgs, &all).unwrap();
    assert!(aggregate(&s.keys, &s.msgs, &all[..2]).is_err(), "a missing signer");
    let mut twice = all.clone();
    twice[2] = all[1];
    assert!(aggregate(&s.keys, &s.msgs, &twice).is_err(), "one signer twice");
    let mut stranger = all.clone();
    stranger[0].0 = random_scalar().base_point_mul();
    assert!(aggregate(&s.keys, &s.msgs, &stranger).is_err(), "a key from outside the pool");
}

#[test]
fn p7_every_bad_signer_is_named() {
    use crate::sign::aggregate;
    let s = signed_pool(4);
    let mut bad = s.psigs.clone();
    bad[1][0] = s.psigs[0][0];
    bad[3][0] = s.psigs[2][0];
    let signers: Vec<_> = (0..4).map(|i| (s.seckeys[i].base_point_mul(), s.pubnonces[i].as_slice(), bad[i].as_slice())).collect();
    let err = aggregate(&s.keys, &s.msgs, &signers).unwrap_err().to_string();
    assert!(err.contains(&s.seckeys[1].base_point_mul().to_string()), "{err}");
    assert!(err.contains(&s.seckeys[3].base_point_mul().to_string()), "{err}");
    assert!(!err.contains(&s.seckeys[0].base_point_mul().to_string()), "{err}");
}

#[test]
fn p7_a_nonce_signs_only_its_own_exit_and_only_a_pool_key_makes_nonces() {
    use crate::sign::partial_sign;
    let s = signed_pool(3);
    let (p, _, _, _) = fake_pool(3);
    let pubs: Vec<&[musig2::PubNonce]> = s.pubnonces.iter().map(|v| v.as_slice()).collect();
    // nonces made for these exits, offered to sign the same exits in another order
    let (mine, _) = make_nonces(s.seckeys[0], &s.keys, &s.msgs, &p.id, &[2u8; 32]).unwrap();
    let txs2 = {
        let (p2, mut regs, payouts, _) = fake_pool(3);
        for (r, sk) in regs.iter_mut().zip(&s.seckeys) {
            r.musig = sk.base_point_mul();
        }
        build(&p2, &regs, &payouts, &s.keys).unwrap()
    };
    let other = exit_messages(&s.keys, &txs2).unwrap();
    assert!(partial_sign(s.seckeys[0], &s.keys, &other, mine, &pubs).is_err());
    // a key that is not the pool's cannot make nonces for it
    assert!(make_nonces(random_scalar(), &s.keys, &s.msgs, &p.id, &[3u8; 32]).is_err());
}

#[test]
fn p7_empty_keys_and_misshapen_rings_are_refused() {
    use crate::ring::Ring;
    assert!(PoolKeys::new(vec![]).is_err());
    let (xs, ring) = ring_of(3);
    assert!(Ring::new(&ring).is_ok());
    assert!(Ring::new(&[]).is_err());
    let mut unsorted = ring.clone();
    unsorted.swap(0, 2);
    assert!(Ring::new(&unsorted).is_err());
    assert!(ring_sign(&unsorted, xs[0], &[1u8; 32], &[0u8; 32]).is_err());
    let dup = vec![ring[0], ring[0], ring[1]];
    assert!(Ring::new(&dup).is_err());
}

#[test]
fn p7_attach_checks_its_counts() {
    let (p, regs, payouts, keys) = fake_pool(3);
    let mut txs = build(&p, &regs, &payouts, &keys).unwrap();
    let n = txs.exits.len();
    assert!(crate::sign::attach(&mut txs, &vec![[0u8; 64]; n - 1]).is_err());
    assert!(crate::sign::attach(&mut txs, &vec![[0u8; 64]; n]).is_ok());
}

// ── P8: strict parsing of everything a peer sends ─────────────────────────────────────────────────────────────────────

#[test]
fn p8_points_are_33_byte_compressed_lowercase_hex() {
    use crate::keys::point_from_hex;
    let p = random_scalar().base_point_mul();
    let lower = hex::encode(p.serialize());
    assert_eq!(point_from_hex(&lower).unwrap(), p);
    assert!(point_from_hex(&lower.to_uppercase()).is_err(), "upper case");
    assert!(point_from_hex(&hex::encode(p.serialize_uncompressed())).is_err(), "65-byte uncompressed");
    let mut hybrid = p.serialize_uncompressed();
    hybrid[0] = 0x06 | (hybrid[64] & 1);
    assert!(point_from_hex(&hex::encode(hybrid)).is_err(), "hybrid");
    assert!(point_from_hex(&format!("{lower}00")).is_err(), "one byte too many");
    assert!(point_from_hex(&format!(" {lower}")).is_err(), "padding");
}

#[test]
fn p8_ring_signatures_are_parsed_strictly() {
    let (xs, ring) = ring_of(3);
    let m = [9u8; 32];
    let sig = ring_sign(&ring, xs[1], &m, &[4u8; 32]).unwrap();
    ring_verify(&ring, &m, &sig).unwrap();
    let mut up = sig.clone();
    up.key_image = up.key_image.to_uppercase();
    assert!(ring_verify(&ring, &m, &up).is_err());
    let mut c0 = sig.clone();
    c0.c0 = format!("{}00", c0.c0);
    assert!(ring_verify(&ring, &m, &c0).is_err());
    let mut s = sig.clone();
    s.s[0] = s.s[0].to_uppercase();
    assert!(ring_verify(&ring, &m, &s).is_err());
    let mut j = serde_json::to_value(&sig).unwrap();
    j["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<crate::ring::RingSig>(j).is_err(), "unknown field");
}

#[test]
fn p8_ownership_proofs_are_parsed_strictly() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let (xonly, _) = sk.public_key(&secp).x_only_public_key();
    let tr = Address::p2tr(&secp, xonly, None, Network::Bitcoin).script_pubkey();
    let m = ownership_msg("pool", &[3; 32], &bitcoin::OutPoint::null());
    let p = prove(&sk, &tr, m, &[1u8; 32]).unwrap();
    verify_proof(&tr, m, &p).unwrap();
    let mut up = p.clone();
    up.sig = up.sig.to_uppercase();
    assert!(verify_proof(&tr, m, &up).is_err());
    let mut long = p.clone();
    long.sig.push_str("01");
    assert!(verify_proof(&tr, m, &long).is_err());
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let wpkh = Address::p2wpkh(&CompressedPublicKey(pk.inner), Network::Bitcoin).script_pubkey();
    let mut q = prove(&sk, &wpkh, m, &[1u8; 32]).unwrap();
    verify_proof(&wpkh, m, &q).unwrap();
    q.pubkey = q.pubkey.map(|k| k.to_uppercase());
    assert!(verify_proof(&wpkh, m, &q).is_err());
}

#[test]
fn p8_nonces_and_partial_signatures_are_parsed_strictly() {
    use crate::sign::{nonce_from_hex, nonce_hex, psig_from_hex, psig_hex};
    let s = signed_pool(3);
    let n = nonce_hex(&s.pubnonces[0][0]);
    assert!(nonce_from_hex(&n).is_ok());
    assert!(nonce_from_hex(&n.to_uppercase()).is_err());
    assert!(nonce_from_hex(&n[..n.len() - 2]).is_err());
    let g = psig_hex(&s.psigs[0][0]);
    assert!(psig_from_hex(&g).is_ok());
    assert!(psig_from_hex(&g.to_uppercase()).is_err());
    assert!(psig_from_hex(&format!("{g}00")).is_err());
}

#[test]
fn p8_envelopes_are_parsed_strictly() {
    use crate::msg::Envelope;
    let ok = r#"{"version":"2","type":"nonces","nonces":["ab"]}"#;
    assert!(Envelope::parse_strict(ok).is_ok());
    assert!(Envelope::parse_strict(r#"{"version":"2","type":"nonces","nonces":["ab"],"note":"x"}"#).is_err(), "unknown field");
    assert!(Envelope::parse_strict(r#"{"version":"1","type":"nonces","nonces":["ab"]}"#).is_err(), "version 1");
    assert!(Envelope::parse_strict(r#"{"version":"2","type":"shutdown"}"#).is_err(), "unknown type");
    assert!(Envelope::parse_strict(r#"["version","2"]"#).is_err(), "not an object");
    assert!(Envelope::parse_strict(
        r#"{"version":"2","type":"inputs","musig_pubkey":"02","ring_pubkey":"03","inputs":[{"txid":"a","vout":0,"amount":1,"script_pubkey":"00","proof":{"sig":"00"},"x":1}],"change":null,"height":7}"#
    )
    .is_err(), "unknown field inside an input");
}

#[test]
fn p8_pool_events_are_parsed_strictly() {
    use crate::msg::PoolEvent;
    let pk33 = hex::encode(random_scalar().base_point_mul().serialize());
    let pk = pk33[2..].to_string();   // P11: the pool's nostr key (x-only), as upstream writes it
    let ev = |id: &str, pk: &str, rate: &str, extra: &str| {
        format!(
            r#"{{"versions":["2"],"id":"{id}","network":"bitcoin","type":"new_pool","public_key":"{pk}","denomination":100000,"peers":3,"timeout":1900000000,"relays":["wss://r.example"],"fee_rate":{rate},"transport":{{"vpn":{{"enable":false,"vpn_gateway":null}},"tor":{{"enable":false}}}}{extra}}}"#
        )
    };
    let id = "0123456789abcdef0123456789abcdef";
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2", "")).is_ok());
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2", r#","autct":{"keyset":"k"}"#)).is_err(), "unknown field");
    assert!(PoolEvent::parse_strict(&ev("x", &pk, "2", "")).is_err(), "id not 32 hex");
    assert!(PoolEvent::parse_strict(&ev(&id.to_uppercase(), &pk, "2", "")).is_err(), "id upper case");
    assert!(PoolEvent::parse_strict(&ev("../../etc/passwd/0123456789abcd", &pk, "2", "")).is_err(), "id a path");
    assert!(PoolEvent::parse_strict(&ev(id, "ab", "2", "")).is_err(), "pool key not 32 bytes");
    assert!(PoolEvent::parse_strict(&ev(id, &pk33, "2", "")).is_err(), "pool key a 33-byte point (P8's old demand; upstream never writes one)");
    assert!(PoolEvent::parse_strict(&ev(id, &pk.to_uppercase(), "2", "")).is_err(), "pool key upper case");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2.5", "")).is_ok(), "P11: a fractional fee rate is a pool option (upstream's demo runs at 1.5)");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "1.001", "")).is_ok(), "thousandths");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2.0005", "")).is_err(), "finer than a thousandth");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "0", "")).is_err(), "zero");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "-1", "")).is_err(), "negative");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2", r#","exit_fee_rates":[3,2.25]"#)).is_ok(), "fractional exit rates");
    assert!(PoolEvent::parse_strict(&ev(id, &pk, "2", r#","exit_fee_rates":[3,2.0001]"#)).is_err(), "exit rate finer than a thousandth");
}

// ── P10: the tagged ring signature (a key image per tag — Tatara's weekly seat image) ──────────────────────────────────

#[test]
fn p10_a_tagged_signature_verifies_under_its_own_tag_only() {
    use crate::ring::{sign_tagged, verify_tagged};
    let (xs, ring) = ring_of(5);
    let m = [5u8; 32];
    let w41 = b"lij/tatara/seat/v1/week-41";
    let w42 = b"lij/tatara/seat/v1/week-42";
    let sig = sign_tagged(&ring, xs[3], &m, &[1u8; 32], w41).unwrap();
    verify_tagged(&ring, &m, &sig, w41).unwrap();
    assert!(verify_tagged(&ring, &m, &sig, w42).is_err(), "another tag");
    assert!(verify_tagged(&ring, &m, &sig, b"").is_err(), "the empty tag");
    assert!(ring_verify(&ring, &m, &sig).is_err(), "untagged");
    assert!(verify_tagged(&ring, &[6u8; 32], &sig, w41).is_err(), "another message");
    let plain = ring_sign(&ring, xs[3], &m, &[1u8; 32]).unwrap();
    assert!(verify_tagged(&ring, &m, &plain, w41).is_err(), "an untagged signature under a tag");
    assert!(sign_tagged(&ring, random_scalar(), &m, &[1u8; 32], w41).is_err(), "a key outside the ring");
}

#[test]
fn p10_the_key_image_links_within_a_tag_and_not_across() {
    use crate::ring::{key_image, key_image_tagged, sign_tagged, verify_tagged};
    let (xs, ring) = ring_of(4);
    let w41 = b"lij/tatara/seat/v1/week-41";
    let w42 = b"lij/tatara/seat/v1/week-42";
    let a = verify_tagged(&ring, &[1u8; 32], &sign_tagged(&ring, xs[0], &[1u8; 32], &[1u8; 32], w41).unwrap(), w41).unwrap();
    let b = verify_tagged(&ring, &[2u8; 32], &sign_tagged(&ring, xs[0], &[2u8; 32], &[2u8; 32], w41).unwrap(), w41).unwrap();
    let c = verify_tagged(&ring, &[1u8; 32], &sign_tagged(&ring, xs[0], &[1u8; 32], &[3u8; 32], w42).unwrap(), w42).unwrap();
    let d = verify_tagged(&ring, &[1u8; 32], &sign_tagged(&ring, xs[1], &[1u8; 32], &[4u8; 32], w41).unwrap(), w41).unwrap();
    assert_eq!(a, b, "one key, one tag: one image (a second seat that week is seen)");
    assert_ne!(a, c, "one key, two tags: two images (weeks do not link)");
    assert_ne!(a, d, "two keys, one tag: two images");
    assert_eq!(a, key_image_tagged(xs[0], w41));
    assert_ne!(a, key_image(xs[0]), "the tagged image is not joinstr's own");
}

#[test]
fn p10_tagged_signatures_are_parsed_and_shaped_as_strictly() {
    use crate::ring::{sign_tagged, verify_tagged, Ring};
    let (xs, ring) = ring_of(3);
    let t = b"lij/tatara/seat/v1/week-41";
    let mut sig = sign_tagged(&ring, xs[1], &[9u8; 32], &[1u8; 32], t).unwrap();
    sig.s[2] = sig.s[2].to_uppercase();
    assert!(verify_tagged(&ring, &[9u8; 32], &sig, t).is_err());
    let mut unsorted = ring.clone();
    unsorted.swap(0, 1);
    assert!(Ring::new_tagged(&unsorted, t).is_err());
    assert!(sign_tagged(&unsorted, xs[1], &[9u8; 32], &[1u8; 32], t).is_err());
}

#[test]
fn p10_every_position_a_one_member_ring_even_y_and_another_ring() {
    use crate::ring::{hash_to_point_tagged, sign_tagged, verify_tagged};
    let t = b"lij/tatara/seat/v1/2026-W41";
    for n in 1..=7 {
        let (xs, ring) = ring_of(n);
        for x in &xs {
            let sig = sign_tagged(&ring, *x, &[n as u8; 32], &[7u8; 32], t).unwrap();
            verify_tagged(&ring, &[n as u8; 32], &sig, t).unwrap();
        }
    }
    let (xs, ring) = ring_of(4);
    for p in &ring {
        assert_eq!(hash_to_point_tagged(p, t).serialize()[0], 0x02, "Hp_t has even y (lift_x)");
    }
    let sig = sign_tagged(&ring, xs[0], &[1u8; 32], &[7u8; 32], t).unwrap();
    let (_, other) = ring_of(4);
    assert!(verify_tagged(&other, &[1u8; 32], &sig, t).is_err(), "checked against another ring");
}

/// Known-answer values for the tagged variant (the adapter's verifier and any other implementation check against these;
/// P4 makes signing deterministic for a fixed aux).
fn kat_key(i: u32) -> Scalar {
    Scalar::from_slice(&crate::util::tagged_hash("lij/test/kat-key", &[&i.to_le_bytes()])).unwrap()
}

#[test]
fn p10_known_answers() {
    use crate::ring::{hash_to_point_tagged, key_image_tagged, sign_tagged, verify_tagged};
    let t = b"lij/tatara/seat/v1/2026-W41";
    let xs: Vec<Scalar> = (0..3).map(kat_key).collect();
    let mut ring: Vec<secp::Point> = xs.iter().map(|x| x.base_point_mul()).collect();
    ring.sort_by_key(|p| p.serialize());
    let signer = xs[1];
    let sig = sign_tagged(&ring, signer, &[0x42; 32], &[0u8; 32], t).unwrap();
    verify_tagged(&ring, &[0x42; 32], &sig, t).unwrap();
    let got = (
        ring.iter().map(|p| hex::encode(p.serialize())).collect::<Vec<_>>(),
        hex::encode(hash_to_point_tagged(&ring[0], t).serialize()),
        key_image_tagged(signer, t).to_string(),
        sig.c0.clone(),
        sig.s.clone(),
    );
    if std::env::var("LIJ_PRINT_KAT").is_ok() {
        println!("KAT {}", serde_json::to_string(&got).unwrap());
    }
    let want: (Vec<String>, String, String, String, Vec<String>) = serde_json::from_str(P10_KAT).unwrap();
    assert_eq!(got, want);
}

const P10_KAT: &str = r#"[["02032211446d417461b08f64b89e98896948e64cca9f0fd4865130ce446d712047","0371d255e3be5e8f95aacb7502bd489d3daa52983a8b1ac67460cd502e02190d0f","03cf270318ba395c546401776e336d0345c68898cd1650d4645a64bf35ca9c6006"],"028fb52c6044f06312dbd3d226f55cf005abd3ba772501b8ca137652a8f88888be","02ccb6b11b832f59132e2896e3b355645d3a2c3a20c5a7feac645748f0e0a03647","d0f7859d4db5ce3f4a6e30c82af9200daa3d84b4f554762ec7c62fe56f0975c4",["fd7517a510990f3a844836c6e760664e20b0618291654a950b39426b0c703baf","d33e44d296f2b466669eb4764bffd2bdcdc9a28441511ccaf5572d9a2d28a0a1","85dde66fc8dbb4c54eb03883d2e378d14bd42c11adfb7558f2076be53a773c6f"]]"#;
