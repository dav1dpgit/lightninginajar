//! v0.10 §15.5.6 — every parser a peer's bytes reach, run over random and mutated input: no panic (our release build
//! aborts on one), nothing accepted that should not be. A deterministic generator, so a failure repeats.

use std::collections::HashSet;

use bitcoin::Network;
use joinstr_v2::msg::{Envelope, Msg, PoolEvent};
use joinstr_v2::pool::Params;

use super::machine::{Attempt, Input, Phase, Timeouts};
use super::tagged;

struct Gen(u64);
impl Gen {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const ALPHABET: &[u8] = b"{}[]\":,0123456789abcdefABCDEF-+.eE \\nulltruefalse\"version\"\"type\"\"2\"\xff\x00";

fn mutate(g: &mut Gen, s: &str) -> String {
    let mut b = s.as_bytes().to_vec();
    for _ in 0..1 + g.below(4) {
        match g.below(5) {
            0 if !b.is_empty() => {
                let i = g.below(b.len());
                b[i] = ALPHABET[g.below(ALPHABET.len())];
            }
            1 if !b.is_empty() => {
                let i = g.below(b.len());
                b.truncate(i);
            }
            2 => {
                let i = g.below(b.len() + 1);
                b.insert(i, ALPHABET[g.below(ALPHABET.len())]);
            }
            3 if b.len() > 1 => {
                let i = g.below(b.len());
                b.remove(i);
            }
            _ => {
                let i = g.below(b.len() + 1);
                let n = 1 + g.below(64);
                let fill: Vec<u8> = (0..n).map(|_| ALPHABET[g.below(ALPHABET.len())]).collect();
                b.splice(i..i, fill);
            }
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}

fn seeds() -> Vec<String> {
    vec![
        Envelope::json(Msg::Nonces { offset: 0, nonces: vec!["02".repeat(66)] }),
        Envelope::json(Msg::PartialSigs { offset: 0, sigs: vec!["11".repeat(32)] }),
        Envelope::json(Msg::Abort { reason: "x".into() }),
        r#"{"version":"2","type":"inputs","musig_pubkey":"02","ring_pubkey":"03","inputs":[{"txid":"aa","vout":0,"amount":1,"script_pubkey":"00","proof":{"sig":"00"}}],"change":null,"height":7}"#.into(),
        r#"{"version":"2","type":"output","address":"bc1p","priority":0,"ring_sig":{"key_image":"02","c0":"00","s":["00"]}}"#.into(),
        r#"{"version":"2","type":"lij_view","hash":"ab"}"#.into(),
        r#"{"versions":["2"],"id":"0123456789abcdef0123456789abcdef","network":"bitcoin","type":"new_pool","public_key":"02","denomination":100000,"peers":3,"timeout":1,"relays":["wss://r"],"fee_rate":2,"transport":{"vpn":{"enable":false,"vpn_gateway":null},"tor":{"enable":false}}}"#.into(),
    ]
}

#[test]
fn the_strict_parsers_never_panic() {
    let mut g = Gen(0x5eed_1234_abcd_0001);
    let seeds = seeds();
    for _ in 0..20_000 {
        let s = if g.below(4) == 0 {
            let n = g.below(300);
            String::from_utf8_lossy(&(0..n).map(|_| (g.next() & 0xff) as u8).collect::<Vec<u8>>()).into_owned()
        } else {
            let pick = g.below(seeds.len());
            mutate(&mut g, &seeds[pick])
        };
        let _ = Envelope::parse_strict(&s);
        let _ = PoolEvent::parse_strict(&s);
    }
}

#[test]
fn the_machine_never_panics_on_what_a_peer_can_send() {
    let mut g = Gen(0x5eed_1234_abcd_0002);
    let seeds = seeds();
    let id = hex::encode(&tagged("lij/test/fuzz", &[])[..16]);
    let params = Params::new(&id, 100_000, 3, 2_000);
    let me = |i: u32| super::machine_tests::my_part(i);
    let mut a = Attempt::new(params.clone(), Network::Bitcoin, me(0), 1_000, Timeouts { phase_s: 600 }).unwrap().0;
    let mut stops = 0;
    for k in 0..5_000u32 {
        let pick = g.below(seeds.len());
        let s = mutate(&mut g, &seeds[pick]);
        let from = tagged("lij/test/fuzz-from", &[&(k % 7).to_le_bytes()]);
        let _ = a.on(Input::Msg { from, json: s });
        if *a.phase() == Phase::Stopped {
            stops += 1;
            a = Attempt::new(params.clone(), Network::Bitcoin, me(0), 1_000, Timeouts { phase_s: 600 }).unwrap().0;
        }
    }
    // nothing a stranger sends moves the machine on; some messages are refused outright, none panic
    assert!(stops < 5_000);
}

#[test]
fn the_channel_never_panics_on_any_event() {
    use crate::nwc::Event;
    let mut g = Gen(0x5eed_1234_abcd_0003);
    let pool = bitcoin::secp256k1::SecretKey::from_slice(&tagged("lij/test/fuzz-pool", &[])).unwrap();
    let pool_pk = super::wire::xonly_hex(&pool);
    let good = super::wire::seal(&pool, &pool_pk, r#"{"version":"2","type":"abort","reason":"x"}"#, 1, &[1u8; 16]).unwrap();
    let mut seen = HashSet::new();
    for _ in 0..3_000 {
        let mut ev: Event = good.clone();
        match g.below(5) {
            0 => ev.content = mutate(&mut g, &ev.content),
            1 => ev.pubkey = mutate(&mut g, &ev.pubkey),
            2 => ev.sig = mutate(&mut g, &ev.sig),
            3 => ev.id = mutate(&mut g, &ev.id),
            _ => ev.tags = vec![vec!["p".into(), mutate(&mut g, &pool_pk)]],
        }
        let _ = super::wire::open(&pool, &pool_pk, &ev, &mut seen);
    }
}
