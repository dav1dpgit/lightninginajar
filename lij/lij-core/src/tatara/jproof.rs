//! S59 (DP 2026-10-14 17:51 "Phase 2 … the compatibility proof with fractional fee rates first"): THE COMPATIBILITY
//! PROOF — this engine's pool member (`Phone`, the patched joinstr v2 core in lij/patches/joinstr-v2) in a pool with the
//! PUBLIC joinstr v2 code, unchanged (docs/design/mix/ref/joinstr-v2-20261006, built as it is), on a nostr relay, the
//! chain mocked. Two directions:
//!   `jproof_join`   — the public code creates the pool (`joinstr-v2 create`), two public members join, THIS engine joins
//!                     as the third through the public handshake (join_pool → credentials), registers its coin, signs the
//!                     exits and the funding, and the pool completes on every side;
//!   `jproof_create` — THIS engine creates the pool and announces it as the public code expects, answers the public
//!                     members' join requests with the pool's credentials, and the pool completes.
//! The harness speaks to the relay over its TCP line bridge (jproof/relay.py, port+1) and to the mock Esplora
//! (jproof/mock_esplora.py) over plain HTTP — std::net only, nothing added to the engine's dependencies. The public
//! members are started by the driver script (jproof/run_proof.sh); their logs are the other half of the verdict.
//! Run: JPROOF_RELAY_TCP=127.0.0.1:7448 JPROOF_ESPLORA=127.0.0.1:7446 JPROOF_RATE=2 cargo +stable test -p lij-core
//!      --offline --lib jproof -- --ignored --nocapture --test-threads 1
#![cfg(test)]

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut, Txid};
use joinstr_v2::msg::PoolEvent;

use super::caps::Declared;
use super::phone::{Common, Joined, Phone, PublicJoin, Out, ANNOUNCE_KIND};
use super::tagged;
use crate::nwc::Event;

fn now_s() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
fn env(k: &str) -> Option<String> { std::env::var(k).ok().filter(|v| !v.is_empty()) }

// ── the relay's TCP line bridge ──
struct Relay { r: BufReader<TcpStream>, w: TcpStream }
impl Relay {
    fn connect(addr: &str) -> Relay {
        let s = TcpStream::connect(addr).expect("relay tcp");
        s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        Relay { r: BufReader::new(s.try_clone().unwrap()), w: s }
    }
    fn send(&mut self, line: &str) { self.w.write_all(line.as_bytes()).unwrap(); self.w.write_all(b"\n").unwrap(); }
    fn req(&mut self, sid: &str, filter: serde_json::Value) { self.send(&serde_json::json!(["REQ", sid, filter]).to_string()); }
    fn post(&mut self, ev_json: &str) { let ev: serde_json::Value = serde_json::from_str(ev_json).unwrap(); self.send(&serde_json::json!(["EVENT", ev]).to_string()); }
    /// Every event line waiting (returns the events' JSON), without blocking beyond the read timeout.
    fn drain(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let v: serde_json::Value = match serde_json::from_str(line.trim()) { Ok(v) => v, Err(_) => continue };
                    if v[0] == "EVENT" { out.push(v[2].to_string()); }
                }
                Err(_) => break,
            }
        }
        out
    }
}

// ── the mock Esplora over plain HTTP ──
fn http(addr: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("esplora tcp");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let b = body.unwrap_or("");
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{b}", b.len());
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new(); let _ = s.read_to_string(&mut resp);
    let status: u16 = resp.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn p2wpkh(k: &SecretKey) -> ScriptBuf { Address::p2wpkh(&CompressedPublicKey(k.public_key(&Secp256k1::new())), Network::Signet).script_pubkey() }
fn p2tr(k: &SecretKey) -> ScriptBuf { let secp = Secp256k1::new(); Address::p2tr(&secp, k.x_only_public_key(&secp).0, None, Network::Signet).script_pubkey() }
fn sk(label: &str, i: u32) -> SecretKey { SecretKey::from_slice(&tagged("lij/jproof", &[label.as_bytes(), &i.to_le_bytes(), &now_s().to_le_bytes()])).unwrap() }

/// The pool's secret handed over as the public code does it: a `credentials` message sealed from the pool key to the
/// joiner's key (NIP-04), tagged with the joiner's key.

struct Harness { relay: Relay, esplora: String, coin_sk: SecretKey, coin: (OutPoint, TxOut) }
impl Harness {
    fn new() -> Harness {
        let tcp = env("JPROOF_RELAY_TCP").expect("JPROOF_RELAY_TCP");
        let esplora = env("JPROOF_ESPLORA").expect("JPROOF_ESPLORA");
        // this member's coin: a P2WPKH output the mock invents (130,000 sats, confirmed)
        let coin_sk = sk("coin", 1);
        let spk = p2wpkh(&coin_sk);
        let (st, body) = http(&esplora, "POST", "/_fund_spk", Some(&serde_json::json!({ "spk": spk.to_hex_string(), "value": 130_000 }).to_string()));
        assert_eq!(st, 200, "fund: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let op = OutPoint::new(v["txid"].as_str().unwrap().parse::<Txid>().unwrap(), v["vout"].as_u64().unwrap() as u32);
        Harness { relay: Relay::connect(&tcp), esplora, coin_sk, coin: (op, TxOut { value: Amount::from_sat(130_000), script_pubkey: spk }) }
    }
    fn tip(&self) -> u32 { http(&self.esplora, "GET", "/blocks/tip/height", None).1.trim().parse().unwrap() }
    fn common(&self, peers: usize, rate_at_join: u64, relay_url: &str) -> Common {
        Common {
            attempt_id: "jproof".into(),
            declared: Declared { sizes: vec![50_000, 100_000], max_fee_sat_vb: 20, relay: relay_url.into(), network: "signet".into(), max_timeout_s: 3_600 },
            size: 100_000, peers,
            coins: vec![(self.coin.0, self.coin.1.clone(), self.coin_sk)],
            payout: Some(p2tr(&sk("payout", 1))), payout_index: Some(7),
            change_spk: p2wpkh(&sk("change", 1)), change_index: 3,
            tip: self.tip(), rate_at_join,
            entropy: tagged("lij/jproof/entropy", &[&now_s().to_le_bytes()]),
            now: now_s(), refused: vec![], network: Network::Signet, public: true,
        }
    }
    /// A coin check as a provider would answer it: the output exists, is unspent, and is as registered.
    fn coin_ok(&self, txid: &str, vout: u32, sats: u64, spk_hex: &str) -> bool {
        let (st, body) = http(&self.esplora, "GET", &format!("/tx/{txid}"), None);
        if st != 200 { return false; }
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let o = &v["vout"][vout as usize];
        if o["value"].as_u64() != Some(sats) || o["scriptpubkey"].as_str() != Some(spk_hex) { return false; }
        let (_, sp) = http(&self.esplora, "GET", &format!("/tx/{txid}/outspends"), None);
        let s: serde_json::Value = serde_json::from_str(&sp).unwrap();
        s[vout as usize]["spent"].as_bool() == Some(false)
    }
    /// The page's loop: post what the phone says, answer its coin checks, save its record, tick, read the relay —
    /// until the funding is complete (then broadcast it and the exits) or the phone stops.
    fn drive(&mut self, phone: &mut Phone, mut out: Out, deadline_s: u64) -> super::phone::Complete {
        let start = Instant::now();
        let mut seen = HashSet::new();
        let mut last_tick = Instant::now();
        loop {
            // what the phone says
            for e in out.relay.drain(..) { self.relay.post(&e); }
            for e in out.payout.drain(..) { self.relay.post(&e); }
            let checks: Vec<_> = out.checks.drain(..).collect();
            for c in checks { let ok = self.coin_ok(&c.txid, c.vout, c.amount_sat, &c.script_pubkey_hex); let o = phone.coin_result(&c.txid, c.vout, Some(ok), now_s()).unwrap(); out.merge(o); }
            if out.save.take().is_some() { let o = phone.record_saved(now_s()).unwrap(); out.merge(o); }
            if let Some(s) = out.stopped.take() { panic!("the phone stopped: {} ({})", s.reason, s.outcome); }
            if let Some(c) = out.complete.take() {
                for hex in super::phone::send_order(&c).unwrap() {
                    let (st, body) = http(&self.esplora, "POST", "/tx", Some(&hex));
                    assert_eq!(st, 200, "broadcast refused: {body}");
                    eprintln!("[lij] broadcast {}", body.trim());
                }
                return c;
            }
            // the relay
            for ev_json in self.relay.drain() {
                let ev: Event = match serde_json::from_str(&ev_json) { Ok(e) => e, Err(_) => continue };
                if !seen.insert(ev.id.clone()) { continue; }
                let o = phone.relay_event(&ev_json, now_s()).unwrap();
                out.merge(o);
            }
            if last_tick.elapsed() >= Duration::from_secs(1) { last_tick = Instant::now(); let o = phone.tick(now_s()).unwrap(); out.merge(o); }
            assert!(start.elapsed().as_secs() < deadline_s, "the pool did not complete in {deadline_s} s (phase {})", out.phase);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// THIS engine joins a pool the public code created.
#[test]
#[ignore]
fn jproof_join() {
    let mut h = Harness::new();
    let relay_url = env("JPROOF_RELAY_URL").unwrap_or_else(|| "ws://127.0.0.1:7447".into());
    let rate_at_join: u64 = env("JPROOF_RATE").map(|v| v.parse::<f64>().unwrap().ceil() as u64).unwrap_or(2);   // the rate the wallet showed at Join (whole sat/vB); the pool's may be a fraction
    // 1. find the pool: kind 2022 of the last hour
    h.relay.req("pools", serde_json::json!({ "kinds": [ANNOUNCE_KIND], "since": now_s() - 3600 }));
    let start = Instant::now();
    let pe = loop {
        let mut found = None;
        for ev_json in h.relay.drain() {
            let ev: Event = match serde_json::from_str(&ev_json) { Ok(e) => e, Err(_) => continue };
            if ev.kind != ANNOUNCE_KIND { continue; }
            match PoolEvent::parse_strict(&ev.content) {
                Ok(p) if p.timeout > now_s() => { eprintln!("[lij] found pool {} ({} peers, {} sats, {} sat/vB)", p.id, p.peers, p.denomination, p.fee_rate); found = Some((ev, p)); }
                Ok(_) => {}
                Err(e) => eprintln!("[lij] a pool event our strict parser refuses: {e:#}"),
            }
        }
        if let Some(f) = found { break f; }
        assert!(start.elapsed().as_secs() < 120, "no pool found");
        std::thread::sleep(Duration::from_millis(200));
    };
    let (ann_ev, pe) = pe;
    assert_eq!(ann_ev.pubkey, pe.public_key, "the announcement's author is the pool key (its nostr x-only key, as the public code writes it)");
    // 2. the engine's own public path (v336): PublicJoin sends join_pool and turns the credentials into the phone
    let c = h.common(pe.peers, rate_at_join, &relay_url);
    let (join, out) = match PublicJoin::new(c, &serde_json::to_string(&ann_ev).unwrap()) {
        Ok(x) => x,
        Err(e) => panic!("PublicJoin refused the public pool: {e:#}"),
    };
    h.relay.req("dm", serde_json::from_str(&join.relay_filter()).unwrap());
    for e in &out.relay { h.relay.post(e); }
    let mut join = Some(join);
    let (mut phone, out) = loop {
        let mut got = None;
        for ev_json in h.relay.drain() {
            let Some(j) = join.take() else { break };
            match j.relay_event(&ev_json, now_s()).unwrap() {
                Joined::Phone(p, o) => { got = Some((p, o)); }
                Joined::Waiting(j) => { join = Some(j); }
                Joined::Rejected => panic!("the pool rejected us"),
            }
        }
        if let Some(x) = got { break x; }
        if let Some(why) = join.as_ref().and_then(|j| j.timed_out(now_s())) { panic!("{why}"); }
        assert!(start.elapsed().as_secs() < 120, "no credentials");
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(phone.is_public());
    eprintln!("[lij] joined pool {} (the engine's public path)", pe.id);
    h.relay.req("pool", serde_json::from_str(&phone.relay_filter()).unwrap());
    let complete = h.drive(&mut phone, out, 300);
    eprintln!("[lij] complete: the funding {} and {} exits", phone.funding_txid().unwrap(), complete.exits_hex.len());
    assert_eq!(complete.exits_hex.len(), pe.peers - 1);
}

/// THIS engine creates the pool; the public code's members join through the public handshake.
#[test]
#[ignore]
fn jproof_create() {
    let mut h = Harness::new();
    let relay_url = env("JPROOF_RELAY_URL").unwrap_or_else(|| "ws://127.0.0.1:7447".into());
    let rate: u64 = env("JPROOF_RATE").map(|v| v.parse().expect("a created pool's rate is whole sat/vB (a provider's pool)")).unwrap_or(2);
    let peers: usize = env("JPROOF_PEERS").map(|v| v.parse().unwrap()).unwrap_or(3);
    let c = h.common(peers, rate, &relay_url);
    // v336: the engine's public pool — no seats named; the phone answers the public members' join requests itself
    let (mut phone, ann, out) = Phone::create_public(c, rate).unwrap();
    let ann_ev: Event = serde_json::from_str(&ann).unwrap();
    assert!(ann_ev.tags.is_empty(), "a public announcement names no seats");
    let pe = PoolEvent::parse_strict(&ann_ev.content).unwrap();
    eprintln!("[lij] created pool {} ({} peers, {} sats, {} sat/vB) — the engine's public path", pe.id, pe.peers, pe.denomination, pe.fee_rate);
    h.relay.post(&serde_json::to_string(&ann_ev).unwrap());
    h.relay.req("pool", serde_json::from_str(&phone.relay_filter()).unwrap());
    let complete = h.drive(&mut phone, out, 300);
    eprintln!("[lij] complete: the funding {} and {} exits", phone.funding_txid().unwrap(), complete.exits_hex.len());
    assert_eq!(complete.exits_hex.len(), peers - 1);
}
