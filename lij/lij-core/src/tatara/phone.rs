//! One phone's attempt, as the page drives it (step 8, slice 1 — S58; spec v0.10 §4.8, §5, §8; docs/design/mix/
//! tatara-phone-r1.md). Pure: the page carries the bytes (the relay's WebSocket, the forwarder, the coin checks, the
//! provider's routes); lij-wasm keeps one `Phone` per attempt and saves the record when asked.
//!
//! - **The pool's key never reaches the provider.** The creating phone makes the pool (its key, the joinstr v2 pool
//!   event with the declared options) and hands the provider an announcement: a nostr event (kind 2022) signed by the
//!   pool's key, the pool event as its content, and one `lij_key` tag per other opened seat — the pool's secret key
//!   sealed (NIP-04) to that seat's key. Only a seat can open its copy; the provider passes the event on and learns the
//!   pool's PUBLIC key (it opens the relay room with it), nothing more.
//! - **A joining phone** checks the announcement before anything else: the event's signature, its author is the pool
//!   event's key, its copy of the key opens and matches, the options are exactly Phase 1's and the provider's declared
//!   ones (caps::phase1_pool), the size, the number of people and the relay are the provider's start message's, and the
//!   fee is within this person's limit (else it does not take part and keeps its place).
//! - **Then the state machine** (machine.rs) runs, its messages sealed under a session key (wire.rs); its payout under a
//!   one-time key for the forwarder; every random byte from the 32 handed in at the start (P4).
//! - **After this phone's funding signature** it keeps reading the relay for the other members' funding signatures:
//!   with every input's witness the funding is complete, and the page sends it with the exits and hands both to the
//!   provider's backup (§5.5).

use std::collections::{HashMap, HashSet};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use joinstr_v2::msg::{Envelope, Msg, PoolEvent};
use musig2::secp::Scalar;
use serde::Serialize;

use super::caps::{self, Declared};
use super::machine::{Action, Attempt, Input, MyPart, Phase, Timeouts};
use super::records::StoredRecord;
use super::rederive::my_change;
use super::{tagged, wire};
use crate::nwc::{self, Event};

/// The announcement's nostr kind (joinstr v2's pool event kind).
pub const ANNOUNCE_KIND: u32 = 2022;
/// Each phase of the setup may take this long before the attempt stops (the app is open throughout).
pub const PHASE_S: u64 = 120;
/// How long a pool may run, from its creation (the provider's ATTEMPT_MAX_S).
pub const POOL_TIMEOUT_S: u64 = 3_600;
/// The smallest change worth an output (a P2WPKH output's dust limit).
pub const CHANGE_DUST: u64 = 294;

/// What every phone brings to an attempt.
pub struct Common {
    /// The provider's attempt id (its start message).
    pub attempt_id: String,
    /// The provider's declared limits, with the relay its start message names.
    pub declared: Declared,
    /// The size and the number of people the provider's start message gives.
    pub size: u64,
    pub peers: usize,
    /// This phone's coins, as joinstr takes them (wallet::coin_for_pool).
    pub coins: Vec<(OutPoint, TxOut, SecretKey)>,
    /// The payout (store::hand_out), and its m/86 index when it is this wallet's. None in a channel pool (Phase 1b,
    /// v0.10 §6.2): the payout is the channel's funding script, given once the page opens the channel.
    pub payout: Option<ScriptBuf>,
    pub payout_index: Option<u32>,
    /// The change address handed out for this attempt, and its m/84 change index (v329: the record keeps both).
    pub change_spk: ScriptBuf,
    pub change_index: u32,
    /// This wallet's chain tip (the registration's height).
    pub tip: u32,
    /// The fee rate shown when the person joined (sat/vB) — the limit's base.
    pub rate_at_join: u64,
    /// 32 fresh bytes from the engine's random source; every random byte of the attempt comes from them.
    pub entropy: [u8; 32],
    pub now: u64,
    /// Coins of sessions that stalled or misbehaved in an earlier try (§8 rule 2).
    pub refused: Vec<OutPoint>,
    pub network: Network,
    /// v335 (Phase 2): a public pool — other joinstr clients at the table, who send no `lij_view` (machine.rs `public`).
    pub public: bool,
}

/// A coin the page must check (v0.10 §7): through a provider's coin check, then `coin_result`.
#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CoinAsk {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
}

/// The funding, complete with every member's signature, and the signed exits — to send, and to hand to the provider.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Complete {
    pub funding_hex: String,
    pub exits_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Stop {
    /// Plain words for the log; the screen says "Not started — your coin has not entered the pool".
    pub reason: String,
    /// What /tatara/report takes: "stopped" or "stopped_at_payouts" (the anonymous step — no one can be named).
    pub outcome: String,
    /// The sessions the rules name (P7, S1) — their coins are refused in a retry.
    pub named_coins: Vec<(String, u32)>,
    /// True when a record was saved for this attempt and this phone had not yet signed: the page wipes it at once.
    pub wipe_record: bool,
    /// Phase 1b: a channel was opened for this attempt (a stop before the funding signature drops it on both sides,
    /// §6.2.4; after the signature the channel is kept until the chain decides, §6.3.4).
    #[serde(default)]
    pub channel_opened: bool,
}

/// What the page does next.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Out {
    /// Events to post on the pool's relay (["EVENT", e]).
    pub relay: Vec<String>,
    /// The payout's event, for the forwarder (POST /tatara/forward/payout at another provider).
    pub payout: Vec<String>,
    pub checks: Vec<CoinAsk>,
    /// Save this record (before the funding signature), then call `record_saved`.
    pub save: Option<StoredRecord>,
    /// This phone's part is done (report "funding_signed").
    pub funding_signed: bool,
    pub complete: Option<Complete>,
    pub stopped: Option<Stop>,
    pub phase: String,
    /// Phase 1b (§6.2.1): open a channel of exactly this many sats with the provider, then call `payout_given` with its
    /// funding script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_channel: Option<u64>,
    /// Phase 1b (§6.2.2): the exit that pays this phone's channel (txid, vout) — hand LDK the outpoint; once the channel
    /// is saved with the provider's signature, call `channel_saved`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fund_channel: Option<(String, u32)>,
    /// v337: the members registered so far, this phone included (a public room's "2 of 3" on the card).
    #[serde(default)]
    pub members: usize,
}

impl Out {
    pub fn merge(&mut self, o: Out) {
        self.relay.extend(o.relay);
        self.payout.extend(o.payout);
        self.checks.extend(o.checks);
        if o.save.is_some() { self.save = o.save; }
        self.funding_signed |= o.funding_signed;
        if o.open_channel.is_some() { self.open_channel = o.open_channel; }
        if o.fund_channel.is_some() { self.fund_channel = o.fund_channel; }
        if o.complete.is_some() { self.complete = o.complete; }
        if o.stopped.is_some() { self.stopped = o.stopped; }
        self.phase = o.phase;
    }
}

fn derive(entropy: &[u8; 32], label: &str, n: u32) -> [u8; 32] {
    tagged("lij/tatara/phone/v1", &[entropy, label.as_bytes(), &n.to_le_bytes()])
}

fn secret(entropy: &[u8; 32], label: &str, n: u32) -> Result<SecretKey> {
    SecretKey::from_slice(&derive(entropy, label, n)).context("a derived key is out of range")
}

fn scalar(entropy: &[u8; 32], label: &str) -> Result<Scalar> {
    Scalar::from_slice(&derive(entropy, label, 0)).map_err(|_| anyhow::anyhow!("a derived scalar is out of range"))
}

fn xonly(sk: &SecretKey) -> [u8; 32] {
    sk.x_only_public_key(&Secp256k1::new()).0.serialize()
}

pub struct Phone {
    attempt_id: String,
    pool_id: String,
    pool_sk: SecretKey,
    pool_x: String,
    session_sk: SecretKey,
    entropy: [u8; 32],
    n: u32,
    seen: HashSet<String>,
    machine: Attempt,
    payout_index: Option<u32>,
    change: (ScriptBuf, u32),
    /// Phase 1b: a channel was opened for this attempt (Action::OpenChannel went out).
    channel_opened: bool,
    funding: Option<Transaction>,
    exits: Vec<String>,
    witnesses: HashMap<OutPoint, Witness>,
    complete_given: bool,
    asked: Vec<(OutPoint, TxOut)>,
    /// v328: None = no provider answered for that coin.
    answers: HashMap<OutPoint, Option<bool>>,
    record_saved: bool,
    signed: bool,
    done: bool,
    /// v336 (Phase 2a): a public pool — this phone created it on a public relay and answers `join_pool` with the pool's
    /// key while seats remain (the public code's handshake), or joined one that way (PublicJoin).
    public: bool,
    /// v336: the joiners this creating phone has answered (their keys); at most peers − 1.
    joiners: Vec<[u8; 32]>,
    /// v336: this phone created the pool (only the creator answers join requests — the public code's pool_sender).
    creator: bool,
}

/// The creating phone's pool: the pool event with the declared Phase 1 options, and the announcement for the provider.
fn make_announcement(c: &Common, fee_rate_sat_vb: u64, seat_pks: &[String], pool_sk: &SecretKey, pool_id: &str) -> Result<String> {
    ensure!(c.public || seat_pks.len() + 1 == c.peers, "{} other seats for a pool of {}", seat_pks.len(), c.peers);   // v336: a public pool's seats come by join_pool
    ensure!(!c.public || seat_pks.is_empty(), "a public pool names no seats");
    let mut uniq = HashSet::new();
    for k in seat_pks {
        ensure!(k.len() == 64 && k.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "a seat key is not 32 bytes of lowercase hex");
        ensure!(uniq.insert(k.clone()), "a seat named twice");
    }
    let secp = Secp256k1::new();
    let pool_pub = PublicKey::from_secret_key(&secp, pool_sk);
    let timeout = c.now + POOL_TIMEOUT_S.min(c.declared.max_timeout_s);
    let ev = serde_json::json!({
        "versions": ["2"], "id": pool_id, "network": c.declared.network, "type": "new_pool",
        "public_key": hex::encode(pool_pub.x_only_public_key().0.serialize()), "denomination": c.size, "peers": c.peers, "timeout": timeout,   // v335 (the proof): the pool's nostr key, as the public code writes and checks it (P11)
        "relays": [c.declared.relay], "fee_rate": fee_rate_sat_vb,
        "transport": {"vpn": {"enable": false, "vpn_gateway": null}, "tor": {"enable": false}}
    });
    let mut ev = ev;
    if c.payout.is_none() { ev["payout_type"] = serde_json::Value::String("p2wsh".into()); }   // P1: a channel pool (Phase 1b)
    let ev = ev.to_string();
    let mut tags: Vec<Vec<String>> = Vec::with_capacity(seat_pks.len());
    for (i, k) in seat_pks.iter().enumerate() {
        let shared = nwc::ecdh_x(pool_sk, &nwc::pubkey_from_hex(k).map_err(|e| anyhow::anyhow!("{e}"))?).map_err(|e| anyhow::anyhow!("{e}"))?;
        let iv: [u8; 16] = derive(&c.entropy, "seal-iv", i as u32)[..16].try_into().expect("16 bytes");
        let sealed = nwc::nip04_encrypt_with_iv(&shared, &iv, &hex::encode(pool_sk.secret_bytes())).map_err(|e| anyhow::anyhow!("{e}"))?;
        tags.push(vec!["lij_key".into(), k.clone(), sealed]);
    }
    let e = nwc::sign_event(pool_sk, c.now, ANNOUNCE_KIND, tags, ev);
    serde_json::to_string(&e).context("announcement")
}

/// v336 (Phase 2a): what a pool announcement found on a public relay says — for the page's list of public pools, from
/// the engine's strict parse (a pool the engine would refuse is not listed). `lij` is true for a provider's pool
/// (lij_key tags: joined through the provider, never by the handshake).
#[derive(Clone, Debug, Serialize)]
pub struct PoolSummary {
    pub id: String,
    pub pool_pk: String,
    pub peers: usize,
    pub denomination: u64,
    pub fee_rate: f64,
    pub timeout: u64,
    pub network: String,
    pub lij: bool,
}

pub fn public_pool_summary(pool_event_json: &str) -> Result<PoolSummary> {
    ensure!(pool_event_json.len() <= 64 * 1024, "pool event too large");
    let e: Event = serde_json::from_str(pool_event_json).context("the pool event")?;
    ensure!(e.kind == ANNOUNCE_KIND, "not a pool announcement");
    nwc::verify_event(&e).map_err(|e| anyhow::anyhow!("the announcement's id or signature: {e}"))?;
    let pe = PoolEvent::parse_strict(&e.content)?;
    ensure!(pe.public_key == e.pubkey, "the announcement is not signed by the pool's key");
    let lij = e.tags.iter().any(|t| !t.is_empty() && t[0] == "lij_key");
    Ok(PoolSummary { id: pe.id.clone(), pool_pk: pe.public_key.clone(), peers: pe.peers, denomination: pe.denomination, fee_rate: pe.fee_rate, timeout: pe.timeout, network: pe.network.clone(), lij })
}

/// v336 (Phase 2a): the public handshake, the joiner's side. A pool found on a public relay (a signed kind-2022 event
/// — the public Joinstr code's, or another LiJ's public pool) is joined the way the public code joins: a `join_pool`
/// message under a key made for this one pool, sealed to the pool's key; the creator answers with `credentials`, the
/// pool's secret key, sealed to that key. With the key in hand the phone starts as any joining phone does. The same
/// checks a LiJ join makes come first (the pool's size, network, timeout, the fee limit), before anything is sent.
pub struct PublicJoin {
    c: Common,
    pe: PoolEvent,
    eph_sk: SecretKey,
    eph_x: String,
    since: u64,
}

/// How long a public join waits for its credentials (the public code's creator answers within its poll interval).
pub const JOIN_WAIT_S: u64 = 90;

/// What a public join's relay event led to.
pub enum Joined {
    /// The credentials came: the phone, and its first Out (the registration).
    Phone(Phone, Out),
    /// Not the answer yet — keep waiting.
    Waiting(PublicJoin),
    /// The creator refused (its reason is not shown — S7).
    Rejected,
}

impl PublicJoin {
    pub fn new(c: Common, pool_event_json: &str) -> Result<(PublicJoin, Out)> {
        ensure!(c.public, "a public join needs a public seat");
        ensure!(pool_event_json.len() <= 64 * 1024, "pool event too large");
        let e: Event = serde_json::from_str(pool_event_json).context("the pool event")?;
        ensure!(e.kind == ANNOUNCE_KIND, "not a pool announcement");
        nwc::verify_event(&e).map_err(|e| anyhow::anyhow!("the announcement's id or signature: {e}"))?;
        let pe = PoolEvent::parse_strict(&e.content)?;
        ensure!(pe.public_key == e.pubkey, "the announcement is not signed by the pool's key");
        ensure!(!e.tags.iter().any(|t| t.len() >= 1 && t[0] == "lij_key"), "a provider's pool: joined through the provider, not the public handshake");
        Phone::checks(&c, &pe)?;
        let eph_sk = secret(&c.entropy, "public-join", 0)?;
        let eph_x = hex::encode(xonly(&eph_sk));
        let iv: [u8; 16] = derive(&c.entropy, "join-iv", 0)[..16].try_into().expect("16 bytes");
        let jp = wire::seal(&eph_sk, &pe.public_key, &Envelope::json(Msg::JoinPool {}), c.now, &iv)?;
        let out = Out { relay: vec![serde_json::to_string(&jp)?], phase: "joining".into(), ..Default::default() };
        let since = c.now;
        Ok((PublicJoin { c, pe, eph_sk, eph_x, since }, out))
    }

    /// The relay subscription while waiting: messages to this join's key.
    pub fn relay_filter(&self) -> String {
        serde_json::json!({ "kinds": [wire::KIND], "#p": [self.eph_x] }).to_string()
    }

    pub fn pool_id(&self) -> &str {
        &self.pe.id
    }

    pub fn pool_pk(&self) -> &str {
        &self.pe.public_key
    }

    /// An event the page read under this join's filter.
    pub fn relay_event(self, event_json: &str, now: u64) -> Result<Joined> {
        if event_json.len() > 64 * 1024 { return Ok(Joined::Waiting(self)); }
        let e: Event = match serde_json::from_str(event_json) { Ok(e) => e, Err(_) => return Ok(Joined::Waiting(self)) };
        if e.kind != wire::KIND || e.pubkey != self.pe.public_key || !e.tags.iter().any(|t| t.len() >= 2 && t[0] == "p" && t[1] == self.eph_x) || e.content.len() > wire::MAX_CONTENT {
            return Ok(Joined::Waiting(self));
        }
        if nwc::verify_event(&e).is_err() { return Ok(Joined::Waiting(self)); }
        let pool_pub = match nwc::pubkey_from_hex(&e.pubkey) { Ok(p) => p, Err(_) => return Ok(Joined::Waiting(self)) };
        let json = match nwc::ecdh_x(&self.eph_sk, &pool_pub).and_then(|s| nwc::nip04_decrypt(&s, &e.content)) { Ok(j) => j, Err(_) => return Ok(Joined::Waiting(self)) };
        if json.len() > caps::MAX_MESSAGE_BYTES { return Ok(Joined::Waiting(self)); }
        match Envelope::parse_strict(&json).map(|e| e.msg) {
            Ok(Msg::Credentials { credentials }) => {
                ensure!(credentials.id == self.pe.id, "credentials for another pool");
                let pool_sk = SecretKey::from_slice(&hex::decode(&credentials.key).context("the pool key")?).context("the pool key")?;
                ensure!(hex::encode(pool_sk.x_only_public_key(&Secp256k1::new()).0.serialize()) == self.pe.public_key, "the credentials are not the pool's key");
                let mut c = self.c;
                c.now = now;
                let (p, out) = Phone::start(c, self.pe, pool_sk)?;
                Ok(Joined::Phone(p, out))
            }
            Ok(Msg::Reject { .. }) => Ok(Joined::Rejected),
            _ => Ok(Joined::Waiting(self)),
        }
    }

    /// Some(reason) when this join has waited too long or the pool's own timeout passed.
    pub fn timed_out(&self, now: u64) -> Option<String> {
        if now >= self.pe.timeout { return Some("the pool's time ran out before it answered".into()); }
        if now.saturating_sub(self.since) > JOIN_WAIT_S { return Some("the pool did not answer the join request".into()); }
        None
    }
}

/// A joining phone's copy of the pool's key, from the announcement: the event checked, its author the pool event's key,
/// this seat's copy opened and matching. Returns the pool event and the pool's secret key.
pub fn open_announcement(announcement: &str, seat_sk: &SecretKey) -> Result<(PoolEvent, SecretKey)> {
    ensure!(announcement.len() <= 32 * 1024, "announcement too large");
    let e: Event = serde_json::from_str(announcement).context("the announcement is not a nostr event")?;
    ensure!(e.kind == ANNOUNCE_KIND, "not a pool announcement");
    nwc::verify_event(&e).map_err(|err| anyhow::anyhow!("the announcement's signature: {err}"))?;
    let pe = PoolEvent::parse_strict(&e.content)?;
    ensure!(pe.public_key == e.pubkey, "the announcement is not signed by the pool's key");   // v335 (P11): the pool event's key is the author's nostr key
    let me = hex::encode(xonly(seat_sk));
    let tag = e.tags.iter().find(|t| t.len() == 3 && t[0] == "lij_key" && t[1] == me).context("the announcement holds no key for this seat")?;
    let shared = nwc::ecdh_x(seat_sk, &nwc::pubkey_from_hex(&e.pubkey).map_err(|err| anyhow::anyhow!("{err}"))?).map_err(|err| anyhow::anyhow!("{err}"))?;
    let sk_hex = nwc::nip04_decrypt(&shared, &tag[2]).map_err(|err| anyhow::anyhow!("this seat's key copy: {err}"))?;
    let pool_sk = SecretKey::from_slice(&hex::decode(sk_hex.trim()).context("the pool key copy")?).context("the pool key copy")?;
    ensure!(hex::encode(pool_sk.x_only_public_key(&Secp256k1::new()).0.serialize()) == pe.public_key, "this seat's key copy is not the pool's key");   // v335
    Ok((pe, pool_sk))
}

impl Phone {
    /// The creating phone (the provider's "create" notice): the pool, its announcement for the provider, and the start
    /// of its own part.
    pub fn create(c: Common, fee_rate_sat_vb: u64, seat_pks: &[String]) -> Result<(Phone, String, Out)> {
        ensure!(!c.public, "a public pool is created with create_public");
        Phone::create_any(c, fee_rate_sat_vb, seat_pks)
    }

    /// v336 (Phase 2a): a public pool on a public relay — the announcement names no seats; the other members arrive by
    /// the public code's handshake (`join_pool` → `credentials`, answered by this phone while seats remain). `c.public`
    /// must be set (the machine's public rules apply: S3 covers the LiJ members' views only).
    pub fn create_public(c: Common, fee_rate_sat_vb: u64) -> Result<(Phone, String, Out)> {
        ensure!(c.public, "a public pool needs a public seat");
        Phone::create_any(c, fee_rate_sat_vb, &[])
    }

    fn create_any(c: Common, fee_rate_sat_vb: u64, seat_pks: &[String]) -> Result<(Phone, String, Out)> {
        ensure!(fee_rate_sat_vb >= caps::RELAY_MIN_SAT_VB && fee_rate_sat_vb <= c.declared.max_fee_sat_vb, "the fee rate is outside what the provider declared");
        ensure!(caps::within_fee_limit(fee_rate_sat_vb, c.rate_at_join, c.declared.max_fee_sat_vb), "fees rose since you joined");
        let pool_sk = secret(&c.entropy, "pool", 0)?;
        let pool_id = hex::encode(&derive(&c.entropy, "pool-id", 0)[..16]);
        let ann = make_announcement(&c, fee_rate_sat_vb, seat_pks, &pool_sk, &pool_id)?;
        let e: Event = serde_json::from_str(&ann)?;
        let pe = PoolEvent::parse_strict(&e.content)?;
        let (mut phone, out) = Phone::start(c, pe, pool_sk)?;
        phone.creator = true;
        Ok((phone, ann, out))
    }

    /// A joining phone (the provider's "announcement" notice).
    pub fn join(c: Common, announcement: &str, seat_sk: &SecretKey) -> Result<(Phone, Out)> {
        let (pe, pool_sk) = open_announcement(announcement, seat_sk)?;
        Phone::start(c, pe, pool_sk)
    }

    /// The checks every joining phone makes on the pool event (v336: also before a public join sends its request).
    fn checks(c: &Common, pe: &PoolEvent) -> Result<joinstr_v2::pool::Params> {
        let params = caps::phase1_pool(pe, &c.declared, c.now)?;
        ensure!(pe.denomination == c.size, "the pool's size is not the provider's");
        ensure!((params.payout_type == joinstr_v2::pool::PayoutType::P2wsh) == c.payout.is_none(), "the pool's payout type is not this seat's route");
        ensure!(pe.peers == c.peers, "the pool's number of people is not the provider's");
        let rate = pe.fee_rate;
        ensure!(caps::within_fee_limit_milli((rate * 1000.0).round() as u64, c.rate_at_join, c.declared.max_fee_sat_vb), "fees rose since you joined — the pool's rate is {rate} sat/vB, you agreed to up to {}", c.rate_at_join.saturating_mul(3) / 2);
        ensure!(!c.coins.is_empty(), "no coin");
        Ok(params)
    }

    fn start(c: Common, pe: PoolEvent, pool_sk: SecretKey) -> Result<(Phone, Out)> {
        let params = Phone::checks(&c, &pe)?;
        let total_in: u64 = c.coins.iter().map(|(_, o, _)| o.value.to_sat()).sum();
        let spks: Vec<&bitcoin::Script> = c.coins.iter().map(|(_, o, _)| o.script_pubkey.as_script()).collect();
        let change = my_change(total_in, c.size, c.peers, params.fee_rate_milli, &spks, &c.change_spk, CHANGE_DUST)?
            .map(|v| TxOut { value: bitcoin::Amount::from_sat(v), script_pubkey: c.change_spk.clone() });
        let session_sk = secret(&c.entropy, "session", 0)?;
        let me = MyPart {
            coins: c.coins,
            change,
            tip: c.tip,
            payout: c.payout,
            session: xonly(&session_sk),
            musig: scalar(&c.entropy, "musig")?,
            ring: scalar(&c.entropy, "ring")?,
            entropy: derive(&c.entropy, "machine", 0),
            rate_at_join: c.rate_at_join,
        };
        let (machine, acts) = Attempt::new(params, c.network, me, c.now, Timeouts { phase_s: PHASE_S })?;
        let public = c.public;
        let mut machine = machine.refusing(c.refused).public(c.public);
        if public {
            machine = machine.first_phase_until(pe.timeout.saturating_add(PHASE_S));   // v338: the room fills while its announcement is open (+ one step), as the public code waits
        }
        let pool_x = hex::encode(pool_sk.x_only_public_key(&Secp256k1::new()).0.serialize());
        let mut p = Phone {
            attempt_id: c.attempt_id,
            pool_id: pe.id.clone(),
            pool_sk,
            pool_x,
            session_sk,
            entropy: c.entropy,
            n: 0,
            seen: HashSet::new(),
            machine,
            payout_index: c.payout_index,
            change: (c.change_spk.clone(), c.change_index),
            channel_opened: false,
            funding: None,
            exits: Vec::new(),
            witnesses: HashMap::new(),
            complete_given: false,
            asked: Vec::new(),
            answers: HashMap::new(),
            record_saved: false,
            signed: false,
            done: false,
            public,
            joiners: Vec::new(),
            creator: false,
        };
        let out = p.act(acts, c.now)?;
        Ok((p, out))
    }

    /// v336: a public pool (created here, or joined by the public handshake).
    pub fn is_public(&self) -> bool {
        self.public
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    fn machine_peers(&self) -> usize {
        self.machine.peers()
    }

    /// The attempt record's id (the pool's id).
    pub fn record_id(&self) -> &str {
        &self.pool_id
    }

    /// The pool's key as the relay knows it (x-only hex) — the REQ filter's "#p".
    pub fn pool_pk(&self) -> &str {
        &self.pool_x
    }

    /// The relay subscription: every pool message.
    pub fn relay_filter(&self) -> String {
        serde_json::json!({ "kinds": [wire::KIND], "#p": [self.pool_x] }).to_string()
    }

    fn next(&mut self, label: &str) -> [u8; 32] {
        self.n += 1;
        derive(&self.entropy, label, self.n)
    }

    fn phase_word(&self) -> String {
        if self.done { return "done".into(); }
        match self.machine.phase() {
            Phase::Inputs => "registering",
            Phase::Channel => "opening_channel",
            Phase::Payouts => "payouts",
            Phase::View => "checking",
            Phase::Signing => "signing",
            Phase::Funding => "funding",
            Phase::FundingSigned => "funding_signed",
            Phase::Stopped => "stopped",
        }
        .into()
    }

    /// Seal a post. It is NOT fed to this phone's own machine here: every phone, this one included, reads only what
    /// the relay holds (the relay echoes a post to its sender too), so all of them see the same pool. Fed early, a post
    /// the relay never got — a payout the forwarder lost, say — would carry this phone a step ahead of the others, and
    /// its timeout would then name members who did nothing wrong.
    fn seal(&mut self, author: &SecretKey, json: &str, now: u64) -> Result<String> {
        let iv: [u8; 16] = self.next("iv")[..16].try_into().expect("16 bytes");
        let e = wire::seal(author, &self.pool_x, json, now, &iv)?;
        Ok(serde_json::to_string(&e)?)
    }

    fn act(&mut self, acts: Vec<Action>, now: u64) -> Result<Out> {
        let mut out = Out::default();
        for a in acts {
            match a {
                Action::Post(json) => {
                    let sk = self.session_sk;
                    out.relay.push(self.seal(&sk, &json, now)?);
                }
                Action::PostPayout(json) => {
                    let k = SecretKey::from_slice(&self.next("one-time")).context("one-time key")?;
                    out.payout.push(self.seal(&k, &json, now)?);
                }
                Action::CheckCoins(list) => {
                    for (op, o) in &list {
                        out.checks.push(CoinAsk { txid: op.txid.to_string(), vout: op.vout, amount_sat: o.value.to_sat(), script_pubkey_hex: hex::encode(o.script_pubkey.as_bytes()) });
                    }
                    self.asked = list;
                    self.answers.clear();
                }
                Action::SaveRecord(rec) => {
                    self.funding = Some(rec.funding.clone());
                    self.exits = rec.exits.iter().map(serialize_hex).collect();
                    out.save = Some(StoredRecord::from_machine(&rec, self.payout_index, Some((&self.change.0, self.change.1)), now.saturating_mul(1000)));
                }
                Action::FundingSigned => {
                    self.signed = true;
                    out.funding_signed = true;
                }
                Action::OpenChannel { sats } => {
                    self.channel_opened = true;
                    out.open_channel = Some(sats);
                }
                Action::FundChannel { txid, vout } => {
                    out.fund_channel = Some((txid, vout));
                }
                Action::Stopped { reason, named } => {
                    let at_payout = matches!(self.machine.phase(), Phase::Stopped) && reason.contains("Payouts");
                    let named_coins = self.machine.coins_of(&named).into_iter().map(|op| (op.txid.to_string(), op.vout)).collect();
                    out.stopped = Some(Stop {
                        reason,
                        outcome: if at_payout { "stopped_at_payouts".into() } else { "stopped".into() },
                        named_coins,
                        wipe_record: self.record_saved && !self.signed,
                        channel_opened: self.channel_opened,
                    });
                }
            }
        }
        out.phase = self.phase_word();
        out.members = self.machine.registered();
        Ok(out)
    }

    /// One event from the relay (or looped back): opened with the pool's key, then the machine — and, after this
    /// phone's signature, the members' funding signatures.
    fn read(&mut self, e: &Event, now: u64) -> Result<Out> {
        let opened = match wire::open(&self.pool_sk, &self.pool_x, e, &mut self.seen) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(Out { phase: self.phase_word(), ..Default::default() }),   // seen already
            Err(_) => return Ok(Out { phase: self.phase_word(), ..Default::default() }),      // not a pool message: ignored (S1)
        };
        let (from, json) = opened;
        // v336 (Phase 2a): a public pool's CREATOR answers `join_pool` — the public code's handshake (peer.rs answer_join,
        // the creator alone: it holds the pool_sender): the pool's key to every asker while seats remain, the same answer
        // to an asker heard again (the relay replays), "pool is full" once peers − 1 are given. The joiners, who hold
        // the key too, say nothing (as the public code's joiners). The machine ignores the message (S1).
        if self.public && self.creator && matches!(Envelope::parse_strict(&json).map(|e| e.msg), Ok(Msg::JoinPool {})) {
            if !self.joiners.contains(&from) && self.joiners.len() + 1 < self.machine_peers() {
                self.joiners.push(from);
            }
            let reply = if self.joiners.contains(&from) {
                Msg::Credentials { credentials: joinstr_v2::msg::Credentials { id: self.pool_id.clone(), key: hex::encode(self.pool_sk.secret_bytes()) } }
            } else {
                Msg::Reject { reason: "pool is full".into() }
            };
            let iv: [u8; 16] = self.next("creds-iv")[..16].try_into().expect("16 bytes");
            let e = wire::seal(&self.pool_sk, &hex::encode(from), &Envelope::json(reply), now, &iv)?;
            return Ok(Out { relay: vec![serde_json::to_string(&e)?], phase: self.phase_word(), ..Default::default() });
        }
        if self.public && !self.creator && matches!(Envelope::parse_strict(&json).map(|e| e.msg), Ok(Msg::JoinPool {})) {
            return Ok(Out { phase: self.phase_word(), ..Default::default() });
        }
        self.collect_witnesses(&json);
        let acts = self.machine.on(Input::Msg { from, json });
        let mut out = self.act(acts, now)?;
        if let Some(c) = self.try_complete() {
            out.complete = Some(c);
        }
        Ok(out)
    }

    /// An event the page read from the relay (["EVENT", sub, e] → e).
    pub fn relay_event(&mut self, event_json: &str, now: u64) -> Result<Out> {
        ensure!(event_json.len() <= 64 * 1024, "relay event too large");
        let e: Event = match serde_json::from_str(event_json) {
            Ok(e) => e,
            Err(_) => return Ok(Out { phase: self.phase_word(), ..Default::default() }),
        };
        self.read(&e, now)
    }

    /// The coin check's answer for one asked coin: Some(true) = proven, unspent and as registered; Some(false) = a
    /// provider answered and the coin failed; None (v328) = no provider answered — the attempt then stops without naming
    /// anyone. With every asked coin answered, the machine hears which failed and which went unanswered.
    pub fn coin_result(&mut self, txid: &str, vout: u32, ok: Option<bool>, now: u64) -> Result<Out> {
        let op = OutPoint { txid: txid.parse().context("txid")?, vout };
        if !self.asked.iter().any(|(o, _)| *o == op) {
            return Ok(Out { phase: self.phase_word(), ..Default::default() });
        }
        self.answers.insert(op, ok);
        if self.answers.len() < self.asked.len() {
            return Ok(Out { phase: self.phase_word(), ..Default::default() });
        }
        let bad: Vec<OutPoint> = self.asked.iter().filter(|(o, _)| self.answers.get(o).copied().flatten() == Some(false)).map(|(o, _)| *o).collect();
        let unanswered: Vec<OutPoint> = self.asked.iter().filter(|(o, _)| self.answers.get(o).copied().flatten().is_none()).map(|(o, _)| *o).collect();
        self.asked.clear();
        self.answers.clear();
        let acts = self.machine.on(Input::CoinsChecked { bad, unanswered });
        self.act(acts, now)
    }

    /// The record is saved (sealed, before the funding signature).
    pub fn record_saved(&mut self, now: u64) -> Result<Out> {
        self.record_saved = true;
        let acts = self.machine.on(Input::RecordSaved);
        self.act(acts, now)
    }

    /// Phase 1b: the channel is open — its funding script (P2WSH) is this phone's payout (§6.2.1).
    pub fn payout_given(&mut self, spk: ScriptBuf, now: u64) -> Result<Out> {
        let acts = self.machine.on(Input::PayoutGiven(spk));
        self.act(acts, now)
    }

    /// Phase 1b: the channel is saved with the provider's first-commitment signature (§6.2.3) — the funding signature
    /// may follow.
    pub fn channel_saved(&mut self, now: u64) -> Result<Out> {
        let acts = self.machine.on(Input::ChannelSaved);
        self.act(acts, now)
    }

    /// Phase 1b: the channel could not be opened, funded or kept — the attempt stops (nothing moved, nobody named).
    pub fn channel_failed(&mut self, why: &str, now: u64) -> Result<Out> {
        let acts = self.machine.on(Input::ChannelFailed(why.to_string()));
        self.act(acts, now)
    }

    /// v339: this phone leaves the pool on purpose (before its coin signature): the members are told (an abort), the
    /// attempt stops with nothing moved and nobody named; the Out carries the stop (the record wiped if written).
    pub fn leave(&mut self, now: u64) -> Result<Out> {
        if self.signed || self.done { return Ok(Out { phase: self.phase_word(), ..Default::default() }); }
        let acts = self.machine.on(Input::Leave);
        self.act(acts, now)
    }

    /// Phase 1b: this phone's coin signature went out — the channel is kept whatever happens next (§6.3.4).
    pub fn signed(&self) -> bool { self.signed }

    /// The clock (every second or so while the app is open).
    pub fn tick(&mut self, now: u64) -> Result<Out> {
        let acts = self.machine.on(Input::Tick { now });
        self.act(acts, now)
    }

    fn collect_witnesses(&mut self, json: &str) {
        let Ok(env) = Envelope::parse_strict(json) else { return };
        let Msg::FundingSigs { witnesses } = env.msg else { return };
        for w in witnesses {
            let Ok(txid) = w.txid.parse::<Txid>() else { continue };
            let items: Option<Vec<Vec<u8>>> = w.witness.iter().map(|h| hex::decode(h).ok()).collect();
            let Some(items) = items else { continue };
            if items.is_empty() || items.len() > 2 { continue; }
            self.witnesses.entry(OutPoint { txid, vout: w.vout }).or_insert_with(|| Witness::from_slice(&items));
        }
    }

    /// Every input of the funding signed → the complete funding and the exits, once.
    fn try_complete(&mut self) -> Option<Complete> {
        if self.complete_given || !self.signed {
            return None;
        }
        let mut tx = self.funding.clone()?;
        for i in tx.input.iter_mut() {
            i.witness = self.witnesses.get(&i.previous_output)?.clone();
        }
        self.complete_given = true;
        self.done = true;
        Some(Complete { funding_hex: serialize_hex(&tx), exits_hex: self.exits.clone() })
    }

    /// The funding as built (unsigned) — its txid is the signed one's.
    pub fn funding_txid(&self) -> Option<String> {
        self.funding.as_ref().map(|t| t.compute_txid().to_string())
    }
}

/// The coin check's answer (the filter server's /coin JSON, through a provider) for one asked coin: proven by Core's
/// own Merkle proof under a header with enough work, unspent, and exactly the amount and script the member registered.
pub fn coin_answer_ok(ask: &CoinAsk, answer_json: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct A {
        txid: String,
        vout: u32,
        unspent: bool,
        tx: Option<String>,
        proof: Option<String>,
    }
    let Ok(a) = serde_json::from_str::<A>(answer_json) else { return false };
    if !a.txid.eq_ignore_ascii_case(&ask.txid) || a.vout != ask.vout {
        return false;
    }
    let (Some(tx), Some(proof)) = (a.tx, a.proof) else { return false };
    let Ok(txid) = ask.txid.parse::<Txid>() else { return false };
    let op = OutPoint { txid, vout: ask.vout };
    let Ok(spk) = hex::decode(&ask.script_pubkey_hex) else { return false };
    match super::coin::check_coin(&op, &tx, &proof, a.unspent, super::coin::pow_floor()) {
        Ok(c) => super::coin::matches_registration(&c, ask.amount_sat, &spk),
        Err(_) => false,
    }
}

/// The funding transaction of a complete pool, its exits: what is sent first (the funding, then each exit in order).
pub fn send_order(c: &Complete) -> Result<Vec<String>> {
    let f: Transaction = deserialize_hex(&c.funding_hex).context("funding")?;
    if f.input.iter().any(|i| i.witness.is_empty()) {
        bail!("the funding is not complete");
    }
    let mut v = vec![c.funding_hex.clone()];
    v.extend(c.exits_hex.iter().cloned());
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Address, Amount, CompressedPublicKey};
    use std::collections::VecDeque;

    fn sk(label: &str, i: u32) -> SecretKey {
        SecretKey::from_slice(&tagged("lij/test/phone", &[label.as_bytes(), &i.to_le_bytes()])).unwrap()
    }
    fn p2wpkh(k: &SecretKey) -> ScriptBuf {
        Address::p2wpkh(&CompressedPublicKey(k.public_key(&Secp256k1::new())), Network::Bitcoin).script_pubkey()
    }
    fn p2tr(k: &SecretKey) -> ScriptBuf {
        let secp = Secp256k1::new();
        Address::p2tr(&secp, k.x_only_public_key(&secp).0, None, Network::Bitcoin).script_pubkey()
    }
    fn declared() -> Declared {
        Declared { sizes: vec![50_000, 100_000], max_fee_sat_vb: 20, relay: "wss://lsp.example/tatara/relay".into(), network: "bitcoin".into(), max_timeout_s: 3_600 }
    }
    const NOW: u64 = 1_800_000_000;

    fn common(i: u32, peers: usize, value: u64) -> Common {
        let coin = sk("coin", i);
        let spk = if i % 2 == 0 { p2wpkh(&coin) } else { p2tr(&coin) };
        let op = OutPoint::new(Txid::from_byte_array(tagged("lij/test/phone-coin", &[&i.to_le_bytes()])), i);
        Common {
            attempt_id: "att-1".into(),
            declared: declared(),
            size: 100_000,
            peers,
            coins: vec![(op, TxOut { value: Amount::from_sat(value), script_pubkey: spk }, coin)],
            payout: Some(p2tr(&sk("payout", i))),
            payout_index: Some(i),
            change_spk: p2wpkh(&sk("change", i)),
            public: false,
            change_index: i,
            tip: 970_000,
            rate_at_join: 2,
            entropy: tagged("lij/test/phone-entropy", &[&i.to_le_bytes()]),
            now: NOW,
            refused: vec![],
            network: Network::Bitcoin,
        }
    }

    /// A relay in memory: every event posted reaches every phone; the forwarder posts payouts the same way; coin checks
    /// answered yes; records "saved" at once.
    struct Room {
        phones: Vec<Phone>,
        queue: VecDeque<(usize, String)>,
        complete: Vec<Option<Complete>>,
        signed: Vec<bool>,
        stops: Vec<Option<Stop>>,
        saved: Vec<Option<StoredRecord>>,
        bad_coin: Option<String>,
        /// v328: this phone gets no answer to its coin checks (its forwarder could not be reached)
        deaf: Option<usize>,
        /// A phone whose payout the forwarder loses.
        lost_payout: Option<usize>,
    }

    impl Room {
        fn handle(&mut self, i: usize, mut out: Out) {
            if self.lost_payout == Some(i) { out.payout.clear(); }
            for e in out.relay.iter().chain(out.payout.iter()) {
                for j in 0..self.phones.len() {
                    self.queue.push_back((j, e.clone()));
                }
            }
            if out.funding_signed { self.signed[i] = true; }
            if out.complete.is_some() { self.complete[i] = out.complete.clone(); }
            if out.stopped.is_some() { self.stops[i] = out.stopped.clone(); }
            if let Some(r) = out.save.clone() {
                self.saved[i] = Some(r);
                let o = self.phones[i].record_saved(NOW).unwrap();
                self.handle(i, o);
            }
            if !out.checks.is_empty() {
                for c in out.checks {
                    let ok = if self.deaf == Some(i) { None } else { Some(self.bad_coin.as_deref() != Some(c.txid.as_str())) };
                    let o = self.phones[i].coin_result(&c.txid, c.vout, ok, NOW).unwrap();
                    self.handle(i, o);
                }
            }
        }
        fn run(&mut self) {
            let mut steps = 0;
            while let Some((j, e)) = self.queue.pop_front() {
                steps += 1;
                assert!(steps < 100_000, "the pool does not settle");
                let o = self.phones[j].relay_event(&e, NOW).unwrap();
                self.handle(j, o);
            }
        }
    }

    fn pool(n: usize, values: &[u64]) -> Room {
        let seats: Vec<SecretKey> = (0..n as u32).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (creator, ann, out0) = Phone::create(common(0, n, values[0]), 2, &others).unwrap();
        let mut room = Room { phones: vec![creator], queue: VecDeque::new(), complete: vec![None; n], signed: vec![false; n], stops: vec![None; n], saved: vec![None; n], bad_coin: None, lost_payout: None, deaf: None };
        let mut outs = vec![(0usize, out0)];
        for i in 1..n {
            let (p, o) = Phone::join(common(i as u32, n, values[i]), &ann, &seats[i]).unwrap();
            room.phones.push(p);
            outs.push((i, o));
        }
        for (i, o) in outs {
            room.handle(i, o);
        }
        room
    }

    // ── v336 (Phase 2a): public pools — the public code's handshake inside the engine ────────────────────────────────

    fn public_common(i: u32, peers: usize, value: u64) -> Common {
        let mut c = common(i, peers, value);
        c.public = true;
        c.declared = Declared { sizes: vec![100_000], max_fee_sat_vb: 3, relay: "wss://relay.example".into(), network: "bitcoin".into(), max_timeout_s: 3_600 };
        c
    }

    /// The creator's answer to one join request, from its Out (the credentials event, tagged to the asker).
    fn answer(creator: &mut Phone, join_out: &Out) -> Vec<String> {
        let mut answers = Vec::new();
        for e in &join_out.relay {
            let o = creator.relay_event(e, NOW).unwrap();
            answers.extend(o.relay);
        }
        answers
    }

    /// A public pool of n: the creator announces on the relay, the others join by `join_pool` → `credentials`, then
    /// the pool runs to the complete funding as a provider's pool does.
    fn public_pool(n: usize) -> Room {
        let values: Vec<u64> = (0..n).map(|i| 100_000 + 5_000 + 20_000 * (i as u64 % 2)).collect();
        let (mut creator, ann, out0) = Phone::create_public(public_common(0, n, values[0]), 2).unwrap();
        let e: Event = serde_json::from_str(&ann).unwrap();
        assert!(e.tags.is_empty(), "a public announcement names no seats");
        assert!(creator.is_public());
        let mut phones = Vec::new();
        let mut outs = vec![out0];
        for i in 1..n {
            let (j, jo) = PublicJoin::new(public_common(i as u32, n, values[i]), &ann).unwrap();
            assert_eq!(jo.phase, "joining");
            assert_eq!(jo.relay.len(), 1, "one join request");
            let answers = answer(&mut creator, &jo);
            assert_eq!(answers.len(), 1, "one credentials event");
            // the request itself, echoed by the relay, is not the answer
            let j = match j.relay_event(&jo.relay[0], NOW).unwrap() { Joined::Waiting(j) => j, _ => panic!("the echo is not the credentials") };
            match j.relay_event(&answers[0], NOW).unwrap() {
                Joined::Phone(p, o) => { assert_eq!(o.phase, "registering"); phones.push(p); outs.push(o); }
                _ => panic!("the credentials start the phone"),
            }
        }
        let mut room = Room { phones: vec![creator], queue: VecDeque::new(), complete: vec![None; n], signed: vec![false; n], stops: vec![None; n], saved: vec![None; n], bad_coin: None, lost_payout: None, deaf: None };
        room.phones.extend(phones);
        for (i, o) in outs.into_iter().enumerate() {
            room.handle(i, o);
        }
        room
    }

    #[test]
    fn p2a_a_public_pool_forms_by_the_public_handshake_and_runs_to_the_complete_funding() {
        for n in [3usize, 5] {
            let mut room = public_pool(n);
            room.run();
            assert!(room.stops.iter().all(|s| s.is_none()), "no stop: {:?}", room.stops);
            assert!(room.signed.iter().all(|s| *s), "every phone signed its coin");
            let c0 = room.complete[0].clone().expect("the funding completes");
            for c in &room.complete { assert_eq!(c.as_ref(), Some(&c0), "every phone completes the same funding"); }
            let f: Transaction = deserialize_hex(&c0.funding_hex).unwrap();
            assert_eq!(f.input.len(), n);
            assert_eq!(c0.exits_hex.len(), n - 1);
        }
    }

    #[test]
    fn p2a_a_public_phone_waits_for_the_room_to_fill_until_the_announcements_timeout() {
        let n = 3;
        let (mut creator, ann, _) = Phone::create_public(public_common(0, n, 120_000), 2).unwrap();
        // a LiJ pool's creator times out PHASE_S after its registration; the public one waits the announcement's hour + a step
        let seats: Vec<SecretKey> = (0..n as u32).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (mut lij, _, _) = Phone::create(common(0, n, 120_000), 2, &others).unwrap();
        assert!(lij.tick(NOW + PHASE_S + 1).unwrap().stopped.is_some(), "a LiJ creator alone stops after PHASE_S");
        assert!(creator.tick(NOW + PHASE_S + 1).unwrap().stopped.is_none(), "a public creator waits");
        assert!(creator.tick(NOW + 3_000).unwrap().stopped.is_none());
        let e: Event = serde_json::from_str(&ann).unwrap();
        let pe = PoolEvent::parse_strict(&e.content).unwrap();
        assert!(creator.tick(pe.timeout + PHASE_S + 1).unwrap().stopped.is_some(), "the announcement's timeout + one step");
    }

    #[test]
    fn p2a_leaving_a_public_room_while_it_fills_tells_the_others_and_frees_the_seat() {
        let n = 3;
        let (mut creator, ann, _) = Phone::create_public(public_common(0, n, 120_000), 2).unwrap();
        let (j1, j1o) = PublicJoin::new(public_common(1, n, 120_000), &ann).unwrap();
        let a1 = answer(&mut creator, &j1o);
        let Joined::Phone(mut joiner, _) = j1.relay_event(&a1[0], NOW).unwrap() else { panic!("joined") };
        let o = joiner.leave(NOW + 5).unwrap();
        assert_eq!(o.relay.len(), 0, "a joiner the relay has not echoed yet is not registered in its own machine — nothing to abort");
        assert!(o.stopped.as_ref().map_or(false, |s| s.reason.contains("left") && s.named_coins.is_empty()), "{:?}", o.stopped);
        assert_eq!(o.phase, "stopped");
        // the creator, registered (its own registration echoed), leaves: the abort goes to the room
        let (mut host, _, o0) = Phone::create_public(public_common(6, n, 120_000), 2).unwrap();
        let echoed = host.relay_event(&o0.relay[0], NOW + 1).unwrap(); assert!(echoed.stopped.is_none());
        let o = host.leave(NOW + 5).unwrap();
        assert_eq!(o.relay.len(), 1, "the abort");
        assert!(o.stopped.as_ref().map_or(false, |s| s.reason.contains("left")));
        assert!(host.leave(NOW + 6).unwrap().stopped.is_none(), "a second leave is nothing");
    }

    #[test]
    fn p2a_the_creator_answers_peers_minus_one_askers_once_each_and_nobody_after() {
        let n = 3;
        let (mut creator, ann, _) = Phone::create_public(public_common(0, n, 120_000), 2).unwrap();
        let (j1, j1o) = PublicJoin::new(public_common(1, n, 120_000), &ann).unwrap();
        let (_, j2) = PublicJoin::new(public_common(2, n, 120_000), &ann).unwrap();
        let (j3, j3o) = PublicJoin::new(public_common(3, n, 120_000), &ann).unwrap();
        let a1 = answer(&mut creator, &j1o);
        assert_eq!(a1.len(), 1);
        assert_eq!(answer(&mut creator, &j1o).len(), 0, "the relay's replay of a request: seen already, no second answer");
        assert_eq!(answer(&mut creator, &j2).len(), 1);
        let full = answer(&mut creator, &j3o);
        assert_eq!(full.len(), 1, "the seats are given: a third asker is told the pool is full (the public code's reject)");
        assert!(matches!(j3.relay_event(&full[0], NOW).unwrap(), Joined::Rejected));
        // a joiner that holds the key says nothing to a join request (the public code's joiners have no pool_sender)
        let Joined::Phone(mut joiner, _) = j1.relay_event(&a1[0], NOW).unwrap() else { panic!("joined") };
        assert_eq!(answer(&mut joiner, &j2).len(), 0, "a joiner ignores join_pool");
        // a provider's pool (not public) never answers a join request
        let seats: Vec<SecretKey> = (0..n as u32).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (mut lij, _, _) = Phone::create(common(0, n, 120_000), 2, &others).unwrap();
        assert!(!lij.is_public());
        assert_eq!(answer(&mut lij, &j1o).len(), 0, "a LiJ pool ignores join_pool (S1)");
    }

    #[test]
    fn p2a_a_public_join_checks_the_pool_before_it_sends_and_refuses_a_providers_pool() {
        let n = 3;
        let (_, ann, _) = Phone::create_public(public_common(0, n, 120_000), 2).unwrap();
        let mut wrong_size = public_common(1, n, 120_000);
        wrong_size.size = 50_000;
        wrong_size.declared.sizes = vec![50_000];
        assert!(PublicJoin::new(wrong_size, &ann).err().expect("refused").to_string().contains("size"), "the size");
        let mut too_dear = public_common(1, n, 120_000);
        too_dear.rate_at_join = 1;
        too_dear.declared.max_fee_sat_vb = 1;
        assert!(PublicJoin::new(too_dear, &ann).is_err(), "a 2 sat/vB pool against a 1 sat/vB cap");
        let mut not_public = public_common(1, n, 120_000);
        not_public.public = false;
        assert!(PublicJoin::new(not_public, &ann).err().expect("refused").to_string().contains("public seat"));
        // a provider's announcement (lij_key tags) is not joined by the handshake
        let seats: Vec<SecretKey> = (0..n as u32).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (_, lij_ann, _) = Phone::create(common(0, n, 120_000), 2, &others).unwrap();
        assert!(PublicJoin::new(public_common(1, n, 120_000), &lij_ann).err().expect("refused").to_string().contains("provider"));
        // a tampered announcement
        let mut e: Event = serde_json::from_str(&ann).unwrap();
        e.content = e.content.replace("\"peers\":3", "\"peers\":4");
        assert!(PublicJoin::new(public_common(1, 4, 120_000), &serde_json::to_string(&e).unwrap()).is_err(), "the signature no longer holds");
        // the wait
        let (j, _) = PublicJoin::new(public_common(1, n, 120_000), &ann).unwrap();
        assert!(j.timed_out(NOW + 30).is_none());
        assert!(j.timed_out(NOW + JOIN_WAIT_S + 1).is_some());
        let f: serde_json::Value = serde_json::from_str(&j.relay_filter()).unwrap();
        assert_eq!(f["kinds"], serde_json::json!([4]));
        assert_eq!(f["#p"][0], hex::encode(xonly(&secret(&public_common(1, n, 120_000).entropy, "public-join", 0).unwrap())), "the filter names the join's own key");
    }

    #[test]
    fn p1_a_whole_pool_of_three_and_of_six_runs_from_the_announcement_to_the_complete_funding() {
        for n in [3usize, 6] {
            let values: Vec<u64> = (0..n).map(|i| 100_000 + 5_000 + 20_000 * (i as u64 % 2)).collect();
            let mut room = pool(n, &values);
            room.run();
            assert!(room.stops.iter().all(|s| s.is_none()), "no stop: {:?}", room.stops);
            assert!(room.signed.iter().all(|s| *s), "every phone signed its coin");
            let c0 = room.complete[0].clone().expect("the funding completes");
            for c in &room.complete { assert_eq!(c.as_ref(), Some(&c0), "every phone completes the same funding"); }
            let f: Transaction = deserialize_hex(&c0.funding_hex).unwrap();
            assert_eq!(f.input.len(), n);
            assert!(f.input.iter().all(|i| !i.witness.is_empty()), "every input signed");
            assert_eq!(c0.exits_hex.len(), n - 1, "the default plan: n − 1 exits");
            // every payout is exactly the pool size, every phone's payout once
            let exits: Vec<Transaction> = c0.exits_hex.iter().map(|h| deserialize_hex(h).unwrap()).collect();
            for i in 0..n {
                let mine = p2tr(&sk("payout", i as u32));
                let hits: Vec<u64> = exits.iter().flat_map(|t| t.output.iter()).filter(|o| o.script_pubkey == mine).map(|o| o.value.to_sat()).collect();
                assert_eq!(hits, vec![100_000], "phone {i}'s payout");
                let r = room.saved[i].as_ref().unwrap();
                assert_eq!(r.payout_index, Some(i as u32));
                assert_eq!(r.exits_hex, c0.exits_hex, "the record holds the signed exits");
            }
            assert_eq!(send_order(&c0).unwrap().len(), n);
            assert_eq!(room.phones[0].phase_word(), "done");
        }
    }

    #[test]
    fn p2_the_change_is_what_is_left_and_a_small_leftover_goes_to_the_miners() {
        // phone 1's coin leaves a leftover under the dust limit: no change output for it
        let n = 3;
        let need = super::super::rederive::member_need(100_000, n, 2_000, &[p2tr(&sk("coin", 1)).as_script()], None).unwrap();
        let mut room = pool(n, &[130_000, need + 200, 140_000]);
        room.run();
        let c = room.complete[0].clone().expect("completes");
        let f: Transaction = deserialize_hex(&c.funding_hex).unwrap();
        let has = |i: u32| f.output.iter().any(|o| o.script_pubkey == p2wpkh(&sk("change", i)));
        assert!(has(0) && !has(1) && has(2), "phone 1's 200 sats went to the miners");
        // a coin short of the need cannot start
        let others: Vec<String> = (1..3).map(|i| hex::encode(xonly(&sk("seat", i)))).collect();
        let (_, ann, _) = Phone::create(common(0, n, 130_000), 2, &others).unwrap();
        let e = Phone::join(common(1, n, need - 1), &ann, &sk("seat", 1)).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("the pool needs"), "{e}");
    }

    #[test]
    fn p3_the_announcement_holds_the_pool_key_only_for_the_named_seats() {
        let seats: Vec<SecretKey> = (0..3).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (_, ann, _) = Phone::create(common(0, 3, 130_000), 2, &others).unwrap();
        // a seat the creator was not told about — the provider, say — gets no key
        let e = open_announcement(&ann, &sk("seat", 9)).unwrap_err().to_string();
        assert!(e.contains("no key for this seat"), "{e}");
        // the content holds no secret: only the sealed copies do
        let ev: Event = serde_json::from_str(&ann).unwrap();
        let (_, pool_sk) = open_announcement(&ann, &seats[1]).unwrap();
        assert!(!ann.contains(&hex::encode(pool_sk.secret_bytes())), "the pool's secret key is never in clear");
        assert_eq!(ev.kind, ANNOUNCE_KIND);
        // a changed content breaks the signature; a re-signed one by another key is not the pool's
        let mut bad = ev.clone();
        bad.content = bad.content.replace("\"fee_rate\":2", "\"fee_rate\":3");
        assert!(open_announcement(&serde_json::to_string(&bad).unwrap(), &seats[1]).is_err());
        let resigned = nwc::sign_event(&sk("thief", 0), ev.created_at, ev.kind, ev.tags.clone(), ev.content.clone());
        assert!(open_announcement(&serde_json::to_string(&resigned).unwrap(), &seats[1]).unwrap_err().to_string().contains("not signed by the pool's key"));
        // the creator must name exactly the other seats
        assert!(Phone::create(common(0, 3, 130_000), 2, &others[..1]).is_err());
        assert!(Phone::create(common(0, 3, 130_000), 2, &[others[0].clone(), others[0].clone()]).is_err());
    }

    /// v332 (DP's first channel pool, 2026-10-13): the announcement round trip for a channel pool — the creating phone
    /// parses its own event (P8's strict parse) and it carries payout_type "p2wsh"; a channel joiner takes it and is told
    /// to open its channel; a chain seat refuses it; a chain pool's event has no payout_type field at all.
    #[test]
    fn p1b_a_channel_pools_announcement_makes_the_round_trip() {
        let seats: Vec<SecretKey> = (0..3).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let channel = |i: u32| { let mut c = common(i, 3, 130_000); c.payout = None; c.payout_index = None; c };
        let (creator, ann, out0) = Phone::create(channel(0), 2, &others).expect("the creator parses its own channel-pool announcement");
        assert!(ann.contains("\\\"payout_type\\\":\\\"p2wsh\\\""), "the event names the payout type: {ann}");
        let (pe, _) = open_announcement(&ann, &seats[1]).unwrap();
        assert_eq!(pe.payout_type, joinstr_v2::pool::PayoutType::P2wsh);
        // the channel is opened after the coin checks (§6.2.1), not here
        assert!(out0.open_channel.is_none() && creator.phase_word() == "registering");
        let (joiner, out1) = Phone::join(channel(1), &ann, &seats[1]).expect("a channel seat joins");
        assert!(out1.open_channel.is_none() && joiner.phase_word() == "registering");
        let e = Phone::join(common(2, 3, 130_000), &ann, &seats[2]).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("payout type is not this seat's route"), "{e}");
        // a chain pool's announcement carries no payout_type — the field is absent, not "p2tr"
        let (_, chain_ann, _) = Phone::create(common(0, 3, 130_000), 2, &others).unwrap();
        assert!(!chain_ann.contains("payout_type"), "{chain_ann}");
        let e = Phone::join(channel(1), &chain_ann, &seats[1]).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("payout type is not this seat's route"), "{e}");
    }

    #[test]
    fn p4_a_joiner_refuses_a_pool_that_is_not_the_providers_or_costs_more_than_agreed() {
        let seats: Vec<SecretKey> = (0..3).map(|i| sk("seat", i)).collect();
        let others: Vec<String> = seats[1..].iter().map(|k| hex::encode(xonly(k))).collect();
        let (_, ann, _) = Phone::create(common(0, 3, 130_000), 3, &others).unwrap();
        let mut c = common(1, 3, 130_000);
        c.rate_at_join = 1;   // agreed to 1 sat/vB (limit 1); the pool runs at 3
        assert!(Phone::join(c, &ann, &seats[1]).err().unwrap().to_string().contains("fees rose"));
        let mut c = common(1, 3, 130_000);
        c.size = 50_000;
        assert!(Phone::join(c, &ann, &seats[1]).err().unwrap().to_string().contains("size"));
        let mut c = common(1, 4, 130_000);
        c.peers = 4;
        assert!(Phone::join(c, &ann, &seats[1]).err().unwrap().to_string().contains("number of people"));
        let mut c = common(1, 3, 130_000);
        c.declared.relay = "wss://another.example/tatara/relay".into();
        assert!(Phone::join(c, &ann, &seats[1]).err().unwrap().to_string().contains("relay"));
        // the creator cannot pick a rate above its own limit or the provider's cap
        assert!(Phone::create(common(0, 3, 130_000), 4, &others).err().unwrap().to_string().contains("fees rose"));
        let mut c = common(0, 3, 130_000);
        c.rate_at_join = 30;
        assert!(Phone::create(c, 21, &others).err().unwrap().to_string().contains("declared"));
    }

    #[test]
    fn p5_a_bad_coin_stops_the_pool_names_its_coin_and_wipes_nothing_unsigned() {
        let n = 3;
        let mut room = pool(n, &[130_000, 130_000, 130_000]);
        room.bad_coin = Some(common(2, n, 0).coins[0].0.txid.to_string());
        room.run();
        let s = room.stops[0].clone().expect("stopped");
        assert_eq!(s.outcome, "stopped");
        assert_eq!(s.named_coins, vec![(common(2, n, 0).coins[0].0.txid.to_string(), 2u32)], "the bad coin is named, for the retry");
        assert!(!s.wipe_record, "nothing was saved yet");
        assert!(room.complete.iter().all(|c| c.is_none()) && room.signed.iter().all(|s| !*s), "nothing moved");
    }

    #[test]
    fn p5b_a_coin_check_with_no_answer_stops_the_pool_naming_no_one() {
        // v328 (DP's first real pools, 2026-10-13): phone 1 cannot reach any coin-check answerer. Before: "no answer" counted
        // as "the coin failed", phone 1 blamed both members, and refused their coins in every retry (each one dead on
        // arrival). Now: it stops with the reason, names no one, and its abort stops the others without blame.
        let n = 3;
        let mut room = pool(n, &[130_000, 130_000, 130_000]);
        room.deaf = Some(1);
        room.run();
        let s = room.stops[1].clone().expect("the deaf phone stopped");
        assert!(s.reason.contains("no answer from any provider"), "its own reason: {}", s.reason);
        assert_eq!((s.outcome.as_str(), s.named_coins.len()), ("stopped", 0), "nobody is named");
        for i in [0usize, 2] {
            let o = room.stops[i].clone().expect("the others stop on its abort");
            assert!(o.named_coins.is_empty(), "phone {i} names no one either: {:?}", o.named_coins);
        }
        assert!(room.complete.iter().all(|c| c.is_none()) && room.signed.iter().all(|s| !*s), "nothing moved");
    }

    #[test]
    fn p6_a_missing_payout_stops_at_the_anonymous_step_naming_no_one() {
        // phone 2's payout never arrives (its forwarder lost it): the pool times out at the payout step
        let n = 3;
        let mut room = pool(n, &[130_000, 130_000, 130_000]);
        room.lost_payout = Some(2);
        room.run();
        for i in 0..n {
            let _ = room.phones[i].tick(NOW + 1).unwrap();
            let o = room.phones[i].tick(NOW + 2 + PHASE_S).unwrap();
            room.handle(i, o);
        }
        for i in 0..n {
            let s = room.stops[i].clone().expect("stopped");
            assert_eq!(s.outcome, "stopped_at_payouts", "phone {i}: {}", s.reason);
            assert!(s.named_coins.is_empty(), "the payouts are anonymous: no one is named");
        }
    }

    #[test]
    fn p7_the_coin_answer_is_checked_against_the_registration() {
        let ask = CoinAsk { txid: "aa".repeat(32), vout: 0, amount_sat: 1, script_pubkey_hex: "00".into() };
        assert!(!coin_answer_ok(&ask, "not json"));
        assert!(!coin_answer_ok(&ask, &serde_json::json!({ "txid": "bb".repeat(32), "vout": 0, "unspent": true, "tx": "00", "proof": "00" }).to_string()), "another coin's answer");
        assert!(!coin_answer_ok(&ask, &serde_json::json!({ "txid": "aa".repeat(32), "vout": 0, "unspent": true, "tx": null, "proof": null }).to_string()), "no proof");
        assert!(!coin_answer_ok(&ask, &serde_json::json!({ "txid": "aa".repeat(32), "vout": 0, "unspent": true, "tx": "00", "proof": "00" }).to_string()), "a proof that does not decode");
    }
}
