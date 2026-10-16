//! The phone's side of the provider's routes (plan r3/r4 step 7, slice 1; the adapter's tatara.js 0.98.0–0.101.0; design
//! docs/design/mix/tatara-adapter-r1.md §2–§3, r2 §2–§3). Pure: every random byte and the time are handed in; nothing
//! here talks to the network, stores anything or touches a coin.
//!
//! - **The seat, v0.8's arrangement:** `seat_message_v1` is what the wallet's node key signs (the engine's
//!   `sign_message`, LND-compatible); the provider checks it with LND's VerifyMessage.
//! - **The seat, doors (door 1):** `ring_seat_digest` under `seat_tag` (the ISO week of the request's time), signed with
//!   joinstr's tagged ring signature over the week's ring — after `check_ring` (the provider's ring holds this wallet's
//!   Tatara key, has at least `min` keys, is sorted, and hashes to the value in the provider's signed registry record).
//! - **Every other request** is signed by the seat's own key (BIP-340) over `action_digest`.
//! - **Every notice** the provider sends is checked against the provider's node key from its registry record
//!   (`verify_notice`) before anything in it is read.

use anyhow::{ensure, Context, Result};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{schnorr, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::Deserialize;
use serde_json::{json, Value};

const SHA: fn(&[u8]) -> [u8; 32] = |b| sha256::Hash::hash(b).to_byte_array();
fn sha_hex(s: &str) -> String { hex::encode(SHA(s.as_bytes())) }

// ── the seat (v0.8's arrangement) ─────────────────────────────────────────────────────────────────────────────────────

/// What the wallet's node key signs for a seat: `lij-tatara-seat:v1|<route>|<size>|<seat_pk>|<ts>` — the route "chain"
/// (the payout on-chain) or, Phase 1b, "channel" (the payout a channel's funding; adapter 0.103.0).
pub fn seat_message_v1(route: &str, size: u64, seat_pk: &str, ts: u64) -> String {
    format!("lij-tatara-seat:v1|{route}|{size}|{seat_pk}|{ts}")
}
/// The body of POST /tatara/seat (v0.8's arrangement); `signature` = the node key's signature over `seat_message_v1`.
pub fn seat_body_v1(route: &str, size: u64, seat_pk: &str, node_pubkey: &str, ts: u64, signature: &str) -> Value {
    json!({ "route": route, "size": size, "seat_pk": seat_pk, "node_pubkey": node_pubkey, "ts": ts, "signature": signature })
}
/// v343/v344 (S59 Thu, Phase 2b — the hosted room): a seat that may go into a public room the provider hosts signs the
/// facts the host needs — the PROVIDER it is for (its node key: a request cannot be replayed at another provider —
/// review 2b #7), `public` (the wallet's Public pools switch) and its `fee_cap_milli` (thousandths of a sat/vB: 1.5×
/// the rate at Join, exactly the limit the phone enforces at a pool — review 2b #2) —
/// `lij-tatara-seat:v3|<provider_pk>|<route>|<size>|<seat_pk>|<public>|<fee_cap_milli>|<ts>` (v2 is the ring-signed
/// seat's digest; adapter 0.106.0 checks v3 when the body carries `public`).
pub fn seat_message_v3(provider_pk: &str, route: &str, size: u64, seat_pk: &str, public: bool, fee_cap_milli: u64, ts: u64) -> String {
    format!("lij-tatara-seat:v3|{provider_pk}|{route}|{size}|{seat_pk}|{}|{fee_cap_milli}|{ts}", if public { "true" } else { "false" })
}
pub fn seat_body_v3(provider_pk: &str, route: &str, size: u64, seat_pk: &str, node_pubkey: &str, public: bool, fee_cap_milli: u64, ts: u64, signature: &str) -> Value {
    json!({ "route": route, "size": size, "seat_pk": seat_pk, "node_pubkey": node_pubkey, "provider_pk": provider_pk, "public": public, "fee_cap_milli": fee_cap_milli, "ts": ts, "signature": signature })
}

// ── the seat key and its requests ────────────────────────────────────────────────────────────────────────────────────

/// What a seat key signs for `action`: sha256("lij-tatara-<action>:v1|" + the fields joined by "|").
pub fn action_digest(action: &str, fields: &[&str]) -> [u8; 32] {
    SHA(format!("lij-tatara-{action}:v1|{}", fields.join("|")).as_bytes())
}

/// A seat's own key: fresh for every seat, from 32 bytes of the engine's random source.
pub struct SeatKey {
    kp: Keypair,
}

impl SeatKey {
    pub fn from_entropy(e: &[u8; 32]) -> Result<Self> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&SHA(&[b"lij/tatara/seat-key/v1".as_slice(), e.as_slice()].concat())).context("seat key")?;
        Ok(SeatKey { kp: Keypair::from_secret_key(&secp, &sk) })
    }
    /// The x-only key, hex — what the seat request names.
    pub fn pk_hex(&self) -> String { hex::encode(self.kp.x_only_public_key().0.serialize()) }
    /// Step 8: the secret — it opens this seat's copy of the pool's key in the announcement (phone::open_announcement).
    pub fn secret(&self) -> SecretKey { self.kp.secret_key() }
    /// BIP-340 over `action_digest(action, fields)`; `aux` from the engine's random source.
    pub fn sign(&self, action: &str, fields: &[&str], aux: &[u8; 32]) -> String {
        let secp = Secp256k1::new();
        let m = Message::from_digest(action_digest(action, fields));
        hex::encode(secp.sign_schnorr_with_aux_rand(&m, &self.kp, aux).as_ref())
    }

    /// POST /tatara/checkin · leave · pause · resume: { seat_id, ts, sig } over [seat_id, ts].
    pub fn simple_body(&self, action: &str, seat_id: &str, ts: u64, aux: &[u8; 32]) -> Result<Value> {
        ensure!(matches!(action, "checkin" | "leave" | "pause" | "resume"), "not a simple action");
        let t = ts.to_string();
        Ok(json!({ "seat_id": seat_id, "ts": ts, "sig": self.sign(action, &[seat_id, &t], aux) }))
    }
    /// POST /tatara/open: over [seat_id, attempt_id, ts].
    pub fn open_body(&self, seat_id: &str, attempt_id: &str, ts: u64, aux: &[u8; 32]) -> Value {
        let t = ts.to_string();
        json!({ "seat_id": seat_id, "attempt_id": attempt_id, "ts": ts, "sig": self.sign("open", &[seat_id, attempt_id, &t], aux) })
    }
    /// v344 (Phase 2b): POST /tatara/open for a hosted ROOM — over [seat_id, attempt_id, join_pk, ts]: the key this
    /// phone's join request will come from, so the host answers it past the strangers' quota and the join itself
    /// carries nothing (byte for byte a Joinstr user's).
    pub fn open_room_body(&self, seat_id: &str, attempt_id: &str, join_pk: &str, ts: u64, aux: &[u8; 32]) -> Value {
        let t = ts.to_string();
        json!({ "seat_id": seat_id, "attempt_id": attempt_id, "join_pk": join_pk, "ts": ts, "sig": self.sign("open", &[seat_id, attempt_id, join_pk, &t], aux) })
    }
    /// POST /tatara/report: over [seat_id, attempt_id, outcome, ts]; outcome funding_signed | stopped | stopped_at_payouts.
    pub fn report_body(&self, seat_id: &str, attempt_id: &str, outcome: &str, ts: u64, aux: &[u8; 32]) -> Result<Value> {
        ensure!(matches!(outcome, "funding_signed" | "stopped" | "stopped_at_payouts"), "not an outcome");
        let t = ts.to_string();
        Ok(json!({ "seat_id": seat_id, "attempt_id": attempt_id, "outcome": outcome, "ts": ts, "sig": self.sign("report", &[seat_id, attempt_id, outcome, &t], aux) }))
    }
    /// POST /tatara/announce: over [seat_id, attempt_id, sha256(announcement) hex, ts].
    pub fn announce_body(&self, seat_id: &str, attempt_id: &str, announcement: &str, ts: u64, aux: &[u8; 32]) -> Value {
        let t = ts.to_string();
        let h = sha_hex(announcement);
        json!({ "seat_id": seat_id, "attempt_id": attempt_id, "announcement": announcement, "ts": ts, "sig": self.sign("announce", &[seat_id, attempt_id, &h, &t], aux) })
    }
    /// POST /tatara/backup: over [seat_id, attempt_id, sha256(funding + "|" + exits joined by "|") hex, ts].
    pub fn backup_body(&self, seat_id: &str, attempt_id: &str, funding_hex: &str, exits: &[String], ts: u64, aux: &[u8; 32]) -> Value {
        let t = ts.to_string();
        let h = sha_hex(&format!("{funding_hex}|{}", exits.join("|")));
        json!({ "seat_id": seat_id, "attempt_id": attempt_id, "funding_hex": funding_hex, "exits": exits, "ts": ts, "sig": self.sign("backup", &[seat_id, attempt_id, &h, &t], aux) })
    }
}

/// Is `sig` a seat key's signature over an action? (The provider's check, here for tests and for the record.)
pub fn seat_sig_ok(seat_pk_hex: &str, action: &str, fields: &[&str], sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(seat_pk_hex), hex::decode(sig_hex)) else { return false };
    let (Ok(pk), Ok(sig)) = (XOnlyPublicKey::from_slice(&pk), schnorr::Signature::from_slice(&sig)) else { return false };
    Secp256k1::verification_only().verify_schnorr(&sig, &Message::from_digest(action_digest(action, fields)), &pk).is_ok()
}

// ── the provider's notices ───────────────────────────────────────────────────────────────────────────────────────────

/// What a seat is told. Every one arrives signed by the provider's node key; nothing here is read before that holds.
#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Notice {
    Start { seat_id: String, attempt_id: String, size: u64, #[serde(rename = "try")] try_n: u32, of: u32, open_within_s: u64, at: u64 },
    Retry { seat_id: String, attempt_id: String, size: u64, #[serde(rename = "try")] try_n: u32, of: u32, open_within_s: u64, at: u64 },
    /// Step 8 (S58): `seat_pks` — the other opened seats' keys (adapter 0.102.0): the creating phone seals the pool's key to
    /// each of them inside its announcement, so the provider that passes it on cannot read the pool.
    Create { seat_id: String, attempt_id: String, size: u64, peers: u32, #[serde(rename = "try")] try_n: u32, token: String, relay: String, at: u64, #[serde(default)] seat_pks: Vec<String> },
    WaitForAnnouncement { seat_id: String, attempt_id: String, size: u64, peers: u32, #[serde(rename = "try")] try_n: u32, token: String, relay: String, at: u64 },
    Announcement { seat_id: String, attempt_id: String, announcement: String, at: u64 },
    MissedStart { seat_id: String, attempt_id: String, missed: u32, of: u32, at: u64 },
    NoPool { seat_id: String, attempt_id: String, opened: u32, needed: u32, at: u64 },
    Stopped { seat_id: String, #[serde(default)] attempt_id: Option<String>, reason: String, at: u64 },
    Removed { seat_id: String, reason: String, at: u64 },
    Done { seat_id: String, #[serde(default)] attempt_id: Option<String>, at: u64 },
    /// v344 (Phase 2b, adapter 0.106.0): the provider's hosted public room is ready for this seat — the announcement (a
    /// signed public pool event), the public relay, `open_within_s` to open; the phone joins it by the public handshake
    /// (its join key named to the provider at `open`, so the host answers it past the strangers' quota).
    Room { seat_id: String, attempt_id: String, route: String, size: u64, peers: u32, relay: String, event: String, open_within_s: u64, at: u64 },
    /// v344: the seat missed a room's wake — no strike, no re-seating; it holds back until the app opens (this check-in).
    MissedRoom { seat_id: String, attempt_id: String, at: u64 },
}

impl Notice {
    pub fn seat_id(&self) -> &str {
        match self {
            Notice::Start { seat_id, .. } | Notice::Retry { seat_id, .. } | Notice::Create { seat_id, .. } | Notice::WaitForAnnouncement { seat_id, .. }
            | Notice::Announcement { seat_id, .. } | Notice::MissedStart { seat_id, .. } | Notice::NoPool { seat_id, .. } | Notice::Stopped { seat_id, .. }
            | Notice::Removed { seat_id, .. } | Notice::Done { seat_id, .. } | Notice::Room { seat_id, .. } | Notice::MissedRoom { seat_id, .. } => seat_id,
        }
    }
}

/// Check a notice `{ body, sig }` against the provider's node key (from its registry record) and read it: the
/// signature (LND-compatible message signing) over "lij-tatara-notice:v1|<seat_id>|<body>", then the body, which must
/// name this seat. Size-capped before anything is checked.
pub fn verify_notice(provider_pk: &PublicKey, seat_id: &str, body: &str, sig: &str) -> Result<Notice> {
    ensure!(body.len() <= 48 * 1024 && sig.len() <= 200, "notice too large");
    let msg = format!("lij-tatara-notice:v1|{seat_id}|{body}");
    ensure!(lightning::util::message_signing::verify(msg.as_bytes(), sig, provider_pk), "the notice is not signed by this provider");
    let n: Notice = serde_json::from_str(body).context("notice body")?;
    ensure!(n.seat_id() == seat_id, "a notice for another seat");
    Ok(n)
}

// ── door 1: the week's ring and the ring-signed seat ─────────────────────────────────────────────────────────────────

/// The ISO 8601 week of a time (UTC): (year, week).
pub fn iso_week(ts: u64) -> (i64, u32) {
    let days = (ts / 86400) as i64;                       // days since 1970-01-01 (a Thursday)
    let weekday = (days + 3).rem_euclid(7);               // Monday 0 … Sunday 6
    let thursday = days - weekday + 3;                    // the Thursday of this week decides its year
    let (y, _, _) = civil_from_days(thursday);
    let jan1 = days_from_civil(y, 1, 1);
    (y, 1 + ((thursday - jan1) / 7) as u32)
}
/// The seat tag: "lij/tatara/seat/v1/<ISO year>-W<week, two digits>" — from the clock, never sent, never served.
pub fn seat_tag(ts: u64) -> String {
    let (y, w) = iso_week(ts);
    format!("lij/tatara/seat/v1/{y}-W{w:02}")
}
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// The ring's hash bound to its tag: H("joinstr/v2/lij/ring_hash_tagged", sha256(keys) ‖ len(tag) ‖ tag) — our own,
/// sharing no code with the signer it feeds (what the provider's record and GET /tatara/ring name).
pub fn ring_hash_tagged(keys: &[[u8; 33]], tag: &str) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for k in keys {
        e.input(k);
    }
    let inner = sha256::Hash::from_engine(e).to_byte_array();
    crate::tatara::tagged("joinstr/v2/lij/ring_hash_tagged", &[&inner, &(tag.len() as u32).to_le_bytes(), tag.as_bytes()])
}

/// The phone's checks on the provider's ring before it signs over it: sorted, no key twice, every key a point, at least
/// `min` keys, this wallet's Tatara key among them, and the hash the provider's signed record names.
pub fn check_ring(keys_hex: &[String], record_hash: &str, my_key: &[u8; 33], tag: &str, min: usize) -> Result<Vec<secp::Point>> {
    ensure!(keys_hex.len() >= min, "a ring of {} — fewer than {min} wallets would show too much", keys_hex.len());
    let mut raw = Vec::with_capacity(keys_hex.len());
    let mut pts = Vec::with_capacity(keys_hex.len());
    for k in keys_hex {
        let p = joinstr_v2::keys::point_from_hex(k)?;
        raw.push(p.serialize());
        pts.push(p);
    }
    ensure!(raw.windows(2).all(|w| w[0] < w[1]), "the ring is not sorted, or a key is there twice");
    ensure!(raw.iter().any(|k| k == my_key), "this wallet's Tatara key is not in the ring");
    ensure!(hex::encode(ring_hash_tagged(&raw, tag)) == record_hash, "the ring is not the one the provider's record names");
    Ok(pts)
}

/// What the ring signature signs for a seat: sha256("lij-tatara-seat:v2|<route>|<size>|<seat_pk>|<sha256(wake_json)>|
/// <ring_hash>|<ts>") — the route "chain" or "channel" (adapter 0.103.0 checks the same).
pub fn ring_seat_digest(route: &str, size: u64, seat_pk: &str, wake_json: &str, ring_hash: &str, ts: u64) -> [u8; 32] {
    SHA(format!("lij-tatara-seat:v2|{route}|{size}|{seat_pk}|{}|{ring_hash}|{ts}", sha_hex(wake_json)).as_bytes())
}

/// Sign a seat request with the wallet's Tatara key over the checked ring (joinstr v2's sign_tagged, P10) and give the
/// body of POST /tatara/seat. `aux`: 32 bytes of the engine's random source.
pub fn ring_seat_body(ring: &[secp::Point], tatara_key: &[u8; 32], route: &str, size: u64, seat_pk: &str, wake_json: &str, ring_hash: &str, ts: u64, aux: &[u8; 32]) -> Result<Value> {
    let x = secp::Scalar::from_slice(tatara_key).context("Tatara key")?;
    let m = ring_seat_digest(route, size, seat_pk, wake_json, ring_hash, ts);
    let sig = joinstr_v2::ring::sign_tagged(ring, x, &m, aux, seat_tag(ts).as_bytes())?;
    Ok(json!({ "route": route, "size": size, "seat_pk": seat_pk, "wake_json": wake_json, "ring_hash": ring_hash, "ts": ts, "ring_sig": sig }))
}

/// The Tatara key's public half (33 bytes, compressed) — what POST /tatara/ring/join names.
pub fn tatara_pk(tatara_key: &[u8; 32]) -> Result<[u8; 33]> {
    let sk = SecretKey::from_slice(tatara_key).context("Tatara key")?;
    Ok(PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize())
}
/// What the wallet's node key signs to turn Mix on: "lij-tatara-ring:v1|join|<tatara_pk>|<ts>"; to turn it off,
/// "lij-tatara-ring:v1|leave|<ts>".
pub fn ring_join_message(tatara_pk_hex: &str, ts: u64) -> String { format!("lij-tatara-ring:v1|join|{tatara_pk_hex}|{ts}") }
pub fn ring_leave_message(ts: u64) -> String { format!("lij-tatara-ring:v1|leave|{ts}") }

#[cfg(test)]
mod tests {
    use super::*;

    // from the adapter (tatara.js 0.101.0, node): seatMsg('checkin', [ab×16, 1791979200]) and seatMsg('report', …)
    const JS_CHECKIN: &str = "f78e654757386466d413fa9165628a9ee55ad5c3753a685c04478309bd4bd8c8";
    const JS_REPORT: &str = "5b027c81fa9881529d0ae95534576f219499890b10b98c0a082fa579ee7c7982";
    // the adapter's tatara-doors.vectors.json, job "a" (signed there by joinstr's sign_tagged)
    const RING: [&str; 3] = [
        "032d9a896282f004b60f9e92b12b23309e0432d66e2647777366fa29c774293d16",
        "0386263f5c333e7358c6ef91377c46a9a902308642c111130888a54db2d2b4ee5a",
        "03bb90e600d908353395c61371db42c4c0271c96802db56a68a097b219940a8ee4",
    ];
    const RING_HASH: &str = "bb1abd8671e41bf26d5b5916da6a781615b83f172f9be6e0f3a18e65f2f092d5";
    const WAKE: &str = r#"{"endpoint":"https://push.example.org/seat-1","keys":{"p256dh":"BP","auth":"au"}}"#;
    const SEAT_A: &str = "d4fcb94b60f6d18d188fce0269e016b1362d44fac8c1d9a1f0fe7e36c20c26e4";
    const M_A: &str = "336ec3dc2f2f8530147dbe01e3422ae1c3637c4e9c29a1937018ab7d8f50dc88";
    const TS: u64 = 1791979200;   // 2026-10-14 12:00 UTC, a Wednesday of 2026-W42

    #[test]
    fn the_seat_key_signs_what_the_adapter_checks() {
        let sid = "ab".repeat(16);
        assert_eq!(hex::encode(action_digest("checkin", &[&sid, "1791979200"])), JS_CHECKIN);
        assert_eq!(hex::encode(action_digest("report", &[&sid, &"cd".repeat(16), "stopped_at_payouts", "1791979200"])), JS_REPORT);
        assert_eq!(seat_message_v1("chain", 50000, &"ef".repeat(32), TS), format!("lij-tatara-seat:v1|chain|50000|{}|{TS}", "ef".repeat(32)));
        assert_eq!(seat_message_v1("channel", 100000, &"ef".repeat(32), TS), format!("lij-tatara-seat:v1|channel|100000|{}|{TS}", "ef".repeat(32)), "Phase 1b: the channel route signed (adapter 0.103.0 R10)");
        assert_eq!(seat_message_v3("02cd", "chain", 50000, &"ef".repeat(32), true, 3000, TS), format!("lij-tatara-seat:v3|02cd|chain|50000|{}|true|3000|{TS}", "ef".repeat(32)), "v343/v344: the provider, the public switch and the fee cap (thousandths) signed (adapter 0.106.0)");
        let b = seat_body_v3("02cd", "chain", 50000, &"ef".repeat(32), "02ab", true, 3000, TS, "sig");
        assert_eq!((b["provider_pk"].as_str(), b["public"].as_bool(), b["fee_cap_milli"].as_u64()), (Some("02cd"), Some(true), Some(3000)));
        let k = SeatKey::from_entropy(&[7u8; 32]).unwrap();
        let b = k.simple_body("checkin", &sid, TS, &[1u8; 32]).unwrap();
        assert!(seat_sig_ok(&k.pk_hex(), "checkin", &[&sid, "1791979200"], b["sig"].as_str().unwrap()));
        assert!(!seat_sig_ok(&k.pk_hex(), "checkin", &[&sid, "1791979201"], b["sig"].as_str().unwrap()), "another time");
        assert!(!seat_sig_ok(&SeatKey::from_entropy(&[8u8; 32]).unwrap().pk_hex(), "checkin", &[&sid, "1791979200"], b["sig"].as_str().unwrap()), "another key");
        let r = k.report_body(&sid, &"cd".repeat(16), "funding_signed", TS, &[2u8; 32]).unwrap();
        assert!(seat_sig_ok(&k.pk_hex(), "report", &[&sid, &"cd".repeat(16), "funding_signed", "1791979200"], r["sig"].as_str().unwrap()));
        assert!(k.report_body(&sid, "x", "won", TS, &[0u8; 32]).is_err() && k.simple_body("seat", &sid, TS, &[0u8; 32]).is_err());
        let a = k.announce_body(&sid, &"cd".repeat(16), "{}", TS, &[3u8; 32]);
        assert!(seat_sig_ok(&k.pk_hex(), "announce", &[&sid, &"cd".repeat(16), &sha_hex("{}"), "1791979200"], a["sig"].as_str().unwrap()));
        let bk = k.backup_body(&sid, &"cd".repeat(16), "aa", &["bb".into(), "cc".into()], TS, &[4u8; 32]);
        assert!(seat_sig_ok(&k.pk_hex(), "backup", &[&sid, &"cd".repeat(16), &sha_hex("aa|bb|cc"), "1791979200"], bk["sig"].as_str().unwrap()));
        assert_ne!(SeatKey::from_entropy(&[7u8; 32]).unwrap().pk_hex(), SeatKey::from_entropy(&[9u8; 32]).unwrap().pk_hex());
    }

    #[test]
    fn a_notice_is_read_only_when_the_provider_signed_it_for_this_seat() {
        let provider = SecretKey::from_slice(&[0x31; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &provider);
        let sid = "ab".repeat(16);
        let body = format!(r#"{{"seat_id":"{sid}","type":"start","attempt_id":"{}","size":50000,"try":1,"of":3,"open_within_s":180,"at":1791979200}}"#, "cd".repeat(16));
        let sig = lightning::util::message_signing::sign(format!("lij-tatara-notice:v1|{sid}|{body}").as_bytes(), &provider);
        match verify_notice(&pk, &sid, &body, &sig).unwrap() {
            Notice::Start { try_n, of, open_within_s, size, .. } => assert_eq!((try_n, of, open_within_s, size), (1, 3, 180, 50000)),
            n => panic!("{n:?}"),
        }
        let other = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[0x32; 32]).unwrap());
        assert!(verify_notice(&other, &sid, &body, &sig).is_err(), "another provider's key");
        assert!(verify_notice(&pk, &sid, &body.replace("50000", "60000"), &sig).is_err(), "a changed body");
        assert!(verify_notice(&pk, &"ef".repeat(16), &body, &sig).is_err(), "signed for another seat");
        // a correctly signed notice that names another seat in its body
        let body2 = body.replace(&format!(r#""seat_id":"{sid}""#), &format!(r#""seat_id":"{}""#, "ef".repeat(16)));
        let sig2 = lightning::util::message_signing::sign(format!("lij-tatara-notice:v1|{sid}|{body2}").as_bytes(), &provider);
        assert!(verify_notice(&pk, &sid, &body2, &sig2).is_err(), "a body naming another seat");
        // the adapter's other notices parse
        for (t, extra) in [("create", r#""size":50000,"peers":3,"try":1,"token":"aa","relay":"wss://x/tatara/relay""#), ("removed", r#""reason":"strikes""#), ("stopped", r#""attempt_id":"cc","reason":"retries_used""#), ("done", r#""attempt_id":"cc""#)] {
            let b = format!(r#"{{"seat_id":"{sid}","type":"{t}","attempt_id":"cc",{extra},"at":1}}"#).replace(r#""attempt_id":"cc","attempt_id":"cc""#, r#""attempt_id":"cc""#);
            let s = lightning::util::message_signing::sign(format!("lij-tatara-notice:v1|{sid}|{b}").as_bytes(), &provider);
            verify_notice(&pk, &sid, &b, &s).unwrap_or_else(|e| panic!("{t}: {e}"));
        }
    }

    #[test]
    fn the_week_tag_is_the_iso_week() {
        // against Python's isocalendar (adapter tatara-ring.test.js G7's edges)
        for (ts_ms, want) in [(1791763200000u64, "2026-W42"), (1791763199000, "2026-W41"), (1767225600000, "2026-W01"), (1766966400000, "2026-W01"),
                              (1609416000000, "2020-W53"), (1609718399000, "2020-W53"), (1609718400000, "2021-W01"), (1798761600000, "2026-W53"), (1798761599000, "2026-W53")] {
            assert_eq!(seat_tag(ts_ms / 1000), format!("lij/tatara/seat/v1/{want}"), "{ts_ms}");
        }
        assert_eq!(seat_tag(TS), "lij/tatara/seat/v1/2026-W42");
    }

    #[test]
    fn the_ring_seat_matches_the_adapter_and_verifies() {
        // the digest and the ring hash the adapter computed (tatara-doors.vectors.json)
        assert_eq!(hex::encode(ring_seat_digest("chain", 50000, SEAT_A, WAKE, RING_HASH, TS)), M_A);
        let raw: Vec<[u8; 33]> = RING.iter().map(|k| hex::decode(k).unwrap().try_into().unwrap()).collect();
        assert_eq!(hex::encode(ring_hash_tagged(&raw, &seat_tag(TS))), RING_HASH);
        // a ring of our own: three Tatara keys, sorted; sign as the second and verify with joinstr's verify_tagged
        let keys: Vec<[u8; 32]> = (1u8..=3).map(|i| SHA(&[b"tatara".as_slice(), &[i]].concat())).collect();
        let mut pks: Vec<[u8; 33]> = keys.iter().map(|k| tatara_pk(k).unwrap()).collect();
        pks.sort();
        let tag = seat_tag(TS);
        let hash = hex::encode(ring_hash_tagged(&pks, &tag));
        let hexes: Vec<String> = pks.iter().map(hex::encode).collect();
        let mine = tatara_pk(&keys[1]).unwrap();
        let ring = check_ring(&hexes, &hash, &mine, &tag, 3).unwrap();
        let body = ring_seat_body(&ring, &keys[1], "chain", 50000, SEAT_A, WAKE, &hash, TS, &[5u8; 32]).unwrap();
        let sig: joinstr_v2::ring::RingSig = serde_json::from_value(body["ring_sig"].clone()).unwrap();
        joinstr_v2::ring::verify_tagged(&ring, &ring_seat_digest("chain", 50000, SEAT_A, WAKE, &hash, TS), &sig, tag.as_bytes()).unwrap();
        assert!(joinstr_v2::ring::verify_tagged(&ring, &ring_seat_digest("channel", 50000, SEAT_A, WAKE, &hash, TS), &sig, tag.as_bytes()).is_err(), "a chain seat's signature does not cover the channel route");
        // the phone's checks on the ring
        assert!(check_ring(&hexes, &hash, &mine, &tag, 4).is_err(), "fewer than the minimum");
        assert!(check_ring(&hexes, &"00".repeat(32), &mine, &tag, 3).is_err(), "not the record's ring");
        assert!(check_ring(&hexes, &hash, &tatara_pk(&[9u8; 32]).unwrap(), &tag, 3).is_err(), "this wallet not in it");
        let mut rev = hexes.clone(); rev.reverse();
        assert!(check_ring(&rev, &hash, &mine, &tag, 3).is_err(), "unsorted");
        assert!(check_ring(&hexes, &hash, &mine, "lij/tatara/seat/v1/2026-W43", 3).is_err(), "another week's hash");
        assert_eq!(ring_join_message("02ab", 5), "lij-tatara-ring:v1|join|02ab|5");
        assert_eq!(ring_leave_message(5), "lij-tatara-ring:v1|leave|5");
    }
}
