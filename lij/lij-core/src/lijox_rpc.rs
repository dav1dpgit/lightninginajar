// lijox_rpc.rs — v383 (S72 Tue 2026-11-24, DP 08:33 on "Section F"; docs/design/routes/f2-r1.md): REQUESTS INSIDE THE
// LIGHTNING CONNECTION, THE WALLET'S SIDE OF THE PATH.
//
// A wallet's payments and channel messages already travel inside the Lightning connection, encrypted between the
// wallet's node key and its provider's. Everything else the wallet asked its provider was a web request, readable by
// whoever ends that address's TLS. This file carries a request inside the connection instead, in the form of LSPS0
// (bLIP-50): one Lightning message type, 37913, whose payload is one UTF-8 JSON-RPC 2.0 object.
//
//   · `call` makes the request, queues its message (or its parts) for the provider and hands back a receiver for
//     the answer. The cooperative-chain handler — the one custom message handler the peer manager has — hands every
//     37913 message that arrives to `on_message`, and drains this queue beside its own.
//   · An answer is taken only from the peer the request was sent to.
//   · PARTS: a message holds 65,535 bytes. JSON over MAX_JSON_WHOLE bytes goes as `lijox.part` messages (no id, no
//     answer): { of, n, total, data } with data = base64 of a slice of the whole JSON text; at most MAX_PARTS.
//   · A request whose peer disconnects is ended at once with a plain reason; one with no answer is ended by its
//     caller's deadline (`cancel`).
// No network, no wallet state and no clock of its own: the caller gives the time. Tested off the browser.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use bitcoin::secp256k1::PublicKey;
use futures::channel::oneshot;
use serde_json::{json, Value};

/// LSPS0's message type (bLIP-50).
pub const TYPE_LSPS0: u16 = 37913;
/// A request or an answer up to this many bytes of JSON is one message.
pub const MAX_JSON_WHOLE: usize = 60_000;
/// A part's slice of the JSON text, before base64.
pub const PART_BYTES: usize = 44_000;
/// What a part may carry at most (its base64 still fits one message).
pub const PART_BYTES_ACCEPTED: usize = 48_000;
pub const MAX_PARTS: usize = 32;
/// The parts of one answer arrive at most this far apart.
pub const PART_GAP_MS: u64 = 30_000;
/// Requests that may wait for an answer at once.
pub const MAX_WAITING: usize = 256;
/// Answers in parts that may be held at once.
pub const MAX_ANSWERS_IN_PARTS: usize = 8;

/// The path's own error: the peer went away before it answered.
pub const E_DISCONNECTED: i64 = -32010;
/// JSON-RPC: unknown method (what a wallet answers to any request — it serves none).
pub const E_METHOD: i64 = -32601;

/// What became of a request.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcOutcome {
    /// The provider's answer: `ok` for a 2xx body (`result`), or a refusal with the web route's status as `status`.
    Answer { ok: bool, status: i64, body: Value },
    /// The path itself failed: an unknown method, a limit, the peer gone. `code` is JSON-RPC's or ours.
    PathError { code: i64, message: String },
}

impl RpcOutcome {
    /// The one shape the page reads for both forms: {"ok":…,"status":…,"body":…} — or, for a path error,
    /// {"ok":false,"status":0,"path_error":{"code":…,"message":…}}.
    pub fn to_json(&self) -> Value {
        match self {
            RpcOutcome::Answer { ok, status, body } => json!({ "ok": ok, "status": status, "body": body }),
            RpcOutcome::PathError { code, message } => json!({ "ok": false, "status": 0, "path_error": { "code": code, "message": message } }),
        }
    }
}

struct Waiting {
    peer: PublicKey,
    tx: oneshot::Sender<RpcOutcome>,
}

struct PartsIn {
    peer: PublicKey,
    total: usize,
    got: HashMap<usize, Vec<u8>>,
    bytes: usize,
    last_ms: u64,
}

/// Counts for the Performance report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcCounts {
    pub sent: u64,
    pub answered: u64,
    pub refused: u64,
    pub path_errors: u64,
    pub ended_by_disconnect: u64,
    pub cancelled: u64,
    pub parts_out: u64,
    pub parts_in: u64,
    pub ignored: u64,
}

pub struct LijoxRpc {
    waiting: Mutex<HashMap<String, Waiting>>,
    outbound: Mutex<VecDeque<(PublicKey, Vec<u8>)>>,
    parts: Mutex<HashMap<String, PartsIn>>,
    next: AtomicU64,
    nonce: String,
    counts: Mutex<RpcCounts>,
    /// v384 (F3a-1): what each provider said it serves inside the connection — the provider's key (hex, lower case)
    /// → the methods of its last `lijox.hello` answer. The page keeps that memory (it outlives a restart) and hands
    /// it here; the engine keeps no memory of its own and never adds to this list by itself.
    served: Mutex<HashMap<String, Vec<String>>>,
}

fn method_ok(m: &str) -> bool {
    let mut it = m.splitn(2, '.');
    let (a, b) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    let word = |s: &str, under: bool| !s.is_empty() && s.len() <= 48 && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || (under && c == b'_'));
    word(a, false) && word(b, true)
}

/// One JSON text → the messages that carry it: itself, or its parts. None when it needs more than MAX_PARTS parts.
pub fn frames(id: &str, text: &str) -> Option<Vec<Vec<u8>>> {
    let bytes = text.as_bytes();
    if bytes.len() <= MAX_JSON_WHOLE {
        return Some(vec![bytes.to_vec()]);
    }
    let total = (bytes.len() + PART_BYTES - 1) / PART_BYTES;
    if total > MAX_PARTS {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let slice = &bytes[i * PART_BYTES..usize::min(bytes.len(), (i + 1) * PART_BYTES)];
        let part = json!({ "jsonrpc": "2.0", "method": "lijox.part", "params": { "of": id, "n": i + 1, "total": total, "data": b64(slice) } });
        out.push(part.to_string().into_bytes());
    }
    Some(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Standard base64 with padding, strictly: no other character, the padding only at the end. None otherwise.
fn unb64(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let last = b.len() / 4 - 1;
    for (i, q) in b.chunks(4).enumerate() {
        let pad = if i == last { q.iter().rev().take_while(|c| **c == b'=').count() } else { 0 };
        if pad > 2 || q[..4 - pad].iter().any(|c| *c == b'=') {
            return None;
        }
        let mut n = 0u32;
        for (k, c) in q.iter().enumerate() {
            n = (n << 6) | if k < 4 - pad { val(*c)? } else { 0 };
        }
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Some(out)
}

impl LijoxRpc {
    /// `seed`: random bytes of this engine start; they make this start's request ids unlike any other start's.
    pub fn new(seed: [u8; 8]) -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            outbound: Mutex::new(VecDeque::new()),
            parts: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            nonce: hex::encode(seed),
            counts: Mutex::new(RpcCounts::default()),
            served: Mutex::new(HashMap::new()),
        }
    }

    /// v384: the page hands over the methods a provider serves inside the connection (its own `lijox.hello` answer).
    /// The whole list for that provider is replaced; an empty list means it serves none. Names that are not method
    /// names are left out. → how many are kept.
    pub fn served_set(&self, peer_hex: &str, methods: &[String]) -> usize {
        let key = peer_hex.trim().to_ascii_lowercase();
        if key.len() != 66 || !key.bytes().all(|c| c.is_ascii_hexdigit()) { return 0; }
        let mut kept: Vec<String> = methods.iter().filter(|m| method_ok(m)).take(200).cloned().collect();
        kept.sort(); kept.dedup();
        let n = kept.len();
        let mut map = self.served.lock().unwrap();
        if map.len() >= 64 && !map.contains_key(&key) { return 0; }   // a wallet has one provider in use; 64 is far past any real list
        map.insert(key, kept);
        n
    }

    /// v384: is `method` on the list this provider gave? A method on the list is asked inside the connection and is
    /// NOT sent to that provider as a web request (f2-r1 §5: no return to the web form that a carrier could force).
    pub fn serves(&self, peer_hex: &str, method: &str) -> bool {
        let key = peer_hex.trim().to_ascii_lowercase();
        self.served.lock().unwrap().get(&key).map(|v| v.iter().any(|m| m == method)).unwrap_or(false)
    }

    /// Make a request to `peer`. Queues its message (or parts) and answers its id and the receiver of its outcome.
    /// The caller flushes the peer manager, then waits on the receiver up to its own deadline and calls `cancel`
    /// when that passes. `params` must be a JSON object.
    pub fn call(&self, peer: PublicKey, method: &str, params: Value) -> Result<(String, oneshot::Receiver<RpcOutcome>), String> {
        if !method_ok(method) {
            return Err(format!("not a method name: {method}"));
        }
        if !params.is_object() {
            return Err("params must be an object".into());
        }
        let id = format!("{}-{}", self.nonce, self.next.fetch_add(1, Ordering::Relaxed));
        let text = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        let fr = frames(&id, &text).ok_or_else(|| format!("the request is too large for this path ({} bytes)", text.len()))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut w = self.waiting.lock().unwrap();
            if w.len() >= MAX_WAITING {
                return Err("too many requests are waiting for an answer".into());
            }
            w.insert(id.clone(), Waiting { peer, tx });
        }
        let n = fr.len();
        {
            let mut q = self.outbound.lock().unwrap();
            for f in fr {
                q.push_back((peer, f));
            }
        }
        let mut c = self.counts.lock().unwrap();
        c.sent += 1;
        if n > 1 { c.parts_out += n as u64; }
        Ok((id, rx))
    }

    /// The caller's deadline passed: the request no longer waits. An answer that comes later is ignored.
    pub fn cancel(&self, id: &str) {
        if self.waiting.lock().unwrap().remove(id).is_some() {
            self.counts.lock().unwrap().cancelled += 1;
        }
        self.parts.lock().unwrap().remove(id);
    }

    /// Messages to send, drained by the handler's get_and_clear_pending_msg.
    pub fn drain_outbound(&self) -> Vec<(PublicKey, Vec<u8>)> {
        self.outbound.lock().unwrap().drain(..).collect()
    }

    pub fn waiting_len(&self) -> usize { self.waiting.lock().unwrap().len() }
    pub fn outbound_len(&self) -> usize { self.outbound.lock().unwrap().len() }
    pub fn counts(&self) -> RpcCounts { self.counts.lock().unwrap().clone() }

    /// 16 random bytes as 32 hex characters: the `rid` of one request that transfers money, made once per action
    /// and kept by the caller until the action is settled.
    pub fn rid_from(random: &[u8; 32]) -> String { hex::encode(&random[..16]) }

    /// The peer's connection ended: every request sent to it ends now, with the reason.
    pub fn peer_disconnected(&self, peer: &PublicKey) {
        let gone: Vec<Waiting> = {
            let mut w = self.waiting.lock().unwrap();
            let ids: Vec<String> = w.iter().filter(|(_, v)| v.peer == *peer).map(|(k, _)| k.clone()).collect();
            ids.into_iter().filter_map(|k| w.remove(&k)).collect()
        };
        self.parts.lock().unwrap().retain(|_, p| p.peer != *peer);
        // anything still queued for that peer would be dropped by the peer manager anyway
        self.outbound.lock().unwrap().retain(|(p, _)| p != peer);
        if !gone.is_empty() {
            self.counts.lock().unwrap().ended_by_disconnect += gone.len() as u64;
        }
        for w in gone {
            let _ = w.tx.send(RpcOutcome::PathError { code: E_DISCONNECTED, message: "the connection to the provider ended before it answered".into() });
        }
    }

    fn resolve(&self, sender: &PublicKey, msg: &Value) {
        let Some(id) = msg.get("id").and_then(|v| v.as_str()) else { self.counts.lock().unwrap().ignored += 1; return; };
        let w = {
            let mut map = self.waiting.lock().unwrap();
            match map.get(id) {
                Some(w) if w.peer == *sender => map.remove(id),
                _ => None,   // unknown, cancelled, or an answer from another peer than the one asked
            }
        };
        let Some(w) = w else { self.counts.lock().unwrap().ignored += 1; return; };
        let outcome = if let Some(result) = msg.get("result") {
            RpcOutcome::Answer { ok: true, status: 200, body: result.clone() }
        } else if let Some(err) = msg.get("error").filter(|e| e.is_object()) {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("").chars().take(200).collect::<String>();
            if (100..=599).contains(&code) {
                let body = match err.get("data") { Some(d) if !d.is_null() => d.clone(), _ => json!({ "ok": false, "error": message }) };
                RpcOutcome::Answer { ok: false, status: code, body }
            } else {
                RpcOutcome::PathError { code, message }
            }
        } else {
            RpcOutcome::PathError { code: 0, message: "an answer with neither a result nor an error".into() }
        };
        {
            let mut c = self.counts.lock().unwrap();
            match &outcome {
                RpcOutcome::Answer { ok: true, .. } => c.answered += 1,
                RpcOutcome::Answer { .. } => c.refused += 1,
                RpcOutcome::PathError { .. } => c.path_errors += 1,
            }
        }
        let _ = w.tx.send(outcome);
    }

    /// One part of a long answer. → Some(text) when the answer is whole.
    fn take_part(&self, sender: &PublicKey, p: &Value, now_ms: u64) -> Option<String> {
        let of = p.get("of")?.as_str()?.to_string();
        // only for a request this wallet made to this peer and that still waits
        if !matches!(self.waiting.lock().unwrap().get(&of), Some(w) if w.peer == *sender) {
            return None;
        }
        let mut parts = self.parts.lock().unwrap();
        parts.retain(|_, e| now_ms.saturating_sub(e.last_ms) <= PART_GAP_MS);
        let drop_it = |parts: &mut HashMap<String, PartsIn>| { parts.remove(&of); None };
        let total = p.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let n = p.get("n").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        if !(2..=MAX_PARTS).contains(&total) || n < 1 || n > total {
            return drop_it(&mut parts);
        }
        let Some(slice) = p.get("data").and_then(|v| v.as_str()).and_then(unb64) else { return drop_it(&mut parts); };
        if slice.is_empty() || slice.len() > PART_BYTES_ACCEPTED {
            return drop_it(&mut parts);
        }
        if !parts.contains_key(&of) && parts.len() >= MAX_ANSWERS_IN_PARTS {
            return None;
        }
        let e = parts.entry(of.clone()).or_insert_with(|| PartsIn { peer: *sender, total, got: HashMap::new(), bytes: 0, last_ms: now_ms });
        if e.total != total || e.got.contains_key(&n) {
            return drop_it(&mut parts);
        }
        e.bytes += slice.len();
        e.got.insert(n, slice);
        e.last_ms = now_ms;
        self.counts.lock().unwrap().parts_in += 1;
        if e.got.len() < e.total {
            return None;
        }
        let e = parts.remove(&of)?;
        let mut whole = Vec::with_capacity(e.bytes);
        for i in 1..=e.total {
            whole.extend_from_slice(e.got.get(&i)?);
        }
        String::from_utf8(whole).ok()
    }

    /// One 37913 message from a peer.
    pub fn on_message(&self, sender: PublicKey, bytes: &[u8], now_ms: u64) {
        self.on_message_inner(sender, bytes, now_ms, false)
    }

    fn on_message_inner(&self, sender: PublicKey, bytes: &[u8], now_ms: u64, via_parts: bool) {
        let msg: Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(_) => { self.counts.lock().unwrap().ignored += 1; return; }
        };
        if !msg.is_object() || msg.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            self.counts.lock().unwrap().ignored += 1;
            return;
        }
        match msg.get("method").and_then(|m| m.as_str()) {
            Some("lijox.part") => {
                if via_parts { self.counts.lock().unwrap().ignored += 1; return; }
                let Some(params) = msg.get("params") else { return; };
                let of = params.get("of").and_then(|v| v.as_str()).map(|s| s.to_string());
                if let Some(text) = self.take_part(&sender, params, now_ms) {
                    // the parts must make the answer they name
                    let named = serde_json::from_str::<Value>(&text).ok().and_then(|v| v.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()));
                    if named.is_some() && named == of {
                        self.on_message_inner(sender, text.as_bytes(), now_ms, true);
                    } else {
                        self.counts.lock().unwrap().ignored += 1;
                    }
                }
            }
            Some(_) => {
                // a request from the peer: this wallet serves no method. With an id it is told so; without one nothing.
                if let Some(id) = msg.get("id").filter(|i| i.is_string()) {
                    let reply = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": E_METHOD, "message": "unknown method" } });
                    self.outbound.lock().unwrap().push_back((sender, reply.to_string().into_bytes()));
                }
                self.counts.lock().unwrap().ignored += 1;
            }
            None => self.resolve(&sender, &msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use futures::FutureExt;

    fn pk(b: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
    }
    fn rpc() -> LijoxRpc { LijoxRpc::new([7u8; 8]) }
    fn sent(r: &LijoxRpc) -> Vec<(PublicKey, Value)> {
        r.drain_outbound().into_iter().map(|(p, b)| (p, serde_json::from_slice(&b).unwrap())).collect()
    }
    fn got(rx: &mut oneshot::Receiver<RpcOutcome>) -> Option<RpcOutcome> {
        rx.now_or_never().and_then(|r| r.ok())
    }
    fn answer(id: &str, result: Value) -> Vec<u8> { json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string().into_bytes() }

    #[test]
    fn f3a1_the_providers_list_is_what_the_page_handed_over_and_nothing_else() {
        let r = rpc();
        let a = "02".to_string() + &"ab".repeat(32);
        let b = "03".to_string() + &"cd".repeat(32);
        assert!(!r.serves(&a, "lijox.route_build"), "no list: nothing is served");
        let n = r.served_set(&a.to_uppercase(), &["lijox.route_build".into(), "lijox.hello".into(), "not a method".into(), "lijox.route_build".into()]);
        assert_eq!(n, 2, "names that are not method names are left out; a repeat counts once");
        assert!(r.serves(&a, "lijox.route_build") && r.serves(&a.to_uppercase(), "lijox.hello"));
        assert!(!r.serves(&a, "lijox.outcome"), "a method that is not on the list");
        assert!(!r.serves(&b, "lijox.route_build"), "another provider's list is its own");
        // the provider's later answer with fewer methods replaces the list whole
        assert_eq!(r.served_set(&a, &["lijox.hello".into()]), 1);
        assert!(!r.serves(&a, "lijox.route_build") && r.serves(&a, "lijox.hello"));
        assert_eq!(r.served_set(&a, &[]), 0);
        assert!(!r.serves(&a, "lijox.hello"), "an empty list: it serves none");
        // a key that is not a node key is not kept
        assert_eq!(r.served_set("nobody", &["lijox.hello".into()]), 0);
        assert!(!r.serves("nobody", "lijox.hello"));
    }

    #[test]
    fn f2_a_request_is_one_message_in_the_form_of_lsps0() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.prefs_set", json!({ "hold_ms": 21_600_000u64 })).unwrap();
        let out = sent(&r);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, pk(1));
        assert_eq!(out[0].1, json!({ "jsonrpc": "2.0", "id": id, "method": "lijox.prefs_set", "params": { "hold_ms": 21_600_000u64 } }));
        assert_eq!(id, "0707070707070707-1");
        assert!(got(&mut rx).is_none(), "nothing is known before the answer");
        assert_eq!(r.waiting_len(), 1);
        // ids of one start never repeat
        let (id2, _rx2) = r.call(pk(1), "lijox.hello", json!({})).unwrap();
        assert_eq!(id2, "0707070707070707-2");
    }

    #[test]
    fn f2_what_is_not_a_request_is_refused_before_anything_is_queued() {
        let r = rpc();
        for bad in ["prefs_set", "Lijox.prefs", "lijox.", ".x", "lijox.prefs set", "lijox.préfs", "a.b.c"] {
            assert!(r.call(pk(1), bad, json!({})).is_err(), "{bad}");
        }
        assert!(r.call(pk(1), "lijox.hello", json!([1])).is_err());
        assert!(r.call(pk(1), "lijox.hello", json!("x")).is_err());
        assert_eq!(r.outbound_len(), 0);
        assert_eq!(r.waiting_len(), 0);
        assert!(r.call(pk(1), "lsps0.list_protocols", json!({})).is_ok(), "a name with a digit and an underscore is a name");
    }

    #[test]
    fn f2_a_result_is_the_answer_and_a_refusal_carries_the_web_status_and_body() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.prefs_set", json!({ "hold_ms": 1 })).unwrap();
        r.on_message(pk(1), &answer(&id, json!({ "ok": true, "hold_ms_effective": 180000 })), 0);
        assert_eq!(got(&mut rx), Some(RpcOutcome::Answer { ok: true, status: 200, body: json!({ "ok": true, "hold_ms_effective": 180000 }) }));
        assert_eq!(r.waiting_len(), 0);

        let (id, mut rx) = r.call(pk(1), "lijox.prefs_set", json!({ "zaps": true })).unwrap();
        let refusal = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": 409, "message": "not_offered", "data": { "ok": false, "error": "not_offered", "zaps_offered": false } } });
        r.on_message(pk(1), refusal.to_string().as_bytes(), 0);
        let o = got(&mut rx).unwrap();
        assert_eq!(o, RpcOutcome::Answer { ok: false, status: 409, body: json!({ "ok": false, "error": "not_offered", "zaps_offered": false }) });
        assert_eq!(o.to_json(), json!({ "ok": false, "status": 409, "body": { "ok": false, "error": "not_offered", "zaps_offered": false } }));

        // a refusal with no data still gives the page a body with the reason
        let (id, mut rx) = r.call(pk(1), "lijox.prefs_set", json!({})).unwrap();
        r.on_message(pk(1), json!({ "jsonrpc": "2.0", "id": id, "error": { "code": 400, "message": "bad request" } }).to_string().as_bytes(), 0);
        assert_eq!(got(&mut rx), Some(RpcOutcome::Answer { ok: false, status: 400, body: json!({ "ok": false, "error": "bad request" }) }));

        // the path's own errors are not answers
        let (id, mut rx) = r.call(pk(1), "lijox.nothing", json!({})).unwrap();
        r.on_message(pk(1), json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "unknown method" } }).to_string().as_bytes(), 0);
        let o = got(&mut rx).unwrap();
        assert_eq!(o, RpcOutcome::PathError { code: -32601, message: "unknown method".into() });
        assert_eq!(o.to_json(), json!({ "ok": false, "status": 0, "path_error": { "code": -32601, "message": "unknown method" } }));
        let c = r.counts();
        assert_eq!((c.sent, c.answered, c.refused, c.path_errors), (4, 1, 2, 1));
    }

    #[test]
    fn f2_an_answer_is_taken_only_from_the_peer_that_was_asked() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.hello", json!({})).unwrap();
        r.on_message(pk(2), &answer(&id, json!({ "v": 9 })), 0);
        assert!(got(&mut rx).is_none(), "another peer's answer to our id changes nothing");
        assert_eq!(r.waiting_len(), 1);
        r.on_message(pk(1), &answer(&id, json!({ "v": 1 })), 0);
        assert_eq!(got(&mut rx), Some(RpcOutcome::Answer { ok: true, status: 200, body: json!({ "v": 1 }) }));
        // a second answer to the same id, an unknown id, bytes that are not JSON, another jsonrpc: all ignored
        r.on_message(pk(1), &answer(&id, json!({ "v": 2 })), 0);
        r.on_message(pk(1), &answer("nobody-1", json!({})), 0);
        r.on_message(pk(1), b"not json {", 0);
        r.on_message(pk(1), json!({ "jsonrpc": "1.0", "id": "x", "result": {} }).to_string().as_bytes(), 0);
        assert_eq!(r.counts().ignored, 5);
        assert_eq!(r.outbound_len(), 1, "only the request itself was ever queued");
    }

    #[test]
    fn f2_the_deadline_cancels_and_a_late_answer_is_ignored() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.hello", json!({})).unwrap();
        r.cancel(&id);
        assert_eq!(r.waiting_len(), 0);
        r.on_message(pk(1), &answer(&id, json!({ "v": 1 })), 0);
        assert!(matches!(rx.try_recv(), Err(_)) || got(&mut rx).is_none(), "the receiver learns nothing after a cancel");
        assert_eq!(r.counts().cancelled, 1);
        r.cancel(&id);
        assert_eq!(r.counts().cancelled, 1, "a second cancel counts nothing");
    }

    #[test]
    fn f2_a_disconnect_ends_that_peers_requests_at_once_with_the_reason() {
        let r = rpc();
        let (_a, mut rxa) = r.call(pk(1), "lijox.hello", json!({})).unwrap();
        let (_b, mut rxb) = r.call(pk(1), "lijox.prefs_set", json!({})).unwrap();
        let (_c, mut rxc) = r.call(pk(2), "lijox.hello", json!({})).unwrap();
        r.peer_disconnected(&pk(1));
        assert!(matches!(got(&mut rxa), Some(RpcOutcome::PathError { code: E_DISCONNECTED, .. })));
        assert!(matches!(got(&mut rxb), Some(RpcOutcome::PathError { code: E_DISCONNECTED, .. })));
        assert!(got(&mut rxc).is_none(), "another peer's request still waits");
        assert_eq!(r.waiting_len(), 1);
        assert_eq!(r.outbound_len(), 1, "what was still queued for the gone peer is let go; the other peer's stays");
        assert_eq!(r.counts().ended_by_disconnect, 2);
    }

    #[test]
    fn f2_a_long_request_goes_in_parts_that_each_fit_one_message() {
        let r = rpc();
        let blob = "é".repeat(60_000);   // 120,000 bytes: parts cut inside two-byte characters
        let (id, _rx) = r.call(pk(1), "lijox.kit_put", json!({ "blob": blob })).unwrap();
        let out = r.drain_outbound();
        assert_eq!(out.len(), 3);
        let mut whole = Vec::new();
        for (i, (p, b)) in out.iter().enumerate() {
            assert_eq!(*p, pk(1));
            assert!(b.len() + 2 <= 65_535, "part {} is {} bytes", i + 1, b.len());
            let v: Value = serde_json::from_slice(b).unwrap();
            assert_eq!(v["method"], "lijox.part");
            assert!(v.get("id").is_none(), "a part has no id of its own");
            assert_eq!(v["params"]["of"], id.as_str());
            assert_eq!(v["params"]["n"], i + 1);
            assert_eq!(v["params"]["total"], 3);
            whole.extend(unb64(v["params"]["data"].as_str().unwrap()).unwrap());
        }
        let back: Value = serde_json::from_slice(&whole).unwrap();
        assert_eq!(back["id"], id.as_str());
        assert_eq!(back["params"]["blob"].as_str().unwrap(), blob);
        assert_eq!(r.counts().parts_out, 3);
        // more than 32 parts is refused before anything is queued
        assert!(r.call(pk(1), "lijox.kit_put", json!({ "blob": "x".repeat(MAX_PARTS * PART_BYTES + 1) })).is_err());
        assert_eq!(r.outbound_len(), 0);
        assert_eq!(r.waiting_len(), 1);
    }

    fn part(of: &str, n: usize, total: usize, data: &[u8]) -> Vec<u8> {
        json!({ "jsonrpc": "2.0", "method": "lijox.part", "params": { "of": of, "n": n, "total": total, "data": b64(data) } }).to_string().into_bytes()
    }

    #[test]
    fn f2_a_long_answer_in_parts_is_put_together_in_any_order() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.lnurl_fetch", json!({})).unwrap();
        let text = json!({ "jsonrpc": "2.0", "id": id, "result": { "body": "é".repeat(50_000) } }).to_string();
        let fr = frames(&id, &text).unwrap();
        assert_eq!(fr.len(), 3);
        for i in [2usize, 0, 1] {
            assert!(got(&mut rx).is_none());
            r.on_message(pk(1), &fr[i], 1000);
        }
        match got(&mut rx).unwrap() {
            RpcOutcome::Answer { ok: true, status: 200, body } => assert_eq!(body["body"].as_str().unwrap().chars().count(), 50_000),
            o => panic!("{o:?}"),
        }
        assert_eq!(r.counts().parts_in, 3);
    }

    #[test]
    fn f2_parts_that_break_the_rules_let_the_answer_go_and_the_request_keeps_waiting() {
        let r = rpc();
        let (id, mut rx) = r.call(pk(1), "lijox.lnurl_fetch", json!({})).unwrap();
        let d = b"abc";
        // a part twice
        r.on_message(pk(1), &part(&id, 1, 3, d), 0);
        r.on_message(pk(1), &part(&id, 1, 3, d), 0);
        assert!(r.parts.lock().unwrap().is_empty(), "a part that comes twice lets the whole answer go");
        // total changed
        r.on_message(pk(1), &part(&id, 1, 3, d), 0);
        r.on_message(pk(1), &part(&id, 2, 4, d), 0);
        assert!(r.parts.lock().unwrap().is_empty());
        // out of range, too many, not base64, too large, empty
        r.on_message(pk(1), &part(&id, 4, 3, d), 0);
        r.on_message(pk(1), &part(&id, 1, 33, d), 0);
        r.on_message(pk(1), json!({ "jsonrpc": "2.0", "method": "lijox.part", "params": { "of": id, "n": 1, "total": 2, "data": "***" } }).to_string().as_bytes(), 0);
        r.on_message(pk(1), &part(&id, 1, 2, &vec![1u8; PART_BYTES_ACCEPTED + 1]), 0);
        assert!(r.parts.lock().unwrap().is_empty());
        // too late: the first part is forgotten after 30 s, the second starts over and the answer never completes
        r.on_message(pk(1), &part(&id, 1, 2, d), 0);
        r.on_message(pk(1), &part(&id, 2, 2, d), PART_GAP_MS + 1);
        assert_eq!(r.parts.lock().unwrap().get(&id).map(|e| e.got.len()), Some(1));
        assert!(got(&mut rx).is_none());
        assert_eq!(r.waiting_len(), 1, "the request still waits for its deadline");
        // parts from another peer, or for an id nobody waits for, are not kept
        let (id2, _rx2) = r.call(pk(1), "lijox.lnurl_fetch", json!({})).unwrap();
        r.on_message(pk(2), &part(&id2, 1, 2, d), 0);
        r.on_message(pk(1), &part("nobody-9", 1, 2, d), 0);
        assert!(!r.parts.lock().unwrap().contains_key(&id2));
        assert!(!r.parts.lock().unwrap().contains_key("nobody-9"));
        // parts that make an answer with another id are not that answer
        let other = json!({ "jsonrpc": "2.0", "id": "someone-else", "result": { "x": "y".repeat(70_000) } }).to_string();
        for f in frames("someone-else", &other).unwrap() {
            let mut v: Value = serde_json::from_slice(&f).unwrap();
            v["params"]["of"] = json!(id2);
            r.on_message(pk(1), v.to_string().as_bytes(), 0);
        }
        assert_eq!(r.waiting_len(), 2);
        // a cancel lets held parts go
        r.cancel(&id);
        assert!(!r.parts.lock().unwrap().contains_key(&id));
    }

    #[test]
    fn f2_a_request_from_the_peer_is_told_this_wallet_serves_no_method() {
        let r = rpc();
        r.on_message(pk(1), json!({ "jsonrpc": "2.0", "id": "p-1", "method": "lijox.hello", "params": {} }).to_string().as_bytes(), 0);
        let out = sent(&r);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, pk(1));
        assert_eq!(out[0].1, json!({ "jsonrpc": "2.0", "id": "p-1", "error": { "code": -32601, "message": "unknown method" } }));
        // a notification (no id) gets nothing
        r.on_message(pk(1), json!({ "jsonrpc": "2.0", "method": "lijox.note", "params": {} }).to_string().as_bytes(), 0);
        assert_eq!(r.outbound_len(), 0);
    }

    #[test]
    fn f2_too_many_waiting_requests_are_refused() {
        let r = rpc();
        let mut keep = Vec::new();
        for _ in 0..MAX_WAITING { keep.push(r.call(pk(1), "lijox.hello", json!({})).unwrap()); }
        assert!(r.call(pk(1), "lijox.hello", json!({})).is_err());
        r.cancel(&keep[0].0);
        assert!(r.call(pk(1), "lijox.hello", json!({})).is_ok());
    }

    #[test]
    fn f2_base64_reads_only_what_it_wrote() {
        for n in [0usize, 1, 2, 3, 4, 5, 255, 44_000] {
            let d: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let s = b64(&d);
            if n == 0 { assert!(unb64(&s).is_none(), "an empty part is no part"); } else { assert_eq!(unb64(&s).unwrap(), d); }
        }
        assert_eq!(b64(b"abc"), "YWJj");
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(b64(b"a"), "YQ==");
        for bad in ["YWJ", "YW=j", "=WJj", "YWJj====", "YW J", "YWJj\n", "Y===", "YQ==YQ=="] {
            assert!(unb64(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn f2_a_rid_is_32_hex_characters() {
        let rid = LijoxRpc::rid_from(&[0xabu8; 32]);
        assert_eq!(rid.len(), 32);
        assert_eq!(rid, "ab".repeat(16));
    }
}
