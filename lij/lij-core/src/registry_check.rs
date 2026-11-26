//! v392 (S72, F — docs/design/routes/sigcheck-r1.md): the wallet's own check of a provider's signature on its
//! registry record.
//!
//! A provider signs its record with its node key (LND `signmessage`) over one text, `lijox-register:vN:…`. Until
//! lij-worker 0.25.0 the registry checked that signature and did not hand it on, so a wallet took the list as the
//! registry gave it: the registry, or anything in the way, could change the addresses a wallet's web requests go to,
//! the fees shown, or take the `rpc` word out (which sends a wallet's requests back to web forms). From 0.25.0 the
//! list carries `signature` and `ts`, and this module checks them.
//!
//! ONE check for both readers of the list: the engine's own (`lsp::fetch_lsp_registry` — the start ladder,
//! `switch_lsp`, `list_lsps`) and the page's (`lijRegistryFetch`, through the `registry_list_check` export).
//!
//! The rule (`check_list`), for each record in a registry's answer:
//!   signature matches, not older than the held record          → `ok`    (used; becomes the held record)
//!   no signature — the registry has never sent one, and this
//!     wallet has never checked a record of this provider       → `none`  (used, as before this version)
//!   signature does not match / the text cannot be rebuilt      → refused `bad`
//!   signature matches, `ts` lower than the held record's       → refused `older`
//!   no signature — from a registry that has sent signatures,
//!     or for a provider whose record this wallet has checked   → refused `unsigned`
//! (Once this wallet has checked a provider's signed record it never again takes an unsigned or a changed one for
//! that provider, from any registry.)
//! A refused record is replaced by the HELD record of that provider (the last one this wallet checked, or — once,
//! after the update — the one the page had stored). With no held record it is left out. So a refused record never
//! takes away a provider this wallet already knows; only a provider it has never held can be left out.
//!
//! `canonical_register_text` is a copy, in Rust, of `canonicalRegisterMsg` (lij-worker/src/index.js; the adapter
//! holds the same function word for word). It is kept in step by a table: lij-worker/make-wallet-vectors.mjs
//! registers records through the registry's own handler, reads them back from its own list and writes each with the
//! text the registry's function makes (testdata/registry_vectors.json). The test below must make the same text and
//! accept the same signature; the registry's own test fails if the table is not the one its code makes.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, Secp256k1};
use serde_json::{json, Map, Value};

/// The last record that passed, per provider key: `{ "<pubkey>": { "rec": {…}, "checked": bool, "at_ms": n } }`.
pub const HELD_KEY: &str = "lij_reg_held_v1";
/// The registries that have sent a signature this wallet checked: `{ "<address>": first_ms }`.
pub const SIGNING_KEY: &str = "lij_reg_signing_v1";
/// The list the page stores after each read (`lijRegistryFetch`) — read ONCE, the first time this module runs, to
/// fill the held records of a wallet that ran before this version.
pub const PAGE_LIST_KEY: &str = "lij_lsp_list_v1";
/// The most held records kept. Past it the ones not in the answer at hand go first: not checked before checked, the
/// longest held before the newest.
pub const HELD_MAX: usize = 300;

// ── the signed text ─────────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Kind { Int, List, Bool, Str }

/// lij-worker's TATARA_FIELDS, in its order.
const TATARA_FIELDS: &[(&str, Kind)] = &[
    ("v", Kind::Int), ("sizes", Kind::List), ("min_people", Kind::Int), ("max_people", Kind::Int), ("countdown_s", Kind::Int),
    ("wake_window_s", Kind::Int), ("max_retries", Kind::Int), ("strikes", Kind::Int), ("max_pools_per_size", Kind::Int),
    ("max_pools_total", Kind::Int), ("max_list_per_size", Kind::Int), ("max_fee_rate", Kind::Int), ("channel_pools", Kind::Bool),
    ("channel_sizes", Kind::List), ("relay_url", Kind::Str), ("relay_for_others", Kind::Bool), ("forward_payouts", Kind::Bool),
    ("forward_coin_checks", Kind::Bool), ("coin_check_url", Kind::Str), ("ring_hash", Kind::Str),
];

/// JavaScript's truthiness of a JSON value (a key that is not there is `undefined`).
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// JavaScript's `String(number)`, for the numbers a record holds. JavaScript writes a number of 1e21 and up, or
/// under 1e-6, with an exponent; this copy does not write those and says so (no record a registry took holds one).
fn js_number(f: f64) -> Result<String, String> {
    if f == 0.0 { return Ok("0".into()); }
    let a = f.abs();
    if !f.is_finite() || a >= 1e21 || a < 1e-6 { return Err("a number this wallet cannot write the way the registry does".into()); }
    Ok(format!("{}", f))
}

/// The registry's `s(v)`: `(v === null || v === undefined) ? '' : String(v)`.
fn s(v: Option<&Value>) -> Result<String, String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(x)) => Ok(x.clone()),
        Some(Value::Bool(b)) => Ok(if *b { "true".into() } else { "false".into() }),
        Some(Value::Number(n)) => js_number(n.as_f64().ok_or("a number that cannot be read")?),
        Some(_) => Err("a list or a block where a word is signed".into()),
    }
}

/// The registry's `n(v)`: `String(Number(v) || 0)`.
fn n(v: Option<&Value>) -> Result<String, String> {
    match v {
        None | Some(Value::Null) => Ok("0".into()),
        Some(Value::Bool(b)) => Ok(if *b { "1".into() } else { "0".into() }),
        Some(Value::Number(x)) => js_number(x.as_f64().ok_or("a number that cannot be read")?),
        Some(_) => Err("a word, a list or a block where a number is signed".into()),
    }
}

fn bit(v: Option<&Value>) -> String { if truthy(v) { "1".into() } else { "0".into() } }

/// A member of a block. JavaScript reads a member of a number, a word or `true` as `undefined`; of `null` it throws.
fn member<'a>(block: Option<&'a Value>, key: &str) -> Option<&'a Value> { block.and_then(|b| b.get(key)) }

/// `x && x.length` for a value the text then calls `.map` on: Some(items) for a list with items, None for what
/// JavaScript reads as empty or absent, Err for what JavaScript would throw on (a word with letters).
fn listed<'a>(v: Option<&'a Value>) -> Result<Option<&'a Vec<Value>>, String> {
    match v {
        Some(Value::Array(a)) if !a.is_empty() => Ok(Some(a)),
        Some(Value::String(x)) if !x.is_empty() => Err("a word where a list is signed".into()),
        _ => Ok(None),
    }
}

/// `(x || []).map(…)`: the items of a list, none for what is absent, Err for anything else that is there.
fn items<'a>(v: Option<&'a Value>) -> Result<&'a [Value], String> {
    match v {
        Some(Value::Array(a)) => Ok(a.as_slice()),
        x if !truthy(x) => Ok(&[]),
        _ => Err("something that is not a list where a list is signed".into()),
    }
}

/// JavaScript's `encodeURIComponent`.
fn enc(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn tatara_fields(t: Option<&Value>) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(TATARA_FIELDS.len());
    for (key, kind) in TATARA_FIELDS {
        let v = member(t, key);
        out.push(match kind {
            Kind::List => { let mut parts = vec![]; for x in items(v)? { parts.push(n(Some(x))?); } parts.join(",") }
            Kind::Bool => bit(v),
            Kind::Int => n(v)?,
            Kind::Str => s(v)?,
        });
    }
    Ok(out)
}

fn routes_field(list: &[Value]) -> Result<String, String> {
    let mut parts = vec![];
    for r in list {
        if r.is_null() { return Err("an empty route".into()); }
        let r = Some(r);
        parts.push([s(member(r, "reach"))?, s(member(r, "endpoint"))?, s(member(r, "wss_url"))?, s(member(r, "filter_url"))?].join("|"));
    }
    Ok(parts.join(";"))
}

fn tower_fields(w: Option<&Value>) -> Result<Vec<String>, String> {
    Ok(vec![bit(member(w, "offered")), n(member(w, "quota_bytes"))?, n(member(w, "keep_days_silent"))?, s(member(w, "form"))?])
}

/// The text a provider signed for this record — `canonicalRegisterMsg` (lij-worker/src/index.js), v1 to v7. Built
/// from the record as the registry lists it. Err when the record holds something the registry's own function would
/// throw on, or a number this copy does not write; such a record cannot be checked and is refused.
pub fn canonical_register_text(f: &Value) -> Result<String, String> {
    if !f.is_object() { return Err("not a record".into()); }
    let g = |k: &str| f.get(k);
    let mut fields = vec![
        s(g("pubkey"))?, n(g("ts"))?, s(g("name"))?, s(g("endpoint"))?, s(g("wss_url"))?,
        s(g("route_endpoint"))?, s(g("route_macaroon"))?,
        n(g("fee_ppm"))?, n(g("fee_base_sats"))?, n(g("channel_open_fee_sats"))?,
        n(g("max_channel_size_sats"))?, bit(g("supports_jit")),
    ];
    let live = |k: &str| -> Option<&Value> { g(k).filter(|v| truthy(Some(v))) };   // `f.x || {}` / `f.x || []`
    let version;
    if let Some(rpc) = listed(g("rpc"))? {
        version = 7;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
        fields.extend(tatara_fields(live("tatara"))?);
        fields.push(routes_field(items(g("routes"))?)?);
        fields.extend(tower_fields(live("tower"))?);
        let c = live("chan_confs");
        fields.push(n(member(c, "min"))?); fields.push(n(member(c, "max"))?);
        let mut words = vec![]; for x in rpc { words.push(s(Some(x))?); }
        fields.push(words.join(","));
    } else if truthy(g("chan_confs")) {
        version = 6;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
        fields.extend(tatara_fields(live("tatara"))?);
        fields.push(routes_field(items(g("routes"))?)?);
        fields.extend(tower_fields(live("tower"))?);
        fields.push(n(member(g("chan_confs"), "min"))?); fields.push(n(member(g("chan_confs"), "max"))?);
    } else if truthy(g("tower")) {
        version = 5;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
        fields.extend(tatara_fields(live("tatara"))?);
        fields.push(routes_field(items(g("routes"))?)?);
        fields.extend(tower_fields(g("tower"))?);
    } else if let Some(routes) = listed(g("routes"))? {
        version = 4;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
        fields.extend(tatara_fields(live("tatara"))?);
        fields.push(routes_field(routes)?);
    } else if truthy(g("tatara")) {
        version = 3;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
        fields.extend(tatara_fields(g("tatara"))?);
    } else if truthy(g("filter_url")) {
        version = 2;
        fields.push(s(g("filter_url"))?); fields.push(bit(g("filter_sp")));
    } else {
        version = 1;
    }
    Ok(format!("lijox-register:v{}:{}", version, fields.iter().map(|x| enc(x)).collect::<Vec<_>>().join(":")))
}

// ── the signature ───────────────────────────────────────────────────────────────────────────────────────────────────

const ZB32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// zbase32, read the way the registry reads it (`zbase32Decode`): letters of either case, whole bytes only.
fn zbase32_decode(text: &str) -> Option<Vec<u8>> {
    let (mut bits, mut acc, mut out) = (0u32, 0u32, Vec::with_capacity(text.len() * 5 / 8));
    for ch in text.bytes() {
        let v = ZB32.iter().position(|&c| c == ch.to_ascii_lowercase())? as u32;
        acc = ((acc << 5) | v) & 0xFFFF; bits += 5;
        if bits >= 8 { bits -= 8; out.push(((acc >> bits) & 0xFF) as u8); }
    }
    Some(out)
}

/// The key that signed `msg` (hex, 33 bytes), by LND's `signmessage` form — the registry's
/// `verifyLndSignedRegistration`, step for step: zbase32 of 65 bytes, a header of 27 to 34, the recovery number
/// `(header − 27) & 3`, the double SHA-256 of "Lightning Signed Message:" + msg. None when the signature cannot be read.
pub fn recover_signer_hex(msg: &str, sig_zbase32: &str) -> Option<String> {
    let sig = zbase32_decode(sig_zbase32)?;
    if sig.len() != 65 { return None; }
    let header = sig[0];
    if !(27..=34).contains(&header) { return None; }
    let rec_id = RecoveryId::from_i32(((header - 27) & 3) as i32).ok()?;
    let mut pre = b"Lightning Signed Message:".to_vec();
    pre.extend_from_slice(msg.as_bytes());
    let digest = sha256d::Hash::hash(&pre);
    let rsig = RecoverableSignature::from_compact(&sig[1..], rec_id).ok()?;
    let key = Secp256k1::verification_only().recover_ecdsa(&Message::from_digest(digest.to_byte_array()), &rsig).ok()?;
    Some(hex::encode(key.serialize()))
}

fn pubkey_of(rec: &Value) -> Option<String> {
    let pk = rec.get("pubkey")?.as_str()?;
    if pk.len() == 66 && pk.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) { Some(pk.to_string()) } else { None }
}

fn ts_of(rec: &Value) -> f64 { rec.get("ts").and_then(|t| t.as_f64()).unwrap_or(0.0) }

/// One record against its own signature. `Ok(true)`: the record's key signed exactly this record. `Ok(false)`: the
/// record carries no signature. `Err(why)`: it carries one and it does not hold.
pub fn record_signed(rec: &Value) -> Result<bool, String> {
    let sig = match rec.get("signature") { Some(Value::String(x)) if !x.is_empty() => x, None | Some(Value::Null) => return Ok(false), Some(Value::String(_)) => return Ok(false), Some(_) => return Err("a signature that is not text".into()) };
    let pk = pubkey_of(rec).ok_or("no usable key on the record")?;
    let text = canonical_register_text(rec).map_err(|e| format!("the signed text cannot be rebuilt: {e}"))?;
    match recover_signer_hex(&text, sig) {
        Some(k) if k == pk => Ok(true),
        Some(_) => Err("the signature is another key's, or the record was changed after signing".into()),
        None => Err("the signature cannot be read".into()),
    }
}

// ── what the wallet holds ───────────────────────────────────────────────────────────────────────────────────────────

/// Where the held records and the signing registries are kept: the browser's storage in the wallet, a map in tests.
pub trait Store {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str);
}

/// The browser's localStorage (plain text values — the page shows them). Outside a browser it holds nothing.
pub struct BrowserStore;
impl Store for BrowserStore {
    fn get(&self, _key: &str) -> Option<String> {
        #[cfg(target_arch = "wasm32")]
        { return web_sys::window().and_then(|w| w.local_storage().ok()).flatten().and_then(|st| st.get_item(_key).ok()).flatten(); }
        #[cfg(not(target_arch = "wasm32"))]
        { None }
    }
    fn set(&self, _key: &str, _value: &str) {
        #[cfg(target_arch = "wasm32")]
        { if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok()).flatten() { let _ = st.set_item(_key, _value); } }
    }
}

/// A map, for tests.
#[derive(Default)]
pub struct MemStore(pub std::cell::RefCell<std::collections::HashMap<String, String>>);
impl Store for MemStore {
    fn get(&self, key: &str) -> Option<String> { self.0.borrow().get(key).cloned() }
    fn set(&self, key: &str, value: &str) { self.0.borrow_mut().insert(key.to_string(), value.to_string()); }
}

fn load_map(store: &dyn Store, key: &str) -> Option<Map<String, Value>> {
    store.get(key).map(|text| match serde_json::from_str::<Value>(&text) { Ok(Value::Object(m)) => m, _ => Map::new() })
}

/// The held records. The first time (no key yet) they are filled from the list the page last stored, each marked
/// not checked — so a wallet that ran before this version has a record to fall back on for every provider it knew.
fn load_held(store: &dyn Store) -> (Map<String, Value>, bool) {
    if let Some(m) = load_map(store, HELD_KEY) { return (m, false); }
    let mut m = Map::new();
    if let Some(Ok(Value::Array(list))) = store.get(PAGE_LIST_KEY).map(|t| serde_json::from_str::<Value>(&t)) {
        for rec in list {
            if let Some(pk) = pubkey_of(&rec) { m.insert(pk, json!({ "rec": bare(&rec), "checked": false, "at_ms": 0 })); }
        }
    }
    (m, true)
}

/// A record without the marks this module adds.
fn bare(rec: &Value) -> Value {
    let mut r = rec.clone();
    if let Some(o) = r.as_object_mut() { for k in ["sig_check", "sig_why", "sig_held_checked"] { o.remove(k); } }
    r
}

fn marked(rec: &Value, marks: &[(&str, Value)]) -> Value {
    let mut r = bare(rec);
    if let Some(o) = r.as_object_mut() { for (k, v) in marks { o.insert((*k).to_string(), v.clone()); } }
    r
}

/// The address of a registry as it is kept: no slash at the end.
pub fn registry_key(url: &str) -> String { url.trim().trim_end_matches('/').to_string() }

/// A registry's answer, checked. Returns the list to use — each record marked `sig_check`: `ok`, `none` or `held`
/// (a held record carries `sig_why`: `bad` | `older` | `unsigned`, and `sig_held_checked`) — and a report:
/// `{ registry, at_ms, signing, ok, none, held: [{pubkey, why, detail, held_checked}], left_out: [{pubkey, why, detail}] }`.
pub fn check_list(store: &dyn Store, registry_url: &str, list: &[Value], now_ms: u64) -> (Vec<Value>, Value) {
    let url = registry_key(registry_url);
    let (mut held, mut held_changed) = load_held(store);
    let mut signing = load_map(store, SIGNING_KEY).unwrap_or_default();
    let mut signing_changed = false;

    // Every signature first: a registry that sends one good signature in this answer is a signing registry for the
    // whole answer, wherever in the list that record stands.
    let verdicts: Vec<Result<bool, String>> = list.iter().map(record_signed).collect();
    if verdicts.iter().any(|v| matches!(v, Ok(true))) && !signing.contains_key(&url) {
        signing.insert(url.clone(), json!(now_ms)); signing_changed = true;
    }
    let is_signing = signing.contains_key(&url);

    let (mut out, mut n_ok, mut n_none) = (Vec::with_capacity(list.len()), 0u32, 0u32);
    let (mut rep_held, mut rep_out) = (vec![], vec![]);
    let mut in_answer = std::collections::HashSet::new();
    for (rec, verdict) in list.iter().zip(verdicts) {
        let pk = pubkey_of(rec);
        if let Some(p) = &pk { in_answer.insert(p.clone()); }
        let held_now = pk.as_ref().and_then(|p| held.get(p)).cloned();
        let held_checked = held_now.as_ref().and_then(|h| h.get("checked")).and_then(|c| c.as_bool()).unwrap_or(false);
        let signed = matches!(verdict, Ok(true));
        let refused: Option<(&str, String)> = match verdict {
            Ok(true) => {
                let older = held_checked && held_now.as_ref().and_then(|h| h.get("rec")).map(|h| ts_of(h) > ts_of(rec)).unwrap_or(false);
                if older { Some(("older", "signed, but this wallet holds a record this provider signed after it".into())) } else { None }
            }
            Ok(false) => if held_checked { Some(("unsigned", "no signature, for a provider whose signed record this wallet has checked".into())) }
                else if is_signing { Some(("unsigned", "no signature, from a registry that has sent signatures".into())) } else { None },
            Err(why) => Some(("bad", why)),
        };
        match refused {
            None => {
                if signed {
                    n_ok += 1;
                    if let Some(p) = &pk { held.insert(p.clone(), json!({ "rec": bare(rec), "checked": true, "at_ms": now_ms })); held_changed = true; }
                    out.push(marked(rec, &[("sig_check", json!("ok"))]));
                } else {
                    n_none += 1;
                    // not checked (and no checked record held — that was refused above): it replaces what is held unchecked
                    if let Some(p) = &pk {
                        let same = held_now.as_ref().and_then(|h| h.get("rec")).map(|h| *h == bare(rec)).unwrap_or(false);
                        if !same { held.insert(p.clone(), json!({ "rec": bare(rec), "checked": false, "at_ms": now_ms })); held_changed = true; }
                    }
                    out.push(marked(rec, &[("sig_check", json!("none"))]));
                }
            }
            Some((why, detail)) => {
                let key = pk.clone().unwrap_or_default();
                match held_now.as_ref().and_then(|h| h.get("rec")) {
                    Some(h) => {
                        rep_held.push(json!({ "pubkey": key, "why": why, "detail": detail, "held_checked": held_checked }));
                        out.push(marked(h, &[("sig_check", json!("held")), ("sig_why", json!(why)), ("sig_held_checked", json!(held_checked))]));
                    }
                    None => rep_out.push(json!({ "pubkey": key, "why": why, "detail": detail })),
                }
            }
        }
    }

    if held.len() > HELD_MAX {
        let mut spare: Vec<(bool, u64, String)> = held.iter().filter(|(k, _)| !in_answer.contains(*k))
            .map(|(k, v)| (v.get("checked").and_then(|c| c.as_bool()).unwrap_or(false), v.get("at_ms").and_then(|a| a.as_u64()).unwrap_or(0), k.clone())).collect();
        spare.sort();
        for (_, _, k) in spare { if held.len() <= HELD_MAX { break; } held.remove(&k); held_changed = true; }
    }
    if held_changed { store.set(HELD_KEY, &Value::Object(held).to_string()); }
    if signing_changed { store.set(SIGNING_KEY, &Value::Object(signing).to_string()); }

    let report = json!({ "registry": url, "at_ms": now_ms, "signing": is_signing, "ok": n_ok, "none": n_none, "held": rep_held, "left_out": rep_out });
    (out, report)
}

/// v393 (DP 2026-11-26 07:44, "3. Yes"): REGISTRIES THAT SIGN, KNOWN BEFORE ANY ANSWER. Until now a registry became
/// a signing one for a wallet when the wallet had SEEN one good signature from it — so the very first answer a new
/// phone read could be handed over with every signature taken out, and was read as "a registry that does not sign".
/// The page names the registries of its own table that sign (`registry_must_sign`, before the wallet starts); each is
/// written among the signing registries here, and `check_list` then refuses an unsigned record from it at the FIRST
/// contact: the held record of that provider is used, and a provider never held is left out. Returns how many were
/// added. A registry already marked is left as it is; nothing is ever unmarked.
pub fn must_sign(store: &dyn Store, urls: &[String], now_ms: u64) -> usize {
    let mut signing = load_map(store, SIGNING_KEY).unwrap_or_default();
    let mut added = 0;
    for u in urls {
        let k = registry_key(u);
        if !k.starts_with("https://") || signing.contains_key(&k) { continue; }
        signing.insert(k, json!(now_ms));
        added += 1;
    }
    if added > 0 { store.set(SIGNING_KEY, &Value::Object(signing).to_string()); }
    added
}

/// The report of the engine's own last read of a registry (`lsp::fetch_lsp_registry`), for the page.
pub static LAST_OWN_REPORT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The engine's own read: the answer's records checked against the browser's storage; the report is kept for the
/// page and each refusal goes to the log.
pub fn check_own_read(registry_url: &str, list: &[Value]) -> Vec<Value> {
    let (out, report) = check_list(&BrowserStore, registry_url, list, crate::storage::now_ms());
    for kind in ["held", "left_out"] {
        for r in report.get(kind).and_then(|x| x.as_array()).into_iter().flatten() {
            log::warn!("[registry check] {}: record of {} refused ({}: {}) — {}", registry_key(registry_url),
                r.get("pubkey").and_then(|p| p.as_str()).unwrap_or(""), r.get("why").and_then(|p| p.as_str()).unwrap_or(""),
                r.get("detail").and_then(|p| p.as_str()).unwrap_or(""), if kind == "held" { "the held record is used" } else { "left out (none held)" });
        }
    }
    if let Ok(mut g) = LAST_OWN_REPORT.lock() { *g = Some(report.to_string()); }
    out
}

#[cfg(test)]
mod v392_registry_check_tests {
    use super::*;

    const TABLE: &str = include_str!("testdata/registry_vectors.json");

    fn cases() -> Vec<Value> { serde_json::from_str::<Value>(TABLE).unwrap()["cases"].as_array().unwrap().clone() }
    fn rec_named(part: &str) -> Value { cases().into_iter().find(|c| c["name"].as_str().unwrap().contains(part)).unwrap_or_else(|| panic!("no case named {part}"))["rec"].clone() }
    fn with(rec: &Value, key: &str, v: Value) -> Value { let mut r = rec.clone(); r.as_object_mut().unwrap().insert(key.into(), v); r }
    fn without(rec: &Value, key: &str) -> Value { let mut r = rec.clone(); r.as_object_mut().unwrap().remove(key); r }
    const REG: &str = "https://registry.example";

    #[test]
    fn v392_the_text_is_the_registrys_text_for_every_version() {
        let cs = cases();
        assert!(cs.len() >= 17, "the table has every version's rows");
        let mut seen = std::collections::BTreeSet::new();
        for c in &cs {
            let text = canonical_register_text(&c["rec"]).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
            assert_eq!(text, c["text"].as_str().unwrap(), "{}", c["name"]);
            seen.insert(text[..18].to_string());
        }
        assert_eq!(seen.len(), 7, "v1 to v7 are all in the table: {seen:?}");
    }

    #[test]
    fn v392_every_listed_record_matches_its_signature_and_a_changed_one_does_not() {
        for c in cases() {
            let rec = &c["rec"];
            assert_eq!(record_signed(rec), Ok(true), "{}", c["name"]);
            // the registry's own words on a record are not in the signed text
            let mut noisy = rec.clone();
            for (k, v) in [("stale", json!(true)), ("last_seen_ms", json!(1)), ("uptime", json!(3)), ("registered_at", json!(5)), ("sig_check", json!("x"))] { noisy.as_object_mut().unwrap().insert(k.into(), v); }
            assert_eq!(record_signed(&noisy), Ok(true), "{}: the registry's own words do not matter", c["name"]);
            for (key, v) in [("endpoint", json!("https://evil.example")), ("wss_url", json!("wss://evil.example")), ("name", json!("someone else")), ("fee_ppm", json!(1)), ("ts", json!(ts_of(rec) + 1.0)), ("supports_jit", json!(!rec["supports_jit"].as_bool().unwrap()))] {
                assert!(record_signed(&with(rec, key, v)).is_err(), "{}: {key} changed", c["name"]);
            }
            assert_eq!(record_signed(&without(rec, "signature")), Ok(false), "{}: no signature is not a bad signature", c["name"]);
        }
    }

    #[test]
    fn v392_the_rpc_word_cannot_be_taken_out_or_put_in() {
        let v7 = rec_named("v7, the rpc list");
        assert!(record_signed(&without(&v7, "rpc")).is_err(), "taken out: the way back to web forms is closed");
        assert!(record_signed(&with(&v7, "rpc", json!(["lsps0", "x2"]))).is_err(), "a word added");
        let v6 = rec_named("v6, chan_confs");
        assert!(record_signed(&with(&v6, "rpc", json!(["lsps0"]))).is_err(), "put in on a record signed without it");
        let routes = rec_named("v4, two routes");
        let mut r2 = routes.clone();
        r2["routes"][0]["reach"] = json!("cloudflare");
        assert!(record_signed(&r2).is_err(), "a route's word for what sits in the way, changed");
        assert!(record_signed(&with(&v6, "tower", json!({ "offered": false, "quota_bytes": 5242880, "keep_days_silent": 400, "form": "teos-v1" }))).is_err(), "the tower switched off");
    }

    #[test]
    fn v392_another_keys_signature_and_broken_signatures_are_refused() {
        let a = rec_named("every base field");
        let b = rec_named("the fewest fields");
        assert!(record_signed(&with(&a, "signature", b["signature"].clone())).is_err(), "another record's signature");
        assert!(record_signed(&with(&a, "pubkey", b["pubkey"].clone())).is_err(), "the record under another key");
        let sig = a["signature"].as_str().unwrap();
        assert!(record_signed(&with(&a, "signature", json!(&sig[..sig.len() - 1]))).is_err(), "a short signature");
        assert!(record_signed(&with(&a, "signature", json!("not zbase32 !"))).is_err(), "not a signature at all");
        assert_eq!(record_signed(&with(&a, "signature", json!(sig.to_uppercase()))), Ok(true), "letters of either case, as the registry reads them");
        assert!(record_signed(&with(&a, "pubkey", json!(a["pubkey"].as_str().unwrap().to_uppercase()))).is_err(), "a key not in lowercase is not a registry key");
        assert!(record_signed(&with(&a, "fee_ppm", json!("250"))).is_err(), "a word where a number is signed: cannot be rebuilt, refused");
        assert!(record_signed(&with(&a, "fee_ppm", json!(1e22))).is_err(), "a number this copy does not write: refused, not guessed");
    }

    #[test]
    fn v392_numbers_are_written_as_javascript_writes_them() {
        for (f, want) in [(0.0, "0"), (-0.0, "0"), (250.0, "250"), (0.5, "0.5"), (1794999997.0, "1794999997"), (2100000000000000.0, "2100000000000000"), (0.000001, "0.000001"), (-3.0, "-3"), (1.5e20, "150000000000000000000")] {
            assert_eq!(js_number(f).unwrap(), want);
        }
        assert!(js_number(1e21).is_err() && js_number(1e-7).is_err() && js_number(f64::NAN).is_err());
        assert_eq!(enc("Bob's Umbrel \u{26a1} caf\u{e9} :;|%&+/?#=~!*()"), "Bob's%20Umbrel%20%E2%9A%A1%20caf%C3%A9%20%3A%3B%7C%25%26%2B%2F%3F%23%3D~!*()");
    }

    #[test]
    fn v393_a_registry_named_as_signing_is_held_to_it_at_the_first_contact() {
        let unsigned: Vec<Value> = cases().iter().take(3).map(|c| without(&without(&c["rec"], "signature"), "ts")).collect();
        // a new phone, nothing held: before v393 this answer was read as "a registry that does not sign" and used
        let st = MemStore::default();
        assert_eq!(must_sign(&st, &[format!("{REG}/"), "http://plain.example".into(), "not an address".into()], 500), 1, "the one https address; a slash at its end is the same registry");
        assert_eq!(must_sign(&st, &[REG.to_string()], 600), 0, "named again: nothing changes");
        let (out, rep) = check_list(&st, REG, &unsigned, 1000);
        assert!(out.is_empty(), "an unsigned answer from a registry that signs, at the first contact: nothing of it is used");
        assert_eq!(rep["signing"], true); assert_eq!(rep["none"], 0);
        assert_eq!(rep["left_out"].as_array().unwrap().len(), 3);
        assert!(rep["left_out"].as_array().unwrap().iter().all(|r| r["why"] == "unsigned"));
        // the signed answer of the same registry is used as ever
        let signed: Vec<Value> = cases().iter().take(3).map(|c| c["rec"].clone()).collect();
        let (out2, rep2) = check_list(&st, REG, &signed, 2000);
        assert_eq!(out2.len(), 3); assert_eq!(rep2["ok"], 3);
        // another registry, not named: read as before
        let (out3, rep3) = check_list(&MemStore::default(), "https://other.example", &unsigned, 1000);
        assert_eq!(out3.len(), 3); assert_eq!(rep3["signing"], false);
        // a phone that already holds a provider (the list the page had stored, not checked): the held record is used
        let st2 = MemStore::default();
        st2.set(PAGE_LIST_KEY, &Value::Array(vec![unsigned[0].clone()]).to_string());
        must_sign(&st2, &[REG.to_string()], 500);
        let moved = with(&unsigned[0], "endpoint", json!("https://moved.example"));
        let (out4, rep4) = check_list(&st2, REG, &[moved], 1000);
        assert_eq!(out4.len(), 1, "the provider this phone knew is not lost");
        assert_eq!(out4[0]["sig_check"], "held"); assert_eq!(out4[0]["endpoint"], unsigned[0]["endpoint"], "and its address is the one held, not the unsigned one");
        assert_eq!(rep4["held"][0]["why"], "unsigned");
    }

    #[test]
    fn v392_a_registry_that_sends_no_signatures_is_read_as_before() {
        let st = MemStore::default();
        let list: Vec<Value> = cases().iter().take(3).map(|c| without(&without(&c["rec"], "signature"), "ts")).collect();
        let (out, rep) = check_list(&st, REG, &list, 1000);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|r| r["sig_check"] == "none"));
        assert_eq!(rep["none"], 3); assert_eq!(rep["ok"], 0); assert_eq!(rep["signing"], false);
        assert!(rep["held"].as_array().unwrap().is_empty() && rep["left_out"].as_array().unwrap().is_empty());
        // every other field is as the registry sent it
        assert_eq!(bare(&out[0]), list[0]);
        // and a record changed between two reads of such a registry is simply the new record (nothing to check it with)
        let moved = with(&list[0], "endpoint", json!("https://moved.example"));
        let (out2, _) = check_list(&st, REG, &[moved.clone()], 2000);
        assert_eq!(out2[0]["endpoint"], "https://moved.example");
    }

    #[test]
    fn v392_a_good_record_is_used_and_held_and_the_registry_is_then_held_to_signing() {
        let st = MemStore::default();
        let a = rec_named("v7, the rpc list");
        let b = rec_named("every base field");
        let (out, rep) = check_list(&st, "https://registry.example/", &[a.clone(), b.clone()], 1000);
        assert!(out.iter().all(|r| r["sig_check"] == "ok"));
        assert_eq!(rep["ok"], 2); assert_eq!(rep["signing"], true); assert_eq!(rep["registry"], REG);
        let held: Value = serde_json::from_str(&st.get(HELD_KEY).unwrap()).unwrap();
        assert_eq!(held[a["pubkey"].as_str().unwrap()]["rec"], a); assert_eq!(held[a["pubkey"].as_str().unwrap()]["checked"], true);
        assert!(st.get(SIGNING_KEY).unwrap().contains(REG));

        // the same registry now sends the list without signatures: refused, the held records are used
        let stripped: Vec<Value> = [&a, &b].iter().map(|r| with(&without(&without(r, "signature"), "ts"), "endpoint", json!("https://evil.example"))).collect();
        let (out, rep) = check_list(&st, REG, &stripped, 2000);
        assert_eq!(out.len(), 2);
        for (o, orig) in out.iter().zip([&a, &b]) {
            assert_eq!(o["sig_check"], "held"); assert_eq!(o["sig_why"], "unsigned"); assert_eq!(o["sig_held_checked"], true);
            assert_eq!(o["endpoint"], orig["endpoint"], "the held record's address, not the changed one");
            assert_eq!(&bare(o), orig);
        }
        assert_eq!(rep["held"].as_array().unwrap().len(), 2); assert_eq!(rep["ok"], 0);
        // a provider never held, unsigned, from a signing registry: left out
        let c = rec_named("the fewest fields");
        let (out, rep) = check_list(&st, REG, &[without(&c, "signature")], 3000);
        assert!(out.is_empty()); assert_eq!(rep["left_out"][0]["why"], "unsigned"); assert_eq!(rep["left_out"][0]["pubkey"], c["pubkey"]);
        // another registry that has never signed is still read as before — for a provider this wallet has never checked
        let (out, _) = check_list(&st, "https://old.example", &[without(&c, "signature")], 4000);
        assert_eq!(out[0]["sig_check"], "none");
        // but not for a provider whose signed record this wallet has checked: from any registry, unsigned is refused
        let (out, rep) = check_list(&st, "https://old.example", &[with(&without(&a, "signature"), "endpoint", json!("https://evil.example")), without(&c, "signature")], 5000);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["sig_check"], "held"); assert_eq!(out[0]["sig_why"], "unsigned"); assert_eq!(out[0]["endpoint"], a["endpoint"]);
        assert_eq!(out[1]["sig_check"], "none");
        assert_eq!(rep["signing"], false); assert_eq!(rep["held"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn v392_a_record_changed_after_signing_is_not_used() {
        let st = MemStore::default();
        let a = rec_named("v7, the rpc list");
        let evil = without(&a, "rpc");   // the rpc word taken out, the signature left on
        // never held: left out
        let (out, rep) = check_list(&st, REG, &[evil.clone()], 1000);
        assert!(out.is_empty());
        assert_eq!(rep["left_out"][0]["why"], "bad"); assert_eq!(rep["signing"], false, "a bad signature does not make a registry a signing one");
        // held: the held record is used, with its rpc word
        check_list(&st, REG, &[a.clone()], 2000);
        let (out, rep) = check_list(&st, REG, &[evil], 3000);
        assert_eq!(out.len(), 1); assert_eq!(out[0]["sig_check"], "held"); assert_eq!(out[0]["sig_why"], "bad");
        assert_eq!(out[0]["rpc"], json!(["lsps0"]));
        assert_eq!(rep["held"][0]["why"], "bad"); assert_eq!(rep["held"][0]["held_checked"], true);
        // one bad record does not touch the others in the answer
        let b = rec_named("every base field");
        let (out, rep) = check_list(&st, REG, &[with(&a, "endpoint", json!("https://evil.example")), b.clone()], 4000);
        assert_eq!(out.len(), 2); assert_eq!(out[0]["sig_check"], "held"); assert_eq!(out[1]["sig_check"], "ok"); assert_eq!(rep["ok"], 1);
    }

    #[test]
    fn v392_an_older_signed_record_does_not_replace_a_newer_one() {
        // two true records of one provider: the table's case, and the same provider's next registration (made here
        // with a key of our own, signed the way the table's are)
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = hex::encode(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize());
        let sign = |mut rec: Value| -> Value {
            rec.as_object_mut().unwrap().insert("pubkey".into(), json!(pk));
            rec.as_object_mut().unwrap().remove("signature");
            let text = canonical_register_text(&rec).unwrap();
            // LDK's signer makes LND's form (header 31 + recovery number) — a second, independent maker of signatures
            let sig = lightning::util::message_signing::sign(text.as_bytes(), &sk);
            with(&rec, "signature", json!(sig))
        };
        let base = rec_named("v6, chan_confs");
        let old = sign(with(&base, "ts", json!(1000)));
        let new = sign(with(&with(&base, "ts", json!(2000)), "rpc", json!(["lsps0"])));
        assert_eq!(record_signed(&old), Ok(true)); assert_eq!(record_signed(&new), Ok(true));

        let st = MemStore::default();
        let (out, _) = check_list(&st, REG, &[new.clone()], 10);
        assert_eq!(out[0]["sig_check"], "ok");
        // the registry (or something in the way) now serves the older true record — the one without the rpc word
        let (out, rep) = check_list(&st, REG, &[old.clone()], 20);
        assert_eq!(out[0]["sig_check"], "held"); assert_eq!(out[0]["sig_why"], "older");
        assert_eq!(out[0]["rpc"], json!(["lsps0"]), "the newer record stays");
        assert_eq!(rep["held"][0]["why"], "older");
        // from another registry too: the newest record this wallet has checked wins, whichever registry it came from
        let (out, _) = check_list(&st, "https://second.example", &[old.clone()], 30);
        assert_eq!(out[0]["sig_why"], "older");
        // the same record again, and a later one, are taken
        let (out, _) = check_list(&st, REG, &[new.clone()], 40);
        assert_eq!(out[0]["sig_check"], "ok");
        let newest = sign(with(&base, "ts", json!(3000)));
        let (out, _) = check_list(&st, REG, &[newest], 50);
        assert_eq!(out[0]["sig_check"], "ok"); assert!(out[0].get("rpc").is_none(), "a provider may take its own word back: it signed that");
        // a wallet that has only ever held the old one takes the old one
        let st2 = MemStore::default();
        let (out, _) = check_list(&st2, REG, &[old], 60);
        assert_eq!(out[0]["sig_check"], "ok");
    }

    #[test]
    fn v392_the_first_run_is_filled_from_the_pages_stored_list() {
        let st = MemStore::default();
        let a = rec_named("v7, the rpc list");
        let b = rec_named("every base field");
        let stored: Vec<Value> = [&a, &b].iter().map(|r| without(&without(r, "signature"), "ts")).collect();   // what an older page stored
        st.set(PAGE_LIST_KEY, &Value::Array(stored.clone()).to_string());
        // the very first answer carries a changed record of a provider this wallet was using
        let evil = with(&a, "endpoint", json!("https://evil.example"));
        let (out, rep) = check_list(&st, REG, &[evil, b.clone()], 1000);
        assert_eq!(out.len(), 2, "the provider this wallet knew is not lost");
        assert_eq!(out[0]["sig_check"], "held"); assert_eq!(out[0]["sig_why"], "bad"); assert_eq!(out[0]["sig_held_checked"], false);
        assert_eq!(bare(&out[0]), stored[0], "the record the wallet was using");
        assert_eq!(out[1]["sig_check"], "ok");
        assert_eq!(rep["held"][0]["held_checked"], false);
        // the fill happens once: a later change to the page's key is not read again
        st.set(PAGE_LIST_KEY, "[]");
        let (out, _) = check_list(&st, REG, &[with(&a, "name", json!("x"))], 2000);
        assert_eq!(out[0]["sig_check"], "held");
        // a record held unchecked gives way to the first good one, and "older" never refuses against an unchecked one
        let (out, _) = check_list(&st, REG, &[a.clone()], 3000);
        assert_eq!(out[0]["sig_check"], "ok");
        // a wallet with nothing stored starts with nothing held, and the key is written so the fill is not tried again
        let fresh = MemStore::default();
        let (out, _) = check_list(&fresh, REG, &[], 1);
        assert!(out.is_empty()); assert_eq!(fresh.get(HELD_KEY).unwrap(), "{}");
    }

    #[test]
    fn v392_what_cannot_be_read_does_not_stop_the_rest() {
        let st = MemStore::default();
        let a = rec_named("every base field");
        st.set(HELD_KEY, "not json"); st.set(SIGNING_KEY, "[1,2]");
        let odd = vec![json!(null), json!("text"), json!({ "name": "no key" }), json!({ "pubkey": "zz", "signature": "abc" }), a.clone()];
        let (out, rep) = check_list(&st, REG, &odd, 1000);
        // before a good signature is seen in the answer the registry is not a signing one — but this answer has one
        assert_eq!(rep["ok"], 1); assert_eq!(rep["signing"], true);
        assert_eq!(out.len(), 1, "the good record; the four that cannot be checked are left out of a signing registry's answer");
        assert_eq!(rep["left_out"].as_array().unwrap().len(), 4);
        // from a registry that has never signed, the same odd records pass as before (the reader's own parsing decides)
        let st2 = MemStore::default();
        let (out, rep) = check_list(&st2, "https://old.example", &odd[..3], 1000);
        assert_eq!(out.len(), 3); assert_eq!(rep["none"], 3);
    }

    /// Not run by default. A registry's real answer, saved to a file, through the same check:
    /// `LIJ_LSPS_FILE=/path/to/lsps.json cargo test -p lij-core --lib v392_a_saved_answer -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn v392_a_saved_answer_from_a_real_registry() {
        let path = std::env::var("LIJ_LSPS_FILE").expect("LIJ_LSPS_FILE names the saved answer");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let list = v["lsps"].as_array().expect("an lsps list").clone();
        let mut bad = 0;
        for rec in &list {
            let r = record_signed(rec);
            println!("{:?}  {}  {}  ts {}{}", r, rec["pubkey"].as_str().unwrap_or("?"), rec["name"], rec["ts"], if rec["stale"] == json!(true) { "  (stale)" } else { "" });
            if r != Ok(true) { bad += 1; println!("   text: {:?}", canonical_register_text(rec)); }
        }
        let st = MemStore::default();
        let (out, rep) = check_list(&st, "https://saved.example", &list, 1);
        println!("{} records · used {} · report {}", list.len(), out.len(), rep);
        assert_eq!(bad, 0, "every record of a real registry's answer matches its own signature");
    }

    #[test]
    fn v392_the_held_records_are_capped() {
        let st = MemStore::default();
        let mut m = Map::new();
        for i in 0..(HELD_MAX + 20) { m.insert(format!("{:066x}", i), json!({ "rec": { "pubkey": format!("{:066x}", i) }, "checked": i % 2 == 0, "at_ms": i })); }
        st.set(HELD_KEY, &Value::Object(m).to_string());
        let a = rec_named("every base field");
        check_list(&st, REG, &[a.clone()], 999_999);
        let held: Value = serde_json::from_str(&st.get(HELD_KEY).unwrap()).unwrap();
        let o = held.as_object().unwrap();
        assert_eq!(o.len(), HELD_MAX);
        assert!(o.contains_key(a["pubkey"].as_str().unwrap()), "the record in the answer at hand is kept");
        assert!(!o.contains_key(&format!("{:066x}", 1)), "not checked, longest held: first to go");
        assert!(o.contains_key(&format!("{:066x}", 0)), "checked ones go last");
    }
}
