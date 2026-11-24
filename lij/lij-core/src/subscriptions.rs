//! S71 (Thu 2026-11-19, DP 14:47 "Go on all subscription work"): LIJOX SUBSCRIPTIONS — THE PURE HALF.
//!
//! What a paying wallet and a plan server say to each other is written in
//! docs/design/subscriptions/lijox-subscriptions-r2.md (the format); this file is that format in code, with no wallet
//! state and no network: the tagged hash, the shared secret, each payment's tag, the signed and the tagged messages,
//! the terms and the exact string they are signed as, the plan's checks, the due dates, the six checks on an invoice,
//! and the records with the rule that ONE PAYMENT NUMBER IS SENT ONCE. The seller's signatures are here too (a LiJ
//! wallet user who sells signs its plans' terms, its receipts and each payment hash with its selling key).
//!
//! A subscription is an agreement with a merchant. Nothing is ever sent automatically: the wallet sends each payment
//! only when the wallet user taps Pay (DP 11-18 11:12). First pass: Lightning only (DP 11-19 13:58).
//!
//! The keys come from key.rs (`subs_key`, `subs_seller_key`); this file takes them as 32 bytes.

use std::str::FromStr;

use bitcoin::secp256k1::{ecdh, schnorr, Keypair, Message, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use hkdf::hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{LijError, LijResult};

/// The format's version: every message carries `"v": 1`, every canonical string starts `lijox-subs/1|`.
pub const V: u32 = 1;
const PREFIX: &str = "lijox-subs/1";
const TAG_SECRET: &str = "LIJOX-Subs/secret";
const TAG_MSG: &str = "LIJOX-Subs/msg";
const TAG_TERMS: &str = "LIJOX-Subs/terms";
/// A signed message's `ts` may be this far from the server's clock (format §1).
pub const CLOCK_SKEW_SECS: u64 = 600;
/// Payment n can be paid from this long before its due date — the first notice (format §3.4).
pub const PAY_EARLY_SECS: u64 = 14 * 86_400;
/// The longest life of a rate stamp and of an invoice (format §14).
pub const INVOICE_LIFE_MAX_SECS: u64 = 600;
/// The wallet's own record of every subscription (in the wallet's state, so a backup carries it).
pub const SUBS_KEY: &str = "lij_subs";

fn err(m: impl Into<String>) -> LijError { LijError::Payment(m.into()) }

// ─────────────────────────────────────────────────────────────────────────────
// Hashes, the shared secret, tags, signatures (format §1, §2)
// ─────────────────────────────────────────────────────────────────────────────

/// TH(tag, data) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data) — the BIP-340 form.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(data);
    h.finalize().into()
}

fn secret_key(sk: &[u8; 32]) -> LijResult<SecretKey> {
    SecretKey::from_slice(sk).map_err(|e| LijError::Key(format!("subscriptions: not a key: {e}")))
}

fn xonly_from_hex(h: &str) -> Result<XOnlyPublicKey, String> {
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("a key must be 64 lowercase hex characters".into());
    }
    let b = hex::decode(h).map_err(|e| format!("a key does not decode: {e}"))?;
    XOnlyPublicKey::from_slice(&b).map_err(|e| format!("not a key: {e}"))
}

/// The public half of a key of this format: x-only (BIP-340), 64 hex.
pub fn public_hex(sk: &[u8; 32]) -> LijResult<String> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &secret_key(sk)?);
    Ok(hex::encode(kp.x_only_public_key().0.serialize()))
}

/// K — the 32 bytes both sides work out without sending them (format §2.3):
/// `TH("LIJOX-Subs/secret", x(my_sk · their_key))`, their x-only key lifted to the point with even y. The x of the
/// product is the same whichever of the two points' signs is taken, so the wallet and the merchant get the same K.
pub fn shared_secret(my_sk: &[u8; 32], their_key_hex: &str) -> LijResult<[u8; 32]> {
    let x = xonly_from_hex(their_key_hex).map_err(LijError::Key)?;
    let point = PublicKey::from_x_only_public_key(x, Parity::Even);
    let xy = ecdh::shared_secret_point(&point, &secret_key(my_sk)?);
    Ok(tagged_hash(TAG_SECRET, &xy[..32]))
}

fn hmac_sha256(k: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).expect("hmac takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// tag(n) — the first 16 bytes of HMAC-SHA256(K, "payment" ‖ u32be(n)), as 32 hex (format §2.4). n starts at 1.
pub fn payment_tag(k: &[u8; 32], n: u32) -> String {
    let mut d = Vec::with_capacity(11);
    d.extend_from_slice(b"payment");
    d.extend_from_slice(&n.to_be_bytes());
    hex::encode(&hmac_sha256(k, &d)[..16])
}

/// mac — hex(HMAC-SHA256(K, canonical string)), for a tagged message that changes something (format §2.5).
pub fn mac_hex(k: &[u8; 32], canonical: &str) -> String {
    hex::encode(hmac_sha256(k, canonical.as_bytes()))
}

/// A signature over `TH("LIJOX-Subs/msg", canonical string)` — BIP-340, 128 hex (format §2.6).
pub fn sign_canonical(sk: &[u8; 32], canonical: &str) -> LijResult<String> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &secret_key(sk)?);
    let msg = Message::from_digest(tagged_hash(TAG_MSG, canonical.as_bytes()));
    Ok(hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &kp).serialize()))
}

pub(crate) fn verify_digest(key_hex: &str, digest: [u8; 32], sig_hex: &str) -> bool {
    let Ok(x) = xonly_from_hex(key_hex) else { return false };
    if sig_hex.len() != 128 { return false; }
    let Ok(sb) = hex::decode(sig_hex) else { return false };
    let Ok(sig) = schnorr::Signature::from_slice(&sb) else { return false };
    Secp256k1::verification_only().verify_schnorr(&sig, &Message::from_digest(digest), &x).is_ok()
}

/// Does `sig_hex` sign this canonical string under `key_hex`?
pub fn verify_canonical(key_hex: &str, canonical: &str, sig_hex: &str) -> bool {
    verify_digest(key_hex, tagged_hash(TAG_MSG, canonical.as_bytes()), sig_hex)
}

/// A plan id (1–40) or a signup code (1–32): letters, digits, `-`, `_`, `.` only — the fields of a signed message are
/// joined by `|` (format §1, r2).
pub fn name_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub(crate) fn canon(kind: &str, fields: &[&str]) -> String {
    let mut s = String::from(PREFIX);
    s.push('|');
    s.push_str(kind);
    for f in fields {
        s.push('|');
        s.push_str(f);
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// The terms (format §3.3) and the exact string they are signed as
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceStep { pub from: u32, pub amount: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Price { pub unit: String, pub by_payment: Vec<PriceStep> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Every { pub unit: String, pub count: u32 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirstPayment {
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub date: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub days: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ending { pub refund: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningTerms { pub nodes: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnchainTerms { pub sp_address: String }

/// The terms of a plan. The merchant's name and the plan's name are INSIDE them since r2: what the wallet user reads
/// at Agree is what the plan key signed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Terms {
    pub terms_version: u32,
    pub merchant_name: String,
    pub plan_name: String,
    pub price: Price,
    pub every: Every,
    pub first_payment: FirstPayment,
    #[serde(default)] pub payments: Option<u32>,
    #[serde(default)] pub price_kept_through: Option<u32>,
    pub grace_days: u32,
    pub ending: Ending,
    pub change_notice_days: u32,
    pub pay_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub lightning: Option<LightningTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub onchain: Option<OnchainTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub free_days_need: Option<String>,
    /// Round 4: one line about the plan, shown under its name. Inside the signed terms like the names; a plan without
    /// one is signed exactly as before round 4.
    #[serde(default, skip_serializing_if = "Option::is_none")] pub plan_description: Option<String>,
}

const KNOWN_TERMS: &[&str] = &["terms_version", "merchant_name", "plan_name", "price", "every", "first_payment", "payments",
    "price_kept_through", "grace_days", "ending", "change_notice_days", "pay_by", "lightning", "onchain", "free_days_need", "plan_description"];

/// A decimal amount as the format writes it: digits, at most one `.`, at most 8 digits after it, at most 20 in all,
/// no sign. Returned as (the digits as one number, how many of them stand after the point).
pub fn parse_decimal(s: &str) -> Result<(u128, u32), String> {
    let (int, frac) = match s.split_once('.') { Some((a, b)) => (a, b), None => (s, "") };
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not an amount: {s:?}"));
    }
    if s.contains('.') && frac.is_empty() { return Err(format!("not an amount: {s:?}")); }
    if frac.len() > 8 || int.len() + frac.len() > 20 { return Err(format!("an amount with too many digits: {s:?}")); }
    let digits = format!("{int}{frac}");
    Ok((digits.parse::<u128>().map_err(|_| format!("not an amount: {s:?}"))?, frac.len() as u32))
}

fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(|c| c.is_control())
}

fn node_key_ok(h: &str) -> bool {
    h.len() == 66 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && hex::decode(h).ok().and_then(|b| PublicKey::from_slice(&b).ok()).is_some()
}

impl Terms {
    /// The limits of format §14 and the shapes of §3.3. A plan whose terms fail any of them is refused.
    pub fn validate(&self) -> Result<(), String> {
        if self.terms_version == 0 { return Err("terms_version starts at 1".into()); }
        if !text_ok(&self.merchant_name, 60) { return Err("the merchant's name: 1–60 characters, no line break".into()); }
        if !text_ok(&self.plan_name, 60) { return Err("the plan's name: 1–60 characters, no line break".into()); }
        if let Some(d) = &self.plan_description { if !text_ok(d, 140) { return Err("the plan's description: 1–140 characters, no line break (or leave it out)".into()); } }
        let u = &self.price.unit;
        let sat = u == "sat";
        if !sat && !(u.len() == 3 && u.bytes().all(|b| b.is_ascii_uppercase())) { return Err("price.unit: sat, or a three-letter currency code".into()); }
        let steps = &self.price.by_payment;
        if steps.is_empty() || steps.len() > 24 { return Err("price.by_payment: 1–24 entries".into()); }
        if steps[0].from != 1 { return Err("price.by_payment starts at payment 1".into()); }
        for (i, st) in steps.iter().enumerate() {
            if i > 0 && st.from <= steps[i - 1].from { return Err("price.by_payment: each entry starts at a higher payment number".into()); }
            let (m, scale) = parse_decimal(&st.amount)?;
            if m == 0 { return Err("a price of zero".into()); }
            if sat && scale != 0 { return Err("a price in sats is a whole number".into()); }
        }
        if !matches!(self.every.unit.as_str(), "week" | "month" | "year") { return Err("every.unit: week, month or year".into()); }
        if !(1..=12).contains(&self.every.count) { return Err("every.count: 1–12".into()); }
        match self.first_payment.rule.as_str() {
            "on_agree" => { if self.first_payment.date.is_some() || self.first_payment.days.is_some() { return Err("first_payment on_agree carries no date and no days".into()); } }
            "on_date" => { if self.first_payment.date.is_none() || self.first_payment.days.is_some() { return Err("first_payment on_date carries a date".into()); } }
            "after_days" => {
                match self.first_payment.days { Some(d) if (1..=366).contains(&d) => {}, _ => return Err("first_payment after_days: 1–366 days".into()) }
                if self.first_payment.date.is_some() { return Err("first_payment after_days carries no date".into()); }
                if !matches!(self.free_days_need.as_deref(), Some("signup_code") | Some("first_payment") | Some("none")) { return Err("free_days_need: signup_code, first_payment or none".into()); }
            }
            _ => return Err("first_payment.rule: on_agree, on_date or after_days".into()),
        }
        if self.first_payment.rule != "after_days" && self.free_days_need.is_some() { return Err("free_days_need belongs to after_days".into()); }
        if let Some(p) = self.payments { if !(1..=1000).contains(&p) { return Err("payments: 1–1,000, or none".into()); } }
        if let (Some(k), Some(p)) = (self.price_kept_through, self.payments) { if k > p { return Err("price_kept_through is past the last payment".into()); } }
        if self.price_kept_through == Some(0) { return Err("price_kept_through starts at 1".into()); }
        if self.grace_days > 60 { return Err("grace_days: 0–60".into()); }
        if !matches!(self.ending.refund.as_str(), "none" | "unused_time") { return Err("ending.refund: none or unused_time".into()); }
        if !(7..=365).contains(&self.change_notice_days) { return Err("change_notice_days: 7–365".into()); }
        if self.pay_by.is_empty() || self.pay_by.len() > 2 || self.pay_by.iter().any(|w| w != "lightning" && w != "onchain")
            || (self.pay_by.len() == 2 && self.pay_by[0] == self.pay_by[1]) { return Err("pay_by: lightning, onchain, or both".into()); }
        if self.pay_by.iter().any(|w| w == "lightning") {
            match &self.lightning { Some(l) if (1..=4).contains(&l.nodes.len()) && l.nodes.iter().all(|n| node_key_ok(n)) => {}, _ => return Err("lightning.nodes: 1–4 node keys".into()) }
        } else if self.lightning.is_some() { return Err("lightning terms without lightning in pay_by".into()); }
        if self.pay_by.iter().any(|w| w == "onchain") {
            match &self.onchain { Some(o) if o.sp_address.starts_with("sp1") && o.sp_address.len() <= 200 && o.sp_address.bytes().all(|b| b.is_ascii_alphanumeric()) => {}, _ => return Err("onchain.sp_address: a silent-payment address".into()) }
        } else if self.onchain.is_some() { return Err("onchain terms without onchain in pay_by".into()); }
        Ok(())
    }

    /// THE TERMS STRING — what `terms_sig` and `terms_digest` cover. Sixteen `key=value` lines in this order, joined by
    /// `\n`, with no line after the last. A list is joined by `,`; a term that is absent is written `key=`.
    /// Round 4: a plan that carries a description has a SEVENTEENTH line, `plan_description=<text>`. A plan without one
    /// has the sixteen lines and nothing more, so every plan signed before round 4 keeps its signature.
    pub fn terms_string(&self) -> String {
        let opt_u = |v: Option<u32>| v.map(|n| n.to_string()).unwrap_or_default();
        let first = match self.first_payment.rule.as_str() {
            "on_date" => format!("on_date:{}", self.first_payment.date.unwrap_or(0)),
            "after_days" => format!("after_days:{}", self.first_payment.days.unwrap_or(0)),
            r => r.to_string(),
        };
        let mut lines = vec![
            format!("terms_version={}", self.terms_version),
            format!("merchant_name={}", self.merchant_name),
            format!("plan_name={}", self.plan_name),
            format!("price.unit={}", self.price.unit),
            format!("price.by_payment={}", self.price.by_payment.iter().map(|s| format!("{}:{}", s.from, s.amount)).collect::<Vec<_>>().join(",")),
            format!("every={}:{}", self.every.unit, self.every.count),
            format!("first_payment={first}"),
            format!("payments={}", opt_u(self.payments)),
            format!("price_kept_through={}", opt_u(self.price_kept_through)),
            format!("grace_days={}", self.grace_days),
            format!("ending.refund={}", self.ending.refund),
            format!("change_notice_days={}", self.change_notice_days),
            format!("pay_by={}", self.pay_by.join(",")),
            format!("lightning.nodes={}", self.lightning.as_ref().map(|l| l.nodes.join(",")).unwrap_or_default()),
            format!("onchain.sp_address={}", self.onchain.as_ref().map(|o| o.sp_address.clone()).unwrap_or_default()),
            format!("free_days_need={}", self.free_days_need.clone().unwrap_or_default()),
        ];
        if let Some(d) = &self.plan_description { lines.push(format!("plan_description={d}")); }
        lines.join("\n")
    }

    /// TH("LIJOX-Subs/terms", terms string) — the plan key signs these 32 bytes; their hex is `terms_digest`.
    pub fn digest(&self) -> [u8; 32] { tagged_hash(TAG_TERMS, self.terms_string().as_bytes()) }
    pub fn digest_hex(&self) -> String { hex::encode(self.digest()) }

    /// The price of payment n: the last entry whose `from` is at or below n.
    pub fn price_for(&self, n: u32) -> Option<&str> {
        if n == 0 { return None; }
        if let Some(p) = self.payments { if n > p { return None; } }
        self.price.by_payment.iter().rev().find(|s| s.from <= n).map(|s| s.amount.as_str())
    }

    fn price_at(&self, n: u32) -> Option<&str> { self.price.by_payment.iter().rev().find(|s| s.from <= n).map(|s| s.amount.as_str()) }

    /// The seller's side: the plan key's signature over the terms.
    pub fn sign(&self, plan_sk: &[u8; 32]) -> LijResult<String> {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &secret_key(plan_sk)?);
        Ok(hex::encode(secp.sign_schnorr_no_aux_rand(&Message::from_digest(self.digest()), &kp).serialize()))
    }
}

/// Terms as they arrive: a term this wallet does not know is passed over unless it says `"required": true`.
pub fn parse_terms(v: &serde_json::Value) -> Result<Terms, String> {
    let obj = v.as_object().ok_or("the terms are not an object")?;
    for (k, val) in obj {
        if !KNOWN_TERMS.contains(&k.as_str()) && val.get("required").and_then(|r| r.as_bool()) == Some(true) {
            return Err(format!("the plan asks for a term this wallet does not know: {k}"));
        }
    }
    let t: Terms = serde_json::from_value(v.clone()).map_err(|e| format!("the terms do not read: {e}"))?;
    t.validate()?;
    Ok(t)
}

// ─────────────────────────────────────────────────────────────────────────────
// The plan code and the plan (format §3.1, §3.2)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanCode {
    /// the address the plan is fetched from (https)
    pub url: String,
    /// the merchant's host — shown to the wallet user at Review
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub signup: Option<String>,
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('@') || host.len() > 253 { return None; }
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':') { return None; }
    Some(host.to_ascii_lowercase())
}

/// `lijoxsubs://<merchant-host>/<path>[?signup=<code>]` → the https address to fetch, the host, the signup code.
pub fn parse_plan_code(code: &str) -> Result<PlanCode, String> {
    let t = code.trim();
    if t.len() > 512 { return Err("a plan code this long is not one".into()); }
    let rest = if t.len() >= 12 && t[..12].eq_ignore_ascii_case("lijoxsubs://") { &t[12..] } else { return Err("not a plan code".into()) };
    if rest.chars().any(|c| c.is_control() || c.is_whitespace()) { return Err("a plan code holds no spaces".into()); }
    let url = format!("https://{rest}");
    let host = host_of(&url).ok_or("the plan code names no host")?;
    let signup = rest.split_once('?').map(|(_, q)| q).and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("signup="))).map(|s| s.to_string());
    if let Some(s) = &signup { if !name_ok(s, 32) { return Err("the signup code: letters, digits, - _ . only, at most 32".into()); } }
    Ok(PlanCode { url, host, signup })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub plan_id: String,
    pub plan_key: String,
    pub server: String,
    pub terms: Terms,
    pub terms_sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub line: Option<String>,
}

/// One short line from the merchant (a status line, a reason): text only, at most 140 characters, and anything that
/// looks like a web address is taken out before it is shown (format §1).
pub fn clean_line(s: &str) -> String {
    let kept: Vec<&str> = s.split_whitespace().filter(|w| {
        let l = w.to_ascii_lowercase();
        !(l.contains("://") || l.starts_with("www.") || l.contains(".com") || l.contains(".net") || l.contains(".org") || l.contains(".io") || l.contains(".xyz"))
    }).collect();
    kept.join(" ").chars().filter(|c| !c.is_control()).take(140).collect()
}

/// A fetched plan, checked (format §3.2): the server is on the plan code's own host; the terms are inside the limits
/// and signed by the plan key; nothing required is unknown.
pub fn check_plan(plan_json: &str, code_host: &str) -> Result<Plan, String> {
    let v: serde_json::Value = serde_json::from_str(plan_json).map_err(|e| format!("the plan does not read: {e}"))?;
    if v.get("v").and_then(|x| x.as_u64()) != Some(V as u64) { return Err("this plan is of another version of the format".into()); }
    if v.get("tag").and_then(|x| x.as_str()) != Some("lijoxSubsPlan") { return Err("this is not a plan".into()); }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string()).ok_or(format!("the plan has no {k}"));
    let plan_id = s("plan_id")?;
    if !name_ok(&plan_id, 40) { return Err("the plan id: letters, digits, - _ . only, at most 40".into()); }
    let plan_key = s("plan_key")?;
    xonly_from_hex(&plan_key)?;
    let server = s("server")?;
    if host_of(&server).as_deref() != Some(code_host.to_ascii_lowercase().as_str()) { return Err("the plan's server is not on the host the plan code named".into()); }
    let terms = parse_terms(v.get("terms").ok_or("the plan has no terms")?)?;
    let terms_sig = s("terms_sig")?;
    if !verify_digest(&plan_key, terms.digest(), &terms_sig) { return Err("the terms are not signed by the plan key".into()); }
    let line = v.get("line").and_then(|x| x.as_str()).map(clean_line).filter(|l| !l.is_empty());
    Ok(Plan { plan_id, plan_key, server: server.trim_end_matches('/').to_string(), terms, terms_sig, line })
}

// ─────────────────────────────────────────────────────────────────────────────
// Due dates (format §3.4) — calendar steps in UTC
// ─────────────────────────────────────────────────────────────────────────────

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m { 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, 4 | 6 | 9 | 11 => 30, _ => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 } }
}

/// When payment n is due: `first_due` plus (n − 1) × `every`, in calendar steps in UTC. A month step keeps the day of
/// the month of `first_due`; a day the month lacks becomes that month's last day (29 February → 28 in other years).
pub fn due(first_due: u64, every: &Every, n: u32) -> Option<u64> {
    if n == 0 { return None; }
    let k = (n as u64 - 1).checked_mul(every.count as u64)?;
    match every.unit.as_str() {
        "week" => first_due.checked_add(k.checked_mul(7 * 86_400)?),
        "month" | "year" => {
            let months = if every.unit == "year" { k.checked_mul(12)? } else { k } as i64;
            let (days, secs) = ((first_due / 86_400) as i64, first_due % 86_400);
            let (y, m, d) = civil_from_days(days);
            let total = y * 12 + (m - 1) + months;
            let (ny, nm) = (total.div_euclid(12), total.rem_euclid(12) + 1);
            let nd = d.min(days_in_month(ny, nm));
            Some(days_from_civil(ny, nm, nd) as u64 * 86_400 + secs)
        }
        _ => None,
    }
}

/// Where payment n stands at `now`: "not_yet" (more than 14 days before its due date), "payable", "overdue" (from the
/// due date), "lapsed" (after the grace days).
pub fn pay_state(now: u64, due_at: u64, grace_days: u32) -> &'static str {
    if now + PAY_EARLY_SECS < due_at { "not_yet" }
    else if now < due_at { "payable" }
    else if now <= due_at + grace_days as u64 * 86_400 { "overdue" }
    else { "lapsed" }
}

// ─────────────────────────────────────────────────────────────────────────────
// The messages (format §4–§11)
// ─────────────────────────────────────────────────────────────────────────────

/// `POST {server}/agree` — the body, signed with the subscription key.
pub fn agree_body(sub_sk: &[u8; 32], plan: &Plan, signup: Option<&str>, ts: u64) -> LijResult<serde_json::Value> {
    let sub_key = public_hex(sub_sk)?;
    let digest = plan.terms.digest_hex();
    let su = signup.unwrap_or("");
    if !su.is_empty() && !name_ok(su, 32) { return Err(err("the signup code: letters, digits, - _ . only")); }
    let c = canon("agree", &[&plan.plan_id, &plan.terms.terms_version.to_string(), &digest, &sub_key, su, &ts.to_string()]);
    let mut b = serde_json::json!({ "v": V, "plan_id": plan.plan_id, "terms_version": plan.terms.terms_version, "terms_digest": digest, "sub_key": sub_key, "ts": ts, "sig": sign_canonical(sub_sk, &c)? });
    if !su.is_empty() { b["signup"] = serde_json::Value::String(su.to_string()); }
    Ok(b)
}

/// The merchant's receipt of an agreement: the plan key over `…|agreed|plan_id|terms_digest|sub_key|first_due`.
pub fn agreed_canonical(plan_id: &str, terms_digest: &str, sub_key: &str, first_due: u64) -> String {
    canon("agreed", &[plan_id, terms_digest, sub_key, &first_due.to_string()])
}

/// How a refund is asked for (format §8, r2): a one-use Lightning address, an invoice, or an on-chain address.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RefundTo { Lnaddr(String), Pr(String), Addr(String) }

impl RefundTo {
    fn canonical(&self) -> String {
        match self { RefundTo::Lnaddr(a) => format!("lnaddr:{a}"), RefundTo::Pr(p) => format!("pr:{p}"), RefundTo::Addr(a) => format!("addr:{a}") }
    }
    fn ok(&self) -> bool {
        let s = match self { RefundTo::Lnaddr(a) => a, RefundTo::Pr(p) => p, RefundTo::Addr(a) => a };
        !s.is_empty() && s.len() <= 2048 && !s.contains('|') && !s.chars().any(|c| c.is_control() || c.is_whitespace())
            && match self { RefundTo::Lnaddr(a) => a.matches('@').count() == 1 && !a.starts_with('@') && !a.ends_with('@'), _ => true }
    }
}

/// `POST {server}/end` — `when` is "now" or "paid_period_end".
pub fn end_body(sub_sk: &[u8; 32], plan_id: &str, when: &str, refund_to: Option<&RefundTo>, ts: u64) -> LijResult<serde_json::Value> {
    if when != "now" && when != "paid_period_end" { return Err(err("end: when is now or paid_period_end")); }
    if let Some(r) = refund_to { if !r.ok() { return Err(err("end: the refund address does not read")); } }
    let sub_key = public_hex(sub_sk)?;
    let rt = refund_to.map(|r| r.canonical()).unwrap_or_default();
    let c = canon("end", &[plan_id, &sub_key, when, &rt, &ts.to_string()]);
    let mut b = serde_json::json!({ "v": V, "plan_id": plan_id, "sub_key": sub_key, "when": when, "ts": ts, "sig": sign_canonical(sub_sk, &c)? });
    if let Some(r) = refund_to { b["refund_to"] = serde_json::to_value(r).map_err(|e| err(e.to_string()))?; }
    Ok(b)
}

/// `POST {server}/accept` — a change of terms the wallet user accepted.
pub fn accept_body(sub_sk: &[u8; 32], plan_id: &str, new_terms: &Terms, ts: u64) -> LijResult<serde_json::Value> {
    let sub_key = public_hex(sub_sk)?;
    let digest = new_terms.digest_hex();
    let c = canon("accept", &[plan_id, &sub_key, &new_terms.terms_version.to_string(), &digest, &ts.to_string()]);
    Ok(serde_json::json!({ "v": V, "plan_id": plan_id, "sub_key": sub_key, "terms_version": new_terms.terms_version, "terms_digest": digest, "ts": ts, "sig": sign_canonical(sub_sk, &c)? }))
}

pub fn accepted_canonical(plan_id: &str, terms_digest: &str, sub_key: &str) -> String {
    canon("accepted", &[plan_id, terms_digest, sub_key])
}

/// `POST {server}/sync` — after any restore, and when the merchant's payment number is not the wallet's.
pub fn sync_body(sub_sk: &[u8; 32], plan_id: &str, ts: u64) -> LijResult<serde_json::Value> {
    let sub_key = public_hex(sub_sk)?;
    let c = canon("sync", &[plan_id, &sub_key, &ts.to_string()]);
    Ok(serde_json::json!({ "v": V, "plan_id": plan_id, "sub_key": sub_key, "ts": ts, "sig": sign_canonical(sub_sk, &c)? }))
}

/// Sign-in on the merchant's website: the subscription key over `…|signin|<merchant-host>|k1`.
pub fn signin(sub_sk: &[u8; 32], merchant_host: &str, k1: &str) -> LijResult<(String, String)> {
    if k1.len() != 64 || !k1.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(err("sign-in: k1 is 64 hex characters")); }
    let host = merchant_host.to_ascii_lowercase();
    if host.is_empty() || host.contains('|') { return Err(err("sign-in: no host")); }
    Ok((public_hex(sub_sk)?, sign_canonical(sub_sk, &canon("signin", &[&host, &k1.to_ascii_lowercase()]))?))
}

/// The query of a tagged request (status, invoice): the plan, the payment number and that payment's tag — never the key.
pub fn tagged_query(plan_id: &str, k: &[u8; 32], n: u32) -> String {
    format!("plan_id={plan_id}&n={n}&tag={}", payment_tag(k, n))
}

/// What an invoice of this format says in its description: `lijox-subs/1 <plan_id> #<n> <tag>`.
pub fn invoice_description(plan_id: &str, n: u32, tag: &str) -> String {
    format!("{PREFIX} {plan_id} #{n} {tag}")
}

/// The canonical string the plan key signs for a payment hash (`hash_sig`, format §6, r2).
pub fn hash_canonical(payment_hash_hex: &str) -> String {
    canon("hash", &[&payment_hash_hex.to_ascii_lowercase()])
}

// ─────────────────────────────────────────────────────────────────────────────
// An invoice, checked before Send is offered (format §6)
// ─────────────────────────────────────────────────────────────────────────────

/// round(price × sat_per_unit × 1000), halves up — a currency plan's amount in millisats.
pub fn msat_for(price: &str, sat_per_unit: &str) -> Result<u64, String> {
    let (p, ps) = parse_decimal(price)?;
    let (r, rs) = parse_decimal(sat_per_unit)?;
    let num = p.checked_mul(r).and_then(|x| x.checked_mul(1000)).ok_or("an amount out of range")?;
    let den = 10u128.pow(ps + rs);
    u64::try_from((num + den / 2) / den).map_err(|_| "an amount out of range".to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckedInvoice {
    pub pr: String,
    pub n: u32,
    pub payment_hash: String,
    pub payee: String,
    pub amount_msat: u64,
    pub price_unit: String,
    pub price_amount: String,
    /// None for a plan priced in sats
    pub sat_per_unit: Option<String>,
    pub period_from: u64,
    pub period_to: u64,
    /// only for a LiJ seller: how long the payment waits for the seller's phone
    pub hold_s: Option<u64>,
    pub expires_at: u64,
}

/// THE SIX CHECKS (format §6). `terms` are the terms the wallet user ACCEPTED, `due_at` is payment n's due date. Any
/// failure is the card's "the invoice does not match", and Send is not offered. There is no check of the merchant's
/// rate against the wallet's own: Review shows both (the Register rule). Whether n was paid already is the record's
/// rule (`Store::begin_payment`).
pub fn check_invoice(plan_id: &str, plan_key: &str, terms: &Terms, k: &[u8; 32], n: u32, due_at: u64, now: u64, answer_json: &str) -> Result<CheckedInvoice, String> {
    let v: serde_json::Value = serde_json::from_str(answer_json).map_err(|e| format!("the answer does not read: {e}"))?;
    let pr = v.get("pr").and_then(|x| x.as_str()).ok_or("the answer has no invoice")?.to_string();
    if v.get("n").and_then(|x| x.as_u64()) != Some(n as u64) { return Err("the invoice is for another payment number".into()); }
    let inv = lightning_invoice::Bolt11Invoice::from_str(pr.trim()).map_err(|e| format!("the invoice does not decode: {e}"))?;
    // 1 — signed by a node the signed terms name
    let payee = hex::encode(inv.payee_pub_key().copied().unwrap_or_else(|| inv.recover_payee_pub_key()).serialize());
    let nodes = terms.lightning.as_ref().map(|l| l.nodes.as_slice()).unwrap_or(&[]);
    if !nodes.iter().any(|x| *x == payee) { return Err("the invoice is not from a node the plan names".into()); }
    // 2 — payable now
    match pay_state(now, due_at, terms.grace_days) {
        "not_yet" => return Err("this payment cannot be paid yet".into()),
        "lapsed" => return Err("this payment's grace days are over".into()),
        _ => {}
    }
    // 3 — the price is the accepted terms' price for n
    let want = terms.price_for(n).ok_or("the plan has no payment of this number")?;
    let price = v.get("price").ok_or("the answer has no price")?;
    let (unit, amount) = (price.get("unit").and_then(|x| x.as_str()).unwrap_or(""), price.get("amount").and_then(|x| x.as_str()).unwrap_or(""));
    if unit != terms.price.unit || parse_decimal(amount).ok().map(norm) != parse_decimal(want).ok().map(norm) { return Err("the price is not the price that was agreed".into()); }
    // 4 — the millisats follow from the price
    let amount_msat = v.get("amount_msat").and_then(|x| x.as_u64()).ok_or("the answer has no amount")?;
    let sat_per_unit = if terms.price.unit == "sat" {
        if msat_for(want, "1")? != amount_msat { return Err("the amount is not the price".into()); }
        None
    } else {
        let rate = v.get("rate").ok_or("a currency plan's answer carries its rate")?;
        let spu = rate.get("sat_per_unit").and_then(|x| x.as_str()).ok_or("the rate does not read")?;
        if rate.get("expires").and_then(|x| x.as_u64()).map(|e| e < now) != Some(false) { return Err("the merchant's rate has run out".into()); }
        if msat_for(want, spu)? != amount_msat { return Err("the amount is not the price at the merchant's rate".into()); }
        Some(spu.to_string())
    };
    // 5 — the invoice's own amount and description
    if inv.amount_milli_satoshis() != Some(amount_msat) { return Err("the invoice's amount is not the amount stated".into()); }
    let tag = payment_tag(k, n);
    let desc = match inv.description() { lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => d.as_inner().0.clone(), _ => String::new() };
    if desc != invoice_description(plan_id, n, &tag) { return Err("the invoice does not carry this payment's tag".into()); }
    let made = inv.duration_since_epoch().as_secs();
    let expires_at = made.saturating_add(inv.expiry_time().as_secs());
    if inv.expiry_time().as_secs() > INVOICE_LIFE_MAX_SECS { return Err("the invoice lives longer than the format allows".into()); }
    if expires_at <= now { return Err("the invoice has run out".into()); }
    // 6 — the payment hash is signed by the plan key
    let payment_hash = hex::encode(inv.payment_hash().as_ref() as &[u8]);
    let hash_sig = v.get("hash_sig").and_then(|x| x.as_str()).unwrap_or("");
    if !verify_canonical(plan_key, &hash_canonical(&payment_hash), hash_sig) { return Err("the invoice's payment hash is not signed by the plan key".into()); }
    let period = v.get("period");
    let pf = |k: &str| period.and_then(|p| p.get(k)).and_then(|x| x.as_u64()).unwrap_or(0);
    Ok(CheckedInvoice { pr, n, payment_hash, payee, amount_msat, price_unit: unit.to_string(), price_amount: want.to_string(), sat_per_unit,
        period_from: pf("from"), period_to: pf("to"), hold_s: v.get("hold_s").and_then(|x| x.as_u64()), expires_at })
}

/// "8000" and "8000.00" are one price.
fn norm((m, s): (u128, u32)) -> (u128, u32) {
    let (mut m, mut s) = (m, s);
    while s > 0 && m % 10 == 0 { m /= 10; s -= 1; }
    (m, s)
}

// ─────────────────────────────────────────────────────────────────────────────
// What the merchant answers (format §4, §5, §8–§10, §15)
// ─────────────────────────────────────────────────────────────────────────────

/// An error answer: its code (format §15) and the merchant's reason, cleaned.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ServerError { pub code: String, pub reason: String }

/// An answer from a plan server: its JSON when `status` is OK; the error's code and reason otherwise. An answer that
/// is not in the format is the code `BAD_ANSWER`.
pub fn read_answer(json: &str) -> Result<serde_json::Value, ServerError> {
    let bad = || ServerError { code: "BAD_ANSWER".into(), reason: "the merchant's server did not answer in the format".into() };
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| bad())?;
    match v.get("status").and_then(|x| x.as_str()) {
        Some("OK") => Ok(v),
        Some("ERROR") => {
            let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("ERROR");
            let code = if name_ok(code, 40) { code.to_ascii_uppercase() } else { "ERROR".to_string() };
            Err(ServerError { code, reason: clean_line(v.get("reason").and_then(|x| x.as_str()).unwrap_or("")) })
        }
        _ => Err(bad()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreed { pub first_due: u64, pub receipt: Option<String> }

/// Does `first_due` follow the terms' own rule for an agreement made at `agreed_at`? A day's leeway for `on_agree` and
/// `after_days`; exactly the date for `on_date`.
pub fn first_due_follows(terms: &Terms, first_due: u64, agreed_at: u64) -> bool {
    let fp = &terms.first_payment;
    let near = |want: u64| first_due + 86_400 >= want && first_due <= want + 86_400;
    match fp.rule.as_str() {
        "on_agree" => near(agreed_at),
        "on_date" => fp.date == Some(first_due),
        "after_days" => near(agreed_at + fp.days.unwrap_or(0) as u64 * 86_400),
        _ => false,
    }
}

/// The answer to an agreement. `first_due` must follow the terms' own rule (a day's leeway for `on_agree` and
/// `after_days`; exactly the date for `on_date`), and the receipt must be the plan key's — or absent with
/// `receipt_pending` (a LiJ seller whose phone has not opened yet).
pub fn check_agreed(plan: &Plan, sub_key: &str, v: &serde_json::Value, now: u64) -> Result<Agreed, String> {
    let first_due = v.get("first_due").and_then(|x| x.as_u64()).ok_or("the answer has no first due date")?;
    if !first_due_follows(&plan.terms, first_due, now) { return Err("the first due date the merchant answered does not follow the plan's terms".into()); }
    let receipt = read_receipt(v, &plan.plan_key, &agreed_canonical(&plan.plan_id, &plan.terms.digest_hex(), sub_key, first_due))?;
    Ok(Agreed { first_due, receipt })
}

/// A receipt in an answer: verified against the plan key, or None when it is absent (a LiJ seller's `receipt_pending`).
fn read_receipt(v: &serde_json::Value, plan_key: &str, canonical: &str) -> Result<Option<String>, String> {
    match v.get("receipt").and_then(|x| x.as_str()) {
        Some(r) if verify_canonical(plan_key, canonical, r) => Ok(Some(r.to_string())),
        Some(_) => Err("the merchant's receipt is not signed by the plan key".into()),
        None if v.get("receipt_pending").and_then(|x| x.as_bool()) == Some(true) => Ok(None),
        None => Err("the merchant's answer carries no receipt".into()),
    }
}

/// The answer to an accepted change: the plan key's receipt over the new terms (or pending, as above).
pub fn check_accepted(plan_id: &str, plan_key: &str, new_terms: &Terms, sub_key: &str, v: &serde_json::Value) -> Result<Option<String>, String> {
    read_receipt(v, plan_key, &accepted_canonical(plan_id, &new_terms.digest_hex(), sub_key))
}

fn same_price(a: Option<&str>, b: Option<&str>) -> bool {
    match (a.and_then(|x| parse_decimal(x).ok()), b.and_then(|x| parse_decimal(x).ok())) { (Some(x), Some(y)) => norm(x) == norm(y), _ => false }
}

/// May the merchant offer this change under the terms that were agreed? (format §5; round 3 adds the first rule.)
/// - the rhythm stays: `every` and `first_payment` are what the due dates are counted from — a new rhythm is a new plan;
/// - `starts` is at least `change_notice_days` after `notice_given`;
/// - no payment number through `price_kept_through` gets another price (or another unit).
pub fn change_allowed(old: &Terms, new: &Terms, starts: u64, notice_given: u64) -> Result<(), String> {
    if new.terms_version <= old.terms_version { return Err("the change does not carry a higher terms version".into()); }
    if new.every != old.every || new.first_payment != old.first_payment { return Err("the change alters when payments are due; that is another plan".into()); }
    if starts < notice_given.saturating_add(old.change_notice_days as u64 * 86_400) { return Err(format!("the change starts less than {} days after its notice", old.change_notice_days)); }
    if let Some(kept) = old.price_kept_through {
        if new.price.unit != old.price.unit { return Err("the change alters the price's unit while a price was kept".into()); }
        let mut at: Vec<u32> = old.price.by_payment.iter().chain(new.price.by_payment.iter()).map(|p| p.from).filter(|f| *f <= kept).collect();
        at.push(1);
        if !at.iter().all(|n| same_price(old.price_at(*n), new.price_at(*n))) { return Err(format!("the change alters a price that was kept through payment {kept}")); }
    }
    Ok(())
}

/// A status answer, read (format §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusView {
    pub state: String,
    pub paid_through: Option<u64>,
    pub next_n: Option<u32>,
    pub line: Option<String>,
    pub ended: Option<Ended>,
    pub change: Option<ChangeOffer>,
    pub change_refused: Option<String>,
    pub receipt: Option<String>,
    pub refund: Option<Refund>,
}

fn read_refund(v: &serde_json::Value) -> Option<Refund> {
    let r = v.get("refund")?;
    let state = r.get("state").and_then(|x| x.as_str())?;
    // "expired" (round 3): the refund could not be delivered in 30 days — the wallet sends a new address
    if !matches!(state, "owed" | "approved" | "paid" | "none" | "expired") { return None; }
    Some(Refund { amount_msat: r.get("amount_msat").and_then(|x| x.as_u64()).unwrap_or(0), state: state.to_string() })
}

pub fn read_status(plan: &Plan, sub_key: &str, first_due: u64, v: &serde_json::Value) -> Result<StatusView, String> {
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("");
    if !matches!(state, "active" | "due" | "overdue" | "lapsed" | "ended") { return Err("the merchant's answer names no state of the format".into()); }
    let ended = v.get("ended").filter(|e| e.is_object()).map(|e| Ended {
        at: e.get("at").and_then(|x| x.as_u64()).unwrap_or(0),
        by: match e.get("by").and_then(|x| x.as_str()) { Some("merchant") => "merchant", Some("subscriber") => "subscriber", _ => "plan" }.to_string(),
        reason: clean_line(e.get("reason").and_then(|x| x.as_str()).unwrap_or("")),
    });
    let (mut change, mut change_refused) = (None, None);
    if let Some(c) = v.get("change").filter(|c| c.is_object()) {
        let read = || -> Result<ChangeOffer, String> {
            let terms = parse_terms(c.get("terms").ok_or("the change carries no terms")?)?;
            let terms_sig = c.get("terms_sig").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if !verify_digest(&plan.plan_key, terms.digest(), &terms_sig) { return Err("the changed terms are not signed by the plan key".into()); }
            if c.get("terms_version").and_then(|x| x.as_u64()) != Some(terms.terms_version as u64) { return Err("the change's version is not its terms' version".into()); }
            let (starts, notice_given) = (c.get("starts").and_then(|x| x.as_u64()).ok_or("the change names no start")?, c.get("notice_given").and_then(|x| x.as_u64()).ok_or("the change names no notice date")?);
            change_allowed(&plan.terms, &terms, starts, notice_given)?;
            Ok(ChangeOffer { terms, terms_sig, starts, notice_given, seen_at: 0 })
        };
        match read() { Ok(o) => change = Some(o), Err(e) => change_refused = Some(e) }
    }
    let receipt = v.get("receipt").and_then(|x| x.as_str())
        .filter(|r| verify_canonical(&plan.plan_key, &agreed_canonical(&plan.plan_id, &plan.terms.digest_hex(), sub_key, first_due), r)).map(|r| r.to_string());
    Ok(StatusView { state: state.to_string(), paid_through: v.get("paid_through").and_then(|x| x.as_u64()),
        next_n: v.get("next").and_then(|n| n.get("n")).and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
        line: v.get("line").and_then(|x| x.as_str()).map(clean_line).filter(|l| !l.is_empty()), ended, change, change_refused, receipt, refund: read_refund(v) })
}

/// A sync answer, read (format §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncView {
    pub state: String,
    pub terms_version: u32,
    pub terms_digest: String,
    pub first_due: u64,
    /// (n, at, payment hash)
    pub paid: Vec<(u32, u64, String)>,
    pub receipt: Option<String>,
    /// the terms the merchant holds this subscription under, with the plan key's signature (round 3: a sync answer
    /// carries them, so a wallet whose copy is older — or lost — has them without asking for the plan again)
    pub terms: Option<(Terms, String)>,
}

pub fn read_sync(plan_key: &str, v: &serde_json::Value) -> Result<SyncView, String> {
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("");
    if !matches!(state, "active" | "due" | "overdue" | "lapsed" | "ended") { return Err("the merchant's answer names no state of the format".into()); }
    let terms_digest = v.get("terms_digest").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if terms_digest.len() != 64 || !terms_digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("the sync answer carries no terms digest".into()); }
    let mut paid = Vec::new();
    for p in v.get("paid").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
        let n = p.get("n").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()).filter(|n| (1..=1000).contains(n)).ok_or("the sync answer lists a payment without its number")?;
        let hash = p.get("payment_hash").and_then(|x| x.as_str()).or_else(|| p.get("txid").and_then(|x| x.as_str())).unwrap_or("");
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("the sync answer lists a payment without its hash".into()); }
        paid.push((n, p.get("at").and_then(|x| x.as_u64()).unwrap_or(0), hash.to_ascii_lowercase()));
    }
    if paid.len() > 1000 { return Err("the sync answer lists more payments than a plan can have".into()); }
    let terms = match v.get("terms").filter(|t| t.is_object()) {
        Some(t) => {
            let terms = parse_terms(t)?;
            let sig = v.get("terms_sig").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if terms.digest_hex() != terms_digest || !verify_digest(plan_key, terms.digest(), &sig) { return Err("the terms in the sync answer are not the terms it names, signed by the plan key".into()); }
            Some((terms, sig))
        }
        None => None,
    };
    Ok(SyncView { state: state.to_string(), terms_version: v.get("terms_version").and_then(|x| x.as_u64()).unwrap_or(0) as u32, terms_digest,
        first_due: v.get("first_due").and_then(|x| x.as_u64()).ok_or("the sync answer carries no first due date")?, paid,
        receipt: v.get("receipt").and_then(|x| x.as_str()).map(|r| r.to_string()), terms })
}

/// The answer to an end (format §8): when it ends, and the refund's state.
pub fn read_end(v: &serde_json::Value) -> Result<(u64, Option<Refund>), String> {
    Ok((v.get("ends").and_then(|x| x.as_u64()).ok_or("the merchant's answer does not say when the subscription ends")?, read_refund(v)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Reminder times (format §12)
// ─────────────────────────────────────────────────────────────────────────────

/// At most this many times are handed to the provider, none further ahead than `REMINDER_AHEAD_SECS`.
pub const REMINDER_MAX: usize = 64;
pub const REMINDER_AHEAD_SECS: u64 = 400 * 86_400;

/// 09:00 on the phone's clock on the day of `t`, as UTC. `utc_offset_secs` is the phone's offset east of UTC.
fn nine_local(t: u64, utc_offset_secs: i64) -> u64 {
    let local = t as i64 + utc_offset_secs;
    (local.div_euclid(86_400) * 86_400 + 9 * 3_600 - utc_offset_secs).max(0) as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// The wallet's records — and the rule that one payment number is sent once
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRec {
    pub n: u32,
    pub payment_hash: String,
    /// "sending" | "paid" | "failed"
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub preimage: Option<String>,
    pub amount_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub fee_msat: Option<u64>,
    pub price_unit: String,
    pub price_amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub sat_per_unit: Option<String>,
    pub at: u64,
    pub period_from: u64,
    pub period_to: u64,
    /// when the invoice runs out — a send that never started cannot start after it
    #[serde(default)] pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubRecord {
    /// the subscription key (public, hex) — this record's name
    pub sub_key: String,
    /// c of key.rs `subs_key`: 0 for the first subscription to this plan
    pub c: u32,
    /// the plan as agreed: its terms and the plan key's signature are the wallet user's record of the agreement
    pub plan: Plan,
    /// the merchant's host, as the plan code named it
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub signup: Option<String>,
    /// the plan key's receipt of the agreement (None while a LiJ seller's phone has not signed it yet)
    #[serde(default, skip_serializing_if = "Option::is_none")] pub receipt: Option<String>,
    pub first_due: u64,
    pub agreed_at: u64,
    /// "active" | "ending" | "ended"
    pub state: String,
    #[serde(default)] pub payments: Vec<PaymentRec>,
    /// after any restore: the merchant is asked (sync) before Pay is offered again
    #[serde(default)] pub needs_sync: bool,
    /// the address the plan was fetched from (the plan code with https) — to fetch the plan again
    #[serde(default)] pub plan_url: String,
    /// what the merchant last said (a status answer), and when
    #[serde(default, skip_serializing_if = "Option::is_none")] pub last: Option<LastStatus>,
    /// a change of terms the merchant offers; it is NEVER applied without Accept
    #[serde(default, skip_serializing_if = "Option::is_none")] pub change: Option<ChangeOffer>,
    /// a change the wallet user ACCEPTED, until it starts: payments due before `starts` are still under `plan.terms`
    #[serde(default, skip_serializing_if = "Option::is_none")] pub accepted: Option<AcceptedChange>,
    /// the merchant holds this subscription under terms this wallet has no copy of (a restore from an older copy, or
    /// lost records): Pay waits until the wallet has those terms (`adopt_terms`)
    #[serde(default, skip_serializing_if = "Option::is_none")] pub terms_behind: Option<String>,
    /// the end the wallet user asked for; repeated at each open until the merchant answers OK
    #[serde(default, skip_serializing_if = "Option::is_none")] pub end: Option<EndState>,
    /// terms that were replaced by an accepted change, with their signatures — the wallet user's record
    #[serde(default, skip_serializing_if = "Vec::is_empty")] pub past_terms: Vec<PastTerms>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastStatus {
    pub state: String,
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub paid_through: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub ended: Option<Ended>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub refund: Option<Refund>,
    /// a change the merchant offered that breaks the agreed terms (too little notice, or a price that was kept)
    #[serde(default, skip_serializing_if = "Option::is_none")] pub change_refused: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ended { pub at: u64, pub by: String, pub reason: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Refund { pub amount_msat: u64, pub state: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeOffer { pub terms: Terms, pub terms_sig: String, pub starts: u64, pub notice_given: u64, #[serde(default)] pub seen_at: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedChange { pub terms: Terms, pub terms_sig: String, pub starts: u64, #[serde(default, skip_serializing_if = "Option::is_none")] pub receipt: Option<String>, pub accepted_at: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndState {
    /// "now" | "paid_period_end"
    pub when: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub refund_to: Option<RefundTo>,
    pub asked_at: u64,
    /// the merchant answered OK
    #[serde(default)] pub acked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub ends: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub refund: Option<Refund>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PastTerms { pub terms: Terms, pub terms_sig: String, #[serde(default, skip_serializing_if = "Option::is_none")] pub receipt: Option<String>, pub until: u64 }

impl SubRecord {
    /// The next payment number that is neither paid nor on its way.
    pub fn next_n(&self) -> u32 {
        let mut n = 1;
        while self.payments.iter().any(|p| p.n == n && (p.state == "paid" || p.state == "sending")) { n += 1; }
        n
    }

    /// The first payment number that is not paid (one on its way is still unpaid) — the number the merchant calls next.
    pub fn first_unpaid(&self) -> u32 {
        let mut n = 1;
        while self.payments.iter().any(|p| p.n == n && p.state == "paid") { n += 1; }
        n
    }

    pub fn sending(&self, n: u32) -> bool { self.payments.iter().any(|p| p.n == n && p.state == "sending") }

    /// When payment n is due. The rhythm never changes with a change of terms (`change_allowed`).
    pub fn due(&self, n: u32) -> Option<u64> { due(self.first_due, &self.plan.terms.every, n) }

    /// The terms payment n is paid under: an accepted change's, from the payment due at or after its start.
    pub fn terms_at(&self, n: u32) -> &Terms {
        match (&self.accepted, self.due(n)) { (Some(a), Some(d)) if d >= a.starts => &a.terms, _ => &self.plan.terms }
    }

    /// Every payment of a plan with a fixed number of payments is paid.
    pub fn all_paid(&self) -> bool { self.terms_at(self.first_unpaid()).payments.map(|p| self.first_unpaid() > p).unwrap_or(false) }

    /// Housekeeping at each read: an accepted change whose start has been reached by the next unpaid payment becomes
    /// the plan's terms (the old ones are kept in `past_terms`); an end that has come is the end; a plan of fixed
    /// length whose last paid period is over has ended.
    pub fn tidy(&mut self, now: u64) -> bool {
        let mut changed = false;
        if let (Some(a), Some(d)) = (self.accepted.clone(), self.due(self.first_unpaid())) {
            if d >= a.starts {
                let old = std::mem::replace(&mut self.plan.terms, a.terms);
                let old_sig = std::mem::replace(&mut self.plan.terms_sig, a.terms_sig);
                self.past_terms.push(PastTerms { terms: old, terms_sig: old_sig, receipt: self.receipt.take(), until: a.starts });
                self.receipt = a.receipt;
                self.accepted = None;
                changed = true;
            }
        }
        if self.state != "ended" {
            if let Some(e) = &self.end { if e.acked && e.ends.map(|t| t <= now).unwrap_or(false) { self.state = "ended".into(); changed = true; } }
        }
        if self.state != "ended" {
            if let Some(p) = self.plan.terms.payments {
                if self.first_unpaid() > p && self.due(p + 1).map(|t| t <= now).unwrap_or(false) { self.state = "ended".into(); changed = true; }
            }
        }
        changed
    }

    /// Is payment n due at or after the start of a change that is offered and not accepted?
    pub fn change_applies(&self, n: u32) -> bool {
        match (&self.change, self.due(n)) { (Some(c), Some(d)) => d >= c.starts, _ => false }
    }

    /// Why Pay is not offered now, or None when it is.
    pub fn why_not_pay(&self, now: u64) -> Option<&'static str> {
        if self.state == "ended" { return Some("ended"); }
        if self.needs_sync { return Some("sync_needed"); }
        if self.terms_behind.is_some() { return Some("terms_behind"); }
        if self.end.is_some() { return Some("ending"); }
        if self.all_paid() { return Some("all_paid"); }
        let n = self.first_unpaid();
        if self.sending(n) { return Some("sending"); }
        match self.due(n).map(|d| pay_state(now, d, self.terms_at(n).grace_days)) {
            // Round 4 §2: a change that is offered and not accepted applies to every payment due at or after its
            // start. The wallet pays none of those under the old terms: the wallet user accepts, or the subscription
            // ends with its paid period.
            Some("payable") | Some("overdue") if self.change_applies(n) => Some("change_pending"),
            Some("payable") | Some("overdue") => None,
            Some("not_yet") => Some("not_yet"),
            Some("lapsed") => Some("lapsed"),
            _ => Some("no_due_date"),
        }
    }

    /// The card: everything the page shows for one subscription. Keys and signatures are public halves and records;
    /// no secret is in it.
    pub fn card(&self, now: u64) -> serde_json::Value {
        let n = self.first_unpaid();
        let all_paid = self.all_paid();
        let next = if self.state == "ended" || all_paid { serde_json::Value::Null } else {
            let t = self.terms_at(n);
            let d = self.due(n);
            serde_json::json!({ "n": n, "due": d, "price": { "unit": t.price.unit, "amount": t.price_for(n) },
                "pay_state": d.map(|d| pay_state(now, d, t.grace_days)), "sending": self.sending(n), "grace_days": t.grace_days })
        };
        let paid: Vec<&PaymentRec> = self.payments.iter().filter(|p| p.state == "paid").collect();
        let last_paid_n = paid.iter().map(|p| p.n).max().unwrap_or(0);
        serde_json::json!({
            "sub_key": self.sub_key, "c": self.c, "plan_id": self.plan.plan_id, "plan_key": self.plan.plan_key, "host": self.host, "server": self.plan.server,
            "plan_url": self.plan_url, "merchant_name": self.plan.terms.merchant_name, "plan_name": self.plan.terms.plan_name, "line": self.last.as_ref().and_then(|l| l.line.clone()).or(self.plan.line.clone()),
            "state": self.state, "needs_sync": self.needs_sync, "terms_behind": self.terms_behind.is_some(),
            "terms": self.plan.terms, "terms_digest": self.plan.terms.digest_hex(), "terms_sig": self.plan.terms_sig, "receipt": self.receipt,
            "first_due": self.first_due, "agreed_at": self.agreed_at, "signup": self.signup,
            "next": next, "all_paid": all_paid, "paid_count": paid.len(),
            "paid_through": if last_paid_n > 0 { self.due(last_paid_n + 1) } else { None },
            "payments": self.payments, "last": self.last, "change": self.change, "accepted": self.accepted, "end": self.end,
            "past_terms": self.past_terms.len(), "why_not_pay": self.why_not_pay(now),
        })
    }

    /// This subscription's reminder times from `now` on: each coming payment's due − 14 days, due − 7 days and the due
    /// day, at 09:00 on the phone's clock. Up to three payment numbers ahead.
    fn reminder_times(&self, now: u64, utc_offset_secs: i64, out: &mut Vec<u64>) {
        if self.state != "active" || self.end.is_some() || self.all_paid() { return; }
        let first = self.first_unpaid();
        for n in first..first.saturating_add(3) {
            if self.terms_at(n).payments.map(|p| n > p).unwrap_or(false) { break; }
            let Some(d) = self.due(n) else { break };
            if d > now + REMINDER_AHEAD_SECS + PAY_EARLY_SECS { break; }
            for before in [PAY_EARLY_SECS, 7 * 86_400, 0] {
                let t = nine_local(d.saturating_sub(before), utc_offset_secs);
                if t > now && t <= now + REMINDER_AHEAD_SECS { out.push(t); }
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Store {
    #[serde(default)] pub subs: Vec<SubRecord>,
}

impl Store {
    pub fn find(&self, sub_key: &str) -> Option<&SubRecord> { self.subs.iter().find(|s| s.sub_key == sub_key) }
    fn find_mut(&mut self, sub_key: &str) -> Result<&mut SubRecord, String> {
        self.subs.iter_mut().find(|s| s.sub_key == sub_key).ok_or_else(|| "no such subscription".to_string())
    }

    /// A new subscription, after the merchant's OK. One record per subscription key.
    pub fn add(&mut self, rec: SubRecord) -> Result<(), String> {
        if self.find(&rec.sub_key).is_some() { return Err("this subscription is on record already".into()); }
        self.subs.push(rec);
        Ok(())
    }

    /// ONE PAYMENT NUMBER IS SENT ONCE. Called before the send starts: refused while that number is paid or on its way
    /// (the NWC double-pay lesson of 11-13 / 11-14), while the subscription waits for its sync after a restore, and
    /// for a payment hash already on record. A number whose send FAILED may be sent again — with a new invoice, or
    /// with THE SAME ONE: a merchant's server hands the same invoice again while it lives (ten minutes), and a send
    /// that failed left nothing on that hash (the record is turned back only when LDK holds nothing on it). So the one
    /// record that does not block a hash is this subscription's own FAILED try of this same number; the new try
    /// replaces it. (Found by the page's gate, S71: for up to ten minutes after a failed send Pay answered "this
    /// invoice was used before".)
    pub fn begin_payment(&mut self, sub_key: &str, inv: &CheckedInvoice, now: u64) -> Result<(), String> {
        let blocked = self.subs.iter().any(|s| s.payments.iter().any(|p| p.payment_hash == inv.payment_hash && !(s.sub_key == sub_key && p.n == inv.n && p.state == "failed")));
        if blocked { return Err("this invoice was used before".into()); }
        let s = self.find_mut(sub_key)?;
        if s.state == "ended" { return Err("this subscription has ended".into()); }
        if s.needs_sync { return Err("this wallet was restored: the merchant is asked what was paid before Pay is offered".into()); }
        if s.terms_behind.is_some() { return Err("the merchant holds this subscription under terms this wallet has no copy of yet".into()); }
        if s.change_applies(inv.n) { return Err("change_pending".into()); }
        if s.payments.iter().any(|p| p.n == inv.n && p.state == "paid") { return Err("this payment is paid already".into()); }
        if s.payments.iter().any(|p| p.n == inv.n && p.state == "sending") { return Err("this payment is on its way".into()); }
        s.payments.retain(|p| !(p.payment_hash == inv.payment_hash && p.state == "failed"));
        s.payments.push(PaymentRec { n: inv.n, payment_hash: inv.payment_hash.clone(), state: "sending".into(), preimage: None, amount_msat: inv.amount_msat, fee_msat: None,
            price_unit: inv.price_unit.clone(), price_amount: inv.price_amount.clone(), sat_per_unit: inv.sat_per_unit.clone(), at: now, period_from: inv.period_from, period_to: inv.period_to, expires_at: inv.expires_at });
        Ok(())
    }

    /// The payment completed: the preimage is the receipt.
    pub fn settle_payment(&mut self, payment_hash: &str, preimage: &str, fee_msat: Option<u64>, now: u64) -> bool {
        for s in self.subs.iter_mut() {
            if let Some(p) = s.payments.iter_mut().find(|p| p.payment_hash == payment_hash) {
                p.state = "paid".into(); if !preimage.is_empty() { p.preimage = Some(preimage.to_string()); } p.fee_msat = fee_msat.or(p.fee_msat); p.at = now;
                return true;
            }
        }
        false
    }

    /// The payment came back: its number may be sent again. A paid payment is never turned back.
    #[cfg(test)]
    fn forget_for_test(&mut self, sub_key: &str) { self.subs.retain(|s| s.sub_key != sub_key); }

    pub fn fail_payment(&mut self, payment_hash: &str) -> bool {
        for s in self.subs.iter_mut() {
            if let Some(p) = s.payments.iter_mut().find(|p| p.payment_hash == payment_hash && p.state == "sending") {
                p.state = "failed".into();
                return true;
            }
        }
        false
    }

    /// After ANY restore (a backup file, the cloud copy, Black start): every subscription waits for its sync.
    pub fn mark_restored(&mut self) { for s in self.subs.iter_mut() { if s.state != "ended" { s.needs_sync = true; } } }

    /// The merchant's sync answer, taken in: payments the merchant holds and this record lacks are written as paid; a
    /// send this record still shows on its way stays so (its own outcome decides it). Then Pay may be offered again.
    /// Terms the merchant holds and this wallet lacks (a restore from an older copy) make Pay wait for `adopt_terms`.
    pub fn apply_sync_view(&mut self, sub_key: &str, v: &SyncView, now: u64) -> Result<(), String> {
        self.apply_sync(sub_key, &v.paid)?;
        let s = self.find_mut(sub_key)?;
        let have = s.plan.terms.digest_hex() == v.terms_digest || s.accepted.as_ref().map(|a| a.terms.digest_hex() == v.terms_digest).unwrap_or(false);
        match (&v.terms, have) {
            (_, true) => s.terms_behind = None,
            // the answer carries the terms themselves (checked against the plan key by read_sync): they are the record's
            (Some((terms, sig)), false) => {
                let old = std::mem::replace(&mut s.plan.terms, terms.clone());
                let old_sig = std::mem::replace(&mut s.plan.terms_sig, sig.clone());
                s.past_terms.push(PastTerms { terms: old, terms_sig: old_sig, receipt: s.receipt.take(), until: now });
                s.terms_behind = None; s.accepted = None; s.change = None;
            }
            (None, false) => s.terms_behind = Some(v.terms_digest.clone()),
        }
        if v.state == "ended" { s.state = "ended".into(); }
        if s.receipt.is_none() {
            if let Some(r) = &v.receipt {
                if verify_canonical(&s.plan.plan_key, &agreed_canonical(&s.plan.plan_id, &s.plan.terms.digest_hex(), &s.sub_key, s.first_due), r) { s.receipt = Some(r.clone()); }
            }
        }
        Ok(())
    }

    /// The plan fetched again holds the terms the merchant says this subscription is under: they become the record's.
    pub fn adopt_terms(&mut self, sub_key: &str, plan: &Plan, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        if plan.plan_key != s.plan.plan_key || plan.plan_id != s.plan.plan_id { return Err("that is another plan".into()); }
        if s.terms_behind.as_deref() != Some(plan.terms.digest_hex().as_str()) { return Err("the plan's terms are not the terms the merchant holds for this subscription".into()); }
        let old = std::mem::replace(&mut s.plan, plan.clone());
        s.past_terms.push(PastTerms { terms: old.terms, terms_sig: old.terms_sig, receipt: s.receipt.take(), until: now });
        s.terms_behind = None; s.accepted = None; s.change = None;
        Ok(())
    }

    /// A status answer, taken in. A change is only kept as an OFFER here.
    pub fn apply_status(&mut self, sub_key: &str, v: &StatusView, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        s.last = Some(LastStatus { state: v.state.clone(), at: now, paid_through: v.paid_through, line: v.line.clone(), ended: v.ended.clone(), refund: v.refund.clone(), change_refused: v.change_refused.clone() });
        if v.state == "ended" || v.ended.is_some() { s.state = "ended".into(); }
        // the merchant's next number is not this wallet's: ask what was paid before Pay is offered
        if let Some(n) = v.next_n { if n != s.first_unpaid() && s.state != "ended" { s.needs_sync = true; } }
        match &v.change {
            Some(offer) if s.accepted.as_ref().map(|a| a.terms.terms_version >= offer.terms.terms_version).unwrap_or(false) => {}
            Some(offer) => {
                let seen_at = s.change.as_ref().filter(|c| c.terms.terms_version == offer.terms.terms_version).map(|c| c.seen_at).unwrap_or(now);
                s.change = Some(ChangeOffer { seen_at, ..offer.clone() });
            }
            None => s.change = None,
        }
        if s.receipt.is_none() { if let Some(r) = &v.receipt { s.receipt = Some(r.clone()); } }
        if let (Some(e), Some(r)) = (s.end.as_mut(), &v.refund) { e.refund = Some(r.clone()); }
        Ok(())
    }

    /// The wallet user accepted the offered change and the merchant answered OK.
    pub fn accept_change(&mut self, sub_key: &str, receipt: Option<String>, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        let c = s.change.take().ok_or("no change is offered")?;
        s.accepted = Some(AcceptedChange { terms: c.terms, terms_sig: c.terms_sig, starts: c.starts, receipt, accepted_at: now });
        s.tidy(now);
        Ok(())
    }

    /// The wallet user asked for the end (it is repeated at each open until the merchant answers OK).
    pub fn end_asked(&mut self, sub_key: &str, when: &str, refund_to: Option<RefundTo>, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        if s.state == "ended" { return Err("this subscription has ended".into()); }
        s.end = Some(EndState { when: when.to_string(), refund_to, asked_at: now, acked: false, ends: None, refund: None });
        if s.state == "active" { s.state = "ending".into(); }
        Ok(())
    }

    /// A new address for a refund that could not be delivered (the merchant's status says `expired`): the end is asked
    /// again with it, and repeated until the merchant answers OK.
    pub fn refund_readdress(&mut self, sub_key: &str, refund_to: RefundTo, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        let e = s.end.as_mut().ok_or("no end was asked for")?;
        if e.refund.as_ref().map(|r| r.state == "paid" || r.state == "none").unwrap_or(false) { return Err("no refund is waiting".into()); }
        e.refund_to = Some(refund_to); e.asked_at = now; e.acked = false;
        Ok(())
    }

    /// The merchant answered the end.
    pub fn end_acked(&mut self, sub_key: &str, ends: u64, refund: Option<Refund>, now: u64) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        let e = s.end.as_mut().ok_or("no end was asked for")?;
        e.acked = true; e.ends = Some(ends); e.refund = refund;
        s.tidy(now);
        Ok(())
    }

    /// The wallet user took back an end the merchant has not answered yet.
    pub fn end_taken_back(&mut self, sub_key: &str) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        if s.end.as_ref().map(|e| e.acked).unwrap_or(true) { return Err("the merchant has answered the end already, or none was asked for".into()); }
        s.end = None;
        if s.state == "ending" { s.state = "active".into(); }
        Ok(())
    }

    /// An ended subscription is taken off the list (the wallet user's choice; never one that is running).
    pub fn forget(&mut self, sub_key: &str) -> Result<(), String> {
        let s = self.find(sub_key).ok_or("no such subscription")?;
        if s.state != "ended" { return Err("only an ended subscription can be taken off the list".into()); }
        if s.payments.iter().any(|p| p.state == "sending") { return Err("a payment of this subscription is still on its way".into()); }
        self.subs.retain(|x| x.sub_key != sub_key);
        Ok(())
    }

    /// Housekeeping across the list; true when anything changed (so it is saved).
    pub fn tidy(&mut self, now: u64) -> bool { self.subs.iter_mut().fold(false, |c, s| s.tidy(now) || c) }

    /// The whole list of reminder times for the wallet's provider (format §12): sorted, each once, the nearest 64.
    pub fn reminder_times(&self, now: u64, utc_offset_secs: i64) -> Vec<u64> {
        let mut out = Vec::new();
        for s in &self.subs { s.reminder_times(now, utc_offset_secs, &mut out); }
        out.sort_unstable(); out.dedup(); out.truncate(REMINDER_MAX);
        out
    }

    /// The payments this store shows on their way: (subscription key, payment hash, the invoice's expiry).
    pub fn sending(&self) -> Vec<(String, String, u64)> {
        self.subs.iter().flat_map(|s| s.payments.iter().filter(|p| p.state == "sending").map(move |p| (s.sub_key.clone(), p.payment_hash.clone(), p.expires_at))).collect()
    }

    pub fn apply_sync(&mut self, sub_key: &str, paid: &[(u32, u64, String)]) -> Result<(), String> {
        let s = self.find_mut(sub_key)?;
        for (n, at, hash) in paid {
            if s.payments.iter().any(|p| p.n == *n && p.state == "paid") { continue; }
            if let Some(p) = s.payments.iter_mut().find(|p| p.n == *n && p.payment_hash == *hash) { p.state = "paid".into(); continue; }
            let (unit, amount) = (s.plan.terms.price.unit.clone(), s.plan.terms.price_for(*n).unwrap_or("").to_string());
            s.payments.push(PaymentRec { n: *n, payment_hash: hash.clone(), state: "paid".into(), preimage: None, amount_msat: 0, fee_msat: None, price_unit: unit, price_amount: amount, sat_per_unit: None, at: *at, period_from: 0, period_to: 0, expires_at: 0 });
        }
        s.needs_sync = false;
        Ok(())
    }
}

pub fn load(storage: &dyn crate::storage::LijStorage) -> LijResult<Store> {
    match storage.get(SUBS_KEY)? {
        Some(b) => serde_json::from_slice(&b).map_err(|e| LijError::Storage(format!("subscriptions parse: {e}"))),
        None => Ok(Store::default()),
    }
}

pub fn save(storage: &dyn crate::storage::LijStorage, s: &Store) -> LijResult<()> {
    let b = serde_json::to_vec(s).map_err(|e| LijError::Storage(format!("subscriptions serialize: {e}")))?;
    storage.set(SUBS_KEY, &b)
}

// ─────────────────────────────────────────────────────────────────────────────
// The seller's half (format §13): a LiJ wallet user who sells
// ─────────────────────────────────────────────────────────────────────────────

/// The selling key's signature on a payment hash the wallet registers with its provider — the `hash_sig` a paying
/// wallet checks, so the provider can refuse or delay a payment and cannot collect it.
pub fn seller_sign_hash(seller_sk: &[u8; 32], payment_hash_hex: &str) -> LijResult<String> {
    if payment_hash_hex.len() != 64 || !payment_hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(err("a payment hash is 64 hex characters")); }
    sign_canonical(seller_sk, &hash_canonical(payment_hash_hex))
}

/// The receipt of an agreement, signed at the seller's next open (the sidecar holds no key and answered
/// `receipt_pending`). The subscriber's own signature on the agreement is checked first. The agreement's `ts` was
/// checked against the clock by the sidecar when it arrived; the phone signs later, so it is not checked again here.
pub fn seller_receipt(seller_sk: &[u8; 32], plan_id: &str, terms: &Terms, agree: &serde_json::Value, first_due: u64) -> LijResult<String> {
    let g = |k: &str| agree.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (sub_key, sig, signup) = (g("sub_key"), g("sig"), g("signup"));
    let ts = agree.get("ts").and_then(|x| x.as_u64()).unwrap_or(0);
    let digest = terms.digest_hex();
    if g("plan_id") != plan_id || g("terms_digest") != digest { return Err(err("the agreement is for other terms")); }
    let c = canon("agree", &[plan_id, &terms.terms_version.to_string(), &digest, &sub_key, &signup, &ts.to_string()]);
    if !verify_canonical(&sub_key, &c, &sig) { return Err(err("the agreement is not signed by its subscription key")); }
    if !first_due_follows(terms, first_due, ts) { return Err(err("the first due date does not follow the plan's terms")); }
    sign_canonical(seller_sk, &agreed_canonical(plan_id, &digest, &sub_key, first_due))
}

/// The tag the seller expects for a subscriber's payment n — handed to the sidecar, and checked by the phone when it
/// takes a payment (a payment whose description carries no known tag is not taken).
pub fn seller_expected_tag(seller_sk: &[u8; 32], sub_key: &str, n: u32) -> LijResult<String> {
    Ok(payment_tag(&shared_secret(seller_sk, sub_key)?, n))
}

/// A waiting payment's description, read by the seller's phone: Some((plan_id, n, tag)) when it has this format's shape.
pub fn parse_description(desc: &str) -> Option<(String, u32, String)> {
    let mut it = desc.split(' ');
    if it.next()? != PREFIX { return None; }
    let plan_id = it.next()?;
    let n = it.next()?.strip_prefix('#')?.parse::<u32>().ok()?;
    let tag = it.next()?;
    if it.next().is_some() || !name_ok(plan_id, 40) || n == 0 || tag.len() != 32 || !tag.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return None; }
    Some((plan_id.to_string(), n, tag.to_string()))
}

/// For other modules' tests: a subscription to a one-payment-a-month sats plan, agreed at `first_due`, signed by
/// `plan_sk`; the subscription key is `sub_sk`'s.
#[cfg(test)]
pub(crate) fn test_record(sub_sk: &[u8; 32], plan_sk: &[u8; 32], first_due: u64) -> SubRecord {
    let node = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c".to_string();
    let terms = Terms { terms_version: 1, merchant_name: "Kissaten Aoi".into(), plan_name: "Coffee club".into(),
        price: Price { unit: "sat".into(), by_payment: vec![PriceStep { from: 1, amount: "8000".into() }] }, every: Every { unit: "month".into(), count: 1 },
        first_payment: FirstPayment { rule: "on_agree".into(), date: None, days: None }, payments: None, price_kept_through: None, grace_days: 7,
        ending: Ending { refund: "none".into() }, change_notice_days: 30, pay_by: vec!["lightning".into()], lightning: Some(LightningTerms { nodes: vec![node] }), onchain: None, free_days_need: None, plan_description: None };
    let plan = Plan { plan_id: "coffee-club".into(), plan_key: public_hex(plan_sk).unwrap(), server: "https://aoi.example/subs".into(), terms_sig: terms.sign(plan_sk).unwrap(), terms, line: None };
    SubRecord { sub_key: public_hex(sub_sk).unwrap(), c: 0, plan, host: "aoi.example".into(), signup: None, receipt: None, first_due, agreed_at: first_due, state: "active".into(),
        payments: vec![], needs_sync: false, plan_url: "https://aoi.example/subs/coffee-club".into(), last: None, change: None, accepted: None, terms_behind: None, end: None, past_terms: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder};

    const SUB_SK: [u8; 32] = [0x11; 32];
    const PLAN_SK: [u8; 32] = [0x22; 32];
    const NODE_SK: [u8; 32] = [0x42; 32];
    const T0: u64 = 1_790_000_000;

    fn node_hex() -> String {
        let secp = Secp256k1::new();
        hex::encode(PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&NODE_SK).unwrap()).serialize())
    }

    fn terms_sat() -> Terms {
        Terms {
            terms_version: 1, merchant_name: "Kissaten Aoi".into(), plan_name: "Coffee club".into(),
            price: Price { unit: "sat".into(), by_payment: vec![PriceStep { from: 1, amount: "8000".into() }, PriceStep { from: 4, amount: "10000".into() }] },
            every: Every { unit: "month".into(), count: 1 },
            first_payment: FirstPayment { rule: "on_agree".into(), date: None, days: None },
            payments: Some(12), price_kept_through: Some(12), grace_days: 7, ending: Ending { refund: "unused_time".into() },
            change_notice_days: 30, pay_by: vec!["lightning".into()], lightning: Some(LightningTerms { nodes: vec![node_hex()] }), onchain: None, free_days_need: None, plan_description: None,
        }
    }

    fn terms_usd() -> Terms {
        let mut t = terms_sat();
        t.price = Price { unit: "USD".into(), by_payment: vec![PriceStep { from: 1, amount: "4.99".into() }] };
        t.payments = None; t.price_kept_through = None;
        t.first_payment = FirstPayment { rule: "after_days".into(), date: None, days: Some(14) };
        t.free_days_need = Some("signup_code".into());
        t
    }

    fn plan_json(t: &Terms, server: &str) -> String {
        serde_json::json!({ "v": 1, "tag": "lijoxSubsPlan", "plan_id": "coffee-club", "plan_key": public_hex(&PLAN_SK).unwrap(), "server": server,
            "terms": serde_json::to_value(t).unwrap(), "terms_sig": t.sign(&PLAN_SK).unwrap(), "line": "Thank you — see https://aoi.example/app for news" }).to_string()
    }

    fn k() -> [u8; 32] { shared_secret(&SUB_SK, &public_hex(&PLAN_SK).unwrap()).unwrap() }

    /// An invoice the way a plan server makes one, and the server's answer around it.
    fn answer(t: &Terms, n: u32, amount_msat: u64, desc: &str, node_sk: &[u8; 32], hash_signer: &[u8; 32], made: u64, life: u64, rate: Option<(&str, u64)>, preimage: u8) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(node_sk).unwrap();
        let hash = sha256::Hash::hash(&[preimage; 32]);
        let raw = InvoiceBuilder::new(Currency::Bitcoin).description(desc.to_string())
            .duration_since_epoch(std::time::Duration::from_secs(made)).payment_hash(hash)
            .payment_secret(lightning::types::payment::PaymentSecret([0x11; 32])).min_final_cltv_expiry_delta(144)
            .expiry_time(std::time::Duration::from_secs(life)).amount_milli_satoshis(amount_msat).build_raw().unwrap();
        let inv = lightning_invoice::Bolt11Invoice::from_signed(raw.sign::<_, ()>(|m| Ok(secp.sign_ecdsa_recoverable(m, &sk))).unwrap()).unwrap();
        let mut a = serde_json::json!({ "v": 1, "n": n, "pr": inv.to_string(), "amount_msat": amount_msat,
            "price": { "unit": t.price.unit, "amount": t.price_for(n).unwrap_or("0") }, "period": { "from": T0, "to": T0 + 30 * 86_400 },
            "hash_sig": seller_sign_hash(hash_signer, &hex::encode(hash.to_byte_array())).unwrap() });
        if let Some((spu, exp)) = rate { a["rate"] = serde_json::json!({ "sat_per_unit": spu, "expires": exp }); }
        a.to_string()
    }

    fn good(n: u32) -> String {
        let t = terms_sat();
        let msat = msat_for(t.price_for(n).unwrap(), "1").unwrap();
        answer(&t, n, msat, &invoice_description("coffee-club", n, &payment_tag(&k(), n)), &NODE_SK, &PLAN_SK, T0, 600, None, n as u8)
    }

    fn check(t: &Terms, n: u32, due_at: u64, now: u64, a: &str) -> Result<CheckedInvoice, String> {
        check_invoice("coffee-club", &public_hex(&PLAN_SK).unwrap(), t, &k(), n, due_at, now, a)
    }

    // ── vectors: the sidecar's own tests must give these same values (format round 3 lists them) ──────────────
    const V_SUB_KEY: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const V_PLAN_KEY: &str = "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
    const V_K: &str = "d24079a83fbd31b649c0560c037b23db9a5a713ab71b903dfecc54b4f55a6cf2";
    const V_DIGEST: &str = "edf9b60f876a4860b3a34d0b7892baafe7e9e43d6676b85d5791c14f528c6ad1";

    #[test]
    fn s71_vectors_keys_secret_tags_and_signatures() {
        assert_eq!(public_hex(&SUB_SK).unwrap(), V_SUB_KEY);
        assert_eq!(public_hex(&PLAN_SK).unwrap(), V_PLAN_KEY);
        assert_eq!(hex::encode(tagged_hash("LIJOX-Subs/msg", b"abc")), "a66794f68048c03d38e658e454215643244025f91af192079bd8396c8526af30");
        // the wallet and the merchant work out the same K, each from its own secret and the other's public key
        assert_eq!(hex::encode(k()), V_K);
        assert_eq!(hex::encode(shared_secret(&PLAN_SK, V_SUB_KEY).unwrap()), V_K, "the merchant's side gives the same K");
        assert_eq!(payment_tag(&k(), 1), "01b7594b75f1e059ce7e766c474409bc");
        assert_eq!(payment_tag(&k(), 2), "961e2315e2be63dd0347c53d5d8a7e4b");
        assert_eq!(mac_hex(&k(), "lijox-subs/1|x|1"), "7aa84413ced1c18bcc617c1569d731264983793b1df98837026ebe94e2508351");
        let c = "lijox-subs/1|sync|coffee-club|k|1790000000";
        let sig = sign_canonical(&SUB_SK, c).unwrap();
        assert_eq!(sig, "92e3c94da38b751d2fa70c0738f99911c9c872c2adcb6a7817d3b7eb66c3c84fa616de4e8c41fec5f5155e5f9b22e34740a9892d72834eb2bed9ade7c5df189e");
        assert!(verify_canonical(V_SUB_KEY, c, &sig));
        assert!(!verify_canonical(V_PLAN_KEY, c, &sig), "another key's signature is not this key's");
        assert!(!verify_canonical(V_SUB_KEY, "lijox-subs/1|sync|coffee-club|k|1790000001", &sig), "one changed character is another message");
        assert!(!verify_canonical(V_SUB_KEY, c, "00"), "a short signature is refused, not a crash");
        assert_eq!(seller_sign_hash(&PLAN_SK, &"ab".repeat(32)).unwrap(),
            "c0feb668ea826bea8288e79a524d37561399a90a3cc5a26c24cbfec727b5a9d84bdb6984d01bc9ba3babf245b8205faea1fd68f648185bc311a0b18a72055739");
        assert!(shared_secret(&SUB_SK, "zz").is_err());
    }

    #[test]
    fn s71_names_hold_no_separator() {
        assert!(name_ok("coffee-club_2.a", 40));
        for bad in ["", "a|b", "a b", "a/b", "é", "a\nb"] { assert!(!name_ok(bad, 40), "{bad:?}"); }
        assert!(!name_ok(&"a".repeat(41), 40));
    }

    #[test]
    fn s71_terms_string_and_digest_are_pinned() {
        let t = terms_sat();
        t.validate().unwrap();
        assert_eq!(t.terms_string(), format!("terms_version=1\nmerchant_name=Kissaten Aoi\nplan_name=Coffee club\nprice.unit=sat\nprice.by_payment=1:8000,4:10000\nevery=month:1\nfirst_payment=on_agree\npayments=12\nprice_kept_through=12\ngrace_days=7\nending.refund=unused_time\nchange_notice_days=30\npay_by=lightning\nlightning.nodes={}\nonchain.sp_address=\nfree_days_need=", node_hex()));
        assert_eq!(node_hex(), "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c");
        assert_eq!(t.digest_hex(), V_DIGEST);
        assert_eq!(t.sign(&PLAN_SK).unwrap(), "4320a0a2b54913b7a1bed3c788a6390940cecf3fb46a20861b0ca069db5112cc3170beeb36052c1e7455757950977e3062a272025eb7d76fc89465c0c17a4dea");
        let u = terms_usd();
        u.validate().unwrap();
        assert!(u.terms_string().contains("\nfirst_payment=after_days:14\npayments=\nprice_kept_through=\n"));
        assert!(u.terms_string().ends_with("\nfree_days_need=signup_code"));
        assert_eq!(u.digest_hex(), "a3463fadd4fe21579ca15148fb96fca8303299e2fa9bfcc7db0f221443f60216");
        // the names are inside what is signed: a changed name is another digest
        let mut other = terms_sat(); other.merchant_name = "Kissaten Aoi 2".into();
        assert_ne!(other.digest_hex(), V_DIGEST);
        // the price of each payment number
        assert_eq!(t.price_for(1), Some("8000")); assert_eq!(t.price_for(3), Some("8000")); assert_eq!(t.price_for(4), Some("10000"));
        assert_eq!(t.price_for(12), Some("10000")); assert_eq!(t.price_for(13), None); assert_eq!(t.price_for(0), None);
        assert_eq!(u.price_for(900), Some("4.99"), "a plan with no last payment has a price for every number");
    }

    #[test]
    fn s71_terms_outside_the_limits_are_refused() {
        let bad = |f: &dyn Fn(&mut Terms)| { let mut t = terms_sat(); f(&mut t); t.validate().is_err() };
        assert!(bad(&|t| t.merchant_name = "".into()));
        assert!(bad(&|t| t.merchant_name = "x".repeat(61)));
        assert!(bad(&|t| t.plan_name = "a\nb".into()), "a name with a line break would forge a line of the terms string");
        assert!(bad(&|t| t.price.unit = "usd".into()));
        assert!(bad(&|t| t.price.by_payment[0].from = 2));
        assert!(bad(&|t| t.price.by_payment[1].from = 1));
        assert!(bad(&|t| t.price.by_payment[0].amount = "0".into()));
        assert!(bad(&|t| t.price.by_payment[0].amount = "8000.5".into()), "sats are whole");
        assert!(bad(&|t| t.price.by_payment[0].amount = "-1".into()));
        assert!(bad(&|t| t.price.by_payment = (1..=25).map(|i| PriceStep { from: i, amount: "1".into() }).collect()));
        assert!(bad(&|t| t.every.unit = "day".into()));
        assert!(bad(&|t| t.every.count = 13));
        assert!(bad(&|t| t.first_payment.rule = "whenever".into()));
        assert!(bad(&|t| t.first_payment.days = Some(3)), "on_agree carries no days");
        assert!(bad(&|t| t.payments = Some(1001)));
        assert!(bad(&|t| t.price_kept_through = Some(13)));
        assert!(bad(&|t| t.grace_days = 61));
        assert!(bad(&|t| t.ending.refund = "maybe".into()));
        assert!(bad(&|t| t.change_notice_days = 6));
        assert!(bad(&|t| t.pay_by = vec![]));
        assert!(bad(&|t| t.pay_by = vec!["lightning".into(), "lightning".into()]));
        assert!(bad(&|t| t.pay_by = vec!["onchain".into()]), "onchain in pay_by needs its address, and lightning terms without lightning are refused");
        assert!(bad(&|t| t.lightning = None));
        assert!(bad(&|t| t.lightning = Some(LightningTerms { nodes: vec![format!("02{}", "ff".repeat(32))] })), "66 hex that is no point");
        assert!(bad(&|t| t.lightning = Some(LightningTerms { nodes: vec![] })));
        assert!(bad(&|t| t.free_days_need = Some("none".into())), "free_days_need belongs to after_days");
        let mut u = terms_usd(); u.free_days_need = None; assert!(u.validate().is_err());
        let mut u = terms_usd(); u.first_payment.days = Some(367); assert!(u.validate().is_err());
        let mut u = terms_usd(); u.price.by_payment[0].amount = "4.999999999".into(); assert!(u.validate().is_err(), "nine digits after the point");
    }

    #[test]
    fn s71_an_unknown_term_is_passed_over_unless_it_is_required() {
        let mut v = serde_json::to_value(terms_sat()).unwrap();
        v["gift"] = serde_json::json!({ "note": "a free cup" });
        assert_eq!(parse_terms(&v).unwrap(), terms_sat());
        v["gift"] = serde_json::json!({ "required": true });
        assert!(parse_terms(&v).unwrap_err().contains("gift"));
        assert!(parse_terms(&serde_json::json!([1])).is_err());
    }

    #[test]
    fn s71_plan_code_and_plan_checks() {
        let c = parse_plan_code("lijoxsubs://Aoi.example/subs/coffee-club?signup=SPRING").unwrap();
        assert_eq!(c, PlanCode { url: "https://Aoi.example/subs/coffee-club?signup=SPRING".into(), host: "aoi.example".into(), signup: Some("SPRING".into()) });
        assert_eq!(parse_plan_code("LIJOXSUBS://aoi.example/p").unwrap().signup, None);
        for bad in ["https://aoi.example/p", "lijoxsubs://", "lijoxsubs:///p", "lijoxsubs://user@aoi.example/p", "lijoxsubs://aoi.example/p?signup=a|b", "lijoxsubs://aoi.example/a b"] {
            assert!(parse_plan_code(bad).is_err(), "{bad}");
        }
        let t = terms_sat();
        let p = check_plan(&plan_json(&t, "https://aoi.example/subs/"), "Aoi.example").unwrap();
        assert_eq!(p.plan_id, "coffee-club"); assert_eq!(p.plan_key, V_PLAN_KEY); assert_eq!(p.server, "https://aoi.example/subs");
        assert_eq!(p.line.as_deref(), Some("Thank you — see for news"), "a web address is taken out of the merchant's line");
        // the server must be on the host the plan code named, and https
        assert!(check_plan(&plan_json(&t, "https://evil.example/subs"), "aoi.example").unwrap_err().contains("host"));
        assert!(check_plan(&plan_json(&t, "http://aoi.example/subs"), "aoi.example").is_err());
        // terms that the plan key did not sign: a changed name, a changed price, another key
        let tamper = |f: &dyn Fn(&mut serde_json::Value)| { let mut v: serde_json::Value = serde_json::from_str(&plan_json(&t, "https://aoi.example/subs")).unwrap(); f(&mut v); check_plan(&v.to_string(), "aoi.example") };
        assert!(tamper(&|v| v["terms"]["merchant_name"] = "Kissaten Ao1".into()).unwrap_err().contains("signed"));
        assert!(tamper(&|v| v["terms"]["price"]["by_payment"][0]["amount"] = "7000".into()).unwrap_err().contains("signed"));
        assert!(tamper(&|v| v["plan_key"] = V_SUB_KEY.into()).unwrap_err().contains("signed"));
        assert!(tamper(&|v| v["plan_id"] = "a|b".into()).is_err());
        assert!(tamper(&|v| v["v"] = 2.into()).is_err());
        assert!(tamper(&|v| v["tag"] = "payRequest".into()).is_err());
        assert_eq!(clean_line(&"x".repeat(300)).chars().count(), 140);
    }

    #[test]
    fn s71_due_dates_step_by_the_calendar() {
        let at = |y, m, d| days_from_civil(y, m, d) as u64 * 86_400 + 3_600;
        assert_eq!(civil_from_days(days_from_civil(2028, 2, 29)), (2028, 2, 29));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        let month = Every { unit: "month".into(), count: 1 };
        // the 31st: February gets its last day, March gets the 31st back (each due date is worked out from the first)
        assert_eq!(due(at(2027, 1, 31), &month, 1), Some(at(2027, 1, 31)));
        assert_eq!(due(at(2027, 1, 31), &month, 2), Some(at(2027, 2, 28)));
        assert_eq!(due(at(2027, 1, 31), &month, 3), Some(at(2027, 3, 31)));
        assert_eq!(due(at(2027, 1, 31), &month, 4), Some(at(2027, 4, 30)));
        assert_eq!(due(at(2027, 1, 31), &month, 14), Some(at(2028, 2, 29)), "a leap year's February");
        assert_eq!(due(at(2027, 11, 15), &Every { unit: "month".into(), count: 3 }, 2), Some(at(2028, 2, 15)), "across the year's end");
        assert_eq!(due(at(2028, 2, 29), &Every { unit: "year".into(), count: 1 }, 2), Some(at(2029, 2, 28)));
        assert_eq!(due(at(2028, 2, 29), &Every { unit: "year".into(), count: 1 }, 5), Some(at(2032, 2, 29)));
        assert_eq!(due(T0, &Every { unit: "week".into(), count: 2 }, 3), Some(T0 + 28 * 86_400));
        assert_eq!(due(T0, &month, 0), None);
        assert_eq!(due(T0, &Every { unit: "day".into(), count: 1 }, 2), None);
        // where a payment stands
        let d = T0 + 30 * 86_400;
        assert_eq!(pay_state(d - 15 * 86_400, d, 7), "not_yet");
        assert_eq!(pay_state(d - 14 * 86_400, d, 7), "payable");
        assert_eq!(pay_state(d, d, 7), "overdue");
        assert_eq!(pay_state(d + 7 * 86_400, d, 7), "overdue");
        assert_eq!(pay_state(d + 7 * 86_400 + 1, d, 7), "lapsed");
    }

    #[test]
    fn s71_signed_messages_verify_and_the_seller_signs_its_receipt() {
        let t = terms_sat();
        let plan = check_plan(&plan_json(&t, "https://aoi.example/subs"), "aoi.example").unwrap();
        let a = agree_body(&SUB_SK, &plan, Some("SPRING"), T0).unwrap();
        assert_eq!(a["sig"], "7640cd5cff272849d178b7965ffae89cc72f793880dc19cb8939d56de82637475ec903e99cc864c1f9b28b5fcb5486b287bc1a79f642533f130aa1ad5c7c1384");
        assert_eq!(a["sub_key"], V_SUB_KEY); assert_eq!(a["terms_digest"], V_DIGEST); assert_eq!(a["signup"], "SPRING");
        assert!(agree_body(&SUB_SK, &plan, None, T0).unwrap().get("signup").is_none());
        assert!(agree_body(&SUB_SK, &plan, Some("a|b"), T0).is_err());
        // the seller's receipt: its key over the agreement — only for an agreement the subscription key signed
        let r = seller_receipt(&PLAN_SK, "coffee-club", &t, &a, T0).unwrap();
        assert!(verify_canonical(V_PLAN_KEY, &agreed_canonical("coffee-club", V_DIGEST, V_SUB_KEY, T0), &r));
        assert!(!verify_canonical(V_PLAN_KEY, &agreed_canonical("coffee-club", V_DIGEST, V_SUB_KEY, T0 + 1), &r), "the first due date is inside the receipt");
        let mut forged = a.clone(); forged["signup"] = "WINTER".into();
        assert!(seller_receipt(&PLAN_SK, "coffee-club", &t, &forged, T0).is_err());
        assert!(seller_receipt(&PLAN_SK, "coffee-club", &terms_usd(), &a, T0).is_err(), "an agreement to other terms");
        // end, with each way a refund is asked for
        let e = end_body(&SUB_SK, "coffee-club", "now", Some(&RefundTo::Lnaddr("r7k2@aoi.example".into())), T0).unwrap();
        assert_eq!(e["refund_to"], serde_json::json!({ "lnaddr": "r7k2@aoi.example" }));
        assert!(verify_canonical(V_SUB_KEY, &format!("lijox-subs/1|end|coffee-club|{V_SUB_KEY}|now|lnaddr:r7k2@aoi.example|{T0}"), e["sig"].as_str().unwrap()));
        let e = end_body(&SUB_SK, "coffee-club", "paid_period_end", None, T0).unwrap();
        assert!(e.get("refund_to").is_none());
        assert!(verify_canonical(V_SUB_KEY, &format!("lijox-subs/1|end|coffee-club|{V_SUB_KEY}|paid_period_end||{T0}"), e["sig"].as_str().unwrap()));
        assert!(end_body(&SUB_SK, "coffee-club", "later", None, T0).is_err());
        assert!(end_body(&SUB_SK, "coffee-club", "now", Some(&RefundTo::Lnaddr("a|b@x".into())), T0).is_err());
        assert!(end_body(&SUB_SK, "coffee-club", "now", Some(&RefundTo::Lnaddr("no-at-sign".into())), T0).is_err());
        // accept, sync, sign-in
        let mut t2 = terms_sat(); t2.terms_version = 2; t2.price.by_payment[1].amount = "11000".into();
        let ac = accept_body(&SUB_SK, "coffee-club", &t2, T0).unwrap();
        assert!(verify_canonical(V_SUB_KEY, &format!("lijox-subs/1|accept|coffee-club|{V_SUB_KEY}|2|{}|{T0}", t2.digest_hex()), ac["sig"].as_str().unwrap()));
        let sy = sync_body(&SUB_SK, "coffee-club", T0).unwrap();
        assert!(verify_canonical(V_SUB_KEY, &format!("lijox-subs/1|sync|coffee-club|{V_SUB_KEY}|{T0}"), sy["sig"].as_str().unwrap()));
        let (key, sig) = signin(&SUB_SK, "Aoi.example", &"AB".repeat(32)).unwrap();
        assert_eq!(key, V_SUB_KEY);
        assert!(verify_canonical(V_SUB_KEY, &format!("lijox-subs/1|signin|aoi.example|{}", "ab".repeat(32)), &sig));
        assert!(signin(&SUB_SK, "aoi.example", "abc").is_err());
        assert_eq!(tagged_query("coffee-club", &k(), 2), "plan_id=coffee-club&n=2&tag=961e2315e2be63dd0347c53d5d8a7e4b");
    }

    #[test]
    fn s71_millisats_follow_from_the_price() {
        assert_eq!(msat_for("8000", "1").unwrap(), 8_000_000);
        assert_eq!(msat_for("4.99", "1052.63157894").unwrap(), 5_252_632, "5252631.578… rounds up");
        assert_eq!(msat_for("1", "0.0005").unwrap(), 1, "exactly half rounds up");
        assert_eq!(msat_for("1", "0.0004").unwrap(), 0);
        assert_eq!(msat_for("0.01", "1000").unwrap(), 10_000);
        assert!(msat_for("1e3", "1").is_err()); assert!(msat_for("1.", "1").is_err()); assert!(msat_for(".5", "1").is_err());
        assert!(msat_for("99999999999999999999", "99999999999999999999").is_err(), "out of range is an error, not a wrap");
        assert_eq!(parse_decimal("8000.00").map(norm), parse_decimal("8000").map(norm));
    }

    #[test]
    fn s71_the_six_checks_on_an_invoice() {
        let t = terms_sat();
        let (due1, now) = (T0, T0 + 60);
        let ok = check(&t, 1, due1, now, &good(1)).unwrap();
        assert_eq!(ok.amount_msat, 8_000_000); assert_eq!(ok.payee, node_hex()); assert_eq!(ok.n, 1); assert_eq!(ok.expires_at, T0 + 600);
        assert_eq!(ok.payment_hash, hex::encode(sha256::Hash::hash(&[1u8; 32]).to_byte_array()));
        let d1 = invoice_description("coffee-club", 1, &payment_tag(&k(), 1));
        assert_eq!(d1, "lijox-subs/1 coffee-club #1 01b7594b75f1e059ce7e766c474409bc");
        // 1 — from a node the signed terms do not name
        let e = check(&t, 1, due1, now, &answer(&t, 1, 8_000_000, &d1, &[0x43; 32], &PLAN_SK, T0, 600, None, 1)).unwrap_err();
        assert!(e.contains("node"), "{e}");
        // 2 — not payable yet / grace days over
        assert!(check(&t, 1, T0 + 15 * 86_400, now, &good(1)).unwrap_err().contains("yet"));
        let late = T0 + 8 * 86_400;
        assert!(check(&t, 1, due1, late, &answer(&t, 1, 8_000_000, &d1, &NODE_SK, &PLAN_SK, late, 600, None, 1)).unwrap_err().contains("grace"));
        // 3 — a price that is not the agreed price for this number (the server states payment 4's price for payment 1)
        let mut v: serde_json::Value = serde_json::from_str(&good(1)).unwrap(); v["price"]["amount"] = "10000".into();
        assert!(check(&t, 1, due1, now, &v.to_string()).unwrap_err().contains("agreed"));
        let mut v: serde_json::Value = serde_json::from_str(&good(1)).unwrap(); v["price"]["unit"] = "USD".into();
        assert!(check(&t, 1, due1, now, &v.to_string()).unwrap_err().contains("agreed"));
        let mut v: serde_json::Value = serde_json::from_str(&good(1)).unwrap(); v["price"]["amount"] = "8000.00".into();
        assert!(check(&t, 1, due1, now, &v.to_string()).is_ok(), "8000.00 is 8000");
        // 4 — an amount that does not follow from the price
        let e = check(&t, 1, due1, now, &answer(&t, 1, 8_000_001, &d1, &NODE_SK, &PLAN_SK, T0, 600, None, 1)).unwrap_err();
        assert!(e.contains("amount is not the price"), "{e}");
        // 5 — the invoice's own amount, its tag, its number, its life
        let mut v: serde_json::Value = serde_json::from_str(&good(1)).unwrap();
        v["pr"] = serde_json::from_str::<serde_json::Value>(&answer(&t, 1, 9_000_000, &d1, &NODE_SK, &PLAN_SK, T0, 600, None, 1)).unwrap()["pr"].clone();
        assert!(check(&t, 1, due1, now, &v.to_string()).unwrap_err().contains("invoice's amount"));
        let d2 = invoice_description("coffee-club", 2, &payment_tag(&k(), 2));
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 8_000_000, &d2, &NODE_SK, &PLAN_SK, T0, 600, None, 1)).unwrap_err().contains("tag"), "payment 2's tag on payment 1");
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 8_000_000, "coffee", &NODE_SK, &PLAN_SK, T0, 600, None, 1)).unwrap_err().contains("tag"));
        assert!(check(&t, 1, due1, now, &good(2)).unwrap_err().contains("number"), "an answer for another payment number");
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 8_000_000, &d1, &NODE_SK, &PLAN_SK, T0, 601, None, 1)).unwrap_err().contains("longer"));
        assert!(check(&t, 1, due1, T0 + 600, &good(1)).unwrap_err().contains("run out"));
        // 6 — a payment hash the plan key did not sign (a provider that swaps in its own invoice cannot make this)
        let e = check(&t, 1, due1, now, &answer(&t, 1, 8_000_000, &d1, &NODE_SK, &SUB_SK, T0, 600, None, 1)).unwrap_err();
        assert!(e.contains("payment hash"), "{e}");
        let mut v: serde_json::Value = serde_json::from_str(&good(1)).unwrap(); v.as_object_mut().unwrap().remove("hash_sig");
        assert!(check(&t, 1, due1, now, &v.to_string()).unwrap_err().contains("payment hash"));
        // a number the plan does not have
        assert!(check(&t, 13, due1, now, &answer(&t, 13, 8_000_000, &invoice_description("coffee-club", 13, &payment_tag(&k(), 13)), &NODE_SK, &PLAN_SK, T0, 600, None, 13)).is_err());
        assert!(check(&t, 1, due1, now, "{}").is_err()); assert!(check(&t, 1, due1, now, "not json").is_err());
    }

    #[test]
    fn s71_a_currency_plan_is_checked_at_the_merchants_rate() {
        let t = terms_usd();
        let (due1, now) = (T0, T0 + 60);
        let d1 = invoice_description("coffee-club", 1, &payment_tag(&k(), 1));
        let rate = Some(("1052.63157894", T0 + 600));
        let ok = check(&t, 1, due1, now, &answer(&t, 1, 5_252_632, &d1, &NODE_SK, &PLAN_SK, T0, 600, rate, 1)).unwrap();
        assert_eq!(ok.sat_per_unit.as_deref(), Some("1052.63157894")); assert_eq!(ok.price_amount, "4.99"); assert_eq!(ok.price_unit, "USD");
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 5_252_631, &d1, &NODE_SK, &PLAN_SK, T0, 600, rate, 1)).unwrap_err().contains("rate"), "one millisat off the stated rate");
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 5_252_632, &d1, &NODE_SK, &PLAN_SK, T0, 600, None, 1)).unwrap_err().contains("rate"), "no rate stated");
        assert!(check(&t, 1, due1, now, &answer(&t, 1, 5_252_632, &d1, &NODE_SK, &PLAN_SK, T0, 600, Some(("1052.63157894", T0)), 1)).unwrap_err().contains("run out"));
    }

    fn record() -> SubRecord {
        let t = terms_sat();
        SubRecord { sub_key: V_SUB_KEY.into(), c: 0, plan: check_plan(&plan_json(&t, "https://aoi.example/subs"), "aoi.example").unwrap(), host: "aoi.example".into(),
            signup: None, receipt: Some("r".into()), first_due: T0, agreed_at: T0, state: "active".into(), payments: vec![], needs_sync: false,
            plan_url: "https://aoi.example/subs/coffee-club".into(), last: None, change: None, accepted: None, terms_behind: None, end: None, past_terms: vec![] }
    }

    #[test]
    fn s71_one_payment_number_is_sent_once() {
        let t = terms_sat();
        let mut st = Store::default();
        st.add(record()).unwrap();
        assert!(st.add(record()).is_err(), "one record per subscription key");
        let inv1 = check(&t, 1, T0, T0 + 60, &good(1)).unwrap();
        assert_eq!(st.find(V_SUB_KEY).unwrap().next_n(), 1);
        st.begin_payment(V_SUB_KEY, &inv1, T0 + 60).unwrap();
        // a second invoice for the same number, while the first is on its way: refused (the double-pay lesson)
        let again = check(&t, 1, T0, T0 + 60, &answer(&t, 1, 8_000_000, &invoice_description("coffee-club", 1, &payment_tag(&k(), 1)), &NODE_SK, &PLAN_SK, T0, 600, None, 77)).unwrap();
        assert!(st.begin_payment(V_SUB_KEY, &again, T0 + 61).unwrap_err().contains("on its way"));
        assert!(st.begin_payment(V_SUB_KEY, &inv1, T0 + 61).unwrap_err().contains("used before"), "the same invoice twice");
        assert_eq!(st.find(V_SUB_KEY).unwrap().next_n(), 2, "a number on its way is not offered again");
        // it comes back: the number may be sent again — with the SAME invoice (the merchant hands it out again while it
        // lives), the failed try being replaced, not doubled …
        assert!(st.fail_payment(&inv1.payment_hash));
        assert_eq!(st.find(V_SUB_KEY).unwrap().next_n(), 1);
        st.begin_payment(V_SUB_KEY, &inv1, T0 + 62).unwrap();
        assert_eq!(st.find(V_SUB_KEY).unwrap().payments.iter().filter(|p| p.payment_hash == inv1.payment_hash).count(), 1, "one record per hash");
        assert!(st.begin_payment(V_SUB_KEY, &inv1, T0 + 62).unwrap_err().contains("used before"), "on its way again: the same invoice is refused");
        assert!(st.fail_payment(&inv1.payment_hash));
        // … or with a new invoice; the failed hash stays unusable for any OTHER number or subscription
        let mut other = record(); other.sub_key = "ab".repeat(32);
        st.add(other).unwrap();
        assert!(st.begin_payment(&"ab".repeat(32), &inv1, T0 + 62).unwrap_err().contains("used before"), "another subscription cannot take a hash on this one's record");
        st.forget_for_test(&"ab".repeat(32));
        st.begin_payment(V_SUB_KEY, &again, T0 + 62).unwrap();
        assert!(st.settle_payment(&again.payment_hash, &"cd".repeat(32), Some(1_000), T0 + 63));
        assert!(!st.fail_payment(&again.payment_hash), "a paid payment is never turned back");
        // paid: refused for good, whatever invoice arrives
        let third = check(&t, 1, T0, T0 + 60, &answer(&t, 1, 8_000_000, &invoice_description("coffee-club", 1, &payment_tag(&k(), 1)), &NODE_SK, &PLAN_SK, T0, 600, None, 78)).unwrap();
        assert!(st.begin_payment(V_SUB_KEY, &third, T0 + 64).unwrap_err().contains("paid already"));
        let p = &st.find(V_SUB_KEY).unwrap().payments;
        assert_eq!(p.iter().filter(|x| x.state == "paid").count(), 1);
        assert_eq!(p.iter().find(|x| x.state == "paid").unwrap().preimage.as_deref(), Some("cd".repeat(32).as_str()));
        assert_eq!(st.find(V_SUB_KEY).unwrap().next_n(), 2);
        assert!(st.begin_payment("nobody", &third, T0).is_err());
        assert!(!st.settle_payment("ff", "00", None, T0));
    }

    #[test]
    fn s71_after_a_restore_the_merchant_is_asked_before_pay_is_offered() {
        let t = terms_sat();
        let mut st = Store::default();
        st.add(record()).unwrap();
        // the backup was made before payments 1 and 2 were sent; the restored wallet does not know of them
        st.mark_restored();
        let inv1 = check(&t, 1, T0, T0 + 60, &good(1)).unwrap();
        assert!(st.begin_payment(V_SUB_KEY, &inv1, T0 + 60).unwrap_err().contains("restored"));
        st.apply_sync(V_SUB_KEY, &[(1, T0 + 10, "aa".repeat(32)), (2, T0 + 20, "bb".repeat(32))]).unwrap();
        assert!(!st.find(V_SUB_KEY).unwrap().needs_sync);
        assert_eq!(st.find(V_SUB_KEY).unwrap().next_n(), 3);
        assert!(st.begin_payment(V_SUB_KEY, &inv1, T0 + 60).unwrap_err().contains("paid already"), "payment 1 is not paid a second time");
        // an ended subscription is not marked, and takes no payment
        let mut st2 = Store::default(); let mut r = record(); r.state = "ended".into(); st2.add(r).unwrap();
        st2.mark_restored();
        assert!(!st2.find(V_SUB_KEY).unwrap().needs_sync);
        assert!(st2.begin_payment(V_SUB_KEY, &inv1, T0).unwrap_err().contains("ended"));
        // a send the record shows on its way stays on its way through a sync that does not list it
        let mut st3 = Store::default(); st3.add(record()).unwrap();
        st3.begin_payment(V_SUB_KEY, &inv1, T0).unwrap();
        st3.apply_sync(V_SUB_KEY, &[]).unwrap();
        assert_eq!(st3.find(V_SUB_KEY).unwrap().payments[0].state, "sending");
        st3.apply_sync(V_SUB_KEY, &[(1, T0 + 5, inv1.payment_hash.clone())]).unwrap();
        assert_eq!(st3.find(V_SUB_KEY).unwrap().payments.len(), 1);
        assert_eq!(st3.find(V_SUB_KEY).unwrap().payments[0].state, "paid");
    }

    #[test]
    fn s71_the_records_are_kept_in_the_wallets_state() {
        let storage = crate::storage::native_storage::MemoryStorage::new();
        assert_eq!(load(&storage).unwrap(), Store::default());
        let mut st = Store::default(); st.add(record()).unwrap();
        save(&storage, &st).unwrap();
        assert_eq!(load(&storage).unwrap(), st);
    }

    #[test]
    fn s71_the_seller_knows_each_subscribers_tags_and_reads_a_description() {
        assert_eq!(seller_expected_tag(&PLAN_SK, V_SUB_KEY, 1).unwrap(), payment_tag(&k(), 1));
        assert_eq!(seller_expected_tag(&PLAN_SK, V_SUB_KEY, 7).unwrap(), payment_tag(&k(), 7));
        assert_ne!(seller_expected_tag(&PLAN_SK, V_PLAN_KEY, 1).unwrap(), payment_tag(&k(), 1), "another subscriber's tags are other tags");
        assert_eq!(parse_description("lijox-subs/1 coffee-club #3 0123456789abcdef0123456789abcdef"), Some(("coffee-club".into(), 3, "0123456789abcdef0123456789abcdef".into())));
        for bad in ["coffee", "lijox-subs/1 coffee-club #0 0123456789abcdef0123456789abcdef", "lijox-subs/1 coffee-club 3 0123456789abcdef0123456789abcdef",
            "lijox-subs/1 coffee-club #3 0123", "lijox-subs/1 coffee-club #3 0123456789ABCDEF0123456789abcdef", "lijox-subs/1 coffee-club #3 0123456789abcdef0123456789abcdef x", "lijox-subs/2 coffee-club #3 0123456789abcdef0123456789abcdef"] {
            assert_eq!(parse_description(bad), None, "{bad}");
        }
        assert!(seller_sign_hash(&PLAN_SK, "abc").is_err());
    }

    // ── the merchant's answers ──────────────────────────────────────────────────────────────────────────────────

    fn plan() -> Plan { check_plan(&plan_json(&terms_sat(), "https://aoi.example/subs"), "aoi.example").unwrap() }
    fn receipt_for(first_due: u64) -> String { sign_canonical(&PLAN_SK, &agreed_canonical("coffee-club", V_DIGEST, V_SUB_KEY, first_due)).unwrap() }

    #[test]
    fn s71_an_answer_is_ok_or_an_error_with_its_code() {
        assert!(read_answer(r#"{"status":"OK","first_due":1}"#).is_ok());
        let e = read_answer(r#"{"status":"ERROR","code":"UNKNOWN_TAG","reason":"use sync — see https://x.example/help"}"#).unwrap_err();
        assert_eq!(e, ServerError { code: "UNKNOWN_TAG".into(), reason: "use sync — see".into() });
        assert_eq!(read_answer(r#"{"status":"ERROR","code":"a b|c"}"#).unwrap_err().code, "ERROR");
        assert_eq!(read_answer("<html>").unwrap_err().code, "BAD_ANSWER");
        assert_eq!(read_answer(r#"{"pr":"lnbc1"}"#).unwrap_err().code, "BAD_ANSWER");
    }

    #[test]
    fn s71_the_agreement_answer_must_follow_the_terms_and_carry_the_plan_keys_receipt() {
        let p = plan();
        let ok = serde_json::json!({ "status": "OK", "first_due": T0 + 30, "receipt": receipt_for(T0 + 30) });
        assert_eq!(check_agreed(&p, V_SUB_KEY, &ok, T0).unwrap(), Agreed { first_due: T0 + 30, receipt: Some(receipt_for(T0 + 30)) });
        // on_agree: a first due date a month away does not follow the terms
        let far = serde_json::json!({ "status": "OK", "first_due": T0 + 30 * 86_400, "receipt": receipt_for(T0 + 30 * 86_400) });
        assert!(check_agreed(&p, V_SUB_KEY, &far, T0).unwrap_err().contains("follow"));
        // a receipt for another first due date, or by another key
        let wrong = serde_json::json!({ "status": "OK", "first_due": T0 + 30, "receipt": receipt_for(T0 + 31) });
        assert!(check_agreed(&p, V_SUB_KEY, &wrong, T0).unwrap_err().contains("receipt"));
        let other = serde_json::json!({ "status": "OK", "first_due": T0, "receipt": sign_canonical(&SUB_SK, &agreed_canonical("coffee-club", V_DIGEST, V_SUB_KEY, T0)).unwrap() });
        assert!(check_agreed(&p, V_SUB_KEY, &other, T0).is_err());
        // a LiJ seller whose phone has not opened: no receipt yet, said so
        assert_eq!(check_agreed(&p, V_SUB_KEY, &serde_json::json!({ "status": "OK", "first_due": T0, "receipt": null, "receipt_pending": true }), T0).unwrap().receipt, None);
        assert!(check_agreed(&p, V_SUB_KEY, &serde_json::json!({ "status": "OK", "first_due": T0 }), T0).is_err(), "no receipt and not said pending");
        // after_days and on_date
        let u = check_plan(&plan_json(&terms_usd(), "https://aoi.example/subs"), "aoi.example").unwrap();
        let fd = T0 + 14 * 86_400;
        let r = sign_canonical(&PLAN_SK, &agreed_canonical("coffee-club", &u.terms.digest_hex(), V_SUB_KEY, fd)).unwrap();
        assert!(check_agreed(&u, V_SUB_KEY, &serde_json::json!({ "first_due": fd, "receipt": r }), T0).is_ok());
        assert!(check_agreed(&u, V_SUB_KEY, &serde_json::json!({ "first_due": T0, "receipt": r }), T0).is_err(), "the free days were not given");
        let mut d = terms_sat(); d.first_payment = FirstPayment { rule: "on_date".into(), date: Some(T0 + 5 * 86_400), days: None };
        let dp = check_plan(&plan_json(&d, "https://aoi.example/subs"), "aoi.example").unwrap();
        let r = sign_canonical(&PLAN_SK, &agreed_canonical("coffee-club", &d.digest_hex(), V_SUB_KEY, T0 + 5 * 86_400)).unwrap();
        assert!(check_agreed(&dp, V_SUB_KEY, &serde_json::json!({ "first_due": T0 + 5 * 86_400, "receipt": r }), T0).is_ok());
        assert!(check_agreed(&dp, V_SUB_KEY, &serde_json::json!({ "first_due": T0 + 5 * 86_400 + 1, "receipt": r }), T0).is_err());
    }

    fn changed(f: &dyn Fn(&mut Terms)) -> Terms { let mut t = terms_sat(); t.terms_version = 2; f(&mut t); t }

    #[test]
    fn s71_a_change_must_keep_the_rhythm_the_notice_and_the_kept_price() {
        let mut old = terms_sat(); old.price_kept_through = Some(6);
        let notice = T0; let starts = T0 + 30 * 86_400;
        // a price change after the kept payments, with full notice: allowed
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment.push(PriceStep { from: 7, amount: "12000".into() })), starts, notice).is_ok());
        // inside the kept payments: refused — at the first payment, at an entry, between entries
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment[0].amount = "9000".into()), starts, notice).unwrap_err().contains("kept"));
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment[1].amount = "11000".into()), starts, notice).unwrap_err().contains("kept"));
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment.insert(1, PriceStep { from: 2, amount: "9000".into() })), starts, notice).unwrap_err().contains("kept"));
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment.push(PriceStep { from: 6, amount: "12000".into() })), starts, notice).unwrap_err().contains("kept"));
        assert!(change_allowed(&old, &changed(&|t| { t.price.unit = "USD".into(); t.price.by_payment = vec![PriceStep { from: 1, amount: "5".into() }]; }), starts, notice).unwrap_err().contains("unit"));
        // the same price written another way is the same price
        assert!(change_allowed(&old, &changed(&|t| t.price.by_payment = vec![PriceStep { from: 1, amount: "8000".into() }, PriceStep { from: 2, amount: "8000".into() }, PriceStep { from: 4, amount: "10000".into() }]), starts, notice).is_ok());
        // too little notice; no higher version; another rhythm
        assert!(change_allowed(&old, &changed(&|_| {}), starts - 1, notice).unwrap_err().contains("30 days"));
        assert!(change_allowed(&old, &old.clone(), starts, notice).unwrap_err().contains("version"));
        assert!(change_allowed(&old, &changed(&|t| t.every.count = 2), starts, notice).unwrap_err().contains("another plan"));
        // no price kept: any price change with notice
        let mut free = terms_sat(); free.price_kept_through = None;
        assert!(change_allowed(&free, &changed(&|t| { t.price_kept_through = None; t.price.by_payment[0].amount = "9000".into(); }), starts, notice).is_ok());
    }

    fn status_json(extra: serde_json::Value) -> serde_json::Value {
        let mut v = serde_json::json!({ "status": "OK", "state": "active", "paid_through": T0 + 31 * 86_400, "next": { "n": 1, "due": T0 }, "line": "New beans this month at www.aoi.example" });
        for (k, x) in extra.as_object().unwrap() { v[k] = x.clone(); }
        v
    }

    #[test]
    fn s71_a_status_answer_is_read_and_a_change_is_only_an_offer() {
        let p = plan();
        let v = read_status(&p, V_SUB_KEY, T0, &status_json(serde_json::json!({}))).unwrap();
        assert_eq!((v.state.as_str(), v.next_n, v.line.as_deref()), ("active", Some(1), Some("New beans this month at")));
        assert!(v.change.is_none() && v.change_refused.is_none() && v.ended.is_none());
        assert!(read_status(&p, V_SUB_KEY, T0, &serde_json::json!({ "status": "OK", "state": "paused" })).is_err());
        // a change the terms allow → an offer; one they do not → refused, with the reason
        let mut base = terms_sat(); base.price_kept_through = Some(3);
        let p3 = check_plan(&plan_json(&base, "https://aoi.example/subs"), "aoi.example").unwrap();
        let t2 = { let mut t = base.clone(); t.terms_version = 2; t.price.by_payment[1].amount = "11000".into(); t };
        let ch = |t: &Terms, starts: u64, signer: &[u8; 32]| serde_json::json!({ "change": { "terms_version": t.terms_version, "terms": serde_json::to_value(t).unwrap(), "terms_sig": t.sign(signer).unwrap(), "starts": starts, "notice_given": T0 } });
        let v = read_status(&p3, V_SUB_KEY, T0, &status_json(ch(&t2, T0 + 30 * 86_400, &PLAN_SK))).unwrap();
        assert_eq!(v.change.as_ref().unwrap().terms, t2);
        let v = read_status(&p3, V_SUB_KEY, T0, &status_json(ch(&t2, T0 + 29 * 86_400, &PLAN_SK))).unwrap();
        assert!(v.change.is_none() && v.change_refused.unwrap().contains("30 days"));
        let v = read_status(&p3, V_SUB_KEY, T0, &status_json(ch(&t2, T0 + 30 * 86_400, &SUB_SK))).unwrap();
        assert!(v.change.is_none() && v.change_refused.unwrap().contains("plan key"));
        // ended by the merchant, with its reason as text
        let v = read_status(&p, V_SUB_KEY, T0, &status_json(serde_json::json!({ "state": "ended", "ended": { "at": T0, "by": "merchant", "reason": "This service is closing." } }))).unwrap();
        assert_eq!(v.ended, Some(Ended { at: T0, by: "merchant".into(), reason: "This service is closing.".into() }));
        // a LiJ seller's receipt arrives with a later status — only the plan key's is taken
        assert_eq!(read_status(&p, V_SUB_KEY, T0, &status_json(serde_json::json!({ "receipt": receipt_for(T0) }))).unwrap().receipt, Some(receipt_for(T0)));
        assert_eq!(read_status(&p, V_SUB_KEY, T0, &status_json(serde_json::json!({ "receipt": receipt_for(T0 + 1) }))).unwrap().receipt, None);
    }

    #[test]
    fn s71_an_accepted_change_applies_from_its_start_and_never_before() {
        let mut base = terms_sat(); base.price_kept_through = Some(1);
        let mut st = Store::default();
        let mut r = record(); r.plan = check_plan(&plan_json(&base, "https://aoi.example/subs"), "aoi.example").unwrap(); r.receipt = None;
        st.add(r).unwrap();
        let t2 = { let mut t = base.clone(); t.terms_version = 2; t.price.by_payment = vec![PriceStep { from: 1, amount: "8000".into() }, PriceStep { from: 2, amount: "9500".into() }]; t };
        let month = 86_400 * 31;
        let offer = ChangeOffer { terms: t2.clone(), terms_sig: t2.sign(&PLAN_SK).unwrap(), starts: T0 + 2 * month, notice_given: T0, seen_at: 0 };
        let view = |change: Option<ChangeOffer>, next_n| StatusView { state: "active".into(), paid_through: None, next_n, line: None, ended: None, change, change_refused: None, receipt: None, refund: None };
        st.apply_status(V_SUB_KEY, &view(Some(offer.clone()), Some(1)), T0 + 100).unwrap();
        assert_eq!(st.find(V_SUB_KEY).unwrap().change.as_ref().unwrap().seen_at, T0 + 100);
        st.apply_status(V_SUB_KEY, &view(Some(offer.clone()), Some(1)), T0 + 900).unwrap();
        assert_eq!(st.find(V_SUB_KEY).unwrap().change.as_ref().unwrap().seen_at, T0 + 100, "first seen stays first seen");
        // offered is not applied: every payment is still under the agreed terms
        assert_eq!(st.find(V_SUB_KEY).unwrap().terms_at(4).price_for(4), Some("10000"));
        assert!(st.accept_change("nobody", None, T0).is_err());
        st.accept_change(V_SUB_KEY, Some("rcpt2".into()), T0 + 1000).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert!(rec.change.is_none() && rec.accepted.is_some());
        // payments 1 and 2 are due before the start (Oct 2026 → Nov 2026 + 1 month): the old price; payment 4: the new
        assert_eq!(rec.terms_at(1).price_for(1), Some("8000"));
        assert_eq!(rec.terms_at(2).price_for(2), Some("8000"), "due before the change starts");
        assert!(rec.due(4).unwrap() >= T0 + 2 * month);
        assert_eq!(rec.terms_at(4).price_for(4), Some("9500"));
        assert_eq!(rec.plan.terms.terms_version, 1, "the plan's terms are not replaced while a payment under them is unpaid");
        // once the next unpaid payment is due at or after the start, the new terms are the plan's and the old are kept
        st.apply_sync(V_SUB_KEY, &[(1, T0, "a1".repeat(32)), (2, T0, "a2".repeat(32)), (3, T0, "a3".repeat(32))]).unwrap();
        assert!(st.tidy(T0 + 2000));
        let rec = st.find(V_SUB_KEY).unwrap();
        assert_eq!(rec.plan.terms.terms_version, 2); assert_eq!(rec.receipt.as_deref(), Some("rcpt2")); assert!(rec.accepted.is_none());
        assert_eq!(rec.past_terms.len(), 1); assert_eq!(rec.past_terms[0].terms, base);
        assert!(!st.tidy(T0 + 2001), "nothing more to do");
        // a status with no change takes an old offer away; a same-or-lower version than the accepted one is not re-offered
        st.apply_status(V_SUB_KEY, &view(None, Some(4)), T0 + 3000).unwrap();
        assert!(st.find(V_SUB_KEY).unwrap().change.is_none() && !st.find(V_SUB_KEY).unwrap().needs_sync);
        // the merchant's next number is not this wallet's → ask before Pay
        st.apply_status(V_SUB_KEY, &view(None, Some(6)), T0 + 3000).unwrap();
        assert!(st.find(V_SUB_KEY).unwrap().needs_sync);
        assert_eq!(st.find(V_SUB_KEY).unwrap().why_not_pay(T0 + 3000), Some("sync_needed"));
    }

    #[test]
    fn s71_sync_brings_terms_the_wallet_lacks_and_pay_waits_for_them() {
        let t = terms_sat();
        let mut st = Store::default(); st.add(record()).unwrap(); st.mark_restored();
        let t2 = { let mut x = t.clone(); x.terms_version = 2; x.grace_days = 10; x };
        let v = read_sync(V_PLAN_KEY, &serde_json::json!({ "status": "OK", "state": "active", "terms_version": 2, "terms_digest": t2.digest_hex(), "first_due": T0,
            "paid": [ { "n": 1, "at": T0 + 5, "payment_hash": "AA".repeat(32), "txid": null } ], "next": { "n": 2, "due": T0 + 31 * 86_400 } })).unwrap();
        assert_eq!(v.paid, vec![(1, T0 + 5, "aa".repeat(32))]);
        st.apply_sync_view(V_SUB_KEY, &v, T0).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert!(!rec.needs_sync && rec.terms_behind.is_some());
        assert_eq!(rec.why_not_pay(T0 + 20 * 86_400), Some("terms_behind"));
        let inv2 = check(&t, 2, rec.due(2).unwrap(), T0 + 60, &good(2));
        assert!(inv2.is_err() || st.begin_payment(V_SUB_KEY, &inv2.unwrap(), T0).is_err());
        // the plan fetched again: other terms are refused, the terms the merchant named are adopted
        assert!(st.adopt_terms(V_SUB_KEY, &plan(), T0).unwrap_err().contains("not the terms"));
        let p2 = check_plan(&plan_json(&t2, "https://aoi.example/subs"), "aoi.example").unwrap();
        st.adopt_terms(V_SUB_KEY, &p2, T0 + 9).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert!(rec.terms_behind.is_none()); assert_eq!(rec.plan.terms.grace_days, 10); assert_eq!(rec.past_terms.len(), 1);
        // a sync that names the terms the wallet has changes nothing; ended is ended
        let same = read_sync(V_PLAN_KEY, &serde_json::json!({ "state": "ended", "terms_version": 2, "terms_digest": t2.digest_hex(), "first_due": T0, "paid": [] })).unwrap();
        st.apply_sync_view(V_SUB_KEY, &same, T0).unwrap();
        assert!(st.find(V_SUB_KEY).unwrap().terms_behind.is_none()); assert_eq!(st.find(V_SUB_KEY).unwrap().state, "ended");
        assert!(read_sync(V_PLAN_KEY, &serde_json::json!({ "state": "active", "terms_digest": "xx", "first_due": T0 })).is_err());
        assert!(read_sync(V_PLAN_KEY, &serde_json::json!({ "state": "active", "terms_digest": t2.digest_hex(), "first_due": T0, "paid": [ { "n": 0, "payment_hash": "aa".repeat(32) } ] })).is_err());
        // round 3: a sync answer that carries the terms themselves — taken when they are the terms it names, signed by the plan key
        let t3 = { let mut x = t2.clone(); x.terms_version = 3; x.grace_days = 12; x };
        let with = |terms: &Terms, signer: &[u8; 32]| serde_json::json!({ "state": "active", "terms_version": 3, "terms_digest": t3.digest_hex(), "first_due": T0, "paid": [],
            "terms": serde_json::to_value(terms).unwrap(), "terms_sig": terms.sign(signer).unwrap() });
        assert!(read_sync(V_PLAN_KEY, &with(&t3, &SUB_SK)).unwrap_err().contains("plan key"));
        assert!(read_sync(V_PLAN_KEY, &with(&t2, &PLAN_SK)).is_err(), "terms that are not the terms the answer names");
        let mut st2 = Store::default(); st2.add(record()).unwrap(); st2.mark_restored();
        st2.apply_sync_view(V_SUB_KEY, &read_sync(V_PLAN_KEY, &with(&t3, &PLAN_SK)).unwrap(), T0 + 5).unwrap();
        let rec = st2.find(V_SUB_KEY).unwrap();
        assert!(rec.terms_behind.is_none() && !rec.needs_sync); assert_eq!(rec.plan.terms.grace_days, 12); assert_eq!(rec.past_terms.len(), 1);
        assert_eq!(rec.plan.terms_sig, t3.sign(&PLAN_SK).unwrap());
    }

    #[test]
    fn s71_ending_is_asked_until_answered_and_an_ended_subscription_can_be_forgotten() {
        let mut st = Store::default(); st.add(record()).unwrap();
        assert!(st.forget(V_SUB_KEY).is_err(), "a running subscription is never taken off the list");
        st.end_asked(V_SUB_KEY, "paid_period_end", None, T0 + 10).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert_eq!(rec.state, "ending"); assert_eq!(rec.why_not_pay(T0 + 10), Some("ending")); assert!(!rec.end.as_ref().unwrap().acked);
        assert!(st.reminder_times(T0, 0).is_empty(), "no reminders for a subscription that is ending");
        st.end_taken_back(V_SUB_KEY).unwrap();
        assert_eq!(st.find(V_SUB_KEY).unwrap().state, "active");
        st.end_asked(V_SUB_KEY, "now", Some(RefundTo::Lnaddr("r7k2@p.example".into())), T0 + 20).unwrap();
        let (ends, refund) = read_end(&serde_json::json!({ "status": "OK", "ends": T0 + 500, "refund": { "amount_msat": 1_650_000, "state": "owed" } })).unwrap();
        st.end_acked(V_SUB_KEY, ends, refund, T0 + 30).unwrap();
        assert!(st.end_taken_back(V_SUB_KEY).is_err(), "answered: it cannot be taken back");
        assert_eq!(st.find(V_SUB_KEY).unwrap().state, "ending");
        assert_eq!(st.find(V_SUB_KEY).unwrap().end.as_ref().unwrap().refund, Some(Refund { amount_msat: 1_650_000, state: "owed".into() }));
        assert!(st.tidy(T0 + 500));
        assert_eq!(st.find(V_SUB_KEY).unwrap().state, "ended");
        assert!(st.end_asked(V_SUB_KEY, "now", None, T0).is_err());
        st.forget(V_SUB_KEY).unwrap();
        assert!(st.subs.is_empty());
        assert!(read_end(&serde_json::json!({ "status": "OK" })).is_err());
    }

    #[test]
    fn s71_a_plan_of_fixed_length_ends_when_its_last_paid_period_is_over() {
        let mut t = terms_sat(); t.payments = Some(2); t.price_kept_through = Some(2); t.price.by_payment.truncate(1);
        let mut st = Store::default();
        let mut r = record(); r.plan = check_plan(&plan_json(&t, "https://aoi.example/subs"), "aoi.example").unwrap();
        st.add(r).unwrap();
        st.apply_sync(V_SUB_KEY, &[(1, T0, "a1".repeat(32)), (2, T0, "a2".repeat(32))]).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert!(rec.all_paid()); assert_eq!(rec.why_not_pay(T0), Some("all_paid")); assert!(rec.card(T0)["next"].is_null());
        assert!(st.reminder_times(T0, 0).is_empty());
        let end = st.find(V_SUB_KEY).unwrap().due(3).unwrap();
        assert!(!st.tidy(end - 1)); assert_eq!(st.find(V_SUB_KEY).unwrap().state, "active");
        assert!(st.tidy(end)); assert_eq!(st.find(V_SUB_KEY).unwrap().state, "ended");
    }

    #[test]
    fn s71_reminder_times_are_nine_on_the_phones_clock() {
        let mut st = Store::default();
        let mut r = record();
        r.first_due = days_from_civil(2027, 3, 20) as u64 * 86_400 + 20 * 3_600;   // 20 March 2027, 20:00 UTC = 21 March 01:30 at UTC+5:30
        st.add(r).unwrap();
        let now = days_from_civil(2027, 3, 1) as u64 * 86_400;
        let off = 5 * 3_600 + 1_800;
        let times = st.reminder_times(now, off);
        let nine = |y, m, d| (days_from_civil(y, m, d) as u64 * 86_400 + 9 * 3_600) - off as u64;
        // payment 1: due 21 March on the phone's clock → 7 March, 14 March, 21 March at 09:00 there; then payments 2 and 3
        assert_eq!(&times[..3], &[nine(2027, 3, 7), nine(2027, 3, 14), nine(2027, 3, 21)]);
        assert_eq!(times.len(), 9); assert!(times.windows(2).all(|w| w[0] < w[1]));
        assert!(times.iter().all(|t| *t > now && *t <= now + REMINDER_AHEAD_SECS));
        // a time already past is not handed over; west of UTC the day is the phone's day
        let later = nine(2027, 3, 14) + 1;
        assert_eq!(st.reminder_times(later, off)[0], nine(2027, 3, 21));
        assert_eq!(st.reminder_times(now, -8 * 3_600)[0], days_from_civil(2027, 3, 6) as u64 * 86_400 + 17 * 3_600, "20:00 UTC is 12:00 the same day at UTC−8: 6 March 09:00 there");
        // many subscriptions: the nearest 64, each time once
        let mut many = Store::default();
        for i in 0..40u8 { let mut r = record(); r.sub_key = hex::encode([i; 32]); r.first_due = now + (20 + i as u64) * 86_400; many.add(r).unwrap(); }
        assert_eq!(many.reminder_times(now, off).len(), REMINDER_MAX);
        // a year plan far ahead: nothing beyond 400 days
        let mut y = record(); y.plan.terms.every = Every { unit: "year".into(), count: 1 }; y.first_due = now + 800 * 86_400;
        let mut ys = Store::default(); ys.add(y).unwrap();
        assert!(ys.reminder_times(now, 0).is_empty());
    }

    #[test]
    fn s71_the_card_says_where_a_subscription_stands() {
        let t = terms_sat();
        let mut st = Store::default(); st.add(record()).unwrap();
        let c = st.find(V_SUB_KEY).unwrap().card(T0 + 60);
        assert_eq!(c["merchant_name"], "Kissaten Aoi"); assert_eq!(c["host"], "aoi.example"); assert_eq!(c["state"], "active");
        assert_eq!(c["next"]["n"], 1); assert_eq!(c["next"]["price"]["amount"], "8000"); assert_eq!(c["next"]["pay_state"], "overdue"); assert_eq!(c["next"]["sending"], false);
        assert!(c["why_not_pay"].is_null()); assert!(c["paid_through"].is_null());
        assert!(!c.to_string().contains(&hex::encode(SUB_SK)), "no secret is in a card");
        let inv = check(&t, 1, T0, T0 + 60, &good(1)).unwrap();
        st.begin_payment(V_SUB_KEY, &inv, T0 + 60).unwrap();
        let c = st.find(V_SUB_KEY).unwrap().card(T0 + 61);
        assert_eq!(c["next"]["sending"], true); assert_eq!(c["why_not_pay"], "sending");
        assert_eq!(st.sending(), vec![(V_SUB_KEY.to_string(), inv.payment_hash.clone(), T0 + 600)]);
        st.settle_payment(&inv.payment_hash, &"cd".repeat(32), Some(2_000), T0 + 70);
        let c = st.find(V_SUB_KEY).unwrap().card(T0 + 71);
        assert_eq!(c["next"]["n"], 2); assert_eq!(c["paid_count"], 1); assert_eq!(c["why_not_pay"], "not_yet");
        assert_eq!(c["paid_through"], st.find(V_SUB_KEY).unwrap().due(2).unwrap());
        assert_eq!(c["payments"][0]["preimage"], "cd".repeat(32));
        let lapsed = st.find(V_SUB_KEY).unwrap().due(2).unwrap() + 8 * 86_400;
        assert_eq!(st.find(V_SUB_KEY).unwrap().card(lapsed)["why_not_pay"], "lapsed");
    }

    // ── format round 4: the plan's description, and a change nobody accepted ─────────────────────────────────────────
    #[test]
    fn s71_r4_a_plans_description_is_inside_the_signed_terms() {
        // no description: the sixteen lines and the digest of round 3 — every plan signed before round 4 stays valid
        let t = terms_sat();
        assert_eq!(t.terms_string().lines().count(), 16);
        assert_eq!(t.digest_hex(), V_DIGEST);
        // a description is the seventeenth line; the sidecar's format.test.js (r4-3) holds the same digest
        let mut d = terms_sat(); d.plan_description = Some("A bag of beans each month, roasted the week it ships.".into());
        d.validate().unwrap();
        assert_eq!(d.terms_string(), format!("{}\nplan_description=A bag of beans each month, roasted the week it ships.", t.terms_string()));
        assert_eq!(d.digest_hex(), "6cf73a672e86357132b84ecaaca03d0973f69f9d6401f551bcc345733b4ea2c9");
        // the signature covers it
        let sig = d.sign(&PLAN_SK).unwrap();
        let key = public_hex(&PLAN_SK).unwrap();
        assert!(verify_digest(&key, d.digest(), &sig));
        assert!(!verify_digest(&key, t.digest(), &sig), "the same plan without the description is other terms");
        let mut other = d.clone(); other.plan_description = Some("A bag of beans each week.".into());
        assert!(!verify_digest(&key, other.digest(), &sig));
        // the limits: 1–140 characters, no line break
        let bad = |v: &str| { let mut x = terms_sat(); x.plan_description = Some(v.into()); x.validate().is_err() };
        assert!(bad("") && bad(&"x".repeat(141)) && bad("a\nb"));
        assert!(!bad(&"x".repeat(140)) && !bad("豆を毎月お届けします"));
        // it travels as JSON: absent stays absent, present comes back the same
        assert!(!serde_json::to_string(&t).unwrap().contains("plan_description"));
        let back = parse_terms(&serde_json::to_value(&d).unwrap()).unwrap();
        assert_eq!(back, d);
        assert_eq!(parse_terms(&serde_json::json!({ "terms_version": 1, "merchant_name": "M", "plan_name": "P", "plan_description": null,
            "price": { "unit": "sat", "by_payment": [{ "from": 1, "amount": "5" }] }, "every": { "unit": "week", "count": 1 }, "first_payment": { "rule": "on_agree" },
            "grace_days": 0, "ending": { "refund": "none" }, "change_notice_days": 7, "pay_by": ["lightning"], "lightning": { "nodes": [node_hex()] } })).unwrap().plan_description, None);
        // a change of the description alone is a change of terms like any other: allowed with its notice
        let mut v2 = d.clone(); v2.terms_version = 2; v2.plan_description = Some("Two bags of beans each month.".into());
        assert!(change_allowed(&d, &v2, T0 + 30 * 86_400, T0).is_ok());
        let mut v2b = d.clone(); v2b.terms_version = 2; v2b.plan_description = None;
        assert!(change_allowed(&d, &v2b, T0 + 30 * 86_400, T0).is_ok());
        // the card hands the page the terms, description and all
        let mut r = record(); r.plan = check_plan(&plan_json(&d, "https://aoi.example/subs"), "aoi.example").unwrap();
        assert_eq!(r.card(T0)["terms"]["plan_description"], "A bag of beans each month, roasted the week it ships.");
        // the sidecar's own plan with a description passes the wallet's checks
        let fx: serde_json::Value = serde_json::from_str(include_str!("testdata/subs_sidecar.json")).unwrap();
        let p = check_plan(&fx["plan_described"].to_string(), "lsp.example.com").expect("the sidecar's described plan passes the wallet's checks");
        assert_eq!(p.terms.plan_description.as_deref(), Some("A bag of beans each month, roasted the week it ships."));
    }

    #[test]
    fn s71_r4_a_change_nobody_accepted_stops_pay_from_its_start() {
        let mut base = terms_sat(); base.price_kept_through = Some(1);
        let mut st = Store::default();
        let mut r = record(); r.plan = check_plan(&plan_json(&base, "https://aoi.example/subs"), "aoi.example").unwrap();
        st.add(r).unwrap();
        // an invoice the plan server makes at `at` for payment n, at the price the terms `t` give it
        let made = |t: &Terms, n: u32, at: u64| answer(t, n, msat_for(t.price_for(n).unwrap(), "1").unwrap(), &invoice_description("coffee-club", n, &payment_tag(&k(), n)), &NODE_SK, &PLAN_SK, at, 600, None, n as u8);
        // payment 1 is paid
        let inv1 = check(&base, 1, T0, T0 + 60, &good(1)).unwrap();
        st.begin_payment(V_SUB_KEY, &inv1, T0 + 60).unwrap();
        assert!(st.settle_payment(&inv1.payment_hash, &"11".repeat(32), None, T0 + 61));
        let (due2, due3) = { let r = st.find(V_SUB_KEY).unwrap(); (r.due(2).unwrap(), r.due(3).unwrap()) };
        // a change is offered; it starts between the day payment 2 is due and the day payment 3 is due
        let t2 = { let mut t = base.clone(); t.terms_version = 2; t.price.by_payment = vec![PriceStep { from: 1, amount: "8000".into() }, PriceStep { from: 2, amount: "9500".into() }]; t };
        let starts = due2 + 86_400;
        let offer = ChangeOffer { terms: t2.clone(), terms_sig: t2.sign(&PLAN_SK).unwrap(), starts, notice_given: starts - 30 * 86_400, seen_at: 0 };
        let view = |change: Option<ChangeOffer>, next_n| StatusView { state: "active".into(), paid_through: None, next_n, line: None, ended: None, change, change_refused: None, receipt: None, refund: None };
        st.apply_status(V_SUB_KEY, &view(Some(offer.clone()), Some(2)), T0 + 100).unwrap();
        // payment 2 is due before the start: Pay is offered, under the agreed terms
        let rec = st.find(V_SUB_KEY).unwrap();
        assert!(!rec.change_applies(2) && rec.change_applies(3));
        assert_eq!(rec.why_not_pay(due2 - 86_400), None);
        assert_eq!(rec.card(due2 - 86_400)["next"]["price"]["amount"], "8000");
        let inv2 = check(&base, 2, due2, due2 - 86_400, &made(&base, 2, due2 - 86_400)).unwrap();
        st.begin_payment(V_SUB_KEY, &inv2, due2 - 86_400).unwrap();
        assert!(st.settle_payment(&inv2.payment_hash, &"22".repeat(32), None, due2 - 86_399));
        // payment 3 is due after the start and the change is not accepted: no Pay under the old terms — not in its
        // payable days, not in its grace days — and a payment cannot be started either
        let rec = st.find(V_SUB_KEY).unwrap();
        assert_eq!(rec.why_not_pay(due3 - 20 * 86_400), Some("not_yet"));
        assert_eq!(rec.why_not_pay(due3 - 86_400), Some("change_pending"));
        assert_eq!(rec.why_not_pay(due3 + 3 * 86_400), Some("change_pending"));
        assert_eq!(rec.card(due3)["why_not_pay"], "change_pending");
        assert_eq!(rec.why_not_pay(due3 + 8 * 86_400), Some("lapsed"), "unpaid, it lapses after its grace days like any other");
        let inv3_old = check(&base, 3, due3, due3 - 86_400, &made(&base, 3, due3 - 86_400)).unwrap();
        assert_eq!(st.begin_payment(V_SUB_KEY, &inv3_old, due3 - 86_400).unwrap_err(), "change_pending");
        assert!(st.find(V_SUB_KEY).unwrap().payments.iter().all(|p| p.n != 3), "nothing is on record for payment 3");
        // accepted: payment 3 is offered again, at the new price
        st.accept_change(V_SUB_KEY, None, due3 - 86_400).unwrap();
        let rec = st.find(V_SUB_KEY).unwrap();
        assert_eq!(rec.why_not_pay(due3 - 86_400), None);
        assert_eq!(rec.terms_at(3).price_for(3), Some("9500"));
        // a change the merchant took back (the status no longer carries it): Pay is offered under the agreed terms
        let mut st2 = Store::default();
        let mut r2 = record(); r2.plan = check_plan(&plan_json(&base, "https://aoi.example/subs"), "aoi.example").unwrap();
        st2.add(r2).unwrap();
        st2.apply_sync(V_SUB_KEY, &[(1, T0, "a1".repeat(32)), (2, T0, "a2".repeat(32))]).unwrap();
        st2.apply_status(V_SUB_KEY, &view(Some(offer), Some(3)), T0 + 100).unwrap();
        assert_eq!(st2.find(V_SUB_KEY).unwrap().why_not_pay(due3), Some("change_pending"));
        st2.apply_status(V_SUB_KEY, &view(None, Some(3)), T0 + 200).unwrap();
        assert_eq!(st2.find(V_SUB_KEY).unwrap().why_not_pay(due3), None);
    }

    // ── the plan sidecar's own answers (the lijox-subscriptions repository, service.test.js writes them) ────────────
    /// What the sidecar answers must pass the wallet's checks, and what the wallet signs must be what the sidecar
    /// checked: two implementations, one format. The file is the sidecar test's output, copied here unchanged.
    #[test]
    fn s71_the_sidecars_answers_pass_the_wallets_checks() {
        let fx: serde_json::Value = serde_json::from_str(include_str!("testdata/subs_sidecar.json")).unwrap();
        let t0 = fx["t0"].as_u64().unwrap();
        let mut sub_sk = [0u8; 32]; hex::decode_to_slice(fx["sub_sk"].as_str().unwrap(), &mut sub_sk).unwrap();
        let sub_key = public_hex(&sub_sk).unwrap();
        // a business's plan, by its plan code
        let pc = parse_plan_code(fx["plan_code"].as_str().unwrap()).unwrap();
        assert_eq!((pc.host.as_str(), pc.url.as_str()), ("lsp.example.com", "https://lsp.example.com/subs/p/coffee-club"));
        let plan = check_plan(&fx["plan"].to_string(), &pc.host).expect("the sidecar's plan passes the wallet's checks");
        assert_eq!(plan.server, "https://lsp.example.com/subs/p/coffee-club");
        // the agreement: the wallet's bytes are the bytes the sidecar verified, and its answer passes
        let mine = agree_body(&sub_sk, &plan, None, t0).unwrap();
        assert_eq!(mine, fx["agree"]["body"], "the wallet signs the same agreement the sidecar's test wallet signed — same string, same signature");
        let agreed = check_agreed(&plan, &sub_key, &read_answer(&fx["agree"]["answer"].to_string()).unwrap(), fx["agree"]["at"].as_u64().unwrap()).unwrap();
        assert!(agreed.receipt.is_some() && agreed.first_due == t0);
        // sync: what is paid, and the terms themselves
        let sv = read_sync(&plan.plan_key, &read_answer(&fx["sync"]["answer"].to_string()).unwrap()).unwrap();
        assert_eq!((sv.paid.len(), sv.paid[0].0, sv.first_due), (1, 1, t0));
        assert_eq!(sv.terms.as_ref().unwrap().0, plan.terms);
        // a status that offers a change: the wallet's own rule allows it
        let st = read_status(&plan, &sub_key, t0, &read_answer(&fx["status"]["answer"].to_string()).unwrap()).unwrap();
        assert!(st.change_refused.is_none(), "{:?}", st.change_refused);
        let offer = st.change.expect("the change is an offer");
        assert_eq!((offer.terms.terms_version, st.next_n, st.receipt.is_some()), (2, Some(2), true));
        // the accept: the wallet's body for that change, and the sidecar's receipt over the new terms
        let acc_terms: Terms = serde_json::from_value(fx["accept"]["terms"].clone()).unwrap();
        assert_eq!(acc_terms, offer.terms);
        assert!(check_accepted(&plan.plan_id, &plan.plan_key, &acc_terms, &sub_key, &read_answer(&fx["accept"]["answer"].to_string()).unwrap()).unwrap().is_some());
        // the end, with the refund owed
        let (ends, refund) = read_end(&read_answer(&fx["end"]["answer"].to_string()).unwrap()).unwrap();
        assert!(ends > t0 && refund.as_ref().map(|r| r.state == "owed" && r.amount_msat > 8_000_000).unwrap_or(false));
        // a wallet user who sells: the plan under /s/<seller>/<plan>, the receipt pending at first and arriving with a status
        let spc = parse_plan_code(fx["seller_plan_code"].as_str().unwrap()).unwrap();
        let splan = check_plan(&fx["seller_plan"].to_string(), &spc.host).expect("a seller's plan passes the same checks");
        assert_eq!(agree_body(&sub_sk, &splan, None, t0).unwrap(), fx["seller_agree"]["body"]);
        let sa = check_agreed(&splan, &sub_key, &read_answer(&fx["seller_agree"]["answer"].to_string()).unwrap(), fx["seller_agree"]["at"].as_u64().unwrap()).unwrap();
        assert!(sa.receipt.is_none(), "pending until the seller's phone opens");
        let ss = read_status(&splan, &sub_key, sa.first_due, &read_answer(&fx["seller_status"]["answer"].to_string()).unwrap()).unwrap();
        assert!(ss.receipt.is_some(), "the seller's receipt, signed on its phone, verifies against the plan key");
        // the refund's fifth state
        assert_eq!(read_refund(&serde_json::json!({ "refund": { "amount_msat": 5, "state": "expired" } })), Some(Refund { amount_msat: 5, state: "expired".into() }));
        let mut st2 = Store::default(); st2.add(record()).unwrap();
        assert!(st2.refund_readdress(V_SUB_KEY, RefundTo::Lnaddr("a@b".into()), T0).is_err(), "nothing to re-address before an end");
        st2.end_asked(V_SUB_KEY, "now", Some(RefundTo::Lnaddr("once--k7q2m9x4t2ab@p.example".into())), T0).unwrap();
        st2.end_acked(V_SUB_KEY, T0 + 5, Some(Refund { amount_msat: 9, state: "expired".into() }), T0 + 1).unwrap();
        st2.refund_readdress(V_SUB_KEY, RefundTo::Lnaddr("once--m3x8q2k9a7bc@p.example".into()), T0 + 9).unwrap();
        let e = st2.find(V_SUB_KEY).unwrap().end.clone().unwrap();
        assert!(!e.acked && e.refund_to == Some(RefundTo::Lnaddr("once--m3x8q2k9a7bc@p.example".into())));
    }
}
