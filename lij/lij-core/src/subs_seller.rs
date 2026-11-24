//! S71 (Thu 2026-11-19): LIJOX SUBSCRIPTIONS — A LiJ WALLET USER WHO SELLS (format §13, "Plans you sell").
//!
//! The public side of a seller's plans is served by its provider's sidecar, which holds NO key of the seller. Every
//! signature is made here, on the seller's phone, with the one selling key (key.rs `subs_seller_key`):
//!   - the terms of each plan (and of each later version of it);
//!   - the receipt of each agreement — after checking the subscriber's own signature and the first due date;
//!   - each selling hash the phone registers with its provider (`hash_sig`, which the paying wallet checks).
//! And the one check nobody else can make: a payment that arrives on a selling hash is TAKEN ONLY IF its description
//! carries the tag of a subscriber this phone knows, for a payment number that subscriber has not paid. Anything else
//! goes back to the payer. The sidecar cannot work out a tag (it has no key), so it cannot make the phone take a
//! payment for a subscriber that does not exist — and the phone never takes a second payment for the same number.
//!
//! This file is the records and the decisions; it has no network. node.rs holds the payment (claim / fail back) and
//! the selling hashes; the page carries the requests.

use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};
use crate::subscriptions::{self as subs, Terms};

/// The seller's records (encrypted at rest; in every backup).
pub const SELLER_KEY: &str = "lij_subs_seller";
/// Taken payments kept on the phone (the sidecar keeps the whole list).
pub const RECEIVED_KEEP: usize = 1_000;
/// The expected tags handed to the sidecar for each subscriber: this many payment numbers from the first unpaid.
pub const TAGS_AHEAD: u32 = 3;

fn err(m: impl Into<String>) -> LijError { LijError::Payment(m.into()) }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTerms { pub terms: Terms, pub terms_sig: String, pub made_at: u64 }

/// A plan this phone signed. `versions` holds every version of its terms, the newest last: a subscriber stays under
/// the version it agreed to until it accepts a newer one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SellerPlan {
    pub plan_id: String,
    pub versions: Vec<SignedTerms>,
    /// takes no new subscribers
    #[serde(default)] pub closed: bool,
}

impl SellerPlan {
    pub fn current(&self) -> Option<&SignedTerms> { self.versions.last() }
    fn by_digest(&self, digest: &str) -> Option<&SignedTerms> { self.versions.iter().find(|v| v.terms.digest_hex() == digest) }
}

/// A subscriber the phone has checked: its agreement carried its own signature, under terms this phone signed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscriber {
    pub plan_id: String,
    pub sub_key: String,
    pub first_due: u64,
    pub terms_digest: String,
    #[serde(default)] pub paid: Vec<u32>,
    #[serde(default)] pub ended: bool,
}

/// A payment that arrived on a selling hash. It is held, not taken, until the phone has decided; once decided for,
/// `claiming` says whose payment it is while LDK completes the claim (the record is written when LDK says claimed).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Waiting {
    pub hash: String,
    pub amount_msat: u64,
    pub since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub claiming: Option<Claiming>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claiming { pub plan_id: String, pub sub_key: String, pub n: u32, pub invoice_msat: u64 }

/// A waiting entry older than this is dropped: the provider's hold and the payment's own timelock are long over, and
/// LDK has sent it back by itself.
pub const WAITING_KEEP_SECS: u64 = 3 * 86_400;

/// A payment the phone took: what the subscriber paid (the invoice) and what reached this wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Received { pub hash: String, pub plan_id: String, pub sub_key: String, pub n: u32, pub invoice_msat: u64, pub received_msat: u64, pub at: u64 }

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SellerStore {
    /// "Plans you sell" is in use on this wallet
    #[serde(default)] pub on: bool,
    /// the next selling-hash index (key.rs `subs_seller_preimage`)
    #[serde(default)] pub next_index: u32,
    #[serde(default)] pub plans: Vec<SellerPlan>,
    #[serde(default)] pub subscribers: Vec<Subscriber>,
    #[serde(default)] pub waiting: Vec<Waiting>,
    #[serde(default)] pub received: Vec<Received>,
}

/// What the phone decided about a waiting payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// take it: it is this subscriber's payment number n
    Take { plan_id: String, sub_key: String, n: u32, invoice_msat: u64 },
    /// the tag matches no subscriber the phone knows YET — fetch the subscribers again before deciding
    AskAgain(String),
    /// not taken: it goes back to the payer
    Refuse(String),
}

impl SellerStore {
    pub fn plan(&self, plan_id: &str) -> Option<&SellerPlan> { self.plans.iter().find(|p| p.plan_id == plan_id) }

    /// A new plan, or a new version of one: the terms are checked against the format's limits and signed with the
    /// selling key. A LiJ seller's plan is paid by Lightning to its provider's node, so `lightning.nodes` must name
    /// `provider_node` and nothing else (the paying wallet's first check), and `pay_by` is Lightning alone.
    pub fn sign_plan(&mut self, seller_sk: &[u8; 32], plan_id: &str, mut terms: Terms, provider_node: &str, now: u64) -> LijResult<SignedTerms> {
        if !subs::name_ok(plan_id, 40) { return Err(err("the plan id: letters, digits, - _ . only, at most 40")); }
        terms.pay_by = vec!["lightning".into()];
        terms.lightning = Some(subs::LightningTerms { nodes: vec![provider_node.to_ascii_lowercase()] });
        terms.onchain = None;
        // the description: spaces tidied; an empty one is no description (format round 4 §1)
        terms.plan_description = terms.plan_description.take().map(|d| d.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|d| !d.is_empty());
        let prior = self.plan(plan_id).and_then(|p| p.current()).cloned();
        terms.terms_version = prior.as_ref().map(|p| p.terms.terms_version + 1).unwrap_or(1);
        terms.validate().map_err(err)?;
        if let Some(p) = &prior {
            if p.terms == (Terms { terms_version: p.terms.terms_version, ..terms.clone() }) { return Err(err("these are the plan's terms already")); }
            // the same rule the paying wallet applies to an offered change, so the seller cannot sign a change its
            // subscribers' wallets will refuse (the notice dates are the sidecar's; here: the rhythm and the kept price)
            subs::change_allowed(&p.terms, &terms, u64::MAX, 0).map_err(err)?;
        }
        let signed = SignedTerms { terms_sig: terms.sign(seller_sk)?, terms, made_at: now };
        match self.plans.iter_mut().find(|p| p.plan_id == plan_id) {
            Some(p) => p.versions.push(signed.clone()),
            None => self.plans.push(SellerPlan { plan_id: plan_id.to_string(), versions: vec![signed.clone()], closed: false }),
        }
        Ok(signed)
    }

    /// The sidecar's list of this seller's subscribers, checked one by one, and the work that follows from it:
    /// receipts the phone signs now (`receipts`), the tags it expects next (`tags`), entries it does not accept
    /// (`refused`, with the reason). The checked subscribers replace the phone's own list.
    ///
    /// `state` = {"subscribers":[{"plan_id","agree":{…the subscriber's signed body…},"first_due","receipt",
    /// "paid":[{"n",…}],"accepted":[{…signed accept bodies…}],"ended":bool}]}.
    pub fn work(&mut self, seller_sk: &[u8; 32], state: &serde_json::Value) -> LijResult<serde_json::Value> {
        let seller_pub = subs::public_hex(seller_sk)?;
        let (mut receipts, mut tags, mut refused, mut checked) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for e in state.get("subscribers").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let plan_id = e.get("plan_id").and_then(|x| x.as_str()).unwrap_or("");
            let agree = e.get("agree").cloned().unwrap_or(serde_json::Value::Null);
            let sub_key = agree.get("sub_key").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut refuse = |why: &str| refused.push(serde_json::json!({ "plan_id": plan_id, "sub_key": sub_key, "why": why }));
            let Some(plan) = self.plan(plan_id) else { refuse("this phone signed no such plan"); continue };
            let digest = agree.get("terms_digest").and_then(|x| x.as_str()).unwrap_or("");
            let Some(agreed) = plan.by_digest(digest) else { refuse("the agreement is to terms this phone did not sign"); continue };
            let first_due = e.get("first_due").and_then(|x| x.as_u64()).unwrap_or(0);
            // the receipt is made again from the checks, never copied from the sidecar: signing is deterministic, so a
            // receipt the sidecar already holds is the same bytes
            let receipt = match subs::seller_receipt(seller_sk, plan_id, &agreed.terms, &agree, first_due) { Ok(r) => r, Err(x) => { refuse(&x.to_string()); continue } };
            if e.get("receipt").and_then(|x| x.as_str()) != Some(receipt.as_str()) {
                receipts.push(serde_json::json!({ "plan_id": plan_id, "sub_key": sub_key, "receipt": receipt }));
            }
            // a later version the subscriber accepted (its own signature over the accept) is the version it is under
            let mut under = agreed;
            for a in e.get("accepted").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
                let d = a.get("terms_digest").and_then(|x| x.as_str()).unwrap_or("");
                let (ts, sig) = (a.get("ts").and_then(|x| x.as_u64()).unwrap_or(0), a.get("sig").and_then(|x| x.as_str()).unwrap_or(""));
                if let Some(v) = plan.by_digest(d) {
                    let c = subs::canon("accept", &[plan_id, &sub_key, &v.terms.terms_version.to_string(), d, &ts.to_string()]);
                    if v.terms.terms_version > under.terms.terms_version && subs::verify_canonical(&sub_key, &c, sig) {
                        under = v;
                        let r = subs::sign_canonical(seller_sk, &subs::accepted_canonical(plan_id, d, &sub_key))?;
                        if a.get("receipt").and_then(|x| x.as_str()) != Some(r.as_str()) {
                            receipts.push(serde_json::json!({ "plan_id": plan_id, "sub_key": sub_key, "terms_digest": d, "receipt": r }));
                        }
                    }
                }
            }
            let mut paid: Vec<u32> = e.get("paid").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|p| p.get("n").and_then(|n| n.as_u64()).and_then(|n| u32::try_from(n).ok())).collect()).unwrap_or_default();
            // what this phone itself took counts even if the sidecar has not heard of it yet
            paid.extend(self.received.iter().filter(|r| r.plan_id == plan_id && r.sub_key == sub_key).map(|r| r.n));
            paid.sort_unstable(); paid.dedup();
            let ended = e.get("ended").and_then(|x| x.as_bool()).unwrap_or(false);
            if !ended {
                let k = subs::shared_secret(seller_sk, &sub_key)?;
                let mut n = 1; while paid.contains(&n) { n += 1; }
                for i in n..n.saturating_add(TAGS_AHEAD) {
                    if under.terms.payments.map(|p| i > p).unwrap_or(false) { break; }
                    tags.push(serde_json::json!({ "plan_id": plan_id, "sub_key": sub_key, "n": i, "tag": subs::payment_tag(&k, i) }));
                }
            }
            checked.push(Subscriber { plan_id: plan_id.to_string(), sub_key, first_due, terms_digest: under.terms.digest_hex(), paid, ended });
        }
        let count = checked.len();
        self.subscribers = checked;
        Ok(serde_json::json!({ "plan_key": seller_pub, "receipts": receipts, "tags": tags, "refused": refused, "subscribers": count }))
    }

    /// A payment arrived on a selling hash. Idempotent.
    pub fn note_waiting(&mut self, hash: &str, amount_msat: u64, now: u64) -> bool {
        if self.waiting.iter().any(|w| w.hash == hash) || self.received.iter().any(|r| r.hash == hash) { return false; }
        self.waiting.push(Waiting { hash: hash.to_string(), amount_msat, since: now, claiming: None });
        true
    }

    /// Is payment n of this subscriber paid, or being claimed right now?
    fn has_paid(&self, plan_id: &str, sub_key: &str, n: u32) -> bool {
        self.subscribers.iter().any(|s| s.plan_id == plan_id && s.sub_key == sub_key && s.paid.contains(&n))
            || self.received.iter().any(|r| r.plan_id == plan_id && r.sub_key == sub_key && r.n == n)
            || self.waiting.iter().any(|w| w.claiming.as_ref().map(|c| c.plan_id == plan_id && c.sub_key == sub_key && c.n == n).unwrap_or(false))
    }

    /// The payments not decided yet (the page asks the provider for each one's description).
    pub fn undecided(&self) -> Vec<&Waiting> { self.waiting.iter().filter(|w| w.claiming.is_none()).collect() }

    /// Old entries are dropped; true when any was.
    pub fn age_out(&mut self, now: u64) -> bool {
        let before = self.waiting.len();
        self.waiting.retain(|w| w.since + WAITING_KEEP_SECS > now);
        before != self.waiting.len()
    }

    /// THE DECISION. `description` is what the provider says the invoice on this hash said; `invoice_msat` what it
    /// asked for. Taken only when the description is a subscription's, its tag is a known subscriber's for that
    /// payment number, and that number is not paid.
    pub fn decide(&self, seller_sk: &[u8; 32], hash: &str, description: Option<&str>, invoice_msat: u64) -> Decision {
        if !self.waiting.iter().any(|w| w.hash == hash && w.claiming.is_none()) { return Decision::Refuse("no payment is waiting on this hash".into()); }
        let Some((plan_id, n, tag)) = description.and_then(subs::parse_description) else { return Decision::Refuse("the invoice on this hash was not a subscription's".into()) };
        let Some(plan) = self.plan(&plan_id) else { return Decision::Refuse("this phone signed no such plan".into()) };
        for s in self.subscribers.iter().filter(|s| s.plan_id == plan_id && !s.ended) {
            let Ok(k) = subs::shared_secret(seller_sk, &s.sub_key) else { continue };
            if subs::payment_tag(&k, n) != tag { continue; }
            if self.has_paid(&plan_id, &s.sub_key, n) { return Decision::Refuse(format!("payment {n} of this subscriber is paid already")); }
            let terms = plan.by_digest(&s.terms_digest).or(plan.current()).map(|v| &v.terms);
            let Some(price) = terms.and_then(|t| t.price_for(n)) else { return Decision::Refuse(format!("the plan has no payment {n}")) };
            // a sats plan's invoice is the price exactly; a currency plan's amount was set at the sidecar's rate, which
            // the paying wallet's user saw and accepted at Review
            if terms.map(|t| t.price.unit == "sat").unwrap_or(false) && subs::msat_for(price, "1").ok() != Some(invoice_msat) {
                return Decision::Refuse("the invoice was not for the plan's price".into());
            }
            return Decision::Take { plan_id, sub_key: s.sub_key.clone(), n, invoice_msat };
        }
        Decision::AskAgain("the tag is no known subscriber's".into())
    }

    /// The phone decided to take it: marked while LDK completes the claim. From here the number counts as paid.
    pub fn claiming(&mut self, hash: &str, plan_id: &str, sub_key: &str, n: u32, invoice_msat: u64) -> bool {
        match self.waiting.iter_mut().find(|w| w.hash == hash && w.claiming.is_none()) {
            Some(w) => { w.claiming = Some(Claiming { plan_id: plan_id.to_string(), sub_key: sub_key.to_string(), n, invoice_msat }); true }
            None => false,
        }
    }

    /// LDK says the payment on this hash is claimed: it leaves the waiting list for the record. Returns the record
    /// when the hash was one being claimed.
    pub fn claimed(&mut self, hash: &str, received_msat: u64, now: u64) -> Option<Received> {
        let i = self.waiting.iter().position(|w| w.hash == hash && w.claiming.is_some())?;
        let w = self.waiting.remove(i);
        let c = w.claiming?;
        let r = Received { hash: hash.to_string(), plan_id: c.plan_id, sub_key: c.sub_key, n: c.n, invoice_msat: c.invoice_msat, received_msat, at: now };
        self.received.push(r.clone());
        if self.received.len() > RECEIVED_KEEP { let over = self.received.len() - RECEIVED_KEEP; self.received.drain(..over); }
        if let Some(s) = self.subscribers.iter_mut().find(|s| s.plan_id == r.plan_id && s.sub_key == r.sub_key) { if !s.paid.contains(&r.n) { s.paid.push(r.n); } }
        Some(r)
    }

    /// The payment was sent back, or left by itself (the provider's hold ended): off the waiting list.
    pub fn gone(&mut self, hash: &str) -> bool {
        let before = self.waiting.len();
        self.waiting.retain(|w| w.hash != hash);
        before != self.waiting.len()
    }
}

/// A subscriber's end, checked before the seller is shown a refund to pay: the end is signed by the subscription key.
/// Returns (when, the refund address as the canonical text) — the sidecar's word alone moves no money.
pub fn check_end(plan_id: &str, end: &serde_json::Value) -> Result<(String, String), String> {
    let g = |k: &str| end.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (sub_key, when, sig) = (g("sub_key"), g("when"), g("sig"));
    let ts = end.get("ts").and_then(|x| x.as_u64()).unwrap_or(0);
    let refund_to = match end.get("refund_to") {
        Some(r) if r.is_object() => {
            let (kind, val) = r.as_object().and_then(|o| o.iter().next()).map(|(k, v)| (k.as_str(), v.as_str().unwrap_or(""))).unwrap_or(("", ""));
            if !matches!(kind, "lnaddr" | "pr" | "addr") || val.is_empty() || val.contains('|') { return Err("the refund address does not read".into()); }
            format!("{kind}:{val}")
        }
        _ => String::new(),
    };
    if g("plan_id") != plan_id { return Err("the end is for another plan".into()); }
    if when != "now" && when != "paid_period_end" { return Err("the end names no time".into()); }
    let c = subs::canon("end", &[plan_id, &sub_key, &when, &refund_to, &ts.to_string()]);
    if !subs::verify_canonical(&sub_key, &c, &sig) { return Err("the end is not signed by its subscription key".into()); }
    Ok((when, refund_to))
}

pub fn load(storage: &dyn crate::storage::LijStorage) -> LijResult<SellerStore> {
    match storage.get(SELLER_KEY)? {
        Some(b) => serde_json::from_slice(&b).map_err(|e| LijError::Storage(format!("seller records parse: {e}"))),
        None => Ok(SellerStore::default()),
    }
}

pub fn save(storage: &dyn crate::storage::LijStorage, s: &SellerStore) -> LijResult<()> {
    let b = serde_json::to_vec(s).map_err(|e| LijError::Storage(format!("seller records serialize: {e}")))?;
    storage.set(SELLER_KEY, &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscriptions::{agree_body, check_plan, end_body, invoice_description, payment_tag, public_hex, shared_secret, Ending, Every, FirstPayment, Plan, Price, PriceStep, RefundTo};

    const SELLER_SK: [u8; 32] = [0x31; 32];
    const SUB_A: [u8; 32] = [0x11; 32];
    const SUB_B: [u8; 32] = [0x12; 32];
    const NODE: &str = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c";
    const T0: u64 = 1_790_000_000;

    fn draft() -> Terms {
        Terms { terms_version: 0, merchant_name: "Mika".into(), plan_name: "Bread box".into(),
            price: Price { unit: "sat".into(), by_payment: vec![PriceStep { from: 1, amount: "5000".into() }] }, every: Every { unit: "week".into(), count: 1 },
            first_payment: FirstPayment { rule: "on_agree".into(), date: None, days: None }, payments: None, price_kept_through: Some(4), grace_days: 3,
            ending: Ending { refund: "none".into() }, change_notice_days: 14, pay_by: vec![], lightning: None, onchain: None, free_days_need: None, plan_description: None }
    }

    fn seller() -> SellerStore {
        let mut s = SellerStore { on: true, ..Default::default() };
        s.sign_plan(&SELLER_SK, "bread", draft(), NODE, T0).unwrap();
        s
    }

    /// The plan as the sidecar serves it, read by a paying wallet.
    fn served(s: &SellerStore) -> Plan {
        let v = s.plan("bread").unwrap().current().unwrap();
        let j = serde_json::json!({ "v": 1, "tag": "lijoxSubsPlan", "plan_id": "bread", "plan_key": public_hex(&SELLER_SK).unwrap(), "server": "https://p.example/s/abc",
            "terms": serde_json::to_value(&v.terms).unwrap(), "terms_sig": v.terms_sig }).to_string();
        check_plan(&j, "p.example").unwrap()
    }

    fn entry(s: &SellerStore, sub_sk: &[u8; 32], paid: &[u32]) -> serde_json::Value {
        serde_json::json!({ "plan_id": "bread", "agree": agree_body(sub_sk, &served(s), None, T0).unwrap(), "first_due": T0, "receipt": null,
            "paid": paid.iter().map(|n| serde_json::json!({ "n": n })).collect::<Vec<_>>() })
    }

    #[test]
    fn s71_a_sellers_plan_is_signed_on_the_phone_and_a_paying_wallet_accepts_it() {
        let s = seller();
        let p = served(&s);
        assert_eq!(p.terms.terms_version, 1);
        assert_eq!(p.terms.pay_by, vec!["lightning".to_string()]);
        assert_eq!(p.terms.lightning.as_ref().unwrap().nodes, vec![NODE.to_string()], "a LiJ seller's plan names its provider's node");
        assert_eq!(p.plan_key, public_hex(&SELLER_SK).unwrap());
        let mut bad = SellerStore::default();
        assert!(bad.sign_plan(&SELLER_SK, "a|b", draft(), NODE, T0).is_err());
        assert!(bad.sign_plan(&SELLER_SK, "bread", Terms { grace_days: 99, ..draft() }, NODE, T0).is_err(), "outside the format's limits");
        assert!(bad.sign_plan(&SELLER_SK, "bread", draft(), "02ff", T0).is_err(), "not a node key");
        assert!(bad.plans.is_empty());
        // round 4: a description is tidied and signed; an empty one is no description
        let mut d = SellerStore::default();
        let signed = d.sign_plan(&SELLER_SK, "bread", Terms { plan_description: Some("  A loaf   each week. ".into()), ..draft() }, NODE, T0).unwrap();
        assert_eq!(signed.terms.plan_description.as_deref(), Some("A loaf each week."));
        assert!(signed.terms.terms_string().ends_with("\nplan_description=A loaf each week."));
        assert_eq!(d.sign_plan(&SELLER_SK, "rolls", Terms { plan_description: Some("   ".into()), ..draft() }, NODE, T0).unwrap().terms.plan_description, None);
        assert!(d.sign_plan(&SELLER_SK, "buns", Terms { plan_description: Some("x".repeat(141)), ..draft() }, NODE, T0).is_err());
        // a new description alone is a new version of the terms
        let v2 = d.sign_plan(&SELLER_SK, "bread", Terms { plan_description: Some("Two loaves each week.".into()), ..draft() }, NODE, T0 + 5).unwrap();
        assert_eq!(v2.terms.terms_version, 2);
    }

    #[test]
    fn s71_a_new_version_keeps_the_rhythm_and_the_kept_price() {
        let mut s = seller();
        assert!(s.sign_plan(&SELLER_SK, "bread", draft(), NODE, T0).unwrap_err().to_string().contains("already"));
        let mut dearer = draft(); dearer.price.by_payment.push(PriceStep { from: 3, amount: "6000".into() });
        assert!(s.sign_plan(&SELLER_SK, "bread", dearer, NODE, T0).unwrap_err().to_string().contains("kept"), "payments 1–4 keep their price");
        let mut other_rhythm = draft(); other_rhythm.every.count = 2;
        assert!(s.sign_plan(&SELLER_SK, "bread", other_rhythm, NODE, T0).is_err());
        let mut later = draft(); later.price.by_payment.push(PriceStep { from: 5, amount: "6000".into() });
        let v2 = s.sign_plan(&SELLER_SK, "bread", later, NODE, T0 + 5).unwrap();
        assert_eq!(v2.terms.terms_version, 2);
        assert_eq!(s.plan("bread").unwrap().versions.len(), 2);
    }

    #[test]
    fn s71_the_phone_signs_receipts_only_for_agreements_it_can_check() {
        let mut s = seller();
        let (a, b) = (entry(&s, &SUB_A, &[]), entry(&s, &SUB_B, &[1]));
        let mut forged = entry(&s, &SUB_A, &[]); forged["agree"]["sub_key"] = public_hex(&[0x55; 32]).unwrap().into();   // the sidecar invents a subscriber
        let mut other_plan = entry(&s, &SUB_A, &[]); other_plan["plan_id"] = "cake".into();
        let mut late = entry(&s, &SUB_A, &[]); late["first_due"] = (T0 + 40 * 86_400).into();   // a first due date the terms do not give
        let out = s.work(&SELLER_SK, &serde_json::json!({ "subscribers": [a, b, forged, other_plan, late] })).unwrap();
        assert_eq!(out["subscribers"], 2);
        assert_eq!(out["receipts"].as_array().unwrap().len(), 2);
        assert_eq!(out["refused"].as_array().unwrap().len(), 3);
        // the receipts are what a paying wallet verifies
        let p = served(&s);
        let key_a = public_hex(&SUB_A).unwrap();
        let r = out["receipts"][0]["receipt"].as_str().unwrap();
        assert!(subs::verify_canonical(&p.plan_key, &subs::agreed_canonical("bread", &p.terms.digest_hex(), &key_a, T0), r));
        // the tags: A from payment 1, B (who paid 1) from payment 2 — each the tag that subscriber's wallet makes
        let tags = out["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 6);
        let ka = shared_secret(&SUB_A, &p.plan_key).unwrap();
        assert_eq!(tags[0]["tag"], payment_tag(&ka, 1)); assert_eq!(tags[0]["n"], 1);
        let kb = shared_secret(&SUB_B, &p.plan_key).unwrap();
        assert_eq!(tags[3]["n"], 2); assert_eq!(tags[3]["tag"], payment_tag(&kb, 2));
        // a second pass with the receipts the sidecar now holds signs nothing again
        let mut a2 = entry(&s, &SUB_A, &[]); a2["receipt"] = r.into();
        let out2 = s.work(&SELLER_SK, &serde_json::json!({ "subscribers": [a2] })).unwrap();
        assert!(out2["receipts"].as_array().unwrap().is_empty());
        assert_eq!(s.subscribers.len(), 1, "the checked list replaces the phone's own");
    }

    fn with_subscribers() -> SellerStore {
        let mut s = seller();
        let st = serde_json::json!({ "subscribers": [entry(&s, &SUB_A, &[]), entry(&s, &SUB_B, &[1])] });
        s.work(&SELLER_SK, &st).unwrap();
        s
    }

    fn desc(s: &SellerStore, sub_sk: &[u8; 32], n: u32) -> String {
        invoice_description("bread", n, &payment_tag(&shared_secret(sub_sk, &served(s).plan_key).unwrap(), n))
    }

    #[test]
    fn s71_a_payment_is_taken_only_with_a_known_subscribers_tag_for_an_unpaid_number() {
        let mut s = with_subscribers();
        let h = "aa".repeat(32);
        assert_eq!(s.decide(&SELLER_SK, &h, Some(&desc(&s, &SUB_A, 1)), 5_000_000), Decision::Refuse("no payment is waiting on this hash".into()));
        assert!(s.note_waiting(&h, 4_900_000, T0));
        assert!(!s.note_waiting(&h, 4_900_000, T0), "noted once");
        let key_a = public_hex(&SUB_A).unwrap();
        // the subscriber's own tag for its unpaid payment 1: taken
        assert_eq!(s.decide(&SELLER_SK, &h, Some(&desc(&s, &SUB_A, 1)), 5_000_000), Decision::Take { plan_id: "bread".into(), sub_key: key_a.clone(), n: 1, invoice_msat: 5_000_000 });
        // an address payment that landed on a selling hash, or no description at all: not a subscription's
        assert!(matches!(s.decide(&SELLER_SK, &h, None, 5_000_000), Decision::Refuse(_)));
        assert!(matches!(s.decide(&SELLER_SK, &h, Some("coffee"), 5_000_000), Decision::Refuse(_)));
        // a tag nobody the phone knows could have made: ask the sidecar again before deciding (a new subscriber)
        assert!(matches!(s.decide(&SELLER_SK, &h, Some(&desc(&s, &[0x77; 32], 1)), 5_000_000), Decision::AskAgain(_)));
        // subscriber A's tag for payment 1 put on a "payment 2" invoice: the tag is not payment 2's
        let wrong_n = invoice_description("bread", 2, &payment_tag(&shared_secret(&SUB_A, &served(&s).plan_key).unwrap(), 1));
        assert!(matches!(s.decide(&SELLER_SK, &h, Some(&wrong_n), 5_000_000), Decision::AskAgain(_)));
        // B paid payment 1 already (the sidecar's record): a second payment 1 is not taken
        assert!(matches!(s.decide(&SELLER_SK, &h, Some(&desc(&s, &SUB_B, 1)), 5_000_000), Decision::Refuse(r) if r.contains("paid already")));
        // an invoice that was not for the plan's price
        assert!(matches!(s.decide(&SELLER_SK, &h, Some(&desc(&s, &SUB_A, 1)), 4_000_000), Decision::Refuse(r) if r.contains("price")));
        // another plan's name
        assert!(matches!(s.decide(&SELLER_SK, &h, Some(&invoice_description("cake", 1, &"0".repeat(32))), 5_000_000), Decision::Refuse(_)));
        // taken: recorded with what the subscriber paid and what arrived; the same number is then never taken again
        assert!(s.claimed(&h, 4_900_000, T0).is_none(), "nothing is recorded before the phone decided");
        assert!(s.claiming(&h, "bread", &key_a, 1, 5_000_000));
        assert!(!s.claiming(&h, "bread", &key_a, 1, 5_000_000), "decided once");
        assert!(s.undecided().is_empty());
        // while LDK completes the claim, a second payment 1 from the same subscriber is already refused
        let h2 = "bb".repeat(32);
        s.note_waiting(&h2, 5_000_000, T0 + 10);
        assert!(matches!(s.decide(&SELLER_SK, &h2, Some(&desc(&s, &SUB_A, 1)), 5_000_000), Decision::Refuse(r) if r.contains("paid already")));
        let r = s.claimed(&h, 4_900_000, T0 + 9).unwrap();
        assert_eq!(r, Received { hash: h.clone(), plan_id: "bread".into(), sub_key: key_a.clone(), n: 1, invoice_msat: 5_000_000, received_msat: 4_900_000, at: T0 + 9 });
        assert_eq!(s.received, vec![r]);
        assert!(s.claimed(&h, 4_900_000, T0 + 9).is_none(), "recorded once");
        assert!(matches!(s.decide(&SELLER_SK, &h2, Some(&desc(&s, &SUB_A, 1)), 5_000_000), Decision::Refuse(r) if r.contains("paid already")));
        assert!(matches!(s.decide(&SELLER_SK, &h2, Some(&desc(&s, &SUB_A, 2)), 5_000_000), Decision::Take { n: 2, .. }));
        assert!(!s.age_out(T0 + 10 + WAITING_KEEP_SECS - 1)); assert_eq!(s.undecided().len(), 1);
        assert!(s.gone(&h2) && !s.gone(&h2));
        s.note_waiting(&"dd".repeat(32), 1, T0);
        assert!(s.age_out(T0 + WAITING_KEEP_SECS) && s.waiting.is_empty(), "an entry three days old is dropped");
        // what the phone took counts in the next pass even when the sidecar has not heard of it
        let st = serde_json::json!({ "subscribers": [entry(&s, &SUB_A, &[])] });
        let out = s.work(&SELLER_SK, &st).unwrap();
        assert_eq!(out["tags"][0]["n"], 2);
    }

    #[test]
    fn s71_an_ended_subscriber_pays_nothing_more_and_an_end_must_be_the_subscribers_own() {
        let mut s = seller();
        let mut e = entry(&s, &SUB_A, &[]); e["ended"] = true.into();
        let out = s.work(&SELLER_SK, &serde_json::json!({ "subscribers": [e] })).unwrap();
        assert!(out["tags"].as_array().unwrap().is_empty());
        s.note_waiting(&"cc".repeat(32), 5_000_000, T0);
        assert!(matches!(s.decide(&SELLER_SK, &"cc".repeat(32), Some(&desc(&s, &SUB_A, 1)), 5_000_000), Decision::AskAgain(_)));
        let end = end_body(&SUB_A, "bread", "now", Some(&RefundTo::Lnaddr("r7k2@p.example".into())), T0).unwrap();
        assert_eq!(check_end("bread", &end).unwrap(), ("now".to_string(), "lnaddr:r7k2@p.example".to_string()));
        let mut moved = end.clone(); moved["refund_to"] = serde_json::json!({ "lnaddr": "thief@p.example" });
        assert!(check_end("bread", &moved).is_err(), "a refund address the subscriber did not sign");
        assert!(check_end("cake", &end).is_err());
    }

    #[test]
    fn s71_the_sellers_records_are_kept() {
        let storage = crate::storage::native_storage::MemoryStorage::new();
        assert_eq!(load(&storage).unwrap(), SellerStore::default());
        let s = with_subscribers();
        save(&storage, &s).unwrap();
        assert_eq!(load(&storage).unwrap(), s);
    }
}
