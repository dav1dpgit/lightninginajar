//! LIJOX channel-registry HTTP client (Phase 1c-write).
//!
//! Posts signed channel records to the LSP's `/lsps/registry/channels`
//! endpoint so that seed-only recovery (Phase 1c-recover) has data to read.
//!
//! ## Signature model
//! Signs with the wallet's LDK node identity key, accessed via
//! [`KeysManager::get_node_secret_key`] (LDK 0.0.123, line 1938 — already
//! `pub fn`, no patches needed). This is the same key the LSP knows the
//! wallet by from the Lightning protocol, so binding the signature to that
//! pubkey is the natural authentication for "this is the wallet that owns
//! these channels."
//!
//! ## Digest format
//! `sha256(domain_separator || action || nonce_bytes || pubkey_bytes [|| record_id_bytes])`
//!
//! MUST match `registry.js:buildSignedMessage` byte-for-byte. The constants
//! `DOMAIN_SEPARATOR`, `ACTION_POST_CHANNEL`, `ACTION_GET_CHANNELS` here
//! mirror the JS-side strings exactly. Tests below pin the digest.
//!
//! ## Canonicalization
//! Records are canonicalized (lowercase hex) by the LSP before storage. The
//! POST response echoes the canonical form; we verify it equals what we sent
//! after our own canonicalization, byte-for-byte via JSON serialization.
//! Any mismatch is a hard error — the registry is not allowed to mutate our
//! data silently.
//!
//! ## HTTP path
//! WASM-only for now (matches what lij-wasm targets). Uses `web_sys` +
//! `wasm_bindgen_futures::JsFuture`, same as `lsps2.rs`. Native builds get
//! a stub that returns `Err(LijError::Lsp("not implemented on native"))`
//! so the module compiles on both targets for unit tests.

use std::sync::Arc;

use bitcoin::secp256k1::{Message, Secp256k1};
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{LijError, LijResult};

// ─── Protocol constants (mirror registry.js exactly) ────────────────────────

const DOMAIN_SEPARATOR: &[u8] = b"lij-registry-v1";
const ACTION_POST_CHANNEL: &[u8] = b"post-channel";
#[allow(dead_code)] // used by Phase 1c-recover; kept here for symmetry
const ACTION_GET_CHANNELS: &[u8] = b"get-channels";
const ACTION_PUSH_SUBSCRIBE: &[u8] = b"push-subscribe";
// v352 (S63, the external review's adapter F7): the wallet signs its Lightning-address registration and release.
const ACTION_LNURL_REGISTER: &[u8] = b"lnurl-register";
const ACTION_LNURL_RELEASE: &[u8] = b"lnurl-release";
const ACTION_ROUTE_REPORT: &[u8] = b"route-report";   // v353 (S63, pathfinding r9 §3a)

// ─── Wire types ─────────────────────────────────────────────────────────────

/// Channel-record schema, mirror of `registry.js:validateChannelRecord` shape.
///
/// **Field order matters**: serde_json preserves struct field declaration
/// order in JSON output, and the LSP's `canonicalizeRecord` produces a
/// specific field order. The echo-verify step compares JSON byte-for-byte,
/// so these fields MUST appear in this exact order to match the LSP's
/// canonical form.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChannelRecord {
    pub channel_id: String,
    pub funding_txid: String,
    pub funding_vout: u32,
    pub channel_value_sat: u64,
    pub commit_type: String,
    pub channel_keys_id_hex: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub close_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub closing_txid: Option<String>,
}

impl ChannelRecord {
    /// Lowercase all hex fields. Mirror of `registry.js:canonicalizeRecord`.
    pub fn canonicalize(&self) -> Self {
        let mut out = self.clone();
        out.channel_id = out.channel_id.to_lowercase();
        out.funding_txid = out.funding_txid.to_lowercase();
        out.channel_keys_id_hex = out.channel_keys_id_hex.to_lowercase();
        if let Some(ref mut cid) = out.closing_txid {
            *cid = cid.to_lowercase();
        }
        out
    }
}

#[derive(Deserialize, Debug)]
struct ChallengeResponse {
    nonce: String,
    #[serde(default)]
    #[allow(dead_code)]
    expires_at: Option<u64>,
}

#[derive(Serialize)]
struct PostChannelRequest<'a> {
    node_pubkey: &'a str,
    nonce: &'a str,
    signature: &'a str,
    record: &'a ChannelRecord,
}

#[derive(Deserialize, Debug)]
struct PostChannelResponse {
    ok: bool,
    record: ChannelRecord,
    #[allow(dead_code)]
    replaced: bool,
    #[allow(dead_code)]
    #[serde(default)]
    stored_at: Option<u64>,
}

/// Push-subscribe request. `subscription` is the browser PushSubscription
/// (endpoint + keys), embedded verbatim as opaque JSON.
#[derive(Serialize)]
struct PushSubscribeRequest<'a> {
    node_pubkey: &'a str,
    nonce: &'a str,
    signature: &'a str,
    subscription: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct PushSubscribeResponse {
    ok: bool,
}

// ─── Signing helpers ────────────────────────────────────────────────────────

/// Build the canonical signed-message digest.
///
/// `record_id` is included for `post-channel` (binds the signature to a
/// specific channel — replay across channels is rejected) and omitted for
/// `get-channels` (signature authorizes a read across all of the
/// caller's channels).
pub(crate) fn build_message_digest(
    action: &[u8],
    nonce_hex: &str,
    pubkey_hex: &str,
    record_id: Option<&str>,
) -> LijResult<[u8; 32]> {
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| LijError::Lsp(format!("nonce hex decode: {e}")))?;
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| LijError::Lsp(format!("pubkey hex decode: {e}")))?;
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(action);
    h.update(&nonce_bytes);
    h.update(&pubkey_bytes);
    if let Some(rid) = record_id {
        h.update(rid.as_bytes());
    }
    Ok(h.finalize().into())
}

/// Return the wallet's node identity pubkey as 66-hex-char compressed string.
fn node_pubkey_hex(keys_manager: &Arc<KeysManager>) -> String {
    let pk = keys_manager
        .get_node_id(Recipient::Node)
        .expect("KeysManager::get_node_id with Recipient::Node is infallible");
    hex::encode(pk.serialize())
}

/// Sign a 32-byte digest with the node identity key. Returns 128-hex-char
/// compact secp256k1 signature.
fn sign_digest(keys_manager: &Arc<KeysManager>, digest: &[u8; 32]) -> String {
    let secp = Secp256k1::new();
    let secret = keys_manager.get_node_secret_key();
    let msg = Message::from_slice(digest)
        .expect("32-byte slice is always a valid Message");
    let sig = secp.sign_ecdsa(&msg, &secret);
    hex::encode(sig.serialize_compact())
}

// ─── HTTP transport (WASM target) ───────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
async fn http_get(url: &str) -> LijResult<String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Lsp(format!("Registry GET build: {e:?}")))?;

    let window = web_sys::window()
        .ok_or_else(|| LijError::Lsp("Registry GET: no window".into()))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| LijError::Lsp(format!("Registry GET fetch: {e:?}")))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| LijError::Lsp("Registry GET response cast".into()))?;

    let text_promise = resp
        .text()
        .map_err(|e| LijError::Lsp(format!("Registry GET text promise: {e:?}")))?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|e| LijError::Lsp(format!("Registry GET text await: {e:?}")))?;
    let text = text_js
        .as_string()
        .ok_or_else(|| LijError::Lsp("Registry GET body not a string".into()))?;

    if !resp.ok() {
        return Err(LijError::Lsp(format!(
            "Registry GET HTTP {} {url} — {text}",
            resp.status()
        )));
    }
    Ok(text)
}

#[cfg(target_arch = "wasm32")]
async fn http_post_json(url: &str, body: &str) -> LijResult<String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&wasm_bindgen::JsValue::from_str(body)));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Lsp(format!("Registry POST build: {e:?}")))?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| LijError::Lsp(format!("Registry POST header: {e:?}")))?;

    let window = web_sys::window()
        .ok_or_else(|| LijError::Lsp("Registry POST: no window".into()))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| LijError::Lsp(format!("Registry POST fetch: {e:?}")))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| LijError::Lsp("Registry POST response cast".into()))?;

    let text_promise = resp
        .text()
        .map_err(|e| LijError::Lsp(format!("Registry POST text promise: {e:?}")))?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|e| LijError::Lsp(format!("Registry POST text await: {e:?}")))?;
    let text = text_js
        .as_string()
        .ok_or_else(|| LijError::Lsp("Registry POST body not a string".into()))?;

    if !resp.ok() {
        return Err(LijError::Lsp(format!(
            "Registry POST HTTP {} {url} — {text}",
            resp.status()
        )));
    }
    Ok(text)
}

// ─── HTTP transport (native target — stubbed) ───────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
async fn http_get(_url: &str) -> LijResult<String> {
    Err(LijError::Lsp(
        "registry_client::http_get not implemented on native target".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
async fn http_post_json(_url: &str, _body: &str) -> LijResult<String> {
    Err(LijError::Lsp(
        "registry_client::http_post_json not implemented on native target".into(),
    ))
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Upload a channel record to the LSP registry.
///
/// Pipeline:
///   1. GET `/lsps/registry/challenge` → 32-byte single-use nonce.
///   2. Build `sha256(domain || "post-channel" || nonce || pubkey ||
///      channel_id.lowercase())` digest, sign with node identity key.
///   3. POST `/lsps/registry/channels` with `{node_pubkey, nonce, signature,
///      record}`.
///   4. Verify the LSP's echoed record equals our canonical form byte-for-byte.
///      Any mismatch is a hard error — registry is not allowed to mutate
///      our data.
///
/// On transport failure (LSP unreachable, network error, non-2xx HTTP) returns
/// `LijError::Lsp` with details. Caller decides retry policy. Step 3 of
/// Phase 1c-write will add a KV-backed retry queue.
pub async fn upload_channel_record(
    keys_manager: &Arc<KeysManager>,
    lsp_endpoint: &str,
    record: &ChannelRecord,
) -> LijResult<()> {
    let endpoint = lsp_endpoint.trim_end_matches('/');

    // 1. Challenge
    let challenge_url = format!("{endpoint}/lsps/registry/challenge");
    let challenge_body = http_get(&challenge_url).await?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_body)
        .map_err(|e| LijError::Lsp(format!("parse challenge: {e} — body: {challenge_body}")))?;
    let nonce = &challenge.nonce;
    if nonce.len() != 64 {
        return Err(LijError::Lsp(format!(
            "challenge nonce wrong length: {} (expected 64)",
            nonce.len()
        )));
    }

    // 2. Canonicalize + build digest + sign
    let canonical = record.canonicalize();
    let pubkey_hex = node_pubkey_hex(keys_manager);
    let digest = build_message_digest(
        ACTION_POST_CHANNEL,
        nonce,
        &pubkey_hex,
        Some(&canonical.channel_id),
    )?;
    let signature = sign_digest(keys_manager, &digest);

    // 3. POST
    let req = PostChannelRequest {
        node_pubkey: &pubkey_hex,
        nonce,
        signature: &signature,
        record: &canonical,
    };
    let req_body = serde_json::to_string(&req)
        .map_err(|e| LijError::Lsp(format!("serialize POST body: {e}")))?;
    let post_url = format!("{endpoint}/lsps/registry/channels");
    let resp_body = http_post_json(&post_url, &req_body).await?;
    let resp: PostChannelResponse = serde_json::from_str(&resp_body)
        .map_err(|e| LijError::Lsp(format!("parse POST response: {e} — body: {resp_body}")))?;

    if !resp.ok {
        return Err(LijError::Lsp(format!(
            "registry POST returned ok=false: {resp_body}"
        )));
    }

    // 4. Echo-verify: serialize both records and compare byte-for-byte. This
    //    catches silent mutation by the LSP (e.g. dropped fields, reordered
    //    keys) that schema-level field equality might miss.
    let sent_json = serde_json::to_string(&canonical)
        .map_err(|e| LijError::Lsp(format!("re-serialize sent record: {e}")))?;
    let echo_json = serde_json::to_string(&resp.record)
        .map_err(|e| LijError::Lsp(format!("re-serialize echo record: {e}")))?;
    if sent_json != echo_json {
        return Err(LijError::Lsp(format!(
            "registry echo MISMATCH — sent {sent_json} received {echo_json}"
        )));
    }

    log::info!(
        "Registry: upload OK channel_id={} replaced={} stored_at={:?}",
        canonical.channel_id,
        resp.replaced,
        resp.stored_at,
    );
    Ok(())
}

/// Register a Web Push wake subscription with the LSP (D-1 2c offline-receive).
///
/// Same signed-challenge auth as channel records, but for the `push-subscribe`
/// action (no record_id). The wallet proves ownership of its node pubkey; the
/// LSP then stores `node_pubkey -> subscription` and pushes a content-free wake
/// when a JIT payment arrives while the wallet is offline.
///
/// Pipeline:
///   1. GET `/lsps/registry/challenge` → 32-byte single-use nonce.
///   2. Build `sha256(domain || "push-subscribe" || nonce || pubkey)` digest,
///      sign with node identity key.
///   3. POST `/lsps2/push-subscribe` with `{node_pubkey, nonce, signature,
///      subscription}`.
///
/// `subscription_json` is the browser `PushSubscription` serialized to JSON;
/// it is parsed and re-embedded as opaque JSON so the LSP receives it verbatim.
pub async fn register_push_subscription(
    keys_manager: &Arc<KeysManager>,
    lsp_endpoint: &str,
    subscription_json: &str,
) -> LijResult<()> {
    let endpoint = lsp_endpoint.trim_end_matches('/');

    // Parse the browser subscription so we can re-embed it as structured JSON.
    let subscription: serde_json::Value = serde_json::from_str(subscription_json)
        .map_err(|e| LijError::Lsp(format!("parse subscription JSON: {e}")))?;

    // 1. Challenge
    let challenge_url = format!("{endpoint}/lsps/registry/challenge");
    let challenge_body = http_get(&challenge_url).await?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_body)
        .map_err(|e| LijError::Lsp(format!("parse challenge: {e} — body: {challenge_body}")))?;
    let nonce = &challenge.nonce;
    if nonce.len() != 64 {
        return Err(LijError::Lsp(format!(
            "challenge nonce wrong length: {} (expected 64)",
            nonce.len()
        )));
    }

    // 2. Build digest (push-subscribe, no record_id) + sign with node key
    let pubkey_hex = node_pubkey_hex(keys_manager);
    let digest = build_message_digest(ACTION_PUSH_SUBSCRIBE, nonce, &pubkey_hex, None)?;
    let signature = sign_digest(keys_manager, &digest);

    // 3. POST
    let req = PushSubscribeRequest {
        node_pubkey: &pubkey_hex,
        nonce,
        signature: &signature,
        subscription,
    };
    let req_body = serde_json::to_string(&req)
        .map_err(|e| LijError::Lsp(format!("serialize POST body: {e}")))?;
    let post_url = format!("{endpoint}/lsps2/push-subscribe");
    let resp_body = http_post_json(&post_url, &req_body).await?;
    let resp: PushSubscribeResponse = serde_json::from_str(&resp_body)
        .map_err(|e| LijError::Lsp(format!("parse POST response: {e} — body: {resp_body}")))?;

    if !resp.ok {
        return Err(LijError::Lsp(format!(
            "push-subscribe returned ok=false: {resp_body}"
        )));
    }

    log::info!("Registry: push subscription registered (pubkey={pubkey_hex})");
    Ok(())
}

// ─── v352 (S63): the Lightning address — signed register and release ───────────────────────────────────────────────
//
// /lnurl/register and /lnurl/release checked only that the pubkey string matched the record; the name is the address
// itself and the node pubkey is in every invoice, so anyone holding the route token could release a wallet's name and
// register it under another key — payers' sats to the attacker. Both calls now carry the push-subscribe proof: a
// single-use challenge from the LSP, signed by the node key over
//   sha256(domain || action || nonce || pubkey || record_id)
// with record_id binding what is asked:
//   lnurl-register: "<name>:<count>:<sha256 hex of the hash fields, lowercased, sorted, joined>"  (an empty probe: count 0)
//   lnurl-release:  "<name>"
// The adapter (0.112.0) builds the same record_id from the body it received and refuses anything else. The page keeps
// doing the HTTP; the engine only answers with the proof — the key never leaves it.

/// The record_id a registration binds: the name, the count of hashes, and a digest over the hash fields.
pub fn lnurlp_register_record_id(name: &str, hashes_json: &str) -> LijResult<String> {
    let v: serde_json::Value = if hashes_json.trim().is_empty() { serde_json::Value::Array(vec![]) } else {
        serde_json::from_str(hashes_json).map_err(|e| LijError::Lsp(format!("hashes JSON: {e}")))?
    };
    let arr = v.as_array().ok_or_else(|| LijError::Lsp("hashes must be a JSON array".into()))?;
    let mut hs: Vec<String> = arr.iter()
        .filter_map(|e| e.get("hash").and_then(|h| h.as_str()).map(|h| h.to_ascii_lowercase()))
        .collect();
    hs.sort();
    let mut h = Sha256::new();
    for x in &hs { h.update(x.as_bytes()); }
    Ok(format!("{}:{}:{}", name.to_ascii_lowercase(), hs.len(), hex::encode(h.finalize())))
}

// ─── v353 (S63, pathfinding r9 §3a): the signed routing report ────────────────────────────────────────────────────────
//
// After a send ends, the wallet tells its provider which nodes and channels refused it, so the provider's LND stops
// offering those paths to this wallet and its other customers. The report carries the 0.112.0 proof — a single-use
// challenge signed by the node key over "route-report" and a record_id that binds the report's content:
//   record_id = "<payment hash, lowercased>:<count>:<sha256 hex over the refusal lines, each
//                '<from>:<to>:<scid>:<amount_msat>:<code>\n' lowercased, sorted bytewise, concatenated>"
// The adapter (0.113.0) rebuilds the same string from the body it received and refuses anything else, then imports only
// the temporary refusals (XImportMissionControl) that were on routes it handed out for that hash. The twin on the
// adapter side is routeReportRecordId; route-report.test.js and the test below pin the same vectors.

/// The record a routing report binds. `failures_json` is a JSON array of {from, to, scid, amount_msat, code}.
pub fn route_report_record_id(payment_hash_hex: &str, failures_json: &str) -> LijResult<String> {
    let v: serde_json::Value = if failures_json.trim().is_empty() { serde_json::Value::Array(vec![]) } else {
        serde_json::from_str(failures_json).map_err(|e| LijError::Lsp(format!("failures JSON: {e}")))?
    };
    let arr = v.as_array().ok_or_else(|| LijError::Lsp("failures must be a JSON array".into()))?;
    let field = |e: &serde_json::Value, k: &str| -> String {
        match e.get(k) {
            Some(serde_json::Value::String(x)) => x.to_ascii_lowercase(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    };
    let mut lines: Vec<String> = arr.iter()
        .map(|e| format!("{}:{}:{}:{}:{}\n", field(e, "from"), field(e, "to"), field(e, "scid"), field(e, "amount_msat"), field(e, "code")))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in &lines { h.update(l.as_bytes()); }
    Ok(format!("{}:{}:{}", payment_hash_hex.to_ascii_lowercase(), lines.len(), hex::encode(h.finalize())))
}

/// Fetch the LSP's challenge and sign the routing report's proof. Returns `{node_pubkey, nonce, signature}` as JSON.
pub async fn route_report_auth(
    keys_manager: &Arc<KeysManager>,
    lsp_endpoint: &str,
    payment_hash_hex: &str,
    failures_json: &str,
) -> LijResult<String> {
    let endpoint = lsp_endpoint.trim_end_matches('/');
    let record_id = route_report_record_id(payment_hash_hex, failures_json)?;
    let challenge_url = format!("{endpoint}/lsps/registry/challenge");
    let challenge_body = http_get(&challenge_url).await?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_body)
        .map_err(|e| LijError::Lsp(format!("parse challenge: {e} — body: {challenge_body}")))?;
    if challenge.nonce.len() != 64 {
        return Err(LijError::Lsp(format!("challenge nonce wrong length: {} (expected 64)", challenge.nonce.len())));
    }
    let pubkey_hex = node_pubkey_hex(keys_manager);
    let digest = build_message_digest(ACTION_ROUTE_REPORT, &challenge.nonce, &pubkey_hex, Some(&record_id))?;
    let signature = sign_digest(keys_manager, &digest);
    let out = LnurlpAuth { node_pubkey: &pubkey_hex, nonce: &challenge.nonce, signature: &signature };
    serde_json::to_string(&out).map_err(|e| LijError::Lsp(format!("serialize auth: {e}")))
}

// ─── v355 (S63, Kimi K3.1 Pro round 2 — DP's rulings F10 and F4/F6 of 2026-10-26) ────────────────────────────────────
//
// THE PROOF, generalised. The adapter's lnurlpAuthCheck already verifies any action over the 0.112.0 digest; the engine
// only knew two actions and computed their record_ids itself. `lsp_proof` signs a single-use challenge over an action
// from a FIXED LIST and a record_id the page hands over — the page assembles the record from the body it is about to
// send (the adapter rebuilds the same string and refuses anything else), the engine proves the node key holds it. The
// list is the whole set of things the key will vouch for; an action not on it is refused here, so a page bug cannot
// turn the node key into a general signing oracle. The records (the adapter's twins, 0.116.0):
//   heartbeat          "<unix minute>"                              — the awake proof (F10): touchWalletActive only on this
//   lsps2-pending      "pending:<unix minute>"                      — the wake poll (F10)
//   client-prefs       "prefs:<hold_ms>"                            — the hold dial (F10)
//   push-claim         "claim:<hash>:<claimant>:<sha256(secret)>:<amount_sats|0>:<expiry|0>:<holder_prefix|>"   (F4/F6)
//   push-deliver       "deliver:<hash>:<claimant>:<sha256(bolt11 lowercased)>"
//   push-claim-status  "claim-status:<hash>:<claimant>"
//   lnurl-note         "note:<hash>:<client>"                       — the payer's note read (F14, the second half)
pub const PROOF_ACTIONS: &[&str] = &["heartbeat", "lsps2-pending", "client-prefs", "push-claim", "push-deliver", "push-claim-status", "lnurl-note"];

/// Fetch the LSP's challenge and sign `action` over `record_id` with the node key. Returns `{node_pubkey, nonce, signature}`
/// as JSON. The action must be on PROOF_ACTIONS; the record_id is the page's (≤ 512 bytes, no control characters).
pub async fn lsp_proof(
    keys_manager: &Arc<KeysManager>,
    lsp_endpoint: &str,
    action: &str,
    record_id: &str,
) -> LijResult<String> {
    if !PROOF_ACTIONS.contains(&action) {
        return Err(LijError::Lsp(format!("lsp_proof: action not on the list: {action}")));
    }
    if record_id.is_empty() || record_id.len() > 512 || record_id.chars().any(|c| c.is_control()) {
        return Err(LijError::Lsp("lsp_proof: record_id empty, over 512 bytes or with control characters".into()));
    }
    let endpoint = lsp_endpoint.trim_end_matches('/');
    let challenge_url = format!("{endpoint}/lsps/registry/challenge");
    let challenge_body = http_get(&challenge_url).await?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_body)
        .map_err(|e| LijError::Lsp(format!("parse challenge: {e} — body: {challenge_body}")))?;
    if challenge.nonce.len() != 64 {
        return Err(LijError::Lsp(format!("challenge nonce wrong length: {} (expected 64)", challenge.nonce.len())));
    }
    let pubkey_hex = node_pubkey_hex(keys_manager);
    let digest = build_message_digest(action.as_bytes(), &challenge.nonce, &pubkey_hex, Some(record_id))?;
    let signature = sign_digest(keys_manager, &digest);
    let out = LnurlpAuth { node_pubkey: &pubkey_hex, nonce: &challenge.nonce, signature: &signature };
    serde_json::to_string(&out).map_err(|e| LijError::Lsp(format!("serialize auth: {e}")))
}

#[derive(Serialize)]
struct LnurlpAuth<'a> {
    node_pubkey: &'a str,
    nonce: &'a str,
    signature: &'a str,
}

/// Fetch the LSP's challenge and sign the register or release proof. Returns `{node_pubkey, nonce, signature}` as JSON
/// for the page to put beside `name`, `client_pubkey` and `hashes` in its POST.
pub async fn lnurlp_auth(
    keys_manager: &Arc<KeysManager>,
    lsp_endpoint: &str,
    action: &str,
    name: &str,
    hashes_json: &str,
) -> LijResult<String> {
    let endpoint = lsp_endpoint.trim_end_matches('/');
    let (action_bytes, record_id) = match action {
        "lnurl-register" => (ACTION_LNURL_REGISTER, lnurlp_register_record_id(name, hashes_json)?),
        "lnurl-release" => (ACTION_LNURL_RELEASE, name.to_ascii_lowercase()),
        other => return Err(LijError::Lsp(format!("lnurlp_auth: unknown action {other}"))),
    };
    let challenge_url = format!("{endpoint}/lsps/registry/challenge");
    let challenge_body = http_get(&challenge_url).await?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_body)
        .map_err(|e| LijError::Lsp(format!("parse challenge: {e} — body: {challenge_body}")))?;
    if challenge.nonce.len() != 64 {
        return Err(LijError::Lsp(format!("challenge nonce wrong length: {} (expected 64)", challenge.nonce.len())));
    }
    let pubkey_hex = node_pubkey_hex(keys_manager);
    let digest = build_message_digest(action_bytes, &challenge.nonce, &pubkey_hex, Some(&record_id))?;
    let signature = sign_digest(keys_manager, &digest);
    let out = LnurlpAuth { node_pubkey: &pubkey_hex, nonce: &challenge.nonce, signature: &signature };
    serde_json::to_string(&out).map_err(|e| LijError::Lsp(format!("serialize auth: {e}")))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // v352 (S63): the record a signed registration binds — the adapter (0.112.0) builds the same string from the body it
    // received; these pin the rule: name lowercased, the count, sha256 over the hash fields lowercased + sorted + joined.
    #[test]
    fn lnurlp_register_record_id_rule() {
        let empty = lnurlp_register_record_id("Alice", "[]").unwrap();
        // sha256 of the empty string
        assert_eq!(empty, "alice:0:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(lnurlp_register_record_id("alice", "").unwrap(), empty, "no JSON at all is an empty probe");
        let two = r#"[{"hash":"BB","secret":"x","index":2},{"hash":"aa","secret":"y"}]"#;
        let id = lnurlp_register_record_id("alice", two).unwrap();
        let mut h = Sha256::new(); h.update(b"aa"); h.update(b"bb");
        assert_eq!(id, format!("alice:2:{}", hex::encode(h.finalize())), "lowercased, sorted, joined; secrets and indexes never enter");
        let swapped = r#"[{"hash":"aa"},{"hash":"bb"}]"#;
        assert_eq!(lnurlp_register_record_id("ALICE", swapped).unwrap(), id, "order and case do not change the record");
        assert!(lnurlp_register_record_id("alice", "{}").is_err(), "not an array");
    }

    // v355 (S63): the proof list is the whole set of things the node key vouches for through lsp_proof; the digest a
    // listed action signs is the 0.112.0 digest with the action's bytes — the adapter's lnurlpAuthCheck twin.
    #[test]
    fn lsp_proof_actions_and_digest() {
        assert_eq!(PROOF_ACTIONS, &["heartbeat", "lsps2-pending", "client-prefs", "push-claim", "push-deliver", "push-claim-status", "lnurl-note"]);
        assert!(!PROOF_ACTIONS.contains(&"post-channel"), "the channel record keeps its own path");
        assert!(!PROOF_ACTIONS.contains(&"lnurl-register"), "the register keeps lnurlp_auth (the engine computes its record)");
        let nonce = "11".repeat(32);
        let pk = "02".to_string() + &"03".repeat(32);
        let a = build_message_digest(b"push-claim", &nonce, &pk, Some("claim:ab:02cd:x:0:0:")).unwrap();
        let b = build_message_digest("push-claim".as_bytes(), &nonce, &pk, Some("claim:ab:02cd:x:0:0:")).unwrap();
        assert_eq!(a, b);
        let c = build_message_digest(b"push-deliver", &nonce, &pk, Some("claim:ab:02cd:x:0:0:")).unwrap();
        assert_ne!(a, c, "the action is inside the digest — a claim's proof cannot deliver");
    }

    // v353 (S63): the routing report's record — the adapter's routeReportRecordId builds the same string; these vectors
    // are shared with route-report.test.js in the adapter repo.
    #[test]
    fn route_report_record_id_rule() {
        let h = "AB".repeat(32);
        let empty = route_report_record_id(&h, "[]").unwrap();
        assert_eq!(empty, format!("{}:0:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ab".repeat(32)));
        let two = r#"[{"from":"02AA","to":"03BB","scid":"123456789","amount_msat":"31020000","code":"temporary","attempt":3},{"from":"02cc","to":"03dd","scid":"5","amount_msat":"7","code":"permanent"}]"#;
        let id = route_report_record_id(&h, two).unwrap();
        let mut sha = Sha256::new();
        sha.update(b"02aa:03bb:123456789:31020000:temporary\n");
        sha.update(b"02cc:03dd:5:7:permanent\n");
        assert_eq!(id, format!("{}:2:{}", "ab".repeat(32), hex::encode(sha.finalize())), "lowercased, sorted, joined; the attempt number never enters");
        let swapped = r#"[{"from":"02cc","to":"03dd","scid":5,"amount_msat":7,"code":"permanent"},{"from":"02aa","to":"03bb","scid":123456789,"amount_msat":31020000,"code":"TEMPORARY"}]"#;
        assert_eq!(route_report_record_id(&h, swapped).unwrap(), id, "order, case and number-vs-string do not change the record");
        assert_eq!(id, format!("{}:2:{}", "ab".repeat(32), "c7cb69c11102edfd7e855283051a57954ee30f825fc95ed93497bdce28ff693d"), "the pinned vector (route-report.test.js carries the same)");
        assert!(route_report_record_id(&h, "{}").is_err(), "not an array");
    }

    #[test]
    fn lnurlp_digest_differs_by_action_and_record() {
        let nonce = "ab".repeat(32); let pk = format!("02{}", "cd".repeat(32));
        let reg = build_message_digest(ACTION_LNURL_REGISTER, &nonce, &pk, Some("alice:0:x")).unwrap();
        let rel = build_message_digest(ACTION_LNURL_RELEASE, &nonce, &pk, Some("alice")).unwrap();
        let reg_other = build_message_digest(ACTION_LNURL_REGISTER, &nonce, &pk, Some("alice:1:y")).unwrap();
        let push = build_message_digest(ACTION_PUSH_SUBSCRIBE, &nonce, &pk, None).unwrap();
        assert!(reg != rel && reg != reg_other && reg != push && rel != push, "a proof for one action or record is no proof for another");
    }

    #[test]
    fn channel_record_serialization_field_order_matches_js() {
        // Field order in the Rust struct must match what registry.js
        // canonicalizeRecord produces, because we compare JSON byte-for-byte.
        let rec = ChannelRecord {
            channel_id: "a".repeat(64),
            funding_txid: "b".repeat(64),
            funding_vout: 0,
            channel_value_sat: 100_000,
            commit_type: "ANCHORS".into(),
            channel_keys_id_hex: "c".repeat(64),
            close_height: None,
            closing_txid: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        // Expected exact prefix (field order, no whitespace, optionals dropped):
        assert!(
            json.starts_with(r#"{"channel_id":""#),
            "first field must be channel_id, got: {json}"
        );
        assert!(json.contains(r#""channel_id":"aa"#));
        assert!(json.contains(r#""funding_txid":"bb"#));
        assert!(json.contains(r#""funding_vout":0"#));
        assert!(json.contains(r#""channel_value_sat":100000"#));
        assert!(json.contains(r#""commit_type":"ANCHORS""#));
        assert!(json.contains(r#""channel_keys_id_hex":"cc"#));
        // close_height + closing_txid must be omitted when None
        assert!(!json.contains("close_height"), "close_height must be skipped when None");
        assert!(!json.contains("closing_txid"), "closing_txid must be skipped when None");
    }

    #[test]
    fn canonicalize_lowercases_hex_fields() {
        let rec = ChannelRecord {
            channel_id: "AABB".to_string() + &"a".repeat(60),
            funding_txid: "DDEE".to_string() + &"b".repeat(60),
            funding_vout: 1,
            channel_value_sat: 50_000,
            commit_type: "STATIC_REMOTE_KEY".into(),
            channel_keys_id_hex: "1122".to_string() + &"f".repeat(60),
            close_height: None,
            closing_txid: Some("FF".to_string() + &"e".repeat(62)),
        };
        let canon = rec.canonicalize();
        assert_eq!(canon.channel_id, canon.channel_id.to_lowercase());
        assert_eq!(canon.funding_txid, canon.funding_txid.to_lowercase());
        assert_eq!(canon.channel_keys_id_hex, canon.channel_keys_id_hex.to_lowercase());
        assert_eq!(
            canon.closing_txid.as_ref().unwrap(),
            &canon.closing_txid.as_ref().unwrap().to_lowercase()
        );
        // commit_type is NOT a hex field — should NOT be lowercased
        assert_eq!(canon.commit_type, "STATIC_REMOTE_KEY");
    }

    #[test]
    fn build_message_digest_is_deterministic_and_known() {
        // Pin the digest with a known input. If this ever changes, the
        // wallet will be out of sync with the LSP and EVERY post will fail
        // signature verification. Touch with extreme care.
        let nonce = "00".repeat(32);
        let pubkey = "02".to_string() + &"03".repeat(32);
        let digest = build_message_digest(
            ACTION_POST_CHANNEL,
            &nonce,
            &pubkey,
            Some(&"a".repeat(64)),
        )
        .unwrap();

        // Recompute via a hand-rolled SHA256 to confirm.
        let mut h = Sha256::new();
        h.update(b"lij-registry-v1");
        h.update(b"post-channel");
        h.update(&[0u8; 32]);
        let mut pkb = vec![0x02u8];
        pkb.extend(std::iter::repeat(0x03u8).take(32));
        h.update(&pkb);
        h.update(&[b'a'; 64]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(digest, expected);
    }

    #[test]
    fn build_message_digest_distinguishes_actions() {
        let nonce = "11".repeat(32);
        let pubkey = "02".to_string() + &"04".repeat(32);
        let d_post = build_message_digest(ACTION_POST_CHANNEL, &nonce, &pubkey, Some("x")).unwrap();
        let d_get = build_message_digest(ACTION_GET_CHANNELS, &nonce, &pubkey, None).unwrap();
        assert_ne!(d_post, d_get, "different actions must produce different digests");
    }

    #[test]
    fn build_message_digest_distinguishes_record_ids() {
        let nonce = "22".repeat(32);
        let pubkey = "02".to_string() + &"05".repeat(32);
        let d_a = build_message_digest(ACTION_POST_CHANNEL, &nonce, &pubkey, Some("a")).unwrap();
        let d_b = build_message_digest(ACTION_POST_CHANNEL, &nonce, &pubkey, Some("b")).unwrap();
        assert_ne!(d_a, d_b, "different record_ids must produce different digests");
    }
}
