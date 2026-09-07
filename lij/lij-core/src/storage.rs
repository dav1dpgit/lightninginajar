// storage.rs
// Two-layer storage strategy:
//
// Layer 1 — localStorage (browser, fast, ephemeral)
//   Channel state is written here on every update.
//   Fast reads on app open. Lost if user clears browser data.
//
// Layer 2 — Cloudflare KV via your Worker (durable, encrypted)
//   Channel state is pushed to your Worker endpoint after every write.
//   Keyed by node pubkey. Encrypted client-side before leaving the PWA.
//   This is the replacement for Mutiny's VSS (Spiral) service.
//   You own the endpoint. You own the data path. No third party.
//
// Recovery flow:
//   User enters mnemonic → derive pubkey → fetch encrypted blob from Worker
//   → decrypt with key derived from mnemonic → restore channel state → reconnect LSP

use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};

/// Configuration for the Cloudflare KV backup Worker endpoint.
/// Injected at wallet initialization from the PWA.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Your Cloudflare Worker URL, e.g. "https://lij-worker.your-account.workers.dev"
    pub worker_url: String,
    /// Auth token the Worker expects — keeps random browsers from writing to your KV
    pub auth_token: String,
}

/// A versioned, encrypted blob of Lightning channel state.
/// Version field prevents rollback attacks (old state can't overwrite new).
#[derive(Serialize, Deserialize, Debug)]
pub struct StateBlob {
    pub version: u64,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,       // AES-GCM nonce, 12 bytes
    pub pubkey_hex: String,   // identifies which wallet this belongs to
}

/// Signs backup challenges with the *portable* key — the BIP32 key whose pubkey
/// indexes the backup blob. Binds every push/read to its own backup slot with
/// no shared secret. Implemented by RootKey (see key.rs).
pub trait BackupSigner {
    /// Hex of the portable pubkey that indexes this wallet's backup.
    fn portable_pubkey_hex(&self) -> LijResult<String>;
    /// 128-hex compact secp256k1 ECDSA signature over a 32-byte digest,
    /// produced with the portable private key.
    fn sign_backup(&self, digest: &[u8; 32]) -> LijResult<String>;
}

/// Trait that abstracts storage operations.
/// Implemented differently for WASM (browser) vs native (tests).
pub trait LijStorage: Send + Sync {
    fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> LijResult<()>;
    fn delete(&self, key: &str) -> LijResult<()>;
    /// Return all keys that begin with `prefix`. Used by restore to enumerate
    /// per-channel monitor blobs without requiring a separate index.
    fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>>;
}

// ── Key name constants ───────────────────────────────────────────────────────
// These are the localStorage keys. Namespaced to avoid collisions.

pub const KEY_CHANNEL_MANAGER: &str = "lij_channel_manager";
pub const KEY_CHANNEL_MONITORS: &str = "lij_channel_monitors";
pub const KEY_NETWORK_GRAPH: &str = "lij_network_graph";
pub const KEY_SCORER: &str = "lij_scorer";
pub const KEY_LSP_CONFIG: &str = "lij_lsp_config";
pub const KEY_BACKUP_VERSION: &str = "lij_backup_version";

// ── WASM localStorage implementation ────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
pub mod wasm_storage {
    use super::*;
    use web_sys::wasm_bindgen::JsValue;
    use web_sys::window;

    pub struct LocalStorage;

    impl LijStorage for LocalStorage {
        fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>> {
            let storage = window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
                .ok_or_else(|| LijError::Storage("localStorage unavailable".into()))?;

            match storage.get_item(key) {
                Ok(Some(val)) => {
                    // Values stored as hex strings
                    let bytes = hex::decode(&val)
                        .map_err(|e| LijError::Storage(format!("Decode error: {e}")))?;
                    Ok(Some(bytes))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(LijError::Storage(format!("localStorage get error: {:?}", e))),
            }
        }

        fn set(&self, key: &str, value: &[u8]) -> LijResult<()> {
            let storage = window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
                .ok_or_else(|| LijError::Storage("localStorage unavailable".into()))?;

            let hex_val = hex::encode(value);
            storage
                .set_item(key, &hex_val)
                .map_err(|e| LijError::Storage(format!("localStorage set error: {:?}", e)))?;
            Ok(())
        }

        fn delete(&self, key: &str) -> LijResult<()> {
            let storage = window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
                .ok_or_else(|| LijError::Storage("localStorage unavailable".into()))?;

            storage
                .remove_item(key)
                .map_err(|e| LijError::Storage(format!("localStorage delete error: {:?}", e)))?;
            Ok(())
        }

        fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>> {
            let storage = window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
                .ok_or_else(|| LijError::Storage("localStorage unavailable".into()))?;
            let len = storage
                .length()
                .map_err(|e| LijError::Storage(format!("localStorage length: {:?}", e)))?;
            let mut keys = Vec::new();
            for i in 0..len {
                if let Ok(Some(k)) = storage.key(i) {
                    if k.starts_with(prefix) {
                        keys.push(k);
                    }
                }
            }
            Ok(keys)
        }
    }
}

// ── Native (non-WASM) in-memory storage for tests ───────────────────────────

#[cfg(not(target_arch = "wasm32"))]
pub mod native_storage {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    pub struct MemoryStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        pub fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl LijStorage for MemoryStorage {
        fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>> {
            let data = self.data.lock().unwrap();
            Ok(data.get(key).cloned())
        }

        fn set(&self, key: &str, value: &[u8]) -> LijResult<()> {
            let mut data = self.data.lock().unwrap();
            data.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &str) -> LijResult<()> {
            let mut data = self.data.lock().unwrap();
            data.remove(key);
            Ok(())
        }

        fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>> {
            let data = self.data.lock().unwrap();
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }
}

// ── Cloudflare KV backup client ──────────────────────────────────────────────
// Pushes encrypted channel state to your Worker after every meaningful update.
// If the push fails, the local state is still intact — backup is best-effort.
// On restore, this is the source of truth.

#[derive(Clone)]
pub struct KvBackupClient {
    config: StorageConfig,
}

impl KvBackupClient {
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Fetch a single-use challenge nonce bound to `pubkey` from the Worker.
    async fn get_challenge(&self, pubkey: &str) -> LijResult<String> {
        let url = format!("{}/backup/challenge?pubkey={pubkey}", self.config.worker_url);
        let text = http_get_auth(&url, "")
            .await?
            .ok_or_else(|| LijError::Backup("challenge: empty response".into()))?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| LijError::Backup(format!("challenge parse: {e}")))?;
        v.get("nonce")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| LijError::Backup("challenge: no nonce field".into()))
    }

    /// Push an encrypted blob, authenticated by a portable-key signature over a
    /// fresh Worker challenge (no shared secret). Fire-and-forget at the call
    /// site — local state remains the live source of truth if this fails.
    pub async fn push(&self, blob: &StateBlob, signer: &dyn BackupSigner) -> LijResult<()> {
        let pubkey = signer.portable_pubkey_hex()?;
        let nonce = self.get_challenge(&pubkey).await?;
        let digest = backup_digest(BACKUP_ACTION_PUSH, &nonce, &pubkey)?;
        let signature = signer.sign_backup(&digest)?;
        let envelope = serde_json::json!({
            "pubkey_hex": pubkey,
            "nonce": nonce,
            "signature": signature,
            "blob": blob,
        });
        let url = format!("{}/backup", self.config.worker_url);
        let resp = http_post_json_auth(&url, &envelope.to_string(), "").await?;
        log::debug!("KV backup push ok (version={}): {resp}", blob.version);
        Ok(())
    }

    /// Pull an encrypted blob, authenticated the same way. `Ok(None)` means the
    /// Worker holds no backup for this pubkey, distinct from a transport error.
    pub async fn pull(
        &self,
        pubkey_hex: &str,
        signer: &dyn BackupSigner,
    ) -> LijResult<Option<StateBlob>> {
        let nonce = self.get_challenge(pubkey_hex).await?;
        let digest = backup_digest(BACKUP_ACTION_READ, &nonce, pubkey_hex)?;
        let signature = signer.sign_backup(&digest)?;
        let envelope = serde_json::json!({
            "pubkey_hex": pubkey_hex,
            "nonce": nonce,
            "signature": signature,
        });
        let url = format!("{}/backup/fetch", self.config.worker_url);
        match http_post_json_opt(&url, &envelope.to_string()).await? {
            Some(text) => {
                // Worker wraps the blob: { "found": true, "blob": StateBlob }
                let v: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| LijError::Backup(format!("fetch parse: {e}")))?;
                if v.get("found").and_then(|f| f.as_bool()) != Some(true) {
                    return Ok(None);
                }
                let blob_val = v
                    .get("blob")
                    .ok_or_else(|| LijError::Backup("fetch: no blob field".into()))?;
                let blob: StateBlob = serde_json::from_value(blob_val.clone())
                    .map_err(|e| LijError::Backup(format!("fetch blob decode: {e}")))?;
                Ok(Some(blob))
            }
            None => Ok(None),
        }
    }
}

// ── HTTP transport (WASM target) ─────────────────────────────────────────────
// Mirrors registry_client's web_sys fetch pattern, plus a Bearer auth header
// the Worker requires on /backup. Kept here (rather than in lij-wasm) so the
// backup client is self-contained and callable from the node event loop.

#[cfg(target_arch = "wasm32")]
async fn http_post_json_auth(url: &str, body: &str, auth_token: &str) -> LijResult<String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&wasm_bindgen::JsValue::from_str(body)));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Backup(format!("Backup POST build: {e:?}")))?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| LijError::Backup(format!("Backup POST header: {e:?}")))?;
    if !auth_token.is_empty() {
        request
            .headers()
            .set("Authorization", &format!("Bearer {auth_token}"))
            .map_err(|e| LijError::Backup(format!("Backup POST auth header: {e:?}")))?;
    }

    let window = web_sys::window()
        .ok_or_else(|| LijError::Backup("Backup POST: no window".into()))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| LijError::Backup(format!("Backup POST fetch: {e:?}")))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| LijError::Backup("Backup POST response cast".into()))?;

    let text_promise = resp
        .text()
        .map_err(|e| LijError::Backup(format!("Backup POST text promise: {e:?}")))?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|e| LijError::Backup(format!("Backup POST text await: {e:?}")))?;
    let text = text_js
        .as_string()
        .ok_or_else(|| LijError::Backup("Backup POST body not a string".into()))?;

    if !resp.ok() {
        return Err(LijError::Backup(format!(
            "Backup POST HTTP {} {url} — {text}",
            resp.status()
        )));
    }
    Ok(text)
}

/// GET that maps HTTP 404 to `Ok(None)` (no backup stored yet) and any other
/// non-2xx to `Err`.
#[cfg(target_arch = "wasm32")]
async fn http_get_auth(url: &str, auth_token: &str) -> LijResult<Option<String>> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Backup(format!("Backup GET build: {e:?}")))?;
    if !auth_token.is_empty() {
        request
            .headers()
            .set("Authorization", &format!("Bearer {auth_token}"))
            .map_err(|e| LijError::Backup(format!("Backup GET auth header: {e:?}")))?;
    }

    let window = web_sys::window()
        .ok_or_else(|| LijError::Backup("Backup GET: no window".into()))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| LijError::Backup(format!("Backup GET fetch: {e:?}")))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| LijError::Backup("Backup GET response cast".into()))?;

    if resp.status() == 404 {
        return Ok(None);
    }

    let text_promise = resp
        .text()
        .map_err(|e| LijError::Backup(format!("Backup GET text promise: {e:?}")))?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|e| LijError::Backup(format!("Backup GET text await: {e:?}")))?;
    let text = text_js
        .as_string()
        .ok_or_else(|| LijError::Backup("Backup GET body not a string".into()))?;

    if !resp.ok() {
        return Err(LijError::Backup(format!(
            "Backup GET HTTP {} {url} — {text}",
            resp.status()
        )));
    }
    Ok(Some(text))
}

// ── HTTP transport (native target — no-op so tests exercise the fresh path) ──
// On native we don't hit the network: push is a silent success, pull reports
// "no backup", so wallet restore falls through to a fresh node exactly as before.

#[cfg(not(target_arch = "wasm32"))]
async fn http_post_json_auth(_url: &str, _body: &str, _auth_token: &str) -> LijResult<String> {
    Ok("{\"ok\":true}".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn http_get_auth(_url: &str, _auth_token: &str) -> LijResult<Option<String>> {
    Ok(None)
}

// ── Backup challenge signing ─────────────────────────────────────────────────
// Digest MUST match the Worker byte-for-byte:
//   sha256("lij-backup-v1" || action || nonce_bytes || pubkey_bytes)
// (nonce and pubkey are hex-decoded before hashing, exactly as the Worker does.)

const BACKUP_DOMAIN: &[u8] = b"lij-backup-v1";
const BACKUP_ACTION_PUSH: &str = "backup-push";
const BACKUP_ACTION_READ: &str = "backup-read";

fn backup_digest(action: &str, nonce_hex: &str, pubkey_hex: &str) -> LijResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let nonce = hex::decode(nonce_hex)
        .map_err(|e| LijError::Backup(format!("nonce hex decode: {e}")))?;
    let pubkey = hex::decode(pubkey_hex)
        .map_err(|e| LijError::Backup(format!("pubkey hex decode: {e}")))?;
    let mut h = Sha256::new();
    h.update(BACKUP_DOMAIN);
    h.update(action.as_bytes());
    h.update(&nonce);
    h.update(&pubkey);
    Ok(h.finalize().into())
}

/// POST that maps HTTP 404 to `Ok(None)` (no backup stored) and other non-2xx
/// to `Err`. Used by the authenticated /backup/fetch read.
#[cfg(target_arch = "wasm32")]
async fn http_post_json_opt(url: &str, body: &str) -> LijResult<Option<String>> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&wasm_bindgen::JsValue::from_str(body)));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| LijError::Backup(format!("Backup fetch build: {e:?}")))?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| LijError::Backup(format!("Backup fetch header: {e:?}")))?;

    let window = web_sys::window()
        .ok_or_else(|| LijError::Backup("Backup fetch: no window".into()))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| LijError::Backup(format!("Backup fetch send: {e:?}")))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| LijError::Backup("Backup fetch response cast".into()))?;

    if resp.status() == 404 {
        return Ok(None);
    }

    let text_promise = resp
        .text()
        .map_err(|e| LijError::Backup(format!("Backup fetch text promise: {e:?}")))?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|e| LijError::Backup(format!("Backup fetch text await: {e:?}")))?;
    let text = text_js
        .as_string()
        .ok_or_else(|| LijError::Backup("Backup fetch body not a string".into()))?;

    if !resp.ok() {
        return Err(LijError::Backup(format!(
            "Backup fetch HTTP {} {url} — {text}",
            resp.status()
        )));
    }
    Ok(Some(text))
}

#[cfg(not(target_arch = "wasm32"))]
async fn http_post_json_opt(_url: &str, _body: &str) -> LijResult<Option<String>> {
    Ok(None)
}

// ── Pluggable backup sinks ───────────────────────────────────────────────────
// A BackupSink is one destination for the full encrypted StateBlob. Users will
// eventually choose which sinks are enabled (privacy vs redundancy): Cloudflare
// KV now, an on-device file later, etc. Enum dispatch rather than a dyn async
// trait because the crate has no async-trait dependency — add a variant to add
// a sink, with no change at the call sites that push/pull.

#[derive(Clone)]
pub enum BackupSink {
    CloudflareKv(KvBackupClient),
    // Future: LocalFile(LocalFileSink) — single encrypted file on the device,
    // overwritten on each channel change.
}

impl BackupSink {
    pub async fn push(&self, blob: &StateBlob, signer: &dyn BackupSigner) -> LijResult<()> {
        match self {
            BackupSink::CloudflareKv(sink) => sink.push(blob, signer).await,
        }
    }

    pub async fn pull(
        &self,
        pubkey_hex: &str,
        signer: &dyn BackupSigner,
    ) -> LijResult<Option<StateBlob>> {
        match self {
            BackupSink::CloudflareKv(sink) => sink.pull(pubkey_hex, signer).await,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            BackupSink::CloudflareKv(_) => "cloudflare-kv",
        }
    }
}

// ── Recovery configuration ───────────────────────────────────────────────────
// Which recovery tiers/sinks are enabled. Hardcoded defaults today; a future
// settings UI just writes these flags — no code change required.
//   Tier A — full encrypted state, one flag per sink (Cloudflare, local file…)
//   Tier B — LSP-assisted: registry summary records + channel reestablish
//   Tier C — seed-only force-close sweep (the always-available floor)

#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    pub full_state_cloudflare: bool,
    pub full_state_local_file: bool, // reserved for the on-device file sink
    pub lsp_assisted: bool,
    pub seed_only_force: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            full_state_cloudflare: true,
            full_state_local_file: false,
            lsp_assisted: true,
            seed_only_force: true,
        }
    }
}

// ── Worker API contract ──────────────────────────────────────────────────────
// These are the endpoints your Cloudflare Worker must implement.
// Document this for when you build the Worker side.
//
// POST /backup
//   Body: StateBlob JSON
//   Headers: Authorization: Bearer {auth_token}
//   Action: KV.put(`backup:{pubkey_hex}`, body)
//   Returns: { "ok": true }
//
// GET /backup/:pubkey_hex
//   Headers: Authorization: Bearer {auth_token}
//   Action: KV.get(`backup:{pubkey_hex}`)
//   Returns: StateBlob JSON or 404
//
// GET /lsps
//   No auth required — public registry
//   Returns: { "lsps": [ { "name", "pubkey", "endpoint", "fee_ppm", "uptime" } ] }
//
// POST /lsps/register
//   Body: { "name", "pubkey", "endpoint", "operator_sig" }
//   Action: validates sig, KV.put(`lsp:{pubkey}`, body)
//   Returns: { "ok": true }
