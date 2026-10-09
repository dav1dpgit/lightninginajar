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
    /// v309 (S56, DP 2026-10-06 "with dates and times of both files"): when this copy was taken, unix
    /// milliseconds. Plain, not encrypted — a date is what the warning before loading a file shows for the
    /// file and for the cloud copy. 0 = taken by an older engine (date unknown).
    #[serde(default)]
    pub saved_at_ms: u64,
}

/// Unix time in milliseconds (the browser's clock on wasm).
pub fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    { js_sys::Date::now() as u64 }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

// ── v309 (S56, DP 2026-10-06 "Go" on the cloud-copy guard): THE BACKUP NUMBER IS KEPT ONLY WHEN THE CLOUD ACCEPTS ──
// Until v309 every snapshot wrote the next number to the phone before the upload was answered, and a refused upload
// (the cloud holds a higher number) was simply tried again 30 s later with the next number — a phone that had loaded
// an older backup file counted its way past the cloud's number in about an hour and replaced newer channel state with
// older. Now the snapshot only PEEKS the next number; the number is COMMITTED after the sink accepted it (or a device
// file was written with it); a refusal is read for the cloud's number and stops the uploads until the person decides.

/// The number the next copy would carry (the stored number + 1); nothing is written.
pub fn backup_version_peek(storage: &dyn LijStorage) -> LijResult<u64> {
    Ok(backup_version_stored(storage)? + 1)
}

/// The number the phone holds (0 when it never held one).
pub fn backup_version_stored(storage: &dyn LijStorage) -> LijResult<u64> {
    Ok(match storage.get(KEY_BACKUP_VERSION)? {
        Some(b) if b.len() == 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b);
            u64::from_be_bytes(a)
        }
        _ => 0,
    })
}

/// Keep `version` as the phone's number — only upward (a lower number never rolls it back).
pub fn backup_version_commit(storage: &dyn LijStorage, version: u64) -> LijResult<()> {
    if version > backup_version_stored(storage)? {
        storage.set(KEY_BACKUP_VERSION, &version.to_be_bytes())?;
    }
    Ok(())
}

// ── v319 (S57, DP 2026-10-08 14:40 "Agreed on the fix for the cloud copy fingerprint. Go"): THE PHONE KNOWS ITS OWN UPLOAD ──
// FOUND (DP's phone, 14:33): "Your cloud copy is newer than this phone — cloud no. 6142, this phone no. 6141". The phone
// had uploaded 6142 itself; the cloud stored it; the app was put away before the OK arrived, so the number was never
// committed (v309 commits only on the OK). At the next open the cloud's 6142 read as another copy's. Now, before each
// upload, the phone NOTES the number and a fingerprint (sha256 of the sealed bytes) of the copy it sends; the cloud
// keeps the fingerprint of the copy it stores (worker 0.10.0) and answers it with the number; a cloud copy carrying
// this phone's own note is this phone's upload — the number is taken, no warning. Only a copy this phone never sent
// raises it. (The worker also accepts a resend of the very same copy as an OK, so the retry after a lost OK while
// the app is open is not a false conflict either.)

/// The fingerprint of a copy — sha256 of its sealed bytes, hex (what the worker computes over the same bytes).
pub fn backup_fingerprint(blob: &StateBlob) -> String {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(&blob.encrypted_data).to_string()
}

/// The note made before an upload: the number and the fingerprint of the copy on its way. 8 bytes BE + 32 bytes.
pub fn backup_inflight_note(storage: &dyn LijStorage, version: u64, fingerprint_hex: &str) -> LijResult<()> {
    let fp = hex::decode(fingerprint_hex).map_err(|e| LijError::Backup(format!("fingerprint hex: {e}")))?;
    if fp.len() != 32 { return Err(LijError::Backup("fingerprint: not 32 bytes".into())); }
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(&fp);
    storage.set(KEY_BACKUP_INFLIGHT, &v)
}

/// The note, if one stands: (number, fingerprint hex). None when no upload is outstanding or the note is malformed.
pub fn backup_inflight(storage: &dyn LijStorage) -> LijResult<Option<(u64, String)>> {
    Ok(match storage.get(KEY_BACKUP_INFLIGHT)? {
        Some(b) if b.len() == 40 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8]);
            Some((u64::from_be_bytes(a), hex::encode(&b[8..])))
        }
        _ => None,
    })
}

/// The note is cleared once the cloud answered (accepted, or refused as older — the copy is not on its way any more).
pub fn backup_inflight_clear(storage: &dyn LijStorage) -> LijResult<()> {
    storage.delete(KEY_BACKUP_INFLIGHT)
}

/// What /backup/meta says the cloud holds: the number, the date, and (worker 0.10.0) the stored copy's fingerprint —
/// None for a copy stored by an older worker, or by a worker without the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMeta {
    pub version: u64,
    pub saved_at_ms: u64,
    pub fingerprint: Option<String>,
}

/// Is the cloud's copy this phone's own upload? — its number AND fingerprint are the ones this phone noted before
/// sending. A cloud copy without a fingerprint, or a phone without a note, is never "own".
pub fn backup_meta_is_own(meta: &BackupMeta, inflight: Option<&(u64, String)>) -> bool {
    match (inflight, meta.fingerprint.as_deref()) {
        (Some((v, fp)), Some(cfp)) => *v == meta.version && fp == cfp,
        _ => false,
    }
}

/// v310: the worker's /backup/meta answer — {"found":true,"version":v,"saved_at_ms":t,"fingerprint":h|null} →
/// Some(BackupMeta); {"found":false} → None; anything else is not an answer (an error, so the caller starts as it
/// always has). v319: the fingerprint (64 hex) when the worker answers one.
pub fn parse_backup_meta(text: &str) -> LijResult<Option<BackupMeta>> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| LijError::Backup(format!("meta parse: {e}")))?;
    match v.get("found").and_then(|f| f.as_bool()) {
        Some(true) => {
            let version = v.get("version").and_then(|x| x.as_u64())
                .ok_or_else(|| LijError::Backup("meta: no version".into()))?;
            let saved_at_ms = v.get("saved_at_ms").and_then(|x| x.as_u64()).unwrap_or(0);
            let fingerprint = v.get("fingerprint").and_then(|x| x.as_str())
                .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
                .map(|s| s.to_ascii_lowercase());
            Ok(Some(BackupMeta { version, saved_at_ms, fingerprint }))
        }
        Some(false) => Ok(None),
        None => Err(LijError::Backup(format!("meta: not an answer: {}", text.chars().take(80).collect::<String>()))),
    }
}

/// The cloud's number out of a refused upload's words ("Stale backup rejected: existing v220 >= incoming v101"),
/// or None when the error is something else (no connection, a 500, …).
pub fn parse_stale_refusal(err: &str) -> Option<u64> {
    if !err.contains("Stale backup rejected") { return None; }
    let i = err.find("existing v")? + "existing v".len();
    let digits: String = err[i..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
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

/// v256 (S46, DP: "Encrypt it"): a storage wrapper that encrypts the named keys at rest
/// with the wallet's persistence key (the same AES-256-GCM the channel blobs use), and
/// reads a legacy plaintext value transparently so the first write after the upgrade
/// migrates it. Other keys pass straight through.
pub struct EncryptedKeys<S: LijStorage> {
    inner: S,
    key: [u8; 32],
    keys: &'static [&'static str],
}

const ENC_MAGIC: &[u8; 4] = b"ENC1";

impl<S: LijStorage> EncryptedKeys<S> {
    pub fn new(inner: S, key: [u8; 32], keys: &'static [&'static str]) -> Self {
        Self { inner, key, keys }
    }
    fn covered(&self, key: &str) -> bool {
        self.keys.iter().any(|k| *k == key)
    }
}

impl<S: LijStorage> LijStorage for EncryptedKeys<S> {
    fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>> {
        let raw = match self.inner.get(key)? {
            Some(v) => v,
            None => return Ok(None),
        };
        if !self.covered(key) || !raw.starts_with(ENC_MAGIC) {
            return Ok(Some(raw));   // pass-through, or a legacy plaintext value
        }
        let pt = crate::persist::decrypt(&self.key, &raw[ENC_MAGIC.len()..])
            .map_err(|e| LijError::Storage(format!("encrypted key {key}: {e}")))?;
        Ok(Some(pt))
    }
    fn set(&self, key: &str, value: &[u8]) -> LijResult<()> {
        if !self.covered(key) {
            return self.inner.set(key, value);
        }
        let ct = crate::persist::encrypt(&self.key, value)
            .map_err(|e| LijError::Storage(format!("encrypt {key}: {e}")))?;
        let mut out = Vec::with_capacity(ENC_MAGIC.len() + ct.len());
        out.extend_from_slice(ENC_MAGIC);
        out.extend_from_slice(&ct);
        self.inner.set(key, &out)
    }
    fn delete(&self, key: &str) -> LijResult<()> {
        self.inner.delete(key)
    }
    fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>> {
        self.inner.list_with_prefix(prefix)
    }
}

/// v263 (S47): a borrowed store is a store — lets EncryptedKeys wrap the node's shared
/// storage (`&dyn LijStorage`) without owning it.
impl<T: LijStorage + ?Sized> LijStorage for &T {
    fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>> { (**self).get(key) }
    fn set(&self, key: &str, value: &[u8]) -> LijResult<()> { (**self).set(key, value) }
    fn delete(&self, key: &str) -> LijResult<()> { (**self).delete(key) }
    fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>> { (**self).list_with_prefix(prefix) }
}

// ── Key name constants ───────────────────────────────────────────────────────
// These are the localStorage keys. Namespaced to avoid collisions.

pub const KEY_CHANNEL_MANAGER: &str = "lij_channel_manager";
pub const KEY_CHANNEL_MONITORS: &str = "lij_channel_monitors";
pub const KEY_NETWORK_GRAPH: &str = "lij_network_graph";
pub const KEY_SCORER: &str = "lij_scorer";
pub const KEY_LSP_CONFIG: &str = "lij_lsp_config";
pub const KEY_BACKUP_VERSION: &str = "lij_backup_version";
/// v319: the number and fingerprint of the copy on its way to the cloud (storage::backup_inflight_note).
pub const KEY_BACKUP_INFLIGHT: &str = "lij_backup_inflight";

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
    /// v250 (S46, DP GO): delete this wallet's cloud copy. Same signed challenge as
    /// push/pull, action "backup-forget" — only the key that wrote the blob can
    /// forget it. Returns whether a blob existed. Local state is untouched.
    pub async fn forget(&self, signer: &dyn BackupSigner) -> LijResult<bool> {
        let pubkey = signer.portable_pubkey_hex()?;
        let nonce = self.get_challenge(&pubkey).await?;
        let digest = backup_digest(BACKUP_ACTION_FORGET, &nonce, &pubkey)?;
        let signature = signer.sign_backup(&digest)?;
        let envelope = serde_json::json!({
            "pubkey_hex": pubkey,
            "nonce": nonce,
            "signature": signature,
        });
        let url = format!("{}/backup/forget", self.config.worker_url);
        let resp = http_post_json_auth(&url, &envelope.to_string(), "").await?;
        let v: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| LijError::Backup(format!("forget parse: {e}")))?;
        if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            return Err(LijError::Backup(format!("forget refused: {resp}")));
        }
        Ok(v.get("existed").and_then(|e| e.as_bool()).unwrap_or(false))
    }

    /// v310 (S57, DP 2026-10-07 "Go with … 1"): the cloud copy's NUMBER AND DATE only (worker 0.9.0 /backup/meta) —
    /// the wallet compares them with its own before it connects to its provider, without pulling the whole sealed
    /// copy (~1.4 MB) at every unlock. Same signed challenge as pull ("backup-read"). Ok(Some(BackupMeta)) (v319: with
    /// the stored copy's fingerprint when the worker answers one) / Ok(None) = the service holds no copy / Err = no
    /// answer, or a worker without the route (its 404).
    pub async fn meta(
        &self,
        pubkey_hex: &str,
        signer: &dyn BackupSigner,
    ) -> LijResult<Option<BackupMeta>> {
        let nonce = self.get_challenge(pubkey_hex).await?;
        let digest = backup_digest(BACKUP_ACTION_READ, &nonce, pubkey_hex)?;
        let signature = signer.sign_backup(&digest)?;
        let envelope = serde_json::json!({
            "pubkey_hex": pubkey_hex,
            "nonce": nonce,
            "signature": signature,
        });
        let url = format!("{}/backup/meta", self.config.worker_url);
        match http_post_json_opt(&url, &envelope.to_string()).await? {
            Some(text) => parse_backup_meta(&text),
            None => Err(LijError::Backup("meta: the backup service has no /backup/meta (404)".into())),
        }
    }

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
/// v250: the wallet forgets its own cloud copy (the worker's /backup/forget).
const BACKUP_ACTION_FORGET: &str = "backup-forget";
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

    /// v250: forget this wallet's copy at the sink. Returns whether one existed.
    pub async fn forget(&self, signer: &dyn BackupSigner) -> LijResult<bool> {
        match self {
            BackupSink::CloudflareKv(sink) => sink.forget(signer).await,
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

#[cfg(test)]
mod v310_backup_meta_tests {
    use super::*;

    #[test]
    fn v310_meta_reads_the_number_and_the_date() {
        assert_eq!(parse_backup_meta(r#"{"found":true,"version":7,"saved_at_ms":1791307311302}"#).unwrap(), Some(BackupMeta { version: 7, saved_at_ms: 1791307311302, fingerprint: None }));
        assert_eq!(parse_backup_meta(r#"{"found":true,"version":3,"saved_at_ms":0}"#).unwrap(), Some(BackupMeta { version: 3, saved_at_ms: 0, fingerprint: None }), "a copy saved before v309 has no date");
    }

    #[test]
    fn v310_no_copy_is_none_and_a_non_answer_is_an_error() {
        assert_eq!(parse_backup_meta(r#"{"found":false}"#).unwrap(), None);
        assert!(parse_backup_meta(r#"{"error":"Not found"}"#).is_err(), "a worker without the route is not 'no copy'");
        assert!(parse_backup_meta("<html>").is_err());
        assert!(parse_backup_meta(r#"{"found":true}"#).is_err(), "found without a number is not an answer");
    }
}

#[cfg(test)]
mod v319_own_upload_tests {
    use super::*;
    use native_storage::MemoryStorage;

    fn blob(seed: u8, version: u64) -> StateBlob {
        StateBlob { version, encrypted_data: (0..5000u32).map(|i| (seed as u32 * 31 + i * 7) as u8).collect(), nonce: vec![], pubkey_hex: "02ab".into(), saved_at_ms: 5 }
    }

    #[test]
    fn v319_the_fingerprint_is_the_sha256_of_the_sealed_bytes_as_the_worker_takes_it() {
        let b = blob(1, 10);
        let fp = backup_fingerprint(&b);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "lowercase hex, as the worker writes it: {fp}");
        // the same bytes the worker's test hashes (test-backup-meta.mjs b8: bytes(1, 5000) → (1*31 + i*7) & 255)
        use sha2::Digest;
        assert_eq!(fp, hex::encode(sha2::Sha256::digest(&b.encrypted_data)), "plain sha256 over encrypted_data, nothing else");
        assert_ne!(fp, backup_fingerprint(&blob(2, 10)), "other bytes, other fingerprint");
        let mut same = blob(1, 11); same.saved_at_ms = 99;
        assert_eq!(fp, backup_fingerprint(&same), "the number and the date are outside the fingerprint — the bytes alone");
    }

    #[test]
    fn v319_the_note_is_made_before_the_upload_and_read_back_whole() {
        let s = MemoryStorage::new();
        assert_eq!(backup_inflight(&s).unwrap(), None, "no upload outstanding");
        let b = blob(1, 6142);
        let fp = backup_fingerprint(&b);
        backup_inflight_note(&s, 6142, &fp).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), Some((6142, fp.clone())), "the number and the fingerprint, as noted");
        assert_eq!(backup_version_stored(&s).unwrap(), 0, "the note commits nothing — the number stays the phone's old one until the cloud answers");
        backup_inflight_clear(&s).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), None, "cleared once the cloud answered");
        assert!(backup_inflight_note(&s, 1, "abcd").is_err(), "a short fingerprint is refused");
        s.set(KEY_BACKUP_INFLIGHT, &[1u8; 7]).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), None, "a malformed note is no note");
    }

    #[test]
    fn v319_the_clouds_copy_is_this_phones_own_only_when_number_and_fingerprint_both_match() {
        let b = blob(1, 6142);
        let fp = backup_fingerprint(&b);
        let note = (6142u64, fp.clone());
        let own = BackupMeta { version: 6142, saved_at_ms: 1, fingerprint: Some(fp.clone()) };
        assert!(backup_meta_is_own(&own, Some(&note)), "DP's case: the phone uploaded 6142, the app was put away before the OK — the cloud's 6142 is this phone's");
        let other_bytes = BackupMeta { version: 6142, saved_at_ms: 1, fingerprint: Some(backup_fingerprint(&blob(2, 6142))) };
        assert!(!backup_meta_is_own(&other_bytes, Some(&note)), "the same number from another copy: not own — the warning stands");
        let other_number = BackupMeta { version: 6143, saved_at_ms: 1, fingerprint: Some(fp.clone()) };
        assert!(!backup_meta_is_own(&other_number, Some(&note)), "another number: not own");
        let old_worker = BackupMeta { version: 6142, saved_at_ms: 1, fingerprint: None };
        assert!(!backup_meta_is_own(&old_worker, Some(&note)), "a cloud copy without a fingerprint (stored by worker 0.9.0): never own");
        assert!(!backup_meta_is_own(&own, None), "a phone without a note: never own");
    }

    #[test]
    fn v319_meta_reads_the_fingerprint_when_the_worker_answers_one() {
        let fp = "ab".repeat(32);
        let m = parse_backup_meta(&format!(r#"{{"found":true,"version":6142,"saved_at_ms":1791307311302,"fingerprint":"{fp}"}}"#)).unwrap().unwrap();
        assert_eq!(m, BackupMeta { version: 6142, saved_at_ms: 1791307311302, fingerprint: Some(fp.clone()) });
        let m = parse_backup_meta(r#"{"found":true,"version":12,"saved_at_ms":5,"fingerprint":null}"#).unwrap().unwrap();
        assert_eq!(m.fingerprint, None, "worker 0.10.0 answers null for a copy stored before it");
        let m = parse_backup_meta(r#"{"found":true,"version":12,"saved_at_ms":5,"fingerprint":"zz"}"#).unwrap().unwrap();
        assert_eq!(m.fingerprint, None, "a malformed fingerprint reads as none (never a match)");
        let m = parse_backup_meta(&format!(r#"{{"found":true,"version":1,"saved_at_ms":5,"fingerprint":"{}"}}"#, "AB".repeat(32))).unwrap().unwrap();
        assert_eq!(m.fingerprint, Some("ab".repeat(32)), "read lowercase, so it compares with the phone's");
    }
}

#[cfg(test)]
mod v309_backup_number_tests {
    use super::*;
    use native_storage::MemoryStorage;

    #[test]
    fn v309_the_number_is_only_peeked_until_the_cloud_accepts_it() {
        let s = MemoryStorage::new();
        assert_eq!(backup_version_peek(&s).unwrap(), 1, "a phone that never held a number offers 1");
        assert_eq!(backup_version_peek(&s).unwrap(), 1, "peeking writes nothing — a refused upload uses up no number");
        backup_version_commit(&s, 1).unwrap();
        assert_eq!(backup_version_peek(&s).unwrap(), 2, "after the cloud accepted 1, the next is 2");
        backup_version_commit(&s, 1).unwrap();
        assert_eq!(backup_version_stored(&s).unwrap(), 1, "a number not above the held one changes nothing");
        backup_version_commit(&s, 220).unwrap();
        assert_eq!(backup_version_peek(&s).unwrap(), 221, "the number may jump up (the cloud's number adopted on purpose)");
    }

    #[test]
    fn v309_a_refusal_names_the_clouds_number_and_nothing_else_does() {
        let w = "Backup POST HTTP 409 https://x/backup — {\"ok\":false,\"error\":\"Stale backup rejected: existing v220 >= incoming v101\"}";
        assert_eq!(parse_stale_refusal(w), Some(220), "the Worker's own words, as the engine receives them");
        assert_eq!(parse_stale_refusal("Backup POST fetch: TypeError: Failed to fetch"), None, "no connection is not a refusal");
        assert_eq!(parse_stale_refusal("Backup POST HTTP 500 https://x/backup — boom"), None);
        assert_eq!(parse_stale_refusal("Stale backup rejected: existing v >= incoming v1"), None, "no digits, no number");
    }

    #[test]
    fn v309_an_older_copy_without_a_date_still_opens_and_a_new_one_carries_its_date() {
        let old = r#"{"version":7,"encrypted_data":[1,2,3],"nonce":[],"pubkey_hex":"02ab"}"#;
        let b: StateBlob = serde_json::from_str(old).expect("a copy taken by an older engine parses");
        assert_eq!(b.saved_at_ms, 0, "date unknown");
        let n = StateBlob { version: 8, encrypted_data: vec![9], nonce: vec![], pubkey_hex: "02ab".into(), saved_at_ms: 1_759_770_000_000 };
        let j = serde_json::to_string(&n).unwrap();
        assert!(j.contains("\"saved_at_ms\":1759770000000"), "the date rides the copy in plain sight: {j}");
        let back: StateBlob = serde_json::from_str(&j).unwrap();
        assert_eq!(back.saved_at_ms, 1_759_770_000_000);
        assert!(now_ms() > 1_700_000_000_000);
    }
}
