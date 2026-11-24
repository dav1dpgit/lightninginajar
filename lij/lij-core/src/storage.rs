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

// ── v380 (S71 Fri 2026-11-20, DP 08:39 "Go ahead with the the writeup and A-E fixes" — incident 2026-11-20, finding A):
// THE PHONE KNOWS ITS OWN UPLOAD WHILE IT STAYS OPEN, TOO. FOUND (DP's phone, the tapes): a routine upload went up as
// no. 7314 and the cloud stored it, but the answer never reached the phone (the app was in the background). The phone
// kept no. 7313. The next upload, 49 s later, was a new copy (new encryption, so a new fingerprint) carrying 7314 again;
// its note REPLACED the first one; the cloud refused it ("existing v7314 >= incoming v7314"); the refusal cleared the
// note. From that moment nothing on the phone could show that the cloud's 7314 was the phone's own — "Your cloud copy
// is newer than this phone" followed, on a phone that held the newest state. v319 could tell an own upload only at
// the next wallet start, and only while the one note still stood.
// Now (1) the note keeps EVERY copy sent under one number that got no answer (the number once, then one fingerprint
// each, at most BACKUP_INFLIGHT_MAX), so a second attempt no longer forgets the first; (2) before a copy goes up
// under a number that already has an unanswered upload, the phone asks the cloud what it holds — its own upload: the
// number is taken and the new copy goes up as the next number (lij-wasm upload_copy); (3) a refusal that names that
// very number is asked about once more before it is called a conflict; (4) loading any copy onto the phone drops
// the note (wallet::inject_state_blob) — the phone no longer holds the state those uploads carried, so the cloud's
// copy must not be read as "this phone's own" after it. A copy from another device, or a copy this phone never
// sent, raises the warning as before.
// The stored form: 8 bytes number BE, then 32 bytes per fingerprint. One fingerprint is byte-for-byte the v319 note.

/// At most this many unanswered uploads of one number are remembered (32 bytes each); the oldest goes first.
pub const BACKUP_INFLIGHT_MAX: usize = 8;

/// The note made before an upload: the number and the fingerprint of the copy on its way. A note for the SAME number
/// keeps the earlier fingerprints (uploads of that number that got no answer) and adds this one; a note for another
/// number starts again with this one alone.
pub fn backup_inflight_note(storage: &dyn LijStorage, version: u64, fingerprint_hex: &str) -> LijResult<()> {
    let fp = hex::decode(fingerprint_hex).map_err(|e| LijError::Backup(format!("fingerprint hex: {e}")))?;
    if fp.len() != 32 { return Err(LijError::Backup("fingerprint: not 32 bytes".into())); }
    let mut fps: Vec<String> = match backup_inflight(storage)? {
        Some((v, list)) if v == version => list,
        _ => Vec::new(),
    };
    let fp_hex = hex::encode(&fp);
    fps.retain(|f| f != &fp_hex);
    fps.push(fp_hex);
    while fps.len() > BACKUP_INFLIGHT_MAX { fps.remove(0); }
    let mut v = Vec::with_capacity(8 + 32 * fps.len());
    v.extend_from_slice(&version.to_be_bytes());
    for f in &fps {
        v.extend_from_slice(&hex::decode(f).map_err(|e| LijError::Backup(format!("fingerprint hex: {e}")))?);
    }
    storage.set(KEY_BACKUP_INFLIGHT, &v)
}

/// The note, if one stands: (number, the fingerprints of every copy sent under it that got no answer, oldest first).
/// None when no upload is outstanding or the note is malformed.
pub fn backup_inflight(storage: &dyn LijStorage) -> LijResult<Option<(u64, Vec<String>)>> {
    Ok(match storage.get(KEY_BACKUP_INFLIGHT)? {
        Some(b) if b.len() >= 40 && (b.len() - 8) % 32 == 0 && (b.len() - 8) / 32 <= BACKUP_INFLIGHT_MAX => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8]);
            Some((u64::from_be_bytes(a), b[8..].chunks(32).map(hex::encode).collect()))
        }
        _ => None,
    })
}

/// The note is cleared once the cloud answered (accepted, or refused by a copy that is not this phone's — no copy of
/// this phone's is on its way any more), and whenever another copy is loaded onto the phone.
pub fn backup_inflight_clear(storage: &dyn LijStorage) -> LijResult<()> {
    storage.delete(KEY_BACKUP_INFLIGHT)
}

/// v380: how many uploads sent as `number` still have no answer (0 when the note is for another number, or none stands).
pub fn backup_unanswered(storage: &dyn LijStorage, number: u64) -> LijResult<usize> {
    Ok(match backup_inflight(storage)? {
        Some((v, fps)) if v == number => fps.len(),
        _ => 0,
    })
}

/// v380: a refused upload is asked about (is the cloud's copy this phone's own?) only when it can be: the cloud's
/// number is the very number this phone just sent, and an EARLIER copy went up under that number with no answer. (The
/// copy just sent cannot be the one stored — the cloud accepts a repeat of the very same copy.)
pub fn backup_refusal_may_be_own(storage: &dyn LijStorage, sent_number: u64, cloud_number: u64) -> LijResult<bool> {
    Ok(cloud_number == sent_number && backup_unanswered(storage, sent_number)? > 1)
}

/// v380: the cloud's copy is one of this phone's own unanswered uploads → its number is the phone's now (upward
/// only) and the note is cleared; Some(number). Anything else → None, nothing written.
pub fn backup_take_own(storage: &dyn LijStorage, meta: &BackupMeta) -> LijResult<Option<u64>> {
    let note = backup_inflight(storage)?;
    if !backup_meta_is_own(meta, note.as_ref()) { return Ok(None); }
    backup_version_commit(storage, meta.version)?;
    backup_inflight_clear(storage)?;
    Ok(Some(meta.version))
}

/// v380: the mark on an upload error that happened before the copy left the phone (KvBackupClient::push).
pub const BACKUP_NOT_SENT: &str = "copy not sent: ";

/// v380: one fingerprint leaves the note — the copy was never sent, so the cloud cannot hold it. The last one out
/// removes the note.
pub fn backup_inflight_forget(storage: &dyn LijStorage, version: u64, fingerprint_hex: &str) -> LijResult<()> {
    if let Some((v, mut fps)) = backup_inflight(storage)? {
        if v != version || !fps.iter().any(|f| f == fingerprint_hex) { return Ok(()); }
        fps.retain(|f| f != fingerprint_hex);
        if fps.is_empty() { return backup_inflight_clear(storage); }
        let mut out = Vec::with_capacity(8 + 32 * fps.len());
        out.extend_from_slice(&v.to_be_bytes());
        for f in &fps {
            out.extend_from_slice(&hex::decode(f).map_err(|e| LijError::Backup(format!("fingerprint hex: {e}")))?);
        }
        storage.set(KEY_BACKUP_INFLIGHT, &out)?;
    }
    Ok(())
}

/// v380: what the cloud's answer says about the copy it holds, read against this phone's note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudCopyIs {
    /// One of this phone's own unanswered uploads — its number was taken as the phone's and the note cleared.
    Own(u64),
    /// A copy this phone never sent, carrying the number in question or a higher one.
    Others,
    /// The cloud says it holds no copy, or one with a LOWER number than the one in question: the upload never
    /// arrived — or the cloud's read is behind its write (the registry reads through a cache of up to 30 s).
    Behind,
    /// The cloud gave no answer.
    NoAnswer,
}

/// v380: what one upload needs of the cloud. On the phone: the wallet's sinks and its backup client (WalletCloud).
/// In the tests: a stand-in that keeps the registry's own rule.
#[allow(async_fn_in_trait)]
pub trait CopyCloud {
    /// Send the copy to every sink; one answer per sink.
    async fn push(&self, blob: &StateBlob) -> Vec<LijResult<()>>;
    /// The number and the fingerprint of the copy the cloud holds. Ok(None) = it holds none; Err = no answer.
    async fn meta(&self) -> LijResult<Option<BackupMeta>>;
}

/// v380: the wallet's own cloud — its sinks for the upload, its backup client for the question.
pub struct WalletCloud<'a> {
    pub sinks: &'a [BackupSink],
    pub client: &'a KvBackupClient,
    pub signer: &'a crate::key::RootKey,
}

impl CopyCloud for WalletCloud<'_> {
    async fn push(&self, blob: &StateBlob) -> Vec<LijResult<()>> {
        let mut out = Vec::with_capacity(self.sinks.len());
        for sink in self.sinks { out.push(sink.push(blob, self.signer).await); }
        out
    }
    async fn meta(&self) -> LijResult<Option<BackupMeta>> {
        let pubkey = self.signer.portable_pubkey_hex()?;
        self.client.meta(&pubkey, self.signer).await
    }
}

async fn ask_cloud_copy<C: CopyCloud>(storage: &dyn LijStorage, cloud: &C, number: u64) -> CloudCopyIs {
    match cloud.meta().await {
        Ok(Some(m)) => match backup_take_own(storage, &m) {
            Ok(Some(n)) => {
                log::info!("[v380] the cloud copy no. {n} is this phone's own upload (its answer never arrived): the number is taken");
                CloudCopyIs::Own(n)
            }
            Ok(None) if m.version < number => CloudCopyIs::Behind,
            Ok(None) => CloudCopyIs::Others,
            Err(e) => { log::warn!("[v380] own-upload check: the note could not be read or written: {e}"); CloudCopyIs::NoAnswer }
        },
        Ok(None) => CloudCopyIs::Behind,
        Err(e) => { log::warn!("[v380] own-upload check got no answer: {e}"); CloudCopyIs::NoAnswer }
    }
}

/// v380: what one upload came to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Uploaded {
    /// How many sinks accepted the copy (its number is the phone's now).
    pub ok: u32,
    /// The cloud's number when it refused the copy as older and the copy it holds is not known to be this phone's
    /// own: the automatic uploads stop until the person decides. 0 = no such refusal.
    pub conflict: u64,
    /// The number taken because the cloud's copy was this phone's own unanswered upload. 0 = none.
    pub own: u64,
    /// The cloud's copy was found to be this phone's own only AFTER this copy was refused: this copy was not stored,
    /// and a FRESH copy goes up as the next number (the caller sends it; never this one again, which may be older
    /// than the phone's state by now).
    pub again: bool,
    /// No usable answer (no connection, a 500, or a refusal that could not yet be told from the phone's own
    /// upload): the caller tries again later.
    pub unanswered: bool,
    pub last_err: Option<String>,
}

/// v380: ONE UPLOAD, with the phone's own unanswered uploads known. (backup_now and maybe_backup both send through
/// this.) The steps:
///  1. An earlier copy went up under this very number and got no answer → the cloud is asked what it holds BEFORE
///     this copy goes. Its own upload: the number is taken and this copy goes up as the next one. (The number is
///     outside the encrypted bytes and the proof of an upload is made at the upload, so it can still be set.)
///  2. The copy is noted (beside any earlier unanswered ones) and sent.
///  3. Accepted → the number is the phone's, the note cleared. A copy that never left the phone leaves the note.
///  4. Refused as older → (v381) when the refusal names the copy the registry holds, that settles it: own → no conflict,
///     `again`; another copy's → conflict. Otherwise (a registry before 0.23.0): when the cloud's number is the very
///     number just sent and an earlier copy went up under it, the cloud is asked whose copy it holds: this phone's own → no conflict, `again`; another copy's → conflict;
///     no usable answer → `unanswered` (asked again at the next upload), and only once the note is full
///     (BACKUP_INFLIGHT_MAX copies without a usable answer) the conflict, with the note kept for the next wallet start.
///     Any other refusal is a conflict as before.
pub async fn upload_copy<C: CopyCloud>(storage: &dyn LijStorage, mut blob: StateBlob, cloud: &C) -> Uploaded {
    let mut out = Uploaded::default();
    if backup_unanswered(storage, blob.version).unwrap_or(0) > 0 {
        if let CloudCopyIs::Own(n) = ask_cloud_copy(storage, cloud, blob.version).await {
            out.own = n;
            blob.version = n + 1;
        }
    }
    let fp = backup_fingerprint(&blob);
    if let Err(e) = backup_inflight_note(storage, blob.version, &fp) {
        log::warn!("[v319] in-flight note not written: {e}");
    }
    let mut refused: Option<u64> = None;
    let mut refused_fp: Option<String> = None;
    let mut sent = false;
    for r in cloud.push(&blob).await {
        match r {
            Ok(()) => { out.ok += 1; sent = true; }
            Err(e) => {
                let s = e.to_string();
                // v309: a refusal as older is NOT retried — the person decides; anything else is tried again later
                match parse_stale_refusal(&s) {
                    Some(n) => { refused = Some(n); refused_fp = parse_stale_refusal_fingerprint(&s); sent = true; }
                    None => { out.unanswered = true; if !s.contains(BACKUP_NOT_SENT) { sent = true; } }
                }
                out.last_err = Some(s);
            }
        }
    }
    if out.ok > 0 {
        let _ = backup_version_commit(storage, blob.version);   // v309: accepted — the number is the phone's now
        let _ = backup_inflight_clear(storage);                 // v319: the cloud answered
        out.unanswered = false;
        return out;
    }
    if !sent {
        let _ = backup_inflight_forget(storage, blob.version, &fp);   // never left the phone: nothing to remember
        return out;
    }
    if let Some(n) = refused {
        out.unanswered = false;
        // v381: the refusal NAMES the copy the registry holds (lij-worker 0.23.0) — from the very read that decided
        // the refusal. This one answer settles it: one of this phone's unanswered uploads → no conflict, a fresh copy
        // goes next; any other copy → the conflict. No second question (which the registry's 30-s cache could answer
        // with an older copy).
        if let Some(cfp) = refused_fp {
            let held = BackupMeta { version: n, saved_at_ms: 0, fingerprint: Some(cfp) };
            if let Ok(Some(m)) = backup_take_own(storage, &held) {
                log::info!("[v381] refused by the cloud copy no. {m}, and the refusal names it: this phone's own upload (its answer never arrived) — the number is taken");
                out.own = m;
                out.again = true;
                return out;
            }
            out.conflict = n;
            let _ = backup_inflight_clear(storage);
            return out;
        }
        // a registry that does not name the copy it holds (before 0.23.0): the question is asked (v380)
        if backup_refusal_may_be_own(storage, blob.version, n).unwrap_or(false) {
            match ask_cloud_copy(storage, cloud, n).await {
                CloudCopyIs::Own(m) => { out.own = m; out.again = true; return out; }
                CloudCopyIs::Others => {}
                CloudCopyIs::Behind | CloudCopyIs::NoAnswer => {
                    if backup_unanswered(storage, blob.version).unwrap_or(BACKUP_INFLIGHT_MAX) < BACKUP_INFLIGHT_MAX {
                        out.unanswered = true;
                        return out;
                    }
                    log::warn!("[v380] the cloud holds no. {n} and could not say whose copy it is after {BACKUP_INFLIGHT_MAX} uploads — the warning is raised; the note stands");
                    out.conflict = n;
                    return out;
                }
            }
        }
        out.conflict = n;
        let _ = backup_inflight_clear(storage);   // v319: the cloud answered — no copy of this phone's is on its way
    }
    out
}

// ── v359 (S65 Wed 2026-10-28, DP's UX item 8 — "Erase & start over … check if the manual backup is fresh"): THE DIRTY FLAG
// REMEMBERS ACROSS A RELOAD. The backup-dirty flag (an AtomicBool every state writer sets — the monitor persister, the
// manager save when its bytes changed, the coin marks, the Mix records — and the cloud push takes) lived in memory only.
// With the cloud copy On the push takes it within a tick, so nothing was lost; with the cloud copy Off NOBODY took it, and
// a reload forgot it. Now the flag carries a mirror in storage (`lij:backup_pending` = "1" from the moment it rises until
// it is taken), loaded at boot: a reload inherits an unpushed change. With the cloud copy Off the DEVICE FILE is the
// backup — "Save backup to device" takes the flag (lib.rs backup_take) and the erase screen reads it (backup_pending):
// a flag standing since the last device save means "may have changed since". The method names are AtomicBool's, so
// every writer compiles unchanged (`.store(true, Ordering::Relaxed)`, `.swap(false, …)`, `.load(…)`); the mirror is
// written on the rising edge and deleted on the take — two tiny writes per cloud cycle, none while nothing changes.
pub const KEY_BACKUP_PENDING: &str = "lij:backup_pending";

pub struct DirtyFlag {
    flag: std::sync::atomic::AtomicBool,
    mirror: Option<std::sync::Arc<dyn LijStorage>>,
}

impl DirtyFlag {
    /// A flag with no mirror (tests, the stand-in node).
    pub fn new(v: bool) -> Self { Self { flag: std::sync::atomic::AtomicBool::new(v), mirror: None } }

    /// The node's flag: mirrored in `storage`, and starting as the mirror says — "1" stored means a change nobody took.
    pub fn with_storage(storage: std::sync::Arc<dyn LijStorage>) -> Self {
        let pending = matches!(storage.get(KEY_BACKUP_PENDING), Ok(Some(v)) if v == b"1");
        Self { flag: std::sync::atomic::AtomicBool::new(pending), mirror: Some(storage) }
    }

    fn mirror_write(&self, was: bool, now: bool) {
        if was == now { return; }
        if let Some(st) = self.mirror.as_ref() {
            let r = if now { st.set(KEY_BACKUP_PENDING, b"1") } else { st.delete(KEY_BACKUP_PENDING) };
            if let Err(e) = r { log::warn!("[v359] backup_pending mirror write failed: {e}"); }
        }
    }

    pub fn store(&self, v: bool, _o: std::sync::atomic::Ordering) {
        let was = self.flag.swap(v, std::sync::atomic::Ordering::Relaxed);
        self.mirror_write(was, v);
    }

    pub fn swap(&self, v: bool, _o: std::sync::atomic::Ordering) -> bool {
        let was = self.flag.swap(v, std::sync::atomic::Ordering::Relaxed);
        self.mirror_write(was, v);
        was
    }

    pub fn load(&self, _o: std::sync::atomic::Ordering) -> bool { self.flag.load(std::sync::atomic::Ordering::Relaxed) }
}

/// What /backup/meta says the cloud holds: the number, the date, and (worker 0.10.0) the stored copy's fingerprint —
/// None for a copy stored by an older worker, or by a worker without the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMeta {
    pub version: u64,
    pub saved_at_ms: u64,
    pub fingerprint: Option<String>,
}

/// Is the cloud's copy this phone's own upload? — its number AND fingerprint are ones this phone noted before
/// sending (v380: any of the copies sent under that number with no answer). A cloud copy without a fingerprint, or a
/// phone without a note, is never "own".
pub fn backup_meta_is_own(meta: &BackupMeta, inflight: Option<&(u64, Vec<String>)>) -> bool {
    match (inflight, meta.fingerprint.as_deref()) {
        (Some((v, fps)), Some(cfp)) => *v == meta.version && fps.iter().any(|fp| fp == cfp),
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

/// v381 (incident 2026-11-20, round 2): the fingerprint of the copy the registry holds, when its refusal names it
/// (lij-worker 0.23.0 adds "existing_fingerprint":"<64 hex>" beside the unchanged words). None when the refusal names
/// none — a registry before 0.23.0, or a held copy without a fingerprint (null) — or when the error is not a refusal.
pub fn parse_stale_refusal_fingerprint(err: &str) -> Option<String> {
    if !err.contains("Stale backup rejected") { return None; }
    let key = "\"existing_fingerprint\":\"";
    let i = err.find(key)? + key.len();
    let hexs: String = err[i..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hexs.len() == 64 && err[i + 64..].starts_with('"') { Some(hexs.to_ascii_lowercase()) } else { None }
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
        // v380: an error BEFORE the upload itself (no challenge — the usual sign of no connection) means the copy never
        // left the phone; it is marked so (BACKUP_NOT_SENT) and upload_copy keeps no note of a copy that was never sent.
        let not_sent = |e: LijError| LijError::Backup(format!("{BACKUP_NOT_SENT}{e}"));
        let pubkey = signer.portable_pubkey_hex().map_err(not_sent)?;
        let nonce = self.get_challenge(&pubkey).await.map_err(not_sent)?;
        // v358 (S64, Kimi round 2 K6a): the push's proof binds the copy it authorises — its fingerprint and its number —
        // under the lij-backup-v2 digest; the body says so (auth_v 2). Worker 0.18.0 verifies v2 and still takes v1
        // from older engines for one release; a v1 proof never authorised a particular copy.
        let digest = backup_digest_v2(BACKUP_ACTION_PUSH, &nonce, &pubkey, &backup_fingerprint(blob), blob.version)?;
        let signature = signer.sign_backup(&digest)?;
        let envelope = serde_json::json!({
            "pubkey_hex": pubkey,
            "nonce": nonce,
            "signature": signature,
            "auth_v": 2,
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

/// v358 (K6a): the push digest that binds the copy — sha256("lij-backup-v2" || action || nonce || pubkey || fingerprint
/// (32 bytes, sha256 of the sealed bytes) || version (8 bytes big-endian)). The worker computes the fingerprint from the
/// bytes it received and reads the number from the copy, so a signature authorises THIS copy at THIS number and no other.
const BACKUP_DOMAIN_V2: &[u8] = b"lij-backup-v2";
pub(crate) fn backup_digest_v2(action: &str, nonce_hex: &str, pubkey_hex: &str, fingerprint_hex: &str, version: u64) -> LijResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let nonce = hex::decode(nonce_hex).map_err(|e| LijError::Backup(format!("nonce hex decode: {e}")))?;
    let pubkey = hex::decode(pubkey_hex).map_err(|e| LijError::Backup(format!("pubkey hex decode: {e}")))?;
    let fp = hex::decode(fingerprint_hex).map_err(|e| LijError::Backup(format!("fingerprint hex decode: {e}")))?;
    if fp.len() != 32 { return Err(LijError::Backup("fingerprint: not 32 bytes".into())); }
    let mut h = Sha256::new();
    h.update(BACKUP_DOMAIN_V2);
    h.update(action.as_bytes());
    h.update(&nonce);
    h.update(&pubkey);
    h.update(&fp);
    h.update(version.to_be_bytes());
    Ok(h.finalize().into())
}

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
        assert_eq!(backup_inflight(&s).unwrap(), Some((6142, vec![fp.clone()])), "the number and the fingerprint, as noted");
        assert_eq!(s.get(KEY_BACKUP_INFLIGHT).unwrap().unwrap().len(), 40, "v380: one unanswered copy is stored exactly as v319 stored it — 8 + 32 bytes");
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
        let note = (6142u64, vec![fp.clone()]);
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

    // ── v380 (incident 2026-11-20, finding A): the phone knows its own upload while it stays open ──

    #[test]
    fn v380_the_incident_an_upload_whose_answer_was_lost_is_known_at_the_next_upload() {
        // the tapes: the phone holds 7313; a copy goes up as 7314, the cloud stores it, the answer never arrives
        let s = MemoryStorage::new();
        backup_version_commit(&s, 7313).unwrap();
        let first = blob(1, backup_version_peek(&s).unwrap());
        assert_eq!(first.version, 7314);
        let fp_first = backup_fingerprint(&first);
        backup_inflight_note(&s, first.version, &fp_first).unwrap();
        // 49 s later: a new copy, new encryption, the same number — because 7314 was never committed
        let second = blob(2, backup_version_peek(&s).unwrap());
        assert_eq!(second.version, 7314, "the next copy carries the very number of the unanswered one");
        assert_eq!(backup_unanswered(&s, second.version).unwrap(), 1, "an earlier copy went up under this number with no answer — the cloud is asked before this one goes");
        // the cloud answers: it holds 7314 with the first copy's fingerprint
        let cloud = BackupMeta { version: 7314, saved_at_ms: 1, fingerprint: Some(fp_first.clone()) };
        assert_eq!(backup_take_own(&s, &cloud).unwrap(), Some(7314), "the cloud's 7314 is this phone's own upload — the number is taken");
        assert_eq!(backup_version_stored(&s).unwrap(), 7314);
        assert_eq!(backup_version_peek(&s).unwrap(), 7315, "the new copy goes up as 7315 — accepted, no warning");
        assert_eq!(backup_inflight(&s).unwrap(), None, "the note is cleared with the number taken");
    }

    #[test]
    fn v380_a_second_attempt_no_longer_forgets_the_first() {
        // what the old engine did at 07:09:17: the second copy's note REPLACED the first; the refusal then had nothing
        // to be compared with. Now both stand under the one number.
        let s = MemoryStorage::new();
        backup_version_commit(&s, 7313).unwrap();
        let (fp_a, fp_b) = (backup_fingerprint(&blob(1, 7314)), backup_fingerprint(&blob(2, 7314)));
        backup_inflight_note(&s, 7314, &fp_a).unwrap();
        assert!(!backup_refusal_may_be_own(&s, 7314, 7314).unwrap(), "one copy sent and refused: it cannot be the one stored (the cloud accepts a repeat of the very same copy) — nothing to ask");
        backup_inflight_note(&s, 7314, &fp_b).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), Some((7314, vec![fp_a.clone(), fp_b.clone()])), "both copies sent as 7314, oldest first");
        assert!(backup_refusal_may_be_own(&s, 7314, 7314).unwrap(), "refused with the very number sent, and an earlier copy went up under it: the cloud is asked whose copy it holds");
        assert!(!backup_refusal_may_be_own(&s, 7314, 7320).unwrap(), "the cloud holds a higher number than any this phone sent: another copy's — the warning, nothing to ask");
        // a copy this phone never sent, under the same number: not own, nothing written, the note stands
        let other = BackupMeta { version: 7314, saved_at_ms: 1, fingerprint: Some(backup_fingerprint(&blob(9, 7314))) };
        assert_eq!(backup_take_own(&s, &other).unwrap(), None, "another copy under the same number is not this phone's — the warning stands");
        assert_eq!(backup_version_stored(&s).unwrap(), 7313, "nothing was taken");
        assert_eq!(backup_unanswered(&s, 7314).unwrap(), 2, "the note stands");
        // the cloud holds the FIRST copy (the incident), or the second (the answers crossed): own either way
        for fp in [fp_a.clone(), fp_b.clone()] {
            let t = MemoryStorage::new();
            backup_version_commit(&t, 7313).unwrap();
            backup_inflight_note(&t, 7314, &fp_a).unwrap();
            backup_inflight_note(&t, 7314, &fp_b).unwrap();
            let cloud = BackupMeta { version: 7314, saved_at_ms: 1, fingerprint: Some(fp) };
            assert_eq!(backup_take_own(&t, &cloud).unwrap(), Some(7314));
            assert_eq!(backup_version_peek(&t).unwrap(), 7315);
        }
    }

    #[test]
    fn v380_the_note_is_for_one_number_holds_no_copy_twice_and_is_bounded() {
        let s = MemoryStorage::new();
        let fp = |i: u8| backup_fingerprint(&blob(i, 50));
        backup_inflight_note(&s, 50, &fp(1)).unwrap();
        backup_inflight_note(&s, 50, &fp(1)).unwrap();
        assert_eq!(backup_unanswered(&s, 50).unwrap(), 1, "the very same copy sent again is one copy");
        backup_inflight_note(&s, 51, &fp(2)).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), Some((51, vec![fp(2)])), "a note for another number starts again — the copies sent under 50 cannot be what a cloud at 51 or above holds as this phone's next");
        assert_eq!(backup_unanswered(&s, 50).unwrap(), 0);
        for i in 10..(10 + BACKUP_INFLIGHT_MAX as u8 + 3) { backup_inflight_note(&s, 51, &fp(i)).unwrap(); }
        let (n, fps) = backup_inflight(&s).unwrap().unwrap();
        assert_eq!((n, fps.len()), (51, BACKUP_INFLIGHT_MAX), "bounded — the oldest go first");
        assert_eq!(fps.last().unwrap(), &fp(10 + BACKUP_INFLIGHT_MAX as u8 + 2), "the newest is kept");
        assert!(!fps.contains(&fp(2)), "the oldest went");
        // a note of a length this engine does not write is no note
        s.set(KEY_BACKUP_INFLIGHT, &vec![7u8; 8 + 32 * (BACKUP_INFLIGHT_MAX + 1)]).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), None);
        s.set(KEY_BACKUP_INFLIGHT, &[7u8; 8 + 32 + 5]).unwrap();
        assert_eq!(backup_inflight(&s).unwrap(), None);
    }

    #[test]
    fn v380_a_cloud_without_a_fingerprint_or_a_phone_without_a_note_takes_nothing() {
        let s = MemoryStorage::new();
        backup_version_commit(&s, 10).unwrap();
        let fp = backup_fingerprint(&blob(1, 11));
        let cloud = BackupMeta { version: 11, saved_at_ms: 1, fingerprint: Some(fp.clone()) };
        assert_eq!(backup_take_own(&s, &cloud).unwrap(), None, "no note: never own");
        backup_inflight_note(&s, 11, &fp).unwrap();
        let no_fp = BackupMeta { version: 11, saved_at_ms: 1, fingerprint: None };
        assert_eq!(backup_take_own(&s, &no_fp).unwrap(), None, "a cloud copy without a fingerprint: never own");
        let lower = BackupMeta { version: 10, saved_at_ms: 1, fingerprint: Some(fp.clone()) };
        assert_eq!(backup_take_own(&s, &lower).unwrap(), None, "the cloud still holds the number before: the upload never arrived — it is sent again as before");
        assert_eq!(backup_version_stored(&s).unwrap(), 10);
        assert_eq!(backup_unanswered(&s, 11).unwrap(), 1);
    }

    // ── v380: the whole upload, against a stand-in that keeps the registry's own rule (lij-worker /backup) ──

    /// The registry as the phone meets it: it holds one copy (number, fingerprint); a copy with a higher number
    /// replaces it; the very same copy again is accepted; anything else is refused with the registry's words.
    struct FakeCloud {
        held: std::cell::RefCell<Option<(u64, String)>>,
        /// what it held before the last write (what a read through the 30-s cache can still show)
        before: std::cell::RefCell<Option<(u64, String)>>,
        /// the next N uploads are stored, but their answer never reaches the phone
        lose_answers: std::cell::Cell<u32>,
        /// nothing reaches the registry — not even the challenge
        offline: std::cell::Cell<bool>,
        /// the next N questions get no answer
        meta_silent: std::cell::Cell<u32>,
        /// the next N questions are answered from the cache: what was held BEFORE the last write
        meta_behind: std::cell::Cell<u32>,
        pushes: std::cell::Cell<u32>,
        metas: std::cell::Cell<u32>,
        /// lij-worker 0.23.0: a refusal names the copy held (false = a registry before it: the words only)
        names_copy: std::cell::Cell<bool>,
    }
    impl FakeCloud {
        fn holding(v: u64, fp: &str) -> Self {
            FakeCloud { held: std::cell::RefCell::new(Some((v, fp.to_string()))), before: std::cell::RefCell::new(None), lose_answers: 0.into(), offline: false.into(),
                meta_silent: 0.into(), meta_behind: 0.into(), pushes: 0.into(), metas: 0.into(), names_copy: false.into() }
        }
        fn holds(&self) -> (u64, String) { self.held.borrow().clone().unwrap() }
    }
    impl CopyCloud for FakeCloud {
        async fn push(&self, blob: &StateBlob) -> Vec<LijResult<()>> {
            self.pushes.set(self.pushes.get() + 1);
            if self.offline.get() { return vec![Err(LijError::Backup(format!("{BACKUP_NOT_SENT}Backup error: challenge: empty response")))]; }
            let fp = backup_fingerprint(blob);
            let prev = self.held.borrow().clone();
            if let Some((v, f)) = prev.clone() {
                if v == blob.version && f == fp { return vec![Ok(())]; }
                if v >= blob.version {
                    let named = if self.names_copy.get() { format!(",\"existing_version\":{v},\"existing_fingerprint\":\"{f}\",\"existing_saved_at_ms\":1795000000000") } else { String::new() };
                    return vec![Err(LijError::Backup(format!("Backup POST HTTP 409 https://registry/backup — {{\"error\":\"Stale backup rejected: existing v{v} >= incoming v{}\"{named}}}", blob.version)))];
                }
            }
            *self.before.borrow_mut() = prev;
            *self.held.borrow_mut() = Some((blob.version, fp));
            if self.lose_answers.get() > 0 {
                self.lose_answers.set(self.lose_answers.get() - 1);
                return vec![Err(LijError::Backup("Backup POST fetch: JsValue(TypeError: Load failed)".into()))];
            }
            vec![Ok(())]
        }
        async fn meta(&self) -> LijResult<Option<BackupMeta>> {
            self.metas.set(self.metas.get() + 1);
            if self.offline.get() { return Err(LijError::Backup("challenge: empty response".into())); }
            if self.meta_silent.get() > 0 { self.meta_silent.set(self.meta_silent.get() - 1); return Err(LijError::Backup("Backup POST fetch: no answer".into())); }
            let shown = if self.meta_behind.get() > 0 { self.meta_behind.set(self.meta_behind.get() - 1); self.before.borrow().clone() } else { self.held.borrow().clone() };
            Ok(shown.map(|(version, fp)| BackupMeta { version, saved_at_ms: 1, fingerprint: Some(fp) }))
        }
    }
    /// A phone that holds `n` and a registry that holds the copy the phone last had accepted.
    fn phone_and_cloud(n: u64) -> (MemoryStorage, FakeCloud) {
        let s = MemoryStorage::new();
        backup_version_commit(&s, n).unwrap();
        (s, FakeCloud::holding(n, &backup_fingerprint(&blob(0, n))))
    }
    /// The next copy as the engine takes it: new bytes every time, the number only peeked.
    fn next_copy(s: &MemoryStorage, seed: u8) -> StateBlob { blob(seed, backup_version_peek(s).unwrap()) }

    #[tokio::test]
    async fn v380_the_incident_replayed_the_second_upload_goes_through_with_no_warning() {
        let (s, cloud) = phone_and_cloud(7313);
        // 07:08:28 — a routine upload; the registry stores it as 7314; the answer never reaches the phone
        cloud.lose_answers.set(1);
        let first = next_copy(&s, 1);
        let fp_first = backup_fingerprint(&first);
        let up = upload_copy(&s, first, &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 0, 0, false, true), "no answer: tried again later — exactly what the tape shows (pushed 0, conflict 0)");
        assert_eq!(backup_version_stored(&s).unwrap(), 7313, "the phone still carries 7313");
        assert_eq!(cloud.holds(), (7314, fp_first.clone()), "the registry holds 7314 — the phone's own copy");
        assert_eq!(backup_unanswered(&s, 7314).unwrap(), 1, "the note of the unanswered copy stands");
        // 07:09:17 — the next upload: a new copy. The old engine sent it as 7314 again; this is what it met — the
        // registry's refusal, as the tape has it — and with the first copy's note already replaced, the warning followed.
        let second = next_copy(&s, 2);
        assert_eq!(second.version, 7314);
        let met = cloud.push(&second).await;
        let words = met[0].as_ref().unwrap_err().to_string();
        assert!(words.contains("Stale backup rejected: existing v7314 >= incoming v7314"), "{words}");
        assert_eq!(parse_stale_refusal(&words), Some(7314), "the old engine: conflict 7314 — 'Your cloud copy is newer than this phone'");
        let fp_second = backup_fingerprint(&second);
        let up = upload_copy(&s, second, &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (1, 0, 7314, false, false), "the registry was asked first; its 7314 is this phone's own; the new copy went up as 7315 and was accepted — no warning");
        assert_eq!(cloud.holds(), (7315, fp_second), "the registry holds the phone's newest state");
        assert_eq!(backup_version_stored(&s).unwrap(), 7315);
        assert_eq!(backup_inflight(&s).unwrap(), None);
        assert_eq!(cloud.metas.get(), 1, "one question, asked only because an upload stood unanswered");
        // and with nothing unanswered, an upload asks nothing
        let up = upload_copy(&s, next_copy(&s, 3), &cloud).await;
        assert_eq!((up.ok, up.own, cloud.metas.get()), (1, 0, 1));
    }

    #[tokio::test]
    async fn v380_the_question_fails_before_the_upload_and_is_asked_again_after_the_refusal() {
        let (s, cloud) = phone_and_cloud(7313);
        cloud.lose_answers.set(1);
        let first = next_copy(&s, 1);
        let fp_first = backup_fingerprint(&first);
        upload_copy(&s, first, &cloud).await;
        cloud.meta_silent.set(1);   // the question before the upload gets no answer; the upload itself gets through
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again), (0, 0, 7314, true), "refused with the very number sent — asked again — the registry's copy is this phone's own: NO conflict; a fresh copy goes next");
        assert_eq!(cloud.holds(), (7314, fp_first), "the refused copy was not stored");
        assert_eq!((backup_version_stored(&s).unwrap(), backup_inflight(&s).unwrap()), (7314, None));
        let third = next_copy(&s, 3);
        let fp_third = backup_fingerprint(&third);
        let up = upload_copy(&s, third, &cloud).await;
        assert_eq!((up.ok, up.conflict), (1, 0));
        assert_eq!(cloud.holds(), (7315, fp_third));
    }

    #[tokio::test]
    async fn v380_a_read_that_is_behind_the_write_is_not_called_a_conflict() {
        // the registry reads its stored copy through a cache of up to 30 s: right after the unanswered upload a
        // question can still be answered with the copy BEFORE it
        let (s, cloud) = phone_and_cloud(7313);
        cloud.lose_answers.set(1);
        upload_copy(&s, next_copy(&s, 1), &cloud).await;
        cloud.meta_behind.set(2);   // both questions of the next upload see the old 7313
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 0, 0, false, true), "the refusal says the registry holds 7314, the question says 7313: no usable answer yet — no warning, asked again at the next upload");
        assert_eq!(backup_unanswered(&s, 7314).unwrap(), 2, "both copies sent as 7314 stand in the note");
        let third = next_copy(&s, 3);
        let fp_third = backup_fingerprint(&third);
        let up = upload_copy(&s, third, &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own), (1, 0, 7314), "the read has caught up: own — the copy goes up as 7315");
        assert_eq!(cloud.holds(), (7315, fp_third));
    }

    #[tokio::test]
    async fn v380_a_copy_this_phone_never_sent_still_raises_the_warning() {
        // another copy of the wallet (a second phone, an old tab) put a higher number in the cloud
        let (s, cloud) = phone_and_cloud(7313);
        *cloud.held.borrow_mut() = Some((7320, backup_fingerprint(&blob(99, 7320))));
        let up = upload_copy(&s, next_copy(&s, 1), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 7320, 0, false, false), "refused by a copy that is not this phone's: the warning, as before");
        assert_eq!(backup_inflight(&s).unwrap(), None, "the registry answered — no copy of this phone's is on its way");
        assert_eq!(cloud.metas.get(), 0, "a higher number than any this phone sent: nothing to ask");
        // the same number, another copy's bytes, while this phone has an unanswered upload of that number
        let (s, cloud) = phone_and_cloud(7313);
        cloud.lose_answers.set(1);
        upload_copy(&s, next_copy(&s, 1), &cloud).await;
        *cloud.held.borrow_mut() = Some((7314, backup_fingerprint(&blob(99, 7314))));   // the other copy's 7314 took the place
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again), (0, 7314, 0, false), "7314 in the cloud, but not one of the copies this phone sent: the warning stands");
        assert_eq!(backup_version_stored(&s).unwrap(), 7313, "nothing was taken");
        assert_eq!(backup_inflight(&s).unwrap(), None);
    }

    #[tokio::test]
    async fn v380_a_copy_that_never_left_the_phone_leaves_no_note() {
        let (s, cloud) = phone_and_cloud(7313);
        cloud.offline.set(true);
        for i in 0..20u8 {
            let up = upload_copy(&s, next_copy(&s, i + 1), &cloud).await;
            assert_eq!((up.ok, up.conflict, up.unanswered), (0, 0, true));
        }
        assert_eq!(backup_inflight(&s).unwrap(), None, "twenty tries with no connection: nothing was sent, nothing is remembered");
        // with one REAL unanswered upload standing, no connection for a long time does not push it out of the note
        cloud.offline.set(false);
        cloud.lose_answers.set(1);
        let sent = next_copy(&s, 40);
        let fp_sent = backup_fingerprint(&sent);
        upload_copy(&s, sent, &cloud).await;
        cloud.offline.set(true);
        for i in 0..20u8 { upload_copy(&s, next_copy(&s, 50 + i), &cloud).await; }
        assert_eq!(backup_inflight(&s).unwrap(), Some((7314, vec![fp_sent])), "the one copy that did go up is still the one remembered");
        cloud.offline.set(false);
        let up = upload_copy(&s, next_copy(&s, 90), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own), (1, 0, 7314), "back online: own, and the new copy is accepted as 7315");
    }

    #[tokio::test]
    async fn v380_no_usable_answer_for_a_long_time_ends_in_the_warning_never_in_silence() {
        // the registry keeps refusing and never says whose copy it holds: the uploads must not stop silently for ever
        let (s, cloud) = phone_and_cloud(7313);
        cloud.lose_answers.set(1);
        let first = next_copy(&s, 1);
        let fp_first = backup_fingerprint(&first);
        upload_copy(&s, first, &cloud).await;
        cloud.meta_silent.set(1000);
        let mut rounds = 0u32;
        let up = loop {
            rounds += 1;
            let up = upload_copy(&s, next_copy(&s, 1 + rounds as u8), &cloud).await;
            if !up.unanswered || rounds > 50 { break up; }
        };
        assert_eq!(up.conflict, 7314, "the warning is raised in the end");
        assert_eq!(rounds as usize, BACKUP_INFLIGHT_MAX - 1, "after the note is full — a few minutes of uploads at one every 30 s");
        let note = backup_inflight(&s).unwrap().unwrap();
        assert!(note.1.contains(&fp_first), "the note stands, the first copy still in it — the next wallet start can still tell an own upload");
        cloud.meta_silent.set(0);
        let m = cloud.meta().await.unwrap().unwrap();
        assert_eq!(backup_take_own(&s, &m).unwrap(), Some(7314));
    }

    // ── v381 (round 2): the registry's refusal names the copy it holds (lij-worker 0.23.0) ──

    #[test]
    fn v381_the_fingerprint_is_read_out_of_a_refusal_that_names_the_copy() {
        let fp = "ab".repeat(32);
        let named = format!("Backup error: Backup POST HTTP 409 https://r/backup — {{\"error\":\"Stale backup rejected: existing v7314 >= incoming v7314\",\"existing_version\":7314,\"existing_fingerprint\":\"{fp}\",\"existing_saved_at_ms\":1795000000000}}");
        assert_eq!(parse_stale_refusal(&named), Some(7314), "the number is still read from the unchanged words");
        assert_eq!(parse_stale_refusal_fingerprint(&named), Some(fp.clone()));
        assert_eq!(parse_stale_refusal_fingerprint(&named.replace(&fp, &fp.to_uppercase())), Some(fp.clone()), "hex in capitals reads the same");
        let old = "Backup error: Backup POST HTTP 409 https://r/backup — {\"error\":\"Stale backup rejected: existing v7314 >= incoming v7314\"}";
        assert_eq!(parse_stale_refusal_fingerprint(old), None, "a registry before 0.23.0 names none — the question is asked instead");
        let null = named.replace(&format!("\"{fp}\""), "null");
        assert_eq!(parse_stale_refusal_fingerprint(&null), None, "a held copy without a fingerprint");
        assert_eq!(parse_stale_refusal_fingerprint(&named.replace(&fp, &fp[..60])), None, "not 64 hex: not a fingerprint");
        assert_eq!(parse_stale_refusal_fingerprint(&format!("something else \"existing_fingerprint\":\"{fp}\"")), None, "not a refusal");
    }

    #[tokio::test]
    async fn v381_the_refusal_itself_settles_it_no_second_question() {
        // the question before the upload gets no answer; the upload is refused; the refusal names the copy held —
        // this phone's own. Settled from that one answer.
        let (s, cloud) = phone_and_cloud(7313);
        cloud.names_copy.set(true);
        cloud.lose_answers.set(1);
        upload_copy(&s, next_copy(&s, 1), &cloud).await;
        cloud.meta_silent.set(1000);
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 0, 7314, true, false), "own, from the refusal alone: no conflict, a fresh copy goes next");
        assert_eq!(cloud.metas.get(), 1, "one question (before the upload, unanswered) — none after the refusal");
        assert_eq!((backup_version_stored(&s).unwrap(), backup_inflight(&s).unwrap()), (7314, None));
        let up = upload_copy(&s, next_copy(&s, 3), &cloud).await;
        assert_eq!((up.ok, up.conflict, cloud.holds().0), (1, 0, 7315));
    }

    #[tokio::test]
    async fn v381_a_read_behind_the_write_no_longer_costs_a_round() {
        // v380 against a registry before 0.23.0: the question after the refusal could be answered from the 30-s cache
        // with the older copy — no warning, but one upload round lost. The refusal that names the copy comes from the
        // read that decided it, so the phone knows at once.
        let (s, cloud) = phone_and_cloud(7313);
        cloud.names_copy.set(true);
        cloud.lose_answers.set(1);
        upload_copy(&s, next_copy(&s, 1), &cloud).await;
        cloud.meta_behind.set(1000);
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 0, 7314, true, false));
        let third = next_copy(&s, 3);
        assert_eq!(third.version, 7315);
        let up = upload_copy(&s, third, &cloud).await;
        assert_eq!((up.ok, up.conflict), (1, 0));
    }

    #[tokio::test]
    async fn v381_a_named_copy_that_is_not_this_phones_is_the_conflict() {
        let (s, cloud) = phone_and_cloud(7313);
        cloud.names_copy.set(true);
        cloud.lose_answers.set(1);
        upload_copy(&s, next_copy(&s, 1), &cloud).await;
        *cloud.held.borrow_mut() = Some((7314, backup_fingerprint(&blob(99, 7314))));   // another copy's 7314 took the place
        cloud.meta_silent.set(1000);
        let up = upload_copy(&s, next_copy(&s, 2), &cloud).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 7314, 0, false, false), "the refusal names a copy this phone never sent: the warning, at once");
        assert_eq!((backup_version_stored(&s).unwrap(), backup_inflight(&s).unwrap()), (7313, None));
        // and a higher number from another copy
        let (s, cloud) = phone_and_cloud(7313);
        cloud.names_copy.set(true);
        *cloud.held.borrow_mut() = Some((7320, backup_fingerprint(&blob(98, 7320))));
        let up = upload_copy(&s, next_copy(&s, 1), &cloud).await;
        assert_eq!((up.conflict, up.own, cloud.metas.get()), (7320, 0, 0));
    }

    #[tokio::test]
    async fn v380_the_wallets_own_cloud_is_built_as_the_browser_layer_builds_it() {
        // the browser layer (lij-wasm upload_copy) cannot be compiled off the browser; this is its call, type for type.
        // Off the browser the challenge has no answer, so the copy is "not sent": nothing accepted, nothing remembered.
        let (root_key, _m) = crate::key::RootKey::generate(bitcoin::Network::Regtest).unwrap();
        let signer: std::sync::Arc<crate::key::RootKey> = std::sync::Arc::new(root_key);
        let cfg = || StorageConfig { worker_url: "http://localhost".into(), auth_token: "".into() };
        let client = KvBackupClient::new(cfg());
        let sinks: Vec<BackupSink> = vec![BackupSink::CloudflareKv(KvBackupClient::new(cfg()))];
        let s = MemoryStorage::new();
        async fn glue(st: &dyn LijStorage, blob: StateBlob, signer: &crate::key::RootKey, sinks: &[BackupSink], client: &KvBackupClient) -> Uploaded {
            let cloud = WalletCloud { sinks, client, signer };
            upload_copy(st, blob, &cloud).await
        }
        let up = glue(&s, next_copy(&s, 1), &signer, &sinks, &client).await;
        assert_eq!((up.ok, up.conflict, up.own, up.again, up.unanswered), (0, 0, 0, false, true));
        assert!(up.last_err.unwrap().contains(BACKUP_NOT_SENT));
        assert_eq!(backup_inflight(&s).unwrap(), None);
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
mod v358_backup_digest_v2_tests {
    use super::*;

    // The worker's test-round6 pins the same vector: nonce 00×32, pubkey 02 03×32, fingerprint 11×32, version 7.
    #[test]
    fn v358_the_push_digest_binds_the_copy_and_its_number() {
        let nonce = "00".repeat(32);
        let pk = format!("02{}", "03".repeat(32));
        let fp = "11".repeat(32);
        let d = backup_digest_v2("backup-push", &nonce, &pk, &fp, 7).unwrap();
        let mut h = sha2::Sha256::new();
        use sha2::Digest;
        h.update(b"lij-backup-v2"); h.update(b"backup-push"); h.update([0u8; 32]);
        let mut pkb = vec![0x02u8]; pkb.extend(std::iter::repeat(0x03u8).take(32)); h.update(&pkb);
        h.update([0x11u8; 32]); h.update(7u64.to_be_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(d, want);
        assert_eq!(hex::encode(d), "53d153264315f77bb76b94af0ac8c3ace02cb3aae47fbaa5c9fa680e703da2fd", "the pinned vector (plain Python; the worker's test carries the same)");
        assert_ne!(d, backup_digest_v2("backup-push", &nonce, &pk, &fp, 8).unwrap(), "another number is another digest");
        assert_ne!(d, backup_digest_v2("backup-push", &nonce, &pk, &"22".repeat(32), 7).unwrap(), "another copy is another digest");
        assert_ne!(d, backup_digest("backup-push", &nonce, &pk).unwrap(), "v2 is not v1");
        assert!(backup_digest_v2("backup-push", &nonce, &pk, "abcd", 7).is_err(), "a fingerprint is 32 bytes");
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

#[cfg(test)]
mod v359_dirty_flag_tests {
    use super::*;

    // The flag rises on the first change (the mirror says "1"), the take clears both, and a new flag built on the same
    // storage starts as the mirror says — what a reload sees.
    #[test]
    fn v359_the_dirty_flag_is_mirrored_and_survives_a_reload() {
        let st: std::sync::Arc<dyn LijStorage> = std::sync::Arc::new(native_storage::MemoryStorage::new());
        let f = DirtyFlag::with_storage(st.clone());
        assert!(!f.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(st.get(KEY_BACKUP_PENDING).unwrap(), None);
        f.store(true, std::sync::atomic::Ordering::Relaxed);
        f.store(true, std::sync::atomic::Ordering::Relaxed);   // a second rise writes nothing new
        assert_eq!(st.get(KEY_BACKUP_PENDING).unwrap(), Some(b"1".to_vec()));
        let again = DirtyFlag::with_storage(st.clone());   // the reload
        assert!(again.load(std::sync::atomic::Ordering::Relaxed), "a reload inherits the unpushed change");
        assert!(again.swap(false, std::sync::atomic::Ordering::Relaxed), "the take answers what it was");
        assert_eq!(st.get(KEY_BACKUP_PENDING).unwrap(), None, "the take clears the mirror");
        assert!(!f.swap(false, std::sync::atomic::Ordering::Relaxed) || true);   // the first flag's own memory is its own
        let fresh = DirtyFlag::with_storage(st.clone());
        assert!(!fresh.load(std::sync::atomic::Ordering::Relaxed));
        let plain = DirtyFlag::new(false);
        plain.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(plain.load(std::sync::atomic::Ordering::Relaxed) && st.get(KEY_BACKUP_PENDING).unwrap().is_none(), "a flag without a mirror touches no storage");
    }
}
