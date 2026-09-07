//! Persistence encryption primitives.
//!
//! Derives a per-wallet key from the BIP39 seed via HKDF-SHA256 and wraps
//! state blobs (ChannelMonitor, ChannelManager) with AES-256-GCM. The 12-byte
//! nonce is freshly randomized per encrypt and prepended to the ciphertext:
//! `nonce (12 B) || ciphertext+tag`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const HKDF_SALT: &[u8] = b"lij-persist-v1";
const HKDF_INFO: &[u8] = b"ChannelMonitor";

pub fn derive_encryption_key(ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is well within HKDF-SHA256's output limit");
    key
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES-256-GCM encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN {
        return Err(anyhow!(
            "ciphertext too short: {} bytes (need ≥ {NONCE_LEN} for nonce)",
            ciphertext.len()
        ));
    }
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|e| anyhow!("AES-256-GCM decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = derive_encryption_key(&[42u8; 64][..]);
        let pt = b"channel monitor state blob";
        let ct = encrypt(&key, pt).unwrap();
        assert!(ct.len() > NONCE_LEN);
        assert_ne!(&ct[NONCE_LEN..], pt);
        assert_eq!(decrypt(&key, &ct).unwrap(), pt);
    }

    #[test]
    fn derive_is_deterministic() {
        let s = [7u8; 64];
        assert_eq!(derive_encryption_key(&s[..]), derive_encryption_key(&s[..]));
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        assert_ne!(
            derive_encryption_key(&[0u8; 64][..]),
            derive_encryption_key(&[1u8; 64][..])
        );
    }

    #[test]
    fn derive_accepts_any_ikm_length() {
        // HKDF-SHA256 doesn't care if the input is 32 vs 64 bytes — both produce
        // a strong 32-byte AES key. We feed master_xprv (32 B) in production.
        let _ = derive_encryption_key(&[1u8; 32][..]);
        let _ = derive_encryption_key(&[1u8; 64][..]);
    }

    #[test]
    fn nonces_are_unique_per_encrypt() {
        let key = derive_encryption_key(&[9u8; 64][..]);
        let a = encrypt(&key, b"same").unwrap();
        let b = encrypt(&key, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails() {
        let k = derive_encryption_key(&[1u8; 64][..]);
        let bad = derive_encryption_key(&[2u8; 64][..]);
        let ct = encrypt(&k, b"secret").unwrap();
        assert!(decrypt(&bad, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = derive_encryption_key(&[3u8; 64][..]);
        let mut ct = encrypt(&k, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&k, &ct).is_err());
    }

    #[test]
    fn short_ciphertext_fails() {
        let k = derive_encryption_key(&[5u8; 64][..]);
        assert!(decrypt(&k, &[]).is_err());
        assert!(decrypt(&k, &[0u8; NONCE_LEN - 1]).is_err());
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = derive_encryption_key(&[11u8; 64][..]);
        let ct = encrypt(&k, b"").unwrap();
        assert_eq!(decrypt(&k, &ct).unwrap(), b"");
    }
}

// ── ChannelMonitor persister ─────────────────────────────────────────────────
//
// Implements LDK's chainmonitor::Persist trait. Encrypts each ChannelMonitor
// blob under the wallet's persistence key before handing it to LijStorage.
// Storage layout:
//   lij:monitor:{txid}:{vout}           — active monitor (encrypted)
//   lij:monitor-archived:{txid}:{vout}  — archived monitor (encrypted)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use lightning::chain::{
    chainmonitor::{MonitorUpdateId, Persist},
    channelmonitor::{ChannelMonitor, ChannelMonitorUpdate},
    transaction::OutPoint,
    ChannelMonitorUpdateStatus,
};
use lightning::sign::ecdsa::WriteableEcdsaChannelSigner;
use lightning::util::ser::Writeable;

use crate::storage::LijStorage;

pub const MONITOR_KEY_PREFIX: &str = "lij:monitor:";
pub const ARCHIVED_MONITOR_KEY_PREFIX: &str = "lij:monitor-archived:";
pub const CHANNEL_MANAGER_KEY: &str = "lij:channel_manager";
// S21 item 2: monotonic write stamps for load-time skew detection.
pub const SEQ_MON_KEY: &str = "lij:seq:mon";
pub const SEQ_CM_KEY: &str = "lij:seq:cm";

pub struct LijChannelMonitorPersister {
    storage: Arc<dyn LijStorage>,
    key: [u8; 32],
    /// Shared with LijNode: flipped true on every monitor write — the
    /// per-commitment, security-critical persists — so the cloud backup tick
    /// captures the new state. This is the canonical "must not lose this" hook.
    backup_dirty: Arc<AtomicBool>,
    /// S21 item 2: sibling of backup_dirty — the node's tick persists the
    /// ChannelManager promptly whenever a monitor advanced, so the manager
    /// on disk never trails a commitment by more than one tick.
    manager_dirty: Arc<AtomicBool>,
    /// S21 item 2: shared monotonic stamp. Every monitor write records it to
    /// lij:seq:mon (manager writes record lij:seq:cm); mon > cm at load means
    /// an interrupted save. Best-effort — never fails a monitor ack.
    persist_seq: Arc<AtomicU64>,
}

impl LijChannelMonitorPersister {
    pub fn new(
        storage: Arc<dyn LijStorage>,
        key: [u8; 32],
        backup_dirty: Arc<AtomicBool>,
        manager_dirty: Arc<AtomicBool>,
        persist_seq: Arc<AtomicU64>,
    ) -> Self {
        Self { storage, key, backup_dirty, manager_dirty, persist_seq }
    }

    pub fn monitor_key(outpoint: &OutPoint) -> String {
        format!("{MONITOR_KEY_PREFIX}{}:{}", outpoint.txid, outpoint.index)
    }

    pub fn archived_key(outpoint: &OutPoint) -> String {
        format!(
            "{ARCHIVED_MONITOR_KEY_PREFIX}{}:{}",
            outpoint.txid, outpoint.index
        )
    }

    fn write_monitor<S: WriteableEcdsaChannelSigner>(
        &self,
        key: &str,
        monitor: &ChannelMonitor<S>,
    ) -> std::result::Result<(), String> {
        let plaintext = monitor.encode();
        let ciphertext =
            encrypt(&self.key, &plaintext).map_err(|e| format!("encrypt failed: {e}"))?;
        self.storage
            .set(key, &ciphertext)
            .map_err(|e| format!("storage set failed: {e}"))
    }
}

impl<S: WriteableEcdsaChannelSigner> Persist<S> for LijChannelMonitorPersister {
    fn persist_new_channel(
        &self,
        funding_txo: OutPoint,
        monitor: &ChannelMonitor<S>,
        _update_id: MonitorUpdateId,
    ) -> ChannelMonitorUpdateStatus {
        let key = Self::monitor_key(&funding_txo);
        match self.write_monitor(&key, monitor) {
            Ok(()) => {
                self.backup_dirty.store(true, Ordering::Relaxed);
                self.manager_dirty.store(true, Ordering::Relaxed);
                let s = self.persist_seq.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = self.storage.set(SEQ_MON_KEY, &s.to_be_bytes());
                log::info!("ChannelMonitor persisted: {key}");
                ChannelMonitorUpdateStatus::Completed
            }
            Err(e) => {
                log::error!("ChannelMonitor persist_new failed for {key}: {e}");
                ChannelMonitorUpdateStatus::UnrecoverableError
            }
        }
    }

    fn update_persisted_channel(
        &self,
        funding_txo: OutPoint,
        _update: Option<&ChannelMonitorUpdate>,
        monitor: &ChannelMonitor<S>,
        _update_id: MonitorUpdateId,
    ) -> ChannelMonitorUpdateStatus {
        // Always persist the full monitor — simpler than batching incremental
        // updates, and the size cost is acceptable for browser storage.
        let key = Self::monitor_key(&funding_txo);
        match self.write_monitor(&key, monitor) {
            Ok(()) => {
                self.backup_dirty.store(true, Ordering::Relaxed);
                self.manager_dirty.store(true, Ordering::Relaxed);
                let s = self.persist_seq.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = self.storage.set(SEQ_MON_KEY, &s.to_be_bytes());
                ChannelMonitorUpdateStatus::Completed
            }
            Err(e) => {
                log::error!("ChannelMonitor update failed for {key}: {e}");
                ChannelMonitorUpdateStatus::UnrecoverableError
            }
        }
    }

    fn archive_persisted_channel(&self, funding_txo: OutPoint) {
        let key = Self::monitor_key(&funding_txo);
        let archived_key = Self::archived_key(&funding_txo);
        match self.storage.get(&key) {
            Ok(Some(blob)) => {
                if let Err(e) = self.storage.set(&archived_key, &blob) {
                    log::error!("Archive write failed for {archived_key}: {e}");
                    return;
                }
                if let Err(e) = self.storage.delete(&key) {
                    log::warn!("Archive: removing original {key} failed: {e}");
                }
                log::info!("ChannelMonitor archived: {key} -> {archived_key}");
            }
            Ok(None) => log::warn!("archive_persisted_channel: no monitor at {key}"),
            Err(e) => log::error!("archive read failed for {key}: {e}"),
        }
    }
}

#[cfg(test)]
mod persister_tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;
    use bitcoin::Txid;
    use std::str::FromStr;

    fn outpoint(index: u16) -> OutPoint {
        let txid = Txid::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        OutPoint { txid, index }
    }

    #[test]
    fn key_format_matches_spec() {
        let op = outpoint(7);
        let k = LijChannelMonitorPersister::monitor_key(&op);
        assert!(k.starts_with("lij:monitor:"));
        assert!(k.ends_with(":7"));
        let a = LijChannelMonitorPersister::archived_key(&op);
        assert!(a.starts_with("lij:monitor-archived:"));
    }

    #[test]
    fn archive_moves_blob_and_clears_active() {
        use crate::signer::LijChannelSigner;
        let storage: Arc<dyn LijStorage> = Arc::new(MemoryStorage::new());
        let key = derive_encryption_key(&[1u8; 32][..]);
        let persister = LijChannelMonitorPersister::new(
            storage.clone(),
            key,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );

        let op = outpoint(0);
        let live_key = LijChannelMonitorPersister::monitor_key(&op);
        let arch_key = LijChannelMonitorPersister::archived_key(&op);
        storage.set(&live_key, b"opaque-encrypted-blob").unwrap();

        // archive_persisted_channel doesn't reference the signer, so the
        // generic must be disambiguated explicitly.
        <LijChannelMonitorPersister as Persist<LijChannelSigner>>::archive_persisted_channel(
            &persister, op,
        );

        assert_eq!(storage.get(&live_key).unwrap(), None);
        assert_eq!(
            storage.get(&arch_key).unwrap().as_deref(),
            Some(&b"opaque-encrypted-blob"[..])
        );
    }
}
