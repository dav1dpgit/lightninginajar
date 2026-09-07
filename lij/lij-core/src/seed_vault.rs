//! Passphrase-based seed vault.
//!
//! Wraps the BIP39 mnemonic under a user-chosen passphrase using Argon2id
//! (password hashing) + AES-256-GCM (authenticated encryption).
//!
//! Blob format (little-endian, no padding):
//!
//!     version (1 B) || salt (16 B) || nonce (12 B) || ciphertext+tag (variable)
//!
//! The passphrase is a **local convenience lock**, independent of Bitcoin key
//! material. It is NOT a BIP39 passphrase / 13th word / seed extension. Its
//! sole purpose is to prevent an attacker with read access to browser storage
//! (malicious extension, stolen device, shared computer) from extracting the
//! mnemonic. Funds are still recoverable via the 12-word seed on any device;
//! forgetting the passphrase is recoverable by re-entering the 12 words.
//!
//! Argon2id parameters (m=48 MiB, t=3, p=1) target ~350-400 ms on modern
//! hardware. Tune per measurement, not theory — see BENCH.md.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

// Argon2id cost parameters. Tuned for ~350-400 ms in a modern browser.
// Re-tune if browser wall-clock falls outside [250, 600] ms — see BENCH.md.
const ARGON2_M_KIB: u32 = 48 * 1024; // 48 MiB
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const KEY_LEN: usize = 32;

/// Wrap `mnemonic` under `passphrase`. Produces a self-describing blob:
/// `version || salt || nonce || ciphertext+tag`.
///
/// Empty `mnemonic` is rejected. Empty `passphrase` is allowed (strength is
/// advisory, enforced at UI layer, not here).
pub fn wrap(mnemonic: &str, passphrase: &str) -> Result<Vec<u8>> {
    if mnemonic.is_empty() {
        return Err(anyhow!("mnemonic must not be empty"));
    }

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| anyhow!("AES-256-GCM encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a blob produced by [`wrap`]. Returns the mnemonic as UTF-8 string.
///
/// Fails with distinct errors for: short blob, unsupported version, wrong
/// passphrase / tampered ciphertext, non-UTF-8 plaintext (corruption).
pub fn unwrap(blob: &[u8], passphrase: &str) -> Result<String> {
    if blob.len() < 1 + SALT_LEN + NONCE_LEN {
        return Err(anyhow!(
            "blob too short: {} bytes (need ≥ {} for header)",
            blob.len(),
            1 + SALT_LEN + NONCE_LEN
        ));
    }
    if blob[0] != VERSION {
        return Err(anyhow!(
            "unsupported vault version: got {}, expected {VERSION}",
            blob[0]
        ));
    }

    let salt = &blob[1..1 + SALT_LEN];
    let nonce_bytes = &blob[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
    let ct = &blob[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| anyhow!("wrong passphrase or tampered blob"))?;

    String::from_utf8(pt).map_err(|e| anyhow!("plaintext is not valid UTF-8: {e}"))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|e| anyhow!("Argon2 params invalid: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derivation failed: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: these tests exercise real Argon2id at production cost. Each
    // wrap+unwrap burns ~700-800 ms on a laptop. Running the full module's
    // tests takes ~10 seconds. Acceptable — we're not iterating on these
    // hourly. Drop cost parameters inline if tuning demands faster feedback.

    const M: &str = "license gadget note home either dial dilemma auto produce syrup pledge brush";

    #[test]
    fn round_trip() {
        let blob = wrap(M, "correct horse battery staple").unwrap();
        assert_eq!(blob[0], VERSION);
        assert_eq!(unwrap(&blob, "correct horse battery staple").unwrap(), M);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = wrap(M, "original").unwrap();
        assert!(unwrap(&blob, "different").is_err());
    }

    #[test]
    fn empty_passphrase_is_allowed() {
        let blob = wrap(M, "").unwrap();
        assert_eq!(unwrap(&blob, "").unwrap(), M);
    }

    #[test]
    fn empty_mnemonic_rejected() {
        assert!(wrap("", "whatever").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = wrap(M, "p").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(unwrap(&blob, "p").is_err());
    }

    #[test]
    fn tampered_salt_fails() {
        // Modifying the salt re-derives a different key — authentication tag
        // check fails, same observable behavior as wrong passphrase.
        let mut blob = wrap(M, "p").unwrap();
        blob[1] ^= 0x01;
        assert!(unwrap(&blob, "p").is_err());
    }

    #[test]
    fn short_blob_fails() {
        assert!(unwrap(&[], "p").is_err());
        assert!(unwrap(&[0u8; 10], "p").is_err());
        assert!(unwrap(&[0u8; 1 + SALT_LEN + NONCE_LEN - 1], "p").is_err());
    }

    #[test]
    fn unsupported_version_fails() {
        let mut blob = wrap(M, "p").unwrap();
        blob[0] = 99;
        let err = unwrap(&blob, "p").unwrap_err().to_string();
        assert!(err.contains("unsupported vault version"), "got: {err}");
    }

    #[test]
    fn same_passphrase_yields_different_blobs() {
        // Fresh salt + nonce per wrap — two calls must produce distinct blobs.
        let a = wrap(M, "same").unwrap();
        let b = wrap(M, "same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn blob_structure_is_correct_length() {
        let blob = wrap("short", "p").unwrap();
        // 1 (version) + 16 (salt) + 12 (nonce) + 5 (plaintext) + 16 (GCM tag) = 50
        assert_eq!(blob.len(), 1 + SALT_LEN + NONCE_LEN + 5 + 16);
    }
}
