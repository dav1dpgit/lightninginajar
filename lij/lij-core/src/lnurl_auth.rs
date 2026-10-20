//! v350 (S61 Mon, DP 2026-10-19 21:31: "I am really only interested in the ability use the wallet as a login as it
//! doesn't add UI requirements to the wallet if done right (the scan flow recognizes the login QR, asks 'Log in to
//! <site>?', done.)") — LNURL-auth, the wallet as a login (LUD-04 + LUD-05).
//!
//! A site shows an LNURL whose URL carries `tag=login` and a 32-byte challenge `k1`. The wallet makes a key for THAT
//! site alone from the seed (LUD-05): the hashing key is `m/138'/0`; `HMAC-SHA256(key = that private key, msg = the
//! site's host)` gives four 32-bit numbers; the linking key is `m/138'/<n1>/<n2>/<n3>/<n4>` (a number at or above
//! 2^31 is a hardened step, as every wallet reads it). The wallet signs k1 with the linking key (ECDSA, DER) and the
//! site checks it against the linking public key — no password, nothing paid, and the key for one site says nothing
//! about the key for another. Everything here is pure: the page fetches the callback.
//!
//! The pinned vector below was computed independently in pure Python (stdlib HMAC/PBKDF2 + a hand-written secp256k1)
//! from the published test mnemonic; the two implementations agree byte for byte.

use crate::error::{LijError, LijResult};
use crate::key::RootKey;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha256;

/// The host part of a login URL, lowercased — the domain the key is made for.
pub fn domain_of(url: &str) -> LijResult<String> {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://")
        .ok_or_else(|| LijError::Key("a login URL must be https".into()))?;
    let host = rest.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("");
    let host = host.split('@').last().unwrap_or("");   // no userinfo tricks
    if host.is_empty() { return Err(LijError::Key("a login URL names no host".into())); }
    Ok(host.to_ascii_lowercase())
}

/// The four path numbers for a domain (LUD-05): the first 16 bytes of HMAC-SHA256(hashing key, domain) as big-endian u32s.
pub fn path_numbers(root: &RootKey, domain: &str) -> LijResult<[u32; 4]> {
    let hashing: DerivationPath = "m/138'/0".parse().map_err(|e| LijError::Key(format!("path: {e}")))?;
    let hk = root.derive_priv(&hashing)?.private_key.secret_bytes();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hk).expect("hmac takes any key length");
    mac.update(domain.as_bytes());
    let d = mac.finalize().into_bytes();
    let n = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    Ok([n(0), n(4), n(8), n(12)])
}

/// The linking key for a domain: `m/138'/<n1>/<n2>/<n3>/<n4>`.
pub fn linking_key(root: &RootKey, domain: &str) -> LijResult<(SecretKey, PublicKey)> {
    let ns = path_numbers(root, domain)?;
    let mut path: Vec<ChildNumber> = vec![ChildNumber::from_hardened_idx(138).map_err(|e| LijError::Key(format!("path: {e}")))?];
    for n in ns { path.push(ChildNumber::from(n)); }   // ≥ 2^31 reads as hardened — the common reading of LUD-05
    let xprv = root.derive_priv(&DerivationPath::from(path))?;
    let secp = Secp256k1::new();
    let sk = xprv.private_key;
    Ok((sk, sk.public_key(&secp)))
}

/// The answer a site expects: the linking public key (33 bytes, hex) and the DER signature of k1 (hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAnswer { pub key: String, pub sig: String }

/// Sign a site's challenge. `k1_hex` is the 32-byte challenge from the URL; the signature is over those bytes as the
/// message (LUD-04 — no hashing on the wallet's side).
pub fn sign(root: &RootKey, domain: &str, k1_hex: &str) -> LijResult<AuthAnswer> {
    let k1 = hex::decode(k1_hex.trim()).map_err(|_| LijError::Key("k1 is not hex".into()))?;
    if k1.len() != 32 { return Err(LijError::Key(format!("k1 is {} bytes, not 32", k1.len()))); }
    let (sk, pk) = linking_key(root, domain)?;
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&k1).map_err(|e| LijError::Key(format!("k1 -> message: {e}")))?;
    let sig = secp.sign_ecdsa(&msg, &sk);
    Ok(AuthAnswer { key: hex::encode(pk.serialize()), sig: hex::encode(sig.serialize_der()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use bitcoin::Network;

    fn root() -> RootKey {
        let m = Mnemonic::parse_normalized("leader monkey parrot ring guide accident before fence cannon height naive bean").unwrap();
        RootKey::from_mnemonic(&m, Network::Bitcoin).unwrap()
    }

    #[test]
    fn v350_the_linking_key_matches_the_independent_python_computation() {
        let r = root();
        assert_eq!(path_numbers(&r, "site.com").unwrap(), [0xa675efa4, 0x48a920db, 0x5c691d50, 0x12c22c7f]);
        assert_eq!(hex::encode(linking_key(&r, "site.com").unwrap().1.serialize()), "02d2b0e663f5f639024f723542f6d57e8dc71ba9a2a431a048fb344a56537175cf");
        assert_eq!(hex::encode(linking_key(&r, "lightninginajar.xyz").unwrap().1.serialize()), "02fb5a831d1038361363cda242445f071e7f5234167106dc9c79659a2b9539598f");
        assert_eq!(hex::encode(linking_key(&r, "stacker.news").unwrap().1.serialize()), "03685bee2e8ae43c769b7782be2b192fae6e9f097ef880347ff0a19950175c8c56");
    }

    #[test]
    fn v350_a_signature_verifies_under_the_linking_key_and_differs_per_site() {
        let r = root();
        let k1 = "11".repeat(32);
        let a = sign(&r, "site.com", &k1).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_slice(&hex::decode(&a.key).unwrap()).unwrap();
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&hex::decode(&a.sig).unwrap()).unwrap();
        assert!(secp.verify_ecdsa(&Message::from_slice(&hex::decode(&k1).unwrap()).unwrap(), &sig, &pk).is_ok());
        let b = sign(&r, "stacker.news", &k1).unwrap();
        assert_ne!(a.key, b.key, "one key per site");
        assert_eq!(sign(&r, "site.com", &k1).unwrap(), a, "deterministic");
    }

    #[test]
    fn v350_the_domain_and_the_challenge_are_checked() {
        let r = root();
        assert_eq!(domain_of("https://Site.com/lnurl-auth?tag=login&k1=aa").unwrap(), "site.com");
        assert_eq!(domain_of("https://user@evil.com/x").unwrap(), "evil.com");
        assert!(domain_of("http://site.com/x").is_err(), "https only");
        assert!(sign(&r, "site.com", "zz").is_err(), "not hex");
        assert!(sign(&r, "site.com", &"11".repeat(31)).is_err(), "31 bytes");
    }
}
