//! v275 (S48, DP GO 2026-09-22) — BLACK START, BS1: the escape kit sealed under a key only the
//! 12 words can make, and signed for its holders and for the relays. The cut copy is
//! docs/black-start-standard.md; every constant here is a line of it.
//!
//! - Kit key   = HKDF-SHA256(ikm = the BIP32 master private key, salt "lijox-black-start",
//!               info "escape-kit-v1") — AES-256-GCM, AAD "lijox-kit-v1:" + npub.
//! - Identity  = the NIP-06 key, m/44'/1237'/0'/0/0; npub = its x coordinate.
//! - Holders   = ECDSA (compact r‖s, low-S) over SHA-256("lijox-kit-put-v1" ‖ pubkey ‖ seq_be8 ‖
//!               SHA-256(envelope)) — a holder verifies with platform crypto, no third-party code.
//! - Relays    = a NIP-78 event, kind 30078, d = "lijox-kit-v1", BIP-340 over the NIP-01 id.
//! Nothing here reads or changes channel state: the kit itself comes from escape_export (v211).

use std::str::FromStr;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::error::{LijError, LijResult};
use crate::key::RootKey;

pub const KIT_VERSION: u32 = 1;
pub const HKDF_SALT: &[u8] = b"lijox-black-start";
pub const HKDF_INFO: &[u8] = b"escape-kit-v1";
pub const AAD_PREFIX: &str = "lijox-kit-v1:";
pub const PUT_DOMAIN: &[u8] = b"lijox-kit-put-v1";
pub const NIP06_PATH: &str = "m/44'/1237'/0'/0/0";
pub const NOSTR_KIND: u64 = 30078;
pub const NOSTR_D_TAG: &str = "lijox-kit-v1";
pub const KDF_LABEL: &str = "hkdf-sha256:lijox-black-start:escape-kit-v1";

/// The two things the words make: the kit key and the NIP-06 identity.
pub struct BlackStartKeys {
    kit_key: [u8; 32],
    secret: SecretKey,
    pub pubkey: PublicKey,
}

impl BlackStartKeys {
    pub fn from_root(root: &RootKey) -> LijResult<Self> {
        let ikm = root.root_secret_bytes();
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
        let mut kit_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut kit_key)
            .map_err(|e| LijError::Key(format!("kit key HKDF: {e}")))?;
        let path = DerivationPath::from_str(NIP06_PATH)
            .map_err(|e| LijError::Key(format!("NIP-06 path: {e}")))?;
        let xprv = root.derive_priv(&path)?;
        let secret = xprv.private_key;
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        Ok(Self { kit_key, secret, pubkey })
    }

    /// The Nostr public key: the x coordinate, 32 bytes hex.
    pub fn npub_hex(&self) -> String {
        hex::encode(self.pubkey.x_only_public_key().0.serialize())
    }

    /// The 33-byte compressed public key, hex — what a holder verifies ECDSA with.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey.serialize())
    }

    fn aad(&self) -> Vec<u8> {
        format!("{}{}", AAD_PREFIX, self.npub_hex()).into_bytes()
    }

    /// Seal a kit's plaintext into the envelope (compact JSON, fixed key order — the canonical
    /// form the holder signature covers).
    pub fn seal(&self, plaintext: &[u8], seq: u64) -> LijResult<String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kit_key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = self.aad();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|e| LijError::Key(format!("kit seal: {e}")))?;
        Ok(format!(
            "{{\"v\":{},\"alg\":\"A256GCM\",\"kdf\":\"{}\",\"npub\":\"{}\",\"seq\":{},\"nonce\":\"{}\",\"ct\":\"{}\"}}",
            KIT_VERSION, KDF_LABEL, self.npub_hex(), seq, hex::encode(nonce), hex::encode(ct)
        ))
    }

    /// Open an envelope produced by `seal` (the /recover page does the same in WebCrypto).
    pub fn open(&self, envelope_json: &str) -> LijResult<Vec<u8>> {
        let v: serde_json::Value = serde_json::from_str(envelope_json)
            .map_err(|e| LijError::Key(format!("kit envelope: {e}")))?;
        let nonce = hex::decode(v["nonce"].as_str().unwrap_or(""))
            .map_err(|e| LijError::Key(format!("kit nonce: {e}")))?;
        let ct = hex::decode(v["ct"].as_str().unwrap_or(""))
            .map_err(|e| LijError::Key(format!("kit ct: {e}")))?;
        if v["npub"].as_str() != Some(self.npub_hex().as_str()) {
            return Err(LijError::Key("kit envelope: not this identity's".into()));
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kit_key));
        let aad = self.aad();
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad })
            .map_err(|e| LijError::Key(format!("kit open: {e}")))
    }

    /// The signed body a holder accepts at POST /v1/kit.
    pub fn put_body(&self, envelope_json: &str, seq: u64) -> String {
        let env_hash = sha256::Hash::hash(envelope_json.as_bytes());
        let mut pre = Vec::with_capacity(16 + 33 + 8 + 32);
        pre.extend_from_slice(PUT_DOMAIN);
        pre.extend_from_slice(&self.pubkey.serialize());
        pre.extend_from_slice(&seq.to_be_bytes());
        pre.extend_from_slice(env_hash.as_ref());
        let digest = sha256::Hash::hash(&pre);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &self.secret);
        format!(
            "{{\"pubkey\":\"{}\",\"seq\":{},\"kit\":{},\"sig\":\"{}\"}}",
            self.pubkey_hex(), seq, envelope_json, hex::encode(sig.serialize_compact())
        )
    }

    /// The signed NIP-78 event a relay accepts: kind 30078, d = lijox-kit-v1, content = the envelope.
    pub fn nostr_event(&self, envelope_json: &str, created_at: u64) -> LijResult<String> {
        let npub = self.npub_hex();
        let tags = serde_json::json!([[ "d", NOSTR_D_TAG ]]);
        let pre = serde_json::json!([0, npub, created_at, NOSTR_KIND, tags, envelope_json]);
        let pre_s = serde_json::to_string(&pre).map_err(|e| LijError::Key(format!("event: {e}")))?;
        let id = sha256::Hash::hash(pre_s.as_bytes());
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &self.secret);
        let mut aux = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut aux);
        let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(id.to_byte_array()), &keypair, &aux);
        let ev = serde_json::json!({
            "id": hex::encode(id.to_byte_array()),
            "pubkey": npub,
            "created_at": created_at,
            "kind": NOSTR_KIND,
            "tags": tags,
            "content": envelope_json,
            "sig": hex::encode(sig.as_ref()),
        });
        serde_json::to_string(&ev).map_err(|e| LijError::Key(format!("event: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use bitcoin::secp256k1::{ecdsa, schnorr, XOnlyPublicKey};
    use bitcoin::Network;

    fn keys() -> BlackStartKeys {
        // the NIP-06 test vector
        let m = Mnemonic::parse("leader monkey parrot ring guide accident before fence cannon height naive bean").unwrap();
        let root = RootKey::from_mnemonic(&m, Network::Bitcoin).unwrap();
        BlackStartKeys::from_root(&root).unwrap()
    }

    #[test]
    fn nip06_vector() {
        let k = keys();
        assert_eq!(k.npub_hex(), "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917");
        assert_eq!(hex::encode(k.secret.secret_bytes()), "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a");
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let k = keys();
        let env = k.seal(b"{\"v\":1,\"channels\":[]}", 1700000000000).unwrap();
        assert!(env.starts_with("{\"v\":1,\"alg\":\"A256GCM\",\"kdf\":\"hkdf-sha256:lijox-black-start:escape-kit-v1\",\"npub\":\"17162c92"));
        assert_eq!(k.open(&env).unwrap(), b"{\"v\":1,\"channels\":[]}");
        // a relabelled envelope does not open (AAD carries the npub)
        let other = env.replace("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917", "00000000000000000000000000000000000000000000000000000000000000ff");
        assert!(k.open(&other).is_err());
        // a flipped byte of ciphertext does not open
        let mut bad = env.clone(); let i = bad.rfind("\"ct\":\"").unwrap() + 8; let c = bad.as_bytes()[i]; bad.replace_range(i..i + 1, if c == b'a' { "b" } else { "a" });
        assert!(k.open(&bad).is_err());
    }

    #[test]
    fn put_body_verifies_with_ecdsa() {
        let k = keys();
        let env = k.seal(b"{}", 42).unwrap();
        let body = k.put_body(&env, 42);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["pubkey"].as_str().unwrap(), k.pubkey_hex());
        assert_eq!(v["seq"].as_u64().unwrap(), 42);
        // a holder rebuilds the canonical envelope from the parsed fields (key order is the parser's business)
        let kv = &v["kit"];
        let canon = format!("{{\"v\":{},\"alg\":\"{}\",\"kdf\":\"{}\",\"npub\":\"{}\",\"seq\":{},\"nonce\":\"{}\",\"ct\":\"{}\"}}",
            kv["v"].as_u64().unwrap(), kv["alg"].as_str().unwrap(), kv["kdf"].as_str().unwrap(), kv["npub"].as_str().unwrap(), kv["seq"].as_u64().unwrap(), kv["nonce"].as_str().unwrap(), kv["ct"].as_str().unwrap());
        assert_eq!(canon, env, "the canonical form (fixed field order, no whitespace) is what the engine sealed");
        let env_hash = sha256::Hash::hash(env.as_bytes());
        let mut pre = Vec::new();
        pre.extend_from_slice(PUT_DOMAIN); pre.extend_from_slice(&k.pubkey.serialize()); pre.extend_from_slice(&42u64.to_be_bytes()); pre.extend_from_slice(env_hash.as_ref());
        let digest = sha256::Hash::hash(&pre);
        let sig = ecdsa::Signature::from_compact(&hex::decode(v["sig"].as_str().unwrap()).unwrap()).unwrap();
        let secp = Secp256k1::new();
        assert!(secp.verify_ecdsa(&Message::from_digest(digest.to_byte_array()), &sig, &k.pubkey).is_ok());
        // the same digest with seq 43 does not verify — seq is inside the signature
        let mut pre2 = Vec::new();
        pre2.extend_from_slice(PUT_DOMAIN); pre2.extend_from_slice(&k.pubkey.serialize()); pre2.extend_from_slice(&43u64.to_be_bytes()); pre2.extend_from_slice(env_hash.as_ref());
        assert!(secp.verify_ecdsa(&Message::from_digest(sha256::Hash::hash(&pre2).to_byte_array()), &sig, &k.pubkey).is_err());
    }

    /// A fixture for the adapter's holder test (cross-implementation): `cargo test -p lij-core
    /// --lib black_start::tests::print_fixture -- --nocapture --ignored`.
    #[test]
    #[ignore]
    fn print_fixture() {
        let k = keys();
        let env = k.seal(b"{\"v\":1,\"channels\":[],\"note\":\"fixture\"}", 1758600000000).unwrap();
        println!("FIXTURE_PUT {}", k.put_body(&env, 1758600000000));
        println!("FIXTURE_EVENT {}", k.nostr_event(&env, 1758600000).unwrap());
        // a second kit, with one channel and an LSP, for the /recover page's gate
        let plain2 = r#"{"v":1,"made_at":1758600100000,"seq":1758600100000,"lsp":{"pubkey":"02aa","endpoint":"http://127.0.0.1:8767"},"sweep_destination_index":7,"sweep_destination_address":"bc1qgatefixture","feerate_normal_sat_vb":10,"feerate_high_sat_vb":40,"channels":[{"channel_id":"c1","open":true,"claimable_sats":12345,"funding_txo":"f1:0","counterparty":"02aa","commitment_txid":"abababababababababababababababababababababababababababababababab","commitment_hex":"0200000001ab","htlc_tx_hexes":[],"to_self_delay":144,"our_to_local_sats":12345,"has_to_local":true,"sweep_txid_normal":"cd","sweep_hex_normal":"0200000002cd","sweep_txid_high":"ef","sweep_hex_high":"0200000003ef"}]}"#;
        let env2 = k.seal(plain2.as_bytes(), 1758600100000).unwrap();
        println!("FIXTURE_PUT2 {}", k.put_body(&env2, 1758600100000));
    }

    #[test]
    fn nostr_event_id_and_schnorr_verify() {
        let k = keys();
        let env = k.seal(b"{}", 7).unwrap();
        let ev_s = k.nostr_event(&env, 1700000000).unwrap();
        let ev: serde_json::Value = serde_json::from_str(&ev_s).unwrap();
        assert_eq!(ev["kind"].as_u64().unwrap(), 30078);
        assert_eq!(ev["tags"][0][1].as_str().unwrap(), "lijox-kit-v1");
        assert_eq!(ev["content"].as_str().unwrap(), env);
        let pre = serde_json::json!([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]);
        let id = sha256::Hash::hash(serde_json::to_string(&pre).unwrap().as_bytes());
        assert_eq!(ev["id"].as_str().unwrap(), hex::encode(id.to_byte_array()));
        let sig = schnorr::Signature::from_slice(&hex::decode(ev["sig"].as_str().unwrap()).unwrap()).unwrap();
        let xonly = XOnlyPublicKey::from_slice(&hex::decode(ev["pubkey"].as_str().unwrap()).unwrap()).unwrap();
        let secp = Secp256k1::new();
        assert!(secp.verify_schnorr(&sig, &Message::from_digest(id.to_byte_array()), &xonly).is_ok());
    }
}
