//! v286 (S50, NWC — cut N1, the engine; DP GO 2026-09-28 17:50 "start on NWC … separate and
//! isolated work"): the pure half of Nostr Wallet Connect (NIP-47) for LiJ.
//!
//! What lives here (no page, no network — the page owns the relay websocket and the UI):
//! - NIP-44 v2 encryption (ChaCha20 + HMAC-SHA256 under HKDF, the padding, base64), gated by the
//!   official test vectors in `testdata/nip44.vectors.json`; ChaCha20 is RFC 8439 written out
//!   below (the engine had no ChaCha20 crate; DP's "no new crate unless told" — none added),
//!   gated by the RFC's own vectors.
//! - Nostr events (NIP-01): the id over the canonical serialization, BIP-340 Schnorr signing and
//!   verification through the secp256k1 the engine already carries.
//! - The connections (one per Nostr app — DP's ruling): the service key pair (secret kept, at
//!   rest under the ledger's encryption, riding the state blob so a restore on the same LSP keeps
//!   them), the client's public key only (NIP-47: the service never stores the client secret),
//!   the connection string handed out once, revoke / expiry / "ended" marks.
//! - The limits (DP's defaults: 5,000 sats per payment, 20,000 sats per rolling day across every
//!   connection, connections expire after 90 days, requests older than 10 minutes dropped), the
//!   paid list they are checked against, and the duplicate check (same payee within 10 minutes,
//!   strongest when the amount matches).
//! - A request's opening: the event verified (kind, signature, author = the connection's client
//!   key, `p` = our service key, created_at within ±10 minutes, the expiration tag), the content
//!   decrypted and parsed; `pay_invoice` checked against the invoice (network, expiry, amount) and
//!   the limits; every refusal carries the NIP-47 error code the reply must use.
//! - The replies (23195, `e` = the request, `p` = the client key), the info event (13194,
//!   `pay_invoice`, encryption `nip44_v2`), and the NIP-42 AUTH event (22242) for the relay.
//!
//! The adapter's relay (nwc.js, cut N2) never sees a key, an invoice, an amount or a payee: only
//! the content is encrypted, and that is all it stores.

use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use hkdf::hmac::{Hmac, Mac};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{LijError, LijResult};

/// The store's key — encrypted at rest (tier2_wallet::ENCRYPTED_KEYS) and in the state blob.
pub const NWC_KEY: &str = "lij_nwc";

pub const KIND_INFO: u32 = 13194;
pub const KIND_REQUEST: u32 = 23194;
pub const KIND_RESPONSE: u32 = 23195;
pub const KIND_AUTH: u32 = 22242;
pub const ENCRYPTION: &str = "nip44_v2";
/// v290 (S50, DP's Nostur zap 21:52 — "this wallet speaks NIP-44 v2 only"): the older scheme, NIP-04
/// (AES-256-CBC under the raw ECDH x, base64 with "?iv="), which Nostur and most NWC apps still send.
/// Accepted and answered in kind; NIP-44 stays the wallet's first choice (the info event lists both).
pub const ENCRYPTION_NIP04: &str = "nip04";
pub const ENCRYPTIONS_OFFERED: &str = "nip44_v2 nip04";
/// The one method a LiJ connection offers (the info event's content).
pub const METHODS: &str = "pay_invoice";

// DP's defaults and constants (2026-09-27).
pub const DEFAULT_PER_PAYMENT_SATS: u64 = 5_000;
pub const DEFAULT_PER_DAY_SATS: u64 = 20_000;
pub const DEFAULT_CONNECTION_DAYS: u32 = 90;
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 600;
pub const MAX_CONNECTIONS: usize = 10;
pub const CREATED_AT_SKEW_SECS: u64 = 600;
pub const DUPLICATE_WINDOW_SECS: u64 = 600;
pub const NAME_MAX_CHARS: usize = 40;
const DAY_SECS: u64 = 24 * 3600;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// ChaCha20 (RFC 8439) — 32-byte key, 12-byte nonce, 32-bit counter. NIP-44 starts at counter 0.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[inline]
fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865; s[1] = 0x3320_646e; s[2] = 0x7962_2d32; s[3] = 0x6b20_6574;
    for i in 0..8 { s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]); }
    s[12] = counter;
    for i in 0..3 { s[13 + i] = u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]); }
    let mut w = s;
    for _ in 0..10 {
        qr(&mut w, 0, 4, 8, 12); qr(&mut w, 1, 5, 9, 13); qr(&mut w, 2, 6, 10, 14); qr(&mut w, 3, 7, 11, 15);
        qr(&mut w, 0, 5, 10, 15); qr(&mut w, 1, 6, 11, 12); qr(&mut w, 2, 7, 8, 13); qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].wrapping_add(s[i]).to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream (encrypt and decrypt are the same operation).
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ks = chacha20_block(key, nonce, counter.wrapping_add(i as u32));
        for (b, k) in chunk.iter_mut().zip(ks.iter()) { *b ^= *k; }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Base64 (RFC 4648, with padding) — NIP-44's payload encoding.
// ─────────────────────────────────────────────────────────────────────────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 { return None; }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    for (ci, chunk) in b.chunks(4).enumerate() {
        let last = ci == b.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) { return None; }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n <<= 6;
            if i >= 4 - pad { continue; }
            n |= val(c)?;
        }
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// NIP-44 v2
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    for p in parts { mac.update(p); }
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { d |= x ^ y; }
    d == 0
}

/// The x-only public key for a 32-byte hex string (a Nostr pubkey), lifted to even y.
pub fn pubkey_from_hex(hex32: &str) -> LijResult<PublicKey> {
    let b = hex::decode(hex32).map_err(|_| LijError::Node("nwc: pubkey is not hex".into()))?;
    let x = XOnlyPublicKey::from_slice(&b).map_err(|_| LijError::Node("nwc: pubkey is not a curve point".into()))?;
    Ok(PublicKey::from_x_only_public_key(x, Parity::Even))
}

/// NIP-44 step 1: the conversation key — HKDF-extract(salt "nip44-v2", ikm = x(a·B)). The same
/// for both sides: conv(a, B) == conv(b, A).
pub fn conversation_key(sk: &SecretKey, pk: &PublicKey) -> LijResult<[u8; 32]> {
    Ok(hkdf_extract(b"nip44-v2", &ecdh_x(sk, pk)?))
}

/// The x-coordinate of the ECDH point sk·pk — NIP-44 hashes it (above); NIP-04 uses it raw as the AES key.
pub fn ecdh_x(sk: &SecretKey, pk: &PublicKey) -> LijResult<[u8; 32]> {
    let secp = Secp256k1::new();
    let shared = pk
        .mul_tweak(&secp, &Scalar::from(*sk))
        .map_err(|e| LijError::Node(format!("nwc: ecdh: {e}")))?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&shared.serialize()[1..33]);
    Ok(x)
}

// ── v290: NIP-04 — AES-256-CBC (PKCS#7) under the raw ECDH x; payload = base64(ct) "?iv=" base64(iv) ──
fn aes256_cbc(key: &[u8; 32], iv: &[u8; 16], data: &[u8], encrypt: bool) -> LijResult<Vec<u8>> {
    use aes_gcm::aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    let cipher = aes_gcm::aes::Aes256::new(GenericArray::from_slice(key));
    if encrypt {
        let pad = 16 - (data.len() % 16);
        let mut buf = Vec::with_capacity(data.len() + pad);
        buf.extend_from_slice(data);
        buf.extend(std::iter::repeat(pad as u8).take(pad));
        let mut prev = *iv;
        for chunk in buf.chunks_mut(16) {
            for (b, p) in chunk.iter_mut().zip(prev.iter()) { *b ^= p; }
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            prev.copy_from_slice(chunk);
        }
        Ok(buf)
    } else {
        if data.is_empty() || data.len() % 16 != 0 {
            return Err(LijError::Node("nwc: nip04 ciphertext is not whole blocks".into()));
        }
        let mut buf = data.to_vec();
        let mut prev = *iv;
        for chunk in buf.chunks_mut(16) {
            let this: [u8; 16] = chunk.try_into().expect("16");
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            for (b, p) in chunk.iter_mut().zip(prev.iter()) { *b ^= p; }
            prev = this;
        }
        let pad = *buf.last().unwrap_or(&0) as usize;
        if pad == 0 || pad > 16 || pad > buf.len() || !buf[buf.len() - pad..].iter().all(|&b| b as usize == pad) {
            return Err(LijError::Node("nwc: nip04 padding is wrong (not our key?)".into()));
        }
        buf.truncate(buf.len() - pad);
        Ok(buf)
    }
}

pub fn nip04_encrypt_with_iv(shared_x: &[u8; 32], iv: &[u8; 16], plaintext: &str) -> LijResult<String> {
    let ct = aes256_cbc(shared_x, iv, plaintext.as_bytes(), true)?;
    Ok(format!("{}?iv={}", base64_encode(&ct), base64_encode(iv)))
}

pub fn nip04_encrypt(shared_x: &[u8; 32], plaintext: &str) -> LijResult<String> {
    let mut iv = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
    nip04_encrypt_with_iv(shared_x, &iv, plaintext)
}

/// True when a content string has NIP-04's shape (base64 "?iv=" base64).
pub fn looks_nip04(content: &str) -> bool {
    content.contains("?iv=")
}

pub fn nip04_decrypt(shared_x: &[u8; 32], payload: &str) -> LijResult<String> {
    let (ct_b64, iv_b64) = payload.split_once("?iv=").ok_or_else(|| LijError::Node("nwc: nip04 payload has no iv".into()))?;
    let ct = base64_decode(ct_b64.trim()).ok_or_else(|| LijError::Node("nwc: nip04 ciphertext is not base64".into()))?;
    let iv_v = base64_decode(iv_b64.trim()).ok_or_else(|| LijError::Node("nwc: nip04 iv is not base64".into()))?;
    if iv_v.len() != 16 {
        return Err(LijError::Node("nwc: nip04 iv is not 16 bytes".into()));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_v);
    let plain = aes256_cbc(shared_x, &iv, &ct, false)?;
    String::from_utf8(plain).map_err(|_| LijError::Node("nwc: nip04 plaintext is not UTF-8".into()))
}

/// NIP-44 step 3: chacha_key ‖ chacha_nonce ‖ hmac_key = HKDF-expand(conversation key, nonce, 76).
fn message_keys(conv: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(conv).expect("32-byte prk");
    let mut okm = [0u8; 76];
    hk.expand(nonce, &mut okm).expect("76 bytes is within HKDF's limit");
    let mut ck = [0u8; 32]; ck.copy_from_slice(&okm[0..32]);
    let mut cn = [0u8; 12]; cn.copy_from_slice(&okm[32..44]);
    let mut hk2 = [0u8; 32]; hk2.copy_from_slice(&okm[44..76]);
    (ck, cn, hk2)
}

/// NIP-44's padded length for a plaintext of `len` bytes (1..=65535).
pub fn calc_padded_len(len: usize) -> usize {
    if len <= 32 { return 32; }
    let next_power = 1usize << (((len - 1) as f64).log2().floor() as u32 + 1);
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((len - 1) / chunk + 1)
}

fn pad(plain: &[u8]) -> LijResult<Vec<u8>> {
    let len = plain.len();
    if len == 0 || len > 65535 {
        return Err(LijError::Node("nwc: invalid plaintext length".into()));
    }
    let mut out = Vec::with_capacity(2 + calc_padded_len(len));
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(plain);
    out.resize(2 + calc_padded_len(len), 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> LijResult<Vec<u8>> {
    if padded.len() < 2 { return Err(LijError::Node("nwc: invalid padding".into())); }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len == 0 || padded.len() < 2 + len || padded.len() != 2 + calc_padded_len(len) {
        return Err(LijError::Node("nwc: invalid padding".into()));
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Encrypt with a given nonce (the vectors need it); `encrypt` below draws a random one.
pub fn nip44_encrypt_with_nonce(conv: &[u8; 32], nonce: &[u8; 32], plaintext: &str) -> LijResult<String> {
    let (ck, cn, hk) = message_keys(conv, nonce);
    let mut buf = pad(plaintext.as_bytes())?;
    chacha20_xor(&ck, &cn, 0, &mut buf);
    let mac = hmac_sha256(&hk, &[nonce, &buf]);
    let mut payload = Vec::with_capacity(1 + 32 + buf.len() + 32);
    payload.push(2u8);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buf);
    payload.extend_from_slice(&mac);
    Ok(base64_encode(&payload))
}

pub fn nip44_encrypt(conv: &[u8; 32], plaintext: &str) -> LijResult<String> {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nip44_encrypt_with_nonce(conv, &nonce, plaintext)
}

pub fn nip44_decrypt(conv: &[u8; 32], payload: &str) -> LijResult<String> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err(LijError::Node("nwc: unknown encryption version".into()));
    }
    if payload.len() < 132 {
        return Err(LijError::Node("nwc: invalid payload length".into()));
    }
    let data = base64_decode(payload).ok_or_else(|| LijError::Node("nwc: invalid base64".into()))?;
    if data.len() < 99 {
        return Err(LijError::Node("nwc: invalid payload length".into()));
    }
    if data[0] != 2 {
        return Err(LijError::Node(format!("nwc: unknown encryption version {}", data[0])));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[1..33]);
    let ct = &data[33..data.len() - 32];
    let mac = &data[data.len() - 32..];
    let (ck, cn, hk) = message_keys(conv, &nonce);
    let want = hmac_sha256(&hk, &[&nonce, ct]);
    if !ct_eq(&want, mac) {
        return Err(LijError::Node("nwc: invalid MAC".into()));
    }
    let mut buf = ct.to_vec();
    chacha20_xor(&ck, &cn, 0, &mut buf);
    let plain = unpad(&buf)?;
    String::from_utf8(plain).map_err(|_| LijError::Node("nwc: plaintext is not UTF-8".into()))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Nostr events (NIP-01)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// The event id: sha256 over `[0, pubkey, created_at, kind, tags, content]` serialized without
/// whitespace (serde_json's escaping is JSON.stringify's — the NIP-01 rule set).
pub fn event_id(pubkey: &str, created_at: u64, kind: u32, tags: &[Vec<String>], content: &str) -> String {
    let ser = serde_json::to_string(&(0u8, pubkey, created_at, kind, tags, content)).expect("serializable");
    sha256::Hash::hash(ser.as_bytes()).to_string()
}

/// Build and sign an event with `sk` (BIP-340 Schnorr, random aux).
pub fn sign_event(sk: &SecretKey, created_at: u64, kind: u32, tags: Vec<Vec<String>>, content: String) -> Event {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, sk);
    let pubkey = hex::encode(kp.x_only_public_key().0.serialize());
    let id = event_id(&pubkey, created_at, kind, &tags, &content);
    let msg = Message::from_digest(<[u8; 32]>::try_from(hex::decode(&id).expect("hex id")).expect("32 bytes"));
    let mut aux = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut aux);
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &kp, &aux);
    Event { id, pubkey, created_at, kind, tags, content, sig: hex::encode(sig.as_ref()) }
}

/// Verify an event: the id is the hash of its fields and the signature is the author's.
pub fn verify_event(ev: &Event) -> LijResult<()> {
    let id = event_id(&ev.pubkey, ev.created_at, ev.kind, &ev.tags, &ev.content);
    if id != ev.id.to_ascii_lowercase() {
        return Err(LijError::Node("nwc: event id does not match its fields".into()));
    }
    let secp = Secp256k1::new();
    let x = XOnlyPublicKey::from_slice(&hex::decode(&ev.pubkey).map_err(|_| LijError::Node("nwc: event pubkey is not hex".into()))?)
        .map_err(|_| LijError::Node("nwc: event pubkey is not a curve point".into()))?;
    let sig = schnorr::Signature::from_slice(&hex::decode(&ev.sig).map_err(|_| LijError::Node("nwc: event sig is not hex".into()))?)
        .map_err(|_| LijError::Node("nwc: event sig is not 64 bytes".into()))?;
    let msg = Message::from_digest(<[u8; 32]>::try_from(hex::decode(&id).expect("hex id")).expect("32 bytes"));
    secp.verify_schnorr(&sig, &msg, &x).map_err(|_| LijError::Node("nwc: event signature does not verify".into()))
}

fn tag_value<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    ev.tags.iter().find(|t| t.len() >= 2 && t[0] == name).map(|t| t[1].as_str())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Connections, limits, the paid list
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub id: u32,
    /// The app's name as the user typed it (cleaned, ≤ 40 chars).
    pub name: String,
    /// The service secret — the key that decrypts requests and signs replies. Never leaves the engine.
    pub service_sk: String,
    /// x-only hex — the connection string's path, the `p` tag every request carries.
    pub service_pk: String,
    /// The client's x-only public key — the author of every request, the `p` of every reply.
    pub client_pk: String,
    pub relay: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    #[serde(default)]
    pub last_used_ms: u64,
    /// None while live; "revoked" / "expired" / "switched" once ended (the row stays, greyed).
    #[serde(default)]
    pub ended: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Limits {
    pub per_payment_sats: u64,
    pub per_day_sats: u64,
    pub connection_days: u32,
    pub request_ttl_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            per_payment_sats: DEFAULT_PER_PAYMENT_SATS,
            per_day_sats: DEFAULT_PER_DAY_SATS,
            connection_days: DEFAULT_CONNECTION_DAYS,
            request_ttl_secs: DEFAULT_REQUEST_TTL_SECS,
        }
    }
}

/// One NWC payment made (the daily total and the duplicate check read this).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paid {
    pub ts_ms: u64,
    pub conn_id: u32,
    pub msat: u64,
    /// The invoice's payee node key (hex) — the duplicate check's "same payee".
    pub payee: String,
    pub payment_hash: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Store {
    #[serde(default)]
    pub conns: Vec<Connection>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub paid: Vec<Paid>,
    #[serde(default)]
    pub next_id: u32,
}

pub fn clean_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(NAME_MAX_CHARS)
        .collect();
    if s.is_empty() { "App".to_string() } else { s }
}

/// What `add` hands back — the client secret appears here and nowhere else.
#[derive(Clone, Debug, Serialize)]
pub struct Added {
    pub id: u32,
    pub name: String,
    pub service_pk: String,
    pub client_pk: String,
    /// `nostr+walletconnect://<service pk>?relay=<url>&secret=<client secret>` — shown once.
    pub uri: String,
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

impl Store {
    pub fn limits(&self) -> Limits {
        self.limits.clone().unwrap_or_default()
    }

    pub fn live(&self, now_ms: u64) -> impl Iterator<Item = &Connection> {
        self.conns.iter().filter(move |c| c.ended.is_none() && c.expires_ms > now_ms)
    }

    /// A new connection for one app. Random service key pair and client secret; the client
    /// secret is returned in the string and forgotten. Capped at MAX_CONNECTIONS live ones.
    pub fn add(&mut self, name: &str, relay: &str, now_ms: u64) -> LijResult<Added> {
        if self.live(now_ms).count() >= MAX_CONNECTIONS {
            return Err(LijError::Node(format!("NWC: at most {MAX_CONNECTIONS} connections — revoke one first")));
        }
        if !(relay.starts_with("wss://") || relay.starts_with("ws://")) || relay.len() > 200 {
            return Err(LijError::Node("NWC: the relay must be a wss:// address".into()));
        }
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let service_sk = SecretKey::new(&mut rng);
        let client_sk = SecretKey::new(&mut rng);
        let service_pk = hex::encode(Keypair::from_secret_key(&secp, &service_sk).x_only_public_key().0.serialize());
        let client_pk = hex::encode(Keypair::from_secret_key(&secp, &client_sk).x_only_public_key().0.serialize());
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        let limits = self.limits();
        let conn = Connection {
            id,
            name: clean_name(name),
            service_sk: hex::encode(service_sk.secret_bytes()),
            service_pk: service_pk.clone(),
            client_pk: client_pk.clone(),
            relay: relay.to_string(),
            created_ms: now_ms,
            expires_ms: now_ms.saturating_add(limits.connection_days as u64 * DAY_SECS * 1000),
            last_used_ms: 0,
            ended: None,
        };
        let uri = format!(
            "nostr+walletconnect://{}?relay={}&secret={}",
            service_pk,
            url_encode(relay),
            hex::encode(client_sk.secret_bytes())
        );
        self.conns.push(conn.clone());
        Ok(Added { id, name: conn.name, service_pk, client_pk, uri })
    }

    pub fn get(&self, id: u32) -> Option<&Connection> {
        self.conns.iter().find(|c| c.id == id)
    }

    /// The live connection a request is addressed to (its `p` tag = our service key).
    pub fn by_service_pk(&self, service_pk: &str, now_ms: u64) -> Option<&Connection> {
        self.live(now_ms).find(|c| c.service_pk.eq_ignore_ascii_case(service_pk))
    }

    /// Mark a connection ended (revoked by the user, expired, or the LSP switched). The secret
    /// is dropped at once; the row stays so the list can say what happened.
    pub fn end(&mut self, id: u32, reason: &str) -> LijResult<()> {
        let c = self.conns.iter_mut().find(|c| c.id == id).ok_or_else(|| LijError::Node("NWC: no such connection".into()))?;
        if c.ended.is_none() {
            c.ended = Some(reason.to_string());
            c.service_sk = String::new();
        }
        Ok(())
    }

    /// Drop an ended connection's row.
    pub fn forget(&mut self, id: u32) {
        self.conns.retain(|c| !(c.id == id && c.ended.is_some()));
    }

    /// Connections past their expiry are marked "expired" (the LSP drops its registration on its own).
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for c in self.conns.iter_mut() {
            if c.ended.is_none() && c.expires_ms <= now_ms {
                c.ended = Some("expired".into());
                c.service_sk = String::new();
                n += 1;
            }
        }
        n
    }

    /// Every live connection ended as "switched" — the LSP switch flow (DP: connections are
    /// revoked on a switch; the user re-adds them with the new LSP if it offers NWC).
    pub fn end_all(&mut self, reason: &str) -> usize {
        let mut n = 0;
        for c in self.conns.iter_mut() {
            if c.ended.is_none() {
                c.ended = Some(reason.to_string());
                c.service_sk = String::new();
                n += 1;
            }
        }
        n
    }

    pub fn set_limits(&mut self, l: Limits) -> LijResult<()> {
        if l.per_payment_sats == 0 || l.per_day_sats == 0 || l.connection_days == 0 || l.request_ttl_secs == 0 {
            return Err(LijError::Node("NWC: a limit cannot be zero".into()));
        }
        if l.per_payment_sats > l.per_day_sats {
            return Err(LijError::Node("NWC: the per-payment limit cannot exceed the daily limit".into()));
        }
        self.limits = Some(l);
        Ok(())
    }

    /// Sats paid through NWC in the rolling 24 h ending now, all connections together.
    pub fn paid_today_msat(&self, now_ms: u64) -> u64 {
        let since = now_ms.saturating_sub(DAY_SECS * 1000);
        self.paid.iter().filter(|p| p.ts_ms >= since).map(|p| p.msat).sum()
    }

    /// Record a payment made (called once the preimage is in hand). Prunes entries older than a day.
    pub fn record_paid(&mut self, conn_id: u32, msat: u64, payee: &str, payment_hash: &str, now_ms: u64) {
        self.paid.push(Paid { ts_ms: now_ms, conn_id, msat, payee: payee.to_ascii_lowercase(), payment_hash: payment_hash.to_ascii_lowercase() });
        let keep_from = now_ms.saturating_sub(DAY_SECS * 1000);
        self.paid.retain(|p| p.ts_ms >= keep_from);
        if let Some(c) = self.conns.iter_mut().find(|c| c.id == conn_id) { c.last_used_ms = now_ms; }
    }

    /// The duplicate check (DP: flag a second request to the same payee; strongest when the
    /// amount matches too): the most recent NWC payment to `payee` within the window.
    pub fn duplicate(&self, payee: &str, msat: u64, now_ms: u64) -> Option<Duplicate> {
        let since = now_ms.saturating_sub(DUPLICATE_WINDOW_SECS * 1000);
        let p = self
            .paid
            .iter()
            .filter(|p| p.ts_ms >= since && p.payee.eq_ignore_ascii_case(payee))
            .max_by_key(|p| p.ts_ms)?;
        Some(Duplicate {
            ago_secs: now_ms.saturating_sub(p.ts_ms) / 1000,
            msat: p.msat,
            same_amount: p.msat == msat,
            conn_id: p.conn_id,
            app: self.get(p.conn_id).map(|c| c.name.clone()).unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Duplicate {
    pub ago_secs: u64,
    pub msat: u64,
    pub same_amount: bool,
    pub conn_id: u32,
    pub app: String,
}

pub fn load(storage: &dyn crate::storage::LijStorage) -> LijResult<Store> {
    match storage.get(NWC_KEY)? {
        Some(b) => serde_json::from_slice(&b).map_err(|e| LijError::Storage(format!("nwc store parse: {e}"))),
        None => Ok(Store::default()),
    }
}

pub fn save(storage: &dyn crate::storage::LijStorage, s: &Store) -> LijResult<()> {
    let b = serde_json::to_vec(s).map_err(|e| LijError::Storage(format!("nwc store serialize: {e}")))?;
    storage.set(NWC_KEY, &b)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The events a connection makes
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn secret_of(c: &Connection) -> LijResult<SecretKey> {
    if c.ended.is_some() || c.service_sk.is_empty() {
        return Err(LijError::Node("NWC: this connection has ended".into()));
    }
    SecretKey::from_slice(&hex::decode(&c.service_sk).map_err(|_| LijError::Node("nwc: bad service key".into()))?)
        .map_err(|_| LijError::Node("nwc: bad service key".into()))
}

/// The info event (13194): what this connection offers — `pay_invoice`; NIP-44 v2 first, NIP-04 too (v290).
pub fn info_event(c: &Connection, now_secs: u64) -> LijResult<Event> {
    let sk = secret_of(c)?;
    Ok(sign_event(&sk, now_secs, KIND_INFO, vec![vec!["encryption".into(), ENCRYPTIONS_OFFERED.into()]], METHODS.into()))
}

/// The NIP-42 AUTH event (22242) that proves this connection's service key to the relay.
pub fn auth_event(c: &Connection, relay: &str, challenge: &str, now_secs: u64) -> LijResult<Event> {
    let sk = secret_of(c)?;
    Ok(sign_event(
        &sk,
        now_secs,
        KIND_AUTH,
        vec![vec!["relay".into(), relay.into()], vec!["challenge".into(), challenge.into()]],
        String::new(),
    ))
}

/// A reply (23195) to `request_id`, encrypted to the connection's client key — in the scheme the
/// request came in (`encryption`: "nip44_v2" or "nip04"; anything else reads as NIP-44).
pub fn reply_event(c: &Connection, request_id: &str, content_json: &str, now_secs: u64, encryption: &str) -> LijResult<Event> {
    let sk = secret_of(c)?;
    let client = pubkey_from_hex(&c.client_pk)?;
    let nip04 = encryption == ENCRYPTION_NIP04;
    let content = if nip04 {
        nip04_encrypt(&ecdh_x(&sk, &client)?, content_json)?
    } else {
        nip44_encrypt(&conversation_key(&sk, &client)?, content_json)?
    };
    let mut tags = vec![
        vec!["p".into(), c.client_pk.clone()],
        vec!["e".into(), request_id.to_ascii_lowercase()],
    ];
    if !nip04 { tags.push(vec!["encryption".into(), ENCRYPTION.into()]); }   // NIP-47: the tag names NIP-44; NIP-04 replies carry none
    Ok(sign_event(&sk, now_secs, KIND_RESPONSE, tags, content))
}

/// The reply bodies (NIP-47): a result, or an error with its code.
pub fn result_json(result_type: &str, result: serde_json::Value) -> String {
    serde_json::json!({ "result_type": result_type, "error": null, "result": result }).to_string()
}

pub fn error_json(result_type: &str, code: &str, message: &str) -> String {
    serde_json::json!({ "result_type": result_type, "error": { "code": code, "message": message }, "result": null }).to_string()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Opening a request
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A request opened: the connection it belongs to, what it asks, and either the checked
/// payment or the refusal (with the NIP-47 code the reply must carry).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Opened {
    pub conn_id: u32,
    pub app: String,
    pub request_id: String,
    pub client_pk: String,
    pub created_at: u64,
    pub age_secs: u64,
    pub method: String,
    /// v290: the scheme the request came in ("nip44_v2" | "nip04") — the reply goes back the same way.
    pub encryption: String,
    pub invoice: Option<String>,
    /// From the invoice (or the request's `amount` for an amountless invoice).
    pub amount_msat: Option<u64>,
    pub payee: Option<String>,
    pub payment_hash: Option<String>,
    pub description: Option<String>,
    pub invoice_expires_at: Option<u64>,
    /// Set when the request must be refused — the page replies with this code and shows the reason.
    pub refusal: Option<Refusal>,
    pub duplicate: Option<Duplicate>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: String,
}

fn refuse(code: &str, message: impl Into<String>) -> Refusal {
    Refusal { code: code.into(), message: message.into() }
}

/// Verify + decrypt + parse + check a request event for `c`. Errors are for events that are not
/// ours or are malformed (the page drops them); an `Opened` with a `refusal` is a valid request
/// the wallet must answer with that error code.
pub fn open_request(store: &Store, c: &Connection, ev: &Event, network: bitcoin::Network, now_secs: u64) -> LijResult<Opened> {
    if ev.kind != KIND_REQUEST {
        return Err(LijError::Node("nwc: not a request event".into()));
    }
    if !ev.pubkey.eq_ignore_ascii_case(&c.client_pk) {
        return Err(LijError::Node("nwc: request is not from this connection's app".into()));
    }
    match tag_value(ev, "p") {
        Some(p) if p.eq_ignore_ascii_case(&c.service_pk) => {}
        _ => return Err(LijError::Node("nwc: request is not addressed to this connection".into())),
    }
    verify_event(ev)?;
    let limits = store.limits();
    let age = now_secs.saturating_sub(ev.created_at);
    if ev.created_at > now_secs + CREATED_AT_SKEW_SECS {
        return Err(LijError::Node("nwc: request is dated in the future".into()));
    }
    if age > limits.request_ttl_secs {
        return Err(LijError::Node(format!("nwc: request is {age} s old — older than the {} s limit", limits.request_ttl_secs)));
    }
    if let Some(exp) = tag_value(ev, "expiration").and_then(|s| s.parse::<u64>().ok()) {
        if exp <= now_secs {
            return Err(LijError::Node("nwc: request has expired (its expiration tag)".into()));
        }
    }
    let mut opened = Opened {
        conn_id: c.id,
        app: c.name.clone(),
        request_id: ev.id.to_ascii_lowercase(),
        client_pk: c.client_pk.clone(),
        created_at: ev.created_at,
        age_secs: age,
        method: String::new(),
        encryption: ENCRYPTION.into(),
        invoice: None,
        amount_msat: None,
        payee: None,
        payment_hash: None,
        description: None,
        invoice_expires_at: None,
        refusal: None,
        duplicate: None,
    };
    // v290: the scheme — the content's shape decides (NIP-04 carries "?iv="); the tag, when present, must agree
    let nip04 = looks_nip04(&ev.content);
    match tag_value(ev, "encryption") {
        Some(enc) if enc == ENCRYPTION && !nip04 => {}
        Some(enc) if enc == ENCRYPTION_NIP04 && nip04 => {}
        None => {}
        Some(_) => {
            opened.method = "unknown".into();
            opened.refusal = Some(refuse("UNSUPPORTED_ENCRYPTION", "this wallet speaks NIP-44 v2 and NIP-04"));
            return Ok(opened);
        }
    }
    let sk = secret_of(c)?;
    let client = pubkey_from_hex(&c.client_pk)?;
    let plain = if nip04 {
        opened.encryption = ENCRYPTION_NIP04.into();
        nip04_decrypt(&ecdh_x(&sk, &client)?, &ev.content)?
    } else {
        nip44_decrypt(&conversation_key(&sk, &client)?, &ev.content)?
    };
    let body: serde_json::Value = serde_json::from_str(&plain).map_err(|_| LijError::Node("nwc: request content is not JSON".into()))?;
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    opened.method = method.clone();
    match method.as_str() {
        "pay_invoice" => {}
        "get_info" => return Ok(opened),   // answered while open (handoff T3 default); the page builds the result
        _ => {
            opened.refusal = Some(refuse("NOT_IMPLEMENTED", format!("{} is not offered on this connection", if method.is_empty() { "that method" } else { method.as_str() })));
            return Ok(opened);
        }
    }
    let params = body.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let invoice_str = match params.get("invoice").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            opened.refusal = Some(refuse("OTHER", "the request carries no invoice"));
            return Ok(opened);
        }
    };
    opened.invoice = Some(invoice_str.clone());
    let inv = match lightning_invoice::Bolt11Invoice::from_str(&invoice_str) {
        Ok(i) => i,
        Err(e) => {
            opened.refusal = Some(refuse("OTHER", format!("the invoice does not decode: {e}")));
            return Ok(opened);
        }
    };
    let inv_net: bitcoin::Network = inv.network();
    if inv_net != network {
        opened.refusal = Some(refuse("OTHER", format!("the invoice is for {inv_net}, this wallet is on {network}")));
        return Ok(opened);
    }
    let payee = inv.payee_pub_key().copied().unwrap_or_else(|| inv.recover_payee_pub_key());
    opened.payee = Some(hex::encode(payee.serialize()));
    opened.payment_hash = Some(hex::encode(inv.payment_hash().as_ref() as &[u8]));
    opened.description = match inv.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => {
            let s = d.to_string();
            if s.is_empty() { None } else { Some(s.chars().take(200).collect()) }
        }
        _ => None,
    };
    let expires_at = inv.duration_since_epoch().as_secs().saturating_add(inv.expiry_time().as_secs());
    opened.invoice_expires_at = Some(expires_at);
    if expires_at <= now_secs {
        opened.refusal = Some(refuse("OTHER", "the invoice has expired"));
        return Ok(opened);
    }
    let amount_msat = match inv.amount_milli_satoshis() {
        Some(a) => a,
        None => match params.get("amount").and_then(|v| v.as_u64()) {
            Some(a) if a > 0 => a,
            _ => {
                opened.refusal = Some(refuse("OTHER", "the invoice names no amount and the request gives none"));
                return Ok(opened);
            }
        },
    };
    opened.amount_msat = Some(amount_msat);
    let sats = (amount_msat + 999) / 1000;
    if sats > limits.per_payment_sats {
        opened.refusal = Some(refuse("QUOTA_EXCEEDED", format!("{sats} sats is over this wallet's NWC limit of {} sats per payment", limits.per_payment_sats)));
        return Ok(opened);
    }
    let today = (store.paid_today_msat(now_secs * 1000) + 999) / 1000;
    if today.saturating_add(sats) > limits.per_day_sats {
        opened.refusal = Some(refuse("QUOTA_EXCEEDED", format!("{sats} sats would take today's NWC total past {} sats ({today} already paid)", limits.per_day_sats)));
        return Ok(opened);
    }
    opened.duplicate = store.duplicate(opened.payee.as_deref().unwrap_or(""), amount_msat, now_secs * 1000);
    Ok(opened)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }

    #[test]
    fn chacha20_rfc8439_block_and_cipher_vectors() {
        let key: [u8; 32] = <[u8; 32]>::try_from(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).unwrap();
        // §2.3.2 the block function
        let nonce: [u8; 12] = <[u8; 12]>::try_from(h("000000090000004a00000000")).unwrap();
        let block = chacha20_block(&key, &nonce, 1);
        assert_eq!(hex::encode(block), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
        // §2.4.2 the cipher
        let nonce2: [u8; 12] = <[u8; 12]>::try_from(h("000000000000004a00000000")).unwrap();
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce2, 1, &mut data);
        assert_eq!(hex::encode(&data), "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
        // and back
        chacha20_xor(&key, &nonce2, 1, &mut data);
        assert!(data.starts_with(b"Ladies and Gentlemen"));
    }

    #[test]
    fn base64_round_trips_and_rejects_bad_input() {
        for n in 0..70usize {
            let v: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            let e = base64_encode(&v);
            assert_eq!(base64_decode(&e).unwrap(), v, "len {n}");
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert!(base64_decode("TWF").is_none());
        assert!(base64_decode("TW=u").is_none());
        assert!(base64_decode("T*Fu").is_none());
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("testdata/nip44.vectors.json")).unwrap()
    }

    #[test]
    fn nip44_official_vectors_valid() {
        let v = vectors();
        let valid = &v["v2"]["valid"];
        // conversation keys
        let mut n = 0;
        for c in valid["get_conversation_key"].as_array().unwrap() {
            let sk = SecretKey::from_slice(&h(c["sec1"].as_str().unwrap())).unwrap();
            let pk = pubkey_from_hex(c["pub2"].as_str().unwrap()).unwrap();
            assert_eq!(hex::encode(conversation_key(&sk, &pk).unwrap()), c["conversation_key"].as_str().unwrap());
            n += 1;
        }
        assert_eq!(n, 35);
        // message keys
        let mk = &valid["get_message_keys"];
        let conv: [u8; 32] = <[u8; 32]>::try_from(h(mk["conversation_key"].as_str().unwrap())).unwrap();
        let mut n = 0;
        for k in mk["keys"].as_array().unwrap() {
            let nonce: [u8; 32] = <[u8; 32]>::try_from(h(k["nonce"].as_str().unwrap())).unwrap();
            let (ck, cn, hk) = message_keys(&conv, &nonce);
            assert_eq!(hex::encode(ck), k["chacha_key"].as_str().unwrap());
            assert_eq!(hex::encode(cn), k["chacha_nonce"].as_str().unwrap());
            assert_eq!(hex::encode(hk), k["hmac_key"].as_str().unwrap());
            n += 1;
        }
        assert_eq!(n, 32);
        // padding
        let mut n = 0;
        for p in valid["calc_padded_len"].as_array().unwrap() {
            let (len, want) = (p[0].as_u64().unwrap() as usize, p[1].as_u64().unwrap() as usize);
            assert_eq!(calc_padded_len(len), want, "len {len}");
            n += 1;
        }
        assert_eq!(n, 24);
        // encrypt / decrypt with the given nonce, both directions, and the key symmetry
        let mut n = 0;
        for e in valid["encrypt_decrypt"].as_array().unwrap() {
            let sk1 = SecretKey::from_slice(&h(e["sec1"].as_str().unwrap())).unwrap();
            let sk2 = SecretKey::from_slice(&h(e["sec2"].as_str().unwrap())).unwrap();
            let secp = Secp256k1::new();
            let pk1 = PublicKey::from_x_only_public_key(Keypair::from_secret_key(&secp, &sk1).x_only_public_key().0, Parity::Even);
            let pk2 = PublicKey::from_x_only_public_key(Keypair::from_secret_key(&secp, &sk2).x_only_public_key().0, Parity::Even);
            let c12 = conversation_key(&sk1, &pk2).unwrap();
            let c21 = conversation_key(&sk2, &pk1).unwrap();
            assert_eq!(c12, c21);
            assert_eq!(hex::encode(c12), e["conversation_key"].as_str().unwrap());
            let nonce: [u8; 32] = <[u8; 32]>::try_from(h(e["nonce"].as_str().unwrap())).unwrap();
            let plain = e["plaintext"].as_str().unwrap();
            let payload = nip44_encrypt_with_nonce(&c12, &nonce, plain).unwrap();
            assert_eq!(payload, e["payload"].as_str().unwrap());
            assert_eq!(nip44_decrypt(&c21, &payload).unwrap(), plain);
            n += 1;
        }
        assert_eq!(n, 10);
        // long messages: sha256 of plaintext and payload
        let mut n = 0;
        for l in valid["encrypt_decrypt_long_msg"].as_array().unwrap() {
            let conv: [u8; 32] = <[u8; 32]>::try_from(h(l["conversation_key"].as_str().unwrap())).unwrap();
            let nonce: [u8; 32] = <[u8; 32]>::try_from(h(l["nonce"].as_str().unwrap())).unwrap();
            let plain = l["pattern"].as_str().unwrap().repeat(l["repeat"].as_u64().unwrap() as usize);
            assert_eq!(sha256::Hash::hash(plain.as_bytes()).to_string(), l["plaintext_sha256"].as_str().unwrap());
            let payload = nip44_encrypt_with_nonce(&conv, &nonce, &plain).unwrap();
            assert_eq!(sha256::Hash::hash(payload.as_bytes()).to_string(), l["payload_sha256"].as_str().unwrap());
            assert_eq!(nip44_decrypt(&conv, &payload).unwrap(), plain);
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[test]
    fn nip44_official_vectors_invalid() {
        let v = vectors();
        let invalid = &v["v2"]["invalid"];
        let conv = [7u8; 32];
        for len in invalid["encrypt_msg_lengths"].as_array().unwrap() {
            let len = len.as_u64().unwrap() as usize;
            let plain = "x".repeat(len);
            assert!(nip44_encrypt(&conv, &plain).is_err(), "len {len} must be refused");
        }
        let mut n = 0;
        for c in invalid["get_conversation_key"].as_array().unwrap() {
            let sk = SecretKey::from_slice(&h(c["sec1"].as_str().unwrap()));
            let pk = pubkey_from_hex(c["pub2"].as_str().unwrap());
            let ok = match (sk, pk) {
                (Ok(sk), Ok(pk)) => conversation_key(&sk, &pk).is_ok(),
                _ => false,
            };
            assert!(!ok, "{}", c["note"]);
            n += 1;
        }
        assert_eq!(n, 8);
        let mut n = 0;
        for d in invalid["decrypt"].as_array().unwrap() {
            let conv: [u8; 32] = <[u8; 32]>::try_from(h(d["conversation_key"].as_str().unwrap())).unwrap();
            assert!(nip44_decrypt(&conv, d["payload"].as_str().unwrap()).is_err(), "{}", d["note"]);
            n += 1;
        }
        assert_eq!(n, 12);
    }

    #[test]
    fn events_sign_verify_and_reject_tampering() {
        let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let ev = sign_event(&sk, 1_700_000_000, KIND_INFO, vec![vec!["encryption".into(), "nip44_v2".into()]], "pay_invoice".into());
        assert_eq!(ev.pubkey.len(), 64);
        assert_eq!(ev.sig.len(), 128);
        verify_event(&ev).unwrap();
        // NIP-01 serialization check against a known id (computed with JSON.stringify's escaping)
        let id = event_id("aa".repeat(32).as_str(), 1, 1, &[vec!["t".into(), "x\"y\n".into()]], "hi \"there\"\n\\ ünï");
        let ser = "[0,\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",1,1,[[\"t\",\"x\\\"y\\n\"]],\"hi \\\"there\\\"\\n\\\\ ünï\"]";
        assert_eq!(id, sha256::Hash::hash(ser.as_bytes()).to_string());
        let mut bad = ev.clone();
        bad.content = "pay_invoice get_balance".into();
        assert!(verify_event(&bad).is_err(), "changed content → id mismatch");
        let mut bad2 = ev.clone();
        bad2.id = event_id(&bad2.pubkey, bad2.created_at, bad2.kind, &bad2.tags, "other");
        bad2.content = "other".into();
        assert!(verify_event(&bad2).is_err(), "re-hashed but the signature is over the old id");
    }

    fn store_with_conn() -> (Store, Added, SecretKey) {
        let mut s = Store::default();
        let a = s.add("Nostur", "wss://lijox-lsp.example/nwc", 1_000_000).unwrap();
        // the client secret from the string
        let secret = a.uri.split("secret=").nth(1).unwrap().to_string();
        let csk = SecretKey::from_slice(&h(&secret)).unwrap();
        (s, a, csk)
    }

    #[test]
    fn connections_add_string_cap_end_expire_switch() {
        let (mut s, a, csk) = store_with_conn();
        assert_eq!(a.id, 1);
        assert!(a.uri.starts_with(&format!("nostr+walletconnect://{}?relay=wss%3A%2F%2Flijox-lsp.example%2Fnwc&secret=", a.service_pk)));
        // the client key in the store is the public half of the secret handed out
        let secp = Secp256k1::new();
        assert_eq!(hex::encode(Keypair::from_secret_key(&secp, &csk).x_only_public_key().0.serialize()), a.client_pk);
        assert!(!s.get(1).unwrap().service_sk.is_empty());
        assert_eq!(s.get(1).unwrap().expires_ms, 1_000_000 + 90 * 24 * 3600 * 1000);
        assert!(s.by_service_pk(&a.service_pk.to_uppercase(), 2_000_000).is_some());
        // the cap
        for i in 0..9 { s.add(&format!("app{i}"), "wss://r", 1_000_000).unwrap(); }
        assert!(s.add("one too many", "wss://r", 1_000_000).unwrap_err().to_string().contains("at most 10"));
        assert!(s.add("bad relay", "https://r", 1_000_000).is_err());
        // revoke drops the secret, keeps the row, frees a slot
        s.end(1, "revoked").unwrap();
        assert_eq!(s.get(1).unwrap().ended.as_deref(), Some("revoked"));
        assert!(s.get(1).unwrap().service_sk.is_empty());
        assert!(s.by_service_pk(&a.service_pk, 2_000_000).is_none());
        assert!(info_event(s.get(1).unwrap(), 5).is_err(), "an ended connection signs nothing");
        s.add("eleventh", "wss://r", 1_000_000).unwrap();
        s.forget(1);
        assert!(s.get(1).is_none());
        // expiry
        assert_eq!(s.expire(1_000_000 + 91 * 24 * 3600 * 1000), 10);
        assert!(s.conns.iter().all(|c| c.ended.as_deref() == Some("expired")));
        // an LSP switch ends every live one
        let mut t = Store::default();
        t.add("a", "wss://r", 1).unwrap(); t.add("b", "wss://r", 1).unwrap();
        assert_eq!(t.end_all("switched"), 2);
        assert_eq!(t.live(2).count(), 0);
        // limits
        assert!(t.set_limits(Limits { per_payment_sats: 30_000, per_day_sats: 20_000, connection_days: 90, request_ttl_secs: 600 }).is_err());
        assert!(t.set_limits(Limits { per_payment_sats: 0, ..Limits::default() }).is_err());
        t.set_limits(Limits { per_payment_sats: 1_000, per_day_sats: 2_000, connection_days: 30, request_ttl_secs: 120 }).unwrap();
        assert_eq!(t.limits().connection_days, 30);
        assert_eq!(clean_name("  Da\u{0}mus  "), "Damus");
        assert_eq!(clean_name(""), "App");
    }

    /// A client-side request as a Nostr app would build it.
    fn client_request(csk: &SecretKey, service_pk: &str, created_at: u64, body: &str, tags_extra: Vec<Vec<String>>) -> Event {
        let service = pubkey_from_hex(service_pk).unwrap();
        let conv = conversation_key(csk, &service).unwrap();
        let content = nip44_encrypt(&conv, body).unwrap();
        let mut tags = vec![vec!["p".into(), service_pk.to_string()], vec!["encryption".into(), ENCRYPTION.into()]];
        tags.extend(tags_extra);
        sign_event(csk, created_at, KIND_REQUEST, tags, content)
    }

    // a mainnet invoice with an amount (from the LDK test set): 250 msat? — use a fixed known one
    const INVOICE_MAINNET: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";

    #[test]
    fn nip04_aes_cbc_matches_the_nist_vector_and_round_trips() {
        // NIST SP 800-38A F.2.5 CBC-AES256.Encrypt, block 1 (no padding involved for the first block)
        let key: [u8; 32] = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ct = aes256_cbc(&key, &iv, &plain, true).unwrap();
        assert_eq!(hex::encode(&ct[..16]), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assert_eq!(ct.len(), 32, "one full block of PKCS#7 padding follows a 16-byte plaintext");
        assert_eq!(aes256_cbc(&key, &iv, &ct, false).unwrap(), plain);
        // the four-block vector, whole
        let plain4 = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
        let ct4 = aes256_cbc(&key, &iv, &plain4, true).unwrap();
        assert_eq!(hex::encode(&ct4[..64]), "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
        // NIP-04 payload shape and round trip; the raw x is the same from either side
        let secp = Secp256k1::new();
        let a = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let b = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let pa = PublicKey::from_secret_key(&secp, &a);
        let pb = PublicKey::from_secret_key(&secp, &b);
        assert_eq!(ecdh_x(&a, &pb).unwrap(), ecdh_x(&b, &pa).unwrap());
        // the same x feeds NIP-44's conversation key (the vectors gate that path): both derive from one ECDH
        assert_eq!(hkdf_extract(b"nip44-v2", &ecdh_x(&a, &pb).unwrap()), conversation_key(&a, &pb).unwrap());
        let x = ecdh_x(&a, &pb).unwrap();
        let payload = nip04_encrypt_with_iv(&x, &iv, r#"{"method":"pay_invoice","params":{"invoice":"lnbc1…"}}"#).unwrap();
        assert!(payload.ends_with("?iv=AAECAwQFBgcICQoLDA0ODw=="));
        assert!(looks_nip04(&payload) && !looks_nip04("AgAA"));
        assert_eq!(nip04_decrypt(&x, &payload).unwrap(), r#"{"method":"pay_invoice","params":{"invoice":"lnbc1…"}}"#);
        assert!(nip04_decrypt(&x, "AgAA").is_err());
        assert!(nip04_decrypt(&x, "not base64!?iv=AAECAwQFBgcICQoLDA0ODw==").is_err());
    }

    #[test]
    fn open_request_checks_author_target_signature_age_and_method() {
        let (mut s, a, csk) = store_with_conn();
        let c = s.get(1).unwrap().clone();
        let now = 1_700_000_000u64;
        // an unknown method → NOT_IMPLEMENTED (a valid request, answered)
        let ev = client_request(&csk, &a.service_pk, now - 5, r#"{"method":"get_balance","params":{}}"#, vec![]);
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!(o.method, "get_balance");
        assert_eq!(o.refusal.as_ref().unwrap().code, "NOT_IMPLEMENTED");
        assert_eq!(o.age_secs, 5);
        // get_info passes through for the page to answer
        let ev = client_request(&csk, &a.service_pk, now, r#"{"method":"get_info","params":{}}"#, vec![]);
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert!(o.refusal.is_none()); assert_eq!(o.method, "get_info");
        // too old → dropped (an error, not a reply)
        let ev = client_request(&csk, &a.service_pk, now - 601, r#"{"method":"pay_invoice","params":{}}"#, vec![]);
        assert!(open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap_err().to_string().contains("old"));
        // expired by its tag → dropped
        let ev = client_request(&csk, &a.service_pk, now - 10, r#"{"method":"pay_invoice","params":{}}"#, vec![vec!["expiration".into(), (now - 1).to_string()]]);
        assert!(open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).is_err());
        // from another key → not ours
        let other = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let ev = client_request(&other, &a.service_pk, now, r#"{"method":"pay_invoice","params":{}}"#, vec![]);
        assert!(open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).is_err());
        // addressed to another service key → not ours
        let other_pk = hex::encode(Keypair::from_secret_key(&Secp256k1::new(), &other).x_only_public_key().0.serialize());
        let ev = client_request(&csk, &other_pk, now, r#"{"method":"pay_invoice","params":{}}"#, vec![]);
        assert!(open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).is_err());
        // a tampered signature
        let mut ev = client_request(&csk, &a.service_pk, now, r#"{"method":"pay_invoice","params":{}}"#, vec![]);
        ev.sig = "00".repeat(64);
        assert!(open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).is_err());
        // an unknown scheme named in the tag → UNSUPPORTED_ENCRYPTION (names both schemes we speak)
        let service = pubkey_from_hex(&a.service_pk).unwrap();
        let conv = conversation_key(&csk, &service).unwrap();
        let ev = sign_event(&csk, now, KIND_REQUEST, vec![vec!["p".into(), a.service_pk.clone()], vec!["encryption".into(), "nip99".into()]], nip44_encrypt(&conv, "{}").unwrap());
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!(o.refusal.as_ref().unwrap().code, "UNSUPPORTED_ENCRYPTION");
        assert_eq!(o.refusal.as_ref().unwrap().message, "this wallet speaks NIP-44 v2 and NIP-04");
        // v290: no tag + NIP-44 content still opens (the shape decides)
        let ev = sign_event(&csk, now, KIND_REQUEST, vec![vec!["p".into(), a.service_pk.clone()]], nip44_encrypt(&conv, r#"{"method":"get_info"}"#).unwrap());
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!((o.method.as_str(), o.encryption.as_str(), o.refusal.is_none()), ("get_info", "nip44_v2", true));
        // v290: NIP-04 (as Nostur sends it: no tag, AES-CBC under the raw ECDH x, "?iv=") opens and is answered in kind
        let x = ecdh_x(&csk, &service).unwrap();
        let ev = sign_event(&csk, now, KIND_REQUEST, vec![vec!["p".into(), a.service_pk.clone()]], nip04_encrypt(&x, r#"{"method":"get_info"}"#).unwrap());
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!((o.method.as_str(), o.encryption.as_str(), o.refusal.is_none()), ("get_info", "nip04", true));
        let reply = reply_event(&c, &o.request_id, &result_json("get_info", serde_json::json!({"alias": "LiJ"})), now + 1, &o.encryption).unwrap();
        verify_event(&reply).unwrap();
        assert_eq!(tag_value(&reply, "encryption"), None, "a NIP-04 reply carries no encryption tag");
        assert!(looks_nip04(&reply.content));
        let v: serde_json::Value = serde_json::from_str(&nip04_decrypt(&x, &reply.content).unwrap()).unwrap();
        assert_eq!(v["result"]["alias"], "LiJ");
        // a NIP-04 body under the wrong key does not open (the padding check)
        let wrong = ecdh_x(&other, &service).unwrap();
        assert!(nip04_decrypt(&wrong, &reply.content).is_err());
        // no invoice → OTHER
        let ev = client_request(&csk, &a.service_pk, now, r#"{"method":"pay_invoice","params":{}}"#, vec![]);
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!(o.refusal.as_ref().unwrap().code, "OTHER");
        // a real invoice (expired long ago) → OTHER "expired"; its fields are read
        let body = format!(r#"{{"method":"pay_invoice","params":{{"invoice":"{INVOICE_MAINNET}"}}}}"#);
        let ev = client_request(&csk, &a.service_pk, now, &body, vec![]);
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, now).unwrap();
        assert_eq!(o.invoice.as_deref(), Some(INVOICE_MAINNET));
        assert!(o.payee.is_some() && o.payment_hash.is_some());
        assert!(o.refusal.as_ref().unwrap().message.contains("expired"));
        // the same invoice, opened at its own time: 250,000 sats is over the 5,000 limit → QUOTA_EXCEEDED
        let then = 1_496_314_658u64 + 10;
        let ev = client_request(&csk, &a.service_pk, then, &body, vec![]);
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, then).unwrap();
        assert_eq!(o.amount_msat, Some(250_000_000));
        assert_eq!(o.refusal.as_ref().unwrap().code, "QUOTA_EXCEEDED");
        // raise the limits: the request passes, then the daily total catches it
        s.set_limits(Limits { per_payment_sats: 300_000, per_day_sats: 400_000, connection_days: 90, request_ttl_secs: 600 }).unwrap();
        let o = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, then).unwrap();
        assert!(o.refusal.is_none(), "{:?}", o.refusal);
        assert!(o.duplicate.is_none());
        s.record_paid(1, 250_000_000, o.payee.as_deref().unwrap(), o.payment_hash.as_deref().unwrap(), then * 1000);
        // (the invoice expires 60 s after its timestamp — every later open stays inside that)
        let o2 = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, then + 20).unwrap();
        assert_eq!(o2.refusal.as_ref().unwrap().code, "QUOTA_EXCEEDED");
        assert!(o2.refusal.as_ref().unwrap().message.contains("today"));
        // with room again, the duplicate check flags the same payee + amount
        s.set_limits(Limits { per_payment_sats: 300_000, per_day_sats: 900_000, connection_days: 90, request_ttl_secs: 600 }).unwrap();
        let o3 = open_request(&s, &c, &ev, bitcoin::Network::Bitcoin, then + 20).unwrap();
        assert!(o3.refusal.is_none(), "{:?}", o3.refusal);
        let d = o3.duplicate.unwrap();
        assert!(d.same_amount); assert_eq!(d.ago_secs, 20); assert_eq!(d.app, "Nostur");
        assert!(s.get(1).unwrap().last_used_ms == then * 1000);
        // the reply round trip: the app decrypts what the wallet sent
        let reply = reply_event(&c, &o3.request_id, &result_json("pay_invoice", serde_json::json!({"preimage": "ab".repeat(32), "fees_paid": 0})), then + 21, &o3.encryption).unwrap();
        verify_event(&reply).unwrap();
        assert_eq!(reply.kind, KIND_RESPONSE);
        assert_eq!(tag_value(&reply, "p"), Some(a.client_pk.as_str()));
        assert_eq!(tag_value(&reply, "e"), Some(o3.request_id.as_str()));
        let plain = nip44_decrypt(&conv, &reply.content).unwrap();
        let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
        assert_eq!(v["result_type"], "pay_invoice");
        assert_eq!(v["result"]["preimage"], "ab".repeat(32));
        assert!(v["error"].is_null());
        let e = error_json("pay_invoice", "QUOTA_EXCEEDED", "over");
        let ev: serde_json::Value = serde_json::from_str(&e).unwrap();
        assert_eq!(ev["error"]["code"], "QUOTA_EXCEEDED");
        // the info and auth events
        let info = info_event(&c, then).unwrap();
        assert_eq!((info.kind, info.content.as_str()), (KIND_INFO, "pay_invoice"));
        assert_eq!(tag_value(&info, "encryption"), Some("nip44_v2 nip04"));   // v290: both schemes offered
        let auth = auth_event(&c, "wss://lijox-lsp.example/nwc", "abc", then).unwrap();
        assert_eq!(auth.kind, KIND_AUTH);
        assert_eq!(tag_value(&auth, "challenge"), Some("abc"));
        verify_event(&auth).unwrap();
        // the store round-trips through storage
        let st = crate::storage::native_storage::MemoryStorage::new();
        save(&st, &s).unwrap();
        assert_eq!(load(&st).unwrap(), s);
    }
}
