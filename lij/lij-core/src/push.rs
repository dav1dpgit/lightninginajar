//! v280 (S49, DP GO 2026-09-25 00:53 — Push Key, step A: the engine). The pure half.
//!
//! A Push Key sets sats aside with one condition: whoever brings the key before the deadline gets
//! them; if nobody does, they are the sender's again. True to the byte: the condition is a hash,
//! the key is its preimage, the setting-aside is an HTLC held in the sender's own channel, the
//! deadline is that HTLC's timelock (docs/push-key.md §1, §6).
//!
//! This module holds what needs no LDK: the link's fragment (built by the sender, parsed by the
//! recipient — and mirrored in plain JS on the static /claim page, which has no engine), the
//! pair check, and the two records the engine persists (an outbound push the sender made, an
//! inbound push the recipient accepted). Everything here is unit-tested; node.rs wires it to the
//! seed, the channel manager and storage.
//!
//! The fragment (everything after `#` — fragments never reach a server):
//!   v1.<amount_sats>.<expiry_unix>.<lsp_pubkey_prefix16>.<preimage_base64url>
//! ~100 characters. The preimage is the key; the rest lets the claim page speak before any wallet
//! is involved (amount, deadline, which provider holds it — so the recipient's wallet knows whom
//! to ask).

use serde::{Deserialize, Serialize};

/// The fragment's version word. Anything else is refused, never guessed at.
pub const PUSH_LINK_VERSION: &str = "v1";
/// DP ruling (S49, 2026-09-23): the window is 72 hours.
pub const PUSH_WINDOW_SECS_DEFAULT: u64 = 72 * 3600;
/// The most a window may ever be: LDK refuses an outbound HTLC whose expiry is further away than
/// CLTV_FAR_FAR_AWAY (two weeks); the hold invoice's timelock must fit under it with room for the
/// provider's own margin. A week is the honest ceiling (docs/push-key.md §7).
pub const PUSH_WINDOW_SECS_MAX: u64 = 7 * 24 * 3600;
/// How many hex characters of the holding provider's pubkey ride in the link: enough to pick one
/// provider out of a registry, short enough for a text.
pub const PUSH_LSP_PREFIX_LEN: usize = 16;

/// Outbound: a push this wallet made. `status`: prepared (the pair exists, nothing paid yet) →
/// locked (the HTLC is out) → taken | returned | void.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PushOut {
    pub index: u32,
    pub hash: String,
    pub amount_sats: u64,
    pub expiry: u64,
    pub created: u64,
    pub lsp: String,
    pub status: String,
    #[serde(default)]
    pub payment_id: Option<String>,
    #[serde(default)]
    pub updated: u64,
}

/// Inbound: a push this wallet accepted from a link. `status`: accepted (the hash is registered,
/// the key is held, waiting for the provider's delivery) → claimed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PushIn {
    pub hash: String,
    pub amount_sats: u64,
    pub expiry: u64,
    pub accepted: u64,
    pub lsp: String,
    pub status: String,
    #[serde(default)]
    pub updated: u64,
}

/// What a parsed link says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushLink {
    pub amount_sats: u64,
    pub expiry: u64,
    pub lsp_prefix: String,
    pub preimage: [u8; 32],
    pub hash_hex: String,
}

/// SHA-256 of the preimage — the condition the channel enforces.
pub fn hash_of(preimage: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::Hash as _;
    bitcoin::hashes::sha256::Hash::hash(preimage).to_byte_array()
}

/// True when `preimage_hex` opens `hash_hex`. Both hex, either case; anything malformed is false.
pub fn verify_pair(preimage_hex: &str, hash_hex: &str) -> bool {
    let pre = match hex::decode(preimage_hex.trim()) {
        Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return false,
    };
    hex::encode(hash_of(&pre)) == hash_hex.trim().to_ascii_lowercase()
}

/// base64url without padding (RFC 4648 §5) — 32 bytes become 43 characters, text-safe.
pub fn b64url_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(T[((n >> 6) & 63) as usize] as char); }
        if chunk.len() > 2 { out.push(T[(n & 63) as usize] as char); }
    }
    out
}

/// The inverse; padding tolerated, anything else refused.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 { return None; }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i as u32);
        }
        out.push(((n >> 16) & 255) as u8);
        if chunk.len() > 2 { out.push(((n >> 8) & 255) as u8); }
        if chunk.len() > 3 { out.push((n & 255) as u8); }
    }
    Some(out)
}

/// The sender's side of the link: the fragment after `#`.
pub fn build_fragment(amount_sats: u64, expiry: u64, lsp_pubkey_hex: &str, preimage: &[u8; 32]) -> String {
    let prefix: String = lsp_pubkey_hex.trim().to_ascii_lowercase().chars().take(PUSH_LSP_PREFIX_LEN).collect();
    format!("{}.{}.{}.{}.{}", PUSH_LINK_VERSION, amount_sats, expiry, prefix, b64url_encode(preimage))
}

/// The recipient's side: a fragment (a leading `#` tolerated, so is a whole claim URL) → what it
/// says, or a reason it is not a Push Key. The hash is computed here, never trusted from anywhere.
pub fn parse_fragment(input: &str) -> Result<PushLink, String> {
    let s = input.trim();
    let s = match s.find('#') { Some(i) => &s[i + 1..], None => s };
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 5 { return Err("not a Push Key link".into()); }
    if parts[0] != PUSH_LINK_VERSION { return Err(format!("unknown Push Key version {}", parts[0])); }
    let amount_sats: u64 = parts[1].parse().map_err(|_| "the amount is not a number".to_string())?;
    if amount_sats == 0 { return Err("the amount is zero".into()); }
    let expiry: u64 = parts[2].parse().map_err(|_| "the deadline is not a number".to_string())?;
    let lsp_prefix = parts[3].to_ascii_lowercase();
    if lsp_prefix.len() != PUSH_LSP_PREFIX_LEN || !lsp_prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the provider mark is malformed".into());
    }
    let pre = b64url_decode(parts[4]).ok_or_else(|| "the key is malformed".to_string())?;
    if pre.len() != 32 { return Err("the key is the wrong length".into()); }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&pre);
    let hash_hex = hex::encode(hash_of(&preimage));
    Ok(PushLink { amount_sats, expiry, lsp_prefix, preimage, hash_hex })
}

/// The window a lock may ask for, clamped to what the timelock allows; zero means the default.
pub fn clamp_window_secs(requested: u64) -> u64 {
    if requested == 0 { PUSH_WINDOW_SECS_DEFAULT } else { requested.min(PUSH_WINDOW_SECS_MAX).max(600) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre() -> [u8; 32] { let mut p = [0u8; 32]; for (i, b) in p.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(37).wrapping_add(11); } p }

    #[test]
    fn the_pair_is_sha256_and_verify_reads_hex_either_case() {
        let p = pre();
        let h = hex::encode(hash_of(&p));
        assert!(verify_pair(&hex::encode(p), &h));
        assert!(verify_pair(&hex::encode(p).to_uppercase(), &h.to_uppercase()));
        let mut wrong = p; wrong[0] ^= 1;
        assert!(!verify_pair(&hex::encode(wrong), &h), "one bit off is not the key");
        assert!(!verify_pair("zz", &h) && !verify_pair(&hex::encode(&p[..31]), &h), "malformed or short is never a match");
    }

    #[test]
    fn base64url_round_trips_32_bytes_in_43_chars_without_padding() {
        let p = pre();
        let s = b64url_encode(&p);
        assert_eq!(s.len(), 43);
        assert!(!s.contains('=') && !s.contains('+') && !s.contains('/'));
        assert_eq!(b64url_decode(&s).unwrap(), p.to_vec());
        assert_eq!(b64url_decode(&(s.clone() + "=")).unwrap(), p.to_vec(), "padding tolerated");
        assert!(b64url_decode("abc$").is_none(), "a foreign character is refused");
        assert!(b64url_decode("a").is_none(), "an impossible length is refused");
        assert_eq!(b64url_encode(b""), "");
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_decode("Zm9vYg").unwrap(), b"foob".to_vec());
    }

    #[test]
    fn the_fragment_builds_and_parses_back_to_the_same_facts() {
        let p = pre();
        let lsp = "03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c";
        let frag = build_fragment(20_000, 1_790_500_000, lsp, &p);
        assert!(frag.starts_with("v1.20000.1790500000.03201938e37213f3."), "{frag}");
        assert!(frag.len() < 110, "a text-sized link: {}", frag.len());
        let link = parse_fragment(&frag).expect("parses");
        assert_eq!(link.amount_sats, 20_000);
        assert_eq!(link.expiry, 1_790_500_000);
        assert_eq!(link.lsp_prefix, "03201938e37213f3");
        assert_eq!(link.preimage, p);
        assert_eq!(link.hash_hex, hex::encode(hash_of(&p)), "the hash is computed from the key, never carried");
        // a whole URL and a leading '#' are fine; the recipient pastes what they got
        let url = format!("https://lightninginajar.xyz/claim#{frag}");
        assert_eq!(parse_fragment(&url).unwrap(), link);
        assert_eq!(parse_fragment(&format!("  #{frag}\n")).unwrap(), link);
    }

    #[test]
    fn a_link_that_is_not_a_push_key_is_refused_with_a_reason() {
        let p = pre();
        let frag = build_fragment(500, 1_790_500_000, "02ab", &p);
        assert!(parse_fragment(&frag).is_err(), "a short provider mark is refused (build does not pad)");
        assert!(parse_fragment("v2.1.2.03201938e37213f3.AAAA").unwrap_err().contains("version"));
        assert!(parse_fragment("v1.0.2.03201938e37213f3.AAAA").unwrap_err().contains("zero"));
        assert!(parse_fragment("v1.x.2.03201938e37213f3.AAAA").unwrap_err().contains("amount"));
        assert!(parse_fragment("v1.1.2.03201938e37213f3.AAAA").unwrap_err().contains("length"));
        assert!(parse_fragment("lnbc1...").unwrap_err().contains("not a Push Key"));
        assert!(parse_fragment("").is_err());
    }

    #[test]
    fn the_window_is_72h_by_default_and_never_past_a_week() {
        assert_eq!(clamp_window_secs(0), 72 * 3600);
        assert_eq!(clamp_window_secs(3600), 3600);
        assert_eq!(clamp_window_secs(30 * 24 * 3600), 7 * 24 * 3600);
        assert_eq!(clamp_window_secs(10), 600, "a lock shorter than ten minutes cannot be delivered honestly");
    }

    #[test]
    fn the_records_serialize_with_their_optional_fields_defaulted() {
        let r: PushOut = serde_json::from_str(r#"{"index":3,"hash":"ab","amount_sats":5,"expiry":9,"created":1,"lsp":"03","status":"prepared"}"#).unwrap();
        assert_eq!(r.payment_id, None);
        assert_eq!(r.updated, 0);
        let s = serde_json::to_string(&r).unwrap();
        let back: PushOut = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
        let i: PushIn = serde_json::from_str(r#"{"hash":"ab","amount_sats":5,"expiry":9,"accepted":1,"lsp":"03","status":"accepted"}"#).unwrap();
        assert_eq!(i.updated, 0);
    }
}
