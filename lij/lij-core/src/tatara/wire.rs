//! The pool's channel (the NIP's "Channel"; v0.10 §15.5.1): kind-4 nostr events encrypted (NIP-04) to the pool's public
//! key and tagged with it. Every member holds the pool's private key, so anyone in the pool can encrypt a message that
//! decrypts as if another key had sent it — only the event's signature says who sent it. So: the event's id and
//! signature are checked before anything in it is read; an event already seen is ignored; the size is capped before
//! anything is decrypted. Through nwc.rs (the engine's own NIP-01 and NIP-04 code).

use std::collections::HashSet;

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::SecretKey;

use super::caps::MAX_MESSAGE_BYTES;
use crate::nwc::{ecdh_x, nip04_decrypt, nip04_encrypt_with_iv, pubkey_from_hex, sign_event, verify_event, Event};

pub const KIND: u32 = 4;

/// The most an event's content may carry: a capped message, base64 (4/3) after AES-CBC padding, plus the "?iv=" part.
const MAX_CONTENT: usize = (MAX_MESSAGE_BYTES + 16) * 4 / 3 + 64;

/// Seal a pool message: encrypted to the pool's key by `author` (the session key, or a one-time key for a payout),
/// tagged with the pool's key, signed by `author`. `iv` comes from the engine's random source.
pub fn seal(author: &SecretKey, pool_pk_hex: &str, json: &str, created_at: u64, iv: &[u8; 16]) -> Result<Event> {
    ensure!(json.len() <= MAX_MESSAGE_BYTES, "message too large to send");
    let pool_pk = pubkey_from_hex(pool_pk_hex)?;
    let content = nip04_encrypt_with_iv(&ecdh_x(author, &pool_pk)?, iv, json)?;
    Ok(sign_event(author, created_at, KIND, vec![vec!["p".into(), pool_pk_hex.to_string()]], content))
}

/// Open a pool event: the kind, the pool's tag and the size first; then the id and the signature; then, once, the
/// content. Returns the author's x-only key and the message — or None for an event already seen.
pub fn open(pool_sk: &SecretKey, pool_pk_hex: &str, ev: &Event, seen: &mut HashSet<String>) -> Result<Option<([u8; 32], String)>> {
    ensure!(ev.kind == KIND, "not a pool message");
    ensure!(ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "p" && t[1] == pool_pk_hex), "not for this pool");
    ensure!(ev.content.len() <= MAX_CONTENT, "pool event too large");
    ensure!(ev.pubkey.len() == 64 && ev.pubkey.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "bad author key");
    verify_event(ev).context("event id or signature")?;
    if !seen.insert(ev.id.clone()) {
        return Ok(None);
    }
    let author = pubkey_from_hex(&ev.pubkey)?;
    let json = nip04_decrypt(&ecdh_x(pool_sk, &author)?, &ev.content)?;
    ensure!(json.len() <= MAX_MESSAGE_BYTES, "pool message too large");
    let mut from = [0u8; 32];
    from.copy_from_slice(&hex::decode(&ev.pubkey)?);
    Ok(Some((from, json)))
}

/// The x-only key (hex) of a secret key — a session key's or a one-time key's nostr name.
pub fn xonly_hex(sk: &SecretKey) -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    hex::encode(sk.x_only_public_key(&secp).0.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> SecretKey {
        SecretKey::from_slice(&crate::tatara::tagged("lij/test/wire", &[&[i]])).unwrap()
    }

    #[test]
    fn a_sealed_message_opens_once_for_every_holder_of_the_pool_key() {
        let pool = key(1);
        let pool_pk = xonly_hex(&pool);
        let alice = key(2);
        let ev = seal(&alice, &pool_pk, r#"{"version":"2","type":"nonces","nonces":["ab"]}"#, 1_700_000_000, &[7u8; 16]).unwrap();
        let mut seen = HashSet::new();
        let (from, json) = open(&pool, &pool_pk, &ev, &mut seen).unwrap().unwrap();
        assert_eq!(hex::encode(from), xonly_hex(&alice));
        assert!(json.contains("nonces"));
        assert!(open(&pool, &pool_pk, &ev, &mut seen).unwrap().is_none(), "an event already seen is ignored");
    }

    #[test]
    fn a_forged_author_a_changed_message_another_pool_or_kind_is_refused() {
        let pool = key(1);
        let pool_pk = xonly_hex(&pool);
        let (alice, bob) = (key(2), key(3));
        let ev = seal(&alice, &pool_pk, r#"{"version":"2","type":"abort","reason":"x"}"#, 1_700_000_000, &[7u8; 16]).unwrap();
        // a member who holds the pool key encrypts "as Bob" but cannot sign as Bob
        let mut forged = seal(&alice, &pool_pk, r#"{"version":"2","type":"abort","reason":"x"}"#, 1_700_000_000, &[8u8; 16]).unwrap();
        forged.pubkey = xonly_hex(&bob);
        assert!(open(&pool, &pool_pk, &forged, &mut HashSet::new()).is_err(), "the id no longer matches");
        let mut resigned_id = forged.clone();
        resigned_id.id = crate::nwc::event_id(&resigned_id.pubkey, resigned_id.created_at, resigned_id.kind, &resigned_id.tags, &resigned_id.content);
        assert!(open(&pool, &pool_pk, &resigned_id, &mut HashSet::new()).is_err(), "the signature is Alice's, not Bob's");
        let mut changed = ev.clone();
        let first = if changed.content.starts_with('A') { "B" } else { "A" };
        changed.content = format!("{first}{}", &changed.content[1..]);
        assert!(open(&pool, &pool_pk, &changed, &mut HashSet::new()).is_err(), "a changed content breaks the id");
        let other = xonly_hex(&key(9));
        assert!(open(&pool, &other, &ev, &mut HashSet::new()).is_err(), "another pool's tag");
        let mut kind = ev.clone();
        kind.kind = 1;
        assert!(open(&pool, &pool_pk, &kind, &mut HashSet::new()).is_err(), "another kind");
        let mut big = ev.clone();
        big.content = "A".repeat(MAX_CONTENT + 1);
        assert!(open(&pool, &pool_pk, &big, &mut HashSet::new()).is_err(), "too large, refused before anything is checked");
        assert!(seal(&alice, &pool_pk, &"x".repeat(MAX_MESSAGE_BYTES + 1), 1, &[0u8; 16]).is_err());
    }
}
