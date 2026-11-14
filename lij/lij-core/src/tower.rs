//! tower.rs — v372 (S69 Fri 2026-11-13, DP "Go on both … Get them all done in one shot"): LIJOX WATCH DUTY W2 — THE
//! WALLET'S SIDE OF THE TOWER (docs/lijox-watch-standard-r1.md §2; the holder is the adapter's tower.js, 0.128.0).
//!
//! Each time the provider replaces a channel state, the wallet makes the PENALTY TRANSACTION for the state just
//! replaced — the transaction that takes the provider's main balance of that state if the provider ever publishes
//! it — signs it at two fee rates (2× and 5× the next-block rate at that moment; DP's ruling), encrypts each under
//! the id of the old state, and queues the items for the page to upload to the tower of a provider that is NOT the
//! provider of that channel.
//!
//! What is here:
//!   · the bytes (`teos-v1`): hint = the first 16 bytes of the old state's id in its own byte order; blob =
//!     ChaCha20-Poly1305(key = SHA-256(the 32 id bytes), nonce = 0) over the serialized penalty, tag last —
//!     checked below against The Eye of Satoshi's own test value, the same value the adapter's holder is checked on;
//!   · the key a wallet signs in to ONE tower with (BIP-340), made from the 12 words for that tower alone
//!     (key.rs `tower_key`) — never the node key;
//!   · the queue: states seen but not yet replaced (kept encrypted), signed items waiting for upload (one storage key
//!     each), a record per channel (its random 16-byte group, its provider, where its penalty pays, which towers hold
//!     its items);
//!   · the requests the page posts (put, drop, status), signed here, and their acks.
//!
//! Rules this file keeps:
//!   · NOTHING here may fail or delay a channel update: every entry point called from the monitor persister returns
//!     nothing and swallows its own errors;
//!   · off unless the page has turned it on (`lij:tower:on`) — off, nothing is read or written;
//!   · the browser's storage is small: at most OUT_MAX items wait; past that the OLDEST are dropped and counted
//!     (`lost`) — the page says so;
//!   · no key of this file begins with the monitor prefix ("lij:monitor:").
//!
//! Not covered, said plainly: payments in flight in the old state (the HTLC outputs); states replaced before this
//! was turned on; a state whose penalty would leave less than dust at both rates.

use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};
use crate::key::RootKey;
use crate::storage::LijStorage;

pub const KEY_ON: &str = "lij:tower:on";
pub const KEY_SEQ: &str = "lij:tower:seq";
pub const KEY_LOST: &str = "lij:tower:lost";
pub const PREFIX_OUT: &str = "lij:tower:out:";
pub const PREFIX_PEND: &str = "lij:tower:pend:";
pub const PREFIX_CHAN: &str = "lij:tower:chan:";
/// Items waiting for upload, at most. Two items a state at about 450 bytes each as stored: 400 items ≈ 180 KB.
pub const OUT_MAX: usize = 400;
/// States seen and not yet replaced, per channel, at most (in normal running there are one or two).
pub const PEND_MAX: usize = 16;
pub const ITEMS_PER_PUT: usize = 64;
/// v373: towers per channel, at most.
pub const PICKS_MAX: usize = 2;
pub const DOMAIN: &str = "lijox-tower-v1";
/// The witness of a penalty for a main output, as LDK counts it (chain/package.rs WEIGHT_REVOKED_OUTPUT):
/// count, signature length, a 73-byte signature, 1, 1, script length, the 77-byte script.
pub const WEIGHT_REVOKED_OUTPUT: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 77;
/// The two fee rates, as multiples of the next-block rate (DP's ruling of 2026-11-13).
pub const FEE_MULTIPLES: [u64; 2] = [2, 5];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The bytes
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Poly1305 (RFC 8439 §2.5) — the one-time authenticator. 26-bit limbs.
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
    let r0 = le(&key[0..4]) & 0x3ff_ffff;
    let r1 = (le(&key[3..7]) >> 2) & 0x3ff_ff03;
    let r2 = (le(&key[6..10]) >> 4) & 0x3ff_c0ff;
    let r3 = (le(&key[9..13]) >> 6) & 0x3f0_3fff;
    let r4 = (le(&key[12..16]) >> 8) & 0x00f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for chunk in msg.chunks(16) {
        let mut b = [0u8; 17];
        b[..chunk.len()].copy_from_slice(chunk);
        b[chunk.len()] = 1;
        h0 += le(&b[0..4]) & 0x3ff_ffff;
        h1 += (le(&b[3..7]) >> 2) & 0x3ff_ffff;
        h2 += (le(&b[6..10]) >> 4) & 0x3ff_ffff;
        h3 += (le(&b[9..13]) >> 6) & 0x3ff_ffff;
        h4 += (le(&b[12..16]) >> 8) | ((b[16] as u64) << 24);
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let mut c = d0 >> 26; h0 = d0 & 0x3ff_ffff;
        d1 += c; c = d1 >> 26; h1 = d1 & 0x3ff_ffff;
        d2 += c; c = d2 >> 26; h2 = d2 & 0x3ff_ffff;
        d3 += c; c = d3 >> 26; h3 = d3 & 0x3ff_ffff;
        d4 += c; c = d4 >> 26; h4 = d4 & 0x3ff_ffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ff_ffff;
        h1 += c;
    }
    // the last carries, then h mod 2^130 − 5
    let mut c = h1 >> 26; h1 &= 0x3ff_ffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ff_ffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ff_ffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ff_ffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ff_ffff;
    h1 += c;
    let mut g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ff_ffff;
    let mut g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ff_ffff;
    let mut g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ff_ffff;
    let mut g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ff_ffff;
    let g4 = (h4 + c).wrapping_sub(1 << 26);
    // g4's top bit is set when h < p (the subtraction borrowed): keep h; otherwise take g
    let take_g = (g4 >> 63) == 0;
    if take_g { h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4 & 0x3ff_ffff; }
    // h as four 32-bit words, plus the second half of the key
    let w0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;
    let mut out = [0u8; 16];
    let mut f = w0 + le(&key[16..20]); out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f = w1 + le(&key[20..24]) + (f >> 32); out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f = w2 + le(&key[24..28]) + (f >> 32); out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f = w3 + le(&key[28..32]) + (f >> 32); out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    out
}

/// ChaCha20-Poly1305 (RFC 8439 §2.8) with an all-zero nonce and no associated data; the tag is the last 16 bytes.
/// The zero nonce is safe ONLY because each key is used once: the key is the hash of one transaction id.
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce = [0u8; 12];
    let mut otk = [0u8; 32];
    crate::nwc::chacha20_xor(key, &nonce, 0, &mut otk);
    let mut ct = plaintext.to_vec();
    crate::nwc::chacha20_xor(key, &nonce, 1, &mut ct);
    let mut mac = ct.clone();
    while mac.len() % 16 != 0 { mac.push(0); }
    mac.extend_from_slice(&0u64.to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    ct.extend_from_slice(&poly1305(&otk, &mac));
    ct
}

/// The opposite, for the checks (a wallet never needs to open its own items).
pub fn aead_decrypt(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() <= 16 { return None; }
    let (ct, tag) = blob.split_at(blob.len() - 16);
    let nonce = [0u8; 12];
    let mut otk = [0u8; 32];
    crate::nwc::chacha20_xor(key, &nonce, 0, &mut otk);
    let mut mac = ct.to_vec();
    while mac.len() % 16 != 0 { mac.push(0); }
    mac.extend_from_slice(&0u64.to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let want = poly1305(&otk, &mac);
    let mut diff = 0u8;
    for (a, b) in want.iter().zip(tag.iter()) { diff |= a ^ b; }
    if diff != 0 { return None; }
    let mut pt = ct.to_vec();
    crate::nwc::chacha20_xor(key, &nonce, 1, &mut pt);
    Some(pt)
}

/// One item for a tower: (hint hex, blob) for a penalty transaction answering the old state `old`.
pub fn item_for(old: &Txid, penalty: &Transaction) -> (String, Vec<u8>) {
    let id = old.to_byte_array();   // the id's own byte order (the reverse of how an id is written)
    let key = sha256::Hash::hash(&id).to_byte_array();
    (hex::encode(&id[..16]), aead_encrypt(&key, &bitcoin::consensus::encode::serialize(penalty)))
}

/// The penalty transaction for the main output of an old state, unsigned: one input, one output to `dest`, the
/// fee taken from the output at `feerate_per_kw` over the size it will have once signed. None when the fee would
/// leave less than `dest`'s dust floor. The same shape LDK builds (chan_utils.rs build_to_local_justice_tx).
pub fn build_penalty(old: &Txid, vout: u32, value_sat: u64, dest: &ScriptBuf, feerate_per_kw: u64) -> Option<Transaction> {
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint { txid: *old, vout }, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }],
        output: vec![TxOut { script_pubkey: dest.clone(), value: Amount::from_sat(value_sat) }],
    };
    let weight = tx.weight().to_wu() + WEIGHT_REVOKED_OUTPUT;
    let fee = feerate_per_kw.checked_mul(weight)?.checked_add(999)? / 1000;
    let out = value_sat.checked_sub(fee)?;
    if out < dest.minimal_non_dust().to_sat() { return None; }
    tx.output[0].value = Amount::from_sat(out);
    Some(tx)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The queue
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A counterparty state seen and not yet replaced: enough to build its penalty the moment it is.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PendingState {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub number: u64,
}

/// What is kept per channel. `chan` in the storage key is the monitor's own storage name ("<txid>:<vout>").
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChanRecord {
    /// 16 random bytes, hex — the name this channel's items go under at every tower (never the channel's id)
    pub group: String,
    /// the channel's provider (node key, hex) — its items never go to that provider's tower
    pub lsp: String,
    /// where this channel's penalties pay (script hex): one address of the wallet's own per channel
    pub dest: String,
    /// towers (provider node keys, hex) that hold items of this channel
    #[serde(default)]
    pub towers: Vec<String>,
    /// v373 (DP 2026-11-14 "agreed" — two towers per channel, picked at random once and then kept): the towers this
    /// channel's items are to go to, at most PICKS_MAX, set by the page (it knows which providers offer a tower).
    /// Every waiting item goes to EACH of them; it leaves the queue when all of them hold it.
    #[serde(default)]
    pub picks: Vec<String>,
    #[serde(default)]
    pub uploaded: u64,
    #[serde(default)]
    pub last_s: u64,
    #[serde(default)]
    pub closed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutItem {
    c: String,   // chan
    g: String,   // group
    l: String,   // the channel's provider
    h: String,   // hint
    b: String,   // blob, base64
    #[serde(default)]
    a: Vec<String>,   // v373: the towers that hold this item already
}

fn get_json<T: for<'a> Deserialize<'a>>(storage: &dyn LijStorage, key: &str) -> Option<T> {
    storage.get(key).ok().flatten().and_then(|v| serde_json::from_slice(&v).ok())
}
fn set_json<T: Serialize>(storage: &dyn LijStorage, key: &str, v: &T) -> LijResult<()> {
    storage.set(key, &serde_json::to_vec(v).map_err(|e| LijError::Node(format!("tower: encode {e}")))?)
}
fn get_u64(storage: &dyn LijStorage, key: &str) -> u64 {
    storage.get(key).ok().flatten().and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok()).map(u64::from_be_bytes).unwrap_or(0)
}

/// Whether the page has turned the tower uploads on.
pub fn is_on(storage: &dyn LijStorage) -> bool {
    matches!(storage.get(KEY_ON), Ok(Some(v)) if v == b"1")
}
/// Turn it on or off. Off also empties what waits (states not yet replaced and items not yet uploaded): they
/// would be stale by the time it is turned on again. The channel records stay — towers still hold their items.
pub fn set_on(storage: &dyn LijStorage, on: bool) -> LijResult<()> {
    if on { return storage.set(KEY_ON, b"1"); }
    storage.delete(KEY_ON)?;
    for k in storage.list_with_prefix(PREFIX_OUT)? { let _ = storage.delete(&k); }
    for k in storage.list_with_prefix(PREFIX_PEND)? { let _ = storage.delete(&k); }
    Ok(())
}

/// The part of the queue the monitor persister feeds. Everything it does is best-effort.
pub struct TowerQueue {
    storage: Arc<dyn LijStorage>,
    enc_key: [u8; 32],
    /// the next-block fee rate now, in sat per 1000 weight units
    next_block_kw: Arc<dyn Fn() -> u32 + Send + Sync>,
    /// a fresh address of the wallet's own (asked for ONCE per channel)
    dest: Arc<dyn Fn() -> Option<ScriptBuf> + Send + Sync>,
    /// 16 random bytes
    rand16: Arc<dyn Fn() -> [u8; 16] + Send + Sync>,
}

impl TowerQueue {
    pub fn new(
        storage: Arc<dyn LijStorage>, enc_key: [u8; 32],
        next_block_kw: Arc<dyn Fn() -> u32 + Send + Sync>,
        dest: Arc<dyn Fn() -> Option<ScriptBuf> + Send + Sync>,
        rand16: Arc<dyn Fn() -> [u8; 16] + Send + Sync>,
    ) -> Self {
        Self { storage, enc_key, next_block_kw, dest, rand16 }
    }

    pub fn on(&self) -> bool { is_on(&*self.storage) }

    fn chan_record(&self, chan: &str, lsp: &str) -> Option<ChanRecord> {
        let key = format!("{PREFIX_CHAN}{chan}");
        if let Some(r) = get_json::<ChanRecord>(&*self.storage, &key) { return Some(r); }
        let dest = (self.dest)()?;
        let r = ChanRecord { group: hex::encode((self.rand16)()), lsp: lsp.to_string(), dest: hex::encode(dest.as_bytes()), ..Default::default() };
        set_json(&*self.storage, &key, &r).ok()?;
        Some(r)
    }
    fn pending(&self, chan: &str) -> Vec<PendingState> {
        let Ok(Some(ct)) = self.storage.get(&format!("{PREFIX_PEND}{chan}")) else { return Vec::new() };
        crate::persist::decrypt(&self.enc_key, &ct).ok().and_then(|pt| serde_json::from_slice(&pt).ok()).unwrap_or_default()
    }
    fn set_pending(&self, chan: &str, list: &[PendingState]) {
        let key = format!("{PREFIX_PEND}{chan}");
        if list.is_empty() { let _ = self.storage.delete(&key); return; }
        let Ok(pt) = serde_json::to_vec(list) else { return };
        if let Ok(ct) = crate::persist::encrypt(&self.enc_key, &pt) { let _ = self.storage.set(&key, &ct); }
    }

    /// A counterparty state came into being (not yet replaced). Remembered until it is.
    pub fn note_state(&self, chan: &str, lsp: &str, st: PendingState) {
        if !self.on() { return; }
        if self.chan_record(chan, lsp).is_none() { return; }
        let mut list = self.pending(chan);
        if list.iter().any(|p| p.txid == st.txid) { return; }
        list.push(st);
        while list.len() > PEND_MAX { list.remove(0); }
        self.set_pending(chan, &list);
    }

    /// Try the oldest remembered states: `sign(unsigned penalty, value, number)` succeeds only once the state has
    /// been replaced (the monitor holds its secret). Each replaced state becomes items at the two fee rates.
    /// Returns how many items were queued.
    pub fn try_sign(&self, chan: &str, sign: &dyn Fn(Transaction, u64, u64) -> Result<Transaction, ()>) -> usize {
        if !self.on() { return 0; }
        let mut list = self.pending(chan);
        if list.is_empty() { return 0; }
        let Some(rec) = get_json::<ChanRecord>(&*self.storage, &format!("{PREFIX_CHAN}{chan}")) else { return 0 };
        let Ok(dest_bytes) = hex::decode(&rec.dest) else { return 0 };
        let dest = ScriptBuf::from_bytes(dest_bytes);
        let base = ((self.next_block_kw)() as u64).max(253);
        let mut queued = 0usize;
        let mut done = 0usize;
        'states: for st in list.iter() {
            let Ok(old) = st.txid.parse::<Txid>() else { done += 1; continue };
            let mut any_built = false;
            for m in FEE_MULTIPLES {
                let Some(unsigned) = build_penalty(&old, st.vout, st.value, &dest, base.saturating_mul(m)) else { continue };
                any_built = true;
                match sign(unsigned, st.value, st.number) {
                    Ok(signed) => {
                        let (hint, blob) = item_for(&old, &signed);
                        if self.push_out(&OutItem { c: chan.to_string(), g: rec.group.clone(), l: rec.lsp.clone(), h: hint, b: crate::nwc::base64_encode(&blob), a: Vec::new() }) { queued += 1; }
                    }
                    Err(()) => break 'states,   // not replaced yet: this one and every later one waits
                }
            }
            let _ = any_built;   // a state whose penalty leaves less than dust at both rates is let go
            done += 1;
        }
        if done > 0 { list.drain(..done); self.set_pending(chan, &list); }
        queued
    }

    fn push_out(&self, item: &OutItem) -> bool {
        let s = &*self.storage;
        let seq = get_u64(s, KEY_SEQ) + 1;
        if s.set(KEY_SEQ, &seq.to_be_bytes()).is_err() { return false; }
        if set_json(s, &format!("{PREFIX_OUT}{seq:012}"), item).is_err() { return false; }
        if let Ok(mut keys) = s.list_with_prefix(PREFIX_OUT) {
            if keys.len() > OUT_MAX {
                keys.sort();
                let over = keys.len() - OUT_MAX;
                for k in keys.iter().take(over) { let _ = s.delete(k); }
                let _ = s.set(KEY_LOST, &(get_u64(s, KEY_LOST) + over as u64).to_be_bytes());
            }
        }
        true
    }

    /// The channel is closed and put away: what waits for it is dropped; its towers are told on the next visit.
    pub fn on_archive(&self, chan: &str) {
        let s = &*self.storage;
        let key = format!("{PREFIX_CHAN}{chan}");
        let Some(mut rec) = get_json::<ChanRecord>(s, &key) else { return };
        let _ = s.delete(&format!("{PREFIX_PEND}{chan}"));
        if let Ok(keys) = s.list_with_prefix(PREFIX_OUT) {
            for k in keys { if get_json::<OutItem>(s, &k).map(|i| i.c == chan).unwrap_or(false) { let _ = s.delete(&k); } }
        }
        if rec.towers.is_empty() { let _ = s.delete(&key); return; }
        rec.closed = true;
        let _ = set_json(s, &key, &rec);
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The requests (the page posts them; a tower is named by its provider's node key)
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn tower_keypair(root: &RootKey, tower_id_hex: &str) -> LijResult<(Keypair, String)> {
    let id = hex::decode(tower_id_hex).map_err(|_| LijError::Node("tower: the tower's id is not hex".into()))?;
    if id.len() != 33 { return Err(LijError::Node("tower: the tower's id must be a node key (33 bytes)".into())); }
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&root.tower_key(&id)).map_err(|e| LijError::Key(format!("tower key: {e}")))?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let x = hex::encode(kp.x_only_public_key().0.serialize());
    Ok((kp, x))
}
fn sign_text(kp: &Keypair, text: &str) -> String {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array());
    hex::encode(secp.sign_schnorr_no_aux_rand(&msg, kp).serialize())
}
/// The key this wallet shows to that tower (x-only, hex).
pub fn tower_pubkey(root: &RootKey, tower_id_hex: &str) -> LijResult<String> {
    Ok(tower_keypair(root, tower_id_hex)?.1)
}

/// The next put for that tower: up to 64 waiting items of ONE channel whose provider is not that tower.
/// → None when nothing waits for it; else {"body":{…the request…},"ids":[…storage keys…],"chan":"…"}.
pub fn put_request(storage: &dyn LijStorage, root: &RootKey, tower_id_hex: &str, now_s: u64) -> LijResult<Option<String>> {
    let (kp, key) = tower_keypair(root, tower_id_hex)?;
    let mut keys = storage.list_with_prefix(PREFIX_OUT)?;
    keys.sort();
    let mut chan: Option<(String, String)> = None;
    let mut ids: Vec<String> = Vec::new();
    let mut items: Vec<(String, Vec<u8>, String)> = Vec::new();
    let t = tower_id_hex.to_ascii_lowercase();
    let mut picked: std::collections::HashMap<String, bool> = std::collections::HashMap::new();   // chan → is this tower one of its picks
    for k in keys {
        let Some(it) = get_json::<OutItem>(storage, &k) else { continue };
        if it.l.eq_ignore_ascii_case(tower_id_hex) { continue; }   // never to the channel's own provider
        if it.a.contains(&t) { continue; }                          // v373: this tower holds it already
        let is_pick = *picked.entry(it.c.clone()).or_insert_with(|| {
            get_json::<ChanRecord>(storage, &format!("{PREFIX_CHAN}{}", it.c)).map(|r| r.picks.is_empty() || r.picks.contains(&t)).unwrap_or(false)
        });
        if !is_pick { continue; }                                   // v373: only to the towers picked for its channel (a channel with no picks yet: any tower, as v372)
        match &chan { None => chan = Some((it.c.clone(), it.g.clone())), Some((c, _)) if *c != it.c => continue, _ => {} }
        let Some(blob) = crate::nwc::base64_decode(&it.b) else { continue };
        ids.push(k); items.push((it.h, blob, it.b));
        if items.len() >= ITEMS_PER_PUT { break; }
    }
    let Some((chan, group)) = chan else { return Ok(None) };
    use bitcoin::hashes::HashEngine;
    let mut eng = sha256::Hash::engine();
    for (h, blob, _) in &items {
        eng.input(&hex::decode(h).unwrap_or_default());
        eng.input(&sha256::Hash::hash(blob).to_byte_array());
    }
    let items_sha = hex::encode(sha256::Hash::from_engine(eng).to_byte_array());
    let sig = sign_text(&kp, &format!("{DOMAIN}|put|{key}|{group}|{now_s}|{items_sha}"));
    let body = serde_json::json!({ "key": key, "group": group, "ts": now_s, "signature": sig,
        "items": items.iter().map(|(h, _, b64)| serde_json::json!({ "hint": h, "blob": b64 })).collect::<Vec<_>>() });
    Ok(Some(serde_json::json!({ "body": body, "ids": ids, "chan": chan }).to_string()))
}

/// The tower answered ok to a put: the items leave the queue; the channel's record names the tower.
pub fn put_ack(storage: &dyn LijStorage, ids: &[String], chan: &str, tower_id_hex: &str, now_s: u64) -> LijResult<()> {
    let mut n = 0u64;
    let key = format!("{PREFIX_CHAN}{chan}");
    let t = tower_id_hex.to_ascii_lowercase();
    let picks = get_json::<ChanRecord>(storage, &key).map(|r| r.picks).unwrap_or_default();
    for k in ids {
        if !k.starts_with(PREFIX_OUT) { continue; }
        let Some(mut it) = get_json::<OutItem>(storage, k) else { continue };
        if it.a.contains(&t) { continue; }   // acked twice: counted once
        it.a.push(t.clone()); n += 1;
        // v373: the item leaves the queue when every tower picked for its channel holds it
        if picks.iter().all(|p| it.a.contains(p)) { storage.delete(k)?; } else { set_json(storage, k, &it)?; }
    }
    if let Some(mut rec) = get_json::<ChanRecord>(storage, &key) {
        if !rec.towers.contains(&t) { rec.towers.push(t); }
        rec.uploaded += n; rec.last_s = now_s;
        set_json(storage, &key, &rec)?;
    }
    Ok(())
}

/// v373: set the towers a channel's items go to (at most PICKS_MAX; never the channel's own provider; each a node
/// key). Items every pick already holds leave the queue. → the picks as kept.
pub fn set_picks(storage: &dyn LijStorage, chan: &str, picks: &[String]) -> LijResult<Vec<String>> {
    let key = format!("{PREFIX_CHAN}{chan}");
    let Some(mut rec) = get_json::<ChanRecord>(storage, &key) else { return Err(LijError::Node("tower: no such channel record".into())) };
    let mut out: Vec<String> = Vec::new();
    for p in picks {
        let p = p.to_ascii_lowercase();
        if hex::decode(&p).map(|b| b.len() != 33).unwrap_or(true) { return Err(LijError::Node("tower: a pick must be a node key (33 bytes, hex)".into())); }
        if p.eq_ignore_ascii_case(&rec.lsp) { return Err(LijError::Node("tower: a channel's own provider cannot watch it".into())); }
        if !out.contains(&p) { out.push(p); }
    }
    if out.len() > PICKS_MAX { return Err(LijError::Node(format!("tower: at most {PICKS_MAX} towers a channel"))); }
    rec.picks = out.clone();
    set_json(storage, &key, &rec)?;
    if !out.is_empty() {
        for k in storage.list_with_prefix(PREFIX_OUT)? {
            if let Some(it) = get_json::<OutItem>(storage, &k) { if it.c == chan && out.iter().all(|p| it.a.contains(p)) { storage.delete(&k)?; } }
        }
    }
    Ok(out)
}

/// The next drop for that tower: a closed channel whose items it holds. → None | {"body":{…},"chan":"…"}.
pub fn drop_request(storage: &dyn LijStorage, root: &RootKey, tower_id_hex: &str, now_s: u64) -> LijResult<Option<String>> {
    let (kp, key) = tower_keypair(root, tower_id_hex)?;
    let t = tower_id_hex.to_ascii_lowercase();
    let mut keys = storage.list_with_prefix(PREFIX_CHAN)?;
    keys.sort();
    for k in keys {
        let Some(rec) = get_json::<ChanRecord>(storage, &k) else { continue };
        if !rec.closed || !rec.towers.contains(&t) { continue; }
        let sig = sign_text(&kp, &format!("{DOMAIN}|drop|{key}|{}|{now_s}", rec.group));
        let body = serde_json::json!({ "key": key, "group": rec.group, "ts": now_s, "signature": sig });
        return Ok(Some(serde_json::json!({ "body": body, "chan": &k[PREFIX_CHAN.len()..] }).to_string()));
    }
    Ok(None)
}

/// The tower answered ok to a drop: it leaves the channel's record; the record goes with its last tower.
pub fn drop_ack(storage: &dyn LijStorage, chan: &str, tower_id_hex: &str) -> LijResult<()> {
    let key = format!("{PREFIX_CHAN}{chan}");
    let Some(mut rec) = get_json::<ChanRecord>(storage, &key) else { return Ok(()) };
    let t = tower_id_hex.to_ascii_lowercase();
    rec.towers.retain(|x| *x != t);
    if rec.towers.is_empty() && rec.closed { storage.delete(&key) } else { set_json(storage, &key, &rec) }
}

/// A status request for that tower (what it holds for this wallet's key there).
pub fn status_request(root: &RootKey, tower_id_hex: &str, now_s: u64) -> LijResult<String> {
    let (kp, key) = tower_keypair(root, tower_id_hex)?;
    let sig = sign_text(&kp, &format!("{DOMAIN}|status|{key}||{now_s}"));
    Ok(serde_json::json!({ "key": key, "ts": now_s, "signature": sig }).to_string())
}

/// What the Safety screen reads: on or off, what waits, what was let go, and each channel's towers.
pub fn summary(storage: &dyn LijStorage) -> LijResult<String> {
    let mut waiting: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut queued = 0u64;
    for k in storage.list_with_prefix(PREFIX_OUT)? {
        if let Some(it) = get_json::<OutItem>(storage, &k) { *waiting.entry(it.c).or_insert(0) += 1; queued += 1; }
    }
    let mut chans = Vec::new();
    let mut keys = storage.list_with_prefix(PREFIX_CHAN)?;
    keys.sort();
    for k in keys {
        let Some(rec) = get_json::<ChanRecord>(storage, &k) else { continue };
        let chan = k[PREFIX_CHAN.len()..].to_string();
        chans.push(serde_json::json!({ "chan": chan, "lsp": rec.lsp, "towers": rec.towers, "picks": rec.picks, "uploaded": rec.uploaded,
            "last_s": rec.last_s, "closed": rec.closed, "waiting": waiting.get(&chan).copied().unwrap_or(0) }));
    }
    Ok(serde_json::json!({ "on": is_on(storage), "queued": queued, "lost": get_u64(storage, KEY_LOST), "out_max": OUT_MAX, "picks_max": PICKS_MAX, "channels": chans }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;
    use bitcoin::secp256k1::{schnorr, XOnlyPublicKey};
    use std::sync::atomic::{AtomicU32, Ordering};

    // The Eye of Satoshi's own test value (rust-teos be344ec, teos-common/src/cryptography.rs) — the adapter's
    // tower.test.js checks its holder against the same three strings.
    const TEOS_TX: &str = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff54038e830a1b4d696e656420627920416e74506f6f6c373432c2005b005e7a0ae3fabe6d6d7841cd582ead8ea5dd8e3de1173cae6fcd2a53c7362ebb7fb6f815604fe07cbe0200000000000000ac0e060005f90000ffffffff04d9476026000000001976a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac0000000000000000266a24aa21a9ed7248c6efddd8d99bfddd7f499f0b915bffa8253003cc934df1ff14a81301e2340000000000000000266a24b9e11b6d7054937e13f39529d6ad7e685e9dd4efa426f247d5f5a5bed58cdddb2d0fa60100000000000000002b6a2952534b424c4f434b3a054a68aa5368740e8b3e3c67bce45619c2cfd07d4d4f0936a5612d2d0034fa0a0120000000000000000000000000000000000000000000000000000000000000000000000000";
    const TEOS_TXID: &str = "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4";
    const TEOS_ENC: &str = "f64d730654738fdbcd9e65068be17bc1abb44e74f8977985cce48e77209cf97292c862e4eb7190aedc6c53ceddda6871a3988d1d9608e2d0dd7a1f59769e410618a7029001479ac3b9d699b11a08b0ccb04e56bfee88461d9cd3207623a4a543996dd3805323c93cd62069636305aaf159e9cca1063ad1f097c16fb3c2ebbcf09be96512c5d7c195c684569cbe8b7979870b04cada9806b7610569c66021afcc63f46dd4af75716950c4de094334cdf7d9e532820afe29d2621dd79920c7e0ecc10853517dd84ca9d699f712c229e86954c227cba1d0fc87c8d48ac05e2de8a6bc980afdfafcd7064e411c8d76065c06cc7f233e869eaff5bd8ccb5d8f0090d91a8f017355cc115863356ecf06cdda9b309096ea766d033dbd4f70a789a5b03138cfc7e2900a79bb465abf07a7ac45c41b4b30c008d4b299aad9d001cf45acd07e47cdd63c3b13d4b0788b041735225b5db1a43a2142311f695478168e31deb260702976fd70d0724ded84a7c3f89b";

    #[test]
    fn poly1305_rfc8439_vector() {
        // RFC 8439 §2.5.2
        let key: [u8; 32] = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap().try_into().unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex::encode(tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn the_eye_of_satoshis_bytes() {
        let old: Txid = TEOS_TXID.parse().unwrap();
        let id = old.to_byte_array();
        let key = sha256::Hash::hash(&id).to_byte_array();
        let tx = hex::decode(TEOS_TX).unwrap();
        assert_eq!(hex::encode(aead_encrypt(&key, &tx)), TEOS_ENC, "our bytes are its bytes");
        assert_eq!(aead_decrypt(&key, &hex::decode(TEOS_ENC).unwrap()).unwrap(), tx);
        let mut bad = hex::decode(TEOS_ENC).unwrap(); bad[5] ^= 1;
        assert!(aead_decrypt(&key, &bad).is_none(), "a changed byte does not open");
        // the hint: the first 16 bytes of the id in its own order = the LAST 16 bytes of the id as written, reversed
        let mut written = hex::decode(TEOS_TXID).unwrap(); written.reverse();
        assert_eq!(hex::encode(&id[..16]), hex::encode(&written[..16]));
    }

    fn root(words: &str) -> RootKey {
        RootKey::from_mnemonic(&bip39::Mnemonic::parse(words).unwrap(), bitcoin::Network::Bitcoin).unwrap()
    }
    const W1: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const W2: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const TOWER_A: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOWER_B: &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_key_per_tower_from_the_words() {
        let r = root(W1);
        let a = tower_pubkey(&r, TOWER_A).unwrap();
        assert_eq!(a, tower_pubkey(&r, TOWER_A).unwrap(), "the same words and tower give the same key");
        assert_ne!(a, tower_pubkey(&r, TOWER_B).unwrap(), "another tower, another key");
        assert_ne!(a, tower_pubkey(&root(W2), TOWER_A).unwrap(), "other words, another key");
        assert_eq!(a.len(), 64);
        assert!(tower_pubkey(&r, "zz").is_err());
        assert!(tower_pubkey(&r, &a).is_err(), "a 32-byte id is not a node key");
    }

    fn queue(s: Arc<MemoryStorage>, rate: u32, dest_calls: Arc<AtomicU32>) -> TowerQueue {
        let n = Arc::new(AtomicU32::new(0));
        TowerQueue::new(
            s, [7u8; 32],
            Arc::new(move || rate),
            Arc::new(move || { dest_calls.fetch_add(1, Ordering::Relaxed); Some(ScriptBuf::from_bytes(hex::decode("0014".to_string() + &"44".repeat(20)).unwrap())) }),
            Arc::new(move || { let mut g = [0u8; 16]; g[0] = n.fetch_add(1, Ordering::Relaxed) as u8 + 1; g }),
        )
    }
    fn st(seed: u8, value: u64, number: u64) -> PendingState {
        PendingState { txid: hex::encode([seed; 32]), vout: 1, value, number }
    }
    // a stand-in for the monitor's signer: states numbered at or above `revoked_from` are replaced
    fn signer(revoked_from: u64) -> impl Fn(Transaction, u64, u64) -> Result<Transaction, ()> {
        move |mut tx, _value, number| {
            if number < revoked_from { return Err(()); }
            tx.input[0].witness.push(vec![0x30u8; 72]); tx.input[0].witness.push([1u8]); tx.input[0].witness.push(vec![2u8; 77]);
            Ok(tx)
        }
    }
    const CHAN: &str = "aa11:0";
    const LSP: &str = TOWER_A;   // the channel's provider is A

    #[test]
    fn off_means_nothing_is_kept() {
        let s = Arc::new(MemoryStorage::new());
        let q = queue(s.clone(), 1000, Arc::new(AtomicU32::new(0)));
        q.note_state(CHAN, LSP, st(1, 70_000, 100));
        assert_eq!(q.try_sign(CHAN, &signer(0)), 0);
        assert!(s.list_with_prefix("lij:tower:").unwrap().is_empty());
    }

    #[test]
    fn a_replaced_state_becomes_two_items_and_only_then() {
        let s = Arc::new(MemoryStorage::new());
        let dest_calls = Arc::new(AtomicU32::new(0));
        let q = queue(s.clone(), 1000, dest_calls.clone());
        set_on(&*s, true).unwrap();
        q.note_state(CHAN, LSP, st(1, 70_000, 100));
        q.note_state(CHAN, LSP, st(1, 70_000, 100));   // told twice: kept once
        assert_eq!(q.pending(CHAN).len(), 1);
        assert_eq!(q.try_sign(CHAN, &signer(101)), 0, "not replaced yet: nothing is made");
        assert_eq!(q.pending(CHAN).len(), 1);
        q.note_state(CHAN, LSP, st(2, 60_000, 99));
        assert_eq!(q.try_sign(CHAN, &signer(100)), 2, "state 100 is replaced: two items; state 99 waits");
        assert_eq!(q.pending(CHAN), vec![st(2, 60_000, 99)]);
        assert_eq!(dest_calls.load(Ordering::Relaxed), 1, "one address per channel, asked for once");
        // the stored pending list is not readable as it lies
        let raw = s.get(&format!("{PREFIX_PEND}{CHAN}")).unwrap().unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains(&hex::encode([2u8; 32])));
        // the items: under the old state's hint; each opens with the old state's id into a penalty that spends it,
        // at 2× and 5× the rate
        let old: Txid = hex::encode([1u8; 32]).parse().unwrap();
        let key = sha256::Hash::hash(&old.to_byte_array()).to_byte_array();
        let mut keys = s.list_with_prefix(PREFIX_OUT).unwrap(); keys.sort();
        let mut fees = Vec::new();
        for k in &keys {
            let it: OutItem = get_json(&*s, k).unwrap();
            assert_eq!(it.h, hex::encode(&old.to_byte_array()[..16]));
            assert_eq!(it.l, LSP);
            let tx: Transaction = bitcoin::consensus::encode::deserialize(&aead_decrypt(&key, &crate::nwc::base64_decode(&it.b).unwrap()).unwrap()).unwrap();
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.input[0].previous_output, OutPoint { txid: old, vout: 1 });
            assert_eq!(tx.input[0].witness.len(), 3);
            fees.push(70_000 - tx.output[0].value.to_sat());
        }
        let w = build_penalty(&old, 1, 70_000, &ScriptBuf::from_bytes(hex::decode("0014".to_string() + &"44".repeat(20)).unwrap()), 1).unwrap().weight().to_wu() + WEIGHT_REVOKED_OUTPUT;
        assert_eq!(fees, vec![(2000 * w + 999) / 1000, (5000 * w + 999) / 1000]);
    }

    #[test]
    fn dust_and_the_floor() {
        let old: Txid = hex::encode([9u8; 32]).parse().unwrap();
        let dest = ScriptBuf::from_bytes(hex::decode("0014".to_string() + &"44".repeat(20)).unwrap());
        assert!(build_penalty(&old, 0, 400, &dest, 253).is_none(), "less than dust left: no penalty");
        assert!(build_penalty(&old, 0, 100, &dest, 5000).is_none(), "a fee above the value: no penalty");
        assert!(build_penalty(&old, 0, 100_000, &dest, 253).is_some());
        // a state too small at 5× still gets its 2× item; one too small at both is let go
        let s = Arc::new(MemoryStorage::new());
        let q = queue(s.clone(), 1000, Arc::new(AtomicU32::new(0)));
        set_on(&*s, true).unwrap();
        q.note_state(CHAN, LSP, st(1, 1_500, 100));
        q.note_state(CHAN, LSP, st(2, 300, 99));
        assert_eq!(q.try_sign(CHAN, &signer(0)), 1);
        assert!(q.pending(CHAN).is_empty());
    }

    #[test]
    fn the_put_the_ack_the_drop() {
        let s = Arc::new(MemoryStorage::new());
        let q = queue(s.clone(), 1000, Arc::new(AtomicU32::new(0)));
        set_on(&*s, true).unwrap();
        let r = root(W1);
        q.note_state(CHAN, LSP, st(1, 70_000, 100));
        q.note_state("bb22:1", TOWER_B, st(3, 50_000, 500));
        assert_eq!(q.try_sign(CHAN, &signer(0)), 2);
        assert_eq!(q.try_sign("bb22:1", &signer(0)), 2);
        // v373: a channel with no picks yet behaves as v372 did (any tower but its own provider's)
        assert!(put_request(&*s, &r, TOWER_B, 1).unwrap().is_some());
        assert!(set_picks(&*s, CHAN, &[TOWER_A.to_string()]).is_err(), "a channel's own provider cannot be its tower");
        assert!(set_picks(&*s, CHAN, &["zz".to_string()]).is_err());
        assert_eq!(set_picks(&*s, CHAN, &[TOWER_B.to_string(), TOWER_B.to_string()]).unwrap(), vec![TOWER_B.to_string()]);
        set_picks(&*s, "bb22:1", &[TOWER_A.to_string()]).unwrap();
        // the channel's own provider (A) is never sent that channel's items — it gets the OTHER channel's
        let to_a: serde_json::Value = serde_json::from_str(&put_request(&*s, &r, TOWER_A, 1_794_550_000).unwrap().unwrap()).unwrap();
        assert_eq!(to_a["chan"], "bb22:1");
        let to_b: serde_json::Value = serde_json::from_str(&put_request(&*s, &r, TOWER_B, 1_794_550_000).unwrap().unwrap()).unwrap();
        assert_eq!(to_b["chan"], CHAN);
        let body = &to_b["body"];
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
        assert_eq!(body["key"], tower_pubkey(&r, TOWER_B).unwrap());
        assert_eq!(body["group"].as_str().unwrap().len(), 32);
        assert_ne!(body["group"], to_a["body"]["group"], "a group per channel");
        // the signature is BIP-340 by the tower key over SHA-256 of the adapter's text
        use bitcoin::hashes::HashEngine;
        let mut eng = sha256::Hash::engine();
        for it in body["items"].as_array().unwrap() {
            eng.input(&hex::decode(it["hint"].as_str().unwrap()).unwrap());
            eng.input(&sha256::Hash::hash(&crate::nwc::base64_decode(it["blob"].as_str().unwrap()).unwrap()).to_byte_array());
        }
        let text = format!("lijox-tower-v1|put|{}|{}|1794550000|{}", body["key"].as_str().unwrap(), body["group"].as_str().unwrap(), hex::encode(sha256::Hash::from_engine(eng).to_byte_array()));
        let secp = Secp256k1::new();
        let sig = schnorr::Signature::from_slice(&hex::decode(body["signature"].as_str().unwrap()).unwrap()).unwrap();
        let x = XOnlyPublicKey::from_slice(&hex::decode(body["key"].as_str().unwrap()).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array()), &x).unwrap();
        // written out for the adapter's own check (tools/tower-cross-check.mjs)
        if let Ok(p) = std::env::var("LIJ_TOWER_VECTOR_OUT") { std::fs::write(p, body.to_string()).unwrap(); }

        // the ack: the items leave; the record names the tower
        let ids: Vec<String> = to_b["ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        put_ack(&*s, &ids, CHAN, TOWER_B, 1_794_550_005).unwrap();
        put_ack(&*s, &ids, CHAN, TOWER_B, 1_794_550_006).unwrap();   // acked twice: counted once
        let sum: serde_json::Value = serde_json::from_str(&summary(&*s).unwrap()).unwrap();
        assert_eq!(sum["queued"], 2);
        let c = sum["channels"].as_array().unwrap().iter().find(|c| c["chan"] == CHAN).unwrap().clone();
        assert_eq!(c["towers"], serde_json::json!([TOWER_B]));
        assert_eq!(c["uploaded"], 2);
        assert_eq!(c["waiting"], 0);
        assert!(put_request(&*s, &r, TOWER_B, 1).unwrap().is_none(), "nothing more for B (the other channel is B's own)");

        // no drop while the channel is open; after the close, one for the tower that holds its items
        assert!(drop_request(&*s, &r, TOWER_B, 1).unwrap().is_none());
        q.note_state(CHAN, LSP, st(4, 65_000, 98));
        q.on_archive(CHAN);
        assert!(s.get(&format!("{PREFIX_PEND}{CHAN}")).unwrap().is_none());
        let d: serde_json::Value = serde_json::from_str(&drop_request(&*s, &r, TOWER_B, 1_794_550_100).unwrap().unwrap()).unwrap();
        assert_eq!(d["chan"], CHAN);
        assert_eq!(d["body"]["group"], body["group"]);
        let text = format!("lijox-tower-v1|drop|{}|{}|1794550100", d["body"]["key"].as_str().unwrap(), d["body"]["group"].as_str().unwrap());
        let sig = schnorr::Signature::from_slice(&hex::decode(d["body"]["signature"].as_str().unwrap()).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array()), &x).unwrap();
        assert!(drop_request(&*s, &r, TOWER_A, 1).unwrap().is_none(), "A never held it");
        drop_ack(&*s, CHAN, TOWER_B).unwrap();
        assert!(s.get(&format!("{PREFIX_CHAN}{CHAN}")).unwrap().is_none(), "the record goes with its last tower");
        // a channel closed before anything reached a tower leaves nothing behind
        q.on_archive("bb22:1");
        assert!(s.list_with_prefix(PREFIX_CHAN).unwrap().is_empty());
        assert!(s.list_with_prefix(PREFIX_OUT).unwrap().is_empty());

        // the status request
        let stq: serde_json::Value = serde_json::from_str(&status_request(&r, TOWER_B, 1_794_550_200).unwrap()).unwrap();
        let text = format!("lijox-tower-v1|status|{}||1794550200", stq["key"].as_str().unwrap());
        let sig = schnorr::Signature::from_slice(&hex::decode(stq["signature"].as_str().unwrap()).unwrap()).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array()), &x).unwrap();
    }

    #[test]
    fn the_queue_has_a_ceiling_and_says_what_it_let_go() {
        let s = Arc::new(MemoryStorage::new());
        let q = queue(s.clone(), 1000, Arc::new(AtomicU32::new(0)));
        set_on(&*s, true).unwrap();
        for i in 0..(OUT_MAX / 2 + 5) {
            let mut id = [0u8; 32]; id[0] = (i % 251) as u8; id[1] = (i / 251) as u8; id[2] = 1;
            q.note_state(CHAN, LSP, PendingState { txid: hex::encode(id), vout: 0, value: 70_000, number: 1_000_000 - i as u64 });
            q.try_sign(CHAN, &signer(0));
        }
        assert_eq!(s.list_with_prefix(PREFIX_OUT).unwrap().len(), OUT_MAX);
        let sum: serde_json::Value = serde_json::from_str(&summary(&*s).unwrap()).unwrap();
        assert_eq!(sum["lost"], 10);
        assert_eq!(sum["queued"], OUT_MAX as u64);
        set_picks(&*s, CHAN, &[TOWER_B.to_string()]).unwrap();
        // a put takes 64 at most, the oldest first
        let p: serde_json::Value = serde_json::from_str(&put_request(&*s, &root(W1), TOWER_B, 1).unwrap().unwrap()).unwrap();
        assert_eq!(p["body"]["items"].as_array().unwrap().len(), ITEMS_PER_PUT);
        // off: what waits is emptied; the record of the channel stays
        set_on(&*s, false).unwrap();
        assert!(s.list_with_prefix(PREFIX_OUT).unwrap().is_empty());
        assert_eq!(s.list_with_prefix(PREFIX_CHAN).unwrap().len(), 1);
    }

    const TOWER_C: &str = "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn two_towers_a_channel_each_gets_every_item() {
        let s = Arc::new(MemoryStorage::new());
        let q = queue(s.clone(), 1000, Arc::new(AtomicU32::new(0)));
        set_on(&*s, true).unwrap();
        let r = root(W1);
        q.note_state(CHAN, LSP, st(1, 70_000, 100));
        assert_eq!(q.try_sign(CHAN, &signer(0)), 2);
        assert!(set_picks(&*s, CHAN, &[TOWER_B.to_string(), TOWER_C.to_string(), "03".to_string() + &"dd".repeat(32)]).is_err(), "two at most");
        set_picks(&*s, CHAN, &[TOWER_B.to_string(), TOWER_C.to_string()]).unwrap();
        let ids = |j: &str| -> Vec<String> { serde_json::from_str::<serde_json::Value>(j).unwrap()["ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect() };
        let to_b = put_request(&*s, &r, TOWER_B, 10).unwrap().unwrap();
        let to_c = put_request(&*s, &r, TOWER_C, 10).unwrap().unwrap();
        assert_eq!(ids(&to_b), ids(&to_c), "both towers are offered the same two items");
        let kb: serde_json::Value = serde_json::from_str(&to_b).unwrap(); let kc: serde_json::Value = serde_json::from_str(&to_c).unwrap();
        assert_ne!(kb["body"]["key"], kc["body"]["key"], "under a different key at each tower");
        assert_eq!(kb["body"]["group"], kc["body"]["group"]);
        // B acks: the items stay for C; B is not offered them again
        put_ack(&*s, &ids(&to_b), CHAN, TOWER_B, 11).unwrap();
        assert_eq!(s.list_with_prefix(PREFIX_OUT).unwrap().len(), 2);
        assert!(put_request(&*s, &r, TOWER_B, 12).unwrap().is_none());
        assert!(put_request(&*s, &r, TOWER_C, 12).unwrap().is_some());
        let sum: serde_json::Value = serde_json::from_str(&summary(&*s).unwrap()).unwrap();
        assert_eq!(sum["channels"][0]["towers"], serde_json::json!([TOWER_B]));
        assert_eq!(sum["channels"][0]["picks"], serde_json::json!([TOWER_B, TOWER_C]));
        assert_eq!(sum["channels"][0]["waiting"], 2);
        // C acks: now both hold them and they leave the queue
        put_ack(&*s, &ids(&to_c), CHAN, TOWER_C, 13).unwrap();
        assert!(s.list_with_prefix(PREFIX_OUT).unwrap().is_empty());
        let sum: serde_json::Value = serde_json::from_str(&summary(&*s).unwrap()).unwrap();
        assert_eq!(sum["channels"][0]["towers"], serde_json::json!([TOWER_B, TOWER_C]));
        assert_eq!(sum["channels"][0]["uploaded"], 4);
        // a pick is replaced while items wait: what the remaining pick holds goes to the new one only
        q.note_state(CHAN, LSP, st(2, 60_000, 99));
        assert_eq!(q.try_sign(CHAN, &signer(0)), 2);
        let to_b = put_request(&*s, &r, TOWER_B, 20).unwrap().unwrap();
        put_ack(&*s, &ids(&to_b), CHAN, TOWER_B, 21).unwrap();
        let d = "03".to_string() + &"dd".repeat(32);
        set_picks(&*s, CHAN, &[TOWER_B.to_string(), d.clone()]).unwrap();
        assert!(put_request(&*s, &r, TOWER_C, 22).unwrap().is_none(), "the tower that was replaced gets nothing more");
        let to_d = put_request(&*s, &r, &d, 22).unwrap().unwrap();
        put_ack(&*s, &ids(&to_d), CHAN, &d, 23).unwrap();
        assert!(s.list_with_prefix(PREFIX_OUT).unwrap().is_empty());
        // narrowing the picks to a tower that already holds everything empties the queue at once
        q.note_state(CHAN, LSP, st(3, 50_000, 98));
        q.try_sign(CHAN, &signer(0));
        let to_b = put_request(&*s, &r, TOWER_B, 30).unwrap().unwrap();
        put_ack(&*s, &ids(&to_b), CHAN, TOWER_B, 31).unwrap();
        assert_eq!(s.list_with_prefix(PREFIX_OUT).unwrap().len(), 2);
        set_picks(&*s, CHAN, &[TOWER_B.to_string()]).unwrap();
        assert!(s.list_with_prefix(PREFIX_OUT).unwrap().is_empty());
        // a closed channel: a drop for every tower that held items — the replaced one too
        q.on_archive(CHAN);
        for t in [TOWER_B, TOWER_C, d.as_str()] {
            let dq: serde_json::Value = serde_json::from_str(&drop_request(&*s, &r, t, 40).unwrap().unwrap()).unwrap();
            assert_eq!(dq["chan"], CHAN);
            drop_ack(&*s, CHAN, t).unwrap();
        }
        assert!(s.list_with_prefix(PREFIX_CHAN).unwrap().is_empty());
    }

    #[test]
    fn no_key_here_looks_like_a_monitor() {
        for k in [KEY_ON, KEY_SEQ, KEY_LOST, PREFIX_OUT, PREFIX_PEND, PREFIX_CHAN] {
            assert!(!k.starts_with(crate::persist::MONITOR_KEY_PREFIX));
            assert!(!k.starts_with(crate::persist::ARCHIVED_MONITOR_KEY_PREFIX));
        }
    }
}
