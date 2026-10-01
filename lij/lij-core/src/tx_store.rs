//! v298 (S52, DP 2026-09-30 22:48 "Yes, build the drill-down from the block the wallet already downloaded" and
//! 23:43 "Go on #2"): the wallet's OWN transactions, kept whole.
//!
//! The on-chain walk and the silent-payment scan download every block that touches this wallet and keep only
//! coins (outpoint, value, height) — the transactions themselves were thrown away, so the drill-down asked four
//! public explorers for every txid tapped (independent.rs fetch_tx), telling each of them which transactions are
//! this wallet's. Now each transaction of the wallet's own (it creates a coin of ours, spends one, or is a spend
//! the newest-first walk saw before its coin) is kept as raw bytes from the block it arrived in, under its own
//! storage key, encrypted at rest with the ledger's key; a send is kept the moment it is broadcast. A txid is the
//! transaction's own hash, so a stored entry is checked against its txid when read — nothing in it can be
//! altered. The store is a cache: anything missing (rows from before v298) is read once more from the block
//! the ledger names, on the wallet's own block-filter server.
//!
//! Size (v300, DP 2026-10-01 00:21 "make sure the additional block data kept doesn't fill up the memory space" and
//! 00:23 "not a hard cap, unless it is super high and never will be hit unless there is something malicious"): no
//! block is kept — only the wallet's own transactions — and each is kept COMPACTLY: the transaction without its
//! signatures (the witness; the txid does not cover it, so the txid check still holds) plus its weight, so the fee
//! rate stays exact — about 0.12 KB for an ordinary transaction (v298 kept the full transaction as hex inside JSON,
//! ~0.6 KB). localStorage holds the encrypted value as hex (2 characters a byte) in a site allowance of 5 MB on
//! Safari, beside the channel state, so the ceilings are set where a normal wallet never reaches them and only
//! spam (dust sent to the wallet's addresses) could: TX_STORE_CAP = 1,000 transactions (~125 KB, ~0.5 MB in the
//! browser) and TX_STORE_MAX_BYTES = 256 KB whatever their size (~1 MB in the browser); a single transaction over
//! TX_MAX_BYTES (16 KB without signatures — hundreds of inputs) is not kept. Past a ceiling the lowest heights go
//! first, never the entries being added, and that row reads its block again when tapped. A write that fails
//! deletes the store outright: the cache can never be what fills the allowance.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::{Transaction, Witness};

use crate::error::{LijError, LijResult};
use crate::storage::LijStorage;

/// The storage key (encrypted at rest: tier2_wallet::ENCRYPTED_KEYS).
pub const TX_STORE_KEY: &str = "tier2_txs";
/// v300: the most transactions kept by default — never reached by a normal wallet (spam only).
pub const TX_STORE_CAP: usize = 1_000;
/// v300 (DP 00:25): the ceilings the user may choose when the wallet nears its own ("expand the size"); each 1,000
/// is ~125 KB kept (~0.5 MB of the browser's 5 MB allowance on Safari), so 4,000 is the top.
pub const CAP_STEPS: [usize; 3] = [1_000, 2_000, 4_000];
/// v300: the most bytes kept per 1,000 of the ceiling, whatever the transactions' sizes (stored ≈ 2 characters a byte).
pub const TX_STORE_MAX_BYTES: usize = 256 * 1024;
/// v300: the share of the ceiling at which the wallet tells its user (90 %).
pub const NEAR_CAP_PERCENT: usize = 90;

/// v300: the ceiling in force — the user's choice from CAP_STEPS, else the default.
pub fn cap_for(storage: &dyn LijStorage) -> usize {
    let c = crate::tier2_wallet::load_marks(storage).map(|m| m.tx_keep_cap as usize).unwrap_or(0);
    if CAP_STEPS.contains(&c) { c } else { TX_STORE_CAP }
}
fn max_bytes_for(cap: usize) -> usize { TX_STORE_MAX_BYTES * cap.max(1_000) / 1_000 }
/// v300: a transaction larger than this without its signatures is not kept (its row reads its block when tapped).
pub const TX_MAX_BYTES: usize = 16 * 1024;
/// v300: the compact format's mark (v298/v299 wrote JSON; it is read and rewritten compactly).
const MAGIC: &[u8; 4] = b"LTX2";

/// A kept transaction: its bytes without signatures, its block (0 = broadcast here, not yet seen in a block), and
/// the full transaction's weight (for vsize and the fee rate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub bytes: Vec<u8>,
    pub height: u32,
    pub weight: u32,
}

/// The store in memory, keyed by txid (computed from the bytes on load — what is not that transaction is never read).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxStore {
    pub txs: BTreeMap<String, Kept>,
}

/// What get() answers: the transaction (without signatures), its block, its full weight.
#[derive(Clone, Debug)]
pub struct KeptTx {
    pub tx: Transaction,
    pub height: u32,
    pub weight: u64,
}

impl TxStore {
    /// The kept transaction for `txid` (without signatures), if kept.
    pub fn tx(&self, txid: &str) -> Option<Transaction> {
        self.txs.get(txid).and_then(|k| bitcoin::consensus::deserialize::<Transaction>(&k.bytes).ok())
    }
}

/// v300: the transaction without its signatures, and its full weight.
pub fn compact(tx: &Transaction) -> (Vec<u8>, u32) {
    let weight = tx.weight().to_wu().min(u32::MAX as u64) as u32;
    let mut t = tx.clone();
    for i in t.input.iter_mut() { i.witness = Witness::new(); }
    (bitcoin::consensus::serialize(&t), weight)
}

/// v300: the store's size as written (before encryption).
pub fn store_bytes(store: &TxStore) -> usize { MAGIC.len() + store.txs.values().map(|k| 12 + k.bytes.len()).sum::<usize>() }

fn encode(store: &TxStore) -> Vec<u8> {
    let mut out = Vec::with_capacity(store_bytes(store));
    out.extend_from_slice(MAGIC);
    for k in store.txs.values() {
        out.extend_from_slice(&k.height.to_le_bytes());
        out.extend_from_slice(&k.weight.to_le_bytes());
        out.extend_from_slice(&(k.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&k.bytes);
    }
    out
}

fn decode(b: &[u8]) -> TxStore {
    let mut store = TxStore::default();
    if b.starts_with(MAGIC) {
        let mut i = MAGIC.len();
        let u32_at = |b: &[u8], i: usize| -> Option<u32> { b.get(i..i + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])) };
        while i + 12 <= b.len() {
            let (Some(height), Some(weight), Some(len)) = (u32_at(b, i), u32_at(b, i + 4), u32_at(b, i + 8)) else { break };
            let len = len as usize;
            let Some(bytes) = b.get(i + 12..i + 12 + len) else { break };
            if let Ok(tx) = bitcoin::consensus::deserialize::<Transaction>(bytes) {
                store.txs.insert(tx.compute_txid().to_string(), Kept { bytes: bytes.to_vec(), height, weight });
            }
            i += 12 + len;
        }
        return store;
    }
    // v298/v299's JSON: {"txs":{txid:{"hex":full transaction,"height":h}}} — read once, kept compactly from now on
    #[derive(serde::Deserialize)]
    struct V1 { #[serde(default)] txs: BTreeMap<String, V1e> }
    #[derive(serde::Deserialize)]
    struct V1e { hex: String, #[serde(default)] height: u32 }
    if let Ok(v1) = serde_json::from_slice::<V1>(b) {
        for (txid, e) in v1.txs {
            if let Some(tx) = decode_checked(&e.hex, &txid) {
                let (bytes, weight) = compact(&tx);
                if bytes.len() <= TX_MAX_BYTES { store.txs.insert(txid, Kept { bytes, height: e.height, weight }); }
            }
        }
    }
    store
}

pub fn load(storage: &dyn LijStorage) -> TxStore {
    match storage.get(TX_STORE_KEY) {
        Ok(Some(b)) => decode(&b),
        _ => TxStore::default(),
    }
}

pub fn save(storage: &dyn LijStorage, store: &TxStore) -> LijResult<()> {
    storage.set(TX_STORE_KEY, &encode(store))
}

/// Add (txid, height, raw hex of the full transaction) entries; an entry already kept gains its block height when it
/// had none (a send seen confirmed). Returns how many entries were added or changed; writes only when something did.
pub fn put(storage: &dyn LijStorage, items: &[(String, u32, String)]) -> LijResult<usize> {
    if items.is_empty() { return Ok(0); }
    let mut store = load(storage);
    let mut changed = 0usize;
    for (txid, height, hex) in items {
        match store.txs.get_mut(txid) {
            Some(e) => {
                if *height > 0 && e.height != *height { e.height = *height; changed += 1; }
            }
            None => {
                let Some(tx) = decode_checked(hex, txid) else { continue };
                let (bytes, weight) = compact(&tx);
                if bytes.len() > TX_MAX_BYTES { continue; }   // v300: hundreds of inputs — its row reads its block when tapped
                store.txs.insert(txid.clone(), Kept { bytes, height: *height, weight });
                changed += 1;
            }
        }
    }
    if changed == 0 { return Ok(0); }
    let adding: std::collections::HashSet<&str> = items.iter().map(|(t, _, _)| t.as_str()).collect();
    trim(&mut store, cap_for(storage), &adding);
    if let Err(e) = save(storage, &store) {
        // never the cache that fills the allowance — a failed write removes the store (the rows read their blocks again)
        let _ = storage.delete(TX_STORE_KEY);
        return Err(e);
    }
    Ok(changed)
}

/// v300: the ceilings — the lowest heights first (confirmed before unconfirmed), never an entry in `keep`.
fn trim(store: &mut TxStore, cap: usize, keep: &std::collections::HashSet<&str>) {
    let max_bytes = max_bytes_for(cap);
    let mut size = store_bytes(store);
    if size > max_bytes || store.txs.len() > cap {
        let mut order: Vec<(u8, u32, String)> = store.txs.iter()
            .filter(|(k, _)| !keep.contains(k.as_str()))
            .map(|(k, e)| (if e.height > 0 { 0u8 } else { 1u8 }, e.height, k.clone()))
            .collect();
        order.sort();
        for (_, _, k) in order {
            if size <= max_bytes && store.txs.len() <= cap { break; }
            if let Some(e) = store.txs.remove(&k) { size = size.saturating_sub(12 + e.bytes.len()); }
        }
        log::warn!("[tier2] v300 tx store at its ceiling ({} transactions, {} bytes, ceiling {cap}) — the oldest went", store.txs.len(), size);
    }
}

/// v300 (DP 00:25): what the wallet tells its user — how many transactions are kept, the ceiling, whether it is near
/// (NEAR_CAP_PERCENT), the bytes, and the oldest block kept.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct KeepStatus {
    pub count: usize,
    pub cap: usize,
    pub near: bool,
    pub bytes: usize,
    pub oldest_height: u32,
    pub steps: Vec<usize>,
}

pub fn status(storage: &dyn LijStorage) -> KeepStatus {
    let store = load(storage);
    let cap = cap_for(storage);
    KeepStatus {
        count: store.txs.len(),
        cap,
        near: store.txs.len() * 100 >= cap * NEAR_CAP_PERCENT,
        bytes: store_bytes(&store),
        oldest_height: store.txs.values().filter(|k| k.height > 0).map(|k| k.height).min().unwrap_or(0),
        steps: CAP_STEPS.to_vec(),
    }
}

/// v300 (DP: "expand the size"): the user's ceiling, one of CAP_STEPS; a lower one trims at once.
pub fn set_cap(storage: &dyn LijStorage, cap: usize) -> LijResult<KeepStatus> {
    if !CAP_STEPS.contains(&cap) {
        return Err(LijError::Storage(format!("the ceiling must be one of {:?}", CAP_STEPS)));
    }
    let mut m = crate::tier2_wallet::load_marks(storage)?;
    m.tx_keep_cap = cap as u32;
    crate::tier2_wallet::save_marks(storage, &m)?;
    let mut store = load(storage);
    let before = store.txs.len();
    trim(&mut store, cap, &std::collections::HashSet::new());
    if store.txs.len() != before { save(storage, &store)?; }
    Ok(status(storage))
}

/// v300 (DP: "delete old data"): drop the kept transactions from blocks below `height` (their rows read their block
/// again when tapped; the ledger — coins, balance, history — is not touched). Returns how many went.
pub fn drop_before(storage: &dyn LijStorage, height: u32) -> LijResult<usize> {
    let mut store = load(storage);
    let before = store.txs.len();
    store.txs.retain(|_, k| k.height == 0 || k.height >= height);
    let gone = before - store.txs.len();
    if gone > 0 { save(storage, &store)?; }
    Ok(gone)
}

/// The kept transaction for `txid` (without signatures), its block and its full weight.
pub fn get(storage: &dyn LijStorage, txid: &str) -> Option<KeptTx> {
    let store = load(storage);
    let k = store.txs.get(txid)?;
    let tx: Transaction = bitcoin::consensus::deserialize(&k.bytes).ok()?;
    Some(KeptTx { tx, height: k.height, weight: k.weight as u64 })
}

/// Decode raw hex and keep it only if it IS `txid` (the txid is the transaction's own hash).
pub fn decode_checked(hex_str: &str, txid: &str) -> Option<Transaction> {
    let bytes = hex::decode(hex_str).ok()?;
    let tx: Transaction = bitcoin::consensus::deserialize(&bytes).ok()?;
    let want = bitcoin::Txid::from_str(txid).ok()?;
    if tx.compute_txid() == want { Some(tx) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

    /// An ordinary one-in, two-out payment with a P2WPKH signature (the witness ~108 bytes).
    fn tx(n: u32) -> Transaction {
        let b = n.to_le_bytes();
        Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([b[0], b[1], b[2], b[3], 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::from_slice(&[vec![7u8; 72], vec![2u8; 33]]) }],
            output: vec![
                TxOut { value: Amount::from_sat(50_000 + n as u64), script_pubkey: ScriptBuf::from_bytes([&[0x00u8, 0x14][..], &[n as u8; 20][..]].concat()) },
                TxOut { value: Amount::from_sat(12_345), script_pubkey: ScriptBuf::from_bytes([&[0x51u8, 0x20][..], &[3u8; 32][..]].concat()) },
            ],
        }
    }
    fn hx(t: &Transaction) -> String { hex::encode(bitcoin::consensus::serialize(t)) }

    #[test]
    fn kept_compactly_checked_by_txid_weight_exact_heights_filled() {
        let s = MemoryStorage::new();
        let (a, b) = (tx(1), tx(2));
        let (ia, ib) = (a.compute_txid().to_string(), b.compute_txid().to_string());
        assert_eq!(put(&s, &[(ia.clone(), 0, hx(&a))]).unwrap(), 1, "a send, kept at broadcast (height 0)");
        assert_eq!(put(&s, &[(ia.clone(), 0, hx(&a))]).unwrap(), 0, "kept once");
        assert_eq!(put(&s, &[(ia.clone(), 969_300, hx(&a)), (ib.clone(), 969_301, hx(&b))]).unwrap(), 2, "the send gains its block; another is added");
        let k = get(&s, &ia).unwrap();
        assert_eq!((k.tx.compute_txid().to_string(), k.height, k.weight), (ia.clone(), 969_300, a.weight().to_wu()), "same txid without the signatures; the full weight kept");
        assert!(k.tx.input[0].witness.is_empty());
        let full = bitcoin::consensus::serialize(&a).len();
        let kept = load(&s).txs[&ia].bytes.len();
        assert!(kept + 12 < full * 2 / 3, "compact: {kept} bytes kept of {full}");
        // bytes under a txid that are not that transaction are refused at the door
        assert_eq!(put(&s, &[("00".repeat(32), 1, hx(&b))]).unwrap(), 0);
        assert!(get(&s, &"00".repeat(32)).is_none());
    }

    #[test]
    fn v300_a_normal_wallet_never_reaches_the_ceiling_spam_does() {
        // DP 00:23: "not a hard cap, unless it is super high and never will be hit unless there is something malicious"
        let s = MemoryStorage::new();
        for n in 0..600u32 {   // far more on-chain transactions than a Lightning-first wallet makes in years
            let t = tx(n);
            put(&s, &[(t.compute_txid().to_string(), 900_000 + n, hx(&t))]).unwrap();
        }
        let st = load(&s);
        assert_eq!(st.txs.len(), 600, "every one kept");
        let stored_chars = 2 * (store_bytes(&st) + 32);
        assert!(stored_chars < 200_000, "600 ordinary transactions ≈ {stored_chars} characters in localStorage");
        // spam: past 1,000 the oldest go, never the one being added
        for n in 600..1_200u32 {
            let t = tx(n);
            put(&s, &[(t.compute_txid().to_string(), 900_000 + n, hx(&t))]).unwrap();
        }
        let st = load(&s);
        assert_eq!(st.txs.len(), TX_STORE_CAP);
        assert!(st.txs.contains_key(&tx(1_199).compute_txid().to_string()) && !st.txs.contains_key(&tx(0).compute_txid().to_string()));
        assert!(store_bytes(&st) <= TX_STORE_MAX_BYTES);
        // a transaction over TX_MAX_BYTES without its signatures is not kept
        let mut big = tx(5_000);
        for _ in 0..500 { big.input.push(big.input[0].clone()); }
        assert_eq!(put(&s, &[(big.compute_txid().to_string(), 969_000, hx(&big))]).unwrap(), 0);
    }

    #[test]
    fn v300_the_wallet_is_told_near_the_ceiling_and_can_expand_or_drop_old() {
        // DP 00:25: "if a wallet approaches 1000 transactions, some notification … delete old data or expand the size"
        let s = MemoryStorage::new();
        for n in 0..899u32 { let t = tx(n); put(&s, &[(t.compute_txid().to_string(), 900_000 + n, hx(&t))]).unwrap(); }
        let st = status(&s);
        assert_eq!((st.count, st.cap, st.near, st.oldest_height), (899, 1_000, false, 900_000));
        let t = tx(899); put(&s, &[(t.compute_txid().to_string(), 900_899, hx(&t))]).unwrap();
        assert!(status(&s).near, "900 of 1,000: the wallet tells its user");
        // expand: only the offered steps
        assert!(set_cap(&s, 1_500).is_err());
        let st = set_cap(&s, 2_000).unwrap();
        assert_eq!((st.cap, st.near), (2_000, false));
        assert_eq!(crate::tier2_wallet::load_marks(&s).unwrap().tx_keep_cap, 2_000, "kept with the marks (rides the backup)");
        for n in 900..1_500u32 { let t = tx(n); put(&s, &[(t.compute_txid().to_string(), 900_000 + n, hx(&t))]).unwrap(); }
        assert_eq!(status(&s).count, 1_500, "nothing went under the larger ceiling");
        // delete old data: below a block — the rest stays
        assert_eq!(drop_before(&s, 901_000).unwrap(), 1_000);
        assert_eq!((status(&s).count, status(&s).oldest_height), (500, 901_000));
        // back down to 1,000 trims at once, oldest first
        for n in 1_500..2_100u32 { let t = tx(n); put(&s, &[(t.compute_txid().to_string(), 900_000 + n, hx(&t))]).unwrap(); }
        let st = set_cap(&s, 1_000).unwrap();
        assert_eq!((st.count, st.oldest_height), (1_000, 901_100));
    }

    #[test]
    fn v300_the_v298_json_store_is_read_and_kept_compactly() {
        let s = MemoryStorage::new();
        let a = tx(11);
        let ia = a.compute_txid().to_string();
        let v1 = serde_json::json!({"txs": {ia.clone(): {"hex": hx(&a), "height": 969_100}, "11".repeat(32): {"hex": hx(&tx(12)), "height": 1}}});
        s.set(TX_STORE_KEY, &serde_json::to_vec(&v1).unwrap()).unwrap();
        let k = get(&s, &ia).unwrap();
        assert_eq!((k.height, k.weight), (969_100, a.weight().to_wu()));
        assert_eq!(load(&s).txs.len(), 1, "an entry that is not its txid is dropped in the reading");
        put(&s, &[(tx(13).compute_txid().to_string(), 2, hx(&tx(13)))]).unwrap();
        assert!(s.get(TX_STORE_KEY).unwrap().unwrap().starts_with(MAGIC), "rewritten compactly");
    }

    #[test]
    fn v299_a_write_that_fails_removes_the_store() {
        struct Full(MemoryStorage);
        impl LijStorage for Full {
            fn get(&self, k: &str) -> LijResult<Option<Vec<u8>>> { self.0.get(k) }
            fn set(&self, _k: &str, _v: &[u8]) -> LijResult<()> { Err(LijError::Storage("QuotaExceededError".into())) }
            fn delete(&self, k: &str) -> LijResult<()> { self.0.delete(k) }
            fn list_with_prefix(&self, p: &str) -> LijResult<Vec<String>> { self.0.list_with_prefix(p) }
        }
        let inner = MemoryStorage::new();
        inner.set(TX_STORE_KEY, b"LTX2").unwrap();
        let full = Full(inner);
        let t = tx(21);
        assert!(put(&full, &[(t.compute_txid().to_string(), 1, hx(&t))]).is_err());
        assert!(full.get(TX_STORE_KEY).unwrap().is_none(), "the store is gone, the space given back");
    }
}
