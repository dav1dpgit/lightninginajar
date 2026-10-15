//! The attempt records on the phone (step 7, slice 4 — S58; spec v0.10 §8 rules 3 and 6, §9).
//!
//! An attempt record — the attempt id, the funding transaction, every signed exit, the payout and this phone's coins —
//! is written BEFORE this phone's coin signature (§8 rule 3; machine::Action::SaveRecord) and lives in the phone's storage
//! only while the attempt is unsettled: sealed at rest (tier2_wallet::ENCRYPTED_KEYS — it links the person's coin to
//! their payout) and so in every backup taken in that time (node::BUNDLE_SINGLE_KEYS). It is wiped fully — the storage
//! key deleted when none is left, so no later backup carries a trace (§9 rule 6) — at settlement, and at once for an
//! attempt that ended before this phone's coin signature.
//!
//! The chain decides (§8 rule 6): `duty` reads the wallet's own ledger (the Tier-2 view) and says, per record, what the
//! wallet does next — send the exits (the funding is in), wipe (settled, or the coin went elsewhere for good), or watch.
//! A record that arrives with a restored copy goes through the same check at once (§9 rule 4): never resumed.
//!
//! Pure apart from `load`/`save` on the storage handed in.

use std::collections::HashSet;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{ScriptBuf, Transaction};
use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};
use crate::storage::LijStorage;
use crate::tier2_wallet::Tier2View;

/// The storage key: sealed at rest and in every backup while any record exists; deleted when none is left.
pub const RECORDS_KEY: &str = "tatara_records";

/// How deep a spend must be before the attempt is settled (§8 rule 6).
pub const SETTLE_DEPTH: u32 = 6;

/// One attempt's record, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecord {
    pub id: String,
    pub funding_hex: String,
    /// Every signed exit, in signing order (a chain: exit k spends pool output k−1).
    pub exits_hex: Vec<String>,
    pub payout_spk_hex: String,
    /// The payout's m/86 receive index when it is this wallet's; None for another wallet's address.
    #[serde(default)]
    pub payout_index: Option<u32>,
    /// This phone's coins in the funding, as (txid, vout).
    pub inputs: Vec<(String, u32)>,
    pub saved_ms: u64,
    /// v329 (S58, DP 2026-10-13 17:12 — "I don't see the spend in ONCHAIN RECENT nor the change in ONCHAIN COINS until
    /// after the first confirmation"): the change address handed out for this attempt (its script, hex) and its m/84
    /// change index, so the funding's pending row can carry its change like any send of this wallet's. Absent on
    /// records written before v329.
    #[serde(default)]
    pub change_spk_hex: Option<String>,
    #[serde(default)]
    pub change_index: Option<u32>,
    /// Phase 1b (§6.2): the payout is this phone's channel's funding — the exit paying it is the channel's funding
    /// transaction (its id: `channel_id()`); the wallet's ledger never holds the payout.
    #[serde(default)]
    pub channel: bool,
    /// v333 (S59, the speed-up): the pool's fee rate (whole sat/vB) every transaction of the chain was built at, so a
    /// speed-up can price the funding's fee (its inputs are every member's). Absent on records written before v333 —
    /// bump.rs then reads the rate from the first exit's own fee.
    #[serde(default)]
    pub rate_sat_vb: Option<u64>,
    /// v337 (Phase 2a): the pool was a public one (store::after writes it from the phone) — the record's card says so.
    #[serde(default)]
    pub public: bool,
}

impl StoredRecord {
    /// From the state machine's record (machine::Action::SaveRecord).
    pub fn from_machine(r: &super::machine::Record, payout_index: Option<u32>, change: Option<(&ScriptBuf, u32)>, now_ms: u64) -> StoredRecord {
        StoredRecord {
            id: r.id.clone(),
            funding_hex: serialize_hex(&r.funding),
            exits_hex: r.exits.iter().map(serialize_hex).collect(),
            payout_spk_hex: hex::encode(r.payout.as_bytes()),
            payout_index,
            inputs: r.inputs.iter().map(|op| (op.txid.to_string(), op.vout)).collect(),
            saved_ms: now_ms,
            change_spk_hex: change.map(|(s, _)| hex::encode(s.as_bytes())),
            change_index: change.map(|(_, i)| i),
            channel: r.channel,
            rate_sat_vb: (r.rate_milli / 1000 > 0).then_some(r.rate_milli / 1000),
            public: false,
        }
    }

    /// Phase 1b: the channel's id — BOLT 2's v1 channel id of the funding outpoint (the exit paying this phone's
    /// channel): the txid's bytes with the output index XORed into the last two. None for an on-chain pool.
    pub fn channel_id(&self) -> Option<String> {
        if !self.channel { return None; }
        let (exit, vout) = self.my_exit().ok()?;
        let txid = exit.compute_txid();
        let mut id: [u8; 32] = *txid.as_ref();
        id[30] ^= ((vout >> 8) & 0xff) as u8;
        id[31] ^= (vout & 0xff) as u8;
        Some(hex::encode(id))
    }

    pub fn funding(&self) -> LijResult<Transaction> {
        deserialize_hex(&self.funding_hex).map_err(|e| LijError::Storage(format!("attempt record {}: funding: {e}", self.id)))
    }

    pub fn exits(&self) -> LijResult<Vec<Transaction>> {
        self.exits_hex
            .iter()
            .map(|h| deserialize_hex(h).map_err(|e| LijError::Storage(format!("attempt record {}: exit: {e}", self.id))))
            .collect()
    }

    /// The exit that pays this record's payout, and the output's index in it.
    pub fn my_exit(&self) -> LijResult<(Transaction, u32)> {
        let spk = ScriptBuf::from_bytes(hex::decode(&self.payout_spk_hex).map_err(|e| LijError::Storage(format!("attempt record {}: payout: {e}", self.id)))?);
        for tx in self.exits()? {
            if let Some(v) = tx.output.iter().position(|o| o.script_pubkey == spk) {
                return Ok((tx, v as u32));
            }
        }
        Err(LijError::Storage(format!("attempt record {}: no exit pays its payout", self.id)))
    }
}

/// The records on this phone (absent key = none).
pub fn load(storage: &dyn LijStorage) -> LijResult<Vec<StoredRecord>> {
    match storage.get(RECORDS_KEY)? {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|e| LijError::Storage(format!("attempt records parse: {e}"))),
    }
}

/// Write the records; none left → the key is DELETED, so no later backup carries a trace (§9 rule 6).
pub fn save(storage: &dyn LijStorage, records: &[StoredRecord]) -> LijResult<()> {
    if records.is_empty() {
        return storage.delete(RECORDS_KEY);
    }
    let b = serde_json::to_vec(records).map_err(|e| LijError::Storage(format!("attempt records serialize: {e}")))?;
    storage.set(RECORDS_KEY, &b)
}

/// Write one record (replacing one with the same id) — before the coin signature (§8 rule 3).
pub fn put(storage: &dyn LijStorage, rec: StoredRecord) -> LijResult<()> {
    let mut all = load(storage)?;
    all.retain(|r| r.id != rec.id);
    all.push(rec);
    save(storage, &all)
}

/// Wipe one record. Returns it (the caller frees its hold, uploads a clean copy and pushes a clean kit twice).
pub fn wipe(storage: &dyn LijStorage, id: &str) -> LijResult<Option<StoredRecord>> {
    let mut all = load(storage)?;
    let Some(i) = all.iter().position(|r| r.id == id) else { return Ok(None) };
    let gone = all.remove(i);
    save(storage, &all)?;
    Ok(Some(gone))
}

/// The coins every record names — what the Mix's hold keeps after a restore (wallet::reconcile_locks).
pub fn held_inputs(records: &[StoredRecord]) -> HashSet<(String, u32)> {
    records.iter().flat_map(|r| r.inputs.iter().map(|(t, v)| (t.to_ascii_lowercase(), *v))).collect()
}

/// What the Black start kit carries (§9 rule 2: the signed exits alone) — one list per record, in signing order (exit k
/// spends pool output k−1, so /recover sends them in this order).
pub fn kit_exits(records: &[StoredRecord]) -> Vec<Vec<String>> {
    records.iter().map(|r| r.exits_hex.clone()).collect()
}

/// What the wallet does next for one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Duty {
    /// Nothing seen yet: the coin stays held. A record restored from a copy, or one whose phone was closed after its save,
    /// is watched — never resumed (§8 rule 0, §9 rule 4).
    Watch,
    /// The funding spent this phone's coin: send every exit, in order (anyone may have already — a repeat is harmless),
    /// until this phone's payout is settled (§8 rule 6).
    SendExits(Vec<String>),
    /// Settled: this phone's payout is SETTLE_DEPTH deep, or its coin was spent by something else (a "Keep my coin out"
    /// send, a kit sweep) that deep, which ends the attempt for good. Wipe it (§9 rule 3).
    Wipe(&'static str),
}

/// How deep a transaction at `height` is when the ledger has scanned to `tip` (0 = not yet).
fn depth(tip: u32, height: u32) -> u32 {
    if height == 0 || tip < height { 0 } else { tip - height + 1 }
}

/// The chain decides (§8 rule 6). `view` is the wallet's ledger; `outside_depth` answers, for a payout to another
/// wallet's address (not in this wallet's ledger), how deep the exit paying it is (None = not known yet).
pub fn duty(r: &StoredRecord, view: &Tier2View, outside_depth: &dyn Fn(&str) -> Option<u32>) -> LijResult<Duty> {
    let tip = view.cursor.scanned_to;
    let funding_txid = r.funding()?.compute_txid().to_string();
    let mut funded_at: Option<u32> = None;
    let mut elsewhere_at: Option<u32> = None;
    for (txid, vout) in &r.inputs {
        let Some(u) = view.utxos.iter().find(|u| u.txid.eq_ignore_ascii_case(txid) && u.vout == *vout) else { continue };
        let (Some(h), Some(by)) = (u.spent_height, u.spent_txid.as_deref()) else { continue };
        if by.eq_ignore_ascii_case(&funding_txid) {
            funded_at = Some(h);
        } else {
            elsewhere_at = Some(elsewhere_at.map_or(h, |e: u32| e.min(h)));
        }
    }
    if funded_at.is_some() {
        let (exit, vout) = r.my_exit()?;
        let exit_txid = exit.compute_txid().to_string();
        let paid_depth = match r.payout_index {
            Some(i) => view
                .utxos
                .iter()
                .find(|u| u.chain == crate::tier2::CHAIN_BIP86 && u.index == i && u.txid.eq_ignore_ascii_case(&exit_txid) && u.vout == vout)
                .map(|u| depth(tip, u.height)),
            None => outside_depth(&exit_txid),
        };
        if paid_depth.unwrap_or(0) >= SETTLE_DEPTH {
            return Ok(Duty::Wipe("settled: the payout is 6 blocks deep"));
        }
        return Ok(Duty::SendExits(r.exits_hex.clone()));
    }
    if let Some(h) = elsewhere_at {
        if depth(tip, h) >= SETTLE_DEPTH {
            return Ok(Duty::Wipe("settled: the coin went elsewhere, 6 blocks deep — this pool can never use it"));
        }
    }
    Ok(Duty::Watch)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tier2_wallet::OnchainUtxo;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
    use std::sync::Mutex;

    struct Mem(Mutex<std::collections::HashMap<String, Vec<u8>>>);
    impl LijStorage for Mem {
        fn get(&self, k: &str) -> LijResult<Option<Vec<u8>>> { Ok(self.0.lock().unwrap().get(k).cloned()) }
        fn set(&self, k: &str, v: &[u8]) -> LijResult<()> { self.0.lock().unwrap().insert(k.into(), v.to_vec()); Ok(()) }
        fn delete(&self, k: &str) -> LijResult<()> { self.0.lock().unwrap().remove(k); Ok(()) }
        fn list_with_prefix(&self, p: &str) -> LijResult<Vec<String>> { Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(p)).cloned().collect()) }
    }

    pub(crate) fn tx(inputs: &[(bitcoin::Txid, u32)], outputs: &[(u64, ScriptBuf)]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs.iter().map(|(t, v)| TxIn { previous_output: OutPoint { txid: *t, vout: *v }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect(),
            output: outputs.iter().map(|(a, s)| TxOut { value: Amount::from_sat(*a), script_pubkey: s.clone() }).collect(),
        }
    }

    fn coin(txid: &str, vout: u32, chain: u32, index: u32, height: u32) -> OnchainUtxo {
        OnchainUtxo { chain, index, txid: txid.into(), vout, value_sats: 100_000, height, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None }
    }

    /// A pool of one member's view: my coin aa:0 → funding → exit 0 (pays someone) → exit 1 (pays me at m/86 index 4).
    pub(crate) fn fixture(payout_index: Option<u32>) -> (StoredRecord, Transaction, Transaction) {
        let my_coin: bitcoin::Txid = "aa".repeat(32).parse().unwrap();
        let pool = ScriptBuf::from_bytes(hex::decode(format!("5120{}", "66".repeat(32))).unwrap());
        let mine = ScriptBuf::from_bytes(hex::decode(format!("5120{}", "44".repeat(32))).unwrap());
        let theirs = ScriptBuf::from_bytes(hex::decode(format!("5120{}", "55".repeat(32))).unwrap());
        let funding = tx(&[(my_coin, 0)], &[(299_000, pool.clone())]);
        let e0 = tx(&[(funding.compute_txid(), 0)], &[(99_000, theirs), (199_000, pool)]);
        let e1 = tx(&[(e0.compute_txid(), 1)], &[(99_000, mine.clone())]);
        let rec = super::super::machine::Record {
            id: "att-1".into(),
            funding: funding.clone(),
            exits: vec![e0.clone(), e1.clone()],
            payout: mine,
            inputs: vec![OutPoint { txid: my_coin, vout: 0 }],
            channel: false,
            rate_milli: 0,
        };
        (StoredRecord::from_machine(&rec, payout_index, None, 7), funding, e1)
    }

    /// Phase 1b: a channel record's id is LDK's own v1 channel id of the exit's outpoint (BOLT 2); an on-chain record
    /// has none.
    #[test]
    fn r0_a_channel_records_id_is_ldks_v1_channel_id_of_its_exits_outpoint() {
        let (mut r, _, e1) = fixture(Some(4));
        assert_eq!(r.channel_id(), None, "an on-chain pool: no channel");
        r.channel = true;
        let want = lightning::ln::types::ChannelId::v1_from_funding_outpoint(lightning::chain::transaction::OutPoint { txid: e1.compute_txid(), index: 0 });
        assert_eq!(r.channel_id(), Some(hex::encode(want.0)));
        // the index lands in the last two bytes (a high vout)
        let (mut r2, _, _) = fixture(Some(4));
        r2.channel = true;
        let e: Transaction = deserialize_hex(&r2.exits_hex[1]).unwrap();
        let mut e2 = e.clone();
        e2.output.insert(0, TxOut { value: bitcoin::Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() });
        r2.exits_hex[1] = serialize_hex(&e2);
        let want2 = lightning::ln::types::ChannelId::v1_from_funding_outpoint(lightning::chain::transaction::OutPoint { txid: e2.compute_txid(), index: 1 });
        assert_eq!(r2.channel_id(), Some(hex::encode(want2.0)));
    }

    #[test]
    fn r1_written_whole_wiped_fully_and_the_key_deleted_when_none_is_left() {
        let s = Mem(Mutex::new(Default::default()));
        assert!(load(&s).unwrap().is_empty());
        let (r, _, _) = fixture(Some(4));
        put(&s, r.clone()).unwrap();
        let mut r2 = r.clone();
        r2.id = "att-2".into();
        put(&s, r2.clone()).unwrap();
        put(&s, r.clone()).unwrap();   // the same id replaces
        assert_eq!(load(&s).unwrap(), vec![r2.clone(), r.clone()]);
        assert_eq!(held_inputs(&load(&s).unwrap()), HashSet::from([("aa".repeat(32), 0u32)]));
        assert_eq!(kit_exits(&[r.clone()]), vec![r.exits_hex.clone()]);
        // §9 rule 1: no secret number is ever written — the record holds exactly these fields
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["change_index", "change_spk_hex", "channel", "exits_hex", "funding_hex", "id", "inputs", "payout_index", "payout_spk_hex", "public", "rate_sat_vb", "saved_ms"]);   // v329: the change address and its index; v333: the pool's rate (no secret); v337: the public-pool label
        assert_eq!(wipe(&s, "att-1").unwrap(), Some(r));
        assert_eq!(wipe(&s, "att-1").unwrap(), None);
        assert!(s.get(RECORDS_KEY).unwrap().is_some());
        wipe(&s, "att-2").unwrap();
        assert!(s.get(RECORDS_KEY).unwrap().is_none(), "no record left: no key, so no later backup carries a trace");
        assert!(s.0.lock().unwrap().is_empty());
    }

    #[test]
    fn r2_the_chain_decides_watch_then_send_the_exits_then_wipe_at_six_deep() {
        let (r, funding, e1) = fixture(Some(4));
        let none = |_: &str| None;
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 900_010;
        // the coin unspent (or not in this ledger yet): watch
        assert_eq!(duty(&r, &view, &none).unwrap(), Duty::Watch);
        view.utxos.push(coin(&"aa".repeat(32), 0, 0, 0, 900_000));
        assert_eq!(duty(&r, &view, &none).unwrap(), Duty::Watch);
        // the funding spent it: send every exit, in order
        view.utxos[0].spent_height = Some(900_005);
        view.utxos[0].spent_txid = Some(funding.compute_txid().to_string());
        assert_eq!(duty(&r, &view, &none).unwrap(), Duty::SendExits(r.exits_hex.clone()));
        // my payout seen, 5 deep: keep sending; 6 deep: settled
        view.utxos.push(coin(&e1.compute_txid().to_string(), 0, crate::tier2::CHAIN_BIP86, 4, 900_006));
        view.cursor.scanned_to = 900_010;
        assert_eq!(duty(&r, &view, &none).unwrap(), Duty::SendExits(r.exits_hex.clone()));
        view.cursor.scanned_to = 900_011;
        assert!(matches!(duty(&r, &view, &none).unwrap(), Duty::Wipe(_)));
        // a coin at the same index paid by some other transaction is not the payout
        let mut other = view.clone();
        other.utxos[1].txid = "bb".repeat(32);
        assert_eq!(duty(&r, &other, &none).unwrap(), Duty::SendExits(r.exits_hex.clone()));
    }

    #[test]
    fn r3_a_coin_spent_elsewhere_ends_the_attempt_at_six_deep() {
        let (r, _, _) = fixture(Some(4));
        let none = |_: &str| None;
        let mut view = Tier2View::default();
        let mut c = coin(&"aa".repeat(32), 0, 0, 0, 900_000);
        c.spent_height = Some(900_100);
        c.spent_txid = Some("cc".repeat(32));
        view.utxos.push(c);
        view.cursor.scanned_to = 900_104;
        assert_eq!(duty(&r, &view, &none).unwrap(), Duty::Watch, "5 deep: not yet");
        view.cursor.scanned_to = 900_105;
        assert!(matches!(duty(&r, &view, &none).unwrap(), Duty::Wipe(m) if m.contains("went elsewhere")));
    }

    #[test]
    fn r4_a_payout_to_another_wallet_settles_on_the_depth_the_caller_finds() {
        let (r, funding, e1) = fixture(None);
        let mut view = Tier2View::default();
        let mut c = coin(&"aa".repeat(32), 0, 0, 0, 900_000);
        c.spent_height = Some(900_005);
        c.spent_txid = Some(funding.compute_txid().to_string());
        view.utxos.push(c);
        view.cursor.scanned_to = 900_050;
        let want = e1.compute_txid().to_string();
        let five = |t: &str| if t == want { Some(5) } else { None };
        let six = |t: &str| if t == want { Some(6) } else { None };
        assert_eq!(duty(&r, &view, &five).unwrap(), Duty::SendExits(r.exits_hex.clone()));
        assert!(matches!(duty(&r, &view, &six).unwrap(), Duty::Wipe(_)));
    }

    #[test]
    fn r5_the_record_is_sealed_at_rest_and_rides_every_backup() {
        assert!(crate::tier2_wallet::ENCRYPTED_KEYS.contains(&RECORDS_KEY));
        assert!(crate::node::BUNDLE_SINGLE_KEYS.contains(&RECORDS_KEY));
    }
}
