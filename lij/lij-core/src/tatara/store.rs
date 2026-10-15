//! The Mix's storage side (step 7, slice 6 — S58): what lij-wasm calls, each a load–change–save on the wallet's sealed
//! store (tier2_wallet::encrypted — the marks and the attempt records are both on its key list). No network here: the
//! caller sends the exits `settle_pass` asks for and answers the depth of another wallet's payout.

use std::collections::HashSet;

use serde::Serialize;

use crate::error::{LijError, LijResult};
use crate::key::RootKey;
use crate::storage::LijStorage;
use crate::tier2_wallet::{load_marks, load_pending, load_view, record_pending, remove_pending_by_txid, save_marks, PendingTx, TxDirection, TxKind};

use super::records::{self, Duty, StoredRecord};
use super::wallet::{next_change, payout_for, reconcile_locks, PayoutChoice};

/// A new attempt's payout and change, handed out together (both marked before either is used — v0.10 §5.2, §5.3).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HandOut {
    pub payout_address: String,
    pub payout_spk_hex: String,
    /// The m/86 index (this wallet's payout); None for another wallet's.
    pub payout_index: Option<u32>,
    pub change_index: u32,
    pub change_spk_hex: String,
}

/// Phase 1b: a channel pool's hand-out — the change only (the payout is the channel's funding script, given later).
pub fn hand_out_change(storage: &dyn LijStorage, root: &RootKey) -> LijResult<HandOut> {
    let view = load_view(storage)?;
    let pending = load_pending(storage);
    let mut marks = load_marks(storage)?;
    let (c, spk) = next_change(root, &view, &pending, &mut marks)?;
    save_marks(storage, &marks)?;
    Ok(HandOut { payout_address: String::new(), payout_spk_hex: String::new(), payout_index: None, change_index: c, change_spk_hex: hex::encode(spk.as_bytes()) })
}

pub fn hand_out(storage: &dyn LijStorage, root: &RootKey, choice: &PayoutChoice) -> LijResult<HandOut> {
    let view = load_view(storage)?;
    let pending = load_pending(storage);
    let mut marks = load_marks(storage)?;
    let p = payout_for(root, &view, &mut marks, choice)?;
    let (c, spk) = next_change(root, &view, &pending, &mut marks)?;
    save_marks(storage, &marks)?;
    Ok(HandOut {
        payout_address: p.address,
        payout_spk_hex: hex::encode(p.script.as_bytes()),
        payout_index: p.index,
        change_index: c,
        change_spk_hex: hex::encode(spk.as_bytes()),
    })
}

/// Hold coins for a Mix (Join) — v0.10 §8 rule 4.
pub fn lock(storage: &dyn LijStorage, coins: &[(String, u32)], now_ms: u64) -> LijResult<()> {
    let mut marks = load_marks(storage)?;
    marks.mix_lock(coins, now_ms);
    save_marks(storage, &marks)
}

/// Free coins (left the list; the attempt ended before this phone's coin signature). A coin an unsettled record names
/// stays held — only its settlement frees it.
pub fn unlock(storage: &dyn LijStorage, coins: &[(String, u32)]) -> LijResult<Vec<(String, u32)>> {
    let named = records::held_inputs(&records::load(storage)?);
    let free: Vec<(String, u32)> = coins.iter().filter(|(t, v)| !named.contains(&(t.to_ascii_lowercase(), *v))).cloned().collect();
    let mut marks = load_marks(storage)?;
    marks.mix_unlock(&free);
    save_marks(storage, &marks)?;
    Ok(free)
}

/// Write a record before the coin signature (§8 rule 3); its coins held. The caller marks the backup dirty (§9 rule 3: a
/// record written or wiped is an upload trigger).
pub fn record_save(storage: &dyn LijStorage, rec: StoredRecord, now_ms: u64) -> LijResult<()> {
    let coins = rec.inputs.clone();
    pool_rows(storage, &rec, now_ms)?;   // v329: the pool among the sends still confirming, from this moment
    records::put(storage, rec)?;
    lock(storage, &coins, now_ms)
}

/// Wipe a record and free its coins — at once for an attempt that ended before this phone's coin signature, or at
/// settlement. The caller marks the backup dirty and pushes a clean kit twice.
pub fn record_wipe(storage: &dyn LijStorage, id: &str) -> LijResult<bool> {
    let Some(gone) = records::wipe(storage, id)? else { return Ok(false) };
    drop_pool_rows(storage, &gone)?;   // v329: its rows go with it (a settled pool's rows are confirmed history by then)
    let mut marks = load_marks(storage)?;
    marks.mix_unlock(&gone.inputs);
    save_marks(storage, &marks)?;
    Ok(true)
}

/// What a settle pass did.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettleReport {
    /// Per record still waiting on its payout: its exits, in order, for the caller to send.
    pub send: Vec<(String, Vec<String>)>,
    /// Records wiped, with why.
    pub wiped: Vec<(String, String)>,
    pub watching: usize,
    /// Records that could not be read (kept; reported, never guessed at).
    pub unreadable: Vec<(String, String)>,
}

/// The chain decides (§8 rule 6), for every record: send its exits, wipe it (and free its coins), or watch. Run after a
/// sync, and at once after a copy is restored (§9 rule 4 — a restored record is watched, never resumed).
/// `outside_depth(exit_txid)` answers for a payout to another wallet's address.
pub fn settle_pass(storage: &dyn LijStorage, outside_depth: &dyn Fn(&str) -> Option<u32>) -> LijResult<SettleReport> {
    let all = records::load(storage)?;
    let mut rep = SettleReport::default();
    if all.is_empty() {
        return Ok(rep);
    }
    let view = load_view(storage)?;
    for r in &all {
        match records::duty(r, &view, outside_depth) {
            Ok(Duty::Watch) => rep.watching += 1,
            Ok(Duty::SendExits(txs)) => rep.send.push((r.id.clone(), txs)),
            Ok(Duty::Wipe(why)) => rep.wiped.push((r.id.clone(), why.to_string())),
            Err(e) => rep.unreadable.push((r.id.clone(), e.to_string())),
        }
    }
    for (id, _) in &rep.wiped {
        record_wipe(storage, id)?;
    }
    Ok(rep)
}

/// At start and after a restore: the Mix's holds become exactly the coins a seat on this phone (`seat_coins`) or an
/// unsettled record names (wallet::reconcile_locks; §9 rule 7). Returns (freed, added).
pub fn reconcile(storage: &dyn LijStorage, seat_coins: &[(String, u32)], now_ms: u64) -> LijResult<(Vec<(String, u32)>, Vec<(String, u32)>)> {
    let mut keep: HashSet<(String, u32)> = records::held_inputs(&records::load(storage)?);
    keep.extend(seat_coins.iter().map(|(t, v)| (t.to_ascii_lowercase(), *v)));
    let mut marks = load_marks(storage)?;
    let out = reconcile_locks(&mut marks, &keep, now_ms);
    if !out.0.is_empty() || !out.1.is_empty() {
        save_marks(storage, &marks)?;
    }
    Ok(out)
}

/// v325 (step 8): the records as the Mix screen shows them — one "Confirming" card each until it settles. The size is
/// the payout's own value (a payout is exactly the pool size). v327: and this phone's coins in the pool, their value,
/// and the state the card says (from the wallet's own ledger and its sends still confirming):
///   "waiting"  — the funding is not in a block and nothing else spent the coin: the coin stays held; the card offers
///                "Keep my coin out of this pool" while no setup is running (v0.10 §8 rule 10);
///   "funded"   — the funding spent the coin: the exits go out, the payout settles it;
///   "kept_out" — this wallet's own send took the coin (in a block, or still confirming): the pool can never use it; the
///                record wipes once that send is 6 deep (records::duty).
/// v329 (DP 2026-10-13 17:12 "How do I find more information about the transaction mixing in the pool"): the pool's
/// transaction ids — the funding, every exit in chain order, and the one that pays this record's payout (with the
/// output's index) — and the payout's address, for the record's own view on the Mix screen.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecordView {
    pub id: String,
    pub size: u64,
    pub payout_index: Option<u32>,
    pub saved_ms: u64,
    pub inputs: Vec<(String, u32)>,
    pub coin_sats: u64,
    pub state: &'static str,
    pub funding_txid: String,
    pub exit_txids: Vec<String>,
    pub my_exit_txid: String,
    pub my_exit_vout: u32,
    pub payout_address: String,
    /// This phone's change from the funding (sats), 0 when none.
    pub change_sats: u64,
    /// Phase 1b: the payout is this phone's channel — its id (hex). None for an on-chain pool.
    pub channel_id: Option<String>,
    /// v333 (S59, the speed-up): a child of this wallet's spending the payout is still confirming — its txid and the
    /// fee it carries (tatara::bump; a send of this wallet's whose spent outpoints name the payout). None otherwise.
    pub sped_up_txid: Option<String>,
    pub sped_up_fee_sats: Option<u64>,
    /// v333: the pool's fee rate (whole sat/vB) when the record kept it.
    pub rate_sat_vb: Option<u64>,
}

/// The pool's transactions of one record: (funding txid, every exit's txid in chain order, my exit's txid and output
/// index). Empty strings / lists when the record's bytes do not parse (a test fixture; never a real record).
fn record_txids(r: &StoredRecord) -> (String, Vec<String>, String, u32) {
    let funding = r.funding().map(|t| t.compute_txid().to_string()).unwrap_or_default();
    let exits = r.exits().map(|v| v.iter().map(|t| t.compute_txid().to_string()).collect()).unwrap_or_default();
    let (mine, vout) = r.my_exit().map(|(t, v)| (t.compute_txid().to_string(), v)).unwrap_or_default();
    (funding, exits, mine, vout)
}

/// This phone's change output in the record's funding, when the record names a change script: (vout, sats).
fn record_change(r: &StoredRecord) -> Option<(u32, u64)> {
    let spk = hex::decode(r.change_spk_hex.as_deref()?).ok()?;
    let f = r.funding().ok()?;
    f.output.iter().position(|o| o.script_pubkey.as_bytes() == spk.as_slice()).map(|i| (i as u32, f.output[i].value.to_sat()))
}

/// v329: the two rows a saved record puts among the wallet's sends still confirming, so ONCHAIN RECENT and ONCHAIN
/// COINS show the pool the moment this phone signs, as they show any send of this wallet's: the funding (this phone's
/// coins out, its change back — kind Mix) and the exit that pays this phone (kind Mix, received). Neither carries the
/// raw bytes: a record is written BEFORE this phone's signature, so its funding is not yet complete; the pool's own
/// sending (mix_send, settle_pass) carries them. Rows are dropped with the record (record_wipe) or when "Keep my coin
/// out" spends the coin elsewhere (drop_pool_rows). A record whose bytes do not parse (a test fixture) puts no rows.
fn pool_rows(storage: &dyn LijStorage, r: &StoredRecord, now_ms: u64) -> LijResult<()> {
    let Ok(f) = r.funding() else { return Ok(()) };
    let (Ok((exit, vout)), Ok(_)) = (r.my_exit(), r.exits()) else { return Ok(()) };
    let view = load_view(storage)?;
    let mut coins_in = 0u64;
    for (t, v) in &r.inputs {
        if let Some(u) = view.utxos.iter().find(|u| u.txid.eq_ignore_ascii_case(t) && u.vout == *v) { coins_in = coins_in.saturating_add(u.value_sats); }
    }
    let change = record_change(r);
    let change_sats = change.map(|(_, s)| s).unwrap_or(0);
    let funding_txid = f.compute_txid().to_string();
    record_pending(storage, PendingTx {
        txid: funding_txid.clone(),
        spent_outpoints: r.inputs.clone(),
        delta_sats: -(coins_in.saturating_sub(change_sats) as i64),
        direction: if change_sats > 0 { TxDirection::SelfTransfer } else { TxDirection::Sent },
        kind: TxKind::Mix,
        created_at_ms: now_ms,
        broadcast_seen: false,
        raw_tx_hex: None,
        change_outpoint: change.map(|(v, _)| (funding_txid.clone(), v)),
        dest_addr: None,
        dest_sats: None,
        fee_sats: None,
        fee_rate_sat_per_kw: None,
        change_value_sats: change_sats,
        change_index: r.change_index.unwrap_or(0),
        dests: Vec::new(),
    })?;
    if r.channel { return Ok(()); }   // Phase 1b: the exit pays this phone's channel, not its ledger — the funding row says "into a pool"; Connections shows the channel
    let paid = exit.output.get(vout as usize).map(|o| o.value.to_sat()).unwrap_or(0);
    record_pending(storage, PendingTx {
        txid: exit.compute_txid().to_string(),
        spent_outpoints: Vec::new(),
        delta_sats: paid as i64,
        direction: TxDirection::Received,
        kind: TxKind::Mix,
        created_at_ms: now_ms,
        broadcast_seen: false,
        raw_tx_hex: None,
        change_outpoint: None,
        dest_addr: None,
        dest_sats: None,
        fee_sats: None,
        fee_rate_sat_per_kw: None,
        change_value_sats: 0,
        change_index: 0,
        dests: Vec::new(),
    })
}

/// The record's two rows out of the wallet's sends still confirming (the funding and this phone's exit).
fn drop_pool_rows(storage: &dyn LijStorage, r: &StoredRecord) -> LijResult<()> {
    let (f, _, e, _) = record_txids(r);
    if !f.is_empty() { remove_pending_by_txid(storage, &f)?; }
    if !e.is_empty() { remove_pending_by_txid(storage, &e)?; }
    Ok(())
}

/// v329: "Keep my coin out" spent a record's coin elsewhere — its pool rows leave ONCHAIN RECENT at once (the record
/// itself stays until that send is 6 deep, records::duty). Returns how many records' rows were dropped.
pub fn drop_pool_rows_for(storage: &dyn LijStorage, coins: &[(String, u32)]) -> LijResult<usize> {
    let mut n = 0;
    for r in records::load(storage)? {
        if r.inputs.iter().any(|(t, v)| coins.iter().any(|(ct, cv)| ct.eq_ignore_ascii_case(t) && cv == v)) {
            drop_pool_rows(storage, &r)?;
            n += 1;
        }
    }
    Ok(n)
}

pub fn records_view(storage: &dyn LijStorage, network: bitcoin::Network) -> LijResult<Vec<RecordView>> {
    let all = records::load(storage)?;
    if all.is_empty() {
        return Ok(Vec::new());
    }
    let view = load_view(storage)?;
    // v329: a record's own funding row (pool_rows) is not "this wallet's own send" — only another send is a keep-out
    let own: HashSet<String> = all.iter().map(|r| record_txids(r).0.to_ascii_lowercase()).collect();
    let pending = load_pending(storage);
    let sending: HashSet<(String, u32)> = pending
        .iter()
        .filter(|p| !own.contains(&p.txid.to_ascii_lowercase()))
        .flat_map(|p| p.spent_outpoints.iter().map(|(t, v)| (t.to_ascii_lowercase(), *v)))
        .collect();
    let mut out = Vec::with_capacity(all.len());
    for r in &all {
        let spk = hex::decode(&r.payout_spk_hex).unwrap_or_default();
        let mut size = 0u64;
        for h in &r.exits_hex {
            if let Ok(tx) = bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(h) {
                if let Some(o) = tx.output.iter().find(|o| o.script_pubkey.as_bytes() == spk.as_slice()) { size = o.value.to_sat(); break; }
            }
        }
        let funding_txid = bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(&r.funding_hex)
            .map(|t| t.compute_txid().to_string())
            .unwrap_or_default();
        let (mut coin_sats, mut funded, mut kept_out) = (0u64, false, false);
        for (t, v) in &r.inputs {
            if let Some(u) = view.utxos.iter().find(|u| u.txid.eq_ignore_ascii_case(t) && u.vout == *v) {
                coin_sats = coin_sats.saturating_add(u.value_sats);
                match u.spent_txid.as_deref() {
                    Some(by) if !funding_txid.is_empty() && by.eq_ignore_ascii_case(&funding_txid) => funded = true,
                    Some(_) => kept_out = true,
                    None => {}
                }
            }
            // the pool's funding is never one of this wallet's own sends (mix_send records nothing), so a send still
            // confirming that spends a record's coin is "Keep my coin out" — the coin is held from every other spend
            if sending.contains(&(t.to_ascii_lowercase(), *v)) {
                kept_out = true;
            }
        }
        let state = if funded { "funded" } else if kept_out { "kept_out" } else { "waiting" };
        let (funding_txid, exit_txids, my_exit_txid, my_exit_vout) = record_txids(r);
        let payout_address = bitcoin::Address::from_script(bitcoin::Script::from_bytes(&spk), network).map(|a| a.to_string()).unwrap_or_default();
        let change_sats = record_change(r).map(|(_, s)| s).unwrap_or(0);
        // v333: a speed-up still confirming — the pending row whose spent outpoints name this phone's payout
        let sped = pending.iter().find(|p| p.kind == TxKind::MixSpeedUp && p.spent_outpoints.iter().any(|(t, v)| t.eq_ignore_ascii_case(&my_exit_txid) && *v == my_exit_vout));
        out.push(RecordView { id: r.id.clone(), size, payout_index: r.payout_index, saved_ms: r.saved_ms, inputs: r.inputs.clone(), coin_sats, state, funding_txid, exit_txids, my_exit_txid, my_exit_vout, payout_address, change_sats, channel_id: r.channel_id(), sped_up_txid: sped.map(|p| p.txid.clone()), sped_up_fee_sats: sped.and_then(|p| p.fee_sats), rate_sat_vb: r.rate_sat_vb });
    }
    Ok(out)
}

// ── the seats (step 8): this phone's places on its provider's waiting list ──

/// The storage key of the seats: sealed at rest, on this phone ONLY (not in a backup — a seat never comes back from a
/// copy, §9 rule 7: the waiting list is an ordinary coin after a restore).
pub const SEATS_KEY: &str = "tatara_seats";

/// One seat on this phone.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Seat {
    /// The provider's seat id ("" until it answered).
    #[serde(default)]
    pub seat_id: String,
    /// The 32 random bytes the seat key comes from (client::SeatKey::from_entropy; it signs the check-ins and opens this
    /// seat's copy of the pool's key) — secret, this phone only.
    pub seat_secret_hex: String,
    pub seat_pk: String,
    pub provider_pk: String,
    pub endpoint: String,
    pub size: u64,
    pub route: String,
    pub coins: Vec<(String, u32)>,
    /// v332 (DP's first channel pool, 2026-10-13: "the seat's coin is not in the wallet's ledger" at a start while the
    /// ledger's coin list was being rewritten — a rebuild or a reorg rollback re-derives a coin within a minute): the
    /// coins' ledger rows as they were when the seat was taken, so a start does not depend on the list's state at that
    /// moment. The ledger's row is used when it is there; this copy when it is not. A coin spent elsewhere is still
    /// refused by the provider's coin check at registration. Empty for seats taken before v332.
    #[serde(default)]
    pub coin_rows: Vec<crate::tier2_wallet::OnchainUtxo>,
    pub payout: PayoutChoice,
    /// The fee rate shown at Join (sat/vB) — the fee limit's base.
    pub rate_at_join: u64,
    pub since_ms: u64,
}

pub fn seats(storage: &dyn LijStorage) -> LijResult<Vec<Seat>> {
    match storage.get(SEATS_KEY)? {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|e| crate::error::LijError::Storage(format!("seats parse: {e}"))),
    }
}

fn save_seats(storage: &dyn LijStorage, all: &[Seat]) -> LijResult<()> {
    if all.is_empty() {
        return storage.delete(SEATS_KEY);
    }
    let b = serde_json::to_vec(all).map_err(|e| crate::error::LijError::Storage(format!("seats serialize: {e}")))?;
    storage.set(SEATS_KEY, &b)
}

/// Join: a new seat (its key from `entropy`), its coins held from now (§8 rule 4). One seat per size and route.
pub fn seat_new(storage: &dyn LijStorage, mut seat: Seat, entropy: &[u8; 32], now_ms: u64) -> LijResult<Seat> {
    let mut all = seats(storage)?;
    if all.iter().any(|s| s.size == seat.size && s.route == seat.route && s.provider_pk == seat.provider_pk) {
        return Err(crate::error::LijError::Node(format!("this wallet already has a seat for {} sats", seat.size)));
    }
    let held = load_marks(storage)?.mix_locked_set();
    if seat.coins.iter().any(|(t, v)| held.contains(&(t.to_ascii_lowercase(), *v))) {
        return Err(crate::error::LijError::Node("that coin is already in a Mix pool".into()));
    }
    let k = super::client::SeatKey::from_entropy(entropy).map_err(|e| crate::error::LijError::Key(e.to_string()))?;
    seat.seat_secret_hex = hex::encode(entropy);
    seat.seat_pk = k.pk_hex();
    seat.seat_id = String::new();
    seat.since_ms = now_ms;
    // v332: the coins' ledger rows ride with the seat (those the ledger holds now; a coin not in it today is simply
    // not copied — the start then reads the ledger as before)
    let view = load_view(storage)?;
    seat.coin_rows = seat
        .coins
        .iter()
        .filter_map(|(t, v)| view.utxos.iter().find(|u| u.txid.eq_ignore_ascii_case(t) && u.vout == *v).cloned())
        .collect();
    lock(storage, &seat.coins, now_ms)?;
    all.push(seat.clone());
    save_seats(storage, &all)?;
    Ok(seat)
}

/// The provider answered: the seat's id.
pub fn seat_confirm(storage: &dyn LijStorage, seat_pk: &str, seat_id: &str) -> LijResult<()> {
    let mut all = seats(storage)?;
    let s = all.iter_mut().find(|s| s.seat_pk == seat_pk).ok_or_else(|| crate::error::LijError::Node("no such seat".into()))?;
    s.seat_id = seat_id.to_string();
    save_seats(storage, &all)
}

/// Leave (or the provider refused the seat, or removed it): the seat goes and its coins are freed — unless an unsettled
/// record names one (only its settlement frees it).
pub fn seat_drop(storage: &dyn LijStorage, seat_pk: &str) -> LijResult<Option<Seat>> {
    let mut all = seats(storage)?;
    let Some(i) = all.iter().position(|s| s.seat_pk == seat_pk) else { return Ok(None) };
    let gone = all.remove(i);
    save_seats(storage, &all)?;
    unlock(storage, &gone.coins)?;
    Ok(Some(gone))
}

// ── From Channel (v327 — v0.10 §3 Phase 1a: coins out of a channel by a cooperative close, then joining) ──

/// The storage key of the close-joins: sealed at rest, on this phone only (not in a backup — after a restore the close's
/// coin is an ordinary coin, which can join by hand).
pub const CLOSE_JOINS_KEY: &str = "tatara_close_joins";

/// A channel this phone is closing so that its coin joins a pool: the person's "Close channel and join". Once the close
/// is in a block, the page takes a seat with that coin in the `size` pool; the entry goes when the seat is taken, when
/// the person leaves before that, or when the coin cannot cover the pool.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CloseJoin {
    pub channel_id: String,
    pub provider_pk: String,
    pub endpoint: String,
    pub size: u64,
    pub payout: PayoutChoice,
    pub rate_at_join: u64,
    /// What the close was expected to pay (the card's figure until the coin is in a block).
    pub balance_sats: u64,
    pub since_ms: u64,
}

pub fn close_joins(storage: &dyn LijStorage) -> LijResult<Vec<CloseJoin>> {
    match storage.get(CLOSE_JOINS_KEY)? {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|e| LijError::Storage(format!("close-joins parse: {e}"))),
    }
}

fn save_close_joins(storage: &dyn LijStorage, all: &[CloseJoin]) -> LijResult<()> {
    if all.is_empty() {
        return storage.delete(CLOSE_JOINS_KEY);
    }
    let b = serde_json::to_vec(all).map_err(|e| LijError::Storage(format!("close-joins serialize: {e}")))?;
    storage.set(CLOSE_JOINS_KEY, &b)
}

/// "Close channel and join": one entry per channel, and — like a seat — one per pool size with a provider.
pub fn close_join_add(storage: &dyn LijStorage, cj: CloseJoin) -> LijResult<()> {
    let mut all = close_joins(storage)?;
    if all.iter().any(|x| x.channel_id == cj.channel_id) {
        return Err(LijError::Node("this channel is already closing into a pool".into()));
    }
    let taken = |size: u64, pk: &str| seats(storage).map(|v| v.iter().any(|s| s.size == size && s.provider_pk == pk));
    if all.iter().any(|x| x.size == cj.size && x.provider_pk == cj.provider_pk) || taken(cj.size, &cj.provider_pk)? {
        return Err(LijError::Node(format!("this wallet already has a seat for {} sats", cj.size)));
    }
    all.push(cj);
    save_close_joins(storage, &all)
}

pub fn close_join_drop(storage: &dyn LijStorage, channel_id: &str) -> LijResult<bool> {
    let mut all = close_joins(storage)?;
    let n = all.len();
    all.retain(|x| x.channel_id != channel_id);
    if all.len() == n {
        return Ok(false);
    }
    save_close_joins(storage, &all)?;
    Ok(true)
}

/// The coins every seat on this phone holds (for `reconcile`).
pub fn seat_coins(storage: &dyn LijStorage) -> LijResult<Vec<(String, u32)>> {
    Ok(seats(storage)?.into_iter().flat_map(|s| s.coins).collect())
}

pub fn seat_by_pk(storage: &dyn LijStorage, seat_pk: &str) -> LijResult<Seat> {
    seats(storage)?.into_iter().find(|s| s.seat_pk == seat_pk).ok_or_else(|| LijError::Node("no such seat on this phone".into()))
}

fn seat_key(seat: &Seat) -> LijResult<super::client::SeatKey> {
    let b = hex::decode(&seat.seat_secret_hex).map_err(|_| LijError::Key("seat secret".into()))?;
    let e: [u8; 32] = b.try_into().map_err(|_| LijError::Key("seat secret".into()))?;
    super::client::SeatKey::from_entropy(&e).map_err(|e| LijError::Key(e.to_string()))
}

/// 32 fresh bytes from the engine's random source (a seat's key, an attempt's every random byte, a signature's aux).
pub fn fresh32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// What Join shows before the person taps it (v0.10 §5.3, §8.7): what the chosen coins must cover at today's rate and
/// at the fee limit (1.5 × today's rate — the most the pool may cost, so the coin must cover that too), the fee on top
/// of the pool size, and the change that comes back (None: none, or too small — then it goes to the miners).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Quote {
    pub size: u64,
    pub coin_sats: u64,
    pub fee_sats: u64,
    pub change_sats: Option<u64>,
    /// The coins cover the pool at the fee limit.
    pub covers: bool,
    pub need_at_limit_sats: u64,
    pub peers: usize,
    pub fee_rate_sat_vb: u64,
    /// v327: with no change, what is left of the coin over the pool size and the fee goes to the miners — this much
    /// (v0.10 §5.3: "Change: none — 180 sats go to the miners"); 0 with change, or when the coin does not cover.
    pub to_miners_sats: u64,
    /// v327 (From Channel — v0.10 §3 Phase 1a, joinstr-fit-r4 C2): for a channel's close coin only — the balance range
    /// that covers the pool at the fee limit and leaves no change at today's rate ("bring this channel to between … and …
    /// sats first"); None when no balance does both, or for a coin already on-chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_change_band: Option<(u64, u64)>,
}

/// A P2WPKH script's shape (its size is what the fee counts).
fn p2wpkh_shape() -> bitcoin::ScriptBuf {
    let mut b = vec![0x00u8, 0x14];
    b.extend_from_slice(&[0u8; 20]);
    bitcoin::ScriptBuf::from_bytes(b)
}

pub fn quote(storage: &dyn LijStorage, root: &RootKey, size: u64, coins: &[(String, u32)], fee_rate_sat_vb: u64, peers: usize) -> LijResult<Quote> {
    let view = load_view(storage)?;
    let mut outs = Vec::with_capacity(coins.len());
    for (t, v) in coins {
        let u = view.utxos.iter().find(|u| u.txid.eq_ignore_ascii_case(t) && u.vout == *v)
            .ok_or_else(|| LijError::Node("a chosen coin is not in the wallet's ledger".into()))?;
        outs.push(super::wallet::coin_for_pool(root, u)?.1);
    }
    if outs.is_empty() {
        return Err(LijError::Node("choose a coin".into()));
    }
    let total: u64 = outs.iter().map(|o| o.value.to_sat()).sum();
    let spks: Vec<&bitcoin::Script> = outs.iter().map(|o| o.script_pubkey.as_script()).collect();
    quote_for(size, total, &spks, fee_rate_sat_vb, peers)
}

/// v327 (From Channel — Phase 1a's "coins out of a channel by a cooperative close sized to the pool, then joining"): the
/// Join quote for the coin a cooperative close of this channel will pay — `coin_sats`, the wallet's whole balance in the
/// channel (LiJ's channels are funded by the provider, which pays the close fee: the wallet's close output is exactly its
/// balance — joinstr-fit-r4 C2), to the wallet's own m/84 shutdown address (P2WPKH). With the band of balances that
/// cover the pool at the fee limit and leave no change at today's rate.
pub fn quote_close(size: u64, coin_sats: u64, fee_rate_sat_vb: u64, peers: usize) -> LijResult<Quote> {
    let shape = p2wpkh_shape();
    let spks = [shape.as_script()];
    let mut q = quote_for(size, coin_sats, &spks, fee_rate_sat_vb, peers)?;
    let e = |x: anyhow::Error| LijError::Node(x.to_string());
    let rate = q.fee_rate_sat_vb;
    let bare = super::rederive::member_need(size, peers, rate * 1000, &spks, None).map_err(e)?;
    let with = super::rederive::member_need(size, peers, rate * 1000, &spks, Some(shape.as_script())).map_err(e)?;
    // change exists from `with + max(dust, out_cost + 1)` on (rederive::my_change); below that, none
    let top = with + super::phone::CHANGE_DUST.max(with - bare + 1) - 1;
    let low = q.need_at_limit_sats;
    q.no_change_band = if low <= top { Some((low, top)) } else { None };
    Ok(q)
}

fn quote_for(size: u64, total: u64, spks: &[&bitcoin::Script], fee_rate_sat_vb: u64, peers: usize) -> LijResult<Quote> {
    let e = |x: anyhow::Error| LijError::Node(x.to_string());
    // the change script's size is a P2WPKH's (the pool's change goes to m/84) — any P2WPKH script will do here
    let change_spk = p2wpkh_shape();
    let rate = fee_rate_sat_vb.max(1);
    let limit = (rate.saturating_mul(3) / 2).max(rate);
    let bare_limit = super::rederive::member_need(size, peers, limit * 1000, spks, None).map_err(e)?;
    let need_now = super::rederive::member_need(size, peers, rate * 1000, spks, None).map_err(e)?;
    let change = if total >= need_now {
        super::rederive::my_change(total, size, peers, rate * 1000, spks, &change_spk, super::phone::CHANGE_DUST).map_err(e)?
    } else {
        None
    };
    let fee = match change {
        Some(c) => total - c - size,
        None => need_now.saturating_sub(size),
    };
    let to_miners_sats = if change.is_none() && total >= need_now { total - need_now } else { 0 };
    Ok(Quote { size, coin_sats: total, fee_sats: fee, change_sats: change, covers: total >= bare_limit, need_at_limit_sats: bare_limit, peers, fee_rate_sat_vb: rate, to_miners_sats, no_change_band: None })
}

/// v326 (step 8; v0.10 §8 rule 10): "Keep my coin out of this pool" — for a coin an unsettled record holds (this phone
/// signed; the funding never came): it is sent, alone, to a new address of this wallet's own (the next change address,
/// marked so nothing else takes it), which ends that attempt for good — the record then settles as "the coin went
/// elsewhere" and is wiped. A coin a seat on this phone holds is not kept out this way: leaving the seat frees it.
/// Returns the destination and a copy of the marks with those coins freed — for the one send that spends them; the
/// stored hold stays until the record is wiped.
pub fn keep_out_plan(storage: &dyn LijStorage, root: &RootKey, coins: &[(String, u32)]) -> LijResult<(String, u32, crate::tier2_wallet::CoinMarks)> {
    keep_out_check(storage, coins)?;
    let view = load_view(storage)?;
    let pending = load_pending(storage);
    let mut marks = load_marks(storage)?;
    let c = crate::tier2_wallet::next_change_index_marked(&view, &pending, &marks);
    let spk = crate::onchain_send::change_script(root, &bitcoin::secp256k1::Secp256k1::new(), root.network, c)?;
    let dest = bitcoin::Address::from_script(&spk, root.network).map_err(|e| LijError::Node(format!("{e}")))?.to_string();
    marks.mix_change.insert(c);
    save_marks(storage, &marks)?;
    let mut free = marks.clone();
    free.mix_unlock(coins);
    Ok((dest, c, free))
}

/// The coins "Keep my coin out" may take: named, each held by an unsettled record and not by a seat on this phone.
fn keep_out_check(storage: &dyn LijStorage, coins: &[(String, u32)]) -> LijResult<()> {
    if coins.is_empty() {
        return Err(LijError::Node("no coin named".into()));
    }
    let named = records::held_inputs(&records::load(storage)?);
    let seated: HashSet<(String, u32)> = seat_coins(storage)?.into_iter().map(|(t, v)| (t.to_ascii_lowercase(), v)).collect();
    for (t, v) in coins {
        let k = (t.to_ascii_lowercase(), *v);
        if seated.contains(&k) {
            return Err(LijError::Node("that coin holds a seat on the list — leave the seat to free it".into()));
        }
        if !named.contains(&k) {
            return Err(LijError::Node("that coin is not in a signed pool".into()));
        }
    }
    Ok(())
}

/// v327 (step 8): what "Keep my coin out of this pool" costs, for the sheet before the person confirms — the same checks
/// as keep_out_plan, nothing written: the coins' value, the fee for them alone to one address of this wallet's own (the
/// send's own arithmetic: onchain_send::coin_quote's one-output Max of exactly those coins), and what arrives.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct KeepOutQuote {
    pub coin_sats: u64,
    pub fee_sats: u64,
    pub arrives_sats: u64,
    pub sat_per_vb: u64,
}

pub fn keep_out_quote(storage: &dyn LijStorage, root: &RootKey, coins: &[(String, u32)], fee_rate_sat_per_kw: u32) -> LijResult<KeepOutQuote> {
    keep_out_check(storage, coins)?;
    let view = load_view(storage)?;
    let pending = load_pending(storage);
    let mut free = load_marks(storage)?;
    free.mix_unlock(coins);
    let pins: Vec<(String, u32)> = coins.iter().map(|(t, v)| (t.to_ascii_lowercase(), *v)).collect();
    let q = crate::onchain_send::coin_quote("", root.network, fee_rate_sat_per_kw, &view, &pending, &free, Some(&pins), None, false);
    if let Some(p) = q.problem {
        return Err(LijError::Node(p));
    }
    if q.max_sats < crate::onchain_send::DUST_THRESHOLD_SATS {
        return Err(LijError::Node(format!("at {} sat/vB the fee would take nearly all of this coin — try a lower fee", q.sat_per_vb)));
    }
    Ok(KeepOutQuote { coin_sats: q.chosen_sats, fee_sats: q.max_fee_sats, arrives_sats: q.max_sats, sat_per_vb: q.sat_per_vb })
}

// ── step 8: the provider's routes, from the seat's side ──

/// The body of POST /tatara/seat (v0.8's arrangement): the node key signs the seat message (`sign` — the wallet's
/// LND-compatible message signing).
pub fn seat_request(seat: &Seat, node_pubkey: &str, ts: u64, sign: &dyn Fn(&str) -> LijResult<String>) -> LijResult<serde_json::Value> {
    let sig = sign(&super::client::seat_message_v1(&seat.route, seat.size, &seat.seat_pk, ts))?;
    Ok(super::client::seat_body_v1(&seat.route, seat.size, &seat.seat_pk, node_pubkey, ts, &sig))
}

/// What a seat asks of its provider, signed by the seat key (client.rs): checkin, leave, pause, resume, open, report,
/// announce, backup.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct SeatAsk {
    pub action: String,
    #[serde(default)]
    pub attempt_id: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub announcement: String,
    #[serde(default)]
    pub funding_hex: String,
    #[serde(default)]
    pub exits: Vec<String>,
}

pub fn seat_body(seat: &Seat, ask: &SeatAsk, ts: u64) -> LijResult<serde_json::Value> {
    if seat.seat_id.is_empty() {
        return Err(LijError::Node("the seat has no id yet".into()));
    }
    let k = seat_key(seat)?;
    let aux = fresh32();
    let e = |x: anyhow::Error| LijError::Node(x.to_string());
    match ask.action.as_str() {
        "checkin" | "leave" | "pause" | "resume" => k.simple_body(&ask.action, &seat.seat_id, ts, &aux).map_err(e),
        "open" => Ok(k.open_body(&seat.seat_id, &ask.attempt_id, ts, &aux)),
        "report" => k.report_body(&seat.seat_id, &ask.attempt_id, &ask.outcome, ts, &aux).map_err(e),
        "announce" => Ok(k.announce_body(&seat.seat_id, &ask.attempt_id, &ask.announcement, ts, &aux)),
        "backup" => Ok(k.backup_body(&seat.seat_id, &ask.attempt_id, &ask.funding_hex, &ask.exits, ts, &aux)),
        other => Err(LijError::Node(format!("not a seat action: {other}"))),
    }
}

/// A provider's notice for this seat, checked against the provider's node key (the seat's provider, from its registry
/// record) — nothing in it is read before that holds.
pub fn read_notice(seat: &Seat, body: &str, sig: &str) -> LijResult<super::client::Notice> {
    let pk = bitcoin::secp256k1::PublicKey::from_slice(&hex::decode(&seat.provider_pk).map_err(|_| LijError::Key("provider key".into()))?)
        .map_err(|_| LijError::Key("provider key".into()))?;
    super::client::verify_notice(&pk, &seat.seat_id, body, sig).map_err(|e| LijError::Node(e.to_string()))
}

/// What the provider's start message and its record give an attempt.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct AttemptStart {
    pub seat_pk: String,
    pub attempt_id: String,
    pub size: u64,
    pub peers: usize,
    pub relay: String,
    /// The provider's declared sizes and fee-rate cap (its registry record).
    pub sizes: Vec<u64>,
    pub max_fee_sat_vb: u64,
    /// Coins of sessions that stalled or misbehaved in an earlier try.
    #[serde(default)]
    pub refused: Vec<(String, u32)>,
}

/// An attempt's start for this phone: the seat's coins from the ledger (unspent; their keys as joinstr takes them), a
/// NEW payout and change handed out and marked (§8 rules 0 and 1 — a retry gets new ones too), the tip, 32 fresh bytes.
/// v332: the third value is a note for the Mix log when the ledger's coin list lacked a coin at that moment and the
/// seat's own copy of its row was used (a rebuild or a reorg rollback was rewriting the list); None otherwise.
pub fn attempt_common(storage: &dyn LijStorage, root: &RootKey, st: &AttemptStart, now: u64) -> LijResult<(Seat, super::phone::Common, Option<String>)> {
    let seat = seat_by_pk(storage, &st.seat_pk)?;
    if st.size != seat.size {
        return Err(LijError::Node("the start is for another size than this seat".into()));
    }
    let view = load_view(storage)?;
    let mut coins = Vec::with_capacity(seat.coins.len());
    let mut from_copy = 0usize;
    for (t, v) in &seat.coins {
        let row = |us: &[crate::tier2_wallet::OnchainUtxo]| us.iter().find(|u| u.txid.eq_ignore_ascii_case(t) && u.vout == *v).cloned();
        let u = match row(&view.utxos) {
            Some(u) => u,
            None => {
                from_copy += 1;
                row(&seat.coin_rows).ok_or_else(|| LijError::Node("the seat's coin is not in the wallet's ledger".into()))?
            }
        };
        coins.push(super::wallet::coin_for_pool(root, &u)?);
    }
    let note = (from_copy > 0).then(|| format!("the wallet's ledger is being rewritten and did not list {} of this seat's coins just now — the seat's own copy was used", from_copy));
    // Phase 1b (v0.10 §6.2): a channel seat brings no payout — the channel opened after registration is the payout; only
    // the change is handed out (and marked) here
    let channel = seat.route == "channel";
    let h = if channel { hand_out_change(storage, root)? } else { hand_out(storage, root, &seat.payout)? };
    let payout = if channel { None } else { Some(bitcoin::ScriptBuf::from_bytes(hex::decode(&h.payout_spk_hex).map_err(|_| LijError::Node("payout".into()))?)) };
    let change_spk = bitcoin::ScriptBuf::from_bytes(hex::decode(&h.change_spk_hex).map_err(|_| LijError::Node("change".into()))?);
    let mut refused = Vec::with_capacity(st.refused.len());
    for (t, v) in &st.refused {
        refused.push(bitcoin::OutPoint { txid: t.parse().map_err(|_| LijError::Node("a refused coin's txid".into()))?, vout: *v });
    }
    let network = match root.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        _ => "regtest",
    };
    let c = super::phone::Common {
        attempt_id: st.attempt_id.clone(),
        declared: super::caps::Declared { sizes: st.sizes.clone(), max_fee_sat_vb: st.max_fee_sat_vb, relay: st.relay.clone(), network: network.into(), max_timeout_s: super::phone::POOL_TIMEOUT_S },
        size: st.size,
        peers: st.peers,
        coins,
        payout,
        payout_index: h.payout_index,
        change_spk,
        change_index: h.change_index,
        tip: view.cursor.scanned_to,
        rate_at_join: seat.rate_at_join,
        entropy: fresh32(),
        now,
        refused,
        network: root.network,
        public: false,
    };
    Ok((seat, c, note))
}

/// The seat's secret key (to open its copy of the pool's key).
pub fn seat_secret(seat: &Seat) -> LijResult<bitcoin::secp256k1::SecretKey> {
    Ok(seat_key(seat)?.secret())
}

/// After every step of an attempt: a record asked for is written (sealed) BEFORE the phone is told it is saved (§8 rule
/// 3) — and so before its funding signature; a stop before this phone's signature wipes its record at once (§9 rule 3).
/// Returns the merged Out and whether the backup must be uploaded (a record written or wiped).
pub fn after(storage: &dyn LijStorage, phone: &mut super::phone::Phone, mut out: super::phone::Out, now: u64) -> LijResult<(super::phone::Out, bool)> {
    let mut dirty = false;
    let mut guard = 0;
    while let Some(rec) = out.save.take() {
        guard += 1;
        if guard > 3 { break; }
        record_save(storage, rec, now.saturating_mul(1000))?;
        dirty = true;
        let o2 = phone.record_saved(now).map_err(|e| LijError::Node(e.to_string()))?;
        out.merge(o2);
    }
    if out.stopped.as_ref().map(|s| s.wipe_record).unwrap_or(false) {
        if record_wipe(storage, phone.record_id())? { dirty = true; }
    }
    Ok((out, dirty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2_wallet::{save_view, OnchainUtxo, Tier2View};
    use bip39::Mnemonic;
    use bitcoin::Network;
    use std::str::FromStr;
    use std::sync::Mutex;

    struct Mem(Mutex<std::collections::HashMap<String, Vec<u8>>>);
    impl LijStorage for Mem {
        fn get(&self, k: &str) -> LijResult<Option<Vec<u8>>> { Ok(self.0.lock().unwrap().get(k).cloned()) }
        fn set(&self, k: &str, v: &[u8]) -> LijResult<()> { self.0.lock().unwrap().insert(k.into(), v.to_vec()); Ok(()) }
        fn delete(&self, k: &str) -> LijResult<()> { self.0.lock().unwrap().remove(k); Ok(()) }
        fn list_with_prefix(&self, p: &str) -> LijResult<Vec<String>> { Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(p)).cloned().collect()) }
    }

    fn root() -> RootKey {
        RootKey::from_mnemonic(&Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap(), Network::Bitcoin).unwrap()
    }

    fn rec(id: &str, coin: &str) -> StoredRecord {
        StoredRecord { id: id.into(), funding_hex: String::new(), exits_hex: vec![], payout_spk_hex: String::new(), payout_index: Some(0), inputs: vec![(coin.into(), 0)], saved_ms: 1, change_spk_hex: None, change_index: None, channel: false, rate_sat_vb: None }
    }

    #[test]
    fn s1_hand_out_marks_the_payout_and_the_change_together() {
        let st = Mem(Mutex::new(Default::default()));
        save_view(&st, &Tier2View::default()).unwrap();
        let r = root();
        let h = hand_out(&st, &r, &PayoutChoice::ThisWallet).unwrap();
        assert_eq!((h.payout_index, h.change_index), (Some(0), 0));
        assert_eq!(h.payout_address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        let h2 = hand_out(&st, &r, &PayoutChoice::ThisWallet).unwrap();
        assert_eq!((h2.payout_index, h2.change_index), (Some(1), 1), "saved: a retry gets new ones");
        let m = load_marks(&st).unwrap();
        assert!(m.mix_exits.contains(&1) && m.mix_change.contains(&1));
    }

    /// v329 (DP 2026-10-13 17:12): a saved record puts the pool among the sends still confirming — the funding (this
    /// phone's coin reserved, its change back, kind Mix) and the exit that pays this phone (received, kind Mix) — the
    /// record's view names the pool's transactions, a record's own funding row is not a keep-out, and the rows go with
    /// the record (wiped) or at once when the coin is kept out.
    #[test]
    fn s1b_a_saved_record_shows_the_pool_among_the_sends_still_confirming_until_it_settles() {
        use crate::tier2_wallet::{load_pending, summary, CoinMarks, TxDirection, TxKind};
        let st = Mem(Mutex::new(Default::default()));
        let (mut r, funding, e1) = records::tests::fixture(Some(4));
        // the ledger holds my coin aa:0 (299,000 sats, m/84 receive) and the funding pays 1,000 sats of change to my change script
        let change_spk = bitcoin::ScriptBuf::from_bytes(hex::decode(format!("0014{}", "77".repeat(20))).unwrap());
        let mut f2 = funding.clone();
        f2.output.push(bitcoin::TxOut { value: bitcoin::Amount::from_sat(1_000), script_pubkey: change_spk.clone() });
        r.funding_hex = bitcoin::consensus::encode::serialize_hex(&f2);
        r.change_spk_hex = Some(hex::encode(change_spk.as_bytes()));
        r.change_index = Some(9);
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 900_010;
        view.utxos.push(OnchainUtxo { chain: crate::tier2::CHAIN_RECEIVE, index: 0, txid: "aa".repeat(32), vout: 0, value_sats: 299_000, height: 900_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        record_save(&st, r.clone(), 5).unwrap();
        let p = load_pending(&st);
        assert_eq!(p.len(), 2, "the funding and my exit");
        let f = p.iter().find(|p| p.txid == f2.compute_txid().to_string()).expect("the funding row");
        assert_eq!((f.kind, f.direction, f.delta_sats, f.spent_outpoints.clone()), (TxKind::Mix, TxDirection::SelfTransfer, -298_000, vec![("aa".repeat(32), 0)]));
        assert_eq!((f.change_outpoint.clone(), f.change_value_sats, f.change_index, f.raw_tx_hex.clone()), (Some((f2.compute_txid().to_string(), 1)), 1_000, 9, None));
        let e = p.iter().find(|p| p.txid == e1.compute_txid().to_string()).expect("my exit's row");
        assert_eq!((e.kind, e.direction, e.delta_sats, e.spent_outpoints.len()), (TxKind::Mix, TxDirection::Received, 99_000, 0));
        let s = summary(&view, &p, 900_010, &CoinMarks::default());
        assert_eq!((s.reserved_sats, s.spendable_sats), (299_000, 1_000), "the coin is reserved at once; the change counts");
        let v = records_view(&st, Network::Bitcoin).unwrap().remove(0);
        assert_eq!(v.state, "waiting", "the record's own funding row is not a keep-out");
        assert_eq!((v.funding_txid, v.exit_txids.len(), v.my_exit_txid, v.my_exit_vout, v.change_sats), (f2.compute_txid().to_string(), 2, e1.compute_txid().to_string(), 0, 1_000));
        assert_eq!(v.payout_address, "bc1pg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zq8ss0kf", "the payout's address (the fixture's 44…44 key; bech32m checked by hand)");
        // a wallet send that spends the coin elsewhere IS a keep-out, and drops the pool's rows at once
        assert_eq!(drop_pool_rows_for(&st, &[("AA".repeat(32), 0)]).unwrap(), 1);
        assert!(load_pending(&st).is_empty(), "the pool's rows are gone");
        record_save(&st, r.clone(), 6).unwrap();
        assert_eq!(load_pending(&st).len(), 2);
        assert!(record_wipe(&st, "att-1").unwrap());
        assert!(load_pending(&st).is_empty(), "wiped with the record");
        // a record whose bytes do not parse puts no rows
        record_save(&st, rec("att-x", "bb"), 7).unwrap();
        assert!(load_pending(&st).is_empty());
        // Phase 1b: a channel record puts the funding row only (the exit pays the channel, not the ledger), and its
        // view names the channel
        let mut rc = r.clone(); rc.id = "att-c".into(); rc.channel = true;
        record_save(&st, rc.clone(), 8).unwrap();
        let p = load_pending(&st);
        assert_eq!((p.len(), p[0].txid.clone(), p[0].kind), (1, f2.compute_txid().to_string(), TxKind::Mix), "the funding row alone");
        let v = records_view(&st, Network::Bitcoin).unwrap().into_iter().find(|v| v.id == "att-c").unwrap();
        assert_eq!(v.channel_id, rc.channel_id());
        assert!(v.channel_id.is_some());
        assert!(record_wipe(&st, "att-c").unwrap() && load_pending(&st).is_empty());
    }

    #[test]
    fn s2_a_records_coins_stay_held_until_it_is_wiped_and_leaving_frees_only_the_rest() {
        let st = Mem(Mutex::new(Default::default()));
        lock(&st, &[("aa".into(), 0), ("bb".into(), 0)], 1).unwrap();
        record_save(&st, rec("att-1", "aa"), 2).unwrap();
        assert_eq!(unlock(&st, &[("AA".into(), 0), ("bb".into(), 0)]).unwrap(), vec![("bb".to_string(), 0)]);
        let m = load_marks(&st).unwrap();
        assert!(m.is_mix_locked("aa", 0) && !m.is_mix_locked("bb", 0), "the record's coin stays held");
        assert!(record_wipe(&st, "att-1").unwrap());
        assert!(!load_marks(&st).unwrap().is_mix_locked("aa", 0));
        assert!(st.get(records::RECORDS_KEY).unwrap().is_none());
        assert!(!record_wipe(&st, "att-1").unwrap());
    }

    #[test]
    fn s3_after_a_restore_the_holds_are_the_records_and_this_phones_seats_only() {
        let st = Mem(Mutex::new(Default::default()));
        // a restored copy: marks hold a waiting-list coin (its seat stayed on the lost phone) and a record's coin lost its hold
        lock(&st, &[("cc".into(), 0)], 1).unwrap();
        records::put(&st, rec("att-1", "aa")).unwrap();
        assert_eq!(reconcile(&st, &[], 5).unwrap(), (vec![("cc".to_string(), 0)], vec![("aa".to_string(), 0)]));
        // a seat on this phone keeps its coin
        lock(&st, &[("dd".into(), 1)], 6).unwrap();
        assert_eq!(reconcile(&st, &[("DD".into(), 1)], 7).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn s5_a_seat_holds_its_coins_until_it_is_dropped_and_its_secret_stays_on_this_phone() {
        let st = Mem(Mutex::new(Default::default()));
        let seat = Seat { seat_id: "x".into(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02aa".into(), endpoint: "https://lsp.example".into(), size: 100_000, route: "chain".into(), coins: vec![("aa".repeat(32), 0)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
        let s = seat_new(&st, seat.clone(), &[7u8; 32], 5).unwrap();
        assert_eq!(s.seat_pk, super::super::client::SeatKey::from_entropy(&[7u8; 32]).unwrap().pk_hex());
        assert_eq!((s.seat_id.as_str(), s.since_ms), ("", 5));
        assert!(load_marks(&st).unwrap().is_mix_locked(&"aa".repeat(32), 0), "held from Join");
        assert!(seat_new(&st, seat.clone(), &[8u8; 32], 6).is_err(), "one seat per size");
        let mut other = seat.clone(); other.size = 50_000;
        assert!(seat_new(&st, other, &[8u8; 32], 6).unwrap_err().to_string().contains("already in a Mix pool"));
        seat_confirm(&st, &s.seat_pk, "seat-9").unwrap();
        assert_eq!(seats(&st).unwrap()[0].seat_id, "seat-9");
        assert_eq!(seat_coins(&st).unwrap(), vec![("aa".repeat(32), 0)]);
        assert_eq!(reconcile(&st, &seat_coins(&st).unwrap(), 9).unwrap(), (vec![], vec![]), "a seat on this phone keeps its hold");
        assert!(seat_drop(&st, &s.seat_pk).unwrap().is_some());
        assert!(!load_marks(&st).unwrap().is_mix_locked(&"aa".repeat(32), 0), "freed on leaving");
        assert!(st.get(SEATS_KEY).unwrap().is_none());
        // the seat store is sealed at rest and never in a backup
        assert!(crate::tier2_wallet::ENCRYPTED_KEYS.contains(&SEATS_KEY));
        assert!(!crate::node::BUNDLE_SINGLE_KEYS.contains(&SEATS_KEY));
    }

    /// v332: the seat took a copy of its coin's row when it was taken; with the ledger's list emptied (a rebuild in
    /// progress) a start still has the coin, and says so; with the row back, no note; a seat without the copy (taken
    /// before v332) fails as before.
    #[test]
    fn s6b_the_seats_coin_copy_outlives_a_ledger_rewrite() {
        const NOW: u64 = 1_800_000_000;
        let root = RootKey::generate(Network::Bitcoin).unwrap().0;
        let st = Mem(Mutex::new(Default::default()));
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 970_000;
        let txid = "1f".repeat(32);
        view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: txid.clone(), vout: 1, value_sats: 130_000, height: 969_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        let seat = Seat { seat_id: String::new(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02".to_string() + &"11".repeat(32), endpoint: "https://lsp.example".into(), size: 100_000, route: "chain".into(), coins: vec![(txid.clone(), 1)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
        let s = seat_new(&st, seat, &fresh32(), 1).unwrap();
        assert_eq!((s.coin_rows.len(), s.coin_rows[0].txid.as_str(), s.coin_rows[0].value_sats), (1, txid.as_str(), 130_000), "the row rides with the seat");
        let start = AttemptStart { seat_pk: s.seat_pk.clone(), attempt_id: "att-1".into(), size: 100_000, peers: 3, relay: "wss://lsp.example/tatara/relay".into(), sizes: vec![100_000], max_fee_sat_vb: 20, refused: vec![] };
        let mut empty = view.clone(); empty.utxos.clear(); save_view(&st, &empty).unwrap();
        let (seat, c, note) = attempt_common(&st, &root, &start, NOW).unwrap();
        assert_eq!(c.coins.len(), 1);
        assert_eq!(c.coins[0].1.value.to_sat(), 130_000);
        assert!(note.as_deref().unwrap_or("").contains("did not list 1 of this seat's coins"), "{note:?}");
        let mut all = seats(&st).unwrap(); all[0].coin_rows.clear(); save_seats(&st, &all).unwrap();
        assert!(attempt_common(&st, &root, &start, NOW).err().map(|e| e.to_string()).unwrap_or_default().contains("not in the wallet's ledger"));
        all[0].coin_rows = seat.coin_rows.clone(); save_seats(&st, &all).unwrap();
        save_view(&st, &view).unwrap();
        let (_, _, note) = attempt_common(&st, &root, &start, NOW).unwrap();
        assert!(note.is_none());
        // an older seat store (no coin_rows field) still parses
        let old = serde_json::to_string(&all).unwrap().replace("\"coin_rows\":[", "\"coin_rows_was\":[");
        let parsed: Vec<Seat> = serde_json::from_str(&old).unwrap();
        assert!(parsed[0].coin_rows.is_empty());
    }

    // Step 8: three wallets, each with its own storage, from Join to the complete funding and then to settlement — the
    // seats, the holds, the attempt's start from the ledger, the announcement, the records written before the signatures,
    // and the settle pass wiping each record once its payout is 6 deep.
    #[test]
    fn s6_three_wallets_from_join_to_settlement() {
        use super::super::phone::{Out, Phone};
        use std::collections::VecDeque;
        const NOW: u64 = 1_800_000_000;
        let roots: Vec<RootKey> = (0..3).map(|_| RootKey::generate(Network::Bitcoin).unwrap().0).collect();
        let stores: Vec<Mem> = (0..3).map(|_| Mem(Mutex::new(Default::default()))).collect();
        let mut seat_pks = Vec::new();
        for i in 0..3 {
            let mut view = Tier2View::default();
            view.cursor.scanned_to = 970_000;
            let txid = format!("{:02x}", 0x10 + i).repeat(32);
            view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: txid.clone(), vout: 1, value_sats: 130_000, height: 969_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
            save_view(&stores[i], &view).unwrap();
            let seat = Seat { seat_id: String::new(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02".to_string() + &"11".repeat(32), endpoint: "https://lsp.example".into(), size: 100_000, route: "chain".into(), coins: vec![(txid, 1)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
            let s = seat_new(&stores[i], seat, &fresh32(), 1).unwrap();
            seat_confirm(&stores[i], &s.seat_pk, &format!("seat-{i}")).unwrap();
            seat_pks.push(s.seat_pk);
        }
        let start = |i: usize| AttemptStart { seat_pk: seat_pks[i].clone(), attempt_id: "att-1".into(), size: 100_000, peers: 3, relay: "wss://lsp.example/tatara/relay".into(), sizes: vec![100_000], max_fee_sat_vb: 20, refused: vec![] };
        let (_, c0, _) = attempt_common(&stores[0], &roots[0], &start(0), NOW).unwrap();
        let (creator, ann, o0) = Phone::create(c0, 2, &seat_pks[1..].to_vec()).unwrap();
        let mut phones = vec![creator];
        let mut outs: Vec<(usize, Out)> = vec![(0, o0)];
        for i in 1..3 {
            let (seat, c, _) = attempt_common(&stores[i], &roots[i], &start(i), NOW).unwrap();
            let (p, o) = Phone::join(c, &ann, &seat_secret(&seat).unwrap()).unwrap();
            phones.push(p);
            outs.push((i, o));
        }
        let mut queue: VecDeque<(usize, String)> = VecDeque::new();
        let mut complete = vec![None; 3];
        let mut dirty = vec![false; 3];
        let mut pending: VecDeque<(usize, Out)> = outs.into_iter().collect();
        let mut steps = 0;
        loop {
            while let Some((i, o)) = pending.pop_front() {
                let (o, d) = after(&stores[i], &mut phones[i], o, NOW).unwrap();
                dirty[i] |= d;
                assert!(o.stopped.is_none(), "phone {i} stopped: {:?}", o.stopped);
                for e in o.relay.iter().chain(o.payout.iter()) { for j in 0..3 { queue.push_back((j, e.clone())); } }
                for c in &o.checks { let r = phones[i].coin_result(&c.txid, c.vout, Some(true), NOW).unwrap(); pending.push_back((i, r)); }
                if o.complete.is_some() { complete[i] = o.complete.clone(); }
            }
            let Some((j, e)) = queue.pop_front() else { break };
            steps += 1;
            assert!(steps < 100_000);
            let o = phones[j].relay_event(&e, NOW).unwrap();
            pending.push_back((j, o));
        }
        let c = complete[0].clone().expect("the funding completes");
        assert!(complete.iter().all(|x| x.as_ref() == Some(&c)));
        let funding: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&c.funding_hex).unwrap();
        for i in 0..3 {
            assert!(dirty[i], "a record written is an upload trigger");
            let recs = records::load(&stores[i]).unwrap();
            assert_eq!(recs.len(), 1, "wallet {i}: its record, written before its signature");
            assert_eq!(recs[0].id, phones[i].record_id());
            assert_eq!(records_view(&stores[i], Network::Bitcoin).unwrap()[0].size, 100_000, "the Confirming card's size: the payout's own value");
            let m = load_marks(&stores[i]).unwrap();
            assert!(m.mix_exits.contains(&0) && m.mix_change.contains(&0), "the payout and the change marked");
            assert!(m.is_mix_locked(&format!("{:02x}", 0x10 + i).repeat(32), 1), "the coin held through the attempt");
            // the chain: the funding spends the coin; the exit pays the payout at m/86 #0, 6 deep
            let mut view = load_view(&stores[i]).unwrap();
            view.utxos[0].spent_height = Some(970_001);
            view.utxos[0].spent_txid = Some(funding.compute_txid().to_string());
            let payout = crate::bip86::address_at(&roots[i], 0, 0).unwrap().0.script_pubkey();
            let exits: Vec<bitcoin::Transaction> = c.exits_hex.iter().map(|h| bitcoin::consensus::encode::deserialize_hex(h).unwrap()).collect();
            let (ex, vout) = exits.iter().find_map(|t| t.output.iter().position(|o| o.script_pubkey == payout).map(|v| (t, v as u32))).expect("this wallet's payout");
            view.utxos.push(OnchainUtxo { chain: crate::tier2::CHAIN_BIP86, index: 0, txid: ex.compute_txid().to_string(), vout, value_sats: 100_000, height: 970_002, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
            view.cursor.scanned_to = 970_006;
            save_view(&stores[i], &view).unwrap();
            let rep = settle_pass(&stores[i], &|_| None).unwrap();
            assert_eq!(rep.send.len(), 1, "5 deep: the exits are still sent");
            view.cursor.scanned_to = 970_007;
            save_view(&stores[i], &view).unwrap();
            let rep = settle_pass(&stores[i], &|_| None).unwrap();
            assert_eq!(rep.wiped.len(), 1, "6 deep: settled");
            assert!(stores[i].get(records::RECORDS_KEY).unwrap().is_none(), "wiped fully");
            let m = load_marks(&stores[i]).unwrap();
            assert!(!m.mix_exits.is_empty(), "the Mixed mark is kept");
            assert!(!m.is_mix_locked(&format!("{:02x}", 0x10 + i).repeat(32), 1), "settled: the hold is gone");
        }
    }

    #[test]
    fn s7_the_join_quote_is_the_pool_size_plus_the_fee_and_the_coin_must_cover_the_limit() {
        let st = Mem(Mutex::new(Default::default()));
        let r = root();
        let mut view = Tier2View::default();
        view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: "aa".repeat(32), vout: 0, value_sats: 130_000, height: 1, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        view.utxos.push(OnchainUtxo { chain: 0, index: 1, txid: "bb".repeat(32), vout: 0, value_sats: 100_500, height: 1, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        let q = quote(&st, &r, 100_000, &[("aa".repeat(32), 0)], 2, 6).unwrap();
        assert!(q.covers);
        assert_eq!(q.coin_sats, 130_000);
        assert_eq!(q.fee_sats + q.size + q.change_sats.unwrap(), 130_000, "the coin = the pool size + the fee + the change");
        let need = super::super::rederive::member_need(100_000, 6, 2_000, &[p2wpkh_shape().as_script()], Some(p2wpkh_shape().as_script())).unwrap();
        assert_eq!(q.fee_sats, need - 100_000, "the fee is the engine's own arithmetic");
        // a coin just over the pool size covers today's fee but not the limit's: Join says it cannot
        let q2 = quote(&st, &r, 100_000, &[("bb".repeat(32), 0)], 2, 6).unwrap();
        assert!(!q2.covers && q2.change_sats.is_none());
        assert!(quote(&st, &r, 100_000, &[], 2, 6).is_err());
    }

    #[test]
    fn s8_keep_out_takes_only_a_signed_pools_coin_to_a_new_address_of_this_wallet() {
        let st = Mem(Mutex::new(Default::default()));
        let r = root();
        save_view(&st, &Tier2View::default()).unwrap();
        // a seat's coin: leave the seat instead
        let seat = Seat { seat_id: "x".into(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02aa".into(), endpoint: "https://lsp.example".into(), size: 100_000, route: "chain".into(), coins: vec![("aa".repeat(32), 0)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
        seat_new(&st, seat, &[7u8; 32], 5).unwrap();
        assert!(keep_out_plan(&st, &r, &[("aa".repeat(32), 0)]).unwrap_err().to_string().contains("leave the seat"));
        // a coin no pool holds
        assert!(keep_out_plan(&st, &r, &[("bb".repeat(32), 0)]).unwrap_err().to_string().contains("not in a signed pool"));
        // a signed pool's coin: the next change address, marked; the copy frees the coin, the store keeps the hold
        record_save(&st, rec("att-1", &"cc".repeat(32)), 1).unwrap();
        let (dest, c, free) = keep_out_plan(&st, &r, &[("cc".repeat(32), 0)]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c, 0);
        assert!(dest.starts_with("bc1q"));
        assert!(!free.is_mix_locked(&"cc".repeat(32), 0) && load_marks(&st).unwrap().is_mix_locked(&"cc".repeat(32), 0));
        assert!(load_marks(&st).unwrap().mix_change.contains(&0), "the address is not handed out again");
        let (_, c2, _) = keep_out_plan(&st, &r, &[("cc".repeat(32), 0)]).unwrap();
        assert_eq!(c2, 1);
    }

    /// A funding-shaped transaction spending one coin (its txid is what the ledger names as the spender).
    fn spending(txid: &str, vout: u32) -> bitcoin::Transaction {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};
        bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_str(txid).unwrap(), vout }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: ScriptBuf::new() }],
        }
    }

    fn pending_spend(st: &Mem, txid: &str, vout: u32) {
        crate::tier2_wallet::record_pending(st, crate::tier2_wallet::PendingTx {
            txid: "ee".repeat(32), spent_outpoints: vec![(txid.into(), vout)], delta_sats: -220,
            direction: crate::tier2_wallet::TxDirection::SelfTransfer, kind: crate::tier2_wallet::TxKind::Onchain,
            created_at_ms: 1, change_outpoint: None, change_value_sats: 0, change_index: 0, broadcast_seen: false,
            raw_tx_hex: None, dest_addr: None, dest_sats: Some(129_780), fee_sats: Some(220), fee_rate_sat_per_kw: Some(500), dests: Vec::new(),
        }).unwrap();
    }

    #[test]
    fn s9_a_records_card_knows_its_coins_and_whether_the_pool_or_this_wallet_took_them() {
        let coin = "cc".repeat(32);
        let funding = spending(&coin, 0);
        let mut r = rec("att-1", &coin);
        r.funding_hex = bitcoin::consensus::encode::serialize_hex(&funding);
        let with = |spent_by: Option<String>, sending: bool| {
            let st = Mem(Mutex::new(Default::default()));
            let mut view = Tier2View::default();
            view.cursor.scanned_to = 970_000;
            view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: coin.clone(), vout: 0, value_sats: 130_000, height: 969_000, spent_height: spent_by.as_ref().map(|_| 969_990), spent_txid: spent_by, sp_tweak: None, sp_label: None });
            save_view(&st, &view).unwrap();
            records::put(&st, r.clone()).unwrap();
            if sending { pending_spend(&st, &coin, 0); }
            records_view(&st, Network::Bitcoin).unwrap().remove(0)
        };
        let v = with(None, false);
        assert_eq!((v.state, v.coin_sats, v.inputs.clone()), ("waiting", 130_000, vec![(coin.clone(), 0)]), "nothing seen: the coin stays held; Keep my coin out is offered");
        assert_eq!(with(None, true).state, "kept_out", "this wallet's own send still confirming");
        assert_eq!(with(Some("dd".repeat(32)), false).state, "kept_out", "spent by this wallet's send, in a block");
        assert_eq!(with(Some(funding.compute_txid().to_string()), false).state, "funded", "the pool's funding spent it");
        let empty = Mem(Mutex::new(Default::default()));
        assert!(records_view(&empty, Network::Bitcoin).unwrap().is_empty(), "no records: the ledger is not read");
    }

    #[test]
    fn s10_the_keep_out_quote_is_the_sends_own_arithmetic_and_writes_nothing() {
        let st = Mem(Mutex::new(Default::default()));
        let r = root();
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 970_000;
        view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: "cc".repeat(32), vout: 0, value_sats: 130_000, height: 969_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        view.utxos.push(OnchainUtxo { chain: 0, index: 1, txid: "aa".repeat(32), vout: 0, value_sats: 50_000, height: 969_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        let seat = Seat { seat_id: "x".into(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02aa".into(), endpoint: "https://lsp.example".into(), size: 100_000, route: "chain".into(), coins: vec![("aa".repeat(32), 0)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
        seat_new(&st, seat, &[7u8; 32], 5).unwrap();
        assert!(keep_out_quote(&st, &r, &[("aa".repeat(32), 0)], 500).unwrap_err().to_string().contains("leave the seat"));
        assert!(keep_out_quote(&st, &r, &[("bb".repeat(32), 0)], 500).unwrap_err().to_string().contains("not in a signed pool"));
        record_save(&st, rec("att-1", &"cc".repeat(32)), 1).unwrap();
        let q = keep_out_quote(&st, &r, &[("cc".repeat(32), 0)], 500).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((q.coin_sats, q.fee_sats, q.arrives_sats, q.sat_per_vb), (130_000, (11 + 68 + 31) * 2, 130_000 - 220, 2), "one coin alone, one output");
        let m = load_marks(&st).unwrap();
        assert!(m.mix_change.is_empty() && m.is_mix_locked(&"cc".repeat(32), 0), "nothing written: no address handed out, the hold kept");
        assert!(keep_out_quote(&st, &r, &[("cc".repeat(32), 0)], 250 * 1300).unwrap_err().to_string().contains("try a lower fee"), "a fee that eats the coin is refused in words");
    }

    #[test]
    fn s11_a_channels_close_coin_is_quoted_as_the_p2wpkh_coin_it_becomes_with_its_no_change_band() {
        let st = Mem(Mutex::new(Default::default()));
        let r = root();
        let mut view = Tier2View::default();
        view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: "aa".repeat(32), vout: 0, value_sats: 130_000, height: 1, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        let on_chain = quote(&st, &r, 100_000, &[("aa".repeat(32), 0)], 2, 6).unwrap();
        let close = quote_close(100_000, 130_000, 2, 6).unwrap();
        assert_eq!((close.fee_sats, close.change_sats, close.covers, close.need_at_limit_sats), (on_chain.fee_sats, on_chain.change_sats, on_chain.covers, on_chain.need_at_limit_sats), "the same arithmetic as the m/84 coin the close pays");
        assert!(on_chain.no_change_band.is_none(), "a coin already on-chain has no band");
        let (low, top) = close.no_change_band.expect("a band at 2 sat/vB");
        let at = |v: u64| quote_close(100_000, v, 2, 6).unwrap();
        assert!(at(low).covers && at(low).change_sats.is_none(), "the band's bottom covers the limit, no change");
        assert!(at(top).change_sats.is_none() && at(top + 1).change_sats.is_some(), "the band's top: one sat more makes change");
        assert!(!at(low - 1).covers, "below the band: the limit is not covered");
        assert_eq!(at(top).fee_sats + at(top).to_miners_sats + 100_000, top, "inside the band: the pool size, the fee, and the rest to the miners — named");
        assert_eq!((close.to_miners_sats, at(low).to_miners_sats + at(low).fee_sats + 100_000), (0, low), "with change nothing is lost; at the bottom the leftover is named too");
    }

    #[test]
    fn s12_a_close_join_is_one_per_channel_and_one_per_size_sealed_on_this_phone_only() {
        let st = Mem(Mutex::new(Default::default()));
        let cj = |id: &str, size: u64| CloseJoin { channel_id: id.into(), provider_pk: "02aa".into(), endpoint: "https://lsp.example".into(), size, payout: PayoutChoice::ThisWallet, rate_at_join: 2, balance_sats: 130_000, since_ms: 1 };
        close_join_add(&st, cj("ch1", 100_000)).unwrap();
        assert!(close_join_add(&st, cj("ch1", 50_000)).unwrap_err().to_string().contains("already closing"));
        assert!(close_join_add(&st, cj("ch2", 100_000)).unwrap_err().to_string().contains("already has a seat"));
        let seat = Seat { seat_id: "x".into(), seat_secret_hex: String::new(), seat_pk: String::new(), provider_pk: "02aa".into(), endpoint: "https://lsp.example".into(), size: 50_000, route: "chain".into(), coins: vec![("aa".repeat(32), 0)], coin_rows: vec![], payout: PayoutChoice::ThisWallet, rate_at_join: 2, since_ms: 0 };
        seat_new(&st, seat, &[7u8; 32], 5).unwrap();
        assert!(close_join_add(&st, cj("ch2", 50_000)).unwrap_err().to_string().contains("already has a seat"), "a seat of that size counts");
        assert_eq!(close_joins(&st).unwrap(), vec![cj("ch1", 100_000)]);
        assert!(close_join_drop(&st, "ch1").unwrap() && !close_join_drop(&st, "ch1").unwrap());
        assert!(st.get(CLOSE_JOINS_KEY).unwrap().is_none(), "none left: the key is gone");
        assert!(crate::tier2_wallet::ENCRYPTED_KEYS.contains(&CLOSE_JOINS_KEY), "sealed at rest");
        assert!(!crate::node::BUNDLE_SINGLE_KEYS.contains(&CLOSE_JOINS_KEY), "this phone only — never in a backup");
    }

    #[test]
    fn s4_a_settle_pass_with_nothing_to_settle_reads_nothing_and_an_unreadable_record_is_kept() {
        let st = Mem(Mutex::new(Default::default()));
        assert_eq!(settle_pass(&st, &|_| None).unwrap(), SettleReport::default(), "no records: not even the ledger is read");
        let mut view = Tier2View::default();
        view.utxos.push(OnchainUtxo { chain: 0, index: 0, txid: "aa".into(), vout: 0, value_sats: 1, height: 1, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None });
        save_view(&st, &view).unwrap();
        records::put(&st, rec("att-1", "aa")).unwrap();
        let rep = settle_pass(&st, &|_| None).unwrap();
        assert_eq!(rep.unreadable.len(), 1, "an empty funding cannot be read — reported, kept");
        assert_eq!(records::load(&st).unwrap().len(), 1);
    }
}
