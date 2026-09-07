// tier2_wallet.rs
// Tier 2 increment 4 (block extraction -> UTXO set + history + balance) and 5
// (cursor persistence + reorg rollback).
//
// Fed by tier2_sync: that module hands us the heights whose blocks touch the
// wallet, each with its PoW+linkage-validated canonical hash. Here we fetch
// those blocks, bind each to its validated hash and verify its transactions
// commit to the header (merkle root), then extract:
//   - outputs paying our scripts -> new UTXOs
//   - inputs spending our known UTXOs -> mark spent (kept, not deleted, so a
//     reorg can un-spend them)
// Balance is the sum of unspent outputs by chain. Everything except the async
// fetch is pure and cargo-tested.

use std::sync::Arc;

use bitcoin::{Block, BlockHash, Transaction};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::{
    error::{LijError, LijResult},
    independent::EsploraHttp,
    storage::LijStorage,
    tier2::{WalletScripts, CHAIN_CHANGE, CHAIN_LEGACY, CHAIN_RECEIVE},
    tier2_sync::{MatchedBlock, SyncCursor},
};

pub const VIEW_KEY: &str = "tier2_view";   // v220: pub — the blob packs it (D3)

/// Milliseconds since the unix epoch. js_sys::Date on wasm, SystemTime on
/// native (the established LiJ pattern; SystemTime panics under wasm).
pub fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// A wallet output discovered on-chain. Kept after spending (with `spent_height`
/// set) so a reorg can resurrect it; balance counts only unspent entries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnchainUtxo {
    pub chain: u32,
    pub index: u32,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Height the output was created at.
    pub height: u32,
    /// Height it was spent at, if spent.
    pub spent_height: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxDirection {
    Received,
    Sent,
    SelfTransfer,
}

/// Classifies an on-chain movement so the UI can label channel funding/closing
/// distinctly from ordinary sends/receives.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TxKind {
    /// Ordinary on-chain send/receive.
    #[default]
    Onchain,
    /// Outgoing tx that funds a Lightning channel ("Adding Lightning capacity").
    ChannelOpen,
    /// On-chain return from a channel close/sweep ("Withdrawing Lightning capacity").
    ChannelClose,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnchainHistoryEntry {
    pub txid: String,
    pub height: u32,
    pub direction: TxDirection,
    /// Net effect on the wallet's balance (+received, -sent).
    pub delta_sats: i64,
    /// What kind of movement this is (defaulted for views persisted before
    /// markers existed).
    #[serde(default)]
    pub kind: TxKind,
}

/// A transaction we originated (on-chain send, channel funding, sweep) and
/// broadcast — or handed to LDK to broadcast — but haven't yet seen confirmed.
/// Recording it lets us reflect the spend immediately: reserve its inputs (so
/// the spendable balance drops at once) and show a pending history row, then
/// reconcile when Tier-2 sees the tx in a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub txid: String,
    /// Our outpoints this tx spends (reserved until confirmed): (txid, vout).
    pub spent_outpoints: Vec<(String, u32)>,
    /// Net effect on balance (negative for a spend).
    pub delta_sats: i64,
    pub direction: TxDirection,
    pub kind: TxKind,
    /// When recorded (unix ms), for staleness/display.
    pub created_at_ms: u64,
    /// Reason-#2 verification: set once a /tx status check confirms the tx is
    /// actually in the mempool (or a block). Lets the UI flag a broadcast that
    /// never showed up.
    #[serde(default)]
    pub broadcast_seen: bool,
    /// Build #4 (open-broadcast regression): the raw tx bytes, hex. LDK
    /// take()s the funding tx at broadcast time and the fast queue used to
    /// drop after 3 strikes — this copy backs rebroadcast-until-seen and
    /// survives relaunch. Absent on records that predate the fix.
    #[serde(default)]
    pub raw_tx_hex: Option<String>,
    /// If this pending tx created a wallet change output: its outpoint
    /// (txid, vout) and value. Lets the next funding/send spend that change
    /// before it confirms; cleared when the tx confirms (the PendingTx is
    /// dropped) and pruned by the reconciliation scan if the parent is evicted.
    #[serde(default)]
    pub change_outpoint: Option<(String, u32)>,
    /// v166 (#29-4b): everything a fee-bump needs to rebuild this send
    /// locally. Absent on sends recorded before v166 — those report
    /// "predates fee-bump support" instead of guessing.
    #[serde(default)]
    pub dest_addr: Option<String>,
    #[serde(default)]
    pub dest_sats: Option<u64>,
    #[serde(default)]
    pub fee_sats: Option<u64>,
    #[serde(default)]
    pub fee_rate_sat_per_kw: Option<u32>,
    #[serde(default)]
    pub change_value_sats: u64,
    /// Change-chain index (m/84'/{coin}'/0'/1/n) of that change output. Needed to
    /// sign it when spent pre-confirmation, since change addresses rotate.
    #[serde(default)]
    pub change_index: u32,
}

/// The persisted on-chain view: where we've scanned to, the UTXO set, and
/// history. Rebuildable from the chain at any time, so it's a cache, not a
/// second ledger. NOTE: locally-originated pending txs are deliberately NOT
/// stored here — they live under their own key (see load_pending/save_pending)
/// so the on-chain sync, which rewrites this view mid-batch, can never clobber
/// a pending the funding/send handler wrote during a network await.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Tier2View {
    pub cursor: SyncCursor,
    pub utxos: Vec<OnchainUtxo>,
    pub history: Vec<OnchainHistoryEntry>,
}

/// Spendable (BIP84 receive+change) and legacy (m/525 force-close) balances,
/// counting only unspent outputs.
pub fn balances(view: &Tier2View) -> (u64, u64) {
    let mut spendable = 0u64;
    let mut legacy = 0u64;
    for u in view.utxos.iter().filter(|u| u.spent_height.is_none()) {
        if u.chain == CHAIN_LEGACY {
            legacy = legacy.saturating_add(u.value_sats);
        } else {
            spendable = spendable.saturating_add(u.value_sats);
        }
    }
    (spendable, legacy)
}

/// Apply a block's transactions to the view (pure). Processes txs in block
/// order so an output created earlier in the block can be spent later in the
/// same block. Marks our spent outputs rather than deleting them.
pub fn apply_txs(view: &mut Tier2View, scripts: &WalletScripts, txs: &[Transaction], height: u32) {
    for tx in txs {
        let txid = tx.txid().to_string();
        let mut spent_sats = 0u64;
        let mut recv_sats = 0u64;

        // Inputs that spend our known unspent outputs.
        for input in &tx.input {
            let pt = input.previous_output.txid.to_string();
            let pv = input.previous_output.vout;
            // v190 (S29): mark EVERY matching copy — under the (now
            // guarded) duplicate world, marking only the first left a
            // live twin behind after every spend.
            for u in view
                .utxos
                .iter_mut()
                .filter(|u| u.spent_height.is_none() && u.txid == pt && u.vout == pv)
            {
                u.spent_height = Some(height);
                spent_sats = spent_sats.saturating_add(u.value_sats);
            }
        }

        // Outputs that pay our scripts.
        for (vout, out) in tx.output.iter().enumerate() {
            if let Some((chain, index)) = scripts.owner_of(&out.script_pubkey) {
                // v190 (S29): re-introduction guard — an overlap rescan
                // (cursor regression) must not duplicate a known outpoint.
                if view
                    .utxos
                    .iter()
                    .any(|u| u.txid == txid && u.vout == vout as u32)
                {
                    continue;
                }
                recv_sats = recv_sats.saturating_add(out.value);
                view.utxos.push(OnchainUtxo {
                    chain,
                    index,
                    txid: txid.clone(),
                    vout: vout as u32,
                    value_sats: out.value,
                    height,
                    spent_height: None,
                });
            }
        }

        if spent_sats > 0 || recv_sats > 0 {
            let delta = recv_sats as i64 - spent_sats as i64;
            let direction = if recv_sats > 0 && spent_sats > 0 {
                TxDirection::SelfTransfer
            } else if delta >= 0 {
                TxDirection::Received
            } else {
                TxDirection::Sent
            };
            view.history.push(OnchainHistoryEntry {
                txid,
                height,
                direction,
                delta_sats: delta,
                kind: TxKind::default(),
            });
        }
    }
}

/// Tag history rows that represent capacity returning from a channel close so
/// the UI shows "withdrawing capacity" instead of a generic receive. A row
/// qualifies when its tx IS a known closing tx (the close paid us directly,
/// e.g. a static-remotekey to_remote) or SPENDS one (the delayed to_local
/// sweep landing on our BIP84 wallet). Only upgrades rows still tagged
/// Onchain; idempotent. `close_txids` is the set of logged closing txids.
pub fn tag_channel_closes(
    view: &mut Tier2View,
    txs: &[Transaction],
    close_txids: &std::collections::HashSet<String>,
) {
    if close_txids.is_empty() {
        return;
    }
    for tx in txs {
        let txid = tx.txid().to_string();
        // A tx is the close ITSELF when its txid is a logged closing txid (the
        // close paid us directly, e.g. static-remotekey to_remote).
        let is_direct_close = close_txids.contains(&txid);
        // A tx SPENDS a close output — intended to catch the delayed to_local
        // sweep landing on our BIP84 wallet. BUT this clause alone is too broad:
        // it also matches a channel FUNDING tx built from recycled close residue
        // (close returns sats on-chain -> you reuse those sats to open a new
        // channel). That funding spends a close output yet is an OPEN, not a
        // close. Distinguish by direction: a real sweep is net-INCOMING
        // (delta_sats > 0); a funding/open is net-OUTGOING (delta_sats < 0). Only
        // an incoming spend-of-close-output is a close arriving. (Bug 2026-06-15:
        // funding tx 020aee81 was mislabeled "withdrawing capacity" via this.)
        let spends_close = tx
            .input
            .iter()
            .any(|i| close_txids.contains(&i.previous_output.txid.to_string()));
        if !is_direct_close && !spends_close {
            continue;
        }
        for h in view.history.iter_mut() {
            if h.txid == txid && h.kind == TxKind::Onchain {
                // Direct close: always a close. Spend-of-close: only when the row
                // is net-incoming (a sweep), never when net-outgoing (a funding).
                if is_direct_close || h.delta_sats > 0 {
                    h.kind = TxKind::ChannelClose;
                }
            }
        }
    }
}

pub const PENDING_KEY: &str = "tier2_pending";   // v220: pub — the blob packs it (D3)

/// Load locally-originated pending txs (own key; never part of Tier2View, so
/// the view-rewriting sync can't clobber them).
/// Next unused change-chain index (m/84'/{coin}'/0'/1/n) for rotation: every
/// change output goes to a FRESH address so change isn't linkable by reuse.
/// Taken from the highest change index already used — confirmed in the view
/// (spent entries are retained for reorg safety, so the full history is present)
/// or recorded on a still-pending tx — plus one. Zero when no change exists yet.
/// Bound: the gap-limited wallet scan watches 0..gap, so this stays discoverable
/// as long as it doesn't outrun the gap window.
pub fn next_change_index(view: &Tier2View, pending: &[PendingTx]) -> u32 {
    next_index_for_chain(view, pending, CHAIN_CHANGE)
}

/// Next unused index for ANY chain (receive / change / legacy): the highest index
/// seen for that chain in the view (spent entries are retained, so the full
/// history is present) — plus, for the change chain only, any higher index on a
/// still-pending tx — plus one. Zero when the chain is unused. Drives both change
/// rotation and the sliding scan window.
pub fn next_index_for_chain(view: &Tier2View, pending: &[PendingTx], chain: u32) -> u32 {
    let view_max = view
        .utxos
        .iter()
        .filter(|u| u.chain == chain)
        .map(|u| u.index)
        .max();
    let pending_max = if chain == CHAIN_CHANGE {
        pending
            .iter()
            .filter(|p| p.change_value_sats > 0)
            .map(|p| p.change_index)
            .max()
    } else {
        None
    };
    view_max
        .into_iter()
        .chain(pending_max)
        .max()
        .map_or(0, |m| m + 1)
}

/// v190 (S29): enforce the UTXO-set invariant — one entry per
/// (txid, vout). Keeps the FIRST occurrence, returns how many
/// duplicates were culled so the caller can witness-log and surface
/// it. A clean view is a no-op; a regressed/overlap-scanned view is
/// healed (the ratchet source: dupes were re-counted and, because the
/// spend-marker only hit the first copy, survived every spend).
pub fn dedupe_utxos(view: &mut Tier2View) -> usize {
    let mut seen: std::collections::HashSet<(String, u32)> = std::collections::HashSet::new();
    let before = view.utxos.len();
    view.utxos.retain(|u| seen.insert((u.txid.clone(), u.vout)));
    before - view.utxos.len()
}

pub fn load_pending(storage: &dyn LijStorage) -> Vec<PendingTx> {
    match storage.get(PENDING_KEY) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Persist the pending list.
pub fn save_pending(storage: &dyn LijStorage, pending: &[PendingTx]) -> LijResult<()> {
    let bytes = serde_json::to_vec(pending)
        .map_err(|e| LijError::Storage(format!("tier2 pending serialize: {e}")))?;
    storage.set(PENDING_KEY, &bytes)
}

/// Outpoints reserved by pending (unconfirmed) txs — excluded from spendable.
fn reserved_outpoints(pending: &[PendingTx]) -> std::collections::HashSet<(String, u32)> {
    let mut set = std::collections::HashSet::new();
    for p in pending {
        for o in &p.spent_outpoints {
            set.insert(o.clone());
        }
    }
    set
}

/// Own unconfirmed change from still-pending txs, as synthetic chain-1 UTXOs
/// (index = change_index). Skips change already reserved by another pending tx
/// or already confirmed into the view — the confirmation-seam guard: once the
/// change confirms it is counted in `balances()` instead, so it is never both
/// optimistic-pending AND confirmed. Sorted most-recent-first. Single source of
/// truth for the optimistic spendable balance, plain-send coin selection, and
/// channel funding (which caps to the first 3).
pub(crate) fn unconfirmed_change_utxos(
    view: &Tier2View,
    pending: &[PendingTx],
) -> Vec<OnchainUtxo> {
    let reserved = reserved_outpoints(pending);
    let mut ordered: Vec<&PendingTx> = pending.iter().collect();
    ordered.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms)); // most recent first
    let mut out: Vec<OnchainUtxo> = Vec::new();
    for p in ordered {
        let (txid, vout) = match &p.change_outpoint {
            Some(o) => o.clone(),
            None => continue,
        };
        if p.change_value_sats == 0 || reserved.contains(&(txid.clone(), vout)) {
            continue;
        }
        // v190 (S29): ANY view presence of this outpoint — spent or not —
        // means the chain has spoken; the optimistic fold must stand down
        // (the old is_none() filter re-folded change whose confirmed row
        // had already been spent onward).
        let confirmed_already = view
            .utxos
            .iter()
            .any(|u| u.txid == txid && u.vout == vout);
        if confirmed_already {
            continue;
        }
        out.push(OnchainUtxo {
            chain: 1,
            index: p.change_index,
            txid,
            vout,
            value_sats: p.change_value_sats,
            height: 0,
            spent_height: None,
        });
    }
    out
}

/// Record (or replace, by txid) a locally-originated pending tx. Synchronous
/// load-modify-save of the pending key — atomic w.r.t. other async tasks in the
/// single-threaded runtime, so a concurrent on-chain sync cannot clobber it.
pub fn record_pending(storage: &dyn LijStorage, pending: PendingTx) -> LijResult<()> {
    let mut list = load_pending(storage);
    list.retain(|p| p.txid != pending.txid);
    list.push(pending);
    save_pending(storage, &list)
}

/// Step 3 (S30): drop a pending tx by txid — the dead-funding janitor's
/// executioner. For permanently-dead records (a funding whose inputs a
/// CONFIRMED tx consumed elsewhere): rebroadcast-until-seen would otherwise
/// rebroadcast forever, and the record's reservation could shadow real
/// coins. The UI holds the judgment (Esplora outspend verdicts on
/// spent_outpoints); this only executes. Case-insensitive txid. Returns
/// whether anything was removed.
pub fn drop_pending_tx(storage: &dyn LijStorage, txid_hex: &str) -> LijResult<bool> {
    let mut list = load_pending(storage);
    let before = list.len();
    list.retain(|p| !p.txid.eq_ignore_ascii_case(txid_hex));
    let removed = list.len() != before;
    if removed {
        save_pending(storage, &list)?;
    }
    Ok(removed)
}

/// Build #4: flip broadcast_seen once the tx is visible to the quorum.
pub fn mark_broadcast_seen(storage: &dyn LijStorage, txid: &str) -> LijResult<()> {
    let mut list = load_pending(storage);
    let mut hit = false;
    for p in list.iter_mut() {
        if p.txid == txid && !p.broadcast_seen {
            p.broadcast_seen = true;
            hit = true;
        }
    }
    if hit {
        save_pending(storage, &list)?;
    }
    Ok(())
}

/// v191 (S29): release CONFLICT-DEAD pending records — a pending whose
/// tx never confirmed but whose input the chain shows SPENT (by anything)
/// can never confirm; its optimistic change is phantom money. Keeps
/// records whose own tx confirmed (reconcile_pending's job) and records
/// whose inputs are unspent or unknown to the view (live or synthetic
/// parents). Returns the released (txid, phantom_change_sats) pairs for
/// witness logging.
pub fn release_conflicted_pending(
    storage: &dyn LijStorage,
    view: &Tier2View,
) -> LijResult<Vec<(String, u64)>> {
    let list = load_pending(storage);
    if list.is_empty() {
        return Ok(Vec::new());
    }
    let confirmed: std::collections::HashSet<String> =
        view.history.iter().map(|h| h.txid.clone()).collect();
    let mut released: Vec<(String, u64)> = Vec::new();
    let keep: Vec<PendingTx> = list
        .into_iter()
        .filter(|p| {
            if confirmed.contains(&p.txid) {
                return true;
            }
            let dead = p.spent_outpoints.iter().any(|(pt, pv)| {
                view.utxos
                    .iter()
                    .any(|u| u.txid == *pt && u.vout == *pv && u.spent_height.is_some())
            });
            if dead {
                released.push((p.txid.clone(), p.change_value_sats));
                false
            } else {
                true
            }
        })
        .collect();
    if !released.is_empty() {
        save_pending(storage, &keep)?;
    }
    Ok(released)
}

/// Build #4: release a dead pending record (frees its reserved inputs).
pub fn remove_pending_by_txid(storage: &dyn LijStorage, txid: &str) -> LijResult<()> {
    let mut list = load_pending(storage);
    let before = list.len();
    list.retain(|p| p.txid != txid);
    if list.len() != before {
        save_pending(storage, &list)?;
    }
    Ok(())
}

/// Fold confirmed pendings into the view: any history row whose txid matches a
/// pending carries that pending's classification (ChannelOpen/ChannelClose)
/// onto the confirmed row, and the pending is then dropped. The caller saves
/// the view afterwards (to persist the stamped kind); the pending key is
/// updated here. Synchronous + idempotent.
pub fn reconcile_pending(storage: &dyn LijStorage, view: &mut Tier2View) -> LijResult<()> {
    let mut list = load_pending(storage);
    if list.is_empty() {
        return Ok(());
    }
    let confirmed: std::collections::HashMap<String, TxKind> =
        list.iter().map(|p| (p.txid.clone(), p.kind)).collect();
    for h in view.history.iter_mut() {
        if let Some(kind) = confirmed.get(&h.txid) {
            if *kind != TxKind::Onchain && h.kind == TxKind::Onchain {
                h.kind = *kind;
            }
        }
    }
    let before = list.len();
    let confirmed_txids: std::collections::HashSet<String> =
        view.history.iter().map(|h| h.txid.clone()).collect();
    list.retain(|p| !confirmed_txids.contains(&p.txid));
    if list.len() != before {
        save_pending(storage, &list)?;
    }
    Ok(())
}

/// Roll the view back to `to_height` after a detected reorg: drop outputs and
/// history created above it, and un-spend any output spent above it. Clears the
/// cursor anchors so the next sync re-validates from `to_height + 1`.
pub fn rollback(view: &mut Tier2View, to_height: u32) {
    view.utxos.retain(|u| u.height <= to_height);
    for u in view.utxos.iter_mut() {
        if let Some(sh) = u.spent_height {
            if sh > to_height {
                u.spent_height = None;
            }
        }
    }
    view.history.retain(|h| h.height <= to_height);
    view.cursor.scanned_to = to_height;
    view.cursor.last_hash = None;
    view.cursor.last_filter_header = None;
}

#[derive(Deserialize)]
struct BlockResp {
    block: String, // raw block hex
}

async fn get_json<T: serde::de::DeserializeOwned>(
    http: &Arc<dyn EsploraHttp>,
    url: &str,
) -> LijResult<T> {
    let resp = http.get(url).await?;
    if resp.status != 200 {
        return Err(LijError::Node(format!("tier2 GET {url} -> status {}", resp.status)));
    }
    serde_json::from_str(&resp.body).map_err(|e| LijError::Node(format!("tier2 parse {url}: {e}")))
}

/// Fetch each matched block, bind it to the validated canonical hash, verify
/// its transactions commit to the header (merkle root), then extract into the
/// view. Network I/O — run OUTSIDE any wallet lock.
pub async fn fetch_and_apply(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    scripts: &WalletScripts,
    view: &mut Tier2View,
    matched: &[MatchedBlock],
    close_txids: &std::collections::HashSet<String>,
) -> LijResult<()> {
    for m in matched {
        let resp: BlockResp = get_json(http, &format!("{base}/block/{}", m.height)).await?;
        let bytes = hex::decode(&resp.block)
            .map_err(|e| LijError::Node(format!("block hex at {}: {e}", m.height)))?;
        let block: Block = bitcoin::consensus::deserialize(&bytes)
            .map_err(|e| LijError::Node(format!("block decode at {}: {e}", m.height)))?;

        // Bind to the chain we validated: this must be the exact block whose
        // header passed PoW + linkage in the sync step.
        let want = BlockHash::from_str(&m.block_hash)
            .map_err(|e| LijError::Node(format!("matched hash parse at {}: {e}", m.height)))?;
        if block.block_hash() != want {
            return Err(LijError::Node(format!(
                "block {} hash does not match validated hash",
                m.height
            )));
        }
        // Transactions must commit to the (PoW-validated) header.
        if !block.check_merkle_root() {
            return Err(LijError::Node(format!("block {} merkle root mismatch", m.height)));
        }

        apply_txs(view, scripts, &block.txdata, m.height);
        tag_channel_closes(view, &block.txdata, close_txids);
    }
    Ok(())
}

/// v102: fetch the given block `heights` and return the transactions whose txid
/// is in `wanted`, each paired with the height fetched.
///
/// Used to hand the OutputSweeper the REAL confirmed sweep txs (the ones in the
/// chain). The sweeper regenerates its own copy of each unconfirmed sweep every
/// block (new locktime -> new txid), so its `latest_spending_tx` drifts away from
/// the tx that confirmed and it never recognizes the sweep landing. We only keep
/// txs whose txid is already a confirmed UTXO in the validated view (`wanted`),
/// so a misbehaving block server cannot inject a false confirmation: a txid is the
/// transaction's own hash, so a matching txid IS the authentic transaction. The
/// whole-block fetch is privacy-equivalent to the scan. Network I/O — run OUTSIDE
/// any wallet lock.
pub async fn fetch_confirmed_txs(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    heights: &[u32],
    wanted: &std::collections::HashSet<String>,
) -> LijResult<Vec<(u32, Transaction)>> {
    let mut out: Vec<(u32, Transaction)> = Vec::new();
    for &h in heights {
        let resp: BlockResp = get_json(http, &format!("{base}/block/{}", h)).await?;
        let bytes = hex::decode(&resp.block)
            .map_err(|e| LijError::Node(format!("block hex at {}: {e}", h)))?;
        let block: Block = bitcoin::consensus::deserialize(&bytes)
            .map_err(|e| LijError::Node(format!("block decode at {}: {e}", h)))?;
        for tx in &block.txdata {
            if wanted.contains(&tx.txid().to_string()) {
                out.push((h, tx.clone()));
            }
        }
    }
    Ok(out)
}

/// Persist the view (serialized JSON) via LijStorage.
pub fn save_view(storage: &dyn LijStorage, view: &Tier2View) -> LijResult<()> {
    let bytes = serde_json::to_vec(view)
        .map_err(|e| LijError::Storage(format!("tier2 view serialize: {e}")))?;
    storage.set(VIEW_KEY, &bytes)
}

/// Load the persisted view, or a fresh default if none exists.
pub fn load_view(storage: &dyn LijStorage) -> LijResult<Tier2View> {
    match storage.get(VIEW_KEY)? {
        Some(b) => serde_json::from_slice(&b)
            .map_err(|e| LijError::Storage(format!("tier2 view parse: {e}"))),
        None => Ok(Tier2View::default()),
    }
}

/// How far back to roll the view on a detected reorg before re-syncing.
const REORG_WINDOW: u32 = 6;

/// A snapshot for the UI: balances, scan progress, unspent UTXOs, history, and
/// locally-originated pending txs.
#[derive(Clone, Debug, Serialize)]
pub struct Tier2Summary {
    /// Confirmed spendable, minus anything reserved by pending (unconfirmed) txs.
    pub spendable_sats: u64,
    /// Total confirmed unspent non-legacy coins, BEFORE the pending reserve is
    /// subtracted. Audit-only:
    /// `spendable_sats == confirmed_sats - reserved_sats + unconfirmed_change_sats`.
    pub confirmed_sats: u64,
    /// Value of confirmed coins currently reserved by pending (unconfirmed)
    /// spends. Audit-only (the amount subtracted to produce `spendable_sats`).
    pub reserved_sats: u64,
    /// Own unconfirmed change folded into `spendable_sats` (optimistic): change
    /// from our still-pending txs, not yet confirmed and not reserved. Lets the
    /// balance avoid the post-send dip and lets that change be spent (send or
    /// open) before it confirms. Audit-only (the amount added).
    pub unconfirmed_change_sats: u64,
    pub legacy_sats: u64,
    pub scanned_to: u32,
    pub tip_height: u32,
    pub caught_up: bool,
    /// Next unused receive index (max receive index ever seen + 1), so the
    /// receive flow never reuses an address. Counts spent outputs too.
    pub next_receive_index: u32,
    pub utxos: Vec<OnchainUtxo>,
    /// The confirmed unspent coins that ARE reserved by a pending spend (hidden
    /// from `utxos`). Audit-only: lets a reconciliation verify every pending
    /// spend's inputs are real confirmed coins (`utxos ∪ reserved_utxos`).
    pub reserved_utxos: Vec<OnchainUtxo>,
    pub history: Vec<OnchainHistoryEntry>,
    /// Locally-originated txs not yet confirmed (own-send immediate view).
    pub pending: Vec<PendingTx>,
}

impl Tier2Summary {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self)
            .map_err(|e| LijError::Storage(format!("tier2 summary serialize: {e}")))
    }
}

/// Build the UI snapshot from the current view: spendable excludes outputs
/// reserved by pending txs, the UTXO list hides reserved outputs and includes
/// the optimistic unconfirmed-change rows (height == 0), history is
/// newest-first, and pending txs are surfaced for the immediate-view UI.
pub fn summary(view: &Tier2View, pending: &[PendingTx], tip_height: u32) -> Tier2Summary {
    let (mut spendable_sats, legacy_sats) = balances(view);
    let confirmed_sats = spendable_sats; // before the pending reserve is subtracted
    let reserved = reserved_outpoints(pending);
    let mut reserved_value = 0u64;
    let mut reserved_utxos: Vec<OnchainUtxo> = Vec::new();
    for u in view.utxos.iter().filter(|u| u.spent_height.is_none()) {
        if u.chain != CHAIN_LEGACY && reserved.contains(&(u.txid.clone(), u.vout)) {
            reserved_value = reserved_value.saturating_add(u.value_sats);
            reserved_utxos.push(u.clone());
        }
    }
    spendable_sats = spendable_sats.saturating_sub(reserved_value);

    // Optimistic own-change: fold in change from our still-pending txs that has
    // not confirmed yet (and isn't reserved by a later pending tx). It's our
    // money — spendable for a send or a channel open, and it removes the
    // post-send balance dip. Seam-safe: once the change confirms it enters the
    // view (counted above) and unconfirmed_change_utxos drops it, never doubled.
    let unconfirmed_change = unconfirmed_change_utxos(view, pending);
    let unconfirmed_change_sats: u64 = unconfirmed_change.iter().map(|u| u.value_sats).sum();
    spendable_sats = spendable_sats.saturating_add(unconfirmed_change_sats);

    let next_receive_index = view
        .utxos
        .iter()
        .filter(|u| u.chain == CHAIN_RECEIVE)
        .map(|u| u.index)
        .max()
        .map_or(0, |m| m + 1);
    let mut utxos: Vec<OnchainUtxo> = view
        .utxos
        .iter()
        .filter(|u| u.spent_height.is_none() && !reserved.contains(&(u.txid.clone(), u.vout)))
        .cloned()
        .collect();
    // v103: the UTXO list must show the same money the balance counts — append
    // the optimistic unconfirmed-change rows (height == 0 marks them pending in
    // the UI). Recomputed from view + pending every sync, so the list tracks
    // confirmations and reorgs in lockstep with the balance: once the change
    // confirms it enters the view above and drops out of this set, never doubled.
    utxos.extend(unconfirmed_change);
    let mut history = view.history.clone();
    history.sort_by(|a, b| b.height.cmp(&a.height));
    Tier2Summary {
        spendable_sats,
        confirmed_sats,
        reserved_sats: reserved_value,
        unconfirmed_change_sats,
        legacy_sats,
        scanned_to: view.cursor.scanned_to,
        tip_height,
        caught_up: view.cursor.scanned_to >= tip_height,
        next_receive_index,
        utxos,
        reserved_utxos,
        history,
        pending: pending.to_vec(),
    }
}

/// If the block recorded at the cursor's tip no longer matches the chain (a
/// reorg orphaned it), roll back a small window so the next sync re-validates
/// forward. Returns true if a rollback happened.
pub async fn reorg_check(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    view: &mut Tier2View,
) -> LijResult<bool> {
    let at = view.cursor.scanned_to;
    let recorded = match &view.cursor.last_hash {
        Some(h) => h.clone(),
        None => return Ok(false),
    };
    if at == 0 || at <= view.cursor.birthday {
        return Ok(false);
    }
    let resp: crate::tier2_sync::HeadersResp =
        get_json(http, &format!("{base}/headers?start={at}&count=1")).await?;
    let current = match resp.headers.first() {
        Some(h) => h.hash.clone(),
        None => return Ok(false),
    };
    if current != recorded {
        let to = at.saturating_sub(REORG_WINDOW).max(view.cursor.birthday);
        rollback(view, to);
        return Ok(true);
    }
    Ok(false)
}

/// v180: retro-tag history rows that were scanned BEFORE their channel's closing
/// txid was known. The per-block tagger only sees blocks as they arrive, so a
/// close whose record was blind at scan time stays mislabeled as a plain receive
/// forever (DP evidence 2026-07-13: a confirmed force close showed "+9,282 sats
/// received" with no "returned from Lightning" row, and the close alert could
/// never find its clear signal). Pure pass over the stored view; idempotent.
/// Returns true when anything changed (caller must persist).
pub fn retag_closes_by_txid(
    view: &mut Tier2View,
    close_txids: &std::collections::HashSet<String>,
) -> bool {
    if close_txids.is_empty() {
        return false;
    }
    let mut changed = false;
    for h in view.history.iter_mut() {
        if h.kind == TxKind::Onchain && close_txids.contains(&h.txid) {
            h.kind = TxKind::ChannelClose;
            changed = true;
        }
    }
    changed
}

#[derive(serde::Deserialize)]
struct OutspendResp {
    spent: bool,
    txid: Option<String>,
}

/// v180: heal BLIND closed records (no closing txid) straight from the chain —
/// whatever spent a channel's funding outpoint IS its closing tx. Independent of
/// the ChainMonitor: the funding-spend walker can only heal records whose monitor
/// still exists, and monitors are evicted at confirmation, so a record written in
/// that same cycle was blind FOREVER. Esplora's outspends endpoint needs nothing
/// but the funding txid. Best-effort: any failure leaves the record blind for the
/// next sync to retry.
pub async fn heal_blind_closes(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    storage: &dyn LijStorage,
) {
    let blind = crate::closed_channel_log::ClosedChannelLog::blind_funding_txos(storage);
    for txo in blind {
        let mut parts = txo.split(':');
        let (txid, vout) = match (parts.next(), parts.next()) {
            (Some(t), Some(v)) => match v.parse::<usize>() {
                Ok(n) => (t.to_string(), n),
                Err(_) => continue,
            },
            _ => continue,
        };
        let outspends: Vec<OutspendResp> =
            match get_json(http, &format!("{base}/tx/{txid}/outspends")).await {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("[heal_blind_closes] outspends({txid}) failed: {e}");
                    continue;
                }
            };
        let spend = match outspends.get(vout) {
            Some(o) if o.spent => o,
            _ => continue,
        };
        if let Some(closing) = spend.txid.as_ref() {
            if crate::closed_channel_log::ClosedChannelLog::heal_closing_txid(
                storage, &txo, closing,
            ) {
                log::info!(
                    "[heal_blind_closes] closed record {txo} healed with closing txid {closing}"
                );
            }
        }
    }
}

/// Drive the scan to the tip: reorg-check, then loop sync_step -> fetch matched
/// blocks -> advance cursor -> checkpoint, until caught up. Blocks are applied
/// BEFORE the cursor advances, so a fetch failure never skips them. Network
/// I/O — run OUTSIDE any wallet lock.
pub async fn sync_to_tip(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    scripts: &WalletScripts,
    view: &mut Tier2View,
    storage: &dyn LijStorage,
    tip_height: u32,
    batch: u32,
) -> LijResult<()> {
    reorg_check(http, base, view).await?;
    // v180: heal blind closed records FIRST so close_txids is complete for both
    // the retro-tag below and the per-block tagger in the loop.
    heal_blind_closes(http, base, storage).await;
    // Closing txids let fetch_and_apply tag close-return receives as
    // "withdrawing capacity". Loaded once per sync; the log is stable here.
    let close_txids = crate::closed_channel_log::ClosedChannelLog::closing_txids(storage);
    // v180: fix rows scanned before their record knew the txid. Must persist even
    // when the loop below does nothing (already at tip — the common case for a
    // close that confirmed several blocks ago).
    if retag_closes_by_txid(view, &close_txids) {
        save_view(storage, view)?;
    }
    loop {
        let outcome =
            crate::tier2_sync::sync_step(http, base, scripts, &view.cursor, tip_height, batch).await?;
        fetch_and_apply(http, base, scripts, view, &outcome.matched, &close_txids).await?;
        view.cursor.scanned_to = outcome.scanned_to;
        view.cursor.last_hash = outcome.last_hash;
        view.cursor.last_filter_header = outcome.last_filter_header;
        save_view(storage, view)?;
        if outcome.caught_up {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2::{CHAIN_RECEIVE, DEFAULT_GAP};
    use bip39::Mnemonic;
    use bitcoin::{absolute::LockTime, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn scripts() -> WalletScripts {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse().unwrap();
        let root = crate::key::RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        WalletScripts::build(&root, Network::Bitcoin, DEFAULT_GAP).unwrap()
    }

    fn our_receive_spk(s: &WalletScripts) -> ScriptBuf {
        s.entries
            .iter()
            .find(|e| e.chain == CHAIN_RECEIVE && e.index == 0)
            .unwrap()
            .script_pubkey
            .clone()
    }

    fn tx_paying(spk: ScriptBuf, value: u64) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: spk,
            }],
        }
    }

    fn tx_spending(prev_txid: bitcoin::Txid, vout: u32, change_spk: ScriptBuf, change: u64) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: change,
                script_pubkey: change_spk,
            }],
        }
    }

    #[test]
    fn receive_then_spend_tracks_balance_and_history() {
        let s = scripts();
        let mut view = Tier2View::default();

        let recv = tx_paying(our_receive_spk(&s), 50_000);
        let recv_txid = recv.txid();
        apply_txs(&mut view, &s, &[recv], 900_000);

        assert_eq!(balances(&view), (50_000, 0), "one unspent receive");
        assert_eq!(view.utxos.len(), 1);
        assert_eq!(view.history.len(), 1);
        assert_eq!(view.history[0].direction, TxDirection::Received);
        assert_eq!(view.history[0].delta_sats, 50_000);

        // Spend it entirely to an external script (no change to us).
        let spend = tx_spending(recv_txid, 0, ScriptBuf::new(), 49_000);
        apply_txs(&mut view, &s, &[spend], 900_010);

        assert_eq!(balances(&view), (0, 0), "spent -> zero spendable");
        assert_eq!(view.utxos.len(), 1, "spent utxo kept (for reorg), not deleted");
        assert_eq!(view.utxos[0].spent_height, Some(900_010));
        assert_eq!(view.history.last().unwrap().direction, TxDirection::Sent);
    }

    #[test]
    fn rollback_unspends_and_drops_above_height() {
        let s = scripts();
        let mut view = Tier2View::default();
        let recv = tx_paying(our_receive_spk(&s), 70_000);
        let recv_txid = recv.txid();
        apply_txs(&mut view, &s, &[recv], 900_000);
        let spend = tx_spending(recv_txid, 0, ScriptBuf::new(), 69_000);
        apply_txs(&mut view, &s, &[spend], 900_020);
        assert_eq!(balances(&view), (0, 0));

        // Reorg back below the spend: the output must be spendable again.
        rollback(&mut view, 900_010);
        assert_eq!(balances(&view), (70_000, 0), "rollback un-spends the output");
        assert_eq!(view.cursor.scanned_to, 900_010);
        assert!(view.cursor.last_hash.is_none());
        // History above the rollback height is gone; the receive remains.
        assert!(view.history.iter().all(|h| h.height <= 900_010));
    }

    #[test]
    fn rollback_drops_outputs_created_above_height() {
        let s = scripts();
        let mut view = Tier2View::default();
        apply_txs(&mut view, &s, &[tx_paying(our_receive_spk(&s), 10_000)], 900_050);
        assert_eq!(balances(&view), (10_000, 0));
        rollback(&mut view, 900_040);
        assert_eq!(balances(&view), (0, 0), "output created above rollback height is dropped");
        assert!(view.utxos.is_empty());
    }

    // Minimal in-memory LijStorage for the persistence round-trip.
    struct MemStorage(Mutex<HashMap<String, Vec<u8>>>);
    impl LijStorage for MemStorage {
        fn get(&self, key: &str) -> LijResult<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &[u8]) -> LijResult<()> {
            self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &str) -> LijResult<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
        fn list_with_prefix(&self, prefix: &str) -> LijResult<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[test]
    fn view_persists_round_trip() {
        let s = scripts();
        let mut view = Tier2View::default();
        apply_txs(&mut view, &s, &[tx_paying(our_receive_spk(&s), 12_345)], 900_000);
        view.cursor.scanned_to = 900_000;

        let storage = MemStorage(Mutex::new(HashMap::new()));
        save_view(&storage, &view).unwrap();
        let loaded = load_view(&storage).unwrap();

        assert_eq!(balances(&loaded), (12_345, 0));
        assert_eq!(loaded.cursor.scanned_to, 900_000);
        assert_eq!(loaded.utxos, view.utxos);
    }

    #[test]
    fn load_view_default_when_absent() {
        let storage = MemStorage(Mutex::new(HashMap::new()));
        let v = load_view(&storage).unwrap();
        assert!(v.utxos.is_empty() && v.history.is_empty());
    }

    #[test]
    fn summary_reflects_balances_and_progress() {
        let s = scripts();
        let mut view = Tier2View::default();
        apply_txs(&mut view, &s, &[tx_paying(our_receive_spk(&s), 33_000)], 900_000);
        view.cursor.scanned_to = 900_000;
        let sm = summary(&view, &[], 900_000);
        assert_eq!(sm.spendable_sats, 33_000);
        assert_eq!(sm.legacy_sats, 0);
        assert!(sm.caught_up);
        assert_eq!(sm.utxos.len(), 1);
        assert_eq!(sm.history.len(), 1);
        assert!(sm.to_json().unwrap().contains("spendable_sats"));
    }

    #[test]
    fn pending_reserves_spendable_then_reconciles_with_marker() {
        let s = scripts();
        let storage = MemStorage(Mutex::new(HashMap::new()));
        let mut view = Tier2View::default();

        // Confirmed 33k receive.
        let recv = tx_paying(our_receive_spk(&s), 33_000);
        let recv_txid = recv.txid();
        apply_txs(&mut view, &s, &[recv], 900_000);
        view.cursor.scanned_to = 900_000;
        assert_eq!(summary(&view, &load_pending(&storage), 900_000).spendable_sats, 33_000);

        // Originate a channel-open funding tx spending that output (no change to
        // us); record it pending in its OWN key. Spendable should drop to 0, the
        // UTXO should disappear from the spendable list, and a pending row with
        // the ChannelOpen marker should surface — all before confirmation.
        let funding = tx_spending(recv_txid, 0, ScriptBuf::new(), 0);
        let funding_txid = funding.txid().to_string();
        record_pending(
            &storage,
            PendingTx {
                txid: funding_txid.clone(),
                spent_outpoints: vec![(recv_txid.to_string(), 0)],
                delta_sats: -33_000,
                direction: TxDirection::Sent,
                kind: TxKind::ChannelOpen,
                created_at_ms: 0,
                dest_addr: None,
                dest_sats: None,
                fee_sats: None,
                fee_rate_sat_per_kw: None,
                change_outpoint: None,
                change_value_sats: 0,
                change_index: 0,
                broadcast_seen: false,
                raw_tx_hex: None,
            },
        )
        .unwrap();
        let sm = summary(&view, &load_pending(&storage), 900_000);
        assert_eq!(sm.spendable_sats, 0, "input reserved while pending");
        assert!(sm.utxos.is_empty(), "reserved utxo hidden");
        assert_eq!(sm.pending.len(), 1);
        assert_eq!(sm.pending[0].kind, TxKind::ChannelOpen);

        // Funding confirms: apply_txs marks the input spent + adds a history
        // row; reconcile_pending stamps that row ChannelOpen and drops the
        // pending from its key.
        apply_txs(&mut view, &s, &[funding], 900_005);
        reconcile_pending(&storage, &mut view).unwrap();
        let sm2 = summary(&view, &load_pending(&storage), 900_005);
        assert!(sm2.pending.is_empty(), "pending cleared on confirm");
        let row = sm2
            .history
            .iter()
            .find(|h| h.txid == funding_txid)
            .expect("confirmed funding row");
        assert_eq!(row.kind, TxKind::ChannelOpen, "marker carried to confirmed row");
        assert_eq!(sm2.spendable_sats, 0, "fully spent, no change to us");
    }
}
