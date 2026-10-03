//! v287 (S50, silent payments — RECEIVE, the wallet's half; DP's five decisions 2026-09-28 17:22):
//! the SCAN that finds this wallet's silent payments with the box's tweak index (docs/sp-tweak-index.md).
//! v288 (DP 21:10): the words — the box builds the INDEX; the wallet's engine on the phone runs the SCAN
//! (it reads hints and filters and checks; it never moves a coin — "sweep" is the Black start kit's word);
//! and the wallet has a say: the switch (CoinMarks::sp_enabled) — off runs no scan and shows no address.
//!
//! The shape, in plain words:
//! - The box (a LIJOX provider's tier-2 filter server) serves, per block, the list of BIP-352 tweaks —
//!   one per transaction that could be a silent payment. `/sp/info` says whether it serves them at all
//!   and from which block; a provider without the index answers 404 and this module does nothing.
//! - This wallet holds the scan key. For each block it multiplies every tweak by the scan key, works out
//!   the taproot address each would have paid, and tests those candidates — together with the scripts of
//!   the silent-payment coins it already holds, so their spends are seen — against the block's BIP158
//!   filter, which the wallet already fetches for its m/84 walk. Only a matching block is downloaded;
//!   the amount and the outpoint come from the block itself (merkle-bound to the PoW-checked header).
//! - The scan runs UPWARD from `from` to the top the m/84 walk has reached: a coin is always met before
//!   its spend, so no block is ever re-read for a spend (the "down-walk re-check" of decision 3 is not
//!   needed in this shape — the cost is the scan itself, decision 4's impact). New blocks at the top are
//!   scanned in the same call that reads them. The m/84 walk is untouched.
//! - `from`: on a fresh view (a restore, a rescan) the later of the box's index start and the wallet's
//!   birthday; on a view that was already walked before this build existed, the top at that moment — no
//!   LiJ wallet could have received a silent payment before it showed an sp1 address (DP's decision 1).
//! - The mempool leg: the box serves the tweaks of unconfirmed eligible transactions with their taproot
//!   outputs; a match is "received · pending" until its block lands.
//! - Decision 2 (one box): every served block's commitment is recomputed from the served tweaks (a box
//!   cannot forge a coin — a wrong tweak never matches — but it could leave one out); with one box the
//!   scan is marked `single_source` so a second box can be compared later.
//!
//! Every key stays in the engine; the box never learns an address, a coin, or a match.

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Block, BlockHash, ScriptBuf};
use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};
use crate::independent::EsploraHttp;
use crate::key::RootKey;
use crate::silent_payment::SpKeys;
use crate::storage::LijStorage;
use crate::tier2::CHAIN_SP;
use crate::tier2_sync::{get_json, FiltersResp, HeadersResp};
use crate::tier2_wallet::{apply_txs, fetch_block_bound, save_view, OnchainUtxo, Tier2View};

/// The scan's state, inside the ledger (`Tier2View::sp`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpScan {
    /// The box serves an index (false = no silent-payment receive on this provider).
    pub available: bool,
    /// The box's index start, as last read.
    pub index_start: u32,
    /// The box's highest indexed block, as last read.
    pub indexed_to: u32,
    /// The first block this wallet scans (see the module header).
    pub from: u32,
    /// The highest block scanned (inclusive); 0 = nothing yet.
    #[serde(alias = "swept_to")]
    pub scanned_to: u32,
    /// The hash and filter header of block `scanned_to`, so the next batch links to this one
    /// (the scan's header chain is continuous from `from` up to the walk's known top).
    #[serde(default, alias = "swept_hash")]
    pub scanned_hash: String,
    #[serde(default, alias = "swept_filter_header")]
    pub scanned_filter_header: String,
    /// Blocks the box had not indexed yet when the scan reached them (they are scanned later).
    #[serde(default)]
    pub waiting_for_index: bool,
    /// The mempool leg's sequence cursor.
    #[serde(default)]
    pub mempool_seq: u64,
    /// Unconfirmed silent payments seen in the mempool (txid → the outputs found).
    #[serde(default)]
    pub pending: Vec<SpPending>,
    /// One provider only — the commitments were recomputed but not compared with a second box.
    #[serde(default)]
    pub single_source: bool,
    /// Provider notes for the face: the last scan's line.
    #[serde(default)]
    pub last_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpPending {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub t_k: String,
    pub k: u32,
    pub seen_ms: u64,
    /// v304: the label it was paid to (see OnchainUtxo::sp_label).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<u32>,
}

// ── the box's answers ──
#[derive(Clone, Debug, Deserialize)]
pub struct SpInfoResp {
    pub format: String,
    pub start_height: u32,
    #[serde(default)]
    pub indexed_to: Option<u32>,
    #[serde(default)]
    pub tip: u32,
    #[serde(default)]
    pub mempool_seq: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpTweakBlock {
    pub height: u32,
    pub hash: String,
    #[serde(default)]
    pub count: u32,
    #[serde(default)]
    pub commit: String,
    pub tweaks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpTweaksResp {
    pub blocks: Vec<SpTweakBlock>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpMempoolOutput {
    pub vout: u32,
    pub key: String,
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpMempoolEntry {
    pub seq: u64,
    pub txid: String,
    pub tweak: String,
    pub outputs: Vec<SpMempoolOutput>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpMempoolResp {
    pub seq: u64,
    pub tweaks: Vec<SpMempoolEntry>,
    #[serde(default)]
    pub gone: Vec<String>,
}

/// spcommit-v1 over a block's tweaks (sorted as strings): what the box must have committed to.
pub fn spcommit_v1(height: u32, block_hash: &str, tweaks: &[String]) -> String {
    let mut sorted: Vec<&String> = tweaks.iter().collect();
    sorted.sort();
    let mut s = format!("spcommit-v1\n{height}\n{block_hash}\n{}\n", sorted.len());
    for t in sorted {
        s.push_str(t);
        s.push('\n');
    }
    sha256::Hash::hash(s.as_bytes()).to_string()
}

fn parse_tweaks(hexes: &[String]) -> Vec<PublicKey> {
    hexes
        .iter()
        .filter_map(|h| hex::decode(h).ok())
        .filter_map(|b| PublicKey::from_slice(&b).ok())
        .collect()
}

fn tweak_hex(t: &[u8; 32]) -> String {
    hex::encode(t)
}

/// The scripts of the silent-payment coins this wallet holds (unspent), so their spends are seen.
pub fn coin_scripts<C: bitcoin::secp256k1::Verification>(secp: &Secp256k1<C>, keys: &SpKeys, view: &Tier2View) -> Vec<ScriptBuf> {
    let mut out = Vec::new();
    for u in view.utxos.iter().filter(|u| u.chain == CHAIN_SP && u.spent_height.is_none()) {
        if let Some(t) = u.sp_tweak.as_deref().and_then(|h| hex::decode(h).ok()) {
            if t.len() == 32 {
                let mut tk = [0u8; 32];
                tk.copy_from_slice(&t);
                if let Ok(s) = keys.script_for(secp, &tk) {
                    out.push(s);
                }
            }
        }
    }
    out
}

/// Add a found coin to the ledger (idempotent by outpoint). Returns true when new.
fn add_coin(view: &mut Tier2View, f: &crate::silent_payment::SpFound, height: u32) -> bool {
    let txid = f.txid.to_string();
    if view.utxos.iter().any(|u| u.txid == txid && u.vout == f.vout) {
        return false;
    }
    view.utxos.push(OnchainUtxo {
        sp_tweak: Some(tweak_hex(&f.t_k)),
        sp_label: f.label,   // v304
        chain: CHAIN_SP,
        index: f.k,
        txid: txid.clone(),
        vout: f.vout,
        value_sats: f.value_sats,
        height,
        spent_height: None,
        spent_txid: None,
    });
    true
}

/// Read `/sp/info`; `available` false on a 404 (no index on this provider). Sets `from` on first use.
pub async fn refresh_info(http: &Arc<dyn EsploraHttp>, base: &str, view: &mut Tier2View) -> LijResult<()> {
    let resp = http.get(&format!("{base}/sp/info")).await?;
    let mut sp = view.sp.clone().unwrap_or_default();
    if resp.status == 404 {
        sp.available = false;
        view.sp = Some(sp);
        return Ok(());
    }
    if resp.status != 200 {
        return Err(LijError::Node(format!("silent-payment index: /sp/info answered {}", resp.status)));
    }
    let info: SpInfoResp = serde_json::from_str(&resp.body).map_err(|e| LijError::Node(format!("silent-payment index: /sp/info parse: {e}")))?;
    if info.format != "spcommit-v1" {
        return Err(LijError::Node(format!("silent-payment index: unknown format {}", info.format)));
    }
    sp.available = true;
    sp.index_start = info.start_height;
    sp.indexed_to = info.indexed_to.unwrap_or(0);
    sp.single_source = true;
    // v297 (S52): the scan opens ONCE (from == 0 = never opened). Until v297 it also re-opened whenever the server had
    // answered 404 in between — a box whose index was away for a while, or (v296) a wallet that read another
    // provider's server — and a re-open of a walked view starts at the walk's top: every block between where the scan
    // stood and that top was never read, and a silent payment in them never found. An opened scan resumes where it was.
    if sp.from == 0 {
        // a fresh view (restore / rescan / first ever walk) scans from the later of the index start and the
        // birthday; a view already walked before this build starts at its current top — no LiJ wallet showed
        // an sp1 address before v287 (DP's decision 1)
        let fresh = view.cursor.scanned_to == 0;
        sp.from = if fresh { info.start_height.max(view.cursor.birthday) } else { info.start_height.max(view.cursor.scanned_to) };
        sp.scanned_to = sp.from.saturating_sub(1);
        log::info!("[sp] the silent-payment scan opens: from {} (index start {}, birthday {}, top {}, fresh {fresh})", sp.from, info.start_height, view.cursor.birthday, view.cursor.scanned_to);
    } else if info.start_height < sp.from && view.cursor.birthday < sp.from && info.start_height.max(view.cursor.birthday) < sp.from {
        // the box backfilled below our start (DP: 840,000) — a restored wallet's history may sit there;
        // only a fresh view / rescan takes it (an existing wallet's rule stands)
        sp.last_note = format!("the provider's index now starts at {} (below this wallet's scan start {})", info.start_height, sp.from);
    }
    view.sp = Some(sp);
    Ok(())
}

/// v293: tweaks whose candidate scripts are computed between two budget checks (≈ 96 elliptic-curve operations).
pub const SP_TWEAK_GROUP: usize = 32;

/// One scan batch: fetch headers + filters + tweaks for [start, end], validate the header chain within
/// the batch (and against the m/84 walk's known top hash when the batch ends there), recompute each
/// block's commitment, test the candidates and the coin scripts against each filter, fetch the matches,
/// apply them. Returns the blocks matched.
async fn scan_batch(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    keys: &SpKeys,
    view: &mut Tier2View,
    start: u32,
    end: u32,
    labels: &[crate::silent_payment::SpLabelTweak],
    found_labels: &mut std::collections::BTreeSet<u32>,
) -> LijResult<usize> {
    let secp = Secp256k1::new();
    let count = end - start + 1;
    let hdrs: HeadersResp = get_json(http, &format!("{base}/headers?start={start}&count={count}")).await?;
    let flts: FiltersResp = get_json(http, &format!("{base}/filters?start={start}&count={count}")).await?;
    let tw: SpTweaksResp = get_json(http, &format!("{base}/sp/tweaks?start={start}&count={count}")).await?;
    if hdrs.headers.len() as u32 != count || flts.filters.len() as u32 != count {
        return Err(LijError::Node(format!("sp scan {start}..{end}: {} headers / {} filters, wanted {count}", hdrs.headers.len(), flts.filters.len())));
    }
    // the header chain: PoW + linkage within the batch, linked to the previous batch's last block, and
    // anchored to the walk's known top when the batch ends there
    let (prev_hash, prev_fh) = match view.sp.as_ref() {
        Some(s) if s.scanned_to + 1 == start && !s.scanned_hash.is_empty() => (
            Some(BlockHash::from_str(&s.scanned_hash).map_err(|e| LijError::Node(format!("sp scan: scanned hash parse: {e}")))?),
            if s.scanned_filter_header.is_empty() { None } else { Some(crate::tier2_sync::filter_header_internal(&s.scanned_filter_header)?) },
        ),
        _ => (None, None),
    };
    let top_hash = crate::tier2_sync::validate_headers(&hdrs.headers, prev_hash)?;
    if end == view.cursor.scanned_to {
        if let Some(known) = view.cursor.last_hash.as_deref() {
            if top_hash.to_string() != known {
                return Err(LijError::Node(format!("sp scan {start}..{end}: header chain does not reach the walk's known top block")));
            }
        }
    }
    // the filter-header chain, linked the same way
    let mut prev_fh: Option<[u8; 32]> = prev_fh;
    let mut last_fh_hex = String::new();
    for f in flts.filters.iter() {
        let bytes = hex::decode(&f.filter).map_err(|e| LijError::Node(format!("filter hex at {}: {e}", f.height)))?;
        let served = crate::tier2_sync::filter_header_internal(&f.filter_header)?;
        if let Some(pfh) = prev_fh {
            if crate::tier2_sync::compute_filter_header(&bytes, &pfh) != served {
                return Err(LijError::Node(format!("sp scan: filter-header chain break at {}", f.height)));
            }
        }
        prev_fh = Some(served);
        last_fh_hex = f.filter_header.clone();
    }
    if end == view.cursor.scanned_to {
        if let Some(known) = view.cursor.last_filter_header.as_deref() {
            if last_fh_hex != known {
                return Err(LijError::Node(format!("sp scan {start}..{end}: filter-header chain does not reach the walk's known top")));
            }
        }
    }
    // tweaks by height; every served block's commitment recomputed
    let mut by_height: std::collections::HashMap<u32, (String, Vec<String>)> = std::collections::HashMap::new();
    for b in tw.blocks.iter() {
        if b.height < start || b.height > end { continue; }
        if !b.commit.is_empty() && spcommit_v1(b.height, &b.hash, &b.tweaks) != b.commit {
            return Err(LijError::Node(format!("sp scan: the provider's commitment for block {} does not match its tweaks", b.height)));
        }
        by_height.insert(b.height, (b.hash.clone(), b.tweaks.clone()));
    }
    // v297 (S52): block by block, in order — a matching block is fetched and applied before the next filter is
    // tested, and a coin found in it joins the scripts tested from the next block on. Until v297 every filter of the
    // batch was tested first, against the coins held at the batch's start: a coin found in a batch and spent later in
    // the SAME batch (a catch-up — a restore, a rescan, a resumed scan: up to 100 blocks at a time) never had its
    // spend read, and the balance kept a coin that was gone. Same fetches, same order.
    let mut own = coin_scripts(&secp, keys, view);
    let mut n = 0usize;
    // v293 (S51, DP — O1): the screen's turn is a TIME budget (tier2_sync::YIELD_BUDGET_MS), checked before every
    // block and between groups of tweaks — not "every 8 blocks", which on an iPhone X was 1–6 s of frozen screen
    // per run (three elliptic-curve operations per tweak, hundreds of tweaks per block). Same work, same order.
    let mut mark = crate::tier2_sync::now_ms();
    for (h, f) in hdrs.headers.iter().zip(flts.filters.iter()) {
        crate::tier2_sync::yield_if_due(&mut mark).await;
        let (tweaks, hash_ok) = match by_height.get(&f.height) {
            Some((bh, hexes)) => (parse_tweaks(hexes), *bh == f.hash),
            None => (Vec::new(), true),
        };
        if !hash_ok {
            return Err(LijError::Node(format!("sp scan: the provider's tweak list for block {} names another block hash", f.height)));
        }
        if h.hash != f.hash {
            return Err(LijError::Node(format!("sp scan: header/filter hash mismatch at {}", f.height)));
        }
        let mut query: Vec<ScriptBuf> = Vec::with_capacity(tweaks.len() * (1 + labels.len()) + own.len());
        for group in tweaks.chunks(SP_TWEAK_GROUP) {   // v293: the same scripts in the same order, with the budgeted yield between groups
            query.extend(keys.candidate_scripts(&secp, group, labels));   // v304: the labels in use
            crate::tier2_sync::yield_if_due(&mut mark).await;
        }
        query.extend(own.iter().cloned());
        if query.is_empty() { continue; }
        let bytes = hex::decode(&f.filter).map_err(|e| LijError::Node(format!("filter hex at {}: {e}", f.height)))?;
        let bh = BlockHash::from_str(&f.hash).map_err(|e| LijError::Node(format!("block hash at {}: {e}", f.height)))?;
        if !crate::tier2::block_matches_scripts(&bytes, &bh, &query)? { continue; }
        let height = f.height;
        let block: Block = fetch_block_bound(http, base, height, &f.hash).await?;   // hash-bound, merkle-checked
        view.block_times.insert(height, block.header.time);
        // spends of every known coin (m/84 and silent-payment alike) are marked by outpoint; the m/84
        // outputs themselves are the walk's business, so the script net is empty here
        let scripts = crate::tier2::WalletScripts::default();
        apply_txs(view, &scripts, &block.txdata, height);
        let found = keys.find_in_block(&secp, &tweaks, &block.txdata, labels);
        let mut new = 0;
        for c in &found {
            if let Some(m) = c.label { found_labels.insert(m); }   // v304: the marks learn a label found here
            if add_coin(view, c, height) { new += 1; own.push(c.script.clone()); }   // v297: tested from the next block on
            let txid = c.txid.to_string();
            if let Some(sp) = view.sp.as_mut() { sp.pending.retain(|p| !(p.txid == txid && p.vout == c.vout)); }
        }
        if new > 0 {
            apply_txs(view, &scripts, &block.txdata, height);   // v297: a coin paid and spent inside this one block
            log::info!("[sp] {new} silent payment(s) found in block {height}");
        }
        crate::tier2_wallet::capture_own_txs(view, &block.txdata, height);   // v298: kept whole for the drill-down
        n += 1;
    }
    if let Some(s) = view.sp.as_mut() {
        s.scanned_hash = top_hash.to_string();
        s.scanned_filter_header = last_fh_hex;
    }
    Ok(n)
}

/// The scan: up to `max_batches` batches of `batch` blocks from `scanned_to + 1` towards the walk's top,
/// never past the box's `indexed_to`. Returns (batches run, a note).
pub async fn scan(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    root_key: &RootKey,
    view: &mut Tier2View,
    storage: &dyn LijStorage,
    batch: u32,
    max_batches: u32,
) -> LijResult<(u32, String)> {
    let sp = match view.sp.clone() { Some(s) if s.available => s, _ => return Ok((0, "no silent-payment index at this provider".into())) };
    let keys = SpKeys::from_root(root_key)?;
    // v304 (S54): the labels to check — the change label, every label made or found, all ten after a words-only restore
    let mut marks = crate::tier2_wallet::load_marks(storage).unwrap_or_default();
    let labels = keys.label_set(&marks.sp_scan_labels());
    let mut found_labels: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let top = view.cursor.scanned_to.min(sp.indexed_to);
    let mut scanned_to = sp.scanned_to.max(sp.from.saturating_sub(1));
    let mut batches = 0u32;
    let mut matched_total = 0usize;
    while scanned_to < top && (max_batches == 0 || batches < max_batches) {
        let start = scanned_to + 1;
        let end = (start + batch.max(1) - 1).min(top);
        matched_total += scan_batch(http, base, &keys, view, start, end, &labels, &mut found_labels).await?;
        scanned_to = end;
        if let Some(s) = view.sp.as_mut() { s.scanned_to = scanned_to; s.waiting_for_index = false; }
        save_view(storage, view)?;
        batches += 1;
    }
    // v304: a coin found under a label this wallet has no entry for (a words-only restore) — keep the number
    let now = crate::tier2_wallet::now_ms();
    if found_labels.iter().fold(false, |acc, m| marks.sp_label_ensure(*m, now) || acc) {
        crate::tier2_wallet::save_marks(storage, &marks)?;
    }
    let waiting = view.cursor.scanned_to > sp.indexed_to && scanned_to >= sp.indexed_to;
    let top_of = view.cursor.scanned_to;
    let mut changed = false;
    if let Some(s) = view.sp.as_mut() {
        let note = format!("scanned to {scanned_to} of {top_of} · {batches} batch(es) · {matched_total} block(s) read{}", if waiting { " · the provider's index is behind the chain" } else { "" });
        changed = s.waiting_for_index != waiting || s.last_note != note;
        s.waiting_for_index = waiting;
        s.last_note = note;
    }
    if changed { save_view(storage, view)?; }
    Ok((batches, view.sp.as_ref().map(|s| s.last_note.clone()).unwrap_or_default()))
}

/// The mempool leg: unconfirmed eligible transactions since the last sequence, matched here.
pub async fn mempool(http: &Arc<dyn EsploraHttp>, base: &str, root_key: &RootKey, view: &mut Tier2View, storage: &dyn LijStorage, now_ms: u64) -> LijResult<usize> {
    let sp = match view.sp.clone() { Some(s) if s.available => s, _ => return Ok(0) };
    let keys = SpKeys::from_root(root_key)?;
    let secp = Secp256k1::new();
    let labels = keys.label_set(&crate::tier2_wallet::load_marks(storage).unwrap_or_default().sp_scan_labels());   // v304
    let resp: SpMempoolResp = get_json(http, &format!("{base}/sp/mempool?since={}", sp.mempool_seq)).await?;
    let mut found = 0usize;
    let mut changed = false;
    let gone: std::collections::HashSet<&String> = resp.gone.iter().collect();
    for e in resp.tweaks.iter() {
        let Some(tweak) = hex::decode(&e.tweak).ok().and_then(|b| PublicKey::from_slice(&b).ok()) else { continue };
        let Ok(txid) = bitcoin::Txid::from_str(&e.txid) else { continue };
        let outs: Vec<(u32, [u8; 32], u64)> = e.outputs.iter().filter_map(|o| {
            let k = hex::decode(&o.key).ok()?;
            if k.len() != 32 { return None; }
            let mut key = [0u8; 32]; key.copy_from_slice(&k);
            Some((o.vout, key, o.value))
        }).collect();
        for f in keys.find_in_outputs(&secp, &tweak, txid, &outs, &labels) {
            let already = view.utxos.iter().any(|u| u.txid == e.txid && u.vout == f.vout)
                || view.sp.as_ref().map(|s| s.pending.iter().any(|p| p.txid == e.txid && p.vout == f.vout)).unwrap_or(false);
            if already { continue; }
            if let Some(s) = view.sp.as_mut() {
                s.pending.push(SpPending { txid: e.txid.clone(), vout: f.vout, value_sats: f.value_sats, t_k: tweak_hex(&f.t_k), k: f.k, seen_ms: now_ms, label: f.label });
            }
            found += 1; changed = true;
            log::info!("[sp] silent payment in the mempool: {}:{} {} sats", &e.txid[..12], f.vout, f.value_sats);
        }
    }
    if let Some(s) = view.sp.as_mut() {
        let before = s.pending.len();
        s.pending.retain(|p| !gone.contains(&p.txid) || view.utxos.iter().any(|u| u.txid == p.txid && u.vout == p.vout));
        // a pending that confirmed is dropped by the scan; one gone from the pool without confirming is dropped here
        s.pending.retain(|p| !view.utxos.iter().any(|u| u.txid == p.txid && u.vout == p.vout));
        if s.pending.len() != before { changed = true; }
        if resp.seq != s.mempool_seq { s.mempool_seq = resp.seq; changed = true; }
    }
    if changed { save_view(storage, view)?; }
    Ok(found)
}

/// The face's view of the scan (part of the summary).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SpSummary {
    /// v288: the wallet-side switch (CoinMarks::sp_enabled).
    pub enabled: bool,
    pub available: bool,
    pub index_start: u32,
    pub indexed_to: u32,
    pub from: u32,
    pub scanned_to: u32,
    pub top: u32,
    pub done: bool,
    pub waiting_for_index: bool,
    pub single_source: bool,
    pub pending: Vec<SpPending>,
    pub pending_sats: u64,
    pub coins: u32,
    pub note: String,
}

pub fn summary(view: &Tier2View, enabled: bool) -> SpSummary {
    let top = view.cursor.scanned_to;
    match view.sp.as_ref() {
        None => SpSummary { enabled, ..SpSummary::default() },
        Some(s) => SpSummary {
            enabled,
            available: s.available,
            index_start: s.index_start,
            indexed_to: s.indexed_to,
            from: s.from,
            scanned_to: s.scanned_to,
            top,
            done: s.available && (s.scanned_to >= top.min(s.indexed_to)),
            waiting_for_index: s.waiting_for_index,
            single_source: s.single_source,
            pending: s.pending.clone(),
            pending_sats: s.pending.iter().map(|p| p.value_sats).sum(),
            coins: view.utxos.iter().filter(|u| u.chain == CHAIN_SP && u.spent_height.is_none()).count() as u32,
            note: s.last_note.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spcommit_matches_the_box_formula() {
        // the indexer's Python: sha256("spcommit-v1\n" height "\n" hash "\n" count "\n" tweak "\n" …), tweaks sorted as strings
        let h = spcommit_v1(900000, "00ab", &["ff".repeat(33), "0a".repeat(33)]);
        let s = format!("spcommit-v1\n900000\n00ab\n2\n{}\n{}\n", "0a".repeat(33), "ff".repeat(33));
        assert_eq!(h, sha256::Hash::hash(s.as_bytes()).to_string());
        assert_eq!(spcommit_v1(1, "x", &[]), sha256::Hash::hash(b"spcommit-v1\n1\nx\n0\n").to_string());
    }

    #[test]
    fn candidate_scripts_in_groups_equal_the_whole() {   // v293: the budgeted loop computes the same scripts in the same order
        let secp = Secp256k1::new();
        let keys = SpKeys::from_root(&root()).unwrap();
        let tweaks: Vec<PublicKey> = (1u32..=70).map(|i| { let mut b = [0u8; 32]; b[28..].copy_from_slice(&i.to_be_bytes()); b[0] = 1; PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&b).unwrap()) }).collect();
        let whole = keys.candidate_scripts(&secp, &tweaks, &keys.label_set(&[0]));
        let mut grouped = Vec::new();
        for g in tweaks.chunks(SP_TWEAK_GROUP) { grouped.extend(keys.candidate_scripts(&secp, g, &keys.label_set(&[0]))); }
        assert_eq!(whole.len(), 140);
        assert_eq!(whole, grouped);
        assert!(crate::tier2_sync::YIELD_BUDGET_MS > 0.0 && crate::tier2_sync::now_ms() > 0.0);
    }

    #[test]
    fn sp_summary_reads_the_state() {
        let mut view = Tier2View::default();
        assert_eq!(summary(&view, true).available, false);
        view.cursor.scanned_to = 969_100;
        view.sp = Some(SpScan { available: true, index_start: 969_075, indexed_to: 969_100, from: 969_080, scanned_to: 969_090, ..Default::default() });
        let s = summary(&view, true);
        assert_eq!((s.top, s.done, s.coins, s.enabled), (969_100, false, 0, true));
        view.sp.as_mut().unwrap().scanned_to = 969_100;
        assert!(summary(&view, true).done);
        // the index behind the chain: done at the index's top
        view.cursor.scanned_to = 969_105;
        assert!(summary(&view, true).done);
    }

    // ── the scan end to end: a box made of a map, two mined blocks, one real silent payment ──
    use crate::independent::HttpResponse;
    use crate::silent_payment::{derive_output_script, parse, tweak_from_inputs, SpInput};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::key::TapTweak;
    use bitcoin::{Network, OutPoint, Transaction, TxIn, TxOut, Txid, Witness};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MapHttp { routes: Mutex<HashMap<String, (u16, String)>>, calls: Mutex<Vec<String>> }
    impl MapHttp {
        fn new() -> Self { Self { routes: Mutex::new(HashMap::new()), calls: Mutex::new(Vec::new()) } }
        fn put(&self, path: &str, status: u16, body: String) { self.routes.lock().unwrap().insert(path.to_string(), (status, body)); }
    }
    impl EsploraHttp for MapHttp {
        fn get<'a>(&'a self, url: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = LijResult<HttpResponse>> + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(url.to_string());
                let path = url.strip_prefix("http://box").unwrap_or(url).to_string();
                match self.routes.lock().unwrap().get(&path) {
                    Some((st, body)) => Ok(HttpResponse { status: *st, body: body.clone() }),
                    None => Ok(HttpResponse { status: 404, body: format!("no route {path}") }),
                }
            })
        }
        fn post<'a>(&'a self, _u: &'a str, _b: &'a [u8], _c: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = LijResult<HttpResponse>> + 'a>> {
            Box::pin(async { Err(LijError::Node("no post".into())) })
        }
    }

    fn root() -> RootKey {
        let m: bip39::Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap();
        RootKey::from_mnemonic(&m, Network::Bitcoin).unwrap()
    }

    /// Mine a regtest-target block (the header's PoW is real, the target is the easy one).
    fn mine(prev: BlockHash, txs: Vec<Transaction>, time: u32) -> Block {
        let mut block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: txs,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        while block.header.validate_pow(block.header.target()).is_err() { block.header.nonce += 1; }
        block
    }

    fn coinbase(height: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig: bitcoin::script::Builder::new().push_int(height as i64).into_script(), sequence: bitcoin::Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: bitcoin::Amount::from_sat(50_000), script_pubkey: ScriptBuf::new_op_return(&[]) }],
        }
    }

    /// The box's filter for a block: BIP158 basic (input prevout scripts from `prevouts`, every output script).
    fn basic_filter(block: &Block, prevouts: &HashMap<OutPoint, ScriptBuf>) -> Vec<u8> {
        bitcoin::bip158::BlockFilter::new_script_filter(block, |op| prevouts.get(op).cloned().ok_or(bitcoin::bip158::Error::UtxoMissing(*op))).unwrap().content
    }

    struct Served { height: u32, block: Block, filter: Vec<u8>, fh: [u8; 32], tweaks: Vec<String> }

    fn serve(http: &MapHttp, blocks: &[Served], tamper_commit: bool) {
        let heights: Vec<u32> = blocks.iter().map(|b| b.height).collect();
        let (lo, hi) = (*heights.iter().min().unwrap(), *heights.iter().max().unwrap());
        for start in lo..=hi {
            for count in 1..=(hi - start + 1) {
                let end = start + count - 1;
                let sel: Vec<&Served> = blocks.iter().filter(|b| b.height >= start && b.height <= end).collect();
                let hdrs: Vec<serde_json::Value> = sel.iter().map(|b| serde_json::json!({"height": b.height, "hash": b.block.block_hash().to_string(), "header": hex::encode(bitcoin::consensus::serialize(&b.block.header))})).collect();
                let flts: Vec<serde_json::Value> = sel.iter().map(|b| serde_json::json!({"height": b.height, "hash": b.block.block_hash().to_string(), "filter": hex::encode(&b.filter), "filter_header": bitcoin::hashes::sha256d::Hash::from_byte_array(b.fh).to_string()})).collect();
                let tw: Vec<serde_json::Value> = sel.iter().map(|b| {
                    let mut commit = spcommit_v1(b.height, &b.block.block_hash().to_string(), &b.tweaks);
                    if tamper_commit { commit = "00".repeat(32); }
                    serde_json::json!({"height": b.height, "hash": b.block.block_hash().to_string(), "count": b.tweaks.len(), "commit": commit, "tweaks": b.tweaks})
                }).collect();
                http.put(&format!("/headers?start={start}&count={count}"), 200, serde_json::json!({"headers": hdrs}).to_string());
                http.put(&format!("/filters?start={start}&count={count}"), 200, serde_json::json!({"filters": flts}).to_string());
                http.put(&format!("/sp/tweaks?start={start}&count={count}"), 200, serde_json::json!({"blocks": tw}).to_string());
            }
        }
        for b in blocks {
            http.put(&format!("/block/{}", b.height), 200, serde_json::json!({"block": hex::encode(bitcoin::consensus::serialize(&b.block))}).to_string());
        }
    }

    /// Two blocks: 101 carries a silent payment of 184,000 sats to the wallet (and a decoy taproot output);
    /// 102 spends that coin. Returns the box, the blocks, the paid script and the mempool tweak of a third,
    /// unconfirmed payment (777 sats).
    fn build_world(tamper_commit: bool) -> (Arc<MapHttp>, Vec<Served>, ScriptBuf, (PublicKey, Txid, [u8; 32])) {
        build_world_to(tamper_commit, None)
    }

    /// v304: the same world, the payments made to label `label`'s address instead of the plain one.
    fn build_world_to(tamper_commit: bool, label: Option<u32>) -> (Arc<MapHttp>, Vec<Served>, ScriptBuf, (PublicKey, Txid, [u8; 32])) {
        let secp = Secp256k1::new();
        let keys = SpKeys::from_root(&root()).unwrap();
        let addr = match label {
            None => parse(&keys.address(), Network::Bitcoin).unwrap(),
            Some(m) => parse(&keys.label_address(&secp, m).unwrap(), Network::Bitcoin).unwrap(),
        };
        // the sender: one P2WPKH input
        let a1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a1_pub = PublicKey::from_secret_key(&secp, &a1);
        let a1_spk = ScriptBuf::new_p2wpkh(&bitcoin::PublicKey::new(a1_pub).wpubkey_hash().unwrap());
        let op1 = OutPoint { txid: Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16").unwrap(), vout: 0 };
        let paid = derive_output_script(&secp, &[SpInput { secret: a1, outpoint: op1, taproot: false }], &addr).unwrap();
        let tweak = tweak_from_inputs(&secp, &[a1_pub], &[op1]).unwrap();
        let pay_tx = Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: op1, script_sig: ScriptBuf::new(), sequence: bitcoin::Sequence::MAX, witness: Witness::from_slice(&[vec![0u8; 71], a1_pub.serialize().to_vec()]) }],
            output: vec![
                TxOut { value: bitcoin::Amount::from_sat(5_000), script_pubkey: ScriptBuf::new_p2tr_tweaked(bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[9u8; 32]).unwrap().dangerous_assume_tweaked()) },
                TxOut { value: bitcoin::Amount::from_sat(184_000), script_pubkey: paid.clone() },
            ],
        };
        let mut prevouts: HashMap<OutPoint, ScriptBuf> = HashMap::new();
        prevouts.insert(op1, a1_spk.clone());
        let genesis = BlockHash::from_str("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206").unwrap();
        let b101 = mine(genesis, vec![coinbase(101), pay_tx.clone()], 1_700_000_000);
        let f101 = basic_filter(&b101, &prevouts);
        let fh101 = crate::tier2_sync::compute_filter_header(&f101, &[0u8; 32]);
        // 102: the wallet's coin is spent (by someone holding its key — the scan only needs the outpoint)
        let spend_tx = Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: pay_tx.compute_txid(), vout: 1 }, script_sig: ScriptBuf::new(), sequence: bitcoin::Sequence::MAX, witness: Witness::from_slice(&[vec![0u8; 64]]) }],
            output: vec![TxOut { value: bitcoin::Amount::from_sat(183_000), script_pubkey: a1_spk.clone() }],
        };
        prevouts.insert(OutPoint { txid: pay_tx.compute_txid(), vout: 1 }, paid.clone());
        let b102 = mine(b101.block_hash(), vec![coinbase(102), spend_tx], 1_700_000_600);
        let f102 = basic_filter(&b102, &prevouts);
        let fh102 = crate::tier2_sync::compute_filter_header(&f102, &fh101);
        let decoy_tweak = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let blocks = vec![
            Served { height: 101, block: b101, filter: f101, fh: fh101, tweaks: vec![hex::encode(decoy_tweak.serialize()), hex::encode(tweak.serialize())] },
            Served { height: 102, block: b102, filter: f102, fh: fh102, tweaks: vec![] },
        ];
        let http = Arc::new(MapHttp::new());
        serve(&http, &blocks, tamper_commit);
        http.put("/sp/info", 200, serde_json::json!({"format": "spcommit-v1", "start_height": 101, "indexed_to": 102, "tip": 102, "mempool_seq": 5}).to_string());
        // a third payment, unconfirmed: another sender, 777 sats
        let a2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let op2 = OutPoint { txid: Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap(), vout: 1 };
        let paid2 = derive_output_script(&secp, &[SpInput { secret: a2, outpoint: op2, taproot: false }], &addr).unwrap();
        let tweak2 = tweak_from_inputs(&secp, &[PublicKey::from_secret_key(&secp, &a2)], &[op2]).unwrap();
        let mut key2 = [0u8; 32]; key2.copy_from_slice(&paid2.as_bytes()[2..34]);
        let txid2 = Txid::from_str("b1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap();
        http.put("/sp/mempool?since=0", 200, serde_json::json!({"seq": 6, "tweaks": [{"seq": 6, "txid": txid2.to_string(), "tweak": hex::encode(tweak2.serialize()), "outputs": [{"vout": 0, "key": hex::encode(key2), "value": 777}, {"vout": 1, "key": hex::encode([8u8; 32]), "value": 1}]}], "gone": []}).to_string());
        http.put("/sp/mempool?since=6", 200, serde_json::json!({"seq": 6, "tweaks": [], "gone": [txid2.to_string()]}).to_string());
        (http, blocks, paid, (tweak2, txid2, key2))
    }

    #[tokio::test]
    async fn the_scan_finds_a_silent_payment_then_its_spend_and_the_mempool_leg_a_pending_one() {
        let (http, blocks, paid, _) = build_world(false);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let secp = Secp256k1::new();
        let keys = SpKeys::from_root(&root()).unwrap();
        // the m/84 walk has read 101 only, anchored by its hash + filter header
        let mut view = Tier2View::default();
        view.cursor.birthday = 90;
        view.cursor.scanned_to = 101;
        view.cursor.last_hash = Some(blocks[0].block.block_hash().to_string());
        view.cursor.last_filter_header = Some(bitcoin::hashes::sha256d::Hash::from_byte_array(blocks[0].fh).to_string());
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        let sp = view.sp.clone().unwrap();
        assert!(sp.available);
        assert_eq!((sp.index_start, sp.indexed_to, sp.from, sp.scanned_to), (101, 102, 101, 100), "a fresh view scans from the later of the index start and the birthday");
        // scan: one batch, block 101 matched, the coin on the ledger as chain 352 with its tweak
        let (batches, note) = scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(batches, 1, "{note}");
        assert_eq!(view.utxos.len(), 1, "{:?}", view.utxos);
        let u = &view.utxos[0];
        assert_eq!((u.chain, u.index, u.vout, u.value_sats, u.height, u.spent_height), (CHAIN_SP, 0, 1, 184_000, 101, None));
        let mut t_k = [0u8; 32]; t_k.copy_from_slice(&hex::decode(u.sp_tweak.as_deref().unwrap()).unwrap());
        assert_eq!(keys.script_for(&secp, &t_k).unwrap(), paid, "the ledger's tweak rebuilds the paid script");
        let sp = view.sp.clone().unwrap();
        assert_eq!((sp.scanned_to, sp.scanned_hash.as_str()), (101, blocks[0].block.block_hash().to_string().as_str()));
        assert_eq!(view.block_times.get(&101), Some(&1_700_000_000));
        // v289: the derived row says how much of it was a silent payment
        let rows = crate::tier2_wallet::derive_history(&view);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].delta_sats, rows[0].silent_payment_sats), (184_000, 184_000));
        let sum = summary(&view, true);
        assert_eq!((sum.done, sum.coins, sum.top, sum.scanned_to), (true, 1, 101, 101));
        // saved: the view on disk carries the scan
        let saved = crate::tier2_wallet::load_view(&storage).unwrap();
        assert_eq!(saved.sp, view.sp);
        // nothing new: no batch
        assert_eq!(scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap().0, 0);
        // the mempool leg: the 777-sat payment is pending (its decoy output is not), the cursor moves
        let n = mempool(&http, "http://box", &root(), &mut view, &storage, 1_700_000_100_000).await.unwrap();
        assert_eq!(n, 1);
        let sp = view.sp.clone().unwrap();
        assert_eq!(sp.mempool_seq, 6);
        assert_eq!(sp.pending.len(), 1);
        assert_eq!((sp.pending[0].vout, sp.pending[0].value_sats, sp.pending[0].k), (0, 777, 0));
        assert_eq!(summary(&view, true).pending_sats, 777);
        // the walk reads 102 (the top moves, linked to 101): the scan follows and sees the coin spent —
        // the batch links to the previous batch's block hash and filter header
        view.cursor.scanned_to = 102;
        view.cursor.last_hash = Some(blocks[1].block.block_hash().to_string());
        view.cursor.last_filter_header = Some(bitcoin::hashes::sha256d::Hash::from_byte_array(blocks[1].fh).to_string());
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        assert_eq!(view.sp.as_ref().unwrap().from, 101, "an opened scan keeps its start");
        let (batches, _) = scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(batches, 1);
        assert_eq!(view.utxos.len(), 1);
        assert_eq!(view.utxos[0].spent_height, Some(102));
        assert_eq!(view.utxos[0].spent_txid.as_deref(), Some(blocks[1].block.txdata[1].compute_txid().to_string().as_str()));
        assert_eq!(summary(&view, true).coins, 0);
        // the pending one left the pool without confirming: dropped
        assert_eq!(mempool(&http, "http://box", &root(), &mut view, &storage, 1_700_000_200_000).await.unwrap(), 0);
        assert!(view.sp.as_ref().unwrap().pending.is_empty());
        // a reorg rollback below the scan rolls the scan back too and clears its anchors
        crate::tier2_wallet::rollback(&mut view, 100);
        let sp = view.sp.as_ref().unwrap();
        assert_eq!((sp.scanned_to, sp.scanned_hash.is_empty(), view.utxos.len()), (100, true, 0));
    }

    #[tokio::test]
    async fn v304_a_payment_to_label_2_is_found_only_when_label_2_is_checked_and_the_restore_keeps_its_number() {
        let (http, blocks, paid, _) = build_world_to(false, Some(2));
        let http: Arc<dyn EsploraHttp> = http;
        let fresh_view = || {
            let mut v = Tier2View::default();
            v.cursor.birthday = 90;
            v.cursor.scanned_to = 101;
            v.cursor.last_hash = Some(blocks[0].block.block_hash().to_string());
            v.cursor.last_filter_header = Some(bitcoin::hashes::sha256d::Hash::from_byte_array(blocks[0].fh).to_string());
            v
        };
        // a wallet that made no labels does not check label 2 (and pays no filter cost for it)
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = fresh_view();
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert!(view.utxos.is_empty(), "label 2 is not checked: {:?}", view.utxos);
        // a words-only restore checks all ten: found, tagged 2, and the marks keep the number (no name yet)
        let storage = crate::storage::native_storage::MemoryStorage::new();
        crate::tier2_wallet::save_marks(&storage, &crate::tier2_wallet::CoinMarks { sp_labels_unknown: true, ..Default::default() }).unwrap();
        let mut view = fresh_view();
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(view.utxos.len(), 1, "{:?}", view.utxos);
        assert_eq!((view.utxos[0].sp_label, view.utxos[0].value_sats), (Some(2), 184_000));
        let secp = Secp256k1::new();
        let keys = SpKeys::from_root(&root()).unwrap();
        let mut t = [0u8; 32]; t.copy_from_slice(&hex::decode(view.utxos[0].sp_tweak.as_deref().unwrap()).unwrap());
        assert_eq!(keys.script_for(&secp, &t).unwrap(), paid, "its stored t rebuilds the labelled script — the spend and the kit work unchanged");
        let marks = crate::tier2_wallet::load_marks(&storage).unwrap();
        assert_eq!(marks.sp_labels.iter().map(|l| (l.m, l.name.clone())).collect::<Vec<_>>(), vec![(2, String::new())]);
        // a wallet that made label 2 checks it (and only it, with the change label)
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut m = crate::tier2_wallet::CoinMarks::default();
        m.sp_label_create("One", 1).unwrap();
        m.sp_label_create("Two", 2).unwrap();
        assert_eq!(m.sp_scan_labels(), vec![0, 1, 2]);
        crate::tier2_wallet::save_marks(&storage, &m).unwrap();
        let mut view = fresh_view();
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(view.utxos.iter().map(|u| u.sp_label).collect::<Vec<_>>(), vec![Some(2)]);
        assert_eq!(crate::tier2_wallet::load_marks(&storage).unwrap().sp_label(2).unwrap().name, "Two", "a named label keeps its name");
    }

    #[tokio::test]
    async fn a_box_whose_commitment_does_not_match_its_tweaks_is_refused() {
        // decision 2: every served block's commitment is recomputed from the served tweaks
        let (http, blocks, _, _) = build_world(true);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 101;
        view.cursor.last_hash = Some(blocks[0].block.block_hash().to_string());
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        let err = scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap_err().to_string();
        assert!(err.contains("commitment"), "{err}");
        assert!(view.utxos.is_empty());
        assert_eq!(view.sp.as_ref().unwrap().scanned_to, 100, "nothing advanced");
    }

    #[tokio::test]
    async fn a_provider_without_the_index_is_simply_not_available() {
        let http = Arc::new(MapHttp::new());
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.scanned_to = 500;
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        assert!(!view.sp.as_ref().unwrap().available);
        assert_eq!(scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap().0, 0);
        assert!(!summary(&view, true).available);
        // a view walked before this build (top at 500, not fresh) opens its scan at the top, not the birthday
        let http2 = Arc::new(MapHttp::new());
        http2.put("/sp/info", 200, serde_json::json!({"format": "spcommit-v1", "start_height": 100, "indexed_to": 500, "tip": 500}).to_string());
        let http2: Arc<dyn EsploraHttp> = http2;
        view.cursor.birthday = 200;
        refresh_info(&http2, "http://box", &mut view).await.unwrap();
        assert_eq!(view.sp.as_ref().unwrap().from, 500, "decision 1: an existing wallet's scan starts at today's top");
    }

    /// v297: the walk's anchors at `i` (0 = block 101, 1 = block 102) in the test world.
    fn walk_at(view: &mut Tier2View, blocks: &[Served], i: usize) {
        view.cursor.scanned_to = blocks[i].height;
        view.cursor.last_hash = Some(blocks[i].block.block_hash().to_string());
        view.cursor.last_filter_header = Some(bitcoin::hashes::sha256d::Hash::from_byte_array(blocks[i].fh).to_string());
    }

    #[tokio::test]
    async fn v297_a_scan_paused_by_a_server_without_the_index_resumes_where_it_was() {
        let (http, blocks, _, _) = build_world(false);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.birthday = 90;
        view.cursor.scanned_to = 100;   // the walk stands at 100 when the scan opens (a walked view, not fresh)
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        assert_eq!((view.sp.as_ref().unwrap().from, view.sp.as_ref().unwrap().scanned_to), (101, 100));
        // a server without the index answers for a while (404) — the walk reads 101 (the payment) and 102 (its spend)
        let none: Arc<dyn EsploraHttp> = Arc::new(MapHttp::new());
        refresh_info(&none, "http://box", &mut view).await.unwrap();
        assert!(!view.sp.as_ref().unwrap().available);
        walk_at(&mut view, &blocks, 1);
        // the index is back: the scan resumes at 101. Before v297 it re-opened at the walk's top (from 102, scanned to
        // 101) and the payment in block 101 was never read.
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        let sp = view.sp.clone().unwrap();
        assert_eq!((sp.available, sp.from, sp.scanned_to), (true, 101, 100), "an opened scan resumes where it stood");
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(view.utxos.len(), 1, "the payment in block 101 is found");
        assert_eq!((view.utxos[0].value_sats, view.utxos[0].spent_height), (184_000, Some(102)));
    }

    #[tokio::test]
    async fn v297_a_ledger_rebuild_reads_the_silent_payments_again() {
        let (http, blocks, _, _) = build_world(false);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.birthday = 90;
        walk_at(&mut view, &blocks, 0);
        view.cursor.scanned_to = 0;   // fresh: the scan starts at the later of the index start and the birthday
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        walk_at(&mut view, &blocks, 0);
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!((view.utxos.len(), view.sp.as_ref().unwrap().scanned_to), (1, 101));
        // a ledger rebuild (a new ledger schema, or the net widened) clears every coin — the silent-payment coins too
        crate::tier2_wallet::rebuild_from_birthday(&mut view, 1);
        assert!(view.utxos.is_empty());
        let sp = view.sp.clone().unwrap();
        assert_eq!((sp.from, sp.scanned_to, sp.scanned_hash.is_empty()), (101, 100, true),
            "the scan starts again from its own start (before v297 it stayed at 101 and the coin was never read again)");
        // the walk reads its way back to 101; the scan follows and finds the coin again
        walk_at(&mut view, &blocks, 0);
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(view.utxos.len(), 1, "the silent-payment coin is back on the ledger");
        assert_eq!((view.utxos[0].chain, view.utxos[0].value_sats, view.utxos[0].spent_height), (CHAIN_SP, 184_000, None));
    }

    #[tokio::test]
    async fn v297_a_coin_paid_and_spent_inside_one_batch_is_seen_spent() {
        // a restore: the walk is at 102; the scan reads 101 (the payment) and 102 (its spend) in ONE batch
        let (http, blocks, _, _) = build_world(false);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.birthday = 90;
        refresh_info(&http, "http://box", &mut view).await.unwrap();   // fresh: from 101
        walk_at(&mut view, &blocks, 1);
        let (batches, _) = scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        assert_eq!(batches, 1);
        assert_eq!(view.utxos.len(), 1);
        assert_eq!(view.utxos[0].spent_height, Some(102), "the spend in the same batch is read (before v297 the coin stayed unspent)");
        assert_eq!(summary(&view, true).coins, 0, "no coin left on the balance");
    }

    #[tokio::test]
    async fn v298_the_drill_down_reads_the_wallets_own_data() {
        // a restore: the walk is at 102; the scan reads the payment (101) and its spend (102) — both kept whole
        let (http, blocks, paid, _) = build_world(false);
        let http: Arc<dyn EsploraHttp> = http;
        let storage = crate::storage::native_storage::MemoryStorage::new();
        let mut view = Tier2View::default();
        view.cursor.birthday = 90;
        refresh_info(&http, "http://box", &mut view).await.unwrap();
        walk_at(&mut view, &blocks, 1);
        scan(&http, "http://box", &root(), &mut view, &storage, 100, 0).await.unwrap();
        let pay = blocks[0].block.txdata[1].clone();
        let spend = blocks[1].block.txdata[1].clone();
        let (pay_id, spend_id) = (pay.compute_txid().to_string(), spend.compute_txid().to_string());
        let kept = crate::tx_store::load(&storage);
        assert_eq!(kept.txs.len(), 2, "the payment and its spend are kept, nothing else: {:?}", kept.txs.keys().collect::<Vec<_>>());
        assert_eq!((kept.txs[&pay_id].height, kept.txs[&spend_id].height), (101, 102));
        assert!(!kept.txs.contains_key(&blocks[0].block.txdata[0].compute_txid().to_string()), "the coinbase is not ours");
        // the drill-down for the payment: built from the kept bytes and the ledger, no outside source
        let parents = |id: &str| crate::tx_store::load(&storage).tx(id);
        let none = |_: &str| false;
        let k = crate::tx_store::get(&storage, &pay_id).unwrap();
        assert_eq!(k.weight, pay.weight().to_wu(), "v300: kept without signatures, the full weight beside it");
        let (etx, fee_known) = crate::tier2_wallet::drill_tx(&view, &[], &parents, &k.tx, Network::Bitcoin, crate::tier2_wallet::ledger_height_of(&view, &pay_id), Some(k.weight));
        assert_eq!(etx.weight, pay.weight().to_wu());
        let own = crate::tier2_wallet::tx_ownership(&view, &etx, &none);
        assert!(!fee_known, "the sender's input is not the wallet's to know: no fee for a receive");
        assert_eq!((own.our_in, own.our_out, own.is_send, own.pick), (0, 184_000, false, Some(1)));
        let addr = bitcoin::Address::from_script(&paid, Network::Bitcoin).unwrap().to_string();
        assert_eq!(etx.vouts[1].address.as_deref(), Some(addr.as_str()), "the address of record is the taproot output the payment made");
        assert_eq!((etx.vouts[1].script_type.as_str(), etx.block_height, etx.block_time), ("v1_p2tr", Some(101), Some(1_700_000_000)));
        // the spend: the input is the wallet's coin (the ledger's value, the kept parent's script) — the fee is exact
        let k = crate::tx_store::get(&storage, &spend_id).unwrap();
        let (etx, fee_known) = crate::tier2_wallet::drill_tx(&view, &[], &parents, &k.tx, Network::Bitcoin, crate::tier2_wallet::ledger_height_of(&view, &spend_id), Some(k.weight));
        let own = crate::tier2_wallet::tx_ownership(&view, &etx, &none);
        assert!(fee_known);
        assert_eq!((etx.fee, own.our_in, own.is_send, own.pick, etx.vins[0].script_type.as_str()), (1_000, 184_000, true, Some(0), "v1_p2tr"));
        assert_eq!(etx.block_height, Some(102));
        // a row from before v298 (nothing kept): its block is read once more from the filter server, the
        // transaction checked by its txid, every own transaction in that block kept
        let s2 = crate::storage::native_storage::MemoryStorage::new();
        crate::tier2_wallet::save_view(&s2, &{ let mut v = view.clone(); v.fresh_txs.clear(); v }).unwrap();
        assert!(crate::tx_store::load(&s2).txs.is_empty());
        let r = crate::tier2_wallet::reread_own_tx(&http, "http://box", &s2, &pay_id, 101).await.unwrap();
        assert_eq!(r.map(|(t, h)| (t.compute_txid().to_string(), h)), Some((pay_id.clone(), 101)));
        assert!(crate::tx_store::get(&s2, &pay_id).is_some(), "kept after the one re-read");
        // a block that does not hold it (a reorg moved it): nothing made up
        assert!(crate::tier2_wallet::reread_own_tx(&http, "http://box", &s2, &spend_id, 101).await.unwrap().is_none());
    }

    #[test]
    fn add_coin_is_idempotent_and_tags_chain_352() {
        let mut view = Tier2View::default();
        let f = crate::silent_payment::SpFound { txid: bitcoin::Txid::all_zeros(), vout: 1, value_sats: 5_000, t_k: [7u8; 32], k: 0, script: ScriptBuf::new(), labelled_change: false, label: None };
        assert!(add_coin(&mut view, &f, 10));
        assert!(!add_coin(&mut view, &f, 10));
        assert_eq!(view.utxos.len(), 1);
        assert_eq!(view.utxos[0].chain, CHAIN_SP);
        assert_eq!(view.utxos[0].sp_tweak.as_deref(), Some("07".repeat(32).as_str()));
    }
}
