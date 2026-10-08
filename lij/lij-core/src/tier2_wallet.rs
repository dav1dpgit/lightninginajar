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

pub const VIEW_KEY: &str = "tier2_view";
/// v281 (S50, coin control): the user's marks on coins — frozen, note — keyed by outpoint.
/// Its OWN key beside the view: a sync loads the view, walks the chain across network
/// I/O and saves it back, so a mark written mid-walk inside the view would be clobbered
/// (the pending list was split off for the same reason). Encrypted at rest like the view,
/// packed in the backup blob (node.rs gather_state_blob), wiped by Erase. Never rebuilt:
/// a rescan, a rollback or a reorg recreates coin RECORDS, never marks (DP 2026-09-28:
/// "a wipe is a wipe" — but a rescan keeps freezes).
pub const MARKS_KEY: &str = "tier2_marks";
/// v263 (S47): the ONE list of on-chain keys encrypted at rest (v256), and the one way to
/// read them. v256 encrypted the view but left four readers on plain storage (the on-chain
/// send, the fee bump, the channel-open estimate and the funding build) — each failed with
/// "tier2 view parse: expected value at line 1 column 1". Every reader goes through this.
pub const ENCRYPTED_KEYS: &[&str] = &[VIEW_KEY, MARKS_KEY, crate::nwc::NWC_KEY, crate::tx_store::TX_STORE_KEY];   // v298: the wallet's own transactions too   // the pending list stays plain: node.rs reads it in four places · v286: the NWC connections (service secrets) are encrypted at rest too
pub fn encrypted<S: LijStorage>(inner: S, key: [u8; 32]) -> crate::storage::EncryptedKeys<S> {
    crate::storage::EncryptedKeys::new(inner, key, ENCRYPTED_KEYS)
}   // v220: pub — the blob packs it (D3)

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
    /// v255: the transaction that spent it — so the history can be DERIVED from the
    /// output set (see derive_history) instead of kept as a second list that can drift.
    #[serde(default)]
    pub spent_txid: Option<String>,
    /// v284 (S50): a silent-payment coin's `t_k` (32 bytes hex) — the scalar that, added to the
    /// spend key, spends it, and from which its script is rebuilt. Chain 352 only; None elsewhere.
    /// Recomputed by the scan whenever the coin is found again (a rebuild loses nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sp_tweak: Option<String>,
    /// v304 (S54): the silent-payment label the coin was paid to — Some(m ≥ 1) a labelled address, Some(0) the
    /// change label (another wallet on the same words), None the plain address or not a silent payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sp_label: Option<u32>,
}

/// v281 (S50, coin control): a user's mark on one coin. Frozen = never picked by a send,
/// by Max or by a channel open (the user can still choose it by hand once unfrozen).
/// Note = up to 120 code points, cleaned (controls, zero-width and bidi marks removed,
/// whitespace collapsed) — the same discipline as the address and Push Key notes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoinMark {
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub note: String,
    /// When the mark last changed (ms since the epoch); display only.
    #[serde(default)]
    pub ts_ms: u64,
}

/// v281: every mark, keyed by outpoint `"<txid>:<vout>"`. See MARKS_KEY for why this is
/// its own store. An entry that is neither frozen nor noted is dropped on write.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinMarks {
    #[serde(default)]
    pub marks: std::collections::HashMap<String, CoinMark>,
    /// v288 (S50, DP: "the wallet has a say"): the wallet-side silent-payment switch. On by default;
    /// off = the engine runs no silent-payment scan and the page shows no sp1 address. Kept here,
    /// not in the view: the view is rewritten by a sync in flight and rebuilt on a rescan; the
    /// user's choice must survive both.
    #[serde(default = "default_true")]
    pub sp_enabled: bool,
    /// v298 (S52, DP 23:43 "Go on #3"): the sp1 address a send from this wallet was typed to, by txid. The chain
    /// shows only the one-time taproot output the sp1 address made; the sp1 itself exists only on the phone that
    /// sent it. Kept here (the marks ride the backup blob), not in the pending list that is dropped at confirmation.
    #[serde(default)]
    pub sp_sends: std::collections::BTreeMap<String, String>,
    /// v306 (S54, DP 2026-10-03 — the sender's details list every recipient): a send to several, by txid — every
    /// recipient AS TYPED (an sp1 stays an sp1), in output order, with its sats. The pending record keeps them only until
    /// the block; these ride the backup blob. A fee bump carries them to the replacement's txid.
    #[serde(default)]
    pub send_dests: std::collections::BTreeMap<String, Vec<(String, u64)>>,
    /// v300 (S52, DP 00:25 "if a wallet approaches 1000 transactions, some notification … delete old data or expand
    /// the size"): the user's ceiling for the kept transactions (0 = the default, tx_store::TX_STORE_CAP; the larger
    /// steps are tx_store::CAP_STEPS). Here so it rides the backup and survives a rescan.
    #[serde(default)]
    pub tx_keep_cap: u32,
    /// v304 (S54, DP 2026-10-02 13:50): the silent-payment labels this wallet made (or found coins under) — number,
    /// name, hidden. Here so they ride the backup blob (sealed) and survive a rescan. The number is derived from the
    /// words (never stored as a secret); the name exists only here.
    #[serde(default)]
    pub sp_labels: Vec<SpLabel>,
    /// v304: a restore from the 12 words alone (no backup came with it) cannot know which labels were handed out, so
    /// it checks all ten (SP_LABEL_MAX) — and keeps checking them, since a label given out before the phone was lost
    /// can still be paid. A backup restore brings the real list (this flag false) and checks only those.
    #[serde(default)]
    pub sp_labels_unknown: bool,
    /// v318 (S57, DP 2026-10-07 23:10 "Leave it on the main coin branch, and can we mark them in the wallet and the
    /// same information kept in the encrypted recovery blob?"): the m/86'/{coin}'/0'/0 indexes handed to a pool as an
    /// exit address. A Mix coin sits on BIP86's ordinary receive branch, where a later "Receive to a taproot address"
    /// would put plain coins too; this mark is what tells them apart. Marked when the index is handed out (before any
    /// coin exists), here so it rides the backup blob (MARKS_KEY is sealed and in BUNDLE_SINGLE_KEYS) and survives a
    /// rescan. A words-only restore has no marks: its taproot coins read as plain until a backup brings them.
    #[serde(default)]
    pub mix_exits: std::collections::BTreeSet<u32>,
}

impl CoinMarks {
    /// v318: is this coin a Mix exit (paid to a marked m/86 receive index)?
    pub fn is_mix(&self, u: &OnchainUtxo) -> bool {
        u.chain == crate::tier2::CHAIN_BIP86 && self.mix_exits.contains(&u.index)
    }
}

/// v318: the next m/86 receive index to hand out (a Mix exit now; a taproot receive later) — past every index the
/// ledger has seen paid AND every index already handed to a pool, paid or not.
pub fn next_tr_receive_index(view: &Tier2View, marks: &CoinMarks) -> u32 {
    let seen = next_index_for_chain(view, &[], crate::tier2::CHAIN_BIP86);
    let handed = marks.mix_exits.iter().next_back().map(|m| m + 1).unwrap_or(0);
    seen.max(handed)
}

/// v304: one silent-payment label. `name` empty = never named here (a coin found under it after a words-only
/// restore) — the page shows "Label m". Hidden = off the Receive pills; still checked, payments still tagged.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpLabel {
    pub m: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub created_ms: u64,
}

/// v304: the cap on a label name, in code points.
pub const SP_LABEL_NAME_MAX_CHARS: usize = 40;

fn default_true() -> bool { true }

impl Default for CoinMarks {
    fn default() -> Self { Self { marks: Default::default(), sp_enabled: true, sp_sends: Default::default(), send_dests: Default::default(), tx_keep_cap: 0, sp_labels: Vec::new(), sp_labels_unknown: false, mix_exits: Default::default() } }
}

/// v281: the cap on a coin note, in code points (the address note's and the Push Key
/// note's cap — one number across the wallet).
pub const COIN_NOTE_MAX_CHARS: usize = 120;

/// v281: clean a user-typed note: control characters (C0/C1), zero-width and bidi marks
/// and the BOM removed, tabs/newlines made spaces, runs of whitespace collapsed, trimmed,
/// cut at COIN_NOTE_MAX_CHARS code points. (No NFC here — the page normalises before
/// it hands the text over; the engine has no normalisation table.)
pub fn clean_note(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(4 * COIN_NOTE_MAX_CHARS));
    let mut last_space = true;   // trims leading whitespace
    let mut n = 0usize;
    for c in raw.chars() {
        let drop = (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
            || matches!(c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'   // zero-width space/non-joiner/joiner/word-joiner, BOM
                | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');   // bidi marks and embeddings
        if drop {
            continue;
        }
        let is_ws = c.is_whitespace();
        if is_ws {
            if last_space {
                continue;
            }
            out.push(' ');
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
        n += 1;
        if n >= COIN_NOTE_MAX_CHARS {
            break;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

impl CoinMarks {
    pub fn key(txid: &str, vout: u32) -> String {
        format!("{}:{vout}", txid.to_ascii_lowercase())
    }
    pub fn get(&self, txid: &str, vout: u32) -> Option<&CoinMark> {
        self.marks.get(&Self::key(txid, vout))
    }
    pub fn is_frozen(&self, txid: &str, vout: u32) -> bool {
        self.get(txid, vout).map(|m| m.frozen).unwrap_or(false)
    }
    /// The frozen outpoints as a set — what every coin picker filters against.
    pub fn frozen_set(&self) -> std::collections::HashSet<(String, u32)> {
        self.marks
            .iter()
            .filter(|(_, m)| m.frozen)
            .filter_map(|(k, _)| {
                let (txid, vout) = k.rsplit_once(':')?;
                Some((txid.to_string(), vout.parse().ok()?))
            })
            .collect()
    }
    /// Set or clear the freeze on one coin. Returns the mark as stored (None once empty).
    pub fn set_frozen(&mut self, txid: &str, vout: u32, frozen: bool, now_ms: u64) -> Option<CoinMark> {
        let k = Self::key(txid, vout);
        let mut m = self.marks.remove(&k).unwrap_or_default();
        m.frozen = frozen;
        m.ts_ms = now_ms;
        self.put(k, m)
    }
    /// Set (or, with an empty string, clear) the note on one coin — cleaned and capped.
    pub fn set_note(&mut self, txid: &str, vout: u32, note: &str, now_ms: u64) -> Option<CoinMark> {
        let k = Self::key(txid, vout);
        let mut m = self.marks.remove(&k).unwrap_or_default();
        m.note = clean_note(note);
        m.ts_ms = now_ms;
        self.put(k, m)
    }
    fn put(&mut self, k: String, m: CoinMark) -> Option<CoinMark> {
        if !m.frozen && m.note.is_empty() {
            return None;   // nothing to keep
        }
        self.marks.insert(k, m.clone());
        Some(m)
    }
    pub fn frozen_count(&self) -> usize {
        self.marks.values().filter(|m| m.frozen).count()
    }

    // ── v304 (S54): silent-payment labels ──

    /// The labels the scan checks: always the change label (0); every label made or found here; and, after a
    /// words-only restore, all ten.
    pub fn sp_scan_labels(&self) -> Vec<u32> {
        let mut v: Vec<u32> = vec![0];
        if self.sp_labels_unknown {
            v.extend(1..=crate::silent_payment::SP_LABEL_MAX);
        }
        v.extend(self.sp_labels.iter().map(|l| l.m));
        v.sort_unstable();
        v.dedup();
        v
    }
    pub fn sp_label(&self, m: u32) -> Option<&SpLabel> {
        self.sp_labels.iter().find(|l| l.m == m)
    }
    /// Make a new label: the next number after the highest made or found (labels are never reused while known),
    /// at most SP_LABEL_MAX. Returns its number.
    pub fn sp_label_create(&mut self, name: &str, now_ms: u64) -> LijResult<u32> {
        let name = clean_label_name(name);
        if name.is_empty() {
            return Err(LijError::Node("a label needs a name".into()));
        }
        let next = self.sp_labels.iter().map(|l| l.m).max().unwrap_or(0) + 1;
        if next > crate::silent_payment::SP_LABEL_MAX {
            return Err(LijError::Node(format!("all {} labels are used", crate::silent_payment::SP_LABEL_MAX)));
        }
        self.sp_labels.push(SpLabel { m: next, name, hidden: false, created_ms: now_ms });
        Ok(next)
    }
    /// Rename and/or hide (no delete — a label handed out can still be paid; hidden labels are still checked).
    pub fn sp_label_update(&mut self, m: u32, name: Option<&str>, hidden: Option<bool>) -> LijResult<SpLabel> {
        let l = self.sp_labels.iter_mut().find(|l| l.m == m).ok_or_else(|| LijError::Node(format!("no label {m}")))?;
        if let Some(n) = name {
            let n = clean_label_name(n);
            if n.is_empty() {
                return Err(LijError::Node("a label needs a name".into()));
            }
            l.name = n;
        }
        if let Some(h) = hidden {
            l.hidden = h;
        }
        Ok(l.clone())
    }
    /// A coin found under label m (m ≥ 1) that this wallet has no entry for (a words-only restore): keep the number
    /// with no name, so it shows as "Label m" and the scan keeps checking it. Returns true when added.
    pub fn sp_label_ensure(&mut self, m: u32, now_ms: u64) -> bool {
        if m == 0 || self.sp_labels.iter().any(|l| l.m == m) {
            return false;
        }
        self.sp_labels.push(SpLabel { m, name: String::new(), hidden: false, created_ms: now_ms });
        self.sp_labels.sort_by_key(|l| l.m);
        true
    }
}

/// v304: a label name — the note's cleaning, cut at SP_LABEL_NAME_MAX_CHARS code points.
pub fn clean_label_name(raw: &str) -> String {
    let c = clean_note(raw);
    let mut out: String = c.chars().take(SP_LABEL_NAME_MAX_CHARS).collect();
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// v281: persist the marks (JSON, encrypted at rest through the ENCRYPTED_KEYS wrapper).
pub fn save_marks(storage: &dyn LijStorage, marks: &CoinMarks) -> LijResult<()> {
    let bytes = serde_json::to_vec(marks)
        .map_err(|e| LijError::Storage(format!("tier2 marks serialize: {e}")))?;
    storage.set(MARKS_KEY, &bytes)
}

/// v281: load the marks, or an empty set when none were ever written.
pub fn load_marks(storage: &dyn LijStorage) -> LijResult<CoinMarks> {
    match storage.get(MARKS_KEY)? {
        Some(b) => serde_json::from_slice(&b)
            .map_err(|e| LijError::Storage(format!("tier2 marks parse: {e}"))),
        None => Ok(CoinMarks::default()),
    }
}

/// v281 (S50, coin control): one row of the coin list as the page shows it — the coin
/// record plus what the user marked and the kind the ledger knows. `tag` is one of
/// `received` (chain 0), `change` (chain 1), `channel_return` (a close's payout, from the
/// node's closing-txid record), `legacy` (chain 525); `silent_payment` joins with chain 352;
/// v316: `mix` with chain 86.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinRow {
    pub chain: u32,
    pub index: u32,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub height: u32,
    pub tag: String,
    pub frozen: bool,
    pub note: String,
    /// v304: the silent-payment label the coin was paid to (see OnchainUtxo::sp_label).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sp_label: Option<u32>,
}

/// v281: the tag for a coin, from the chain and the ledger's records. v318: and the marks — a BIP86 coin is `mix` when
/// its receive index was handed to a pool (CoinMarks::mix_exits), else `received` (/0) or `change` (/1) like m/84.
pub fn coin_tag(view: &Tier2View, marks: &CoinMarks, u: &OnchainUtxo) -> &'static str {
    if u.chain == CHAIN_LEGACY {
        "legacy"
    } else if u.chain == crate::tier2::CHAIN_SP {
        "silent_payment"
    } else if marks.is_mix(u) {
        "mix"
    } else if u.chain == crate::tier2::CHAIN_BIP86_INTERNAL {
        "change"
    } else if view.closing_txids.contains(&u.txid)
        || matches!(view.kinds.get(&u.txid), Some(TxKind::ChannelClose))
    {
        "channel_return"
    } else if u.chain == CHAIN_CHANGE {
        "change"
    } else {
        "received"
    }
}

impl CoinRow {
    pub fn from_utxo(view: &Tier2View, marks: &CoinMarks, u: &OnchainUtxo) -> CoinRow {
        let m = marks.get(&u.txid, u.vout);
        CoinRow {
            chain: u.chain,
            index: u.index,
            txid: u.txid.clone(),
            vout: u.vout,
            value_sats: u.value_sats,
            height: u.height,
            tag: coin_tag(view, marks, u).to_string(),
            frozen: m.map(|m| m.frozen).unwrap_or(false),
            note: m.map(|m| m.note.clone()).unwrap_or_default(),
            sp_label: u.sp_label,
        }
    }
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
    /// v259: the block's header time (unix seconds); 0 when unknown.
    #[serde(default)]
    pub time: u32,
    /// v289 (S50, SP receive on the page): the sats this transaction paid to the wallet's
    /// silent-payment address (chain 352 coins) — 0 for an ordinary row. The face reads it to
    /// say "silent payment" on the row without matching coins itself.
    #[serde(default)]
    pub silent_payment_sats: u64,
    /// v304 (S54): the labels (m ≥ 1) this transaction paid — the face names them from the marks ("Donations").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sp_labels: Vec<u32>,
    /// v306 (S54, DP 2026-10-03 13:59 — RECEIVE = ONE LINE PER ADDRESS (OR SP LABEL) PER TRANSACTION): on a received
    /// transaction (direction Received, kind Onchain) its lines — one per own address (chain, index) or per
    /// silent-payment label — each with the parts that paid it, in output order. The row stays one per transaction;
    /// the page draws the lines. Empty on a send, a self-move, a channel open or close.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<RecvLine>,
}

/// v306: one received line — an own address (`chain`, `index`; `address` named by the sync from the wallet's scripts,
/// see name_line_addresses) or a silent-payment label (`sp`; `sp_label` None = the plain sp1 address, Some(m) = label
/// m), its total and its parts (vout, sats) in output order.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecvLine {
    pub chain: u32,
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub sp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sp_label: Option<u32>,
    pub value_sats: u64,
    pub parts: Vec<(u32, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// v307: a silent-payment line paying an address a silent payment made before (the same tweak as an earlier coin).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
}

/// v306: a received transaction's coins → its lines (one per own address or sp1 label), in output order.
fn recv_lines(coins: &[&OnchainUtxo], reused: &std::collections::HashSet<(String, u32)>) -> Vec<RecvLine> {
    let mut sorted: Vec<&OnchainUtxo> = coins.to_vec();
    sorted.sort_by_key(|u| u.vout);
    let mut lines: Vec<RecvLine> = Vec::new();
    for u in sorted {
        let sp = u.chain == crate::tier2::CHAIN_SP;
        let at = lines.iter().position(|l| if sp { l.sp && l.sp_label == u.sp_label } else { !l.sp && l.chain == u.chain && l.index == u.index });
        let i = match at {
            Some(i) => i,
            None => {
                lines.push(RecvLine { chain: u.chain, index: if sp { 0 } else { u.index }, sp, sp_label: if sp { u.sp_label } else { None }, value_sats: 0, parts: Vec::new(), address: None, reused: false });
                lines.len() - 1
            }
        };
        lines[i].value_sats = lines[i].value_sats.saturating_add(u.value_sats);
        lines[i].parts.push((u.vout, u.value_sats));
        if reused.contains(&(u.txid.clone(), u.vout)) { lines[i].reused = true; }   // v307
    }
    lines
}

/// v306: the sync names each ordinary line's address from the wallet's own scripts (the (chain, index) the scan matched
/// the coin to). A line whose key is outside the scripts at hand keeps no address (the page shows the parts' outputs).
pub fn name_line_addresses(history: &mut [OnchainHistoryEntry], scripts: &crate::tier2::WalletScripts, network: bitcoin::Network) {
    let mut want: std::collections::HashMap<(u32, u32), Option<String>> = std::collections::HashMap::new();
    for h in history.iter() { for l in &h.lines { if !l.sp { want.insert((l.chain, l.index), None); } } }
    if want.is_empty() { return; }
    for e in &scripts.entries {
        if let Some(slot) = want.get_mut(&(e.chain, e.index)) {
            if slot.is_none() { *slot = bitcoin::Address::from_script(&e.script_pubkey, network).ok().map(|a| a.to_string()); }
        }
    }
    for h in history.iter_mut() {
        for l in h.lines.iter_mut() {
            if !l.sp { if let Some(Some(a)) = want.get(&(l.chain, l.index)) { l.address = Some(a.clone()); } }
        }
    }
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
    /// v305 (S54): every recipient of a send to several, in output order (address, sats) — the fee bump rebuilds
    /// all of them. Empty on a one-recipient send (dest_addr / dest_sats carry it, as before).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dests: Vec<(String, u64)>,
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
    /// v251 (S46, DP's #20 run): per chain, the highest address index ever seen paid —
    /// SPENT outputs included. The window frontier used to come from unspent outputs
    /// only, so a restored wallet whose early addresses were all spent scanned 0..50
    /// while its real activity sat past 50 — the "large gap" DP saw against BlueWallet.
    #[serde(default)]
    pub used_next: std::collections::HashMap<u32, u32>,
    /// v251: the HEAD walk — the newest ~1,500 blocks scanned FIRST after a restore so
    /// recent activity shows within a minute; the historic walk continues behind it and
    /// the two merge when they meet. `heights` are the head's matched blocks, replayed
    /// at the merge so spends of historic outputs resolve.
    #[serde(default)]
    pub head: Option<HeadCursor>,
    /// v253: per chain, the used frontier at which the last widen-and-rewalk was
    /// triggered — a rewalk fires only when the frontier has GROWN past that mark,
    /// so it can never loop (v252's edge test fired on every completed walk).
    #[serde(default)]
    pub rewalk_at: std::collections::HashMap<u32, u32>,
    /// v256 (S46, DP: "one ledger"): the view's rule version. A view below VIEW_SCHEMA is
    /// rebuilt from the birthday under the current rules the next time it is opened.
    #[serde(default)]
    pub schema: u32,
    /// v256: the fixed net — addresses watched per branch from index 0 (LND's recovery
    /// window is 2,500). Widened by NET_WIDTH and the walk redone when a coin lands within
    /// NET_WIDEN_MARGIN of the far edge.
    #[serde(default)]
    pub net_width: u32,
    /// v256: kind tags by transaction id (channel open / sweep, from the pending list).
    #[serde(default)]
    pub kinds: std::collections::HashMap<String, TxKind>,
    /// v271 (running totals, DP 2026-09-21): funding txids of every channel this wallet has
    /// had — the closed-channel log's funding outpoints and the live channels' funding txids,
    /// noted by the sync at each call and only ever added to. Unlike `kinds` this is NOT
    /// walk-derived and is NOT cleared by a rebuild: a funding tx this wallet paid for derives
    /// as ChannelOpen under any walk, because the record of the channel is the node's, not the
    /// scanner's. (Before v271 the S46 rebuild dropped every pre-rebuild open's tag, so those
    /// rows read as plain sends and the Lightning book lost its "+moved to Lightning" rows.)
    #[serde(default)]
    pub funding_txids: std::collections::HashSet<String>,
    /// v272: the same record for CLOSES — every closing txid the closed-channel log has ever
    /// held (plus a live channel's closing txid once its funding spend is sighted), noted at each
    /// sync, only ever added to, NOT cleared by a rebuild. The walk's close hints are computed
    /// from the log at walk time; the log does not ride the cloud copy, so on a reloaded phone a
    /// later rebuild would have tagged the opens (v271's record travels in this view) but not the
    /// closes. Symmetric records, symmetric rows.
    #[serde(default)]
    pub closing_txids: std::collections::HashSet<String>,
    /// v256: close hints by transaction id — true = a close transaction itself, false =
    /// a transaction spending a close's output (a close only when net-incoming).
    #[serde(default)]
    pub close_hints: std::collections::HashMap<String, bool>,
    /// v256: when the newest 144 blocks were last re-walked to re-confirm every recent
    /// spend against the chain (ms since epoch; 0 = never).
    #[serde(default)]
    pub last_tail_verify_ms: u64,
    /// v257 (S46, DP GO — the new process): the DOWNWARD cursor. `cursor` is the top
    /// (the newest block scanned, extended forward as blocks arrive); `down` is the lowest
    /// block scanned so far, read newest-first until it reaches the birthday.
    #[serde(default)]
    pub down: Option<DownCursor>,
    /// v257: spends seen before their coin (newest-first order) — "txid:vout" of the
    /// coin -> (spending txid, height). Recognised by the spender's own pubkey in the
    /// witness (every LiJ address is P2WPKH). Applied the moment the coin's block is read.
    #[serde(default)]
    pub pending_spends: std::collections::HashMap<String, (String, u32)>,
    /// v317 (DP 2026-10-07 22:58 "Proceed with the scanner fix"): the taproot half of pending_spends. A key-path spend's
    /// witness names no key, so a spend of a BIP86 coin the walk has not met yet is known only by its script in the
    /// block's filter (tier2::tr_hits): one hint per (script, block). When the coin is met, the hinted block is read
    /// again and the exact spending input found (resolve_tr_spends) — one extra block per spent coin, nothing asked.
    #[serde(default)]
    pub tr_hints: Vec<TrHint>,
    /// v257: the last sync call's result, for the face and the tapes.
    #[serde(default)]
    pub last_sync: Option<SyncNote>,
    /// v259 (DP: clock time under each on-chain amount): block height -> header time
    /// (unix seconds) for every block the walk fetched, so a derived row can carry its
    /// clock time without another network read.
    #[serde(default)]
    pub block_times: std::collections::HashMap<u32, u32>,
    /// v287 (S50, SP receive): the silent-payment scan's state — where it starts, how far it has
    /// scanned, the mempool cursor, the pending (unconfirmed) silent payments. None until the first
    /// sync under v287 asks the provider whether it serves a tweak index.
    #[serde(default)]
    pub sp: Option<crate::sp_scan::SpScan>,
    /// v298 (S52, DP #2): this call's newly met own transactions (txid, height, raw hex), never persisted with the
    /// view — save_view hands them to the tx store (crate::tx_store), so every place that saves the view keeps them.
    #[serde(skip)]
    pub fresh_txs: Vec<(String, u32, String)>,
}

/// v298 (S52, DP #2): the wallet's own transactions in a block it has just applied — those that created a coin of
/// ours, spent one, or are a spend the newest-first walk met before its coin — noted for the tx store.
pub fn capture_own_txs(view: &mut Tier2View, txs: &[Transaction], height: u32) {
    let mut own: std::collections::HashSet<String> = std::collections::HashSet::new();
    for u in &view.utxos {
        own.insert(u.txid.clone());
        if let Some(t) = u.spent_txid.as_ref() { own.insert(t.clone()); }
    }
    for (t, _) in view.pending_spends.values() { own.insert(t.clone()); }
    if own.is_empty() { return; }
    for tx in txs {
        let id = tx.compute_txid().to_string();
        if own.contains(&id) && !view.fresh_txs.iter().any(|(t, h, _)| *t == id && *h == height) {
            view.fresh_txs.push((id, height, hex::encode(bitcoin::consensus::serialize(tx))));
        }
    }
}

/// v298: the block height the ledger records for a transaction of the wallet's own (the block that created one of
/// its coins, or spent one); None when the ledger does not hold it.
pub fn ledger_height_of(view: &Tier2View, txid: &str) -> Option<u32> {
    for u in &view.utxos {
        if u.txid == txid && u.height > 0 { return Some(u.height); }
        if u.spent_txid.as_deref() == Some(txid) { if let Some(h) = u.spent_height { if h > 0 { return Some(h); } } }
    }
    view.pending_spends.values().find(|(t, h)| t == txid && *h > 0).map(|(_, h)| *h)
}

/// v298: Esplora's name for an output script's kind (what the drill-down's "type" row has always shown).
pub fn script_kind(spk: &bitcoin::Script) -> &'static str {
    if spk.is_p2pkh() { "p2pkh" }
    else if spk.is_p2sh() { "p2sh" }
    else if spk.is_p2wpkh() { "v0_p2wpkh" }
    else if spk.is_p2wsh() { "v0_p2wsh" }
    else if spk.is_p2tr() { "v1_p2tr" }
    else if spk.is_op_return() { "op_return" }
    else if spk.is_p2pk() { "p2pk" }
    else { "unknown" }
}

/// v298 (S52, DP #2): the drill-down's transaction built from the wallet's own data — the raw transaction (kept
/// whole, or re-read from its block) and the ledger. An input's spent output is known when the ledger holds that
/// coin (its value) or its parent transaction is kept (value and script); an input of someone else's is not, and
/// then the fee is not known (`fee_known` false: a receive's fee, a send with another party's inputs). Nothing
/// is asked of anyone.
pub fn drill_tx(
    view: &Tier2View,
    pending: &[PendingTx],
    parents: &dyn Fn(&str) -> Option<Transaction>,
    tx: &Transaction,
    network: bitcoin::Network,
    height: Option<u32>,
    weight: Option<u64>,   // v300: a kept transaction has no signatures; its full weight is kept beside it
) -> (crate::independent::EsploraTx, bool) {
    use crate::independent::{EsploraTx, EsploraTxPrevout, EsploraTxVout};
    let mut fee_known = true;
    let mut in_total: u64 = 0;
    let mut vins = Vec::with_capacity(tx.input.len());
    for i in &tx.input {
        let pt = i.previous_output.txid.to_string();
        let pv = i.previous_output.vout;
        let mut p = EsploraTxPrevout { prev_txid: pt.clone(), prev_vout: pv, ..Default::default() };
        let mut known = false;
        if let Some(u) = view.utxos.iter().find(|u| u.txid == pt && u.vout == pv) {
            p.value = u.value_sats; known = true;
        } else if let Some(q) = pending.iter().find(|q| q.change_outpoint.as_ref() == Some(&(pt.clone(), pv))) {
            p.value = q.change_value_sats; known = true;   // a pending send's change, spent before it confirmed
        }
        if let Some(parent) = parents(&pt) {
            if let Some(o) = parent.output.get(pv as usize) {
                p.value = o.value.to_sat();
                p.scriptpubkey = hex::encode(o.script_pubkey.as_bytes());
                p.script_type = script_kind(&o.script_pubkey).to_string();
                p.address = bitcoin::Address::from_script(&o.script_pubkey, network).ok().map(|a| a.to_string());
                known = true;
            }
        }
        if known { in_total = in_total.saturating_add(p.value); } else { fee_known = false; }
        vins.push(p);
    }
    let mut out_total: u64 = 0;
    let vouts: Vec<EsploraTxVout> = tx.output.iter().map(|o| {
        out_total = out_total.saturating_add(o.value.to_sat());
        EsploraTxVout {
            scriptpubkey: hex::encode(o.script_pubkey.as_bytes()),
            value: o.value.to_sat(),
            script_type: script_kind(&o.script_pubkey).to_string(),
            address: bitcoin::Address::from_script(&o.script_pubkey, network).ok().map(|a| a.to_string()),
        }
    }).collect();
    if tx.input.is_empty() || in_total < out_total { fee_known = false; }
    let fee = if fee_known { in_total - out_total } else { 0 };
    let h = height.filter(|h| *h > 0);
    let t = EsploraTx {
        txid: tx.compute_txid().to_string(),
        vouts,
        vins,
        fee,
        weight: weight.unwrap_or_else(|| tx.weight().to_wu()),
        confirmed: h.is_some(),
        block_height: h,
        block_time: h.and_then(|h| view.block_times.get(&h).map(|t| *t as u64)),
    };
    (t, fee_known)
}

/// v298 (S52, DP #2 — "is that always possible?"): a row of the ledger from before v298 has no kept transaction;
/// its block is read once more from the wallet's block-filter server (the block the walk or the scan once read).
/// The header's proof of work is checked and the block bound to it; the asked transaction is authentic by its
/// txid. Every own transaction in the block is kept (to the tx store), so the block is read at most once.
/// Returns the asked transaction, or None when the block does not hold it (a reorg moved it).
pub async fn reread_own_tx(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    storage: &dyn LijStorage,
    txid: &str,
    height: u32,
) -> LijResult<Option<(Transaction, u32)>> {
    let hdrs: crate::tier2_sync::HeadersResp = get_json(http, &format!("{base}/headers?start={height}&count=1")).await?;
    let hdr = hdrs.headers.first().ok_or_else(|| LijError::Node(format!("block-filter server: no header at {height}")))?;
    if hdr.height != height { return Err(LijError::Node(format!("block-filter server: header {} asked {height}", hdr.height))); }
    crate::tier2_sync::validate_headers(&hdrs.headers, None)?;
    let block = fetch_block_bound(http, base, height, &hdr.hash).await?;
    // load-modify-save with no await in between: a sync in flight is never overwritten with an older view
    let mut view = load_view(storage)?;
    let had_time = view.block_times.contains_key(&height);
    view.block_times.insert(height, block.header.time);
    capture_own_txs(&mut view, &block.txdata, height);
    let found = block.txdata.iter().find(|t| t.compute_txid().to_string() == txid).cloned();
    if let Some(t) = found.as_ref() {
        if !view.fresh_txs.iter().any(|(x, _, _)| x == txid) {
            view.fresh_txs.push((txid.to_string(), height, hex::encode(bitcoin::consensus::serialize(t))));
        }
    }
    if !had_time { save_view(storage, &view)?; }   // the row gains its clock; save_view keeps the transactions too
    else if !view.fresh_txs.is_empty() { crate::tx_store::put(storage, &view.fresh_txs)?; }
    Ok(found.map(|t| (t, height)))
}

/// v257: the downward cursor (see Tier2View::down).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DownCursor {
    pub low: u32,
    pub low_hash: String,
    pub low_filter_header: String,
    pub done: bool,
}

/// v257: what the last sync call did or why it failed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncNote {
    pub at_ms: u64,
    pub ok: bool,
    pub note: String,
}

/// v256/v257: the ledger's rule version (see Tier2View::schema). 3 = the downward walk.
pub const VIEW_SCHEMA: u32 = 3;
/// v256: addresses watched per branch from index 0.
pub const NET_WIDTH: u32 = 2500;
/// v256: a coin this close to the net's far edge widens the net and redoes the walk.
pub const NET_WIDEN_MARGIN: u32 = 100;

/// v317: the widen rule with each branch's own width (the BIP86 branches are TR_WIDTH_DIV-th as deep, and their margin
/// shrinks with them) — a used index within the margin of its branch's far edge means the net must widen.
pub fn net_is_hot(view: &Tier2View) -> bool {
    view.used_next.iter().any(|(&chain, &u)| {
        let w = crate::tier2::branch_width(chain, view.net_width);
        let margin = if crate::tier2::bip86_branch(chain).is_some() { (NET_WIDEN_MARGIN / crate::tier2::TR_WIDTH_DIV).max(1) } else { NET_WIDEN_MARGIN };
        u >= w.saturating_sub(margin)
    })
}
/// v256: blocks re-walked by the daily tail verification.
pub const TAIL_VERIFY_BLOCKS: u32 = 144;

/// v271: note funding txids from the node's records (closed-channel log + live channels).
/// Only ever adds; returns true when the set grew (the caller saves the view then).
pub fn note_funding_txids<I: IntoIterator<Item = String>>(view: &mut Tier2View, txids: I) -> bool {
    let mut grew = false;
    for t in txids {
        if t.is_empty() { continue; }
        if view.funding_txids.insert(t) { grew = true; }
    }
    grew
}

/// v272: note closing txids from the node's records (closed-channel log + live sightings).
/// Only ever adds; returns true when the set grew.
pub fn note_closing_txids<I: IntoIterator<Item = String>>(view: &mut Tier2View, txids: I) -> bool {
    let mut grew = false;
    for t in txids {
        if t.is_empty() { continue; }
        if view.closing_txids.insert(t) { grew = true; }
    }
    grew
}

/// v256: rebuild the ledger from scratch under the current rules — nothing copied but the
/// birthday (and, v271/v272, the node's funding- and closing-txid records). Coins, spend
/// marks, rows, tags and the head cursor are re-derived by the walk.
pub fn rebuild_from_birthday(view: &mut Tier2View, now_ms: u64) {
    view.utxos.clear();
    view.history.clear();
    view.head = None;
    view.used_next.clear();
    view.rewalk_at.clear();
    view.kinds.clear();
    // v271/v272: funding_txids and closing_txids are deliberately NOT cleared — the node's records, not the walk's.
    view.close_hints.clear();
    view.down = None;
    view.pending_spends.clear();
    view.tr_hints.clear();   // v317
    view.block_times.clear();
    view.cursor.scanned_to = 0;
    view.cursor.last_hash = None;
    view.cursor.last_filter_header = None;
    view.schema = VIEW_SCHEMA;
    if view.net_width < NET_WIDTH { view.net_width = NET_WIDTH; }
    view.last_tail_verify_ms = now_ms;
    // v297 (S52): the silent-payment scan starts again from its own start. The rebuild clears every coin above —
    // the silent-payment coins with the rest — and until v297 the scan kept its place, so they were never read
    // again: after a ledger-schema rebuild or a widened net the balance lost every silent-payment coin. The start
    // (`from`) stands; the scan re-reads from it up to wherever the walk has reached.
    if let Some(sp) = view.sp.as_mut() {
        if sp.from > 0 { sp.scanned_to = sp.from - 1; }
        sp.scanned_hash.clear();
        sp.scanned_filter_header.clear();
        sp.waiting_for_index = false;
    }
}

/// v317: a BIP86 script seen in a fetched block's filter (see Tier2View::tr_hints).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrHint {
    pub chain: u32,
    pub index: u32,
    pub height: u32,
    pub hash: String,
    /// an output of that block pays the script too (a receipt; a spend may still be there — read last)
    #[serde(default)]
    pub paid_here: bool,
    /// the coins ("txid:vout") already looked for in this block
    #[serde(default)]
    pub checked: Vec<String>,
}

/// v251: the head-first cursor (see Tier2View::head).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeadCursor {
    pub start: u32,
    pub cursor: SyncCursor,
    pub heights: Vec<u32>,
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
            let mut known = false;
            for u in view
                .utxos
                .iter_mut()
                .filter(|u| u.spent_height.is_none() && u.txid == pt && u.vout == pv)
            {
                u.spent_height = Some(height);
                u.spent_txid = Some(txid.clone());   // v255
                spent_sats = spent_sats.saturating_add(u.value_sats);
                known = true;
            }
            if !known && !view.utxos.iter().any(|u| u.txid == pt && u.vout == pv) {
                // v257: the coin is not known yet (newest-first walk). If the witness carries
                // one of OUR pubkeys, remember the spend for the moment the coin appears.
                if witness_pays_us(&input.witness, scripts) {
                    view.pending_spends.insert(format!("{pt}:{pv}"), (txid.clone(), height));
                }
            }
        }

        // Outputs that pay our scripts.
        for (vout, out) in tx.output.iter().enumerate() {
            if let Some((chain, index)) = scripts.owner_of(&out.script_pubkey) {
                let e = view.used_next.entry(chain).or_insert(0);   // v251: the used frontier, spent or not
                if index + 1 > *e { *e = index + 1; }
                // v190 (S29): re-introduction guard — an overlap rescan
                // (cursor regression) must not duplicate a known outpoint.
                if view
                    .utxos
                    .iter()
                    .any(|u| u.txid == txid && u.vout == vout as u32)
                {
                    continue;
                }
                recv_sats = recv_sats.saturating_add(out.value.to_sat());
                // v257: a spend of this coin may already have been seen above it
                let pend = view.pending_spends.remove(&format!("{txid}:{vout}"));
                view.utxos.push(OnchainUtxo {
                    sp_tweak: None,
                    sp_label: None,
                    chain,
                    index,
                    txid: txid.clone(),
                    vout: vout as u32,
                    value_sats: out.value.to_sat(),
                    height,
                    spent_height: pend.as_ref().map(|p| p.1),
                    spent_txid: pend.map(|p| p.0),
                });
            }
        }

        // v256: no row is written here — rows are derived from the coins (derive_history).
        if spent_sats > 0 || recv_sats > 0 {
            let _ = (&txid, height);
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
        // v256: a hint by txid; derive_history decides (a spend-of-close is a close only
        // when the row is net-incoming — a sweep, never a funding).
        let e = view.close_hints.entry(txid).or_insert(false);
        if is_direct_close { *e = true; }
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
    let used = view.used_next.get(&chain).copied().unwrap_or(0);   // v251: spent outputs count too
    view_max
        .into_iter()
        .chain(pending_max)
        .max()
        .map_or(0, |m| m + 1)
        .max(used)
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
            sp_tweak: None,
            sp_label: None,
            chain: 1,
            index: p.change_index,
            txid,
            vout,
            value_sats: p.change_value_sats,
            height: 0,
            spent_height: None,
            spent_txid: None,
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
    let derived = derive_history(view);   // v256: rows are derived; confirmed = present in the derivation
    let confirmed_txids: std::collections::HashSet<String> =
        derived.iter().map(|h| h.txid.clone()).collect();
    for p in &list {
        if confirmed_txids.contains(&p.txid) && p.kind != TxKind::Onchain {
            view.kinds.entry(p.txid.clone()).or_insert(p.kind);
        }
    }
    let before = list.len();
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
                u.spent_txid = None;   // v257: the mark and its spender go together
            }
        }
    }
    view.pending_spends.retain(|_, (_, h)| *h <= to_height);   // v257
    view.tr_hints.retain(|h| h.height <= to_height);   // v317
    view.history.retain(|h| h.height <= to_height);
    view.cursor.scanned_to = to_height;
    view.cursor.last_hash = None;
    view.cursor.last_filter_header = None;
    // v287: the silent-payment scan rolls back with the walk (its coins above went with the utxos)
    if let Some(sp) = view.sp.as_mut() {
        if sp.scanned_to > to_height {
            sp.scanned_to = to_height;
            sp.scanned_hash.clear();
            sp.scanned_filter_header.clear();
        }
    }
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

/// v287 (S50, SP receive): fetch one block by height, bind it to the validated canonical hash and check
/// its transactions commit to the header (merkle root). The one block fetch the m/84 walk and the
/// silent-payment scan share. Network I/O — run OUTSIDE any wallet lock.
pub(crate) async fn fetch_block_bound(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    height: u32,
    block_hash: &str,
) -> LijResult<Block> {
    let resp: BlockResp = get_json(http, &format!("{base}/block/{height}")).await?;
    let bytes = hex::decode(&resp.block)
        .map_err(|e| LijError::Node(format!("block hex at {height}: {e}")))?;
    let block: Block = bitcoin::consensus::deserialize(&bytes)
        .map_err(|e| LijError::Node(format!("block decode at {height}: {e}")))?;
    // Bind to the chain we validated: this must be the exact block whose
    // header passed PoW + linkage in the sync step.
    let want = BlockHash::from_str(block_hash)
        .map_err(|e| LijError::Node(format!("matched hash parse at {height}: {e}")))?;
    if block.block_hash() != want {
        return Err(LijError::Node(format!(
            "block {height} hash does not match validated hash"
        )));
    }
    // Transactions must commit to the (PoW-validated) header.
    if !block.check_merkle_root() {
        return Err(LijError::Node(format!("block {height} merkle root mismatch")));
    }
    Ok(block)
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
        let block = fetch_block_bound(http, base, m.height, &m.block_hash).await?;   // v287: the shared fetch

        view.block_times.insert(m.height, block.header.time);   // v259
        apply_txs(view, scripts, &block.txdata, m.height);
        note_tr_hints(view, scripts, &block.txdata, m);   // v317
        tag_channel_closes(view, &block.txdata, close_txids);
        capture_own_txs(view, &block.txdata, m.height);   // v298: the wallet's own transactions, kept whole
    }
    resolve_tr_spends(http, base, view).await?;   // v317: a BIP86 coin met now whose spend was seen above it
    Ok(())
}

/// v317: note each BIP86 script of `m`'s filter as a hint (once per script and block).
pub fn note_tr_hints(view: &mut Tier2View, scripts: &WalletScripts, txs: &[Transaction], m: &crate::tier2_sync::MatchedBlock) {
    for &(chain, index) in &m.tr_hits {
        if view.tr_hints.iter().any(|h| h.chain == chain && h.index == index && h.height == m.height) { continue; }
        let paid_here = txs.iter().any(|tx| tx.output.iter().any(|o| scripts.owner_of(&o.script_pubkey) == Some((chain, index))));
        view.tr_hints.push(TrHint { chain, index, height: m.height, hash: m.block_hash.clone(), paid_here, checked: Vec::new() });
    }
}

/// v317: the hinted blocks to read for each unspent BIP86 coin — (coin "txid:vout", hint position), a block above the
/// coin not yet read for it; blocks that only spend before blocks that also pay.
pub fn tr_spend_checks(view: &Tier2View) -> Vec<(String, usize)> {
    let mut out: Vec<(bool, u32, String, usize)> = Vec::new();
    for u in view.utxos.iter().filter(|u| u.spent_height.is_none() && crate::tier2::bip86_branch(u.chain).is_some()) {
        let op = format!("{}:{}", u.txid, u.vout);
        for (i, h) in view.tr_hints.iter().enumerate() {
            if h.chain == u.chain && h.index == u.index && h.height > u.height && !h.checked.contains(&op) {
                out.push((h.paid_here, h.height, op.clone(), i));
            }
        }
    }
    out.sort();
    out.into_iter().map(|(_, _, op, i)| (op, i)).collect()
}

/// v317: mark a coin spent by the transaction in `txs` whose input spends it; true when found.
pub fn apply_tr_spend(view: &mut Tier2View, op: &str, txs: &[Transaction], height: u32) -> bool {
    let Some((txid, vout)) = op.rsplit_once(':') else { return false };
    let Ok(vout) = vout.parse::<u32>() else { return false };
    for tx in txs {
        if tx.input.iter().any(|i| i.previous_output.vout == vout && i.previous_output.txid.to_string() == txid) {
            let spender = tx.compute_txid().to_string();
            for u in view.utxos.iter_mut().filter(|u| u.txid == txid && u.vout == vout && u.spent_height.is_none()) {
                u.spent_height = Some(height);
                u.spent_txid = Some(spender.clone());
            }
            return true;
        }
    }
    false
}

/// v317: read the hinted blocks for every unspent BIP86 coin (tr_spend_checks) and mark the spends found. Each block
/// is read once per call, bound to its hash as every block the walk reads.
pub async fn resolve_tr_spends(http: &Arc<dyn EsploraHttp>, base: &str, view: &mut Tier2View) -> LijResult<u32> {
    let checks = tr_spend_checks(view);
    if checks.is_empty() { return Ok(0); }
    let mut blocks: std::collections::HashMap<u32, Block> = std::collections::HashMap::new();
    let mut found = 0u32;
    for (op, i) in checks {
        if !view.utxos.iter().any(|u| format!("{}:{}", u.txid, u.vout) == op && u.spent_height.is_none()) { continue; }   // found by an earlier hint
        let (height, hash) = (view.tr_hints[i].height, view.tr_hints[i].hash.clone());
        if !blocks.contains_key(&height) {
            let b = fetch_block_bound(http, base, height, &hash).await?;
            blocks.insert(height, b);
        }
        let txs = &blocks[&height].txdata;
        let hit = apply_tr_spend(view, &op, txs, height);
        view.tr_hints[i].checked.push(op.clone());
        if hit {
            found += 1;
            capture_own_txs(view, txs, height);   // the spend is the wallet's own transaction
            log::info!("[tier2] v317 a taproot coin {}… spent in block {height} (its filter named the script)", op.get(..12).unwrap_or(&op));
        }
    }
    Ok(found)
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
    storage.set(VIEW_KEY, &bytes)?;
    // v298: the own transactions met since the view was loaded go to the tx store (only new ones are written);
    // a failure here never fails the ledger's save — the drill-down re-reads the block instead
    if !view.fresh_txs.is_empty() {
        if let Err(e) = crate::tx_store::put(storage, &view.fresh_txs) { log::warn!("[tier2] v298 tx store: {e}"); }
    }
    Ok(())
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
    /// v281 (S50, coin control): the value of frozen coins inside `spendable_sats`
    /// (unspent, not reserved; unconfirmed change included if marked). The balance
    /// card shows `spendable_sats` unchanged — a freeze hides nothing; a send, Max and
    /// a channel open work from `sendable_sats` = spendable − frozen.
    pub frozen_sats: u64,
    pub sendable_sats: u64,
    pub frozen_count: u32,
    pub scanned_to: u32,
    pub tip_height: u32,
    pub caught_up: bool,
    /// v253: the walk's shape for the face — where the historic walk started, whether a
    /// head walk (newest blocks first) is still running, and how far it has got.
    pub birthday: u32,
    pub head_active: bool,
    pub head_start: u32,
    pub head_scanned_to: u32,
    /// Next unused receive index (max receive index ever seen + 1), so the
    /// receive flow never reuses an address. Counts spent outputs too.
    pub next_receive_index: u32,
    /// v256: violated invariants (empty = the ledger agrees with itself).
    pub invariants: Vec<String>,
    /// v257: the downward walk's lowest scanned block and whether it reached the birthday.
    pub down_low: u32,
    pub down_done: bool,
    /// v257: the last sync call's result (for the face).
    pub last_sync: Option<SyncNote>,
    /// v281: the coin list as rows — record + tag + the user's frozen/note marks.
    pub utxos: Vec<CoinRow>,
    /// The confirmed unspent coins that ARE reserved by a pending spend (hidden
    /// from `utxos`). Audit-only: lets a reconciliation verify every pending
    /// spend's inputs are real confirmed coins (`utxos ∪ reserved_utxos`).
    pub reserved_utxos: Vec<OnchainUtxo>,
    pub history: Vec<OnchainHistoryEntry>,
    /// Locally-originated txs not yet confirmed (own-send immediate view).
    pub pending: Vec<PendingTx>,
    /// v287 (S50, SP receive): the silent-payment scan for the face — the wallet's switch,
    /// available at this provider, how far it has scanned, the pending (mempool) silent payments.
    #[serde(default)]
    pub sp: crate::sp_scan::SpSummary,
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
pub fn summary(view: &Tier2View, pending: &[PendingTx], tip_height: u32, marks: &CoinMarks) -> Tier2Summary {
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
    let mut utxos: Vec<CoinRow> = view
        .utxos
        .iter()
        .filter(|u| u.spent_height.is_none() && !reserved.contains(&(u.txid.clone(), u.vout)))
        .map(|u| CoinRow::from_utxo(view, marks, u))
        .collect();
    // v103: the UTXO list must show the same money the balance counts — append
    // the optimistic unconfirmed-change rows (height == 0 marks them pending in
    // the UI). Recomputed from view + pending every sync, so the list tracks
    // confirmations and reorgs in lockstep with the balance: once the change
    // confirms it enters the view above and drops out of this set, never doubled.
    utxos.extend(unconfirmed_change.iter().map(|u| CoinRow::from_utxo(view, marks, u)));
    // v281 (S50, coin control): frozen = the marked coins among the rows above (legacy
    // coins are not spendable anyway and stay out of the figure); sendable = what a
    // send, Max or an open may use. The balance card keeps spendable_sats.
    let frozen_sats: u64 = utxos
        .iter()
        .filter(|r| r.frozen && r.chain != CHAIN_LEGACY)
        .map(|r| r.value_sats)
        .sum();
    let frozen_count = utxos.iter().filter(|r| r.frozen && r.chain != CHAIN_LEGACY).count() as u32;
    let sendable_sats = spendable_sats.saturating_sub(frozen_sats);
    let history = derive_history(view);   // v255/v256: rows come from the coins; ordered inside
    // v256: the invariants — the double-entry checks from S15, on every summary.
    let mut invariants: Vec<String> = Vec::new();
    if spendable_sats != confirmed_sats.saturating_sub(reserved_value).saturating_add(unconfirmed_change_sats) {
        invariants.push(format!("spendable {spendable_sats} != confirmed {confirmed_sats} - reserved {reserved_value} + unconfirmed change {unconfirmed_change_sats}"));
    }
    for p in pending {
        for op in &p.spent_outpoints {
            if !view.utxos.iter().any(|u| u.txid == op.0 && u.vout == op.1) {
                invariants.push(format!("pending {} spends an unknown coin {}:{}", &p.txid[..12.min(p.txid.len())], &op.0[..12.min(op.0.len())], op.1));
            }
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        for h in &history { if !seen.insert(h.txid.clone()) { invariants.push(format!("row {} appears twice", &h.txid[..12.min(h.txid.len())])); } }
    }
    for line in &invariants { log::warn!("[tier2] INVARIANT: {line}"); }
    Tier2Summary {
        invariants,
        spendable_sats,
        confirmed_sats,
        reserved_sats: reserved_value,
        unconfirmed_change_sats,
        legacy_sats,
        frozen_sats,
        sendable_sats,
        frozen_count,
        scanned_to: view.cursor.scanned_to,
        tip_height,
        caught_up: view.down.as_ref().map(|d| d.done).unwrap_or(true) && view.cursor.scanned_to >= tip_height,   // v257: done when the downward walk reached the birthday and the top is at the tip (no down cursor = nothing left below)
        birthday: view.cursor.birthday,
        head_active: false,
        head_start: 0,
        head_scanned_to: 0,
        down_low: view.down.as_ref().map(|d| d.low).unwrap_or(0),
        down_done: view.down.as_ref().map(|d| d.done).unwrap_or(false),
        last_sync: view.last_sync.clone(),
        next_receive_index,
        utxos,
        reserved_utxos,
        history,
        pending: pending.to_vec(),
        sp: crate::sp_scan::summary(view, marks.sp_enabled),   // v287 · v288 the switch
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
/// v257: a P2WPKH input's witness is [signature, pubkey]; the pubkey names the script
/// being spent. True when that script is one of the wallet's.
fn witness_pays_us(witness: &bitcoin::Witness, scripts: &WalletScripts) -> bool {
    if witness.len() != 2 { return false; }
    let pk_bytes = match witness.nth(1) { Some(b) => b, None => return false };
    if pk_bytes.len() != 33 { return false; }
    let pk = match bitcoin::PublicKey::from_slice(pk_bytes) { Ok(p) => p, Err(_) => return false };
    let wpkh = match pk.wpubkey_hash() { Ok(h) => h, Err(_) => return false };
    let spk = bitcoin::ScriptBuf::new_p2wpkh(&wpkh);
    scripts.owner_of(&spk).is_some()
}

/// v255 (S46, DP: "it doesn't make sense that the balance can be right but the rows
/// wrong"): the rows are DERIVED from the same output set the balance is summed from,
/// so the two can no longer disagree. Every output the wallet holds or held yields a
/// Received row for its creating transaction; every spent output yields a Sent (or
/// SelfTransfer) row for its spending transaction; the persisted `history` list is read
/// only for the kind tags (channel open/close/sweep) and as a fallback for spends
/// recorded before spent_txid existed.
pub fn derive_history(view: &Tier2View) -> Vec<OnchainHistoryEntry> {
    use std::collections::HashMap;
    let mut recv: HashMap<String, (u32, u64)> = HashMap::new();
    let mut spent: HashMap<String, (u32, u64)> = HashMap::new();
    let mut sp_sats: HashMap<String, u64> = HashMap::new();   // v289: silent-payment sats per txid
    let mut sp_labs: HashMap<String, Vec<u32>> = HashMap::new();   // v304: the labels paid, per txid
    let mut coins_of: HashMap<String, Vec<&OnchainUtxo>> = HashMap::new();   // v306: each transaction's coins → its lines
    // v307: a silent-payment coin with the same tweak (and label) as an earlier one pays the same address again
    let reused: std::collections::HashSet<(String, u32)> = {
        let mut first: HashMap<(String, Option<u32>), (u32, String, u32)> = HashMap::new();
        for u in view.utxos.iter().filter(|u| u.chain == crate::tier2::CHAIN_SP) {
            let Some(t) = u.sp_tweak.clone() else { continue };
            let here = (u.height, u.txid.clone(), u.vout);
            let e = first.entry((t, u.sp_label)).or_insert_with(|| here.clone());
            if here < *e { *e = here; }
        }
        view.utxos.iter().filter(|u| u.chain == crate::tier2::CHAIN_SP).filter_map(|u| {
            let t = u.sp_tweak.clone()?;
            let f = first.get(&(t, u.sp_label))?;
            if (u.height, u.txid.clone(), u.vout) != *f { Some((u.txid.clone(), u.vout)) } else { None }
        }).collect()
    };
    for u in &view.utxos {
        coins_of.entry(u.txid.clone()).or_default().push(u);
        if let Some(m) = u.sp_label.filter(|m| *m > 0) {
            let e = sp_labs.entry(u.txid.clone()).or_default();
            if !e.contains(&m) { e.push(m); e.sort_unstable(); }
        }
        let r = recv.entry(u.txid.clone()).or_insert((u.height, 0));
        r.1 = r.1.saturating_add(u.value_sats);
        if u.chain == crate::tier2::CHAIN_SP {
            let e = sp_sats.entry(u.txid.clone()).or_insert(0);
            *e = e.saturating_add(u.value_sats);
        }
        if let (Some(sh), Some(st)) = (u.spent_height, u.spent_txid.as_ref()) {
            let s = spent.entry(st.clone()).or_insert((sh, 0));
            s.1 = s.1.saturating_add(u.value_sats);
        }
    }
    let mut txids: Vec<String> = recv.keys().cloned().collect();
    for k in spent.keys() { if !recv.contains_key(k) { txids.push(k.clone()); } }
    let mut out: Vec<OnchainHistoryEntry> = Vec::with_capacity(txids.len());
    for txid in txids {
        let (hr, r) = recv.get(&txid).copied().unwrap_or((0, 0));
        let (hs, s) = spent.get(&txid).copied().unwrap_or((0, 0));
        let height = if s > 0 { hs } else { hr };
        let delta = r as i64 - s as i64;
        let direction = if r > 0 && s > 0 {
            TxDirection::SelfTransfer
        } else if delta >= 0 {
            TxDirection::Received
        } else {
            TxDirection::Sent
        };
        let kind = match view.kinds.get(&txid) {
            Some(k) => *k,
            None => match view.close_hints.get(&txid) {
                Some(true) => TxKind::ChannelClose,
                Some(false) if delta > 0 => TxKind::ChannelClose,
                // v271: a funding tx this wallet paid for is a ChannelOpen under any walk (the
                // node's record, see Tier2View::funding_txids) — net-outgoing only, so a coin
                // that merely arrived in a funding tx (never ours to fund) is not mislabeled.
                _ if delta < 0 && view.funding_txids.contains(&txid) => TxKind::ChannelOpen,
                _ => TxKind::default(),
            },
        };
        let time = view.block_times.get(&height).copied().unwrap_or(0);   // v259
        let silent_payment_sats = sp_sats.get(&txid).copied().unwrap_or(0);   // v289
        let sp_labels = sp_labs.remove(&txid).unwrap_or_default();   // v304
        // v306: a received transaction's lines — one per own address or sp1 label
        let lines = if direction == TxDirection::Received && kind == TxKind::Onchain {
            coins_of.get(&txid).map(|c| recv_lines(c, &reused)).unwrap_or_default()
        } else { Vec::new() };
        out.push(OnchainHistoryEntry { txid, height, direction, delta_sats: delta, kind, time, silent_payment_sats, sp_labels, lines });
    }
    // v256: height newest first, then txid — same height never swaps between refreshes.
    out.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.txid.cmp(&b.txid)));
    out
}

/// v257 (S46, DP GO — the new process): ONE walk, newest-first.
///
/// `view.cursor` is the TOP: the newest block scanned (extended forward with the ordinary
/// forward step as blocks arrive, reorg-checked at every call). `view.down` is the LOWEST
/// block scanned so far; each call reads up to `max_batches` batches below it until the
/// birthday. A spend seen before its coin is held in `pending_spends` (recognised by the
/// spender's own pubkey in the witness) and applied when the coin's block is read. Rows
/// are derived from the coins, so the list fills from the top in the order it is shown.
/// Returns (batches walked, a one-line note).
pub async fn sync_down(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    scripts: &WalletScripts,
    view: &mut Tier2View,
    storage: &dyn LijStorage,
    tip_height: u32,
    tip_hash: &str,
    batch: u32,
    max_batches: u32,
) -> LijResult<(u32, String)> {
    let mut batches = 0u32;
    // v272: the walk's close hints come from the log ∪ the view's own record (the record is what
    // survives a rebuild on a reloaded phone, where the log is empty); the log's txids are noted
    // into the record here so the two never drift apart.
    let mut close_txids = crate::closed_channel_log::ClosedChannelLog::closing_txids(storage);
    if note_closing_txids(view, close_txids.iter().cloned()) {
        save_view(storage, view)?;
    }
    close_txids.extend(view.closing_txids.iter().cloned());
    // ── (0) a fresh view: the top is the tip itself ──
    if view.cursor.scanned_to == 0 || view.down.is_none() {
        let flts: crate::tier2_sync::FiltersResp =
            get_json(http, &format!("{base}/filters?start={tip_height}&count=1")).await?;
        let f = flts.filters.first().ok_or_else(|| LijError::Node("tip filter missing".into()))?;
        if f.hash != tip_hash {
            return Err(LijError::Node(format!("tip filter hash {} != tip {}", f.hash, tip_hash)));
        }
        let filter_bytes = hex::decode(&f.filter).map_err(|e| LijError::Node(format!("tip filter hex: {e}")))?;
        let bh = BlockHash::from_str(&f.hash).map_err(|e| LijError::Node(format!("tip hash: {e}")))?;
        if crate::tier2::block_matches(&filter_bytes, &bh, scripts)? {
            fetch_and_apply(http, base, scripts, view, &[crate::tier2_sync::MatchedBlock { height: tip_height, block_hash: f.hash.clone(), tr_hits: crate::tier2::tr_hits(&filter_bytes, &bh, scripts)? }], &close_txids).await?;
        }
        view.cursor.scanned_to = tip_height;
        view.cursor.last_hash = Some(f.hash.clone());
        view.cursor.last_filter_header = Some(f.filter_header.clone());
        view.down = Some(DownCursor { low: tip_height, low_hash: f.hash.clone(), low_filter_header: f.filter_header.clone(), done: tip_height <= view.cursor.birthday });
        save_view(storage, view)?;
        log::info!("[tier2] v257 walk opened at the tip {tip_height}; reading down to {}", view.cursor.birthday);
    }
    // ── (1) forward: new blocks above the top, reorg-checked ──
    reorg_check(http, base, view).await?;
    while view.cursor.scanned_to < tip_height {
        let outcome = crate::tier2_sync::sync_step(http, base, scripts, &view.cursor, tip_height, batch).await?;
        fetch_and_apply(http, base, scripts, view, &outcome.matched, &close_txids).await?;
        view.cursor.scanned_to = outcome.scanned_to;
        view.cursor.last_hash = outcome.last_hash;
        view.cursor.last_filter_header = outcome.last_filter_header;
        save_view(storage, view)?;
        batches += 1;
        if outcome.caught_up { break; }
        if max_batches > 0 && batches >= max_batches { break; }
    }
    // ── (2) down: the newest unread blocks, until the birthday or the budget ──
    let mut down = view.down.clone().unwrap_or_default();
    while !down.done && (max_batches == 0 || batches < max_batches) {
        let o = crate::tier2_sync::sync_step_down(http, base, scripts, down.low, &down.low_hash, &down.low_filter_header, view.cursor.birthday, batch).await?;
        // highest first within the batch, so a spend lands before its coin when both are inside
        let mut matched = o.matched.clone();
        matched.sort_by(|a, b| b.height.cmp(&a.height));
        fetch_and_apply(http, base, scripts, view, &matched, &close_txids).await?;
        down = DownCursor { low: o.low, low_hash: o.low_hash, low_filter_header: o.low_filter_header, done: o.done };
        view.down = Some(down.clone());
        save_view(storage, view)?;
        batches += 1;
    }
    let note = format!("top {} (tip {tip_height}) · low {} → {} · {} batch(es) · {} coin(s) · {} pending spend(s){}",
        view.cursor.scanned_to, down.low, view.cursor.birthday, batches, view.utxos.len(), view.pending_spends.len(), if down.done { " · history complete" } else { "" });
    Ok((batches, note))
}

/// v294 (S52, DP 21:49 — "a silent-payment receive's ADDRESS in the drill-down says reading… and never fills"):
/// which inputs and outputs of a transaction are this wallet's, for the drill-down (tx_details). Until v294 the
/// only test was the script against the m/84 net (receive, change, the close branch), so a silent-payment coin —
/// a one-time taproot output at m/352, never in that net — was nobody's: a silent-payment receive had no output
/// of ours (no address of record; the page waited for one for ever) and a send FROM a silent-payment coin had no
/// input of ours (read as a receive; its change shown as the address of record). Now an output is ours when its
/// script is in the net OR the ledger holds that outpoint as a coin (spent or not; silent-payment coins included,
/// and the scan's unconfirmed ones); an input is ours when its spent output's script is in the net OR the ledger
/// holds the outpoint it spends. The ledger is the wallet's own record — nothing is asked of anyone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOwnership {
    pub our_in: u64,
    pub our_out: u64,
    /// One flag per output, in order.
    pub outs_ours: Vec<bool>,
    /// A send (we spent more than came back to us).
    pub is_send: bool,
    /// The output of record: a send → the first output that isn't ours (else our first); a receive or a
    /// self-move → our first output. None when no output qualifies.
    pub pick: Option<usize>,
}

pub fn tx_ownership(
    view: &Tier2View,
    tx: &crate::independent::EsploraTx,
    ours_script: &dyn Fn(&str) -> bool,
) -> TxOwnership {
    let mut held: std::collections::HashSet<(String, u32)> = view.utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect();
    if let Some(sp) = view.sp.as_ref() {
        for p in &sp.pending { held.insert((p.txid.clone(), p.vout)); }
    }
    let mut our_in: u64 = 0;
    for i in &tx.vins {
        if ours_script(&i.scriptpubkey) || (!i.prev_txid.is_empty() && held.contains(&(i.prev_txid.clone(), i.prev_vout))) {
            our_in = our_in.saturating_add(i.value);
        }
    }
    let mut our_out: u64 = 0;
    let mut outs_ours = Vec::with_capacity(tx.vouts.len());
    for (n, o) in tx.vouts.iter().enumerate() {
        let mine = ours_script(&o.scriptpubkey) || held.contains(&(tx.txid.clone(), n as u32));
        if mine { our_out = our_out.saturating_add(o.value); }
        outs_ours.push(mine);
    }
    let is_send = our_in > 0 && our_in > our_out;
    let first = |want: bool| outs_ours.iter().position(|m| *m == want);
    let pick = if is_send { first(false).or_else(|| first(true)) } else { first(true) };
    TxOwnership { our_in, our_out, outs_ours, is_send, pick }
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

    fn c306(txid: &str, vout: u32, chain: u32, index: u32, value: u64, sp_label: Option<u32>) -> OnchainUtxo {
        OnchainUtxo { chain, index, txid: txid.to_string(), vout, value_sats: value, height: 969_101, spent_height: None, spent_txid: None, sp_tweak: if chain == crate::tier2::CHAIN_SP { Some("07".repeat(32)) } else { None }, sp_label }
    }

    #[test]
    fn v306_a_received_transaction_is_one_line_per_address_or_label() {
        use crate::tier2::CHAIN_SP;
        let t = "c3".repeat(32); let r2 = "e5".repeat(32);
        let mut view = Tier2View::default();
        // DP's test (2026-10-02 18:21): three parts to one address, one to the sp1 label 1 — and a later payment to the address
        view.utxos = vec![
            c306(&t, 2, CHAIN_RECEIVE, 7, 3_333, None), c306(&t, 0, CHAIN_RECEIVE, 7, 1_111, None), c306(&t, 1, CHAIN_RECEIVE, 7, 2_222, None),
            c306(&t, 3, CHAIN_SP, 4, 5_000, Some(1)),
            c306(&r2, 0, CHAIN_RECEIVE, 7, 2_000, None),
        ];
        let rows = derive_history(&view);
        assert_eq!(rows.len(), 2, "still one row per transaction");
        let rt = rows.iter().find(|h| h.txid == t).unwrap();
        assert_eq!(rt.delta_sats, 11_666);
        assert_eq!(rt.lines.len(), 2);
        assert_eq!((rt.lines[0].sp, rt.lines[0].chain, rt.lines[0].index, rt.lines[0].value_sats), (false, CHAIN_RECEIVE, 7, 6_666));
        assert_eq!(rt.lines[0].parts, vec![(0, 1_111), (1, 2_222), (2, 3_333)], "the parts in output order");
        assert_eq!((rt.lines[1].sp, rt.lines[1].sp_label, rt.lines[1].index, rt.lines[1].value_sats, rt.lines[1].parts.clone()), (true, Some(1), 0, 5_000, vec![(3, 5_000)]));
        assert_eq!(rt.lines.iter().map(|l| l.value_sats).sum::<u64>() as i64, rt.delta_sats, "the lines add up to the row");
        let r = rows.iter().find(|h| h.txid == r2).unwrap();
        assert_eq!((r.lines.len(), r.lines[0].index, r.lines[0].value_sats), (1, 7, 2_000), "a later payment to the same address: its own row, its own line");
        // two of the wallet's addresses in one transaction → two lines; the plain sp1 and a label → two lines
        let u = "d4".repeat(32);
        view.utxos = vec![c306(&u, 0, CHAIN_RECEIVE, 3, 1_000, None), c306(&u, 1, CHAIN_RECEIVE, 4, 2_000, None), c306(&u, 2, CHAIN_SP, 0, 300, None), c306(&u, 3, CHAIN_SP, 1, 400, Some(2))];
        let rows = derive_history(&view);
        assert_eq!(rows[0].lines.iter().map(|l| (l.sp, l.index, l.sp_label, l.value_sats)).collect::<Vec<_>>(), vec![(false, 3, None, 1_000), (false, 4, None, 2_000), (true, 0, None, 300), (true, 0, Some(2), 400)]);
    }

    #[test]
    fn v306_sends_self_moves_and_closes_carry_no_lines() {
        let a = "a1".repeat(32); let b = "b2".repeat(32);
        let mut view = Tier2View::default();
        let mut spent = c306(&a, 0, CHAIN_RECEIVE, 1, 50_000, None);
        spent.spent_height = Some(969_200); spent.spent_txid = Some(b.clone());
        view.utxos = vec![spent, c306(&b, 1, crate::tier2::CHAIN_CHANGE, 0, 30_000, None)];
        let rows = derive_history(&view);
        let rb = rows.iter().find(|h| h.txid == b).unwrap();
        assert!(rb.lines.is_empty(), "a send (here a self-move with change): no received lines");
        let ra = rows.iter().find(|h| h.txid == a).unwrap();
        assert_eq!(ra.lines.len(), 1, "the original receive keeps its line after the coin is spent");
        view.close_hints.insert(a.clone(), true);
        let rows = derive_history(&view);
        assert!(rows.iter().find(|h| h.txid == a).unwrap().lines.is_empty(), "a channel close: no lines");
    }

    #[test]
    fn v306_the_sync_names_each_lines_address_from_the_wallets_scripts() {
        let s = scripts();
        let e = s.entries.iter().find(|e| e.chain == CHAIN_RECEIVE && e.index == 7).unwrap();
        let want = bitcoin::Address::from_script(&e.script_pubkey, Network::Bitcoin).unwrap().to_string();
        let t = "c3".repeat(32);
        let mut view = Tier2View::default();
        view.utxos = vec![c306(&t, 0, CHAIN_RECEIVE, 7, 1_111, None), c306(&t, 1, crate::tier2::CHAIN_SP, 0, 5_000, Some(1))];
        let mut rows = derive_history(&view);
        name_line_addresses(&mut rows, &s, Network::Bitcoin);
        assert_eq!(rows[0].lines[0].address.as_deref(), Some(want.as_str()));
        assert!(want.starts_with("bc1q"));
        assert_eq!(rows[0].lines[1].address, None, "an sp1 line is named by its label, not an address");
        // the JSON the page reads
        let j = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(j["lines"][0]["parts"], serde_json::json!([[0, 1111]]));
        assert_eq!(j["lines"][1]["sp_label"], serde_json::json!(1));
        // a row from before v306 (no lines) still reads
        let old: OnchainHistoryEntry = serde_json::from_str(r#"{"txid":"ab","height":1,"direction":"Received","delta_sats":5}"#).unwrap();
        assert!(old.lines.is_empty());
    }

    #[test]
    fn v306_marks_keep_every_recipient_of_a_send_and_old_marks_still_read() {
        let mut m = CoinMarks::default();
        m.send_dests.insert("c3".repeat(32), vec![("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".into(), 1_111), ("sp1qqgste7k9".into(), 5_000)]);
        let back: CoinMarks = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back.send_dests, m.send_dests);
        let old: CoinMarks = serde_json::from_str(r#"{"marks":{},"sp_enabled":true,"sp_sends":{}}"#).unwrap();
        assert!(old.send_dests.is_empty());
    }

    #[test]
    fn v298_capture_keeps_only_the_wallets_own_transactions() {
        let s = scripts();
        let spk = our_receive_spk(&s);
        let recv = tx_paying(spk.clone(), 50_000);
        let other = tx_paying(ScriptBuf::new_op_return(&[1]), 7);
        let mut view = Tier2View::default();
        apply_txs(&mut view, &s, &[recv.clone(), other.clone()], 900);
        capture_own_txs(&mut view, &[recv.clone(), other.clone()], 900);
        assert_eq!(view.fresh_txs.iter().map(|(t, h, _)| (t.clone(), *h)).collect::<Vec<_>>(), vec![(recv.compute_txid().to_string(), 900)]);
        capture_own_txs(&mut view, &[recv.clone()], 900);
        assert_eq!(view.fresh_txs.len(), 1, "noted once");
        // a spend the newest-first walk met before its coin counts too
        view.pending_spends.insert(format!("{}:0", "ab".repeat(32)), (other.compute_txid().to_string(), 950));
        capture_own_txs(&mut view, &[other.clone()], 950);
        assert_eq!(view.fresh_txs.len(), 2);
        // save_view hands them to the tx store; the view itself never carries them
        let st = crate::storage::native_storage::MemoryStorage::new();
        save_view(&st, &view).unwrap();
        assert_eq!(crate::tx_store::load(&st).txs.len(), 2);
        assert!(load_view(&st).unwrap().fresh_txs.is_empty());
        assert_eq!(ledger_height_of(&view, &recv.compute_txid().to_string()), Some(900));
        assert_eq!(ledger_height_of(&view, &other.compute_txid().to_string()), Some(950));
        assert!(ENCRYPTED_KEYS.contains(&crate::tx_store::TX_STORE_KEY), "kept encrypted at rest");
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
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: spk,
            }],
        }
    }

    fn tx_spending(prev_txid: bitcoin::Txid, vout: u32, change_spk: ScriptBuf, change: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(change),
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
        let rows = derive_history(&view);   // v256: rows are derived from the coins
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].direction, TxDirection::Received);
        assert_eq!(rows[0].delta_sats, 50_000);

        // Spend it entirely to an external script (no change to us).
        let spend = tx_spending(recv_txid, 0, ScriptBuf::new(), 49_000);
        apply_txs(&mut view, &s, &[spend], 900_010);

        assert_eq!(balances(&view), (0, 0), "spent -> zero spendable");
        assert_eq!(view.utxos.len(), 1, "spent utxo kept (for reorg), not deleted");
        assert_eq!(view.utxos[0].spent_height, Some(900_010));
        let rows = derive_history(&view);
        assert_eq!(rows.len(), 2, "a Received row and a Sent row, both from the coins");
        assert_eq!(rows[0].direction, TxDirection::Sent, "newest first");
        assert_eq!(rows[0].delta_sats, -50_000);
        // v256: balance and rows come from one list — they agree by construction
        let net: i64 = rows.iter().map(|r| r.delta_sats).sum();
        assert_eq!(net, balances(&view).0 as i64);
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
        assert!(derive_history(&view).iter().all(|h| h.height <= 900_010));
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

    /// v263: the view written encrypted is read back only through the encrypted wrapper —
    /// the same storage read plain is the field error ("tier2 view parse").
    #[test]
    fn encrypted_view_round_trip() {
        let s = scripts();
        let mut view = Tier2View::default();
        apply_txs(&mut view, &s, &[tx_paying(our_receive_spk(&s), 21_000)], 900_000);
        let inner = MemStorage(Mutex::new(HashMap::new()));
        let enc = encrypted(&inner, [7u8; 32]);
        save_view(&enc, &view).unwrap();
        assert_eq!(balances(&load_view(&enc).unwrap()), (21_000, 0));
        assert!(load_view(&inner).is_err());
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
        let sm = summary(&view, &[], 900_000, &CoinMarks::default());
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
        assert_eq!(summary(&view, &load_pending(&storage), 900_000, &CoinMarks::default()).spendable_sats, 33_000);

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
                dests: Vec::new(),
                change_outpoint: None,
                change_value_sats: 0,
                change_index: 0,
                broadcast_seen: false,
                raw_tx_hex: None,
            },
        )
        .unwrap();
        let sm = summary(&view, &load_pending(&storage), 900_000, &CoinMarks::default());
        assert_eq!(sm.spendable_sats, 0, "input reserved while pending");
        assert!(sm.utxos.is_empty(), "reserved utxo hidden");
        assert_eq!(sm.pending.len(), 1);
        assert_eq!(sm.pending[0].kind, TxKind::ChannelOpen);

        // Funding confirms: apply_txs marks the input spent + adds a history
        // row; reconcile_pending stamps that row ChannelOpen and drops the
        // pending from its key.
        apply_txs(&mut view, &s, &[funding], 900_005);
        reconcile_pending(&storage, &mut view).unwrap();
        let sm2 = summary(&view, &load_pending(&storage), 900_005, &CoinMarks::default());
        assert!(sm2.pending.is_empty(), "pending cleared on confirm");
        let row = sm2
            .history
            .iter()
            .find(|h| h.txid == funding_txid)
            .expect("confirmed funding row");
        assert_eq!(row.kind, TxKind::ChannelOpen, "marker carried to confirmed row");
        assert_eq!(sm2.spendable_sats, 0, "fully spent, no change to us");
    }

    /// v271: a funding tx whose tag the rebuild dropped derives as ChannelOpen again once the
    /// node's funding-txid record is noted — and the record itself survives a rebuild.
    #[test]
    fn funding_txids_retag_opens_across_rebuilds() {
        let s = scripts();
        let mut view = Tier2View::default();
        let recv = tx_paying(our_receive_spk(&s), 33_000);
        let recv_txid = recv.txid();
        apply_txs(&mut view, &s, &[recv], 900_000);
        let funding = tx_spending(recv_txid, 0, ScriptBuf::new(), 0);
        let funding_txid = funding.txid().to_string();
        apply_txs(&mut view, &s, &[funding], 900_005);
        view.cursor.scanned_to = 900_005;
        // no pending record ever reconciled (a restored phone, or a tag lost to the S46 rebuild)
        let before = derive_history(&view);
        let row = before.iter().find(|h| h.txid == funding_txid).expect("funding row");
        assert_eq!(row.kind, TxKind::Onchain, "untagged: a plain send");
        assert!(note_funding_txids(&mut view, vec![funding_txid.clone()]));
        assert!(!note_funding_txids(&mut view, vec![funding_txid.clone()]), "second note adds nothing");
        let after = derive_history(&view);
        let row = after.iter().find(|h| h.txid == funding_txid).expect("funding row");
        assert_eq!(row.kind, TxKind::ChannelOpen, "noted: a channel open");
        // the receive row that merely arrived is untouched even if its txid were noted
        assert!(note_funding_txids(&mut view, vec![recv_txid.to_string()]));
        let again = derive_history(&view);
        let rrow = again.iter().find(|h| h.txid == recv_txid.to_string()).expect("receive row");
        assert_eq!(rrow.kind, TxKind::Onchain, "net-incoming stays a receive");
        // a rebuild keeps the records — funding (v271) and closing (v272) alike
        assert!(note_closing_txids(&mut view, vec!["c0ffee".to_string()]));
        assert!(!note_closing_txids(&mut view, vec!["c0ffee".to_string(), String::new()]), "a repeat and an empty id add nothing");
        rebuild_from_birthday(&mut view, 0);
        assert!(view.funding_txids.contains(&funding_txid), "funding record survives the rebuild");
        assert!(view.closing_txids.contains("c0ffee"), "closing record survives the rebuild");
        assert!(view.kinds.is_empty() && view.utxos.is_empty() && view.close_hints.is_empty(), "the walk's own data is gone");
    }

    // ---- v281 (S50, coin control): marks, rows, frozen figures ----------------------

    #[test]
    fn clean_note_strips_controls_collapses_space_and_caps() {
        assert_eq!(clean_note("  hello\t\tworld \u{200B}!\n "), "hello world !");
        assert_eq!(clean_note("a\u{202E}b\u{0007}c"), "abc");
        assert_eq!(clean_note(""), "");
        let long: String = std::iter::repeat('x').take(200).collect();
        assert_eq!(clean_note(&long).chars().count(), COIN_NOTE_MAX_CHARS);
        // a multi-byte character counts as one
        let jp: String = std::iter::repeat('蔵').take(130).collect();
        assert_eq!(clean_note(&jp).chars().count(), COIN_NOTE_MAX_CHARS);
    }

    #[test]
    fn marks_set_get_and_drop_when_empty() {
        let mut m = CoinMarks::default();
        assert!(m.set_frozen("AB", 1, true, 5).is_some());
        assert!(m.is_frozen("ab", 1), "keys are case-insensitive on the txid");
        assert_eq!(m.frozen_set(), std::collections::HashSet::from([("ab".to_string(), 1u32)]));
        assert!(m.set_note("ab", 1, "  keep  for  rent ", 6).is_some());
        assert_eq!(m.get("ab", 1).unwrap().note, "keep for rent");
        assert!(m.get("ab", 1).unwrap().frozen, "a note keeps the freeze");
        assert_eq!(m.get("ab", 1).unwrap().ts_ms, 6);
        assert!(m.set_frozen("ab", 1, false, 7).is_some(), "still noted");
        assert!(!m.is_frozen("ab", 1));
        assert!(m.set_note("ab", 1, "", 8).is_none(), "neither frozen nor noted → dropped");
        assert!(m.marks.is_empty());
        assert_eq!(m.frozen_count(), 0);
    }

    #[test]
    fn marks_persist_and_load_empty_when_absent() {
        let storage = MemStorage(Mutex::new(HashMap::new()));
        assert!(load_marks(&storage).unwrap().marks.is_empty());
        let mut m = CoinMarks::default();
        m.set_frozen("cd", 0, true, 1);
        save_marks(&storage, &m).unwrap();
        let back = load_marks(&storage).unwrap();
        assert!(back.is_frozen("cd", 0));
        // the store goes through the encrypted wrapper in the wallet: the key is listed
        assert!(ENCRYPTED_KEYS.contains(&MARKS_KEY));
    }

    #[test]
    fn summary_rows_carry_tag_freeze_note_and_the_frozen_figures() {
        let s = scripts();
        let mut view = Tier2View::default();
        let a = tx_paying(our_receive_spk(&s), 30_000);
        let b = tx_paying(our_receive_spk(&s), 20_000);
        let a_txid = a.txid().to_string();
        let b_txid = b.txid().to_string();
        apply_txs(&mut view, &s, &[a, b], 900_000);
        view.cursor.scanned_to = 900_000;
        let mut marks = CoinMarks::default();
        marks.set_frozen(&a_txid, 0, true, 1);
        marks.set_note(&b_txid, 0, "from Bob", 2);
        let sm = summary(&view, &[], 900_000, &marks);
        assert_eq!(sm.spendable_sats, 50_000, "the balance card figure does not move");
        assert_eq!(sm.frozen_sats, 30_000);
        assert_eq!(sm.frozen_count, 1);
        assert_eq!(sm.sendable_sats, 20_000);
        let ra = sm.utxos.iter().find(|r| r.txid == a_txid).unwrap();
        let rb = sm.utxos.iter().find(|r| r.txid == b_txid).unwrap();
        assert!(ra.frozen && ra.note.is_empty() && ra.tag == "received");
        assert!(!rb.frozen && rb.note == "from Bob" && rb.tag == "received");
        assert!(sm.invariants.is_empty());
        // a close's payout is tagged by the node's record, whatever chain it landed on
        view.closing_txids.insert(b_txid.clone());
        let sm2 = summary(&view, &[], 900_000, &marks);
        assert_eq!(sm2.utxos.iter().find(|r| r.txid == b_txid).unwrap().tag, "channel_return");
    }

    #[test]
    fn a_rebuild_recreates_the_coin_and_the_mark_still_applies() {
        // The mark lives beside the view, keyed by outpoint: a rebuild (or a rollback,
        // or a reorg) wipes coin RECORDS; when the walk finds the coin again, the row
        // is frozen again. DP 2026-09-28: a rescan keeps freezes.
        let s = scripts();
        let mut view = Tier2View::default();
        let a = tx_paying(our_receive_spk(&s), 30_000);
        let a_txid = a.txid().to_string();
        apply_txs(&mut view, &s, &[a.clone()], 900_000);
        let mut marks = CoinMarks::default();
        marks.set_frozen(&a_txid, 0, true, 1);
        rebuild_from_birthday(&mut view, 0);
        assert!(view.utxos.is_empty());
        assert_eq!(summary(&view, &[], 900_000, &marks).frozen_sats, 0, "no coin, no frozen figure");
        apply_txs(&mut view, &s, &[a], 900_000);
        let sm = summary(&view, &[], 900_000, &marks);
        assert!(sm.utxos[0].frozen);
        assert_eq!(sm.frozen_sats, 30_000);
    }

    // v294 (S52): the drill-down's ownership — silent-payment coins are the wallet's own.
    fn etx(txid: &str, vins: Vec<(&str, u64, &str, u32)>, vouts: Vec<(&str, u64)>) -> crate::independent::EsploraTx {
        crate::independent::EsploraTx {
            txid: txid.to_string(),
            vouts: vouts.into_iter().map(|(spk, v)| crate::independent::EsploraTxVout { scriptpubkey: spk.to_string(), value: v, script_type: "x".into(), address: Some(format!("addr-{spk}")) }).collect(),
            vins: vins.into_iter().map(|(spk, v, pt, pv)| crate::independent::EsploraTxPrevout { scriptpubkey: spk.to_string(), value: v, script_type: "x".into(), address: None, prev_txid: pt.to_string(), prev_vout: pv }).collect(),
            fee: 0, weight: 0, confirmed: true, block_height: Some(1), block_time: None,
        }
    }
    fn coin(chain: u32, txid: &str, vout: u32, value: u64, spent_txid: Option<&str>) -> OnchainUtxo {
        OnchainUtxo { chain, index: 0, txid: txid.into(), vout, value_sats: value, height: 1, spent_height: spent_txid.map(|_| 2), spent_txid: spent_txid.map(|s| s.to_string()), sp_tweak: if chain == 352 { Some("00".repeat(32)) } else { None }, sp_label: None }
    }

    #[test]
    fn drill_down_ownership_knows_silent_payment_coins() {
        let net = |spk: &str| spk == "m84a" || spk == "m84chg";
        let mut view = Tier2View::default();
        // a silent-payment receive: output 1 of R is a chain-352 coin; its script is not in the m/84 net
        view.utxos.push(coin(352, "R", 1, 5_000, None));
        let r = etx("R", vec![("theirs", 9_000, "P", 0)], vec![("theirchange", 3_800), ("sp-taproot", 5_000)]);
        let o = tx_ownership(&view, &r, &net);
        assert_eq!((o.our_in, o.our_out, o.is_send, o.pick), (0, 5_000, false, Some(1)), "the SP output is ours and is the address of record");
        // before v294 (script only): nothing was ours, no address of record
        let old = tx_ownership(&Tier2View::default(), &r, &net);
        assert_eq!(old.pick, None);
        // a send FROM a silent-payment coin: the input spends the held SP coin; change to m/84
        view.utxos[0].spent_txid = Some("S".into());
        let s = etx("S", vec![("sp-taproot", 5_000, "R", 1)], vec![("someone", 2_000), ("m84chg", 2_800)]);
        let o = tx_ownership(&view, &s, &net);
        assert_eq!((o.our_in, o.our_out, o.is_send, o.pick), (5_000, 2_800, true, Some(0)), "a send: the payee's output is the address of record, not our change");
        // DP 21:58: a send TO an sp1 address from an m/84 coin — the destination (a taproot output not ours) is the
        // address of record, with the script test alone (pre-v294) and with the ledger: only a send that spent a
        // silent-payment coin ever showed our change
        let d = etx("D", vec![("m84a", 9_000, "W", 0)], vec![("m84chg", 3_700), ("their-sp-taproot", 5_000)]);
        assert_eq!(tx_ownership(&Tier2View::default(), &d, &net).pick, Some(1));
        assert_eq!(tx_ownership(&view, &d, &net).pick, Some(1));
        let old_s = tx_ownership(&Tier2View::default(), &s, &net);
        assert_eq!((old_s.our_in, old_s.is_send, old_s.pick), (0, false, Some(1)), "pre-v294: the SP-coin spend read as a receive and picked our change");
        // an ordinary m/84 receive still works by script alone
        let m = etx("M", vec![("theirs", 10_000, "Q", 0)], vec![("m84a", 7_000), ("theirchange", 2_900)]);
        let o = tx_ownership(&Tier2View::default(), &m, &net);
        assert_eq!((o.is_send, o.pick, o.outs_ours.clone()), (false, Some(0), vec![true, false]));
        // the scan's unconfirmed silent payment (mempool leg) is ours too
        let mut v2 = Tier2View::default();
        let mut sc = crate::sp_scan::SpScan::default();
        sc.pending.push(crate::sp_scan::SpPending { txid: "U".into(), vout: 0, value_sats: 1_234, t_k: "00".repeat(32), k: 0, seen_ms: 0, label: None, reused: false });
        v2.sp = Some(sc);
        let u = etx("U", vec![("theirs", 2_000, "Z", 0)], vec![("sp-taproot-2", 1_234), ("theirchange", 600)]);
        assert_eq!(tx_ownership(&v2, &u, &net).pick, Some(0));
    }

    // ── v304 (S54): silent-payment labels in the marks ──
    #[test]
    fn v304_labels_are_made_in_order_renamed_hidden_never_deleted_and_capped_at_ten() {
        let mut m = CoinMarks::default();
        assert_eq!(m.sp_scan_labels(), vec![0], "a new wallet checks the change label only");
        assert_eq!(m.sp_label_create("  Donations\u{200B} ", 1).unwrap(), 1);
        assert_eq!(m.sp_label_create("Rent from Bob", 2).unwrap(), 2);
        assert!(m.sp_label_create("   ", 3).is_err(), "a label needs a name");
        assert_eq!(m.sp_label(1).unwrap().name, "Donations", "cleaned like a note");
        assert_eq!(m.sp_scan_labels(), vec![0, 1, 2]);
        let l = m.sp_label_update(2, Some("Rent"), Some(true)).unwrap();
        assert_eq!((l.name.as_str(), l.hidden), ("Rent", true));
        assert_eq!(m.sp_scan_labels(), vec![0, 1, 2], "a hidden label is still checked");
        assert!(m.sp_label_update(9, Some("x"), None).is_err());
        assert_eq!(m.sp_label_create("Shop", 4).unwrap(), 3, "never reuses a number");
        for i in 4..=10 { assert_eq!(m.sp_label_create(&format!("L{i}"), 5).unwrap(), i); }
        assert!(m.sp_label_create("eleven", 6).is_err(), "ten at most");
        assert_eq!(clean_label_name(&"x".repeat(60)).chars().count(), SP_LABEL_NAME_MAX_CHARS);
    }

    #[test]
    fn v304_a_words_only_restore_checks_all_ten_and_keeps_found_numbers() {
        let mut m = CoinMarks { sp_labels_unknown: true, ..Default::default() };
        assert_eq!(m.sp_scan_labels(), (0..=10).collect::<Vec<u32>>());
        assert!(m.sp_label_ensure(3, 7));
        assert!(!m.sp_label_ensure(3, 8) && !m.sp_label_ensure(0, 8), "once; never the change label");
        assert_eq!((m.sp_label(3).unwrap().name.as_str(), m.sp_label(3).unwrap().hidden), ("", false), "shown as Label 3 until named");
        assert_eq!(m.sp_label_create("New one", 9).unwrap(), 4, "after the highest found");
        assert_eq!(m.sp_scan_labels(), (0..=10).collect::<Vec<u32>>(), "still all ten — a label handed out before can still be paid");
    }

    #[test]
    fn v304_old_marks_parse_and_labels_ride_the_record() {
        let old: CoinMarks = serde_json::from_str(r#"{"marks":{},"sp_enabled":true}"#).unwrap();
        assert!(old.sp_labels.is_empty() && !old.sp_labels_unknown, "a v303 record: no labels, and known to have none");
        let mut m = CoinMarks::default();
        m.sp_label_create("Donations", 1).unwrap();
        m.sp_label_update(1, None, Some(true)).unwrap();
        let back: CoinMarks = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(back.sp_labels, m.sp_labels);
        // a coin keeps its label; an old coin record parses with none
        let u: OnchainUtxo = serde_json::from_str(r#"{"chain":352,"index":0,"txid":"aa","vout":1,"value_sats":5,"height":9,"spent_height":null,"sp_tweak":"00"}"#).unwrap();
        assert_eq!(u.sp_label, None);
        let mut u2 = u.clone();
        u2.sp_label = Some(1);
        let j = serde_json::to_string(&u2).unwrap();
        assert!(j.contains("\"sp_label\":1"));
        assert!(!serde_json::to_string(&u).unwrap().contains("sp_label"), "nothing written for a coin without one");
    }
}

#[cfg(test)]
mod v317_tests {
    use super::*;

    fn tr_coin(txid: &str, chain: u32, index: u32, height: u32) -> OnchainUtxo {
        OnchainUtxo { chain, index, txid: txid.into(), vout: 0, value_sats: 100_000, height, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None }
    }
    fn hint(chain: u32, index: u32, height: u32, paid_here: bool) -> TrHint {
        TrHint { chain, index, height, hash: format!("{height:064x}"), paid_here, checked: Vec::new() }
    }

    #[test]
    fn v317_the_checks_read_only_blocks_above_the_coin_spends_first_and_once() {
        let c = crate::tier2::CHAIN_BIP86_INTERNAL;
        let mut view = Tier2View::default();
        view.utxos = vec![tr_coin("aa", c, 3, 900), tr_coin("bb", c, 4, 900), tr_coin("cc", 0, 3, 900)];
        view.tr_hints = vec![
            hint(c, 3, 950, true),    // a later payment to the same address (read last)
            hint(c, 3, 920, false),   // the spend
            hint(c, 3, 890, false),   // below the coin: never read for it
            hint(c, 9, 930, false),   // another script
            hint(0, 3, 930, false),   // not a BIP86 chain: m/84 spends are found by the witness
        ];
        let checks = tr_spend_checks(&view);
        assert_eq!(checks, vec![("aa:0".to_string(), 1), ("aa:0".to_string(), 0)]);
        view.tr_hints[1].checked.push("aa:0".into());
        assert_eq!(tr_spend_checks(&view), vec![("aa:0".to_string(), 0)], "a block is read once for a coin");
        view.utxos[0].spent_height = Some(920);
        assert!(tr_spend_checks(&view).is_empty(), "a spent coin needs no reading");
    }

    #[test]
    fn v317_the_widen_rule_watches_each_branch_at_its_own_width() {
        let mut view = Tier2View::default();
        view.net_width = NET_WIDTH;
        view.used_next.insert(0, 2_000);
        view.used_next.insert(crate::tier2::CHAIN_BIP86_INTERNAL, 470);
        assert!(!net_is_hot(&view), "470 of 500 on m/86 is inside the margin of 20; 2,000 of 2,500 on m/84");
        view.used_next.insert(crate::tier2::CHAIN_BIP86_INTERNAL, 480);
        assert!(net_is_hot(&view), "480 of 500 reaches it");
        view.used_next.remove(&crate::tier2::CHAIN_BIP86_INTERNAL);
        view.used_next.insert(1, 2_400);
        assert!(net_is_hot(&view), "the m/84 rule is unchanged");
    }

    #[test]
    fn v318_a_mix_coin_is_known_by_its_mark_not_its_branch() {
        let mut view = Tier2View::default();
        view.utxos = vec![tr_coin("aa", crate::tier2::CHAIN_BIP86, 4, 900), tr_coin("bb", crate::tier2::CHAIN_BIP86, 5, 900), tr_coin("cc", crate::tier2::CHAIN_BIP86_INTERNAL, 0, 900)];
        let mut marks = CoinMarks::default();
        marks.mix_exits.insert(4);
        marks.mix_exits.insert(9);   // handed to a pool, not paid yet
        assert_eq!(coin_tag(&view, &marks, &view.utxos[0]), "mix");
        assert_eq!(coin_tag(&view, &marks, &view.utxos[1]), "received", "the same branch, not handed to a pool");
        assert_eq!(coin_tag(&view, &marks, &view.utxos[2]), "change");
        assert_eq!(next_tr_receive_index(&view, &marks), 10, "past the paid 5 and the handed-out 9");
        // the marks ride the backup blob: they are in the sealed marks record, which the bundle carries
        let back: CoinMarks = serde_json::from_slice(&serde_json::to_vec(&marks).unwrap()).unwrap();
        assert_eq!(back.mix_exits, marks.mix_exits);
        let old: CoinMarks = serde_json::from_str("{}").unwrap();
        assert!(old.mix_exits.is_empty(), "an older record reads with no marks");
        assert!(ENCRYPTED_KEYS.contains(&MARKS_KEY) && crate::node::BUNDLE_SINGLE_KEYS.contains(&MARKS_KEY));
    }

    #[test]
    fn v317_a_rollback_and_a_rebuild_drop_the_hints_above() {
        let c = crate::tier2::CHAIN_BIP86;
        let mut view = Tier2View::default();
        view.tr_hints = vec![hint(c, 1, 900, false), hint(c, 1, 960, false)];
        rollback(&mut view, 950);
        assert_eq!(view.tr_hints.iter().map(|h| h.height).collect::<Vec<_>>(), vec![900]);
        rebuild_from_birthday(&mut view, 0);
        assert!(view.tr_hints.is_empty());
    }
}
