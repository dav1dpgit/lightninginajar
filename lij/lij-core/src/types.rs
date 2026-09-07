// types.rs
// Shared data structures that cross the Rust/JavaScript boundary.
// These get serialized to JSON by the WASM layer and returned to the PWA.

use serde::{Deserialize, Serialize};

/// Wallet balance snapshot.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Balance {
    /// Spendable Lightning balance in satoshis
    pub lightning_sats: u64,
    /// On-chain balance in satoshis (includes Taproot sweep outputs)
    pub onchain_sats: u64,
    /// Pending inbound (not yet claimable)
    pub pending_inbound_sats: u64,
    /// Pending outbound (in-flight payments)
    pub pending_outbound_sats: u64,
}

/// Result of sending a Lightning payment.
#[derive(Serialize, Deserialize, Debug)]
pub struct PaymentResult {
    pub success: bool,
    pub preimage: Option<String>, // hex-encoded payment preimage on success
    pub fee_sats: Option<u64>,
    pub error: Option<String>,
}

/// A created Lightning invoice.
#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceResult {
    pub bolt11: String,
    pub payment_hash: String,
    pub amount_sats: Option<u64>,
    pub expiry_seconds: u64,
    /// v168: hex payment_secret — registered with the LSP (hash-keyed) so
    /// held forwards can settle via trampoline with the sender offline.
    /// Acceptance gate only; the preimage never leaves this wallet.
    pub payment_secret: String,
}

/// Summary of a single Lightning channel.
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub counterparty_pubkey: String, // the LSP's pubkey
    pub balance_sats: u64,
    /// S21 capacity lockdown: the ONE spendable lens — what a new HTLC can
    /// actually carry right now: min(outbound_capacity,
    /// next_outbound_htlc_limit), in sats. Display, the send gate, and the
    /// MPP planner all read THIS number; balance_sats (raw outbound) stays
    /// for capacity-accounting detail only.
    pub spendable_sats: u64,
    /// S45 (DP, "truly 0"): the same lens in millisats, so Max can price and
    /// send the exact sub-sat amount. Display stays whole sats.
    #[serde(default)]
    pub spendable_msat: u64,
    pub inbound_capacity_sats: u64,
    pub is_usable: bool,
    pub is_public: bool,
    /// v178 (close-awareness): the funding-spend walker has SEEN this
    /// channel's funding outpoint spent by an UNCONFIRMED tx — a close is
    /// in the mempool. Display-only signal: eviction stays confirmation-
    /// gated. The frontend paints "Closing — in the mempool", excludes
    /// the channel from spendable sums, and marks the Closing card.
    #[serde(default)]
    pub closing_seen_mempool: bool,
    /// The unconfirmed spending (closing) txid, when seen.
    #[serde(default)]
    pub closing_txid: Option<String>,
    /// v178: terminus pin state (UCID bit) — this channel's to_remote
    /// pays the seed's m/84 tree directly on force close.
    #[serde(default)]
    pub terminus_pinned: bool,
    /// On-chain funding txid (the value to look up on a block explorer), if the
    /// channel has a funding outpoint yet. Distinct from channel_id.
    pub funding_txid: Option<String>,
    /// Funding confirmations so far (None until first seen on-chain). Lets the
    /// UI separate confirmed capacity from a pending zero-conf open.
    pub confirmations: Option<u32>,
    /// Whether channel_ready has been exchanged (usable for routing).
    pub is_channel_ready: bool,
    /// Our (the holder's) unspendable channel reserve, in satoshis. This must
    /// remain in the channel and is NOT part of balance_sats (outbound
    /// capacity) — it's surfaced to explain why the full balance isn't
    /// spendable. None until LDK reports it.
    pub our_reserve_sats: Option<u64>,
    /// Counterparty (LSP) unspendable reserve, in satoshis.
    pub their_reserve_sats: u64,
    /// v163: when inbound_capacity is 0 because the counterparty's side hasn't
    /// met its own reserve yet (fresh LSPS1 opens), this is ~how many sats the
    /// user must SEND before receiving unlocks. None once inbound is live.
    pub inbound_unlock_after_sats: Option<u64>,
    /// v212 (Receivable reserve ledger): our FULL side of the channel in sats
    /// (LDK balance_msat) — includes the reserve portion, unlike balance_sats
    /// (net outbound). Lets the UI show, on a fresh inbound channel still
    /// under its reserve, exactly how much has built up and how much remains
    /// before anything is sendable. Serde default keeps old JSON readable.
    #[serde(default)]
    pub our_balance_gross_sats: u64,
    /// R3 (v174): true while the channel is anywhere in LDK's shutdown
    /// pipeline (ShutdownInitiated → ShutdownComplete). Lets the frontend
    /// distinguish a not-yet-ready OPENING channel (a genuine pending
    /// arrival to Lightning) from a no-longer-ready CLOSING channel (sats
    /// already counted as an on-chain return) — the close-time ghost
    /// "arriving to lightning" alert.
    pub is_shutting_down: bool,
}

/// Result of wallet creation.
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletCreated {
    /// 12-word BIP39 mnemonic — user MUST back this up
    pub mnemonic: String,
    /// Node public key (hex) — used for LSP registration
    pub pubkey: String,
}

/// Result of wallet restore.
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletRestored {
    pub pubkey: String,
    pub channels_recovered: u32,
    /// Session 23 (1a): true only when the encrypted vault blob was
    /// actually pulled and injected on this restore (fresh device).
    /// Same-device restores with local state report false.
    pub restored_from_vault: bool,
    /// The injected blob's version when restored_from_vault is true.
    pub vault_version: Option<u64>,
}

/// Configuration passed from the PWA at wallet initialization.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletConfig {
    /// "bitcoin", "testnet", or "signet"
    pub network: String,
    /// Your Cloudflare Worker base URL
    pub worker_url: String,
    /// Auth token for backup Worker endpoint
    pub backup_auth_token: String,
    /// Esplora URL for on-chain data (can use public: "https://blockstream.info/api")
    pub esplora_url: String,
    /// Optional: specific LSP to use (if None, auto-select from registry)
    pub preferred_lsp_pubkey: Option<String>,
}


/// Result of creating a Lightning invoice with an LSPS2 JIT channel promise.
///
/// The `invoice` is the BOLT11 to share with the payer. The route_hint baked
/// into the invoice contains a fake SCID (`jit.jit_channel_scid`) that the LSP
/// will recognize when the payment HTLC arrives — at that point the LSP opens
/// a zero-conf channel to the wallet and forwards the payment over it (Phase D).
///
/// The `jit` field surfaces the LSP's promise data (open fee, expiry, human
/// summary) so the wallet UI can disclose pricing before the user shares the
/// invoice.
#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceWithJitResult {
    pub invoice: InvoiceResult,
    pub jit: InvoiceJitInfo,
    /// Hex-encoded 32-byte BOLT11 payment_secret (payment_addr) for this invoice.
    /// Sent to the LSP out-of-band via /lsps2/register_secret (Option B) so it can
    /// rebuild the sendToRouteV2 final hop. NOT the preimage -- already present in
    /// the bolt11 itself, so exposing it here leaks nothing new.
    pub payment_secret_hex: String,
}

/// LSPS2 promise data mirrored from the adapter's /lsps2/buy response.
/// Stringified u64 fields preserved for JSON safety across the WASM boundary.
/// (Not a re-export of `lsps2::Lsps2BuyResponse` — kept here so the boundary
/// types module has no LSP-specific dependencies.)
#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceJitInfo {
    pub jit_channel_scid: String,
    pub lsp_pubkey: String,
    pub fee_msat: String,
    /// v217 (S36, O5): binding payer-funds-the-floor prefund (stringified
    /// msat; "0" when the promise carries none / open-amount path).
    pub prefund_msat: String,
    pub promise_expires_at: u64,
    pub human_summary: String,
}
