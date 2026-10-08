// lij-core: Lightning-in-a-Jar core library
// Forked from MutinyWallet/mutiny-node (MIT License)
//
// What we kept:    LDK channel management, key generation, invoice handling,
//                  BDK on-chain wallet, Rapid Gossip Sync
//
// What we removed: Nostr, Fedimint, hardcoded Voltage/Zeus LSP endpoints,
//                  Mutiny VSS (Spiral) backup service, social features
//
// What we added:   Configurable LSP registry (any Umbrel clearnet node),
//                  Cloudflare KV backup endpoint (your Worker),
//                  Open LSP switching via LSPS1/LSPS2 protocol

pub mod error;
pub mod key;
pub mod persisted_counter;
pub mod signer;
pub mod storage;
pub mod lsp;
pub mod lsps2;
pub mod node;
pub mod push;   // v280 (S49): Push Key — the pure half (link, pair, records)
pub mod peer;
pub mod persist;
pub mod seed_vault;
pub mod wallet;
pub mod types;
pub mod broadcaster;
pub mod fee_estimator;
pub mod chain_filter;
pub mod cooperative_chain_msg;
pub mod cooperative_chain_handler;
pub mod chain_coordinator;
pub mod cooperative_chain_bridge;
pub mod independent;
pub mod http_stub;
pub mod sync_state;
pub mod priority_scan;
pub mod cold_start;
pub mod onchain_scan;
pub mod onchain_send;
pub mod coin_select;   // v281 (S50, coin control): DP's one pick rule — smallest single coin that covers, else largest first
pub mod silent_payment;
pub mod sp_scan;   // v287 (S50, SP receive): the upward sweep over the box's tweak index + the mempool leg
pub mod tx_store;   // v298 (S52, DP #2): the wallet's own transactions, kept whole — the drill-down reads them, no explorer asked
pub mod invoice_facts;   // v303 (S54, DP): a BOLT11 invoice's payee, amount, hash — read and signature-checked, for the page to check before paying
pub mod nwc;   // v286 (S50, NWC cut N1): NIP-44 v2, Nostr events, the connections and limits — the pure half
pub mod channel_open;
pub mod tier2;
pub mod tier2_sync;
pub mod tier2_wallet;
pub mod close_attempt;
pub mod closed_channel_log;
pub mod closed_channel_watcher;
pub mod sweeper;
pub mod registry_client;
pub mod black_start;   // v275 (S48, DP): BLACK START BS1 — the sealed, signed escape kit (docs/black-start-standard.md)
pub mod kit_merge;   // v313 (S57, DP 17:55): the Black start kit across copies (docs/design/black-start/kit-merge-r1.md)
pub mod bip86;   // v314 (S57, DP 21:36 — joinstr-fit-r5, the wallet side, step 1): BIP86 taproot addresses for pool exits
pub mod musig;   // v315 (S57, DP 21:53 "Go on 1 & 2" — joinstr-fit-r5 step 2): the wallet's MuSig2 signer (BIP-327), nonces once, in memory only
pub mod cancelled_open;   // v277 (S48, DP): the cancelled-open sweep's honest proof (history + quorum + a two-hour floor)

