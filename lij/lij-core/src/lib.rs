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
pub mod silent_payment;
pub mod channel_open;
pub mod tier2;
pub mod tier2_sync;
pub mod tier2_wallet;
pub mod close_attempt;
pub mod closed_channel_log;
pub mod closed_channel_watcher;
pub mod sweeper;
pub mod registry_client;

