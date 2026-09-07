// cooperative_chain_bridge.rs
//
// Step 4c — bridges the cooperative chain handler (step 4b) to the rest of
// the wallet. Fills the trait stubs from steps 1 and 2:
//   - CooperativeBroadcaster (broadcaster.rs) — translates broadcast requests
//     into BroadcastTx wire messages.
//   - CooperativeFeeSource (fee_estimator.rs) — exposes the most-recently-
//     received fee schedule from inbound ChainDataBundle/FeeScheduleUpdate.
//
// Also provides:
//   - send_subscribe(): called by node.rs on LSP connect to push the
//     initial SubscribeChainData message including the current chain-filter
//     watch-list snapshot.
//   - process_inbound_tick(): called from background_tick to drain inbound
//     messages from the handler and route each to the right component
//     (chain filter for confirmations, fee estimator for fee updates,
//     broadcaster for acks).
//
// This file does NOT implement waiting/polling for BroadcastAck — that
// would deadlock with LDK's synchronous call pattern. The broadcaster
// returns Ok(()) optimistically when the message is enqueued; if the
// LSP later returns Rejected/Unavailable, we record the failure on the
// next tick and surface it via the broadcaster's hard-fail surface.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::BlockHash;
use bitcoin::secp256k1::PublicKey;

use crate::broadcaster::{CooperativeBroadcaster, LijBroadcaster};
use crate::chain_filter::LijChainFilter;
use crate::cooperative_chain_handler::{CooperativeChainHandler, CooperativeChainMessage};
use crate::cooperative_chain_msg::{
    BroadcastResult, BroadcastTx, ChannelStateChange, FeeScheduleUpdate, FundingTxConfirmed,
    RegisterWatchOutput, RegisterWatchTx, SubscribeChainData,
};
use crate::error::{LijError, LijResult};
use crate::fee_estimator::{CooperativeFeeSource, FeeQuote, LijFeeEstimator};

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

// Step 3.6 (F7): WASM-safe Unix epoch seconds. Mirrors node.rs's private
// current_time_secs() helper; duplicated here rather than imported so the
// dependency arrow doesn't reverse (node depends on bridge, not the inverse).
fn current_time_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    { (js_sys::Date::now() / 1000.0) as u64 }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

// ── Shared state ────────────────────────────────────────────────────────────
// The bridge owns shared state read by the broadcaster bridge and fee source
// bridge. Wrapped in Arc<Mutex<...>> so the trait impls can hold their own
// references.

#[derive(Clone, Debug, Default)]
struct SharedState {
    /// Most recent fee schedule received from the LSP. Set by ChainDataBundle
    /// and FeeScheduleUpdate inbound messages.
    last_fee_quote: Option<FeeQuote>,
    /// Most recent block height. For now informational; the cold-start
    /// orchestrator (step 6) will read this.
    last_block_height: Option<u32>,
    /// Phase 3.7.L: most recent block hash from cooperative ChainDataBundle
    /// or BlockHeightUpdate. Paired with last_block_height for feeding the
    /// chain coordinator's bridge_observed_tip (verification only).
    last_block_hash: Option<BlockHash>,
    /// Whether we have a peer connection that completed cooperative subscribe.
    /// Read by the bridges' is_available() to decide whether to attempt sends.
    subscribed: bool,
    /// Step 3.6 (F7): Unix epoch seconds when the last cooperative chain
    /// message (ChainDataBundle or BlockHeightUpdate) was received. Surfaced
    /// via cooperative_last_update_ts() for the wallet's freshness display
    /// ("X s ago" on the cooperative card).
    last_update_ts: Option<u64>,
    /// Outstanding broadcast requests indexed by request_id. Used to match
    /// inbound BroadcastAck back to the originating tx for status surfacing.
    pending_broadcasts: HashMap<u64, String>, // request_id -> txid_hex
    /// Step 8c: pending FundingTxConfirmed messages awaiting routing to LDK's
    /// Confirm trait. Drained by LijNode::background_tick which has access to
    /// ChannelManager + ChainMonitor.
    pending_confirmations: Vec<FundingTxConfirmed>,
}

// ── CooperativeChainBridge ──────────────────────────────────────────────────

pub struct CooperativeChainBridge {
    handler: Arc<CooperativeChainHandler>,
    chain_filter: Arc<LijChainFilter>,
    fee_estimator: Arc<LijFeeEstimator>,
    broadcaster: Arc<LijBroadcaster>,
    state: Arc<Mutex<SharedState>>,
    /// Currently-connected LSP pubkey. Wrapped in Arc<Mutex> so the
    /// broadcaster sub-bridge can share the same value without redirection.
    lsp_pubkey: Arc<Mutex<Option<PublicKey>>>,
}

impl CooperativeChainBridge {
    pub fn new(
        handler: Arc<CooperativeChainHandler>,
        chain_filter: Arc<LijChainFilter>,
        fee_estimator: Arc<LijFeeEstimator>,
        broadcaster: Arc<LijBroadcaster>,
    ) -> Arc<Self> {
        let state = Arc::new(Mutex::new(SharedState::default()));
        let lsp_pubkey: Arc<Mutex<Option<PublicKey>>> = Arc::new(Mutex::new(None));

        let bridge = Arc::new(Self {
            handler: handler.clone(),
            chain_filter,
            fee_estimator: fee_estimator.clone(),
            broadcaster: broadcaster.clone(),
            state: state.clone(),
            lsp_pubkey: lsp_pubkey.clone(),
        });

        // Register the bridge as the cooperative source for fee_estimator
        // and broadcaster. These calls satisfy the trait stubs from steps 1 and 2.
        let coop_fee = Arc::new(BridgeFeeSource {
            state: state.clone(),
        });
        fee_estimator.set_cooperative(coop_fee);

        let coop_bcast = Arc::new(BridgeBroadcaster {
            handler,
            state,
            next_request_id: AtomicU64::new(1),
            lsp_pubkey,
        });
        broadcaster.set_cooperative(coop_bcast);

        bridge
    }

    /// Send the initial SubscribeChainData message to the LSP. Called by
    /// node.rs once the peer connection completes the Noise handshake and
    /// LDK signals the peer is ready.
    pub fn send_subscribe(&self, lsp_pubkey: PublicKey) -> LijResult<()> {
        // Snapshot the chain-filter registry so the LSP knows what to watch.
        let watched_txs = self.chain_filter.all_watched_txs();
        let watched_outputs = self.chain_filter.all_watched_outputs();
        let txids: Vec<_> = watched_txs.iter().map(|w| w.txid).collect();
        let scripts: Vec<_> = watched_txs
            .iter()
            .map(|w| w.script_pubkey.clone())
            .chain(watched_outputs.iter().map(|o| o.script_pubkey.clone()))
            .collect();

        let msg = SubscribeChainData {
            watch_txids: txids,
            watch_scripts: scripts,
        };
        log::info!(
            "cooperative_chain_bridge: sending SubscribeChainData to {} ({} txids, {} scripts)",
            lsp_pubkey,
            msg.watch_txids.len(),
            msg.watch_scripts.len(),
        );
        self.handler.send_subscribe(lsp_pubkey, msg);
        *self.lsp_pubkey.lock().unwrap() = Some(lsp_pubkey);
        Ok(())
    }

    /// Send a RegisterWatchTx for one tx. Called when LijChainFilter
    /// reports a newly-registered tx via take_new_registrations().
    pub fn send_register_watch_tx(&self, lsp_pubkey: PublicKey, watched: &crate::chain_filter::WatchedTx) {
        self.handler.send_register_watch_tx(
            lsp_pubkey,
            RegisterWatchTx {
                txid: watched.txid,
                script_pubkey: watched.script_pubkey.clone(),
            },
        );
    }

    /// Send a RegisterWatchOutput for one output. Called from the same flow.
    pub fn send_register_watch_output(
        &self,
        lsp_pubkey: PublicKey,
        watched: &lightning::chain::WatchedOutput,
    ) {
        self.handler.send_register_watch_output(
            lsp_pubkey,
            RegisterWatchOutput {
                funding_txid: watched.outpoint.txid,
                output_index: watched.outpoint.index as u32,
                script_pubkey: watched.script_pubkey.clone(),
                created_in_block: watched.block_hash,
            },
        );
    }

    /// Process inbound messages from the handler, routing each to the
    /// appropriate component. Called from background_tick once per second.
    pub fn process_inbound_tick(&self, current_tick: u64) {
        let received = self.handler.take_received();
        if received.is_empty() {
            return;
        }
        log::debug!(
            "cooperative_chain_bridge: processing {} inbound message(s)",
            received.len()
        );
        for r in received {
            self.dispatch(r.message, current_tick);
        }
    }

    /// Drain newly-registered watches from the filter and forward each as
    /// a register_watch_* message. Called from background_tick after
    /// process_inbound_tick.
    pub fn process_new_registrations_tick(&self) {
        let lsp = match *self.lsp_pubkey.lock().unwrap() {
            Some(p) => p,
            None => return, // not subscribed yet
        };
        let new_regs = self.chain_filter.take_new_registrations();
        if new_regs.is_empty() {
            return;
        }
        for tx in &new_regs.txs {
            self.send_register_watch_tx(lsp, tx);
        }
        for out in &new_regs.outputs {
            self.send_register_watch_output(lsp, out);
        }
        log::debug!(
            "cooperative_chain_bridge: forwarded {} new tx watches and {} new output watches",
            new_regs.txs.len(),
            new_regs.outputs.len(),
        );
    }

    /// Mark the cooperative path as disconnected. Called from node.rs on
    /// peer disconnect / LSP unreachable. Bridges' is_available() will
    /// return false until the next successful subscribe.
    pub fn mark_disconnected(&self) {
        *self.lsp_pubkey.lock().unwrap() = None;
        self.state.lock().unwrap().subscribed = false;
        log::info!("cooperative_chain_bridge: marked disconnected");
    }

    /// Whether the cooperative path has received its initial ChainDataBundle.
    /// Used by the cold-start orchestrator (step 6d) to decide state transitions.
    pub fn cooperative_subscribed(&self) -> bool {
        self.state.lock().unwrap().subscribed
    }

    /// The LSP pubkey we've been told to subscribe to (set by send_subscribe).
    /// Used by node.rs background_tick to detect when the BOLT peer connection
    /// has come up so the SubscribeChainData re-issue retry can fire.
    /// Returns None until send_subscribe has been called at least once.
    pub fn target_lsp(&self) -> Option<PublicKey> {
        *self.lsp_pubkey.lock().unwrap()
    }

    /// Last known cooperative-cached block height. None if no bundle received yet.
    /// Used by the cold-start orchestrator.
    pub fn cooperative_block_height(&self) -> Option<u32> {
        self.state.lock().unwrap().last_block_height
    }

    /// Phase 3.7.L: Last known cooperative-cached block hash, paired with
    /// cooperative_block_height(). Read by node.rs background_tick to feed
    /// the chain coordinator's bridge_observed_tip (verification only).
    pub fn cooperative_block_hash(&self) -> Option<BlockHash> {
        self.state.lock().unwrap().last_block_hash
    }

    /// Step 3.6 (F7): Unix epoch seconds of the last cooperative chain
    /// message received. None until the first ChainDataBundle arrives.
    pub fn cooperative_last_update_ts(&self) -> Option<u64> {
        self.state.lock().unwrap().last_update_ts
    }

    /// Drain pending FundingTxConfirmed messages. Called from LijNode::background_tick
    /// once per tick. The caller is responsible for routing each into LDK's
    /// transactions_confirmed() and persisting channel state afterward.
    pub fn take_pending_confirmations(&self) -> Vec<FundingTxConfirmed> {
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut state.pending_confirmations)
    }

    /// v231: put confirmations back (in front) that the tick could not apply yet
    /// because their block is above the accepted tip; the next tick takes them again.
    pub fn requeue_pending_confirmations(&self, mut held: Vec<FundingTxConfirmed>) {
        let mut state = self.state.lock().unwrap();
        held.append(&mut state.pending_confirmations);
        state.pending_confirmations = held;
    }

    fn dispatch(&self, msg: CooperativeChainMessage, current_tick: u64) {
        match msg {
            CooperativeChainMessage::ChainDataBundle(b) => {
                let mut state = self.state.lock().unwrap();
                state.last_block_height = Some(b.tip_height);
                state.last_block_hash = Some(b.tip_blockhash);  // Phase 3.7.L
                state.last_fee_quote = Some(FeeQuote::from_fast_sat_per_vb(b.fee_sat_per_vb_fast));
                state.subscribed = true;
                state.last_update_ts = Some(current_time_secs());  // Step 3.6 (F7)
                drop(state);
                log::info!(
                    "cooperative_chain_bridge: ChainDataBundle received, tip {} fast_fee {} sat/vB",
                    b.tip_height,
                    b.fee_sat_per_vb_fast,
                );
                // Trigger the fee estimator to refresh from the new cache.
                // We can't await here — fire-and-forget on WASM via spawn_local
                // happens at the call site (node.rs background_tick).
                let _ = current_tick;
            }
            CooperativeChainMessage::BlockHeightUpdate(h) => {
                // Step 3.6 (F7): single lock, set both fields together.
                // Phase 3.7.L: also store the new block hash.
                let mut state = self.state.lock().unwrap();
                state.last_block_height = Some(h.new_height);
                state.last_block_hash = Some(h.new_blockhash);
                state.last_update_ts = Some(current_time_secs());
                drop(state);
                log::debug!("cooperative_chain_bridge: BlockHeightUpdate to {}", h.new_height);
            }
            CooperativeChainMessage::FeeScheduleUpdate(f) => {
                self.state.lock().unwrap().last_fee_quote =
                    Some(FeeQuote::from_fast_sat_per_vb(f.fee_sat_per_vb_fast));
                log::debug!(
                    "cooperative_chain_bridge: FeeScheduleUpdate fast={} sat/vB",
                    f.fee_sat_per_vb_fast
                );
            }
            CooperativeChainMessage::FundingTxConfirmed(c) => {
                // Step 8c: verify the LSP-supplied tx bytes hash to the
                // claimed txid, then queue for LijNode::background_tick to
                // route into LDK's Confirm trait.
                use bitcoin::consensus::encode::deserialize as consensus_deserialize;
                let parsed_tx: Result<bitcoin::Transaction, _> = consensus_deserialize(&c.raw_tx_bytes);
                match parsed_tx {
                    Ok(tx) => {
                        let computed_txid = tx.txid();
                        if computed_txid != c.txid {
                            log::warn!(
                                "cooperative_chain_bridge: FundingTxConfirmed txid MISMATCH — claimed {} but raw_tx_bytes hashes to {}, dropping",
                                c.txid, computed_txid
                            );
                        } else {
                            log::info!(
                                "cooperative_chain_bridge: FundingTxConfirmed txid={} at height={} confs={} — queued for LDK",
                                c.txid, c.confirmed_at_height, c.confirmations
                            );
                            self.state.lock().unwrap().pending_confirmations.push(c);
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "cooperative_chain_bridge: FundingTxConfirmed raw_tx_bytes failed to parse: {} — dropping",
                            e
                        );
                    }
                }
            }
            CooperativeChainMessage::ChannelStateUpdate(u) => {
                log::info!(
                    "cooperative_chain_bridge: ChannelStateUpdate funding={} state={:?}",
                    u.funding_txid, u.state
                );
                // Specific state-change handlers wire in step 6.
                if matches!(u.state, ChannelStateChange::ForceCloseInitiated) {
                    log::warn!(
                        "cooperative_chain_bridge: LSP reports FORCE CLOSE on {} — independent verification required (trigger 2c)",
                        u.funding_txid
                    );
                }
            }
            CooperativeChainMessage::BroadcastAck(a) => {
                let mut state = self.state.lock().unwrap();
                let txid_hex = state.pending_broadcasts.remove(&a.request_id);
                drop(state);
                match a.result {
                    BroadcastResult::Relayed => {
                        log::info!(
                            "cooperative_chain_bridge: BroadcastAck Relayed for request {} (tx {})",
                            a.request_id,
                            txid_hex.as_deref().unwrap_or("?"),
                        );
                    }
                    BroadcastResult::Rejected => {
                        log::warn!(
                            "cooperative_chain_bridge: BroadcastAck REJECTED for request {} (tx {}): {}",
                            a.request_id,
                            txid_hex.as_deref().unwrap_or("?"),
                            a.detail,
                        );
                    }
                    BroadcastResult::Unavailable => {
                        log::warn!(
                            "cooperative_chain_bridge: BroadcastAck Unavailable for request {} (tx {}): {}",
                            a.request_id,
                            txid_hex.as_deref().unwrap_or("?"),
                            a.detail,
                        );
                    }
                }
            }
            // Wallet → LSP messages should never arrive at the wallet's
            // handler. These would indicate a misconfigured peer (e.g. an
            // adapter echoing requests). Log and ignore.
            CooperativeChainMessage::SubscribeChainData(_)
            | CooperativeChainMessage::RegisterWatchTx(_)
            | CooperativeChainMessage::RegisterWatchOutput(_)
            | CooperativeChainMessage::BroadcastTx(_) => {
                log::warn!(
                    "cooperative_chain_bridge: received wallet→LSP message at wallet — ignoring"
                );
            }
        }
    }
}

// ── BridgeFeeSource ─────────────────────────────────────────────────────────
// Implements CooperativeFeeSource (from fee_estimator.rs) by reading the
// shared state's last_fee_quote.

struct BridgeFeeSource {
    state: Arc<Mutex<SharedState>>,
}

impl CooperativeFeeSource for BridgeFeeSource {
    fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>> {
        Box::pin(async move {
            self.state
                .lock()
                .unwrap()
                .last_fee_quote
                .clone()
                .ok_or_else(|| LijError::Lsp("no cooperative fee quote received yet".into()))
        })
    }

    fn is_available(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.subscribed && s.last_fee_quote.is_some()
    }
}

// ── BridgeBroadcaster ───────────────────────────────────────────────────────
// Implements CooperativeBroadcaster (from broadcaster.rs) by enqueueing
// BroadcastTx in the handler's outbound queue.

struct BridgeBroadcaster {
    handler: Arc<CooperativeChainHandler>,
    state: Arc<Mutex<SharedState>>,
    next_request_id: AtomicU64,
    lsp_pubkey: Arc<Mutex<Option<PublicKey>>>,
}

impl CooperativeBroadcaster for BridgeBroadcaster {
    fn broadcast<'a>(&'a self, raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>> {
        Box::pin(async move {
            let lsp = match *self.lsp_pubkey.lock().unwrap() {
                Some(p) => p,
                None => return Err(LijError::Lsp("no LSP connected for cooperative broadcast".into())),
            };
            let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
            // Compute txid for status surfacing. If the bytes don't parse as a
            // valid Bitcoin tx, log and proceed — the LSP will reject it on its
            // side and we'll get a Rejected ack.
            let txid_hex = match bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(raw_tx) {
                Ok(tx) => tx.txid().to_string(),
                Err(_) => "unparseable".to_string(),
            };
            self.state
                .lock()
                .unwrap()
                .pending_broadcasts
                .insert(request_id, txid_hex);
            self.handler.send_broadcast_tx(
                lsp,
                BroadcastTx {
                    request_id,
                    raw_tx: raw_tx.to_vec(),
                },
            );
            Ok(())
        })
    }

    fn is_available(&self) -> bool {
        self.lsp_pubkey.lock().unwrap().is_some() && self.state.lock().unwrap().subscribed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize as consensus_serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{absolute::LockTime, Transaction, TxIn, TxOut, Witness};

    fn dummy_pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        let sk = SecretKey::from_slice(&bytes).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    /// Build a simple valid bitcoin::Transaction for tests.
    fn build_dummy_tx(seed: u8) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: seed as u64 * 1000,
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn make_bridge() -> Arc<CooperativeChainBridge> {
        let handler = Arc::new(crate::cooperative_chain_handler::CooperativeChainHandler::new());
        let chain_filter = Arc::new(crate::chain_filter::LijChainFilter::new());
        let fee_estimator = Arc::new(crate::fee_estimator::LijFeeEstimator::new());
        let broadcaster = Arc::new(crate::broadcaster::LijBroadcaster::new());
        CooperativeChainBridge::new(handler, chain_filter, fee_estimator, broadcaster)
    }

    #[test]
    fn funding_tx_confirmed_with_matching_txid_gets_queued() {
        let bridge = make_bridge();
        let tx = build_dummy_tx(7);
        let txid = tx.txid();
        let raw_bytes = consensus_serialize(&tx);
        let blockhash = bitcoin::BlockHash::from_byte_array([0xab; 32]);
        let msg = CooperativeChainMessage::FundingTxConfirmed(FundingTxConfirmed {
            txid,
            confirmed_at_height: 880_500,
            blockhash_of_confirmation: blockhash,
            confirmations: 3,
            raw_tx_bytes: raw_bytes,
            tx_index: 0,  // Step 3.6 (SCID fix)
        });
        bridge.dispatch(msg, 0);
        let pending = bridge.take_pending_confirmations();
        assert_eq!(pending.len(), 1, "valid message should be queued");
        assert_eq!(pending[0].txid, txid);
        assert_eq!(pending[0].confirmed_at_height, 880_500);
    }

    #[test]
    fn funding_tx_confirmed_with_mismatched_txid_dropped() {
        let bridge = make_bridge();
        let tx = build_dummy_tx(8);
        let raw_bytes = consensus_serialize(&tx);
        // Claim a wrong txid
        let wrong_txid = bitcoin::Txid::from_byte_array([0xff; 32]);
        let msg = CooperativeChainMessage::FundingTxConfirmed(FundingTxConfirmed {
            txid: wrong_txid,
            confirmed_at_height: 880_500,
            blockhash_of_confirmation: bitcoin::BlockHash::from_byte_array([0xab; 32]),
            confirmations: 1,
            raw_tx_bytes: raw_bytes,
            tx_index: 0,  // Step 3.6 (SCID fix)
        });
        bridge.dispatch(msg, 0);
        let pending = bridge.take_pending_confirmations();
        assert_eq!(pending.len(), 0, "txid mismatch should be dropped");
    }

    #[test]
    fn funding_tx_confirmed_with_garbage_bytes_dropped() {
        let bridge = make_bridge();
        let txid = bitcoin::Txid::from_byte_array([0xaa; 32]);
        let msg = CooperativeChainMessage::FundingTxConfirmed(FundingTxConfirmed {
            txid,
            confirmed_at_height: 880_500,
            blockhash_of_confirmation: bitcoin::BlockHash::from_byte_array([0xab; 32]),
            confirmations: 1,
            raw_tx_bytes: vec![0xff, 0xff, 0xff], // not a valid tx
            tx_index: 0,  // Step 3.6 (SCID fix)
        });
        bridge.dispatch(msg, 0);
        let pending = bridge.take_pending_confirmations();
        assert_eq!(pending.len(), 0, "unparseable raw_tx_bytes should be dropped");
    }

    // Suppress warning if dummy_pubkey isn't directly used
    #[allow(dead_code)]
    fn _unused(_: bitcoin::secp256k1::PublicKey) {}
}

