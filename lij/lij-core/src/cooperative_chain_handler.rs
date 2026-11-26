// cooperative_chain_handler.rs
//
// Step 4b — CustomMessageHandler implementation for the cooperative chain-data path.
// Wires the wire-protocol types from step 4a (cooperative_chain_msg.rs) into
// LDK's PeerManager via the `CustomMessageHandler` and `CustomMessageReader`
// traits.
//
// Architecture:
//   - LDK's PeerManager holds an Arc<CooperativeChainHandler> in its
//     custom-message slot (replacing the prior Arc<IgnoringMessageHandler>).
//   - On inbound bytes whose type_id matches one of our reserved IDs, LDK
//     calls `CustomMessageReader::read` to decode → `CustomMessageHandler::handle_custom_message`
//     to dispatch.
//   - To send, the handler enqueues an outbound (peer_pubkey, message) pair;
//     PeerManager drains the queue via `get_and_clear_pending_msg` on its
//     normal event-pumping cadence.
//
// Inbound dispatch:
//   The handler maintains an `InboundCallbacks` struct of optional fn-pointer-style
//   closures, one per message type. The bridge in step 4c registers callbacks
//   that route messages into LijFeeEstimator, LijChainFilter, LijBroadcaster, etc.
//   In step 4b we just buffer received messages so tests can inspect them.
//
// Outbound queue:
//   Send-side methods (send_subscribe, send_register_watch_tx, send_broadcast_tx, …)
//   push onto an internal queue. PeerManager drains via get_and_clear_pending_msg.
//
// Feature bits:
//   We declare a custom feature bit so peers can advertise support. Until a
//   BLIP is published with an officially-allocated bit, we use a high
//   experimental bit (bit 257, the first odd bit ≥256).

use std::collections::VecDeque;
use std::sync::Mutex;

use bitcoin::secp256k1::PublicKey;
use lightning::types::features::{InitFeatures, NodeFeatures};
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::util::ser::{Readable, Writeable, Writer};

use crate::cooperative_chain_msg::{
    BlockHeightUpdate, BroadcastAck, BroadcastTx, ChainDataBundle, ChannelStateUpdate,
    FeeRatesKw, FeeScheduleUpdate, FundingTxConfirmed, JitFundingAbandoned, RegisterWatchOutput, RegisterWatchTx,
    SubscribeChainData, TYPE_BLOCK_HEIGHT_UPDATE, TYPE_BROADCAST_ACK, TYPE_BROADCAST_TX,
    TYPE_CHAIN_DATA_BUNDLE, TYPE_CHANNEL_STATE_UPDATE, TYPE_FEE_RATES_KW, TYPE_FEE_SCHEDULE_UPDATE,
    TYPE_FUNDING_TX_CONFIRMED, TYPE_JIT_FUNDING_ABANDONED, TYPE_REGISTER_WATCH_OUTPUT, TYPE_REGISTER_WATCH_TX,
    TYPE_SUBSCRIBE_CHAIN_DATA,
};

// ── Unified message enum for CustomMessageHandler::CustomMessage ────────────
// LDK's trait expects ONE associated type representing all messages this
// handler can produce or consume. We wrap the 10 step-4a structs.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CooperativeChainMessage {
    SubscribeChainData(SubscribeChainData),
    ChainDataBundle(ChainDataBundle),
    BlockHeightUpdate(BlockHeightUpdate),
    FundingTxConfirmed(FundingTxConfirmed),
    FeeScheduleUpdate(FeeScheduleUpdate),
    ChannelStateUpdate(ChannelStateUpdate),
    RegisterWatchTx(RegisterWatchTx),
    RegisterWatchOutput(RegisterWatchOutput),
    BroadcastTx(BroadcastTx),
    BroadcastAck(BroadcastAck),
    FeeRatesKw(FeeRatesKw),   // v362
    JitFundingAbandoned(JitFundingAbandoned),   // v363
    /// v383 (S72, docs/design/routes/f2-r1.md §7.1): LSPS0 (bLIP-50), message 37913 — one JSON-RPC 2.0 object as its
    /// UTF-8 bytes. A request inside the Lightning connection, or its answer (lijox_rpc.rs). It never enters the
    /// inbound queue of the chain-data kinds: handle_custom_message hands it to LijoxRpc.
    Lsps0(Vec<u8>),
}

impl Writeable for CooperativeChainMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
        match self {
            Self::SubscribeChainData(m) => m.write(w),
            Self::ChainDataBundle(m) => m.write(w),
            Self::BlockHeightUpdate(m) => m.write(w),
            Self::FundingTxConfirmed(m) => m.write(w),
            Self::FeeScheduleUpdate(m) => m.write(w),
            Self::ChannelStateUpdate(m) => m.write(w),
            Self::RegisterWatchTx(m) => m.write(w),
            Self::RegisterWatchOutput(m) => m.write(w),
            Self::BroadcastTx(m) => m.write(w),
            Self::BroadcastAck(m) => m.write(w),
            Self::FeeRatesKw(m) => m.write(w),
            Self::JitFundingAbandoned(m) => m.write(w),
            Self::Lsps0(bytes) => w.write_all(bytes),   // v383: the payload is the JSON text itself
        }
    }
}

impl Type for CooperativeChainMessage {
    fn type_id(&self) -> u16 {
        match self {
            Self::SubscribeChainData(_) => TYPE_SUBSCRIBE_CHAIN_DATA,
            Self::ChainDataBundle(_) => TYPE_CHAIN_DATA_BUNDLE,
            Self::BlockHeightUpdate(_) => TYPE_BLOCK_HEIGHT_UPDATE,
            Self::FundingTxConfirmed(_) => TYPE_FUNDING_TX_CONFIRMED,
            Self::FeeScheduleUpdate(_) => TYPE_FEE_SCHEDULE_UPDATE,
            Self::ChannelStateUpdate(_) => TYPE_CHANNEL_STATE_UPDATE,
            Self::RegisterWatchTx(_) => TYPE_REGISTER_WATCH_TX,
            Self::RegisterWatchOutput(_) => TYPE_REGISTER_WATCH_OUTPUT,
            Self::BroadcastTx(_) => TYPE_BROADCAST_TX,
            Self::BroadcastAck(_) => TYPE_BROADCAST_ACK,
            Self::FeeRatesKw(_) => TYPE_FEE_RATES_KW,
            Self::JitFundingAbandoned(_) => TYPE_JIT_FUNDING_ABANDONED,
            Self::Lsps0(_) => crate::lijox_rpc::TYPE_LSPS0,   // v383
        }
    }
}

// ── Inbound buffer ──────────────────────────────────────────────────────────
// In step 4b we just buffer received messages so tests and step-4c bridge
// code can drain them. Real dispatch into LijChainFilter / LijFeeEstimator /
// LijBroadcaster is wired in step 4c.

#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub sender: PublicKey,
    pub message: CooperativeChainMessage,
}

// ── Handler ─────────────────────────────────────────────────────────────────

/// Custom feature bit used to advertise support for the cooperative chain-data
/// protocol. Bit 257 is the first odd bit at/above 256, well clear of any
/// currently-allocated Lightning feature bits.
///
/// Per BOLT 9, odd bits are "optional" — peers without support stay connected
/// and ignore. When the BLIP allocates a real bit, we'll change this constant.
pub const COOPERATIVE_CHAIN_DATA_FEATURE_BIT: usize = 257;

/// v363 (wallet trusts LSP — docs/design/jit-trust/wallet-trusts-lsp-v0.1.md §5.1/§6.1): this wallet accepts a JIT
/// channel whose funding transaction the provider HOLDS BACK until the wallet has claimed the payment, and it
/// understands `JitFundingAbandoned` (type 32823) when the payment was refused. A provider reads this bit from its
/// node's peer list (LND `ListPeers` → `features`) at open time; a wallet without it gets the publish-first open.
/// Odd = optional (BOLT 9). NOT 259: LDK 0.2's node context knows 258/259 as DnsResolver (bLIP-32), and
/// set_optional_custom_bit refuses a known bit (lightning-types features.rs KNOWN_FEATURE_MASK byte 32). 261 is the
/// next odd bit free in both the init and the node context.
pub const LIJ_FUNDING_HOLD_FEATURE_BIT: usize = 261;

pub struct CooperativeChainHandler {
    /// Outbound queue. Drained by PeerManager via get_and_clear_pending_msg.
    outbound: Mutex<VecDeque<(PublicKey, CooperativeChainMessage)>>,
    /// Inbound buffer. Drained by step-4c bridge code via take_received().
    inbound: Mutex<VecDeque<ReceivedMessage>>,
    /// v249 (S46, DP): the peer we last sent SubscribeChainData to (the LSP).
    subscribe_target: Mutex<Option<PublicKey>>,
    /// v249: set when that peer (re)connects or disconnects — the tick re-issues the
    /// subscription. The LSP's chain bridge drops a subscriber after three failed sends
    /// while the wallet is asleep, and until now nothing on this side ever subscribed
    /// again after a reconnect (mark_disconnected was never called; the pulse's reconnect
    /// path sends no subscribe) — the wallet then sat on its last tip for as long as the
    /// socket lived (DP's Android: six blocks behind, every internal send refused by LND).
    resubscribe_wanted: std::sync::atomic::AtomicBool,
    /// v321 (S58, DP 2026-10-12 — the CHAIN dot): the last SubscribeChainData sent to the target. The one sent while
    /// the provider is not yet connected is dropped by LDK; peer_connected sends this one again AT ONCE, so the
    /// process_events that follows the socket read delivers it in the same pass (it used to wait for the next tick).
    last_subscribe: Mutex<Option<SubscribeChainData>>,
    /// v383 (S72): requests inside the Lightning connection (LSPS0, message 37913). This handler is the peer manager's
    /// one custom message handler, so it carries the path's messages too: a 37913 message that arrives goes to
    /// `rpc.on_message`, and the path's own queue is drained beside the chain queue. The twelve chain-data kinds pass
    /// through the same lines as before.
    rpc: std::sync::Arc<crate::lijox_rpc::LijoxRpc>,
}

impl CooperativeChainHandler {
    pub fn new() -> Self {
        Self {
            outbound: Mutex::new(VecDeque::new()),
            inbound: Mutex::new(VecDeque::new()),
            subscribe_target: Mutex::new(None),
            resubscribe_wanted: std::sync::atomic::AtomicBool::new(false),
            last_subscribe: Mutex::new(None),
            rpc: std::sync::Arc::new(crate::lijox_rpc::LijoxRpc::new({
                let r = crate::peer::ephemeral_bytes();
                let mut seed = [0u8; 8];
                seed.copy_from_slice(&r[..8]);
                seed
            })),
        }
    }

    /// v383: the path for requests inside the Lightning connection (lijox_rpc.rs).
    pub fn rpc(&self) -> std::sync::Arc<crate::lijox_rpc::LijoxRpc> {
        self.rpc.clone()
    }

    /// v249: true once, when the subscribe target has (re)connected or disconnected since
    /// the last read. The bridge/tick re-issues SubscribeChainData on it.
    pub fn take_resubscribe_wanted(&self) -> bool {
        self.resubscribe_wanted.swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    /// v295 (S52): put the request back (the tick could not send it this time).
    pub fn want_resubscribe(&self) {
        self.resubscribe_wanted.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Drain all received messages. Step-4c bridge calls this each tick.
    pub fn take_received(&self) -> Vec<ReceivedMessage> {
        let mut q = self.inbound.lock().unwrap();
        q.drain(..).collect()
    }

    /// Number of messages waiting in the inbound buffer (for status panel).
    pub fn inbound_depth(&self) -> usize {
        self.inbound.lock().unwrap().len()
    }

    /// Number of messages waiting to be sent (for status panel).
    pub fn outbound_depth(&self) -> usize {
        self.outbound.lock().unwrap().len()
    }

    // ── Send-side helpers ────────────────────────────────────────────────────
    // Step-4c bridge calls these to push outbound messages. Each just enqueues;
    // PeerManager pulls via get_and_clear_pending_msg on its event-pump cycle.

    pub fn send_subscribe(&self, peer: PublicKey, msg: SubscribeChainData) {
        *self.subscribe_target.lock().unwrap() = Some(peer);   // v249
        *self.last_subscribe.lock().unwrap() = Some(msg.clone());   // v321
        self.enqueue(peer, CooperativeChainMessage::SubscribeChainData(msg));
    }

    pub fn send_register_watch_tx(&self, peer: PublicKey, msg: RegisterWatchTx) {
        self.enqueue(peer, CooperativeChainMessage::RegisterWatchTx(msg));
    }

    pub fn send_register_watch_output(&self, peer: PublicKey, msg: RegisterWatchOutput) {
        self.enqueue(peer, CooperativeChainMessage::RegisterWatchOutput(msg));
    }

    pub fn send_broadcast_tx(&self, peer: PublicKey, msg: BroadcastTx) {
        self.enqueue(peer, CooperativeChainMessage::BroadcastTx(msg));
    }

    /// Generic enqueue. Used by tests and by the LSP-side handler (when the
    /// adapter is built; the same handler type is reusable for both ends).
    pub fn enqueue(&self, peer: PublicKey, msg: CooperativeChainMessage) {
        log::debug!(
            "cooperative_chain: enqueue {:?} → {}",
            msg.type_id(),
            peer
        );
        self.outbound.lock().unwrap().push_back((peer, msg));
    }
}

// ── CustomMessageReader ─────────────────────────────────────────────────────
// Decodes inbound bytes by type ID. Returns Ok(None) for unknown type IDs
// so LDK's ignorable-odd-bit semantics work — peers can speak features we
// don't understand without disconnecting us.

impl CustomMessageReader for CooperativeChainHandler {
    type CustomMessage = CooperativeChainMessage;

    fn read<R: lightning::io::Read>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        let msg = match message_type {
            TYPE_SUBSCRIBE_CHAIN_DATA => {
                CooperativeChainMessage::SubscribeChainData(Readable::read(buffer)?)
            }
            TYPE_CHAIN_DATA_BUNDLE => {
                CooperativeChainMessage::ChainDataBundle(Readable::read(buffer)?)
            }
            TYPE_BLOCK_HEIGHT_UPDATE => {
                CooperativeChainMessage::BlockHeightUpdate(Readable::read(buffer)?)
            }
            TYPE_FUNDING_TX_CONFIRMED => {
                CooperativeChainMessage::FundingTxConfirmed(Readable::read(buffer)?)
            }
            TYPE_FEE_SCHEDULE_UPDATE => {
                CooperativeChainMessage::FeeScheduleUpdate(Readable::read(buffer)?)
            }
            TYPE_CHANNEL_STATE_UPDATE => {
                CooperativeChainMessage::ChannelStateUpdate(Readable::read(buffer)?)
            }
            TYPE_REGISTER_WATCH_TX => {
                CooperativeChainMessage::RegisterWatchTx(Readable::read(buffer)?)
            }
            TYPE_REGISTER_WATCH_OUTPUT => {
                CooperativeChainMessage::RegisterWatchOutput(Readable::read(buffer)?)
            }
            TYPE_BROADCAST_TX => {
                CooperativeChainMessage::BroadcastTx(Readable::read(buffer)?)
            }
            TYPE_BROADCAST_ACK => {
                CooperativeChainMessage::BroadcastAck(Readable::read(buffer)?)
            }
            TYPE_FEE_RATES_KW => {
                CooperativeChainMessage::FeeRatesKw(Readable::read(buffer)?)
            }
            TYPE_JIT_FUNDING_ABANDONED => {
                CooperativeChainMessage::JitFundingAbandoned(Readable::read(buffer)?)
            }
            // v383: LSPS0 — the whole payload is one JSON text; it is read to its end and judged by lijox_rpc.rs.
            crate::lijox_rpc::TYPE_LSPS0 => {
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = buffer.read(&mut chunk)?;
                    if n == 0 { break; }
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.len() > 65_535 { return Err(DecodeError::InvalidValue); }
                }
                CooperativeChainMessage::Lsps0(bytes)
            }
            _ => return Ok(None),
        };
        Ok(Some(msg))
    }
}

// ── CustomMessageHandler ────────────────────────────────────────────────────

impl CustomMessageHandler for CooperativeChainHandler {
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log::debug!(
            "cooperative_chain: received {:?} from {}",
            msg.type_id(),
            sender_node_id
        );
        // v383: a request's answer (or a part of one) goes to the path, never into the chain-data queue
        if let CooperativeChainMessage::Lsps0(bytes) = &msg {
            self.rpc.on_message(sender_node_id, bytes, crate::storage::now_ms());
            return Ok(());
        }
        self.inbound.lock().unwrap().push_back(ReceivedMessage {
            sender: sender_node_id,
            message: msg,
        });
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut out: Vec<(PublicKey, Self::CustomMessage)> = {
            let mut q = self.outbound.lock().unwrap();
            q.drain(..).collect()
        };
        // v383: the path's own queue, after the chain-data messages
        out.extend(self.rpc.drain_outbound().into_iter().map(|(peer, bytes)| (peer, CooperativeChainMessage::Lsps0(bytes))));
        out
    }

    fn provided_node_features(&self) -> NodeFeatures {
        let mut f = NodeFeatures::empty();
        f.set_optional_custom_bit(COOPERATIVE_CHAIN_DATA_FEATURE_BIT)
            .expect("custom bit should be in the optional range");
        f.set_optional_custom_bit(LIJ_FUNDING_HOLD_FEATURE_BIT)   // v363
            .expect("custom bit should be in the optional range");
        f
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        self.rpc.peer_disconnected(&their_node_id);   // v383: a request that waits on this peer ends now, with the reason
        // v249: the LSP's stream is gone with the socket — subscribe again on the next connect.
        if *self.subscribe_target.lock().unwrap() == Some(their_node_id) {
            log::info!("cooperative_chain_handler: LSP peer disconnected — SubscribeChainData will be re-issued on reconnect");
            self.resubscribe_wanted.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    fn peer_connected(
        &self,
        their_node_id: PublicKey,
        _msg: &lightning::ln::msgs::Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        // v249: every (re)connect of the LSP gets a fresh subscription (the LSP keeps no
        // subscriber across a disconnect; the wallet used to assume it did).
        if *self.subscribe_target.lock().unwrap() == Some(their_node_id) {
            // v321 (S58): the last subscription goes out NOW (LDK calls this while reading the peer's init, and the
            // socket read is followed at once by process_events), instead of on the next tick's flush. The flag stays:
            // the tick still sends a fresh snapshot of the watch lists (anything registered while the peer was away),
            // which costs the provider one more bundle.
            let last = self.last_subscribe.lock().unwrap().clone();
            if let Some(m) = last {
                log::info!("cooperative_chain_handler: LSP peer connected — SubscribeChainData sent at once");
                self.enqueue(their_node_id, CooperativeChainMessage::SubscribeChainData(m));
            } else {
                log::info!("cooperative_chain_handler: LSP peer connected — re-issuing SubscribeChainData");
            }
            self.resubscribe_wanted.store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }
    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        let mut f = InitFeatures::empty();
        f.set_optional_custom_bit(COOPERATIVE_CHAIN_DATA_FEATURE_BIT)
            .expect("custom bit should be in the optional range");
        f.set_optional_custom_bit(LIJ_FUNDING_HOLD_FEATURE_BIT)   // v363: the provider reads this one from ListPeers
            .expect("custom bit should be in the optional range");
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{BlockHash, ScriptBuf, Txid};

    fn dummy_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1); // avoid all-zero secret
        let sk = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn dummy_txid(b: u8) -> Txid {
        Txid::from_byte_array([b; 32])
    }

    fn dummy_blockhash(b: u8) -> BlockHash {
        BlockHash::from_byte_array([b; 32])
    }

    fn init_msg() -> lightning::ln::msgs::Init {
        lightning::ln::msgs::Init { features: InitFeatures::empty(), networks: None, remote_network_address: None }
    }

    // v321 (S58, the CHAIN dot): the subscription sent before the provider connected is dropped by LDK; the moment the
    // provider's peer connects it goes out again in the same pass — and the tick's fresh snapshot is still asked for.
    #[test]
    fn v321_peer_connected_sends_the_last_subscription_at_once() {
        let h = CooperativeChainHandler::new();
        let lsp = dummy_pubkey(9);
        let sub = SubscribeChainData { watch_txids: vec![dummy_txid(3)], watch_scripts: vec![ScriptBuf::from(vec![0x51])] };
        h.send_subscribe(lsp, sub.clone());
        assert_eq!(h.get_and_clear_pending_msg().len(), 1);   // drained while the peer was not yet connected (LDK drops it)
        h.peer_connected(lsp, &init_msg(), false).unwrap();
        let out = h.get_and_clear_pending_msg();
        assert_eq!(out.len(), 1, "the subscription goes out at once");
        assert_eq!(out[0].0, lsp);
        assert_eq!(out[0].1, CooperativeChainMessage::SubscribeChainData(sub));
        assert!(h.take_resubscribe_wanted(), "the tick still sends a fresh snapshot after");
    }

    #[test]
    fn v321_another_peer_or_no_subscription_sends_nothing() {
        let h = CooperativeChainHandler::new();
        h.peer_connected(dummy_pubkey(4), &init_msg(), false).unwrap();   // nothing ever subscribed
        assert_eq!(h.get_and_clear_pending_msg().len(), 0);
        assert!(!h.take_resubscribe_wanted());
        let lsp = dummy_pubkey(9);
        h.send_subscribe(lsp, SubscribeChainData { watch_txids: vec![], watch_scripts: vec![] });
        let _ = h.get_and_clear_pending_msg();
        h.peer_connected(dummy_pubkey(5), &init_msg(), true).unwrap();   // a different peer (not the provider)
        assert_eq!(h.get_and_clear_pending_msg().len(), 0);
        assert!(!h.take_resubscribe_wanted());
    }

    #[test]
    fn v321_each_reconnect_sends_the_newest_subscription() {
        let h = CooperativeChainHandler::new();
        let lsp = dummy_pubkey(9);
        h.send_subscribe(lsp, SubscribeChainData { watch_txids: vec![dummy_txid(1)], watch_scripts: vec![] });
        let newer = SubscribeChainData { watch_txids: vec![dummy_txid(1), dummy_txid(2)], watch_scripts: vec![] };
        h.send_subscribe(lsp, newer.clone());
        let _ = h.get_and_clear_pending_msg();
        h.peer_disconnected(lsp);
        h.peer_connected(lsp, &init_msg(), false).unwrap();
        let out = h.get_and_clear_pending_msg();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, CooperativeChainMessage::SubscribeChainData(newer));
    }

    #[test]
    fn enqueue_and_drain_outbound() {
        let h = CooperativeChainHandler::new();
        let peer = dummy_pubkey(1);
        h.send_subscribe(peer, SubscribeChainData {
            watch_txids: vec![dummy_txid(1)],
            watch_scripts: vec![],
        });
        h.send_broadcast_tx(peer, BroadcastTx {
            request_id: 42,
            raw_tx: vec![0u8; 100],
        });
        assert_eq!(h.outbound_depth(), 2);
        let drained = h.get_and_clear_pending_msg();
        assert_eq!(drained.len(), 2);
        assert_eq!(h.outbound_depth(), 0);
        // Second drain returns empty
        assert_eq!(h.get_and_clear_pending_msg().len(), 0);
    }

    #[test]
    fn inbound_dispatch_buffers_message() {
        let h = CooperativeChainHandler::new();
        let peer = dummy_pubkey(2);
        let msg = CooperativeChainMessage::BlockHeightUpdate(BlockHeightUpdate {
            new_height: 880_500,
            new_blockhash: dummy_blockhash(0xab),
        });
        h.handle_custom_message(msg.clone(), peer).unwrap();
        let received = h.take_received();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].sender, peer);
        assert_eq!(received[0].message, msg);
        // Second drain returns empty
        assert_eq!(h.take_received().len(), 0);
    }

    #[test]
    fn reader_decodes_known_types() {
        let h = CooperativeChainHandler::new();
        let original = BlockHeightUpdate {
            new_height: 880_500,
            new_blockhash: dummy_blockhash(7),
        };
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let mut cursor: &[u8] = &bytes;   // 0.2: readers must be length-limited; a byte slice is
        let result = h.read(TYPE_BLOCK_HEIGHT_UPDATE, &mut cursor).unwrap();
        match result {
            Some(CooperativeChainMessage::BlockHeightUpdate(m)) => {
                assert_eq!(m.new_height, 880_500);
            }
            other => panic!("unexpected decode result: {:?}", other),
        }
    }

    #[test]
    fn reader_returns_none_for_unknown_type() {
        let h = CooperativeChainHandler::new();
        let mut cursor: &[u8] = &[0u8; 10][..];
        let result = h.read(0xFFFF, &mut cursor).unwrap();
        assert!(result.is_none(), "unknown type should return None");
    }

    #[test]
    fn message_enum_type_id_matches_inner() {
        let m = CooperativeChainMessage::BlockHeightUpdate(BlockHeightUpdate {
            new_height: 1,
            new_blockhash: dummy_blockhash(0),
        });
        assert_eq!(m.type_id(), TYPE_BLOCK_HEIGHT_UPDATE);

        let m2 = CooperativeChainMessage::BroadcastTx(BroadcastTx {
            request_id: 0,
            raw_tx: vec![],
        });
        assert_eq!(m2.type_id(), TYPE_BROADCAST_TX);
    }

    #[test]
    fn message_enum_writeable_round_trips_via_inner() {
        let original = ChainDataBundle {
            tip_height: 880_247,
            tip_blockhash: dummy_blockhash(7),
            recent_blockhashes: vec![dummy_blockhash(7), dummy_blockhash(6)],
            fee_sat_per_vb_fast: 32,
            fee_sat_per_vb_medium: 16,
            fee_sat_per_vb_slow: 4,
        };
        let wrapped = CooperativeChainMessage::ChainDataBundle(original.clone());

        // Writing the enum delegates to the inner Writeable
        let mut enum_bytes = Vec::new();
        wrapped.write(&mut enum_bytes).unwrap();

        // Writing the inner struct directly should produce the same bytes
        let mut inner_bytes = Vec::new();
        original.write(&mut inner_bytes).unwrap();

        assert_eq!(enum_bytes, inner_bytes);
    }

    #[test]
    fn provided_features_set_custom_bit() {
        let h = CooperativeChainHandler::new();
        let node_features = h.provided_node_features();
        // Verify the bit is set by checking that it's required-or-optional.
        // NodeFeatures doesn't expose a public `is_set` for arbitrary bits,
        // but we can serialize and inspect the byte length.
        let mut bytes = Vec::new();
        node_features.write(&mut bytes).unwrap();
        // Bit 257 lives in byte 32 (257 / 8 = 32, 257 % 8 = 1).
        // Plus 2-byte length prefix at the start.
        // Don't rely on exact bytes; just verify nonempty (would be empty
        // if no bit was set).
        assert!(!bytes.is_empty());

        let init_features = h.provided_init_features(dummy_pubkey(1));
        let mut init_bytes = Vec::new();
        init_features.write(&mut init_bytes).unwrap();
        assert!(!init_bytes.is_empty());
        // v363: both custom bits are in the init features and both are OPTIONAL (odd) — the provider reads bit 259
        // from LND's peer list; an LSP that does not know either bit keeps the connection (BOLT 9).
        assert!(init_features.supports_unknown_bits(), "custom bits must be set");
        assert!(init_features.requires_unknown_bits() == false, "custom bits must be optional, never required");
        // the serialized vector: a 2-byte length then the bytes, most significant first. Bit 257 is byte index 32
        // from the LEAST significant end (257 / 8), bit value 1 << 1; bit 261 is the same byte, value 1 << 5.
        let len = u16::from_be_bytes([init_bytes[0], init_bytes[1]]) as usize;
        assert_eq!(init_bytes.len(), 2 + len);
        let byte_from_lsb = |i: usize| init_bytes[2 + (len - 1 - i)];
        assert_eq!(byte_from_lsb(32) & (1 << 1), 1 << 1, "bit 257");
        assert_eq!(byte_from_lsb(32) & (1 << 5), 1 << 5, "bit 261");
        // and the node features carry both as well (the node context knows 258/259 — DnsResolver — hence 261)
        let mut nb = Vec::new(); node_features.write(&mut nb).unwrap();
        let nlen = u16::from_be_bytes([nb[0], nb[1]]) as usize;
        let nbyte = nb[2 + (nlen - 1 - 32)];
        assert_eq!(nbyte & (1 << 1), 1 << 1); assert_eq!(nbyte & (1 << 5), 1 << 5);
    }

    #[test]
    fn handle_custom_message_returns_ok() {
        let h = CooperativeChainHandler::new();
        let peer = dummy_pubkey(3);
        let msg = CooperativeChainMessage::FundingTxConfirmed(FundingTxConfirmed {
            txid: dummy_txid(0xab),
            confirmed_at_height: 880_103,
            blockhash_of_confirmation: dummy_blockhash(0x42),
            confirmations: 3,
            raw_tx_bytes: vec![1u8, 2, 3, 4],
            tx_index: 0,
        });
        let result = h.handle_custom_message(msg, peer);
        assert!(result.is_ok());
    }

    #[test]
    fn outbound_preserves_fifo_order() {
        let h = CooperativeChainHandler::new();
        let peer = dummy_pubkey(4);
        for i in 0..5 {
            h.enqueue(peer, CooperativeChainMessage::BlockHeightUpdate(BlockHeightUpdate {
                new_height: i,
                new_blockhash: dummy_blockhash(i as u8),
            }));
        }
        let drained = h.get_and_clear_pending_msg();
        assert_eq!(drained.len(), 5);
        for (i, (_, msg)) in drained.iter().enumerate() {
            match msg {
                CooperativeChainMessage::BlockHeightUpdate(m) => {
                    assert_eq!(m.new_height, i as u32);
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    // Suppress unused-import warning when bitcoin's ScriptBuf isn't directly
    // referenced in tests but is exported by cooperative_chain_msg.
    #[allow(dead_code)]
    fn _unused_imports_anchor(_: ScriptBuf) {}

    // ── v383 (S72): the path for requests rides the same handler ──
    #[test]
    fn v383_the_reader_takes_37913_whole_and_still_says_unknown_for_other_types() {
        let h = CooperativeChainHandler::new();
        let text = br#"{"jsonrpc":"2.0","id":"a-1","result":{"ok":true}}"#;
        let got = h.read(crate::lijox_rpc::TYPE_LSPS0, &mut &text[..]).unwrap().unwrap();
        assert_eq!(got, CooperativeChainMessage::Lsps0(text.to_vec()));
        assert_eq!(got.type_id(), 37913);
        let mut w = Vec::new();
        got.write(&mut w).unwrap();
        assert_eq!(w, text.to_vec(), "written as the JSON text itself, nothing added");
        assert!(h.read(37915, &mut &text[..]).unwrap().is_none());
        assert!(h.read(40001, &mut &b""[..]).unwrap().is_none());
        // a payload of the largest size a Lightning message holds is read whole
        let big = vec![b' '; 65_533];
        assert_eq!(h.read(crate::lijox_rpc::TYPE_LSPS0, &mut &big[..]).unwrap(), Some(CooperativeChainMessage::Lsps0(big)));
    }

    #[test]
    fn v383_an_answer_reaches_the_request_and_never_the_chain_queue() {
        use futures::FutureExt;
        let h = CooperativeChainHandler::new();
        let lsp = dummy_pubkey(9);
        let (id, rx) = h.rpc().call(lsp, "lijox.prefs_set", serde_json::json!({ "hold_ms": 60000 })).unwrap();
        // the request leaves through the handler's one queue, as message 37913
        let out = h.get_and_clear_pending_msg();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, lsp);
        assert_eq!(out[0].1.type_id(), 37913);
        let answer = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } }).to_string().into_bytes();
        h.handle_custom_message(CooperativeChainMessage::Lsps0(answer), lsp).unwrap();
        assert_eq!(h.inbound_depth(), 0, "a 37913 message is not a chain-data message");
        assert_eq!(rx.now_or_never().unwrap().unwrap().to_json(), serde_json::json!({ "ok": true, "status": 200, "body": { "ok": true } }));
    }

    #[test]
    fn v383_chain_messages_and_requests_leave_in_one_drain_chain_first() {
        let h = CooperativeChainHandler::new();
        let lsp = dummy_pubkey(9);
        let _ = h.rpc().call(lsp, "lijox.hello", serde_json::json!({})).unwrap();
        h.send_register_watch_tx(lsp, RegisterWatchTx { txid: dummy_txid(1), script_pubkey: ScriptBuf::new() });
        let out = h.get_and_clear_pending_msg();
        assert_eq!(out.iter().map(|(_, m)| m.type_id()).collect::<Vec<_>>(), vec![TYPE_REGISTER_WATCH_TX, 37913]);
        assert!(h.get_and_clear_pending_msg().is_empty());
        // a chain-data message that arrives still goes to the chain queue
        h.handle_custom_message(CooperativeChainMessage::BlockHeightUpdate(BlockHeightUpdate { new_height: 7, new_blockhash: dummy_blockhash(1) }), lsp).unwrap();
        assert_eq!(h.inbound_depth(), 1);
    }

    #[test]
    fn v383_a_disconnect_ends_the_requests_that_wait_on_that_peer() {
        use futures::FutureExt;
        let h = CooperativeChainHandler::new();
        let lsp = dummy_pubkey(9);
        let (_id, rx) = h.rpc().call(lsp, "lijox.hello", serde_json::json!({})).unwrap();
        h.peer_disconnected(lsp);
        let o = rx.now_or_never().unwrap().unwrap();
        assert!(matches!(o, crate::lijox_rpc::RpcOutcome::PathError { code: crate::lijox_rpc::E_DISCONNECTED, .. }));
    }
}
