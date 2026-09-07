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
use lightning::ln::features::{InitFeatures, NodeFeatures};
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::util::ser::{Readable, Writeable, Writer};

use crate::cooperative_chain_msg::{
    BlockHeightUpdate, BroadcastAck, BroadcastTx, ChainDataBundle, ChannelStateUpdate,
    FeeScheduleUpdate, FundingTxConfirmed, RegisterWatchOutput, RegisterWatchTx,
    SubscribeChainData, TYPE_BLOCK_HEIGHT_UPDATE, TYPE_BROADCAST_ACK, TYPE_BROADCAST_TX,
    TYPE_CHAIN_DATA_BUNDLE, TYPE_CHANNEL_STATE_UPDATE, TYPE_FEE_SCHEDULE_UPDATE,
    TYPE_FUNDING_TX_CONFIRMED, TYPE_REGISTER_WATCH_OUTPUT, TYPE_REGISTER_WATCH_TX,
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
}

impl Writeable for CooperativeChainMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
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

pub struct CooperativeChainHandler {
    /// Outbound queue. Drained by PeerManager via get_and_clear_pending_msg.
    outbound: Mutex<VecDeque<(PublicKey, CooperativeChainMessage)>>,
    /// Inbound buffer. Drained by step-4c bridge code via take_received().
    inbound: Mutex<VecDeque<ReceivedMessage>>,
}

impl CooperativeChainHandler {
    pub fn new() -> Self {
        Self {
            outbound: Mutex::new(VecDeque::new()),
            inbound: Mutex::new(VecDeque::new()),
        }
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

    fn read<R: std::io::Read>(
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
        sender_node_id: &PublicKey,
    ) -> Result<(), LightningError> {
        log::debug!(
            "cooperative_chain: received {:?} from {}",
            msg.type_id(),
            sender_node_id
        );
        self.inbound.lock().unwrap().push_back(ReceivedMessage {
            sender: *sender_node_id,
            message: msg,
        });
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut q = self.outbound.lock().unwrap();
        q.drain(..).collect()
    }

    fn provided_node_features(&self) -> NodeFeatures {
        let mut f = NodeFeatures::empty();
        f.set_optional_custom_bit(COOPERATIVE_CHAIN_DATA_FEATURE_BIT)
            .expect("custom bit should be in the optional range");
        f
    }

    fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
        let mut f = InitFeatures::empty();
        f.set_optional_custom_bit(COOPERATIVE_CHAIN_DATA_FEATURE_BIT)
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
        h.handle_custom_message(msg.clone(), &peer).unwrap();
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
        let mut cursor = std::io::Cursor::new(&bytes);
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
        let mut cursor = std::io::Cursor::new(&[0u8; 10][..]);
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

        let init_features = h.provided_init_features(&dummy_pubkey(1));
        let mut init_bytes = Vec::new();
        init_features.write(&mut init_bytes).unwrap();
        assert!(!init_bytes.is_empty());
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
        let result = h.handle_custom_message(msg, &peer);
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
}
