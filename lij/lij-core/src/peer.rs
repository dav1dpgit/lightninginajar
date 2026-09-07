// peer.rs — Lightning peer connection layer
//
// Implements LDK's SocketDescriptor trait for use with PeerManager.
// The actual transport (WebSocket in browser, TCP elsewhere) is injected
// via the SocketDispatcher trait — keeps lij-core platform-agnostic.
//
// Architecture:
//   PeerManager → LijSocketDescriptor.send_data(bytes)
//              → GLOBAL_DISPATCHER.send(id, bytes)
//              → (lij-wasm) WebSocketManager looks up WebSocket by id, writes binary frame
//
// And the reverse on receive:
//   (lij-wasm) WebSocket.onmessage fires
//              → looks up wallet, calls PeerManager::read_event(descriptor, bytes)
//              → LDK processes Noise handshake / Lightning messages
//
// Phase 4 step 4b: custom message slot now holds CooperativeChainHandler
// (formerly IgnoringMessageHandler). The handler implements LDK's
// CustomMessageHandler/CustomMessageReader traits and carries the
// inbound buffer + outbound queue for the cooperative chain-data protocol.

use std::sync::Arc;
use std::hash::{Hash, Hasher};

use lightning::{
    ln::peer_handler::{
        IgnoringMessageHandler, MessageHandler, PeerManager, SocketDescriptor,
    },
    sign::KeysManager,
    util::logger::Logger,
};

use crate::cooperative_chain_handler::CooperativeChainHandler;
use crate::node::{
    DynBroadcaster, DynFeeEst, DynLogger, LijChannelManager,
};

// ── SocketDispatcher trait ───────────────────────────────────────────────────
// lij-wasm provides the real implementation using web_sys::WebSocket.
// Tests can provide a mock implementation.

pub trait SocketDispatcher: Send + Sync {
    /// Send bytes to the peer identified by `id`.
    /// Returns the number of bytes written (may be less than data.len() if
    /// the transport buffer is full, in which case LDK will retry).
    fn send(&self, id: u64, data: &[u8]) -> usize;

    /// Disconnect the socket identified by `id`.
    /// Called by LDK when it wants to drop a peer.
    fn disconnect(&self, id: u64);
}

// ── Global dispatcher registration ───────────────────────────────────────────
// Set once at startup by lij-wasm. Static lifetime is required because
// LijSocketDescriptor can outlive any specific wallet instance.

use std::sync::OnceLock;

static GLOBAL_DISPATCHER: OnceLock<Arc<dyn SocketDispatcher>> = OnceLock::new();

/// Register the platform-specific socket dispatcher.
/// Called once from lij-wasm during initialization.
/// Subsequent calls are ignored (OnceLock semantics).
pub fn set_dispatcher(dispatcher: Arc<dyn SocketDispatcher>) -> Result<(), &'static str> {
    GLOBAL_DISPATCHER
        .set(dispatcher)
        .map_err(|_| "dispatcher already set")
}

fn dispatcher() -> Option<&'static Arc<dyn SocketDispatcher>> {
    GLOBAL_DISPATCHER.get()
}

// ── LijSocketDescriptor ──────────────────────────────────────────────────────
// Implements LDK's SocketDescriptor trait.
// Held by PeerManager as a HashMap key — needs Eq, Hash, Clone.
// The only state it carries is the `id` — all transport state lives in the
// dispatcher's own bookkeeping (e.g., WebSocketManager in lij-wasm).

#[derive(Clone)]
pub struct LijSocketDescriptor {
    id: u64,
}

impl LijSocketDescriptor {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl SocketDescriptor for LijSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        // resume_read is a hint for back-pressure. We don't implement pausing
        // in the browser WebSocket transport (WebSocket API doesn't have native
        // flow control), so we ignore this hint. In practice Lightning traffic
        // volume doesn't trigger it.
        match dispatcher() {
            Some(d) => d.send(self.id, data),
            None => {
                log::error!("SocketDescriptor::send_data called but no dispatcher registered");
                0
            }
        }
    }

    fn disconnect_socket(&mut self) {
        if let Some(d) = dispatcher() {
            d.disconnect(self.id);
        }
    }
}

impl PartialEq for LijSocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for LijSocketDescriptor {}

impl Hash for LijSocketDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ── PeerManager type alias ───────────────────────────────────────────────────
// Concrete PeerManager with our specific handler types.
//
// Generics:
//   CMH = Channel Message Handler     → ChannelManager
//   RMH = Routing Message Handler     → IgnoringMessageHandler (RGS handles gossip separately)
//   OMH = Onion Message Handler       → IgnoringMessageHandler (no onion messages for now)
//   L   = Logger                       → our DynLogger
//   CustomH = Custom Message Handler  → CooperativeChainHandler (Phase 4 step 4b)
//   NS  = Node Signer                  → KeysManager

pub type LijPeerManagerType = PeerManager<
    LijSocketDescriptor,
    Arc<LijChannelManager>,              // CMH
    Arc<IgnoringMessageHandler>,         // RMH
    Arc<IgnoringMessageHandler>,         // OMH
    DynLogger,                           // L
    Arc<CooperativeChainHandler>,        // Custom (was IgnoringMessageHandler before step 4b)
    Arc<KeysManager>,                    // NS
>;

/// Build the MessageHandler struct that PeerManager needs.
/// Exposed so node.rs can construct it cleanly.
///
/// Phase 4 step 4b: custom_message_handler is now a CooperativeChainHandler
/// rather than the prior IgnoringMessageHandler. node.rs constructs the
/// handler once per LijNode (kept on the struct so step-4c bridge can
/// reach it) and passes it in here.
pub fn build_message_handler(
    channel_manager: Arc<LijChannelManager>,
    ignoring: Arc<IgnoringMessageHandler>,
    cooperative_chain: Arc<CooperativeChainHandler>,
) -> MessageHandler<
    Arc<LijChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<CooperativeChainHandler>,
> {
    MessageHandler {
        chan_handler: channel_manager,
        route_handler: Arc::clone(&ignoring),
        onion_message_handler: ignoring,
        custom_message_handler: cooperative_chain,
    }
}

/// Generate 32 ephemeral random bytes for PeerManager initialization.
/// PeerManager uses these to derive per-connection ephemeral keys.
pub fn ephemeral_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    #[cfg(target_arch = "wasm32")]
    {
        getrandom::getrandom(&mut bytes).expect("getrandom failed in WASM");
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
    }
    bytes
}
