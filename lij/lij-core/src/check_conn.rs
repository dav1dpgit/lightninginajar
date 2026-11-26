// check_conn.rs — v389 (S72 Wed 2026-11-25, F2b — docs/design/routes/f2b-r1.md §2; the plan's §2.5, DP: "I agree with
// this"): THE CHECK CONNECTION. A short Lightning connection to the provider under a key made for one start.
//
// Why: before the wallet connects as itself it asks its provider up to four things (the statement and the pass, the
// channel state file, its channel list, a close in a recovery). They must be asked BEFORE the wallet connects as
// itself — the provider's node closes a channel by force the moment a wallet reconnects with an older state — so they
// cannot go inside the wallet's own connection. A key with no channels has nothing to re-establish: nothing can be
// closed on it. Inside this connection the requests travel as they do inside the real one (LSPS0, message 37913),
// encrypted to the provider's node key, and each still carries the proof made by the wallet's REAL key.
//
// How: LDK's peer manager has one identity, and its handshake code is not public. So this is a SECOND peer manager on
// a throwaway key manager — LDK's own handshake and encryption, none written here. It has no channel handler, no
// gossip and no onion messages; its one handler carries message 37913 to the same request path the real connection
// uses (lijox_rpc.rs).
//
// No network in this file: bytes come in through `read`, bytes go out through the socket dispatcher that exists
// (peer.rs), under this connection's own socket number. lij-wasm owns the WebSocket.

use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::PublicKey;
use futures::channel::oneshot;
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::{
    CustomMessageHandler, ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
};
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use lightning::types::features::{InitFeatures, NodeFeatures};
use lightning::util::ser::{Writeable, Writer};
use serde_json::Value;

use crate::error::{LijError, LijResult};
use crate::lijox_rpc::{LijoxRpc, RpcOutcome, TYPE_LSPS0};
use crate::node::DynLogger;
use crate::peer::LijSocketDescriptor;

/// The text frame that marks a check connection at the provider's tunnel (lijox-adapter ws-tunnel.js names the same).
pub const CHECK_FRAME: &str = "lijox-check";

/// The one message kind a check connection carries: an LSPS0 payload, the JSON text itself.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckMessage(pub Vec<u8>);

impl Writeable for CheckMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
        w.write_all(&self.0)
    }
}

impl Type for CheckMessage {
    fn type_id(&self) -> u16 {
        TYPE_LSPS0
    }
}

/// The check connection's one handler: message 37913 in and out, nothing else. It offers no feature bits — a check
/// connection says nothing about the wallet it is made for.
pub struct CheckHandler {
    rpc: Arc<LijoxRpc>,
}

impl CheckHandler {
    fn new() -> Self {
        let r = crate::peer::ephemeral_bytes();
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&r[..8]);
        Self { rpc: Arc::new(LijoxRpc::new(seed)) }
    }
}

impl CustomMessageReader for CheckHandler {
    type CustomMessage = CheckMessage;

    fn read<R: lightning::io::Read>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        if message_type != TYPE_LSPS0 {
            return Ok(None);   // anything else the provider sends is not for a check connection
        }
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = buffer.read(&mut chunk)?;
            if n == 0 { break; }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > 65_535 { return Err(DecodeError::InvalidValue); }
        }
        Ok(Some(CheckMessage(bytes)))
    }
}

impl CustomMessageHandler for CheckHandler {
    fn handle_custom_message(&self, msg: Self::CustomMessage, sender_node_id: PublicKey) -> Result<(), LightningError> {
        self.rpc.on_message(sender_node_id, &msg.0, crate::storage::now_ms());
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        self.rpc.drain_outbound().into_iter().map(|(peer, bytes)| (peer, CheckMessage(bytes))).collect()
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        self.rpc.peer_disconnected(&their_node_id);   // a request that waits ends now, with the reason
    }

    fn peer_connected(&self, _their_node_id: PublicKey, _msg: &lightning::ln::msgs::Init, _inbound: bool) -> Result<(), ()> {
        Ok(())
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }
}

type CheckPeerManager = PeerManager<
    LijSocketDescriptor,
    Arc<ErroringMessageHandler>,    // no channels: a channel message is answered with an error
    Arc<IgnoringMessageHandler>,    // no gossip
    Arc<IgnoringMessageHandler>,    // no onion messages
    DynLogger,
    Arc<CheckHandler>,
    Arc<KeysManager>,
    Arc<IgnoringMessageHandler>,
>;

/// One check connection: its own key, its own peer manager, its own socket number.
pub struct CheckConn {
    pm: CheckPeerManager,
    handler: Arc<CheckHandler>,
    provider: PublicKey,
    our_key: PublicKey,
    socket_id: u64,
    closed: Mutex<bool>,
}

impl CheckConn {
    /// Make the one-time key and the handshake's first bytes toward `provider`. `wallet_key` is the wallet's own
    /// node key: the one-time key must not be it (it cannot be — 32 fresh random bytes — and the rule is checked all
    /// the same, because a wallet's real key on a check connection is the one thing that must never happen).
    /// `socket_id` is the number lij-wasm opened this connection's socket under.
    pub fn open(provider: PublicKey, wallet_key: &PublicKey, socket_id: u64, logger: DynLogger) -> LijResult<(Self, Vec<u8>)> {
        let seed = crate::peer::ephemeral_bytes();
        let now = crate::storage::now_ms();
        let km = Arc::new(KeysManager::new(&seed, now / 1000, ((now % 1000) * 1_000_000) as u32, true));
        let our_key = km
            .get_node_id(Recipient::Node)
            .map_err(|_| LijError::Node("check connection: no one-time key".to_string()))?;
        if our_key == *wallet_key {
            return Err(LijError::Node("check connection: the one-time key is the wallet's own key — refused".to_string()));
        }
        if our_key == provider {
            return Err(LijError::Node("check connection: the one-time key is the provider's key — refused".to_string()));
        }
        let handler = Arc::new(CheckHandler::new());
        let ignoring = Arc::new(IgnoringMessageHandler {});
        let pm: CheckPeerManager = PeerManager::new(
            MessageHandler {
                chan_handler: Arc::new(ErroringMessageHandler::new()),
                route_handler: Arc::clone(&ignoring),
                onion_message_handler: Arc::clone(&ignoring),
                custom_message_handler: Arc::clone(&handler),
                send_only_message_handler: ignoring,
            },
            (now / 1000) as u32,
            &crate::peer::ephemeral_bytes(),
            logger,
            km,
        );
        let first = pm
            .new_outbound_connection(provider, LijSocketDescriptor::new(socket_id), None)
            .map_err(|e| LijError::Node(format!("check connection: new_outbound_connection: {:?}", e)))?;
        Ok((Self { pm, handler, provider, our_key, socket_id, closed: Mutex::new(false) }, first))
    }

    /// `open`, from the keys as the page holds them (66 hex characters each), under a socket number of its own.
    pub fn open_hex(provider_hex: &str, wallet_key_hex: &str) -> LijResult<(Self, Vec<u8>)> {
        use std::str::FromStr;
        let provider = PublicKey::from_str(provider_hex.trim())
            .map_err(|_| LijError::Node("check connection: the provider's key is not a node key".to_string()))?;
        let wallet_key = PublicKey::from_str(wallet_key_hex.trim())
            .map_err(|_| LijError::Node("check connection: the wallet's key is not a node key".to_string()))?;
        let logger: DynLogger = Arc::new(crate::node::LijLogger);
        Self::open(provider, &wallet_key, crate::node::next_socket_id_global(), logger)
    }

    /// `call`, with the params as JSON text (an object).
    pub fn call_json(&self, method: &str, params_json: &str) -> Result<(String, oneshot::Receiver<RpcOutcome>), String> {
        let params: Value = serde_json::from_str(params_json).map_err(|_| "params are not JSON".to_string())?;
        if !params.is_object() { return Err("params must be an object".to_string()); }
        self.call(method, params)
    }

    /// The key this connection is made under (for the journal and the tests; never the wallet's).
    pub fn our_key(&self) -> PublicKey { self.our_key }
    pub fn provider(&self) -> PublicKey { self.provider }
    pub fn socket_id(&self) -> u64 { self.socket_id }

    /// Bytes that came from the provider. What the peer manager wants to send in answer goes out through the socket
    /// dispatcher before this returns.
    pub fn read(&self, bytes: &[u8]) -> LijResult<()> {
        if *self.closed.lock().unwrap() { return Err(LijError::Node("check connection: closed".to_string())); }
        let mut d = LijSocketDescriptor::new(self.socket_id);
        let r = self.pm.read_event(&mut d, bytes);
        self.pm.process_events();
        match r {
            Ok(_) => Ok(()),
            Err(e) => {
                *self.closed.lock().unwrap() = true;
                Err(LijError::Node(format!("check connection: the provider's bytes were refused: {:?}", e)))
            }
        }
    }

    /// True once the handshake is done and the provider's `init` has been read: requests can be sent.
    pub fn ready(&self) -> bool {
        !*self.closed.lock().unwrap() && self.pm.peer_by_node_id(&self.provider).is_some()
    }

    /// One request inside the check connection. → its id, and the place its answer arrives. The request's bytes go
    /// out through the socket dispatcher before this returns.
    pub fn call(&self, method: &str, params: Value) -> Result<(String, oneshot::Receiver<RpcOutcome>), String> {
        if !self.ready() { return Err("not_connected".to_string()); }
        let r = self.handler.rpc.call(self.provider, method, params)?;
        self.pm.process_events();
        Ok(r)
    }

    /// Stop waiting for a request (its time is up).
    pub fn cancel(&self, id: &str) { self.handler.rpc.cancel(id); }

    /// Once a second while the connection lives: lets the peer manager send what it holds.
    pub fn tick(&self) { if !*self.closed.lock().unwrap() { self.pm.process_events(); } }

    /// The socket has closed (or is being closed): every waiting request ends with the reason.
    pub fn closed(&self) {
        let mut c = self.closed.lock().unwrap();
        if *c { return; }
        *c = true;
        self.pm.socket_disconnected(&LijSocketDescriptor::new(self.socket_id));
    }

    pub fn is_closed(&self) -> bool { *self.closed.lock().unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::LijLogger;
    use crate::peer::{set_dispatcher, SocketDispatcher};
    use std::collections::{HashMap, VecDeque};
    use std::sync::OnceLock;

    // The tests' socket dispatcher: what a peer manager writes to socket `id` is kept under that number.
    struct TestWires { q: Mutex<HashMap<u64, VecDeque<Vec<u8>>>>, cut: Mutex<Vec<u64>> }
    impl SocketDispatcher for TestWires {
        fn send(&self, id: u64, data: &[u8]) -> usize {
            self.q.lock().unwrap().entry(id).or_default().push_back(data.to_vec());
            data.len()
        }
        fn disconnect(&self, id: u64) { self.cut.lock().unwrap().push(id); }
    }
    fn wires() -> &'static Arc<TestWires> {
        static W: OnceLock<Arc<TestWires>> = OnceLock::new();
        W.get_or_init(|| {
            let w = Arc::new(TestWires { q: Mutex::new(HashMap::new()), cut: Mutex::new(Vec::new()) });
            let _ = set_dispatcher(w.clone());   // another test of this crate may have set one; these tests then cannot run
            w
        })
    }
    fn take(id: u64) -> Vec<Vec<u8>> { wires().q.lock().unwrap().remove(&id).map(|q| q.into_iter().collect()).unwrap_or_default() }

    // The provider's side for the tests: a peer manager under its own key whose handler answers every 37913 request
    // with a result that names the method and the key it came from.
    struct Provider { seen: Mutex<Vec<(PublicKey, String)>>, out: Mutex<Vec<(PublicKey, CheckMessage)>> }
    impl CustomMessageReader for Provider {
        type CustomMessage = CheckMessage;
        fn read<R: lightning::io::Read>(&self, t: u16, b: &mut R) -> Result<Option<CheckMessage>, DecodeError> {
            if t != TYPE_LSPS0 { return Ok(None); }
            let mut v = Vec::new(); let mut c = [0u8; 4096];
            loop { let n = b.read(&mut c)?; if n == 0 { break; } v.extend_from_slice(&c[..n]); }
            Ok(Some(CheckMessage(v)))
        }
    }
    impl CustomMessageHandler for Provider {
        fn handle_custom_message(&self, msg: CheckMessage, from: PublicKey) -> Result<(), LightningError> {
            let j: Value = serde_json::from_slice(&msg.0).unwrap();
            let method = j["method"].as_str().unwrap_or("").to_string();
            self.seen.lock().unwrap().push((from, method.clone()));
            let ans = serde_json::json!({ "jsonrpc": "2.0", "id": j["id"], "result": { "ok": true, "method": method, "caller": from.to_string(), "params": j["params"] } });
            self.out.lock().unwrap().push((from, CheckMessage(ans.to_string().into_bytes())));
            Ok(())
        }
        fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, CheckMessage)> { std::mem::take(&mut *self.out.lock().unwrap()) }
        fn provided_node_features(&self) -> NodeFeatures { NodeFeatures::empty() }
        fn peer_disconnected(&self, _: PublicKey) {}
        fn peer_connected(&self, _: PublicKey, _: &lightning::ln::msgs::Init, _: bool) -> Result<(), ()> { Ok(()) }
        fn provided_init_features(&self, _: PublicKey) -> InitFeatures { InitFeatures::empty() }
    }
    type ProviderPm = PeerManager<LijSocketDescriptor, Arc<ErroringMessageHandler>, Arc<IgnoringMessageHandler>, Arc<IgnoringMessageHandler>, DynLogger, Arc<Provider>, Arc<KeysManager>, Arc<IgnoringMessageHandler>>;
    fn provider(seed: u8) -> (ProviderPm, Arc<Provider>, PublicKey) {
        let _ = wires();   // the tests' dispatcher is in place before any peer manager writes a byte
        let km = Arc::new(KeysManager::new(&[seed; 32], 1_800_000_000, 7, true));
        let pk = km.get_node_id(Recipient::Node).unwrap();
        let h = Arc::new(Provider { seen: Mutex::new(Vec::new()), out: Mutex::new(Vec::new()) });
        let ig = Arc::new(IgnoringMessageHandler {});
        let logger: DynLogger = Arc::new(LijLogger);
        let pm: ProviderPm = PeerManager::new(
            MessageHandler { chan_handler: Arc::new(ErroringMessageHandler::new()), route_handler: Arc::clone(&ig), onion_message_handler: Arc::clone(&ig), custom_message_handler: Arc::clone(&h), send_only_message_handler: ig },
            1_800_000_000, &[seed.wrapping_add(1); 32], logger, km);
        (pm, h, pk)
    }
    fn wallet_key() -> PublicKey { KeysManager::new(&[9u8; 32], 1_800_000_000, 1, true).get_node_id(Recipient::Node).unwrap() }

    // Carry bytes both ways until neither side has anything to say.
    fn pump(c: &CheckConn, c_id: u64, p: &ProviderPm, p_id: u64) {
        for _ in 0..40 {
            let a = take(c_id); let b = take(p_id);
            if a.is_empty() && b.is_empty() { break; }
            for bytes in a { let mut d = LijSocketDescriptor::new(p_id); p.read_event(&mut d, &bytes).unwrap(); p.process_events(); }
            for bytes in b { c.read(&bytes).unwrap(); }
            p.process_events(); c.tick();
        }
    }

    #[test]
    fn v389_a_check_connection_under_a_one_time_key_carries_a_request_and_its_answer() {
        let (c_id, p_id) = (910_001u64, 910_002u64);
        let (ppm, ph, ppk) = provider(31);
        let logger: DynLogger = Arc::new(LijLogger);
        let wk = wallet_key();
        let (c, first) = CheckConn::open(ppk, &wk, c_id, logger).unwrap();
        assert_ne!(c.our_key(), wk, "the key on the check connection is never the wallet's");
        assert!(!c.ready(), "not ready before the handshake");
        assert!(c.call("lijox.hello", serde_json::json!({})).is_err(), "nothing is sent before the handshake is done");
        // the provider takes the connection (inbound) and is given the first bytes
        ppm.new_inbound_connection(LijSocketDescriptor::new(p_id), None).unwrap();
        { let mut d = LijSocketDescriptor::new(p_id); ppm.read_event(&mut d, &first).unwrap(); ppm.process_events(); }
        pump(&c, c_id, &ppm, p_id);
        assert!(c.ready(), "the handshake and the two init messages are done");
        assert!(ppm.peer_by_node_id(&c.our_key()).is_some(), "the provider knows this peer by the ONE-TIME key");
        assert!(ppm.peer_by_node_id(&wk).is_none(), "and not by the wallet's key");
        // a request, with the wallet's real key named INSIDE it (as the check requests do)
        let (id, mut rx) = c.call("lijox.state", serde_json::json!({ "node_pubkey": wk.to_string(), "channels": {} })).unwrap();
        assert!(!id.is_empty());
        pump(&c, c_id, &ppm, p_id);
        let got = rx.try_recv().unwrap().expect("the answer has arrived");
        let j = got.to_json();
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["body"]["method"], "lijox.state");
        assert_eq!(j["body"]["caller"], c.our_key().to_string(), "the provider's caller is the one-time key");
        assert_eq!(j["body"]["params"]["node_pubkey"], wk.to_string(), "the wallet's key travels inside the request only");
        assert_eq!(ph.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn v389_a_closed_check_connection_ends_what_waits_and_sends_nothing_more() {
        let (c_id, p_id) = (910_011u64, 910_012u64);
        let (ppm, _ph, ppk) = provider(41);
        let logger: DynLogger = Arc::new(LijLogger);
        let (c, first) = CheckConn::open(ppk, &wallet_key(), c_id, logger).unwrap();
        ppm.new_inbound_connection(LijSocketDescriptor::new(p_id), None).unwrap();
        { let mut d = LijSocketDescriptor::new(p_id); ppm.read_event(&mut d, &first).unwrap(); ppm.process_events(); }
        pump(&c, c_id, &ppm, p_id);
        assert!(c.ready());
        let (_id, mut rx) = c.call("lijox.my_channels", serde_json::json!({})).unwrap();
        let _ = take(c_id);   // the request is lost: the socket closes before it is carried
        c.closed();
        assert!(c.is_closed() && !c.ready());
        let end = rx.try_recv().unwrap().expect("the waiting request ended when the connection closed");
        assert!(matches!(end, RpcOutcome::PathError { code: crate::lijox_rpc::E_DISCONNECTED, .. }), "{:?}", end.to_json());
        assert!(c.call("lijox.state", serde_json::json!({})).is_err(), "nothing is sent on a closed check connection");
        assert!(c.read(&[0u8; 18]).is_err(), "and nothing is read on it");
    }

    #[test]
    fn v389_two_check_connections_never_share_a_key() {
        let (_ppm, _ph, ppk) = provider(51);
        let wk = wallet_key();
        let l1: DynLogger = Arc::new(LijLogger); let l2: DynLogger = Arc::new(LijLogger);
        let (a, _) = CheckConn::open(ppk, &wk, 910_021, l1).unwrap();
        let (b, _) = CheckConn::open(ppk, &wk, 910_022, l2).unwrap();
        assert_ne!(a.our_key(), b.our_key(), "a key made for one start is not made again");
        assert_ne!(a.our_key(), wk); assert_ne!(b.our_key(), wk);
    }

    #[test]
    fn v389_open_from_the_keys_as_the_page_holds_them() {
        let (_ppm, _ph, ppk) = provider(61);
        let wk = wallet_key();
        let (a, first) = CheckConn::open_hex(&ppk.to_string(), &wk.to_string()).unwrap();
        let (b, _) = CheckConn::open_hex(&ppk.to_string(), &wk.to_string()).unwrap();
        assert_eq!(first.len(), 50, "the handshake's first message is 50 bytes");
        assert_ne!(a.socket_id(), b.socket_id(), "each check connection has a socket number of its own");
        assert!(CheckConn::open_hex("not a key", &wk.to_string()).is_err());
        assert!(CheckConn::open_hex(&ppk.to_string(), "02abcd").is_err());
        assert!(a.call_json("lijox.state", "{}").is_err(), "not ready: nothing is sent");
        assert_eq!(a.call_json("lijox.state", "[1]").unwrap_err(), "params must be an object");
        assert_eq!(a.call_json("lijox.state", "{}").unwrap_err(), "not_connected");
    }

    #[test]
    fn v389_the_frame_that_marks_a_check_connection() {
        assert_eq!(CHECK_FRAME, "lijox-check");
        let m = CheckMessage(b"{}".to_vec());
        assert_eq!(m.type_id(), 37913);
    }
}
