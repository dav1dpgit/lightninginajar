// chain_filter.rs
// Replaces the `None` Filter argument in ChainMonitor::new.
// Implements LDK's `lightning::chain::Filter` trait.
//
// Architecture role:
//   The Filter is LDK's mechanism for expressing INTEREST in chain events.
//   When LDK opens a channel, it calls register_tx() for the funding txid.
//   When LDK watches a channel monitor, it calls register_output() for the
//   funding outpoint and any HTLC outputs.
//
//   The Filter does NOT deliver events back to LDK. That's done via the
//   `Confirm` trait, which ChannelManager and ChainMonitor already
//   implement. The cooperative and independent paths (steps 4 and 5)
//   read this Filter's registry to know WHAT to watch for, then call
//   `cm.transactions_confirmed(...)` and `chain_monitor.transactions_confirmed(...)`
//   when matching events arrive.
//
// Step 3 status:
//   - Trait impl: REAL.
//   - Thread-safe registry: REAL.
//   - "newly-registered since last poll" cursor: REAL (so cooperative
//     path doesn't re-subscribe to everything every tick).
//   - Read accessors for cooperative/independent paths: REAL.
//   - Wiring into ChainMonitor::new: REAL.
//   - Notification routing back to LDK: NOT here — that lives in the
//     cooperative/independent path implementations (steps 4 and 5).

use std::sync::Mutex;

use bitcoin::{BlockHash, ScriptBuf, Txid};
use lightning::chain::{Filter, WatchedOutput};

/// A transaction we're watching. LDK calls register_tx with a (txid, scriptPubKey)
/// pair when it wants to know about confirmation/spending of a specific tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedTx {
    pub txid: Txid,
    pub script_pubkey: ScriptBuf,
}

/// A snapshot of newly-registered items since the last poll. Cooperative
/// and independent paths use this to subscribe incrementally.
#[derive(Clone, Default)]
pub struct NewRegistrations {
    pub txs: Vec<WatchedTx>,
    pub outputs: Vec<WatchedOutput>,
}

impl NewRegistrations {
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty() && self.outputs.is_empty()
    }
}

/// Registry state. Lives behind a Mutex.
struct Registry {
    /// Everything we've ever been asked to watch. Persistent across polls.
    /// On wallet restart we re-subscribe to everything in this list.
    watched_txs: Vec<WatchedTx>,
    watched_outputs: Vec<WatchedOutput>,

    /// Items registered since last `take_new_registrations()` call.
    /// Cooperative path drains this each tick to subscribe incrementally.
    pending_new_txs: Vec<WatchedTx>,
    pending_new_outputs: Vec<WatchedOutput>,
}

impl Registry {
    fn new() -> Self {
        Self {
            watched_txs: Vec::new(),
            watched_outputs: Vec::new(),
            pending_new_txs: Vec::new(),
            pending_new_outputs: Vec::new(),
        }
    }
}

/// LDK-facing filter. Records interest, exposes registry to step-4 and
/// step-5 callers.
pub struct LijChainFilter {
    registry: Mutex<Registry>,
}

impl LijChainFilter {
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(Registry::new()),
        }
    }

    /// Drain the "newly-registered since last call" lists. Cooperative
    /// and independent paths call this each tick to know what to start
    /// watching for. After this returns, the pending lists are empty;
    /// the persistent watched_* lists are unchanged.
    pub fn take_new_registrations(&self) -> NewRegistrations {
        let mut reg = self.registry.lock().unwrap();
        NewRegistrations {
            txs: std::mem::take(&mut reg.pending_new_txs),
            outputs: std::mem::take(&mut reg.pending_new_outputs),
        }
    }

    /// Get a snapshot of all registered txs. Used on cooperative path
    /// reconnect to re-subscribe to everything.
    pub fn all_watched_txs(&self) -> Vec<WatchedTx> {
        self.registry.lock().unwrap().watched_txs.clone()
    }

    /// Get a snapshot of all registered outputs. Used on cooperative path
    /// reconnect.
    pub fn all_watched_outputs(&self) -> Vec<WatchedOutput> {
        self.registry.lock().unwrap().watched_outputs.clone()
    }

    /// Total count of registered items (for status panel display).
    pub fn watch_count(&self) -> (usize, usize) {
        let reg = self.registry.lock().unwrap();
        (reg.watched_txs.len(), reg.watched_outputs.len())
    }

    /// Re-mark all currently-watched items as newly-registered. Called on
    /// cooperative path reconnect when we want to push the full registry
    /// to the LSP afresh (instead of just incremental new items).
    pub fn mark_all_for_resubscribe(&self) {
        let mut reg = self.registry.lock().unwrap();
        reg.pending_new_txs = reg.watched_txs.clone();
        reg.pending_new_outputs = reg.watched_outputs.clone();
    }

    /// Report whether a given txid is in our watch list. Used by the
    /// cooperative/independent paths when filtering incoming events.
    pub fn is_watching_txid(&self, txid: &Txid) -> bool {
        self.registry
            .lock()
            .unwrap()
            .watched_txs
            .iter()
            .any(|w| &w.txid == txid)
    }

    /// Report whether any watched output is from the given block.
    /// Used during chain rescan after registering an output mid-block.
    pub fn watching_outputs_for_block(&self, block_hash: &BlockHash) -> Vec<WatchedOutput> {
        self.registry
            .lock()
            .unwrap()
            .watched_outputs
            .iter()
            .filter(|o| o.block_hash.as_ref() == Some(block_hash))
            .cloned()
            .collect()
    }
}

impl Filter for LijChainFilter {
    fn register_tx(&self, txid: &Txid, script_pubkey: &bitcoin::Script) {
        let entry = WatchedTx {
            txid: *txid,
            script_pubkey: script_pubkey.to_owned(),
        };
        let mut reg = self.registry.lock().unwrap();
        // Dedupe on (txid, script). LDK can call register_tx multiple times
        // for the same channel under some restart conditions.
        if reg.watched_txs.iter().any(|w| w == &entry) {
            log::debug!("chain_filter: register_tx dedup for {txid}");
            return;
        }
        log::info!("chain_filter: register_tx {txid}");
        reg.watched_txs.push(entry.clone());
        reg.pending_new_txs.push(entry);
    }

    fn register_output(&self, output: WatchedOutput) {
        let mut reg = self.registry.lock().unwrap();
        if reg.watched_outputs.iter().any(|o| o == &output) {
            log::debug!(
                "chain_filter: register_output dedup for {:?}",
                output.outpoint
            );
            return;
        }
        log::info!("chain_filter: register_output {:?}", output.outpoint);
        reg.watched_outputs.push(output.clone());
        reg.pending_new_outputs.push(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use lightning::chain::transaction::OutPoint;

    fn dummy_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn dummy_script() -> ScriptBuf {
        ScriptBuf::from(vec![0u8; 22])
    }

    fn dummy_outpoint(byte: u8) -> OutPoint {
        OutPoint {
            txid: dummy_txid(byte),
            index: 0,
        }
    }

    fn dummy_watched_output(byte: u8) -> WatchedOutput {
        WatchedOutput {
            block_hash: None,
            outpoint: dummy_outpoint(byte),
            script_pubkey: dummy_script(),
        }
    }

    #[test]
    fn register_tx_and_drain_new() {
        let f = LijChainFilter::new();
        f.register_tx(&dummy_txid(1), &dummy_script());
        f.register_tx(&dummy_txid(2), &dummy_script());
        let new_regs = f.take_new_registrations();
        assert_eq!(new_regs.txs.len(), 2);
        assert!(new_regs.outputs.is_empty());
        // Second drain returns empty
        let new_regs2 = f.take_new_registrations();
        assert!(new_regs2.is_empty());
        // But persistent registry still has them
        assert_eq!(f.all_watched_txs().len(), 2);
    }

    #[test]
    fn register_output_and_drain() {
        let f = LijChainFilter::new();
        f.register_output(dummy_watched_output(1));
        f.register_output(dummy_watched_output(2));
        let new_regs = f.take_new_registrations();
        assert_eq!(new_regs.outputs.len(), 2);
        assert!(new_regs.txs.is_empty());
    }

    #[test]
    fn dedup_register_tx() {
        let f = LijChainFilter::new();
        f.register_tx(&dummy_txid(1), &dummy_script());
        f.register_tx(&dummy_txid(1), &dummy_script());
        assert_eq!(f.all_watched_txs().len(), 1);
    }

    #[test]
    fn dedup_register_output() {
        let f = LijChainFilter::new();
        f.register_output(dummy_watched_output(1));
        f.register_output(dummy_watched_output(1));
        assert_eq!(f.all_watched_outputs().len(), 1);
    }

    #[test]
    fn mark_all_for_resubscribe() {
        let f = LijChainFilter::new();
        f.register_tx(&dummy_txid(1), &dummy_script());
        f.register_output(dummy_watched_output(2));
        // Drain initial pending
        let _ = f.take_new_registrations();
        // Mark for full resubscribe (e.g. after reconnect)
        f.mark_all_for_resubscribe();
        let new_regs = f.take_new_registrations();
        assert_eq!(new_regs.txs.len(), 1);
        assert_eq!(new_regs.outputs.len(), 1);
    }

    #[test]
    fn is_watching_txid_works() {
        let f = LijChainFilter::new();
        f.register_tx(&dummy_txid(7), &dummy_script());
        assert!(f.is_watching_txid(&dummy_txid(7)));
        assert!(!f.is_watching_txid(&dummy_txid(99)));
    }

    #[test]
    fn watch_count_works() {
        let f = LijChainFilter::new();
        assert_eq!(f.watch_count(), (0, 0));
        f.register_tx(&dummy_txid(1), &dummy_script());
        f.register_tx(&dummy_txid(2), &dummy_script());
        f.register_output(dummy_watched_output(3));
        assert_eq!(f.watch_count(), (2, 1));
    }

    #[test]
    fn outputs_for_block_filter() {
        let f = LijChainFilter::new();
        let block = BlockHash::from_byte_array([7u8; 32]);
        let mut o1 = dummy_watched_output(1);
        o1.block_hash = Some(block);
        let o2 = dummy_watched_output(2); // no block hash
        let mut o3 = dummy_watched_output(3);
        o3.block_hash = Some(BlockHash::from_byte_array([99u8; 32])); // different block
        f.register_output(o1.clone());
        f.register_output(o2);
        f.register_output(o3);
        let matched = f.watching_outputs_for_block(&block);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].outpoint, o1.outpoint);
    }
}
