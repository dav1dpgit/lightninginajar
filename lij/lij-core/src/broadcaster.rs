// broadcaster.rs
// Replaces NoopBroadcaster. Implements LDK's BroadcasterInterface.
//
// Architecture (per Phase4_chain_data_trust_model_v1.md):
//   - Cooperative path FIRST: push tx through LSP via BOLT 8 custom message.
//     LSP relays to its LND which broadcasts to Bitcoin network.
//   - Independent path FALLBACK: Esplora-quorum POST /tx to N endpoints.
//   - Hard-fail VISIBLY when both paths fail. No silent drops.
//
// Async-over-sync constraint:
//   LDK's BroadcasterInterface::broadcast_transactions is synchronous.
//   Our network calls are async. Resolution: enqueue serialized txs,
//   drain the queue from background_tick (existing 1-Hz heartbeat in node.rs).
//   The LDK call returns immediately after enqueueing.
//
// Step 1 status:
//   - Queue + drain + retry plumbing: REAL (this file).
//   - Cooperative client: TRAIT DEFINED, implementation deferred to step 4.
//   - Independent client: TRAIT DEFINED, implementation deferred to step 5.
//   - Hard-fail surfacing to status panel: hook present, panel wired in step 7.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bitcoin::Transaction;
use bitcoin::consensus::encode::serialize;
use lightning::chain::chaininterface::BroadcasterInterface;

use crate::error::LijResult;

/// How many times we retry a single transaction across both paths
/// before declaring it permanently failed and surfacing to the user.
const MAX_BROADCAST_ATTEMPTS: u8 = 3;

/// Build #4: park-ring cadence — one slow pass every N process_queue calls
/// (~30 s at the 1-Hz tick), forever. Funds-critical txs are never dropped.
const PARK_INTERVAL_ROUNDS: u64 = 30;
/// Conflict-class park rounds before retiring a tx as permanently conflicted.
const MAX_CONFLICT_STRIKES: u8 = 10;

#[derive(PartialEq)]
enum ErrClass { AlreadyKnown, Conflict, Transient }

/// Build #4: read the aggregated endpoint bodies. "already ..." means the tx
/// is out there (success); missing/spent/conflict means it may never confirm.
fn classify_err(msg: &str) -> ErrClass {
    let m = msg.to_lowercase();
    if m.contains("already") || m.contains("duplicate") {
        return ErrClass::AlreadyKnown;
    }
    if m.contains("missingorspent") || m.contains("bad-txns")
        || m.contains("mempool-conflict") || m.contains("conflict")
    {
        return ErrClass::Conflict;
    }
    ErrClass::Transient
}

/// One pending transaction in the broadcast queue.
/// We keep raw serialized bytes (not the parsed Transaction) because
/// LDK's interface gives us refs and we need to outlive the call.
#[derive(Clone, Debug)]
struct PendingTx {
    /// Raw serialized transaction bytes
    raw: Vec<u8>,
    /// Hex txid for logging and status surfaces
    txid_hex: String,
    /// How many attempts we've made on this tx
    attempts: u8,
    /// Last error seen, if any (for status panel surfacing)
    last_error: Option<String>,
    /// Build #4: conflict-class rejections seen while parked. A tx whose
    /// inputs are verifiably gone can never confirm; after
    /// MAX_CONFLICT_STRIKES slow rounds it is retired loudly.
    conflict_strikes: u8,
}

/// Type alias for the kind of futures our trait methods return.
/// Equivalent to what `#[async_trait(?Send)]` would generate, but
/// without the macro dependency. We use `LocalBoxFuture` semantics
/// (no Send bound) because WASM is single-threaded.
type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Cooperative broadcast — sends the tx via the LSP's BOLT 8 channel.
/// Implementation deferred to step 4 (BOLT 8 custom messages).
pub trait CooperativeBroadcaster {
    /// Submit a raw transaction through the LSP. Returns Ok(()) on
    /// successful relay (LSP acknowledged), Err otherwise. The LSP's
    /// own LND handles actual chain broadcast.
    fn broadcast<'a>(&'a self, raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>>;

    /// Whether the cooperative path is currently usable (LSP connected,
    /// subscription healthy). Skipped silently when false.
    fn is_available(&self) -> bool;
}

/// Independent broadcast — sends the tx to multiple Esplora endpoints.
/// Implementation deferred to step 5 (Esplora-quorum independent path).
///
/// Quorum semantics for broadcast (different from queries):
/// - Submit to ALL configured endpoints in parallel
/// - SUCCESS if any endpoint accepts (200/201)
/// - FAILURE only if ALL endpoints reject
/// - This is correct because Bitcoin network broadcast is "any-of" —
///   one accepting node propagates the tx to the rest of the mempool.
pub trait IndependentBroadcaster {
    /// Submit a raw transaction to all configured Esplora endpoints.
    /// Returns Ok if at least one endpoint accepted.
    fn broadcast<'a>(&'a self, raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>>;

    /// Whether the independent path has a usable quorum of endpoints.
    fn is_available(&self) -> bool;
}

/// LDK-facing broadcaster. Implements BroadcasterInterface synchronously
/// by enqueuing; actual network work happens in process_queue (called
/// from background_tick).
pub struct LijBroadcaster {
    queue: Arc<Mutex<VecDeque<PendingTx>>>,
    /// Build #4: slow ring for txs that exhausted fast attempts — retried
    /// every PARK_INTERVAL_ROUNDS drains until accepted, already-known, or
    /// provably conflicted. Never silently dropped.
    parked: Arc<Mutex<VecDeque<PendingTx>>>,
    /// Counts process_queue calls to pace the park ring.
    drain_rounds: std::sync::atomic::AtomicU64,
    cooperative: Mutex<Option<Arc<dyn CooperativeBroadcaster + Send + Sync>>>,
    independent: Mutex<Option<Arc<dyn IndependentBroadcaster + Send + Sync>>>,
    /// Set when a tx exhausts retries on both paths. UI checks this
    /// (via `take_failures`) to surface to the status panel.
    failures: Arc<Mutex<Vec<BroadcastFailure>>>,
    /// S45: newest-last ring of the last 16 transactions LDK handed us
    /// (txid hex, raw). The ChannelClosed handler finds the cooperative
    /// closing tx here by the funding input it spends.
    recent: Mutex<VecDeque<(String, Vec<u8>)>>,
}

/// A transaction that exhausted both paths. Surfaced to the user in the
/// chain-data status panel as a "problem" row.
#[derive(Clone, Debug)]
pub struct BroadcastFailure {
    pub txid_hex: String,
    pub attempts: u8,
    pub last_error: String,
}

impl LijBroadcaster {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            parked: Arc::new(Mutex::new(VecDeque::new())),
            drain_rounds: std::sync::atomic::AtomicU64::new(0),
            cooperative: Mutex::new(None),
            independent: Mutex::new(None),
            failures: Arc::new(Mutex::new(Vec::new())),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// S45: the most recent LDK-handed transaction spending `prev_txid:vout`
    /// (raw bytes), or None. Used to capture the cooperative closing tx.
    pub fn recent_spending(&self, prev_txid_hex: &str, vout: u32) -> Option<Vec<u8>> {
        let ring = self.recent.lock().unwrap();
        for (_txid, raw) in ring.iter().rev() {
            if let Ok(tx) = bitcoin::consensus::encode::deserialize::<Transaction>(raw) {
                if tx.input.iter().any(|i| {
                    i.previous_output.vout == vout && i.previous_output.txid.to_string() == prev_txid_hex
                }) {
                    return Some(raw.clone());
                }
            }
        }
        None
    }

    /// S45: re-enqueue a raw transaction the wallet already holds (a pending
    /// cooperative close the mempool dropped). No-op if already queued.
    pub fn enqueue_raw(&self, raw: Vec<u8>, txid_hex: String) {
        let mut q = self.queue.lock().unwrap();
        if q.iter().any(|p| p.txid_hex == txid_hex) {
            return;
        }
        q.push_back(PendingTx { raw, txid_hex, attempts: 0, last_error: None, conflict_strikes: 0 });
    }

    /// Wire the cooperative path. Called by node.rs once the LSP
    /// connection + BOLT 8 chain-data subscription is established (step 4).
    pub fn set_cooperative(
        &self,
        cooperative: Arc<dyn CooperativeBroadcaster + Send + Sync>,
    ) {
        *self.cooperative.lock().unwrap() = Some(cooperative);
    }

    /// Wire the independent path. Called by node.rs once Esplora-quorum
    /// client is constructed (step 5).
    pub fn set_independent(
        &self,
        independent: Arc<dyn IndependentBroadcaster + Send + Sync>,
    ) {
        *self.independent.lock().unwrap() = Some(independent);
    }

    /// Drain failures for surfacing to the UI. After return, failures
    /// list is cleared — caller is responsible for displaying them.
    pub fn take_failures(&self) -> Vec<BroadcastFailure> {
        std::mem::take(&mut *self.failures.lock().unwrap())
    }

    /// Non-draining read of the broadcast failures, for diagnostics. Unlike
    /// take_failures (which consumes), this clones so repeated diagnostic reads
    /// don't clear the list.
    pub fn peek_failures(&self) -> Vec<BroadcastFailure> {
        self.failures.lock().unwrap().clone()
    }

    /// Process one round of the broadcast queue. Called from
    /// background_tick. Tries cooperative first, then independent,
    /// re-enqueues with attempts++ on transient failure, surfaces to
    /// failures list when MAX_BROADCAST_ATTEMPTS is exceeded.
    pub async fn process_queue(&self) -> LijResult<()> {
        // Build #4: slow ring — one pass over parked txs every
        // PARK_INTERVAL_ROUNDS calls, before draining the fast queue.
        let round = self.drain_rounds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if round % PARK_INTERVAL_ROUNDS == 0 {
            self.process_parked().await;
        }
        loop {
            // Pop one tx (release lock before await)
            let mut pending = {
                let mut q = self.queue.lock().unwrap();
                match q.pop_front() {
                    Some(p) => p,
                    None => return Ok(()),
                }
            };

            log::info!(
                "broadcaster: processing {} (attempt {}/{})",
                pending.txid_hex,
                pending.attempts + 1,
                MAX_BROADCAST_ATTEMPTS
            );

            // Try cooperative path first
            let coop_result = {
                let coop_opt = self.cooperative.lock().unwrap().clone();
                match coop_opt {
                    Some(coop) if coop.is_available() => {
                        Some(coop.broadcast(&pending.raw).await)
                    }
                    Some(_) => {
                        log::debug!("broadcaster: cooperative present but unavailable");
                        None
                    }
                    None => {
                        log::debug!("broadcaster: cooperative not yet wired (step 4 pending)");
                        None
                    }
                }
            };

            if let Some(Ok(())) = &coop_result {
                log::info!("broadcaster: {} sent via cooperative", pending.txid_hex);
                continue;
            }
            if let Some(Err(e)) = &coop_result {
                log::warn!("broadcaster: cooperative failed for {}: {}", pending.txid_hex, e);
                pending.last_error = Some(format!("cooperative: {e}"));
            }

            // Fall to independent path
            let indep_result = {
                let indep_opt = self.independent.lock().unwrap().clone();
                match indep_opt {
                    Some(indep) if indep.is_available() => {
                        Some(indep.broadcast(&pending.raw).await)
                    }
                    Some(_) => {
                        log::debug!("broadcaster: independent present but no quorum available");
                        None
                    }
                    None => {
                        log::debug!("broadcaster: independent not yet wired (step 5 pending)");
                        None
                    }
                }
            };

            if let Some(Ok(())) = &indep_result {
                log::info!("broadcaster: {} sent via independent", pending.txid_hex);
                continue;
            }
            if let Some(Err(e)) = &indep_result {
                log::warn!("broadcaster: independent failed for {}: {}", pending.txid_hex, e);
                pending.last_error = Some(format!(
                    "{} | independent: {e}",
                    pending.last_error.as_deref().unwrap_or("")
                ));
            }

            // Build #4: an "already known / in mempool / in block" rejection
            // means the tx is out there — that IS success (and makes
            // rebroadcasts idempotent).
            if classify_err(pending.last_error.as_deref().unwrap_or(""))
                == ErrClass::AlreadyKnown
            {
                log::info!(
                    "broadcaster: {} already known to the network — done",
                    pending.txid_hex
                );
                continue;
            }

            // Neither path succeeded. Decide retry vs. hard-fail.
            pending.attempts += 1;
            if pending.attempts >= MAX_BROADCAST_ATTEMPTS {
                log::error!(
                    "broadcaster: HARD FAIL for {} after {} attempts: {}",
                    pending.txid_hex,
                    pending.attempts,
                    pending.last_error.as_deref().unwrap_or("(no detail)"),
                );
                self.failures.lock().unwrap().push(BroadcastFailure {
                    txid_hex: pending.txid_hex.clone(),
                    attempts: pending.attempts,
                    last_error: pending
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "no path available".into()),
                });
                // Build #4: never silently dropped — funds-critical txs move
                // to the slow ring and keep trying until seen or provably
                // conflicted.
                log::warn!("broadcaster: parking {} for slow retry", pending.txid_hex);
                self.parked.lock().unwrap().push_back(pending);
            } else {
                // Re-enqueue at the back for another tick
                self.queue.lock().unwrap().push_back(pending);
                // Stop draining for this round — give next tick a chance
                // for paths to come back online before retrying.
                return Ok(());
            }
        }
    }

    /// Build #4: one attempt per parked tx via a fresh path pass. Returns
    /// Ok on acceptance OR already-known; Err carries the combined message
    /// for classification.
    async fn try_paths_once(&self, raw: &[u8]) -> Result<(), String> {
        let coop_opt = self.cooperative.lock().unwrap().clone();
        let mut coop_msg: Option<String> = None;
        if let Some(coop) = coop_opt {
            if coop.is_available() {
                match coop.broadcast(raw).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = format!("cooperative: {e}");
                        if classify_err(&msg) == ErrClass::AlreadyKnown {
                            return Ok(());
                        }
                        coop_msg = Some(msg);
                    }
                }
            }
        }
        let indep_opt = self.independent.lock().unwrap().clone();
        if let Some(indep) = indep_opt {
            if indep.is_available() {
                return match indep.broadcast(raw).await {
                    Ok(()) => Ok(()),
                    Err(e) => Err(match coop_msg {
                        Some(m) => format!("{m} | independent: {e}"),
                        None => format!("independent: {e}"),
                    }),
                };
            }
        }
        Err(coop_msg.unwrap_or_else(|| "no path available".into()))
    }

    /// Build #4: slow-ring pass. Acceptance or already-known retires the tx;
    /// conflict-class strikes accumulate toward loud permanent retirement;
    /// transient errors keep it parked.
    async fn process_parked(&self) {
        let batch: Vec<PendingTx> = {
            let mut p = self.parked.lock().unwrap();
            p.drain(..).collect()
        };
        if batch.is_empty() {
            return;
        }
        log::info!("broadcaster: slow-ring pass over {} parked tx(s)", batch.len());
        for mut pending in batch {
            match self.try_paths_once(&pending.raw).await {
                Ok(()) => {
                    log::info!(
                        "broadcaster: parked {} accepted/known — retired",
                        pending.txid_hex
                    );
                }
                Err(msg) => {
                    let class = classify_err(&msg);
                    pending.last_error = Some(msg);
                    if class == ErrClass::Conflict {
                        pending.conflict_strikes += 1;
                        if pending.conflict_strikes >= MAX_CONFLICT_STRIKES {
                            log::error!(
                                "broadcaster: {} CONFLICTED after {} slow rounds — retiring permanently: {}",
                                pending.txid_hex,
                                pending.conflict_strikes,
                                pending.last_error.as_deref().unwrap_or("")
                            );
                            self.failures.lock().unwrap().push(BroadcastFailure {
                                txid_hex: pending.txid_hex.clone(),
                                attempts: pending.attempts,
                                last_error: format!(
                                    "CONFLICT (permanent): {}",
                                    pending.last_error.as_deref().unwrap_or("")
                                ),
                            });
                            continue;
                        }
                    }
                    self.parked.lock().unwrap().push_back(pending);
                }
            }
        }
    }

    /// Build #4: parked-ring depth, for diagnostics.
    pub fn parked_depth(&self) -> usize {
        self.parked.lock().unwrap().len()
    }

    /// How many txs are queued. Used by status panel.
    pub fn queue_depth(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

impl BroadcasterInterface for LijBroadcaster {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let mut q = self.queue.lock().unwrap();
        for tx in txs {
            let raw = serialize(*tx);
            let txid_hex = tx.txid().to_string();
            log::info!("broadcaster: enqueuing {} ({} bytes)", txid_hex, raw.len());
            {
                // S45: remember what LDK handed us (see `recent_spending`).
                let mut r = self.recent.lock().unwrap();
                r.push_back((txid_hex.clone(), raw.clone()));
                while r.len() > 16 {
                    r.pop_front();
                }
            }
            q.push_back(PendingTx {
                raw,
                txid_hex,
                attempts: 0,
                last_error: None,
                conflict_strikes: 0,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LijError;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct FlakeyCooperative {
        calls: AtomicU32,
        fail_count: u32,
    }

    impl CooperativeBroadcaster for FlakeyCooperative {
        fn broadcast<'a>(&'a self, _raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>> {
            Box::pin(async move {
                let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n <= self.fail_count {
                    Err(LijError::Lsp(format!("flake {n}")))
                } else {
                    Ok(())
                }
            })
        }
        fn is_available(&self) -> bool { true }
    }

    struct AlwaysSuccessIndependent;

    impl IndependentBroadcaster for AlwaysSuccessIndependent {
        fn broadcast<'a>(&'a self, _raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn is_available(&self) -> bool { true }
    }

    struct AlwaysFailIndependent;

    impl IndependentBroadcaster for AlwaysFailIndependent {
        fn broadcast<'a>(&'a self, _raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>> {
            Box::pin(async move { Err(LijError::Storage("indep fail".into())) })
        }
        fn is_available(&self) -> bool { true }
    }

    fn dummy_tx_bytes() -> Vec<u8> {
        // 1-byte version, 0 inputs, 0 outputs, locktime — minimal valid tx skeleton
        // for testing serialize/queue plumbing without needing a real tx
        vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    #[tokio::test]
    async fn no_paths_wired_does_not_crash() {
        let bc = LijBroadcaster::new();
        // No cooperative, no independent — should retry then hard-fail
        bc.queue.lock().unwrap().push_back(PendingTx {
            raw: dummy_tx_bytes(),
            txid_hex: "deadbeef".into(),
            attempts: 0,
            last_error: None,
            conflict_strikes: 0,
        });
        // Will retry MAX_BROADCAST_ATTEMPTS times across multiple process_queue calls
        for _ in 0..MAX_BROADCAST_ATTEMPTS {
            bc.process_queue().await.unwrap();
        }
        let failures = bc.take_failures();
        assert_eq!(failures.len(), 1, "expected one hard-fail");
        assert_eq!(failures[0].txid_hex, "deadbeef");
    }

    #[tokio::test]
    async fn cooperative_succeeds_independent_not_called() {
        let bc = LijBroadcaster::new();
        bc.set_cooperative(Arc::new(FlakeyCooperative {
            calls: AtomicU32::new(0),
            fail_count: 0, // never fails
        }));
        bc.set_independent(Arc::new(AlwaysFailIndependent));
        bc.queue.lock().unwrap().push_back(PendingTx {
            raw: dummy_tx_bytes(),
            txid_hex: "abc123".into(),
            attempts: 0,
            last_error: None,
            conflict_strikes: 0,
        });
        bc.process_queue().await.unwrap();
        assert_eq!(bc.queue_depth(), 0);
        assert_eq!(bc.take_failures().len(), 0);
    }

    #[tokio::test]
    async fn cooperative_fails_independent_succeeds() {
        let bc = LijBroadcaster::new();
        bc.set_cooperative(Arc::new(FlakeyCooperative {
            calls: AtomicU32::new(0),
            fail_count: 999, // always fails
        }));
        bc.set_independent(Arc::new(AlwaysSuccessIndependent));
        bc.queue.lock().unwrap().push_back(PendingTx {
            raw: dummy_tx_bytes(),
            txid_hex: "fallback_test".into(),
            attempts: 0,
            last_error: None,
            conflict_strikes: 0,
        });
        bc.process_queue().await.unwrap();
        assert_eq!(bc.queue_depth(), 0);
        assert_eq!(bc.take_failures().len(), 0);
    }

    #[tokio::test]
    async fn both_paths_fail_eventually_hard_fails() {
        let bc = LijBroadcaster::new();
        bc.set_cooperative(Arc::new(FlakeyCooperative {
            calls: AtomicU32::new(0),
            fail_count: 999,
        }));
        bc.set_independent(Arc::new(AlwaysFailIndependent));
        bc.queue.lock().unwrap().push_back(PendingTx {
            raw: dummy_tx_bytes(),
            txid_hex: "doomed".into(),
            attempts: 0,
            last_error: None,
            conflict_strikes: 0,
        });
        for _ in 0..MAX_BROADCAST_ATTEMPTS {
            bc.process_queue().await.unwrap();
        }
        let failures = bc.take_failures();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].last_error.contains("cooperative"));
        assert!(failures[0].last_error.contains("independent"));
    }

    #[tokio::test]
    async fn enqueue_via_ldk_interface_works() {
        let bc = LijBroadcaster::new();
        // We can't easily build a real bitcoin::Transaction in this test
        // without bringing in a lot of fixtures. The enqueue path is exercised
        // by the other tests via direct queue push. This test verifies the
        // BroadcasterInterface impl exists and queue starts empty.
        assert_eq!(bc.queue_depth(), 0);
    }
}
