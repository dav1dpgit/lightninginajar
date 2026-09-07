//! OutputSweeper support: LDK trait adapters for LiJ's storage and signer.
//!
//! This module provides the adapter types needed to instantiate
//! [`lightning::util::sweep::OutputSweeper`] with LiJ's existing infrastructure:
//!
//!   - [`LijKVStore`] wraps `Arc<dyn LijStorage>` and exposes LDK's [`KVStore`]
//!     trait with a `lij:sweeper:` namespace prefix. LDK's three-level
//!     `(primary_namespace, secondary_namespace, key)` model is flattened onto
//!     LiJ's `get / set / delete / list_with_prefix` storage interface.
//!
//!   - [`LijChangeDestinationSource`] wraps `Arc<LijSignerProvider>` and returns
//!     a fresh `m/84'/0'/0'/0/n` P2WPKH destination script each call. It
//!     delegates to `<LijSignerProvider as SignerProvider>::get_destination_script`,
//!     which already implements the right pattern (increment persistent
//!     counter, derive at new index, return script) and ignores its
//!     `channel_keys_id` parameter — so a dummy `[0u8; 32]` is fine.
//!
//!   - [`UnusedFilter`] is a no-op [`Filter`] implementation. OutputSweeper's
//!     `chain_data_source` parameter is `Option<F>` where `F: Deref` with
//!     `F::Target: Filter + Sync + Send`. LiJ does not register OutputSweeper
//!     outputs via LDK's Filter interface — chain data flows in through LiJ's
//!     own bridge, which will call `transactions_confirmed` /
//!     `best_block_updated` on the sweeper directly. We still need a concrete
//!     `F` type for the `OutputSweeper<...>` type parameters to be well-formed,
//!     so we provide a stub whose methods never run.
//!
//!   - [`LijOutputSweeper`] is the type alias binding all seven generic
//!     parameters together so callers in `node.rs` and elsewhere don't have
//!     to spell out the full form.
//!
//! ## What this file does NOT do (yet)
//!
//! No wiring into [`crate::node::LijNode`] — that's the next step. This file
//! is pure type/trait scaffolding: it adds adapters that satisfy LDK's
//! generic bounds, but does not construct an OutputSweeper instance, hook
//! `Event::SpendableOutputs`, or call `chain_monitor.process_pending_events`.
//! Those steps land in subsequent commits.

use std::io;
use std::sync::Arc;

use bitcoin::{Network, ScriptBuf, Txid, Script};

use lightning::chain::{BestBlock, Filter, WatchedOutput};
use lightning::sign::{ChangeDestinationSource, KeysManager};
use lightning::util::persist::{
    KVStore,
    OUTPUT_SWEEPER_PERSISTENCE_KEY,
    OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
    OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::ReadableArgs;

use crate::broadcaster::LijBroadcaster;
use crate::error::{LijError, LijResult};
use crate::fee_estimator::LijFeeEstimator;
use crate::node::DynLogger;
use crate::signer::LijSignerProvider;
use crate::storage::LijStorage;

/// Top-level prefix under which all OutputSweeper KV state is stored in
/// [`LijStorage`]. Full key format:
///   `lij:sweeper:{primary_namespace}:{secondary_namespace}:{key}`
///
/// Both `primary_namespace` and `secondary_namespace` may be the empty string;
/// LDK's `KVStore` contract permits empty namespaces, and the resulting keys
/// like `lij:sweeper:::foo` are still unique under our prefix.
pub const SWEEPER_KEY_PREFIX: &str = "lij:sweeper";

// ─── LijKVStore ─────────────────────────────────────────────────────────────

/// Adapter from LDK's [`KVStore`] trait onto [`LijStorage`].
pub struct LijKVStore {
    inner: Arc<dyn LijStorage>,
}

impl LijKVStore {
    pub fn new(inner: Arc<dyn LijStorage>) -> Self {
        Self { inner }
    }

    fn full_key(primary: &str, secondary: &str, key: &str) -> String {
        format!("{SWEEPER_KEY_PREFIX}:{primary}:{secondary}:{key}")
    }

    /// Prefix used by `list` to enumerate keys under a `(primary, secondary)`
    /// namespace. The trailing colon prevents accidental matches between
    /// secondary namespaces that share a textual prefix (e.g. `"foo"` would
    /// otherwise also match `"foobar"`).
    fn list_prefix(primary: &str, secondary: &str) -> String {
        format!("{SWEEPER_KEY_PREFIX}:{primary}:{secondary}:")
    }
}

impl KVStore for LijKVStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        let full = Self::full_key(primary_namespace, secondary_namespace, key);
        match self.inner.get(&full) {
            Ok(Some(bytes)) => Ok(bytes),
            // LDK contract: NotFound is the signal that a key doesn't exist.
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("LijKVStore: key not found: {full}"),
            )),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("LijKVStore::read: LijStorage::get failed: {e}"),
            )),
        }
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: &[u8],
    ) -> Result<(), io::Error> {
        let full = Self::full_key(primary_namespace, secondary_namespace, key);
        self.inner.set(&full, buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("LijKVStore::write: LijStorage::set failed: {e}"),
            )
        })
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        _lazy: bool,
    ) -> Result<(), io::Error> {
        // LijStorage has no lazy-delete path; we always remove synchronously.
        // LDK's `_lazy` parameter is honored as a hint only — semantics
        // require that subsequent `list` calls reflect the removal, which
        // synchronous delete also satisfies.
        let full = Self::full_key(primary_namespace, secondary_namespace, key);
        self.inner.delete(&full).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("LijKVStore::remove: LijStorage::delete failed: {e}"),
            )
        })
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        let prefix = Self::list_prefix(primary_namespace, secondary_namespace);
        match self.inner.list_with_prefix(&prefix) {
            Ok(keys) => Ok(keys
                .into_iter()
                .filter_map(|k| k.strip_prefix(&prefix).map(|s| s.to_string()))
                .collect()),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("LijKVStore::list: LijStorage::list_with_prefix failed: {e}"),
            )),
        }
    }
}

// ─── LijChangeDestinationSource ─────────────────────────────────────────────

/// Returns a fresh `m/84'/0'/0'/0/n` P2WPKH destination script each call,
/// where `n` is the next value from the persistent counter inside
/// [`LijSignerProvider`].
///
/// Funds swept via [`lightning::util::sweep::OutputSweeper`] land at these
/// addresses. BlueWallet (BIP84-default) and any other BIP84-discovering
/// wallet with the same seed will pick them up automatically on the receive
/// chain at gap-limit depth.
pub struct LijChangeDestinationSource {
    signer_provider: Arc<LijSignerProvider>,
}

impl LijChangeDestinationSource {
    pub fn new(signer_provider: Arc<LijSignerProvider>) -> Self {
        Self { signer_provider }
    }
}

impl ChangeDestinationSource for LijChangeDestinationSource {
    fn get_change_destination_script(&self) -> Result<ScriptBuf, ()> {
        // v185 (Session 27): route through the signer's memoized sweep
        // destination. The OutputSweeper calls this on EVERY per-block
        // regeneration of a pending sweep; the old fresh-index-per-call
        // path burned one m/84 index per block per pending sweep (the
        // dominant cause of the BlueWallet gap blowout) and pointed each
        // rebroadcast at a different address. One pinned destination per
        // epoch: RBF-coherent, one address exposed to mempool observers
        // instead of N, zero on-chain difference. Released by the node
        // tick once nothing can rebroadcast.
        self.signer_provider.sweep_destination_script().map_err(|_| ())
    }
}

// ─── UnusedFilter ───────────────────────────────────────────────────────────

/// No-op [`Filter`] implementation used only to satisfy [`OutputSweeper`]'s
/// generic type parameters. LiJ delivers chain data via its own bridge,
/// calling `transactions_confirmed` / `best_block_updated` on the sweeper
/// directly, so this filter's methods are never invoked at runtime.
///
/// Instances are constructed but never registered. We pass `None` for
/// OutputSweeper's `chain_data_source: Option<F>` parameter; the `F` type
/// in [`LijOutputSweeper`] must still be a concrete type that satisfies the
/// trait bounds.
pub struct UnusedFilter;

impl UnusedFilter {
    pub fn new() -> Self { Self }
}

impl Default for UnusedFilter {
    fn default() -> Self { Self::new() }
}

impl Filter for UnusedFilter {
    fn register_tx(&self, _txid: &Txid, _script_pubkey: &Script) {}
    fn register_output(&self, _output: WatchedOutput) {}
}

// ─── LijOutputSweeper ───────────────────────────────────────────────────────

/// Type alias for [`lightning::util::sweep::OutputSweeper`] bound to LiJ's
/// concrete trait implementations.
///
/// Generic parameter mapping (in OutputSweeper-declaration order):
///   - `B` = `Arc<LijBroadcaster>`              → BroadcasterInterface
///   - `D` = `Arc<LijChangeDestinationSource>`  → ChangeDestinationSource (m/84)
///   - `E` = `Arc<LijFeeEstimator>`             → FeeEstimator
///   - `F` = `Arc<UnusedFilter>`                → Filter (None at runtime)
///   - `K` = `Arc<LijKVStore>`                  → KVStore (over LijStorage)
///   - `L` = `DynLogger`                        → Logger (already Arc<dyn Logger>)
///   - `O` = `Arc<KeysManager>`                 → OutputSpender (KeysManager
///                                                 impls OutputSpender natively;
///                                                 used for sweep-tx signing)
///
/// Note on `O`: post Plan A (drop m/525 override on new channels), KeysManager's
/// default HKDF-derived static_remote_key matches what the OutputSpender impl
/// expects when signing for SpendableOutputDescriptor::StaticPaymentOutput.
/// Legacy m/525-override channels predate this and are recovered via separate
/// manual tools (see RECOVERY.md Part 5).
///
/// DEPRECATED (2026-06-15, per DP): the m/525-override method and its separate
/// manual recovery tools are deprecated and slated for deletion. The ONLY m/525
/// path that remains is the force-close static_remote destination, from which the
/// sweeper moves everything to m/84. The "legacy m/525-override channel" framing
/// above no longer applies to current channels — do not use it to explain stuck
/// sweeps. TODO: delete the override branches + manual-tool references.
pub type LijOutputSweeper = lightning::util::sweep::OutputSweeper<
    Arc<LijBroadcaster>,
    Arc<LijChangeDestinationSource>,
    Arc<LijFeeEstimator>,
    Arc<UnusedFilter>,
    Arc<LijKVStore>,
    DynLogger,
    Arc<KeysManager>,
>;

// ─── build_output_sweeper ───────────────────────────────────────────────────

/// Construct a [`LijOutputSweeper`], restoring from persisted [`LijKVStore`]
/// state if present, otherwise initializing fresh against
/// [`BestBlock::from_network`].
///
/// All construction logic lives in this single helper so the two LijNode
/// init paths (`restore()` and `init_channel_manager()`) share identical
/// behavior. The helper:
///
///   1. Checks the OutputSweeper's reserved persistence key in KVStore.
///   2. If present: deserializes via [`ReadableArgs`]; `best_block` is read
///      from the persisted blob.
///   3. If absent (NotFound): fresh init against [`BestBlock::from_network`].
///
/// On read errors *other than NotFound*, the helper returns
/// [`LijError::Storage`] rather than silently falling back to fresh init.
/// Silent fallback would lose any in-flight sweep state, including outputs
/// already being swept. Force user intervention instead.
pub fn build_output_sweeper(
    storage: Arc<dyn LijStorage>,
    broadcaster: Arc<LijBroadcaster>,
    fee_estimator: Arc<LijFeeEstimator>,
    keys_manager: Arc<KeysManager>,
    signer_provider: Arc<LijSignerProvider>,
    logger: DynLogger,
    network: Network,
) -> LijResult<Arc<LijOutputSweeper>> {
    let kv_store: Arc<LijKVStore> = Arc::new(LijKVStore::new(storage));
    let change_destination_source: Arc<LijChangeDestinationSource> =
        Arc::new(LijChangeDestinationSource::new(signer_provider));

    // Probe the persisted state. NotFound is the expected case on first run.
    let persisted: Option<Vec<u8>> = match kv_store.read(
        OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
        OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
        OUTPUT_SWEEPER_PERSISTENCE_KEY,
    ) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(LijError::Storage(format!(
                "OutputSweeper KVStore read failed (not NotFound): {e}"
            )));
        }
    };

    let sweeper: LijOutputSweeper = match persisted {
        Some(bytes) => {
            // Restore. best_block lives inside the blob (ReadableArgs reads it).
            log::info!(
                "OutputSweeper: restoring from {}-byte persisted state",
                bytes.len()
            );
            let mut cursor = io::Cursor::new(&bytes);
            let args = (
                broadcaster,
                fee_estimator,
                None::<Arc<UnusedFilter>>,
                keys_manager,
                change_destination_source,
                kv_store,
                logger,
            );
            <LijOutputSweeper as ReadableArgs<_>>::read(&mut cursor, args).map_err(|e| {
                LijError::Storage(format!(
                    "OutputSweeper restore deserialization failed: {e:?}. \
                     If you have in-flight sweeps, do NOT overwrite this state.",
                ))
            })?
        }
        None => {
            log::info!(
                "OutputSweeper: no persisted state, initializing fresh against {network:?} genesis"
            );
            let best_block = BestBlock::from_network(network);
            LijOutputSweeper::new(
                best_block,
                broadcaster,
                fee_estimator,
                None,
                keys_manager,
                change_destination_source,
                kv_store,
                logger,
            )
        }
    };

    Ok(Arc::new(sweeper))
}
