// persisted_counter.rs
// Persistent monotonic counter for channel indexing.
//
// Used by LijSignerProvider to allocate distinct BIP32 child indices for
// each channel's shutdown_script and on-chain destination scripts. The
// counter MUST be persistent across wallet restarts — a regression to a
// prior counter value would cause address reuse on the cooperative-close
// destination chain (m/84h/0h/0h/0/n) which fingerprints multiple channels
// to the same on-chain output.
//
// Semantics:
//   - read_and_increment() atomically reads the current value, writes
//     value+1 to storage, returns the value that was just read.
//   - The write to storage happens BEFORE the value is returned. If the
//     write fails, an error propagates and the caller MUST abort the
//     channel-open path. Never burn an in-memory increment that wasn't
//     persisted.
//   - In-process synchronization via Mutex prevents two concurrent
//     read_and_increment() calls from racing.
//
// Burned indices:
//   If a channel-open fails after the counter increment (LSP refuses,
//   network drops), the allocated index is "burned" — never used in a
//   real channel. Burned indices leave gaps — acceptable per the Phase 4
//   design doc. CORRECTED (S26, from DP's live test): third-party
//   gap-limit scans do NOT reliably reach these indices (a real coop
//   close landed past BlueWallet's default gap); seed-only recovery in a
//   third-party wallet needs its gap limit raised to >=500. LiJ itself
//   derives from this persisted counter and always sees everything.

use std::sync::{Arc, Mutex};

use crate::{
    error::{LijError, LijResult},
    storage::LijStorage,
};

/// localStorage key for the channel-index counter.
/// Matches the existing key naming convention in storage.rs.
pub const KEY_NEXT_CHANNEL_INDEX: &str = "lij_next_channel_index";

/// localStorage key for the upward ratchet — the highest value the counter
/// has ever reached. Updated alongside the counter on every increment.
/// On startup, refusal to issue indices if counter < ratchet (guards against
/// counter regression after a partial restore or storage corruption).
pub const KEY_COUNTER_UPWARD_RATCHET: &str = "lij_counter_upward_ratchet";

/// A persistent monotonic counter backed by LijStorage.
/// Cloneable across LDK callsites via the inner Arc<Mutex<...>>.
#[derive(Clone)]
pub struct PersistedCounter {
    storage: Arc<dyn LijStorage>,
    key: String,
    /// Storage key for the upward ratchet. Updated alongside the counter
    /// on every increment. Never decreases. On reconstruction, refuses to
    /// build if storage shows counter < ratchet.
    ratchet_key: String,
    /// In-memory cache of the next-to-issue value. Invariant: matches
    /// what's persisted. Reads from storage on construction; writes to
    /// storage before each handout.
    state: Arc<Mutex<u32>>,
}

impl PersistedCounter {
    /// Construct from storage. Reads the current value (or 0 if absent),
    /// caches in memory, returns ready to issue indices.
    ///
    /// The first call to read_and_increment() will return whatever value
    /// is currently in storage (or 0 if storage was empty), then advance
    /// storage to that value + 1.
    ///
    /// Errors if storage shows counter < upward_ratchet (regression guard).
    pub fn new(storage: Arc<dyn LijStorage>) -> LijResult<Self> {
        Self::new_with_keys(
            storage,
            KEY_NEXT_CHANNEL_INDEX.to_string(),
            KEY_COUNTER_UPWARD_RATCHET.to_string(),
        )
    }

    /// Variant with a custom storage key. Used in tests.
    pub fn new_with_key(storage: Arc<dyn LijStorage>, key: String) -> LijResult<Self> {
        let ratchet_key = format!("{}__upward_ratchet", key);
        Self::new_with_keys(storage, key, ratchet_key)
    }

    /// Variant with separate counter and ratchet keys. Used internally and
    /// by tests that need to verify ratchet semantics directly.
    pub fn new_with_keys(
        storage: Arc<dyn LijStorage>,
        key: String,
        ratchet_key: String,
    ) -> LijResult<Self> {
        let current = match storage.get(&key)? {
            Some(bytes) => parse_u32(&bytes)?,
            None => 0u32,
        };
        let ratchet = match storage.get(&ratchet_key)? {
            Some(bytes) => parse_u32(&bytes)?,
            None => 0u32,
        };
        // Guard: counter must never be less than ratchet. If it is,
        // storage state is inconsistent (regression after fresh-device
        // restore, manual storage edit, etc.) — refuse to construct.
        if current < ratchet {
            return Err(LijError::Storage(format!(
                "Counter regression detected: counter={} ratchet={}.                  Refusing to issue indices to prevent address reuse.",
                current, ratchet
            )));
        }
        Ok(Self {
            storage,
            key,
            ratchet_key,
            state: Arc::new(Mutex::new(current)),
        })
    }

    /// Atomically read the current counter value, persist value+1 to
    /// storage along with the upward ratchet, return the value that was
    /// read.
    ///
    /// If either storage write fails, the in-memory state is NOT advanced
    /// and an error is returned. The caller MUST treat this as a fatal
    /// error and abort whatever operation requested an index.
    pub fn read_and_increment(&self) -> LijResult<u32> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| LijError::Storage(format!("Counter mutex poisoned: {e}")))?;
        let issued = *state;
        let next = issued
            .checked_add(1)
            .ok_or_else(|| LijError::Storage("Channel index counter overflow".into()))?;
        // Write counter BEFORE ratchet. Both before returning. If counter
        // write succeeds but ratchet write fails, we have a state where
        // counter > ratchet — ratchet repair on next startup will catch it.
        self.storage.set(&self.key, &next.to_be_bytes())?;
        self.storage.set(&self.ratchet_key, &next.to_be_bytes())?;
        *state = next;
        Ok(issued)
    }

    /// Raise the counter floor to `n` (Option B allocator unification,
    /// Session 23): the on-chain RECEIVE index and the signer's channel
    /// indices mint on the SAME m/84 chain-0 path. When the frontend
    /// shows or advances a receive index, it reserves that territory
    /// here so the signer can never issue an index at or below it.
    ///
    /// Semantics mirror read_and_increment: persist BEFORE the in-memory
    /// update, counter then ratchet, both raised together (invariant
    /// counter >= ratchet preserved; a counter-write-then-ratchet-fail
    /// leaves counter > ratchet, which startup repair already tolerates).
    /// MUST be called on the LIVE instance — a storage-direct write while
    /// a node runs would desync the in-memory cache and trip the ratchet
    /// regression guard on the next restart.
    ///
    /// No-op when n <= current (floors never lower). Skipped indices are
    /// ordinary burned indices per the header comment.
    pub fn raise_floor(&self, n: u32) -> LijResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| LijError::Storage(format!("Counter mutex poisoned: {e}")))?;
        if n <= *state {
            return Ok(());
        }
        self.storage.set(&self.key, &n.to_be_bytes())?;
        self.storage.set(&self.ratchet_key, &n.to_be_bytes())?;
        *state = n;
        Ok(())
    }

    /// Read the current upward ratchet value without advancing.
    /// For health checks and diagnostics only.
    pub fn peek_ratchet(&self) -> LijResult<u32> {
        match self.storage.get(&self.ratchet_key)? {
            Some(bytes) => parse_u32(&bytes),
            None => Ok(0u32),
        }
    }

    /// Read the current next-to-issue value without advancing.
    /// For inspection only — never use this to allocate an index.
    pub fn peek(&self) -> LijResult<u32> {
        let state = self
            .state
            .lock()
            .map_err(|e| LijError::Storage(format!("Counter mutex poisoned: {e}")))?;
        Ok(*state)
    }
}

/// Read the persisted next-to-issue counter value directly from storage,
/// without constructing a PersistedCounter (read-only; no ratchet guard).
/// Returns 0 when absent or unparseable — callers use this to WIDEN the
/// Tier-2 scan window, so a conservative 0 merely falls back to the
/// view-derived frontier; it can never shrink coverage below it.
pub fn peek_persisted(storage: &dyn LijStorage) -> u32 {
    match storage.get(KEY_NEXT_CHANNEL_INDEX) {
        Ok(Some(bytes)) => parse_u32(&bytes).unwrap_or_else(|e| {
            log::warn!("peek_persisted: counter unparseable ({e}); using 0 for scan-window purposes");
            0
        }),
        _ => 0,
    }
}

fn parse_u32(bytes: &[u8]) -> LijResult<u32> {
    if bytes.len() != 4 {
        return Err(LijError::Storage(format!(
            "Counter value has wrong length: expected 4 bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    use crate::storage::native_storage::MemoryStorage;

    #[cfg(not(target_arch = "wasm32"))]
    fn test_storage() -> Arc<dyn LijStorage> {
        Arc::new(MemoryStorage::new())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fresh_counter_starts_at_zero() {
        let storage = test_storage();
        let counter = PersistedCounter::new(storage).unwrap();
        assert_eq!(counter.peek().unwrap(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn read_and_increment_returns_then_advances() {
        let storage = test_storage();
        let counter = PersistedCounter::new(storage).unwrap();
        assert_eq!(counter.read_and_increment().unwrap(), 0);
        assert_eq!(counter.read_and_increment().unwrap(), 1);
        assert_eq!(counter.read_and_increment().unwrap(), 2);
        assert_eq!(counter.peek().unwrap(), 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn counter_persists_across_reconstruction() {
        let storage = test_storage();
        // First counter: issue 0, 1, 2 — leaves storage at 3
        {
            let counter = PersistedCounter::new(storage.clone()).unwrap();
            counter.read_and_increment().unwrap();
            counter.read_and_increment().unwrap();
            counter.read_and_increment().unwrap();
        }
        // Reconstruct — should resume at 3, not 0
        let counter2 = PersistedCounter::new(storage).unwrap();
        assert_eq!(counter2.peek().unwrap(), 3);
        assert_eq!(counter2.read_and_increment().unwrap(), 3);
        assert_eq!(counter2.read_and_increment().unwrap(), 4);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn corrupted_counter_value_returns_error() {
        let storage = test_storage();
        // Write garbage of wrong length
        storage.set(KEY_NEXT_CHANNEL_INDEX, &[0xde, 0xad]).unwrap();
        let result = PersistedCounter::new(storage);
        assert!(result.is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn clone_shares_state() {
        let storage = test_storage();
        let counter1 = PersistedCounter::new(storage).unwrap();
        let counter2 = counter1.clone();
        // Increment via clone — original sees it
        assert_eq!(counter2.read_and_increment().unwrap(), 0);
        assert_eq!(counter1.peek().unwrap(), 1);
        assert_eq!(counter1.read_and_increment().unwrap(), 1);
        assert_eq!(counter2.peek().unwrap(), 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ratchet_advances_with_counter() {
        let storage = test_storage();
        let counter = PersistedCounter::new(storage).unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 0);
        counter.read_and_increment().unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 1);
        counter.read_and_increment().unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 2);
        counter.read_and_increment().unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn counter_regression_below_ratchet_returns_error() {
        let storage = test_storage();
        // Bring storage to counter=5, ratchet=5 via normal increments
        {
            let counter = PersistedCounter::new(storage.clone()).unwrap();
            for _ in 0..5 {
                counter.read_and_increment().unwrap();
            }
        }
        // Verify ratchet sees 5
        let ratchet_bytes = storage.get(KEY_COUNTER_UPWARD_RATCHET).unwrap().unwrap();
        assert_eq!(u32::from_be_bytes([
            ratchet_bytes[0], ratchet_bytes[1], ratchet_bytes[2], ratchet_bytes[3]
        ]), 5);

        // Manually corrupt counter back to 2 — simulating regression
        // (e.g. partial restore from old backup, manual storage edit)
        storage.set(KEY_NEXT_CHANNEL_INDEX, &2u32.to_be_bytes()).unwrap();

        // Reconstruction must refuse
        let err = match PersistedCounter::new(storage) {
            Err(e) => e,
            Ok(_) => panic!("Counter < ratchet must be rejected"),
        };
        let err_msg = format!("{:?}", err);
        assert!(err_msg.contains("regression") || err_msg.contains("Refusing"),
            "Error message should explain regression: {}", err_msg);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn peek_ratchet_returns_current_value() {
        let storage = test_storage();
        let counter = PersistedCounter::new(storage).unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 0);
        counter.read_and_increment().unwrap();
        counter.read_and_increment().unwrap();
        assert_eq!(counter.peek_ratchet().unwrap(), 2);
        // peek_ratchet does not advance
        assert_eq!(counter.peek_ratchet().unwrap(), 2);
    }
}
