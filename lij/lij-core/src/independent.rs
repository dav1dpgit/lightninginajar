// independent.rs
//
// Step 5 — Esplora-quorum independent path.
// Fills the IndependentBroadcaster and IndependentFeeSource trait stubs
// from steps 1 and 2.
//
// Architecture (per Phase4_chain_data_trust_model_v1.md §5):
//   - Default 4 endpoints, user-configurable up to 7.
//   - Endpoints: LIJOX-served + Blockstream + mempool.space + TBD.
//     Organizationally diverse; user can add their own (their own
//     Umbrel's Esplora, etc.) and remove any default.
//   - Agreement rules:
//       * Strict equality for chain-state queries (height, txid presence)
//       * 25% tolerance for fee estimates
//   - Disagreement ladder:
//       * Slight (one dissenter, majority intact) → demote dissenter, log
//       * Even split or no quorum → re-query with backoff, then prompt user
//       * Total disagreement (all different) → hard-stop, surface anomaly
//   - Endpoint health: down after 3 attempts × 5s timeouts each.
//     Reinstated after 1 successful response.
//   - Broadcast quorum is "any-of": submit to all, success if any accepts.
//
// HTTP abstraction:
//   The EsploraHttp trait abstracts the actual network call. Production
//   code injects a real implementation (WASM fetch in lij-wasm, reqwest
//   in native). Tests inject mock implementations to exercise quorum
//   logic without touching the network. Real implementation lands with
//   step 8 send/receive.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bitcoin::BlockHash;
use serde::Deserialize;

use crate::broadcaster::IndependentBroadcaster;
use crate::error::{LijError, LijResult};

/// v208: broadcast routing mode. false = submit to ALL healthy endpoints
/// (default, most reliable); true = one-at-a-time with rotation, stopping at
/// the first acceptance. Set from the page via the wasm export.
pub static BROADCAST_ONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
use crate::fee_estimator::{FeeQuote, IndependentFeeSource};

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

// Step 3.6 (F6): WASM-safe Unix epoch milliseconds. Used by query_all to
// time individual endpoint requests for the rolling latency window.
fn current_time_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    { js_sys::Date::now() as u64 }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }
}

// ── Constants ───────────────────────────────────────────────────────────────

/// Per-endpoint request timeout. Endpoint considered failed if the response
/// hasn't arrived within this window.
pub const REQUEST_TIMEOUT_SECS: u64 = 5;

/// Number of consecutive failures before an endpoint is demoted to "down".
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Default endpoint count when not user-configured.
///
/// Reflects the current shipped default in `default_endpoints()` — 4 since
/// May 2026 when zeusln.com and electrs.getalbypro.com lost CORS support
/// and were dropped from the rotation. Restore to 5 once the LIJOX reference
/// instance fills the 5th slot. Keep this in sync with `default_endpoints()`
/// — the `default_endpoints_matches_quorum_size` test asserts the invariant.
pub const DEFAULT_QUORUM_SIZE: usize = 4;

/// Maximum quorum size the user can configure.
pub const MAX_QUORUM_SIZE: usize = 7;

/// Tolerance window for fee disagreement (per §7b).
pub const FEE_TOLERANCE_PCT: u32 = 25;

/// Step 3.6 (F6): rolling-window size for per-endpoint latency samples.
/// Median of these is surfaced through endpoint_status() for Card 4.
pub const LATENCY_SAMPLE_COUNT: usize = 8;

// ── HTTP abstraction ────────────────────────────────────────────────────────
// Real implementation in step 8 (lij-wasm). Tests provide mocks.

/// HTTP response from an Esplora endpoint.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// HTTP backend abstraction. Production: WASM fetch. Tests: mock.
/// A UTXO returned by an Esplora `/address/{addr}/utxo` query.
/// Public fields used by onchain_scan to construct ResidueUtxo records.
#[derive(Clone, Debug)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// True once the creating tx is in a block; false while still in the mempool.
    /// Esplora's /address/{addr}/utxo carries this per entry in a `status` block.
    pub confirmed: bool,
}

#[derive(serde::Deserialize)]
struct EsploraUtxoRaw {
    txid: String,
    vout: u32,
    value: u64,
    status: EsploraTxStatus,
}

impl From<EsploraUtxoRaw> for EsploraUtxo {
    fn from(raw: EsploraUtxoRaw) -> Self {
        Self {
            txid: raw.txid,
            vout: raw.vout,
            value_sats: raw.value,
            confirmed: raw.status.confirmed,
        }
    }
}

/// One entry from an Esplora `/tx/{txid}/outspends` response.
/// Indicates whether output[i] of the tx has been spent.
#[derive(Clone, Debug)]
pub struct EsploraOutspend {
    pub spent: bool,
    pub txid: Option<String>,
    pub vin: Option<u32>,
    /// Confirmation status of the spending tx (Some only when spent and
    /// the response carried a status block — typically present once the
    /// spending tx is on-chain; None when spent-in-mempool or unspent).
    pub status: Option<EsploraTxStatus>,
}

#[derive(serde::Deserialize)]
struct EsploraOutspendRaw {
    spent: bool,
    txid: Option<String>,
    vin: Option<u32>,
    status: Option<EsploraTxStatus>,
}

impl From<EsploraOutspendRaw> for EsploraOutspend {
    fn from(raw: EsploraOutspendRaw) -> Self {
        Self {
            spent: raw.spent,
            txid: raw.txid,
            vin: raw.vin,
            status: raw.status,
        }
    }
}

/// A transaction returned by an Esplora `/tx/{txid}` query.
/// Only the fields needed by closed_channel_watcher are extracted.
#[derive(Clone, Debug)]
pub struct EsploraTx {
    pub txid: String,
    pub vouts: Vec<EsploraTxVout>,
}

#[derive(Clone, Debug)]
pub struct EsploraTxVout {
    pub scriptpubkey: String,
    pub value: u64,
}

#[derive(serde::Deserialize)]
struct EsploraTxRaw {
    txid: String,
    vout: Vec<EsploraTxVoutRaw>,
}

#[derive(serde::Deserialize)]
struct EsploraTxVoutRaw {
    scriptpubkey: String,
    value: u64,
}

impl From<EsploraTxRaw> for EsploraTx {
    fn from(raw: EsploraTxRaw) -> Self {
        Self {
            txid: raw.txid,
            vouts: raw
                .vout
                .into_iter()
                .map(|v| EsploraTxVout {
                    scriptpubkey: v.scriptpubkey,
                    value: v.value,
                })
                .collect(),
        }
    }
}

pub trait EsploraHttp: Send + Sync {
    /// GET request. Implementation enforces REQUEST_TIMEOUT_SECS.
    fn get<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, LijResult<HttpResponse>>;

    /// POST request with raw body (for tx broadcast).
    fn post<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        content_type: &'a str,
    ) -> LocalBoxFuture<'a, LijResult<HttpResponse>>;
}

// ── Endpoint health tracking ────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct EndpointHealth {
    /// Base URL, e.g. "https://blockstream.info/api"
    url: String,
    /// Consecutive failures since last success. Resets on any successful response.
    consecutive_failures: u32,
    /// Whether the endpoint is currently considered usable for queries.
    /// Set to false after MAX_CONSECUTIVE_FAILURES, back to true after one success.
    is_healthy: bool,
    /// True after first contact attempt (success or failure). Until then, the
    /// endpoint does not contribute to healthy_count even though is_healthy
    /// defaults to true. Step 9 v20: quorum honesty on initial startup.
    probed: bool,
    /// Step 3.6 (F6): rolling window of recent successful-query latencies
    /// in milliseconds. Newest at the back; capped at LATENCY_SAMPLE_COUNT.
    latency_samples: VecDeque<u64>,
}

impl EndpointHealth {
    fn new(url: String) -> Self {
        Self {
            url,
            consecutive_failures: 0,
            is_healthy: true,
            probed: false,
            latency_samples: VecDeque::with_capacity(LATENCY_SAMPLE_COUNT),
        }
    }

    fn record_success(&mut self) {
        if !self.is_healthy {
            log::info!("independent: endpoint {} reinstated as healthy", self.url);
        }
        self.consecutive_failures = 0;
        self.is_healthy = true;
        self.probed = true;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.probed = true;
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES && self.is_healthy {
            log::warn!(
                "independent: endpoint {} demoted (down) after {} failures",
                self.url, self.consecutive_failures
            );
            self.is_healthy = false;
        }
    }

    /// Step 3.6 (F6): record a successful-query latency sample. Drops the
    /// oldest sample once the window exceeds LATENCY_SAMPLE_COUNT.
    fn record_latency_ms(&mut self, ms: u64) {
        self.latency_samples.push_back(ms);
        while self.latency_samples.len() > LATENCY_SAMPLE_COUNT {
            self.latency_samples.pop_front();
        }
    }

    /// Step 3.6 (F6): median of the rolling latency window. None if no
    /// samples have been recorded yet (endpoint never queried successfully).
    fn median_latency_ms(&self) -> Option<u64> {
        if self.latency_samples.is_empty() {
            return None;
        }
        let mut samples: Vec<u64> = self.latency_samples.iter().copied().collect();
        samples.sort_unstable();
        Some(samples[samples.len() / 2])
    }
}

// ── Quorum disagreement state ──────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumState {
    /// Last query produced a clear majority. Normal operation.
    Healthy,
    /// One or more endpoints disagreed but majority held. Demoted dissenters.
    SlightDisagreement,
    /// v225 (S42, DP RULED — the v476 floor lands in the engine): exactly ONE
    /// healthy independent source answered. It cannot form a majority alone;
    /// cold_start requires the LSP's cooperative height to AGREE with it before
    /// Ready (two agreeing sources). The on-chain face keeps 2-of-4 on the page.
    SingleSource,
    /// Even split, no clear majority. Status panel should prompt user.
    NoQuorum,
    /// All endpoints returned different values. Anomaly — refuse chain-dependent ops.
    TotalDisagreement,
    /// Not enough healthy endpoints to form a quorum (≥3 required).
    InsufficientEndpoints,
}

// ── Default endpoints ──────────────────────────────────────────────────────

/// Default Esplora endpoint list. 4 CORS-friendly Esplora instances.
/// Reduced from 5 to 4 in May 2026 after electrs.zeusln.com and
/// electrs.getalbypro.com both lost CORS support in production.
/// Quorum threshold lowered to 2-of-4 to compensate
/// (see cold_start.rs::decide_state_pure and is_available below).
/// LIJOX reference instance will fill a 5th slot when live.
pub fn default_endpoints() -> Vec<String> {
    vec![
        // 1. Blockstream — verified CORS-friendly.
        "https://blockstream.info/api".to_string(),
        // 2. mempool.space — verified CORS-friendly.
        "https://mempool.space/api".to_string(),
        // 3. btcscan.org — verified CORS-friendly Esplora instance.
        "https://btcscan.org/api".to_string(),
        // 4. Emzy's community mempool instance — independent OPERATOR
        //    diversity (not another mempool.space cluster). Replaces the
        //    Frankfurt cluster, which lost CORS in production (S32 road
        //    verdict: Safari passed, the engine's CORS fetch failed ⇒
        //    wallet-legitimate count of 1). Self-hosted mempool ships
        //    permissive CORS by default; FIELD-VERIFY via the Connections
        //    chain area's per-endpoint states, re-swap if red.
        "https://mempool.emzy.de/api".to_string(),
    ]
}

// ── Esplora response shapes ────────────────────────────────────────────────
// Esplora's HTTP API returns JSON. We model only the fields we use.

#[derive(Debug, Deserialize)]
struct EsploraFeeEstimates {
    // Esplora's /fee-estimates returns a map of {confirmation_target → sat/vB}.
    // We accept arbitrary fields; the helper below picks the buckets we want.
    #[serde(flatten)]
    by_target: HashMap<String, f64>,
}

impl EsploraFeeEstimates {
    /// Pick the fastest available estimate (1-block target if present,
    /// else the smallest target available).
    fn fast_sat_per_vb(&self) -> Option<u32> {
        // Try "1" first (1-block target)
        if let Some(v) = self.by_target.get("1") {
            return Some(v.round().max(1.0) as u32);
        }
        // Otherwise find the smallest numeric key
        let mut best: Option<(u32, f64)> = None;
        for (k, v) in &self.by_target {
            if let Ok(target) = k.parse::<u32>() {
                if best.is_none() || target < best.unwrap().0 {
                    best = Some((target, *v));
                }
            }
        }
        best.map(|(_, v)| v.round().max(1.0) as u32)
    }
}

#[derive(Debug, Deserialize)]
struct EsploraBlocksTip {
    height: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)] // some fields surface to the cold-start orchestrator (step 6)
pub struct EsploraTxStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<String>,
}

// ── IndependentClient ──────────────────────────────────────────────────────

pub struct IndependentClient {
    http: Mutex<Arc<dyn EsploraHttp>>,
    endpoints: Mutex<Vec<EndpointHealth>>,
    last_quorum_state: Mutex<QuorumState>,
    /// Step 3.6 (F5): cached consensus tip from the most recent successful
    /// fetch_tip_height call. Surfaced via last_block_height() for Card 4.
    last_consensus_height: Mutex<Option<u32>>,
    /// v226 (S43, speed item 0): called with the FIRST successful tip height
    /// of a fetch_tip_height round, before the other endpoints have answered.
    /// node.rs installs the cold-start marker here so Ready can land on the
    /// first agreeing source (the v225 floor) instead of after the slowest.
    first_height_hook: Mutex<Option<Arc<dyn Fn(u32) + Send + Sync>>>,
}

impl IndependentClient {
    pub fn new(http: Arc<dyn EsploraHttp>, endpoint_urls: Vec<String>) -> Self {
        let endpoints: Vec<EndpointHealth> = endpoint_urls
            .into_iter()
            .map(EndpointHealth::new)
            .collect();
        Self {
            http: Mutex::new(http),
            endpoints: Mutex::new(endpoints),
            last_quorum_state: Mutex::new(QuorumState::InsufficientEndpoints),
            last_consensus_height: Mutex::new(None),  // Step 3.6 (F5)
            first_height_hook: Mutex::new(None),      // v226
        }
    }

    /// v226: install (or replace) the first-height hook. See the field doc.
    pub fn set_first_height_hook(&self, hook: Arc<dyn Fn(u32) + Send + Sync>) {
        *self.first_height_hook.lock().unwrap() = Some(hook);
    }

    pub fn with_defaults(http: Arc<dyn EsploraHttp>) -> Self {
        Self::new(http, default_endpoints())
    }

    /// Add a user-configured endpoint. Idempotent: re-adding an existing URL is a no-op.
    /// Returns Err if the configured count would exceed MAX_QUORUM_SIZE.
    pub fn add_endpoint(&self, url: String) -> LijResult<()> {
        let mut eps = self.endpoints.lock().unwrap();
        if eps.iter().any(|e| e.url == url) {
            return Ok(());
        }
        if eps.len() >= MAX_QUORUM_SIZE {
            return Err(LijError::InvalidArgument(format!(
                "endpoint count would exceed max ({MAX_QUORUM_SIZE})"
            )));
        }
        eps.push(EndpointHealth::new(url));
        Ok(())
    }

    /// Remove an endpoint by URL. Returns Ok even if the URL wasn't present.
    pub fn remove_endpoint(&self, url: &str) {
        self.endpoints
            .lock()
            .unwrap()
            .retain(|e| e.url != url);
    }

    /// Snapshot of all endpoint URLs and their health, for status panel.
    /// Step 3.6 (F6): added Option<u64> latency_ms median (4th tuple element).
    pub fn endpoint_status(&self) -> Vec<(String, bool, u32, Option<u64>)> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.url.clone(), e.is_healthy, e.consecutive_failures, e.median_latency_ms()))
            .collect()
    }

    /// Step 3.6 (F5): cached consensus tip height from the last successful
    /// fetch_tip_height call. None until the first quorum-validated tip
    /// arrives. Read by Card 4 of the wallet dashboard.
    pub fn last_block_height(&self) -> Option<u32> {
        *self.last_consensus_height.lock().unwrap()
    }

    /// Step 3.6 (F6): record a successful-query latency for a specific
    /// endpoint URL. Quietly no-ops if the URL isn't found.
    fn record_endpoint_latency(&self, url: &str, ms: u64) {
        let mut eps = self.endpoints.lock().unwrap();
        if let Some(ep) = eps.iter_mut().find(|e| e.url == url) {
            ep.record_latency_ms(ms);
        }
    }

    /// Replace the HTTP backend in place. Used by lij-wasm to swap from the
    /// stub backend (set at construction) to the real WasmEsploraHttp once
    /// the wallet is fully initialized.
    pub fn replace_http(&self, http: std::sync::Arc<dyn EsploraHttp>) {
        *self.http.lock().unwrap() = http;
        log::info!("independent: HTTP backend replaced");
    }

    pub fn last_quorum_state(&self) -> QuorumState {
        *self.last_quorum_state.lock().unwrap()
    }

    /// Number of currently-healthy endpoints.
    pub fn healthy_count(&self) -> usize {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.is_healthy && e.probed)
            .count()
    }

    /// v210 (quorum wiring, DP design): replace the endpoint set at runtime —
    /// LSP-declared defaults merged with wallet additions arrive from the page.
    /// Health states reset; the ≥1-healthy function floor and all quorum
    /// semantics are unchanged. Never called with fewer than the LSP defaults
    /// (page enforces additive-only).
    pub fn set_endpoints(&self, urls: Vec<String>) {
        let eps: Vec<EndpointHealth> = urls.into_iter().map(EndpointHealth::new).collect();
        if eps.is_empty() { return; }
        *self.endpoints.lock().unwrap() = eps;
    }

    fn record_endpoint_result(&self, url: &str, succeeded: bool) {
        {
            let mut eps = self.endpoints.lock().unwrap();
            if let Some(ep) = eps.iter_mut().find(|e| e.url == url) {
                if succeeded {
                    ep.record_success();
                } else {
                    ep.record_failure();
                }
            }
        } // drop lock before calling set_quorum_state (which acquires its own)

        // Step 9 v22 — eager degradation reporting.
        // If we've dropped below quorum minimum, surface InsufficientEndpoints
        // immediately rather than waiting for the next fetch_tip_height round.
        // We only DEGRADE here; promotion up the state ladder still requires
        // a full consensus round in fetch_tip_height (Healthy/SlightDisagreement/etc).
        // Quorum minimum is 2 (lowered from 3 in May 2026 when zeusln and
        // getalbypro lost CORS support and the endpoint list was trimmed
        // from 5 to 4 — 2-of-4 = 50% threshold).
        // FUTURE: when LIJOX reference instance is added as a 5th slot,
        // revisit whether to restore >= 3.
        // v225: the floor is ONE healthy source; degrade only at zero.
        if self.healthy_count() == 0 {
            self.set_quorum_state(QuorumState::InsufficientEndpoints);
        }
    }

    fn set_quorum_state(&self, state: QuorumState) {
        let mut current = self.last_quorum_state.lock().unwrap();
        if *current != state {
            log::info!("independent: quorum state {:?} → {:?}", *current, state);
            *current = state;
        }
    }

    /// Get healthy endpoint URLs as a snapshot.
    fn healthy_urls(&self) -> Vec<String> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.is_healthy)
            .map(|e| e.url.clone())
            .collect()
    }

    /// Query all healthy endpoints in parallel. Returns Vec<(url, result)>.
    /// Used by both query (tip height, fees) and broadcast paths.
    async fn query_all<F, T>(&self, mk: F) -> Vec<(String, LijResult<T>)>
    where
        F: Fn(&str) -> LocalBoxFuture<'_, LijResult<T>>,
    {
        self.query_all_each(mk, |_, _| {}).await
    }

    /// v226 (S43, speed item 0): the endpoints are asked CONCURRENTLY and
    /// `on_each` runs as each one answers, in completion order. Until v226
    /// this loop awaited the endpoints one after another, so a round lasted
    /// the SUM of four latencies and one stalled endpoint held every answer
    /// (the "prepare failed" first send after a cold open — the cold-start
    /// Ready rule waits for this round). Health and latency bookkeeping is
    /// per completion, exactly as before; result order is completion order
    /// (no caller depends on order — majorities and dissenter scans are
    /// order-free).
    async fn query_all_each<F, T, C>(&self, mk: F, mut on_each: C) -> Vec<(String, LijResult<T>)>
    where
        F: Fn(&str) -> LocalBoxFuture<'_, LijResult<T>>,
        C: FnMut(&str, &LijResult<T>),
    {
        use futures::stream::{FuturesUnordered, StreamExt};
        let urls = self.healthy_urls();
        let mut results = Vec::with_capacity(urls.len());
        let mut pending: FuturesUnordered<_> = urls
            .iter()
            .map(|url| {
                // Step 3.6 (F6): time each endpoint query so we can populate the
                // rolling latency window on success.
                let start_ms = current_time_ms();
                let fut = mk(url.as_str());
                async move {
                    let res = fut.await;
                    (url, start_ms, res)
                }
            })
            .collect();
        while let Some((url, start_ms, res)) = pending.next().await {
            let elapsed_ms = current_time_ms().saturating_sub(start_ms);
            let succeeded = res.is_ok();
            self.record_endpoint_result(url.as_str(), succeeded);
            if succeeded {
                self.record_endpoint_latency(url.as_str(), elapsed_ms);
            }
            on_each(url.as_str(), &res);
            results.push((url.clone(), res));
        }
        results
    }

    /// Fetch current chain tip height from the quorum.
    /// Used by cold-start sync (step 6) and the 30–45min spot-check (trigger 2f).
    pub async fn fetch_tip_height(&self) -> LijResult<u32> {
        // Step 9 v21 — Option (b): no upfront gate. Probe through the query.
        // Endpoints get probed via record_endpoint_result; quorum trust is
        // enforced post-query via min successful response count.
        let http = self.http.lock().unwrap().clone();
        // v226: the first endpoint to answer reports early — quorum goes to
        // SingleSource (only when nothing better is already standing, so a
        // 30 s spot-check never demotes a Healthy face mid-round), the
        // consensus height is filled if empty, and the cold-start hook fires
        // so Ready can land on the first source that agrees with the LSP's
        // feed. The full round still runs and its majority verdict overwrites.
        let mut first_reported = false;
        let results = self
            .query_all_each(|url| {
                let url_owned = format!("{url}/blocks/tip/height");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!(
                            "tip/height status {}",
                            resp.status
                        )));
                    }
                    resp.body
                        .trim()
                        .parse::<u32>()
                        .map_err(|e| LijError::Lsp(format!("tip/height parse: {e}")))
                })
            }, |url, res| {
                if first_reported { return; }
                if let Ok(h) = res {
                    first_reported = true;
                    let standing = self.last_quorum_state();
                    if !matches!(standing, QuorumState::Healthy | QuorumState::SlightDisagreement | QuorumState::SingleSource) {
                        self.set_quorum_state(QuorumState::SingleSource);
                    }
                    {
                        let mut c = self.last_consensus_height.lock().unwrap();
                        if c.is_none() { *c = Some(*h); }
                    }
                    let hook = self.first_height_hook.lock().unwrap().clone();
                    if let Some(f) = hook {
                        log::debug!("independent: first answer {} from {} — early report", h, url);
                        (*f)(*h);
                    }
                }
            })
            .await;

        let heights: Vec<u32> = results.iter().filter_map(|(_, r)| r.as_ref().ok().copied()).collect();
        // Step 9 v21 — Option (b) trust check: need ≥3 successful responses
        // before we trust any consensus result. Fewer = InsufficientEndpoints.
        // TEMPORARY: consensus minimum lowered from 3 to 2 (see line 409 note)
        if heights.is_empty() {
            self.set_quorum_state(QuorumState::InsufficientEndpoints);
            return Err(LijError::Lsp(
                "independent quorum: no successful responses".to_string()
            ));
        }
        // v225 (S42, DP RULED): one healthy source is the Lightning floor (v476).
        // Report it as SingleSource and hand its height up; Ready still needs
        // the cooperative height to agree with it (cold_start).
        if heights.len() == 1 {
            self.set_quorum_state(QuorumState::SingleSource);
            *self.last_consensus_height.lock().unwrap() = Some(heights[0]);
            return Ok(heights[0]);
        }

        let majority = strict_majority(&heights);
        match majority {
            MajorityResult::Clear(value) => {
                let dissenters: Vec<&str> = results
                    .iter()
                    .filter_map(|(url, r)| match r {
                        Ok(v) if *v != value => Some(url.as_str()),
                        _ => None,
                    })
                    .collect();
                if dissenters.is_empty() {
                    self.set_quorum_state(QuorumState::Healthy);
                } else {
                    log::warn!(
                        "independent: tip-height majority {} but dissenters: {:?}",
                        value, dissenters
                    );
                    // Demote dissenters by recording a failure (they returned a
                    // wrong-but-otherwise-valid response, which is a form of failure
                    // for trust purposes).
                    for url in &dissenters {
                        self.record_endpoint_result(url, false);
                    }
                    self.set_quorum_state(QuorumState::SlightDisagreement);
                }
                // Step 3.6 (F5): cache consensus height for Card 4 readout.
                *self.last_consensus_height.lock().unwrap() = Some(value);
                Ok(value)
            }
            MajorityResult::EvenSplit => {
                self.set_quorum_state(QuorumState::NoQuorum);
                Err(LijError::Lsp("independent quorum: no majority".into()))
            }
            MajorityResult::AllDifferent => {
                self.set_quorum_state(QuorumState::TotalDisagreement);
                Err(LijError::Lsp("independent quorum: total disagreement".into()))
            }
        }
    }

    /// Fetch tip block hash from quorum. Verify-only telemetry for
    /// ChainCoordinator (Phase 3.7.C). NEVER calls LDK directly.
    /// Mirrors fetch_tip_height policy: >=2 successful responses, strict_majority.
    /// Does NOT mutate quorum state - fetch_tip_height owns that.
    pub async fn fetch_tip_hash(&self) -> LijResult<BlockHash> {
        let http = self.http.lock().unwrap().clone();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/blocks/tip/hash");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!("tip/hash status {}", resp.status)));
                    }
                    BlockHash::from_str(resp.body.trim())
                        .map_err(|e| LijError::Lsp(format!("tip/hash parse: {e}")))
                })
            })
            .await;
        let hashes: Vec<BlockHash> = results.iter()
            .filter_map(|(_, r)| r.as_ref().ok().copied())
            .collect();
        if hashes.len() < 2 {
            return Err(LijError::Lsp(format!(
                "independent quorum: only {} tip-hash responses, need >=2", hashes.len()
            )));
        }
        match strict_majority(&hashes) {
            MajorityResult::Clear(value) => Ok(value),
            MajorityResult::EvenSplit => Err(LijError::Lsp(
                "independent quorum: no majority on tip hash".into())),
            MajorityResult::AllDifferent => Err(LijError::Lsp(
                "independent quorum: total disagreement on tip hash".into())),
        }
    }

    /// Fetch the outspends array for a given txid via the independent quorum.
    ///
    /// Esplora endpoint /tx/{txid}/outspends returns one entry per output:
    ///   { spent: bool, txid: Option<String>, vin: Option<u32>, status: ... }
    ///
    /// Used by closed_channel_watcher to determine if a funding output has
    /// been spent (i.e., the channel close has confirmed on-chain).
    ///
    /// Behavior: first endpoint with a usable response wins (no quorum
    /// agreement required — outspend status is monotonic on-chain).
    pub async fn fetch_tx_outspends(&self, txid: &str) -> LijResult<Vec<EsploraOutspend>> {
        let healthy = self.healthy_count();
        if healthy == 0 {
            return Err(LijError::Lsp("independent quorum: no healthy endpoints".into()));
        }
        let http = self.http.lock().unwrap().clone();
        let txid = txid.to_string();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/tx/{txid}/outspends");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status == 404 {
                        return Ok(Vec::<EsploraOutspend>::new());
                    }
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!(
                            "outspends status {}",
                            resp.status
                        )));
                    }
                    let raw: Vec<EsploraOutspendRaw> = serde_json::from_str(&resp.body)
                        .map_err(|e| LijError::Lsp(format!("outspends parse: {e}")))?;
                    Ok(raw.into_iter().map(EsploraOutspend::from).collect())
                })
            })
            .await;

        for (_url, r) in &results {
            if let Ok(outspends) = r {
                if !outspends.is_empty() {
                    return Ok(outspends.clone());
                }
            }
        }
        // All empty or all failed.
        if results.iter().any(|(_, r)| r.is_ok()) {
            Ok(Vec::new())
        } else {
            Err(LijError::Lsp(format!(
                "fetch_tx_outspends: all endpoints failed for {txid}"
            )))
        }
    }

    /// Fetch a transaction by txid via the independent quorum.
    ///
    /// Used by closed_channel_watcher to read the closing tx's outputs
    /// once the funding output is found to have been spent.
    pub async fn fetch_tx(&self, txid: &str) -> LijResult<EsploraTx> {
        let healthy = self.healthy_count();
        if healthy == 0 {
            return Err(LijError::Lsp("independent quorum: no healthy endpoints".into()));
        }
        let http = self.http.lock().unwrap().clone();
        let txid = txid.to_string();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/tx/{txid}");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!("tx status {}", resp.status)));
                    }
                    let raw: EsploraTxRaw = serde_json::from_str(&resp.body)
                        .map_err(|e| LijError::Lsp(format!("tx parse: {e}")))?;
                    Ok(EsploraTx::from(raw))
                })
            })
            .await;

        for (_url, r) in &results {
            if let Ok(tx) = r {
                return Ok(tx.clone());
            }
        }
        Err(LijError::Lsp(format!(
            "fetch_tx: all endpoints failed for {txid}"
        )))
    }

    /// v186 (S27): block position of a CONFIRMED tx via
    /// `/tx/{txid}/merkle-proof`. Returns (block_height, pos). Errors when
    /// the tx is unconfirmed (endpoints answer non-200) or all endpoints
    /// fail — so a single call answers confirmed-or-not, height, and pos.
    /// Used by the live funding-confirmation heal in node.rs: SCID
    /// computation needs the REAL tx_index for funding confirmations
    /// (Step 3.6), unlike the closing-tx path where tx_index=0 is safe.
    pub async fn fetch_tx_merkle_pos(&self, txid: &str) -> LijResult<(u32, u32)> {
        #[derive(serde::Deserialize)]
        struct EsploraMerkleProofRaw {
            block_height: u32,
            pos: u32,
        }
        let healthy = self.healthy_count();
        if healthy == 0 {
            return Err(LijError::Lsp("independent quorum: no healthy endpoints".into()));
        }
        let http = self.http.lock().unwrap().clone();
        let txid = txid.to_string();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/tx/{txid}/merkle-proof");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!("merkle-proof status {}", resp.status)));
                    }
                    let raw: EsploraMerkleProofRaw = serde_json::from_str(&resp.body)
                        .map_err(|e| LijError::Lsp(format!("merkle-proof parse: {e}")))?;
                    Ok((raw.block_height, raw.pos))
                })
            })
            .await;
        for (_url, r) in &results {
            if let Ok(v) = r {
                return Ok(*v);
            }
        }
        Err(LijError::Lsp(format!(
            "fetch_tx_merkle_pos: all endpoints failed or tx unconfirmed for {txid}"
        )))
    }

    /// Fetch raw serialized transaction bytes by txid via the independent
    /// quorum. Esplora's `/tx/{txid}/hex` endpoint returns the hex-encoded
    /// raw tx as the response body (no JSON wrapper). This method decodes
    /// the hex into bytes ready for `bitcoin::consensus::deserialize`.
    ///
    /// Used by the offline force-close detection path in node.rs: when a
    /// funding outpoint is observed spent via `fetch_tx_outspends`, the
    /// spending tx bytes are pulled here and routed into LDK's Confirm
    /// trait through the chain coordinator.
    pub async fn fetch_tx_hex(&self, txid: &str) -> LijResult<Vec<u8>> {
        let healthy = self.healthy_count();
        if healthy == 0 {
            return Err(LijError::Lsp("independent quorum: no healthy endpoints".into()));
        }
        let http = self.http.lock().unwrap().clone();
        let txid = txid.to_string();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/tx/{txid}/hex");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!("tx/hex status {}", resp.status)));
                    }
                    let body = resp.body.trim();
                    hex::decode(body)
                        .map_err(|e| LijError::Lsp(format!("tx/hex decode: {e}")))
                })
            })
            .await;

        for (_url, r) in &results {
            if let Ok(bytes) = r {
                return Ok(bytes.clone());
            }
        }
        Err(LijError::Lsp(format!(
            "fetch_tx_hex: all endpoints failed for {txid}"
        )))
    }

    /// Fetch UTXOs at a given Bitcoin address via the independent quorum.
    ///
    /// Used by onchain_scan for wallet residue recovery. Unlike fetch_tip_height
    /// or fetch_fee_quote, this does NOT require strict majority agreement —
    /// UTXO state is not adversarially manipulable in the same way (an endpoint
    /// can lag but cannot fabricate a fake UTXO without breaking the chain).
    ///
    /// Behavior:
    ///   - If any endpoint returns UTXOs, those are returned.
    ///   - If all endpoints return empty, returns Ok(vec![]).
    ///   - If all endpoints fail, returns Err.
    ///   - Endpoint failures count toward demotion via record_endpoint_result.
    pub async fn fetch_address_utxos(&self, address: &str) -> LijResult<Vec<EsploraUtxo>> {
        let healthy = self.healthy_count();
        if healthy == 0 {
            return Err(LijError::Lsp("independent quorum: no healthy endpoints".into()));
        }
        let http = self.http.lock().unwrap().clone();
        let address = address.to_string();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/address/{address}/utxo");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status == 404 {
                        // Some endpoints return 404 for never-used addresses.
                        return Ok(Vec::<EsploraUtxo>::new());
                    }
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!(
                            "address utxo status {}",
                            resp.status
                        )));
                    }
                    let utxos: Vec<EsploraUtxoRaw> = serde_json::from_str(&resp.body)
                        .map_err(|e| LijError::Lsp(format!("address utxo parse: {e}")))?;
                    Ok(utxos.into_iter().map(EsploraUtxo::from).collect())
                })
            })
            .await;

        // First non-empty success wins. Lagging endpoints returning empty are
        // not a problem; we only need one endpoint to know the truth.
        let mut had_success = false;
        for (_url, r) in &results {
            match r {
                Ok(utxos) => {
                    had_success = true;
                    if !utxos.is_empty() {
                        return Ok(utxos.clone());
                    }
                }
                Err(_) => {}
            }
        }
        if had_success {
            // All successful endpoints returned empty — address truly has no UTXOs.
            Ok(Vec::new())
        } else {
            Err(LijError::Lsp(format!(
                "address utxo: all endpoints failed for {address}"
            )))
        }
    }

    /// Fetch median fee schedule from the quorum.
    /// Tolerance window applies between cooperative and this median (in fee_estimator.rs).
    /// Within this method we also internally tolerance-check across endpoints.
    pub async fn fetch_fee_quote(&self) -> LijResult<FeeQuote> {
        // No upfront gate. Probe through the query, same pattern as
        // fetch_tip_height. Endpoints get probed via record_endpoint_result
        // (inside query_all); trust is enforced post-query via the
        // `rates.is_empty()` / minimum-response check below. The previous
        // upfront `healthy_count() < 2` gate was broken-by-design: on a
        // fresh IndependentClient no endpoint has been probed yet, so
        // healthy_count() returns 0 and the gate refused every fee quote
        // until tip-height had been fetched at least once. Removing the
        // gate restores the intended behavior. (See cold_start.rs notes.)
        let http = self.http.lock().unwrap().clone();
        let results = self
            .query_all(|url| {
                let url_owned = format!("{url}/fee-estimates");
                let http = http.clone();
                Box::pin(async move {
                    let resp = http.get(&url_owned).await?;
                    if resp.status != 200 {
                        return Err(LijError::Lsp(format!(
                            "fee-estimates status {}",
                            resp.status
                        )));
                    }
                    let parsed: EsploraFeeEstimates = serde_json::from_str(&resp.body)
                        .map_err(|e| LijError::Lsp(format!("fee-estimates parse: {e}")))?;
                    parsed
                        .fast_sat_per_vb()
                        .ok_or_else(|| LijError::Lsp("fee-estimates: no usable target".into()))
                })
            })
            .await;

        let mut rates: Vec<u32> = results.iter().filter_map(|(_, r)| r.as_ref().ok().copied()).collect();
        if rates.is_empty() {
            self.set_quorum_state(QuorumState::InsufficientEndpoints);
            return Err(LijError::Lsp("all endpoints failed for fees".into()));
        }
        rates.sort();
        let median = rates[rates.len() / 2];
        // Soft tolerance: don't fail on disagreement within 25% of median.
        // (Fee estimates legitimately vary across mempool views.)
        let max_dev = rates
            .iter()
            .map(|r| ((r.abs_diff(median)) as u64 * 100) / median.max(1) as u64)
            .max()
            .unwrap_or(0);
        if max_dev > FEE_TOLERANCE_PCT as u64 {
            log::warn!(
                "independent: fee dispersion {}% across endpoints (median {} sat/vB)",
                max_dev, median
            );
            // Don't change quorum state for fees — fee variance is not adversarial
            // by itself.
        } else {
            self.set_quorum_state(QuorumState::Healthy);
        }
        Ok(FeeQuote::from_fast_sat_per_vb(median))
    }

    /// Broadcast a raw tx to all endpoints. Success if any endpoint accepts.
    /// Esplora's POST /tx accepts hex-encoded tx body.
    /// Public entrypoint to broadcast a raw (consensus-serialized) transaction
    /// through the independent quorum. Returns Err if no endpoint accepted it
    /// (including 4xx rejects), so callers learn when a tx is invalid/rejected.
    pub async fn broadcast_raw_tx(&self, raw_tx: &[u8]) -> LijResult<()> {
        self.broadcast_to_quorum(raw_tx).await
    }

    async fn broadcast_to_quorum(&self, raw_tx: &[u8]) -> LijResult<()> {
        let mut urls = self.healthy_urls();
        if urls.is_empty() {
            return Err(LijError::Lsp("no healthy endpoints for broadcast".into()));
        }
        // v208 BROADCAST ROUTING (DP privacy pane): 'one' mode submits to a
        // single endpoint and stops at the first acceptance — the rest are
        // tried only on refusal, so usually one operator sees the broadcast.
        // Start index rotates per-tx (first payload byte) so no single
        // operator becomes the permanent observer. Default stays all-four.
        let one_mode = BROADCAST_ONE.load(std::sync::atomic::Ordering::Relaxed);
        if one_mode && urls.len() > 1 {
            let start = raw_tx.first().copied().unwrap_or(0) as usize % urls.len();
            urls.rotate_left(start);
        }
        let hex_body = hex::encode(raw_tx);
        let mut any_success = false;
        // Build #4: carry rejection bodies to the caller so the broadcaster
        // can classify (already-known vs conflict vs transient).
        let mut reject_bodies: Vec<String> = Vec::new();
        for url in &urls {
            let url_owned = format!("{url}/tx");
            let http = self.http.lock().unwrap().clone();
            let result = http.post(&url_owned, hex_body.as_bytes(), "text/plain").await;
            match result {
                Ok(resp) if resp.status >= 200 && resp.status < 300 => {
                    self.record_endpoint_result(url, true);
                    any_success = true;
                    log::info!("independent: broadcast accepted by {url}");
                    if one_mode {
                        break;   // v208: one-mode stops at the first acceptance
                    }
                }
                Ok(resp) => {
                    log::warn!(
                        "independent: broadcast rejected by {url}: status {} body {}",
                        resp.status, resp.body
                    );
                    reject_bodies.push(resp.body.chars().take(160).collect::<String>());
                    // 4xx rejects don't necessarily indicate the endpoint is bad
                    // (the tx itself may be invalid), but we record as success
                    // for health purposes — the endpoint is reachable and
                    // responsive. Different from network failures.
                    self.record_endpoint_result(url, true);
                }
                Err(e) => {
                    log::warn!("independent: broadcast network error on {url}: {e}");
                    self.record_endpoint_result(url, false);
                }
            }
        }
        if any_success {
            Ok(())
        } else {
            Err(LijError::Lsp(format!(
                "broadcast: no endpoint accepted (tried {}): {}",
                urls.len(),
                reject_bodies.join(" | ")
            )))
        }
    }
}

// ── Trait impls ─────────────────────────────────────────────────────────────

impl IndependentBroadcaster for IndependentClient {
    fn broadcast<'a>(&'a self, raw_tx: &'a [u8]) -> LocalBoxFuture<'a, LijResult<()>> {
        Box::pin(async move { self.broadcast_to_quorum(raw_tx).await })
    }

    fn is_available(&self) -> bool {
        self.healthy_count() >= 1
    }
}

impl IndependentFeeSource for IndependentClient {
    fn fetch<'a>(&'a self) -> LocalBoxFuture<'a, LijResult<FeeQuote>> {
        Box::pin(async move { self.fetch_fee_quote().await })
    }

    fn is_available(&self) -> bool {
        // 2-of-4 threshold; see default_endpoints comment for history.
        self.healthy_count() >= 2
    }
}

// ── Strict-majority helper ─────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum MajorityResult<T> {
    Clear(T),
    EvenSplit,
    AllDifferent,
}

fn strict_majority<T: Clone + PartialEq + Eq + std::hash::Hash>(values: &[T]) -> MajorityResult<T> {
    if values.is_empty() {
        return MajorityResult::EvenSplit;
    }
    let mut counts: HashMap<&T, usize> = HashMap::new();
    for v in values {
        *counts.entry(v).or_insert(0) += 1;
    }
    let total = values.len();
    let mut best: Option<(&T, usize)> = None;
    for (v, c) in &counts {
        if best.is_none() || *c > best.unwrap().1 {
            best = Some((v, *c));
        }
    }
    let (top, top_count) = best.unwrap();
    if top_count * 2 > total {
        MajorityResult::Clear(top.clone())
    } else if counts.len() == values.len() {
        MajorityResult::AllDifferent
    } else {
        MajorityResult::EvenSplit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock HTTP backend. Per-URL canned responses.
    struct MockHttp {
        responses: Mutex<HashMap<String, Vec<LijResult<HttpResponse>>>>,
        get_calls: AtomicU32,
        post_calls: AtomicU32,
    }

    impl MockHttp {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
                get_calls: AtomicU32::new(0),
                post_calls: AtomicU32::new(0),
            }
        }
        fn add_response(&self, url_substr: &str, resp: LijResult<HttpResponse>) {
            self.responses
                .lock()
                .unwrap()
                .entry(url_substr.to_string())
                .or_insert_with(Vec::new)
                .push(resp);
        }
        fn pop_response(&self, full_url: &str) -> Option<LijResult<HttpResponse>> {
            let mut map = self.responses.lock().unwrap();
            for (key, queue) in map.iter_mut() {
                if full_url.contains(key.as_str()) && !queue.is_empty() {
                    return Some(queue.remove(0));
                }
            }
            None
        }
    }

    impl EsploraHttp for MockHttp {
        fn get<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, LijResult<HttpResponse>> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            let response = self.pop_response(url);
            Box::pin(async move {
                response.unwrap_or_else(|| Err(LijError::Lsp(format!("no mock for {url}"))))
            })
        }
        fn post<'a>(
            &'a self,
            url: &'a str,
            _body: &'a [u8],
            _content_type: &'a str,
        ) -> LocalBoxFuture<'a, LijResult<HttpResponse>> {
            self.post_calls.fetch_add(1, Ordering::SeqCst);
            let response = self.pop_response(url);
            Box::pin(async move {
                response.unwrap_or_else(|| Err(LijError::Lsp(format!("no mock for {url}"))))
            })
        }
    }

    fn ok_body(body: &str) -> LijResult<HttpResponse> {
        Ok(HttpResponse { status: 200, body: body.to_string() })
    }

    fn three_endpoints() -> Vec<String> {
        vec![
            "https://a.example/api".to_string(),
            "https://b.example/api".to_string(),
            "https://c.example/api".to_string(),
        ]
    }

    fn four_endpoints() -> Vec<String> {
        vec![
            "https://a.example/api".to_string(),
            "https://b.example/api".to_string(),
            "https://c.example/api".to_string(),
            "https://d.example/api".to_string(),
        ]
    }

    #[tokio::test]
    async fn tip_height_unanimous_agreement() {
        let mock = Arc::new(MockHttp::new());
        for ep in ["a.example", "b.example", "c.example"] {
            mock.add_response(ep, ok_body("880247"));
        }
        let client = IndependentClient::new(mock.clone(), three_endpoints());
        let height = client.fetch_tip_height().await.unwrap();
        assert_eq!(height, 880_247);
        assert_eq!(client.last_quorum_state(), QuorumState::Healthy);
    }

    #[tokio::test]
    async fn tip_height_majority_one_dissenter() {
        let mock = Arc::new(MockHttp::new());
        // a, b agree on 880247; c says 880240 (off by 7)
        mock.add_response("a.example", ok_body("880247"));
        mock.add_response("b.example", ok_body("880247"));
        mock.add_response("c.example", ok_body("880240"));
        mock.add_response("d.example", ok_body("880247"));
        let client = IndependentClient::new(mock, four_endpoints());
        let height = client.fetch_tip_height().await.unwrap();
        assert_eq!(height, 880_247);
        assert_eq!(client.last_quorum_state(), QuorumState::SlightDisagreement);
        // c was demoted on the failure side
        let status = client.endpoint_status();
        let c = status.iter().find(|(u, _, _, _)| u.contains("c.example")).unwrap();
        assert_eq!(c.2, 1);
    }

    #[tokio::test]
    async fn tip_height_total_disagreement() {
        let mock = Arc::new(MockHttp::new());
        mock.add_response("a.example", ok_body("880247"));
        mock.add_response("b.example", ok_body("880200"));
        mock.add_response("c.example", ok_body("880100"));
        let client = IndependentClient::new(mock, three_endpoints());
        let result = client.fetch_tip_height().await;
        assert!(result.is_err());
        assert_eq!(client.last_quorum_state(), QuorumState::TotalDisagreement);
    }

    #[tokio::test]
    async fn tip_height_insufficient_endpoints() {
        let mock = Arc::new(MockHttp::new());
        // 2 endpoints, fewer than 3 minimum
        let client = IndependentClient::new(
            mock,
            vec!["https://a.example/api".to_string(), "https://b.example/api".to_string()],
        );
        let result = client.fetch_tip_height().await;
        assert!(result.is_err());
        assert_eq!(client.last_quorum_state(), QuorumState::InsufficientEndpoints);
    }

    #[tokio::test]
    async fn endpoint_demoted_after_three_failures() {
        let mock = Arc::new(MockHttp::new());
        // c fails 3 times; a, b succeed each time
        for _ in 0..3 {
            mock.add_response("a.example", ok_body("880247"));
            mock.add_response("b.example", ok_body("880247"));
            mock.add_response("c.example", Err(LijError::Lsp("network".into())));
            mock.add_response("d.example", ok_body("880247"));
        }
        let client = IndependentClient::new(mock, four_endpoints());
        for _ in 0..3 {
            let _ = client.fetch_tip_height().await;
        }
        let status = client.endpoint_status();
        let c = status.iter().find(|(u, _, _, _)| u.contains("c.example")).unwrap();
        assert!(!c.1, "c should be demoted to unhealthy");
        assert_eq!(c.2, 3);
        // a, b, d still healthy
        let healthy = client.healthy_count();
        assert_eq!(healthy, 3);
    }

    #[tokio::test]
    async fn endpoint_reinstated_on_one_success() {
        let mock = Arc::new(MockHttp::new());
        // First 3 rounds: c fails. 4th round: c succeeds.
        for _ in 0..3 {
            mock.add_response("a.example", ok_body("880247"));
            mock.add_response("b.example", ok_body("880247"));
            mock.add_response("c.example", Err(LijError::Lsp("network".into())));
            mock.add_response("d.example", ok_body("880247"));
        }
        let client = IndependentClient::new(mock.clone(), four_endpoints());
        for _ in 0..3 {
            let _ = client.fetch_tip_height().await;
        }
        // c demoted. Now: queue success for c.
        mock.add_response("a.example", ok_body("880248"));
        mock.add_response("b.example", ok_body("880248"));
        mock.add_response("d.example", ok_body("880248"));
        // c is unhealthy so it won't be queried — manually re-add
        // healthy by recording one success directly. (In production a manual
        // user "retry" would do this.)
        client.record_endpoint_result("https://c.example/api", true);
        let status = client.endpoint_status();
        let c = status.iter().find(|(u, _, _, _)| u.contains("c.example")).unwrap();
        assert!(c.1, "c should be reinstated after success");
        assert_eq!(c.2, 0);
    }

    #[tokio::test]
    async fn fee_quote_median_within_tolerance() {
        let mock = Arc::new(MockHttp::new());
        mock.add_response("a.example", ok_body(r#"{"1":32.0,"6":20.0}"#));
        mock.add_response("b.example", ok_body(r#"{"1":30.0,"6":18.0}"#));
        mock.add_response("c.example", ok_body(r#"{"1":34.0,"6":22.0}"#));
        let client = IndependentClient::new(mock, three_endpoints());
        let quote = client.fetch_fee_quote().await.unwrap();
        // Median of 32,30,34 = 32 → on_chain_sweep = 32*250 = 8000 sat/kw
        assert_eq!(quote.on_chain_sweep, 32 * 250);
    }

    #[tokio::test]
    async fn fee_quote_with_one_outlier() {
        let mock = Arc::new(MockHttp::new());
        // a, b agree around 30; c is 100 (way out of tolerance)
        mock.add_response("a.example", ok_body(r#"{"1":30.0}"#));
        mock.add_response("b.example", ok_body(r#"{"1":32.0}"#));
        mock.add_response("c.example", ok_body(r#"{"1":100.0}"#));
        let client = IndependentClient::new(mock, three_endpoints());
        let quote = client.fetch_fee_quote().await.unwrap();
        // Median is 32. Tolerance check logs but doesn't fail.
        assert_eq!(quote.on_chain_sweep, 32 * 250);
    }

    #[tokio::test]
    async fn broadcast_succeeds_if_any_endpoint_accepts() {
        let mock = Arc::new(MockHttp::new());
        mock.add_response("a.example", Err(LijError::Lsp("network".into())));
        mock.add_response(
            "b.example",
            Ok(HttpResponse { status: 200, body: "txid_hash".into() }),
        );
        mock.add_response("c.example", Err(LijError::Lsp("network".into())));
        let client = IndependentClient::new(mock, three_endpoints());
        let result = client.broadcast_to_quorum(&[0u8; 100]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn broadcast_fails_if_all_endpoints_fail() {
        let mock = Arc::new(MockHttp::new());
        mock.add_response("a.example", Err(LijError::Lsp("network".into())));
        mock.add_response("b.example", Err(LijError::Lsp("network".into())));
        mock.add_response("c.example", Err(LijError::Lsp("network".into())));
        let client = IndependentClient::new(mock, three_endpoints());
        let result = client.broadcast_to_quorum(&[0u8; 100]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn broadcast_4xx_counts_as_endpoint_alive() {
        // Endpoint reachable but rejects the tx (e.g., already in mempool, malformed).
        // Endpoint should NOT be demoted because it's clearly responsive.
        let mock = Arc::new(MockHttp::new());
        mock.add_response(
            "a.example",
            Ok(HttpResponse { status: 400, body: "bad-txns-inputs-missingorspent".into() }),
        );
        mock.add_response(
            "b.example",
            Ok(HttpResponse { status: 400, body: "bad-txns-inputs-missingorspent".into() }),
        );
        mock.add_response(
            "c.example",
            Ok(HttpResponse { status: 400, body: "bad-txns-inputs-missingorspent".into() }),
        );
        let client = IndependentClient::new(mock, three_endpoints());
        let result = client.broadcast_to_quorum(&[0u8; 100]).await;
        // No endpoint accepted (all 400s) — this is a tx-validity issue, returns Err
        assert!(result.is_err());
        // But endpoints are still healthy
        for (_, healthy, _, _) in client.endpoint_status() {
            assert!(healthy, "endpoints should remain healthy after 4xx response");
        }
    }

    #[test]
    fn add_remove_endpoints() {
        let mock = Arc::new(MockHttp::new());
        let client = IndependentClient::new(mock, three_endpoints());
        assert_eq!(client.endpoint_status().len(), 3);
        client.add_endpoint("https://my.umbrel/api".to_string()).unwrap();
        assert_eq!(client.endpoint_status().len(), 4);
        // Idempotent re-add
        client.add_endpoint("https://my.umbrel/api".to_string()).unwrap();
        assert_eq!(client.endpoint_status().len(), 4);
        client.remove_endpoint("https://my.umbrel/api");
        assert_eq!(client.endpoint_status().len(), 3);
    }

    #[test]
    fn add_endpoint_respects_max() {
        let mock = Arc::new(MockHttp::new());
        let client = IndependentClient::new(mock, vec![]);
        for i in 0..MAX_QUORUM_SIZE {
            client.add_endpoint(format!("https://e{i}.example/api")).unwrap();
        }
        assert_eq!(client.endpoint_status().len(), MAX_QUORUM_SIZE);
        let result = client.add_endpoint("https://overflow.example/api".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn strict_majority_unanimous() {
        let r = strict_majority(&[1, 1, 1]);
        assert_eq!(r, MajorityResult::Clear(1));
    }

    #[test]
    fn strict_majority_majority_with_dissent() {
        let r = strict_majority(&[1, 1, 2]);
        assert_eq!(r, MajorityResult::Clear(1));
    }

    #[test]
    fn strict_majority_even_split() {
        let r = strict_majority(&[1, 1, 2, 2]);
        assert_eq!(r, MajorityResult::EvenSplit);
    }

    #[test]
    fn strict_majority_all_different() {
        let r = strict_majority(&[1, 2, 3]);
        assert_eq!(r, MajorityResult::AllDifferent);
    }

    #[test]
    fn default_endpoints_matches_quorum_size() {
        assert_eq!(default_endpoints().len(), DEFAULT_QUORUM_SIZE);
    }

}
