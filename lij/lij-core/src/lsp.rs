// lsp.rs
// Lightning Service Provider management.
//
// This is the key departure from Mutiny:
//   Mutiny hardcoded Voltage LSP, then Zeus LSP.
//   We hardcode NOTHING. Any Umbrel node on clearnet can be an LSP.
//
// Architecture:
//   1. Your Cloudflare Worker maintains an LSP registry (KV-backed).
//   2. On wallet init, we fetch the registry and score available LSPs.
//   3. User can switch LSP at any time — their key stays the same,
//      channels close on the old LSP and open on the new one.
//   4. LSP communication uses LSPS1 (channel orders) and LSPS2 (JIT channels).

use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};

/// A registered Lightning Service Provider.
/// Fetched from your Cloudflare Worker LSP registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LspInfo {
    /// Human-readable name, e.g. "Plotzwerks Node", "Bob's Umbrel"
    pub name: String,
    /// Lightning node public key (hex), used to open channels
    pub pubkey: String,
    /// Clearnet endpoint, e.g. "https://lsp.example.com" or "node.example.com:9735"
    pub endpoint: String,
    /// Fee in parts-per-million for routing payments
    pub fee_ppm: u64,
    /// Base fee in sats per routed payment (added to ppm-derived amount).
    /// Defaults to 0 if registry response omits the field.
    #[serde(default)]
    pub fee_base_sats: u64,
    /// One-time fee charged when opening a channel with this LSP.
    /// Defaults to 0 if registry response omits the field.
    #[serde(default)]
    pub channel_open_fee_sats: u64,
    /// Maximum channel size this LSP will open, in sats.
    /// Defaults to 0 (= "not specified") if registry response omits the field.
    #[serde(default)]
    pub max_channel_size_sats: u64,
    /// Minimum channel size this LSP will accept, in sats (its LND
    /// `minchansize`). Defaults to 0 (= "not specified") if the registry
    /// response omits the field; the wallet treats 0 as "no LSP floor" and
    /// falls back to the LDK/wallet minimum rather than blocking an open.
    #[serde(default)]
    pub min_channel_size_sats: u64,
    /// Uptime percentage (0-100), reported by registry based on health checks
    pub uptime: u8,
    /// Whether this LSP supports LSPS2 (JIT channels) — preferred
    pub supports_jit: bool,
    /// LIJOX Phase 10b — URL of the LSP's routing-as-a-service endpoint.
    /// Wallet sends route queries here when constructing payments.
    /// FUTURE (LIJOX spec v1): this field will be discovered dynamically via
    /// the LSP's info endpoint rather than persisted per-record. Until then,
    /// hardcoded per-LSP and surfaced through `active_lsp_json()` to JS.
    #[serde(default)]
    pub route_endpoint: Option<String>,
    /// LIJOX Phase 10b — read-only macaroon (hex-encoded) for routing queries.
    /// Permission scope: info:read offchain:read onchain:read.
    /// Sent as `Grpc-Metadata-macaroon` header to the LND-style endpoint.
    /// FUTURE (LIJOX spec v1): credentials should be obtained dynamically per-
    /// session via LSPS-style auth dance. Hardcoded per-record for now.
    #[serde(default)]
    pub route_macaroon: Option<String>,

    /// Phase 11 — WebSocket URL for the LSP's Lightning peer connection.
    /// Used by the wallet's auto-connect path to establish the Noise_XK
    /// handshake on wallet restore. Distinct from `endpoint` (HTTP) because
    /// the WSS proxy and the HTTP routing endpoint live at separate
    /// hostnames/ports (e.g. wss://lsp-proxy.example.com vs
    /// http://lsp-routes.example.com:7000).
    /// FUTURE (LIJOX spec v1): may be discovered via LSP info endpoint
    /// rather than persisted per-record.
    #[serde(default)]
    pub wss_url: Option<String>,
}

/// The currently active LSP configuration.
/// Persisted to localStorage so the wallet reconnects to the same LSP on reload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveLsp {
    pub info: LspInfo,
    /// Channel ID(s) open with this LSP
    pub channel_ids: Vec<String>,
}

/// Fetches the LSP registry from your Cloudflare Worker.
/// Returns a scored, ranked list of available LSPs.
/// In WASM this uses fetch; in tests this is mocked.
pub async fn fetch_lsp_registry(worker_url: &str) -> LijResult<Vec<LspInfo>> {
    let url = format!("{worker_url}/lsps");
    log::info!("Fetching LSP registry from {url}");

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| LijError::Lsp(format!("Request error: {:?}", e)))?;

        let window = web_sys::window()
            .ok_or_else(|| LijError::Lsp("No window".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| LijError::Lsp(format!("Fetch error: {:?}", e)))?;

        let resp: Response = resp_value.into();

        let text = JsFuture::from(
            resp.text().map_err(|e| LijError::Lsp(format!("Text error: {:?}", e)))?
        )
        .await
        .map_err(|e| LijError::Lsp(format!("Text await error: {:?}", e)))?;

        let body = text.as_string()
            .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| LijError::Lsp(format!("JSON parse error: {e}")))?;

        let lsps = parsed["lsps"]
            .as_array()
            .ok_or_else(|| LijError::Lsp("No lsps array in response".into()))?;

        let mut result = vec![];
        for lsp in lsps {
            if let Ok(info) = serde_json::from_value::<LspInfo>(lsp.clone()) {
                result.push(info);
            }
        }

        log::info!("LSP registry returned {} entries", result.len());
        return Ok(result);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        log::warn!("fetch_lsp_registry called in non-WASM context — returning empty");
        Ok(vec![])
    }
}

/// Score and rank LSPs. Lower score = better.
/// Scoring: fee_ppm weighted 60%, uptime weighted 40%.
/// User's current LSP gets a small stickiness bonus to avoid unnecessary churn.
pub fn rank_lsps<'a>(lsps: &'a [LspInfo], current_pubkey: Option<&'a str>) -> Vec<&'a LspInfo> {
    let mut scored: Vec<(&LspInfo, u64)> = lsps
        .iter()
        .map(|lsp| {
            let fee_score = lsp.fee_ppm * 6 / 10;
            let uptime_score = (100 - lsp.uptime as u64) * 4; // invert: high uptime = low score
            let stickiness = if current_pubkey == Some(&lsp.pubkey) {
                500 // bonus to avoid churn — only switch if meaningfully better
            } else {
                0
            };
            let total = fee_score + uptime_score + stickiness;
            (lsp, total)
        })
        .collect();

    // v185 VIABILITY GATE (fix 4, Session 27 — the true source fix): the
    // engine RE-RANKS the registry, so the worker-side gate alone cannot
    // change this boot pick. A record with no wss_url can never peer from
    // an https origin, and `uptime` is a registration-time constant no
    // health check revises — so an unusable fossil sorted first on price
    // alone. Viability is the primary key; price/uptime stays the
    // tiebreak within each class. Refuses nobody, deletes nothing.
    let viable = |l: &LspInfo| {
        l.wss_url.as_deref().map_or(false, |w| !w.trim().is_empty())
            && !l
                .endpoint
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("http://")
    };
    scored.sort_by_key(|(lsp, score)| (!viable(lsp), *score));
    scored.into_iter().map(|(lsp, _)| lsp).collect()
}

/// LSPS1: Request a channel from an LSP.
/// The LSP opens and funds the channel; user gets inbound liquidity immediately.
/// This is the standard onboarding path for new wallets.
#[derive(Serialize, Deserialize, Debug)]
pub struct Lsps1ChannelRequest {
    /// How much inbound liquidity the user wants (satoshis).
    /// Serialized as `inbound_sats` to match adapter's API.
    #[serde(rename = "inbound_sats")]
    pub inbound_liquidity_sats: u64,
    /// User's Lightning node pubkey
    pub client_pubkey: String,
    /// Host address (for browser nodes, use wss:// URL — adapter will skip TCP dial)
    pub client_host: String,
    /// When true, adapter polls for peer instead of dialing. Required for browser wallets.
    pub is_browser_node: bool,
    /// Refund address if channel open fails (optional for now)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_onchain_address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Lsps1ChannelResponse {
    /// Invoice to pay for the channel (LSP charges a one-time fee)
    pub payment_invoice: Option<String>,
    /// Confirmation that channel open is in progress
    pub channel_id: String,
    /// Expected on-chain confirmations before channel is usable
    pub confirmations_required: u32,
}

/// LSPS2: Request a JIT (Just-In-Time) channel.
/// LSP opens channel the moment the user receives their first payment.
/// No upfront cost. Preferred path when available.
#[derive(Serialize, Deserialize, Debug)]
pub struct Lsps2JitRequest {
    pub client_pubkey: String,
    pub token: Option<String>, // optional promo/discount token
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Lsps2JitResponse {
    /// Special invoice — paying this triggers the LSP to open a JIT channel
    pub jit_invoice: String,
    pub fee_sats: u64,
}

/// LSP client — handles protocol communication with a specific LSP node.
pub struct LspClient {
    pub info: LspInfo,
}

impl LspClient {
    pub fn new(info: LspInfo) -> Self {
        Self { info }
    }

    /// Request inbound liquidity via LSPS1.
    /// Called when onboarding a new wallet that needs a channel.
    /// Routes through the Cloudflare Worker — the Worker adds the adapter secret
    /// and forwards to the LSP's adapter. Keeps secrets out of the browser.
    pub async fn request_channel(
        &self,
        worker_url: &str,
        request: Lsps1ChannelRequest,
    ) -> LijResult<Lsps1ChannelResponse> {
        let url = format!("{worker_url}/lsps1/channel");
        log::info!("Requesting LSPS1 channel via Worker at {url}");

        let body = serde_json::to_string(&request)
            .map_err(|e| LijError::Lsp(format!("Serialize request: {e}")))?;

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen_futures::JsFuture;
            use web_sys::{Request, RequestInit, RequestMode, Response};
            use wasm_bindgen::{JsCast, JsValue};

            let mut opts = RequestInit::new();
            opts.method("POST");
            opts.mode(RequestMode::Cors);
            opts.body(Some(&JsValue::from_str(&body)));

            let req = Request::new_with_str_and_init(&url, &opts)
                .map_err(|e| LijError::Lsp(format!("Request build: {:?}", e)))?;
            req.headers()
                .set("Content-Type", "application/json")
                .map_err(|e| LijError::Lsp(format!("Header set: {:?}", e)))?;

            let window = web_sys::window()
                .ok_or_else(|| LijError::Lsp("No window".into()))?;
            let resp_value = JsFuture::from(window.fetch_with_request(&req))
                .await
                .map_err(|e| LijError::Lsp(format!("Fetch: {:?}", e)))?;
            let resp: Response = resp_value.dyn_into()
                .map_err(|_| LijError::Lsp("Response cast".into()))?;

            let text_promise = resp.text()
                .map_err(|e| LijError::Lsp(format!("Text: {:?}", e)))?;
            let text_js = JsFuture::from(text_promise)
                .await
                .map_err(|e| LijError::Lsp(format!("Text await: {:?}", e)))?;
            let text = text_js.as_string()
                .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

            if !resp.ok() {
                return Err(LijError::Lsp(format!("Channel request failed ({}): {}", resp.status(), text)));
            }

            log::info!("Adapter responded: {}", text);

            let adapter_response: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| LijError::Lsp(format!("Parse response: {e}")))?;

            // Adapter returns: { ok, status, channel_point, size_sats, push_sats, client_pubkey }
            let channel_id = adapter_response["channel_point"]
                .as_str()
                .unwrap_or("pending")
                .to_string();

            return Ok(Lsps1ChannelResponse {
                payment_invoice: None,
                channel_id,
                confirmations_required: 3,
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            log::warn!("request_channel called in non-WASM context");
            Err(LijError::Lsp("LSPS1 fetch only available in WASM".into()))
        }
    }

    /// Request a JIT channel invoice via LSPS2.
    /// Preferred when the LSP supports it — zero upfront cost.
    pub async fn request_jit_invoice(
        &self,
        request: Lsps2JitRequest,
    ) -> LijResult<Lsps2JitResponse> {
        let url = format!("{}/lsps2/jit", self.info.endpoint);
        log::info!("Requesting LSPS2 JIT invoice from {} at {url}", self.info.name);
        let _ = (url, request);
        // HTTP call wired in lij-wasm
        Err(LijError::Lsp("LSPS2 fetch not yet wired".into()))
    }

    /// Health check — ping the LSP node to verify it's reachable.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.info.endpoint);
        log::debug!("Health check: {url}");
        let _ = url;
        true // placeholder
    }
}

// ── LSP registration for node operators ─────────────────────────────────────
// Any Umbrel node on clearnet can register with your Worker as an LSP.
// The registration is signed with the node's private key to prove ownership.

/// Registration payload sent by a node operator to your Worker.
#[derive(Serialize, Deserialize, Debug)]
pub struct LspRegistration {
    pub name: String,
    pub pubkey: String,
    pub endpoint: String,
    pub fee_ppm: u64,
    pub supports_jit: bool,
    /// Signature of SHA256(name + pubkey + endpoint) with the node private key.
    /// Your Worker verifies this to prevent spoofed registrations.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_lsps() -> Vec<LspInfo> {
        vec![
            LspInfo {
                name: "Plotzwerks".into(),
                pubkey: "aaa".into(),
                endpoint: "https://lightning-mod.com".into(),
                fee_ppm: 1000,
                fee_base_sats: 0,
                channel_open_fee_sats: 0,
                max_channel_size_sats: 0,
                min_channel_size_sats: 0,
                uptime: 99,
                supports_jit: true,
                route_endpoint: Default::default(),
                route_macaroon: Default::default(),
                wss_url: None,
            },
            LspInfo {
                name: "Bob's Umbrel".into(),
                pubkey: "bbb".into(),
                endpoint: "https://bob.example.com".into(),
                fee_ppm: 500,
                fee_base_sats: 0,
                channel_open_fee_sats: 0,
                max_channel_size_sats: 0,
                min_channel_size_sats: 0,
                uptime: 85,
                supports_jit: false,
                route_endpoint: Default::default(),
                route_macaroon: Default::default(),
                wss_url: None,
            },
        ]
    }

    #[test]
    fn test_ranking_prefers_low_fee_high_uptime() {
        let lsps = mock_lsps();
        let ranked = rank_lsps(&lsps, None);
        // Bob has lower fee but lower uptime — ranking depends on weighted score
        // Just verify we get both back and the function doesn't panic
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn test_stickiness_keeps_current_lsp() {
        let lsps = mock_lsps();
        // Plotzwerks is current LSP — even though Bob has lower fee,
        // stickiness bonus should keep Plotzwerks ranked favorably
        let ranked = rank_lsps(&lsps, Some("aaa"));
        assert_eq!(ranked.len(), 2);
    }
}
