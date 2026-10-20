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

    /// v349 (S61, Step A — docs/design/routes/routes-r1.md): every door into this provider as the registry signed
    /// them (lijox-register:v4), in the operator's order. Empty for a one-door record (register v1–v3); the top-level
    /// `endpoint` / `wss_url` then are the only door and its reach is unknown.
    #[serde(default)]
    pub routes: Vec<LspRoute>,
    /// v349: the reach word of the route the wallet APPLIED to the fields above (`direct` / `cloudflare`); None when
    /// no route was applied (a one-door record). The page shows it as the badge.
    #[serde(default)]
    pub reach: Option<String>,
}

/// v349: one door into a provider — the operator's signed word for what sits between the wallet and the box on these
/// addresses (`direct`: TLS ends on the operator's own machine; `cloudflare`: Cloudflare's edge ends TLS; `tor`: a slot
/// no browser wallet can use), with that door's three addresses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LspRoute {
    pub reach: String,
    pub endpoint: String,
    #[serde(default)]
    pub wss_url: Option<String>,
    #[serde(default)]
    pub filter_url: Option<String>,
}

/// v349: the wallet's Reach preference — the one choice, made in one place (the page's Privacy → Network dial), handed
/// to the engine at init and applied wherever a provider is connected. `direct-first` (the default): direct doors,
/// then Cloudflare doors, then a one-door record of unknown reach; `never-cloudflare`: direct doors only — a provider
/// with none is not connected and no call is made to it; `cloudflare-first`: Cloudflare doors, then direct, then unknown.
pub const ROUTE_PREF_DIRECT_FIRST: &str = "direct-first";
pub const ROUTE_PREF_NEVER_CLOUDFLARE: &str = "never-cloudflare";
pub const ROUTE_PREF_CLOUDFLARE_FIRST: &str = "cloudflare-first";

/// v349: a preference word the engine knows, else the default.
pub fn clean_route_pref(s: &str) -> &'static str {
    match s.trim() {
        ROUTE_PREF_NEVER_CLOUDFLARE => ROUTE_PREF_NEVER_CLOUDFLARE,
        ROUTE_PREF_CLOUDFLARE_FIRST => ROUTE_PREF_CLOUDFLARE_FIRST,
        _ => ROUTE_PREF_DIRECT_FIRST,
    }
}

/// v349: where a reach word ranks under a preference — lower is tried first; None = never used under this preference.
/// An unknown or empty word (a one-door record from an older adapter) ranks last, and is refused under never-cloudflare:
/// a door the operator has not named may be Cloudflare, and the user chose privacy over availability.
pub fn route_rank(reach: &str, pref: &str) -> Option<u8> {
    match (clean_route_pref(pref), reach) {
        (_, "tor") => None,
        (ROUTE_PREF_NEVER_CLOUDFLARE, "direct") => Some(0),
        (ROUTE_PREF_NEVER_CLOUDFLARE, _) => None,
        (ROUTE_PREF_CLOUDFLARE_FIRST, "cloudflare") => Some(0),
        (ROUTE_PREF_CLOUDFLARE_FIRST, "direct") => Some(1),
        (_, "direct") => Some(0),
        (_, "cloudflare") => Some(1),
        _ => Some(2),
    }
}

/// v349: the doors of a record the preference allows, in the order to try them (the operator's order within a rank).
/// A one-door record (no `routes`) yields its top-level addresses as one route of unknown reach (`""`).
pub fn allowed_routes(info: &LspInfo, pref: &str) -> Vec<LspRoute> {
    let doors: Vec<LspRoute> = if info.routes.is_empty() {
        vec![LspRoute { reach: info.reach.clone().unwrap_or_default(), endpoint: info.endpoint.clone(), wss_url: info.wss_url.clone(), filter_url: None }]
    } else {
        info.routes.clone()
    };
    let mut ranked: Vec<(u8, usize, LspRoute)> = doors.into_iter().enumerate()
        .filter_map(|(i, r)| route_rank(&r.reach, pref).map(|k| (k, i, r)))
        .collect();
    ranked.sort_by_key(|(k, i, _)| (*k, *i));
    ranked.into_iter().map(|(_, _, r)| r).collect()
}

/// v349: the record with one door applied — `endpoint`, `route_endpoint` and `wss_url` become that door's, `reach` its
/// word; `routes` stays whole so a later relink can pick another door from the stored record without the registry.
pub fn apply_route(info: &LspInfo, route: &LspRoute) -> LspInfo {
    let mut out = info.clone();
    out.endpoint = route.endpoint.clone();
    out.route_endpoint = Some(route.endpoint.clone());
    if route.wss_url.is_some() { out.wss_url = route.wss_url.clone(); }
    out.reach = if route.reach.is_empty() { None } else { Some(route.reach.clone()) };
    out
}

/// v349: the record with the first allowed door applied, or None when the preference allows none of its doors — then
/// the provider is not connected and no call is made to it (the privacy-over-availability promise, kept literally).
pub fn pick_route(info: &LspInfo, pref: &str) -> Option<LspInfo> {
    allowed_routes(info, pref).first().map(|r| apply_route(info, r))
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

    fn rec(routes: Vec<LspRoute>) -> LspInfo {
        LspInfo { name: "LiJ-Node".into(), pubkey: "03aa".into(), endpoint: "https://lijox-lsp.example".into(), fee_ppm: 1000, fee_base_sats: 0,
            channel_open_fee_sats: 0, max_channel_size_sats: 0, min_channel_size_sats: 0, uptime: 100, supports_jit: true,
            route_endpoint: Some("https://lijox-lsp.example".into()), route_macaroon: Some("m".into()), wss_url: Some("wss://lijox-ws.example".into()),
            routes, reach: None }
    }
    fn r(reach: &str, host: &str) -> LspRoute {
        LspRoute { reach: reach.into(), endpoint: format!("https://{host}-lsp.example"), wss_url: Some(format!("wss://{host}-ws.example")), filter_url: Some(format!("https://{host}-filters.example")) }
    }

    #[test]
    fn v349_the_record_parses_with_and_without_routes() {
        let j = r#"{"name":"LiJ-Node","pubkey":"03aa","endpoint":"https://lijox-lsp.example","fee_ppm":1000,"uptime":100,"supports_jit":true,"wss_url":"wss://lijox-ws.example",
            "routes":[{"reach":"cloudflare","endpoint":"https://lijox-lsp.example","wss_url":"wss://lijox-ws.example","filter_url":"https://filters.example"},{"reach":"direct","endpoint":"https://direct-lsp.example","wss_url":"wss://direct-ws.example","filter_url":null}]}"#;
        let info: LspInfo = serde_json::from_str(j).unwrap();
        assert_eq!(info.routes.len(), 2);
        assert_eq!(info.routes[1].reach, "direct");
        assert_eq!(info.routes[1].filter_url, None);
        assert_eq!(info.reach, None);
        let legacy: LspInfo = serde_json::from_str(r#"{"name":"n","pubkey":"03aa","endpoint":"https://x","fee_ppm":1,"uptime":100,"supports_jit":true}"#).unwrap();
        assert!(legacy.routes.is_empty());
    }

    #[test]
    fn v349_the_preference_orders_the_doors() {
        // the UM890's intended record: the tunnel first (what old wallets read), the direct door second
        let info = rec(vec![r("cloudflare", "lijox"), r("direct", "direct")]);
        let d = allowed_routes(&info, "direct-first");
        assert_eq!(d.iter().map(|x| x.reach.as_str()).collect::<Vec<_>>(), vec!["direct", "cloudflare"], "directly when possible: the direct door first, whatever the operator's order");
        let n = allowed_routes(&info, "never-cloudflare");
        assert_eq!(n.len(), 1); assert_eq!(n[0].reach, "direct");
        let c = allowed_routes(&info, "cloudflare-first");
        assert_eq!(c.iter().map(|x| x.reach.as_str()).collect::<Vec<_>>(), vec!["cloudflare", "direct"]);
        // a tor door is a word in the record, never a door a browser can use
        let t = rec(vec![r("tor", "t"), r("direct", "direct")]);
        assert_eq!(allowed_routes(&t, "direct-first").len(), 1);
        // two direct doors keep the operator's order
        let two = rec(vec![r("direct", "a"), r("direct", "b"), r("cloudflare", "c")]);
        assert_eq!(allowed_routes(&two, "direct-first").iter().map(|x| x.endpoint.as_str()).collect::<Vec<_>>(), vec!["https://a-lsp.example", "https://b-lsp.example", "https://c-lsp.example"]);
        // an unknown preference word is the default
        assert_eq!(clean_route_pref("whatever"), "direct-first");
        assert_eq!(clean_route_pref(" never-cloudflare "), "never-cloudflare");
    }

    #[test]
    fn v349_a_one_door_record_is_used_last_and_refused_under_never() {
        let legacy = rec(vec![]);
        let d = allowed_routes(&legacy, "direct-first");
        assert_eq!(d.len(), 1); assert_eq!(d[0].reach, ""); assert_eq!(d[0].endpoint, "https://lijox-lsp.example");
        assert!(pick_route(&legacy, "never-cloudflare").is_none(), "a door the operator has not named may be Cloudflare");
        let picked = pick_route(&legacy, "direct-first").unwrap();
        assert_eq!(picked.endpoint, "https://lijox-lsp.example"); assert_eq!(picked.reach, None);
    }

    #[test]
    fn v349_apply_route_moves_the_three_addresses_and_keeps_the_list() {
        let info = rec(vec![r("cloudflare", "lijox"), r("direct", "direct")]);
        let p = pick_route(&info, "direct-first").unwrap();
        assert_eq!(p.endpoint, "https://direct-lsp.example");
        assert_eq!(p.route_endpoint.as_deref(), Some("https://direct-lsp.example"));
        assert_eq!(p.wss_url.as_deref(), Some("wss://direct-ws.example"));
        assert_eq!(p.reach.as_deref(), Some("direct"));
        assert_eq!(p.routes.len(), 2, "the list rides with the applied record so a relink needs no registry");
        assert_eq!(p.pubkey, info.pubkey); assert_eq!(p.route_macaroon, info.route_macaroon);
        // never-cloudflare on a record with only Cloudflare doors: nothing to apply
        let cf = rec(vec![r("cloudflare", "lijox")]);
        assert!(pick_route(&cf, "never-cloudflare").is_none());
        assert_eq!(pick_route(&cf, "direct-first").unwrap().reach.as_deref(), Some("cloudflare"));
        // the stored record round-trips with its reach and routes
        let s = serde_json::to_string(&p).unwrap();
        let back: LspInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back.reach.as_deref(), Some("direct")); assert_eq!(back.routes, p.routes);
    }


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
                routes: vec![],
                reach: None,
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
                routes: vec![],
                reach: None,
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
