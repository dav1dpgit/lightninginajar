// lij-core/src/lsps2.rs
// LSPS2 client — JIT channel discovery and promise acquisition.
//
// This module talks to a LIJOX adapter v0.16+ that implements the LSPS2
// Phase A endpoints (/lsps2/get_info, /lsps2/buy). The wallet uses these
// to discover an LSP's JIT service terms (pricing, limits) and to obtain
// a JIT channel promise.
//
// The actual channel-open happens in Phase D, when an HTLC arrives at
// the LSP carrying the jit_channel_scid that the wallet embedded in its
// invoice's route_hint. Phase B (this module) and Phase C (route-hint
// integration) are the wallet-side scaffolding; Phase D is the adapter-side
// htlc-interceptor that makes the channel actually open.
//
// Architecture note: LSPS2 endpoints are called DIRECTLY from the wallet
// to the LSP adapter (via the Cloudflare-fronted HTTPS tunnel), not via
// the LIJOX Worker. The auth model is the shared route_macaroon published
// in the LIJOX registry — see docs/TUNNELS.md "Security model" for the
// rationale.

use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};

// ── Response types ───────────────────────────────────────────────────────────

/// Response from `GET /lsps2/get_info` on a LIJOX adapter v0.16+.
///
/// Combines LSPS2 protocol fields (machine-readable) with LIJOX extension
/// fields (human-readable display strings, pricing transparency).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lsps2GetInfoResponse {
    // ── Protocol fields (LSPS2 standard) ──
    pub supported_versions: Vec<u32>,
    /// Stringified u64 — adapter serializes large msat values as strings
    /// for JSON safety. Use [`Lsps2GetInfoResponse::min_payment_size_msat_u64`]
    /// for parsed access.
    pub min_payment_size_msat: String,
    pub max_payment_size_msat: String,
    pub base_fee_msat: String,
    pub fee_ppm: u64,
    pub promise_validity_secs: u64,
    pub client_trusts_lsp: bool,
    /// v217 (S36, O5 full balance availability): ADVISORY payer-funds-the-floor
    /// prefund (stringified msat; adapter 0.56.0+). Absent on older adapters —
    /// serde(default) keeps them parsing. The buy response's stamp is BINDING.
    #[serde(default)]
    pub prefund_msat: Option<String>,

    // ── LIJOX extension fields ──
    pub channel_open_fee_sats: u64,
    /// "direct" today; "superscalar_leaf" when SuperScalar channel factories
    /// ship. Allows wallets to distinguish per-channel vs. factory-leaf
    /// service models without a breaking schema change.
    pub channel_model: String,

    // ── Human-readable display strings ──
    pub human_summary: String,
    pub fee_pct_display: String,
    pub fee_sat_per_send_display: String,
    pub channel_open_fee_display: String,

    // ── Pricing transparency ──
    pub pricing_inputs: Lsps2PricingInputs,

    /// v188 (S27): open/variable-mode terms. #[serde(default)] so
    /// pre-v188 adapters (field absent) parse cleanly to None and the
    /// engine refuses open-amount JIT gracefully.
    #[serde(default)]
    pub variable: Option<Lsps2VariableInfo>,
}

/// Pricing inputs that drive the fee fields — exposed for transparency,
/// not used at runtime. Documented in `docs/LSP_PRICING.md`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lsps2PricingInputs {
    pub capital_apr_bps: u32,
    pub expected_lifetime_days: u32,
    pub force_close_probability_bps: u32,
    pub adversarial_reserve_bps: u32,
}

/// v188 (S27): variable/open-amount JIT terms. Present only on adapters
/// that support zero-amount invoices (LSPS2_VAR_ENABLED). The deduction
/// at quiescence flush is max(min_fee_msat, ceil(sum * fee_ppm / 1e6));
/// the invoice route-hint carries fee_ppm (base 0) so senders price it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lsps2VariableInfo {
    pub enabled: bool,
    pub fee_ppm: u64,
    /// Stringified u64 msat (adapter JSON-safety convention).
    pub min_fee_msat: String,
}

impl Lsps2VariableInfo {
    pub fn min_fee_msat_u64(&self) -> LijResult<u64> {
        self.min_fee_msat.parse()
            .map_err(|e| LijError::Lsp(format!("Invalid variable.min_fee_msat: {e}")))
    }
}

impl Lsps2GetInfoResponse {
    /// v217 (O5): advisory prefund in msat — 0 when absent (older adapters).
    pub fn prefund_msat_u64(&self) -> u64 {
        self.prefund_msat.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    /// Parse the stringified `min_payment_size_msat` into a u64.
    pub fn min_payment_size_msat_u64(&self) -> LijResult<u64> {
        self.min_payment_size_msat.parse()
            .map_err(|e| LijError::Lsp(format!("Invalid min_payment_size_msat: {e}")))
    }

    /// Parse the stringified `max_payment_size_msat` into a u64.
    pub fn max_payment_size_msat_u64(&self) -> LijResult<u64> {
        self.max_payment_size_msat.parse()
            .map_err(|e| LijError::Lsp(format!("Invalid max_payment_size_msat: {e}")))
    }

    /// Parse the stringified `base_fee_msat` into a u64.
    pub fn base_fee_msat_u64(&self) -> LijResult<u64> {
        self.base_fee_msat.parse()
            .map_err(|e| LijError::Lsp(format!("Invalid base_fee_msat: {e}")))
    }
}

// ── Request type for /lsps2/buy ──────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lsps2BuyRequest {
    pub version: u32,
    /// v188 (S27): None = OPEN/VARIABLE mode (zero-amount invoice) — the
    /// field is omitted from the wire entirely; the adapter sizes the JIT
    /// channel from the observed shard sum at quiescence flush. Some(n)
    /// serializes as the bare number: fixed-mode wire is byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_size_msat: Option<u64>,
    /// Phase A.1: hex-encoded node pubkey of the wallet that will receive
    /// payments via this JIT promise. REQUIRED — the LSP needs this to know
    /// where to open the channel when an HTLC arrives matching the promise.
    /// 66 hex chars (33-byte compressed secp256k1 pubkey).
    pub client_pubkey: String,
    /// Optional discount/promo token. Ignored by adapter Phase A; reserved
    /// for paid-tier flows in future.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

// ── Response type for /lsps2/buy ─────────────────────────────────────────────

/// Response from `POST /lsps2/buy` on a LIJOX adapter v0.16+.
///
/// `jit_channel_scid` is an 8-byte (16 hex char) opaque SCID alias the
/// adapter assigns to this promise. The wallet embeds this SCID in the
/// route_hint of its BOLT11 invoice. When an HTLC arrives at the LSP
/// targeting this SCID, the htlc-interceptor (Phase D) recognizes the
/// promise, opens a zero-conf channel, and forwards the HTLC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lsps2BuyResponse {
    pub jit_channel_scid: String,
    pub lsp_pubkey: String,
    /// Stringified u64 — fee the LSP will charge for opening the channel.
    /// Use [`Lsps2BuyResponse::fee_msat_u64`] for parsed access.
    pub fee_msat: String,
    /// Millisecond Unix timestamp. After this time, the promise is invalid
    /// and the wallet must call /lsps2/buy again.
    pub promise_expires_at: u64,
    pub human_summary: String,
    /// v217 (O5): BINDING payer-funds-the-floor prefund for THIS promise
    /// (stringified msat; adapter 0.56.0+ stamps it). Absent = 0.
    #[serde(default)]
    pub prefund_msat: Option<String>,
}

impl Lsps2BuyResponse {
    /// Parse the stringified `fee_msat` into a u64.
    pub fn fee_msat_u64(&self) -> LijResult<u64> {
        self.fee_msat.parse()
            .map_err(|e| LijError::Lsp(format!("Invalid fee_msat: {e}")))
    }

    /// Returns true if the promise has expired relative to the given
    /// timestamp (ms since Unix epoch).
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.promise_expires_at
    }

    /// v217 (O5): the binding prefund in msat — 0 when absent (older
    /// adapters) or unparseable. Never errors: absence is the honest zero.
    pub fn prefund_msat_u64(&self) -> u64 {
        self.prefund_msat.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0)
    }
}

// ── Client functions ─────────────────────────────────────────────────────────

/// Fetch LSPS2 service terms from an LSP.
///
/// - `endpoint`: HTTPS base URL of the LSP adapter
///   (e.g. `"https://lijox-lsp.lightning-mod.com"`). Must NOT include the
///   `/lsps2/get_info` path — this function appends it.
/// - `route_macaroon`: shared LSP capability token, as published in the
///   LIJOX registry's `route_macaroon` field. Sent as the
///   `grpc-metadata-macaroon` header per the adapter's auth convention.
///
/// Returns the parsed service terms on success, or `LijError::Lsp` on
/// network failure, HTTP error, or JSON parse failure. The error message
/// includes the HTTP status and (for parse errors) the raw response body
/// for forensic diagnosis.
pub async fn fetch_lsps2_info(
    endpoint: &str,
    route_macaroon: &str,
) -> LijResult<Lsps2GetInfoResponse> {
    let url = format!("{endpoint}/lsps2/get_info");
    log::info!("Fetching LSPS2 info from {url}");

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| LijError::Lsp(format!("Request build: {:?}", e)))?;
        request.headers()
            .set("grpc-metadata-macaroon", route_macaroon)
            .map_err(|e| LijError::Lsp(format!("Header set: {:?}", e)))?;

        let window = web_sys::window()
            .ok_or_else(|| LijError::Lsp("No window".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| LijError::Lsp(format!("Fetch: {:?}", e)))?;
        let resp: Response = resp_value.dyn_into()
            .map_err(|_| LijError::Lsp("Response cast".into()))?;

        let text_promise = resp.text()
            .map_err(|e| LijError::Lsp(format!("Text promise: {:?}", e)))?;
        let text_js = JsFuture::from(text_promise)
            .await
            .map_err(|e| LijError::Lsp(format!("Text await: {:?}", e)))?;
        let text = text_js.as_string()
            .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

        if !resp.ok() {
            return Err(LijError::Lsp(format!("get_info HTTP {} — {}", resp.status(), text)));
        }

        let parsed: Lsps2GetInfoResponse = serde_json::from_str(&text)
            .map_err(|e| LijError::Lsp(format!("Parse get_info response: {e} — body: {text}")))?;
        Ok(parsed)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (url, route_macaroon);
        Err(LijError::Lsp("fetch_lsps2_info: HTTP only available in WASM".into()))
    }
}

/// Request a JIT channel promise for inbound `payment_size_msat`.
///
/// - `endpoint`: HTTPS base URL of the LSP adapter.
/// - `route_macaroon`: shared LSP capability token (same source as for
///   [`fetch_lsps2_info`]).
/// - `payment_size_msat`: amount of inbound capacity the wallet wants for
///   its upcoming receive. Must be within the LSP's
///   `[min_payment_size_msat, max_payment_size_msat]` range, otherwise the
///   adapter responds 400.
///
/// Returns a [`Lsps2BuyResponse`] containing the `jit_channel_scid` to embed
/// in the BOLT11 route_hint (Phase C), the fee the LSP will charge at HTLC
/// time, and the promise expiry. The wallet should treat the promise as
/// opaque and not commit any user-visible state to it until Phase C / D
/// wire the receive flow.
pub async fn lsps2_buy(
    endpoint: &str,
    route_macaroon: &str,
    payment_size_msat: Option<u64>,
    client_pubkey: &str,
) -> LijResult<Lsps2BuyResponse> {
    let url = format!("{endpoint}/lsps2/buy");
    log::info!(
        "Requesting LSPS2 buy from {url} for {:?} msat (pubkey {}...) — None = open/variable (v188)",
        payment_size_msat,
        &client_pubkey[..16.min(client_pubkey.len())]
    );

    // Phase A.1: validate pubkey shape before sending (cheap; saves a round-trip).
    if client_pubkey.len() != 66 || !client_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LijError::Lsp(format!(
            "lsps2_buy: client_pubkey must be 66 hex chars, got {}",
            client_pubkey.len()
        )));
    }

    let body = Lsps2BuyRequest {
        version: 1,
        payment_size_msat,
        client_pubkey: client_pubkey.to_string(),
        token: None,
    };
    let body_json = serde_json::to_string(&body)
        .map_err(|e| LijError::Lsp(format!("Serialize buy request: {e}")))?;

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(&body_json));

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| LijError::Lsp(format!("Request build: {:?}", e)))?;
        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| LijError::Lsp(format!("Content-Type set: {:?}", e)))?;
        request.headers()
            .set("grpc-metadata-macaroon", route_macaroon)
            .map_err(|e| LijError::Lsp(format!("Auth header set: {:?}", e)))?;

        let window = web_sys::window()
            .ok_or_else(|| LijError::Lsp("No window".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| LijError::Lsp(format!("Fetch: {:?}", e)))?;
        let resp: Response = resp_value.dyn_into()
            .map_err(|_| LijError::Lsp("Response cast".into()))?;

        let text_promise = resp.text()
            .map_err(|e| LijError::Lsp(format!("Text promise: {:?}", e)))?;
        let text_js = JsFuture::from(text_promise)
            .await
            .map_err(|e| LijError::Lsp(format!("Text await: {:?}", e)))?;
        let text = text_js.as_string()
            .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

        if !resp.ok() {
            return Err(LijError::Lsp(format!("buy HTTP {} — {}", resp.status(), text)));
        }

        let parsed: Lsps2BuyResponse = serde_json::from_str(&text)
            .map_err(|e| LijError::Lsp(format!("Parse buy response: {e} — body: {text}")))?;
        Ok(parsed)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (url, body_json, route_macaroon);
        Err(LijError::Lsp("lsps2_buy: HTTP only available in WASM".into()))
    }
}

/// Option B: register the BOLT11 payment_secret with the LSP for a JIT promise.
///
/// Called right after the wallet builds its JIT invoice and BEFORE the invoice is
/// shown/shared, so the secret is in place before any payment can arrive. The LSP
/// needs it to rebuild the final hop in sendToRouteV2 -- the secret lives in the
/// wallet's final-hop onion layer, which the LSP (penultimate hop) cannot decrypt.
/// NOT the preimage: it cannot be used to claim funds.
///
/// - `jit_channel_scid`: 16-hex SCID from the buy response (the promise key).
/// - `payment_secret_hex`: hex-encoded 32-byte payment_secret (payment_addr).
/// - `total_msat`: the NET the wallet will receive (== invoice amount - open fee);
///   used as the MPP total in the LSP's sendToRouteV2 final hop.
pub async fn lsps2_register_secret(
    endpoint: &str,
    route_macaroon: &str,
    jit_channel_scid: &str,
    payment_secret_hex: &str,
    total_msat: u64,
) -> LijResult<()> {
    let url = format!("{endpoint}/lsps2/register_secret");
    log::info!(
        "Registering JIT payment_secret with LSP: scid={jit_channel_scid} total_msat={total_msat}"
    );

    // Fields are hex / integer (no escaping hazards) -- build JSON directly.
    let body_json = format!(
        r#"{{"jit_channel_scid":"{}","payment_secret":"{}","total_msat":{}}}"#,
        jit_channel_scid, payment_secret_hex, total_msat
    );

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(&body_json));

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| LijError::Lsp(format!("Request build: {:?}", e)))?;
        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| LijError::Lsp(format!("Content-Type set: {:?}", e)))?;
        request.headers()
            .set("grpc-metadata-macaroon", route_macaroon)
            .map_err(|e| LijError::Lsp(format!("Auth header set: {:?}", e)))?;

        let window = web_sys::window()
            .ok_or_else(|| LijError::Lsp("No window".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| LijError::Lsp(format!("Fetch: {:?}", e)))?;
        let resp: Response = resp_value.dyn_into()
            .map_err(|_| LijError::Lsp("Response cast".into()))?;

        let text_promise = resp.text()
            .map_err(|e| LijError::Lsp(format!("Text promise: {:?}", e)))?;
        let text_js = JsFuture::from(text_promise)
            .await
            .map_err(|e| LijError::Lsp(format!("Text await: {:?}", e)))?;
        let text = text_js.as_string()
            .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

        if !resp.ok() {
            return Err(LijError::Lsp(format!("register_secret HTTP {} -- {}", resp.status(), text)));
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (url, body_json, route_macaroon);
        Err(LijError::Lsp("lsps2_register_secret: HTTP only available in WASM".into()))
    }
}

/// v168: register a PLAIN invoice's payment_secret with the LSP, keyed by
/// payment_hash (no JIT promise exists). Enables trampoline settles of held
/// forwards when the sender is offline. Same endpoint; the adapter branches
/// on the presence of `payment_hash` (B-10).
pub async fn lsps2_register_invoice_secret(
    endpoint: &str,
    route_macaroon: &str,
    payment_hash_hex: &str,
    payment_secret_hex: &str,
    total_msat: u64,
) -> LijResult<()> {
    let url = format!("{endpoint}/lsps2/register_secret");
    log::info!(
        "Registering plain-invoice payment_secret with LSP: hash={payment_hash_hex} total_msat={total_msat}"
    );
    let body_json = format!(
        r#"{{"payment_hash":"{}","payment_secret":"{}","total_msat":{}}}"#,
        payment_hash_hex, payment_secret_hex, total_msat
    );

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(&body_json));

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| LijError::Lsp(format!("Request build: {:?}", e)))?;
        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| LijError::Lsp(format!("Content-Type set: {:?}", e)))?;
        request.headers()
            .set("grpc-metadata-macaroon", route_macaroon)
            .map_err(|e| LijError::Lsp(format!("Auth header set: {:?}", e)))?;

        let window = web_sys::window()
            .ok_or_else(|| LijError::Lsp("No window".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| LijError::Lsp(format!("Fetch: {:?}", e)))?;
        let resp: Response = resp_value.dyn_into()
            .map_err(|_| LijError::Lsp("Response cast".into()))?;

        let text_promise = resp.text()
            .map_err(|e| LijError::Lsp(format!("Text promise: {:?}", e)))?;
        let text_js = JsFuture::from(text_promise)
            .await
            .map_err(|e| LijError::Lsp(format!("Text await: {:?}", e)))?;
        let text = text_js.as_string()
            .ok_or_else(|| LijError::Lsp("Response not a string".into()))?;

        if !resp.ok() {
            return Err(LijError::Lsp(format!("register_invoice_secret HTTP {} -- {}", resp.status(), text)));
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (url, body_json, route_macaroon);
        Err(LijError::Lsp("lsps2_register_invoice_secret: HTTP only available in WASM".into()))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Canned response captured from a real v0.16 adapter
    /// (smoke test 3 of the deploy: curl /lsps2/get_info via Cloudflare).
    /// Pinning this here detects any future adapter changes that would
    /// break the wallet's parsing.
    const REAL_GET_INFO_RESPONSE: &str = r#"{
        "supported_versions": [1],
        "min_payment_size_msat": "1000000",
        "max_payment_size_msat": "1000000000",
        "base_fee_msat": "1000",
        "fee_ppm": 1000,
        "promise_validity_secs": 600,
        "client_trusts_lsp": true,
        "channel_open_fee_sats": 2500,
        "channel_model": "direct",
        "human_summary": "Channel opening: 2,500 sats. Sending: 0.10% + 1 sat per payment. Your offer is valid for 10 minutes.",
        "fee_pct_display": "0.10%",
        "fee_sat_per_send_display": "1 sat + 0.10% per send",
        "channel_open_fee_display": "2,500 sats",
        "pricing_inputs": {
            "capital_apr_bps": 80,
            "expected_lifetime_days": 90,
            "force_close_probability_bps": 1000,
            "adversarial_reserve_bps": 500
        }
    }"#;

    /// Canned buy response (smoke test 4 of the deploy).
    const REAL_BUY_RESPONSE: &str = r#"{
        "jit_channel_scid": "9b7eab0ee34f496a",
        "lsp_pubkey": "03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c",
        "fee_msat": "2500000",
        "promise_expires_at": 1779758719380,
        "human_summary": "Pay 2,500 sats to open a channel. You'll be able to receive up to 50,000 sats after this. Offer valid for 10 minutes."
    }"#;

    #[test]
    fn parses_real_get_info_response() {
        let parsed: Lsps2GetInfoResponse = serde_json::from_str(REAL_GET_INFO_RESPONSE)
            .expect("real get_info response must parse");
        assert_eq!(parsed.supported_versions, vec![1]);
        assert_eq!(parsed.fee_ppm, 1000);
        assert_eq!(parsed.promise_validity_secs, 600);
        assert!(parsed.client_trusts_lsp);
        assert_eq!(parsed.channel_open_fee_sats, 2500);
        assert_eq!(parsed.channel_model, "direct");
        assert_eq!(parsed.pricing_inputs.capital_apr_bps, 80);
        assert_eq!(parsed.pricing_inputs.expected_lifetime_days, 90);
        assert_eq!(parsed.pricing_inputs.force_close_probability_bps, 1000);
        assert_eq!(parsed.pricing_inputs.adversarial_reserve_bps, 500);
    }

    #[test]
    fn get_info_u64_accessors_work() {
        let parsed: Lsps2GetInfoResponse =
            serde_json::from_str(REAL_GET_INFO_RESPONSE).unwrap();
        assert_eq!(parsed.min_payment_size_msat_u64().unwrap(), 1_000_000);
        assert_eq!(parsed.max_payment_size_msat_u64().unwrap(), 1_000_000_000);
        assert_eq!(parsed.base_fee_msat_u64().unwrap(), 1000);
    }

    #[test]
    fn parses_real_buy_response() {
        let parsed: Lsps2BuyResponse = serde_json::from_str(REAL_BUY_RESPONSE)
            .expect("real buy response must parse");
        assert_eq!(parsed.jit_channel_scid.len(), 16, "scid must be 8 bytes hex");
        assert!(parsed.jit_channel_scid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(parsed.lsp_pubkey.len(), 66);
        assert_eq!(parsed.fee_msat_u64().unwrap(), 2_500_000);
        assert_eq!(parsed.promise_expires_at, 1_779_758_719_380);
    }

    #[test]
    fn buy_request_serializes_without_token() {
        let req = Lsps2BuyRequest {
            version: 1,
            payment_size_msat: Some(50_000_000),
            client_pubkey: "03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c".into(),
            token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        // skip_serializing_if = Option::is_none means no "token":null field
        assert_eq!(json, r#"{"version":1,"payment_size_msat":50000000,"client_pubkey":"03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c"}"#);
    }

    #[test]
    fn buy_request_serializes_with_token() {
        let req = Lsps2BuyRequest {
            version: 1,
            payment_size_msat: Some(50_000_000),
            client_pubkey: "03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c".into(),
            token: Some("promo-abc".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"version":1,"payment_size_msat":50000000,"client_pubkey":"03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c","token":"promo-abc"}"#
        );
    }

    #[test]
    fn buy_response_expiry_check() {
        let parsed: Lsps2BuyResponse = serde_json::from_str(REAL_BUY_RESPONSE).unwrap();
        assert!(parsed.is_expired_at(parsed.promise_expires_at));
        assert!(parsed.is_expired_at(parsed.promise_expires_at + 1));
        assert!(!parsed.is_expired_at(parsed.promise_expires_at - 1));
    }

    #[test]
    fn rejects_garbage_get_info() {
        let r: Result<Lsps2GetInfoResponse, _> = serde_json::from_str("{}");
        assert!(r.is_err(), "must reject empty object");
        let r: Result<Lsps2GetInfoResponse, _> = serde_json::from_str(r#"{"fee_ppm": 1000}"#);
        assert!(r.is_err(), "must reject partial object");
    }

    #[test]
    fn rejects_garbage_buy() {
        let r: Result<Lsps2BuyResponse, _> = serde_json::from_str("{}");
        assert!(r.is_err(), "must reject empty object");
        let r: Result<Lsps2BuyResponse, _> =
            serde_json::from_str(r#"{"jit_channel_scid":"abc"}"#);
        assert!(r.is_err(), "must reject partial object");
    }
}

