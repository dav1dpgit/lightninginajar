// lij-wasm/src/lib.rs
// The WASM bindings layer. Everything marked #[wasm_bindgen] becomes a
// JavaScript function or class that the PWA can call directly.
//
// This is the complete API surface of Lightning-in-a-Jar from the PWA's perspective.
// The PWA imports this as an npm package and calls these functions.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use std::sync::Arc;

use lij_core::{
    storage::wasm_storage::LocalStorage,
    types::WalletConfig,
    wallet::LijWallet,
};

// Thread-local storage for internal WebSocket callbacks to reach the wallet
// without round-tripping through JS.
thread_local! {
    static CURRENT_WALLET_INNER: std::cell::RefCell<Option<Arc<std::sync::Mutex<LijWallet>>>>
        = std::cell::RefCell::new(None);
}

fn set_current_wallet_inner(inner: Arc<std::sync::Mutex<LijWallet>>) {
    // v219 (DEFECT B, F4): a replaced instance's sockets must not keep feeding
    // the new PeerManager. Close them first; WS_MAP entries leave via their
    // own on_close path.
    ws_transport::close_all_sockets();
    CURRENT_WALLET_INNER.with(|slot| *slot.borrow_mut() = Some(inner));
}

fn current_wallet_inner() -> Option<Arc<std::sync::Mutex<LijWallet>>> {
    CURRENT_WALLET_INNER.with(|slot| slot.borrow().clone())
}

/// v227 (S43, speed): the event pass, run on the turn after inbound bytes.
/// try_lock only — if a send or the tick holds the wallet, the tick catches
/// up within a second exactly as before. Events seen ⇒ write the resulting
/// messages (claim / fulfill) now and flag the manager dirty so the next
/// tick's persistence fires as if the tick had seen them.
thread_local! {
    /// v227: at most ONE early pass queued at a time — a burst of inbound
    /// frames schedules one pass, not one per frame.
    static EARLY_PASS_PENDING: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

fn schedule_early_event_pass() {
    if EARLY_PASS_PENDING.with(|c| c.replace(true)) { return; }
    wasm_bindgen_futures::spawn_local(async {
        EARLY_PASS_PENDING.with(|c| c.set(false));
        early_event_pass();
    });
}

fn early_event_pass() {
    let inner = match current_wallet_inner() {
        Some(i) => i,
        None => return,
    };
    let wallet = match inner.try_lock() {
        Ok(w) => w,
        Err(_) => return,
    };
    let node = wallet.node();
    match node.process_channel_events() {
        Ok(true) => {
            node.mark_manager_dirty();
            node.pump_outbound();
        }
        Ok(false) => {}
        Err(e) => log::debug!("early_event_pass: skipped ({e})"),
    }
}

// ── Initialization ───────────────────────────────────────────────────────────

#[wasm_bindgen(start)]
pub fn lij_init() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();

    let dispatcher: std::sync::Arc<dyn lij_core::peer::SocketDispatcher> =
        std::sync::Arc::new(ws_transport::WsDispatcher);
    if let Err(e) = lij_core::peer::set_dispatcher(dispatcher) {
        log::error!("Failed to register WebSocket dispatcher: {e}");
    }

    log::info!("Lightning-in-a-Jar WASM initialized");
}

/// Build version of THIS compiled WASM binary. The frontend compares it to its
/// own LIJ_FRONTEND_VERSION; a mismatch means the deployed binary is stale
/// (an incremental build that skipped WASM regen). Bump on every WASM rebuild.
#[wasm_bindgen]
pub fn wasm_build_version() -> String {
    "phase11-v240".to_string()  // v240 (S45, DP: #14): BIP-352 silent payments, SEND side — an sp1q… destination in send_onchain (and its RBF bump) pays a one-time taproot output derived from the selected inputs (lij_core::silent_payment; gated by the BIP's own vectors natively). Receiving not yet.
    // v239 (S45): ChannelInfo.spendable_msat — the spendable lens in millisats for the exact Max. // v238 (S45, DP "truly 0"): send_payment_with_retries takes an exact millisat override for a no-amount invoice (single path; MPP parts stay whole sats) via prepare_lsp_route_request_msat. // v237 (S45, DP): quote_route_fee_to_pubkey — a route quote to a node key with no invoice, so Max can price an LNURL address served by another LSP before any invoice is minted. // v236 (S45, DP): CPFP is a user dial — automatic mode default OFF (set_coop_cpfp_auto), manual Speed up via coop_cpfp(channel_id, send) with a plan mode that shows the fee before the tap; the shared coop_cpfp() applies the automatic gates for the hold loop. // v235 (S45, DP GO): CPFP for a slow cooperative close — after 3 blocks pending, when the sweep rate is well above what the coop tx pays, the wallet spends the coop tx's output to itself with a child that lifts the package (one attempt per 6 blocks; records carry cpfp_txid_hex / cpfp_last_height). // v234 (S45): the watcher also recognises our commitment by shape for records that predate v233 (a cooperative record whose confirmed spend is not its intended tx and pays none of our addresses). // v233 (S45, DP GO): cooperative-close hold — LDK's startup rule (monitor without a manager channel → broadcast the holder commitment) held for cooperative closes this wallet signed that are still pending; rebroadcast; 144-block ceiling; records carry the coop tx + holder commitment txid; the watcher keeps polling until a spend CONFIRMS (intended → actual), relabels a lost race as Force, follows the sweep. // v232 (S43, DP GO): a ProcessingError closure is filed as CloseKind::Force — LDK force-closes on it — so the page's close-inbound bridge shows the returning sats in the mempool as for every other force-close (0a80ac8d had shown nothing until the closing tx confirmed). Prior — v231 (S43, DP GO after the 0a80ac8d force-close was read from the tape): background_tick now hands LDK the LSP\u2019s tip BEFORE the confirmations, holds any confirmation from a block above the accepted tip in the bridge until the tip reaches it, and persists on the tip advance (manager_dirty) — the stored best block can no longer sit one below a funding block, the state that made a later boot\u2019s replay of an older funding block force-close a ready channel. Prior — v230 (S43, DP field 2026-09-02 — "Add to Lightning" at Max twice, the second while the first funding tx sat in the mempool): channel_open::spendable_utxos now excludes outpoints reserved by a pending open/send, exactly as build_funding_tx has since v191, so spendable_total and max_channel_value (the sheet's Available and Max) drop to what is truly fundable the moment a tx is broadcast. Prior — v229 (S43, DP GO — the robust static-address design, replacing the v228 patch): (1) LNURLp preimages are DERIVED from the master key by index (RootKey::lnurlp_preimage, HKDF-SHA256, own salt) — nothing to back up, a wallet restored from its words recomputes every preimage; the local pool is a cache, and a claim that misses the cache searches derived indices (8192+) before failing back. (2) Each hash is registered in this engine for 30 YEARS (was 30 days — the cliff that killed every static address older than a month) and the same `expires` rides to the LSP in the registration JSON so the two sides can never disagree; `index` rides too, and the page passes the LSP's next_index back as a start hint so a restored wallet continues the sequence. Pairs with adapter 0.67.0 (honors expires, cancels the held original on a definitive refusal, reads LND for in-flight truth). Prior — v228 (S43, DP field 2026-09-02 — a same-LSP send to a wallet restored on a new iPhone hung twice, "payment failed"; the UM890 journal showed the LSP's 4 s belt bumping its own in-flight HTLCs): ROOT — the LNURLp preimage pool (lij_lnurlp_preimages, random per device, v195) was never in the backup bundle, so a restore on another device carried the channels and the registered hashes but not the preimages; every payment to the static address then arrived as a PaymentClaimable the wallet could not claim, and it hung until LDK's own expiry. FIX (1) the pool rides in the bundle (gather_state_blob; restores through the generic inject path). FIX (2) a readable pool that lacks the hash fails the HTLC back at once (fail_htlc_backwards after the closure) so the sender learns in a second; an unreadable pool keeps holding and looks again. Not caused by S43's speed work — the same hang existed on any version. Prior — v227 (S43, DP GO — same-LSP speed, engine half, under "extra careful nothing breaks at all"): (i) an internal send (dest == the active LSP) skips the route ask — the v222 self-hop never read the answer and adapter 0.62.1 answered a fixed empty body, which the engine now hands over verbatim; external destinations fetch exactly as before. (ii) a dispatched HTLC (every send_payment_with_route Ok arm: internal, external, MPP) is written to the wire immediately (pump_outbound = the tick's own pm.process_events) instead of waiting for the next tick. (iii) the ChannelManager event pass is extracted VERBATIM from background_tick into process_channel_events and ALSO run on the turn after inbound bytes (never inside the socket callback; try_lock, tick catches up otherwise) — a receiver claims when its HTLC lands, a sender learns "paid" when the fulfill arrives; events seen there flag manager_dirty so the next tick persists as before. Prior — v226 (S43, DP agreed — speed item 0, the cold-open first send): the boot's independent quorum round asked the four chain endpoints ONE AFTER ANOTHER with NO enforced timeout, and the Ready rule waited for the whole round, so the first send after a cold open failed "prepare" and retried on Ready ~2 s later (DP + Dan, 2026-09-01). Now: the four are asked concurrently (independent.rs query_all_each, FuturesUnordered), every WASM GET races a real 5 s timeout (REQUEST_TIMEOUT_SECS finally enforced), and the FIRST endpoint to answer reports early (SingleSource when nothing better stands, consensus height if empty, cold-start marked queried via a hook node.rs installs) so Ready lands on the first source that agrees with the LSP feed — the v225 floor — instead of after the slowest endpoint. Page v655 pairs (Ready retry poll 2 s → 0.5 s). Prior — v225 (S42, DP RULED — the v476 floor lands in the ENGINE): the send/Ready rule required 2 healthy independent chain sources; a phone at 1/4 (VPN, field 2026-09-01) could never reach Ready and every send sat at "finishing its chain check". Now ONE healthy source whose height agrees with the LSP's feed is enough for Ready (two agreeing sources); zero stays ReadOnly/dark. New QuorumState::SingleSource; the page keeps the on-chain face at 2-of-4. // v224 (S41, tester-zero DP): SELECTION LADDER — boot NEVER re-decides a provider (old auto_select re-ranked every boot; two tying providers broke on registry order and flipped funded wallets unpressed). Choice persisted by switch_lsp (full snapshot, registry-outage-proof) > channel counterparty > LiJ-Node default for fresh wallets > top viable listing only when the default is absent; LOYALTY OVER AVAILABILITY (a chosen/channeled provider down = no provider this session, never a substitute); connect failures no longer fail wallet BOOT; list_lsps stickiness armed (was comparing the wallet's own pubkey — never fired once). Prior — v223 (S39): escape-kit truth fields (per-monitor open + claimable_sats \u2014 the kit stops quoting dead commitments); archiver ungated from reconcile_done + resolved monitors leave the spend walk; dest_is_lsp on send silence events (0.57.0 item h). Prior \u2014 v222 internal LNURLp single-hop: dest==LSP ⇒ the prepend IS the route; LND's out-and-back same-channel answer to a self-dest+public-hints query is never parsed (DP field 5/5 cured). Prior — v221 device-file import (import_backup_blob → LijWallet::import_state_blob via node accessors — the cloud-restore inject path made public). Prior — v220 RECOVERY ARC: D3 blob carries on-chain view/pendings/counters (instant blob restores); tier2_rescan_from for imported foreign seeds (SegWit-activation floor 481,824 — wpkh cannot predate it, so 2009-era picks are honored, empty years skipped, failure impossible). Prior: v219 socket-id realm fix.
}

// ── Seed vault (passphrase-wrapped mnemonic) ─────────────────────────────────
//
// Wrap/unwrap the BIP39 mnemonic under a user-chosen passphrase. The passphrase
// is a local convenience lock — it does NOT modify the mnemonic or derived keys
// (see seed_vault module docs). Argon2id cost runs ~400 ms in browser; calls
// block the JS thread for that duration.


/// Wrap `mnemonic` under `passphrase`. Returns a hex-encoded blob suitable for
// ── Phase B (S32): OFFLINE START — engine-side courtesy flag. When set
// before construction: the Step-8a esplora swap is skipped (the stub
// stays — zero chain queries) and the backup client is hard-silenced at
// BOTH entries. Keys, derivation, and persisted state remain fully live.
pub static OFFLINE_START: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[wasm_bindgen]
pub fn set_offline_start(v: bool) {
    OFFLINE_START.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// v208: broadcast routing — true routes each tx to one endpoint at a time
/// (rotating, stop at first acceptance); false fans to all healthy endpoints.
#[wasm_bindgen]
pub fn set_broadcast_one(v: bool) {
    lij_core::independent::BROADCAST_ONE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// v209: standalone cloud-backup gate (DP privacy pane). true silences the
/// backup client at every entry — nothing leaves the device — independent of
/// offline_start. Mirrors the OFFLINE_START pattern.
pub static BACKUP_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[wasm_bindgen]
pub fn set_backup_off(v: bool) {
    BACKUP_OFF.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// localStorage. Throws on empty mnemonic or Argon2 failure.
#[wasm_bindgen]
pub fn wrap_mnemonic(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    let blob = lij_core::seed_vault::wrap(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(blob))
}

/// Unwrap a hex-encoded blob produced by [`wrap_mnemonic`]. Returns the
/// mnemonic string. Throws on bad hex, short blob, wrong passphrase,
/// tampered data, or version mismatch — error messages disambiguate.
#[wasm_bindgen]
pub fn unwrap_mnemonic(blob_hex: &str, passphrase: &str) -> Result<String, JsValue> {
    let blob = hex::decode(blob_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))?;
    lij_core::seed_vault::unwrap(&blob, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}



/// Suggest BIP39 English words matching a prefix. Returns up to `max` matches,
/// lexicographically sorted (the wordlist is pre-sorted). Case-insensitive.
/// Returns empty vec for empty prefix or no matches.
#[wasm_bindgen]
pub fn bip39_suggest(prefix: &str, max: usize) -> Vec<JsValue> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let needle = prefix.to_lowercase();
    let words = bip39::Language::English.word_list();
    words.iter()
        .filter(|w| w.starts_with(&needle))
        .take(max)
        .map(|w| JsValue::from_str(w))
        .collect()
}



/// Validate a full BIP39 mnemonic string (word validity + checksum).
/// Accepts 12, 15, 18, 21, or 24-word phrases. Returns Ok on valid, Err with
/// descriptive message on invalid word, wrong count, or checksum mismatch.
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> Result<(), JsValue> {
    let trimmed = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse_normalized(&trimmed)
        .map(|_| ())
        .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Given 11 valid BIP39 words and 7 binary bits ("0"s and "1"s), compute the
/// 12th (checksum) word that completes a valid mnemonic.
///
/// BIP39 encodes a 12-word mnemonic as 128 bits entropy + 4-bit checksum,
/// packed as 12 × 11-bit word indices. The 12th word's 11 bits are
/// [7 user bits] || [4 checksum bits], where the checksum is the first 4
/// bits of SHA256(entropy).
///
/// This exposes the "secret binary path" for seed reset: a user who types
/// 7 bits into the 12th field gets the deterministic checksum word back.
#[wasm_bindgen]
pub fn checksum_word_for_bits(
    first_eleven: Vec<JsValue>,
    seven_bits: &str,
) -> Result<String, JsValue> {
    use sha2::{Digest, Sha256};

    // Validate input shape
    if first_eleven.len() != 11 {
        return Err(JsValue::from_str(&format!(
            "expected 11 words, got {}", first_eleven.len()
        )));
    }
    if seven_bits.len() != 7 {
        return Err(JsValue::from_str(&format!(
            "expected 7 bits, got {} characters", seven_bits.len()
        )));
    }
    if !seven_bits.chars().all(|c| c == '0' || c == '1') {
        return Err(JsValue::from_str("bits must be 0 or 1"));
    }

    let wordlist = bip39::Language::English.word_list();

    // Extract each word's index (0..2048) from the wordlist
    let mut indices: Vec<u16> = Vec::with_capacity(11);
    for (i, v) in first_eleven.iter().enumerate() {
        let word = v.as_string()
            .ok_or_else(|| JsValue::from_str(&format!("word {} not a string", i + 1)))?;
        let idx = wordlist.iter().position(|w| *w == word.as_str())
            .ok_or_else(|| JsValue::from_str(&format!(
                "word {} (\"{}\") is not in BIP39 English wordlist", i + 1, word
            )))?;
        indices.push(idx as u16);
    }

    // Build the 121 bits of word indices, then append 7 user bits → 128 bits entropy.
    // Pack indices MSB-first, 11 bits each.
    let mut bits: Vec<u8> = Vec::with_capacity(128);
    for idx in &indices {
        for shift in (0..11).rev() {
            bits.push(((idx >> shift) & 1) as u8);
        }
    }
    for c in seven_bits.chars() {
        bits.push(if c == '1' { 1 } else { 0 });
    }
    // We now have exactly 128 bits = 16 bytes of entropy
    debug_assert_eq!(bits.len(), 128);
    let mut entropy = [0u8; 16];
    for (i, bit) in bits.iter().enumerate() {
        entropy[i / 8] |= bit << (7 - (i % 8));
    }

    // Checksum = first 4 bits of SHA256(entropy)
    let mut hasher = Sha256::new();
    hasher.update(&entropy);
    let hash = hasher.finalize();
    let checksum_nibble = (hash[0] >> 4) & 0x0F;

    // 12th-word index = (7 user bits << 4) | 4 checksum bits
    let mut user_bits_val: u16 = 0;
    for c in seven_bits.chars() {
        user_bits_val = (user_bits_val << 1) | (if c == '1' { 1 } else { 0 });
    }
    let word_idx = (user_bits_val << 4) | checksum_nibble as u16;

    Ok(wordlist[word_idx as usize].to_string())
}



/// Derive the authoritative Lightning node pubkey from a BIP39 mnemonic.
/// Mirrors what LijNode does in ~3ms instead of ~3s — skips LDK setup,
/// LSP registry fetch, chain monitor init. Used for seed-verification in
/// the forgot-passphrase reset flow.
#[wasm_bindgen]
pub fn pubkey_from_mnemonic(mnemonic: &str, network: &str) -> Result<String, JsValue> {
    use lij_core::key::RootKey;
    use lightning::sign::{KeysManager, NodeSigner, Recipient};

    let mnemonic_parsed: bip39::Mnemonic = mnemonic.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {e}")))?;

    let btc_network = match network {
        "bitcoin" => bitcoin::Network::Bitcoin,
        "testnet" => bitcoin::Network::Testnet,
        "signet"  => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(JsValue::from_str(&format!("Unknown network: {network}"))),
    };

    let root_key = RootKey::from_mnemonic(&mnemonic_parsed, btc_network)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {e}")))?;

    let seed = root_key.lightning_node_key()
        .map_err(|e| JsValue::from_str(&format!("Lightning key derivation failed: {e}")))?
        .private_key.secret_bytes();

    // Timestamps don't affect node_id (KeysManager derives it from seed alone),
    // but the API requires them. Use a fixed value for determinism.
    let keys_manager = KeysManager::new(&seed, 0, 0);

    let node_id = keys_manager.get_node_id(Recipient::Node)
        .map_err(|_| JsValue::from_str("Failed to get node pubkey"))?;

    Ok(hex::encode(node_id.serialize()))
}

// ── LSPS2 client (Phase B — v0.16 adapter compatible) ──────────────────────

/// Fetch LSPS2 service terms from an LSP endpoint.
///
/// JS receives the parsed [Lsps2GetInfoResponse] as a JSON string.
/// Errors (HTTP failure, parse failure) are thrown as JS exceptions.
///
/// # Example (JS)
/// ```javascript
/// const json = await window.lij_wasm.lsps2_get_info(
///   "https://lijox-lsp.lightning-mod.com",
///   route_macaroon_from_registry,
/// );
/// const info = JSON.parse(json);
/// console.log(info.human_summary);
/// ```
#[wasm_bindgen]
pub fn lsps2_get_info(endpoint: &str, route_macaroon: &str) -> js_sys::Promise {
    let endpoint = endpoint.to_string();
    let route_macaroon = route_macaroon.to_string();
    future_to_promise(async move {
        let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &route_macaroon)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let json = serde_json::to_string(&info)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsValue::from_str(&json))
    })
}

/// Buy an LSPS2 JIT channel promise for inbound `payment_size_msat`.
///
/// JS receives the parsed [Lsps2BuyResponse] as a JSON string. The
/// returned `jit_channel_scid` must be embedded as a route_hint in the
/// BOLT11 invoice the wallet generates for the upcoming receive (Phase C).
/// Promise expires after `promise_expires_at` ms — wallet must call again
/// if expired.
///
/// # Example (JS)
/// ```javascript
/// const json = await window.lij_wasm.lsps2_buy_promise(
///   endpoint, route_macaroon, BigInt(50_000_000)
/// );
/// const promise = JSON.parse(json);
/// embedRouteHint(promise.jit_channel_scid, promise.lsp_pubkey);
/// ```
#[wasm_bindgen]
/// v0.16 Phase B + Phase A.1: free-function wrapper for LSPS2 /buy.
/// client_pubkey is REQUIRED — adapter v0.18+ uses it to determine where
/// to open the JIT channel when a matching HTLC arrives. Must be the
/// wallet's 66-hex-char node pubkey.
pub fn lsps2_buy_promise(
    endpoint: &str,
    route_macaroon: &str,
    payment_size_msat: u64,
    client_pubkey: &str,
) -> js_sys::Promise {
    let endpoint = endpoint.to_string();
    let route_macaroon = route_macaroon.to_string();
    let client_pubkey = client_pubkey.to_string();
    future_to_promise(async move {
        let resp = lij_core::lsps2::lsps2_buy(&endpoint, &route_macaroon, Some(payment_size_msat), &client_pubkey)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let json = serde_json::to_string(&resp)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsValue::from_str(&json))
    })
}

// ── Wallet handle ────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct LijWalletHandle {
    inner: Arc<std::sync::Mutex<LijWallet>>,
}

#[wasm_bindgen]
impl LijWalletHandle {
    #[wasm_bindgen(static_method_of = LijWalletHandle)]
    pub fn create(config_json: &str) -> js_sys::Promise {
        let config_json = config_json.to_string();

        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;

            let storage = Arc::new(LocalStorage);

            let (wallet, created) = LijWallet::create(config, storage)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let handle = LijWalletHandle {
                inner: Arc::new(std::sync::Mutex::new(wallet)),
            };

            set_current_wallet_inner(handle.inner.clone());
            // Step 8a: swap StubEsploraHttp for the real WasmEsploraHttp now
            // that the wallet is fully constructed.
            {
                let w = handle.inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                if !OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed) {
                    w.node().set_independent_http(std::sync::Arc::new(WasmEsploraHttp::new()));
                } // Phase B: offline_start keeps the stub — zero network
            }

            let result_json = serde_json::to_string(&created)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let global = js_sys::global();
            let handle_val = JsValue::from(handle);
            js_sys::Reflect::set(
                &global,
                &JsValue::from_str("_lijWalletInstance"),
                &handle_val,
            ).map_err(|e| JsValue::from_str(&format!("Failed to store handle: {:?}", e)))?;

            Ok(JsValue::from_str(&result_json))
        })
    }

    #[wasm_bindgen(static_method_of = LijWalletHandle)]
    pub fn restore(mnemonic: &str, config_json: &str) -> js_sys::Promise {
        let mnemonic = mnemonic.to_string();
        let config_json = config_json.to_string();

        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;

            let storage = Arc::new(LocalStorage);

            let (wallet, restored) = LijWallet::restore(&mnemonic, config, storage)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let handle = LijWalletHandle {
                inner: Arc::new(std::sync::Mutex::new(wallet)),
            };

            set_current_wallet_inner(handle.inner.clone());
            // Step 8a: swap StubEsploraHttp for the real WasmEsploraHttp now
            // that the wallet is fully constructed.
            {
                let w = handle.inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                if !OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed) {
                    w.node().set_independent_http(std::sync::Arc::new(WasmEsploraHttp::new()));
                } // Phase B: offline_start keeps the stub — zero network
            }

            let result_json = serde_json::to_string(&restored)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let global = js_sys::global();
            let handle_val = JsValue::from(handle);
            js_sys::Reflect::set(
                &global,
                &JsValue::from_str("_lijWalletInstance"),
                &handle_val,
            ).map_err(|e| JsValue::from_str(&format!("Failed to store handle: {:?}", e)))?;

            Ok(JsValue::from_str(&result_json))
        })
    }

    #[wasm_bindgen]
    pub fn get_balance(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let balance = wallet.get_balance()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&balance)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    #[wasm_bindgen]
    pub fn send_payment(&self, bolt11: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let result = wallet.send_payment(&bolt11)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Manually push the current encrypted wallet state to all enabled backup
    /// sinks (scenario-A backup). Returns `{"ok":true}`. This is the "Back up
    /// now" action and our round-trip test entrypoint; automatic triggers will
    /// reuse the same `LijWallet::backup()` path.
    #[wasm_bindgen]
    pub fn backup_now(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            // Snapshot what the push needs while holding the lock, then RELEASE
            // it before any network I/O. Holding the wallet mutex across the
            // push's `.await` lets a background tick re-enter and panic the
            // single-threaded WASM mutex.
            let prep = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet
                    .prepare_backup()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            let (blob, signer, sinks) = match prep {
                Some(t) => t,
                None => return Ok(JsValue::from_str("{\"ok\":true,\"pushed\":0}")),
            };
            // Network push happens with NO wallet lock held.
            let mut ok = 0u32;
            let mut last_err: Option<String> = None;
            for sink in &sinks {
                match sink.push(&blob, &*signer).await {
                    Ok(()) => ok += 1,
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            if ok == 0 {
                if let Some(e) = last_err {
                    return Err(JsValue::from_str(&format!("backup: all sinks failed: {e}")));
                }
            }
            Ok(JsValue::from_str(&format!("{{\"ok\":true,\"pushed\":{ok}}}")))
        })
    }

    /// Auto-backup tick: if channel state changed since the last push, snapshot
    /// it under the lock, release, then push to enabled sinks UNLOCKED. Cheap
    /// no-op when nothing changed; the frontend calls this on a slow debounce
    /// interval. Never holds the wallet mutex across the push's `.await`.
    #[wasm_bindgen]
    pub fn maybe_backup(&self) -> js_sys::Promise {
        // Phase B: offline_start hard-silences the backup client.
        if OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed)
            || BACKUP_OFF.load(std::sync::atomic::Ordering::Relaxed) {   // v209
            return js_sys::Promise::resolve(&JsValue::UNDEFINED);
        }
        let inner = self.inner.clone();
        future_to_promise(async move {
            let prep = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet
                    .prepare_backup_if_dirty()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            let (blob, signer, sinks, dirty) = match prep {
                Some(t) => t,
                None => return Ok(JsValue::from_str("{\"ok\":true,\"pushed\":0}")),
            };
            // Push with NO wallet lock held. On failure re-mark dirty to retry
            // next tick; on success leave it as cleared at snapshot (a concurrent
            // state change during the push will already have re-dirtied it).
            let mut ok = 0u32;
            for sink in &sinks {
                match sink.push(&blob, &*signer).await {
                    Ok(()) => ok += 1,
                    Err(_) => dirty.store(true, std::sync::atomic::Ordering::Relaxed),
                }
            }
            Ok(JsValue::from_str(&format!("{{\"ok\":true,\"pushed\":{ok}}}")))
        })
    }

    /// Abandon all channels WITHOUT broadcasting (safe recovery from a stale
    /// restore). Call this BEFORE reconnecting to peers to avoid the
    /// data-loss-protect panic on channel_reestablish. Returns channels closed.
    #[wasm_bindgen]
    pub fn force_close_all_without_broadcasting(&self) -> Result<u32, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet
            .force_close_all_without_broadcasting()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Read-only on-chain wallet summary (D, increment 1): scans the BIP84
    /// spendable chain + legacy m/525 residue and returns balance, UTXOs, and a
    /// fresh receive address as JSON. Snapshots handles under the lock, then
    /// runs the scan UNLOCKED (network I/O), like the backup path.
    #[wasm_bindgen]
    pub fn onchain_summary(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let summary =
                lij_core::onchain_scan::onchain_summary(&root_key, independent, network)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = summary
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Tier 2 (privacy-default) on-chain sync: pull compact block filters from
    /// the node, match them LOCALLY against our scripts, fetch and verify only
    /// the blocks that hit, and assemble the UTXO set + history + balances
    /// entirely client-side — the node never learns which scripts are ours.
    /// Persists across sessions and resumes from the saved cursor. `birthday`
    /// is the wallet's creation height, used only when no cursor exists yet.
    /// Returns Tier2Summary JSON.
    #[wasm_bindgen]
    pub fn tier2_onchain_sync(&self, birthday: f64) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let (rk, _independent, net) = wallet.onchain_handles();
                (rk, net)
            };
            let base = "https://filters.lightning-mod.com";
            let http: Arc<dyn lij_core::independent::EsploraHttp> =
                Arc::new(WasmEsploraHttp::new());
            let storage: Arc<dyn lij_core::storage::LijStorage> = Arc::new(LocalStorage);

            let mut view = lij_core::tier2_wallet::load_view(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if view.cursor.birthday == 0 {
                view.cursor.birthday = birthday as u32;
            }

            // Sliding gap: each chain's scan window covers 0..(frontier + gap),
            // recomputed from the view + pending every sync, so receive/change
            // rotation never outruns address discovery (replaces the fixed 0..gap).
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            let scripts = lij_core::tier2::WalletScripts::build_sliding(
                &root_key,
                network,
                lij_core::tier2::DEFAULT_GAP,
                // v105: sweeper + coop-close destinations derive at chain-0
                // indexes from the signer's persistent counter, which the view
                // cannot see until a landing is scanned — a chicken/egg that
                // let a sweep pay index 50 one past the 0..50 window and go
                // invisible (Session 17, e2476af7). Widen the receive frontier
                // to the counter so destination scripts are ALWAYS watched
                // before anything pays them.
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_RECEIVE)
                    .max(lij_core::persisted_counter::peek_persisted(storage.as_ref())),
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_CHANGE),
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_LEGACY),
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let tip = lij_core::tier2_sync::fetch_tip(&http, base)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            lij_core::tier2_wallet::sync_to_tip(
                &http,
                base,
                &scripts,
                &mut view,
                storage.as_ref(),
                tip.height,
                lij_core::tier2_sync::DEFAULT_BATCH,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Fold any now-confirmed pendings into the view (stamps the
            // ChannelOpen/ChannelClose marker onto the confirmed row, drops them
            // from the pending key), persist the stamped view, then build the
            // summary from the freshly-loaded pending list. reconcile + load are
            // synchronous, so a funding/send handler that wrote a pending during
            // the sync's network await is preserved here, never clobbered.
            lij_core::tier2_wallet::reconcile_pending(storage.as_ref(), &mut view)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // v191 (S29): CONFLICT-DEAD RELEASE — zombie pendings whose
            // input the chain shows spent can never confirm; their folded
            // change is phantom balance. Release + witness each.
            let conflicts = lij_core::tier2_wallet::release_conflicted_pending(
                storage.as_ref(),
                &view,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            for (dead_txid, phantom_chg) in &conflicts {
                log::warn!(
                    "[CONFLICT-AUDIT] released dead pending {} (phantom change {} sats)",
                    &dead_txid[..16.min(dead_txid.len())],
                    phantom_chg
                );
            }

            // v102: reconcile the OutputSweeper against confirmed sweep txs.
            //
            // The sweeper regenerates each unconfirmed sweep every block (locktime
            // = current height -> a new txid each time), so it never recognizes its
            // own sweep landing and sits at "sweeping" forever, double-counting the
            // swept funds (already in spendable) in the maturing alert. Feed it the
            // REAL confirmed sweep txs from the blocks this scan covers:
            // is_spent_in() on the sweeper matches each to the source descriptor it
            // spends (no txid/value heuristic) and advances sweeping -> confirming,
            // which the UI excludes. Gated on there actually being a "sweeping"
            // output, so the common path costs nothing. Non-fatal: a transient
            // block-fetch failure must never fail the sync (the next one retries).
            let needs_sweeper_reconcile = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().sweeper_pending_first_count() > 0
            };
            if needs_sweeper_reconcile {
                // Candidate sweep destinations: unspent chain-0 view UTXOs (the
                // sweeper always sweeps to m/84'/0'/0'/0/n = CHAIN_RECEIVE). We
                // accept only txs whose txid is one of these already-validated
                // rows, so a bad block server cannot inject a false confirmation.
                let mut wanted: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut heights: Vec<u32> = Vec::new();
                for u in &view.utxos {
                    if u.spent_height.is_none() && u.chain == lij_core::tier2::CHAIN_RECEIVE {
                        wanted.insert(u.txid.clone());
                        heights.push(u.height);
                    }
                }
                heights.sort_unstable();
                heights.dedup();
                if !wanted.is_empty() {
                    if let Ok(confirmed) = lij_core::tier2_wallet::fetch_confirmed_txs(
                        &http, base, &heights, &wanted,
                    )
                    .await
                    {
                        if !confirmed.is_empty() {
                            if let Ok(wallet) = inner.lock() {
                                wallet.node().reconcile_sweeper_confirmations(&confirmed);
                            }
                        }
                    }
                }
            }
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());

            // v190 (S29): UTXO-set invariant — heal duplicates (keep first),
            // witness-log the cull, persist the healed view, and surface the
            // count to the audit line. A clean view is a no-op.
            let view_dupes = lij_core::tier2_wallet::dedupe_utxos(&mut view);
            if view_dupes > 0 {
                log::warn!(
                    "[VIEW-AUDIT] healed {} duplicate utxo entr(ies) — persisted",
                    view_dupes
                );
                lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }

            let json = lij_core::tier2_wallet::summary(&view, &pending, tip.height)
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = json.replacen(
                '{',
                &format!(
                    "{{\"view_dupes\":{},\"conflicts\":{},",
                    view_dupes,
                    conflicts.len()
                ),
                1,
            );
            Ok(JsValue::from_str(&json))
        })
    }

    /// On-chain send (option D, increment 2): P2WPKH spend from the m/84
    /// spendable chain, change to m/84'/{coin}'/0'/1/0. `amount_sats` is a JS
    /// number (f64 is exact up to 2^53, far above the 2.1e15-sat supply cap);
    /// `fee_rate_sat_per_kw` is LDK sat/kilo-weight (use FeeQuote::on_chain_sweep).
    /// S45 (DP): plan (send=false) or send (send=true) a CPFP child for a
    /// pending cooperative close — the user's Speed up on the on-chain face.
    /// Always forced (the user's tap skips the automatic mode's gates).
    /// Returns JSON {ok, can, reason, child_fee_sats, parent_rate_vb, target_vb, txid}.
    #[wasm_bindgen]
    pub fn coop_cpfp(&self, channel_id_hex: &str, send: bool) -> js_sys::Promise {
        let inner = self.inner.clone();
        let cid = channel_id_hex.to_string();
        future_to_promise(async move {
            let h = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().coop_cpfp_handles()
            };
            let storage: Arc<dyn lij_core::storage::LijStorage> = Arc::new(LocalStorage);
            let j = lij_core::node::coop_cpfp(storage, h, &cid, send, true)
                .await
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            Ok(JsValue::from_str(&j))
        })
    }

    /// Lock-prepare-unlock: snapshot handles under the lock, then build/sign/
    /// broadcast with the lock released (network I/O). Returns SendResult JSON.
    #[wasm_bindgen]
    pub fn send_onchain(
        &self,
        dest: &str,
        amount_sats: f64,
        fee_rate_sat_per_kw: u32,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let dest = dest.to_string();
        future_to_promise(async move {
            if !(amount_sats.is_finite() && amount_sats >= 1.0) {
                return Err(JsValue::from_str(
                    "amount must be a positive whole number of sats",
                ));
            }
            let amount = amount_sats as u64;
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            // Plain-send coins now come from the canonical Tier-2 view (the same
            // source as channel funding and the displayed balance), not a live
            // scan. Load the view + pending once: they pick the next change index
            // (rotation) AND supply the spendable set to build_and_send.
            let (view, pending) = {
                let storage = LocalStorage;
                let view = lij_core::tier2_wallet::load_view(&storage)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let pending = lij_core::tier2_wallet::load_pending(&storage);
                (view, pending)
            };
            let change_index = lij_core::tier2_wallet::next_change_index(&view, &pending);
            let result = lij_core::onchain_send::build_and_send(
                &root_key,
                independent,
                network,
                &dest,
                amount,
                fee_rate_sat_per_kw,
                change_index,
                &view,
                &pending,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Own-send immediate view: reserve the spent inputs so spendable
            // drops now (before confirmation); reconciled when Tier-2 sees it.
            // Written to the dedicated pending key (decoupled from the synced
            // view, so a concurrent sync can't clobber it).
            {
                let storage: Arc<dyn lij_core::storage::LijStorage> = Arc::new(LocalStorage);
                let delta = -((result.amount_sats as i64) + (result.fee_sats as i64));
                if let Err(e) = lij_core::tier2_wallet::record_pending(
                    storage.as_ref(),
                    lij_core::tier2_wallet::PendingTx {
                        txid: result.txid.clone(),
                        spent_outpoints: result.spent_outpoints.clone(),
                        delta_sats: delta,
                        direction: lij_core::tier2_wallet::TxDirection::Sent,
                        kind: lij_core::tier2_wallet::TxKind::Onchain,
                        created_at_ms: lij_core::tier2_wallet::now_ms(),
                        change_outpoint: result.change_outpoint.clone(),
                        change_value_sats: result.change_sats,
                        change_index: result.change_index,
                        broadcast_seen: false,
                        // Build #4: sends rebuild from v166 metadata; byte
                        // persistence for sends is staged separately.
                        raw_tx_hex: None,
                        dest_addr: Some(dest.clone()),
                        dest_sats: Some(amount),
                        fee_sats: Some(result.fee_sats),
                        fee_rate_sat_per_kw: Some(fee_rate_sat_per_kw),
                    },
                ) {
                    log::error!("record pending on-chain send failed: {e}");
                }
            }

            let json = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v166 (#29-4b): raw pending list for the bump UI (storage-only).
    pub fn list_pending_json(&self) -> Result<String, JsValue> {
        let storage = LocalStorage;
        let pending = lij_core::tier2_wallet::load_pending(&storage);
        serde_json::to_string(&pending).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v166 (#29-4b): RBF-replace one of OUR pending on-chain sends at a
    /// higher fee. Same inputs, same destination; the delta comes out of the
    /// change. The engine enforces BIP-125 economics and answers with
    /// actionable minimum/maximum sat/vB messages on violation.
    pub fn bump_onchain_send(&self, old_txid: String, new_fee_rate_sat_per_kw: u32) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let storage = LocalStorage;
            let view = lij_core::tier2_wallet::load_view(&storage)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pending = lij_core::tier2_wallet::load_pending(&storage);
            let prev = pending
                .iter()
                .find(|p| p.txid == old_txid)
                .ok_or_else(|| JsValue::from_str(
                    "that send is not pending anymore — it may have confirmed; refresh",
                ))?;
            let result = lij_core::onchain_send::build_and_send_bump(
                &root_key,
                independent,
                network,
                prev,
                new_fee_rate_sat_per_kw,
                &view,
                &pending,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let dest_addr_keep = prev.dest_addr.clone();
            let dest_sats_keep = prev.dest_sats;
            {
                let storage2: Arc<dyn lij_core::storage::LijStorage> = Arc::new(LocalStorage);
                let mut list = lij_core::tier2_wallet::load_pending(storage2.as_ref());
                list.retain(|p| p.txid != old_txid);
                list.push(lij_core::tier2_wallet::PendingTx {
                    txid: result.txid.clone(),
                    spent_outpoints: result.spent_outpoints.clone(),
                    delta_sats: -((result.amount_sats as i64) + (result.fee_sats as i64)),
                    direction: lij_core::tier2_wallet::TxDirection::Sent,
                    kind: lij_core::tier2_wallet::TxKind::Onchain,
                    created_at_ms: lij_core::tier2_wallet::now_ms(),
                    broadcast_seen: false,
                    raw_tx_hex: None,
                    change_outpoint: result.change_outpoint.clone(),
                    change_value_sats: result.change_sats,
                    change_index: result.change_index,
                    dest_addr: dest_addr_keep,
                    dest_sats: dest_sats_keep,
                    fee_sats: Some(result.fee_sats),
                    fee_rate_sat_per_kw: Some(new_fee_rate_sat_per_kw),
                });
                lij_core::tier2_wallet::save_pending(storage2.as_ref(), &list)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            let body = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&format!(
                "{{\"replaced\":\"{}\",\"result\":{}}}",
                old_txid, body
            )))
        })
    }

    /// v105 dev/recovery tool: roll the Tier-2 scan cursor back so the next
    /// background sync re-walks blocks from `from_height` (inclusive) to tip.
    /// Use when a block was scanned before its matching script entered the
    /// watch window (e.g. a sweep paid an address past the old gap) — the
    /// counter-aware window above makes the re-walk actually match this time.
    /// Pure storage operation (no wallet lock). Floors at the birthday; no-op
    /// if the cursor is already at or below the target. Returns the persisted
    /// cursor as JSON. Balances/history may look odd for the few seconds the
    /// re-walk takes; the next completed sync restores full truth.
    #[wasm_bindgen]
    pub fn tier2_rescan_from(&self, from_height: f64) -> Result<String, JsValue> {
        if !(from_height.is_finite() && from_height >= 1.0) {
            return Err(JsValue::from_str("from_height must be a positive block height"));
        }
        let storage: Arc<dyn lij_core::storage::LijStorage> = Arc::new(LocalStorage);
        let mut view = lij_core::tier2_wallet::load_view(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        // v220 (foreign-seed re-anchor; supersedes my duplicate — discovered
        // this v105 tool AFTER implementing, process failure ledgered): a seed
        // imported from another wallet can carry history BELOW this wallet's
        // recorded birthday, so a request under the birthday now LOWERS the
        // birthday to the request — floored at SegWit activation (481,824):
        // every watched script is wpkh and cannot predate it, so 2009-era
        // picks are honored, provably-empty years are skipped, and no
        // nonexistent-day math can ever fail. Requests at/above the birthday
        // keep the exact v105 semantics.
        const SEGWIT_ACTIVATION: u32 = 481_824;
        let mut requested = from_height as u32;
        let mut dirty = false;
        if requested < view.cursor.birthday {
            requested = requested.max(SEGWIT_ACTIVATION);
            view.cursor.birthday = requested;
            dirty = true;
        }
        // The cursor names the last-scanned block, so to re-include
        // `requested` it must sit one below it (never below birthday-1).
        let target = requested
            .saturating_sub(1)
            .max(view.cursor.birthday.saturating_sub(1));
        if view.cursor.scanned_to > target {
            lij_core::tier2_wallet::rollback(&mut view, target);
            dirty = true;
        }
        if dirty {
            lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        // Re-read so the caller sees the persisted truth, not our intent.
        let check = lij_core::tier2_wallet::load_view(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"scanned_to\":{}}}", check.cursor.scanned_to))
    }

    /// Session 23 Option B (allocator unification): next-to-issue value of
    /// the shared channel-index allocator, without advancing. The frontend
    /// maxes this into getOnchainRecvIndex() so receive minting can never
    /// collide with signer-issued indices (shutdown pins, sweep
    /// destinations, and — post-terminus — pinned to_remote keys) that
    /// haven't landed on-chain yet. Reads the LIVE counter instance.
    #[wasm_bindgen]
    pub fn peek_channel_index(&self) -> Result<f64, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let v = wallet
            .node()
            .signer_provider()
            .peek_index()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(v as f64)
    }

    /// Session 23 Option B (allocator unification, the other direction):
    /// the frontend reserves receive-index territory. Raises the shared
    /// allocator floor to index+1 on the LIVE counter instance, so the
    /// signer can never issue an index at or below a shown/used receive
    /// address. No-op when the allocator is already past it.
    #[wasm_bindgen]
    pub fn reserve_onchain_index(&self, index: f64) -> Result<(), JsValue> {
        if !(index.is_finite() && index >= 0.0) {
            return Err(JsValue::from_str("index must be a non-negative integer"));
        }
        let idx = index as u32;
        let floor = idx
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("index overflow"))?;
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet
            .node()
            .signer_provider()
            .raise_index_floor(floor)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Session 23 (1b engine half): version of the last vault push, read
    /// from KEY_BACKUP_VERSION (u64 BE). Returns 0 when no push has ever
    /// happened. Feeds the standing Backup drilldown row
    /// ("vault · vNNN · synced").
    #[wasm_bindgen]
    pub fn last_backup_version(&self) -> Result<f64, JsValue> {
        match lij_core::storage::LijStorage::get(
            &LocalStorage,
            lij_core::storage::KEY_BACKUP_VERSION,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(buf) as f64)
            }
            Some(_) => Err(JsValue::from_str("backup version malformed")),
            None => Ok(0.0),
        }
    }

    /// Network-free receive address at `index` (BIP84 m/84'/{coin}'/0'/0/index).
    /// Synchronous + offline: derives from the seed only, so receiving never
    /// depends on a chain scan. The frontend persists the index and reconciles
    /// it upward whenever a scan succeeds, advancing per receive to avoid reuse.
    #[wasm_bindgen]
    pub fn next_receive_address(&self, index: f64) -> Result<String, JsValue> {
        if !(index.is_finite() && index >= 0.0) {
            return Err(JsValue::from_str("index must be a non-negative integer"));
        }
        let idx = index as u32;
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let (root_key, _independent, network) = wallet.onchain_handles();
        lij_core::onchain_scan::receive_address_at(&root_key, idx, network)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Chunk 1 (receive watcher): query a single watched address for incoming
    /// outputs — INCLUDING 0-conf mempool ones — via the independent Esplora
    /// quorum. The confirmed-block BIP158 scanner is mempool-blind by design, so
    /// this is the ONLY mempool-aware path, deliberately narrow: it is called
    /// only for an address the user is actively awaiting payment on (an open
    /// expectation row), never across the whole wallet. Returns a JSON array of
    /// { txid, vout, value_sats, confirmed } — the frontend turns unconfirmed
    /// entries into a pending-inbound alert-bar amount and flips the awaiting
    /// row; confirmed entries are left for the scanner to fold in normally.
    ///
    /// Privacy note: this reveals the queried address to the quorum endpoints.
    /// That address was just shown to a payer, the query only fires for actively
    /// awaited addresses, and the endpoint is user-configurable (own node →
    /// zero leak). The wallet-wide BIP158 model is untouched.
    #[wasm_bindgen]
    pub fn watch_address_inbound(&self, address: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let independent = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let (_rk, independent, _net) = wallet.onchain_handles();
                independent
            };
            let utxos = independent
                .fetch_address_utxos(&address)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            // Hand the frontend the raw per-output truth; it owns the
            // pending-inbound bookkeeping and dedup against the scanner.
            let items: Vec<String> = utxos
                .iter()
                .map(|u| {
                    format!(
                        "{{\"txid\":\"{}\",\"vout\":{},\"value_sats\":{},\"confirmed\":{}}}",
                        u.txid, u.vout, u.value_sats, u.confirmed
                    )
                })
                .collect();
            Ok(JsValue::from_str(&format!("[{}]", items.join(","))))
        })
    }

    /// On-chain transaction history for the RECENT list. The trusted-node source
    /// was removed with the shim; this returns an empty list until Tier 2
    /// (client-side BIP158 filter matching) reconstructs history locally. Kept so
    /// the frontend RECENT wiring stays stable across the transition.
    #[wasm_bindgen]
    pub fn onchain_history(&self) -> js_sys::Promise {
        future_to_promise(async move { Ok::<JsValue, JsValue>(JsValue::from_str("[]")) })
    }

    /// Phase 10b — Send via LSP-provided route (Routing as a Service).
    ///
    /// Today's signature takes route_endpoint and route_macaroon as parameters.
    /// JS callers must look these up themselves (e.g., from a hardcoded test
    /// constant or from the wallet's active LSP record).
    ///
    /// FUTURE — LIJOX MARKETPLACE INTEGRATION:
    /// When the LIJOX marketplace UI ships and the user selects an LSP, the
    /// active LSP record will carry `route_endpoint` and `route_macaroon`
    /// (already added to LspInfo struct). At that point this method should be
    /// changed to:
    ///   pub fn send_payment_via_lsp_route(&self, bolt11: &str) -> js_sys::Promise
    /// and read the credentials from `wallet.active_lsp()` internally.
    /// See lsp.rs LspInfo for the field definitions.
    ///
    /// v8: refactored to release the wallet mutex during the HTTP fetch.
    /// Pattern: lock-prepare-unlock, fetch (no lock), lock-apply-unlock. Mirrors
    /// open_channel's structure. Required to prevent the mutex_no_threads panic
    /// observed in session 14 when LDK background_tick tried to acquire the
    /// wallet lock during a long-running Phase 10b POST.
    #[wasm_bindgen]
    pub fn send_payment_via_lsp_route(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        future_to_promise(async move {
            // Phase 1: lock, prepare, release
            let prep = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node()
                    .prepare_lsp_route_request(&bolt11, &route_endpoint, &[], None)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // mutex released here

            // Phase 2: HTTP fetch WITHOUT the wallet lock held
            let response_text = lij_core::node::fetch_post_with_macaroon(
                &prep.url,
                &route_macaroon_hex,
                &prep.request_body,
            )
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Phase 3: lock, apply, release
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node()
                    .apply_lsp_route_and_send(&response_text, &prep)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v8: Send a Lightning payment via Phase 10b LSP routing with automatic
    /// retry-on-path-failure. On each attempt, the wallet asks the LSP for a
    /// route, submits the HTLC with a FRESH PaymentId, then polls the per-
    /// payment outcome map for the final result. If the result is PathFailed
    /// (a hop bounced the HTLC with temporary_channel_failure or similar), the
    /// failed (from, to) pubkey pair is appended to the excluded-pairs list,
    /// the old PaymentId is abandoned in LDK's OutboundPayments, and the next
    /// attempt asks the LSP to route around the failed hop with a new id.
    ///
    /// Up to `max_retries` attempts. Returns the final PaymentResult — either
    /// success (Sent), permanent failure (Failed or PathFailed with
    /// payment_failed_permanently=true), or "retries exhausted" if all
    /// max_retries attempts had path failures.
    ///
    /// Mutex discipline: the wallet lock is acquired briefly for prepare,
    /// apply, and abandon, then released for the HTTP fetch AND for the
    /// outcome polling loop. Background_tick and WS handlers can run while we
    /// wait, which is required for LDK to process the PaymentSent/PathFailed/
    /// Failed events from the peer messages and populate the outcome map.
    #[wasm_bindgen]
    pub fn send_payment_with_retries(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        max_retries: u32,
        progress_callback: &js_sys::Function,
        amount_sats_override: Option<u64>,
        amount_msat_override: Option<u64>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        let max_retries = max_retries.max(1); // at least one attempt
        // S45 (DP, "truly 0"): an exact millisat amount for a no-amount invoice.
        // It rides the single-path prepare only; MPP parts stay whole sats. The
        // sats override is derived from it when the page gives only msat.
        let amount_sats_override: Option<u64> = amount_sats_override.or(amount_msat_override.map(|m| m / 1000));
        let progress_callback = progress_callback.clone();
        future_to_promise(async move {
            use lij_core::node::PaymentOutcome;

            // v10: emit progress events to JS so the wallet UI can render
            // per-attempt telemetry (attempt number, exclusion count, outcome).
            // The callback receives a single JSON string argument; JS parses
            // and renders. Errors from the callback are swallowed so a buggy
            // UI handler can never break the payment flow.
            let emit = |json: String| {
                let _ = progress_callback.call1(
                    &wasm_bindgen::JsValue::NULL,
                    &wasm_bindgen::JsValue::from_str(&json),
                );
            };

            // ── MPP gate (v158) ───────────────────────────────────────────────
            // Decide single-path vs multipath up front. `Single` falls through to
            // the unchanged retry loop below; every other outcome is handled and
            // RETURNS here. Multipath assembles one shard per usable channel and
            // submits a single send_payment_with_route (one payment_hash).
            let mpp_decision = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().mpp_decision(&bolt11, amount_sats_override)
            };
            match mpp_decision {
                Ok(lij_core::node::MppDecision::Single) => {
                    // fall through to the single-path retry loop below.
                }
                Ok(lij_core::node::MppDecision::NoMppSupport) => {
                    emit(r#"{"phase":"no_mpp_support"}"#.to_string());
                    return Ok(payment_result_json(false, None, None, Some(
                        "recipient does not support split (MPP) payments — consolidate liquidity or request a smaller invoice".to_string())));
                }
                Ok(lij_core::node::MppDecision::ExceedsTotal { sendable_msat }) => {
                    let sendable_sats = sendable_msat / 1000;
                    emit(format!(r#"{{"phase":"exceeds_total","sendable_sats":{}}}"#, sendable_sats));
                    return Ok(payment_result_json(false, None, None, Some(format!(
                        "amount exceeds your total sendable across all channels (~{} sats)", sendable_sats))));
                }
                Ok(lij_core::node::MppDecision::Multi(parts)) => {
                    let shard_count = parts.len();
                    log::info!("[MPP] multipath send: {} shard(s)", shard_count);
                    emit(format!(r#"{{"phase":"mpp_start","shards":{}}}"#, shard_count));
                    let mut responses: Vec<(String, u64)> = Vec::with_capacity(shard_count);
                    for (i, part) in parts.iter().enumerate() {
                        let part_sats = part.part_msat / 1000;
                        emit(format!(
                            r#"{{"phase":"mpp_shard","shard":{},"shards":{},"sats":{}}}"#,
                            i + 1, shard_count, part_sats));
                        // lock: build THIS shard's route-build body (part amount)
                        let (url, body) = {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            match wallet.node().prepare_lsp_route_request(
                                &bolt11, &route_endpoint, &[], Some(part_sats))
                            {
                                Ok(p) => (p.url, p.request_body),
                                Err(e) => {
                                    emit(r#"{"phase":"mpp_error"}"#.to_string());
                                    return Ok(payment_result_json(false, None, None, Some(
                                        format!("MPP shard {} prepare failed: {}", i + 1, e))));
                                }
                            }
                        };
                        // fetch (lock released)
                        let resp = match lij_core::node::fetch_post_with_macaroon(
                            &url, &route_macaroon_hex, &body).await
                        {
                            Ok(t) => t,
                            Err(e) => {
                                emit(r#"{"phase":"mpp_error"}"#.to_string());
                                return Ok(payment_result_json(false, None, None, Some(
                                    format!("MPP shard {} HTTP error: {}", i + 1, e))));
                            }
                        };
                        responses.push((resp, part.scid));
                    }
                    // lock: assemble all shards + send as ONE payment.
                    // v160: also grab the outcomes handle — submission is NOT
                    // success (review 1.1); truth comes from LDK events.
                    let (result, outcomes_handle) = {
                        let wallet = inner.lock()
                            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                        (
                            wallet.node().send_mpp_from_responses(responses, &bolt11),
                            wallet.node().payment_outcomes_handle(),
                        )
                    };
                    let payment_id = match result {
                        Ok((r, pid)) if r.success => pid,
                        Ok((r, _)) => {
                            // synchronous rejection — abandon already ran in core
                            emit(r#"{"phase":"mpp_failed","stage":"submit"}"#.to_string());
                            return Ok(payment_result_json(false, None, None, r.error));
                        }
                        Err(e) => {
                            emit(r#"{"phase":"mpp_failed","stage":"submit"}"#.to_string());
                            return Ok(payment_result_json(false, None, None, Some(
                                format!("MPP send failed: {}", e))));
                        }
                    };

                    // Settlement poll: the recipient must assemble ALL shards
                    // before claiming; its MPP window (~60s) plus fail-back
                    // propagation bounds the wait — 120s covers the envelope.
                    emit(format!(r#"{{"phase":"mpp_settling","shards":{}}}"#, shard_count));
                    let outcome = wait_for_outcome(
                        outcomes_handle.clone(), payment_id, 120_000).await;
                    return match outcome {
                        Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                            log::info!("[MPP] settled: all shards claimed by recipient");
                            emit(r#"{"phase":"mpp_settled"}"#.to_string());
                            Ok(payment_result_json(true, preimage_hex,
                                fee_paid_msat.map(|m| m / 1000), None))
                        }
                        Some(PaymentOutcome::PathFailed { failed_scid, is_permanent, .. }) => {
                            let scid_str = failed_scid.map(|s| s.to_string())
                                .unwrap_or_else(|| "none".into());
                            log::warn!("[MPP] shard path failed at scid={} permanent={}",
                                scid_str, is_permanent);
                            emit(format!(
                                r#"{{"phase":"mpp_failed","stage":"shard","scid":"{}","permanent":{}}}"#,
                                scid_str, is_permanent));
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[MPP] abandon_payment warning: {}", e);
                                }
                                outcomes_handle.lock().unwrap().remove(&payment_id);
                            }
                            Ok(payment_result_json(false, None, None, Some(format!(
                                "MPP shard failed at scid={} — nothing was delivered; funds returned to you",
                                scid_str))))
                        }
                        Some(PaymentOutcome::Failed { reason }) => {
                            log::warn!("[MPP] payment terminally failed: {}", reason);
                            emit(r#"{"phase":"mpp_failed","stage":"terminal"}"#.to_string());
                            Ok(payment_result_json(false, None, None, Some(
                                format!("MPP payment failed: {}", reason))))
                        }
                        None => {
                            log::warn!("[MPP] settlement unconfirmed after 120s — abandoning, then waiting for the verdict (6a discipline)");
                            emit(r#"{"phase":"mpp_timeout"}"#.to_string());
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[MPP] abandon_payment warning: {}", e);
                                }
                            }
                            // 6a (S36, sender concurrent-retry redesign): the
                            // same abandon-then-wait as single-path — shards
                            // may sit held and abandon cannot recall them; a
                            // blind user resend is the same-hash duplicate
                            // class. Wait for the verdict before reporting.
                            emit(r#"{"phase":"awaiting_release","mpp":true}"#.to_string());
                            let verdict = wait_for_outcome(
                                outcomes_handle.clone(), payment_id, 600_000).await;
                            match verdict {
                                Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                                    log::info!("[MPP] late settle after timeout — payment succeeded");
                                    emit(r#"{"phase":"mpp_settled"}"#.to_string());
                                    Ok(payment_result_json(true, preimage_hex,
                                        fee_paid_msat.map(|m| m / 1000), None))
                                }
                                Some(_) => Ok(payment_result_json(false, None, None, Some(
                                    "split payment failed back — nothing was delivered; funds returned to you; safe to retry".to_string()))),
                                None => Ok(payment_result_json(false, None, None, Some(
                                    "split payment still unresolved after 10 more minutes — your sats are locked in flight, not lost; do NOT resend (check Activity)".to_string()))),
                            }
                        }
                    };
                }
                Err(e) => {
                    return Ok(payment_result_json(false, None, None, Some(
                        format!("MPP planning failed: {}", e))));
                }
            }

            // ── 6a (S36, sender concurrent-retry redesign) m2: pre-dispatch
            // in-flight probe. If LDK still tracks a PENDING outbound payment
            // for this invoice's hash (e.g. a page reload mid-hold), JOIN THE
            // WAIT — dispatching now would create a same-hash duplicate HTLC
            // (the S35 stacking class: one revealed preimage claims every
            // sibling). Poll until it resolves (≤10 min), then stop with
            // honest words: the in-loop verdict logic below only governs
            // attempts THIS call dispatched; an inherited in-flight payment
            // resolves to Activity, never to an auto-resend.
            {
                let preexisting = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    wallet.node().pending_payment_for_bolt11(&bolt11)
                };
                if let Some(pid_hex) = preexisting {
                    log::warn!("[6a-guard] in-flight HTLC already tracked for this invoice (payment_id={}) — waiting, not dispatching", pid_hex);
                    emit(r#"{"phase":"awaiting_release","inherited":true}"#.to_string());
                    use wasm_timer::Delay as GuardDelay;
                    let guard_started = js_sys::Date::now();
                    loop {
                        let _ = GuardDelay::new(std::time::Duration::from_millis(2000)).await;
                        let still = {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            wallet.node().pending_payment_for_bolt11(&bolt11)
                        };
                        if still.is_none() { break; }
                        if js_sys::Date::now() - guard_started > 600_000.0 {
                            return Ok(payment_result_json(false, None, None, Some(
                                "a previous attempt for this invoice is still in flight after 10 minutes — your sats are locked, not lost; do NOT resend; it will settle or fail back on its own (check Activity)".to_string())));
                        }
                    }
                    // Resolved — but WHICH way is not knowable from here
                    // (this call has no outcomes entry for an inherited id).
                    // Never auto-resend on ambiguity.
                    return Ok(payment_result_json(false, None, None, Some(
                        "a previous attempt for this invoice just resolved — check Activity before sending again (if the recipient was paid, the invoice is settled)".to_string())));
                }
            }

            let mut excluded_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut last_error: Option<String> = None;

            for attempt in 1..=max_retries {
                log::info!("[Phase10b-retry] attempt {}/{}, {} excluded pair(s) so far",
                    attempt, max_retries, excluded_pairs.len());
                emit(format!(
                    r#"{{"phase":"attempt_start","attempt":{},"max_retries":{},"excluded":{}}}"#,
                    attempt, max_retries, excluded_pairs.len()
                ));

                // ── Phase 1: lock, prepare (new PaymentId), release ──────────
                let prep = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    match wallet.node()
                        .prepare_lsp_route_request_msat(&bolt11, &route_endpoint, &excluded_pairs, amount_msat_override.or(amount_sats_override.map(|s| s.saturating_mul(1000)))) // B1: open-invoice amount ride; S45: msat-exact when the page gives its the single path
                    {
                        Ok(p) => p,
                        Err(e) => {
                            // Prepare failure (e.g. invoice decode) — terminal.
                            emit(format!(
                                r#"{{"phase":"prepare_error","attempt":{},"max_retries":{}}}"#,
                                attempt, max_retries
                            ));
                            return Ok(payment_result_json(false, None, None,
                                Some(format!("prepare failed: {}", e))));
                        }
                    }
                };

                // v223 (S39, 0.57.0 item h): held-claim internal sends have
                // dest == the active LSP; stamp the silence-phase events so
                // the page narrates a HELD payment instead of a search.
                let dest_is_lsp = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    wallet.node().dest_is_active_lsp(&prep.dest_pubkey_hex)
                };

                let payment_id = prep.payment_id;

                // ── Phase 2: HTTP fetch WITHOUT lock ──────────────────────
                // v227 (S43, speed): an INTERNAL send (dest == the active LSP)
                // never needed the answer — apply_lsp_route_and_send's v222
                // branch builds the wallet→LSP self-hop before reading it, and
                // since adapter 0.62.1 the LSP answered this exact body. Skip
                // the round trip and hand that body over verbatim; everything
                // downstream (lsp_hold parse, apply) sees what it saw before.
                // External destinations take the fetch exactly as before.
                let response_text = if dest_is_lsp {
                    log::info!("[Phase10b-retry] internal send (dest == active LSP) — route ask skipped (v227)");
                    String::from(r#"{"ok":false,"error":"destination_is_lsp","routes":[],"internal":true}"#)
                } else { match lij_core::node::fetch_post_with_macaroon(
                    &prep.url,
                    &route_macaroon_hex,
                    &prep.request_body,
                ).await {
                    Ok(t) => t,
                    Err(e) => {
                        last_error = Some(format!("HTTP error: {}", e));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"http_error","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        continue;
                    }
                } };

                // #29-hold (v167): adapter-signaled bounded hold — recipient
                // offline, LSP parks the HTLC (B-1/B-7). One HTLC, patient
                // wait, and NEVER a second attempt: retries against a held
                // payment stack duplicate HTLCs and manufacture false
                // failures while the money quietly settles (M3 evidence).
                let lsp_hold_cap_s: Option<u64> = (|| {
                    let parsed: serde_json::Value = serde_json::from_str(&response_text).ok()?;
                    let hold = parsed.get("lsp_hold")?;
                    if hold.get("active")?.as_bool()? { hold.get("cap_s")?.as_u64() } else { None }
                })();

                // ── Phase 3: lock, apply (submit HTLC), get outcomes handle, release ──
                let (apply_result, outcomes_handle) = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    let result = wallet.node()
                        .apply_lsp_route_and_send(&response_text, &prep)
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    let handle = wallet.node().payment_outcomes_handle();
                    (result, handle)
                };

                if !apply_result.success {
                    // Synchronous failure from cm.send_payment_with_route —
                    // typically means an immediate validation rejection
                    // (insufficient capacity, route_not_found, etc.). No
                    // outcome event will fire for this attempt.
                    last_error = apply_result.error.clone();
                    log::warn!("[Phase10b-retry] synchronous send rejection: {:?}", last_error);
                    emit(format!(
                        r#"{{"phase":"sync_reject","attempt":{},"max_retries":{}}}"#,
                        attempt, max_retries
                    ));
                    if attempt >= max_retries {
                        return Ok(payment_result_json(false, None, None, last_error));
                    }
                    continue;
                }

                // ── Phase 4: poll outcomes map WITHOUT lock ────────────────
                // Normal: 30s per attempt. HELD: the LSP told us it parked the
                // HTLC (recipient offline) — wait the full hold cap + 60s
                // grace; the upstream settle or watchdog-fail decides.
                let wait_ms = match lsp_hold_cap_s {
                    Some(cap) => {
                        emit(format!(
                            r#"{{"phase":"held","attempt":{},"cap_s":{}}}"#,
                            attempt, cap));
                        cap.saturating_add(60) * 1000
                    }
                    None => 30000,
                };
                let outcome = wait_for_outcome(outcomes_handle.clone(), payment_id, wait_ms).await;

                match outcome {
                    Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                        log::info!("[Phase10b-retry] PAYMENT SUCCEEDED on attempt {}/{}",
                            attempt, max_retries);
                        emit(format!(
                            r#"{{"phase":"succeeded","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        return Ok(payment_result_json(
                            true,
                            preimage_hex,
                            fee_paid_msat.map(|m| m / 1000),
                            None,
                        ));
                    }
                    Some(PaymentOutcome::PathFailed {
                        failed_scid,
                        failed_from_pubkey,
                        failed_to_pubkey,
                        is_permanent,
                    }) => {
                        let scid_str = failed_scid.map(|s| s.to_string()).unwrap_or_else(|| "none".into());
                        last_error = Some(format!(
                            "path failed at scid={} (attempt {}/{}{})",
                            scid_str, attempt, max_retries,
                            if is_permanent { ", permanent" } else { "" }
                        ));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"path_failed","attempt":{},"max_retries":{},"scid":"{}","permanent":{}}}"#,
                            attempt, max_retries, scid_str, is_permanent
                        ));

                        if lsp_hold_cap_s.is_some() {
                            // Held payments never retry: the failure IS the
                            // hold's verdict (recipient stayed offline past
                            // the window); the sats are already returned.
                            log::warn!("[Phase10b-retry] held payment failed — recipient stayed offline; not retrying");
                            return Ok(payment_result_json(false, None, None, Some(
                                "recipient stayed offline — the held payment expired and your sats were returned".to_string())));
                        }
                        if is_permanent {
                            log::warn!("[Phase10b-retry] permanent failure — not retrying");
                            return Ok(payment_result_json(false, None, None, last_error));
                        }

                        if let (Some(from), Some(to)) = (failed_from_pubkey, failed_to_pubkey) {
                            log::info!("[Phase10b-retry] adding exclusion: from={}… to={}…",
                                hex::encode(&from[..8.min(from.len())]),
                                hex::encode(&to[..8.min(to.len())]));
                            excluded_pairs.push((from, to));
                        } else {
                            log::warn!("[Phase10b-retry] no exclusion data (failed scid=0 or self-channel) — retry may hit same path");
                        }

                        // Abandon the old payment_id in LDK so its Retryable
                        // state is cleaned up. This fires PaymentFailed for
                        // the old id (our handler records it, then we drain
                        // it below). Without abandon, the OutboundPayments
                        // map grows by one entry per retry attempt.
                        {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                log::warn!("[Phase10b-retry] abandon_payment warning: {}", e);
                            }
                            // Also drop the old outcome entry to prevent map growth
                            outcomes_handle.lock().unwrap().remove(&payment_id);
                        }

                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        // continue loop for next attempt
                    }
                    Some(PaymentOutcome::Failed { reason }) => {
                        // v9: RetriesExhausted is LDK's internal retry budget,
                        // not a terminal payment failure. node.rs PaymentFailed
                        // handler preserves the prior PathFailed in this case,
                        // so we usually take the PathFailed arm above. This is
                        // a safety net for cases where Failed somehow arrives
                        // without a prior PathFailed (shouldn't happen in
                        // practice but defensive coding here costs nothing).
                        if reason.contains("RetriesExhausted") && attempt < max_retries && lsp_hold_cap_s.is_none() {
                            last_error = Some(format!(
                                "LDK retries exhausted (attempt {}/{}) — retrying without specific exclusion",
                                attempt, max_retries));
                            log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[Phase10b-retry] abandon_payment warning: {}", e);
                                }
                                outcomes_handle.lock().unwrap().remove(&payment_id);
                            }
                            continue;
                        }
                        log::warn!("[Phase10b-retry] PaymentFailed (terminal): {}", reason);
                        emit(format!(
                            r#"{{"phase":"terminal_failure","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        return Ok(payment_result_json(false, None, None,
                            Some(format!("terminal failure: {}", reason))));
                    }
                    None => {
                        if lsp_hold_cap_s.is_some() {
                            // Held wait elapsed without any event — treat as
                            // the hold expiring; never a second attempt.
                            emit(format!(r#"{{"phase":"held_expired","attempt":{}}}"#, attempt));
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            let _ = wallet.node().abandon_payment(payment_id);
                            outcomes_handle.lock().unwrap().remove(&payment_id);
                            return Ok(payment_result_json(false, None, None, Some(
                                "hold window elapsed — recipient did not return; your sats return automatically".to_string())));
                        }
                        last_error = Some(format!(
                            "timeout waiting for outcome (attempt {}/{}, 30s elapsed)",
                            attempt, max_retries));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"timeout","attempt":{},"max_retries":{},"dest_is_lsp":{}}}"#,
                            attempt, max_retries, dest_is_lsp
                        ));

                        // ── 6a (S36, sender concurrent-retry redesign) m1:
                        // ABANDON-THEN-WAIT. Silence ≠ failure: the HTLC may
                        // be parked at an interceptor (unsignaled hold), and
                        // abandon_payment cannot recall an in-flight HTLC —
                        // it only stops LDK's own retries; the terminal
                        // PaymentFailed fires ONLY once every HTLC has
                        // actually failed back. The old code deleted its map
                        // entry and re-dispatched immediately — a fresh
                        // full-amount HTLC per 30s of silence (the S35
                        // five-sibling stack; one revealed preimage claims
                        // every sibling). Now: abandon, KEEP the entry, wait
                        // for the verdict; only a confirmed fail-back
                        // permits a retry.
                        {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                log::warn!("[Phase10b-retry] abandon_payment (timeout) warning: {}", e);
                            }
                            // outcomes entry deliberately NOT removed — it is
                            // the release signal we are about to wait on.
                        }
                        emit(format!(
                            r#"{{"phase":"awaiting_release","attempt":{},"max_retries":{},"dest_is_lsp":{}}}"#,
                            attempt, max_retries, dest_is_lsp
                        ));
                        let verdict = wait_for_outcome(
                            outcomes_handle.clone(), payment_id, 600_000).await;
                        match verdict {
                            Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                                // Late settle: the "stuck" HTLC was a held
                                // payment that completed — success, and the
                                // exact case where a blind retry double-pays.
                                log::info!("[6a-guard] late settle after timeout — payment succeeded");
                                emit(format!(r#"{{"phase":"late_settle","attempt":{}}}"#, attempt));
                                return Ok(payment_result_json(true, preimage_hex,
                                    fee_paid_msat.map(|m| m / 1000), None));
                            }
                            Some(PaymentOutcome::PathFailed { .. }) => {
                                // PaymentPathFailed IS the fail-back receipt:
                                // the HTLC came home. Drain the trailing
                                // PaymentFailed(UserAbandoned) the abandon
                                // above will fire for this id, then retry.
                                log::info!("[6a-guard] fail-back confirmed after timeout — retry permitted");
                                emit(format!(r#"{{"phase":"release_confirmed","attempt":{}}}"#, attempt));
                                {
                                    use wasm_timer::Delay as DrainDelay;
                                    for _ in 0..15 {
                                        let _ = DrainDelay::new(std::time::Duration::from_millis(100)).await;
                                        if outcomes_handle.lock().unwrap().remove(&payment_id).is_some() { break; }
                                    }
                                }
                            }
                            Some(PaymentOutcome::Failed { .. }) => {
                                // Terminal PaymentFailed: every HTLC for this
                                // id resolved failed. Retry is safe.
                                log::info!("[6a-guard] terminal fail-back confirmed after timeout — retry permitted");
                                emit(format!(r#"{{"phase":"release_confirmed","attempt":{}}}"#, attempt));
                            }
                            None => {
                                // Ten further minutes and the HTLC is STILL
                                // neither settled nor failed back. Honest
                                // stop — the invariant forbids another
                                // dispatch while it hangs.
                                return Ok(payment_result_json(false, None, None, Some(
                                    "previous attempt still unresolved after 10 minutes — your sats are locked in flight, not lost; do NOT resend; it will settle or fail back on its own (check Activity)".to_string())));
                            }
                        }

                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        // continue — retry without specific exclusion
                    }
                }
            }

            // Loop fell through (shouldn't happen — every branch returns).
            Ok(payment_result_json(false, None, None,
                last_error.or_else(|| Some("retry loop exhausted".into()))))
        })
    }

    /// S45 (DP): the same quote for a PUBKEY destination with no invoice —
    /// Max pricing a route to another LSP's node (an LNURL address that LSP
    /// serves) before any invoice is minted. Records any lsp_first_hop_policy
    /// sighting like quote_route_fee. Resolves to the same JSON shape.
    #[wasm_bindgen]
    pub fn quote_route_fee_to_pubkey(
        &self,
        dest_pubkey_hex: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        amount_sats: u64,
    ) -> js_sys::Promise {
        let dest = dest_pubkey_hex.to_string();
        let endpoint = route_endpoint.to_string();
        let mac = route_macaroon_hex.to_string();
        future_to_promise(async move {
            let (url, body) = lij_core::node::prepare_route_quote_to_pubkey(&dest, &endpoint, amount_sats)
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let response_text = lij_core::node::fetch_post_with_macaroon(&url, &mac, &body).await
                .map_err(|e| JsValue::from_str(&format!("quote fetch: {}", e)))?;
            let amount_msat = amount_sats.saturating_mul(1000);
            let fee_msat = lij_core::node::quote_total_fee_msat_from_response(&response_text, amount_msat);
            let synth = serde_json::from_str::<serde_json::Value>(&response_text).ok()
                .and_then(|v| v.get("_synth").and_then(|s| s.as_bool()))
                .unwrap_or(false);
            let policy_seen = lij_core::node::LSP_FEE_SEEN.load(std::sync::atomic::Ordering::Relaxed);
            Ok(JsValue::from_str(&format!(
                r#"{{"fee_msat":{},"fee_sats":{},"amount_msat":{},"policy_seen":{},"synth":{}}}"#,
                fee_msat, (fee_msat + 999) / 1000, amount_msat, policy_seen, synth)))
        })
    }

    /// v216 (S36, O6 fee headroom → exact-fee): the scan-time quote. Runs the
    /// SAME route-build the send path uses (pure QueryRoutes proxy — verified
    /// side-effect-free in adapter code), records any lsp_first_hop_policy
    /// sighting into the exact-fee cache, and returns the total sender fee
    /// for this invoice/amount. The throwaway PaymentId from prepare is never
    /// applied. Resolves to JSON:
    ///   {"fee_msat":N,"fee_sats":N,"amount_msat":N,"policy_seen":bool,"synth":bool}
    #[wasm_bindgen]
    pub fn quote_route_fee(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        amount_sats_override: Option<u64>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        future_to_promise(async move {
            // Amount first: invoice-fixed or override (open invoices) — core
            // helper, lij-wasm carries no lightning-invoice dep of its own.
            let amount_msat: u64 = lij_core::node::invoice_amount_msat(&bolt11, amount_sats_override)
                .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
            // Prepare under lock (brief), release before network — v8 discipline.
            let prep = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node()
                    .prepare_lsp_route_request(&bolt11, &route_endpoint, &[], amount_sats_override)
                    .map_err(|e| JsValue::from_str(&format!("quote prepare: {}", e)))?
            };
            let response_text = lij_core::node::fetch_post_with_macaroon(
                &prep.url, &route_macaroon_hex, &prep.request_body).await
                .map_err(|e| JsValue::from_str(&format!("quote fetch: {}", e)))?;
            let fee_msat = lij_core::node::quote_total_fee_msat_from_response(
                &response_text, amount_msat);
            let synth = serde_json::from_str::<serde_json::Value>(&response_text).ok()
                .and_then(|v| v.get("_synth").and_then(|s| s.as_bool()))
                .unwrap_or(false);
            let policy_seen = lij_core::node::LSP_FEE_SEEN
                .load(std::sync::atomic::Ordering::Relaxed);
            Ok(JsValue::from_str(&format!(
                r#"{{"fee_msat":{},"fee_sats":{},"amount_msat":{},"policy_seen":{},"synth":{}}}"#,
                fee_msat, (fee_msat + 999) / 1000, amount_msat, policy_seen, synth)))
        })
    }

    #[wasm_bindgen]
    pub fn create_invoice(
        &self,
        amount_sats: Option<u64>,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: Option<String>,
        lsp_route_macaroon: Option<String>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        future_to_promise(async move {
            // Build under lock (sync, brief), release before any network I/O
            // -- the v8 mutex discipline.
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.create_invoice(amount_sats, &memo, expiry_seconds)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            // v168: best-effort hash-keyed secret registration so held
            // forwards can trampoline (B-10) with the sender offline. NEVER
            // fails the invoice -- a miss just means legacy RESUME semantics.
            if let (Some(ep), Some(mac), Some(amt)) = (lsp_endpoint, lsp_route_macaroon, amount_sats) {
                if let Err(e) = lij_core::lsps2::lsps2_register_invoice_secret(
                    &ep, &mac, &result.payment_hash, &result.payment_secret, amt * 1000,
                ).await {
                    log::warn!("v168: invoice-secret registration failed (non-fatal): {}", e);
                }
            }
            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v0.16 Phase C: create a Lightning invoice with an LSPS2 JIT channel
    /// route_hint.
    ///
    /// Three-phase flow with proper mutex discipline (matches v8 send-path
    /// pattern that fixed mutex_no_threads panics):
    ///   1. lsps2 get_info — network round-trip, NO wallet lock held
    ///   2. lsps2 buy      — network round-trip, NO wallet lock held
    ///   3. build invoice  — sync, wallet lock held briefly
    ///
    /// JS receives the parsed InvoiceWithJitResult as a JSON string. Errors
    /// (network failure, validation failure, lock failure) are thrown as JS
    /// exceptions.
    ///
    /// # Example (JS)
    /// ```javascript
    /// const r = await wallet.create_invoice_with_jit(
    ///   BigInt(50000), "Coffee", BigInt(600),
    ///   "https://lijox-lsp.lightning-mod.com", route_macaroon,
    /// );
    /// const result = JSON.parse(r);
    /// displayInvoice(result.invoice.bolt11);
    /// displayFeeBreakdown(result.jit.human_summary);
    /// ```
    #[wasm_bindgen]
    pub fn create_invoice_with_jit(
        &self,
        amount_sats: u64,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: &str,
        lsp_route_macaroon: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        let endpoint = lsp_endpoint.to_string();
        let macaroon = lsp_route_macaroon.to_string();
        future_to_promise(async move {
            // Phase 0 (NEW for D.2): fetch wallet pubkey BRIEFLY under lock,
            // then release before any network I/O. Pubkey is needed by the
            // adapter v0.18+ /lsps2/buy endpoint to know where to open the
            // JIT channel when a matching HTLC arrives.
            let client_pubkey = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (pubkey): {e}")))?;
                wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // lock released

            // Phase 1: fetch service terms WITHOUT wallet lock
            let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &macaroon)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Phase 2: buy the JIT promise WITHOUT wallet lock (passing our pubkey)
            // v217 (S36, O5 full balance availability): the prefund rides INSIDE
            // payment_size — sized from get_info's ADVISORY, verified against the
            // buy's BINDING stamp. Loose overage instead would strand an MPP
            // payer's last shard beyond the completeness gross and our own A6
            // (duplicate-retry shard guard) would bounce it. A governor flip
            // between the two calls = one rebuy at the stamped value; a second
            // disagreement = final fallback with no prefund. Abandoned promises
            // simply expire adapter-side.
            let amount_msat = amount_sats * 1000;
            let mut prefund_msat = info.prefund_msat_u64();
            let mut buy = lij_core::lsps2::lsps2_buy(
                &endpoint, &macaroon, Some(amount_msat + prefund_msat), &client_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if buy.prefund_msat_u64() != prefund_msat {
                let stamped = buy.prefund_msat_u64();
                log::warn!("[O5] prefund advisory {} != binding stamp {} — rebuying at the stamp", prefund_msat, stamped);
                prefund_msat = stamped;
                buy = lij_core::lsps2::lsps2_buy(
                    &endpoint, &macaroon, Some(amount_msat + prefund_msat), &client_pubkey)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                if buy.prefund_msat_u64() != prefund_msat {
                    log::warn!("[O5] stamp moved again — final fallback: no prefund this invoice");
                    prefund_msat = 0;
                    buy = lij_core::lsps2::lsps2_buy(
                        &endpoint, &macaroon, Some(amount_msat), &client_pubkey)
                        .await
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    if buy.prefund_msat_u64() != 0 { buy.prefund_msat = Some("0".to_string()); }
                }
            }

            // Phase 3: build invoice WITH wallet lock (sync, brief)
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (build): {e}")))?;
                wallet.build_invoice_with_jit_promise(amount_sats, &memo, expiry_seconds, &info, buy)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // lock released

            // Phase 4 (Option B): register the invoice's payment_secret with the
            // LSP BEFORE returning, so it is in place before the payer can pay.
            // The LSP needs it to rebuild the final hop in sendToRouteV2 (it can't
            // read it from the onion -- penultimate hop). total_msat is the NET the
            // wallet will receive (== amount_msat); the LSP deducts its open fee
            // from the inflated invoice and forwards exactly this.
            // v217 (O5): the registered total is the NET the wallet will receive
            // — amount + prefund — the adapter rebuilds the final hop's mpp
            // total from THIS number, so it must match create_inbound exactly.
            lij_core::lsps2::lsps2_register_secret(
                &endpoint,
                &macaroon,
                &result.jit.jit_channel_scid,
                &result.payment_secret_hex,
                amount_msat + prefund_msat,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v188 (S27): OPEN-AMOUNT JIT invoice — zero-amount sibling of
    /// create_invoice_with_jit. Same Phase 0-4 choreography; buy carries
    /// NO payment_size (variable mode); register_secret sends total_msat=0
    /// (the variable sentinel — adapter fills the real total at flush).
    #[wasm_bindgen]
    /// v195 (S30): LNURLp hash pool — generates preimages inside the wallet,
    /// persists them, and returns JSON [{hash, secret}] for LSP registration.
    /// Preimages never cross this boundary.
    /// v229: `start_hint` = the LSP's next_index for this name (the page passes
    /// it from the register probe; undefined/None when the LSP is older).
    pub fn lnurlp_prepare_hashes(&self, count: u32, start_hint: Option<u32>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error (lnurlp): {e}")))?;
            wallet
                .lnurlp_prepare_hashes(count, start_hint)
                .map(|s| JsValue::from_str(&s))
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    pub fn create_open_invoice_with_jit(
        &self,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: &str,
        lsp_route_macaroon: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        let endpoint = lsp_endpoint.to_string();
        let macaroon = lsp_route_macaroon.to_string();
        future_to_promise(async move {
            let client_pubkey = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (pubkey): {e}")))?;
                wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &macaroon)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let buy = lij_core::lsps2::lsps2_buy(&endpoint, &macaroon, None, &client_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (build): {e}")))?;
                wallet.build_open_invoice_with_jit_promise(&memo, expiry_seconds, &info, buy)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            lij_core::lsps2::lsps2_register_secret(
                &endpoint,
                &macaroon,
                &result.jit.jit_channel_scid,
                &result.payment_secret_hex,
                0, // VARIABLE SENTINEL — adapter fills real total at quiescence flush
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    #[wasm_bindgen]
    pub fn node_pubkey(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node_pubkey()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v184: node-key message signing (LND signmessage-compatible zbase32).
    /// Serves the LIJOX delegate slip/void digests. Sync, no I/O.
    #[wasm_bindgen]
    pub fn sign_message(&self, msg: &str) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.sign_message(msg)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn list_lsps(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let lsps = wallet.list_lsps()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&lsps)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Step 3.6 (F4): synchronous accessor for the currently-active LSP.
    /// Returns the LSP's info as a JSON string, or None when no LSP is set.
    ///
    /// Unlike list_lsps(), this does NOT do an HTTP fetch — it reads from
    /// in-memory state under the wallet mutex, then releases the lock before
    /// returning. Safe to call from polling loops without risking the
    /// "cannot recursively acquire mutex" panic that hit Step 3.5's hot-fix
    /// when getActiveLsp() tried list_lsps() as a fallback.
    ///
    /// The frontend's getActiveLsp() helper already calls this binding; once
    /// this method ships, the LSP fields on Cards 2 and 3 will populate and
    /// the LSP relationship card on the Connection screen will render.
    #[wasm_bindgen]
    pub fn active_lsp_json(&self) -> Result<Option<String>, JsValue> {
        // Phase 3.8.B: try_lock to avoid recursive-mutex panic when an async
        // user action is holding the lock. JS treats WALLET_BUSY as a
        // skip-this-tick signal; UI keeps last-known state.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        match wallet.active_lsp() {
            Some(active) => {
                let json = serde_json::to_string(&active.info)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                Ok(Some(json))
            }
            None => Ok(None),
        }
    }

    // ── Channel close operations ────────────────────────────────────────

    /// Initiate a cooperative close. Synchronous from JS perspective —
    /// returns once shutdown is sent. Actual close confirmation arrives
    /// later via the closed-channels list.
    #[wasm_bindgen]
    pub fn close_channel(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.close_channel(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Force close a channel. Destructive — UI must confirm first.
    #[wasm_bindgen]
    pub fn force_close(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.force_close(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Force-close ONE channel without broadcasting any tx. For a stranded
    /// open whose funding never confirmed (LDK's no-progress watchdog keeps
    /// dropping the peer over it). Broadcasts nothing — safe for an
    /// unconfirmed funding. Destructive — UI must confirm first.
    #[wasm_bindgen]
    pub fn force_close_without_broadcasting(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.force_close_without_broadcasting(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Step 3 (S30): drop a tier-2 pending tx by txid — the dead-funding
    /// janitor's executioner. The UI judges (Esplora outspend verdicts on the
    /// record's spent_outpoints); this removes the record so
    /// rebroadcast-until-seen stops and its input reservation releases.
    /// Returns {"removed":bool}.
    #[wasm_bindgen]
    pub fn drop_pending_tx(&self, txid_hex: &str) -> Result<String, JsValue> {
        let storage: std::sync::Arc<dyn lij_core::storage::LijStorage> =
            std::sync::Arc::new(LocalStorage);
        let removed = lij_core::tier2_wallet::drop_pending_tx(storage.as_ref(), txid_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"removed\":{}}}", removed))
    }

    /// End relationship with an LSP. Returns JSON array of per-channel
    /// outcomes: [{ "channel_id_hex": "...", "ok": true/false, "error": "..." }, ...]
    #[wasm_bindgen]
    pub fn end_lsp_relationship(&self, lsp_pubkey_hex: &str) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let results = wallet.end_lsp_relationship(lsp_pubkey_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mapped: Vec<serde_json::Value> = results.into_iter().map(|(cid, r)| {
            match r {
                Ok(()) => serde_json::json!({
                    "channel_id_hex": cid,
                    "ok": true,
                }),
                Err(e) => serde_json::json!({
                    "channel_id_hex": cid,
                    "ok": false,
                    "error": e.to_string(),
                }),
            }
        }).collect();
        serde_json::to_string(&mapped)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return the closed-channel log as JSON.
    #[wasm_bindgen]
    pub fn list_closed_channels(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let records = wallet.list_closed_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&records)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Maturing on-chain outputs from channel closes still tracked by the
    /// OutputSweeper. Each entry is a force-close to_local (or other spendable)
    /// output that has not yet fully landed in the spendable balance. The UI
    /// sums these for the balance-card "maturing" subtext and groups them by
    /// channel for per-close detail. Returns a JSON array; "[]" before the
    /// sweeper is initialized (the narrow pre-init window) or when nothing is
    /// maturing.
    ///
    /// Each entry: { value_sats, status, delayed_until_height, confirmation_height, channel_id }
    ///   status "pending_broadcast" — sweep tx not yet broadcast. CSV-locked
    ///     while delayed_until_height is in the future; blocks-remaining =
    ///     delayed_until_height - tip (the UI computes this against its tip).
    ///   status "sweeping"          — sweep tx broadcast, awaiting first
    ///     confirmation (≈1 block out).
    ///   status "confirming"        — sweep tx confirmed; the funds are landing
    ///     in the spendable balance via the normal Tier-2 scan, so the UI does
    ///     NOT count these as still-maturing (avoids double-counting).
    #[wasm_bindgen]
    pub fn maturing_outputs(&self) -> Result<String, JsValue> {
        use lightning::sign::SpendableOutputDescriptor as SOD;
        use lightning::util::sweep::OutputSpendStatus as OSS;
        use serde_json::json;
        // try_lock: this is called from the balance refresh path, which runs
        // alongside the background tick — never block it (mirrors get_channels
        // / active_lsp_json). A momentary WALLET_BUSY just retries next refresh.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let sweeper = match wallet.node().output_sweeper() {
            Some(s) => s,
            None => return Ok("[]".to_string()),
        };
        let outputs = sweeper.tracked_spendable_outputs();
        let arr: Vec<serde_json::Value> = outputs
            .iter()
            .map(|o| {
                // bitcoin 0.30: TxOut.value is u64 sats across all descriptor variants.
                // Also surface the variant + destination scriptPubKey (hex) so we
                // can tell a coop StaticOutput paying m/84 from one paying the
                // m/525 P2WSH anchor script (the v128-exclusion diagnosis).
                let (value_sats, descriptor_type, dest_spk): (u64, &str, String) = match &o.descriptor {
                    SOD::StaticOutput { output, .. } =>
                        (output.value, "StaticOutput", hex::encode(output.script_pubkey.as_bytes())),
                    SOD::DelayedPaymentOutput(d) =>
                        (d.output.value, "DelayedPaymentOutput", hex::encode(d.output.script_pubkey.as_bytes())),
                    SOD::StaticPaymentOutput(d) =>
                        (d.output.value, "StaticPaymentOutput", hex::encode(d.output.script_pubkey.as_bytes())),
                };
                let (status, delayed_until_height, confirmation_height): (&str, Option<u32>, Option<u32>) =
                    match &o.status {
                        OSS::PendingInitialBroadcast { delayed_until_height } => {
                            ("pending_broadcast", *delayed_until_height, None)
                        }
                        OSS::PendingFirstConfirmation { .. } => ("sweeping", None, None),
                        OSS::PendingThresholdConfirmations { confirmation_height, .. } => {
                            ("confirming", None, Some(*confirmation_height))
                        }
                    };
                json!({
                    "value_sats": value_sats,
                    "descriptor_type": descriptor_type,
                    "dest_spk": dest_spk,
                    "status": status,
                    "delayed_until_height": delayed_until_height,
                    "confirmation_height": confirmation_height,
                    // ChannelId Display is lowercase hex — matches get_channels'
                    // channel_id / closed-record channel_id_hex for UI linkage.
                    "channel_id": o.channel_id.as_ref().map(|c| c.to_string()),
                })
            })
            .collect();
        serde_json::to_string(&arr).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// TEMP diagnostic: dump the SpendableOutputs event log — every descriptor
    /// (incl. v128-excluded StaticOutputs) seen at the event handler, with
    /// variant + value + destination script. Confirms what an anchors coop
    /// close emits. Returns a JSON array of objects. No wallet lock needed
    /// (thread_local). Remove with the rest of the temp diagnostics.
    #[wasm_bindgen]
    pub fn spendable_outputs_log(&self) -> String {
        let lines = lij_core::node::spendable_log_dump();
        format!("[{}]", lines.join(","))
    }

    /// TEMP diagnostic: dump the close-event log — every ChannelClosed reason and
    /// every coop/force close invocation, with timestamps, so the close SEQUENCE
    /// for a channel is visible. Remove with the rest of the temp diagnostics.
    #[wasm_bindgen]
    pub fn close_event_log(&self) -> String {
        let lines = lij_core::node::close_event_dump();
        format!("[{}]", lines.join(","))
    }

    /// TEMP diagnostic: why matured sweeps aren't broadcasting — broadcaster queue
    /// depth + failures, and the sweeper's internal height vs the real tip.
    #[wasm_bindgen]
    pub fn sweeper_broadcast_diag(&self, real_tip: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().sweeper_broadcast_diag(real_tip))
    }

    /// TEMP diagnostic: replicate the sweeper's spend_outputs to find which step
    /// fails (fee / change-script / signing) and the fee-vs-value numbers.
    #[wasm_bindgen]
    pub fn sweeper_spend_attempt_diag(&self, real_tip: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().sweeper_spend_attempt_diag(real_tip))
    }
    #[wasm_bindgen]
    pub fn outstanding_close_attempts(&self) -> Result<String, JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let snapshot = wallet.outstanding_close_attempts_snapshot()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&snapshot)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Pre-maturity closing funds (ChannelMonitor claimable, CSV-locked).
    /// See node::maturing_balances_json.
    #[wasm_bindgen]
    pub fn maturing_balances_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().maturing_balances_json())
    }

    /// v206: payments CLAIMED this session, as `[{"hash":"<hex>","sats":N}]`.
    /// The frontend ledger completes a pending receive only when its
    /// payment_hash appears here — an authoritative claim signal that replaces
    /// the balance-delta heuristic. See node::claimed_payments_json.
    #[wasm_bindgen]
    pub fn claimed_payments_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().claimed_payments_json())
    }

    /// S21 build #1 (ledger reconciler): expose LDK's recent outbound
    /// payments for the startup RECENT backfill. JSON array of
    /// {state, payment_id, payment_hash?, total_msat?}. try_lock — the
    /// frontend retries on a stagger, never blocks the UI thread.
    /// v189 (S29): abandon a stuck outbound payment by PaymentId hex, as
    /// reported by list_recent_payments_json. Makes ledger retirement
    /// terminal in LDK, so Pass-2 backfill can never resurrect a ghost
    /// after a history clear.
    #[wasm_bindgen]
    pub fn abandon_payment_by_id(&self, payment_id_hex: &str) -> Result<(), JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().abandon_payment_by_id_hex(payment_id_hex)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn list_recent_payments_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().recent_payments_json())
    }

    /// S21 item 2 (persistence audit): true when load-time stamps showed the
    /// manager stale vs monitors (interrupted save). Frontend surfaces honest
    /// copy; LDK's protective FC is expected behavior in this state.
    #[wasm_bindgen]
    pub fn persist_skew_at_load(&self) -> bool {
        match self.inner.try_lock() {
            Ok(w) => w.node().persist_skew_at_load(),
            Err(_) => false,
        }
    }

    /// Build #4 confirmation instrument: pending-record audit vs the
    /// independent quorum. Async — the wallet lock is dropped before any
    /// network I/O.
    #[wasm_bindgen]
    pub async fn pending_onchain_audit_json(&self) -> Result<String, JsValue> {
        let (storage, indep) = {
            let wallet = match self.inner.try_lock() {
                Ok(w) => w,
                Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
            };
            wallet.node().audit_handles()
        };
        Ok(lij_core::node::pending_onchain_audit(storage, indep).await)
    }

    /// v173: the planner's own sendable ceiling — the ONE number every send
    /// surface quotes (identical math to mpp_plan's total_usable_sats).
    #[wasm_bindgen]
    pub fn max_sendable_sats(&self) -> u64 {
        match self.inner.try_lock() {
            Ok(w) => w.node().max_sendable_sats(),
            Err(_) => 0,
        }
    }

    /// FOREGROUND HINT: force the next background tick to re-scan for closes,
    /// regardless of cadence phase. Best-effort — silently skips if the wallet
    /// is busy (a walk is likely already in flight). See node::note_foreground.
    #[wasm_bindgen]
    pub fn note_foreground(&self) {
        if let Ok(wallet) = self.inner.try_lock() {
            wallet.node().note_foreground();
        }
    }

    /// BACKGROUND HINT (D-1 JIT safety): clears the channel-acceptance gate so a
    /// backgrounded/offline wallet refuses inbound JIT opens it couldn't claim
    /// into. The wallet lock is never held across an await, so try_lock is free
    /// at the visibilitychange callback boundary; the event also fires before any
    /// grace-period background tick can process an OpenChannelRequest.
    #[wasm_bindgen]
    pub fn note_background(&self) {
        if let Ok(wallet) = self.inner.try_lock() {
            wallet.node().note_background();
        }
    }

    /// DIAGNOSTICS: monitor census + spend-walker liveness for the on-device
    /// status pane (iOS has no console). See node::diagnostics_json.
    #[wasm_bindgen]
    pub fn diagnostics_json(&self) -> Result<String, JsValue> {
        // try_lock — called from the status-pane refresh alongside the
        // background tick; never block it (mirrors maturing_outputs).
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().diagnostics_json())
    }

    #[wasm_bindgen]
    pub fn switch_lsp(&self, lsp_pubkey: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let lsp_pubkey = lsp_pubkey.to_string();
        future_to_promise(async move {
            let mut wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.switch_lsp(&lsp_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::undefined())
        })
    }

    /// Register a Web Push wake subscription (D-1 2c offline-receive). Takes the
    /// browser PushSubscription serialized to JSON; signs the `push-subscribe`
    /// challenge with the node key and POSTs to the active LSP. The returned
    /// Promise resolves on success and rejects with the error string on failure.
    #[wasm_bindgen]
    pub fn register_push_subscription(&self, subscription_json: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.register_push_subscription(&subscription_json)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::undefined())
        })
    }

    #[wasm_bindgen]
    pub fn backup(&self) -> js_sys::Promise {
        // Delegate to the lock-safe path (snapshot under lock, push unlocked).
        // The frontend may call this automatically after payments/channel events,
        // so it must not hold the wallet mutex across the push's .await.
        self.backup_now()
    }

    #[wasm_bindgen]
    /// v209: the SAME ciphertext the cloud sink receives, returned to the page
    /// for a manual device download. Forces a fresh snapshot via the dirty
    /// handle; state is unchanged, so the next auto-backup is a cheap no-op.
    #[wasm_bindgen]
    pub fn export_backup_blob(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node().backup_dirty_handle().store(true, std::sync::atomic::Ordering::Relaxed);
        let prep = wallet.prepare_backup_if_dirty()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        match prep {
            Some((blob, _signer, _sinks, _dirty)) => serde_json::to_string(&blob)
                .map_err(|e| JsValue::from_str(&e.to_string())),
            None => Err(JsValue::from_str("no backup state yet")),
        }
    }

    /// v221 (DP fire-and-forget): device-file backup import — parses the v209
    /// export's StateBlob JSON and injects through the same generic path the
    /// cloud restore uses (wrong-seed files fail decryption). Returns
    /// {"keys":N}; the page gates live channels and reloads — state applies
    /// on the reboot.
    #[wasm_bindgen]
    pub fn import_backup_blob(&self, blob_json: &str) -> Result<String, JsValue> {
        let blob: lij_core::storage::StateBlob = serde_json::from_str(blob_json)
            .map_err(|_e| JsValue::from_str("Not a LiJ backup file."))?;
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let n = wallet.import_state_blob(&blob)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"keys\":{n}}}"))
    }

    /// v210 (quorum wiring): set the independent quorum endpoint list at
    /// runtime. urls_json = JSON array of https base URLs (LSP defaults ∪
    /// wallet additions, page-merged, additive-only). Empty = rejected.
    #[wasm_bindgen]
    pub fn set_quorum_endpoints(&self, urls_json: &str) -> Result<(), JsValue> {
        let urls: Vec<String> = serde_json::from_str(urls_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if urls.is_empty() { return Err(JsValue::from_str("empty endpoint list")); }
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().set_independent_endpoints(urls);
        Ok(())
    }

    /// v211 (ESCAPE KIT): per-channel signed latest holder commitment
    /// ("THE CLOSE") + pre-signed to_local sweep ("THE COLLECT",
    /// nSequence = to_self_delay, two feerates — no RBF after the fact),
    /// destination = PEEKED m/84 allocator index. Read-only by
    /// constitution: nothing broadcast, nothing queued, counter not
    /// advanced, state unchanged. Runs on the offline read-only instance.
    /// Returns the kit as a JSON string.
    #[wasm_bindgen]
    pub fn escape_export(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().escape_export()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn get_channels(&self) -> Result<String, JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let channels = wallet.get_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&channels)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Step 3.6 diagnostic: returns full LDK ChannelDetails as a JSON
    /// string. Use from F12 console for inspection when the slim
    /// get_channels() output isn't enough.
    #[wasm_bindgen]
    pub fn dump_channel_details_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node().dump_channel_details_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// S24 Build 13: per-channel close values (see lij-core close_values_json).
    #[wasm_bindgen]
    pub fn close_values_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        Ok(wallet.node().close_values_json())
    }

    #[wasm_bindgen]
    pub fn get_chain_status(&self) -> Result<String, JsValue> {
        use serde_json::json;

        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };

        let sync_state = wallet.node().get_sync_state();
        let overall_color = match sync_state.dot_color() {
            lij_core::sync_state::DotColor::Green => "green",
            lij_core::sync_state::DotColor::Yellow => "yellow",
            lij_core::sync_state::DotColor::Red => "red",
        };

        let coop_subscribed = wallet.node().cooperative_subscribed();
        let coop_height = wallet.node().cooperative_block_height();
        let coop_last_update_ts = wallet.node().cooperative_last_update_ts();  // Step 3.6 (F7)
        let coop_color = if coop_subscribed && coop_height.is_some() {
            "green"
        } else if coop_subscribed {
            "yellow"
        } else {
            "red"
        };

        let healthy = wallet.node().independent_healthy_count();
        let total = wallet.node().independent_total_count();
        let indep_height = wallet.node().independent_block_height();  // Step 3.6 (F5)
        let quorum_state = wallet.node().independent_quorum_state();
        let quorum_str = match quorum_state {
            lij_core::independent::QuorumState::Healthy => "Healthy",
            lij_core::independent::QuorumState::SlightDisagreement => "SlightDisagreement",
            lij_core::independent::QuorumState::SingleSource => "SingleSource",   // v225
            lij_core::independent::QuorumState::NoQuorum => "NoQuorum",
            lij_core::independent::QuorumState::TotalDisagreement => "TotalDisagreement",
            lij_core::independent::QuorumState::InsufficientEndpoints => "InsufficientEndpoints",
        };
        // Two-layer dot color (step 8d):
        //   1. Quorum state hard-overrides — TotalDisagreement is always red.
        //   2. Otherwise, percentage of healthy endpoints determines color:
        //      ≥80% healthy → green
        //      50-79% healthy → yellow
        //      <50% healthy → red
        // This way a path with 3/5 healthy endpoints reads as "degraded but
        // working" rather than "all good".
        let healthy_pct = if total > 0 {
            (healthy * 100) / total
        } else {
            0
        };
        let indep_color = if matches!(quorum_state, lij_core::independent::QuorumState::TotalDisagreement) {
            // Adversarial disagreement always trumps percentage — never green.
            "red"
        } else if healthy_pct >= 80 {
            "green"
        } else if healthy_pct >= 50 {
            "yellow"
        } else {
            "red"
        };

        let endpoint_status = wallet.node().independent_endpoint_status();
        // Step 3.6 (F6): destructure the 4-tuple including latency_ms.
        let endpoints_json: Vec<_> = endpoint_status.iter().map(|(url, h, f, l)| {
            json!({
                "url": url,
                "healthy": h,
                "failures": f,
                "latency_ms": l,
            })
        }).collect();

        let result = json!({
            "overall": {
                "state": format!("{:?}", sync_state),
                "color": overall_color,
                "display": sync_state.display(),
            },
            "cooperative": {
                "subscribed": coop_subscribed,
                "block_height": coop_height,
                "color": coop_color,
                "last_update_ts": coop_last_update_ts,  // Step 3.6 (F7)
            },
            "independent": {
                "healthy_count": healthy,
                "total_count": total,
                "quorum": quorum_str,
                "color": indep_color,
                "endpoints": endpoints_json,
                "block_height": indep_height,  // Step 3.6 (F5)
            },
        });

        Ok(result.to_string())
    }


    /// Request a channel from the active LSP via LSPS1.
    /// Returns JSON with channel_point (funding txid:output_index) once adapter replies.
    ///
    /// @param inbound_sats - Channel capacity in satoshis (adapter enforces min/max)
    /// @returns Promise<string> - JSON { channel_id, confirmations_required }
    ///
    /// Implementation note: extracts all needed data from the wallet INSIDE the mutex
    /// (synchronous, fast), then releases the lock BEFORE doing the HTTP call.
    /// Holding the lock across an `.await` deadlocks with background_tick.
    #[wasm_bindgen]
    pub fn open_channel(&self, inbound_sats: u64) -> js_sys::Promise {
        let inner = self.inner.clone();

        future_to_promise(async move {
            // Step 1 — extract channel request data while holding the lock (no await inside)
            let (worker_url, lsp_info, client_pubkey) = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;

                let active = wallet.active_lsp()
                    .ok_or_else(|| JsValue::from_str("No active LSP — call auto_select_lsp first"))?;

                let worker_url = wallet.worker_url().to_string();
                let lsp_info = active.info.clone();
                let client_pubkey = wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;

                (worker_url, lsp_info, client_pubkey)
            };  // <-- mutex released here

            // Step 2 — build request and make HTTP call WITHOUT holding the lock
            use lij_core::lsp::{Lsps1ChannelRequest, LspClient};
            let request = Lsps1ChannelRequest {
                inbound_liquidity_sats: inbound_sats,
                client_pubkey,
                client_host: "wss://lijox-ws.lightning-mod.com".to_string(),
                is_browser_node: true,
                refund_onchain_address: None,
            };

            let client = LspClient::new(lsp_info);
            let response = client.request_channel(&worker_url, request)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let result = serde_json::json!({
                "channel_id": response.channel_id,
                "confirmations_required": response.confirmations_required,
                "status": "opening"
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Open an OUTBOUND channel to the active LSP, funded from on-chain balance.
    /// `amount_sats` is the channel capacity; `fee_rate_sat_per_vb` is the
    /// on-chain fee rate for the funding transaction. Returns a status JSON
    /// immediately; the channel opens asynchronously (watch background_tick /
    /// channel list for ChannelReady). The funding tx is built + signed by the
    /// wallet from its Tier-2 UTXOs and broadcast by LDK — not the adapter.
    #[wasm_bindgen]
    pub fn open_lsp_channel(&self, amount_sats: u64, fee_rate_sat_per_vb: f64) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let status = wallet
                .open_channel_to_lsp(amount_sats, fee_rate_sat_per_vb)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&status))
        })
    }

    /// v165 (#29-4a): current fee-rate tiers for the speed picker (JSON).
    pub fn get_fee_rates(&self) -> Result<String, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        Ok(wallet.fee_rates_json())
    }

    /// Estimate for the + Add channel UI: spendable on-chain, the MAX channel
    /// value openable at this fee rate (spendable − funding fee − anchor
    /// reserve), and the floor/reserve constants. Reads the Tier-2 view from
    /// local storage; needs no wallet lock.
    #[wasm_bindgen]
    pub fn lsp_channel_open_estimate(&self, fee_rate_sat_per_vb: f64) -> js_sys::Promise {
        future_to_promise(async move {
            let storage = LocalStorage;
            let fee_rate_sat_per_kw = ((fee_rate_sat_per_vb * 250.0).round() as u32).max(250);
            let spendable = lij_core::channel_open::spendable_total(&storage)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let max = lij_core::channel_open::max_channel_value(&storage, fee_rate_sat_per_kw)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let result = serde_json::json!({
                "spendable_sats": spendable,
                "max_channel_sats": max,
                "anchor_reserve_sats": lij_core::channel_open::ANCHOR_FEE_RESERVE_SATS,
                "min_channel_sats": lij_core::channel_open::LDK_MIN_CHANNEL_SATS,
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Connect to a Lightning peer over WebSocket.
    #[wasm_bindgen]
    pub fn connect_to_peer(&self, pubkey_hex: &str, wss_url: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let pubkey_hex = pubkey_hex.to_string();
        let wss_url = wss_url.to_string();

        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;

            let (socket_id, first_bytes) = wallet.begin_peer_connection(&pubkey_hex)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            ws_transport::open_websocket(&wss_url, socket_id, first_bytes)?;

            let result = serde_json::json!({
                "socket_id": socket_id,
                "status": "connecting",
                "note": "Noise_XK handshake in progress. Call list_peers() after a moment to verify."
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Background tick — JS calls every second to keep LDK alive.
    /// Handles peer keepalives, channel maintenance, and event processing.
    #[wasm_bindgen]
    /// S30 (v199): read the chain flight recorder — the ChainCoordinator's
    /// event ledger (tip advances, stale drops, confirmations, independent
    /// observations, with heights). Read-only diagnosis surface.
    #[wasm_bindgen]
    pub fn chain_events_json(&self, limit: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().chain_events_json(limit as usize)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// S30 (v197) fix-probe: explicit outbound pump. The codebase pumps
    /// process_events after inbound bytes, after disconnects, and on the
    /// background tick — but never immediately after locally INITIATING an
    /// action. A channel open is the one purely self-initiated message in
    /// the system; it must not wait for borrowed timing to reach the wire.
    /// `do_timer` also fires the peer keepalive tick, extending short iOS
    /// sessions through the multi-message funding handshake.
    #[wasm_bindgen]
    pub fn pump_peer(&self, do_timer: bool) -> Result<(), JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let pm = wallet.node().peer_manager()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if do_timer { pm.timer_tick_occurred(); }
        pm.process_events();
        Ok(())
    }

    pub fn background_tick(&self, tick_count: u64) -> Result<(), JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().background_tick(tick_count)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Dev tool: manually mark a funding transaction as confirmed at a
    /// given height. Synthesizes block headers and notifies LDK's chain
    /// listeners — pre-Neutrino workaround for the stuck-channel case.
    /// Returns the channels list as JSON after the confirmation is processed.
    #[wasm_bindgen]
    pub fn mark_funding_confirmed(
        &self,
        funding_tx_hex: &str,
        confirmed_at_height: u32,
    ) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node()
            .mark_funding_confirmed(funding_tx_hex, confirmed_at_height)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let channels = wallet.node().get_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&channels)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List currently connected Lightning peers.
    #[wasm_bindgen]
    pub fn list_peers(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let peers = wallet.list_peers()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&peers)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }
}

// ── HTTP fetch helper ────────────────────────────────────────────────────────

pub mod fetch {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    pub async fn get(url: &str, auth_token: Option<&str>) -> Result<String, String> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        if let Some(token) = auth_token {
            request.headers()
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|e| format!("Header error: {:?}", e))?;
        }

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        text.as_string().ok_or("Response is not a string".into())
    }

    pub async fn post(url: &str, body: &str, auth_token: Option<&str>) -> Result<String, String> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| format!("Header error: {:?}", e))?;

        if let Some(token) = auth_token {
            request.headers()
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|e| format!("Header error: {:?}", e))?;
        }

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        text.as_string().ok_or("Response is not a string".into())
    }

    /// Like get() but returns (status, body) so callers can distinguish
    /// 4xx tx-validity rejects from network failures. Used by the
    /// EsploraHttp trait impl which needs the status code.
    pub async fn get_with_status(url: &str) -> Result<(u16, String), String> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let status = resp.status();
        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        let body = text.as_string().ok_or("Response is not a string".to_string())?;
        Ok((status, body))
    }

    pub async fn post_with_status(
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<(u16, String), String> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        request.headers()
            .set("Content-Type", content_type)
            .map_err(|e| format!("Header error: {:?}", e))?;

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let status = resp.status();
        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        let body = text.as_string().ok_or("Response is not a string".to_string())?;
        Ok((status, body))
    }
}

// ── Core HTTP bridge ─────────────────────────────────────────────────────────

#[wasm_bindgen]
pub async fn fetch_lsp_registry(worker_url: &str) -> Result<String, JsValue> {
    let url = format!("{}/lsps", worker_url);
    fetch::get(&url, None).await.map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn push_backup(worker_url: &str, auth_token: &str, blob_json: &str) -> Result<(), JsValue> {
    // Phase B: belt+suspenders — no backup HTTP in offline_start, ever.
    // v209: BACKUP_OFF silences the same choke — every backup path exits here.
    if OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed)
        || BACKUP_OFF.load(std::sync::atomic::Ordering::Relaxed) { return Ok(()); }
    let url = format!("{}/backup", worker_url);
    fetch::post(&url, blob_json, Some(auth_token))
        .await.map(|_| ()).map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn pull_backup(worker_url: &str, auth_token: &str, pubkey_hex: &str) -> Result<String, JsValue> {
    let url = format!("{}/backup/{}", worker_url, pubkey_hex);
    fetch::get(&url, Some(auth_token)).await.map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn register_lsp(worker_url: &str, registration_json: &str) -> Result<(), JsValue> {
    let url = format!("{}/lsps/register", worker_url);
    fetch::post(&url, registration_json, None)
        .await.map(|_| ()).map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn health_check_lsp(endpoint: &str) -> bool {
    let url = format!("{}/health", endpoint);
    fetch::get(&url, None).await.is_ok()
}

// ── WebSocket transport ──────────────────────────────────────────────────────

pub mod ws_transport {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

    use lij_core::peer::SocketDispatcher;

    pub struct WsEntry {
        pub ws: WebSocket,
        pub _on_open: Closure<dyn FnMut()>,
        pub _on_message: Closure<dyn FnMut(MessageEvent)>,
        pub _on_close: Closure<dyn FnMut(CloseEvent)>,
        pub _on_error: Closure<dyn FnMut(ErrorEvent)>,
    }

    thread_local! {
        pub static WS_MAP: RefCell<HashMap<u64, WsEntry>> = RefCell::new(HashMap::new());
    }

    pub struct WsDispatcher;

    impl SocketDispatcher for WsDispatcher {
        fn send(&self, id: u64, data: &[u8]) -> usize {
            WS_MAP.with(|map| {
                if let Some(entry) = map.borrow().get(&id) {
                    match entry.ws.send_with_u8_array(data) {
                        Ok(_) => data.len(),
                        Err(e) => {
                            log::warn!("WebSocket send failed for id {id}: {:?}", e);
                            0
                        }
                    }
                } else {
                    log::warn!("WebSocket send for unknown id {id}");
                    0
                }
            })
        }

        fn disconnect(&self, id: u64) {
            // Don't remove the WsEntry here — that would drop the closures
            // (on_open/on_message/on_close/on_error) before the browser fires
            // on_close, causing "closure invoked after being dropped" when
            // the asynchronous close event arrives. Just close the WebSocket;
            // the on_close handler (which defers WS_MAP removal via
            // spawn_local — see open_websocket below) is the sole removal
            // path. Pre-Phase-13 this method did `remove` then `close`,
            // which raced the browser.
            let ws_opt = WS_MAP.with(|map| {
                map.borrow().get(&id).map(|e| e.ws.clone())
            });
            if let Some(ws) = ws_opt {
                let _ = ws.close();
                log::info!("WebSocket {id} disconnected by LDK");
            }
        }
    }

    pub fn open_websocket(url: &str, id: u64, first_bytes: Vec<u8>) -> Result<(), JsValue> {
        let ws = WebSocket::new(url)
            .map_err(|e| JsValue::from_str(&format!("WebSocket::new failed: {:?}", e)))?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let ws_clone_open = ws.clone();
        let first_bytes_clone = first_bytes.clone();
        let on_open = Closure::wrap(Box::new(move || {
            log::info!("WebSocket {id} opened, sending {} initial bytes", first_bytes_clone.len());
            if let Err(e) = ws_clone_open.send_with_u8_array(&first_bytes_clone) {
                log::error!("Failed to send initial bytes: {:?}", e);
            }
        }) as Box<dyn FnMut()>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            let data = match e.data().dyn_into::<js_sys::ArrayBuffer>() {
                Ok(buf) => js_sys::Uint8Array::new(&buf).to_vec(),
                Err(_) => {
                    log::warn!("WebSocket {id} received non-binary frame, ignoring");
                    return;
                }
            };
            handle_incoming_bytes(id, data);
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let on_close = Closure::wrap(Box::new(move |e: CloseEvent| {
            log::info!("WebSocket {id} closed: code={}, reason={}", e.code(), e.reason());
            handle_disconnect(id);
            // Defer the WS_MAP removal out of this closure: removing the
            // WsEntry would drop the very closure currently executing
            // (_on_close field owns this Box<dyn FnMut>), which wasm-bindgen
            // detects as a use-after-free and throws "closure invoked
            // recursively or after being dropped". spawn_local queues the
            // removal as a microtask so the closure can return cleanly first.
            wasm_bindgen_futures::spawn_local(async move {
                WS_MAP.with(|map| { map.borrow_mut().remove(&id); });
            });
        }) as Box<dyn FnMut(CloseEvent)>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        let on_error = Closure::wrap(Box::new(move |e: ErrorEvent| {
            // v164: browsers fire a PLAIN Event on ws.onerror — the ErrorEvent
            // typing is a lie, so e.message() returns undefined and the
            // wasm-bindgen string glue crashes (passStringToWasm0 reading
            // .length of undefined) on every WS handshake failure. Read the
            // field defensively; the CloseEvent that follows carries the
            // actionable code/reason anyway.
            let msg = js_sys::Reflect::get(e.as_ref(), &wasm_bindgen::JsValue::from_str("message"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "(no message)".to_string());
            log::error!("WebSocket {id} error: {msg}");
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let entry = WsEntry {
            ws,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
            _on_error: on_error,
        };
        // v219 (DEFECT B, F2 belt): under realm-global ids a collision is
        // impossible by construction — but if one EVER appears, never drop the
        // old quartet synchronously (its socket's async events may still be in
        // flight). Take it out, close the socket, defer the drop past this
        // turn, and shout.
        WS_MAP.with(|map| {
            if let Some(old) = map.borrow_mut().remove(&id) {
                log::error!("WS_MAP collision on id {id} — should be impossible under realm-global ids; closing stale socket, deferring drop. Investigate.");
                let _ = old.ws.close();
                wasm_bindgen_futures::spawn_local(async move { drop(old); });
            }
        });
        WS_MAP.with(|map| { map.borrow_mut().insert(id, entry); });
        Ok(())
    }

    /// v219 (DEFECT B, F4 hygiene): close every open socket. Called before a
    /// new wallet instance is installed in the slot, so a replaced instance's
    /// sockets stop routing bytes into the NEW PeerManager. Each entry leaves
    /// WS_MAP via its own on_close path — the sanctioned removal — so no
    /// closure is dropped while its events are in flight.
    pub fn close_all_sockets() {
        let sockets: Vec<web_sys::WebSocket> = WS_MAP.with(|map| {
            map.borrow().values().map(|e| e.ws.clone()).collect()
        });
        if !sockets.is_empty() {
            log::info!("Closing {} lingering WebSocket(s) before wallet install", sockets.len());
        }
        for ws in sockets { let _ = ws.close(); }
    }

    fn handle_incoming_bytes(id: u64, bytes: Vec<u8>) {
        use lij_core::peer::LijSocketDescriptor;

        let inner = match crate::current_wallet_inner() {
            Some(i) => i,
            None => {
                log::error!("Received bytes for id {id} but no wallet instance");
                return;
            }
        };

        // Phase 3.8.D v1 (band-aid): try_lock instead of blocking lock.
        // Prevents recursive-mutex panic when Phase 10b's send_payment_via_lsp_route
        // holds the wallet lock during its HTTP fetch .await. Dropped WS messages
        // during the (short) fetch window are recovered via LDK's auto-reconnect.
        // TODO post-3.D: remove once user-action bindings release lock before await.
        let wallet = match inner.try_lock() {
            Ok(w) => w,
            Err(std::sync::TryLockError::Poisoned(e)) => {
                log::error!("Wallet lock poisoned: {e}"); return;
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                log::warn!("WS id {id}: wallet busy, dropping {} bytes (Phase 3.8.D band-aid)", bytes.len());
                return;
            }
        };

        let pm = match wallet.node().peer_manager() {
            Ok(p) => p,
            Err(e) => { log::error!("PeerManager unavailable: {e}"); return; }
        };

        let mut descriptor = LijSocketDescriptor::new(id);
        match pm.read_event(&mut descriptor, &bytes) {
            Ok(_pause_read) => {}
            Err(e) => {
                log::warn!("read_event error on id {id}: {:?}", e);
                WS_MAP.with(|map| {
                    if let Some(entry) = map.borrow_mut().remove(&id) {
                        let _ = entry.ws.close();
                    }
                });
                return;
            }
        }

        pm.process_events();
        drop(wallet);

        // v227 (S43, speed): run the ChannelManager event pass on the NEXT
        // turn — never inside this socket callback — so a receiver claims the
        // moment its HTLC lands and a sender learns "paid" the moment the
        // fulfill arrives, instead of on the 1-second tick. Same routine the
        // tick runs (process_channel_events); it only runs sooner.
        crate::schedule_early_event_pass();
    }

    fn handle_disconnect(id: u64) {
        use lij_core::peer::LijSocketDescriptor;

        let inner = match crate::current_wallet_inner() {
            Some(i) => i,
            None => return,
        };

        // Phase 3.8.D v1 (band-aid): try_lock instead of blocking lock.
        // See handle_incoming_bytes for rationale.
        let wallet = match inner.try_lock() {
            Ok(w) => w,
            Err(std::sync::TryLockError::Poisoned(_)) => return,
            Err(std::sync::TryLockError::WouldBlock) => {
                log::warn!("WS id {id}: wallet busy, deferring disconnect notification (Phase 3.8.D band-aid)");
                return;
            }
        };

        if let Ok(pm) = wallet.node().peer_manager() {
            let descriptor = LijSocketDescriptor::new(id);
            pm.socket_disconnected(&descriptor);
            pm.process_events();
        }
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// Step 8a: WasmEsploraHttp — real EsploraHttp implementation using web_sys::fetch
// ─────────────────────────────────────────────────────────────────────────────

pub struct WasmEsploraHttp;

impl WasmEsploraHttp {
    pub fn new() -> Self { Self }
}

impl lij_core::independent::EsploraHttp for WasmEsploraHttp {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = lij_core::error::LijResult<lij_core::independent::HttpResponse>> + 'a>> {
        Box::pin(async move {
            // v226 (S43, speed item 0): the trait promises REQUEST_TIMEOUT_SECS
            // and this impl never enforced it — a stalled endpoint held a
            // quorum round (and the cold-start Ready rule behind it) until the
            // browser gave up. Race the fetch against a 5 s delay; on timeout
            // the fetch future is dropped and the endpoint records a failure.
            use futures::future::{select, Either};
            let timeout = wasm_timer::Delay::new(std::time::Duration::from_secs(
                lij_core::independent::REQUEST_TIMEOUT_SECS,
            ));
            match select(Box::pin(fetch::get_with_status(url)), Box::pin(timeout)).await {
                Either::Left((Ok((status, body)), _)) => Ok(lij_core::independent::HttpResponse { status, body }),
                Either::Left((Err(e), _)) => Err(lij_core::error::LijError::Lsp(format!("WasmEsploraHttp GET {url}: {e}"))),
                Either::Right((_, _)) => Err(lij_core::error::LijError::Lsp(format!(
                    "WasmEsploraHttp GET {url}: timeout after {}s",
                    lij_core::independent::REQUEST_TIMEOUT_SECS
                ))),
            }
        })
    }

    fn post<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        content_type: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = lij_core::error::LijResult<lij_core::independent::HttpResponse>> + 'a>> {
        Box::pin(async move {
            // Esplora's POST /tx accepts hex-encoded text. The body is already
            // hex from independent.rs::broadcast_to_quorum (which calls hex::encode).
            let body_str = std::str::from_utf8(body)
                .map_err(|e| lij_core::error::LijError::Lsp(format!("body utf8: {e}")))?;
            match fetch::post_with_status(url, body_str, content_type).await {
                Ok((status, resp)) => Ok(lij_core::independent::HttpResponse { status, body: resp }),
                Err(e) => Err(lij_core::error::LijError::Lsp(format!("WasmEsploraHttp POST {url}: {e}"))),
            }
        })
    }
}

// ============================================================================
// Phase 3.7.J — wasm binding for zombie monitor cleanup
// ============================================================================
//
// Exposes LijNode::purge_force_closed_monitor (defined in lij-core, added in
// Phase 3.7.H) to JavaScript so the wallet's DevTools console can clean up
// zombie ChannelMonitor entries — force-closed channels whose underlying
// outputs were already swept on chain but whose persistence records cause
// redundant chain_filter re-registration and broadcaster claim re-attempts
// on each wallet restart.
//
// JS usage:
//   await wallet.purge_force_closed_monitor("<funding_txid_hex>", <vout>);
//   // returns true if archived, false if no monitor existed.
#[wasm_bindgen]
impl LijWalletHandle {
    /// Archive a force-closed ChannelMonitor by funding outpoint.
    /// Returns true if a monitor was archived, false if none existed at the
    /// given outpoint. Throws on invalid txid hex or storage failure.
    #[wasm_bindgen]
    pub fn purge_force_closed_monitor(
        &self,
        funding_txid_hex: &str,
        output_index: u32,
    ) -> Result<bool, JsValue> {
        let txid = funding_txid_hex
            .parse::<bitcoin::Txid>()
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Invalid funding_txid_hex (expected 64 hex chars): {e}"
                ))
            })?;
        let wallet = self.inner.lock().map_err(|e| {
            JsValue::from_str(&format!("Lock error: {e}"))
        })?;
        wallet
            .node()
            .purge_force_closed_monitor(txid, output_index)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}


// ── v8 module-level helpers ───────────────────────────────────────────────
//
// Both used by send_payment_with_retries:
//   - wait_for_outcome: poll the per-payment outcome map with timeout, no
//     wallet lock held (event handler populates the map; we just observe).
//   - payment_result_json: serialize a PaymentResult to a JsValue, the shape
//     doSend() in wallet/index.html v8 expects.

/// Poll the outcome map for the given PaymentId, sleeping briefly between
/// checks. Returns Some(outcome) when an entry is found (and removes it from
/// the map), or None on timeout.
///
/// The lock is held ONLY during the map check (microseconds), then released
/// for the sleep — keeps background_tick free to run.
async fn wait_for_outcome(
    outcomes: std::sync::Arc<std::sync::Mutex<
        std::collections::HashMap<
            lightning::ln::channelmanager::PaymentId,
            lij_core::node::PaymentOutcome,
        >,
    >>,
    payment_id: lightning::ln::channelmanager::PaymentId,
    timeout_ms: u64,
) -> Option<lij_core::node::PaymentOutcome> {
    use wasm_timer::Delay;
    use std::time::Duration;

    let start_ms = js_sys::Date::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        // Brief lock: check + remove if present.
        {
            let mut map = match outcomes.lock() {
                Ok(m) => m,
                Err(_) => return None, // poisoned mutex — treat as timeout
            };
            if let Some(outcome) = map.remove(&payment_id) {
                return Some(outcome);
            }
        } // mutex released before sleep

        let elapsed = js_sys::Date::now() - start_ms;
        if elapsed >= timeout_ms as f64 {
            return None;
        }

        // Sleep before next poll. Ignore Delay errors (shouldn't happen in
        // WASM).
        let _ = Delay::new(poll_interval).await;
    }
}

/// Convenience: serialize a PaymentResult to a JsValue for return to JS.
fn payment_result_json(
    success: bool,
    preimage: Option<String>,
    fee_sats: Option<u64>,
    error: Option<String>,
) -> JsValue {
    let result = lij_core::types::PaymentResult {
        success,
        preimage,
        fee_sats,
        error,
    };
    match serde_json::to_string(&result) {
        Ok(s) => JsValue::from_str(&s),
        Err(_) => JsValue::from_str(
            r#"{"success":false,"preimage":null,"fee_sats":null,"error":"serde_json failure"}"#,
        ),
    }
}


// ── Phase C-1 (S32): AIRGAPPED PSBT SIGNER — pure key math, no wallet
// state, fully functional under offline_start. A coordinator (Sparrow
// watch-only over our xpub) builds the PSBT with bip32_derivation hints;
// we sign every input whose fingerprint+path derive to this seed's keys
// and hand the rest back untouched. BIP39 passphrase empty (house
// standard). PSBT travels as HEX both ways (page converts base64↔hex,
// sidestepping the crate's base64 feature gate).
#[wasm_bindgen]
pub fn sign_psbt_hex(mnemonic: &str, psbt_hex: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::Secp256k1;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&format!("xprv: {e}")))?;
    // Hand-rolled hex (DP-confirmed): no trait dependence — the pinned
    // toolchain's hashes generation dropped ToHex (E0432/E0599 in CI).
    let ph = psbt_hex.trim();
    if ph.is_empty() || ph.len() % 2 != 0 || !ph.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(JsValue::from_str("hex: invalid"));
    }
    let bytes: Vec<u8> = (0..ph.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&ph[i..i + 2], 16).unwrap_or(0))
        .collect();
    let mut psbt = Psbt::deserialize(&bytes)
        .map_err(|e| JsValue::from_str(&format!("psbt: {e}")))?;
    let mut signed_inputs = match psbt.sign(&root, &secp) {
        Ok(map) => map.len(),
        Err((map, _errs)) => map.len(),
    };
    // v205 FALLBACK: some coordinators (BlueWallet watch-only) write a NULL
    // or foreign master fingerprint (DP field: 00000000 vs ours), so the
    // fingerprint match finds nothing. Trust the PATH: derive our child at
    // the hint path; if its pubkey equals the hint pubkey it is provably our
    // input, and we sign the p2wpkh input manually.
    {
        use bitcoin::sighash::{SighashCache, EcdsaSighashType};
        let txclone = psbt.unsigned_tx.clone();
        let mut adds: Vec<(usize, bitcoin::PublicKey, bitcoin::secp256k1::ecdsa::Signature)> = Vec::new();
        {
            let mut cache = SighashCache::new(&txclone);
            for i in 0..psbt.inputs.len() {
                let hints: Vec<(bitcoin::secp256k1::PublicKey, bitcoin::bip32::DerivationPath)> =
                    psbt.inputs[i].bip32_derivation.iter().map(|(pk, (_fp, path))| (*pk, path.clone())).collect();
                let wu = match psbt.inputs[i].witness_utxo.as_ref() { Some(o) => o.clone(), None => continue };
                if !wu.script_pubkey.is_v0_p2wpkh() { continue; }
                for (hint_pk, path) in hints.iter() {
                    let child = match root.derive_priv(&secp, path) { Ok(c) => c, Err(_) => continue };
                    let sk = child.private_key;
                    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
                    let our_wph = bitcoin::WPubkeyHash::from_raw_hash(bitcoin::hashes::Hash::hash(&pk.inner.serialize()));
                    let sb = wu.script_pubkey.as_bytes();
                    let spk_ok = sb.len() == 22 && &sb[2..22] == &our_wph[..];  // v206: match by witness program hash of the derived key
                    let _ = hint_pk;
                    if !spk_ok { continue; }
                    if psbt.inputs[i].partial_sigs.contains_key(&pk) { continue; }
                    // v205c: VENDORED API AS-READ — spk.p2wpkh_script_code()
                    // builds the BIP143 scriptCode; segwit_signature_hash is
                    // the cache method this crate actually ships.
                    let code = match wu.script_pubkey.p2wpkh_script_code() { Some(c) => c, None => continue };
                    let sh = match cache.segwit_signature_hash(i, &code, wu.value, EcdsaSighashType::All) {
                        Ok(s) => s, Err(_) => continue };
                    let msg = match bitcoin::secp256k1::Message::from_slice(sh.as_ref()) { Ok(m2) => m2, Err(_) => continue };
                    let sig = secp.sign_ecdsa(&msg, &sk);
                    adds.push((i, pk, sig));
                }
            }
        }
        for (i, pk, sig) in adds.into_iter() {
            let esig = bitcoin::ecdsa::Signature { sig, hash_ty: EcdsaSighashType::All };
            psbt.inputs[i].partial_sigs.insert(pk, esig);
            signed_inputs += 1;
        }
    }
    if signed_inputs == 0 {
        return Err(JsValue::from_str("no inputs matched this seed's keys (checked fingerprint and derived pubkey)"));
    }
    Ok(psbt.serialize().iter().map(|b| format!("{:02x}", b)).collect::<String>())
}


// ── Phase C-3 (S32): OFFLINE RECEIVE ADDRESS — pure key math. Derives the
// standard house path m/84'/0'/0'/0/{index} to a p2wpkh address. The page
// owns index continuity via lij_onchain_recv_index (the same key the
// online wallet already reads). BIP39 passphrase empty (house standard).
#[wasm_bindgen]
pub fn derive_receive_address(mnemonic: &str, index: u32) -> Result<String, JsValue> {
    use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{index}"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let child = root.derive_priv(&secp, &path)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    let addr = bitcoin::Address::p2wpkh(&pk, bitcoin::Network::Bitcoin)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(addr.to_string())
}


// ── S33 B2 rider: ACCOUNT ZPUB EXPORT — pure key math, no state. Derives the
// account node m/84'/0'/0', serializes the xpub, and re-versions the four
// prefix bytes to zpub (0x04b24746) so watch-only coordinators (Sparrow,
// BlueWallet, Electrum) import it directly. Kills the golden-gate step-0:
// no more typing the 12 words into an offline machine to build a watcher.
/// v213 (evil-LSP reserve dial): the reserve the user demands the LSP keep
/// on its side, ppm, NEW channels only. Clamped 0..=50_000 (5% cap); 0 =
/// LDK's 1,000-sat floor. Free fn — callable before any wallet exists so
/// the boot re-apply lands ahead of create/restore (JIT accepts read the
/// ChannelManager config captured at construction). Returns the APPLIED
/// (clamped) value.
#[wasm_bindgen]
pub fn set_lsp_reserve_ppm(ppm: u32) -> u32 {
    let clamped = ppm.min(50_000);
    lij_core::node::LSP_RESERVE_PPM.store(clamped, std::sync::atomic::Ordering::Relaxed);
    clamped
}

/// v216 (S36, O6 fee headroom → exact-fee): the user's fee-race margin in
/// sats — subtracted once at the aggregate inside max_sendable_sats. Page
/// persists (WALLET → Controls dial) and boot-applies before any wallet
/// exists (free fn, LSP-reserve pattern). Clamped 0..=5,000. Returns applied.
/// S45 (DP): Dials → Speed up slow closes — Off / Automatic (default Off).
#[wasm_bindgen]
pub fn set_coop_cpfp_auto(on: bool) -> bool {
    lij_core::node::COOP_CPFP_AUTO.store(on, std::sync::atomic::Ordering::Relaxed);
    on
}

#[wasm_bindgen]
pub fn set_fee_margin_sats(sats: u32) -> u32 {
    let clamped = sats.min(5_000);
    lij_core::node::FEE_MARGIN_SATS.store(clamped as u64, std::sync::atomic::Ordering::Relaxed);
    clamped
}

#[wasm_bindgen]
pub fn derive_account_zpub(mnemonic: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let path = DerivationPath::from_str("m/84'/0'/0'")
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let acct = root.derive_priv(&secp, &path)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let xpub = ExtendedPubKey::from_priv(&secp, &acct);
    let mut data = xpub.encode();
    // zpub version bytes per SLIP-132 (BIP84 mainnet public).
    data[0] = 0x04; data[1] = 0xb2; data[2] = 0x47; data[3] = 0x46;
    Ok(bitcoin::base58::check_encode_slice(&data))
}


// ── S32 FORENSICS: PSBT KEY-MATCH PROBE — no signing, no state. Reports
// our master fingerprint and, per input, every bip32_derivation keysource
// (fingerprint + path) the coordinator recorded, with a match flag. Built
// because a sign attempt returned byte-identical output while claiming
// success — the data, not a theory, will name the mechanism.
#[wasm_bindgen]
pub fn psbt_probe(mnemonic: &str, psbt_hex: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::Secp256k1;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let our_fp = root.fingerprint(&secp).to_string();
    let ph = psbt_hex.trim();
    if ph.is_empty() || ph.len() % 2 != 0 || !ph.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(JsValue::from_str("hex: invalid"));
    }
    let bytes: Vec<u8> = (0..ph.len()).step_by(2)
        .map(|i| u8::from_str_radix(&ph[i..i + 2], 16).unwrap_or(0)).collect();
    let psbt = Psbt::deserialize(&bytes)
        .map_err(|e| JsValue::from_str(&format!("psbt: {e}")))?;
    let mut inputs = Vec::new();
    for (idx, inp) in psbt.inputs.iter().enumerate() {
        let mut entries = Vec::new();
        for (pk, (fp, path)) in inp.bip32_derivation.iter() {
            let derived = root.derive_priv(&secp, path).ok()
                .map(|c| bitcoin::PublicKey::new(c.private_key.public_key(&secp)).inner.to_string())
                .unwrap_or_else(|| "derive_failed".to_string());
            entries.push(serde_json::json!({
                "pubkey": pk.to_string(),
                "derived_pubkey": derived,
                "derived_matches_hint": derived == pk.to_string(),
                "fingerprint": fp.to_string(),
                "path": path.to_string(),
                "fp_matches_ours": fp.to_string() == our_fp,
            }));
        }
        let has_wu = inp.witness_utxo.is_some();
        let is_wpkh = inp.witness_utxo.as_ref().map(|o| o.script_pubkey.is_v0_p2wpkh()).unwrap_or(false);
        inputs.push(serde_json::json!({
            "input": idx,
            "partial_sigs": inp.partial_sigs.len(),
            "has_witness_utxo": has_wu,
            "is_p2wpkh": is_wpkh,
            "derivations": entries,
        }));
    }
    let out = serde_json::json!({ "our_master_fp": our_fp, "inputs": inputs });
    Ok(out.to_string())
}
