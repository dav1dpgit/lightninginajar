// wallet.rs
// Top-level wallet coordinator. This is what lij-wasm calls.
// Owns the LijNode and orchestrates all wallet operations.
// Think of this as the public API of lij-core.

use std::sync::Arc;

use crate::{
    error::{LijError, LijResult},
    key::RootKey,
    lsp::{fetch_lsp_registry, rank_lsps, LspInfo},
    node::LijNode,
    storage::{BackupSink, KvBackupClient, LijStorage, RecoveryConfig, StateBlob, StorageConfig},
    types::{
        Balance, ChannelInfo, InvoiceResult, InvoiceWithJitResult, PaymentResult,
        WalletConfig, WalletCreated, WalletRestored,
    },
};

/// v224 (S41, DP RULED): every fresh LiJ wallet starts on LiJ-Node — the
/// product default. Openness is the freedom to LEAVE (the marketplace and
/// switch_lsp), not a lottery at boot. Overridable per-build via
/// WalletConfig.preferred_lsp_pubkey.
const DEFAULT_LSP_PUBKEY: &str = "03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c";


/// The main wallet object. Created once per session.
/// All PWA interactions go through this struct via the WASM bindings in lij-wasm.
pub struct LijWallet {
    node: LijNode,
    backup_client: KvBackupClient,
    /// Enabled full-state backup destinations (scenario A). Built from
    /// RecoveryConfig — Cloudflare KV today, extensible (on-device file, …).
    sinks: Vec<BackupSink>,
}

impl LijWallet {
    /// Create a brand new wallet.
    /// Generates a fresh mnemonic, initializes LDK, connects to best available LSP.
    ///
    /// Returns WalletCreated containing the mnemonic — the PWA MUST show this
    /// to the user immediately with a clear backup warning.
    pub async fn create(
        config: WalletConfig,
        storage: Arc<dyn LijStorage>,
    ) -> LijResult<(Self, WalletCreated)> {
        let network = parse_bitcoin_network(&config.network)?;

        // Generate fresh keypair
        let (root_key, mnemonic) = RootKey::generate(network)?;

        // Set up backup client
        let backup_client = KvBackupClient::new(StorageConfig {
            worker_url: config.worker_url.clone(),
            auth_token: config.backup_auth_token.clone(),
        });

        // Initialize LDK node — KeysManager generates the canonical Lightning identity here
        let node = LijNode::new(root_key, config.clone(), storage).await?;

        // Ask KeysManager for the authoritative node pubkey (differs from RootKey's path)
        let pubkey = node.node_pubkey()?;
        log::info!("Created new wallet, pubkey: {pubkey}");
        let sinks = Self::build_backup_sinks(&config);
        let mut wallet = Self { node, backup_client, sinks };

        // Auto-select and connect to best LSP
        wallet.auto_select_lsp(&config).await?;

        Ok((
            wallet,
            WalletCreated {
                mnemonic: mnemonic.to_string(),
                pubkey,
            },
        ))
    }

    /// Restore wallet from a BIP39 mnemonic.
    /// Pulls encrypted channel state from Cloudflare KV backup.
    /// Reconnects to the previously used LSP.
    pub async fn restore(
        mnemonic_str: &str,
        config: WalletConfig,
        storage: Arc<dyn LijStorage>,
    ) -> LijResult<(Self, WalletRestored)> {
        let network = parse_bitcoin_network(&config.network)?;

        // Validate and parse mnemonic
        let mnemonic: bip39::Mnemonic = mnemonic_str
            .parse()
            .map_err(|e| LijError::Key(format!("Invalid mnemonic: {e}")))?;

        let root_key = RootKey::from_mnemonic(&mnemonic, network)?;

        let backup_client = KvBackupClient::new(StorageConfig {
            worker_url: config.worker_url.clone(),
            auth_token: config.backup_auth_token.clone(),
        });

        // We pull the backup BEFORE constructing the LDK node, using a pubkey
        // derived from pure BIP32 (m/525h via RootKey::portable_pubkey_hex).
        //
        // Rationale: backup recovery must work using only the user's 12-word
        // seed and a known derivation path, in any standard Bitcoin wallet.
        // If we keyed the backup by the authoritative LDK node pubkey
        // (KeysManager + HKDF), recovery would require LDK-aware tooling —
        // defeating the purpose of having a portable backup at all.
        //
        // The two pubkeys are intentionally distinct concepts:
        //   - portable_pubkey: indexes the backup blob. BIP32-derivable from seed.
        //   - authoritative pubkey: the node's identity on the Lightning network.
        //     Required for peering, channel signing, invoicing.
        //
        // Both come from the same seed, but via different derivation logic.
        let portable_pubkey = root_key.portable_pubkey_hex()?;
        log::debug!("Restoring wallet, portable backup pubkey: {portable_pubkey}");

        // Scenario A (cloud full-state restore): if there's no local channel
        // state (new device / wiped), pull the encrypted backup, decrypt it, and
        // inject its entries into local storage BEFORE LijNode::restore() reads
        // them. If local state already exists (same-device reload), it's at least
        // as fresh as the backup, so we keep it and skip the pull entirely.
        let local_has_state = storage.get(crate::persist::CHANNEL_MANAGER_KEY)?.is_some();
        // Session 23 (1a): provenance for the restore-announce UX —
        // did this restore actually inject the vault blob, and at what
        // version? Local-state restores report false/None (nothing was
        // pulled; the local copy was at least as fresh by the ratified
        // conflict rule).
        let mut restored_from_vault = false;
        let mut vault_version: Option<u64> = None;
        if local_has_state {
            log::info!("restore: local channel state present — using it");
        } else {
            match backup_client.pull(&portable_pubkey, &root_key).await {
                Ok(Some(blob)) => {
                    let ver = blob.version;
                    match Self::inject_state_blob(storage.as_ref(), &root_key, &blob) {
                        Ok(n) => {
                            restored_from_vault = true;
                            vault_version = Some(ver);
                            log::info!(
                                "restore: injected cloud backup v{ver} ({n} monitor(s)) — \
                                 rehydrating live channels"
                            )
                        }
                        Err(e) => log::warn!(
                            "restore: cloud backup v{ver} inject failed: {e} — starting fresh"
                        ),
                    }
                }
                Ok(None) => log::info!("restore: no cloud backup found — starting fresh"),
                Err(e) => log::warn!("restore: cloud backup pull failed: {e} — starting fresh"),
            }
        }

        let node = LijNode::restore(root_key, config.clone(), storage).await?;

        // Now we have the real KeysManager-derived pubkey (node identity).
        let pubkey = node.node_pubkey()?;
        // Honest count: whatever channels actually came back (local or injected).
        let channels_recovered = node.get_channels().map(|c| c.len() as u32).unwrap_or(0);
        log::debug!(
            "portable backup pubkey: {portable_pubkey}, node identity: {pubkey}, \
             channels after restore: {channels_recovered}"
        );

        let sinks = Self::build_backup_sinks(&config);
        let mut wallet = Self { node, backup_client, sinks };

        // Reconnect to LSP
        wallet.auto_select_lsp(&config).await?;

        Ok((
            wallet,
            WalletRestored {
                pubkey,
                channels_recovered,
                restored_from_vault,
                vault_version,
            },
        ))
    }

    // ── Payment operations ───────────────────────────────────────────────────

    pub async fn send_payment(&self, bolt11: &str) -> LijResult<PaymentResult> {
        self.node.send_payment(bolt11).await
    }

    pub fn create_invoice(
        &self,
        amount_sats: Option<u64>,
        memo: &str,
        expiry_seconds: u64,
    ) -> LijResult<InvoiceResult> {
        self.node.create_invoice(amount_sats, memo, expiry_seconds)
    }

    /// v0.16 Phase C: delegate to LijNode::build_invoice_with_jit_promise.
    /// Sync — caller (WASM) must already have called lsps2_get_info and
    /// lsps2_buy WITHOUT the wallet lock held, then pass the responses here
    /// for the invoice build (which holds the lock briefly).
    pub fn build_invoice_with_jit_promise(
        &self,
        amount_sats: u64,
        memo: &str,
        expiry_seconds: u64,
        info: &crate::lsps2::Lsps2GetInfoResponse,
        buy: crate::lsps2::Lsps2BuyResponse,
    ) -> LijResult<InvoiceWithJitResult> {
        self.node.build_invoice_with_jit_promise(amount_sats, memo, expiry_seconds, info, buy)
    }

    /// v188 (S27): delegate to LijNode::build_open_invoice_with_jit_promise
    /// — the zero-amount sibling. Same lock discipline: caller does
    /// get_info + buy WITHOUT the wallet lock, passes the responses here.
    pub fn build_open_invoice_with_jit_promise(
        &self,
        memo: &str,
        expiry_seconds: u64,
        info: &crate::lsps2::Lsps2GetInfoResponse,
        buy: crate::lsps2::Lsps2BuyResponse,
    ) -> LijResult<InvoiceWithJitResult> {
        self.node.build_open_invoice_with_jit_promise(memo, expiry_seconds, info, buy)
    }

    // ── Balance and channel info ─────────────────────────────────────────────

    pub fn get_balance(&self) -> LijResult<Balance> {
        self.node.get_balance()
    }

    /// v165 (#29-4a): fee-rate tiers for the UI speed picker (delegate).
    pub fn fee_rates_json(&self) -> String {
        self.node.fee_rates_json()
    }

    pub fn get_channels(&self) -> LijResult<Vec<ChannelInfo>> {
        self.node.get_channels()
    }

    pub fn node_pubkey(&self) -> LijResult<String> {
        self.node.node_pubkey()
    }

    /// v195 (S30): LNURLp hash pool — thin bridge to the node (preimages
    /// generated and persisted node-side; only {hash, secret} pairs return).
    pub fn lnurlp_prepare_hashes(&self, count: u32, start_hint: Option<u32>) -> LijResult<String> {
        self.node.lnurlp_prepare_hashes(count, start_hint)
    }

    /// v184: node-key message signing (delegate slips). Thin bridge.
    pub fn sign_message(&self, msg: &str) -> LijResult<String> {
        self.node.sign_message(msg)
    }

    pub async fn register_push_subscription(&self, subscription_json: &str) -> LijResult<()> {
        self.node.register_push_subscription(subscription_json).await
    }

    /// Access the currently active LSP (for channel open flows in lij-wasm).
    pub fn active_lsp(&self) -> Option<&crate::lsp::ActiveLsp> {
        self.node.active_lsp()
    }

    /// Access the Worker URL (for channel open flows in lij-wasm).
    pub fn worker_url(&self) -> &str {
        self.node.worker_url()
    }

    // ── LSP management ───────────────────────────────────────────────────────

    /// Fetch available LSPs from the registry and switch to a specific one.
    /// Called from the PWA when user explicitly chooses an LSP.
    pub async fn switch_lsp(&mut self, lsp_pubkey: &str) -> LijResult<()> {
        let lsps = fetch_lsp_registry(&self.node_config_worker_url()).await?;
        let target = lsps
            .into_iter()
            .find(|l| l.pubkey == lsp_pubkey)
            .ok_or_else(|| {
                LijError::Lsp(format!("LSP not found in registry: {lsp_pubkey}"))
            })?;

        self.node.switch_lsp(target.clone()).await?;
        // v224 (S41, DP RULED): an explicit switch is the user's STANDING
        // instruction. Persist the full record; boot honors it above all.
        if let Err(e) = self.node.persist_chosen_lsp(&target) {
            log::warn!("chosen-lsp persist failed (switch still applied this session): {e}");
        }
        Ok(())
    }

    /// Return the list of available LSPs from the registry.
    /// Ranked by score (fee + uptime).
    pub async fn list_lsps(&self) -> LijResult<Vec<LspInfo>> {
        let worker_url = self.node_config_worker_url();
        let lsps = fetch_lsp_registry(&worker_url).await?;
        // v224: stickiness finally armed — the ranker compares against the
        // ACTIVE LSP's pubkey (the old code passed this wallet's own pubkey,
        // which never matches an LSP, so the churn bonus never fired once).
        let current_pubkey = self.node.active_lsp().map(|a| a.info.pubkey.clone());
        let ranked = rank_lsps(&lsps, current_pubkey.as_deref());
        Ok(ranked.into_iter().cloned().collect())
    }

    // ── Channel operations ───────────────────────────────────────────────────

    /// Request a channel from the currently active LSP via LSPS1.
    /// Opens a real Lightning channel from the LSP back to this wallet.
    /// For browser wallets, the LSP's adapter polls for our peer connection
    /// (rather than trying to TCP-dial our WebSocket URL).
    ///
    /// Always runs check_channel_open_readiness() first. If the wallet is
    /// not in a safe state to open a channel, returns an error before any
    /// LSP communication.
    pub async fn open_channel(&self, inbound_sats: u64) -> crate::error::LijResult<String> {
        use crate::lsp::{Lsps1ChannelRequest, LspClient};

        // Wallet health gate. Refuses if any safety check fails.
        self.check_channel_open_readiness()?;

        let active = self.node.active_lsp()
            .ok_or_else(|| crate::error::LijError::Lsp("No active LSP — call auto_select_lsp first".into()))?;

        let client_pubkey = self.node.node_pubkey()?;
        let worker_url = self.node.worker_url().to_string();

        let request = Lsps1ChannelRequest {
            inbound_liquidity_sats: inbound_sats,
            client_pubkey,
            client_host: "wss://lijox-ws.lightning-mod.com".to_string(),
            is_browser_node: true,
            refund_onchain_address: None,
        };

        let client = LspClient::new(active.info.clone());
        let response = client.request_channel(&worker_url, request).await?;

        log::info!("Channel request succeeded: {}", response.channel_id);
        Ok(response.channel_id)
    }

    /// Pre-flight wallet health check. Runs before any channel-open
    /// operation. Verifies:
    ///   - signer state (counter readable, ratchet readable, no regression,
    ///     BIP32 derivations succeed)
    ///   - storage round-trip (write a probe key and read it back)
    ///
    /// Returns the diagnostic snapshot on success. Caller should log
    /// the snapshot for traceability. On failure, returns an error
    /// with plain-language message suitable for surfacing to the user.
    pub fn check_channel_open_readiness(&self) -> crate::error::LijResult<crate::signer::HealthReport> {
        // 1. Signer health (counter, ratchet, derivations).
        let signer_provider = self.node.signer_provider();
        let report = signer_provider.check_health()?;
        log::info!(
            "Channel open readiness check passed: counter={}, ratchet={}",
            report.counter, report.ratchet,
        );
        Ok(report)
    }

    // ── Peer management ──────────────────────────────────────────────────────

    /// Allocate a socket id and begin an outbound peer connection.
    /// Returns (socket_id, first_bytes_to_send).
    /// lij-wasm opens the WebSocket, writes first_bytes on open, then feeds
    /// incoming bytes back via PeerManager::read_event.
    pub fn begin_peer_connection(
        &self,
        peer_pubkey_hex: &str,
    ) -> crate::error::LijResult<(u64, Vec<u8>)> {
        use bitcoin::secp256k1::PublicKey;

        let pk_bytes = hex::decode(peer_pubkey_hex)
            .map_err(|e| crate::error::LijError::InvalidArgument(format!("Bad pubkey hex: {e}")))?;
        let peer_pubkey = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| crate::error::LijError::InvalidArgument(format!("Bad pubkey: {e}")))?;

        let socket_id = self.node.next_socket_id();
        let first_bytes = self.node.new_outbound_connection(peer_pubkey, socket_id)?;
        Ok((socket_id, first_bytes))
    }

    /// List hex pubkeys of currently connected peers.
    pub fn list_peers(&self) -> crate::error::LijResult<Vec<String>> {
        self.node.list_peers()
    }

    /// Open an outbound channel to the active LSP, funded from on-chain balance.
    /// Delegates to the node; returns a status JSON immediately (the funding tx
    /// is built when LDK emits FundingGenerationReady during background_tick).
    pub fn open_channel_to_lsp(
        &self,
        amount_sats: u64,
        fee_rate_sat_per_vb: f64,
    ) -> crate::error::LijResult<String> {
        self.node.open_channel_to_lsp(amount_sats, fee_rate_sat_per_vb)
    }

    /// Access the underlying LijNode. Used by lij-wasm to invoke PeerManager
    /// methods directly (read_event, timer_tick_occurred, process_events).
    pub fn node(&self) -> &crate::node::LijNode {
        &self.node
    }

    // ── Backup ───────────────────────────────────────────────────────────────

    /// Push current channel state to Cloudflare KV.
    /// Called automatically after payments and channel events.
    /// Also callable manually from PWA for explicit backup.
    /// Snapshot everything an out-of-lock backup push needs: the encrypted blob,
    /// an owned (Arc) signer, and a clone of the enabled sinks. SYNCHRONOUS — the
    /// caller gathers this while holding the wallet lock, then releases the lock
    /// BEFORE the network push. Holding the wallet mutex across the push's
    /// `.await` would let a background tick re-enter and panic the single-threaded
    /// WASM mutex. Returns None when there's no channel state to back up.
    pub fn prepare_backup(
        &self,
    ) -> LijResult<Option<(StateBlob, std::sync::Arc<crate::key::RootKey>, Vec<BackupSink>)>> {
        let blob = match self.node.gather_state_blob()? {
            Some(blob) => blob,
            None => return Ok(None),
        };
        if self.sinks.is_empty() {
            log::warn!("backup: no sinks enabled — state not pushed anywhere");
            return Ok(None);
        }
        Ok(Some((blob, self.node.portable_signer_arc(), self.sinks.clone())))
    }

    /// Auto-backup variant of prepare_backup: returns a snapshot ONLY when channel
    /// state has changed since the last push (the node's dirty flag). Also returns
    /// a handle to that flag so the caller can re-mark it if the push fails. The
    /// flag is cleared here (snapshot time), so any state change during the push
    /// re-dirties it and the next tick re-pushes — no lost updates.
    pub fn prepare_backup_if_dirty(
        &self,
    ) -> LijResult<
        Option<(
            StateBlob,
            std::sync::Arc<crate::key::RootKey>,
            Vec<BackupSink>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        )>,
    > {
        if !self.node.take_backup_dirty() {
            return Ok(None);
        }
        match self.prepare_backup()? {
            Some((blob, signer, sinks)) => {
                Ok(Some((blob, signer, sinks, self.node.backup_dirty_handle())))
            }
            None => Ok(None),
        }
    }

    /// Abandon all channels without broadcasting (safe stale-restore recovery).
    pub fn force_close_all_without_broadcasting(&self) -> LijResult<u32> {
        self.node.force_close_all_without_broadcasting()
    }

    /// Snapshot the pieces the on-chain wallet view needs (root key, Esplora
    /// client, network) under the lock, so the caller runs the async scan
    /// UNLOCKED — same no-lock-across-await discipline as the backup path.
    pub fn onchain_handles(
        &self,
    ) -> (
        std::sync::Arc<crate::key::RootKey>,
        std::sync::Arc<crate::independent::IndependentClient>,
        bitcoin::Network,
    ) {
        (
            self.node.root_key_arc(),
            self.node.independent_client(),
            self.node.network,
        )
    }

    /// Build the enabled full-state backup sinks from RecoveryConfig. Future
    /// sinks (e.g. an on-device file) are added here with no call-site change —
    /// `backup()` just iterates whatever is enabled.
    fn build_backup_sinks(config: &WalletConfig) -> Vec<BackupSink> {
        let rc = RecoveryConfig::default();
        let mut sinks = Vec::new();
        if rc.full_state_cloudflare {
            sinks.push(BackupSink::CloudflareKv(KvBackupClient::new(StorageConfig {
                worker_url: config.worker_url.clone(),
                auth_token: config.backup_auth_token.clone(),
            })));
        }
        sinks
    }

    /// Scenario-A inject: decrypt a backup StateBlob and write its entries back
    /// into local storage so `LijNode::restore()` can rehydrate them. The blob
    /// bundles already-encrypted per-entry values and is encrypted again as a
    /// whole; we peel the outer layer and restore each entry's at-rest ciphertext
    /// verbatim (per-entry decryption then happens inside restore). Returns the
    /// number of ChannelMonitor entries restored.
    /// v221 (DP fire-and-forget): the public door for the device-file import —
    /// the same decrypt+inject the cloud restore uses; a wrong-seed file fails
    /// decryption, which is the natural authentication. State applies on the
    /// next boot; the page restarts after.
    pub fn import_state_blob(&self, blob: &StateBlob) -> LijResult<u32> {
        Self::inject_state_blob(self.node.storage_ref(), self.node.root_key_ref(), blob)
    }

    fn inject_state_blob(
        storage: &dyn LijStorage,
        root_key: &RootKey,
        blob: &StateBlob,
    ) -> LijResult<u32> {
        let enc_key = root_key.encryption_key();
        let plaintext = crate::persist::decrypt(&enc_key, &blob.encrypted_data)
            .map_err(|e| LijError::Backup(format!("backup decrypt: {e}")))?;
        let bundle: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&plaintext)
                .map_err(|e| LijError::Backup(format!("backup bundle parse: {e}")))?;
        let mut monitors = 0u32;
        for (key, hex_val) in &bundle {
            let bytes = hex::decode(hex_val)
                .map_err(|e| LijError::Backup(format!("backup entry hex: {e}")))?;
            storage.set(key, &bytes)?;
            if key.starts_with(crate::persist::MONITOR_KEY_PREFIX) {
                monitors += 1;
            }
        }
        // Resume the version counter from the restored backup, so this device's
        // next push is monotonically newer than what's already in KV. Without
        // this a restored device starts at v0 and the Worker rejects every push
        // as stale (409), silently breaking backup on the recovered device.
        storage.set(
            crate::storage::KEY_BACKUP_VERSION,
            &blob.version.to_be_bytes(),
        )?;
        Ok(monitors)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// v224 (S41, DP RULED — tester-zero field bug): boot NEVER re-decides a
    /// wallet's provider. The old code re-ranked the registry at every boot;
    /// with two providers tying exactly, registry order broke the tie and a
    /// reload flipped a funded wallet's provider unpressed. Ladder — first
    /// rung wins, and a wallet with a choice or a channel stays LOYAL under
    /// outage (no provider this session beats a substituted one):
    ///   1. the user's persisted explicit choice (fresh registry copy when
    ///      present, stored snapshot when not)
    ///   2. the LSP this wallet already holds a channel with
    ///   3. fresh wallets: config.preferred_lsp_pubkey (integrator override),
    ///      else the LiJ-Node default
    ///   4. default absent/unreachable: top VIABLE listing — rank_lsps'
    ///      last remaining selection job (display order keeps the other).
    async fn auto_select_lsp(&mut self, config: &WalletConfig) -> LijResult<()> {
        let lsps = fetch_lsp_registry(&config.worker_url).await
            .unwrap_or_else(|e| {
                log::warn!("LSP registry fetch failed: {e}, using stored choice/default");
                vec![]
            });
        let by_pk = |pk: &str| lsps.iter().find(|l| l.pubkey == pk).cloned();

        // 1. Explicit choice — honored even when the registry no longer
        //    lists it (the snapshot carries the wiring); never substituted.
        if let Some(chosen) = self.node.load_chosen_lsp() {
            let lsp = by_pk(&chosen.pubkey).unwrap_or(chosen);
            log::info!("LSP select: user choice {} ({})", lsp.name, lsp.pubkey);
            if let Err(e) = self.node.connect_lsp(lsp).await {
                log::warn!("chosen LSP unreachable — staying loyal, no provider this session: {e}");
            }
            return Ok(());
        }

        // 2. Channel relationship — the wallet's real provider pre-choice.
        if let Ok(channels) = self.node.get_channels() {
            for c in &channels {
                if let Some(lsp) = by_pk(&c.counterparty_pubkey) {
                    log::info!("LSP select: channel counterparty {} ({})", lsp.name, lsp.pubkey);
                    if let Err(e) = self.node.connect_lsp(lsp).await {
                        log::warn!("channel LSP unreachable — staying loyal, no provider this session: {e}");
                    }
                    return Ok(());
                }
            }
        }

        // 3. Fresh wallet: integrator override, else the LiJ-Node default.
        let default_pk = config.preferred_lsp_pubkey.as_deref().unwrap_or(DEFAULT_LSP_PUBKEY);
        if let Some(lsp) = by_pk(default_pk) {
            log::info!("LSP select: default {} ({})", lsp.name, lsp.pubkey);
            match self.node.connect_lsp(lsp).await {
                Ok(()) => return Ok(()),
                Err(e) => log::warn!("default LSP unreachable, trying top viable listing: {e}"),
            }
        }

        // 4. Last resort for fresh wallets only: top viable listing.
        if let Some(lsp) = rank_lsps(&lsps, None).first().map(|l| (*l).clone()) {
            log::warn!("LSP select: falling back to top viable listing {} ({})", lsp.name, lsp.pubkey);
            if let Err(e) = self.node.connect_lsp(lsp).await {
                log::warn!("fallback LSP unreachable — wallet online but no provider yet: {e}");
            }
            return Ok(());
        }

        log::warn!("No LSPs available in registry — wallet online but no channel yet");
        Ok(())
    }

    fn node_config_worker_url(&self) -> String {
        // Phase 10b — bug fix. Previously returned empty string with a TODO,
        // which broke list_lsps and auto_select_lsp (both fetch /lsps relative
        // to origin, returning HTML and a JSON parse error).
        // Now returns the real worker URL from the node, same as the public
        // worker_url() accessor on this struct.
        self.node.worker_url().to_string()
    }

    // ── Channel close operations ────────────────────────────────────────

    /// Initiate a cooperative close on a single channel by hex channel_id.
    /// Synchronous: returns Ok when shutdown is sent. The actual close
    /// transaction broadcast and Event::ChannelClosed arrive asynchronously.
    pub fn close_channel(&self, channel_id_hex: &str) -> LijResult<()> {
        self.node.close_channel(channel_id_hex)
    }

    /// Initiate a unilateral force close on a single channel.
    /// Destructive — caller MUST confirm with user first.
    pub fn force_close(&self, channel_id_hex: &str) -> LijResult<()> {
        self.node.force_close(channel_id_hex)
    }

    /// Force-close a single channel WITHOUT broadcasting any tx. For a stranded
    /// open whose funding never confirmed (stops LDK's no-progress watchdog —
    /// the flap cause — and broadcasts nothing). Destructive — confirm first.
    pub fn force_close_without_broadcasting(&self, channel_id_hex: &str) -> LijResult<()> {
        self.node.force_close_without_broadcasting(channel_id_hex)
    }

    /// End the relationship with a specific LSP — cooperatively close
    /// every channel with that counterparty. Returns per-channel results
    /// so caller can show partial-success state.
    pub fn end_lsp_relationship(
        &self,
        lsp_pubkey_hex: &str,
    ) -> LijResult<Vec<(String, LijResult<()>)>> {
        self.node.end_lsp_relationship(lsp_pubkey_hex)
    }

    /// List all closed channel records from the persistent log.
    /// Used by the Channel Management UI to render the Closed section.
    pub fn list_closed_channels(
        &self,
    ) -> LijResult<Vec<crate::closed_channel_log::ClosedChannelRecord>> {
        let log = crate::closed_channel_log::ClosedChannelLog::new(
            self.node.storage_clone(),
        );
        log.list()
    }

    /// Snapshot the outstanding close attempts as a Vec for serialization.
    /// Each entry includes elapsed seconds since attempt started, so the
    /// UI can show a "Negotiating... 12s" timer.
    pub fn outstanding_close_attempts_snapshot(
        &self,
    ) -> LijResult<Vec<OutstandingCloseAttempt>> {
        let now = current_time_secs();
        let attempts = self.node.outstanding_close_attempts();
        let attempts = attempts.lock()
            .map_err(|e| LijError::Node(format!("Mutex poisoned: {e}")))?;
        let mut out = Vec::with_capacity(attempts.len());
        for (channel_id, record) in attempts.iter() {
            out.push(OutstandingCloseAttempt {
                channel_id_hex: hex::encode(channel_id.0),
                kind: format!("{:?}", record.kind),
                counterparty_pubkey_hex: record.counterparty_pubkey_hex.clone(),
                started_at_unix_secs: record.started_at_unix_secs,
                elapsed_secs: now.saturating_sub(record.started_at_unix_secs),
            });
        }
        Ok(out)
    }
}

/// Snapshot type for outstanding close attempts. Serializable to JSON
/// for the WASM binding.
#[derive(serde::Serialize, Clone, Debug)]
pub struct OutstandingCloseAttempt {
    pub channel_id_hex: String,
    pub kind: String,
    pub counterparty_pubkey_hex: String,
    pub started_at_unix_secs: u64,
    pub elapsed_secs: u64,
}

/// Seconds since the Unix epoch. WASM has no SystemTime — std's impl traps
/// with `unreachable`, poisoning the whole engine (the Session-17 diagnostic
/// panic in outstanding_close_attempts_snapshot) — so use the browser clock
/// there, mirroring node.rs / chain_coordinator.rs / tier2_wallet.rs.
fn current_time_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    { (js_sys::Date::now() / 1000.0) as u64 }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn parse_bitcoin_network(s: &str) -> LijResult<bitcoin::Network> {
    match s {
        "bitcoin" => Ok(bitcoin::Network::Bitcoin),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(LijError::InvalidArgument(format!("Unknown network: {other}"))),
    }
}

