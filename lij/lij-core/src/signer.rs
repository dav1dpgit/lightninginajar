// signer.rs
// LiJ's custom LDK signer wrapper.
//
// Replaces direct KeysManager use as the SignerProvider for the channel
// manager. Overrides shutdown / destination script derivation to land at
// BIP84 paths (m/84h/{coin}h/0h/0/n) that any BIP84-default wallet
// (BlueWallet, Sparrow, electrum-personal-server with BIP84 enabled,
// hardware wallet imports) auto-discovers from the seed alone.
//
// Architecture:
//   - LijSignerProvider wraps Arc<KeysManager>.
//   - KeysManager retains its EntropySource and NodeSigner duties
//     (random bytes, node identity, invoice signing) — those are still
//     accessed directly via the Arc<KeysManager> stored on LijNode.
//   - LijSignerProvider implements SignerProvider only. All channel
//     signer factory calls go through LijSignerProvider; the wrapped
//     KeysManager only sees these calls indirectly via LijChannelSigner.
//
// Override surface (settled in v0.2.0 — Plan A cutover):
//   ChannelSigner trait:
//     channel_keys_id() — inner KeysManager's keys_id, with our
//       channel_index encoded in bytes 0..4 (set during
//       generate_channel_keys_id)
//     pubkeys() — delegate to inner. NO override on payment_point.
//     all other methods — delegate to inner InMemorySigner.
//   EcdsaChannelSigner trait:
//     all methods delegate to inner InMemorySigner.
//   SignerProvider trait:
//     generate_channel_keys_id() — allocate channel_index from counter,
//       encode in bytes 0..4 of the inner-generated keys_id.
//     derive_channel_signer() — delegate to inner; wrap result in
//       LijChannelSigner (a thin delegating wrapper plus channel_index
//       metadata).
//     read_chan_signer() — pre-LDK-0.0.113 legacy, panics.
//     get_destination_script() — BIP84 path m/84h/{coin}h/0h/0/{counter}.
//     get_shutdown_scriptpubkey() — BIP84 path m/84h/{coin}h/0h/0/{counter}.
//
// Recovery contracts (v0.2.0+, with OutputSweeper):
//   ALL channel closures (cooperative, force, HTLC-timeout-induced)
//     → swept on-chain to m/84h/{coin}h/0h/0/n
//     → P2WPKH, BlueWallet (and any BIP84-default wallet) auto-discovers
//       the residue from the seed alone, no custom path required.
//
//   Force-close sweep happens via lightning::util::sweep::OutputSweeper
//   (see crate::sweeper). The signer's job is just to mint the correct
//   destination_script (m/84) — OutputSweeper handles tx construction,
//   fee-bumping, and broadcast.
//
// Historical context (pre-v0.2.0, retained for legacy-channel recovery):
//   Before v0.2.0 LiJ overrode pubkeys() to force the payment_point onto
//   a BIP32-derived static_remotekey at m/525h/0/0/0/{channel_index}.
//   That override landed force-close to_remote outputs at predictable
//   BIP32 addresses recoverable via BlueWallet's custom-path import
//   (P2WPKH for STATIC_REMOTE_KEY channels, descriptor-sweep for ANCHORS).
//   That mechanism is replaced by OutputSweeper. Existing pre-v0.2.0
//   channels with on-chain residue at m/525h paths are handled by the
//   deprecated `closed_channel_watcher.rs` fallback, and ultimately by
//   the seed-only recovery flow in Phase 1c.

use std::sync::{Arc, Mutex};

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Address, Network, ScriptBuf,
};
use lightning::{
    ln::script::ShutdownScript,
    sign::{
        ecdsa::{EcdsaChannelSigner, WriteableEcdsaChannelSigner},
        ChannelSigner, EntropySource, HTLCDescriptor, InMemorySigner, KeysManager,
        SignerProvider,
    },
    util::ser::{Writeable, Writer},
};
use lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction, HolderCommitmentTransaction, HTLCOutputInCommitment};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::PaymentPreimage;

use crate::{
    error::{LijError, LijResult},
    persisted_counter::PersistedCounter,
};

// ── LijSignerProvider ────────────────────────────────────────────────────────

/// LiJ's wrapping signer provider.
///
/// Holds an Arc<KeysManager> for delegation of operational signer
/// construction, plus the BIP32 xprivs and persistent counter that
/// govern our recovery-aware path scheme.
pub struct LijSignerProvider {
    inner: Arc<KeysManager>,
    /// xpriv at m/84h/{coin}h/0h/0 — children are cooperative-close /
    /// destination scripts.
    shutdown_xpriv: ExtendedPrivKey,
    /// Persistent counter for shutdown_script and destination_script
    /// allocation. Distinct from per-channel signer indexing
    /// (channel_index is encoded in keys_id and consumed by LDK only).
    counter: PersistedCounter,
    /// Bitcoin network for address encoding.
    network: Network,
    /// v185 SWEEP-DESTINATION MEMO (Session 27). One m/84 destination is
    /// pinned for the lifetime of a pending-sweep epoch and reused across
    /// the OutputSweeper's per-block regenerations, instead of minting a
    /// fresh index every block (the dominant index burner behind the
    /// BlueWallet gap-limit failure). Cleared by the node's background
    /// tick the moment no tracked output can rebroadcast (per-epoch
    /// release rule; docs/session27.md privacy analysis).
    sweep_memo: Mutex<Option<ScriptBuf>>,
}

impl LijSignerProvider {
    /// Next-to-issue allocator index, without advancing (diagnostics +
    /// the frontend's receive-index max-in; Session 23 Option B).
    pub fn peek_index(&self) -> crate::error::LijResult<u32> {
        self.counter.peek()
    }

    /// Raise the shared allocator floor to `n` (Session 23 Option B):
    /// the frontend reserves receive-index territory here so signer
    /// scripts can never collide with shown/used receive addresses.
    /// Routes through the LIVE counter instance by construction.
    pub fn raise_index_floor(&self, n: u32) -> crate::error::LijResult<()> {
        self.counter.raise_floor(n)
    }

    pub fn new(
        inner: Arc<KeysManager>,
        shutdown_xpriv: ExtendedPrivKey,
        counter: PersistedCounter,
        network: Network,
    ) -> Self {
        Self {
            inner,
            shutdown_xpriv,
            counter,
            network,
            sweep_memo: Mutex::new(None),
        }
    }

    /// Access the inner KeysManager for EntropySource / NodeSigner duties
    /// that LijNode still routes directly to KeysManager.
    pub fn inner(&self) -> &Arc<KeysManager> {
        &self.inner
    }

    /// Read the current counter value without advancing. Used by health
    /// checks and diagnostics.
    pub fn peek_counter(&self) -> LijResult<u32> {
        self.counter.peek()
    }

    /// v211 (escape kit): PEEK the allocator — no increment, no memo — and
    /// derive the m/84 P2WPKH destination at that index. The offline room is
    /// read-only by constitution, so the escape export must not advance the
    /// persisted counter. If the index is later handed out normally, the
    /// worst case is address reuse, which is safe by design (accounting is
    /// per-outpoint) and stays inside the BIP84 gap window by construction.
    pub fn peek_destination_script(&self) -> LijResult<(u32, ScriptBuf)> {
        let index = self.counter.peek()?;
        let script = self.derive_shutdown_script_at(index)?;
        Ok((index, script))
    }

    /// Read the upward ratchet value without advancing. Should always
    /// equal peek_counter() under normal operation.
    pub fn peek_ratchet(&self) -> LijResult<u32> {
        self.counter.peek_ratchet()
    }

    /// v185: memoized sweep destination. First call in an epoch allocates
    /// ONE index (read_and_increment — same cost as any other handout)
    /// and derives its m/84 P2WPKH script; every later call returns the
    /// same script until clear_sweep_memo(). O(1) at call time.
    pub fn sweep_destination_script(&self) -> LijResult<ScriptBuf> {
        let mut memo = self
            .sweep_memo
            .lock()
            .map_err(|e| LijError::Node(format!("sweep memo mutex poisoned: {e}")))?;
        if let Some(script) = memo.as_ref() {
            return Ok(script.clone());
        }
        let index = self.counter.read_and_increment()?;
        let script = self.derive_shutdown_script_at(index)?;
        log::info!(
            "sweep memo: pinned m/84 index {} for this pending-sweep epoch",
            index
        );
        *memo = Some(script.clone());
        Ok(script)
    }

    /// v185: close the sweep epoch. Called by the node's background tick
    /// when no tracked output is in a rebroadcastable state. The next
    /// epoch allocates fresh — a confirmed destination is never reused.
    pub fn clear_sweep_memo(&self) {
        if let Ok(mut memo) = self.sweep_memo.lock() {
            if memo.take().is_some() {
                log::info!("sweep memo: epoch closed, destination released");
            }
        }
    }

    /// Wallet health check. Verifies counter readability, ratchet
    /// monotonicity, and that BIP32 derivations succeed at the current
    /// counter index. Called before any channel-open operation.
    ///
    /// Returns Ok with diagnostic on success. Returns Err with a
    /// plain-language message on failure — the caller should refuse
    /// the channel-open and surface the message to the user.
    pub fn check_health(&self) -> LijResult<HealthReport> {
        // 1. Counter readable
        let counter = self
            .counter
            .peek()
            .map_err(|e| LijError::Node(format!(
                "Wallet storage check failed (counter unreadable).                  Cannot safely open a channel. Details: {e}"
            )))?;

        // 2. Ratchet readable
        let ratchet = self
            .counter
            .peek_ratchet()
            .map_err(|e| LijError::Node(format!(
                "Wallet storage check failed (ratchet unreadable).                  Cannot safely open a channel. Details: {e}"
            )))?;

        // 3. Counter must be >= ratchet. Guards against regressions.
        if counter < ratchet {
            return Err(LijError::Node(format!(
                "Wallet state regressed (counter={} < ratchet={}).                  Cannot safely open a channel. This usually means storage                  was partially restored or modified. Try restoring from                  backup or contact support.",
                counter, ratchet
            )));
        }

        // 4. Verify shutdown_xpriv derivation at current index succeeds
        let _shutdown_script = self
            .derive_shutdown_script_at(counter)
            .map_err(|e| LijError::Node(format!(
                "Cooperative-close destination derivation failed at index {}.                  Cannot safely open a channel. Details: {e}",
                counter
            )))?;

        Ok(HealthReport {
            counter,
            ratchet,
        })
    }
}

/// Diagnostic snapshot returned by check_health on success.
/// All fields safe to log; none are private key material.
#[derive(Clone, Debug)]
pub struct HealthReport {
    pub counter: u32,
    pub ratchet: u32,
}

impl LijSignerProvider {

    /// Derive the raw public key at m/84h/{coin}h/0h/0/{index} — the
    /// terminus pin's payment_point. Same parent and path as
    /// derive_shutdown_script_at; this returns the key itself where that
    /// returns the P2WPKH script wrapping it.
    fn derive_payment_pubkey_at(&self, index: u32) -> LijResult<PublicKey> {
        let secp = Secp256k1::new();
        let child = self
            .shutdown_xpriv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
                    .map_err(|e| LijError::Key(format!("Bad child number: {e}")))?]),
            )
            .map_err(|e| LijError::Key(format!("shutdown_xpriv derivation failed: {e}")))?;
        Ok(child.private_key.public_key(&secp))
    }

    /// Derive the on-chain destination script at m/84h/{coin}h/0h/0/{index}.
    /// Returns a P2WPKH ScriptBuf encoded for self.network.
    fn derive_shutdown_script_at(&self, index: u32) -> LijResult<ScriptBuf> {
        let secp = Secp256k1::new();
        let child = self
            .shutdown_xpriv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
                    .map_err(|e| LijError::Key(format!("Bad child number: {e}")))?]),
            )
            .map_err(|e| LijError::Key(format!("shutdown_xpriv derivation failed: {e}")))?;
        let pubkey = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
        let address = Address::p2wpkh(&pubkey, self.network)
            .map_err(|e| LijError::Key(format!("p2wpkh encoding failed: {e}")))?;
        Ok(address.script_pubkey())
    }
}

// Encode/decode channel_index in the first 4 bytes of keys_id.
fn encode_channel_index(index: u32, inner_id: [u8; 32]) -> [u8; 32] {
    let mut out = inner_id;
    out[..4].copy_from_slice(&index.to_be_bytes());
    out
}

// ── Terminus v2 marker (Session 23) ─────────────────────────────────────────
//
// The TERMINUS FIX pins a channel's to_remote payment_point to the seed's
// m/84 tree so LSP force-closes pay a plain P2WPKH any BIP84 wallet reads.
// The pin decision is encoded IN the persisted channel_keys_id so that
// signer reconstruction is deterministic across restarts, and so that
// EXISTING (pre-v176) channels are structurally untouchable: no marker,
// no override, byte-identical passthrough behavior. Changing pubkeys
// under a live channel would invalidate its signatures — the marker
// makes that impossible rather than merely avoided.
//
// Layout: bytes 0..4 = channel_index (unchanged since Phase 4);
// bytes 4..8 = magic [0x4C, 0x4A, 0x84, 0x02] ("LJ", m/84, v2). For
// unmarked channels bytes 4..8 come from KeysManager entropy — an
// accidental 4-byte match has probability 2^-32 per channel; with this
// fleet's channel count the risk is negligible, and a false positive
// degrades to a force-close-and-sweep, never fund loss.
const TERMINUS_MARKER: [u8; 4] = [0x4C, 0x4A, 0x84, 0x02];

/// High bit of user_channel_id requests the terminus pin at keys-id
/// generation. Set by our own code only: outbound opens (which propose
/// no-anchors) and inbound accepts (iff the proposed channel_type is
/// non-anchors, read from Event::OpenChannelRequest). Low 32 bits carry
/// the open fee rate; bits 32..96 a nonce — bit 127 is unclaimed.
pub const UCID_TERMINUS_PIN_BIT: u128 = 1u128 << 127;

fn encode_channel_index_v2(index: u32, inner_id: [u8; 32]) -> [u8; 32] {
    let mut out = encode_channel_index(index, inner_id);
    out[4..8].copy_from_slice(&TERMINUS_MARKER);
    out
}

pub fn keys_id_has_terminus_marker(keys_id: [u8; 32]) -> bool {
    keys_id[4..8] == TERMINUS_MARKER
}

fn decode_channel_index(keys_id: [u8; 32]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&keys_id[..4]);
    u32::from_be_bytes(buf)
}

impl SignerProvider for LijSignerProvider {
    type EcdsaSigner = LijChannelSigner;
    #[cfg(taproot)]
    type TaprootSigner = LijChannelSigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        // Allocate the next channel index. On counter write failure
        // we cannot return Result here, so we have to choose: panic or
        // burn an index. Panicking surfaces the bug; silent burning
        // would cause address reuse on next attempt. Panic.
        let index = self
            .counter
            .read_and_increment()
            .expect("PersistedCounter write failed during channel keys id generation");
        let inner_id =
            self.inner
                .generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id);
        // Terminus v2 (Session 23): callers that guarantee a non-anchors
        // channel request the m/84 payment_point pin via the UCID bit.
        // The marker persists in keys_id, making the pin deterministic
        // across restarts and structurally absent on legacy channels.
        if user_channel_id & UCID_TERMINUS_PIN_BIT != 0 {
            log::info!(
                "[terminus] keys_id generated WITH v2 pin marker (index={index}, inbound={inbound})"
            );
            encode_channel_index_v2(index, inner_id)
        } else {
            encode_channel_index(index, inner_id)
        }
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        // Delegate channel-key derivation entirely to inner KeysManager.
        // The keys_id we received still has our channel_index encoded in
        // bytes 0..4 (placed there by generate_channel_keys_id); inner
        // KeysManager's HKDF doesn't care about the first 4 bytes being
        // any particular value, so we pass through verbatim. Bytes 0..4
        // are now metadata for LiJ's own bookkeeping only.
        let inner_signer =
            self.inner
                .derive_channel_signer(channel_value_satoshis, channel_keys_id);
        let channel_index = decode_channel_index(channel_keys_id);
        // Terminus v2 (Session 23): marked channels get their
        // payment_point pinned to m/84h/{coin}h/0h/0/{channel_index}.
        // The pin index IS the channel_index — same shared allocator,
        // already persisted in keys_id, so reconstruction here is
        // deterministic on every restart. Unmarked (all pre-v176)
        // channels take the untouched passthrough below.
        if keys_id_has_terminus_marker(channel_keys_id) {
            match self.derive_payment_pubkey_at(channel_index) {
                Ok(pinned_point) => {
                    let mut pinned = inner_signer.pubkeys().clone();
                    pinned.payment_point = pinned_point;
                    log::info!(
                        "[terminus] signer derived WITH m/84 pin at index {channel_index}"
                    );
                    return LijChannelSigner::new_pinned(inner_signer, channel_index, pinned);
                }
                Err(e) => {
                    // A marked channel whose pin cannot be derived must not
                    // silently fall back to HKDF keys: the channel was
                    // NEGOTIATED with the pinned point, and mismatched
                    // pubkeys would brick it anyway. This derivation is
                    // pure BIP32 from material we hold — failure here is
                    // a bug, not an environment condition. Panic loudly.
                    panic!(
                        "[terminus] pinned payment_point derivation failed at index {channel_index}: {e}"
                    );
                }
            }
        }
        LijChannelSigner::new(inner_signer, channel_index)
    }

    fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        // LDK calls this only for objects written by LDK pre-0.0.113.
        // We're on 0.0.123 with no migration history — should never fire.
        // Panic loudly if it does so we know something unexpected happened.
        unimplemented!(
            "LijSignerProvider::read_chan_signer: LDK pre-0.0.113 not supported. \
             If this fires, LDK is reading legacy persisted state we don't have."
        );
    }

    fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        let index = self.counter.read_and_increment().map_err(|_| ())?;
        self.derive_shutdown_script_at(index).map_err(|_| ())
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        let index = self.counter.read_and_increment().map_err(|_| ())?;
        let script = self.derive_shutdown_script_at(index).map_err(|_| ())?;
        ShutdownScript::try_from(script).map_err(|_| ())
    }
}

// ── LijChannelSigner ─────────────────────────────────────────────────────────

/// Channel signer wrapping LDK's InMemorySigner.
///
/// As of v0.2.0 this is a thin delegating wrapper:
///   - All ChannelSigner / EcdsaChannelSigner methods pass through to inner.
///   - channel_index is retained as observable metadata (bytes 0..4 of the
///     keys_id), useful for diagnostics and the deprecated
///     ClosedChannelWatcher fallback path. It is NOT consumed by any
///     signing logic.
///
/// Historical note (pre-0.2.0): this struct overrode pubkeys() to force the
/// payment_point onto a BIP32-derived static_remotekey at m/525h/0/0/0/{n}.
/// That override was removed when OutputSweeper landed — sweep funds now
/// land at m/84h/0h/0h/0/n via the OutputSweeper's ChangeDestinationSource.
pub struct LijChannelSigner {
    inner: InMemorySigner,
    channel_index: u32,
    /// Terminus v2 (Session 23): Some(...) only for channels whose
    /// keys_id carries the v2 marker — inner pubkeys with payment_point
    /// replaced by the m/84 child at channel_index. pubkeys() returns
    /// this set, so the pinned point flows into open/accept messages,
    /// commitment construction, and the ChannelMonitor's to_remote watch
    /// script (channel.rs clones holder pubkeys from pubkeys(); the
    /// monitor derives counterparty_payment_script from the same set).
    /// None = pre-v176 passthrough, byte-identical to prior behavior.
    pinned_pubkeys: Option<ChannelPublicKeys>,
}

impl LijChannelSigner {
    pub fn new(inner: InMemorySigner, channel_index: u32) -> Self {
        Self {
            inner,
            channel_index,
            pinned_pubkeys: None,
        }
    }

    /// Terminus v2 constructor: signer for a marked channel, with the
    /// payment_point pinned to the seed's m/84 tree.
    pub fn new_pinned(
        inner: InMemorySigner,
        channel_index: u32,
        pinned: ChannelPublicKeys,
    ) -> Self {
        Self {
            inner,
            channel_index,
            pinned_pubkeys: Some(pinned),
        }
    }

    pub fn channel_index(&self) -> u32 {
        self.channel_index
    }
}

impl ChannelSigner for LijChannelSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        self.inner
            .validate_holder_commitment(holder_tx, outbound_htlc_preimages)
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        self.inner.validate_counterparty_revocation(idx, secret)
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        // Terminus v2 (Session 23): marked channels return the pinned set
        // (payment_point = m/84 child at channel_index) — LSP force-closes
        // then pay the seed's standard tree directly. Unmarked channels
        // delegate verbatim to inner, exactly as pre-v176: the
        // static_remote_key is whatever KeysManager's HKDF produces, and
        // force-close sweep destinations are decided downstream by
        // OutputSweeper via ChangeDestinationSource (m/84h/0h/0h/0/n).
        // The payment KEY is never used in channel-operation signing
        // (commitments/HTLCs/justice) — only in the descriptor-spend
        // path, which the node's S6 exemption keeps pinned outputs away
        // from (they are already spendable by any BIP84 wallet).
        match &self.pinned_pubkeys {
            Some(pinned) => pinned,
            None => self.inner.pubkeys(),
        }
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        // Inner stores the keys_id we passed during derive_channel_signer.
        // That keys_id has our channel_index encoded in bytes 0..4 already,
        // so a passthrough delegation is correct.
        self.inner.channel_keys_id()
    }

    fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters) {
        self.inner.provide_channel_parameters(channel_parameters);
    }
}

impl EcdsaChannelSigner for LijChannelSigner {
    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        inbound_htlc_preimages: Vec<PaymentPreimage>,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
        self.inner.sign_counterparty_commitment(
            commitment_tx,
            inbound_htlc_preimages,
            outbound_htlc_preimages,
            secp_ctx,
        )
    }

    fn sign_holder_commitment(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_holder_commitment(commitment_tx, secp_ctx)
    }

    // v211 (escape kit): the `unsafe_revoked_tx_signing` feature — enabled so
    // the read-only escape export can copy-sign the latest holder commitment
    // without the once-only lockdown `sign_holder_commitment` enforces — adds
    // this required trait method. Delegate straight to the inner
    // InMemorySigner, which implements it under the same gate. Same signing
    // material, no state, no lockdown flag; used only by escape_export.
    #[cfg(any(test, feature = "escape_kit"))]
    fn unsafe_sign_holder_commitment(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.unsafe_sign_holder_commitment(commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_justice_revoked_output(
            justice_tx, input, amount, per_commitment_key, secp_ctx,
        )
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_justice_revoked_htlc(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            htlc,
            secp_ctx,
        )
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        htlc_descriptor: &HTLCDescriptor,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner
            .sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx)
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(
            htlc_tx,
            input,
            amount,
            per_commitment_point,
            htlc,
            secp_ctx,
        )
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &ClosingTransaction,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_holder_anchor_input(
        &self,
        anchor_tx: &bitcoin::Transaction,
        input: usize,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_holder_anchor_input(anchor_tx, input, secp_ctx)
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        msg: &UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner
            .sign_channel_announcement_with_funding_key(msg, secp_ctx)
    }
}

// ── Writeable ────────────────────────────────────────────────────────────────
//
// LDK serializes signers as part of ChannelMonitor and ChannelManager
// persistence. Our serialization wraps inner's serialization with a
// 4-byte channel_index prefix. As of v0.2.0 there is no static_remotekey
// override, so the channel_index is observable metadata only — useful
// for diagnostics and the deprecated ClosedChannelWatcher path. On
// deserialization the inner signer is re-derived from KeysManager via
// the keys_id.
//
// (For Phase 4, deserialization is not yet wired — channel manager
// re-derivation flows through SignerProvider::derive_channel_signer
// using the channel_keys_id stored in ChannelManager state. This
// Writeable impl exists to satisfy the trait bound but won't be the
// hot path until we add read-side deserialization in Phase 5.)

impl Writeable for LijChannelSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        // Format: [channel_index: u32 BE][inner: variable]
        self.channel_index.to_be_bytes().write(writer)?;
        self.inner.write(writer)?;
        Ok(())
    }
}

impl WriteableEcdsaChannelSigner for LijChannelSigner {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    use crate::storage::native_storage::MemoryStorage;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn channel_index_round_trip() {
        let inner = [0xabu8; 32];
        let encoded = encode_channel_index(42, inner);
        assert_eq!(decode_channel_index(encoded), 42);
        // Bytes 4..32 preserved
        for i in 4..32 {
            assert_eq!(encoded[i], inner[i]);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn channel_index_zero_decodes_correctly() {
        let inner = [0u8; 32];
        let encoded = encode_channel_index(0, inner);
        assert_eq!(decode_channel_index(encoded), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn channel_index_max_decodes_correctly() {
        let inner = [0xffu8; 32];
        let encoded = encode_channel_index(u32::MAX, inner);
        assert_eq!(decode_channel_index(encoded), u32::MAX);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn shutdown_script_at_index_0_matches_pinned() {
        use bip39::Mnemonic;
        use crate::key::RootKey;

        let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .parse()
            .unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        let storage = Arc::new(MemoryStorage::new());

        let seed = root.lightning_node_key().unwrap().private_key.secret_bytes();
        let inner = Arc::new(KeysManager::new(&seed, 0, 0));
        let counter = PersistedCounter::new(storage).unwrap();

        let provider = LijSignerProvider::new(
            inner,
            root.shutdown_xpriv().unwrap(),
            counter,
            Network::Bitcoin,
        );

        let script = provider.derive_shutdown_script_at(0).unwrap();
        // Convert script back to an address and compare to pinned
        let address = Address::from_script(&script, Network::Bitcoin).unwrap();
        assert_eq!(
            address.to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "shutdown script at index 0 must match BlueWallet's m/84'/0'/0'/0/0"
        );
    }
}
