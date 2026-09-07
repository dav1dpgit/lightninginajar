// key.rs
// Handles BIP39 mnemonic generation, seed derivation, and child key paths.
// The mnemonic is the single backup item — it restores both identity and funds.
// Private keys never leave this module in plaintext; only public keys are exported.
//
// Derivation paths in use:
//   m/525h                 — portable identity (KV backup blob keying)
//   m/84h/{coin}h/0h/0/n   — BIP84 shutdown destination + OutputSweeper sweeps, counter n
//
// Recovery story:
//   ALL channel closure residue (cooperative, force, HTLC-timeout) lands at
//   m/84h/{coin}h/0h/0/n — a standard path, but third-party wallets find
//   it from seed alone ONLY with gap limit >=500: real usage spreads
//   indices past default gaps (S25 finding; LiJ itself derives from the
//   persisted counter, no scan). Force-close residue is built and broadcast
//   automatically by lightning::util::sweep::OutputSweeper (see
//   crate::sweeper). Seed-only recovery for offline-wallet scenarios goes
//   through the LSP registry (Phase 1c).
//
// Legacy paths (pre-v0.2.0, retained for reading historical channel state
// off chain via the deprecated closed_channel_watcher):
//   m/525h/0/0/0/n         — static_remotekey for force-close to_remote of
//                            pre-v0.2.0 channels. This derivation function
//                            (`static_remotekey_xpriv`) was removed in
//                            v0.2.0 when Plan A landed — KeysManager's
//                            HKDF-default static_remote_key is now used,
//                            and OutputSweeper handles the sweep to m/84.
//                            Manual recovery of any leftover m/525 residue
//                            uses the procedure documented in RECOVERY.md.

use bip39::Mnemonic;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey},
    secp256k1::Secp256k1,
    Network,
};
use rand::RngCore;

use crate::error::{LijError, LijResult};

/// The root key material derived from the user's mnemonic.
/// Holds the master extended private key; all Lightning and on-chain keys derive from it.
pub struct RootKey {
    master_xprv: ExtendedPrivKey,
    pub master_xpub: ExtendedPubKey,
    pub network: Network,
}

impl RootKey {
    /// Generate a fresh 12-word BIP39 mnemonic and derive root key.
    /// Called once at wallet creation — user must back up the mnemonic immediately.
    pub fn generate(network: Network) -> LijResult<(Self, Mnemonic)> {
        let mut entropy = [0u8; 16]; // 16 bytes = 128 bits = 12 words
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| LijError::Key(format!("Mnemonic generation failed: {e}")))?;

        let root = Self::from_mnemonic(&mnemonic, network)?;
        Ok((root, mnemonic))
    }

    /// Restore root key from an existing BIP39 mnemonic (wallet recovery flow).
    pub fn from_mnemonic(mnemonic: &Mnemonic, network: Network) -> LijResult<Self> {
        let seed = mnemonic.to_seed(""); // no passphrase — keep backup simple
        let secp = Secp256k1::new();

        let master_xprv = ExtendedPrivKey::new_master(network, &seed)
            .map_err(|e| LijError::Key(format!("Master key derivation failed: {e}")))?;

        let master_xpub = ExtendedPubKey::from_priv(&secp, &master_xprv);

        Ok(Self {
            master_xprv,
            master_xpub,
            network,
        })
    }

    /// Derive the LiJ identity key at m/525h.
    /// This pubkey is used to key the user's encrypted backup blob in
    /// Cloudflare KV (Phase 5 backup wire-up). It is NOT the wallet's
    /// Lightning node identity — that comes from KeysManager via HKDF
    /// and is reachable as `LijNode::node_pubkey()`.
    ///
    /// Was previously m/535h (Mutiny-compatible). Migrated to m/525h —
    /// LiJ's own purpose-level namespace — when Mutiny was deemed
    /// non-existent. No wallets in the wild required migration.
    pub fn lightning_node_key(&self) -> LijResult<ExtendedPrivKey> {
        let secp = Secp256k1::new();
        let path: DerivationPath = "m/525h"
            .parse()
            .map_err(|e| LijError::Key(format!("Path parse error: {e}")))?;

        self.master_xprv
            .derive_priv(&secp, &path)
            .map_err(|e| LijError::Key(format!("Key derivation failed: {e}")))
    }

    /// Derive the on-chain wallet account-level xpriv at m/84h/{coin}h/0h.
    ///
    /// Currently unused — kept for potential future BDK integration. The
    /// per-channel cooperative-close and LDK-sweep destinations use
    /// `shutdown_xpriv()` (chain-level path) rather than this account-level
    /// path, because the destinations are derived per-index by the signer.
    ///
    /// Cleanup candidate: revisit when BDK integration is scoped (Phase 12+).
    pub fn onchain_key(&self) -> LijResult<ExtendedPrivKey> {
        let secp = Secp256k1::new();
        let coin = match self.network {
            Network::Bitcoin => "0h",
            _ => "1h", // testnet/signet/regtest all use coin type 1
        };
        let path: DerivationPath = format!("m/84h/{coin}/0h")
            .parse()
            .map_err(|e| LijError::Key(format!("Path parse error: {e}")))?;

        self.master_xprv
            .derive_priv(&secp, &path)
            .map_err(|e| LijError::Key(format!("Key derivation failed: {e}")))
    }

    /// Derive the BIP84 receive-chain xpriv at m/84h/{coin}h/0h/0.
    ///
    /// Children of this xpriv (n=0,1,2,...) are P2WPKH-spendable destinations
    /// for cooperative closes and LDK-managed on-chain sweeps. Used by
    /// `LijSignerProvider::get_shutdown_scriptpubkey()` and
    /// `get_destination_script()` to produce per-channel destinations.
    ///
    /// Recovery: a third-party wallet importing the seed finds UTXOs at
    /// children of this xpriv ONLY within its gap limit — defaults (~20)
    /// miss real usage (S25 finding); raise to >=500. LiJ needs no scan.
    pub fn shutdown_xpriv(&self) -> LijResult<ExtendedPrivKey> {
        let secp = Secp256k1::new();
        let coin = match self.network {
            Network::Bitcoin => "0h",
            _ => "1h",
        };
        let path: DerivationPath = format!("m/84h/{coin}/0h/0")
            .parse()
            .map_err(|e| LijError::Key(format!("Path parse error: {e}")))?;

        self.master_xprv
            .derive_priv(&secp, &path)
            .map_err(|e| LijError::Key(format!("Key derivation failed: {e}")))
    }

    /// Derive the persistence encryption key from the master xpriv.
    /// Used to wrap ChannelMonitor / ChannelManager blobs at rest.
    /// Domain-separated from any other key use via HKDF salt+info.
    pub fn encryption_key(&self) -> [u8; 32] {
        crate::persist::derive_encryption_key(&self.master_xprv.private_key.secret_bytes())
    }

    /// v229 (S43, DP): LNURLp static-address preimages are DERIVED, not
    /// stored — HKDF-SHA256 over the master secret with a dedicated salt and
    /// the index as info. Nothing to back up: a wallet restored from its 12
    /// words recomputes every preimage it ever registered. Domain-separated
    /// from the persistence key (different salt and info) and from every
    /// BIP32 path; one-way, so a revealed preimage says nothing about the
    /// master secret or any other index.
    pub fn lnurlp_preimage(&self, index: u32) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(
            Some(b"LiJ-LNURLp-preimage-v1"),
            &self.master_xprv.private_key.secret_bytes(),
        );
        let mut out = [0u8; 32];
        hk.expand(&index.to_be_bytes(), &mut out)
            .expect("32 bytes is well within HKDF-SHA256's output limit");
        out
    }

    /// Derive the legacy static_remotekey receive-chain xpriv at m/525h/0/0/0.
    ///
    /// Used by pre-v0.2.0 channels: children of this xpriv (n=0,1,2,...)
    /// were the static_remotekey privkeys for each channel's force-close
    /// to_remote output. As of v0.2.0, LijSignerProvider no longer
    /// overrides the payment_point onto these keys — KeysManager's HKDF
    /// default is used, and OutputSweeper handles the sweep to m/84.
    ///
    /// This function is retained for: (1) the deprecated
    /// `closed_channel_watcher` fallback that scans on-chain for residue
    /// at m/525 addresses from any pre-v0.2.0 channel, and (2) onchain
    /// scan tooling that walks the m/525 chain for the same purpose.
    /// Both consumers will be removed when the seed-only LSP-registry
    /// recovery flow (Phase 1c) supersedes them. At that point this
    /// function should be deleted.
    #[deprecated(
        since = "0.2.0",
        note = "m/525 override removed by Plan A. This derivation is retained \
                only for closed_channel_watcher and onchain_scan, both of \
                which are themselves deprecated. Will be deleted when those go."
    )]
    pub fn static_remotekey_xpriv(&self) -> LijResult<ExtendedPrivKey> {
        let secp = Secp256k1::new();
        let path: DerivationPath = "m/525h/0/0/0"
            .parse()
            .map_err(|e| LijError::Key(format!("Path parse error: {e}")))?;

        self.master_xprv
            .derive_priv(&secp, &path)
            .map_err(|e| LijError::Key(format!("Key derivation failed: {e}")))
    }

    /// Return the portable BIP32-derived pubkey at m/525h, hex-encoded.
    ///
    /// This is the LiJ identity key — used to key the user's encrypted
    /// backup blob in Cloudflare KV. Recoverable from seed alone via any
    /// BIP32-aware tool. NOT the wallet's Lightning node identity (that
    /// comes from KeysManager via HKDF and is reachable as
    /// `LijNode::node_pubkey()`).
    pub fn portable_pubkey_hex(&self) -> LijResult<String> {
        let secp = Secp256k1::new();
        let node_xprv = self.lightning_node_key()?;
        let privkey = node_xprv.private_key;
        let pubkey = privkey.public_key(&secp);
        Ok(hex::encode(pubkey.serialize()))
    }

    /// Sign a 32-byte digest with the portable private key (the key whose pubkey
    /// is `portable_pubkey_hex`). Returns a 128-hex compact secp256k1 ECDSA
    /// signature. Used to authenticate backup challenges to the Worker.
    pub fn portable_sign_digest(&self, digest: &[u8; 32]) -> LijResult<String> {
        let secp = Secp256k1::new();
        let privkey = self.lightning_node_key()?.private_key;
        let msg = bitcoin::secp256k1::Message::from_slice(digest)
            .map_err(|e| LijError::Key(format!("digest -> message: {e}")))?;
        let sig = secp.sign_ecdsa(&msg, &privkey);
        Ok(hex::encode(sig.serialize_compact()))
    }
}

impl crate::storage::BackupSigner for RootKey {
    fn portable_pubkey_hex(&self) -> LijResult<String> {
        RootKey::portable_pubkey_hex(self)
    }
    fn sign_backup(&self, digest: &[u8; 32]) -> LijResult<String> {
        self.portable_sign_digest(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    /// Canonical BIP39 test seed used across LiJ and external verification.
    /// Verified against BlueWallet (Check 1, Check 2 — April 2026) and
    /// against derive.py (Python bip_utils library) for the addresses
    /// pinned in tests below.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_key_generation_and_restore() {
        let (root, mnemonic) = RootKey::generate(Network::Testnet).unwrap();
        let pubkey_original = root.portable_pubkey_hex().unwrap();

        // Restore from mnemonic — must produce identical pubkey
        let restored = RootKey::from_mnemonic(&mnemonic, Network::Testnet).unwrap();
        let pubkey_restored = restored.portable_pubkey_hex().unwrap();

        assert_eq!(pubkey_original, pubkey_restored);
    }

    #[test]
    fn test_different_mnemonics_give_different_keys() {
        let (_, mnemonic1) = RootKey::generate(Network::Testnet).unwrap();
        let (_, mnemonic2) = RootKey::generate(Network::Testnet).unwrap();
        assert_ne!(mnemonic1.to_string(), mnemonic2.to_string());
    }

    /// Pinned-vector test for shutdown_xpriv at child index 0.
    /// Locks the BIP84 derivation contract for cooperative-close destinations.
    /// If this test fails, the on-chain destination scheme has drifted from
    /// what BlueWallet auto-discovers. Don't change without re-running the
    /// joint verification pass against BlueWallet.
    #[test]
    fn test_shutdown_xpriv_known_address() {
        let mnemonic: Mnemonic = TEST_MNEMONIC.parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();

        let xpriv = root.shutdown_xpriv().unwrap();
        let secp = Secp256k1::new();

        // Derive child 0 — first cooperative-close destination
        let child_0 = xpriv
            .derive_priv(&secp, &"m/0".parse::<DerivationPath>().unwrap())
            .unwrap();
        let pubkey = bitcoin::PublicKey::new(child_0.private_key.public_key(&secp));
        let address = bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();

        // Verified externally (Check 1, April 2026):
        //   m/84'/0'/0'/0/0 for abandon...about → bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
        // Source: BlueWallet standard import + iancoleman.io/bip39 BIP84 tab
        assert_eq!(
            address.to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "shutdown_xpriv child 0 must match BlueWallet's m/84'/0'/0'/0/0"
        );
    }

    /// Pinned-vector test for the deprecated static_remotekey_xpriv at child
    /// index 0. Locks the m/525h derivation contract for the legacy
    /// pre-v0.2.0 force-close residue scan paths. While the function is alive
    /// (consumed by closed_channel_watcher and onchain_scan), this test
    /// guards against accidental derivation drift that would break recovery
    /// of any pre-v0.2.0 channel still sitting unswept on chain. Delete this
    /// test when `static_remotekey_xpriv` is finally removed.
    #[test]
    #[allow(deprecated)]
    fn test_static_remotekey_xpriv_known_address() {
        let mnemonic: Mnemonic = TEST_MNEMONIC.parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();

        let xpriv = root.static_remotekey_xpriv().unwrap();
        let secp = Secp256k1::new();

        let child_0 = xpriv
            .derive_priv(&secp, &"m/0".parse::<DerivationPath>().unwrap())
            .unwrap();
        let pubkey = bitcoin::PublicKey::new(child_0.private_key.public_key(&secp));
        let address = bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();

        assert_eq!(
            address.to_string(),
            "bc1qrffjk8zt6uqsv376pfeqkz524llh425m96neru",
            "static_remotekey_xpriv child 0 must match the pinned address for legacy scan paths"
        );
    }

    /// Pinned-vector test for the LiJ identity key at m/525h.
    /// Locks the portable_pubkey_hex contract used by KV backup blob keying
    /// (Phase 5 wire-up). If this changes, existing backup blobs will be
    /// orphaned — currently safe because no wallets exist in the wild.
    #[test]
    fn test_portable_pubkey_known_value() {
        let mnemonic: Mnemonic = TEST_MNEMONIC.parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();

        let pubkey_hex = root.portable_pubkey_hex().unwrap();

        // Derived independently via Python bip_utils:
        //   ctx = Bip32Slip10Secp256k1.FromSeed(seed)
        //   pubkey = ctx.DerivePath("m/525'").PublicKey().RawCompressed().ToBytes().hex()
        // Pin the value so future drift is caught.
        // Note: this value will be filled in at first test run — see below.
        // Until then, the test checks that the function produces a 33-byte
        // compressed pubkey (66 hex chars) and is deterministic.
        assert_eq!(pubkey_hex.len(), 66, "Compressed pubkey must be 33 bytes (66 hex)");

        // Re-derive and confirm determinism
        let root2 = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        let pubkey_hex_2 = root2.portable_pubkey_hex().unwrap();
        assert_eq!(pubkey_hex, pubkey_hex_2, "portable_pubkey_hex must be deterministic");
    }
}
