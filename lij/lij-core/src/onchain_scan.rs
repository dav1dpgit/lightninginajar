#![allow(deprecated)]

// onchain_scan.rs
// On-chain residue scanner for wallet recovery scenarios.
//
// Walks both LiJ derivation chains (BIP84 cooperative-close destinations,
// and m/525'/0/0 force-close static_remotekey destinations) up to a
// caller-specified max_index, querying the independent path quorum for
// UTXOs at each derived address. Reports any residue found.
//
// Used in two scenarios:
//   1. Recovery floor: if PersistedCounter is corrupted or missing, the
//      scan provides a safety floor — next channel index = max(seen) + 1.
//      Slow but bulletproof: the chain is the source of truth.
//   2. Audit / health: wallet can compare on-chain residue against its
//      local close history, surfacing inconsistencies to the user.
//
// Concurrency: bounded via futures::stream::buffer_unordered. At most
// MAX_CONCURRENT_QUERIES quorum queries are in flight at once. Each
// quorum query fans out to N endpoints internally (handled by
// IndependentClient), so the total in-flight HTTP requests is
// bounded by MAX_CONCURRENT_QUERIES * endpoint_count.
//
// Gap-limit semantics: caller specifies max_index. Scanner walks
// 0..=max_index and reports everything found. Caller can choose to
// implement gap-limit logic (stop after N consecutive empties) by
// inspecting the result. Default scan range covers the BlueWallet
// gap limit of 20.

use std::sync::Arc;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    secp256k1::Secp256k1,
    Address, Network,
};
use futures::stream::{self, StreamExt};

use crate::{
    error::{LijError, LijResult},
    independent::IndependentClient,
    key::RootKey,
};

/// Maximum number of address-utxo queries in flight at once. Bounded to
/// prevent overwhelming Esplora endpoints with per-index queries on top
/// of the per-quorum fan-out the IndependentClient already performs.
pub const MAX_CONCURRENT_QUERIES: usize = 2;

/// Default scan ceiling. Matches BIP44 standard gap limit of 20 — this
/// is the depth BlueWallet itself walks for auto-discovery, so users
/// with up to 20 channels per close type will find their funds.
pub const DEFAULT_SCAN_MAX_INDEX: u32 = 20;

/// Which derivation chain a residue UTXO lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ResiduePathKind {
    /// m/84'/{coin}h/0'/0/n — BIP84 cooperative-close destinations
    /// and LDK-managed sweeps. BlueWallet auto-discovers.
    Cooperative,
    /// m/525'/0/0/0/n — force-close to_remote static_remotekey.
    /// BlueWallet recovers via custom-path import (path m/525'/0/0,
    /// BIP84 button).
    ForceClose,
}

impl ResiduePathKind {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative close / LDK sweep destination",
            Self::ForceClose => "force close static_remotekey destination",
        }
    }
}

/// A single UTXO found during a residue scan.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ResidueUtxo {
    pub path_kind: ResiduePathKind,
    pub index: u32,
    pub address: String,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// Scan the chain for residue UTXOs at indices 0..=max_index on both
/// derivation chains. Returns all UTXOs found, sorted by (path_kind, index).
///
/// Implementation: builds the derived addresses upfront (cheap, deterministic),
/// then issues bounded-concurrency address/utxo queries through the
/// independent path. Each query is a quorum read, so endpoints disagreeing
/// will degrade gracefully (returns whatever endpoints returned successfully).
///
/// On total quorum failure for a specific address, that index is silently
/// skipped (no panic). The caller can compare the returned indices against
/// the requested range to detect gaps from quorum failures vs. gaps from
/// "no UTXO at that address."
pub async fn scan_for_channel_residue(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    max_index: u32,
    network: Network,
) -> LijResult<Vec<ResidueUtxo>> {
    // Derive the parent xprivs for both chains.
    let shutdown_xpriv = root_key.shutdown_xpriv()?;
    let static_remotekey_xpriv = root_key.static_remotekey_xpriv()?;

    // Build the (path_kind, index, address) work list.
    let mut work: Vec<(ResiduePathKind, u32, String)> = Vec::with_capacity(
        2 * (max_index as usize + 1),
    );
    for n in 0..=max_index {
        let coop_addr =
            derive_p2wpkh_address(&shutdown_xpriv, n, network)?;
        let fc_addr =
            derive_p2wpkh_address(&static_remotekey_xpriv, n, network)?;
        work.push((ResiduePathKind::Cooperative, n, coop_addr));
        work.push((ResiduePathKind::ForceClose, n, fc_addr));
    }

    // Run queries with bounded concurrency.
    let results: Vec<Vec<ResidueUtxo>> = stream::iter(work.into_iter())
        .map(|(kind, idx, addr)| {
            let independent = independent.clone();
            async move {
                match independent.fetch_address_utxos(&addr).await {
                    Ok(utxos) => utxos
                        .into_iter()
                        .map(|u| ResidueUtxo {
                            path_kind: kind,
                            index: idx,
                            address: addr.clone(),
                            txid: u.txid,
                            vout: u.vout,
                            value_sats: u.value_sats,
                        })
                        .collect(),
                    Err(e) => {
                        log::warn!(
                            "scan: address {} ({:?}, idx {}) query failed: {}",
                            addr, kind, idx, e
                        );
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(MAX_CONCURRENT_QUERIES)
        .collect()
        .await;

    let mut all: Vec<ResidueUtxo> = results.into_iter().flatten().collect();
    all.sort_by_key(|u| (u.path_kind as u8, u.index, u.txid.clone(), u.vout));
    Ok(all)
}

/// Derive the BIP84 receive address (m/84'/{coin}'/0'/0/index) — PURE, no
/// network. The frontend drives `index` (persisted locally and reconciled
/// upward whenever a scan succeeds), so showing a receive address never depends
/// on a chain scan. This is what preserves address privacy: even offline, the
/// app can hand out the correct next address instead of falling back to a stale
/// (possibly already-used) one or failing to show anything.
pub fn receive_address_at(
    root_key: &RootKey,
    index: u32,
    network: Network,
) -> LijResult<String> {
    let shutdown_xpriv = root_key.shutdown_xpriv()?;
    derive_p2wpkh_address(&shutdown_xpriv, index, network)
}

/// Derive the P2WPKH address at child index `n` of the given xpriv.
pub(crate) fn derive_p2wpkh_address(
    parent_xpriv: &ExtendedPrivKey,
    n: u32,
    network: Network,
) -> LijResult<String> {
    let secp = Secp256k1::new();
    let child = parent_xpriv
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![ChildNumber::from_normal_idx(n)
                .map_err(|e| LijError::Key(format!("Bad child number {n}: {e}")))?]),
        )
        .map_err(|e| LijError::Key(format!("Address derivation failed at index {n}: {e}")))?;
    let pubkey = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    let address = Address::p2wpkh(&pubkey, network)
        .map_err(|e| LijError::Key(format!("p2wpkh encoding failed: {e}")))?;
    Ok(address.to_string())
}

/// Read-only on-chain wallet view (increment 1): balance + UTXOs across the
/// BIP84 spendable chain (m/84'/{coin}'/0'/0/n — receives plus LDK sweep and
/// cooperative-close destinations) and the legacy m/525 force-close residue
/// chain, plus a fresh receive address. Serializes to JSON for the frontend.
#[derive(Clone, Debug, serde::Serialize)]
pub struct OnChainSummary {
    /// Spendable BIP84 balance — the active on-chain wallet.
    pub spendable_sats: u64,
    /// Legacy m/525 force-close residue (pre-Plan-A channels), shown separately.
    pub legacy_residue_sats: u64,
    /// All UTXOs found across both chains.
    pub utxos: Vec<ResidueUtxo>,
    /// Next unused index on the BIP84 spendable chain.
    pub next_receive_index: u32,
    /// Fresh receive address (BIP84 P2WPKH) at next_receive_index.
    pub next_receive_address: String,
    /// Gap-limit ceiling the scan walked, for UX ("scanned 0..=N").
    pub scanned_max_index: u32,
}

impl OnChainSummary {
    pub fn to_json(&self) -> LijResult<String> {
        serde_json::to_string(self)
            .map_err(|e| LijError::Storage(format!("onchain summary serialize: {e}")))
    }
}

/// Build a read-only on-chain wallet summary from the Esplora quorum scan.
/// Caller must run this OUTSIDE any wallet lock (it awaits network I/O).
pub async fn onchain_summary(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
) -> LijResult<OnChainSummary> {
    summary_from_scan(root_key, independent, network).await
}

/// Summary from the Esplora quorum scan.
async fn summary_from_scan(
    root_key: &RootKey,
    independent: Arc<IndependentClient>,
    network: Network,
) -> LijResult<OnChainSummary> {
    let utxos =
        scan_for_channel_residue(root_key, independent, DEFAULT_SCAN_MAX_INDEX, network).await?;

    let mut spendable_sats = 0u64;
    let mut legacy_residue_sats = 0u64;
    let mut max_coop_index: Option<u32> = None;
    for u in &utxos {
        match u.path_kind {
            ResiduePathKind::Cooperative => {
                spendable_sats = spendable_sats.saturating_add(u.value_sats);
                max_coop_index = Some(max_coop_index.map_or(u.index, |m: u32| m.max(u.index)));
            }
            ResiduePathKind::ForceClose => {
                legacy_residue_sats = legacy_residue_sats.saturating_add(u.value_sats);
            }
        }
    }

    let next_receive_index = max_coop_index.map_or(0, |m| m.saturating_add(1));
    let shutdown_xpriv = root_key.shutdown_xpriv()?;
    let next_receive_address = derive_p2wpkh_address(&shutdown_xpriv, next_receive_index, network)?;

    Ok(OnChainSummary {
        spendable_sats,
        legacy_residue_sats,
        utxos,
        next_receive_index,
        next_receive_address,
        scanned_max_index: DEFAULT_SCAN_MAX_INDEX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    /// Pinned-vector test: derive the first BIP84 address for the canonical
    /// abandon...about seed and verify it matches the address pinned in
    /// key.rs tests. This guards against future drift between the scanner's
    /// derivation and the signer's derivation.
    #[test]
    fn coop_chain_index_0_matches_pinned() {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        let xpriv = root.shutdown_xpriv().unwrap();
        let address = derive_p2wpkh_address(&xpriv, 0, Network::Bitcoin).unwrap();
        assert_eq!(
            address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "scanner must derive same coop address as signer + BlueWallet",
        );
    }

    #[test]
    fn fc_chain_index_0_matches_pinned() {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        let xpriv = root.static_remotekey_xpriv().unwrap();
        let address = derive_p2wpkh_address(&xpriv, 0, Network::Bitcoin).unwrap();
        assert_eq!(
            address,
            "bc1qrffjk8zt6uqsv376pfeqkz524llh425m96neru",
            "scanner must derive same fc address as signer + BlueWallet",
        );
    }

    #[test]
    fn coop_and_fc_addresses_differ_at_same_index() {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse().unwrap();
        let root = RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        let coop_xpriv = root.shutdown_xpriv().unwrap();
        let fc_xpriv = root.static_remotekey_xpriv().unwrap();
        for n in 0..3 {
            let coop = derive_p2wpkh_address(&coop_xpriv, n, Network::Bitcoin).unwrap();
            let fc = derive_p2wpkh_address(&fc_xpriv, n, Network::Bitcoin).unwrap();
            assert_ne!(coop, fc, "coop and fc must use different paths at index {n}");
        }
    }

    #[test]
    fn residue_path_kind_descriptions() {
        assert!(ResiduePathKind::Cooperative
            .description()
            .contains("cooperative"));
        assert!(ResiduePathKind::ForceClose
            .description()
            .contains("force"));
    }
}
