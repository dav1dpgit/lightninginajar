#![allow(deprecated)]

// tier2.rs
// Tier 2 (privacy-default) on-chain backend: client-side BIP158 compact
// block-filter matching.
//
// Architecture role:
//   The node serves the SAME compact filters / headers / blocks to every
//   client (global chain data, never a per-user query), so it cannot learn
//   which scripts belong to whom. The client downloads filters from its
//   birthday height, tests each against its own scriptPubKey set LOCALLY
//   (GCS match), and only fetches the full blocks that match. The node
//   reveals nothing about the user's wallet — the privacy property of Tier 2.
//
// This module is the FOUNDATION (increment 1). It builds the wallet's match
// set (the scriptPubKeys to test filters against) and wraps the BIP158 match.
// Layered on top in later increments (see the phase plan):
//   - sync loop: walk filters from birthday -> tip, collect matching heights
//   - header chain + BIP157 filter-header validation (anti-omission hardening)
//   - block fetch + tx extraction -> UTXO set + history assembly
//   - reorg handling + incremental catch-up + persistence
//   - WASM bindings + frontend swap (replace the Esplora on-chain path)
//
// Crypto note: GCS decode/match is rust-bitcoin's vetted `bitcoin::bip158`
// implementation — we do NOT hand-roll Golomb-Rice. Our job is correct
// invocation and correct script derivation, both covered by the tests below.
// Run `cargo test -p lij-core` to verify before any WASM build.

use std::collections::HashMap;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    bip158::BlockFilter,
    secp256k1::Secp256k1,
    Address, BlockHash, Network, ScriptBuf,
};

use crate::{
    error::{LijError, LijResult},
    key::RootKey,
};

/// Default look-ahead per chain. Addresses are handed out sequentially, so a
/// modest gap covers normal use; the sync increment can widen it when a match
/// lands near the ceiling.
pub const DEFAULT_GAP: u32 = 50;

/// Derivation chain identifiers, matching the rest of the on-chain code:
/// 0 = BIP84 receive, 1 = BIP84 change, 525 = legacy force-close residue.
pub const CHAIN_RECEIVE: u32 = 0;
pub const CHAIN_CHANGE: u32 = 1;
pub const CHAIN_LEGACY: u32 = 525;

/// One scriptPubKey we watch, tagged with the (chain, index) needed to derive
/// its signing key later.
#[derive(Clone, Debug)]
pub struct MatchEntry {
    pub chain: u32,
    pub index: u32,
    pub script_pubkey: ScriptBuf,
}

/// The wallet's full match set: every scriptPubKey we test compact filters
/// against, plus a reverse index from scriptPubKey -> (chain, index) so a
/// block hit tells us exactly which key owns the output.
#[derive(Clone, Debug, Default)]
pub struct WalletScripts {
    pub entries: Vec<MatchEntry>,
    by_spk: HashMap<Vec<u8>, (u32, u32)>,
}

impl WalletScripts {
    /// Build the match set for receive (0), change (1), and legacy (525)
    /// chains, each over index 0..gap.
    pub fn build(root_key: &RootKey, network: Network, gap: u32) -> LijResult<Self> {
        // Fixed window 0..gap for every chain (frontier = 0). Kept for tests and
        // callers that don't need the sliding behavior.
        Self::build_sliding(root_key, network, gap, 0, 0, 0)
    }

    /// Like `build`, but each chain's window SLIDES: it covers 0..(frontier + gap),
    /// where `frontier` is that chain's next-unused index. Recomputed from the
    /// view + pending every sync, the window always keeps `gap` fresh addresses
    /// ahead of the highest used one — so receive/change rotation can run
    /// indefinitely without outrunning address discovery.
    pub fn build_sliding(
        root_key: &RootKey,
        network: Network,
        gap: u32,
        frontier_receive: u32,
        frontier_change: u32,
        frontier_legacy: u32,
    ) -> LijResult<Self> {
        let receive_parent = root_key.shutdown_xpriv()?; // m/84'/{coin}'/0'/0
        let change_parent = derive_child(&root_key.onchain_key()?, CHAIN_CHANGE)?; // m/84'/{coin}'/0'/1
        let legacy_parent = root_key.static_remotekey_xpriv()?; // m/525'/0/0/0

        let plan = [
            (CHAIN_RECEIVE, &receive_parent, frontier_receive.saturating_add(gap)),
            (CHAIN_CHANGE, &change_parent, frontier_change.saturating_add(gap)),
            (CHAIN_LEGACY, &legacy_parent, frontier_legacy.saturating_add(gap)),
        ];
        let cap: usize = plan.iter().map(|(_, _, end)| *end as usize).sum();
        let mut entries = Vec::with_capacity(cap);
        let mut by_spk = HashMap::with_capacity(cap);
        for (chain, parent, end) in plan {
            for index in 0..end {
                let spk = derive_p2wpkh_spk(parent, index, network)?;
                by_spk.insert(spk.to_bytes(), (chain, index));
                entries.push(MatchEntry {
                    chain,
                    index,
                    script_pubkey: spk,
                });
            }
        }
        Ok(Self { entries, by_spk })
    }

    /// scriptPubKey byte-slices for passing to the BIP158 matcher.
    pub fn query_bytes(&self) -> Vec<&[u8]> {
        self.entries
            .iter()
            .map(|e| e.script_pubkey.as_bytes())
            .collect()
    }

    /// Reverse lookup: which (chain, index) owns this scriptPubKey, if any.
    pub fn owner_of(&self, script_pubkey: &ScriptBuf) -> Option<(u32, u32)> {
        self.by_spk.get(&script_pubkey.to_bytes()).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Derive the immediate child xpriv at a normal (non-hardened) index.
fn derive_child(parent: &ExtendedPrivKey, index: u32) -> LijResult<ExtendedPrivKey> {
    let secp = Secp256k1::new();
    parent
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
                .map_err(|e| LijError::Key(format!("bad child index {index}: {e}")))?]),
        )
        .map_err(|e| LijError::Key(format!("child derivation at {index}: {e}")))
}

/// Derive the P2WPKH scriptPubKey at child index `n` of `parent`. Mirrors
/// onchain_scan::derive_p2wpkh_address but returns the scriptPubKey we match
/// compact filters against.
fn derive_p2wpkh_spk(parent: &ExtendedPrivKey, n: u32, network: Network) -> LijResult<ScriptBuf> {
    let secp = Secp256k1::new();
    let child = derive_child(parent, n)?;
    let pubkey = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    let address = Address::p2wpkh(&pubkey, network)
        .map_err(|e| LijError::Key(format!("p2wpkh encode at {n}: {e}")))?;
    Ok(address.script_pubkey())
}

/// Does this block's compact filter match any of the wallet's scripts? `true`
/// means "fetch this block and inspect it"; `false` means "provably skip it"
/// — the privacy + bandwidth win, since we only download blocks that touch us.
///
/// `filter_content` is the BIP158 basic filter bytes for the block (as served
/// by the node). GCS matching is rust-bitcoin's vetted implementation.
pub fn block_matches(
    filter_content: &[u8],
    block_hash: &BlockHash,
    scripts: &WalletScripts,
) -> LijResult<bool> {
    if scripts.is_empty() {
        return Ok(false);
    }
    let filter = BlockFilter::new(filter_content);
    let query = scripts.query_bytes();
    filter
        .match_any(block_hash, &mut query.iter().copied())
        .map_err(|e| LijError::Node(format!("bip158 match: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use std::str::FromStr;

    fn test_root() -> RootKey {
        let mnemonic: Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .parse().unwrap();
        RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap()
    }

    fn spk_of(addr: &str) -> ScriptBuf {
        Address::from_str(addr)
            .unwrap()
            .assume_checked()
            .script_pubkey()
    }

    /// The match set must derive the SAME addresses the signer/scanner use.
    /// These two pinned values are the canonical abandon...about vectors that
    /// onchain_scan and key.rs already assert against — guarding against drift.
    #[test]
    fn match_set_derivation_matches_pinned_addresses() {
        let scripts = WalletScripts::build(&test_root(), Network::Bitcoin, DEFAULT_GAP).unwrap();
        // receive (chain 0) index 0 == coop pinned address
        assert_eq!(
            scripts.owner_of(&spk_of("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")),
            Some((CHAIN_RECEIVE, 0)),
        );
        // legacy (chain 525) index 0 == fc pinned address
        assert_eq!(
            scripts.owner_of(&spk_of("bc1qrffjk8zt6uqsv376pfeqkz524llh425m96neru")),
            Some((CHAIN_LEGACY, 0)),
        );
    }

    #[test]
    fn match_set_covers_all_three_chains_and_round_trips() {
        let gap = 10;
        let scripts = WalletScripts::build(&test_root(), Network::Bitcoin, gap).unwrap();
        assert_eq!(scripts.len(), (gap as usize) * 3);
        for e in &scripts.entries {
            assert_eq!(scripts.owner_of(&e.script_pubkey), Some((e.chain, e.index)));
        }
    }

    #[test]
    fn change_chain_does_not_collide_with_receive() {
        let scripts = WalletScripts::build(&test_root(), Network::Bitcoin, 5).unwrap();
        let recv: Vec<_> = scripts
            .entries
            .iter()
            .filter(|e| e.chain == CHAIN_RECEIVE)
            .map(|e| e.script_pubkey.clone())
            .collect();
        for c in scripts.entries.iter().filter(|e| e.chain == CHAIN_CHANGE) {
            assert!(
                !recv.contains(&c.script_pubkey),
                "change spk collided with a receive spk at index {}",
                c.index
            );
        }
    }

    /// Empty set never matches (guards the sync loop's pre-birthday window).
    #[test]
    fn empty_scripts_never_match() {
        let scripts = WalletScripts::default();
        let zero = BlockHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(block_matches(&[0u8], &zero, &scripts).unwrap(), false);
    }
}
