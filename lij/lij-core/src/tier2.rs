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
/// v284 (S50): silent-payment coins (BIP-352) — found by the scan, not by an index on a chain; the
/// coin's own `sp_tweak` (t_k) derives its script and its key. Spendable like chain 0/1.
pub const CHAIN_SP: u32 = 352;
/// v316 (S57, DP 2026-10-07 21:53 "Go on 1 & 2" — joinstr-fit-r5 step 1b): taproot coins at the wallet's own BIP86
/// addresses (bip86.rs), both of BIP86's branches, as every BIP86 wallet scans them: chain 86 = m/86'/{coin}'/0'/0/{i},
/// chain 87 = m/86'/{coin}'/0'/1/{i}. DP 23:10: a Mix exit takes the ordinary receive branch (/0) — "Leave it on the
/// main coin branch" — and is told apart by its mark (CoinMarks::mix_exits, in the backup blob), never by its branch;
/// /1 is taproot change, if the wallet ever makes any. Signed on the taproot key path like chain 352. v317 (DP 22:58
/// "Proceed with the scanner fix"): in the walk's net, TR_WIDTH_DIV-th of its width.
pub const CHAIN_BIP86: u32 = 86;
pub const CHAIN_BIP86_INTERNAL: u32 = 87;
/// v317: the m/86 branches are watched to net_width / TR_WIDTH_DIV (500 of 2,500): an exit per round, not a receive per
/// payment — and a taproot key costs about twice a P2WPKH one to derive.
pub const TR_WIDTH_DIV: u32 = 5;

/// v317: is this chain a BIP86 branch, and which (0 or 1)?
pub fn bip86_branch(chain: u32) -> Option<u32> {
    match chain {
        CHAIN_BIP86 => Some(0),
        CHAIN_BIP86_INTERNAL => Some(1),
        _ => None,
    }
}

/// v317: how deep a branch is watched for a net of `net_width`.
pub fn branch_width(chain: u32, net_width: u32) -> u32 {
    if bip86_branch(chain).is_some() { (net_width / TR_WIDTH_DIV).max(1) } else { net_width }
}

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
        // v317: the BIP86 branches (no frontier of their own here: a fixed window from 0)
        let secp = Secp256k1::new();
        for chain in [CHAIN_BIP86, CHAIN_BIP86_INTERNAL] {
            let parent = crate::bip86::branch_xpriv(root_key, bip86_branch(chain).unwrap_or(0))?;
            for index in 0..branch_width(chain, gap) {
                let spk = crate::bip86::spk_at(&secp, &parent, index, network)?;
                by_spk.insert(spk.to_bytes(), (chain, index));
                entries.push(MatchEntry { chain, index, script_pubkey: spk });
            }
        }
        Ok(Self { entries, by_spk })
    }

    /// scriptPubKey byte-slices for passing to the BIP158 matcher.
    /// v262 (DP's second dots read): the 7,500-key net took 1–2 s of unbroken CPU to derive
    /// on a phone, once per session, right at boot — the balance's waiting dots froze for
    /// exactly that long. This builds the same net in slices, yielding to the browser
    /// between them (no-op natively).
    pub async fn build_fixed_async(
        root_key: &RootKey,
        network: Network,
        width: u32,
    ) -> LijResult<Self> {
        let receive_parent = root_key.shutdown_xpriv()?;
        let change_parent = derive_child(&root_key.onchain_key()?, CHAIN_CHANGE)?;
        let legacy_parent = root_key.static_remotekey_xpriv()?;
        let plan = [
            (CHAIN_RECEIVE, &receive_parent),
            (CHAIN_CHANGE, &change_parent),
            (CHAIN_LEGACY, &legacy_parent),
        ];
        let cap = (width as usize) * 3;
        let mut entries = Vec::with_capacity(cap);
        let mut by_spk = HashMap::with_capacity(cap);
        let mut n: u32 = 0;
        for (chain, parent) in plan {
            for index in 0..width {
                let spk = derive_p2wpkh_spk(parent, index, network)?;
                by_spk.insert(spk.to_bytes(), (chain, index));
                entries.push(MatchEntry { chain, index, script_pubkey: spk });
                n += 1;
                if n % 128 == 0 { crate::tier2_sync::yield_now().await; }
            }
        }
        // v317: the BIP86 branches, each to width / TR_WIDTH_DIV, in the same slices
        let secp = Secp256k1::new();
        for chain in [CHAIN_BIP86, CHAIN_BIP86_INTERNAL] {
            let parent = crate::bip86::branch_xpriv(root_key, bip86_branch(chain).unwrap_or(0))?;
            for index in 0..branch_width(chain, width) {
                let spk = crate::bip86::spk_at(&secp, &parent, index, network)?;
                by_spk.insert(spk.to_bytes(), (chain, index));
                entries.push(MatchEntry { chain, index, script_pubkey: spk });
                n += 1;
                if n % 64 == 0 { crate::tier2_sync::yield_now().await; }
            }
        }
        Ok(Self { entries, by_spk })
    }

    /// v317: the BIP86 entries alone (the subset whose spends the witness cannot name).
    pub fn tr_entries(&self) -> impl Iterator<Item = &MatchEntry> {
        self.entries.iter().filter(|e| bip86_branch(e.chain).is_some())
    }
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
    let address = Address::p2wpkh(&bitcoin::CompressedPublicKey(pubkey.inner), network);
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

/// v317 (DP 22:58 "Proceed with the scanner fix"): which of the wallet's BIP86 scripts are in this block's filter. A
/// BIP158 basic filter holds every output script of the block AND the script of every output it spends, so a BIP86
/// script here that no output of the block pays was SPENT in this block — the only trace of a taproot key-path spend,
/// whose witness names no key. Tested only after the whole net matched: one pass over the BIP86 subset, then one per
/// script when that hits (rare — a block that pays or spends a Mix coin).
pub fn tr_hits(filter_content: &[u8], block_hash: &BlockHash, scripts: &WalletScripts) -> LijResult<Vec<(u32, u32)>> {
    let tr: Vec<&MatchEntry> = scripts.tr_entries().collect();
    if tr.is_empty() {
        return Ok(Vec::new());
    }
    let filter = BlockFilter::new(filter_content);
    let mut all = tr.iter().map(|e| e.script_pubkey.as_bytes());
    if !filter.match_any(block_hash, &mut all).map_err(|e| LijError::Node(format!("bip158 match: {e}")))? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for e in tr {
        let mut one = std::iter::once(e.script_pubkey.as_bytes());
        if filter.match_any(block_hash, &mut one).map_err(|e| LijError::Node(format!("bip158 match: {e}")))? {
            out.push((e.chain, e.index));
        }
    }
    Ok(out)
}

/// v287 (silent-payment receive): match a filter against an arbitrary script list — the block's
/// silent-payment candidates plus the scripts of the coins already found.
pub fn block_matches_scripts(
    filter_content: &[u8],
    block_hash: &BlockHash,
    scripts: &[bitcoin::ScriptBuf],
) -> LijResult<bool> {
    if scripts.is_empty() {
        return Ok(false);
    }
    let filter = BlockFilter::new(filter_content);
    let query: Vec<&[u8]> = scripts.iter().map(|s| s.as_bytes()).collect();
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
        assert_eq!(scripts.len(), (gap as usize) * 3 + 2 * (gap / TR_WIDTH_DIV) as usize);   // v317: + the two BIP86 branches
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

    #[test]
    fn v317_the_net_holds_both_bip86_branches_at_the_bip86_vectors() {
        let scripts = WalletScripts::build(&test_root(), Network::Bitcoin, DEFAULT_GAP).unwrap();
        // BIP86's own vectors: receive 0 and 1, change 0
        assert_eq!(scripts.owner_of(&spk_of("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")), Some((CHAIN_BIP86, 0)));
        assert_eq!(scripts.owner_of(&spk_of("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh")), Some((CHAIN_BIP86, 1)));
        assert_eq!(scripts.owner_of(&spk_of("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")), Some((CHAIN_BIP86_INTERNAL, 0)));
        assert_eq!(scripts.tr_entries().count(), 2 * (DEFAULT_GAP / TR_WIDTH_DIV) as usize);
        assert_eq!(branch_width(CHAIN_BIP86, 2500), 500);
        assert_eq!(branch_width(CHAIN_RECEIVE, 2500), 2500);
    }

    #[test]
    fn v317_tr_hits_names_the_bip86_scripts_in_a_filter() {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, Block, OutPoint, Transaction, TxIn, TxOut, Witness, Sequence, CompactTarget, TxMerkleNode};
        use bitcoin::block::{Header, Version as BV};
        use bitcoin::hashes::Hash;
        let scripts = WalletScripts::build(&test_root(), Network::Bitcoin, DEFAULT_GAP).unwrap();
        let tr1 = spk_of("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh");
        let stranger = spk_of("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
        // one transaction spends a coin whose script is our m/86 receive 1 and pays a stranger
        let tx = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([7u8; 32]), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::from_slice(&[[1u8; 64].to_vec()]) }],
            output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: stranger }],
        };
        let block = Block {
            header: Header { version: BV::TWO, prev_blockhash: BlockHash::all_zeros(), merkle_root: TxMerkleNode::all_zeros(), time: 0, bits: CompactTarget::from_consensus(0x207fffff), nonce: 0 },
            // the first transaction is the coinbase, whose input BIP158 leaves out
            txdata: vec![Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }], output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new_op_return([]) }] }, tx],
        };
        let filter = BlockFilter::new_script_filter(&block, |op| {
            assert_eq!(op.vout, 0);
            Ok(tr1.clone())
        }).unwrap();
        let bh = block.block_hash();
        assert!(block_matches(&filter.content, &bh, &scripts).unwrap(), "the spent script is in the filter");
        assert_eq!(tr_hits(&filter.content, &bh, &scripts).unwrap(), vec![(CHAIN_BIP86, 1)], "and it is named");
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
