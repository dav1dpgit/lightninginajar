//! The wallet's own pieces of a Mix (step 7, slice 2 — S58; tatara-rollout-r3 step 7; spec v0.10 §5.2, §5.3, §8 rules 1
//! and 4, §9 rule 7; DP 2026-10-12 23:21).
//!
//! - The payout: the wallet's next m/86 receive address, marked a Mix exit when it is handed out and always inside the
//!   net a restore from the 12 words alone watches (§5.2); or — room for later, DP 23:21 "make sure we make space for
//!   it" — another wallet's taproot address.
//! - The change: the next m/84 change address, marked so no later send's change reuses an address the pool's other
//!   members have seen (§5.3, §8 rule 1).
//! - The coins: their keys as joinstr v2 takes them.
//! - The coin lock after a restore: kept only on a coin an unsettled attempt record names (§9 rule 7).
//!
//! Pure: the caller loads and saves the marks (CoinMarks rides the backup blob, sealed).

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
use serde::{Deserialize, Serialize};

use crate::error::{LijError, LijResult};
use crate::key::RootKey;
use crate::tier2::{bip86_branch, branch_width, CHAIN_BIP86, CHAIN_CHANGE, CHAIN_RECEIVE, TR_WIDTH_DIV};
use crate::tier2_wallet::{next_change_index_marked, next_tr_receive_index, CoinMarks, OnchainUtxo, PendingTx, Tier2View, NET_WIDEN_MARGIN, NET_WIDTH};

/// The highest m/86 receive index a Mix hands out as a payout: inside the net a restore from the 12 words alone watches
/// on that branch (tier2::branch_width at NET_WIDTH: 500) less that branch's widen margin (20). So every payout is found
/// by any restore, whatever happened to the payouts before it — a stopped attempt's address is never paid and never
/// handed out again (§8 rule 1). 480 addresses: about 160 pools of three tries each in one wallet's life.
pub fn payout_index_max() -> u32 {
    let w = branch_width(CHAIN_BIP86, NET_WIDTH);
    let margin = (NET_WIDEN_MARGIN / TR_WIDTH_DIV).max(1);
    w.saturating_sub(margin).saturating_sub(1)
}

/// Where a pool's payout goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "to", rename_all = "snake_case")]
pub enum PayoutChoice {
    /// The wallet's own next m/86 receive address, marked Mixed (v0.10 §5.2).
    ThisWallet,
    /// Another wallet's taproot address (DP 23:21; the screen is Phase 2 or late 1a — his call; the engine takes it now).
    /// The coin is the recipient's once the exit confirms: no Mixed mark here, and a restore of this wallet does not find
    /// it.
    Outside { address: String },
}

/// A payout, ready for the attempt (machine::MyPart::payout is `script`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub script: ScriptBuf,
    pub address: String,
    /// The m/86 receive index (this wallet's payout); None for another wallet's.
    pub index: Option<u32>,
}

/// The payout for a new attempt — a new one every attempt (§8 rule 0 and 1: a retry gets a new address too).
pub fn payout_for(root: &RootKey, view: &Tier2View, marks: &mut CoinMarks, choice: &PayoutChoice) -> LijResult<Payout> {
    match choice {
        PayoutChoice::ThisWallet => next_payout(root, view, marks),
        PayoutChoice::Outside { address } => outside_payout(root, view, marks, address),
    }
}

/// This wallet's next m/86 receive address, marked a Mix exit at once (CoinMarks::mix_exits — before any coin exists,
/// so a stopped attempt's address counts as used and stays watched).
pub fn next_payout(root: &RootKey, view: &Tier2View, marks: &mut CoinMarks) -> LijResult<Payout> {
    let i = next_tr_receive_index(view, marks);
    if i > payout_index_max() {
        return Err(LijError::Node(format!(
            "this wallet has used the {} Mix addresses a restore from its 12 words is sure to find — it cannot take another pool's payout",
            payout_index_max() + 1
        )));
    }
    let (addr, _) = crate::bip86::address_at(root, CHAIN_RECEIVE, i)?;
    marks.mix_exits.insert(i);
    Ok(Payout { script: addr.script_pubkey(), address: addr.to_string(), index: Some(i) })
}

/// Another wallet's address as a payout: a taproot address (bc1p…: witness v1, 32 bytes) on this wallet's network —
/// every payout in an on-chain pool is P2TR (§5.4), so none stands out — and not one of this wallet's own m/86 receive
/// addresses (that is "This wallet", which also marks the coin Mixed and never hands an address out twice).
pub fn outside_payout(root: &RootKey, view: &Tier2View, marks: &CoinMarks, address: &str) -> LijResult<Payout> {
    let network = root.network;
    let unchecked = Address::from_str(address.trim()).map_err(|_| LijError::Node("that is not a bitcoin address".into()))?;
    let addr = unchecked
        .require_network(network)
        .map_err(|_| LijError::Node("that address is for another bitcoin network".into()))?;
    let spk = addr.script_pubkey();
    if !spk.is_p2tr() {
        return Err(LijError::Node(
            "a Mix payout must be a taproot address (bc1p…) — every payout in a pool is the same kind, so none stands out".into(),
        ));
    }
    let secp = Secp256k1::new();
    let parent = crate::bip86::branch_xpriv(root, 0)?;
    let upto = next_tr_receive_index(view, marks).min(payout_index_max() + 1);
    for i in 0..upto {
        if crate::bip86::spk_at(&secp, &parent, i, network)? == spk {
            return Err(LijError::Node("that is one of this wallet's own addresses — choose This wallet instead".into()));
        }
    }
    Ok(Payout { script: spk, address: addr.to_string(), index: None })
}

/// The next m/84 change address for a pool's funding, marked at once (CoinMarks::mix_change): a later send's change
/// never takes it, even when the pool stopped and the address never reached the chain (§5.3, §8 rule 1).
pub fn next_change(root: &RootKey, view: &Tier2View, pending: &[PendingTx], marks: &mut CoinMarks) -> LijResult<(u32, ScriptBuf)> {
    let c = next_change_index_marked(view, pending, marks);
    let spk = crate::onchain_send::change_script(root, &Secp256k1::new(), root.network, c)?;
    marks.mix_change.insert(c);
    Ok((c, spk))
}

/// Can this coin go into a pool? An unspent m/84 coin (P2WPKH) or a coin at a BIP86 address (P2TR — a mixed coin may
/// be mixed again). A silent-payment coin cannot: its output key carries no BIP86 tweak, and joinstr v2's proof and
/// signature tweak every taproot key. Legacy m/525 residue never.
pub fn pool_coin(u: &OnchainUtxo) -> bool {
    u.spent_height.is_none() && (u.chain == CHAIN_RECEIVE || u.chain == CHAIN_CHANGE || bip86_branch(u.chain).is_some())
}

/// The coin as joinstr v2 takes it (machine::MyPart::coins): its outpoint, its output and its key — an m/84 coin's
/// P2WPKH secret, or a BIP86 coin's INTERNAL (untweaked) secret, since joinstr applies the BIP341 tweak itself.
pub fn coin_for_pool(root: &RootKey, u: &OnchainUtxo) -> LijResult<(OutPoint, TxOut, SecretKey)> {
    if !pool_coin(u) {
        return Err(LijError::Node("this coin cannot go into a pool (spent, a silent-payment coin, or legacy)".into()));
    }
    let secp = Secp256k1::new();
    let (sk, spk) = match bip86_branch(u.chain) {
        Some(branch) => crate::bip86::internal_secret_and_script(root, branch, u.index)?,
        None => {
            let sk = crate::onchain_send::signing_secret(root, &secp, u.chain, u.index)?;
            let pk = bitcoin::CompressedPublicKey(sk.public_key(&secp));
            (sk, ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()))
        }
    };
    let txid = Txid::from_str(&u.txid).map_err(|e| LijError::Node(format!("coin txid: {e}")))?;
    Ok((OutPoint { txid, vout: u.vout }, TxOut { value: Amount::from_sat(u.value_sats), script_pubkey: spk }, sk))
}

/// §9 rule 7: the Mix's holds are exactly the coins a seat on this phone or an unsettled attempt record names (`keep`:
/// records::held_inputs and the seats' coins). After a copy is restored the waiting list is gone (a seat lives on its own
/// phone only), so its holds go; a record that came with the copy keeps — or gets back — its hold. Also run at start, so
/// a hold can never outlive the seat or the record behind it. Returns (freed, added).
pub fn reconcile_locks(marks: &mut CoinMarks, keep: &HashSet<(String, u32)>, now_ms: u64) -> (Vec<(String, u32)>, Vec<(String, u32)>) {
    let have = marks.mix_locked_set();
    let mut freed: Vec<(String, u32)> = have.iter().filter(|k| !keep.contains(*k)).cloned().collect();
    let mut added: Vec<(String, u32)> = keep.iter().filter(|k| !have.contains(*k)).cloned().collect();
    freed.sort();
    added.sort();
    marks.mix_unlock(&freed);
    marks.mix_lock(&added, now_ms);
    (freed, added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use joinstr_v2::funding::{ownership_msg, prove, verify_proof};

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn root() -> RootKey {
        RootKey::from_mnemonic(&Mnemonic::from_str(WORDS).unwrap(), Network::Bitcoin).unwrap()
    }

    fn utxo(chain: u32, index: u32, value: u64) -> OnchainUtxo {
        OnchainUtxo { chain, index, txid: "ab".repeat(32), vout: 1, value_sats: value, height: 900_000, spent_height: None, spent_txid: None, sp_tweak: None, sp_label: None }
    }

    #[test]
    fn w1_the_payout_window_is_the_restore_net_less_its_margin() {
        assert_eq!(payout_index_max(), 479);
        assert!(payout_index_max() < branch_width(CHAIN_BIP86, NET_WIDTH), "inside what a words-only restore watches");
    }

    #[test]
    fn w2_this_wallets_payout_is_the_next_m86_address_marked_at_once_and_never_twice() {
        let r = root();
        let view = Tier2View::default();
        let mut marks = CoinMarks::default();
        let p0 = payout_for(&r, &view, &mut marks, &PayoutChoice::ThisWallet).unwrap();
        // BIP86's own first vector for these words
        assert_eq!(p0.address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        assert_eq!(p0.index, Some(0));
        assert!(marks.mix_exits.contains(&0), "marked when handed out, before any coin");
        let p1 = next_payout(&r, &view, &mut marks).unwrap();
        assert_eq!((p1.index, p1.address.as_str()), (Some(1), "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"));
        // a coin seen further on moves it past that too
        let mut view2 = Tier2View::default();
        view2.utxos.push(utxo(CHAIN_BIP86, 6, 1_000));
        assert_eq!(next_payout(&r, &view2, &mut marks).unwrap().index, Some(7));
        // past the window: refused in plain words
        marks.mix_exits.insert(payout_index_max());
        let e = next_payout(&r, &view, &mut marks).unwrap_err().to_string();
        assert!(e.contains("480 Mix addresses"), "{e}");
    }

    #[test]
    fn w3_another_wallets_payout_must_be_taproot_on_this_network_and_not_ours() {
        let r = root();
        let view = Tier2View::default();
        let mut marks = CoinMarks::default();
        // another wallet's BIP86 address
        let (other, _) = RootKey::generate(Network::Bitcoin).unwrap();
        let (theirs, _) = crate::bip86::address_at(&other, 0, 0).unwrap();
        let p = payout_for(&r, &view, &mut marks, &PayoutChoice::Outside { address: format!("  {theirs} ") }).unwrap();
        assert_eq!((p.index, p.script.clone()), (None, theirs.script_pubkey()));
        assert!(marks.mix_exits.is_empty(), "no Mixed mark: the coin is not this wallet's");
        let refuse = |a: &str, marks: &mut CoinMarks| payout_for(&r, &view, marks, &PayoutChoice::Outside { address: a.into() }).unwrap_err().to_string();
        // P2WPKH: one of BIP84's vectors
        assert!(refuse("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", &mut marks).contains("taproot"));
        // a testnet taproot address on a mainnet wallet
        let (tn, _) = crate::bip86::address_at(&RootKey::generate(Network::Testnet).unwrap().0, 0, 0).unwrap();
        assert!(refuse(&tn.to_string(), &mut marks).contains("another bitcoin network"));
        assert!(refuse("not an address", &mut marks).contains("not a bitcoin address"));
        assert!(refuse("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv", &mut marks).contains("not a bitcoin address"));
        // this wallet's own m/86 address, once handed out
        let mine = next_payout(&r, &view, &mut marks).unwrap();
        assert!(refuse(&mine.address, &mut marks).contains("this wallet's own"));
    }

    #[test]
    fn w4_the_pools_change_is_marked_so_no_send_reuses_it() {
        let r = root();
        let view = Tier2View::default();
        let mut marks = CoinMarks::default();
        let (c0, spk0) = next_change(&r, &view, &[], &mut marks).unwrap();
        assert_eq!(c0, 0);
        assert_eq!(spk0, crate::onchain_send::change_script(&r, &Secp256k1::new(), Network::Bitcoin, 0).unwrap());
        assert_eq!(crate::tier2_wallet::next_change_index(&view, &[]), 0, "the plain rule does not know the pool's");
        assert_eq!(next_change_index_marked(&view, &[], &marks), 1, "the marked rule does");
        let (c1, _) = next_change(&r, &view, &[], &mut marks).unwrap();
        assert_eq!(c1, 1, "a retry gets a new change address too");
        let mut view2 = Tier2View::default();
        view2.utxos.push(utxo(CHAIN_CHANGE, 9, 5_000));
        assert_eq!(next_change(&r, &view2, &[], &mut marks).unwrap().0, 10);
    }

    #[test]
    fn w5_a_coins_key_proves_ownership_through_joinstr_for_m84_and_m86_and_a_silent_payment_coin_stays_out() {
        let r = root();
        let session = [5u8; 32];
        for (chain, index) in [(CHAIN_RECEIVE, 3), (CHAIN_CHANGE, 2), (CHAIN_BIP86, 1), (crate::tier2::CHAIN_BIP86_INTERNAL, 0)] {
            let u = utxo(chain, index, 60_000);
            let (op, out, sk) = coin_for_pool(&r, &u).unwrap();
            // the script is the one the wallet's own scan watches for that (chain, index)
            let scripts = crate::tier2::WalletScripts::build(&r, Network::Bitcoin, 50).unwrap();
            assert_eq!(scripts.owner_of(&out.script_pubkey), Some((chain, index)), "chain {chain}");
            assert_eq!(out.value.to_sat(), 60_000);
            let m = ownership_msg("attempt-1", &session, &op);
            let proof = prove(&sk, &out.script_pubkey, m, &[9u8; 32]).unwrap();
            verify_proof(&out.script_pubkey, m, &proof).unwrap_or_else(|e| panic!("chain {chain}: {e}"));
        }
        let mut sp = utxo(crate::tier2::CHAIN_SP, 0, 60_000);
        sp.sp_tweak = Some("11".repeat(32));
        assert!(!pool_coin(&sp));
        assert!(coin_for_pool(&r, &sp).is_err());
        let mut spent = utxo(CHAIN_RECEIVE, 0, 60_000);
        spent.spent_height = Some(900_001);
        assert!(coin_for_pool(&r, &spent).is_err());
        assert!(!pool_coin(&utxo(crate::tier2::CHAIN_LEGACY, 0, 60_000)));
    }

    #[test]
    fn w6_the_holds_are_exactly_the_coins_a_seat_or_an_unsettled_record_names() {
        let mut marks = CoinMarks::default();
        marks.mix_lock(&[("AA".into(), 0), ("bb".into(), 1)], 5);
        marks.mix_lock(&[("aa".into(), 0)], 9);
        assert_eq!(marks.mix_locks.get("aa:0"), Some(&5), "a coin already held keeps its first time");
        let keep = HashSet::from([("bb".to_string(), 1u32), ("cc".to_string(), 2u32)]);
        assert_eq!(reconcile_locks(&mut marks, &keep, 11), (vec![("aa".to_string(), 0)], vec![("cc".to_string(), 2)]));
        assert!(!marks.is_mix_locked("aa", 0) && marks.is_mix_locked("BB", 1) && marks.is_mix_locked("cc", 2));
        assert_eq!(marks.mix_locks.get("bb:1"), Some(&5), "a kept hold keeps its time");
        assert_eq!(reconcile_locks(&mut marks, &keep, 12), (vec![], vec![]));
    }
}
