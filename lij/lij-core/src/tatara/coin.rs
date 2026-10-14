//! The coin check (spec v0.10 §7; plan r3/r4 step 6): before it signs, the phone proves each member's coin is real.
//!
//! For a coin `txid:vout` the provider's filter server answers from Bitcoin Core: the raw transaction, Core's proof that
//! it is in a block (`gettxoutproof`: the block header and the Merkle branch) and whether the output is unspent
//! (`gettxout`). The phone checks, in this order:
//! 1. the transaction decodes and hashes to the txid; the output exists — its amount and script are read from the
//!    transaction itself, never from the provider's word;
//! 2. the proof decodes, names exactly that txid once, and its branch leads to the header's Merkle root;
//! 3. the header's proof of work meets its own target, and that target is no easier than POW_FLOOR — a made-up coin
//!    needs a real block's worth of work;
//! 4. "unspent" — the provider's word. A lie can only stall a pool: a funding transaction spending a spent coin is
//!    invalid, nothing moves.
//!
//! Sizes are capped before anything is decoded. Pure: no network; the answer is handed in.

use anyhow::{bail, ensure, Context, Result};
use bitcoin::consensus::deserialize;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{BlockHash, MerkleBlock, OutPoint, ScriptBuf, Transaction, Txid};

/// The easiest block target the phone accepts in a coin proof: difficulty 10 T (compact 0x171c25a6) — DP 2026-10-12
/// 22:07 ("If so, then 10 T"). Mainnet was 132.7 T on 2026-10-10 and 124.9 T at this year's low (2026-06-14). Without a
/// floor a made-up header that meets its own easy target costs seconds on a laptop; at the floor it costs ~4.3 × 10^22
/// hashes — and a fake coin can only stall a pool.
pub const POW_FLOOR_BITS: u32 = 0x171c_25a6;

/// A raw transaction larger than this is refused before decoding (a standard transaction is at most 100,000 vbytes;
/// a pool member's coin comes from an ordinary transaction).
pub const MAX_TX_BYTES: usize = 400_000;
/// A `gettxoutproof` answer larger than this is refused before decoding (80-byte header, a count, at most ~4,000
/// hashes and their flag bits for any real block).
pub const MAX_PROOF_BYTES: usize = 200_000;

/// What the coin check proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCoin {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    pub script_pubkey: ScriptBuf,
    pub block_hash: BlockHash,
}

/// The floor as a target.
pub fn pow_floor() -> Target {
    Target::from_compact(CompactTarget::from_consensus(POW_FLOOR_BITS))
}

/// Check one coin against the filter server's answer (hex as served). `floor` is `pow_floor()` in the wallet; tests
/// pass their own.
pub fn check_coin(outpoint: &OutPoint, raw_tx_hex: &str, proof_hex: &str, unspent: bool, floor: Target) -> Result<CheckedCoin> {
    ensure!(raw_tx_hex.len() <= 2 * MAX_TX_BYTES, "transaction too large");
    ensure!(proof_hex.len() <= 2 * MAX_PROOF_BYTES, "proof too large");
    // 1. the transaction and its output
    let tx_bytes = hex::decode(raw_tx_hex).context("transaction is not hex")?;
    let tx: Transaction = deserialize(&tx_bytes).context("transaction does not decode")?;
    ensure!(tx.compute_txid() == outpoint.txid, "the transaction does not hash to the coin's txid");
    let out = tx.output.get(outpoint.vout as usize).context("the transaction has no such output")?;
    // 2. the proof
    let proof_bytes = hex::decode(proof_hex).context("proof is not hex")?;
    let mb: MerkleBlock = deserialize(&proof_bytes).context("proof does not decode")?;
    let mut matches: Vec<Txid> = Vec::new();
    let mut indexes: Vec<u32> = Vec::new();
    if mb.extract_matches(&mut matches, &mut indexes).is_err() {
        bail!("the proof's branch does not lead to its header's Merkle root");
    }
    ensure!(matches.len() == 1 && matches[0] == outpoint.txid, "the proof does not name exactly this transaction");
    // 3. the work
    let target = mb.header.target();
    let block_hash = mb.header.validate_pow(target).map_err(|_| anyhow::anyhow!("the header does not meet its own target"))?;
    ensure!(target <= floor, "the header's target is easier than the wallet's floor");
    // 4. the provider's word
    ensure!(unspent, "the provider says the coin is spent");
    Ok(CheckedCoin { outpoint: *outpoint, value_sat: out.value.to_sat(), script_pubkey: out.script_pubkey.clone(), block_hash })
}

/// A registered input matches its checked coin: the same amount and script the member registered.
pub fn matches_registration(c: &CheckedCoin, amount_sat: u64, script_pubkey: &[u8]) -> bool {
    c.value_sat == amount_sat && c.script_pubkey.as_bytes() == script_pubkey
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::Block;

    // Mainnet block 80,000 and `gettxoutproof ["5a4e…d3e2"]` (rust-bitcoin's merkle_tree::block vectors). Real
    // transaction, real branch, real work — at 2010's difficulty, far below the floor.
    const BLOCK_80000: &str = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
    const PROOF_80000: &str = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570200000002252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0e2d32adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a0105";
    const TXID: &str = "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2";

    fn tx_hex() -> String {
        let block: Block = deserialize(&hex::decode(BLOCK_80000).unwrap()).unwrap();
        hex::encode(serialize(&block.txdata[1]))
    }
    fn op(vout: u32) -> OutPoint { OutPoint { txid: TXID.parse().unwrap(), vout } }
    fn own_target() -> Target {
        let mb: MerkleBlock = deserialize(&hex::decode(PROOF_80000).unwrap()).unwrap();
        mb.header.target()
    }

    #[test]
    fn a_real_coin_passes_when_the_floor_allows_its_block() {
        let c = check_coin(&op(0), &tx_hex(), PROOF_80000, true, own_target()).unwrap();
        assert_eq!(c.value_sat, 50 * 100_000_000);
        assert_eq!(hex::encode(c.script_pubkey.as_bytes()), "76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac");
        assert_eq!(c.block_hash.to_string(), "000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6");
        assert!(matches_registration(&c, 50 * 100_000_000, &hex::decode("76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac").unwrap()));
        assert!(!matches_registration(&c, 50 * 100_000_000 - 1, c.script_pubkey.as_bytes()), "an amount one sat off");
        assert!(!matches_registration(&c, 50 * 100_000_000, &[0x51]), "another script");
    }

    #[test]
    fn the_wallet_floor_refuses_2010_work() {
        let e = check_coin(&op(0), &tx_hex(), PROOF_80000, true, pow_floor()).unwrap_err();
        assert!(e.to_string().contains("easier than the wallet's floor"), "{e}");
        // the floor is difficulty 10 T (DP 2026-10-12 22:07)
        let d = pow_floor().difficulty_float();
        assert!((9.99e12..10.01e12).contains(&d), "{d}");
    }

    #[test]
    fn a_wrong_transaction_output_proof_or_word_is_refused() {
        let floor = own_target();
        // another txid than the transaction's
        let mut other = op(0);
        other.txid = Txid::all_zeros();
        assert!(check_coin(&other, &tx_hex(), PROOF_80000, true, floor).unwrap_err().to_string().contains("does not hash"));
        // an output the transaction does not have
        assert!(check_coin(&op(1), &tx_hex(), PROOF_80000, true, floor).unwrap_err().to_string().contains("no such output"));
        // the transaction changed (its amount): no longer the txid
        let mut tx: Transaction = deserialize(&hex::decode(tx_hex()).unwrap()).unwrap();
        tx.output[0].value = bitcoin::Amount::from_sat(1);
        assert!(check_coin(&op(0), &hex::encode(serialize(&tx)), PROOF_80000, true, floor).is_err());
        // a proof whose branch was changed: the root no longer matches
        let mut p = hex::decode(PROOF_80000).unwrap();
        let last_hash_byte = p.len() - 3;
        p[last_hash_byte] ^= 1;
        assert!(check_coin(&op(0), &tx_hex(), &hex::encode(&p), true, floor).is_err());
        // a header whose nonce was changed: its hash no longer meets its target
        let mut h = hex::decode(PROOF_80000).unwrap();
        h[76] ^= 1;
        assert!(check_coin(&op(0), &tx_hex(), &hex::encode(&h), true, floor).is_err());
        // a proof for the other transaction in the block (the coinbase)
        let block: Block = deserialize(&hex::decode(BLOCK_80000).unwrap()).unwrap();
        let cb = block.txdata[0].compute_txid();
        let mb = MerkleBlock::from_block_with_predicate(&block, |t| *t == cb);
        assert!(check_coin(&op(0), &tx_hex(), &hex::encode(serialize(&mb)), true, floor).unwrap_err().to_string().contains("exactly this transaction"));
        // a proof naming both transactions
        let both = MerkleBlock::from_block_with_predicate(&block, |_| true);
        assert!(check_coin(&op(0), &tx_hex(), &hex::encode(serialize(&both)), true, floor).is_err());
        // the provider says spent
        assert!(check_coin(&op(0), &tx_hex(), PROOF_80000, false, floor).unwrap_err().to_string().contains("spent"));
        // not hex, too large
        assert!(check_coin(&op(0), "zz", PROOF_80000, true, floor).is_err());
        assert!(check_coin(&op(0), &"00".repeat(MAX_TX_BYTES + 1), PROOF_80000, true, floor).unwrap_err().to_string().contains("too large"));
        assert!(check_coin(&op(0), &tx_hex(), &"00".repeat(MAX_PROOF_BYTES + 1), true, floor).unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn random_and_cut_answers_never_panic() {
        let mut x: u64 = 0x5eed_c0de_0000_0001;
        let mut next = || { x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x.wrapping_mul(0x2545_F491_4F6C_DD1D) };
        let tx = hex::decode(tx_hex()).unwrap();
        let pf = hex::decode(PROOF_80000).unwrap();
        for _ in 0..3_000 {
            let mut a = tx.clone();
            let mut b = pf.clone();
            match next() % 4 {
                0 => { let i = (next() as usize) % a.len(); a[i] = next() as u8; }
                1 => { let i = (next() as usize) % b.len(); b[i] = next() as u8; }
                2 => { let n = (next() as usize) % a.len(); a.truncate(n); }
                _ => { let n = (next() as usize) % b.len(); b.truncate(n); }
            }
            let _ = check_coin(&op(0), &hex::encode(&a), &hex::encode(&b), true, own_target());
        }
    }
}
