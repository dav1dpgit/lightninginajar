//! Speed up a stuck pool (S59, DP 2026-10-14 "Bump stuck Mix exits is now-work"; spec v0.10 §6.4 — on-chain pools use
//! the member's own Speed up).
//!
//! The pool's transactions are a chain: the funding, then the exits in signing order, each spending the last pool
//! output. This phone's payout sits in its exit. A child spending that payout (CPFP) pays a fee that lifts every
//! UNCONFIRMED ancestor — the funding and the exits up to this phone's — to the target rate: miners take a transaction by
//! its ancestor fee rate, so the whole chain moves, and every member benefits. The fee comes out of this phone's new
//! coin, which lands at a fresh m/86 address of this wallet's (marked mixed like the payout — the child spends the
//! payout alone, so nothing links it to any other coin).
//!
//! Only an on-chain record with this wallet's own payout can be bumped: a channel pool's payout is a 2-of-2 no member
//! can spend alone (§6.4 — it pays a safe rate up front), and another wallet's payout is not ours to spend.
//!
//! Pure: the quote and the build take the record, what the chain servers said about each ancestor, and the rate. The
//! wasm layer asks the quorum, hands out the address, broadcasts and records the row.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::consensus::encode::serialize;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde::Serialize;

use crate::error::{LijError, LijResult};
use crate::onchain_send::DUST_THRESHOLD_SATS;
use crate::key::RootKey;

use super::records::StoredRecord;

/// The child's size, exact (test b4 measures it): 444 weight units = 40 (version, locktime, the two counts) + 2 (the
/// segwit marker and flag) + 164 (one input) + 66 (its 64-byte Schnorr witness with its counts) + 172 (one P2TR output)
/// → 111 vB.
pub const CHILD_VSIZE: u64 = 111;

/// One transaction of the chain, as the quote saw it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Ancestor {
    pub txid: String,
    pub vsize: u64,
    pub fee_sats: u64,
    /// What the chain servers said: in a block (true), not yet (false), or no answer (None — counted as unconfirmed,
    /// so the child errs on paying more, never less).
    pub confirmed: Option<bool>,
}

/// The figures the sheet shows before the person confirms — and what the build uses, so they are the figures that go out.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BumpQuote {
    pub record_id: String,
    pub ancestors: Vec<Ancestor>,
    /// The unconfirmed part of the chain this child lifts: its size and the fee it already carries.
    pub unconfirmed_vsize: u64,
    pub paid_fee_sats: u64,
    /// The rate that part sits at today (whole sat/vB, rounded down), and the rate asked for.
    pub current_sat_vb: u64,
    pub target_sat_vb: u64,
    pub child_vsize: u64,
    pub child_fee_sats: u64,
    /// This phone's payout (the pool size) and what the new coin carries after the fee.
    pub coin_sats: u64,
    pub arrives_sats: u64,
    /// The payout's outpoint (the exit's txid and the output's index).
    pub exit_txid: String,
    pub exit_vout: u32,
    /// Set when no child can be offered — in plain words, for the sheet.
    pub problem: Option<String>,
}

/// The fee a transaction of the chain paid. An exit's is exact from the record's own bytes (its one input is a pool
/// output whose value the previous transaction carries); the funding's inputs belong to every member, so its fee is
/// the pool's rate over its size (the NIP's own rule, each member's part rounded up — so a few sats under, never over,
/// which errs on the child paying more).
fn chain_fees(r: &StoredRecord) -> LijResult<Vec<(Transaction, u64)>> {
    let funding = r.funding()?;
    let exits = r.exits()?;
    let mut out: Vec<(Transaction, u64)> = Vec::with_capacity(1 + exits.len());
    let mut prev: Transaction = funding.clone();
    let mut exit_fees: Vec<u64> = Vec::with_capacity(exits.len());
    for e in &exits {
        let mut in_sats = 0u64;
        for i in &e.input {
            if i.previous_output.txid != prev.compute_txid() {
                return Err(LijError::Node(format!("attempt record {}: an exit spends something other than the last pool output", r.id)));
            }
            let o = prev.output.get(i.previous_output.vout as usize).ok_or_else(|| LijError::Node(format!("attempt record {}: an exit spends a missing output", r.id)))?;
            in_sats = in_sats.saturating_add(o.value.to_sat());
        }
        let out_sats: u64 = e.output.iter().map(|o| o.value.to_sat()).sum();
        exit_fees.push(in_sats.saturating_sub(out_sats));
        prev = e.clone();
    }
    let rate_sat_vb = match r.rate_sat_vb {
        Some(x) if x > 0 => x,
        _ => {
            // a record from before the rate was kept: the pool ran at one rate, so the first exit's own tells it
            let (e, f) = (exits.first(), exit_fees.first());
            match (e, f) {
                (Some(e), Some(f)) => (*f).div_ceil((e.vsize() as u64).max(1)).max(1),
                _ => 1,
            }
        }
    };
    out.push((funding.clone(), (funding.vsize() as u64).saturating_mul(rate_sat_vb)));
    for (e, f) in exits.into_iter().zip(exit_fees) {
        out.push((e, f));
    }
    Ok(out)
}

/// What a speed-up of `r` costs at `target_sat_vb`, given what the chain servers said about each transaction of the
/// chain (`confirmed(txid)`). Never writes. A record that cannot be bumped answers with `problem` set and the rest zero.
pub fn bump_quote(r: &StoredRecord, confirmed: &dyn Fn(&str) -> Option<bool>, target_sat_vb: u64) -> LijResult<BumpQuote> {
    let (exit, vout) = r.my_exit()?;
    let exit_txid = exit.compute_txid().to_string();
    let coin_sats = exit.output.get(vout as usize).map(|o| o.value.to_sat()).unwrap_or(0);
    let mut q = BumpQuote {
        record_id: r.id.clone(),
        ancestors: Vec::new(),
        unconfirmed_vsize: 0,
        paid_fee_sats: 0,
        current_sat_vb: 0,
        target_sat_vb,
        child_vsize: CHILD_VSIZE,
        child_fee_sats: 0,
        coin_sats,
        arrives_sats: 0,
        exit_txid: exit_txid.clone(),
        exit_vout: vout,
        problem: None,
    };
    if r.channel {
        q.problem = Some("A channel pool's payout is the channel's own 2-of-2 — no member can speed it up alone; it was sent at a next-block rate.".into());
        return Ok(q);
    }
    if r.payout_index.is_none() {
        q.problem = Some("The payout goes to another wallet's address — only that wallet can spend it, so only it can speed the pool up.".into());
        return Ok(q);
    }
    if target_sat_vb == 0 {
        q.problem = Some("No fee rate.".into());
        return Ok(q);
    }
    // the chain up to and including this phone's exit — what the child's fee lifts
    let mut chain = chain_fees(r)?;
    let my = chain.iter().position(|(t, _)| t.compute_txid().to_string() == exit_txid).ok_or_else(|| LijError::Node(format!("attempt record {}: its exit is not in its chain", r.id)))?;
    chain.truncate(my + 1);
    for (t, f) in &chain {
        let id = t.compute_txid().to_string();
        let c = confirmed(&id);
        q.ancestors.push(Ancestor { txid: id, vsize: t.vsize() as u64, fee_sats: *f, confirmed: c });
    }
    if q.ancestors.last().and_then(|a| a.confirmed) == Some(true) {
        q.problem = Some("Your exit is already in a block — nothing to speed up.".into());
        return Ok(q);
    }
    for a in &q.ancestors {
        if a.confirmed != Some(true) {
            q.unconfirmed_vsize = q.unconfirmed_vsize.saturating_add(a.vsize);
            q.paid_fee_sats = q.paid_fee_sats.saturating_add(a.fee_sats);
        }
    }
    q.current_sat_vb = q.paid_fee_sats / q.unconfirmed_vsize.max(1);
    let need = target_sat_vb.saturating_mul(q.unconfirmed_vsize.saturating_add(CHILD_VSIZE));
    q.child_fee_sats = need.saturating_sub(q.paid_fee_sats).max(target_sat_vb.saturating_mul(CHILD_VSIZE));
    if target_sat_vb <= q.current_sat_vb {
        q.problem = Some(format!("The pool already sits at {} sat/vB — a speed-up at {} sat/vB would change nothing.", q.current_sat_vb, target_sat_vb));
        return Ok(q);
    }
    if coin_sats <= q.child_fee_sats.saturating_add(DUST_THRESHOLD_SATS) {
        q.problem = Some(format!("Your {} sats cannot pay a {}-sat speed-up and still be worth sending.", coin_sats, q.child_fee_sats));
        q.child_fee_sats = 0;
        return Ok(q);
    }
    q.arrives_sats = coin_sats - q.child_fee_sats;
    Ok(q)
}

/// Build and sign the child: this phone's payout (the exit's output, P2TR key-path at m/86 index `payout_index`) spent
/// alone to `dest` (a fresh m/86 address of this wallet's) with the quote's fee. Returns the signed transaction and its
/// raw bytes. The caller broadcasts.
pub fn build_bump(root: &RootKey, r: &StoredRecord, q: &BumpQuote, dest: &ScriptBuf) -> LijResult<(Transaction, Vec<u8>)> {
    if let Some(p) = &q.problem {
        return Err(LijError::Node(p.clone()));
    }
    if q.record_id != r.id {
        return Err(LijError::Node("the quote is for another pool".into()));
    }
    let (exit, vout) = r.my_exit()?;
    if exit.compute_txid().to_string() != q.exit_txid || vout != q.exit_vout {
        return Err(LijError::Node("the quote names another exit".into()));
    }
    let index = r.payout_index.ok_or_else(|| LijError::Node("the payout is not this wallet's".into()))?;
    let out = exit.output.get(vout as usize).ok_or_else(|| LijError::Node("the exit has no such output".into()))?;
    let value = out.value.to_sat();
    if value != q.coin_sats || q.child_fee_sats == 0 || value <= q.child_fee_sats.saturating_add(DUST_THRESHOLD_SATS) {
        return Err(LijError::Node("the quote no longer fits the payout".into()));
    }
    let secp = Secp256k1::new();
    let (sk, spk) = crate::bip86::secret_and_script(root, 0, index)?;
    if spk != out.script_pubkey {
        return Err(LijError::Node(format!("the payout is not at m/86 index {index} of this wallet")));
    }
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: exit.compute_txid(), vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value - q.child_fee_sats), script_pubkey: dest.clone() }],
    };
    let prevouts = [TxOut { value: Amount::from_sat(value), script_pubkey: spk }];
    let sighash = {
        let cache_tx = tx.clone();
        let mut cache = SighashCache::new(&cache_tx);
        cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| LijError::Node(format!("speed-up sighash: {e}")))?
    };
    let msg = Message::from_digest(sighash.to_byte_array());
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let mut w = Witness::new();
    w.push(sig.as_ref());
    tx.input[0].witness = w;
    let raw = serialize(&tx);
    Ok((tx, raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tatara::records::tests::tx;
    use bitcoin::OutPoint;

    fn all_unconfirmed(_: &str) -> Option<bool> { Some(false) }
    fn p2tr(b: &str) -> ScriptBuf { ScriptBuf::from_bytes(hex::decode(format!("5120{}", b.repeat(32))).unwrap()) }

    /// A pool of three as one member's record: my coin → the funding (one pool output) → exit 0 (pays someone, 150 sats
    /// of fee) → exit 1 (pays me at m/86 index 4 — `mine` — and someone else, 150 sats of fee). ~1 sat/vB throughout.
    fn pool(mine: ScriptBuf, rate_milli: u64) -> (StoredRecord, Transaction, Transaction, Transaction) {
        let my_coin: bitcoin::Txid = "aa".repeat(32).parse().unwrap();
        let funding = tx(&[(my_coin, 0)], &[(299_000, p2tr("66"))]);
        let e0 = tx(&[(funding.compute_txid(), 0)], &[(99_000, p2tr("55")), (199_850, p2tr("67"))]);
        let e1 = tx(&[(e0.compute_txid(), 1)], &[(99_000, mine.clone()), (100_700, p2tr("58"))]);
        let rec = crate::tatara::machine::Record { id: "att-b".into(), funding: funding.clone(), exits: vec![e0.clone(), e1.clone()], payout: mine, inputs: vec![OutPoint { txid: my_coin, vout: 0 }], channel: false, rate_milli };
        (StoredRecord::from_machine(&rec, Some(4), None, 7), funding, e0, e1)
    }

    /// b1: the chain up to this phone's exit (the funding, exit 0, exit 1) is what the child lifts; the exits' fees are
    /// exact from the bytes, the funding's from the rate; the child's fee lifts the package to the target and the new coin
    /// is the payout less that fee.
    #[test]
    fn b1_the_quote_lifts_the_unconfirmed_chain_to_the_target() {
        let (r, funding, _, e1) = pool(p2tr("44"), 2000);
        assert_eq!(r.rate_sat_vb, Some(2));
        let q = bump_quote(&r, &all_unconfirmed, 10).unwrap();
        assert_eq!(q.problem, None);
        assert_eq!(q.ancestors.len(), 3);
        assert_eq!(q.ancestors[0].txid, funding.compute_txid().to_string());
        assert_eq!(q.ancestors[0].fee_sats, funding.vsize() as u64 * 2, "the funding's fee from the rate");
        assert_eq!(q.ancestors[1].fee_sats, 150, "exit 0's fee from the bytes");
        assert_eq!(q.ancestors[2].fee_sats, 150, "exit 1's fee from the bytes");
        assert_eq!(q.exit_txid, e1.compute_txid().to_string());
        assert_eq!(q.exit_vout, 0);
        assert_eq!(q.coin_sats, 99_000);
        let v: u64 = q.ancestors.iter().map(|a| a.vsize).sum();
        assert_eq!(q.unconfirmed_vsize, v);
        let need = 10 * (v + CHILD_VSIZE);
        assert_eq!(q.child_fee_sats, need - q.paid_fee_sats);
        assert!(q.child_fee_sats > 10 * CHILD_VSIZE, "the child pays for its ancestors too");
        assert_eq!(q.arrives_sats, 99_000 - q.child_fee_sats);
        assert!(q.current_sat_vb < 10 && q.current_sat_vb >= 1, "{}", q.current_sat_vb);
    }

    /// b2: a confirmed funding leaves the package (its size and fee out); an exit already in a block, a channel pool,
    /// another wallet's payout, a rate below today's and a coin too small each answer with a problem, nothing else.
    #[test]
    fn b2_what_cannot_be_bumped_says_why() {
        let (r, funding, _, e1) = pool(p2tr("44"), 2000);
        let f = funding.compute_txid().to_string();
        let q = bump_quote(&r, &|t: &str| Some(t == f), 10).unwrap();
        assert_eq!(q.ancestors.len(), 3);
        assert_eq!(q.unconfirmed_vsize, q.ancestors[1].vsize + q.ancestors[2].vsize, "the confirmed funding is not lifted");
        assert_eq!(q.paid_fee_sats, 300);
        let ex = e1.compute_txid().to_string();
        let q2 = bump_quote(&r, &|t: &str| Some(t == ex), 10).unwrap();
        assert!(q2.problem.as_deref().unwrap_or("").contains("already in a block"));
        let mut ch = r.clone(); ch.channel = true;
        assert!(bump_quote(&ch, &all_unconfirmed, 10).unwrap().problem.as_deref().unwrap_or("").contains("2-of-2"));
        let mut outside = r.clone(); outside.payout_index = None;
        assert!(bump_quote(&outside, &all_unconfirmed, 10).unwrap().problem.as_deref().unwrap_or("").contains("another wallet"));
        let low = bump_quote(&r, &all_unconfirmed, 1).unwrap();
        assert!(low.problem.as_deref().unwrap_or("").contains("would change nothing"), "{:?}", low.problem);
        let huge = bump_quote(&r, &all_unconfirmed, 2_000).unwrap();
        assert!(huge.problem.as_deref().unwrap_or("").contains("cannot pay"), "{:?}", huge.problem);
        assert_eq!(huge.child_fee_sats, 0);
        // no answer from the servers counts as unconfirmed: the child errs on paying more
        let unknown = bump_quote(&r, &|_: &str| None, 10).unwrap();
        assert_eq!(unknown.unconfirmed_vsize, q.unconfirmed_vsize + q.ancestors[0].vsize);
    }

    /// b3: a record from before the rate was kept takes the pool's rate from its first exit's own fee.
    #[test]
    fn b3_an_old_record_reads_the_rate_from_its_first_exit() {
        let (r, funding, e0, _) = pool(p2tr("44"), 0);
        assert_eq!(r.rate_sat_vb, None);
        let q = bump_quote(&r, &all_unconfirmed, 50).unwrap();
        let rate = 150u64.div_ceil(e0.vsize() as u64);
        assert_eq!(q.ancestors[0].fee_sats, funding.vsize() as u64 * rate);
    }

    /// b4: the child spends the payout alone (one P2TR key-path input, one output to the given script) with the quote's
    /// fee, signed with the m/86 key of the payout's index — a payout at another index is refused, as is a quote with a
    /// problem.
    #[test]
    fn b4_the_child_spends_the_payout_alone_and_is_signed_by_its_own_key() {
        use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
        let root = RootKey::generate(bitcoin::Network::Bitcoin).unwrap().0;
        let dest = p2tr("77");
        // a payout that is not at m/86 index 4 of this seed: refused
        let (r, _, _, _) = pool(p2tr("44"), 2000);
        let q = bump_quote(&r, &all_unconfirmed, 10).unwrap();
        assert_eq!(q.problem, None);
        assert!(build_bump(&root, &r, &q, &dest).unwrap_err().to_string().contains("not at m/86 index 4"));
        // a record whose payout IS this wallet's index 4
        let (_, spk) = crate::bip86::secret_and_script(&root, 0, 4).unwrap();
        let (r, _, _, e1) = pool(spk.clone(), 2000);
        let q = bump_quote(&r, &all_unconfirmed, 10).unwrap();
        assert_eq!(q.problem, None);
        let (tx, raw) = build_bump(&root, &r, &q, &dest).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, OutPoint { txid: e1.compute_txid(), vout: 0 });
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].script_pubkey, dest);
        assert_eq!(tx.output[0].value.to_sat(), 99_000 - q.child_fee_sats);
        assert_eq!(tx.vsize() as u64, CHILD_VSIZE, "the child's size is what the quote priced");
        assert!(!raw.is_empty());
        // the Schnorr signature verifies against the payout's own x-only key over the key-path sighash
        let secp = Secp256k1::new();
        let prevouts = [TxOut { value: Amount::from_sat(99_000), script_pubkey: spk.clone() }];
        let mut cache = SighashCache::new(&tx);
        let sh = cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let x = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..]).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(sh.to_byte_array()), &x).unwrap();
        // a quote with a problem builds nothing
        let bad = bump_quote(&r, &all_unconfirmed, 1).unwrap();
        assert!(build_bump(&root, &r, &bad, &dest).is_err());
    }
}
