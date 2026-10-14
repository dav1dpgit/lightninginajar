//! MuSig2 signing of the pre-signed exits.

use anyhow::{anyhow, ensure, Result};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::Witness;
use musig2::{AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce};
use secp::{Point, Scalar};

use crate::keys::PoolKeys;
use crate::pool::{exit_sighash, PoolTxs};
use crate::util::tagged_hash;

/// LiJ P7: the fields are private — an exit message comes only from `exit_messages`, so a caller can never sign a message
/// it did not compute from the transactions.
pub struct ExitMessage {
    /// Position of the exit in signing order.
    index: u32,
    /// The pool output it spends, whose key `0/key` signs it.
    key: u32,
    msg: [u8; 32],
    output_key: XOnlyPublicKey,
}

impl ExitMessage {
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn key(&self) -> u32 {
        self.key
    }
    pub fn msg(&self) -> [u8; 32] {
        self.msg
    }
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }
}

/// LiJ P7: one member's secret nonces for one signing, each bound to the exit it was made for. No Clone, no Debug, no
/// serialization, no accessor: the only way out is `partial_sign`, which consumes it — so a secret nonce can never be
/// copied, printed, saved or used twice (the r7 §8 rules). (Its scalars cannot be wiped in place: secp's `Scalar` is Copy;
/// dropping this is as far as the types allow.)
pub struct ExitNonces {
    nonces: Vec<(u32, [u8; 32], SecNonce)>,
}

impl ExitNonces {
    pub fn len(&self) -> usize {
        self.nonces.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }
}

/// The message and the spent pool output key of every exit.
pub fn exit_messages(keys: &PoolKeys, txs: &PoolTxs) -> Result<Vec<ExitMessage>> {
    txs.exits
        .iter()
        .zip(&txs.spent)
        .zip(&txs.links)
        .enumerate()
        .map(|(i, ((tx, spent), link))| {
            Ok(ExitMessage {
                index: i as u32,
                key: link.from,
                msg: exit_sighash(tx, spent),
                output_key: keys.output_key(link.from)?,
            })
        })
        .collect()
}

/// One secret nonce per exit. They are only kept in memory and are consumed by signing. LiJ P4: `aux` is 32 fresh random
/// bytes from the caller, never reused; each exit's seed is a tagged hash of it and the exit's index, and musig2's
/// NonceGen mixes in the secret key, the aggregate key, the exit's message and `extra`.
pub fn make_nonces(
    seckey: Scalar,
    keys: &PoolKeys,
    msgs: &[ExitMessage],
    id: &str,
    aux: &[u8; 32],
) -> Result<(ExitNonces, Vec<PubNonce>)> {
    ensure!(!msgs.is_empty(), "no exits to sign");
    ensure!(
        keys.keys.contains(&seckey.base_point_mul()),
        "this key is not one of the pool's keys"
    );
    let mut secs = Vec::new();
    let mut pubs = Vec::new();
    for m in msgs {
        let aggpk: Point = keys.ctx(m.key)?.aggregated_pubkey();
        let k = m.index + 1;
        let extra = [id.as_bytes(), &k.to_le_bytes()].concat();
        let seed = tagged_hash("joinstr/v2/lij/nonce-seed", &[aux, &m.index.to_le_bytes()]);
        let sec = SecNonce::generate(seed, seckey, aggpk, m.msg, extra);
        pubs.push(sec.public_nonce());
        secs.push((m.index, m.msg, sec));
    }
    Ok((ExitNonces { nonces: secs }, pubs))
}

fn agg_nonce(nonces: &[&[PubNonce]], i: usize) -> AggNonce {
    AggNonce::sum(nonces.iter().map(|v| v[i].clone()))
}

/// LiJ P7: every list's length is checked (an Err, never a panic or a silently shorter result), and each secret nonce
/// signs only the exit it was made for.
pub fn partial_sign(
    seckey: Scalar,
    keys: &PoolKeys,
    msgs: &[ExitMessage],
    secnonces: ExitNonces,
    nonces: &[&[PubNonce]],
) -> Result<Vec<PartialSignature>> {
    ensure!(nonces.len() == keys.keys.len(), "missing nonces");
    ensure!(
        secnonces.nonces.len() == msgs.len(),
        "{} secret nonces for {} exits",
        secnonces.nonces.len(),
        msgs.len()
    );
    ensure!(
        nonces.iter().all(|v| v.len() == msgs.len()),
        "a member's nonce list does not have one nonce per exit"
    );
    secnonces
        .nonces
        .into_iter()
        .zip(msgs)
        .enumerate()
        .map(|(i, ((index, msg, sec), m))| {
            ensure!(
                index == m.index && msg == m.msg,
                "the nonce for exit {} was made for another message",
                i + 1
            );
            let ctx = keys.ctx(m.key)?;
            musig2::sign_partial(&ctx, seckey, sec, &agg_nonce(nonces, i), m.msg)
                .map_err(|e| anyhow!("sign exit {}: {e}", i + 1))
        })
        .collect()
}

/// Verify every partial signature, aggregate them and check the result against the
/// pool output key. `signers` holds each signer's key, nonces and partial signatures.
///
/// LiJ P7: the signers must be exactly the pool's keys, each once; every signer's lists must have one entry per exit;
/// every bad signer of an exit is named, not only the first.
pub fn aggregate(
    keys: &PoolKeys,
    msgs: &[ExitMessage],
    signers: &[(Point, &[PubNonce], &[PartialSignature])],
) -> Result<Vec<[u8; 64]>> {
    let secp = Secp256k1::verification_only();
    {
        let mut got: Vec<[u8; 33]> = signers.iter().map(|s| s.0.serialize()).collect();
        got.sort();
        let mut want: Vec<[u8; 33]> = keys.keys.iter().map(|k| k.serialize()).collect();
        want.sort();
        ensure!(got == want, "the signers are not exactly the pool's keys");
    }
    for (pk, pubnonces, sigs) in signers {
        ensure!(
            pubnonces.len() == msgs.len() && sigs.len() == msgs.len(),
            "{pk} did not send one nonce and one partial signature per exit"
        );
    }
    let nonces: Vec<&[PubNonce]> = signers.iter().map(|s| s.1).collect();
    let mut out = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        let ctx = keys.ctx(m.key)?;
        let agg = agg_nonce(&nonces, i);
        let bad: Vec<String> = signers
            .iter()
            .filter(|(pk, pubnonces, sigs)| {
                musig2::verify_partial(&ctx, sigs[i], &agg, *pk, &pubnonces[i], m.msg).is_err()
            })
            .map(|(pk, _, _)| pk.to_string())
            .collect();
        ensure!(
            bad.is_empty(),
            "invalid partial signature for exit {} from {}",
            i + 1,
            bad.join(", ")
        );
        let sig: CompactSignature =
            musig2::aggregate_partial_signatures(&ctx, &agg, signers.iter().map(|s| s.2[i]), m.msg)
                .map_err(|e| anyhow!("aggregate exit {}: {e}", i + 1))?;
        let bytes = sig.serialize();
        secp.verify_schnorr(
            &schnorr::Signature::from_slice(&bytes)?,
            &Message::from_digest(m.msg),
            &m.output_key,
        )
        .map_err(|_| anyhow!("exit {} signature does not verify", i + 1))?;
        out.push(bytes);
    }
    Ok(out)
}

/// LiJ P7: one signature per exit, each exit with its one input — else an Err (was: a silent partial attach or a panic).
pub fn attach(txs: &mut PoolTxs, sigs: &[[u8; 64]]) -> Result<()> {
    ensure!(sigs.len() == txs.exits.len(), "{} signatures for {} exits", sigs.len(), txs.exits.len());
    ensure!(txs.exits.iter().all(|tx| tx.input.len() == 1), "an exit without exactly one input");
    for (tx, sig) in txs.exits.iter_mut().zip(sigs) {
        let mut w = Witness::new();
        w.push(sig);
        tx.input[0].witness = w;
    }
    Ok(())
}

pub fn nonce_hex(n: &PubNonce) -> String {
    hex::encode(n.serialize())
}

/// LiJ P8: exactly 66 bytes of lowercase hex.
pub fn nonce_from_hex(s: &str) -> Result<PubNonce> {
    let b = crate::util::strict_hex(s, 66).map_err(|e| anyhow!("bad nonce: {e}"))?;
    PubNonce::from_bytes(&b).map_err(|e| anyhow!("bad nonce: {e}"))
}

pub fn psig_hex(s: &PartialSignature) -> String {
    hex::encode(s.serialize())
}

/// LiJ P8: exactly 32 bytes of lowercase hex.
pub fn psig_from_hex(s: &str) -> Result<PartialSignature> {
    let b = crate::util::strict_hex(s, 32).map_err(|e| anyhow!("bad partial signature: {e}"))?;
    PartialSignature::from_slice(&b).map_err(|e| anyhow!("bad partial signature: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{build, check_input_registrations, InputRegistration};
    use crate::util::random_scalar;

    #[test]
    fn musig_exit_chain() {
        let (p, mut regs, payouts, _) = crate::pool::tests_support::fake_pool(5);
        let seckeys: Vec<Scalar> = (0..5).map(|_| random_scalar()).collect();
        for (r, sk) in regs.iter_mut().zip(&seckeys) {
            r.musig = sk.base_point_mul();
        }
        check_input_registrations(&p, &regs).unwrap();
        let keys =
            PoolKeys::new(regs.iter().map(|r: &InputRegistration| r.musig).collect()).unwrap();
        let mut txs = build(&p, &regs, &payouts, &keys).unwrap();
        let msgs = exit_messages(&keys, &txs).unwrap();

        let (secs, pubnonces): (Vec<ExitNonces>, Vec<Vec<PubNonce>>) = seckeys
            .iter()
            .map(|sk| make_nonces(*sk, &keys, &msgs, &p.id, &crate::util::random_bytes()).unwrap())
            .unzip();
        let pubs: Vec<&[PubNonce]> = pubnonces.iter().map(|v| v.as_slice()).collect();
        let mut psigs = Vec::new();
        for (sk, secs) in seckeys.iter().zip(secs) {
            psigs.push(partial_sign(*sk, &keys, &msgs, secs, &pubs).unwrap());
        }
        let signers: Vec<_> = seckeys
            .iter()
            .enumerate()
            .map(|(i, sk)| (sk.base_point_mul(), pubs[i], psigs[i].as_slice()))
            .collect();
        let sigs = aggregate(&keys, &msgs, &signers).unwrap();
        attach(&mut txs, &sigs).unwrap();
        assert!(txs.exits.iter().all(|t| t.input[0].witness.len() == 1));

        let mut bad = psigs.clone();
        bad[2][1] = psigs[3][1];
        let signers: Vec<_> = seckeys
            .iter()
            .enumerate()
            .map(|(i, sk)| (sk.base_point_mul(), pubs[i], bad[i].as_slice()))
            .collect();
        let err = aggregate(&keys, &msgs, &signers).unwrap_err().to_string();
        assert!(err.contains("exit 2") && err.contains(&seckeys[2].base_point_mul().to_string()));
    }

    #[test]
    fn rejects_a_signature_over_another_chain() {
        let (p, mut regs, payouts, _) = crate::pool::tests_support::fake_pool(3);
        let seckeys: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
        for (r, sk) in regs.iter_mut().zip(&seckeys) {
            r.musig = sk.base_point_mul();
        }
        let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
        let txs = build(&p, &regs, &payouts, &keys).unwrap();
        let msgs = exit_messages(&keys, &txs).unwrap();
        let mut other = payouts.clone();
        other[0] = payouts[1].clone();
        other[1] = payouts[0].clone();
        other[2] = crate::pool::tests_support::fake_pool(3).2[0].clone();
        let evil = build(&p, &regs, &other, &keys).unwrap();
        let evil_msgs = exit_messages(&keys, &evil).unwrap();

        // LiJ P7: member 1 signs the other chain. Through our API that is refused at once (its nonces were made for
        // `msgs`); a dishonest member goes around it with musig2 directly, and the aggregation still names it.
        let mut secs: Vec<Option<ExitNonces>> = Vec::new();
        let mut pubnonces: Vec<Vec<PubNonce>> = Vec::new();
        let mut raw1: Vec<SecNonce> = Vec::new();
        for (i, sk) in seckeys.iter().enumerate() {
            if i == 1 {
                for m in &msgs {
                    let aggpk: Point = keys.ctx(m.key).unwrap().aggregated_pubkey();
                    raw1.push(SecNonce::generate(crate::util::random_bytes(), *sk, aggpk, m.msg, [0u8; 0]));
                }
                pubnonces.push(raw1.iter().map(|s| s.public_nonce()).collect());
                secs.push(None);
            } else {
                let (s, p) = make_nonces(*sk, &keys, &msgs, &p.id, &crate::util::random_bytes()).unwrap();
                pubnonces.push(p);
                secs.push(Some(s));
            }
        }
        let pubs: Vec<&[PubNonce]> = pubnonces.iter().map(|v| v.as_slice()).collect();
        {
            let (mine, _) = make_nonces(seckeys[1], &keys, &msgs, &p.id, &crate::util::random_bytes()).unwrap();
            assert!(partial_sign(seckeys[1], &keys, &evil_msgs, mine, &pubs).is_err(), "our API refuses another chain");
        }
        let mut psigs = Vec::new();
        for (i, (sk, secs)) in seckeys.iter().zip(secs).enumerate() {
            if i == 1 {
                let s: Vec<PartialSignature> = std::mem::take(&mut raw1)
                    .into_iter()
                    .zip(&evil_msgs)
                    .enumerate()
                    .map(|(j, (sec, m))| {
                        musig2::sign_partial(&keys.ctx(m.key).unwrap(), *sk, sec, &agg_nonce(&pubs, j), m.msg).unwrap()
                    })
                    .collect();
                psigs.push(s);
            } else {
                psigs.push(partial_sign(*sk, &keys, &msgs, secs.unwrap(), &pubs).unwrap());
            }
        }
        let signers: Vec<_> = seckeys
            .iter()
            .enumerate()
            .map(|(i, sk)| (sk.base_point_mul(), pubs[i], psigs[i].as_slice()))
            .collect();
        let err = aggregate(&keys, &msgs, &signers).unwrap_err().to_string();
        assert!(err.contains(&seckeys[1].base_point_mul().to_string()));
    }
}
