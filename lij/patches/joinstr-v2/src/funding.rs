//! Funding input signatures and ownership proofs, for P2TR (key path) and P2WPKH.

use anyhow::{bail, ensure, Context, Result};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::{ecdsa, schnorr, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{CompressedPublicKey, OutPoint, Script, ScriptBuf, Transaction, TxOut, Witness};
use serde::{Deserialize, Serialize};

use crate::util::tagged_hash;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct Proof {
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
}

pub fn ownership_msg(id: &str, session: &[u8; 32], op: &OutPoint) -> [u8; 32] {
    tagged_hash(
        "joinstr/v2/ownership",
        &[id.as_bytes(), session, &serialize(op)],
    )
}

fn tweaked_keypair(sk: &SecretKey) -> Keypair {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, sk)
        .tap_tweak(&secp, None)
        .to_keypair()
}

fn p2tr_output_key(spk: &Script) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])?)
}

/// LiJ P4: `aux` is 32 fresh random bytes from the caller (BIP-340's auxiliary randomness).
pub fn prove(sk: &SecretKey, spk: &Script, msg: [u8; 32], aux: &[u8; 32]) -> Result<Proof> {
    let secp = Secp256k1::new();
    let m = Message::from_digest(msg);
    if spk.is_p2tr() {
        let sig = secp.sign_schnorr_with_aux_rand(&m, &tweaked_keypair(sk), aux);
        Ok(Proof {
            sig: hex::encode(sig.serialize()),
            pubkey: None,
        })
    } else if spk.is_p2wpkh() {
        let sig = secp.sign_ecdsa_low_r(&m, sk);
        Ok(Proof {
            sig: hex::encode(sig.serialize_der()),
            pubkey: Some(hex::encode(
                PublicKey::from_secret_key(&secp, sk).serialize(),
            )),
        })
    } else {
        bail!("unsupported input type")
    }
}

fn p2wpkh_pubkey(spk: &Script, pubkey: &[u8]) -> Result<CompressedPublicKey> {
    let pk = CompressedPublicKey::from_slice(pubkey)?;
    ensure!(
        ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()) == *spk,
        "public key does not match the P2WPKH program"
    );
    Ok(pk)
}

pub fn verify_proof(spk: &Script, msg: [u8; 32], proof: &Proof) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let m = Message::from_digest(msg);
    // LiJ P8: a Schnorr proof is exactly 64 bytes, an ECDSA proof 8 to 72 bytes of DER, a key 33 bytes — lowercase hex
    let sig = if spk.is_p2tr() {
        crate::util::strict_hex(&proof.sig, 64)?
    } else {
        crate::util::strict_hex_range(&proof.sig, 8, 72)?
    };
    if spk.is_p2tr() {
        secp.verify_schnorr(
            &schnorr::Signature::from_slice(&sig)?,
            &m,
            &p2tr_output_key(spk)?,
        )
        .context("invalid ownership proof")?;
    } else if spk.is_p2wpkh() {
        let pk = p2wpkh_pubkey(spk, &crate::util::strict_hex(proof.pubkey.as_deref().unwrap_or(""), 33)?)?;
        secp.verify_ecdsa(&m, &ecdsa::Signature::from_der(&sig)?, &pk.0)
            .context("invalid ownership proof")?;
    } else {
        bail!("unsupported input type")
    }
    Ok(())
}

/// LiJ P4: `aux` is 32 fresh random bytes from the caller (BIP-340's auxiliary randomness; unused for P2WPKH).
pub fn sign_input(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    sk: &SecretKey,
    aux: &[u8; 32],
) -> Result<Witness> {
    let secp = Secp256k1::new();
    let spk = &prevouts[index].script_pubkey;
    let mut cache = SighashCache::new(tx);
    if spk.is_p2tr() {
        let h = cache.taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )?;
        let sig = secp.sign_schnorr_with_aux_rand(
            &Message::from_digest(h.to_byte_array()),
            &tweaked_keypair(sk),
            aux,
        );
        Ok(Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        }))
    } else if spk.is_p2wpkh() {
        let h = cache.p2wpkh_signature_hash(
            index,
            spk,
            prevouts[index].value,
            EcdsaSighashType::All,
        )?;
        let sig = secp.sign_ecdsa_low_r(&Message::from_digest(h.to_byte_array()), sk);
        Ok(Witness::p2wpkh(
            &bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            },
            &PublicKey::from_secret_key(&secp, sk),
        ))
    } else {
        bail!("unsupported input type")
    }
}

/// Check a witness for funding input `index`. Only `SIGHASH_DEFAULT` (P2TR) and
/// `SIGHASH_ALL` (P2WPKH) are accepted, so the funding txid cannot change.
pub fn verify_input(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    witness: &Witness,
) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let spk = &prevouts[index].script_pubkey;
    let mut cache = SighashCache::new(tx);
    if spk.is_p2tr() {
        ensure!(
            witness.len() == 1 && witness[0].len() == 64,
            "P2TR witness must be one 64 byte signature"
        );
        let h = cache.taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )?;
        secp.verify_schnorr(
            &schnorr::Signature::from_slice(&witness[0])?,
            &Message::from_digest(h.to_byte_array()),
            &p2tr_output_key(spk)?,
        )
        .context("invalid P2TR funding signature")?;
    } else if spk.is_p2wpkh() {
        ensure!(witness.len() == 2, "P2WPKH witness must have two items");
        let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0])?;
        ensure!(
            sig.sighash_type == EcdsaSighashType::All,
            "funding signatures must use SIGHASH_ALL"
        );
        let pk = p2wpkh_pubkey(spk, &witness[1])?;
        let h = cache.p2wpkh_signature_hash(
            index,
            spk,
            prevouts[index].value,
            EcdsaSighashType::All,
        )?;
        secp.verify_ecdsa(
            &Message::from_digest(h.to_byte_array()),
            &sig.signature,
            &pk.0,
        )
        .context("invalid P2WPKH funding signature")?;
    } else {
        bail!("unsupported input type")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, TxIn, Txid};
    use std::str::FromStr;

    fn spk_for(sk: &SecretKey, taproot: bool) -> ScriptBuf {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, sk);
        if taproot {
            ScriptBuf::new_p2tr(&secp, XOnlyPublicKey::from(pk), None)
        } else {
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash())
        }
    }

    #[test]
    fn sign_verify_and_proofs() {
        let keys: Vec<SecretKey> = (1..=2u8)
            .map(|i| SecretKey::from_slice(&[i; 32]).unwrap())
            .collect();
        let prevouts: Vec<TxOut> = keys
            .iter()
            .zip([true, false])
            .map(|(k, tr)| TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: spk_for(k, tr),
            })
            .collect();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..2)
                .map(|i| TxIn {
                    previous_output: OutPoint::new(Txid::from_str(&"ab".repeat(32)).unwrap(), i),
                    sequence: Sequence(0xfffffffd),
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: prevouts[0].script_pubkey.clone(),
            }],
        };
        for i in 0..2 {
            let w = sign_input(&tx, i, &prevouts, &keys[i], &crate::util::random_bytes()).unwrap();
            verify_input(&tx, i, &prevouts, &w).unwrap();
            assert!(verify_input(&tx, 1 - i, &prevouts, &w).is_err());
            let m = ownership_msg("pool", &[3; 32], &tx.input[i].previous_output);
            let p = prove(&keys[i], &prevouts[i].script_pubkey, m, &crate::util::random_bytes()).unwrap();
            verify_proof(&prevouts[i].script_pubkey, m, &p).unwrap();
            assert!(verify_proof(&prevouts[i].script_pubkey, [0; 32], &p).is_err());
            assert!(verify_proof(&prevouts[1 - i].script_pubkey, m, &p).is_err());
        }
    }

    fn two_input_tx(prevouts: &[TxOut]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..2)
                .map(|i| TxIn {
                    previous_output: OutPoint::new(Txid::from_str(&"cd".repeat(32)).unwrap(), i),
                    sequence: Sequence(0xfffffffd),
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: prevouts[0].script_pubkey.clone(),
            }],
        }
    }

    fn keys_and_prevouts() -> (Vec<SecretKey>, Vec<TxOut>) {
        let keys: Vec<SecretKey> = (5..=6u8)
            .map(|i| SecretKey::from_slice(&[i; 32]).unwrap())
            .collect();
        let prevouts = keys
            .iter()
            .zip([true, false])
            .map(|(k, tr)| TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: spk_for(k, tr),
            })
            .collect();
        (keys, prevouts)
    }

    fn p2wpkh_sig(
        tx: &Transaction,
        i: usize,
        prevouts: &[TxOut],
        sk: &SecretKey,
        t: EcdsaSighashType,
    ) -> bitcoin::ecdsa::Signature {
        let secp = Secp256k1::new();
        let h = SighashCache::new(tx)
            .p2wpkh_signature_hash(i, &prevouts[i].script_pubkey, prevouts[i].value, t)
            .unwrap();
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa_low_r(&Message::from_digest(h.to_byte_array()), sk),
            sighash_type: t,
        }
    }

    #[test]
    fn rejects_anyonecanpay_and_explicit_sighash() {
        let (keys, prevouts) = keys_and_prevouts();
        let tx = two_input_tx(&prevouts);
        let secp = Secp256k1::new();

        let acp = p2wpkh_sig(
            &tx,
            1,
            &prevouts,
            &keys[1],
            EcdsaSighashType::AllPlusAnyoneCanPay,
        );
        let w = Witness::p2wpkh(&acp, &PublicKey::from_secret_key(&secp, &keys[1]));
        assert_eq!(w[0].last(), Some(&0x81));
        assert!(verify_input(&tx, 1, &prevouts, &w).is_err());

        for t in [TapSighashType::AllPlusAnyoneCanPay, TapSighashType::All] {
            let h = SighashCache::new(&tx)
                .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), t)
                .unwrap();
            let sig = secp.sign_schnorr_with_aux_rand(
                &Message::from_digest(h.to_byte_array()),
                &tweaked_keypair(&keys[0]),
                &crate::util::random_bytes(),
            );
            let w = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: t,
            });
            assert_eq!(w[0].len(), 65);
            assert!(verify_input(&tx, 0, &prevouts, &w).is_err());
        }
    }

    /// Why funding inputs never use ANYONECANPAY: such a signature stays valid when
    /// someone adds an input, which changes the txid the pre-signed exits spend from.
    #[test]
    fn anyonecanpay_lets_others_change_the_txid() {
        let (keys, mut prevouts) = keys_and_prevouts();
        let tx = two_input_tx(&prevouts);
        let all = p2wpkh_sig(&tx, 1, &prevouts, &keys[1], EcdsaSighashType::All);
        let acp = p2wpkh_sig(
            &tx,
            1,
            &prevouts,
            &keys[1],
            EcdsaSighashType::AllPlusAnyoneCanPay,
        );

        let mut changed = tx.clone();
        changed.input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_str(&"ef".repeat(32)).unwrap(), 7),
            sequence: Sequence(0xfffffffd),
            ..Default::default()
        });
        prevouts.push(prevouts[0].clone());
        assert_ne!(changed.compute_txid(), tx.compute_txid());

        let secp = Secp256k1::verification_only();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &keys[1]);
        let still_valid = |sig: &bitcoin::ecdsa::Signature| {
            let h = SighashCache::new(&changed)
                .p2wpkh_signature_hash(
                    1,
                    &prevouts[1].script_pubkey,
                    prevouts[1].value,
                    sig.sighash_type,
                )
                .unwrap();
            secp.verify_ecdsa(
                &Message::from_digest(h.to_byte_array()),
                &sig.signature,
                &pk,
            )
            .is_ok()
        };
        assert!(
            still_valid(&acp),
            "an ANYONECANPAY signature survives the extra input"
        );
        assert!(!still_valid(&all), "a SIGHASH_ALL signature does not");
    }

    #[test]
    fn proofs_are_bound_to_the_session_key() {
        let (keys, prevouts) = keys_and_prevouts();
        let op = OutPoint::new(Txid::from_str(&"cd".repeat(32)).unwrap(), 0);
        for (k, p) in keys.iter().zip(&prevouts) {
            let proof = prove(k, &p.script_pubkey, ownership_msg("pool", &[3; 32], &op), &crate::util::random_bytes()).unwrap();
            verify_proof(
                &p.script_pubkey,
                ownership_msg("pool", &[3; 32], &op),
                &proof,
            )
            .unwrap();
            assert!(verify_proof(
                &p.script_pubkey,
                ownership_msg("pool", &[4; 32], &op),
                &proof
            )
            .is_err());
            assert!(verify_proof(
                &p.script_pubkey,
                ownership_msg("other", &[3; 32], &op),
                &proof
            )
            .is_err());
        }
    }
}
