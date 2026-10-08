//! v314 (S57, DP 2026-10-07 21:36 "Go ahead. Write up, Design, and start building the wallet side now" — joinstr-fit-r5,
//! the wallet side, step 1): BIP86 single-key taproot addresses at m/86'/{coin}'/0'/{chain}/{index}. A pool's exits pay
//! P2TR (joinstr v2), so the wallet's exit destination — To my wallet, and every round of Keep mixing — is a fresh BIP86
//! address from the 12 words: any BIP86 wallet on the same words finds it (DP's ruling, round 3: the wallet's scanning
//! changes too). This module derives only: the address, its internal key and the key-path signing keypair (BIP341 tweak
//! with no script tree). The on-chain walker, /recover and the Black start kit learn the chain in the next steps.

use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};

use crate::error::{LijError, LijResult};
use crate::key::RootKey;

/// External (receive) and internal (change) chains, as BIP44/84/86.
pub const CHAIN_RECEIVE: u32 = 0;
pub const CHAIN_CHANGE: u32 = 1;

/// m/86'/{coin}'/0'/{chain}/{index} — coin 0' on mainnet, 1' on every test network (as m/84 in key.rs).
pub fn path(network: Network, chain: u32, index: u32) -> LijResult<DerivationPath> {
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    DerivationPath::from_str(&format!("m/86h/{coin}h/0h/{chain}/{index}"))
        .map_err(|e| LijError::Key(format!("BIP86 path: {e}")))
}

/// The untweaked keypair at the BIP86 path.
fn keypair_at(root: &RootKey, chain: u32, index: u32) -> LijResult<Keypair> {
    let xprv = root.derive_priv(&path(root.network, chain, index)?)?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &xprv.private_key))
}

/// The BIP86 address and its internal (untweaked, x-only) key.
pub fn address_at(root: &RootKey, chain: u32, index: u32) -> LijResult<(Address, UntweakedPublicKey)> {
    let secp = Secp256k1::new();
    let (internal, _) = keypair_at(root, chain, index)?.x_only_public_key();
    Ok((Address::p2tr(&secp, internal, None, root.network), internal))
}

/// The key-path signing keypair for a coin at that address: the BIP341 tweak with no script tree.
pub fn tweaked_keypair_at(root: &RootKey, chain: u32, index: u32) -> LijResult<TweakedKeypair> {
    Ok(keypair_at(root, chain, index)?.tap_tweak(&Secp256k1::new(), None))
}

/// v316 (step 1b): the signing secret and the prevout script of a coin at m/86'/{coin}'/0'/{branch}/{index} — the
/// secret is the tweaked one (BIP341, no script tree), so a BIP340 signature with it verifies against the address's
/// output key, and BIP-352's sender rule (negate for an odd y) applies to it as to any taproot input.
pub fn secret_and_script(root: &RootKey, branch: u32, index: u32) -> LijResult<(bitcoin::secp256k1::SecretKey, bitcoin::ScriptBuf)> {
    let sk = tweaked_keypair_at(root, branch, index)?.to_inner().secret_key();
    let (addr, _) = address_at(root, branch, index)?;
    Ok((sk, addr.script_pubkey()))
}

/// v317 (the walk's net): the branch's parent key m/86'/{coin}'/0'/{branch}, derived once per net.
pub fn branch_xpriv(root: &RootKey, branch: u32) -> LijResult<bitcoin::bip32::Xpriv> {
    let coin = if root.network == Network::Bitcoin { 0 } else { 1 };
    let p = DerivationPath::from_str(&format!("m/86h/{coin}h/0h/{branch}")).map_err(|e| LijError::Key(format!("BIP86 path: {e}")))?;
    root.derive_priv(&p)
}

/// v317: the P2TR script at child `index` of a branch parent (the same script address_at gives).
pub fn spk_at<C: bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>, parent: &bitcoin::bip32::Xpriv, index: u32, network: Network,
) -> LijResult<bitcoin::ScriptBuf> {
    let child = parent
        .derive_priv(secp, &[bitcoin::bip32::ChildNumber::from_normal_idx(index).map_err(|e| LijError::Key(format!("BIP86 index {index}: {e}")))?])
        .map_err(|e| LijError::Key(format!("BIP86 child {index}: {e}")))?;
    let (internal, _) = Keypair::from_secret_key(secp, &child.private_key).x_only_public_key();
    Ok(Address::p2tr(secp, internal, None, network).script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    // BIP86's own test vectors: the "abandon … about" mnemonic, no passphrase, mainnet.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn root() -> RootKey {
        RootKey::from_mnemonic(&Mnemonic::from_str(MNEMONIC).unwrap(), Network::Bitcoin).unwrap()
    }

    #[test]
    fn v314_bip86_vectors() {
        let r = root();
        let cases = [
            (CHAIN_RECEIVE, 0, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115", "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            (CHAIN_RECEIVE, 1, "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145", "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
            (CHAIN_CHANGE, 0, "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef", "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"),
        ];
        for (chain, index, internal_hex, output_hex, addr) in cases {
            let (a, internal) = address_at(&r, chain, index).unwrap();
            assert_eq!(hex::encode(internal.serialize()), internal_hex, "internal key m/86'/0'/0'/{chain}/{index}");
            assert_eq!(a.to_string(), addr, "address m/86'/0'/0'/{chain}/{index}");
            let tweaked = tweaked_keypair_at(&r, chain, index).unwrap();
            let (out_key, _) = tweaked.to_inner().x_only_public_key();
            assert_eq!(hex::encode(out_key.serialize()), output_hex, "output key m/86'/0'/0'/{chain}/{index}");
            // the address's witness program is the tweaked output key the signing keypair holds
            assert_eq!(&a.script_pubkey().as_bytes()[2..], &out_key.serialize()[..], "the signing key spends this address");
        }
    }

    #[test]
    fn v314_test_networks_use_coin_type_one() {
        assert_eq!(path(Network::Bitcoin, 0, 7).unwrap().to_string(), "86'/0'/0'/0/7");
        assert_eq!(path(Network::Signet, 1, 2).unwrap().to_string(), "86'/1'/0'/1/2");
        assert_eq!(path(Network::Testnet, 0, 0).unwrap().to_string(), "86'/1'/0'/0/0");
    }
}
