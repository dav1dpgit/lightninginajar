// examples/recover_anchor.rs
//
// Anchor-channel force-close residue recovery tool.
//
// Companion to inspect_monitor.rs. Where inspect_monitor needs a ChannelMonitor
// blob (and uses it to derive the exact channel index), recover_anchor needs
// only the BIP39 mnemonic and the on-chain destination address of the
// to_remote output. It scans candidate channel indices and reports which
// derivation matches.
//
// Use case: incognito wallet (no localStorage, no monitor blob) where the
// counterparty force-closed an ANCHORS channel and the to_remote address
// is visible on-chain via a block explorer.
//
// Usage:
//   cargo run --example recover_anchor -- <target_p2wsh_address> <network>
//
// Then enter the mnemonic on stdin.
//
// Output:
//   - Matching channel index n (or "no match within scan range" if not found)
//   - WIF private key for m/525h/0/0/0/n
//   - Compressed pubkey hex (for Sparrow miniscript descriptor)
//   - Sparrow descriptor string ready to paste
//
// Followup: take the WIF + pubkey into Sparrow with the descriptor
// wsh(and_v(v:pk(<hex_pubkey>),older(1))) and sweep. See RECOVERY.md Part 5.
//
// Scan range is [0, 32) by default — enough for any realistic incognito
// wallet, where the channel index is almost always 0, 1, or 2 (it advances
// once per channel-open and a few times per channel for shutdown / destination
// script allocation). Override the upper bound with the SCAN_MAX env var
// if you have a high-volume wallet.

use std::env;
use std::io::{self, BufRead, Write};
use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    blockdata::{opcodes, script::Builder},
    secp256k1::Secp256k1,
    Address, Network, PrivateKey,
};

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network: {other}")),
    }
}

fn read_mnemonic_from_stdin() -> Result<(Mnemonic, usize), String> {
    eprint!("Enter BIP39 mnemonic (12 or 24 words, single line): ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("stdin read failed: {e}"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("empty mnemonic".to_string());
    }
    let word_count = trimmed.split_whitespace().count();
    let mnemonic =
        Mnemonic::from_str(trimmed).map_err(|e| format!("mnemonic parse failed: {e}"))?;
    Ok((mnemonic, word_count))
}

fn derive_static_remotekey_xpriv(
    mnemonic: &Mnemonic,
    network: Network,
) -> Result<ExtendedPrivKey, String> {
    // Match key.rs::RootKey::static_remotekey_xpriv. Path is mainnet-style
    // m/525h/0/0/0 regardless of network — we encode network only in the
    // resulting address, not in the derivation, to keep recovery vectors
    // stable across testnets.
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(network, &seed)
        .map_err(|e| format!("xpriv master failed: {e}"))?;
    let secp = Secp256k1::new();
    let path = "m/525h/0/0/0"
        .parse::<DerivationPath>()
        .map_err(|e| format!("parse derivation path: {e}"))?;
    master
        .derive_priv(&secp, &path)
        .map_err(|e| format!("derive static_remotekey_xpriv: {e}"))
}

fn anchor_p2wsh_address(
    xpriv: &ExtendedPrivKey,
    index: u32,
    network: Network,
) -> Result<(Address, bitcoin::PublicKey, bitcoin::PrivateKey), String> {
    let secp = Secp256k1::new();
    let child = xpriv
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
                .map_err(|e| format!("bad child {index}: {e}"))?]),
        )
        .map_err(|e| format!("derive child {index}: {e}"))?;
    let pubkey = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    let privkey = PrivateKey {
        compressed: true,
        network,
        inner: child.private_key,
    };
    let anchor_redeem = Builder::new()
        .push_slice(pubkey.inner.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_int(1)
        .push_opcode(opcodes::all::OP_CSV)
        .into_script();
    let address = Address::p2wsh(&anchor_redeem, network);
    Ok((address, pubkey, privkey))
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: {} <target_p2wsh_address> <network>\n\
             Networks: bitcoin, testnet, signet, regtest\n\
             Mnemonic is read from stdin after launch.",
            args.first().map(|s| s.as_str()).unwrap_or("recover_anchor")
        );
        return Err("bad arguments".to_string());
    }
    let target_addr_str = &args[1];
    let network = parse_network(&args[2])?;

    // Target address must be parseable in this network and a P2WSH.
    let target_addr = Address::from_str(target_addr_str)
        .map_err(|e| format!("target address parse failed: {e}"))?
        .require_network(network)
        .map_err(|e| format!("target address not on {network:?}: {e}"))?;

    println!("Target P2WSH address: {target_addr}");
    println!("Network: {network:?}");

    let (mnemonic, word_count) = read_mnemonic_from_stdin()?;
    println!("Mnemonic parsed OK ({word_count} words)");

    let xpriv = derive_static_remotekey_xpriv(&mnemonic, network)?;
    println!("Derived static_remotekey_xpriv at m/525h/0/0/0");

    let scan_max: u32 = env::var("SCAN_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    println!("Scanning n in [0, {scan_max})…");

    for n in 0..scan_max {
        let (addr, pubkey, privkey) = anchor_p2wsh_address(&xpriv, n, network)?;
        if addr == target_addr {
            let wif = privkey.to_wif();
            let pubkey_hex = hex::encode(pubkey.inner.serialize());
            println!();
            println!("── MATCH at channel index n = {n} ──");
            println!("Address (P2WSH-anchor): {addr}");
            println!("Pubkey (compressed hex): {pubkey_hex}");
            println!("Private key (WIF): {wif}");
            println!();
            println!("Sparrow descriptor (paste into Custom wallet settings):");
            println!("  wsh(and_v(v:pk({pubkey_hex}),older(1)))");
            println!();
            println!("Spending checklist:");
            println!("  - Wait for commit tx to have >=1 confirmation");
            println!("  - Set nSequence >= 1 on the spending input (CSV satisfied)");
            println!("  - Witness = [<DER signature + SIGHASH_ALL byte>, <redeem_script>]");
            println!("  - BIP143 sighash (segwit)");
            return Ok(());
        }
    }

    println!();
    println!("── NO MATCH within scan range [0, {scan_max}) ──");
    println!("Possible causes:");
    println!("  - Wrong mnemonic for this wallet (check word order / typos)");
    println!("  - Wrong network (mainnet vs testnet — addresses look similar at a glance)");
    println!("  - Channel index higher than scan range. Re-run with SCAN_MAX=128 env var.");
    println!("  - This output is NOT an anchor-variant to_remote (e.g. it's the LSP's");
    println!("    CSV-delayed to_local, or an anchor 330-sat output). Verify the");
    println!("    target address corresponds to your share of the channel.");
    Err("no match".to_string())
}
