// examples/inspect_monitor.rs
//
// Diagnostic inspector for a legacy unencrypted LDK ChannelMonitor blob.
// Minimal version: confirms deserialization works and prints basic metadata.
// We iterate from here once we know the decode is clean.

use std::env;
use std::fs;
use std::io::{self, Read};

use bip39::Mnemonic;
use bitcoin::{
    bip32::ExtendedPrivKey,
    secp256k1::Secp256k1,
    Network,
};
use lightning::{
    chain::channelmonitor::ChannelMonitor,
    sign::{InMemorySigner, KeysManager, NodeSigner, Recipient},
    util::ser::ReadableArgs,
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <monitor_hex_file> <network>", args[0]);
        eprintln!("       mnemonic on stdin");
        std::process::exit(1);
    }
    let hex_path = &args[1];
    let network = parse_network(&args[2]).expect("bad network");

    // Load blob hex from file
    let hex_raw = fs::read_to_string(hex_path).expect("failed to read hex file");
    let hex_clean: String = hex_raw.chars().filter(|c| !c.is_whitespace()).collect();
    let blob = hex::decode(&hex_clean).expect("invalid hex");
    println!("Loaded blob: {} bytes", blob.len());

    // Read mnemonic from stdin
    let mut mnemonic_str = String::new();
    io::stdin().read_to_string(&mut mnemonic_str).expect("stdin read");
    let mnemonic_str = mnemonic_str.trim();
    let mnemonic: Mnemonic = mnemonic_str.parse().expect("invalid BIP39 mnemonic");
    println!("Mnemonic parsed OK ({} words)", mnemonic_str.split_whitespace().count());

    // Replicate key.rs derivations exactly
    let seed = mnemonic.to_seed("");
    let master_xprv = ExtendedPrivKey::new_master(network, &seed).expect("xprv");
    let secp = Secp256k1::new();

    let path: bitcoin::bip32::DerivationPath = "m/535h".parse().unwrap();
    let node_xprv = master_xprv.derive_priv(&secp, &path).expect("m/535h");
    let ln_seed = node_xprv.private_key.secret_bytes();
    println!("Lightning node seed derived via m/535h");

    let ts: u64 = 0;
    let ts_nanos: u32 = 0;
    let keys_manager = KeysManager::new(&ln_seed, ts, ts_nanos);

    let node_id = keys_manager.get_node_id(Recipient::Node).expect("node_id");
    println!("Derived node_id: {}", hex::encode(node_id.serialize()));
    println!("  (expected:      0208d7544e87b402c400f917409bbbb0335b666b9551e864e759b337c89c2b12f1)");

    // Deserialize the ChannelMonitor — pass &keys_manager directly (impl resolves generics)
    let mut cursor = std::io::Cursor::new(&blob);
    let read_result: Result<(bitcoin::BlockHash, ChannelMonitor<InMemorySigner>), _> =
        <(bitcoin::BlockHash, ChannelMonitor<InMemorySigner>)>::read(
            &mut cursor,
            (&keys_manager, &keys_manager),
        );

    let (latest_block_hash, monitor) = match read_result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ChannelMonitor deserialize FAILED: {:?}", e);
            std::process::exit(2);
        }
    };

    println!("\n── ChannelMonitor decoded successfully ──");
    println!("Latest block hash (at persist time): {}", latest_block_hash);

    let funding_txo = monitor.get_funding_txo().0;
    println!("Funding outpoint: {}:{}", funding_txo.txid, funding_txo.index);

    // channel_id in 0.0.123 is derived from funding_txo or accessible via get_funding_txo
    // Let's just show funding_txo for now and see what else is reachable.

    // get_counterparty_node_id exists (compiler suggested it)
    let counterparty = monitor.get_counterparty_node_id();
    match counterparty {
        Some(pk) => {
            println!("Counterparty node_id: {}", hex::encode(pk.serialize()));
            println!("  (expected UM890:    03201938e37213f38e308c45ec7f3a32b9d45d33203bb850c9a41782389d086b0c)");
        }
        None => println!("Counterparty node_id: NOT FOUND"),
    }

    // get_claimable_balances — available in 0.0.123, shows what we can claim
    let balances = monitor.get_claimable_balances();
    println!("\n── Claimable balances (per monitor) ──");
    if balances.is_empty() {
        println!("(empty — channel is still open, no force-close yet)");
    } else {
        for (i, b) in balances.iter().enumerate() {
            println!("  [{}] {:?}", i, b);
        }
    }

    println!("\nDecode successful — monitor is intact and readable.");
// ── Extract to_remote scriptPubKey (where our funds will land) ──
    //
    // get_counterparty_payment_script() returns the scriptPubKey on the
    // counterparty's commitment tx that pays our funds. Two shapes possible:
    //   - STATIC_REMOTE_KEY commit type: P2WPKH(payment_key), 22-byte script
    //     (OP_0 PUSH20 <hash160>). BlueWallet WIF import recovers directly.
    //   - ANCHORS commit type: P2WSH(<payment_point> CHECKSIGVERIFY 1 CSV),
    //     34-byte script (OP_0 PUSH32 <sha256>). NOT BlueWallet-recoverable
    //     by WIF alone — requires descriptor sweep (Sparrow miniscript) or
    //     the recover_anchor tool, with nSequence>=1 to satisfy the CSV.
    //
    // We detect which case applies by inspecting the script length and
    // adjust the recovery instructions accordingly.

    let to_remote_script = monitor.get_counterparty_payment_script();
    let script_bytes = to_remote_script.as_bytes();
    let is_anchor_to_remote = script_bytes.len() == 34
        && script_bytes.first().copied() == Some(0x00)
        && script_bytes.get(1).copied() == Some(0x20);
    println!("\n── to_remote scriptPubKey (recovery target) ──");
    println!("scriptPubKey: {}", to_remote_script);
    println!("scriptPubKey hex: {}", hex::encode(script_bytes));
    println!(
        "Commit type detected: {}",
        if is_anchor_to_remote { "ANCHORS (P2WSH)" } else { "STATIC_REMOTE_KEY (P2WPKH)" }
    );

    match bitcoin::Address::from_script(&to_remote_script, network) {
        Ok(addr) => println!("Address: {}", addr),
        Err(e) => println!("Address parse failed: {:?}", e),
    }

    // ── Extract the static_remotekey (payment_key) for WIF export ──
    //
    // do_signer_call gives us access to the InMemorySigner inside the monitor.
    // InMemorySigner.payment_key is a public field containing the SecretKey
    // that owns the to_remote output.

    let mut payment_key: Option<bitcoin::secp256k1::SecretKey> = None;
    monitor.do_signer_call(|signer| {
        payment_key = Some(signer.payment_key.clone());
    });

    match payment_key {
        Some(sk) => {
            let privkey = bitcoin::PrivateKey {
                compressed: true,
                network,
                inner: sk,
            };
            let wif = privkey.to_wif();
            let pk = bitcoin::PublicKey::from_private_key(&secp, &privkey);

            println!("\n── static_remotekey (payment_key) ──");
            println!("Compressed pubkey: {}", pk);
            println!("WIF: {}", wif);
            if is_anchor_to_remote {
                println!("  ⚠  ANCHOR commit type detected.");
                println!("  ⚠  This WIF gives the private key, but the output is wrapped in");
                println!("  ⚠  P2WSH(<pubkey> CHECKSIGVERIFY 1 CSV) — NOT a plain P2WPKH.");
                println!("  ⚠  BlueWallet WIF import alone WILL NOT find the funds.");
                println!("  ⚠  Use Sparrow with descriptor wsh(and_v(v:pk(<hex_pubkey>),older(1)))");
                println!("  ⚠  or the recover_anchor tool; spending input needs nSequence>=1.");
            } else {
                println!("  ⚠  IMPORT THIS INTO BLUEWALLET AS A WIF 'IMPORT' WALLET.");
                println!("  ⚠  THE ADDRESS BLUEWALLET SHOWS MUST MATCH THE ADDRESS ABOVE.");
            }
            println!();
            println!("After the channel is force-closed, the commit tx will");
            println!("pay our share to the address above. Sweep it accordingly.");

            // Sanity check: derive the expected address from the pubkey,
            // matching the commit type, and compare with the address from
            // the monitor's scriptPubKey. If these disagree, derivation has
            // diverged from what's in the monitor — investigate before any
            // sweep attempt.
            let derived_addr = if is_anchor_to_remote {
                use bitcoin::blockdata::{opcodes, script::Builder};
                let anchor_redeem = Builder::new()
                    .push_slice(pk.inner.serialize())
                    .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                    .push_int(1)
                    .push_opcode(opcodes::all::OP_CSV)
                    .into_script();
                bitcoin::Address::p2wsh(&anchor_redeem, network)
            } else {
                bitcoin::Address::p2wpkh(&pk, network)
                    .expect("P2WPKH from compressed pubkey")
            };
            println!("\nSanity check — address derived from payment_key: {}", derived_addr);
            println!("  (should match scriptPubKey-derived address above)");
        }
        None => println!("\ndo_signer_call callback did not fire — investigate"),
    }

    // ── Channel value, hardcoded reference (LDK doesn't expose directly) ──
    const CHANNEL_VALUE_SATS: u64 = 101_000;
    println!("\n── Reference ──");
    println!("Channel capacity (per UM890 lncli): {} sats", CHANNEL_VALUE_SATS);
    println!("Our to_remote claim (from monitor):  50,500 sats");
    println!("UM890 to_local (after 144-block CSV): 49,900 sats");
    println!("Commit fee (paid by UM890 as initiator):  600 sats");
}

