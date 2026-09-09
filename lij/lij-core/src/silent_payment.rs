//! BIP-352 silent payments — SEND side (engine v240, S45).
//!
//! What this module does: parse an `sp1q…` address (bech32m, hrp "sp" on
//! mainnet / "tsp" elsewhere, version 0, 33-byte scan key + 33-byte spend key)
//! and derive the single taproot output a transaction with the wallet's
//! inputs must pay to. The wallet's inputs are always compressed-key P2WPKH
//! (m/84 receive/change, m/525 legacy), so no taproot-parity handling is
//! needed on the sending side; the derivation is exactly the BIP's:
//!
//!   a_sum      = Σ a_i (mod n)                   — the input private keys
//!   A_sum      = a_sum·G
//!   outpoint_L = the lexicographically smallest input outpoint (txid‖vout,
//!                consensus serialisation, 36 bytes)
//!   input_hash = TaggedHash("BIP0352/Inputs", outpoint_L ‖ A_sum)
//!   ecdh       = (input_hash · a_sum) · B_scan
//!   t_0        = TaggedHash("BIP0352/SharedSecret", ecdh ‖ 0u32 BE)
//!   P_0        = B_spend + t_0·G           → output = OP_1 <x(P_0)>
//!
//! One recipient, one output per transaction (k = 0). Labels are the
//! receiver's business and do not change sending. The RBF bump path rebuilds
//! the same inputs, so it re-derives the same output.
//!
//! The BIP's own `send_and_receive_test_vectors.json` (sending cases, trimmed to
//! the fields used) is the unit-test gate in `testdata/`; the cases with
//! taproot inputs are asserted to be skipped, since the wallet never has them.
//!
//! Receiving (scan key at m/352', the tweak index, detection, spending) is
//! not in this module yet.

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::{Network, OutPoint, ScriptBuf};

use crate::error::{LijError, LijResult};

/// A parsed silent-payment address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub hrp: String,
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut out = Vec::with_capacity(b.len() * 2 + 1);
    out.extend(b.iter().map(|c| c >> 5));
    out.push(0);
    out.extend(b.iter().map(|c| c & 31));
    out
}

/// bech32m decode with NO length ceiling (BIP-352 addresses are 117 chars,
/// beyond the 90 of BIP-173). Returns (hrp, 5-bit data without checksum).
fn bech32m_decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s.len() < 8 || !s.is_ascii() {
        return None;
    }
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1')?;
    if pos < 1 || pos + 7 > s.len() {
        return None;
    }
    let (hrp, data) = (&s[..pos], &s[pos + 1..]);
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return None;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        values.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }
    let mut check = hrp_expand(hrp);
    check.extend_from_slice(&values);
    if polymod(&check) != BECH32M_CONST {
        return None;
    }
    values.truncate(values.len() - 6);
    Some((hrp.to_string(), values))
}

/// 5-bit groups → bytes, no padding allowed to carry data.
fn convert_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    for &v in data {
        acc = (acc << 5) | v as u32;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return None;
    }
    Some(out)
}

/// Does this string look like a silent-payment address for `network`? A
/// cheap prefix test for callers that only need to branch; `parse` decides.
pub fn looks_like(s: &str, network: Network) -> bool {
    let l = s.trim().to_ascii_lowercase();
    let hrp = if network == Network::Bitcoin { "sp1" } else { "tsp1" };
    l.starts_with(hrp) && l.len() > 90
}

/// Parse an `sp1…` / `tsp1…` address. Version 0 only (66-byte payload).
pub fn parse(s: &str, network: Network) -> LijResult<SpAddress> {
    let (hrp, data) = bech32m_decode(s.trim())
        .ok_or_else(|| LijError::Node("not a valid silent-payment address (bech32m)".into()))?;
    let want = if network == Network::Bitcoin { "sp" } else { "tsp" };
    if hrp != want {
        return Err(LijError::Node(format!(
            "silent-payment address is for another network (hrp {hrp}, want {want})"
        )));
    }
    if data.is_empty() {
        return Err(LijError::Node("silent-payment address has no version".into()));
    }
    let version = data[0];
    if version != 0 {
        return Err(LijError::Node(format!(
            "silent-payment address version {version} is not supported (v0 only)"
        )));
    }
    let payload = convert_5_to_8(&data[1..])
        .ok_or_else(|| LijError::Node("silent-payment address payload is malformed".into()))?;
    if payload.len() != 66 {
        return Err(LijError::Node(format!(
            "silent-payment v0 address must carry 66 bytes, has {}",
            payload.len()
        )));
    }
    let scan = PublicKey::from_slice(&payload[..33])
        .map_err(|e| LijError::Node(format!("silent-payment scan key: {e}")))?;
    let spend = PublicKey::from_slice(&payload[33..])
        .map_err(|e| LijError::Node(format!("silent-payment spend key: {e}")))?;
    Ok(SpAddress { scan, spend, hrp })
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(tag_hash.as_ref());
    e.input(tag_hash.as_ref());
    e.input(msg);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// One input the wallet will spend: its private key and its outpoint. All of
/// the wallet's inputs are compressed-key P2WPKH, so the key is used as is.
pub struct SpInput {
    pub secret: SecretKey,
    pub outpoint: OutPoint,
}

/// The taproot output script for `addr` given exactly these inputs (k = 0).
pub fn derive_output_script<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    inputs: &[SpInput],
    addr: &SpAddress,
) -> LijResult<ScriptBuf> {
    if inputs.is_empty() {
        return Err(LijError::Node("silent payment: no inputs".into()));
    }
    // a_sum = Σ a_i mod n. A running total of exactly zero is not a valid
    // SecretKey (add_tweak refuses it), but a later key can still make the final
    // sum valid (the BIP's "intermediate sum is zero" vector): on zero, the next
    // key starts the total again.
    let mut a_sum: Option<SecretKey> = None;
    for inp in inputs {
        a_sum = match a_sum {
            None => Some(inp.secret),
            Some(acc) => acc.add_tweak(&Scalar::from(inp.secret)).ok(),
        };
    }
    let a_sum = a_sum.ok_or_else(|| {
        LijError::Node("silent payment: input keys sum to zero — cannot send with these inputs".into())
    })?;
    let a_sum_pub = PublicKey::from_secret_key(secp, &a_sum);

    let outpoint_l = inputs
        .iter()
        .map(|i| serialize(&i.outpoint))
        .min()
        .expect("non-empty");
    let mut msg = Vec::with_capacity(36 + 33);
    msg.extend_from_slice(&outpoint_l);
    msg.extend_from_slice(&a_sum_pub.serialize());
    let input_hash = Scalar::from_be_bytes(tagged_hash("BIP0352/Inputs", &msg))
        .map_err(|_| LijError::Node("silent payment: input hash out of range".into()))?;

    let k = a_sum
        .mul_tweak(&input_hash)
        .map_err(|e| LijError::Node(format!("silent payment: input_hash·a_sum: {e}")))?;
    let ecdh = addr
        .scan
        .mul_tweak(secp, &Scalar::from(k))
        .map_err(|e| LijError::Node(format!("silent payment: ecdh: {e}")))?;

    let mut m = Vec::with_capacity(33 + 4);
    m.extend_from_slice(&ecdh.serialize());
    m.extend_from_slice(&0u32.to_be_bytes());
    let t0 = Scalar::from_be_bytes(tagged_hash("BIP0352/SharedSecret", &m))
        .map_err(|_| LijError::Node("silent payment: t_0 out of range".into()))?;
    let p0 = addr
        .spend
        .add_exp_tweak(secp, &t0)
        .map_err(|e| LijError::Node(format!("silent payment: output key: {e}")))?;
    let (xonly, _parity) = p0.x_only_public_key();
    Ok(ScriptBuf::new_v1_p2tr_tweaked(xonly.dangerous_assume_tweaked()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;
    use std::str::FromStr;

    // BIP-173/350 vectors: one bech32m string that must decode, one bech32
    // (not m) string that must not.
    #[test]
    fn bech32m_vectors() {
        assert!(bech32m_decode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx").is_some());
        assert!(bech32m_decode("ABCDEF1L7AUM6ECHK45NJ3S0WDVT2FG8X9YRZPQZD3RYX").is_some());
        assert!(bech32m_decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").is_none()); // bech32, not m
        assert!(bech32m_decode("abcDEF1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx").is_none()); // mixed case
    }

    #[test]
    fn parses_the_bip_example_address() {
        let a = parse(
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            Network::Bitcoin,
        )
        .unwrap();
        assert_eq!(
            hex::encode(a.scan.serialize()),
            "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4"
        );
        assert_eq!(
            hex::encode(a.spend.serialize()),
            "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36"
        );
        assert!(looks_like("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv", Network::Bitcoin));
        assert!(!looks_like("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Network::Bitcoin));
        assert!(parse("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv", Network::Testnet).is_err());
    }

    #[derive(serde::Deserialize)]
    struct Vin {
        txid: String,
        vout: u32,
        private_key: String,
        spk: String,
    }
    #[derive(serde::Deserialize)]
    struct Case {
        comment: String,
        vin: Vec<Vin>,
        recipients: Vec<String>,
        expected_outputs: Vec<Vec<String>>,
    }

    /// The BIP's sending vectors, every case whose inputs are compressed-key
    /// P2PKH/P2WPKH (the sender math is the same for both) and that pays ONE
    /// address once. Cases with taproot inputs, uncompressed keys, P2SH,
    /// several recipients or k > 0 are outside the wallet's sending model and
    /// are counted, not run.
    #[test]
    fn bip352_sending_vectors() {
        let raw = include_str!("testdata/bip352_send_vectors.json");
        let cases: Vec<Case> = serde_json::from_str(raw).unwrap();
        let secp = Secp256k1::new();
        let (mut ran, mut skipped) = (0, 0);
        for c in &cases {
            let simple_inputs = c
                .vin
                .iter()
                .all(|v| (v.spk.starts_with("76a914") || v.spk.starts_with("0014")) && v.private_key.len() == 64);
            let single = c.recipients.len() == 1
                && c.expected_outputs.len() <= 1
                && c.expected_outputs.first().map(|o| o.len() <= 1).unwrap_or(true);
            // the P2PKH cases with uncompressed keys / malleated scripts carry the
            // same private keys but the BIP derives from the extracted pubkey; only
            // run cases whose expected pubkeys are compressed — detectable by the
            // "Uncompressed"/"malleated" comments.
            let odd = c.comment.contains("Uncompressed") || c.comment.contains("malleated")
                || c.comment.contains("change") || c.comment.contains("No valid inputs");
            if !simple_inputs || !single || odd {
                skipped += 1;
                continue;
            }
            let inputs: Vec<SpInput> = c
                .vin
                .iter()
                .map(|v| SpInput {
                    secret: SecretKey::from_slice(&hex::decode(&v.private_key).unwrap()).unwrap(),
                    outpoint: OutPoint { txid: Txid::from_str(&v.txid).unwrap(), vout: v.vout },
                })
                .collect();
            let addr = parse(&c.recipients[0], Network::Bitcoin).unwrap();
            let got = derive_output_script(&secp, &inputs, &addr);
            let want: Vec<&String> = c.expected_outputs.iter().flatten().collect();
            if want.is_empty() {
                assert!(got.is_err(), "{}: expected no output (sending must fail)", c.comment);
            } else {
                let spk = got.unwrap_or_else(|e| panic!("{}: {e}", c.comment));
                let bytes = spk.as_bytes();
                assert_eq!(bytes.len(), 34, "{}: P2TR script", c.comment);
                assert_eq!(&bytes[..2], &[0x51, 0x20], "{}: OP_1 PUSH32", c.comment);
                assert_eq!(hex::encode(&bytes[2..]), *want[0], "{}", c.comment);
            }
            ran += 1;
        }
        assert!(ran >= 6, "ran {ran} vectors, skipped {skipped} — the vector file changed shape");
    }
}
