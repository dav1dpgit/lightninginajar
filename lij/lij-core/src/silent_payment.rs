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
//! RECEIVING (v284, S50 — the engine groundwork, DP's SP design of 2026-09-28): the keys at
//! m/352'/{coin}'/0'/1'/0 (scan) and m/352'/{coin}'/0'/0'/0 (spend), the sp1 address, the
//! receiver's arithmetic against a block's tweak list (the box index serves
//! `tweak = input_hash·A_sum` per eligible transaction; the phone does
//! `ecdh = b_scan·tweak`, `t_k`, `P_k = B_spend + t_k·G` and looks for x(P_k) among the
//! transaction's taproot outputs), the script of a found coin from its `t_k`, and the key that
//! spends it (`b_spend + t_k`, negated when P_k has an odd y). The tweak's own arithmetic is here
//! too (`tweak_from_inputs`) so a wallet holding a block with prevouts, or a test, can check the
//! box. See `SpKeys`.

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey};
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

/// One input the wallet will spend: its private key and its outpoint. A P2WPKH
/// input's key is used as is; a taproot input (v284: a silent-payment coin at
/// chain 352) contributes its x-only key with even y, so its secret is negated
/// when the public key's y is odd (the BIP's rule for taproot inputs).
pub struct SpInput {
    pub secret: SecretKey,
    pub outpoint: OutPoint,
    pub taproot: bool,
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
        let mut sk = inp.secret;
        if inp.taproot {
            // v284: a taproot input counts as its x-only key with even y
            let (_, parity) = PublicKey::from_secret_key(secp, &sk).x_only_public_key();
            if parity == Parity::Odd {
                sk = sk.negate();
            }
        }
        a_sum = match a_sum {
            None => Some(sk),
            Some(acc) => acc.add_tweak(&Scalar::from(sk)).ok(),
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
    Ok(ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()))
}

// ─────────────────────────────────────────────────────────────────────────────
// RECEIVE (v284, S50)
// ─────────────────────────────────────────────────────────────────────────────

/// bech32m encode (no length ceiling): `hrp` + '1' + version + payload as 5-bit groups + checksum.
pub fn bech32m_encode(hrp: &str, version: u8, payload: &[u8]) -> String {
    let mut data: Vec<u8> = vec![version];
    // 8 → 5 with padding
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in payload {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &d in &data {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

/// The wallet's own silent-payment keys — BIP-352's paths on the 12 words:
/// scan `m/352'/{coin}'/0'/1'/0`, spend `m/352'/{coin}'/0'/0'/0` (Cake's and Sparrow's,
/// so a restore into either finds the coins from the words — DP's recovery rule R3).
#[derive(Clone)]
pub struct SpKeys {
    pub scan: SecretKey,
    pub spend: SecretKey,
    pub scan_pub: PublicKey,
    pub spend_pub: PublicKey,
    pub network: Network,
}

/// A coin found by the scan: where it sits, its value, and the `t_k` that spends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpFound {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub value_sats: u64,
    /// The scalar added to the spend key for this coin (hex on the ledger record).
    pub t_k: [u8; 32],
    pub k: u32,
    /// The output script, `OP_1 <x(P_k)>`.
    pub script: ScriptBuf,
    /// Found under the change label (a seed that was used in another wallet).
    pub labelled_change: bool,
}

impl SpKeys {
    pub fn from_root(root: &crate::key::RootKey) -> LijResult<SpKeys> {
        use bitcoin::bip32::DerivationPath;
        use std::str::FromStr;
        let coin = if root.network == Network::Bitcoin { 0 } else { 1 };
        let scan = root
            .derive_priv(&DerivationPath::from_str(&format!("m/352'/{coin}'/0'/1'/0")).map_err(|e| LijError::Key(format!("{e}")))?)?
            .private_key;
        let spend = root
            .derive_priv(&DerivationPath::from_str(&format!("m/352'/{coin}'/0'/0'/0")).map_err(|e| LijError::Key(format!("{e}")))?)?
            .private_key;
        let secp = Secp256k1::new();
        Ok(SpKeys {
            scan,
            spend,
            scan_pub: PublicKey::from_secret_key(&secp, &scan),
            spend_pub: PublicKey::from_secret_key(&secp, &spend),
            network: root.network,
        })
    }

    /// The reusable address: `sp1…` (mainnet) / `tsp1…` (else), version 0, scan ‖ spend.
    pub fn address(&self) -> String {
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&self.scan_pub.serialize());
        payload.extend_from_slice(&self.spend_pub.serialize());
        bech32m_encode(if self.network == Network::Bitcoin { "sp" } else { "tsp" }, 0, &payload)
    }

    /// The change label `hash("BIP0352/Label", b_scan ‖ 0)` — the one label the BIP asks every
    /// wallet to scan for on a restore (another wallet may have paid its change to it).
    pub fn change_label(&self) -> LijResult<Scalar> {
        let mut m = Vec::with_capacity(36);
        m.extend_from_slice(&self.scan.secret_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        Scalar::from_be_bytes(tagged_hash("BIP0352/Label", &m)).map_err(|_| LijError::Node("silent payment: label out of range".into()))
    }

    /// The shared secret for one transaction's tweak: `ecdh = b_scan · tweak`.
    fn ecdh<C: Verification>(&self, secp: &Secp256k1<C>, tweak: &PublicKey) -> LijResult<PublicKey> {
        tweak
            .mul_tweak(secp, &Scalar::from(self.scan))
            .map_err(|e| LijError::Node(format!("silent payment: ecdh: {e}")))
    }

    /// `t_k` and `P_k = B_spend + t_k·G` for the k-th output of a transaction with this ecdh.
    fn output_k<C: Verification>(&self, secp: &Secp256k1<C>, ecdh: &PublicKey, k: u32) -> LijResult<([u8; 32], XOnlyPublicKey)> {
        let mut m = Vec::with_capacity(37);
        m.extend_from_slice(&ecdh.serialize());
        m.extend_from_slice(&k.to_be_bytes());
        let t_k = tagged_hash("BIP0352/SharedSecret", &m);
        let tk = Scalar::from_be_bytes(t_k).map_err(|_| LijError::Node("silent payment: t_k out of range".into()))?;
        let p = self.spend_pub.add_exp_tweak(secp, &tk).map_err(|e| LijError::Node(format!("silent payment: P_k: {e}")))?;
        Ok((t_k, p.x_only_public_key().0))
    }

    /// The candidate output scripts (k = 0) for a block's tweaks — what the phone tests against
    /// the block's BIP158 filter before it fetches the block. With `change_label`, the labelled
    /// candidates too (one point addition each).
    pub fn candidate_scripts<C: Verification>(&self, secp: &Secp256k1<C>, tweaks: &[PublicKey], change_label: bool) -> Vec<ScriptBuf> {
        let mut out = Vec::with_capacity(tweaks.len() * if change_label { 2 } else { 1 });
        let label = if change_label { self.change_label().ok() } else { None };
        for tw in tweaks {
            let Ok(ecdh) = self.ecdh(secp, tw) else { continue };
            let Ok((_, p0)) = self.output_k(secp, &ecdh, 0) else { continue };
            out.push(ScriptBuf::new_p2tr_tweaked(p0.dangerous_assume_tweaked()));
            if let Some(l) = label.as_ref() {
                if let Ok(pl) = PublicKey::from_x_only_public_key(p0, Parity::Even).add_exp_tweak(secp, l) {
                    out.push(ScriptBuf::new_p2tr_tweaked(pl.x_only_public_key().0.dangerous_assume_tweaked()));
                }
            }
        }
        out
    }

    /// Find this wallet's coins in a block: `tweaks` is the box's list for the block (order does
    /// not matter), `txs` its transactions. For each tweak, k = 0, 1, 2 … while an output matches.
    pub fn find_in_block<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        tweaks: &[PublicKey],
        txs: &[bitcoin::Transaction],
        change_label: bool,
    ) -> Vec<SpFound> {
        use std::collections::HashMap;
        // every taproot output in the block, by its x-only key
        let mut by_key: HashMap<[u8; 32], Vec<(bitcoin::Txid, u32, u64)>> = HashMap::new();
        for tx in txs {
            let txid = tx.compute_txid();
            for (i, o) in tx.output.iter().enumerate() {
                let b = o.script_pubkey.as_bytes();
                if b.len() == 34 && b[0] == 0x51 && b[1] == 0x20 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&b[2..34]);
                    by_key.entry(key).or_default().push((txid, i as u32, o.value.to_sat()));
                }
            }
        }
        self.find_by_keys(secp, tweaks, &by_key, change_label)
    }

    /// v287: the same search over one transaction's taproot outputs given as (vout, x-only key,
    /// value) — the mempool leg (the box serves an unconfirmed transaction's tweak and outputs).
    pub fn find_in_outputs<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        tweak: &PublicKey,
        txid: bitcoin::Txid,
        outputs: &[(u32, [u8; 32], u64)],
        change_label: bool,
    ) -> Vec<SpFound> {
        use std::collections::HashMap;
        let mut by_key: HashMap<[u8; 32], Vec<(bitcoin::Txid, u32, u64)>> = HashMap::new();
        for (vout, key, value) in outputs {
            by_key.entry(*key).or_default().push((txid, *vout, *value));
        }
        self.find_by_keys(secp, std::slice::from_ref(tweak), &by_key, change_label)
    }

    fn find_by_keys<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        tweaks: &[PublicKey],
        by_key: &std::collections::HashMap<[u8; 32], Vec<(bitcoin::Txid, u32, u64)>>,
        change_label: bool,
    ) -> Vec<SpFound> {
        let label = if change_label { self.change_label().ok() } else { None };
        let mut found = Vec::new();
        for tw in tweaks {
            let Ok(ecdh) = self.ecdh(secp, tw) else { continue };
            let mut k = 0u32;
            loop {
                let Ok((t_k, p)) = self.output_k(secp, &ecdh, k) else { break };
                let mut hit = false;
                if let Some(v) = by_key.get(&p.serialize()) {
                    for (txid, vout, value) in v {
                        found.push(SpFound { txid: *txid, vout: *vout, value_sats: *value, t_k, k, script: ScriptBuf::new_p2tr_tweaked(p.dangerous_assume_tweaked()), labelled_change: false });
                    }
                    hit = true;
                }
                if let Some(l) = label.as_ref() {
                    if let Ok(pl) = PublicKey::from_x_only_public_key(p, Parity::Even).add_exp_tweak(secp, l) {
                        let xl = pl.x_only_public_key().0;
                        if let Some(v) = by_key.get(&xl.serialize()) {
                            // t for a labelled output = t_k + label
                            let tl = Scalar::from_be_bytes(t_k).ok().and_then(|t| SecretKey::from_slice(&t.to_be_bytes()).ok()).and_then(|sk| sk.add_tweak(l).ok());
                            if let Some(tl) = tl {
                                for (txid, vout, value) in v {
                                    found.push(SpFound { txid: *txid, vout: *vout, value_sats: *value, t_k: tl.secret_bytes(), k, script: ScriptBuf::new_p2tr_tweaked(xl.dangerous_assume_tweaked()), labelled_change: true });
                                }
                                hit = true;
                            }
                        }
                    }
                }
                if !hit || k >= 10_000 {
                    break;
                }
                k += 1;
            }
        }
        found
    }

    /// The script of a coin from its stored `t_k` (the forward walk adds it to the filter query,
    /// so a spend of the coin is seen).
    pub fn script_for<C: Verification>(&self, secp: &Secp256k1<C>, t_k: &[u8; 32]) -> LijResult<ScriptBuf> {
        let tk = Scalar::from_be_bytes(*t_k).map_err(|_| LijError::Node("silent payment: t_k out of range".into()))?;
        let p = self.spend_pub.add_exp_tweak(secp, &tk).map_err(|e| LijError::Node(format!("silent payment: P_k: {e}")))?;
        Ok(ScriptBuf::new_p2tr_tweaked(p.x_only_public_key().0.dangerous_assume_tweaked()))
    }

    /// The key that spends a coin: `b_spend + t_k`, negated when `P_k` has an odd y (a taproot
    /// key-path signature is over the x-only key with even y).
    pub fn spend_secret<C: Signing + Verification>(&self, secp: &Secp256k1<C>, t_k: &[u8; 32]) -> LijResult<SecretKey> {
        let tk = Scalar::from_be_bytes(*t_k).map_err(|_| LijError::Node("silent payment: t_k out of range".into()))?;
        let sk = self.spend.add_tweak(&tk).map_err(|e| LijError::Node(format!("silent payment: spend key: {e}")))?;
        let (_, parity) = PublicKey::from_secret_key(secp, &sk).x_only_public_key();
        Ok(if parity == Parity::Odd { sk.negate() } else { sk })
    }
}

/// The tweak the box index serves for a transaction, from its inputs' public keys and outpoints:
/// `input_hash · A_sum` (None when the keys sum to the point at infinity, or nothing is eligible).
/// A wallet holding a block with prevouts can check the box with it; the tests do.
pub fn tweak_from_inputs<C: Verification>(secp: &Secp256k1<C>, keys: &[PublicKey], outpoints: &[OutPoint]) -> Option<PublicKey> {
    if keys.is_empty() || outpoints.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let a_sum = PublicKey::combine_keys(&refs).ok()?;
    let outpoint_l = outpoints.iter().map(serialize).min()?;
    let mut msg = Vec::with_capacity(69);
    msg.extend_from_slice(&outpoint_l);
    msg.extend_from_slice(&a_sum.serialize());
    let ih = Scalar::from_be_bytes(tagged_hash("BIP0352/Inputs", &msg)).ok()?;
    a_sum.mul_tweak(secp, &ih).ok()
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
            // v284: taproot inputs run too (the parity rule) — a NUMS script-path input stays skipped (the wallet never has one)
            let simple_inputs = c
                .vin
                .iter()
                .all(|v| (v.spk.starts_with("76a914") || v.spk.starts_with("0014") || v.spk.starts_with("5120")) && v.private_key.len() == 64)
                && !c.comment.contains("NUMS") && !c.comment.contains("K_max");   // K_max is the reference scanner's own cap, not a sending rule
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
                .map(|v| SpInput { taproot: v.spk.starts_with("5120"),
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
        assert!(ran >= 9, "ran {ran} vectors, skipped {skipped} — the vector file changed shape");
    }

    // ── v284 (S50): the receive side ──

    fn test_keys() -> SpKeys {
        let mnemonic: bip39::Mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap();
        let root = crate::key::RootKey::from_mnemonic(&mnemonic, Network::Bitcoin).unwrap();
        SpKeys::from_root(&root).unwrap()
    }

    #[test]
    fn bech32m_encode_round_trips_the_vectors_address() {
        let sp = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
        let a = parse(sp, Network::Bitcoin).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&a.scan.serialize());
        payload.extend_from_slice(&a.spend.serialize());
        assert_eq!(bech32m_encode("sp", 0, &payload), sp);
        // BIP-350's own vector: "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx" decodes to 5-bit values 31..0
        let (hrp, data) = bech32m_decode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx").unwrap();
        assert_eq!(hrp, "abcdef");
        assert_eq!(data, (0..32u8).rev().collect::<Vec<u8>>());
    }

    #[test]
    fn own_address_parses_back_to_own_keys() {
        let k = test_keys();
        let s = k.address();
        assert!(s.starts_with("sp1q") && s.len() == 116, "{s}");   // 2 + 1 + 1 + 106 + 6
        let a = parse(&s, Network::Bitcoin).unwrap();
        assert_eq!(a.scan, k.scan_pub);
        assert_eq!(a.spend, k.spend_pub);
        assert!(looks_like(&s, Network::Bitcoin));
    }

    #[test]
    fn known_paths_for_the_test_words() {
        // Sparrow/Cake derive at m/352'/0'/0'/1'/0 (scan) and m/352'/0'/0'/0'/0 (spend); the keys are
        // pinned so a later refactor cannot silently move them (the words' recovery in another wallet).
        let k = test_keys();
        let secp = Secp256k1::new();
        assert_eq!(PublicKey::from_secret_key(&secp, &k.scan), k.scan_pub);
        let root = crate::key::RootKey::from_mnemonic(&"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(), Network::Bitcoin).unwrap();
        let scan2 = root.derive_priv(&bitcoin::bip32::DerivationPath::from_str("m/352'/0'/0'/1'/0").unwrap()).unwrap().private_key;
        assert_eq!(scan2, k.scan);
        let spend2 = root.derive_priv(&bitcoin::bip32::DerivationPath::from_str("m/352'/0'/0'/0'/0").unwrap()).unwrap().private_key;
        assert_eq!(spend2, k.spend);
    }

    /// The round trip that proves the receive side: the SENDER (vector-checked) pays this wallet's
    /// sp1 from two P2WPKH inputs; the box's arithmetic (`tweak_from_inputs`) yields the tweak; the
    /// RECEIVER finds the output in the block with only the tweak and its scan key, records `t_k`,
    /// rebuilds the script from `t_k`, and its spending key signs for the output's x-only key.
    #[test]
    fn sender_to_receiver_round_trip_with_the_box_tweak() {
        let secp = Secp256k1::new();
        let k = test_keys();
        let addr = parse(&k.address(), Network::Bitcoin).unwrap();
        // two sender inputs (P2WPKH) with fixed keys
        let a1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let op1 = OutPoint { txid: Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16").unwrap(), vout: 0 };
        let op2 = OutPoint { txid: Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap(), vout: 1 };
        let inputs = vec![SpInput { secret: a1, outpoint: op1, taproot: false }, SpInput { secret: a2, outpoint: op2, taproot: false }];
        let paid_script = derive_output_script(&secp, &inputs, &addr).unwrap();
        // the box: tweak = input_hash·A_sum from the PUBLIC keys and outpoints
        let pubs = vec![PublicKey::from_secret_key(&secp, &a1), PublicKey::from_secret_key(&secp, &a2)];
        let tweak = tweak_from_inputs(&secp, &pubs, &[op1, op2]).unwrap();
        // the block: the paying transaction plus a decoy with a taproot output nobody owns
        let pay_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn { previous_output: op1, script_sig: ScriptBuf::new(), sequence: bitcoin::Sequence::MAX, witness: bitcoin::Witness::new() }],
            output: vec![
                bitcoin::TxOut { value: bitcoin::Amount::from_sat(5_000), script_pubkey: ScriptBuf::new_p2tr_tweaked(XOnlyPublicKey::from_slice(&[9u8; 32]).unwrap().dangerous_assume_tweaked()) },
                bitcoin::TxOut { value: bitcoin::Amount::from_sat(184_000), script_pubkey: paid_script.clone() },
            ],
        };
        let decoy = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![],
            output: vec![bitcoin::TxOut { value: bitcoin::Amount::from_sat(1), script_pubkey: ScriptBuf::new_p2tr_tweaked(XOnlyPublicKey::from_slice(&[7u8; 32]).unwrap().dangerous_assume_tweaked()) }],
        };
        let decoy_tweak = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        // the filter candidates carry the paid script
        let cands = k.candidate_scripts(&secp, &[decoy_tweak, tweak], false);
        assert_eq!(cands.len(), 2);
        assert!(cands.contains(&paid_script));
        // the receiver finds exactly the paid output
        let found = k.find_in_block(&secp, &[decoy_tweak, tweak], &[decoy.clone(), pay_tx.clone()], true);
        assert_eq!(found.len(), 1, "{found:?}");
        let f = &found[0];
        assert_eq!((f.txid, f.vout, f.value_sats, f.k, f.labelled_change), (pay_tx.compute_txid(), 1, 184_000, 0, false));
        assert_eq!(f.script, paid_script);
        // the script comes back from t_k alone (what the ledger stores)
        assert_eq!(k.script_for(&secp, &f.t_k).unwrap(), paid_script);
        // the spending key signs for the output's x-only key
        let sk = k.spend_secret(&secp, &f.t_k).unwrap();
        let (xonly, parity) = PublicKey::from_secret_key(&secp, &sk).x_only_public_key();
        assert_eq!(parity, Parity::Even);
        assert_eq!(&paid_script.as_bytes()[2..], &xonly.serialize()[..]);
        let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
        let msg = bitcoin::secp256k1::Message::from_digest([5u8; 32]);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        assert!(secp.verify_schnorr(&sig, &msg, &xonly).is_ok());
        // a wrong tweak finds nothing; the wallet's own words on another network give another address
        assert!(k.find_in_block(&secp, &[decoy_tweak], &[pay_tx.clone()], true).is_empty());
    }

    #[test]
    fn two_outputs_to_the_same_wallet_in_one_transaction_are_both_found() {
        let secp = Secp256k1::new();
        let k = test_keys();
        let addr = parse(&k.address(), Network::Bitcoin).unwrap();
        let a1 = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let op1 = OutPoint { txid: Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16").unwrap(), vout: 3 };
        // k = 0 from the sender code; k = 1 by hand (the same ecdh, the next hash)
        let s0 = derive_output_script(&secp, &[SpInput { secret: a1, outpoint: op1, taproot: false }], &addr).unwrap();
        let tweak = tweak_from_inputs(&secp, &[PublicKey::from_secret_key(&secp, &a1)], &[op1]).unwrap();
        let ecdh = k.ecdh(&secp, &tweak).unwrap();
        let (_, p1) = k.output_k(&secp, &ecdh, 1).unwrap();
        let s1 = ScriptBuf::new_p2tr_tweaked(p1.dangerous_assume_tweaked());
        assert_ne!(s0, s1);
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![],
            output: vec![bitcoin::TxOut { value: bitcoin::Amount::from_sat(10), script_pubkey: s1.clone() }, bitcoin::TxOut { value: bitcoin::Amount::from_sat(20), script_pubkey: s0.clone() }],
        };
        let found = k.find_in_block(&secp, &[tweak], &[tx], false);
        let mut got: Vec<(u32, u32, u64)> = found.iter().map(|f| (f.k, f.vout, f.value_sats)).collect();
        got.sort();
        assert_eq!(got, vec![(0, 1, 20), (1, 0, 10)]);
    }

    #[test]
    fn a_taproot_input_with_odd_y_is_negated_on_the_sending_side() {
        // the BIP's rule, checked against the receiver: a sender whose taproot input key has odd y
        // negates the secret; the receiver (public data only) lifts the x-only key to even y — both
        // sides must agree or the payment is lost.
        let secp = Secp256k1::new();
        let k = test_keys();
        let addr = parse(&k.address(), Network::Bitcoin).unwrap();
        let mut sk = SecretKey::from_slice(&[11u8; 32]).unwrap();
        // pick a key with odd y
        while PublicKey::from_secret_key(&secp, &sk).x_only_public_key().1 == Parity::Even {
            sk = sk.add_tweak(&Scalar::ONE).unwrap();
        }
        let op = OutPoint { txid: Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap(), vout: 0 };
        let script = derive_output_script(&secp, &[SpInput { secret: sk, outpoint: op, taproot: true }], &addr).unwrap();
        let (xonly, _) = PublicKey::from_secret_key(&secp, &sk).x_only_public_key();
        let even = PublicKey::from_x_only_public_key(xonly, Parity::Even);
        let tweak = tweak_from_inputs(&secp, &[even], &[op]).unwrap();
        assert_eq!(k.candidate_scripts(&secp, &[tweak], false), vec![script]);
    }
}
