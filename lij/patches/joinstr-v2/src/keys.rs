use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::key::{TweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{NetworkKind, ScriptBuf};
use musig2::KeyAggContext;
use secp::{Point, Scalar};

/// BIP328 chaincode, SHA256("MuSig2MuSig2MuSig2").
const BIP328_CHAINCODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// The MuSig2 keys of a pool and the pool outputs derived from them,
/// `tr(musig(K1,...,KN)/0/*)`.
#[derive(Clone, Debug)]
pub struct PoolKeys {
    pub keys: Vec<Point>,
    pub xpub: Xpub,
    base: KeyAggContext,
    child0: Xpub,
    t0: Scalar,
    /// Pools with exits in any order sign thousands of exits, each needing its context
    /// several times.
    cache: Arc<Mutex<HashMap<u32, KeyAggContext>>>,
}

impl PoolKeys {
    pub fn new(mut keys: Vec<Point>) -> Result<Self> {
        if keys.is_empty() {
            return Err(anyhow!("a pool needs at least one key"));   // LiJ P7 (was a panic)
        }
        keys.sort_by_key(|k| k.serialize());
        let base = KeyAggContext::new(keys.clone())?;
        let agg: Point = base.aggregated_pubkey();
        let xpub = synthetic_xpub(&agg)?;
        let zero = ChildNumber::from_normal_idx(0)?;
        let (t0, _) = xpub.ckd_pub_tweak(zero)?;
        let child0 = xpub.ckd_pub(&Secp256k1::verification_only(), zero)?;
        Ok(Self {
            keys,
            xpub,
            base,
            child0,
            t0: Scalar::from_slice(&t0.secret_bytes())?,
            cache: Arc::default(),
        })
    }

    /// Signing context for pool output `index`: BIP32 tweaks of `0/index`, then the BIP86 tweak.
    pub fn ctx(&self, index: u32) -> Result<KeyAggContext> {
        if let Some(c) = self.cache.lock().expect("cache").get(&index) {
            return Ok(c.clone());
        }
        let (t1, _) = self
            .child0
            .ckd_pub_tweak(ChildNumber::from_normal_idx(index)?)?;
        let ctx = self
            .base
            .clone()
            .with_plain_tweak(self.t0)?
            .with_plain_tweak(Scalar::from_slice(&t1.secret_bytes())?)?
            .with_unspendable_taproot_tweak()?;
        self.cache.lock().expect("cache").insert(index, ctx.clone());
        Ok(ctx)
    }

    /// The aggregate key of all participants, before any derivation.
    pub fn aggregate(&self) -> Point {
        self.base.aggregated_pubkey()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.xpub.fingerprint()
    }

    pub fn path(index: u32) -> Result<DerivationPath> {
        Ok(DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(index)?,
        ]))
    }

    /// The internal key of pool output `index`, the child `0/index` before the BIP86 tweak.
    pub fn internal_key(&self, index: u32) -> Result<XOnlyPublicKey> {
        let child = self.child0.ckd_pub(
            &Secp256k1::verification_only(),
            ChildNumber::from_normal_idx(index)?,
        )?;
        Ok(XOnlyPublicKey::from(child.public_key))
    }

    pub fn output_key(&self, index: u32) -> Result<XOnlyPublicKey> {
        let p: Point = self.ctx(index)?.aggregated_pubkey();
        Ok(XOnlyPublicKey::from_slice(&p.serialize_xonly())?)
    }

    pub fn script_pubkey(&self, index: u32) -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(self.output_key(index)?),
        ))
    }

    pub fn descriptor(&self) -> String {
        let keys: Vec<String> = self.keys.iter().map(|k| k.to_string()).collect();
        format!("tr(musig({})/0/*)", keys.join(","))
    }
}

/// BIP328 synthetic xpub of an aggregate key.
pub fn synthetic_xpub(agg: &Point) -> Result<Xpub> {
    Ok(Xpub {
        network: NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_normal_idx(0)?,
        public_key: PublicKey::from_slice(&agg.serialize())?,
        chain_code: ChainCode::from(BIP328_CHAINCODE),
    })
}

/// LiJ P8: 33-byte compressed points only, lowercase hex — no 65-byte uncompressed or hybrid forms, no upper case.
pub fn point_from_hex(s: &str) -> Result<Point> {
    let b = crate::util::strict_hex(s, 33).map_err(|e| anyhow!("bad point: {e}"))?;
    if b[0] != 0x02 && b[0] != 0x03 {
        return Err(anyhow!("bad point: not compressed"));
    }
    Point::from_slice(&b).map_err(|e| anyhow!("bad point: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::TapTweak;
    use std::str::FromStr;

    #[test]
    fn bip328_vectors() {
        let vectors = [
            (
                vec![
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                ],
                "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
            ),
            (
                vec![
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                ],
                "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
            ),
            (
                vec![
                    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                ],
                "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
            ),
        ];
        for (keys, agg_hex, xpub) in vectors {
            // LiJ P8: the BIP's vectors are upper case; point_from_hex takes a peer's lowercase hex only
            let keys: Vec<Point> = keys.iter().map(|k| point_from_hex(&k.to_lowercase()).unwrap()).collect();
            let agg: Point = KeyAggContext::new(keys).unwrap().aggregated_pubkey();
            assert_eq!(agg.to_string(), agg_hex);
            assert_eq!(synthetic_xpub(&agg).unwrap().to_string(), xpub);
        }
    }

    #[test]
    fn output_keys_match_bip32_and_bip86() {
        let secp = Secp256k1::new();
        let keys: Vec<Point> = (1..=4u8)
            .map(|i| Scalar::from_slice(&[i; 32]).unwrap().base_point_mul())
            .collect();
        let pool = PoolKeys::new(keys).unwrap();
        for index in 0..5 {
            let path = [
                ChildNumber::from_normal_idx(0).unwrap(),
                ChildNumber::from_normal_idx(index).unwrap(),
            ];
            let child = pool.xpub.derive_pub(&secp, &path).unwrap();
            let (tweaked, _) = XOnlyPublicKey::from(child.public_key).tap_tweak(&secp, None);
            assert_eq!(
                pool.output_key(index).unwrap(),
                tweaked.to_x_only_public_key()
            );
        }
        for index in 0..5 {
            let path = PoolKeys::path(index).unwrap();
            let child = pool.xpub.derive_pub(&secp, &path).unwrap();
            assert_eq!(
                pool.internal_key(index).unwrap(),
                XOnlyPublicKey::from(child.public_key)
            );
        }
        assert!(pool.descriptor().starts_with("tr(musig(02"));
        assert!(XOnlyPublicKey::from_str(&pool.output_key(0).unwrap().to_string()).is_ok());
    }
}
