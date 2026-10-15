//! Nostr wire format: the kind 2022 pool event and the NIP-4 channel messages.

use serde::{Deserialize, Serialize};

use anyhow::{bail, Result};

use crate::funding::Proof;
use crate::pool::{default_exits, Class, FeeSplit, Params, PayoutType, Structure};
use crate::ring::RingSig;

pub const VERSION: &str = "2";
pub const POOL_KIND: u16 = 2022;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Broadcast {
    /// Broadcast the funding transaction and every exit at once, in waves.
    #[default]
    Now,
    /// Broadcast each exit only after the transaction it spends confirmed.
    Staggered,
    /// Broadcast the funding transaction only. Every peer leaves when it wants.
    Hold,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vpn {
    pub enable: bool,
    pub vpn_gateway: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tor {
    pub enable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transport {
    pub vpn: Vpn,
    pub tor: Tor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolEvent {
    pub versions: Vec<String>,
    pub id: String,
    pub network: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub public_key: String,
    pub denomination: u64,
    pub peers: usize,
    pub timeout: u64,
    pub relays: Vec<String>,
    pub fee_rate: f64,
    #[serde(default)]
    pub broadcast: Broadcast,
    /// Several denominations sharing the pool, each with its number of peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denominations: Option<Vec<Class>>,
    /// Payouts per exit, in chain order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exits: Option<Vec<usize>>,
    /// Fee rate of the first and the last exit in sat/vB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_fee_rates: Option<[f64; 2]>,
    #[serde(default)]
    pub fee_split: FeeSplit,
    /// `"p2a"` adds an anchor output to every exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// How the pre-signed exits leave the pool, a chain when absent.
    #[serde(default, skip_serializing_if = "is_chain")]
    pub structure: Structure,
    /// P1 (LiJ): what every payout is — P2TR when absent, `"p2wsh"` for a channel pool (a channel's 2-of-2).
    #[serde(default, skip_serializing_if = "is_p2tr")]
    pub payout_type: PayoutType,
    pub transport: Transport,
}

fn is_chain(s: &Structure) -> bool {
    *s == Structure::Chain
}

fn is_p2tr(p: &PayoutType) -> bool {
    *p == PayoutType::P2tr
}

/// LiJ P6: a fee rate is finite, positive and at most the cap — 1e300 no longer becomes u64::MAX.
fn milli(rate: f64) -> Result<u64> {
    let cap = crate::pool::MAX_FEE_RATE_MILLI as f64;
    if !(rate.is_finite() && rate > 0.0 && rate * 1000.0 <= cap) {
        bail!("fee rate {rate} out of range");
    }
    Ok((rate * 1000.0).round() as u64)
}

impl PoolEvent {
    /// LiJ P8: the strict parse a LiJ phone uses for a pool announcement — no field the event does not have (so no
    /// `autct`), the pool id 32 lowercase hex characters (upstream makes 16 random bytes), the pool key the pool's nostr
    /// key (32 bytes x-only — P11), and fee rates in whole thousandths of a sat/vB (P11; review finding 11 had asked for
    /// whole numbers, which the public code does not keep to).
    pub fn parse_strict(s: &str) -> Result<PoolEvent> {
        // P1 (v332, DP's first channel pool 2026-10-13): `payout_type` is a field of the event — the creating phone parses
        // its own announcement with this list, and a channel pool's carries "p2wsh" (the list lacked it: every create
        // stopped with "unknown field in the pool event").
        const FIELDS: &[&str] = &["versions", "id", "network", "type", "public_key", "denomination", "peers", "timeout",
            "relays", "fee_rate", "broadcast", "denominations", "exits", "exit_fee_rates", "fee_split", "anchor",
            "structure", "payout_type", "transport"];
        let v: serde_json::Value = serde_json::from_str(s)?;
        let Some(o) = v.as_object() else { bail!("a pool event is a JSON object") };
        for k in o.keys() {
            if !FIELDS.contains(&k.as_str()) {
                bail!("unknown field in the pool event");
            }
        }
        let e: PoolEvent = serde_json::from_value(v)?;
        crate::util::strict_hex(&e.id, 16).map_err(|_| anyhow::anyhow!("the pool id is not 32 lowercase hex characters"))?;
        // P11 (LiJ S59, the compatibility proof): `public_key` is the pool's NOSTR key — 32 bytes, x-only, as upstream's
        // peer writes it (`keys.public_key().to_hex()`) and checks it (the announcement's author must equal it); P8 had
        // asked for a compressed point, which no upstream pool carries. Fee rates: a finite, positive number with at most
        // three decimals (upstream takes any f64; the builders work in thousandths of a sat/vB, so a rate that is not a
        // whole number of thousandths would round differently on different sides).
        crate::util::strict_hex(&e.public_key, 32).map_err(|_| anyhow::anyhow!("the pool key is not 32 bytes of lowercase hex"))?;
        let milli_ok = |r: f64| r.is_finite() && r > 0.0 && ((r * 1000.0) - (r * 1000.0).round()).abs() < 1e-6;   // 1.001 × 1000 is not exactly 1001 in binary
        if !milli_ok(e.fee_rate) || !e.exit_fee_rates.map_or(true, |r| milli_ok(r[0]) && milli_ok(r[1])) {
            bail!("fee rates are sat/vB with at most three decimals");
        }
        Ok(e)
    }

    pub fn params(&self) -> Result<Params> {
        let fee_rate_milli = milli(self.fee_rate)?;
        let rates = self
            .exit_fee_rates
            .unwrap_or([self.fee_rate, self.fee_rate]);
        let anchor = match self.anchor.as_deref() {
            None => false,
            Some("p2a") => true,
            Some(other) => bail!("unknown anchor type {other}"),
        };
        let classes = self.denominations.clone().unwrap_or_else(|| {
            vec![Class {
                amount: self.denomination,
                peers: self.peers,
            }]
        });
        let mut params = Params::with_classes(&self.id, classes, fee_rate_milli);
        if params.peers != self.peers {
            bail!("the denominations do not add up to {} peers", self.peers);
        }
        params.exits = self
            .exits
            .clone()
            .unwrap_or_else(|| default_exits(self.peers));
        params.exit_rates_milli = (milli(rates[0])?, milli(rates[1])?);
        params.payout_type = self.payout_type;
        params.fee_split = self.fee_split;
        params.anchor = anchor;
        params.structure = self.structure;
        params.validate()?;
        Ok(params)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct InputMsg {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: String,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct ChangeMsg {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct WitnessMsg {
    pub txid: String,
    pub vout: u32,
    pub witness: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct Credentials {
    pub id: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Msg {
    JoinPool {},
    Credentials {
        credentials: Credentials,
    },
    Reject {
        reason: String,
    },
    Inputs {
        musig_pubkey: String,
        ring_pubkey: String,
        inputs: Vec<InputMsg>,
        change: Option<ChangeMsg>,
        height: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denomination: Option<u64>,
    },
    Output {
        address: String,
        ring_sig: RingSig,
        #[serde(default, skip_serializing_if = "is_zero")]
        priority: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denomination: Option<u64>,
    },
    /// Nonces for the exits from `offset` on, so that a pool with thousands of exits sends
    /// them in several messages.
    Nonces {
        #[serde(default, skip_serializing_if = "is_zero_usize")]
        offset: usize,
        nonces: Vec<String>,
    },
    PartialSigs {
        #[serde(default, skip_serializing_if = "is_zero_usize")]
        offset: usize,
        sigs: Vec<String>,
    },
    FundingSigs {
        witnesses: Vec<WitnessMsg>,
    },
    Abort {
        reason: String,
    },
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

/// Most nonces in one message, about 27 kB of JSON.
pub const NONCES_PER_MSG: usize = 200;
/// Most partial signatures in one message.
pub const SIGS_PER_MSG: usize = 400;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    #[serde(flatten)]
    pub msg: Msg,
}

/// LiJ P8: the fields each message type may carry (besides "version" and "type").
fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "join_pool" => &[],
        "credentials" => &["credentials"],
        "reject" | "abort" => &["reason"],
        "inputs" => &["musig_pubkey", "ring_pubkey", "inputs", "change", "height", "denomination"],
        "output" => &["address", "ring_sig", "priority", "denomination"],
        "nonces" => &["offset", "nonces"],
        "partial_sigs" => &["offset", "sigs"],
        "funding_sigs" => &["witnesses"],
        _ => return None,
    })
}

impl Envelope {
    /// LiJ P8: the strict parse a LiJ phone uses for every pool message — version "2" only, a known type, no field the
    /// type does not have (serde cannot refuse unknown fields through `flatten`), then the ordinary parse.
    pub fn parse_strict(s: &str) -> Result<Envelope> {
        let v: serde_json::Value = serde_json::from_str(s)?;
        let Some(o) = v.as_object() else { bail!("a message is a JSON object") };
        if o.get("version").and_then(|x| x.as_str()) != Some(VERSION) {
            bail!("unknown version");
        }
        let kind = o.get("type").and_then(|x| x.as_str()).unwrap_or("");
        let Some(allowed) = allowed_fields(kind) else { bail!("unknown message type") };
        for k in o.keys() {
            if k != "version" && k != "type" && !allowed.contains(&k.as_str()) {
                bail!("unknown field in a {kind} message");
            }
        }
        Ok(serde_json::from_value(v)?)
    }

    pub fn json(msg: Msg) -> String {
        serde_json::to_string(&Envelope {
            version: VERSION.into(),
            msg,
        })
        .expect("serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shape() {
        let s = Envelope::json(Msg::Nonces {
            offset: 0,
            nonces: vec!["ab".into()],
        });
        assert_eq!(s, r#"{"version":"2","type":"nonces","nonces":["ab"]}"#);
        let s = Envelope::json(Msg::PartialSigs {
            offset: 400,
            sigs: vec!["cd".into()],
        });
        assert_eq!(
            s,
            r#"{"version":"2","type":"partial_sigs","offset":400,"sigs":["cd"]}"#
        );
        let e: Envelope = serde_json::from_str(r#"{"type":"join_pool","version":"2"}"#).unwrap();
        assert_eq!(e.msg, Msg::JoinPool {});
        let e: Envelope = serde_json::from_str(r#"{"version":"2","type":"inputs","musig_pubkey":"02","ring_pubkey":"03","inputs":[],"change":null,"height":7}"#).unwrap();
        assert!(matches!(
            e.msg,
            Msg::Inputs {
                height: 7,
                change: None,
                ..
            }
        ));
    }

    #[test]
    fn every_message_roundtrips() {
        let msgs = vec![
            Msg::JoinPool {},
            Msg::Credentials {
                credentials: Credentials {
                    id: "a".into(),
                    key: "b".into(),
                },
            },
            Msg::Reject {
                reason: "pool is full".into(),
            },
            Msg::Inputs {
                musig_pubkey: "02aa".into(),
                ring_pubkey: "03bb".into(),
                inputs: vec![InputMsg {
                    txid: "cc".into(),
                    vout: 1,
                    amount: 2,
                    script_pubkey: "5120".into(),
                    proof: Proof {
                        sig: "00".into(),
                        pubkey: None,
                    },
                }],
                change: Some(ChangeMsg {
                    address: "tb1q".into(),
                    amount: 3,
                }),
                height: 4,
                denomination: Some(50_000),
            },
            Msg::Output {
                address: "tb1p".into(),
                ring_sig: RingSig {
                    key_image: "02".into(),
                    c0: "00".into(),
                    s: vec!["01".into()],
                },
                priority: 0,
                denomination: None,
            },
            Msg::Output {
                address: "tb1p".into(),
                ring_sig: RingSig {
                    key_image: "02".into(),
                    c0: "00".into(),
                    s: vec!["01".into()],
                },
                priority: 3,
                denomination: Some(10_000),
            },
            Msg::Nonces {
                offset: 0,
                nonces: vec!["ab".into()],
            },
            Msg::Nonces {
                offset: 200,
                nonces: vec!["ab".into()],
            },
            Msg::PartialSigs {
                offset: 0,
                sigs: vec!["cd".into()],
            },
            Msg::FundingSigs {
                witnesses: vec![WitnessMsg {
                    txid: "ef".into(),
                    vout: 0,
                    witness: vec!["00".into()],
                }],
            },
            Msg::Abort { reason: "x".into() },
        ];
        for m in msgs {
            let s = Envelope::json(m.clone());
            let back: Envelope = serde_json::from_str(&s).unwrap();
            assert_eq!(back.msg, m);
            assert_eq!(back.version, VERSION);
            assert!(!s.contains("\"pubkey\":null"));
        }
    }

    #[test]
    fn pool_event_defaults_and_unknown_fields() {
        let e: PoolEvent = serde_json::from_str(
            r#"{"versions":["2"],"id":"x","network":"signet","type":"new_pool","public_key":"ab","denomination":100000,"peers":5,"timeout":1,"relays":["wss://r"],"fee_rate":2,"transport":{"vpn":{"enable":false,"vpn_gateway":null},"tor":{"enable":true}},"autct":{"keyset":"k"}}"#,
        )
        .unwrap();
        assert_eq!(e.broadcast, Broadcast::Now);
        assert_eq!(e.fee_rate, 2.0);
        assert_eq!(e.denomination, 100_000);
        let p = e.params().unwrap();
        assert_eq!(p.exits, vec![1, 1, 1, 2]);
        assert_eq!(p.exit_rates_milli, (2_000, 2_000));
        assert!(!p.anchor);
        let e: PoolEvent = serde_json::from_str(
            r#"{"versions":["2"],"id":"x","network":"signet","type":"new_pool","public_key":"ab","denomination":50000,"peers":6,"timeout":1,"relays":["wss://r"],"fee_rate":2,"exits":[1,3,2],"exit_fee_rates":[10,2.5],"fee_split":"by_exit","anchor":"p2a","transport":{"vpn":{"enable":false,"vpn_gateway":null},"tor":{"enable":true}}}"#,
        )
        .unwrap();
        let p = e.params().unwrap();
        assert_eq!(
            p.classes,
            vec![Class {
                amount: 50_000,
                peers: 6
            }]
        );
        assert_eq!(p.exits, vec![1, 3, 2]);
        assert_eq!(p.exit_rates_milli, (10_000, 2_500));
        assert_eq!(p.fee_split, FeeSplit::ByExit);
        assert!(p.anchor);
        let e: PoolEvent = serde_json::from_str(
            r#"{"versions":["2"],"id":"x","network":"signet","type":"new_pool","public_key":"ab","denomination":100000,"peers":7,"denominations":[{"amount":100000,"peers":3},{"amount":50000,"peers":4}],"timeout":1,"relays":["wss://r"],"fee_rate":2,"transport":{"vpn":{"enable":false,"vpn_gateway":null},"tor":{"enable":true}}}"#,
        )
        .unwrap();
        let p = e.params().unwrap();
        assert_eq!(p.classes.len(), 2);
        assert_eq!(p.class(50_000).unwrap().peers, 4);
        assert_eq!(p.structure, Structure::Chain);
        let e: PoolEvent = serde_json::from_str(
            r#"{"versions":["2"],"id":"x","network":"signet","type":"new_pool","public_key":"ab","denomination":100000,"peers":5,"timeout":1,"relays":["wss://r"],"fee_rate":2,"broadcast":"hold","structure":"any_order","transport":{"vpn":{"enable":false,"vpn_gateway":null},"tor":{"enable":true}}}"#,
        )
        .unwrap();
        assert_eq!(e.broadcast, Broadcast::Hold);
        assert_eq!(e.params().unwrap().structure, Structure::AnyOrder);
        assert!(serde_json::to_string(&e)
            .unwrap()
            .contains(r#""structure":"any_order""#));
    }
}
