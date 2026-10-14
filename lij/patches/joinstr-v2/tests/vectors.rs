//! Test vectors for other implementations of the NIP: `tests/vectors.json`.
//! `UPDATE_VECTORS=1 cargo test --test vectors` rewrites the file.

use std::str::FromStr;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut, Txid};
use joinstr_v2::funding::ownership_msg;
use joinstr_v2::keys::{point_from_hex, PoolKeys};
use joinstr_v2::pool::{self, Class, FeeSplit, InputRegistration, Params, Payout, Structure};
use joinstr_v2::ring::{hash_to_point, key_image};
use joinstr_v2::util::tagged_hash;
use secp::Scalar;
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
const NETWORK: Network = Network::Signet;

fn key(label: &str, i: usize) -> SecretKey {
    let h = tagged_hash(
        "joinstr/v2/vector",
        &[label.as_bytes(), &(i as u32).to_le_bytes()],
    );
    SecretKey::from_slice(&h).expect("valid key")
}

fn hex32(b: [u8; 32]) -> String {
    hex::encode(b)
}

struct Options {
    classes: Option<Vec<Class>>,
    exits: Option<Vec<usize>>,
    exit_fee_rates: Option<[f64; 2]>,
    fee_split: FeeSplit,
    anchor: bool,
    priorities: Vec<u8>,
    structure: Structure,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            classes: None,
            exits: None,
            exit_fee_rates: None,
            fee_split: FeeSplit::Equal,
            anchor: false,
            priorities: vec![0; 20],
            structure: Structure::Chain,
        }
    }
}

fn pool_json(name: &str, peers: usize, o: &Options) -> Value {
    let mut pool = json!({
        "id": format!("joinstr-v2-vector-{name}"),
        "network": "signet",
        "denomination": 100_000,
        "peers": peers,
        "fee_rate": 2,
    });
    if let Some(c) = &o.classes {
        pool["denominations"] = json!(c);
        pool["denomination"] = json!(c[0].amount);
        pool["peers"] = json!(c.iter().map(|c| c.peers).sum::<usize>());
    }
    if let Some(e) = &o.exits {
        pool["exits"] = json!(e);
    }
    if let Some(r) = o.exit_fee_rates {
        pool["exit_fee_rates"] = json!(r);
    }
    if o.fee_split == FeeSplit::ByExit {
        pool["fee_split"] = json!("by_exit");
    }
    if o.anchor {
        pool["anchor"] = json!("p2a");
    }
    if o.structure != Structure::Chain {
        pool["structure"] = json!(o.structure);
    }
    pool
}

fn params_of(pool: &Value) -> Params {
    let rate = (pool["fee_rate"].as_f64().unwrap() * 1000.0).round() as u64;
    let mut p = match pool.get("denominations") {
        Some(c) => Params::with_classes(
            pool["id"].as_str().unwrap(),
            serde_json::from_value(c.clone()).unwrap(),
            rate,
        ),
        None => Params::new(
            pool["id"].as_str().unwrap(),
            pool["denomination"].as_u64().unwrap(),
            pool["peers"].as_u64().unwrap() as usize,
            rate,
        ),
    };
    if let Some(e) = pool["exits"].as_array() {
        p.exits = e.iter().map(|g| g.as_u64().unwrap() as usize).collect();
    }
    if let Some(r) = pool["exit_fee_rates"].as_array() {
        let milli = |v: &Value| (v.as_f64().unwrap() * 1000.0).round() as u64;
        p.exit_rates_milli = (milli(&r[0]), milli(&r[1]));
    } else {
        p.exit_rates_milli = (p.fee_rate_milli, p.fee_rate_milli);
    }
    if pool["fee_split"] == "by_exit" {
        p.fee_split = FeeSplit::ByExit;
    }
    p.anchor = pool["anchor"] == "p2a";
    if let Some(s) = pool.get("structure") {
        p.structure = serde_json::from_value(s.clone()).unwrap();
    }
    p.validate().unwrap();
    p
}

/// Deterministic inputs of one vector.
fn make_inputs(name: &str, peers: usize, taproot: &[bool], change: &[bool], o: Options) -> Value {
    let secp = Secp256k1::new();
    let pool = pool_json(name, peers, &o);
    let params = params_of(&pool);
    let mut class_of = Vec::new();
    for c in &params.classes {
        class_of.extend(std::iter::repeat_n(c.amount, c.peers));
    }
    let mut list = Vec::new();
    for i in 0..peers {
        let musig = key("musig", i);
        let ring = key("ring", i);
        let session = key("session", i);
        let input_key = key("input", i);
        let pk = PublicKey::from_secret_key(&secp, &input_key);
        let spk = if taproot[i] {
            ScriptBuf::new_p2tr(&secp, XOnlyPublicKey::from(pk), None)
        } else {
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash())
        };
        let change_key = key("change", i);
        let change_addr = Address::p2tr(
            &secp,
            XOnlyPublicKey::from(PublicKey::from_secret_key(&secp, &change_key)),
            None,
            NETWORK,
        );
        let probe = TxOut {
            value: Amount::ZERO,
            script_pubkey: spk.clone(),
        };
        let (amount, change_json) = if change[i] {
            let change_out = TxOut {
                value: Amount::ZERO,
                script_pubkey: change_addr.script_pubkey(),
            };
            let need = params
                .required(class_of[i], std::slice::from_ref(&probe), Some(&change_out))
                .unwrap();
            let extra = 23_456 * (i as u64 + 1);
            (
                need + extra,
                json!({"address": change_addr.to_string(), "amount": extra}),
            )
        } else {
            (
                params
                    .required(class_of[i], std::slice::from_ref(&probe), None)
                    .unwrap(),
                Value::Null,
            )
        };
        let payout = Address::p2tr(
            &secp,
            XOnlyPublicKey::from(PublicKey::from_secret_key(&secp, &key("payout", i))),
            None,
            NETWORK,
        );
        let txid = tagged_hash("joinstr/v2/vector/txid", &[name.as_bytes(), &[i as u8]]);
        list.push(json!({
            "musig_seckey": hex32(musig.secret_bytes()),
            "musig_pubkey": PublicKey::from_secret_key(&secp, &musig).to_string(),
            "ring_seckey": hex32(ring.secret_bytes()),
            "ring_pubkey": PublicKey::from_secret_key(&secp, &ring).to_string(),
            "session_pubkey": XOnlyPublicKey::from(PublicKey::from_secret_key(&secp, &session)).to_string(),
            "inputs": [{
                "txid": Txid::from_str(&hex32(txid)).unwrap().to_string(),
                "vout": i,
                "amount": amount,
                "script_pubkey": spk.to_hex_string(),
            }],
            "change": change_json,
            "height": 300_000 + i as u32 * 3,
            "payout": payout.to_string(),
            "priority": o.priorities[i],
            "denomination": class_of[i],
        }));
    }
    json!({
        "name": name,
        "pool": pool,
        "peers": list,
    })
}

fn script_of(address: &str) -> ScriptBuf {
    Address::from_str(address)
        .unwrap()
        .require_network(NETWORK)
        .unwrap()
        .script_pubkey()
}

/// Everything another implementation must reproduce from a vector's inputs.
fn expected(v: &Value) -> Value {
    let params = params_of(&v["pool"]);
    let peers = v["peers"].as_array().unwrap();
    let mut regs = Vec::new();
    let mut ownership = Vec::new();
    let mut hp = Vec::new();
    let mut images = Vec::new();
    let mut payout_msgs = Vec::new();
    let mut required = Vec::new();
    for p in peers {
        let session: [u8; 32] = hex::decode(p["session_pubkey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let inputs: Vec<(OutPoint, TxOut)> = p["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    OutPoint::new(
                        Txid::from_str(i["txid"].as_str().unwrap()).unwrap(),
                        i["vout"].as_u64().unwrap() as u32,
                    ),
                    TxOut {
                        value: Amount::from_sat(i["amount"].as_u64().unwrap()),
                        script_pubkey: ScriptBuf::from_hex(i["script_pubkey"].as_str().unwrap())
                            .unwrap(),
                    },
                )
            })
            .collect();
        for (op, _) in &inputs {
            ownership.push(hex32(ownership_msg(&params.id, &session, op)));
        }
        let change = (!p["change"].is_null()).then(|| TxOut {
            value: Amount::from_sat(p["change"]["amount"].as_u64().unwrap()),
            script_pubkey: script_of(p["change"]["address"].as_str().unwrap()),
        });
        let ring = point_from_hex(p["ring_pubkey"].as_str().unwrap()).unwrap();
        hp.push(hash_to_point(&ring).to_string());
        let ring_sk = Scalar::from_hex(p["ring_seckey"].as_str().unwrap()).unwrap();
        assert_eq!(ring_sk.base_point_mul(), ring);
        images.push(key_image(ring_sk).to_string());
        let payout = script_of(p["payout"].as_str().unwrap());
        let priority = p["priority"].as_u64().unwrap() as u8;
        let amount = p["denomination"].as_u64().unwrap();
        payout_msgs.push(hex32(pool::payout_msg(
            &params.id, priority, amount, &payout,
        )));
        let prevouts: Vec<TxOut> = inputs.iter().map(|(_, o)| o.clone()).collect();
        required.push(params.required(amount, &prevouts, change.as_ref()).unwrap());
        regs.push(InputRegistration {
            session,
            amount,
            musig: point_from_hex(p["musig_pubkey"].as_str().unwrap()).unwrap(),
            ring,
            inputs,
            change,
            height: p["height"].as_u64().unwrap() as u32,
        });
    }
    pool::check_input_registrations(&params, &regs).unwrap();
    let payouts: Vec<Payout> = peers
        .iter()
        .map(|p| Payout {
            script: script_of(p["payout"].as_str().unwrap()),
            amount: p["denomination"].as_u64().unwrap(),
            priority: p["priority"].as_u64().unwrap() as u8,
        })
        .collect();
    let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect()).unwrap();
    let txs = pool::build(&params, &regs, &payouts, &keys).unwrap();
    pool::check_txs(&params, &txs, &keys).unwrap();
    let amounts = params.amounts(&txs.payout_amounts);
    let set = params.exit_set(&txs.payout_amounts);
    let address = |s: &ScriptBuf| Address::from_script(s, NETWORK).unwrap().to_string();
    let mut out = json!({
        "exit_share": params.exit_share(),
        "exit_amounts": amounts.exits.iter().map(|e| json!({
            "payouts": e.payouts,
            "weight": e.weight,
            "fee": e.fee,
            "pool": e.pool,
        })).collect::<Vec<_>>(),
        "required_contributions": required,
        "pool_values": amounts.pools,
        "ownership_messages": ownership,
        "hash_to_point": hp,
        "key_images": images,
        "payout_messages": payout_msgs,
        "sorted_musig_pubkeys": keys.keys.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        "aggregate_pubkey": keys.xpub.public_key.to_string(),
        "synthetic_xpub": keys.xpub.to_string(),
        "descriptor": keys.descriptor(),
        "pool_output_keys": (0..params.exits.len() as u32)
            .map(|k| keys.output_key(k).unwrap().to_string())
            .collect::<Vec<_>>(),
        "locktime": pool::locktime(&regs),
        "payout_order": txs.payouts.iter().map(address).collect::<Vec<_>>(),
        "funding": {
            "txid": txs.funding.compute_txid().to_string(),
            "pool_vout": txs.pool_vout,
            "unsigned_hex": serialize_hex(&txs.funding),
        },
        "exits": txs.exits.iter().zip(&txs.spent).map(|(tx, spent)| json!({
            "txid": tx.compute_txid().to_string(),
            "sighash": hex32(pool::exit_sighash(tx, spent)),
            "unsigned_hex": serialize_hex(tx),
        })).collect::<Vec<_>>(),
    });
    if params.structure != Structure::Chain {
        // every pool output by index, and where each exit sits
        let obj = out.as_object_mut().unwrap();
        obj.remove("exit_amounts");
        obj.insert("pool_values".into(), json!(set.pools));
        obj.insert(
            "pool_output_keys".into(),
            json!((0..set.pools.len() as u32)
                .map(|i| keys.output_key(i).unwrap().to_string())
                .collect::<Vec<_>>()),
        );
        for (e, (link, plan)) in obj["exits"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(txs.links.iter().zip(&set.plans))
        {
            e["from"] = json!(link.from);
            e["to"] = json!(link.to);
            e["pays"] = json!(link.pays);
            e["depth"] = json!(link.depth);
            e["fee"] = json!(plan.fee);
        }
    }
    out
}

fn generate() -> Value {
    let vectors = [
        make_inputs(
            "three",
            3,
            &[true, false, true],
            &[true, true, true],
            Options::default(),
        ),
        make_inputs(
            "five",
            5,
            &[true, true, false, true, false],
            &[true, false, true, false, false],
            Options::default(),
        ),
        make_inputs(
            "groups",
            7,
            &[true; 7],
            &[true, false, true, false, true, false, true],
            Options {
                exits: Some(vec![1, 3, 1, 2]),
                anchor: true,
                ..Options::default()
            },
        ),
        make_inputs(
            "classes",
            7,
            &[true, false, true, true, false, true, true],
            &[true, true, false, true, true, false, true],
            Options {
                classes: Some(vec![
                    Class {
                        amount: 100_000,
                        peers: 3,
                    },
                    Class {
                        amount: 50_000,
                        peers: 4,
                    },
                ]),
                exits: Some(vec![1, 2, 2, 2]),
                ..Options::default()
            },
        ),
        make_inputs(
            "fees",
            6,
            &[true, false, true, false, true, false],
            &[true; 6],
            Options {
                exit_fee_rates: Some([10.0, 2.0]),
                fee_split: FeeSplit::ByExit,
                anchor: true,
                priorities: vec![0, 2, 0, 1, 0, 0],
                ..Options::default()
            },
        ),
        make_inputs(
            "any_order",
            4,
            &[true, false, true, true],
            &[true, true, false, true],
            Options {
                structure: Structure::AnyOrder,
                ..Options::default()
            },
        ),
        make_inputs(
            "any_order_fees",
            4,
            &[false, true, true, false],
            &[true; 4],
            Options {
                structure: Structure::AnyOrder,
                exit_fee_rates: Some([10.0, 2.0]),
                fee_split: FeeSplit::ByExit,
                anchor: true,
                ..Options::default()
            },
        ),
        make_inputs(
            "tree",
            7,
            &[true, true, false, true, true, false, true],
            &[true, false, true, true, false, true, true],
            Options {
                structure: Structure::Tree,
                exit_fee_rates: Some([6.0, 2.0]),
                anchor: true,
                ..Options::default()
            },
        ),
    ];
    json!({
        "description": "joinstr v2 test vectors. From pool and peers, an implementation must derive every field of expected. Secret keys are included only so that key images can be checked.",
        "vectors": vectors.iter().map(|v| {
            let mut v = v.clone();
            v["expected"] = expected(&v);
            v
        }).collect::<Vec<_>>(),
    })
}

#[test]
fn vectors_match() {
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&generate()).unwrap() + "\n",
        )
        .unwrap();
    }
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    for v in file["vectors"].as_array().unwrap() {
        assert_eq!(
            expected(v),
            v["expected"],
            "vector {} does not match",
            v["name"]
        );
    }
    assert_eq!(
        file,
        generate(),
        "vector inputs changed, run with UPDATE_VECTORS=1"
    );
}
