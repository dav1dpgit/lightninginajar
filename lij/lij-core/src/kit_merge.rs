//! v313 (S57, DP 2026-10-07 17:55 on the recovery recheck's item 1: "it's not just fewer channels, it is where anything
//! is different. Let's not wear blinders. Write it well and thoughtfully — Go."): THE BLACK START KIT ACROSS COPIES.
//! docs/design/black-start/kit-merge-r1.md is the cut copy. Before a push the wallet reads the kits it can reach; this
//! module merges them with this copy's own kit, entry by entry, never removing or downgrading what it cannot prove is
//! finished or older:
//!   - a channel only a held kit has is CARRIED unchanged while it can still matter (its funding output unspent, or spent
//!     by that entry's own CLOSE with the delayed output still unspent); the chain unknown keeps it;
//!   - a channel this copy holds at an OLDER commitment number than a held kit keeps the held entry (a revoked CLOSE never
//!     enters the kit) and is reported, so the person is told;
//!   - silent-payment coins only a held kit has are carried while unspent;
//!   - the kit's seq is never below the highest held seq + 1 (a wrong clock neither blocks nor is blocked).
//! Pure: JSON in, JSON out. node.rs supplies this copy's kit, the opened held kits, the chain's answers and a decoder
//! for the commitment numbers of channels this copy knows.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

/// BOLT 3: a commitment transaction carries its obscured number split across its locktime (upper byte 0x20, low 24
/// bits) and its single input's sequence (upper byte 0x80, high 24 bits), XOR the channel's factor. Returns the BOLT
/// number (0 = the first commitment, higher = newer); None for a transaction that is not a commitment.
pub fn decode_commitment_number(tx: &bitcoin::Transaction, factor: u64) -> Option<u64> {
    let input = tx.input.first()?;
    let lt = tx.lock_time.to_consensus_u32() as u64;
    let sq = input.sequence.0 as u64;
    if (lt >> 24) != 0x20 || (sq >> 24) != 0x80 {
        return None;
    }
    Some(((((sq & 0xff_ffff) << 24) | (lt & 0xff_ffff)) ^ factor) & 0xffff_ffff_ffff)
}

/// A held kit, opened: its envelope seq and its plaintext.
pub struct HeldKit {
    pub seq: u64,
    pub plain: Value,
}

/// One chain answer: an outpoint spent (by which transaction, when known) or not. An outpoint the chain was not asked
/// about, or could not answer, is UNKNOWN — and unknown never drops anything.
#[derive(Clone, Debug, PartialEq)]
pub enum Fact {
    Unspent,
    Spent(Option<String>),
}

/// Parse the page's chain answers: {"txid:vout": {"spent": bool, "by": "txid"|null} | null}.
pub fn parse_chain(chain_json: &str) -> HashMap<String, Fact> {
    let mut out = HashMap::new();
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(chain_json) {
        for (k, v) in m {
            match v.get("spent").and_then(|s| s.as_bool()) {
                Some(false) => { out.insert(k, Fact::Unspent); }
                Some(true) => { out.insert(k, Fact::Spent(v.get("by").and_then(|b| b.as_str()).map(|s| s.to_lowercase()))); }
                None => {}
            }
        }
    }
    out
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// The delayed output a channel entry's COLLECT spends ("txid:vout"), read from its pre-signed sweep.
pub fn to_local_outpoint(entry: &Value) -> Option<String> {
    for k in ["sweep_hex_normal", "sweep_hex_high"] {
        if let Some(h) = entry.get(k).and_then(|x| x.as_str()) {
            if let Ok(bytes) = hex::decode(h) {
                if let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes) {
                    if let Some(i) = tx.input.first() {
                        return Some(format!("{}:{}", i.previous_output.txid, i.previous_output.vout));
                    }
                }
            }
        }
    }
    None
}

fn coin_key(c: &Value) -> String {
    format!("{}:{}", s(c, "txid"), c.get("vout").and_then(|v| v.as_u64()).unwrap_or(u64::MAX))
}

/// For each funding outpoint, the held entry to compare or carry: the higher commitment number when both say, else
/// the entry from the kit with the higher seq. Returns funding → (entry, its kit's seq).
fn best_held<'a>(
    held: &'a [HeldKit],
    number_of: &dyn Fn(&Value) -> Option<u64>,
) -> HashMap<String, (&'a Value, u64)> {
    let mut kits: Vec<&HeldKit> = held.iter().collect();
    kits.sort_by(|a, b| b.seq.cmp(&a.seq));
    let mut best: HashMap<String, (&Value, u64)> = HashMap::new();
    for k in kits {
        for e in k.plain.get("channels").and_then(|c| c.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let f = s(e, "funding_txo");
            if f.is_empty() { continue; }
            match best.get(&f) {
                None => { best.insert(f, (e, k.seq)); }
                Some((cur, _)) => {
                    if let (Some(a), Some(b)) = (number_of(e), number_of(cur)) {
                        if a > b { best.insert(f, (e, k.seq)); }
                    }
                    // otherwise the higher-seq kit's entry (seen first) stays
                }
            }
        }
    }
    best
}

/// The outpoints the chain must be asked about before a merge: each channel only a held kit has (its funding output and
/// its delayed output) and each silent-payment coin only a held kit has.
pub fn plan(own: &Value, held: &[HeldKit]) -> Vec<String> {
    let owned: HashSet<String> = own.get("channels").and_then(|c| c.as_array())
        .map(|a| a.iter().map(|e| s(e, "funding_txo")).collect()).unwrap_or_default();
    let own_coins: HashSet<String> = own.get("silent_payments").and_then(|c| c.as_array())
        .map(|a| a.iter().map(coin_key).collect()).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |o: String, out: &mut Vec<String>| { if !o.is_empty() && seen.insert(o.clone()) { out.push(o); } };
    for k in held {
        for e in k.plain.get("channels").and_then(|c| c.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let f = s(e, "funding_txo");
            if f.is_empty() || owned.contains(&f) { continue; }
            add(f, &mut out);
            if let Some(tl) = to_local_outpoint(e) { add(tl, &mut out); }
        }
        for c in k.plain.get("silent_payments").and_then(|c| c.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let ck = coin_key(c);
            if own_coins.contains(&ck) { continue; }
            add(ck, &mut out);
        }
    }
    out
}

/// Whether a channel entry this copy does not hold can still matter, by the chain's answers.
fn still_matters(e: &Value, chain: &HashMap<String, Fact>) -> bool {
    match chain.get(&s(e, "funding_txo")) {
        None | Some(Fact::Unspent) => true,
        Some(Fact::Spent(by)) => {
            let own_close = s(e, "commitment_txid").to_lowercase();
            match by {
                None => true,   // spent, by an unknown transaction: cannot prove the COLLECT is not needed
                Some(b) if !own_close.is_empty() && *b == own_close => match to_local_outpoint(e) {
                    None => false,   // this entry's own CLOSE confirmed and it has no delayed output to collect
                    Some(tl) => !matches!(chain.get(&tl), Some(Fact::Spent(_))),
                },
                Some(_) => false,   // closed by another transaction: the share is at m/84 (or the provider's close)
            }
        }
    }
}

/// The merged kit and its report. `own` is this copy's kit plaintext (escape export + the bundle fields);
/// `number_of` reads an entry's commitment number (its plain field, else decoded for a channel this copy knows).
pub fn merge(
    own: &Value,
    held: &[HeldKit],
    chain: &HashMap<String, Fact>,
    number_of: &dyn Fn(&Value) -> Option<u64>,
    now_ms: u64,
) -> (Value, Value) {
    let mut kit = own.clone();
    let mut kept_newer: Vec<String> = Vec::new();
    let (mut carried, mut carried_coins, mut dropped) = (0u64, 0u64, 0u64);
    let best = best_held(held, number_of);
    // channels
    let mut channels: Vec<Value> = kit.get("channels").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let owned: HashSet<String> = channels.iter().map(|e| s(e, "funding_txo")).collect();
    for e in channels.iter_mut() {
        let f = s(e, "funding_txo");
        if let Some((h, _)) = best.get(&f) {
            if let (Some(hn), Some(on)) = (number_of(h), number_of(e)) {
                if hn > on {
                    let mut kept = (*h).clone();
                    if let Some(o) = kept.as_object_mut() {
                        o.insert("kept_newer".into(), json!(true));
                        o.insert("this_copy_commitment_number".into(), json!(on));
                        o.insert("commitment_number".into(), json!(hn));
                    }
                    kept_newer.push(s(e, "channel_id"));
                    *e = kept;
                }
            }
        }
    }
    let mut extra: Vec<(String, Value)> = Vec::new();
    for (f, (h, seq)) in best.iter() {
        if owned.contains(f) { continue; }
        if still_matters(h, chain) {
            let mut c = (*h).clone();
            if let Some(o) = c.as_object_mut() {
                let since = h.get("carried_since").and_then(|x| x.as_u64()).unwrap_or(now_ms);
                o.insert("carried".into(), json!(true));
                o.insert("carried_since".into(), json!(since));
                o.insert("carried_from_seq".into(), json!(seq));
                if o.get("commitment_number").is_none() { if let Some(n) = number_of(h) { o.insert("commitment_number".into(), json!(n)); } }
            }
            extra.push((f.clone(), c));
            carried += 1;
        } else {
            dropped += 1;
        }
    }
    extra.sort_by(|a, b| a.0.cmp(&b.0));
    channels.extend(extra.into_iter().map(|x| x.1));
    // silent-payment coins
    let mut coins: Vec<Value> = kit.get("silent_payments").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let mut have: HashSet<String> = coins.iter().map(coin_key).collect();
    let mut kits: Vec<&HeldKit> = held.iter().collect();
    kits.sort_by(|a, b| b.seq.cmp(&a.seq));
    for k in kits {
        for c in k.plain.get("silent_payments").and_then(|c| c.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let ck = coin_key(c);
            if have.contains(&ck) { continue; }
            have.insert(ck.clone());
            if matches!(chain.get(&ck), Some(Fact::Spent(_))) { dropped += 1; continue; }
            let mut cc = c.clone();
            if let Some(o) = cc.as_object_mut() {
                let since = c.get("carried_since").and_then(|x| x.as_u64()).unwrap_or(now_ms);
                o.insert("carried".into(), json!(true));
                o.insert("carried_since".into(), json!(since));
                o.insert("carried_from_seq".into(), json!(k.seq));
            }
            coins.push(cc);
            carried_coins += 1;
        }
    }
    let max_held = held.iter().map(|k| k.seq).max().unwrap_or(0);
    let seq = now_ms.max(max_held.saturating_add(1));
    if let Some(o) = kit.as_object_mut() {
        o.insert("channels".into(), Value::Array(channels));
        o.insert("silent_payments".into(), Value::Array(coins));
        o.insert("seq".into(), json!(seq));
        o.insert("made_at".into(), json!(now_ms));
    }
    let report = json!({
        "held_opened": held.len(),
        "carried_channels": carried,
        "carried_coins": carried_coins,
        "kept_newer": kept_newer,
        "dropped": dropped,
        "seq": seq,
    });
    (kit, report)
}

/// Keep the sealed kit under the holder's cap: drop CARRIED silent-payment coins, the oldest (lowest height) first,
/// until the plaintext is at most `max_plain` bytes. Channels are never dropped. Returns how many coins went.
pub fn trim_to_fit(kit: &mut Value, max_plain: usize) -> u64 {
    let mut n = 0u64;
    loop {
        let len = serde_json::to_string(kit).map(|x| x.len()).unwrap_or(0);
        if len <= max_plain { return n; }
        let coins = match kit.get_mut("silent_payments").and_then(|c| c.as_array_mut()) { Some(c) => c, None => return n };
        let pick = coins.iter().enumerate()
            .filter(|(_, c)| c.get("carried").and_then(|x| x.as_bool()) == Some(true))
            .min_by_key(|(_, c)| c.get("height").and_then(|h| h.as_u64()).unwrap_or(0))
            .map(|(i, _)| i);
        match pick { Some(i) => { coins.remove(i); n += 1; } None => return n }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, Amount};

    fn commitment(n: u64, factor: u64) -> Transaction {
        let o = n ^ factor;
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(((0x20u64 << 24) | (o & 0xff_ffff)) as u32),
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence((((0x80u64 << 24) | ((o >> 24) & 0xff_ffff)) as u32)), witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        }
    }
    fn sweep_of(txid: &str, vout: u32) -> String {
        let tx = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: txid.parse().unwrap(), vout }, script_sig: ScriptBuf::new(), sequence: Sequence(144), witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(900), script_pubkey: ScriptBuf::new() }],
        };
        hex::encode(bitcoin::consensus::serialize(&tx))
    }
    fn ch(id: &str, funding: &str, n: Option<u64>, close_txid: &str, to_local_vout: Option<u32>) -> Value {
        let mut e = json!({ "channel_id": id, "funding_txo": funding, "commitment_txid": close_txid, "commitment_hex": "", "has_to_local": to_local_vout.is_some() });
        if let Some(n) = n { e["commitment_number"] = json!(n); }
        if let Some(v) = to_local_vout { e["sweep_hex_normal"] = json!(sweep_of(close_txid, v)); }
        e
    }
    fn tx(c: char) -> String { std::iter::repeat(c).take(64).collect() }
    fn num(e: &Value) -> Option<u64> { e.get("commitment_number").and_then(|x| x.as_u64()) }
    fn ids(k: &Value) -> Vec<String> { k["channels"].as_array().unwrap().iter().map(|e| s(e, "channel_id")).collect() }

    #[test]
    fn v313_decode_commitment_number_bolt3() {
        let factor = 0x0000_1234_5678_9abc;
        for n in [0u64, 1, 2, 0xff_ffff, 0x1_0000_00, 281_474_976_710_000] {
            assert_eq!(decode_commitment_number(&commitment(n, factor), factor), Some(n), "n = {n}");
        }
        let mut not_commit = commitment(5, factor);
        not_commit.lock_time = LockTime::ZERO;
        assert_eq!(decode_commitment_number(&not_commit, factor), None, "a transaction that is not a commitment");
    }

    #[test]
    fn v313_a_channel_only_the_held_kit_has_is_carried_while_it_matters() {
        let own = json!({ "channels": [], "silent_payments": [] });
        let (fa, fb, fc, fd, fe) = (format!("{}:0", tx('a')), format!("{}:0", tx('b')), format!("{}:0", tx('c')), format!("{}:0", tx('d')), format!("{}:1", tx('e')));
        let held = vec![HeldKit { seq: 100, plain: json!({ "channels": [
            ch("A-open", &fa, Some(7), &tx('1'), Some(0)),         // funding unspent → carried
            ch("B-unknown", &fb, Some(3), &tx('2'), Some(0)),      // chain not answered → carried
            ch("C-coop", &fc, Some(9), &tx('3'), Some(0)),         // spent by another tx (a coop close) → dropped
            ch("D-ours-collect", &fd, Some(4), &tx('4'), Some(1)), // spent by its own CLOSE, delayed output unspent → carried
            ch("E-collected", &fe, Some(4), &tx('5'), Some(0)),    // spent by its own CLOSE, delayed output spent → dropped
        ] }) }];
        let mut chain = HashMap::new();
        chain.insert(fa.clone(), Fact::Unspent);
        chain.insert(fc.clone(), Fact::Spent(Some(tx('9'))));
        chain.insert(fd.clone(), Fact::Spent(Some(tx('4'))));
        chain.insert(format!("{}:1", tx('4')), Fact::Unspent);
        chain.insert(fe.clone(), Fact::Spent(Some(tx('5'))));
        chain.insert(format!("{}:0", tx('5')), Fact::Spent(Some(tx('6'))));
        let checks = plan(&own, &held);
        assert!(checks.contains(&fa) && checks.contains(&format!("{}:1", tx('4'))), "the plan asks for funding and delayed outputs: {checks:?}");
        let (kit, rep) = merge(&own, &held, &chain, &num, 50);
        let mut got = ids(&kit); got.sort();
        assert_eq!(got, vec!["A-open", "B-unknown", "D-ours-collect"]);
        assert_eq!(rep["carried_channels"], 3);
        assert_eq!(rep["dropped"], 2);
        let a = kit["channels"].as_array().unwrap().iter().find(|e| s(e, "channel_id") == "A-open").unwrap();
        assert_eq!((a["carried"].as_bool(), a["carried_since"].as_u64(), a["carried_from_seq"].as_u64()), (Some(true), Some(50), Some(100)));
    }

    #[test]
    fn v313_this_copy_older_keeps_the_held_entry_and_says_so() {
        let f = format!("{}:0", tx('a'));
        let own = json!({ "channels": [ ch("X", &f, Some(4), &tx('1'), Some(0)) ], "silent_payments": [] });
        let held = vec![HeldKit { seq: 10, plain: json!({ "channels": [ ch("X", &f, Some(9), &tx('2'), Some(0)) ] }) }];
        let (kit, rep) = merge(&own, &held, &HashMap::new(), &num, 50);
        let e = &kit["channels"][0];
        assert_eq!((s(e, "commitment_txid"), e["kept_newer"].as_bool(), e["this_copy_commitment_number"].as_u64()), (tx('2'), Some(true), Some(4)));
        assert_eq!(rep["kept_newer"], json!(["X"]));
        // this copy newer or equal: its own entry
        let held_old = vec![HeldKit { seq: 10, plain: json!({ "channels": [ ch("X", &f, Some(4), &tx('3'), Some(0)) ] }) }];
        let (kit2, rep2) = merge(&own, &held_old, &HashMap::new(), &num, 50);
        assert_eq!((s(&kit2["channels"][0], "commitment_txid"), rep2["kept_newer"].as_array().unwrap().len()), (tx('1'), 0));
        // a held entry with no number this copy cannot decode: this copy's entry (nothing proven)
        let held_unknown = vec![HeldKit { seq: 10, plain: json!({ "channels": [ ch("X", &f, None, &tx('3'), Some(0)) ] }) }];
        let (kit3, _) = merge(&own, &held_unknown, &HashMap::new(), &num, 50);
        assert_eq!(s(&kit3["channels"][0], "commitment_txid"), tx('1'));
    }

    #[test]
    fn v313_an_older_kit_without_numbers_is_ordered_by_this_copys_decoder() {
        // the held entry has no commitment_number; this copy knows the channel and decodes the held commitment
        let f = format!("{}:0", tx('a'));
        let own = json!({ "channels": [ ch("X", &f, Some(4), &tx('1'), Some(0)) ], "silent_payments": [] });
        let mut held_e = ch("X", &f, None, &tx('2'), Some(0));
        held_e["decodes_to"] = json!(6);   // stands in for the commitment hex the node decodes with the channel's factor
        let held = vec![HeldKit { seq: 10, plain: json!({ "channels": [ held_e ] }) }];
        let dec = |e: &Value| num(e).or_else(|| e.get("decodes_to").and_then(|x| x.as_u64()));
        let (kit, rep) = merge(&own, &held, &HashMap::new(), &dec, 50);
        assert_eq!((s(&kit["channels"][0], "commitment_txid"), kit["channels"][0]["commitment_number"].as_u64(), rep["kept_newer"].as_array().unwrap().len()), (tx('2'), Some(6), 1));
    }

    #[test]
    fn v313_two_held_kits_the_newer_state_wins_and_the_seq_beats_the_clock() {
        let f = format!("{}:0", tx('a'));
        let own = json!({ "channels": [], "silent_payments": [] });
        let held = vec![
            HeldKit { seq: 900, plain: json!({ "channels": [ ch("X", &f, Some(3), &tx('1'), Some(0)) ] }) },   // the newer KIT, an older state
            HeldKit { seq: 800, plain: json!({ "channels": [ ch("X", &f, Some(8), &tx('2'), Some(0)) ] }) },   // an older kit, the newer state
        ];
        let (kit, rep) = merge(&own, &held, &HashMap::new(), &num, 50);
        assert_eq!(s(&kit["channels"][0], "commitment_txid"), tx('2'), "the higher commitment number wins across held kits");
        assert_eq!((kit["seq"].as_u64(), rep["seq"].as_u64()), (Some(901), Some(901)), "a clock behind the held seq: held + 1");
        let (kit2, _) = merge(&own, &held, &HashMap::new(), &num, 5_000);
        assert_eq!(kit2["seq"].as_u64(), Some(5_000), "a clock ahead: the clock");
    }

    #[test]
    fn v313_silent_payment_coins_are_united_while_unspent_and_trimmed_last() {
        let own = json!({ "channels": [], "silent_payments": [ { "txid": tx('a'), "vout": 0, "height": 10 } ] });
        let held = vec![HeldKit { seq: 5, plain: json!({ "silent_payments": [
            { "txid": tx('a'), "vout": 0, "height": 10 },   // this copy has it
            { "txid": tx('b'), "vout": 1, "height": 20 },   // unspent → carried
            { "txid": tx('c'), "vout": 0, "height": 30 },   // spent → dropped
            { "txid": tx('d'), "vout": 2, "height": 5 },    // unknown → carried
        ] }) }];
        let mut chain = HashMap::new();
        chain.insert(format!("{}:1", tx('b')), Fact::Unspent);
        chain.insert(format!("{}:0", tx('c')), Fact::Spent(None));
        let (mut kit, rep) = merge(&own, &held, &chain, &num, 50);
        let keys: Vec<String> = kit["silent_payments"].as_array().unwrap().iter().map(coin_key).collect();
        assert_eq!(keys, vec![format!("{}:0", tx('a')), format!("{}:1", tx('b')), format!("{}:2", tx('d'))]);
        assert_eq!((rep["carried_coins"].as_u64(), rep["dropped"].as_u64()), (Some(2), Some(1)));
        // over the cap: carried coins go, the oldest first; this copy's own coin and every channel stay
        let small = serde_json::to_string(&kit).unwrap().len() - 10;
        let n = trim_to_fit(&mut kit, small);
        let keys2: Vec<String> = kit["silent_payments"].as_array().unwrap().iter().map(coin_key).collect();
        assert_eq!((n, keys2), (1, vec![format!("{}:0", tx('a')), format!("{}:1", tx('b'))]));
    }

    #[test]
    fn v313_chain_answers_parse_and_unknown_stays_unknown() {
        let c = parse_chain(r#"{"a:0":{"spent":false},"b:1":{"spent":true,"by":"ABC"},"c:2":null,"d:3":{}}"#);
        assert_eq!(c.get("a:0"), Some(&Fact::Unspent));
        assert_eq!(c.get("b:1"), Some(&Fact::Spent(Some("abc".into()))));
        assert!(c.get("c:2").is_none() && c.get("d:3").is_none());
    }
}
