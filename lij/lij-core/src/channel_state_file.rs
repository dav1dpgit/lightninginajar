//! v365 (S68 Wed 2026-11-11, DP "Continue/go" — docs/design/recovery/peer-storage-and-recovery-v0.4.md §2):
//! THE CHANNEL STATE FILE. What keeps channels open — the channel manager and one record (ChannelMonitor) per
//! channel — as ONE encrypted binary file of exactly 65,531 bytes, the size BOLT #1110 (peer storage) allows, so any
//! node that holds peer storage can hold it. The channel partner keeps the latest one. It is not the Black start kit
//! (the signed close and sweep, for a provider that is gone) and it does not replace the LIJOX copy, which is unchanged.
//!
//! THE SPILL RULE. The file always starts with a list: one line per channel (its record's name, update number,
//! SHA-256 and length). After the list come the manager and then whole records, smallest first, while they fit. A
//! record that does not fit has only its line; its bytes are in the LIJOX copy, as today. Nothing is cut in the middle.
//!
//! Everything here works on the wallet's storage and its persistence key — no node, no network — so the same code
//! builds the file in a running wallet, compares a held file with this copy, and applies a file before a wallet is built.
//!
//! Plaintext, big-endian, then zero padding to PLAIN_MAX; AES-256-GCM (persist::encrypt) adds 28 bytes:
//!   "LJCS" · u8 format=1 · u64 version · u64 saved_at_ms
//!   manager: u8 included · [32] sha256 · u32 len
//!   u16 n · n × ( u16 name_len · name ("txid:vout") · u64 update_id · [32] sha256 · u32 len · u8 included )
//!   bodies: the manager (if included), then each included record in list order

use crate::error::{LijError, LijResult};
use crate::persist::{self, CHANNEL_MANAGER_KEY, MONITOR_KEY_PREFIX};
use crate::storage::LijStorage;
use bitcoin::hashes::{sha256, Hash};
use std::collections::HashMap;

/// BOLT #1110: the peer_storage blob is at most 65,531 bytes.
pub const FILE_MAX: usize = 65_531;
const ENC_OVERHEAD: usize = 28; // 12-byte nonce + 16-byte tag
pub const PLAIN_MAX: usize = FILE_MAX - ENC_OVERHEAD;
const MAGIC: &[u8; 4] = b"LJCS";
const FORMAT: u8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub name: String,
    pub update_id: u64,
    pub sha: [u8; 32],
    pub len: u32,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    pub version: u64,
    pub saved_at_ms: u64,
    pub manager_sha: [u8; 32],
    pub manager_len: u32,
    pub manager: Option<Vec<u8>>,
    pub lines: Vec<Line>,
}

pub struct Built {
    pub file: Vec<u8>,
    pub state_fp: String,
    pub included: usize,
    pub spilled: usize,
}

fn err(m: impl Into<String>) -> LijError { LijError::Backup(format!("channel state file: {}", m.into())) }
fn sha(b: &[u8]) -> [u8; 32] { sha256::Hash::hash(b).to_byte_array() }

/// This copy's channel state, read from storage and decrypted: the manager and every record by name.
fn read_local(storage: &dyn LijStorage, key: &[u8; 32]) -> LijResult<Option<(Vec<u8>, Vec<(String, Vec<u8>)>)>> {
    let cm = match storage.get(CHANNEL_MANAGER_KEY)? { Some(v) => v, None => return Ok(None) };
    let manager = persist::decrypt(key, &cm).map_err(|e| err(format!("manager decrypt: {e}")))?;
    let mut recs = Vec::new();
    let mut keys = storage.list_with_prefix(MONITOR_KEY_PREFIX)?;
    keys.sort();
    for k in keys {
        if let Some(v) = storage.get(&k)? {
            let plain = persist::decrypt(key, &v).map_err(|e| err(format!("record {k} decrypt: {e}")))?;
            recs.push((k[MONITOR_KEY_PREFIX.len()..].to_string(), plain));
        }
    }
    Ok(Some((manager, recs)))
}

/// One fingerprint for the whole channel state: the manager's hash and every record's name, update number and hash.
/// The wallet sends it beside the file and asks the holder for it on reconnect; equal = nothing to fetch.
fn state_fp_of(manager_sha: &[u8; 32], lines: &[(String, u64, [u8; 32])]) -> String {
    let mut v: Vec<&(String, u64, [u8; 32])> = lines.iter().collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    let mut buf = Vec::with_capacity(32 + v.len() * 80);
    buf.extend_from_slice(manager_sha);
    for (name, id, h) in v {
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(h);
    }
    hex::encode(sha(&buf))
}

/// This copy's fingerprint (None: no channel manager yet). `ids`: each record's update number by name.
pub fn local_state_fp(storage: &dyn LijStorage, key: &[u8; 32], ids: &HashMap<String, u64>) -> LijResult<Option<String>> {
    let (manager, recs) = match read_local(storage, key)? { Some(x) => x, None => return Ok(None) };
    let lines: Vec<(String, u64, [u8; 32])> = recs.iter().map(|(n, b)| (n.clone(), *ids.get(n).unwrap_or(&0), sha(b))).collect();
    Ok(Some(state_fp_of(&sha(&manager), &lines)))
}

/// Build the file from this copy. None: no channel manager yet (nothing to keep).
pub fn build(storage: &dyn LijStorage, key: &[u8; 32], ids: &HashMap<String, u64>, version: u64, saved_at_ms: u64) -> LijResult<Option<Built>> {
    let (manager, recs) = match read_local(storage, key)? { Some(x) => x, None => return Ok(None) };
    if recs.len() > u16::MAX as usize { return Err(err("too many channels")); }
    let manager_sha = sha(&manager);
    let mut lines: Vec<Line> = recs.into_iter().map(|(name, b)| Line { update_id: *ids.get(&name).unwrap_or(&0), sha: sha(&b), len: b.len() as u32, name, body: Some(b) }).collect();
    // the list is always whole: its size first
    let head = 4 + 1 + 8 + 8 + (1 + 32 + 4) + 2 + lines.iter().map(|l| 2 + l.name.len() + 8 + 32 + 4 + 1).sum::<usize>();
    if head > PLAIN_MAX { return Err(err("the list alone does not fit")); }
    let mut left = PLAIN_MAX - head;
    let manager_in = manager.len() <= left;
    if manager_in { left -= manager.len(); }
    // whole records, smallest first, while they fit — and only beside the manager: a record without it resumes nothing
    let mut order: Vec<usize> = (0..lines.len()).collect();
    order.sort_by(|&a, &b| lines[a].len.cmp(&lines[b].len).then(lines[a].name.cmp(&lines[b].name)));
    let mut keep = vec![false; lines.len()];
    if manager_in {
        for i in order {
            let n = lines[i].len as usize;
            if n <= left { keep[i] = true; left -= n; } else { break; }
        }
    }
    let fp = state_fp_of(&manager_sha, &lines.iter().map(|l| (l.name.clone(), l.update_id, l.sha)).collect::<Vec<_>>());
    let mut p = Vec::with_capacity(PLAIN_MAX);
    p.extend_from_slice(MAGIC); p.push(FORMAT);
    p.extend_from_slice(&version.to_be_bytes()); p.extend_from_slice(&saved_at_ms.to_be_bytes());
    p.push(manager_in as u8); p.extend_from_slice(&manager_sha); p.extend_from_slice(&(manager.len() as u32).to_be_bytes());
    p.extend_from_slice(&(lines.len() as u16).to_be_bytes());
    for (i, l) in lines.iter().enumerate() {
        p.extend_from_slice(&(l.name.len() as u16).to_be_bytes()); p.extend_from_slice(l.name.as_bytes());
        p.extend_from_slice(&l.update_id.to_be_bytes()); p.extend_from_slice(&l.sha); p.extend_from_slice(&l.len.to_be_bytes());
        p.push(keep[i] as u8);
    }
    if manager_in { p.extend_from_slice(&manager); }
    for (i, l) in lines.iter_mut().enumerate() { if keep[i] { p.extend_from_slice(l.body.as_ref().unwrap()); } }
    debug_assert!(p.len() <= PLAIN_MAX);
    p.resize(PLAIN_MAX, 0);
    let file = persist::encrypt(key, &p).map_err(|e| err(format!("encrypt: {e}")))?;
    if file.len() != FILE_MAX { return Err(err(format!("built {} bytes, want {FILE_MAX}", file.len()))); }
    let included = keep.iter().filter(|k| **k).count();
    Ok(Some(Built { file, state_fp: fp, included, spilled: keep.len() - included }))
}

struct Cur<'a> { b: &'a [u8], i: usize }
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> LijResult<&'a [u8]> {
        if self.i + n > self.b.len() { return Err(err("cut short")); }
        let s = &self.b[self.i..self.i + n]; self.i += n; Ok(s)
    }
    fn u8(&mut self) -> LijResult<u8> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> LijResult<u16> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> LijResult<u32> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> LijResult<u64> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn h32(&mut self) -> LijResult<[u8; 32]> { Ok(self.take(32)?.try_into().unwrap()) }
}

/// Open a file with this wallet's key. Opening is the proof it is this wallet's: AES-GCM fails on any other bytes.
/// Every body carried is checked against its line's hash.
pub fn parse(key: &[u8; 32], file: &[u8]) -> LijResult<Parsed> {
    if file.len() > FILE_MAX { return Err(err("larger than 65,531 bytes")); }
    let p = persist::decrypt(key, file).map_err(|_| err("does not open with this wallet's key"))?;
    let mut c = Cur { b: &p, i: 0 };
    if c.take(4)? != MAGIC { return Err(err("not a channel state file")); }
    if c.u8()? != FORMAT { return Err(err("a format this wallet does not read")); }
    let (version, saved_at_ms) = (c.u64()?, c.u64()?);
    let (manager_in, manager_sha, manager_len) = (c.u8()? == 1, c.h32()?, c.u32()?);
    let n = c.u16()? as usize;
    let mut lines = Vec::with_capacity(n);
    let mut inc = Vec::with_capacity(n);
    for _ in 0..n {
        let nl = c.u16()? as usize;
        let name = String::from_utf8(c.take(nl)?.to_vec()).map_err(|_| err("a record name is not text"))?;
        let (update_id, h, len) = (c.u64()?, c.h32()?, c.u32()?);
        inc.push(c.u8()? == 1);
        lines.push(Line { name, update_id, sha: h, len, body: None });
    }
    let manager = if manager_in {
        let b = c.take(manager_len as usize)?.to_vec();
        if sha(&b) != manager_sha { return Err(err("the manager does not match its line")); }
        Some(b)
    } else { None };
    for (i, l) in lines.iter_mut().enumerate() {
        if inc[i] {
            let b = c.take(l.len as usize)?.to_vec();
            if sha(&b) != l.sha { return Err(err(format!("record {} does not match its line", l.name))); }
            l.body = Some(b);
        }
    }
    Ok(Parsed { version, saved_at_ms, manager_sha, manager_len, manager, lines })
}

/// A held file against this copy, channel by channel, by update number.
///   same           — nothing differs
///   local_newer    — this copy is ahead (or has a channel the file lacks): send a new file
///   file_newer     — the file is ahead and can be applied: the manager and every record that is ahead are in it, and
///                    every record that is only a line equals this copy's record
///   file_newer_incomplete — the file is ahead but a record that is ahead is only a line: this copy is older than the
///                    channels and the bytes to continue are not here
///   conflict       — each side is ahead on some channel
pub fn compare(storage: &dyn LijStorage, key: &[u8; 32], ids: &HashMap<String, u64>, file: &[u8]) -> LijResult<serde_json::Value> {
    let f = parse(key, file)?;
    let (_, recs) = read_local(storage, key)?.ok_or_else(|| err("this copy has no channel state"))?;
    let local: HashMap<String, (u64, [u8; 32])> = recs.iter().map(|(n, b)| (n.clone(), (*ids.get(n).unwrap_or(&0), sha(b)))).collect();
    let (mut ahead_f, mut ahead_l, mut usable) = (false, false, f.manager.is_some());
    let mut rows = Vec::new();
    for l in &f.lines {
        let loc = local.get(&l.name);
        let file_ahead = match loc { Some((id, _)) => l.update_id > *id, None => true };
        let local_ahead = matches!(loc, Some((id, _)) if *id > l.update_id);
        let same_bytes = matches!(loc, Some((_, h)) if *h == l.sha);
        if file_ahead { ahead_f = true; if l.body.is_none() { usable = false; } }
        if local_ahead { ahead_l = true; }
        if l.body.is_none() && !same_bytes && !local_ahead { usable = false; }
        rows.push(serde_json::json!({ "record": l.name, "file_update": l.update_id, "local_update": loc.map(|x| x.0), "in_file": l.body.is_some(), "same_bytes": same_bytes }));
    }
    for (n, (id, _)) in &local {
        if !f.lines.iter().any(|l| &l.name == n) {
            ahead_l = true;
            rows.push(serde_json::json!({ "record": n, "file_update": null, "local_update": id, "in_file": false, "same_bytes": false }));
        }
    }
    let kind = match (ahead_f, ahead_l) {
        (false, false) => "same",
        (false, true) => "local_newer",
        (true, true) => "conflict",
        (true, false) => if usable { "file_newer" } else { "file_newer_incomplete" },
    };
    Ok(serde_json::json!({ "kind": kind, "version": f.version, "saved_at_ms": f.saved_at_ms, "records": rows }))
}

/// Write a file's manager and records into storage, for a wallet that is not running. Refused unless the file can
/// stand whole: the manager is in it, and every record that is only a line equals the record already stored (the rule
/// that makes `file_newer` — checked again here, on the bytes, because this is the step that writes).
/// Returns how many records were written.
pub fn apply(storage: &dyn LijStorage, key: &[u8; 32], file: &[u8]) -> LijResult<u32> {
    let f = parse(key, file)?;
    let manager = f.manager.as_ref().ok_or_else(|| err("the manager is not in the file — nothing can resume from it"))?;
    let (_, recs) = read_local(storage, key)?.ok_or_else(|| err("this copy has no channel state"))?;
    let local: HashMap<String, [u8; 32]> = recs.iter().map(|(n, b)| (n.clone(), sha(b))).collect();
    for l in &f.lines {
        if l.body.is_none() && local.get(&l.name) != Some(&l.sha) {
            return Err(err(format!("record {} is only a line in the file and this copy's record is not the same — not applied", l.name)));
        }
    }
    let mut n = 0u32;
    for l in &f.lines {
        if let Some(b) = &l.body {
            let ct = persist::encrypt(key, b).map_err(|e| err(format!("encrypt: {e}")))?;
            storage.set(&format!("{MONITOR_KEY_PREFIX}{}", l.name), &ct)?;
            n += 1;
        }
    }
    // the manager last: a stop in the middle leaves records ahead of the manager — the direction LDK treats as safe
    let ct = persist::encrypt(key, manager).map_err(|e| err(format!("encrypt: {e}")))?;
    storage.set(CHANNEL_MANAGER_KEY, &ct)?;
    // the save stamps level, so the load does not read this as an interrupted save
    let read = |k: &str| storage.get(k).ok().flatten().and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok()).map(u64::from_be_bytes).unwrap_or(0);
    let s = read(persist::SEQ_CM_KEY).max(read(persist::SEQ_MON_KEY)) + 1;
    storage.set(persist::SEQ_MON_KEY, &s.to_be_bytes())?;
    storage.set(persist::SEQ_CM_KEY, &s.to_be_bytes())?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::native_storage::MemoryStorage;

    const K: [u8; 32] = [7u8; 32];
    fn put(s: &MemoryStorage, name: Option<&str>, body: &[u8]) {
        let k = match name { Some(n) => format!("{MONITOR_KEY_PREFIX}{n}"), None => CHANNEL_MANAGER_KEY.to_string() };
        s.set(&k, &persist::encrypt(&K, body).unwrap()).unwrap();
    }
    fn get(s: &MemoryStorage, name: Option<&str>) -> Vec<u8> {
        let k = match name { Some(n) => format!("{MONITOR_KEY_PREFIX}{n}"), None => CHANNEL_MANAGER_KEY.to_string() };
        persist::decrypt(&K, &s.get(&k).unwrap().unwrap()).unwrap()
    }
    fn ids(v: &[(&str, u64)]) -> HashMap<String, u64> { v.iter().map(|(n, i)| (n.to_string(), *i)).collect() }
    fn body(seed: u8, len: usize) -> Vec<u8> { (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect() }

    #[test]
    fn v365_the_file_is_always_65531_bytes_and_opens_only_with_its_key() {
        let s = MemoryStorage::new();
        assert!(build(&s, &K, &ids(&[]), 1, 1).unwrap().is_none(), "no manager: nothing to keep");
        put(&s, None, &body(1, 3746)); put(&s, Some("aa:0"), &body(2, 4893));
        let b = build(&s, &K, &ids(&[("aa:0", 5)]), 9, 1000).unwrap().unwrap();
        assert_eq!((b.file.len(), b.included, b.spilled), (FILE_MAX, 1, 0));
        let f = parse(&K, &b.file).unwrap();
        assert_eq!((f.version, f.saved_at_ms, f.manager.as_deref(), f.lines.len()), (9, 1000, Some(&body(1, 3746)[..]), 1));
        assert_eq!((f.lines[0].name.as_str(), f.lines[0].update_id, f.lines[0].body.as_deref()), ("aa:0", 5, Some(&body(2, 4893)[..])));
        assert!(parse(&[8u8; 32], &b.file).is_err(), "another wallet's key does not open it");
        let mut bad = b.file.clone(); bad[100] ^= 1;
        assert!(parse(&K, &bad).is_err(), "one changed byte and it does not open");
        // a wallet with one more byte of state still builds the same size (the size says nothing)
        put(&s, Some("aa:0"), &body(2, 4894));
        assert_eq!(build(&s, &K, &ids(&[("aa:0", 6)]), 10, 1001).unwrap().unwrap().file.len(), FILE_MAX);
    }

    #[test]
    fn v365_the_spill_rule_whole_records_smallest_first_and_a_line_for_the_rest() {
        let s = MemoryStorage::new();
        put(&s, None, &body(1, 9000));
        put(&s, Some("big:0"), &body(2, 40_000)); put(&s, Some("mid:0"), &body(3, 30_000)); put(&s, Some("small:1"), &body(4, 5_000));
        let b = build(&s, &K, &ids(&[("big:0", 300), ("mid:0", 200), ("small:1", 3)]), 1, 1).unwrap().unwrap();
        assert_eq!((b.file.len(), b.included, b.spilled), (FILE_MAX, 2, 1), "small and mid fit beside the manager; big is a line only");
        let f = parse(&K, &b.file).unwrap();
        let by = |n: &str| f.lines.iter().find(|l| l.name == n).unwrap().clone();
        assert!(by("small:1").body.is_some() && by("mid:0").body.is_some() && by("big:0").body.is_none());
        assert_eq!((by("big:0").len, by("big:0").update_id, by("big:0").sha), (40_000, 300, sha(&body(2, 40_000))), "the line still says which state is the newest");
        // nothing is cut: a record one byte too large is a line, never a part
        let s2 = MemoryStorage::new();
        put(&s2, None, &body(1, 1000));
        let room = PLAIN_MAX - (4 + 1 + 8 + 8 + 37 + 2 + (2 + 3 + 8 + 32 + 4 + 1)) - 1000;
        put(&s2, Some("x:0"), &body(5, room));
        assert_eq!(build(&s2, &K, &ids(&[]), 1, 1).unwrap().unwrap().included, 1, "exactly fits");
        put(&s2, Some("x:0"), &body(5, room + 1));
        let b2 = build(&s2, &K, &ids(&[]), 1, 1).unwrap().unwrap();
        assert_eq!((b2.included, b2.spilled, b2.file.len()), (0, 1, FILE_MAX), "one byte more: a line only");
    }

    #[test]
    fn v365_the_fingerprint_follows_the_state_not_the_encryption() {
        let s = MemoryStorage::new();
        put(&s, None, &body(1, 100)); put(&s, Some("aa:0"), &body(2, 200));
        let i = ids(&[("aa:0", 5)]);
        let a = build(&s, &K, &i, 1, 1).unwrap().unwrap();
        let b = build(&s, &K, &i, 2, 2).unwrap().unwrap();
        assert_ne!(a.file, b.file, "fresh encryption each time");
        assert_eq!(a.state_fp, b.state_fp, "same state, same fingerprint");
        assert_eq!(local_state_fp(&s, &K, &i).unwrap().unwrap(), a.state_fp, "what the wallet works out on reconnect");
        put(&s, None, &body(1, 100));   // stored again, new ciphertext, same bytes
        assert_eq!(local_state_fp(&s, &K, &i).unwrap().unwrap(), a.state_fp);
        put(&s, Some("aa:0"), &body(9, 200));
        assert_ne!(local_state_fp(&s, &K, &ids(&[("aa:0", 6)])).unwrap().unwrap(), a.state_fp, "a changed record changes it");
    }

    #[test]
    fn v365_compare_and_apply() {
        // the phone that made the file: two channels, aa at update 7, bb at update 300 (too large to ride)
        let phone = MemoryStorage::new();
        put(&phone, None, &body(1, 5000)); put(&phone, Some("aa:0"), &body(2, 6000)); put(&phone, Some("bb:1"), &body(3, 58_000));
        let file = build(&phone, &K, &ids(&[("aa:0", 7), ("bb:1", 300)]), 50, 50).unwrap().unwrap();
        assert_eq!((file.included, file.spilled), (1, 1));
        let kind = |s: &MemoryStorage, i: &HashMap<String, u64>| compare(s, &K, i, &file.file).unwrap()["kind"].as_str().unwrap().to_string();
        assert_eq!(kind(&phone, &ids(&[("aa:0", 7), ("bb:1", 300)])), "same");
        // a restored copy that is behind on aa only: bb is the same record → the file can be applied
        let r1 = MemoryStorage::new();
        put(&r1, None, &body(8, 4900)); put(&r1, Some("aa:0"), &body(9, 5800)); put(&r1, Some("bb:1"), &body(3, 58_000));
        assert_eq!(kind(&r1, &ids(&[("aa:0", 5), ("bb:1", 300)])), "file_newer");
        assert_eq!(apply(&r1, &K, &file.file).unwrap(), 1);
        assert_eq!((get(&r1, None), get(&r1, Some("aa:0")), get(&r1, Some("bb:1"))), (body(1, 5000), body(2, 6000), body(3, 58_000)), "the manager and aa are the file's; bb untouched");
        assert_eq!(r1.get(persist::SEQ_CM_KEY).unwrap(), r1.get(persist::SEQ_MON_KEY).unwrap(), "the save stamps are level");
        assert_eq!(kind(&r1, &ids(&[("aa:0", 7), ("bb:1", 300)])), "same");
        // a restored copy that is behind on bb: bb is only a line → not applied, nothing written
        let r2 = MemoryStorage::new();
        put(&r2, None, &body(8, 4900)); put(&r2, Some("aa:0"), &body(2, 6000)); put(&r2, Some("bb:1"), &body(4, 57_000));
        assert_eq!(kind(&r2, &ids(&[("aa:0", 7), ("bb:1", 290)])), "file_newer_incomplete");
        assert!(apply(&r2, &K, &file.file).is_err());
        assert_eq!((get(&r2, None), get(&r2, Some("bb:1"))), (body(8, 4900), body(4, 57_000)), "a refused file writes nothing");
        // this copy ahead; a channel the file does not have; each side ahead on one channel
        assert_eq!(kind(&phone, &ids(&[("aa:0", 8), ("bb:1", 300)])), "local_newer");
        put(&phone, Some("cc:0"), &body(5, 100));
        assert_eq!(kind(&phone, &ids(&[("aa:0", 7), ("bb:1", 300), ("cc:0", 1)])), "local_newer");
        assert_eq!(kind(&r2, &ids(&[("aa:0", 9), ("bb:1", 290)])), "conflict");
        // a copy that does not have a channel the file has (in the file whole) → can be applied
        let r3 = MemoryStorage::new();
        put(&r3, None, &body(8, 4900)); put(&r3, Some("bb:1"), &body(3, 58_000));
        assert_eq!(kind(&r3, &ids(&[("bb:1", 300)])), "file_newer");
        assert_eq!(apply(&r3, &K, &file.file).unwrap(), 1);
        assert_eq!(get(&r3, Some("aa:0")), body(2, 6000));
        // garbage and another wallet's file
        assert!(compare(&phone, &K, &ids(&[]), &[1, 2, 3]).is_err());
        assert!(apply(&phone, &[9u8; 32], &file.file).is_err());
    }
}
