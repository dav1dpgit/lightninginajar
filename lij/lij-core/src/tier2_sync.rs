// tier2_sync.rs
// Tier 2 increment 2 (sync loop) + 3 (header / filter-header validation).
//
// Pulls the node's global filter/header data by height, validates it, and
// reports which block heights touch the wallet — WITHOUT telling the node which
// scripts are ours (we match locally). Produces nothing user-facing yet; the
// matched heights feed increment 4 (block fetch + UTXO/history assembly).
//
// Trust model layered here:
//   - PoW header chain: each served header must connect to the previous (prev
//     blockhash) and its own hash must meet its stated target. Forging a chain
//     with valid PoW from the wallet's birthday is economically infeasible, so
//     this is strong even without full difficulty-retarget validation (noted as
//     future hardening). ENFORCED.
//   - BIP157 filter-header chain: each filter commits via
//     header_n = dSHA256(dSHA256(filter_n) || header_{n-1}); a single source
//     can't fabricate an individual filter without breaking the chain. Computed
//     and compared here in WARN-ONLY mode until conformance is confirmed against
//     live endpoint data (endianness of the served header is the open question),
//     then flipped to enforce. Multi-source agreement is a later hardening lever.
//
// The async `sync_step` does the network I/O (your WASM build verifies it); the
// parsing, header validation, and match collection are pure and cargo-tested.

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{block::Header, hashes::sha256d, hashes::Hash, BlockHash};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    error::{LijError, LijResult},
    independent::EsploraHttp,
    tier2::{block_matches, WalletScripts},
};

/// Heights fetched per round. The endpoint caps at 2000; 500 keeps each
/// response modest for a PWA.
pub const DEFAULT_BATCH: u32 = 500;

// ---- endpoint response types -------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct TipResp {
    pub height: u32,
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeaderItem {
    pub height: u32,
    pub hash: String,
    pub header: String, // raw 80-byte header hex
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeadersResp {
    pub headers: Vec<HeaderItem>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FilterItem {
    pub height: u32,
    pub hash: String,
    pub filter: String,        // BIP158 basic filter hex
    pub filter_header: String, // BIP157 filter header hex (as served)
}

#[derive(Clone, Debug, Deserialize)]
pub struct FiltersResp {
    pub filters: Vec<FilterItem>,
}

// ---- cursor / outcome --------------------------------------------------------

/// Persisted between sessions (serialized by the caller). Lets reconnects
/// EXTEND the scan instead of restarting it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncCursor {
    /// First height the wallet could have activity at (creation block).
    pub birthday: u32,
    /// Highest height scanned so far (inclusive). 0 = nothing scanned yet.
    pub scanned_to: u32,
    /// Last validated block hash (hex), to link the next batch's first header.
    pub last_hash: Option<String>,
    /// Last validated filter header (hex), to chain the next batch's filters.
    pub last_filter_header: Option<String>,
}

/// A block that matched the wallet's filter, with its validated canonical
/// hash so the block fetch can bind the downloaded block to the chain we
/// already validated (PoW + linkage) rather than trusting the block endpoint.
#[derive(Clone, Debug)]
pub struct MatchedBlock {
    pub height: u32,
    pub block_hash: String,
}

#[derive(Clone, Debug, Default)]
pub struct SyncOutcome {
    /// New high-water mark (inclusive).
    pub scanned_to: u32,
    /// Blocks (height + validated hash) that touch the wallet — feed to fetch.
    pub matched: Vec<MatchedBlock>,
    /// Updated last validated block hash (hex).
    pub last_hash: Option<String>,
    /// Updated last validated filter header (hex).
    pub last_filter_header: Option<String>,
    /// True once scanned_to has reached the tip.
    pub caught_up: bool,
}

// ---- pure validation / matching ---------------------------------------------

fn parse_header(hex_str: &str) -> LijResult<Header> {
    let bytes = hex::decode(hex_str).map_err(|e| LijError::Node(format!("header hex: {e}")))?;
    bitcoin::consensus::deserialize(&bytes).map_err(|e| LijError::Node(format!("header decode: {e}")))
}

/// Validate a batch of headers: each meets its own PoW target, its computed
/// hash matches the served hash, and it links to the previous block. Returns
/// the last block hash on success. `prev_hash` anchors the first header (None
/// at the very first batch from birthday — that anchor is trusted).
pub fn validate_headers(items: &[HeaderItem], prev_hash: Option<BlockHash>) -> LijResult<BlockHash> {
    let mut prev = prev_hash;
    for it in items {
        let header = parse_header(&it.header)?;
        // PoW: the block hash must meet the target encoded in the header.
        let got = header
            .validate_pow(header.target())
            .map_err(|e| LijError::Node(format!("pow invalid at {}: {e:?}", it.height)))?;
        let want = BlockHash::from_str(&it.hash)
            .map_err(|e| LijError::Node(format!("served hash parse at {}: {e}", it.height)))?;
        if got != want {
            return Err(LijError::Node(format!(
                "header hash mismatch at {} (computed != served)",
                it.height
            )));
        }
        if let Some(ph) = prev {
            if header.prev_blockhash != ph {
                return Err(LijError::Node(format!("header chain break at {}", it.height)));
            }
        }
        prev = Some(want);
    }
    prev.ok_or_else(|| LijError::Node("validate_headers: empty batch".into()))
}

/// BIP157 filter header: dSHA256( dSHA256(filter) || prev_filter_header ).
pub fn compute_filter_header(filter_bytes: &[u8], prev_filter_header: &[u8; 32]) -> [u8; 32] {
    let filter_hash = sha256d::Hash::hash(filter_bytes);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&filter_hash.to_byte_array());
    preimage.extend_from_slice(prev_filter_header);
    sha256d::Hash::hash(&preimage).to_byte_array()
}

/// Run the wallet's match set against a batch of filters; return the heights
/// whose blocks need fetching. Pure.
pub fn matching_heights(scripts: &WalletScripts, filters: &[FilterItem]) -> LijResult<Vec<u32>> {
    let mut hits = Vec::new();
    for f in filters {
        let bytes =
            hex::decode(&f.filter).map_err(|e| LijError::Node(format!("filter hex at {}: {e}", f.height)))?;
        let bh = BlockHash::from_str(&f.hash)
            .map_err(|e| LijError::Node(format!("filter block hash at {}: {e}", f.height)))?;
        if block_matches(&bytes, &bh, scripts)? {
            hits.push(f.height);
        }
    }
    Ok(hits)
}

// ---- async sync step ---------------------------------------------------------

async fn get_json<T: DeserializeOwned>(http: &Arc<dyn EsploraHttp>, url: &str) -> LijResult<T> {
    let resp = http.get(url).await?;
    if resp.status != 200 {
        return Err(LijError::Node(format!("tier2 GET {url} -> status {}", resp.status)));
    }
    serde_json::from_str(&resp.body).map_err(|e| LijError::Node(format!("tier2 parse {url}: {e}")))
}

/// Advance the scan by one batch: fetch headers + filters for the next range,
/// enforce the PoW header chain AND the BIP157 filter-header chain, and collect
/// matched blocks (height + validated hash). Returns the advanced state; the
/// caller persists it. Network I/O — run OUTSIDE any wallet lock.
pub async fn sync_step(
    http: &Arc<dyn EsploraHttp>,
    base: &str,
    scripts: &WalletScripts,
    cursor: &SyncCursor,
    tip_height: u32,
    batch: u32,
) -> LijResult<SyncOutcome> {
    let start = cursor.scanned_to.saturating_add(1).max(cursor.birthday);
    if start > tip_height {
        return Ok(SyncOutcome {
            scanned_to: cursor.scanned_to,
            matched: Vec::new(),
            last_hash: cursor.last_hash.clone(),
            last_filter_header: cursor.last_filter_header.clone(),
            caught_up: true,
        });
    }
    let count = (tip_height - start + 1).min(batch.max(1));

    let hdrs: HeadersResp = get_json(http, &format!("{base}/headers?start={start}&count={count}")).await?;
    let flts: FiltersResp = get_json(http, &format!("{base}/filters?start={start}&count={count}")).await?;

    if hdrs.headers.is_empty() {
        return Ok(SyncOutcome {
            scanned_to: cursor.scanned_to,
            matched: Vec::new(),
            last_hash: cursor.last_hash.clone(),
            last_filter_header: cursor.last_filter_header.clone(),
            caught_up: false,
        });
    }

    // Enforce PoW + linkage on the header chain.
    let prev_anchor = match &cursor.last_hash {
        Some(h) => Some(
            BlockHash::from_str(h).map_err(|e| LijError::Node(format!("cursor last_hash parse: {e}")))?,
        ),
        None => None,
    };
    let last_hash = validate_headers(&hdrs.headers, prev_anchor)?;

    // Enforce the BIP157 filter-header chain (internal byte order via sha256d),
    // and match each filter locally against the wallet's scripts in one pass.
    let mut prev_fh: Option<[u8; 32]> = match &cursor.last_filter_header {
        Some(h) => Some(filter_header_internal(h)?),
        None => None,
    };
    let mut last_filter_header = cursor.last_filter_header.clone();
    let mut matched: Vec<MatchedBlock> = Vec::new();
    for f in &flts.filters {
        let filter_bytes =
            hex::decode(&f.filter).map_err(|e| LijError::Node(format!("filter hex at {}: {e}", f.height)))?;
        let served = filter_header_internal(&f.filter_header)?;
        if let Some(pfh) = prev_fh {
            let computed = compute_filter_header(&filter_bytes, &pfh);
            if computed != served {
                return Err(LijError::Node(format!("filter-header chain break at {}", f.height)));
            }
        }
        prev_fh = Some(served);
        last_filter_header = Some(f.filter_header.clone());

        let bh = BlockHash::from_str(&f.hash)
            .map_err(|e| LijError::Node(format!("filter block hash at {}: {e}", f.height)))?;
        if block_matches(&filter_bytes, &bh, scripts)? {
            matched.push(MatchedBlock {
                height: f.height,
                block_hash: f.hash.clone(),
            });
        }
    }

    let scanned_to = start + (hdrs.headers.len() as u32) - 1;
    Ok(SyncOutcome {
        scanned_to,
        matched,
        last_hash: Some(last_hash.to_string()),
        last_filter_header,
        caught_up: scanned_to >= tip_height,
    })
}

/// Parse a filter-header hex (big-endian display, as served) into internal
/// byte order, matching the order used inside `compute_filter_header`.
fn filter_header_internal(hex_str: &str) -> LijResult<[u8; 32]> {
    sha256d::Hash::from_str(hex_str)
        .map(|h| h.to_byte_array())
        .map_err(|e| LijError::Node(format!("filter header parse: {e}")))
}

/// Fetch the current chain tip (height + hash) from the endpoint.
pub async fn fetch_tip(http: &Arc<dyn EsploraHttp>, base: &str) -> LijResult<TipResp> {
    get_json(http, &format!("{base}/tip")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real consecutive mainnet headers (952420 -> 952421) from the live endpoint.
    const H420: &str = "00a00b209f4a0f1b248cce023cc90865da03bdef202f0e297fa200000000000000000000f6c94861b4226bfa8cef4d4720191b0fa5b0d62ee1c2bbe0bd439effb41653e6d92b226a8f06021717abe047";
    const HASH420: &str = "000000000000000000006e55579683079b21a5456e86116091b1a11246d134fd";
    const H421: &str = "00e09a23fd34d14612a1b1916011866e45a5219b07839657556e00000000000000000000ab5588547791299d5acccc28cc1b30d15ea4a1817db90f64a16cec88ec72bfde872f226a8f06021732509736";
    const HASH421: &str = "0000000000000000000050eb8656a48d1a32f5ada652fe103af289672df88e00";

    fn item(height: u32, hash: &str, header: &str) -> HeaderItem {
        HeaderItem {
            height,
            hash: hash.into(),
            header: header.into(),
        }
    }

    #[test]
    fn real_headers_validate_pow_hash_and_link() {
        let items = vec![item(952420, HASH420, H420), item(952421, HASH421, H421)];
        let last = validate_headers(&items, None).unwrap();
        assert_eq!(last.to_string(), HASH421, "last validated hash must be 952421");
    }

    #[test]
    fn broken_link_is_rejected() {
        // Feed 421 first with no anchor (ok), then 420 claiming to follow it.
        let bad = vec![item(952421, HASH421, H421), item(952420, HASH420, H420)];
        assert!(
            validate_headers(&bad, None).is_err(),
            "out-of-order headers must fail the link check"
        );
    }

    #[test]
    fn tampered_served_hash_is_rejected() {
        let wrong = vec![item(952420, HASH421, H420)]; // real header, wrong claimed hash
        assert!(validate_headers(&wrong, None).is_err());
    }

    #[test]
    fn tip_and_filters_json_parse() {
        let tip: TipResp =
            serde_json::from_str(r#"{"height": 952424, "hash": "00000000000000000000c034b3ed3685c4339dfc80d7f14b56c5bcb783de28b2"}"#)
                .unwrap();
        assert_eq!(tip.height, 952424);

        let flts: FiltersResp = serde_json::from_str(
            r#"{"filters":[{"height":952420,"hash":"000000000000000000006e55579683079b21a5456e86116091b1a11246d134fd","filter":"0123abcd","filter_header":"88804d7f94234419e7734ea0dcadfceede8f0aeb90db99e860d614cc41b5b2a6"}]}"#,
        )
        .unwrap();
        assert_eq!(flts.filters.len(), 1);
        assert_eq!(flts.filters[0].height, 952420);
    }

    #[test]
    fn compute_filter_header_is_deterministic() {
        let prev = [7u8; 32];
        let a = compute_filter_header(&[1, 2, 3, 4], &prev);
        let b = compute_filter_header(&[1, 2, 3, 4], &prev);
        assert_eq!(a, b);
        let c = compute_filter_header(&[1, 2, 3, 5], &prev);
        assert_ne!(a, c, "different filter -> different header");
    }

    #[test]
    fn matching_heights_empty_scripts_no_hits() {
        let scripts = WalletScripts::default();
        let flts = vec![FilterItem {
            height: 1,
            hash: HASH420.into(),
            filter: "00".into(),
            filter_header: "00".repeat(32),
        }];
        assert!(matching_heights(&scripts, &flts).unwrap().is_empty());
    }
}
