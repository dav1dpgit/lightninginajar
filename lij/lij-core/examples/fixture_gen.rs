// fixture_gen.rs — standalone wire-format fixture generator
//
// Self-contained: no external deps, no Cargo project needed.
// Writes canonical bytes for every LiJ cooperative chain message type,
// matching the byte layout from lij-core/src/cooperative_chain_msg.rs
// exactly. The encoding logic here is a hand transliteration of the
// Writeable impls in that file.
//
// Why standalone: lij-core's lib has unconditional web_sys imports that
// only compile on wasm32. We don't want to either modify the wallet
// source or wrestle with target gating, so we just hand-write the wire
// bytes here. The wire format is small, primitives are stable, and
// pinning byte layout directly is more robust than chasing library
// version compatibility.
//
// Build and run (no Cargo):
//   rustc fixture_gen.rs -o /tmp/fixture_gen
//   /tmp/fixture_gen

const PROTOCOL_VERSION: u8 = 2;

// Type IDs (must match cooperative_chain_msg.rs)
const TYPE_SUBSCRIBE_CHAIN_DATA: u16   = 32801;
const TYPE_CHAIN_DATA_BUNDLE: u16      = 32803;
const TYPE_BLOCK_HEIGHT_UPDATE: u16    = 32805;
const TYPE_FUNDING_TX_CONFIRMED: u16   = 32807;
const TYPE_FEE_SCHEDULE_UPDATE: u16    = 32809;
const TYPE_CHANNEL_STATE_UPDATE: u16   = 32811;
const TYPE_REGISTER_WATCH_TX: u16      = 32813;
const TYPE_REGISTER_WATCH_OUTPUT: u16  = 32815;
const TYPE_BROADCAST_TX: u16           = 32817;
const TYPE_BROADCAST_ACK: u16          = 32819;

// ChannelStateChange enum byte values
#[allow(dead_code)]
const STATE_PENDING: u8           = 0;
const STATE_ACTIVE: u8            = 1;
#[allow(dead_code)]
const STATE_INACTIVE: u8          = 2;
#[allow(dead_code)]
const STATE_COOP_CLOSE_INIT: u8   = 3;
const STATE_FORCE_CLOSE_INIT: u8  = 4;
#[allow(dead_code)]
const STATE_CLOSED_ON_CHAIN: u8   = 5;

// BroadcastResult enum byte values
const RESULT_RELAYED: u8     = 0;
const RESULT_REJECTED: u8    = 1;
const RESULT_UNAVAILABLE: u8 = 2;

// ── Wire primitives (big-endian, matching LDK Writeable conventions) ────────

fn write_u8(out: &mut Vec<u8>, v: u8)   { out.push(v); }
fn write_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_be_bytes()); }
fn write_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }
fn write_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_be_bytes()); }

fn write_bytes_u16(out: &mut Vec<u8>, b: &[u8]) {
    write_u16(out, b.len() as u16);
    out.extend_from_slice(b);
}
fn write_bytes_u32(out: &mut Vec<u8>, b: &[u8]) {
    write_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

fn write_version(out: &mut Vec<u8>) { write_u8(out, PROTOCOL_VERSION); }

// 32-byte hash (Txid, BlockHash) — 32 raw bytes, no length prefix
fn write_hash32(out: &mut Vec<u8>, h: &[u8; 32]) { out.extend_from_slice(h); }

// 33-byte compressed pubkey — raw bytes, no length prefix
fn write_pubkey(out: &mut Vec<u8>, pk: &[u8; 33]) { out.extend_from_slice(pk); }

// Option<u32>: 1-byte tag (0=None, 1=Some), then u32 if Some
fn write_opt_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => write_u8(out, 0),
        Some(x) => { write_u8(out, 1); write_u32(out, x); }
    }
}

// Option<[u8; 32]>: 1-byte tag, then 32-byte hash if Some
fn write_opt_hash32(out: &mut Vec<u8>, v: Option<&[u8; 32]>) {
    match v {
        None => write_u8(out, 0),
        Some(h) => { write_u8(out, 1); write_hash32(out, h); }
    }
}

// ── Message encoders (mirror cooperative_chain_msg.rs Writeable impls) ──────

fn encode_subscribe_chain_data(watch_txids: &[[u8; 32]], watch_scripts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u16(&mut out, watch_txids.len() as u16);
    for t in watch_txids { write_hash32(&mut out, t); }
    write_u16(&mut out, watch_scripts.len() as u16);
    for s in watch_scripts { write_bytes_u16(&mut out, s); }
    out
}

fn encode_chain_data_bundle(
    tip_height: u32,
    tip_blockhash: &[u8; 32],
    recent: &[[u8; 32]],
    fast: u32, medium: u32, slow: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u32(&mut out, tip_height);
    write_hash32(&mut out, tip_blockhash);
    write_u16(&mut out, recent.len() as u16);
    for h in recent { write_hash32(&mut out, h); }
    write_u32(&mut out, fast);
    write_u32(&mut out, medium);
    write_u32(&mut out, slow);
    out
}

fn encode_block_height_update(new_height: u32, new_blockhash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u32(&mut out, new_height);
    write_hash32(&mut out, new_blockhash);
    out
}

fn encode_funding_tx_confirmed(
    txid: &[u8; 32],
    confirmed_at_height: u32,
    blockhash_of_confirmation: &[u8; 32],
    confirmations: u32,
    raw_tx_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_hash32(&mut out, txid);
    write_u32(&mut out, confirmed_at_height);
    write_hash32(&mut out, blockhash_of_confirmation);
    write_u32(&mut out, confirmations);
    write_bytes_u32(&mut out, raw_tx_bytes);
    out
}

fn encode_fee_schedule_update(fast: u32, medium: u32, slow: u32) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u32(&mut out, fast);
    write_u32(&mut out, medium);
    write_u32(&mut out, slow);
    out
}

fn encode_channel_state_update(
    counterparty_pubkey: &[u8; 33],
    funding_txid: &[u8; 32],
    state_byte: u8,
    observed_at_height: Option<u32>,
) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_pubkey(&mut out, counterparty_pubkey);
    write_hash32(&mut out, funding_txid);
    write_u8(&mut out, state_byte);
    write_opt_u32(&mut out, observed_at_height);
    out
}

fn encode_register_watch_tx(txid: &[u8; 32], script: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_hash32(&mut out, txid);
    write_bytes_u16(&mut out, script);
    out
}

fn encode_register_watch_output(
    funding_txid: &[u8; 32],
    output_index: u32,
    script: &[u8],
    created_in_block: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_hash32(&mut out, funding_txid);
    write_u32(&mut out, output_index);
    write_bytes_u16(&mut out, script);
    write_opt_hash32(&mut out, created_in_block);
    out
}

fn encode_broadcast_tx(request_id: u64, raw_tx: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u64(&mut out, request_id);
    write_bytes_u32(&mut out, raw_tx);
    out
}

fn encode_broadcast_ack(request_id: u64, result_byte: u8, detail: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_version(&mut out);
    write_u64(&mut out, request_id);
    write_u8(&mut out, result_byte);
    let detail_bytes = detail.as_bytes();
    write_u16(&mut out, detail_bytes.len() as u16);
    out.extend_from_slice(detail_bytes);
    out
}

// ── Test fixtures (deterministic inputs matching JS test) ────────────────────

fn hash32(b: u8) -> [u8; 32] { [b; 32] }

fn dummy_script() -> Vec<u8> {
    vec![
        0x76, 0xa9, 0x14,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        0x88, 0xac,
    ]
}

// Compressed secp256k1 generator point G — both this Rust generator and the
// JS test hardcode the exact same 33 bytes, so the channel_state fixtures
// match without needing any elliptic-curve math on either side.
const DUMMY_PUBKEY: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
    0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}

fn emit(name: &str, type_id: u16, bytes: &[u8]) {
    let pad = if name.len() < 38 { 38 - name.len() } else { 2 };
    println!("  '{}':{}'{}',", name, " ".repeat(pad), to_hex(bytes));
    eprintln!("    {} type={} len={}", name, type_id, bytes.len());
}

fn main() {
    eprintln!("LiJ wire-format fixture generator (standalone)");
    eprintln!("Protocol version: {}", PROTOCOL_VERSION);
    eprintln!();

    println!("// ── BEGIN PASTE-READY FIXTURES (Rust-generated) ──");

    // 1. SubscribeChainData (empty)
    emit("subscribe_empty", TYPE_SUBSCRIBE_CHAIN_DATA,
        &encode_subscribe_chain_data(&[], &[]));

    // 2. SubscribeChainData (populated)
    emit("subscribe_populated", TYPE_SUBSCRIBE_CHAIN_DATA,
        &encode_subscribe_chain_data(
            &[hash32(1), hash32(2), hash32(3)],
            &[dummy_script(), dummy_script()]));

    // 3. ChainDataBundle
    emit("chain_data_bundle", TYPE_CHAIN_DATA_BUNDLE,
        &encode_chain_data_bundle(
            880_247, &hash32(7),
            &[hash32(7), hash32(6), hash32(5)],
            32, 16, 4));

    // 4. BlockHeightUpdate
    emit("block_height_update", TYPE_BLOCK_HEIGHT_UPDATE,
        &encode_block_height_update(880_248, &hash32(8)));

    // 5. FundingTxConfirmed
    emit("funding_tx_confirmed", TYPE_FUNDING_TX_CONFIRMED,
        &encode_funding_tx_confirmed(
            &hash32(0xab), 880_103, &hash32(0x42), 3, &[1, 2, 3, 4]));

    // 6. FeeScheduleUpdate
    emit("fee_schedule_update", TYPE_FEE_SCHEDULE_UPDATE,
        &encode_fee_schedule_update(50, 25, 8));

    // 7a. ChannelStateUpdate (with height)
    emit("channel_state_with_height", TYPE_CHANNEL_STATE_UPDATE,
        &encode_channel_state_update(
            &DUMMY_PUBKEY, &hash32(0x77), STATE_ACTIVE, Some(880_500)));

    // 7b. ChannelStateUpdate (without height)
    emit("channel_state_no_height", TYPE_CHANNEL_STATE_UPDATE,
        &encode_channel_state_update(
            &DUMMY_PUBKEY, &hash32(0x99), STATE_FORCE_CLOSE_INIT, None));

    // 8. RegisterWatchTx
    emit("register_watch_tx", TYPE_REGISTER_WATCH_TX,
        &encode_register_watch_tx(&hash32(0x33), &dummy_script()));

    // 9a. RegisterWatchOutput (with block)
    emit("register_watch_output_with_block", TYPE_REGISTER_WATCH_OUTPUT,
        &encode_register_watch_output(
            &hash32(0x55), 1, &dummy_script(), Some(&hash32(0x11))));

    // 9b. RegisterWatchOutput (without block)
    emit("register_watch_output_no_block", TYPE_REGISTER_WATCH_OUTPUT,
        &encode_register_watch_output(
            &hash32(0x66), 0, &dummy_script(), None));

    // 10. BroadcastTx
    emit("broadcast_tx", TYPE_BROADCAST_TX,
        &encode_broadcast_tx(0xDEADBEEFCAFEBABE, &vec![0u8; 250]));

    // 11a. BroadcastAck (Relayed)
    emit("broadcast_ack_relayed", TYPE_BROADCAST_ACK,
        &encode_broadcast_ack(42, RESULT_RELAYED, ""));

    // 11b. BroadcastAck (Rejected with detail)
    emit("broadcast_ack_rejected", TYPE_BROADCAST_ACK,
        &encode_broadcast_ack(100, RESULT_REJECTED, "bad-txns-inputs-missingorspent"));

    // 11c. BroadcastAck (Unavailable)
    emit("broadcast_ack_unavailable", TYPE_BROADCAST_ACK,
        &encode_broadcast_ack(0, RESULT_UNAVAILABLE, "lsp offline"));

    println!("// ── END PASTE-READY FIXTURES ──");
}
