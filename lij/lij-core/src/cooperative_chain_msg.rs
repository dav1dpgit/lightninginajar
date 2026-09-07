// cooperative_chain_msg.rs
//
// Step 4a — wire protocol for the cooperative chain-data path.
// Custom Lightning peer messages exchanged between wallet and LSP over BOLT 8.
//
// This file defines ONLY the data types and their encoding. The handler
// that wires these into LDK's PeerManager comes in step 4b. The bridge
// that exposes these to the rest of the wallet (filling the
// CooperativeBroadcaster and CooperativeFeeSource trait stubs from
// steps 1 and 2) comes in step 4c.
//
// Wire format
// -----------
// Every message body starts with a 1-byte protocol version. Currently
// PROTOCOL_VERSION = 1. Future revisions can either bump this byte or
// allocate new message IDs for incompatible changes.
//
// Type IDs are in the experimental odd-number range (>=32768 per BOLT 1)
// so that a peer that doesn't understand them can ignore them safely.
// Range 32801..=32810 is reserved here.
//
// BLIP candidacy
// --------------
// This format is intended to be documented as a candidate BLIP for
// cross-wallet adoption. Implementations should be compatible byte-for-byte.
// No plotzwerks-specific assumptions baked in.

use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, ScriptBuf, Txid};
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::ln::msgs::DecodeError;

/// Protocol version byte at the start of every message body.
pub const PROTOCOL_VERSION: u8 = 2; // bumped to v2 in step 8c (raw_tx_bytes added to FundingTxConfirmed)

// ── Type IDs ────────────────────────────────────────────────────────────────
// Odd numbers in BOLT 1's experimental range. Order matches the §4 design doc.

/// Wallet → LSP: subscribe to chain data, request initial bundle.
pub const TYPE_SUBSCRIBE_CHAIN_DATA: u16 = 32801;
/// LSP → Wallet: initial state on subscribe.
pub const TYPE_CHAIN_DATA_BUNDLE: u16 = 32803;
/// LSP → Wallet: new block tip.
pub const TYPE_BLOCK_HEIGHT_UPDATE: u16 = 32805;
/// LSP → Wallet: specific funding-tx confirmation.
pub const TYPE_FUNDING_TX_CONFIRMED: u16 = 32807;
/// LSP → Wallet: updated fee schedule.
pub const TYPE_FEE_SCHEDULE_UPDATE: u16 = 32809;
/// LSP → Wallet: channel-state change observed by LSP.
pub const TYPE_CHANNEL_STATE_UPDATE: u16 = 32811;
/// Wallet → LSP: register interest in a transaction.
pub const TYPE_REGISTER_WATCH_TX: u16 = 32813;
/// Wallet → LSP: register interest in a watched output.
pub const TYPE_REGISTER_WATCH_OUTPUT: u16 = 32815;
/// Wallet → LSP: ask LSP to broadcast a tx for us.
pub const TYPE_BROADCAST_TX: u16 = 32817;
/// LSP → Wallet: result of a broadcast request.
pub const TYPE_BROADCAST_ACK: u16 = 32819;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn write_version<W: Writer>(w: &mut W) -> Result<(), std::io::Error> {
    PROTOCOL_VERSION.write(w)
}

fn read_version<R: std::io::Read>(r: &mut R) -> Result<u8, DecodeError> {
    let v: u8 = Readable::read(r)?;
    if v != PROTOCOL_VERSION {
        // Unknown protocol version; report as InvalidValue so peer can
        // surface the disconnect. A future-proof handler may negotiate
        // versions in a separate handshake; for now we hard-require v1.
        return Err(DecodeError::InvalidValue);
    }
    Ok(v)
}

// ── 1. SubscribeChainData (wallet → LSP) ────────────────────────────────────
// Sent on peer connect to request initial state + ongoing pushes.
// Includes the wallet's interest registry snapshot so the LSP knows
// what specific txs/outputs to watch on our behalf.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribeChainData {
    /// All txids the wallet currently wants watched.
    pub watch_txids: Vec<Txid>,
    /// All script-pubkeys the wallet currently wants watched.
    pub watch_scripts: Vec<ScriptBuf>,
}

impl Writeable for SubscribeChainData {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        (self.watch_txids.len() as u16).write(w)?;
        for txid in &self.watch_txids {
            txid.write(w)?;
        }
        (self.watch_scripts.len() as u16).write(w)?;
        for s in &self.watch_scripts {
            s.write(w)?;
        }
        Ok(())
    }
}

impl Readable for SubscribeChainData {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let n_txids: u16 = Readable::read(r)?;
        let mut watch_txids = Vec::with_capacity(n_txids as usize);
        for _ in 0..n_txids {
            watch_txids.push(Readable::read(r)?);
        }
        let n_scripts: u16 = Readable::read(r)?;
        let mut watch_scripts = Vec::with_capacity(n_scripts as usize);
        for _ in 0..n_scripts {
            watch_scripts.push(Readable::read(r)?);
        }
        Ok(Self { watch_txids, watch_scripts })
    }
}

impl Type for SubscribeChainData {
    fn type_id(&self) -> u16 { TYPE_SUBSCRIBE_CHAIN_DATA }
}

// ── 2. ChainDataBundle (LSP → wallet) ───────────────────────────────────────
// Initial state pushed in response to SubscribeChainData. Contains
// everything needed to compute time-to-useful-block-height under 5s.
// Per design doc §6 cold-start: bundled subscribe response.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainDataBundle {
    /// Current chain tip block height per LSP's own LND.
    pub tip_height: u32,
    /// Current chain tip blockhash.
    pub tip_blockhash: BlockHash,
    /// Recent block hashes for the last N blocks (most recent first).
    /// Used for short reorg detection without full chain history.
    pub recent_blockhashes: Vec<BlockHash>,
    /// Fee rate (sat per vByte) for fast confirmation.
    pub fee_sat_per_vb_fast: u32,
    /// Fee rate for medium-priority.
    pub fee_sat_per_vb_medium: u32,
    /// Fee rate for slow.
    pub fee_sat_per_vb_slow: u32,
}

impl Writeable for ChainDataBundle {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.tip_height.write(w)?;
        self.tip_blockhash.write(w)?;
        (self.recent_blockhashes.len() as u16).write(w)?;
        for h in &self.recent_blockhashes {
            h.write(w)?;
        }
        self.fee_sat_per_vb_fast.write(w)?;
        self.fee_sat_per_vb_medium.write(w)?;
        self.fee_sat_per_vb_slow.write(w)?;
        Ok(())
    }
}

impl Readable for ChainDataBundle {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let tip_height = Readable::read(r)?;
        let tip_blockhash = Readable::read(r)?;
        let n_recent: u16 = Readable::read(r)?;
        let mut recent_blockhashes = Vec::with_capacity(n_recent as usize);
        for _ in 0..n_recent {
            recent_blockhashes.push(Readable::read(r)?);
        }
        Ok(Self {
            tip_height,
            tip_blockhash,
            recent_blockhashes,
            fee_sat_per_vb_fast: Readable::read(r)?,
            fee_sat_per_vb_medium: Readable::read(r)?,
            fee_sat_per_vb_slow: Readable::read(r)?,
        })
    }
}

impl Type for ChainDataBundle {
    fn type_id(&self) -> u16 { TYPE_CHAIN_DATA_BUNDLE }
}

// ── 3. BlockHeightUpdate (LSP → wallet) ─────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeightUpdate {
    pub new_height: u32,
    pub new_blockhash: BlockHash,
}

impl Writeable for BlockHeightUpdate {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.new_height.write(w)?;
        self.new_blockhash.write(w)
    }
}

impl Readable for BlockHeightUpdate {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        Ok(Self {
            new_height: Readable::read(r)?,
            new_blockhash: Readable::read(r)?,
        })
    }
}

impl Type for BlockHeightUpdate {
    fn type_id(&self) -> u16 { TYPE_BLOCK_HEIGHT_UPDATE }
}

// ── 4. FundingTxConfirmed (LSP → wallet) ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingTxConfirmed {
    pub txid: Txid,
    pub confirmed_at_height: u32,
    pub blockhash_of_confirmation: BlockHash,
    /// Number of confirmations as of this message.
    pub confirmations: u32,
    /// The raw funding transaction bytes. Wallet verifies sha256d(raw_tx_bytes)
    /// matches `txid` before passing to LDK's Confirm trait. Added in protocol
    /// v2 (step 8c) — without these bytes, the wallet cannot advance LDK's
    /// channel state on cooperative confirmation messages.
    pub raw_tx_bytes: Vec<u8>,
    /// Step 3.6 (SCID fix): position of the funding tx within its block.
    /// Required for LDK to compute the correct on-chain SCID. Without
    /// it LDK falls back to 0 placeholder, the resulting SCID doesn't
    /// match the LSP's view of the channel, and invoice route hints
    /// become unrecognizable to the LSP. Old senders may not include
    /// this field; the Readable impl defaults to 0 on ShortRead for
    /// backwards compatibility.
    pub tx_index: u32,
}

impl Writeable for FundingTxConfirmed {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.txid.write(w)?;
        self.confirmed_at_height.write(w)?;
        self.blockhash_of_confirmation.write(w)?;
        self.confirmations.write(w)?;
        // 1MB sanity cap on tx bytes (mirrors BroadcastTx max).
        if self.raw_tx_bytes.len() > 1_000_000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "raw_tx_bytes exceeds 1MB",
            ));
        }
        (self.raw_tx_bytes.len() as u32).write(w)?;
        w.write_all(&self.raw_tx_bytes)?;
        // Step 3.6 (SCID fix): tx_index appended at end. Backwards-
        // compatible — old decoders ignore trailing bytes.
        self.tx_index.write(w)
    }
}

impl Readable for FundingTxConfirmed {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let txid: Txid = Readable::read(r)?;
        let confirmed_at_height: u32 = Readable::read(r)?;
        let blockhash_of_confirmation: BlockHash = Readable::read(r)?;
        let confirmations: u32 = Readable::read(r)?;
        let len: u32 = Readable::read(r)?;
        if len > 1_000_000 {
            return Err(DecodeError::InvalidValue);
        }
        let mut raw_tx_bytes = vec![0u8; len as usize];
        r.read_exact(&mut raw_tx_bytes).map_err(|_| DecodeError::ShortRead)?;
        // Step 3.6 (SCID fix): tx_index appended after raw_tx_bytes.
        // Backwards-compatible — old senders don't write this field;
        // we default to 0 on ShortRead.
        let tx_index: u32 = match Readable::read(r) {
            Ok(v) => v,
            Err(DecodeError::ShortRead) => 0,
            Err(e) => return Err(e),
        };
        Ok(Self {
            txid,
            confirmed_at_height,
            blockhash_of_confirmation,
            confirmations,
            raw_tx_bytes,
            tx_index,
        })
    }
}

impl Type for FundingTxConfirmed {
    fn type_id(&self) -> u16 { TYPE_FUNDING_TX_CONFIRMED }
}

// ── 5. FeeScheduleUpdate (LSP → wallet) ─────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeScheduleUpdate {
    pub fee_sat_per_vb_fast: u32,
    pub fee_sat_per_vb_medium: u32,
    pub fee_sat_per_vb_slow: u32,
}

impl Writeable for FeeScheduleUpdate {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.fee_sat_per_vb_fast.write(w)?;
        self.fee_sat_per_vb_medium.write(w)?;
        self.fee_sat_per_vb_slow.write(w)
    }
}

impl Readable for FeeScheduleUpdate {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        Ok(Self {
            fee_sat_per_vb_fast: Readable::read(r)?,
            fee_sat_per_vb_medium: Readable::read(r)?,
            fee_sat_per_vb_slow: Readable::read(r)?,
        })
    }
}

impl Type for FeeScheduleUpdate {
    fn type_id(&self) -> u16 { TYPE_FEE_SCHEDULE_UPDATE }
}

// ── 6. ChannelStateUpdate (LSP → wallet) ────────────────────────────────────
// Reports a state change in one of our channels as observed by the LSP.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStateChange {
    Pending = 0,
    Active = 1,
    Inactive = 2,
    CooperativeCloseInitiated = 3,
    ForceCloseInitiated = 4,
    ClosedOnChain = 5,
}

impl ChannelStateChange {
    fn as_u8(&self) -> u8 { *self as u8 }
    fn from_u8(b: u8) -> Result<Self, DecodeError> {
        match b {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Active),
            2 => Ok(Self::Inactive),
            3 => Ok(Self::CooperativeCloseInitiated),
            4 => Ok(Self::ForceCloseInitiated),
            5 => Ok(Self::ClosedOnChain),
            _ => Err(DecodeError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelStateUpdate {
    /// Counterparty pubkey identifying the channel (combined with funding outpoint
    /// for unambiguous identification in future protocol versions).
    pub counterparty_pubkey: PublicKey,
    pub funding_txid: Txid,
    pub state: ChannelStateChange,
    /// Block height at which the LSP observed this state change, if known.
    pub observed_at_height: Option<u32>,
}

impl Writeable for ChannelStateUpdate {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.counterparty_pubkey.write(w)?;
        self.funding_txid.write(w)?;
        self.state.as_u8().write(w)?;
        match self.observed_at_height {
            Some(h) => {
                1u8.write(w)?;
                h.write(w)
            }
            None => 0u8.write(w),
        }
    }
}

impl Readable for ChannelStateUpdate {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let counterparty_pubkey = Readable::read(r)?;
        let funding_txid = Readable::read(r)?;
        let state_byte: u8 = Readable::read(r)?;
        let state = ChannelStateChange::from_u8(state_byte)?;
        let has_height: u8 = Readable::read(r)?;
        let observed_at_height = match has_height {
            0 => None,
            1 => Some(Readable::read(r)?),
            _ => return Err(DecodeError::InvalidValue),
        };
        Ok(Self { counterparty_pubkey, funding_txid, state, observed_at_height })
    }
}

impl Type for ChannelStateUpdate {
    fn type_id(&self) -> u16 { TYPE_CHANNEL_STATE_UPDATE }
}

// ── 7. RegisterWatchTx (wallet → LSP) ───────────────────────────────────────
// Wallet asks LSP to start watching for a specific txid.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterWatchTx {
    pub txid: Txid,
    pub script_pubkey: ScriptBuf,
}

impl Writeable for RegisterWatchTx {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.txid.write(w)?;
        self.script_pubkey.write(w)
    }
}

impl Readable for RegisterWatchTx {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        Ok(Self {
            txid: Readable::read(r)?,
            script_pubkey: Readable::read(r)?,
        })
    }
}

impl Type for RegisterWatchTx {
    fn type_id(&self) -> u16 { TYPE_REGISTER_WATCH_TX }
}

// ── 8. RegisterWatchOutput (wallet → LSP) ───────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterWatchOutput {
    pub funding_txid: Txid,
    pub output_index: u32,
    pub script_pubkey: ScriptBuf,
    /// Block hash where the output was created, if known.
    pub created_in_block: Option<BlockHash>,
}

impl Writeable for RegisterWatchOutput {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.funding_txid.write(w)?;
        self.output_index.write(w)?;
        self.script_pubkey.write(w)?;
        match self.created_in_block {
            Some(h) => {
                1u8.write(w)?;
                h.write(w)
            }
            None => 0u8.write(w),
        }
    }
}

impl Readable for RegisterWatchOutput {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let funding_txid = Readable::read(r)?;
        let output_index = Readable::read(r)?;
        let script_pubkey = Readable::read(r)?;
        let has_block: u8 = Readable::read(r)?;
        let created_in_block = match has_block {
            0 => None,
            1 => Some(Readable::read(r)?),
            _ => return Err(DecodeError::InvalidValue),
        };
        Ok(Self { funding_txid, output_index, script_pubkey, created_in_block })
    }
}

impl Type for RegisterWatchOutput {
    fn type_id(&self) -> u16 { TYPE_REGISTER_WATCH_OUTPUT }
}

// ── 9. BroadcastTx (wallet → LSP) ───────────────────────────────────────────
// Wallet asks LSP to relay a raw tx to the Bitcoin network.
// Used by LijBroadcaster's cooperative path.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastTx {
    /// Client-supplied request ID; LSP echoes it in BroadcastAck.
    pub request_id: u64,
    pub raw_tx: Vec<u8>,
}

impl Writeable for BroadcastTx {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.request_id.write(w)?;
        (self.raw_tx.len() as u32).write(w)?;
        w.write_all(&self.raw_tx)
    }
}

impl Readable for BroadcastTx {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let request_id = Readable::read(r)?;
        let len: u32 = Readable::read(r)?;
        // Sanity cap: largest standard Bitcoin tx is ~100 KB. Anything
        // bigger is malformed or hostile. 1 MB is generous safety margin.
        if len > 1_000_000 {
            return Err(DecodeError::InvalidValue);
        }
        let mut raw_tx = vec![0u8; len as usize];
        r.read_exact(&mut raw_tx).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { request_id, raw_tx })
    }
}

impl Type for BroadcastTx {
    fn type_id(&self) -> u16 { TYPE_BROADCAST_TX }
}

// ── 10. BroadcastAck (LSP → wallet) ─────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastResult {
    /// LSP relayed the tx to its mempool.
    Relayed = 0,
    /// LSP rejected the tx (invalid signature, conflicting input, etc.).
    Rejected = 1,
    /// LSP can't relay right now (offline, congested, no path).
    Unavailable = 2,
}

impl BroadcastResult {
    fn as_u8(&self) -> u8 { *self as u8 }
    fn from_u8(b: u8) -> Result<Self, DecodeError> {
        match b {
            0 => Ok(Self::Relayed),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Unavailable),
            _ => Err(DecodeError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastAck {
    /// Echo of BroadcastTx.request_id.
    pub request_id: u64,
    pub result: BroadcastResult,
    /// Optional human-readable detail. Empty if none.
    pub detail: String,
}

impl Writeable for BroadcastAck {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_version(w)?;
        self.request_id.write(w)?;
        self.result.as_u8().write(w)?;
        let bytes = self.detail.as_bytes();
        if bytes.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "detail too long",
            ));
        }
        (bytes.len() as u16).write(w)?;
        w.write_all(bytes)
    }
}

impl Readable for BroadcastAck {
    fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
        let _v = read_version(r)?;
        let request_id = Readable::read(r)?;
        let result_byte: u8 = Readable::read(r)?;
        let result = BroadcastResult::from_u8(result_byte)?;
        let len: u16 = Readable::read(r)?;
        let mut detail_bytes = vec![0u8; len as usize];
        r.read_exact(&mut detail_bytes).map_err(|_| DecodeError::ShortRead)?;
        let detail = String::from_utf8(detail_bytes)
            .map_err(|_| DecodeError::InvalidValue)?;
        Ok(Self { request_id, result, detail })
    }
}

impl Type for BroadcastAck {
    fn type_id(&self) -> u16 { TYPE_BROADCAST_ACK }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn dummy_txid(b: u8) -> Txid {
        Txid::from_byte_array([b; 32])
    }
    fn dummy_blockhash(b: u8) -> BlockHash {
        BlockHash::from_byte_array([b; 32])
    }
    fn dummy_script() -> ScriptBuf {
        ScriptBuf::from(vec![0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                              11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac])
    }
    fn dummy_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xab; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    /// Encode/decode roundtrip helper. Verifies type_id and bytewise stability.
    fn roundtrip<T: Writeable + Readable + PartialEq + std::fmt::Debug + Type>(
        msg: &T,
        expected_type_id: u16,
    ) {
        assert_eq!(msg.type_id(), expected_type_id, "type_id mismatch");
        let mut bytes = Vec::new();
        msg.write(&mut bytes).expect("write should succeed");
        let mut cursor = std::io::Cursor::new(&bytes);
        let decoded = T::read(&mut cursor).expect("read should succeed");
        assert_eq!(*msg, decoded, "roundtrip mismatch");
        // Re-encode the decoded message, verify byte-stable
        let mut bytes2 = Vec::new();
        decoded.write(&mut bytes2).expect("re-write should succeed");
        assert_eq!(bytes, bytes2, "encoding not byte-stable");
    }

    #[test]
    fn roundtrip_subscribe_chain_data_empty() {
        let msg = SubscribeChainData {
            watch_txids: vec![],
            watch_scripts: vec![],
        };
        roundtrip(&msg, TYPE_SUBSCRIBE_CHAIN_DATA);
    }

    #[test]
    fn roundtrip_subscribe_chain_data_populated() {
        let msg = SubscribeChainData {
            watch_txids: vec![dummy_txid(1), dummy_txid(2), dummy_txid(3)],
            watch_scripts: vec![dummy_script(), dummy_script()],
        };
        roundtrip(&msg, TYPE_SUBSCRIBE_CHAIN_DATA);
    }

    #[test]
    fn roundtrip_chain_data_bundle() {
        let msg = ChainDataBundle {
            tip_height: 880_247,
            tip_blockhash: dummy_blockhash(7),
            recent_blockhashes: vec![dummy_blockhash(7), dummy_blockhash(6), dummy_blockhash(5)],
            fee_sat_per_vb_fast: 32,
            fee_sat_per_vb_medium: 16,
            fee_sat_per_vb_slow: 4,
        };
        roundtrip(&msg, TYPE_CHAIN_DATA_BUNDLE);
    }

    #[test]
    fn roundtrip_block_height_update() {
        let msg = BlockHeightUpdate {
            new_height: 880_248,
            new_blockhash: dummy_blockhash(8),
        };
        roundtrip(&msg, TYPE_BLOCK_HEIGHT_UPDATE);
    }

    #[test]
    fn roundtrip_funding_tx_confirmed() {
        let msg = FundingTxConfirmed {
            txid: dummy_txid(0xab),
            confirmed_at_height: 880_103,
            blockhash_of_confirmation: dummy_blockhash(0x42),
            confirmations: 3,
            raw_tx_bytes: vec![1u8, 2, 3, 4],
            tx_index: 17,  // Step 3.6 (SCID fix)
        };
        roundtrip(&msg, TYPE_FUNDING_TX_CONFIRMED);
    }

    #[test]
    fn roundtrip_fee_schedule_update() {
        let msg = FeeScheduleUpdate {
            fee_sat_per_vb_fast: 50,
            fee_sat_per_vb_medium: 25,
            fee_sat_per_vb_slow: 8,
        };
        roundtrip(&msg, TYPE_FEE_SCHEDULE_UPDATE);
    }

    #[test]
    fn roundtrip_channel_state_update_with_height() {
        let msg = ChannelStateUpdate {
            counterparty_pubkey: dummy_pubkey(),
            funding_txid: dummy_txid(0x77),
            state: ChannelStateChange::Active,
            observed_at_height: Some(880_500),
        };
        roundtrip(&msg, TYPE_CHANNEL_STATE_UPDATE);
    }

    #[test]
    fn roundtrip_channel_state_update_without_height() {
        let msg = ChannelStateUpdate {
            counterparty_pubkey: dummy_pubkey(),
            funding_txid: dummy_txid(0x99),
            state: ChannelStateChange::ForceCloseInitiated,
            observed_at_height: None,
        };
        roundtrip(&msg, TYPE_CHANNEL_STATE_UPDATE);
    }

    #[test]
    fn roundtrip_register_watch_tx() {
        let msg = RegisterWatchTx {
            txid: dummy_txid(0x33),
            script_pubkey: dummy_script(),
        };
        roundtrip(&msg, TYPE_REGISTER_WATCH_TX);
    }

    #[test]
    fn roundtrip_register_watch_output_with_block() {
        let msg = RegisterWatchOutput {
            funding_txid: dummy_txid(0x55),
            output_index: 1,
            script_pubkey: dummy_script(),
            created_in_block: Some(dummy_blockhash(0x11)),
        };
        roundtrip(&msg, TYPE_REGISTER_WATCH_OUTPUT);
    }

    #[test]
    fn roundtrip_register_watch_output_without_block() {
        let msg = RegisterWatchOutput {
            funding_txid: dummy_txid(0x66),
            output_index: 0,
            script_pubkey: dummy_script(),
            created_in_block: None,
        };
        roundtrip(&msg, TYPE_REGISTER_WATCH_OUTPUT);
    }

    #[test]
    fn roundtrip_broadcast_tx() {
        let msg = BroadcastTx {
            request_id: 0xDEADBEEFCAFEBABE,
            raw_tx: vec![0u8; 250],
        };
        roundtrip(&msg, TYPE_BROADCAST_TX);
    }

    #[test]
    fn roundtrip_broadcast_ack_relayed() {
        let msg = BroadcastAck {
            request_id: 42,
            result: BroadcastResult::Relayed,
            detail: String::new(),
        };
        roundtrip(&msg, TYPE_BROADCAST_ACK);
    }

    #[test]
    fn roundtrip_broadcast_ack_rejected_with_detail() {
        let msg = BroadcastAck {
            request_id: 100,
            result: BroadcastResult::Rejected,
            detail: "bad-txns-inputs-missingorspent".to_string(),
        };
        roundtrip(&msg, TYPE_BROADCAST_ACK);
    }

    #[test]
    fn roundtrip_broadcast_ack_unavailable() {
        let msg = BroadcastAck {
            request_id: 0,
            result: BroadcastResult::Unavailable,
            detail: "lsp offline".to_string(),
        };
        roundtrip(&msg, TYPE_BROADCAST_ACK);
    }

    #[test]
    fn type_ids_are_unique() {
        let ids = [
            TYPE_SUBSCRIBE_CHAIN_DATA,
            TYPE_CHAIN_DATA_BUNDLE,
            TYPE_BLOCK_HEIGHT_UPDATE,
            TYPE_FUNDING_TX_CONFIRMED,
            TYPE_FEE_SCHEDULE_UPDATE,
            TYPE_CHANNEL_STATE_UPDATE,
            TYPE_REGISTER_WATCH_TX,
            TYPE_REGISTER_WATCH_OUTPUT,
            TYPE_BROADCAST_TX,
            TYPE_BROADCAST_ACK,
        ];
        let mut sorted = ids.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate type IDs");
    }

    #[test]
    fn type_ids_in_experimental_range() {
        let ids = [
            TYPE_SUBSCRIBE_CHAIN_DATA,
            TYPE_CHAIN_DATA_BUNDLE,
            TYPE_BLOCK_HEIGHT_UPDATE,
            TYPE_FUNDING_TX_CONFIRMED,
            TYPE_FEE_SCHEDULE_UPDATE,
            TYPE_CHANNEL_STATE_UPDATE,
            TYPE_REGISTER_WATCH_TX,
            TYPE_REGISTER_WATCH_OUTPUT,
            TYPE_BROADCAST_TX,
            TYPE_BROADCAST_ACK,
        ];
        for id in ids {
            assert!(id >= 32768, "type {id} below experimental range");
            assert_eq!(id % 2, 1, "type {id} not odd (BOLT 1: ignorable messages must be odd)");
        }
    }

    #[test]
    fn rejects_wrong_protocol_version() {
        // Manually construct a v=99 message body and verify it fails to decode.
        // Current PROTOCOL_VERSION is 2 (bumped in step 8c). Use 99 as
        // "definitely future, definitely wrong" so this test stays robust
        // through future protocol bumps below 99.
        let mut bytes = Vec::new();
        99u8.write(&mut bytes).unwrap(); // wrong version
        880_000u32.write(&mut bytes).unwrap();
        dummy_blockhash(1).write(&mut bytes).unwrap();
        let mut cursor = std::io::Cursor::new(&bytes);
        let result = BlockHeightUpdate::read(&mut cursor);
        assert!(result.is_err(), "should reject wrong protocol version");
    }
}
