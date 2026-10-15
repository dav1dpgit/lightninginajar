//! LIJOX's Tatara — the engine's pool core (plan r3 step 3; docs/design/mix/tatara-engine-r1.md; spec
//! docs/design/mix/LIJOX-tatara-v0.10.md; DP 2026-10-12 19:11 "Go on Step 3").
//!
//! Pure code: no socket, no timer, no storage, no random source of its own. The vendored joinstr v2 core
//! (lij/patches/joinstr-v2, patches P2–P10) builds and signs; this module checks every pool against LiJ's rules before
//! the phone signs anything:
//! - `caps`      — S6: the Phase 1 pool options and the limits, checked before anything is parsed further;
//! - `rederive`  — S10: our own re-derivation of the funding transaction and every exit from the registrations, written
//!   from the NIP's text, not through joinstr's builder;
//! - `checks`    — S4 (no payout equal to a pool, change or input script) and S5 (the checks before the funding
//!   signature).
//! - `client`    — the phone's side of the provider's routes: the seat (node key or ring signature), the seat key's
//!   requests, the provider's notices checked against its node key, the week's tag and ring (step 7, slice 1).
//! - `coin`      — the coin check (v0.10 §7): a member's coin proven from the filter server's answer — the transaction,
//!   Core's Merkle proof, its header's work against a floor — before the phone signs.
//! - `wallet`    — the wallet's own pieces (step 7, slice 2): the payout (this wallet's next m/86 address, or another
//!   wallet's taproot address), the pool's change address, the coins' keys as joinstr takes them, the coin lock after a
//!   restore.
//! - `records`   — the attempt records on the phone (step 7, slice 4): written before the coin signature, sealed, in
//!   every backup while unsettled, wiped fully; the chain decides what the wallet does next (send the exits, wipe, watch).
//! - `phone`     — one phone's attempt as the page drives it (step 8): the pool's key sealed to each opened seat in the
//!   announcement, the joiner's checks, the machine's posts sealed, the coin checks, the record, the complete funding.
//! - `store`     — the storage side lij-wasm calls (step 7, slice 6): the payout and change handed out together, the
//!   hold, a record saved or wiped with its coins, the settle pass, the holds reconciled at start and after a restore.
//! The page drives the attempt itself in step 8.

pub mod caps;
pub mod checks;
pub mod client;
pub mod coin;
pub mod machine;
pub mod phone;
pub mod wallet;
pub mod wire;
pub mod rederive;
pub mod records;
pub mod bump;
pub mod store;

#[cfg(test)]
mod fuzz_tests;
#[cfg(test)]
mod machine_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod jproof;   // S59: the compatibility proof with the public joinstr v2 code (ignored; run by jproof/run_proof.sh)

/// A BIP-340 tagged hash, our own (the NIP's `H(tag, x)`) — kept apart from joinstr's util so the re-derivation shares
/// no code with the builder it checks.
pub(crate) fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}
