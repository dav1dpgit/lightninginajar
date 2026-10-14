//! joinstr v2's protocol core, vendored for LiJ: the allow-listed modules only (Tatara v0.9 §15.2). Upstream's lib.rs
//! also declares chain, exit, http, peer, psbt, relay and wallet — the network, the files, the command line and the
//! PSBTs — which never come in (§15.3; review P3). Ours, not upstream's.
pub mod funding;
pub mod keys;
pub mod msg;
pub mod pool;
pub mod ring;
pub mod sign;
pub mod util;

#[cfg(test)]
mod lij_tests;
