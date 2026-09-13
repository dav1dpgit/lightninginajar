#!/bin/sh
set -eox

RUSTFLAGS="--cfg=dnssec_prover_c_hashers_test --cfg=dnssec_prover_c_hashers" cargo test --features std,tokio,validation

cargo $RUST_VERSION test --no-default-features
cargo $RUST_VERSION test
cargo $RUST_VERSION test --no-default-features --features std
cargo $RUST_VERSION test --no-default-features --features tokio
cargo $RUST_VERSION test --no-default-features --features validation
cargo $RUST_VERSION test --features std,tokio,validation
cargo $RUST_VERSION test --features std,tokio,validation,slower_smaller_binary
cargo $RUST_VERSION test --no-default-features --features build_server
cargo $RUST_VERSION build --lib
cargo $RUST_VERSION build --lib --features std
cargo $RUST_VERSION build --lib --features tokio
cargo $RUST_VERSION build --lib --features validation
cargo $RUST_VERSION build --lib --features std,tokio,validation
cargo $RUST_VERSION build --lib --features std,tokio,validation --release
cargo $RUST_VERSION build --bin http_proof_gen --features build_server
cargo $RUST_VERSION doc --features std,tokio,validation
cd fuzz
RUSTFLAGS="--cfg=fuzzing --cfg=dnssec_prover_fuzzing" RUSTC_BOOTSTRAP=1 cargo build --features stdin_fuzz
RUSTFLAGS="--cfg=fuzzing --cfg=dnssec_prover_fuzzing" RUSTC_BOOTSTRAP=1 cargo test
cd ../bench
RUSTFLAGS="--cfg=dnssec_validate_bench" cargo bench
