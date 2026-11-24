# Reproducible build — how the served engine is checked against this source

The wallet is a static site: `lij-pwa/frontend/` is served as-is at https://lightninginajar.xyz, and the engine is the WebAssembly module `lij-pwa/frontend/pkg/lij_wasm_bg.wasm` (about 11.2 MB at engine v382) plus its JS glue `lij_wasm.js`. Both are built by the `lij-build` GitHub Actions workflow in this repository from `lij/` and committed back; the deploy branch is a byte copy of `lij-pwa/frontend/`.

## Recipe (what CI runs — `.github/workflows/lij-build.yml`)

```
# toolchain: lij/rust-toolchain.toml pins stable 1.90.0 with the wasm32-unknown-unknown target
rustup target add wasm32-unknown-unknown
curl -sSf https://rustwasm.github.io/wasm-pack/installer/init.sh | sh
cd lij
cargo clean -p lij-wasm
wasm-pack build --release --target web --out-dir ../../lij-pwa/frontend/pkg lij-wasm
```

Crate sources are vendored under `lij/vendor` and `lij/.cargo/config.toml` points Cargo at them (`replace-with = "vendored-sources"`), so the build does not fetch from crates.io. The `lightning` crate comes from `lij/patches/lightning` — see [ldk-patches.md](ldk-patches.md) for the full diff against upstream 0.2.7. `wasm-opt -Oz` runs as part of `wasm-pack build` (`lij/lij-wasm/Cargo.toml`).

## What is pinned (all of it, since page v710's workflow)

- The Rust toolchain: `lij/rust-toolchain.toml` — stable 1.90.0 since engine v241 (before that nightly-2025-01-01).
- Every crate: vendored under `lij/vendor`, `Cargo.lock` checksums; `wasm-bindgen` 0.2.128 (crate and CLI) at engine v382.
- The `lightning` patch set: in-tree.
- `wasm-pack` v0.15.0: the release tarball is downloaded from GitHub and refused unless its sha256 is `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a`.
- `wasm-opt` (binaryen) version_117 — the version wasm-pack v0.15.0 would fetch itself, now downloaded explicitly and refused unless its sha256 is `3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212`; it is put on PATH first, which is what wasm-pack uses when present.

Before v710 the workflow installed the latest wasm-pack from its installer script and let it fetch binaryen itself; the engine phase11-v239 row below was built that way (with v0.15.0 / version_117 — the versions current on 2026-09-06). The row after it is the first built under the pins.

The remaining variable is the runner image (`ubuntu-latest`: its clang is recorded in the `producers` section too, `Ubuntu clang 18.1.3`). The workflow's `cargo clean -p lij-wasm` before each build keeps the crate's own objects fresh; the vendored dependencies come from the runner's cargo cache.

**2026-11-14 — the runner image is now pinned (`ubuntu-24.04`) in lij-build and lij-engine-build.** `ubuntu-latest` began handing out ubuntu-26.04 between two page builds of the same engine source (v372): run 43536974281 on ubuntu-24.04 rebuilt the committed wasm byte for byte; run 43542778878 on ubuntu-26.04 produced different bytes and the stamp guard stopped the deploy. The image moves only together with an engine build.

## Checking what you are served

Every release row in [releases.md](releases.md) carries the sha256 of the engine binary, the glue, the wallet page and the service worker as committed here. To compare against what your browser loads:

```
curl -s https://lightninginajar.xyz/pkg/lij_wasm_bg.wasm | sha256sum
curl -s https://lightninginajar.xyz/pkg/lij_wasm.js      | sha256sum
curl -s https://lightninginajar.xyz/wallet/sw.js         | sha256sum
```

Since 2026-10-21 lightninginajar.xyz is served from the author's own node, through a relay that passes the encrypted connection on without opening it, and every file is served byte-identical to the repository — the wallet page too:

```
curl -s https://lightninginajar.xyz/wallet/ | sha256sum
curl -s https://lightninginajar.xyz/wallet/ | grep -o "phase11-v[0-9]*" | head -1
```

(Before 2026-10-21 Cloudflare served the site and inserted a per-request link right after the page's `<body>`, so the page's hash differed on every fetch; that is over.)

Cloudflare keeps a copy of the same deploy branch at https://lij-git.pages.dev. The wallet uses it only for app-update downloads, as its Reach setting allows, and checks every file it takes from it against the sha256 list in the service worker fetched from lightninginajar.xyz itself; a file that does not match is dropped and taken from lightninginajar.xyz. A daily check compares the two hosts.

The page's Content-Security-Policy (`lij-pwa/frontend/_headers`, `/wallet/*` block) lists a sha256 for each of the page's inline script blocks, written by the cut script from the final page bytes; a browser refuses any inline script whose hash is not in that list.

## The current build's hashes

They are the **last row of [releases.md](releases.md)**, which CI writes from the committed files at every page or engine build — this page does not repeat them. (Until 2026-10-20 a table here carried one build's hashes — engine phase11-v239 / page phase11-v709, the first strict-CSP build — and was never updated; the silentpayments.xyz review pointed it out. The row in releases.md was correct throughout.) To compare the repository's own files with that row:

```
sha256sum lij-pwa/frontend/pkg/lij_wasm_bg.wasm lij-pwa/frontend/pkg/lij_wasm.js lij-pwa/frontend/wallet/index.html lij-pwa/frontend/wallet/sw.js
```

## From engine v241 (2026-09-12): LDK 0.2.6, stable toolchain, release profile

- `lightning` 0.2.6 (patched: `lij/patches/lightning`, hunks listed in docs/ldk-patches.md), `lightning-invoice` 0.34, `bitcoin` 0.32.
- Toolchain: **stable 1.90.0** (`lij/rust-toolchain.toml`) — the earlier pinned nightly cannot read edition-2024 manifests in the new dependency tree; nothing in the engine needs nightly.
- Release profile (`lij/Cargo.toml`): `opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "debuginfo"`; wasm-pack/binaryen pins unchanged (0.15.0 / version_117).
- The binary is ~7.9 MB (was ~9.5 MB on 0.0.123 with the default profile).

## From engine v375 (2026-11-17): LDK 0.2.7

- `lightning` 0.2.6 → 0.2.7, the patch set carried over; docs/ldk-patches.md was refreshed for v375 and again for v376 (the one HTLC timing rule). Toolchain, profile and the wasm-pack/binaryen pins unchanged.

## From engine v292 (2026-09-29): the multiply path — libsecp256k1 on its 64-bit limbs

- `lij/.cargo/config.toml` carries `[env] CFLAGS_wasm32_unknown_unknown = "-DUSE_FORCE_WIDEMUL_INT64"`. The `cc` crate (1.4.5) reads a per-target `CFLAGS_<target>` and passes it to every C file it compiles for wasm32; the only C in the tree that reads that macro is libsecp256k1 (`lij/vendor/secp256k1-sys`, unmodified upstream 0.10.1).
- Why: clang defines `__SIZEOF_INT128__` for wasm32, so libsecp256k1's `util.h` picked its 128-bit multiply path (5x52 field, 4x64 scalar) — but WebAssembly has no 128-bit multiply, so every 64x64→128 product became a call into `compiler_builtins`' `__multi3`. The 64-bit path (10x26 field, 8x32 scalar) multiplies 32x32→64, one native `i64.mul` each. It is the path every 32-bit platform runs and is part of libsecp256k1's own CI matrix.
- Gate (2026-09-29): the vendored library built to wasm as int128 and int64 at -Oz and -O3, and natively as int128 and int64 — six builds, one byte-identical 494,756-byte output over 600 rounds of every operation the engine uses (pubkey create, tweak add/mul, combine, negate, seckey tweaks, ECDH, x-only + taproot tweak, Schnorr sign/verify, ECDSA sign/verify/recover) plus BIP-340 test vector 0 as a known answer; the mix ran 2.2x faster under Node 22 (2,149 → 957 ms). Results do not change; only the time does.
- Reproducing: nothing to do — the config file is in the tree, so the recipe above picks it up. Removing the `[env]` line rebuilds the previous arithmetic path; state on disk is unaffected either way.
