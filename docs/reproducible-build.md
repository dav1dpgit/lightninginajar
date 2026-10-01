# Reproducible build — how the served engine is checked against this source

The wallet is a static site: `lij-pwa/frontend/` is served as-is at https://lightninginajar.xyz, and the engine is the WebAssembly module `lij-pwa/frontend/pkg/lij_wasm_bg.wasm` (about 9.4 MB) plus its JS glue `lij_wasm.js`. Both are built by the `lij-build` GitHub Actions workflow in this repository from `lij/` and committed back; the deploy branch is a byte copy of `lij-pwa/frontend/`.

## Recipe (what CI runs — `.github/workflows/lij-build.yml`)

```
# toolchain: lij/rust-toolchain.toml pins nightly-2025-01-01 with the wasm32-unknown-unknown target
rustup target add wasm32-unknown-unknown
curl -sSf https://rustwasm.github.io/wasm-pack/installer/init.sh | sh
cd lij
cargo clean -p lij-wasm
wasm-pack build --release --target web --out-dir ../../lij-pwa/frontend/pkg lij-wasm
```

Crate sources are vendored under `lij/vendor` and `lij/.cargo/config.toml` points Cargo at them (`replace-with = "vendored-sources"`), so the build does not fetch from crates.io. The `lightning` crate comes from `lij/patches/lightning` — see [ldk-patches.md](ldk-patches.md) for the full diff against upstream 0.0.123. `wasm-opt -Oz` runs as part of `wasm-pack build` (`lij/lij-wasm/Cargo.toml`).

## What is pinned (all of it, since page v710's workflow)

- The Rust toolchain: `lij/rust-toolchain.toml` (nightly-2025-01-01, `rustc 1.85.0-nightly (d117b7f21 2024-12-31)` — that string is in the binary's `producers` section).
- Every crate: vendored under `lij/vendor`, `Cargo.lock` checksums; `wasm-bindgen` 0.2.116 (crate and CLI).
- The `lightning` patch set: in-tree.
- `wasm-pack` v0.15.0: the release tarball is downloaded from GitHub and refused unless its sha256 is `c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a`.
- `wasm-opt` (binaryen) version_117 — the version wasm-pack v0.15.0 would fetch itself, now downloaded explicitly and refused unless its sha256 is `3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212`; it is put on PATH first, which is what wasm-pack uses when present.

Before v710 the workflow installed the latest wasm-pack from its installer script and let it fetch binaryen itself; the engine phase11-v239 row below was built that way (with v0.15.0 / version_117 — the versions current on 2026-09-06). The row after it is the first built under the pins.

The remaining variable is the runner image (`ubuntu-latest`: its clang is recorded in the `producers` section too, `Ubuntu clang 18.1.3`). The workflow's `cargo clean -p lij-wasm` before each build keeps the crate's own objects fresh; the vendored dependencies come from the runner's cargo cache.

## Checking what you are served

Every release row in [releases.md](releases.md) carries the sha256 of the engine binary, the glue, the wallet page and the service worker as committed here. To compare against what your browser loads:

```
curl -s https://lightninginajar.xyz/pkg/lij_wasm_bg.wasm | sha256sum
curl -s https://lightninginajar.xyz/pkg/lij_wasm.js      | sha256sum
curl -s https://lightninginajar.xyz/wallet/sw.js         | sha256sum
```

The engine, glue and service worker are served byte-identical to the repository. The wallet page (`/wallet/`) is NOT: Cloudflare injects a per-request bot-protection link right after `<body>`, so its hash differs on every fetch. Check the page by its version string instead:

```
curl -s https://lightninginajar.xyz/wallet/ | grep -o "phase11-v[0-9]*" | head -1
```

and, if you want the byte comparison, diff the served page against `lij-pwa/frontend/wallet/index.html` — the only difference should be that one injected `<a href="https://lightninginajar.xyz/cdn-cgi/content?id=…">` line.

The page's Content-Security-Policy (`lij-pwa/frontend/_headers`, `/wallet/*` block) lists a sha256 for each of the page's inline script blocks, written by the cut script from the final page bytes; a browser refuses any inline script whose hash is not in that list.

## Current build (main at the time of this commit)

| artifact | sha256 |
|---|---|
| `lij-pwa/frontend/pkg/lij_wasm_bg.wasm` (engine phase11-v300) | `1145e6e9915d7a9c8972cf4954c0b5e4775e964d403b9048cc3ef2d857b8ca97` |
| `lij-pwa/frontend/pkg/lij_wasm.js` | `9339005c25ea0ce4e9a8352859d0db37f34e83060a89cb48ac3aa981f8af0f4e` |
| `lij-pwa/frontend/wallet/index.html` (page phase11-v896) | `6b11006c0c5df5a2bc59e121ff3fbcd8588354ac740e2de8f1536509a1e82d0e` |
| `lij-pwa/frontend/wallet/sw.js` | `bc93f62b3363c69cc8da039b8607819e6845ab6a7d920f9030a6833f060b0892` |
| `lij-pwa/frontend/recover/index.html` (Black start page, build v896) | `c3348998f72b8360d21b8d2c29d9901275d33d031551358f81b74997476a313f` |

## From engine v292 (2026-09-29): the multiply path — libsecp256k1 on its 64-bit limbs

- `lij/.cargo/config.toml` carries `[env] CFLAGS_wasm32_unknown_unknown = "-DUSE_FORCE_WIDEMUL_INT64"`. The `cc` crate (1.4.5) reads a per-target `CFLAGS_<target>` and passes it to every C file it compiles for wasm32; the only C in the tree that reads that macro is libsecp256k1 (`lij/vendor/secp256k1-sys`, unmodified upstream 0.10.1).
- Why: clang defines `__SIZEOF_INT128__` for wasm32, so libsecp256k1's `util.h` picked its 128-bit multiply path (5x52 field, 4x64 scalar) — but WebAssembly has no 128-bit multiply, so every 64x64→128 product became a call into `compiler_builtins`' `__multi3`. The 64-bit path (10x26 field, 8x32 scalar) multiplies 32x32→64, one native `i64.mul` each. It is the path every 32-bit platform runs and is part of libsecp256k1's own CI matrix.
- Gate (2026-09-29): the vendored library built to wasm as int128 and int64 at -Oz and -O3, and natively as int128 and int64 — six builds, one byte-identical 494,756-byte output over 600 rounds of every operation the engine uses (pubkey create, tweak add/mul, combine, negate, seckey tweaks, ECDH, x-only + taproot tweak, Schnorr sign/verify, ECDSA sign/verify/recover) plus BIP-340 test vector 0 as a known answer; the mix ran 2.2x faster under Node 22 (2,149 → 957 ms). Results do not change; only the time does.
- Reproducing: nothing to do — the config file is in the tree, so the recipe above picks it up. Removing the `[env]` line rebuilds the previous arithmetic path; state on disk is unaffected either way.

## From engine v241 (2026-09-12): LDK 0.2.6, stable toolchain, release profile

- `lightning` 0.2.6 (patched: `lij/patches/lightning`, hunks listed in docs/ldk-patches.md — to be re-issued for 0.2.6), `lightning-invoice` 0.34, `bitcoin` 0.32.
- Toolchain: **stable 1.90.0** (`lij/rust-toolchain.toml`) — the earlier pinned nightly cannot read edition-2024 manifests in the new dependency tree; nothing in the engine needs nightly.
- Release profile (`lij/Cargo.toml`): `opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "debuginfo"`; wasm-pack/binaryen pins unchanged (0.15.0 / version_117).
- The binary is ~7.9 MB (was ~9.5 MB on 0.0.123 with the default profile).
