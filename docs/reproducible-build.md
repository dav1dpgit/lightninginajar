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
| `lij-pwa/frontend/pkg/lij_wasm_bg.wasm` (engine phase11-v239) | `6006fcfa3d548d7619526246133df97daea501177e0ce1250d2a788fa269f527` |
| `lij-pwa/frontend/pkg/lij_wasm.js` | `51d0c0a706bcb12d517921b2294be07290633eb3fc92136a23c80b5ec1809f17` |
| `lij-pwa/frontend/wallet/index.html` (page phase11-v709) | `f645d1c7c5fc9b81b315ce93845c3712dd1cb564b8d93a1f3e01138f187c72dd` |
| `lij-pwa/frontend/wallet/sw.js` | `6bb8fe0e5d0933815ea77a235c85be87d0e9b62e54cad78d8590198548c61b93` |
