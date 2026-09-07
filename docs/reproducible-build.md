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

## What is pinned and what is not (honest list)

Pinned: the Rust toolchain (`rust-toolchain.toml`), every crate (vendored, `Cargo.lock`), the `lightning` patch set (in-tree).

Not pinned today: the `wasm-pack` version (the installer fetches the latest) and the `wasm-opt`/binaryen version that `wasm-pack` downloads. Two builds on different days can therefore differ in the optimizer's output even from identical source. Pinning both is a one-line change each in the workflow and is on the list; until then, treat the hashes below as "this is what CI produced from this commit", verifiable by re-running the same workflow on a fork, not yet as a bit-for-bit promise from an arbitrary machine.

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
