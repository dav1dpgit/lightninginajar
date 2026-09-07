# Lightning in a Jar

A bitcoin wallet that runs in the browser: on-chain plus Lightning, the Lightning side built on LDK compiled to WebAssembly, connected to a Lightning service provider (LSP) through the open LIJOX registry. Live at https://lightninginajar.xyz. This repository is the wallet — the engine, the page, the build that produces what is served, and the design records.

**Status: pre-release. No third-party security audit. Read the whole of this file before funding it.**

## What it is

- **Pure Lightning, no side-chain.** Channels are the wallet's own LDK channels with its LSP; there is no Spark/Ark-style shared-custody construction. On-chain funds sit at ordinary BIP84 addresses.
- **Your bitcoin key is your Lightning key.** Everything derives from the 12 words. On-chain funds are recoverable in any BIP84 wallet; cooperative and force closes pay the wallet's side straight to its own m/84 address.
- **An open LSP market (LIJOX).** Any node operator can run the adapter, register, and serve any wallet that speaks the standard; wallets choose and switch providers. The protocol and the registry live in [dav1dpgit/LIJOX](https://github.com/dav1dpgit/LIJOX); the LSP side in [dav1dpgit/lijox-lnd-adapter](https://github.com/dav1dpgit/lijox-lnd-adapter).
- **Always-on lives at the LSP; control stays in the wallet.** The LSP holds inbound payments while the phone is offline (registered payment hashes; preimages never leave the device) and cannot claim them. Keys never leave the device.
- **A static site plus WASM.** No app store, no account. It runs offline once installed (a read-only room with the last known state).

## Read this before funding: what is true today

**One operator is nearly every counterparty.** At the time of this release, both registered LSPs, the chain-data endpoint and the backup host are run by the wallet's author. Provider choice is real in the protocol and nominal in practice until other operators register. This is a single point of failure for liveness (payments, channel opens, backups), not for custody: the wallet's channel state and keys are on the device, closes pay the device's own addresses, and a silent wallet's channel is force-closed by the LSP's lease timer after 60 days, which returns its balance to its m/84 address without any action by the user.

**A website can serve different code tomorrow.** That is true of every browser wallet and this one does not escape it. What exists against it:

- The engine and the page are built by the CI workflow in this repository from this source; every release's hashes are in [docs/releases.md](docs/releases.md) and [docs/reproducible-build.md](docs/reproducible-build.md) says how to compare the served files to them. The engine, its JS glue and the service worker are served byte-identical to the repository; the page differs only by one line Cloudflare injects per request.
- **You can pin a build.** Menu → Dials → Updates → *Ask me*: the service worker then serves the installed build cache-first and a new build waits until you tap the update card. Under *Automatic* (the default) the wallet takes each new build on its next online open.
- The page's Content-Security-Policy allows only same-origin scripts and the page's own inline blocks by sha256 — no inline handlers, no `eval`. HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and a camera-only `Permissions-Policy` are set (`lij-pwa/frontend/_headers`).

**LDK is patched.** The engine builds against `lightning` 0.0.123 with 10 files changed, +229/−29 lines. Nobody independent has reviewed those lines yet. The full diff, with the purpose of every hunk, is [docs/ldk-patches.md](docs/ldk-patches.md). Six of the ten changed files are wasm32 clock substitutions; the rest are the cooperative-close fee floor, additive read-only accessors in the channel monitor, one boot-time hold that stops a pending cooperative close being double-spent by the holder commitment, and a sweeper guard. Commitment, revocation, HTLC and penalty logic are upstream's.

**Browser storage is fragile.** iOS can evict an installed web app's storage; "clear browsing data" wipes it. The 12 words recover on-chain funds; channel balances need the channel state. Keep the encrypted cloud backup on (Privacy → Cloud) and keep a downloaded copy (Menu → Save backup to device). What each recovery path can and cannot do is in [docs/recovery-classes.md](docs/recovery-classes.md) and [docs/recovery-outcomes.md](docs/recovery-outcomes.md).

**If the infrastructure disappears.** With the device and its state: the wallet force-closes its own channels and sweeps. With only the 12 words: the encrypted state blob at the backup host restores channels; if that too is gone, the LSP's lease timer closes a silent wallet's channels to its m/84 address within 60 days; and the escape kit (Menu → Recovery → Escape kit) is a pre-signed close-and-collect for the case where every party is gone. Replicating the sealed state blob across every LIJOX LSP is designed and not yet built.

**Everything here is new.** The wallet domain is months old, there is no audit and no community history. Fund it with an amount whose loss you accept while that is so.

## Layout

```
lij/                 the engine: lij-core (wallet logic), lij-wasm (the wasm-bindgen surface),
                     patches/lightning (LDK 0.0.123 + the patch set), vendor/ (all crates, offline build)
lij-pwa/frontend/    the site and the wallet page, sw.js, styles, _headers (CSP), pkg/ (CI-built engine)
ops/frontend/        lij_csp.py (writes the CSP hashes at cut time), the handler-conversion test
ops/lij-tier2-filters.py   the tier-2 chain-data endpoint (headers / BIP158 filters / blocks off bitcoind)
.github/workflows/   lij-build (engine + page, deploy branch, hashes), lij-engine-build
docs/                design records: recovery, the static-address model, delegation, closes, the escape kit
```

## Building

See [docs/reproducible-build.md](docs/reproducible-build.md). Short form: Rust nightly-2025-01-01 (pinned in `lij/rust-toolchain.toml`), `wasm-pack build --release --target web --out-dir ../../lij-pwa/frontend/pkg lij-wasm` inside `lij/`, crates vendored. The page is plain HTML/JS with no build step; the CSP hash line is written by `ops/frontend/lij_csp.py`.

## History

The engine began as a fork of MutinyWallet/mutiny-node (MIT); its notice is retained in [LICENSE](LICENSE). This repository starts from a clean first commit; the private development history (about 1,700 commits since 2026-03) is not published.

## License

MIT — see [LICENSE](LICENSE).
