# Releases — hashes of what is served

One row per build that went live. The engine and the page carry independent version strings: the engine's is `wasm_build_version()` inside the binary (`lij/lij-wasm/src/lib.rs`), the page's is `LIJ_FRONTEND_VERSION` in `lij-pwa/frontend/wallet/index.html`. A page build that does not rebuild the engine keeps the engine row's hash.

How to check a served file against a row: see [reproducible-build.md](reproducible-build.md).

| date (UTC) | page | engine | `lij_wasm_bg.wasm` sha256 | `lij_wasm.js` sha256 | `sw.js` sha256 | notes |
|---|---|---|---|---|---|---|
| 2026-09-07 | phase11-v709 | phase11-v239 | `6006fcfa3d548d7619526246133df97daea501177e0ce1250d2a788fa269f527` | `51d0c0a706bcb12d517921b2294be07290633eb3fc92136a23c80b5ec1809f17` | `6bb8fe0e5d0933815ea77a235c85be87d0e9b62e54cad78d8590198548c61b93` | first public release; CI zip `lij-v709.zip` sha256 `cbb0a692eebcd9842f0a208d227ba55457b3853fb3a2c9db6269a5a8a5be409a` |

Rows are appended by the `lij-build` workflow itself after every green build (the row for the first public release was written by hand from the CI's `build-status.json`). The 2026-09-07 page v710 row was the first build under the pinned toolchain: its engine hash equals the v239 hash built the day before without pins — bit-for-bit.
| 2026-09-07 | phase11-v710 | phase11-v239 | `6006fcfa3d548d7619526246133df97daea501177e0ce1250d2a788fa269f527` | `51d0c0a706bcb12d517921b2294be07290633eb3fc92136a23c80b5ec1809f17` | `96614b859405127b65ca71abf7028eff618f6406de038dc883d790b8834e505b` | commit c4257b4d; CI zip `lij-v710.zip` sha256 `7343d0bc264bac5d157b754120d5af00b7fb04e33f542ea667078eb19539d6d4` |
