# Releases — hashes of what is served

One row per build that went live. The engine and the page carry independent version strings: the engine's is `wasm_build_version()` inside the binary (`lij/lij-wasm/src/lib.rs`), the page's is `LIJ_FRONTEND_VERSION` in `lij-pwa/frontend/wallet/index.html`. A page build that does not rebuild the engine keeps the engine row's hash.

How to check a served file against a row: see [reproducible-build.md](reproducible-build.md).

| date (UTC) | page | engine | `lij_wasm_bg.wasm` sha256 | `lij_wasm.js` sha256 | `sw.js` sha256 | notes |
|---|---|---|---|---|---|---|
| 2026-09-07 | phase11-v709 | phase11-v239 | `6006fcfa3d548d7619526246133df97daea501177e0ce1250d2a788fa269f527` | `51d0c0a706bcb12d517921b2294be07290633eb3fc92136a23c80b5ec1809f17` | `6bb8fe0e5d0933815ea77a235c85be87d0e9b62e54cad78d8590198548c61b93` | first public release; CI zip `lij-v709.zip` sha256 `cbb0a692eebcd9842f0a208d227ba55457b3853fb3a2c9db6269a5a8a5be409a` |

Rows are appended by the `lij-build` workflow itself after every green build (the row for the first public release was written by hand from the CI's `build-status.json`). The 2026-09-07 page v710 row was the first build under the pinned toolchain: its engine hash equals the v239 hash built the day before without pins — bit-for-bit.
| 2026-09-07 | phase11-v710 | phase11-v239 | `6006fcfa3d548d7619526246133df97daea501177e0ce1250d2a788fa269f527` | `51d0c0a706bcb12d517921b2294be07290633eb3fc92136a23c80b5ec1809f17` | `96614b859405127b65ca71abf7028eff618f6406de038dc883d790b8834e505b` | commit c4257b4d; CI zip `lij-v710.zip` sha256 `7343d0bc264bac5d157b754120d5af00b7fb04e33f542ea667078eb19539d6d4` |
| 2026-09-07 | phase11-v710 | phase11-v240 | `84ffa33ba6530f83ef9eb7acc32af34d27caf07aa960bafb732dfe106672678e` | `697c6328da42bf7bf89fb333654114f50c0e04c23e96058a36f44780256a72bf` | `96614b859405127b65ca71abf7028eff618f6406de038dc883d790b8834e505b` | commit 62fc0218; CI zip `lij-v710.zip` sha256 `a1b59395aae66178ad0ae3b49e040f8d77ebb8d9619ca3b2426b2bca656b1779` |
| 2026-09-07 | phase11-v711 | phase11-v240 | `84ffa33ba6530f83ef9eb7acc32af34d27caf07aa960bafb732dfe106672678e` | `697c6328da42bf7bf89fb333654114f50c0e04c23e96058a36f44780256a72bf` | `cf2bcca49652f401c20109938ba7e93f7a06b5f33b78a3a628f2797bd4f71554` | commit 3d9c5c14; CI zip `lij-v711.zip` sha256 `ca412eeb818981676c2bae90d6f99e522af14067d8a2bbc569610453e74b669f` |
| 2026-09-07 | phase11-v712 | phase11-v240 | `84ffa33ba6530f83ef9eb7acc32af34d27caf07aa960bafb732dfe106672678e` | `697c6328da42bf7bf89fb333654114f50c0e04c23e96058a36f44780256a72bf` | `b4a87e9672c1c2823f9752ac27b316287abfdf2f4e38a61564081616d419b590` | commit 24291c40; CI zip `lij-v712.zip` sha256 `05ea8aa9d465bc074a9db2ca558c1134e6abd3433a1c145d254533c1b84a42e9` |
