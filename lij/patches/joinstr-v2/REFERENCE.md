# joinstr v2 — our vendored copy (lij/patches/joinstr-v2)

**Upstream:** gitlab.com/1440000bytes/joinstr-v2 (MIT, LICENSE kept), branch main at commit
**83637efafd6fdf04691bbe9930c95d5e026fa231** — named in the comment of the zip DP attached on 2026-10-12 16:42
(joinstr-v2-main.zip, 3,920,335 bytes, sha256 47d9adcf54ffeb6ce4f76d8e8e5818984ec3e1e97e4f4f5eb3ca895b7da3d4ed; byte
for byte the 10-06 download in docs/design/mix/ref/joinstr-v2-20261006, which is the pristine copy the patch gate diffs
against). Reviewed before it came in: docs/design/mix/joinstr-v2-review-r1.md (DP's word 2026-10-12 17:54).

**What came in (Tatara v0.9 §15.2)** — upstream's bytes, each file's sha256 as upstream ships it:

| File | Upstream sha256 | Changed by us |
|---|---|---|
| LICENSE | c8a3e70f430cdf31fd814698195068a323a25093bb69b77228d344991a4d3073 | never |
| NIP.md | a7c889db68a981959d8bfa645dec3a4249a9b190235f12fd0eb6ccaa781576f2 | never (the protocol's text, for reading) |
| src/keys.rs | e3c7d1a8069230c2e05cfe6760214003f5171ba81c591307ec25e489c99a1462 | see docs/joinstr-patches.md |
| src/sign.rs | 4aa3781ae767d615af567c6ea540666cdb3c7d5ee071390680e03d4447df5be5 | see docs/joinstr-patches.md |
| src/ring.rs | a6d85c7a16602e7209a40aa694601f2ad06f906678c78f7594d42d68555482c8 | see docs/joinstr-patches.md |
| src/pool.rs | 649e7adb3e69a9059945190d0498362e2347068026e7bcb8e0c94f5474ae73c2 | see docs/joinstr-patches.md |
| src/funding.rs | f03b7f382d1eb3b87abcb6feb55659474b7636ddef1e14f80f0d36852d71218e | see docs/joinstr-patches.md |
| src/msg.rs | 80c4f1ecd97dd38755361949c5535680e24d82749af82245abd1831ea25e86b3 | see docs/joinstr-patches.md |
| src/util.rs | 6ab74b24bd759cb2fae06c2dd01f138bb4f5f151df979912c0ebd99391569320 | see docs/joinstr-patches.md |
| tests/vectors.rs | 0a201aeb06cc3d14f0724859acafb1c4874188a4fbd13c5ccc54f8de68383ade | see docs/joinstr-patches.md |
| tests/vectors.json | 77717e68c9eed64a17b32dfe8b3598d9945ea38612a97efdaaba80271fba4efe | never (the vectors are the check) |
| contrib/check_vectors.py | 705e79a33cd963796df0ea96f67e31cfeb7a5933f664f3d7e10b2e77a4421758 | never |

**Ours, not upstream's:** Cargo.toml, src/lib.rs (the allow-listed modules only), src/lij_tests.rs (the tests of our patches), this file.

**What never came in (§15.3):** src/chain.rs, exit.rs, http.rs, main.rs, peer.rs, psbt.rs (review P3), relay.rs,
wallet.rs; upstream's Cargo.toml and Cargo.lock (tungstenite, rustls, webpki-roots, socks5 and nostrd from git, nostr,
clap, env_logger, log, bip39, base64); contrib/regtest.sh; docs/.

**The gate** (ops/joinstr/gate.sh, run in CI on every change here): the unchanged files hash as above; every changed
file differs from the pristine copy exactly by the recorded patch (docs/joinstr-patches.diff); the dependency tree holds
only the allowed crates; no `unsafe`; the vectors (Rust and Python) and the failing tests pass.
