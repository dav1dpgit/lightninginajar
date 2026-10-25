#!/usr/bin/env bash
# ops/joinstr/gate.sh — the vendored joinstr v2 copy (lij/patches/joinstr-v2) is upstream's bytes plus docs/joinstr-patches.diff,
# nothing else — and it is fit to build into the engine. Run from anywhere:
#   bash ops/joinstr/gate.sh [--no-cargo]     (CI: .github/workflows/joinstr-gate.yml, .gitlab-ci.yml; the private repository's
#                                              lij-joinstr-gate.yml, which also records the result in ops/joinstr/last-gate.txt)
# Two hands wrote it. The byte check that needs nothing the public repository lacks is /dev/fd0's (joinstr's author; merge request
# !1 of 2026-10-23): the recorded diff is reverse-applied to the vendored files and every result must have the upstream sha256
# listed in REFERENCE.md; no file but those and ours; no `unsafe`; only allowed crates; the crate's tests and the Python vectors.
# The rest is S58's (Tatara v0.9 §15; docs/joinstr-patches.md): where the pristine copy exists (the private repository), the
# vendored files must differ from it by exactly the recorded diff; the dependency tree may hold only crates the engine already
# uses, nothing from git, and no random source of its own (P5); the crate builds for wasm32 where the target is installed; and the
# engine's Tatara core passes its tests on the same toolchain.
# Fails (exit 1) on the first thing that is not so; nothing is written outside a temp directory.
set -euo pipefail
cd "$(dirname "$0")/../.."
TC=${JOINSTR_GATE_TOOLCHAIN:+"+$JOINSTR_GATE_TOOLCHAIN"}   # CI: the pinned toolchain (lij/rust-toolchain.toml); locally e.g. stable
P=lij/patches/joinstr-v2
R=docs/design/mix/ref/joinstr-v2-20261006   # the pristine copy — private; absent from the public repository
DIFF=docs/joinstr-patches.diff
REF=$P/REFERENCE.md
OURS="Cargo.toml src/lib.rs src/lij_tests.rs REFERENCE.md"
ALLOWED="anyhow arrayvec base16ct base58ck bech32 bitcoin bitcoin_hashes bitcoin-io bitcoin-units block-buffer cfg-if
cpufeatures crypto-common digest generic-array hex hex-conservative hex_lit hmac itoa joinstr-v2 memchr musig2
proc-macro2 quote secp secp256k1 secp256k1-sys serde serde_core serde_derive serde_json sha2 subtle syn typenum
unicode-ident zmij"
ALLOWED_BUILD="cc find-msvc-tools shlex version_check"   # build scripts only (secp256k1-sys's C build; typenum's version check)
fail() { echo "JOINSTR GATE FAIL: $*"; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 1. upstream's bytes, from the hashes alone: REFERENCE.md's table → the listed files, the recorded diff reverse-applied → sha256
awk -F'|' 'NF >= 4 { f = $2; h = $3; gsub(/ /, "", f); gsub(/ /, "", h); if (length(h) == 64 && h ~ /^[0-9a-f]+$/) print h "  " f }' "$REF" > "$TMP/upstream.sha256"
[ -s "$TMP/upstream.sha256" ] || fail "no upstream hashes in $REF"
mkdir "$TMP/tree"
while read -r _ f; do
  [ -f "$P/$f" ] || fail "$f is listed in REFERENCE.md but missing"
  mkdir -p "$TMP/tree/$(dirname "$f")"
  cp "$P/$f" "$TMP/tree/$f"
done < "$TMP/upstream.sha256"
while read -r f; do
  grep -q "  $f\$" "$TMP/upstream.sha256" || fail "the diff touches $f, which REFERENCE.md does not list"
done < <(sed -n 's|^+++ b/||p' "$DIFF")
(cd "$TMP/tree" && patch -R -p1 -s --no-backup-if-mismatch < "$OLDPWD/$DIFF") || fail "the recorded diff does not reverse-apply"
(cd "$TMP/tree" && sha256sum --quiet -c "$TMP/upstream.sha256") || fail "a file differs from upstream by more than the recorded diff"
echo "  ok · upstream's bytes: $(wc -l < "$TMP/upstream.sha256") files hash as REFERENCE.md says once the recorded diff is taken off"

# 2. no file but upstream's and ours
while read -r f; do
  f="${f#"$P"/}"
  case " $OURS " in *" $f "*) continue ;; esac
  grep -q "  $f\$" "$TMP/upstream.sha256" || fail "$f is neither upstream's (REFERENCE.md) nor ours"
done < <(find "$P" -type f)
echo "  ok · no file but upstream's and ours"

# 3. the pristine copy, where it exists: upstream's bytes there too, and the vendored files differ from it by exactly the diff
if [ -d "$R" ]; then
  while read -r h f; do
    case "$f" in src/*) echo "$h  $R/$f" | sha256sum --quiet -c - >/dev/null 2>&1 || fail "the pristine copy's $f is not upstream's bytes";; esac
  done < "$TMP/upstream.sha256"
  for f in keys sign ring pool funding msg util; do
    diff -u --label "a/src/$f.rs" --label "b/src/$f.rs" "$R/src/$f.rs" "$P/src/$f.rs" || true
  done > "$TMP/now.diff"
  cmp -s "$TMP/now.diff" "$DIFF" || { diff "$TMP/now.diff" "$DIFF" | head -40 || true; fail "the vendored files differ from the pristine copy by more (or less) than $DIFF"; }
  echo "  ok · the pristine copy: upstream's bytes; every change is the recorded patch"
else
  echo "  -- no pristine copy here (the public repository); step 1 stands on the hashes"
fi

# 4. no unsafe
if grep -n -E '\bunsafe\b' $P/src/*.rs; then fail "unsafe code"; fi
echo "  ok · no unsafe"

[ "${1:-}" = "--no-cargo" ] && { echo "JOINSTR GATE PASS (bytes only — cargo skipped)"; exit 0; }

# 5. dependencies: nothing from git; only the allowed crates; only crates the engine already uses; no random source (P5)
cd lij
grep -q 'source = "git+' Cargo.lock && fail "Cargo.lock names a git source"
cargo $TC tree -p joinstr-v2 -e normal --prefix none --offline 2>/dev/null | awk '{print $1}' | sort -u > "$TMP/jv2-normal.txt"
cargo $TC tree -p joinstr-v2 -e normal,build --prefix none --offline 2>/dev/null | awk '{print $1}' | sort -u > "$TMP/jv2-deps.txt"
[ -s "$TMP/jv2-normal.txt" ] && [ -s "$TMP/jv2-deps.txt" ] || fail "cargo tree listed nothing"
for c in $(cat "$TMP/jv2-normal.txt"); do case " $(echo $ALLOWED) " in *" $c "*) ;; *) fail "crate $c is not on the allowed list";; esac; done
for c in $(cat "$TMP/jv2-deps.txt"); do case " $(echo $ALLOWED $ALLOWED_BUILD) " in *" $c "*) ;; *) fail "crate $c (a build-script dependency) is not on the allowed list";; esac; done
# the engine's tree WITHOUT joinstr-v2 (lij-core depends on it — pruned, so the comparison stays meaningful)
cargo $TC tree -p lij-core -e normal,build --prefix none --offline --prune joinstr-v2 2>/dev/null | awk '{print $1}' | sort -u > "$TMP/core-deps.txt"
grep -q '^joinstr-v2$' "$TMP/core-deps.txt" && fail "the prune did not take joinstr-v2 out of the engine's tree"
EXTRA=$(comm -23 "$TMP/jv2-deps.txt" "$TMP/core-deps.txt" | grep -v '^joinstr-v2$' || true)
[ -z "$EXTRA" ] || fail "joinstr-v2 pulls in crates the engine does not use: $EXTRA"
RNG=$(grep -E '^(rand|rand_core|rand_chacha|getrandom)$' "$TMP/jv2-deps.txt" || true)
[ -z "$RNG" ] || fail "the library can reach a random source of its own (P5): $RNG"
echo "  ok · dependencies: $(wc -l < "$TMP/jv2-deps.txt") crates, all allowed and all already in the engine's tree"

# 6. it builds for the browser (where the engine runs) — when the wasm target is installed (CI: yes)
if rustup $TC target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  cargo $TC build -p joinstr-v2 --release --offline --target wasm32-unknown-unknown > "$TMP/wasm.log" 2>&1 || { tail -30 "$TMP/wasm.log"; fail "the wasm build"; }
  echo "  ok · builds for wasm32-unknown-unknown"
else
  echo "  -- wasm32 target not installed here; the wasm build is checked in CI"
fi

# 7. the tests and the vectors — the crate's, the engine's Tatara core over it, then upstream's independent Python check
cargo $TC test -p joinstr-v2 --release --offline 2>&1 | tee "$TMP/jv2-test.log" | grep -E '^test result' || true
grep -q -E 'test result: FAILED|error(\[E[0-9]+\])?:' "$TMP/jv2-test.log" && fail "cargo test -p joinstr-v2"
[ "$(grep -c '^test result: ok' "$TMP/jv2-test.log")" -ge 2 ] || fail "cargo test did not run the unit tests and the vectors"
cargo $TC test -p lij-core --lib --offline tatara 2>&1 | tee "$TMP/tatara-test.log" | grep -E '^test result' || true
grep -q -E 'test result: FAILED|error(\[E[0-9]+\])?:' "$TMP/tatara-test.log" && { grep -E '^error|FAILED|panicked' "$TMP/tatara-test.log" | head -20; fail "the Tatara core's tests"; }
TT=$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/tatara-test.log" | head -1 | grep -oE '[0-9]+ passed')
[ -n "$TT" ] || fail "the Tatara core's tests did not run"
echo "  ok · the engine's Tatara core: $TT"
cd ..
python3 -I "$P/contrib/check_vectors.py" "$P/tests/vectors.json" > "$TMP/py.txt" || { cat "$TMP/py.txt"; fail "check_vectors.py"; }
[ "$(grep -c '^ok: vector' "$TMP/py.txt")" = "8" ] || fail "check_vectors.py did not pass all 8 vectors"
echo "  ok · the tests ($(grep '^test result: ok' "$TMP/jv2-test.log" | head -1 | grep -oE '[0-9]+ passed')) and the vectors (Rust; Python 8 of 8)"
echo "JOINSTR GATE PASS"
