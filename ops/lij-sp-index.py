#!/usr/bin/env python3
"""
lij-sp-index.py — the silent-payment (BIP-352) tweak index for a LIJOX box.

S50 (2026-09-28, DP: "Agreed with Alongside"). Runs beside lij-tier2-filters.py on the same box,
reads the same bitcoind, and writes ONE sqlite file the filter server serves read-only. It never
sees a wallet key: the index is GLOBAL data — for every eligible transaction in a block, the
33-byte point `input_hash × A_sum` (the "tweak") that every silent-payment wallet needs to test
whether the transaction paid it. A wallet multiplies the tweak by its own scan key on the phone;
this box learns nothing about who received what.

What is indexed (BIP-352 "eligible" transaction):
  - at least one output pays a taproot key (witness v1, a 32-byte program), and
  - at least one input carries a public key we can read from the transaction itself or its
    prevout: P2TR (the 32-byte output key from the prevout script — unless the spend is a
    script-path spend whose control block names the NUMS point H as the internal key), P2WPKH
    (the 33-byte key in the witness), P2SH-P2WPKH (the same, behind a 0014… redeem script),
    P2PKH (the 33-byte key at the end of the scriptSig; uncompressed keys are ignored).
  A_sum = the sum of those keys (x-only keys lifted to even y). The point at infinity → not eligible.
  input_hash = sha256-tagged("BIP0352/Inputs", smallest_outpoint(36 bytes: txid || vout LE) || A_sum).
  tweak = input_hash · A_sum, serialized compressed (33 bytes).

Per block the index keeps: height, hash, the tweak list (sorted lexicographically, as the public
spcommit-v1 format wants), the count, and the commitment
  sha256("spcommit-v1\\n" height "\\n" blockhash "\\n" count "\\n" tweak1 "\\n" tweak2 "\\n" …)
(every line ends with \\n; tweaks as 66-char lowercase hex, sorted as strings) — the tamper-evident
fingerprint two LIJOX boxes compare before a wallet's scan cursor passes a block (the quorum
cross-check), and the chain head = sha256(prev_head_hex || commit_hex) as ASCII.

The mempool leg (SP_MEMPOOL=1): every POLL_SECS, new mempool transactions get the same treatment,
plus their taproot outputs (vout, x-only key, value) so a wallet with no filter to test can match
them directly and show "Silent payment received · pending". Rows leave when the transaction
confirms or drops. Served by lij-tier2-filters.py from the same sqlite:
  /sp/info · /tweaks/<height> (the public spec's shape) · /sp/tweaks?start&count · /sp/commits?start&count
  · /sp/mempool?since=<seq>

Requires: bitcoind ≥ 24 (`getblock <hash> 3` gives each input's prevout; `getrawtransaction … 2`
gives a mempool transaction's prevouts) and coincurve (libsecp256k1, from pip — no apt package on Ubuntu 24.04; the pure-Python
fallback below is correct but ~100× slower — fine for a test, not for a box). Stdlib otherwise.
No request logging. Nothing leaves the box.

Env:
  BITCOIND_RPC_URL      default http://127.0.0.1:8332
  BITCOIND_COOKIE_FILE  e.g. /mnt/blockchain/.bitcoin/.cookie   (preferred)
  BITCOIND_RPC_USER / BITCOIND_RPC_PASS                          (fallback)
  SP_DB                 default /var/lib/lij-sp-index/sp.sqlite
  SP_START_HEIGHT       the first block to index — required on the first run, then kept in the DB
                        (a lower value later widens the index downward: the backfill runs first)
  SP_MEMPOOL            default 1
  SP_POLL_SECS          default 10
  SP_BATCH              default 50 (blocks indexed between commits)
  SP_REINDEX=1          2026-10-19 (the review, findings 1 and 3): re-index every block already in the DB, oldest
                        first, a slice a pass BEHIND the live head, replacing each row in place (never a hole in
                        what is served); the chain heads are re-linked when it ends. It runs only when the DB was
                        built by an older parser (the DB carries the PARSER_VERSION that last indexed it), so it is
                        harmless left set: a finished re-index, or a fresh DB, never starts another.
"""

import base64
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.request

RPC_URL = os.environ.get("BITCOIND_RPC_URL", "http://127.0.0.1:8332")
COOKIE_FILE = os.environ.get("BITCOIND_COOKIE_FILE", "")
RPC_USER = os.environ.get("BITCOIND_RPC_USER", "")
RPC_PASS = os.environ.get("BITCOIND_RPC_PASS", "")
SP_DB = os.environ.get("SP_DB", "/var/lib/lij-sp-index/sp.sqlite")
SP_START_HEIGHT = os.environ.get("SP_START_HEIGHT", "")
SP_MEMPOOL = os.environ.get("SP_MEMPOOL", "1") == "1"
SP_POLL_SECS = float(os.environ.get("SP_POLL_SECS", "10"))
SP_REINDEX = os.environ.get("SP_REINDEX", "0") == "1"
SP_BATCH = int(os.environ.get("SP_BATCH", "50"))
SP_ONCE = os.environ.get("SP_ONCE", "0") == "1"   # one pass, then exit (a health check, and the test harness)
# bumped whenever the way a block's tweaks are computed changes; a DB stamped with an older one is re-indexed under SP_REINDEX=1
PARSER_VERSION = "2026-10-19"

# ── secp256k1: coincurve when the box has it, a plain-Python fallback otherwise ─────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

try:
    import coincurve  # type: ignore
    HAVE_COINCURVE = True
except Exception:  # pragma: no cover
    HAVE_COINCURVE = False


def _inv(a):
    return pow(a, P - 2, P)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, pt):
    r = None
    a = pt
    while k:
        if k & 1:
            r = _add(r, a)
        a = _add(a, a)
        k >>= 1
    return r


def _lift_x(x):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        return None
    return (x, y if y % 2 == 0 else P - y)


def _parse(pk33):
    x = int.from_bytes(pk33[1:33], "big")
    pt = _lift_x(x)
    if pt is None:
        return None
    x_, y = pt
    if (pk33[0] == 3) != (y % 2 == 1):
        y = P - y
    return (x_, y)


def _ser(pt):
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


class Point:
    """One tiny wrapper so the index code reads the same with or without coincurve."""

    __slots__ = ("raw",)

    def __init__(self, raw):
        self.raw = raw   # coincurve.PublicKey, or an (x, y) tuple, or None for infinity

    @staticmethod
    def from_bytes(b):
        if HAVE_COINCURVE:
            try:
                return Point(coincurve.PublicKey(bytes(b)))
            except Exception:
                return None
        pt = _parse(bytes(b)) if len(b) == 33 else None
        return Point(pt) if pt is not None else None

    @staticmethod
    def from_xonly(x32):
        return Point.from_bytes(b"\x02" + bytes(x32))

    @staticmethod
    def sum(points):
        pts = [p for p in points if p is not None]
        if not pts:
            return None
        if HAVE_COINCURVE:
            try:
                return Point(coincurve.PublicKey.combine_keys([p.raw for p in pts]))
            except Exception:
                return None   # the point at infinity (or a bad key)
        acc = None
        for p in pts:
            acc = _add(acc, p.raw)
        return Point(acc) if acc is not None else None

    def mul(self, scalar32):
        k = int.from_bytes(scalar32, "big") % N
        if k == 0:
            return None
        if HAVE_COINCURVE:
            try:
                return Point(self.raw.multiply(k.to_bytes(32, "big")))
            except Exception:
                return None
        r = _mul(k, self.raw)
        return Point(r) if r is not None else None

    def ser(self):
        if HAVE_COINCURVE:
            return self.raw.format(compressed=True)
        return _ser(self.raw)


def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


# ── the input-key rules (BIP-352 "inputs for shared secret derivation") ─────────────────────────
def _pushes(script):
    """Every push in a script, as bytes, in order. Non-push opcodes are SKIPPED, not fatal: BIP-352 says the receiver
    "MUST parse the scriptSig for the public key, even if the scriptSig does not match the template" (third-party
    malleability of P2PKH scriptSigs — e.g. <dummy> OP_DROP <sig> <key>, or OP_1 OP_IF <sig> <key> OP_ELSE … OP_ENDIF).
    Until 2026-10-19 (the silentpayments.xyz review, finding 3) any non-push opcode returned None, so such an input
    contributed no key, the transaction got a wrong tweak, and the receiver never found the payment.
    A truncated push (data running past the end) ends the parse with what was read so far."""
    out = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op == 0:
            out.append(b"")
        elif op <= 75:
            if i + op > n: break
            out.append(script[i:i + op]); i += op
        elif op == 76:
            if i >= n: break
            ln = script[i]; i += 1
            if i + ln > n: break
            out.append(script[i:i + ln]); i += ln
        elif op == 77:
            if i + 2 > n: break
            ln = int.from_bytes(script[i:i + 2], "little"); i += 2
            if i + ln > n: break
            out.append(script[i:i + ln]); i += ln
        elif op == 78:
            if i + 4 > n: break
            ln = int.from_bytes(script[i:i + 4], "little"); i += 4
            if i + ln > n: break
            out.append(script[i:i + ln]); i += ln
        else:
            continue   # a non-push opcode: skipped
    return out


def input_pubkey(spk_hex, script_sig_hex, witness_hexes):
    """The public key a BIP-352 input contributes, as a Point — or None when the input type is
    not eligible (or an uncompressed / unreadable key)."""
    spk = bytes.fromhex(spk_hex or "")
    wit = [bytes.fromhex(w) for w in (witness_hexes or [])]
    ssig = bytes.fromhex(script_sig_hex or "")
    # P2TR: OP_1 <32>
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        if len(wit) >= 2:
            items = wit[:-1] if (len(wit) >= 2 and wit[-1][:1] == b"\x50") else wit   # drop an annex
            if len(items) >= 2:
                control = items[-1]
                if len(control) >= 33 and (len(control) - 33) % 32 == 0 and control[1:33] == NUMS_H:
                    return None   # script-path spend with the NUMS internal key: not eligible
        return Point.from_xonly(spk[2:34])
    # P2WPKH: OP_0 <20>
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        if len(wit) == 2 and len(wit[1]) == 33:
            return Point.from_bytes(wit[1])
        return None
    # P2SH-P2WPKH: OP_HASH160 <20> OP_EQUAL with scriptSig = push(0014<20>)
    if len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87:
        pushes = _pushes(ssig)
        if pushes and len(pushes) == 1 and len(pushes[0]) == 22 and pushes[0][:2] == b"\x00\x14":
            if len(wit) == 2 and len(wit[1]) == 33:
                return Point.from_bytes(wit[1])
        return None
    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG — the key is the compressed 33-byte push whose hash160
    # matches the script, searched from the END of the scriptSig (BIP-352 reference: scan the pushes backwards; the
    # malleated vectors put decoy keys and opcodes before the real one). Uncompressed keys are skipped by the BIP.
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC:
        for push in reversed(_pushes(ssig) or []):
            if len(push) == 33 and push[0] in (2, 3):
                if hashlib.new("ripemd160", hashlib.sha256(push).digest()).digest() == spk[3:23]:
                    return Point.from_bytes(push)
        return None
    return None


def is_taproot_output(spk_hex):
    return len(spk_hex) == 68 and spk_hex.startswith("5120")


def tx_tweak(vin, vout_spks):
    """The tweak for one transaction, or None when it is not eligible.
    vin: [{"txid","vout","spk","scriptSig","witness":[...]}] — spk = the prevout's scriptPubKey hex.
    vout_spks: the transaction's output scriptPubKeys (hex)."""
    if not any(is_taproot_output(s) for s in vout_spks):
        return None
    keys = []
    smallest = None
    for i in vin:
        op = bytes.fromhex(i["txid"])[::-1] + int(i["vout"]).to_bytes(4, "little")
        if smallest is None or op < smallest:
            smallest = op
        k = input_pubkey(i.get("spk", ""), i.get("scriptSig", ""), i.get("witness") or [])
        if k is not None:
            keys.append(k)
    if not keys or smallest is None:
        return None
    a_sum = Point.sum(keys)
    if a_sum is None:
        return None
    ih = tagged_hash("BIP0352/Inputs", smallest + a_sum.ser())
    t = a_sum.mul(ih)
    return t.ser().hex() if t is not None else None


def spcommit_v1(height, block_hash, tweaks_sorted):
    s = "spcommit-v1\n%d\n%s\n%d\n" % (height, block_hash, len(tweaks_sorted)) + "".join(t + "\n" for t in tweaks_sorted)
    return hashlib.sha256(s.encode("ascii")).hexdigest()


def chain_head(prev_head_hex, commit_hex):
    return hashlib.sha256((prev_head_hex + commit_hex).encode("ascii")).hexdigest()


GENESIS_HEAD_V1 = hashlib.sha256(b"spcommit-v1-genesis").hexdigest()   # a fixed start; the measurement repo's own genesis value is adopted once its vectors are checked (see docs)


# ── bitcoind ────────────────────────────────────────────────────────────────────────────────────
def _auth_header():
    if COOKIE_FILE:
        with open(COOKIE_FILE, "r") as f:
            raw = f.read().strip()
    else:
        raw = f"{RPC_USER}:{RPC_PASS}"
    return "Basic " + base64.b64encode(raw.encode()).decode()


def rpc(method, params=None, timeout=120):
    body = json.dumps({"jsonrpc": "1.0", "id": "lij-sp-index", "method": method, "params": params or []}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"Content-Type": "application/json", "Authorization": _auth_header()})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read())
    if out.get("error"):
        raise RuntimeError(str(out["error"]))
    return out["result"]


def block_tweaks_from_rpc(height):
    """(hash, sorted tweak list) for one block, from `getblock <hash> 3` (prevouts inline)."""
    bh = rpc("getblockhash", [height])
    blk = rpc("getblock", [bh, 3], timeout=600)
    tweaks = []
    for tx in blk["tx"]:
        vin = tx.get("vin") or []
        if not vin or "coinbase" in vin[0]:
            continue
        vouts = [o.get("scriptPubKey", {}).get("hex", "") for o in tx.get("vout") or []]
        if not any(is_taproot_output(s) for s in vouts):
            continue
        ins = []
        for i in vin:
            pv = i.get("prevout") or {}
            ins.append({"txid": i["txid"], "vout": i["vout"], "spk": pv.get("scriptPubKey", {}).get("hex", ""),
                        "scriptSig": (i.get("scriptSig") or {}).get("hex", ""), "witness": i.get("txinwitness") or []})
        t = tx_tweak(ins, vouts)
        if t:
            tweaks.append(t)
    tweaks.sort()
    return bh, tweaks


def mempool_entry_from_rpc(txid):
    """(tweak, taproot outputs) for a mempool transaction via getrawtransaction verbosity 2 (prevouts)."""
    tx = rpc("getrawtransaction", [txid, 2])
    vin = tx.get("vin") or []
    if not vin or "coinbase" in vin[0]:
        return None
    vouts = tx.get("vout") or []
    spks = [o.get("scriptPubKey", {}).get("hex", "") for o in vouts]
    if not any(is_taproot_output(s) for s in spks):
        return None
    ins = []
    for i in vin:
        pv = i.get("prevout") or {}
        ins.append({"txid": i["txid"], "vout": i["vout"], "spk": pv.get("scriptPubKey", {}).get("hex", ""),
                    "scriptSig": (i.get("scriptSig") or {}).get("hex", ""), "witness": i.get("txinwitness") or []})
    t = tx_tweak(ins, spks)
    if not t:
        return None
    outs = [{"vout": o["n"], "key": spks[o["n"]][4:], "value": int(round(float(o["value"]) * 1e8))} for o in vouts if is_taproot_output(spks[o["n"]])]
    return t, outs


# ── the store ───────────────────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, count INTEGER NOT NULL,
  commit_v1 TEXT NOT NULL, head TEXT NOT NULL, tweaks BLOB NOT NULL, indexed_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mempool (seq INTEGER PRIMARY KEY AUTOINCREMENT, txid TEXT NOT NULL UNIQUE,
  tweak TEXT NOT NULL, outputs TEXT NOT NULL, seen_ms INTEGER NOT NULL, gone_seq INTEGER);
CREATE INDEX IF NOT EXISTS mempool_gone ON mempool (gone_seq);
"""


def open_db(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)
    return db


def meta_get(db, k, default=None):
    r = db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def meta_set(db, k, v):
    db.execute("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def pack(tweaks):
    return b"".join(bytes.fromhex(t) for t in tweaks)


def unpack(blob):
    return [blob[i:i + 33].hex() for i in range(0, len(blob), 33)]


def index_block(db, height, prev_head):
    bh, tweaks = block_tweaks_from_rpc(height)
    commit = spcommit_v1(height, bh, tweaks)
    head = chain_head(prev_head, commit)
    db.execute("INSERT OR REPLACE INTO blocks (height, hash, count, commit_v1, head, tweaks, indexed_ms) VALUES (?,?,?,?,?,?,?)",
               (height, bh, len(tweaks), commit, head, pack(tweaks), int(time.time() * 1000)))
    return bh, head, len(tweaks)


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " [SP-INDEX] " + msg, flush=True)


def run():
    if not HAVE_COINCURVE:
        log("WARNING: coincurve not found — running the pure-Python curve (about 100x slower); python3 -m pip install --user --break-system-packages coincurve")
    db = open_db(SP_DB)
    start = meta_get(db, "start_height")
    if start is None:
        if not SP_START_HEIGHT:
            log("first run needs SP_START_HEIGHT (the first block to index)"); sys.exit(2)
        start = int(SP_START_HEIGHT)
        meta_set(db, "start_height", start); db.commit()
    start = int(start)
    if SP_START_HEIGHT and int(SP_START_HEIGHT) < start:
        # S50 (DP: backfill to 840,000): the gap below is filled a slice at a time BEHIND the live head — new tip
        # blocks and the mempool keep going — and the chain heads above the old start are re-linked once the gap
        # closes (their heads were chained from the genesis value while the block below them was missing).
        log("start height lowered %d -> %s: the backfill runs behind the live head" % (start, SP_START_HEIGHT))
        if meta_get(db, "rechain_from") is None:
            meta_set(db, "rechain_from", start)
        start = int(SP_START_HEIGHT); meta_set(db, "start_height", start); db.commit()
    top0 = db.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
    if top0 is None and meta_get(db, "parser_version") is None:
        meta_set(db, "parser_version", PARSER_VERSION); db.commit()   # a fresh DB is built by this parser
    if SP_REINDEX and meta_get(db, "reindex_cursor") is None and top0 is not None and meta_get(db, "parser_version") != PARSER_VERSION:
        meta_set(db, "reindex_cursor", start); meta_set(db, "reindex_to", int(top0)); db.commit()
        log("SP_REINDEX: the DB was indexed by parser %s; re-indexing %d..%d in place behind the live head under parser %s (the P2PKH keys in malleated scriptSigs)" % (meta_get(db, "parser_version") or "(unstamped, pre-2026-10-19)", start, int(top0), PARSER_VERSION))
    elif SP_REINDEX and meta_get(db, "reindex_cursor") is None:
        log("SP_REINDEX set, nothing to do: the DB is already indexed by parser %s" % PARSER_VERSION)
    log("start height %d · db %s · mempool %s" % (start, SP_DB, "on" if SP_MEMPOOL else "off"))
    while True:
        backfilling = False
        try:
            tip = int(rpc("getblockcount"))
            # 1. a reorg check on the newest indexed blocks (6 deep), then the forward walk
            top = db.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
            if top is not None:
                for h in range(max(start, top - 5), top + 1):
                    row = db.execute("SELECT hash FROM blocks WHERE height=?", (h,)).fetchone()
                    if row and row[0] != rpc("getblockhash", [h]):
                        log("reorg at %d — re-indexing from there" % h)
                        db.execute("DELETE FROM blocks WHERE height>=?", (h,)); db.commit()
                        break
            # 2. the live head first (every new block above the highest indexed one), then a slice of any gap
            #    below (a lowered start — the backfill, oldest first, SP_BATCH*4 blocks a pass so the head and
            #    the mempool never wait more than about a minute)
            have = set(r[0] for r in db.execute("SELECT height FROM blocks WHERE height BETWEEN ? AND ?", (start, tip)))
            top_now = max(have) if have else start - 1
            gap = [h for h in range(start, tip + 1) if h not in have]
            ahead = [h for h in gap if h > top_now]
            below = [h for h in gap if h <= top_now]
            todo = ahead + below[:SP_BATCH * 4]
            backfilling = len(below) > SP_BATCH * 4
            done = 0
            t0 = time.time()
            for h in todo:
                prev = db.execute("SELECT head FROM blocks WHERE height=?", (h - 1,)).fetchone()
                prev_head = prev[0] if prev else GENESIS_HEAD_V1
                _, _, n = index_block(db, h, prev_head)
                done += 1
                if done % SP_BATCH == 0:
                    db.commit()
            if done:
                db.commit()
                log("indexed %d block(s) to %d in %.1fs (tip %d, %d left)" % (done, todo[done - 1], time.time() - t0, tip, max(0, len(gap) - done)))
            meta_set(db, "tip", tip); db.commit()
            # 2a. the re-index (SP_REINDEX): a slice of the already-indexed blocks, oldest first, each row replaced in
            #     place — the served range never has a hole; a changed tweak set changes that block's commitment;
            #     the heads are re-linked from the start when the last slice is done
            rc = meta_get(db, "reindex_cursor")
            if rc is not None and not ahead:
                rc = int(rc); rto = int(meta_get(db, "reindex_to"))
                slice_to = min(rto, rc + SP_BATCH * 4 - 1)
                t1 = time.time(); changed = 0; n_slice = 0
                for h in range(rc, slice_to + 1):
                    old = db.execute("SELECT commit_v1 FROM blocks WHERE height=?", (h,)).fetchone()
                    prev = db.execute("SELECT head FROM blocks WHERE height=?", (h - 1,)).fetchone()
                    bh, _, n = index_block(db, h, prev[0] if prev else GENESIS_HEAD_V1)
                    new = db.execute("SELECT commit_v1 FROM blocks WHERE height=?", (h,)).fetchone()
                    if old is None or old[0] != new[0]:
                        changed += 1
                    n_slice += 1
                    if n_slice % SP_BATCH == 0:
                        db.commit()
                db.commit()
                log("re-indexed %d..%d in %.1fs (%d block(s) changed; %d left)" % (rc, slice_to, time.time() - t1, changed, max(0, rto - slice_to)))
                if slice_to >= rto:
                    if meta_get(db, "rechain_from") is None:
                        meta_set(db, "rechain_from", start)
                    db.execute("DELETE FROM meta WHERE k IN ('reindex_cursor', 'reindex_to')")
                    meta_set(db, "parser_version", PARSER_VERSION); db.commit()
                    log("re-index complete (parser %s): the chain heads are re-linked from %d (this pass, once no gap is left below)" % (PARSER_VERSION, start))
                else:
                    meta_set(db, "reindex_cursor", slice_to + 1); db.commit()
                backfilling = backfilling or slice_to < rto
            # 2b. the gap closed after a lowered start: re-link the chain heads from the old start up
            rf = meta_get(db, "rechain_from")
            if rf is not None and len(gap) == done:
                rf = int(rf); n_re = 0
                prev = db.execute("SELECT head FROM blocks WHERE height=?", (rf - 1,)).fetchone()
                prev_head = prev[0] if prev else GENESIS_HEAD_V1
                for (h, commit) in db.execute("SELECT height, commit_v1 FROM blocks WHERE height>=? ORDER BY height", (rf,)).fetchall():
                    head = chain_head(prev_head, commit)
                    db.execute("UPDATE blocks SET head=? WHERE height=?", (head, h))
                    prev_head = head; n_re += 1
                db.execute("DELETE FROM meta WHERE k='rechain_from'"); db.commit()
                log("backfill complete: %d chain head(s) re-linked from %d" % (n_re, rf))
            # 3. the mempool leg — every pass, backfill or not
            if SP_MEMPOOL:
                pool = set(rpc("getrawmempool"))
                known = dict((r[0], r[1]) for r in db.execute("SELECT txid, seq FROM mempool WHERE gone_seq IS NULL"))
                seq_max = db.execute("SELECT COALESCE(MAX(seq),0) FROM mempool").fetchone()[0]
                gone = [t for t in known if t not in pool]
                for t in gone:
                    seq_max += 1
                    db.execute("UPDATE mempool SET gone_seq=? WHERE txid=?", (seq_max, t))
                new = [t for t in pool if t not in known][:2000]
                added = 0
                for t in new:
                    try:
                        e = mempool_entry_from_rpc(t)
                    except Exception:
                        continue   # it may have left the pool between the two calls
                    if not e:
                        db.execute("INSERT OR IGNORE INTO mempool (txid, tweak, outputs, seen_ms, gone_seq) VALUES (?,?,?,?,?)", (t, "", "[]", int(time.time() * 1000), -1))   # remembered as not eligible, never served
                        continue
                    db.execute("INSERT OR IGNORE INTO mempool (txid, tweak, outputs, seen_ms) VALUES (?,?,?,?)", (t, e[0], json.dumps(e[1], separators=(",", ":")), int(time.time() * 1000)))
                    added += 1
                # forget rows gone for more than a day
                db.execute("DELETE FROM mempool WHERE gone_seq IS NOT NULL AND seen_ms < ?", (int(time.time() * 1000) - 86400000,))
                db.commit()
                if added or gone:
                    log("mempool: +%d eligible, %d gone" % (added, len(gone)))
        except Exception as e:
            log("error: %s" % e)
        if SP_ONCE:
            return
        time.sleep(0.2 if backfilling else SP_POLL_SECS)   # a backfill in progress: straight on


# ── self-test against the BIP-352 sending vectors (the private keys prove the public-key path) ──
def selftest(vectors_path, receive_vectors_path=None):
    """Two checks over the BIP-352 vectors. (A) the BIP's own answer: for every send case, the tweak this indexer
    computes from the vins must equal the `tweak` the matching receive case states (the value a light client gets from
    an index) — the independent reference; until 2026-10-19 the check below (B) derived its reference through this
    file's own input parser, so a parser that dropped an input agreed with itself (the malleated-P2PKH case passed
    while wrong). (B) the sender's private-key derivation, as before."""
    v = json.load(open(vectors_path))
    truth = {}
    if receive_vectors_path:
        for rc in json.load(open(receive_vectors_path)):
            if rc.get("tweak"):
                truth.setdefault(rc["comment"], rc["tweak"])
    ok = 0
    checked_truth = 0
    for case in v:
        if case["comment"] in truth:
            vin = [{"txid": i["txid"], "vout": i["vout"], "spk": i["spk"], "scriptSig": i.get("scriptSig", ""), "witness": _witness_items(i.get("witness", ""))} for i in case["vin"]]
            t = tx_tweak(vin, ["5120" + "00" * 32])
            assert t == truth[case["comment"]], "BIP tweak: %s: %s != %s" % (case["comment"], t, truth[case["comment"]])
            checked_truth += 1
        vin = [{"txid": i["txid"], "vout": i["vout"], "spk": i["spk"], "scriptSig": i.get("scriptSig", ""), "witness": _witness_items(i.get("witness", ""))} for i in case["vin"]]
        t = tx_tweak(vin, ["5120" + "00" * 32])   # a taproot output, so the tx is eligible
        # the sender's side: a_sum from the private keys (a taproot input with an odd-y key negates), then (input_hash·a_sum)·G
        keys = []
        for i in case["vin"]:
            k = input_pubkey(i["spk"], i.get("scriptSig", ""), _witness_items(i.get("witness", "")))
            if k is None:
                continue
            a = int(i["private_key"], 16)
            if i["spk"].startswith("5120"):
                pt = _mul(a, G)
                if pt[1] % 2 == 1:
                    a = N - a
            keys.append(a)
        if not keys:
            assert t is None, case["comment"]; ok += 1; continue
        a_sum = sum(keys) % N
        if a_sum == 0:
            assert t is None, case["comment"]; ok += 1; continue
        smallest = min(bytes.fromhex(i["txid"])[::-1] + int(i["vout"]).to_bytes(4, "little") for i in case["vin"])
        A = _mul(a_sum, G)
        ih = int.from_bytes(tagged_hash("BIP0352/Inputs", smallest + _ser(A)), "big") % N
        want = _ser(_mul(ih * a_sum % N, G)).hex()
        assert t == want, "%s: %s != %s" % (case["comment"], t, want)
        ok += 1
    unchecked = [c["comment"] for c in v if c["comment"] not in truth]
    print("selftest: %d cases agree with the sender's private-key derivation; %d match the BIP's own tweak (coincurve=%s)" % (ok, checked_truth, HAVE_COINCURVE))
    if receive_vectors_path and unchecked:
        print("  no BIP tweak to check for %d case(s) (no eligible inputs, a zero key sum, or no receive case in the file): %s" % (len(unchecked), "; ".join(unchecked)))


def _witness_items(w):
    """The vectors carry the witness as one hex string: count || (len || item)*; empty when none."""
    if not w:
        return []
    b = bytes.fromhex(w)
    n = b[0]; i = 1; items = []
    for _ in range(n):
        ln = b[i]; i += 1
        if ln == 0xFD:
            ln = int.from_bytes(b[i:i + 2], "little"); i += 2
        items.append(b[i:i + ln].hex()); i += ln
    return items


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--selftest":
        selftest(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        run()
