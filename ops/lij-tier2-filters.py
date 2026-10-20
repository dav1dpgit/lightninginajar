#!/usr/bin/env python3
"""
lij-tier2-filters.py — read-only Tier 2 chain-data endpoint for LiJ.

Serves GLOBAL chain data only — block headers, BIP157 filter headers, BIP158
basic filters, and full blocks, all addressed by height. It NEVER takes a
per-user query (no addresses, no descriptors, no wallet names cross the wire),
so it cannot learn which scripts belong to which client. Every client gets the
same bytes; privacy comes from the client matching filters locally and fetching
only the blocks that hit.

Endpoints (all GET):
  /tip                         -> {"height": H, "hash": "..."}
  /headers?start=H&count=N     -> {"headers": [{"height","hash","header"}]}
  /filters?start=H&count=N     -> {"filters": [{"height","hash","filter","filter_header"}]}
  /block/<height>              -> {"height","hash","block"}   (raw block hex)

S50 (2026-09-28): the silent-payment tweak index, read from the sqlite lij-sp-index.py writes
(SP_DB; absent = these routes answer 404 "no silent-payment index on this box"):
  /sp/info                     -> {"format":"spcommit-v1","start_height","indexed_to","tip","mempool_seq"}
  /tweaks/<height>             -> {"height","hash","dust_limit":0,"filter_spent":0,"tweaks":[hex33...]}
                                  (the public BIP-352 index-server spec's shape)
  /sp/tweaks?start=H&count=N   -> {"blocks":[{"height","hash","count","commit","tweaks":[...]}]}  (N <= 500)
  /sp/commits?start=H&count=N  -> {"commits":[{"height","hash","count","commit","head"}]}
  /sp/mempool?since=S          -> {"seq","tweaks":[{"seq","txid","tweak","outputs":[{"vout","key","value"}]}],"gone":[txid...]}

S58 (2026-10-12, LIJOX's Tatara step 6 — spec v0.10 §7): the coin check, OFF unless COIN_CHECK=1:
  /coin?txid=<64 hex>&vout=<n> -> {"txid","vout","unspent","confirmations","tx","proof"}
     tx    = the raw transaction (getrawtransaction at the proof's block — no txindex needed)
     proof = Core's gettxoutproof (the block header + the Merkle branch); null when the transaction is not in a block
             or none of its outputs is unspent
     unspent = gettxout, confirmed outputs only
  The one route that takes a per-coin question. Pool members' phones never ask it themselves: their checks come
  through another LIJOX provider (door 2), so this server sees that provider, not the wallet. Never cached.

Requires bitcoind with `blockfilterindex=1` (for getblockfilter). Stdlib only.
Credentials and CORS origin come from the environment — nothing is hardcoded.
No request logging. No general RPC passthrough — only the fixed methods below.

Env:
  BITCOIND_RPC_URL      default http://127.0.0.1:8332
  BITCOIND_COOKIE_FILE  e.g. /mnt/blockchain/.bitcoin/.cookie   (preferred)
  BITCOIND_RPC_USER / BITCOIND_RPC_PASS                          (fallback)
  CORS_ORIGIN           default https://lightninginajar.xyz
  LISTEN_ADDR           default 127.0.0.1:3000
  MAX_COUNT             default 2000  (per-request range cap)
"""

import base64
import hashlib
import json
import os
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

RPC_URL = os.environ.get("BITCOIND_RPC_URL", "http://127.0.0.1:8332")
COOKIE_FILE = os.environ.get("BITCOIND_COOKIE_FILE", "")
RPC_USER = os.environ.get("BITCOIND_RPC_USER", "")
RPC_PASS = os.environ.get("BITCOIND_RPC_PASS", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://lightninginajar.xyz")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "127.0.0.1:3000")
MAX_COUNT = int(os.environ.get("MAX_COUNT", "2000"))
SP_DB = os.environ.get("SP_DB", "")          # S50: the tweak index's sqlite (lij-sp-index.py); empty = no index here
SP_MAX_BLOCKS = int(os.environ.get("SP_MAX_BLOCKS", "500"))
COIN_CHECK = os.environ.get("COIN_CHECK", "") == "1"   # S58: /coin answers only when switched on


def _auth_header():
    # Read the cookie fresh each call so it survives a bitcoind restart.
    if COOKIE_FILE:
        with open(COOKIE_FILE, "r") as f:
            raw = f.read().strip()
    else:
        raw = f"{RPC_USER}:{RPC_PASS}"
    return "Basic " + base64.b64encode(raw.encode()).decode()


def rpc(method, params=None):
    body = json.dumps(
        {"jsonrpc": "1.0", "id": "lij-tier2", "method": method, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        RPC_URL,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": _auth_header()},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.loads(resp.read().decode())
    if out.get("error"):
        raise RuntimeError(str(out["error"]))
    return out["result"]


def tip():
    h = rpc("getblockcount")
    return {"height": h, "hash": rpc("getbestblockhash")}


def _clamp_count(n):
    return max(1, min(int(n), MAX_COUNT))


def headers(start, count):
    out = []
    for height in range(start, start + count):
        try:
            bh = rpc("getblockhash", [height])
        except RuntimeError:
            break  # past tip
        out.append(
            {
                "height": height,
                "hash": bh,
                "header": rpc("getblockheader", [bh, False]),  # raw 80-byte header hex
            }
        )
    return {"headers": out}


def filters(start, count):
    out = []
    for height in range(start, start + count):
        try:
            bh = rpc("getblockhash", [height])
        except RuntimeError:
            break
        f = rpc("getblockfilter", [bh, "basic"])  # {"filter","header"}
        out.append(
            {
                "height": height,
                "hash": bh,
                "filter": f["filter"],
                "filter_header": f["header"],
            }
        )
    return {"filters": out}


def block(height):
    bh = rpc("getblockhash", [height])
    return {"height": height, "hash": bh, "block": rpc("getblock", [bh, 0])}


# ── S58: the coin check (Tatara step 6; spec v0.10 §7) ─────────────────────────────────────────
class BadRequest(Exception):
    pass


def coin(txid, vout):
    if not re.fullmatch(r"[0-9a-f]{64}", txid or ""):
        raise BadRequest("txid must be 64 lowercase hex")
    if not re.fullmatch(r"[0-9]{1,6}", vout or ""):
        raise BadRequest("vout must be a whole number")
    n = int(vout)
    out = rpc("gettxout", [txid, n, False])          # null = spent, or never in a block (mempool not counted)
    try:
        proof = rpc("gettxoutproof", [[txid]])       # header + Merkle branch; needs an unspent output (no txindex)
    except RuntimeError:
        proof = None
    tx = None
    if proof:
        header = bytes.fromhex(proof[:160])
        bh = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        tx = rpc("getrawtransaction", [txid, 0, bh])
    return {
        "txid": txid,
        "vout": n,
        "unspent": out is not None,
        "confirmations": (out or {}).get("confirmations", 0),
        "tx": tx,
        "proof": proof,
    }


# ── S50: the silent-payment tweak index (read-only; lij-sp-index.py writes it) ──────────────────
class NoIndex(Exception):
    pass


def _sp_db():
    if not SP_DB or not os.path.exists(SP_DB):
        raise NoIndex()
    import sqlite3
    return sqlite3.connect("file:%s?mode=ro" % SP_DB, uri=True, timeout=10)


def _unpack(blob):
    return [blob[i:i + 33].hex() for i in range(0, len(blob), 33)]


_SP_RUN = {"top": None, "start": None, "at": 0.0}


def _sp_served_run(db, meta_start):
    """The run of consecutively indexed blocks that ends at the head: (start, indexed_to). 2026-10-19 (the
    silentpayments.xyz review, finding 2): `indexed_to` was MAX(height), which overstated coverage while a backfill
    was still filling the blocks below (a lowered start is indexed oldest-first BEHIND the live head), and a wallet
    that asked for a height in the hole was told "no tweaks here". Now only the gap-free run that contains the head
    is advertised: a backfill in progress shows the OLD start until its gap closes, then the new one — and the
    engine (v348) pulls a wallet's sweep down to a start that drops. Cached for 30 s per head."""
    top = db.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
    if top is None:
        return meta_start, None
    now = time.time()
    if _SP_RUN["top"] == top and now - _SP_RUN["at"] < 30:
        return _SP_RUN["start"], top
    # the lowest height of the topmost run = the greatest "run start" (a height whose predecessor is missing)
    run_start = db.execute("SELECT MAX(b.height) FROM blocks b WHERE b.height > ? AND NOT EXISTS (SELECT 1 FROM blocks WHERE height = b.height - 1)", (meta_start,)).fetchone()[0]
    start = max(meta_start, int(run_start)) if run_start is not None else meta_start
    _SP_RUN.update({"top": top, "start": start, "at": now})
    return start, top


def sp_info():
    db = _sp_db()
    try:
        meta = dict(db.execute("SELECT k, v FROM meta").fetchall())
        meta_start = int(meta.get("start_height", 0) or 0)
        start, top = _sp_served_run(db, meta_start)
        seq = db.execute("SELECT COALESCE(MAX(seq),0) FROM mempool").fetchone()[0]
        return {"format": "spcommit-v1", "start_height": start, "indexed_to": top,
                "tip": int(meta.get("tip", 0) or 0), "mempool_seq": seq, "dust_limit": 0, "filter_spent": "N/A"}
    finally:
        db.close()


def sp_block(height):
    db = _sp_db()
    try:
        r = db.execute("SELECT hash, tweaks FROM blocks WHERE height=?", (height,)).fetchone()
        if not r:
            raise KeyError("block %d is not indexed" % height)
        return {"height": height, "hash": r[0], "dust_limit": 0, "filter_spent": 0, "tweaks": _unpack(r[1])}
    finally:
        db.close()


def sp_tweaks(start, count):
    count = max(1, min(int(count), SP_MAX_BLOCKS))
    db = _sp_db()
    try:
        rows = db.execute("SELECT height, hash, count, commit_v1, tweaks FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height",
                          (start, start + count - 1)).fetchall()
        return {"blocks": [{"height": h, "hash": bh, "count": n, "commit": c, "tweaks": _unpack(b)} for (h, bh, n, c, b) in rows]}
    finally:
        db.close()


def sp_commits(start, count):
    count = _clamp_count(count)
    db = _sp_db()
    try:
        rows = db.execute("SELECT height, hash, count, commit_v1, head FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height",
                          (start, start + count - 1)).fetchall()
        return {"commits": [{"height": h, "hash": bh, "count": n, "commit": c, "head": hd} for (h, bh, n, c, hd) in rows]}
    finally:
        db.close()


def sp_mempool(since):
    db = _sp_db()
    try:
        seq = db.execute("SELECT COALESCE(MAX(seq),0) FROM mempool").fetchone()[0]
        rows = db.execute("SELECT seq, txid, tweak, outputs FROM mempool WHERE seq>? AND gone_seq IS NULL AND tweak<>'' ORDER BY seq LIMIT 2000", (since,)).fetchall()
        gone = db.execute("SELECT txid FROM mempool WHERE gone_seq>? AND gone_seq>0 ORDER BY gone_seq LIMIT 2000", (since,)).fetchall()
        return {"seq": seq, "tweaks": [{"seq": s, "txid": t, "tweak": tw, "outputs": json.loads(o)} for (s, t, tw, o) in rows], "gone": [g[0] for g in gone]}
    finally:
        db.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # no request logging (privacy)

    def _send(self, code, payload, cache="public, max-age=60"):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/tip":
                self._send(200, tip())
            elif u.path == "/headers":
                start = int(q.get("start", ["0"])[0])
                count = _clamp_count(q.get("count", ["1"])[0])
                self._send(200, headers(start, count))
            elif u.path == "/filters":
                start = int(q.get("start", ["0"])[0])
                count = _clamp_count(q.get("count", ["1"])[0])
                self._send(200, filters(start, count))
            elif u.path.startswith("/block/"):
                height = int(u.path[len("/block/"):])
                self._send(200, block(height))
            # S50: the silent-payment index (read-only from lij-sp-index.py's sqlite)
            elif u.path == "/sp/info":
                self._send(200, sp_info())
            elif u.path.startswith("/tweaks/"):
                self._send(200, sp_block(int(u.path[len("/tweaks/"):])))
            elif u.path == "/sp/tweaks":
                self._send(200, sp_tweaks(int(q.get("start", ["0"])[0]), q.get("count", ["1"])[0]))
            elif u.path == "/sp/commits":
                self._send(200, sp_commits(int(q.get("start", ["0"])[0]), q.get("count", ["1"])[0]))
            elif u.path == "/sp/mempool":
                self._send(200, sp_mempool(int(q.get("since", ["0"])[0])))
            # S58: the coin check — off unless COIN_CHECK=1; never cached (spent-ness changes)
            elif u.path == "/coin" and COIN_CHECK:
                self._send(200, coin(q.get("txid", [""])[0], q.get("vout", [""])[0]), cache="no-store")
            else:
                self._send(404, {"error": "not found"})
        except BadRequest as e:
            self._send(400, {"error": str(e)}, cache="no-store")
        except NoIndex:
            self._send(404, {"error": "no silent-payment index on this box"})
        except KeyError as e:
            self._send(404, {"error": str(e).strip("'")})
        except Exception as e:
            self._send(502, {"error": str(e)}, cache=("no-store" if u.path == "/coin" else "public, max-age=60"))


if __name__ == "__main__":
    host, port = LISTEN_ADDR.split(":")
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
