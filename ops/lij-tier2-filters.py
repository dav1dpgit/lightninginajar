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
import json
import os
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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # no request logging (privacy)

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Cache-Control", "public, max-age=60")
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
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(502, {"error": str(e)})


if __name__ == "__main__":
    host, port = LISTEN_ADDR.split(":")
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
