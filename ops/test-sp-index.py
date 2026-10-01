#!/usr/bin/env python3
"""S50: the tweak index end to end against a FAKE bitcoind — the RPC shapes (getblock 3 with prevout,
getrawtransaction 2, getrawmempool), the sqlite, the spcommit-v1 chain, a reorg, the mempool leg, and the
tier-2 read routes. Blocks are built from the BIP-352 sending vectors' inputs (real keys, real tweaks)."""
import json, os, subprocess, sys, threading, time, urllib.request, hashlib, importlib.util, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("spi", os.path.join(HERE, "lij-sp-index.py")); spi = importlib.util.module_from_spec(spec); spec.loader.exec_module(spi)
V = json.load(open(os.path.join(HERE, "..", "lij", "lij-core", "src", "testdata", "bip352_send_vectors.json")))

def wit(w):
    return spi._witness_items(w)

# ── the chain: 4 blocks, each carrying two vector transactions (one eligible, one without a taproot output) ──
CHAIN = []   # [{hash, tx:[...]}]
def mk_tx(case, taproot_out):
    vin = [{"txid": i["txid"], "vout": i["vout"], "scriptSig": {"hex": i.get("scriptSig", "")}, "txinwitness": wit(i.get("witness", "")),
            "prevout": {"scriptPubKey": {"hex": i["spk"]}, "value": 0.5}} for i in case["vin"]]
    vout = [{"n": 0, "value": 0.1, "scriptPubKey": {"hex": ("5120" + case["expected_outputs"][0][0]) if taproot_out and case["expected_outputs"] and case["expected_outputs"][0] else "0014" + "11" * 20}}]
    txid = hashlib.sha256(json.dumps(case["comment"]).encode()).hexdigest()
    return {"txid": txid, "vin": vin, "vout": vout}
for b in range(4):
    txs = [{"txid": "cb%02d" % b + "0" * 60, "vin": [{"coinbase": "00"}], "vout": []}]
    txs.append(mk_tx(V[b], True)); txs.append(mk_tx(V[b + 4], False))
    CHAIN.append({"hash": hashlib.sha256(("block%d" % b).encode()).hexdigest(), "tx": txs})
START = 900000
MEMPOOL = {}   # txid -> tx (verbosity-2 shape)
STATE = {"reorged": False}

class RPC(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m, p = body["method"], body.get("params") or []
        try:
            if m == "getblockcount": r = STATE.get("base", START) + len(CHAIN) - 1
            elif m == "getbestblockhash": r = CHAIN[-1]["hash"]
            elif m == "getblockhash":
                h = p[0] - STATE.get("base", START)
                if not (0 <= h < len(CHAIN)): raise Exception("Block height out of range")
                r = CHAIN[h]["hash"]
            elif m == "getblock":
                bh, verb = p[0], p[1]; blk = next(b for b in CHAIN if b["hash"] == bh); r = {"hash": bh, "tx": blk["tx"]}
            elif m == "getrawmempool": r = list(MEMPOOL.keys())
            elif m == "getrawtransaction":
                if p[0] not in MEMPOOL: raise Exception("No such mempool or blockchain transaction")
                r = MEMPOOL[p[0]]
            else: raise Exception("unknown " + m)
            out = {"result": r, "error": None, "id": body["id"]}
        except Exception as e:
            out = {"result": None, "error": {"code": -1, "message": str(e)}, "id": body["id"]}
        data = json.dumps(out).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

srv = HTTPServer(("127.0.0.1", 18765), RPC); threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = tempfile.mkdtemp(); db = os.path.join(tmp, "sp.sqlite")
env = dict(os.environ, BITCOIND_RPC_URL="http://127.0.0.1:18765", BITCOIND_RPC_USER="u", BITCOIND_RPC_PASS="p", SP_DB=db, SP_START_HEIGHT=str(START), SP_ONCE="1", SP_POLL_SECS="0")
fails = 0
def check(cond, msg):
    global fails
    print(("  ok · " if cond else "FAIL · ") + msg)
    if not cond: fails += 1
def run_once():
    r = subprocess.run([sys.executable, os.path.join(HERE, "lij-sp-index.py")], env=env, capture_output=True, text=True, timeout=120)
    return r.stdout + r.stderr

out = run_once()
check("indexed 4 block(s)" in out, "first pass indexes the 4 blocks: " + out.strip().splitlines()[-1][:90])
import sqlite3
c = sqlite3.connect(db)
rows = c.execute("SELECT height, hash, count, commit_v1, head FROM blocks ORDER BY height").fetchall()
check([r[0] for r in rows] == [START, START + 1, START + 2, START + 3], "heights " + str([r[0] for r in rows]))
check([r[2] for r in rows] == [1, 1, 1, 1], "one eligible transaction per block (the taproot-less twin is skipped)")
# the tweak equals the vector-derived one
tw = spi.unpack(c.execute("SELECT tweaks FROM blocks WHERE height=?", (START,)).fetchone()[0])
case = V[0]
vin = [{"txid": i["txid"], "vout": i["vout"], "spk": i["spk"], "scriptSig": i.get("scriptSig", ""), "witness": wit(i.get("witness", ""))} for i in case["vin"]]
check(tw == [spi.tx_tweak(vin, ["5120" + "00" * 32])], "the stored tweak is the transaction's tweak")
# the commitment and the chain
h0 = spi.spcommit_v1(START, CHAIN[0]["hash"], tw)
check(rows[0][3] == h0, "spcommit-v1 of block 0 recomputes")
check(rows[0][4] == spi.chain_head(spi.GENESIS_HEAD_V1, h0), "the head chains from the genesis head")
check(rows[1][4] == spi.chain_head(rows[0][4], rows[1][3]), "…and block 1's head from block 0's")
c.close()

# a reorg: replace the last block, run again
CHAIN[3]["hash"] = hashlib.sha256(b"block3-reorg").hexdigest()
CHAIN[3]["tx"][1] = mk_tx(V[9], True)
out = run_once()
c = sqlite3.connect(db)
r3 = c.execute("SELECT hash, count FROM blocks WHERE height=?", (START + 3,)).fetchone()
check("reorg at %d" % (START + 3) in out and r3[0] == CHAIN[3]["hash"], "a changed block hash is re-indexed (reorg)")
c.close()

# the mempool leg: one eligible tx, one not; then one leaves
def mp_tx(case, taproot_out, name):
    t = mk_tx(case, taproot_out); t["txid"] = hashlib.sha256(name.encode()).hexdigest(); t["vout"][0]["n"] = 0
    return t
MEMPOOL["a" * 64] = mp_tx(V[10], True, "mp-a"); MEMPOOL["b" * 64] = mp_tx(V[11], False, "mp-b")
out = run_once()
c = sqlite3.connect(db)
mp = dict((r[0], r) for r in c.execute("SELECT txid, tweak, outputs, gone_seq FROM mempool").fetchall())
ma, mb = mp.get("a" * 64), mp.get("b" * 64)
check(len(mp) == 2 and ma and ma[1] != "" and ma[3] is None, "the eligible mempool transaction is indexed with its tweak")
check(mb and mb[1] == "" and mb[3] == -1, "the taproot-less one is remembered as not eligible (never served)")
outs = json.loads(ma[2]) if ma else []; check(outs and outs[0]["key"] == V[10]["expected_outputs"][0][0] and outs[0]["value"] == 10000000, "its taproot outputs carry vout, x-only key, value")
c.close()
del MEMPOOL["a" * 64]
out = run_once()
c = sqlite3.connect(db)
gone = c.execute("SELECT gone_seq FROM mempool WHERE txid=?", ("a" * 64,)).fetchone()[0]
check(gone is not None and gone > 0, "a transaction that left the pool is marked gone")
c.close()

# the tier-2 routes
t2env = dict(os.environ, BITCOIND_RPC_URL="http://127.0.0.1:18765", BITCOIND_RPC_USER="u", BITCOIND_RPC_PASS="p", SP_DB=db, LISTEN_ADDR="127.0.0.1:18766", CORS_ORIGIN="https://example.test")
t2 = subprocess.Popen([sys.executable, os.path.join(HERE, "lij-tier2-filters.py")], env=t2env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.8)
def get(path):
    try:
        with urllib.request.urlopen("http://127.0.0.1:18766" + path, timeout=10) as r: return r.status, json.loads(r.read()), r.headers.get("Access-Control-Allow-Origin")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read()), None
try:
    st, j, cors = get("/sp/info"); check(st == 200 and j["format"] == "spcommit-v1" and j["start_height"] == START and j["indexed_to"] == START + 3 and j["tip"] == START + 3, "/sp/info: " + json.dumps(j)); check(cors == "https://example.test", "CORS origin on the SP routes")
    st, j, _ = get("/tweaks/%d" % START); check(st == 200 and j["hash"] == CHAIN[0]["hash"] and j["tweaks"] == tw and j["dust_limit"] == 0, "/tweaks/<height> (the public spec's shape)")
    st, j, _ = get("/sp/tweaks?start=%d&count=10" % START); check(st == 200 and len(j["blocks"]) == 4 and j["blocks"][3]["hash"] == CHAIN[3]["hash"] and "commit" in j["blocks"][0], "/sp/tweaks range (4 blocks, commits inline)")
    st, j, _ = get("/sp/commits?start=%d&count=3" % START); check(st == 200 and len(j["commits"]) == 3 and j["commits"][0]["commit"] == h0 and "head" in j["commits"][0], "/sp/commits range")
    st, j, _ = get("/sp/mempool?since=0"); check(st == 200 and j["tweaks"] == [] and j["gone"] == ["a" * 64], "/sp/mempool: the eligible one is gone now, reported as gone")
    st, j, _ = get("/tweaks/123"); check(st == 404, "/tweaks of an unindexed block → 404")
    st, j, _ = get("/tip"); check(st == 200 and j["height"] == START + 3, "/tip still answers (the old routes untouched)")
finally:
    t2.terminate()
# no index configured → a plain 404 with the reason
t2env2 = dict(t2env); t2env2.pop("SP_DB")
t2 = subprocess.Popen([sys.executable, os.path.join(HERE, "lij-tier2-filters.py")], env=t2env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(0.8)
try:
    st, j, _ = get("/sp/info"); check(st == 404 and "no silent-payment index" in j["error"], "no SP_DB → 404 'no silent-payment index on this box'")
finally:
    t2.terminate()
# S50 (DP: backfill the UM890 to 840,000): a lowered start fills the gap below and re-links the chain heads at the seam
for b in (3, 2, 1):
    txs = [{"txid": "cb9%d" % b + "0" * 60, "vin": [{"coinbase": "00"}], "vout": []}, mk_tx(V[10 + b], True)]
    CHAIN.insert(0, {"hash": hashlib.sha256(("below%d" % b).encode()).hexdigest(), "tx": txs})
STATE["base"] = START - 3
env["SP_START_HEIGHT"] = str(START - 3)
out = run_once()
check("lowered %d -> %d" % (START, START - 3) in out and "indexed 3 block(s)" in out and "backfill complete: 4 chain head(s) re-linked from %d" % START in out, "a lowered start: the 3 blocks below are indexed and the 4 above re-linked: " + " | ".join(l[-80:] for l in out.strip().splitlines()[-3:]))
c = sqlite3.connect(db)
rows = c.execute("SELECT height, commit_v1, head FROM blocks ORDER BY height").fetchall()
check([r[0] for r in rows] == list(range(START - 3, START + 4)), "heights now %d..%d" % (START - 3, START + 3))
ph = spi.GENESIS_HEAD_V1; okc = True
for (h, commit, head) in rows:
    if head != spi.chain_head(ph, commit): okc = False
    ph = head
check(okc, "every head chains from the one below, from the genesis value at %d through %d (the seam re-linked)" % (START - 3, START + 3))
check(c.execute("SELECT v FROM meta WHERE k='rechain_from'").fetchone() is None, "the rechain marker is cleared")
c.close()
out = run_once()
check("re-linked" not in out and "indexed" not in out, "a further pass has nothing to do")
srv.shutdown()
print("GATE FAILED (%d)" % fails if fails else "GATE PASS: the tweak index end to end")
sys.exit(1 if fails else 0)
