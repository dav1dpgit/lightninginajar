#!/usr/bin/env python3
"""2026-10-19 (the silentpayments.xyz review, findings 2 and 3): the served run and the in-place re-index, against a
model chain — no bitcoind, no network. Runs lij-sp-index.py's own loop one pass at a time with its RPC and its
per-block tweak function replaced.

  1. /sp/info describes the gap-free run that ends at the head: a hole below shrinks the run to the blocks above it
     (the wallet is never pointed into the hole); the gap walk fills it and the run is whole again.
  2. SP_REINDEX=1 on a DB built by an older parser: every block is re-indexed in place, SP_BATCH*4 a pass behind the
     live head (a new tip block goes first), exactly the blocks whose tweak set changed get a new commitment, a
     restart resumes at the cursor, the chain heads are re-linked from the genesis value, the DB is stamped.
  3. SP_REINDEX left set after that: nothing starts again.
"""
import importlib.util, os, sqlite3, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []
def check(cond, what):
    print(("  ok · " if cond else "  FAIL · ") + what)
    if not cond: FAILS.append(what)

def load(env):
    for k, v in env.items(): os.environ[k] = v
    spec = importlib.util.spec_from_file_location("spi", os.path.join(HERE, "lij-sp-index.py")); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
def load_filters(dbp):
    os.environ["SP_DB"] = dbp
    spec = importlib.util.spec_from_file_location("flt", os.path.join(HERE, "lij-tier2-filters.py")); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

class Stop(Exception): pass
def world(batch):
    tmp = tempfile.mkdtemp(); dbp = os.path.join(tmp, "sp.sqlite")
    idx = load({"SP_DB": dbp, "SP_START_HEIGHT": "100", "SP_MEMPOOL": "0", "SP_REINDEX": "0", "SP_BATCH": str(batch)})
    st = {"parser": 1, "tip": 110}
    def tweaks(height):   # the model: one key a block; the newer parser finds a second key in every third block
        tw = ["02" + ("%02x" % (height % 256)) * 32]
        if st["parser"] == 2 and height % 3 == 0: tw.append("03" + "ab" * 32)
        return "h%d" % height, sorted(tw)
    def rpc(method, params=None, timeout=120):
        if method == "getblockcount": return st["tip"]
        if method == "getblockhash": return "h%d" % params[0]
        raise RuntimeError(method)
    def sleep(s): raise Stop()
    idx.block_tweaks_from_rpc = tweaks; idx.rpc = rpc; idx.time.sleep = sleep
    def one_pass():
        try: idx.run()
        except Stop: pass
    return idx, dbp, st, one_pass
def meta(db): return dict(db.execute("SELECT k, v FROM meta").fetchall())
def heads_chain(idx, db, lo, hi):
    prev = idx.GENESIS_HEAD_V1
    for h in range(lo, hi + 1):
        c, head = db.execute("SELECT commit_v1, head FROM blocks WHERE height=?", (h,)).fetchone()
        prev = idx.chain_head(prev, c)
        if head != prev: return False
    return True

print("1. the served run")
idx, dbp, st, one_pass = world(3)
one_pass(); db = sqlite3.connect(dbp)
check([r[0] for r in db.execute("SELECT height FROM blocks ORDER BY height")] == list(range(100, 111)), "11 blocks indexed, 100..110")
flt = load_filters(dbp); i = flt.sp_info()
check((i["start_height"], i["indexed_to"]) == (100, 110), "/sp/info whole: 100..110")
db.execute("DELETE FROM blocks WHERE height IN (105,106)"); db.commit(); flt._SP_RUN["at"] = 0; i = flt.sp_info()
check((i["start_height"], i["indexed_to"]) == (107, 110), "a hole at 105..106: /sp/info says 107..110 (not 100..110)")
one_pass(); flt._SP_RUN["at"] = 0; i = flt.sp_info()
check((i["start_height"], i["indexed_to"]) == (100, 110), "the gap walk filled the hole: /sp/info whole again")
check(heads_chain(idx, db, 100, 110), "the heads chain from the genesis value after the fill")

print("2. the re-index behind a moving head")
idx, dbp, st, one_pass = world(1)   # SP_BATCH=1 → slices of 4
one_pass(); db = sqlite3.connect(dbp)
v1 = {h: c for h, c in db.execute("SELECT height, commit_v1 FROM blocks")}
db.execute("DELETE FROM meta WHERE k='parser_version'"); db.commit()   # a DB from before the stamp existed
st["parser"] = 2; idx.SP_REINDEX = True
one_pass(); m = meta(db)
check(m.get("reindex_cursor") == "104" and m.get("reindex_to") == "110", "armed on the unstamped DB; first slice 100..103 done, cursor 104, to 110")
st["tip"] = 111; one_pass(); m = meta(db)
check(db.execute("SELECT count(*) FROM blocks WHERE height=111").fetchone()[0] == 1 and m.get("reindex_cursor") == "104", "a new tip block went first; the re-index waited that pass")
one_pass(); m = meta(db)   # a restart (run() entered again with SP_REINDEX set) resumes at the cursor
check(m.get("reindex_cursor") == "108", "resumed at the cursor after a restart: 104..107 done, cursor 108")
one_pass(); m = meta(db)
check("reindex_cursor" not in m and "reindex_to" not in m and "rechain_from" not in m, "the last slice done: markers cleared, heads re-linked in the same pass")
rows = {h: (c, n) for h, c, n in db.execute("SELECT height, commit_v1, count FROM blocks")}
check(sorted(h for h in range(100, 111) if rows[h][0] != v1[h]) == [102, 105, 108], "exactly the blocks whose tweak set changed have a new commitment (102, 105, 108)")
check(all(rows[h][1] == (2 if h % 3 == 0 else 1) for h in range(100, 112)), "every block's count is the new parser's (111 was indexed new, never re-indexed)")
check(heads_chain(idx, db, 100, 111), "the heads chain from the genesis value through 111")
check(m.get("parser_version") == idx.PARSER_VERSION, "the DB is stamped with the parser version %s" % idx.PARSER_VERSION)

print("3. SP_REINDEX left set")
one_pass(); m = meta(db)
check("reindex_cursor" not in m, "a stamped DB is not re-indexed again")
idx2, dbp2, st2, one_pass2 = world(3); idx2.SP_REINDEX = True; one_pass2(); db2 = sqlite3.connect(dbp2); m2 = meta(db2)
check("reindex_cursor" not in m2 and m2.get("parser_version") == idx2.PARSER_VERSION, "a fresh DB is stamped as built and never re-indexed")

if FAILS:
    print("GATE FAIL: %d" % len(FAILS)); sys.exit(1)
print("GATE PASS: the served run and the re-index")
