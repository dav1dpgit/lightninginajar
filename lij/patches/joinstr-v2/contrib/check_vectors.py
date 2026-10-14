#!/usr/bin/env python3
"""Check tests/vectors.json against the rules in NIP.md, independently of the Rust code.

Covers amounts for every exit plan, fee split and mix of denominations, the chain, every order
and tree structures, tagged hash orderings, output order, anchors, locktime, sequences, txids,
ownership and payout messages, hash to point and key images. Needs only Python 3.
"""
import hashlib
import json
import math
import sys
from collections import deque
from pathlib import Path

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def lift_x(x):
    if x >= P:
        return None
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x * x * x + 7) % P:
        return None
    return x, y if y % 2 == 0 else P - y


def ser(pt):
    return bytes([2 + pt[1] % 2]) + pt[0].to_bytes(32, "big")


def parse_point(h):
    b = bytes.fromhex(h)
    pt = lift_x(int.from_bytes(b[1:], "big"))
    return pt if b[0] == 2 else (pt[0], P - pt[1])


def th(tag, *parts):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + b"".join(parts)).digest()


def hash_to_point(pt):
    i = 0
    while True:
        cand = lift_x(int.from_bytes(th("joinstr/v2/hash_to_point", ser(pt), i.to_bytes(4, "little")), "big"))
        if cand:
            return cand
        i += 1


def varint(b, i):
    v = b[i]
    if v < 0xFD:
        return v, i + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[v]
    return int.from_bytes(b[i + 1:i + 1 + size], "little"), i + 1 + size


def parse_tx(h):
    b = bytes.fromhex(h)
    i = 4
    n, i = varint(b, i)
    ins = []
    for _ in range(n):
        outpoint = b[i:i + 36]
        i += 36
        slen, i = varint(b, i)
        ins.append({"outpoint": outpoint, "script_sig": b[i:i + slen], "sequence": int.from_bytes(b[i + slen:i + slen + 4], "little")})
        i += slen + 4
    n, i = varint(b, i)
    outs = []
    for _ in range(n):
        start = i
        value = int.from_bytes(b[i:i + 8], "little")
        slen, j = varint(b, i + 8)
        outs.append({"value": value, "spk": b[j:j + slen], "raw": b[start:j + slen]})
        i = j + slen
    return {
        "version": int.from_bytes(b[:4], "little"),
        "inputs": ins,
        "outputs": outs,
        "locktime": int.from_bytes(b[i:i + 4], "little"),
        "txid": hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex(),
    }


def outpoint(txid, vout):
    return bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little")


def fee(weight, milli):
    return -(-weight * milli // 4000)


def bech32_spk(addr):
    """Decode a segwit address to its script (enough for the vectors)."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = [charset.index(c) for c in addr[addr.rfind("1") + 1:-6]]
    version, rest = data[0], data[1:]
    acc, bits, prog = 0, 0, []
    for v in rest:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xFF)
    return bytes([0x50 + version if version else 0, len(prog)]) + bytes(prog)


def input_weight(spk):
    if len(spk) == 22 and spk[0] == 0:
        return 272
    if len(spk) == 34 and spk[0] == 0x51:
        return 230
    raise ValueError("unsupported input")


def amounts(pool, ordered):
    """Exit amounts for payouts whose denominations, in chain order, are `ordered`."""
    n = pool["peers"]
    milli = round(pool["fee_rate"] * 1000)
    exits = pool.get("exits") or ([1] * (n - 2) + [min(n, 2)])
    first, last = [round(r * 1000) for r in pool.get("exit_fee_rates", [pool["fee_rate"]] * 2)]
    anchor = 240 if pool.get("anchor") == "p2a" else 0
    m = len(exits)
    out = []
    for j, g in enumerate(exits):
        weight = 42 + 230 + 172 * (g + (1 if j + 1 < m else 0)) + (52 if anchor else 0)
        rate = first if m == 1 else (first * (m - 1 - j) + last * j) // (m - 1)
        out.append({"payouts": g, "weight": weight, "fee": fee(weight, rate), "pool": None})
    by_exit = pool.get("fee_split", "equal") == "by_exit"
    share = 0 if by_exit else -(-sum(e["fee"] + anchor for e in out) // n)
    pools = [sum(ordered) + n * share]
    start = 0
    for j, e in enumerate(out):
        cost = -(-(e["fee"] + anchor) // e["payouts"])
        e["payouts"] = [a - cost if by_exit else a for a in ordered[start:start + e["payouts"]]]
        start += len(e["payouts"])
        paid = sum(e["payouts"]) + anchor
        if j + 1 < m:
            e["pool"] = pools[-1] - paid - e["fee"]
            pools.append(e["pool"])
        else:
            e["fee"] = pools[-1] - paid
    out = [{"payouts": e["payouts"], "weight": e["weight"], "fee": e["fee"], "pool": e["pool"]} for e in out]
    return share, pools, out, exits, anchor, milli


def any_order(pool, ordered, costs, share, anchor):
    """Every state is the order in which payouts left, breadth first. One exit per remaining
    payout while three or more are left, one final exit for the last two."""
    n = len(ordered)
    by_exit = pool.get("fee_split", "equal") == "by_exit"
    states, level = [[]], [[]]
    for _ in range(n - 2):
        level = [s + [q] for s in level for q in range(n) if q not in s]
        states += level
    index = {tuple(s): i for i, s in enumerate(states)}
    pools = [0] * len(states)
    pools[0] = sum(ordered) + n * share
    plans = []
    for si, state in enumerate(states):
        left = [q for q in range(n) if q not in state]
        f = costs[len(state)]
        if len(left) >= 3:
            for q in left:
                value = ordered[q] - (f + anchor) if by_exit else ordered[q]
                to = index[tuple(state + [q])]
                pools[to] = pools[si] - value - anchor - f
                plans.append({"from": si, "pays": [(q, value)], "to": [(to, pools[to])], "fee": f, "depth": len(state)})
        else:
            per = -(-(f + anchor) // 2)
            pays = [(q, ordered[q] - per if by_exit else ordered[q]) for q in left]
            fee_paid = pools[si] - sum(x[1] for x in pays) - anchor
            plans.append({"from": si, "pays": pays, "to": [], "fee": fee_paid, "depth": len(state)})
    return pools, plans


def tree(pool, ordered, anchor):
    """Binary tree over the payout order, breadth first. A node of n payouts gives the first
    ceil(n / 2) to its first child. Rates go from the first exit rate at the root to the last
    one at the deepest node."""
    n = len(ordered)
    nodes, queue, nxt = [], deque([(0, n, 0)]), 1
    while queue:
        lo, hi, depth = queue.popleft()
        mid = lo + -(-(hi - lo) // 2)
        children = []
        for a, b in ((lo, mid), (mid, hi)):
            if b - a == 1:
                children.append(("payout", a))
            else:
                queue.append((a, b, depth + 1))
                children.append(("pool", nxt))
                nxt += 1
        nodes.append((depth, children))
    first, last = [round(r * 1000) for r in pool.get("exit_fee_rates", [pool["fee_rate"]] * 2)]
    deepest = max(d for d, _ in nodes)
    weight = 42 + 230 + 172 * 2 + (52 if anchor else 0)
    fees = [fee(weight, first if deepest == 0 else (first * (deepest - d) + last * d) // deepest) for d, _ in nodes]
    share = -(-sum(f + anchor for f in fees) // n)
    pools = [0] * len(nodes)
    for i in reversed(range(len(nodes))):
        pools[i] = fees[i] + anchor + sum(ordered[x] if kind == "payout" else pools[x] for kind, x in nodes[i][1])
    pools[0] = sum(ordered) + n * share
    plans = []
    for i, (depth, children) in enumerate(nodes):
        pays = [(x, ordered[x]) for kind, x in children if kind == "payout"]
        to = [(x, pools[x]) for kind, x in children if kind == "pool"]
        paid = sum(v for _, v in pays) + sum(v for _, v in to) + anchor
        plans.append({"from": i, "pays": pays, "to": to, "fee": pools[i] - paid, "depth": depth})
    return share, pools, plans


def check_structure(v, pid, payouts, ordered_peers, funding, locktime):
    """Exits of a pool with exits in every order or a tree."""
    pool, exp = v["pool"], v["expected"]
    ordered = [p["denomination"] for p in ordered_peers]
    share, _, chain, _, anchor, _ = amounts(pool, ordered)
    if pool["structure"] == "any_order":
        # every path has the exits of the chain, so the costs come from the chain
        first, last = [round(r * 1000) for r in pool.get("exit_fee_rates", [pool["fee_rate"]] * 2)]
        m = len(chain)
        weight = 42 + 230 + 172 * 2 + (52 if anchor else 0)
        costs = [fee(weight, first if m == 1 else (first * (m - 1 - j) + last * j) // (m - 1)) for j in range(m)]
        pools, plans = any_order(pool, ordered, costs, share, anchor)
    else:
        assert pool["structure"] == "tree"
        share, pools, plans = tree(pool, ordered, anchor)
    assert share == exp["exit_share"]
    assert pools == exp["pool_values"], "pool values"
    assert len(plans) == len(exp["exits"])
    created = {0: outpoint(funding["txid"], exp["funding"]["pool_vout"])}
    raw = lambda value, spk: value.to_bytes(8, "little") + bytes([len(spk)]) + spk
    pool_spk = lambda i: b"\x51\x20" + bytes.fromhex(exp["pool_output_keys"][i])
    for k, (plan, e) in enumerate(zip(plans, exp["exits"]), start=1):
        tx = parse_tx(e["unsigned_hex"])
        assert tx["txid"] == e["txid"] and tx["version"] == 2 and tx["locktime"] == locktime
        assert len(tx["inputs"]) == 1 and tx["inputs"][0]["outpoint"] == created[plan["from"]]
        assert tx["inputs"][0]["sequence"] == 0xFFFFFFFD
        outs = [(value, payouts[q]) for q, value in plan["pays"]] + [(value, pool_spk(i)) for i, value in plan["to"]]
        if anchor:
            outs.append((anchor, bytes.fromhex("51024e73")))
        expected = sorted((raw(*o) for o in outs),
                          key=lambda r: th("joinstr/v2/exit_output_order", pid, k.to_bytes(4, "little"), r))
        assert [o["raw"] for o in tx["outputs"]] == expected, f"exit {k}"
        spks = [o["spk"] for o in tx["outputs"]]
        assert e["from"] == plan["from"] and e["depth"] == plan["depth"] and e["fee"] == plan["fee"]
        assert [tuple(x) for x in e["pays"]] == [(q, spks.index(payouts[q])) for q, _ in plan["pays"]]
        assert [tuple(x) for x in e["to"]] == [(i, spks.index(pool_spk(i))) for i, _ in plan["to"]]
        for i, _ in plan["to"]:
            created[i] = outpoint(tx["txid"], spks.index(pool_spk(i)))


def check(v):
    pool, peers, exp = v["pool"], v["peers"], v["expected"]
    pid = pool["id"].encode()
    n = pool["peers"]
    structured = pool.get("structure", "chain") != "chain"

    classes = pool.get("denominations") or [{"amount": pool["denomination"], "peers": n}]
    for c in classes:
        assert sum(1 for p in peers if p["denomination"] == c["amount"]) == c["peers"]
    ordered_peers = sorted(peers, key=lambda p: (-p["priority"], th("joinstr/v2/payout_order", pid, bech32_spk(p["payout"]))))
    payouts = [bech32_spk(p["payout"]) for p in ordered_peers]
    share, pools, exit_amounts, exits, anchor, milli = amounts(pool, [p["denomination"] for p in ordered_peers])
    if pool.get("structure") == "tree":
        share = tree(pool, [p["denomination"] for p in ordered_peers], anchor)[0]
        pools = exp["pool_values"][:1]
    if not structured:
        assert share == exp["exit_share"] and pools == exp["pool_values"]
        assert exit_amounts == exp["exit_amounts"]

    required, ownership, hp, images, payout_msgs = [], [], [], [], []
    for p in peers:
        session = bytes.fromhex(p["session_pubkey"])
        weight = math.ceil(214 / n)
        for i in p["inputs"]:
            weight += input_weight(bytes.fromhex(i["script_pubkey"]))
            ownership.append(th("joinstr/v2/ownership", pid, session, outpoint(i["txid"], i["vout"])).hex())
        if p["change"]:
            weight += 4 * (9 + len(bech32_spk(p["change"]["address"])))
        required.append(p["denomination"] + share + fee(weight, milli))
        ring = parse_point(p["ring_pubkey"])
        assert mul(int(p["ring_seckey"], 16), G) == ring
        h = hash_to_point(ring)
        hp.append(ser(h).hex())
        images.append(ser(mul(int(p["ring_seckey"], 16), h)).hex())
        payout_msgs.append(th("joinstr/v2/payout", pid, bytes([p["priority"]]),
                              p["denomination"].to_bytes(8, "little"), bech32_spk(p["payout"])).hex())
    assert required == exp["required_contributions"]
    assert ownership == exp["ownership_messages"]
    assert hp == exp["hash_to_point"] and images == exp["key_images"]
    assert payout_msgs == exp["payout_messages"]
    assert sorted(p["musig_pubkey"] for p in peers) == exp["sorted_musig_pubkeys"]

    locktime = min(p["height"] for p in peers)
    assert locktime == exp["locktime"]

    funding = parse_tx(exp["funding"]["unsigned_hex"])
    assert funding["txid"] == exp["funding"]["txid"]
    assert funding["version"] == 2 and funding["locktime"] == locktime
    registered = [outpoint(i["txid"], i["vout"]) for p in peers for i in p["inputs"]]
    order = sorted(registered, key=lambda o: th("joinstr/v2/input_order", pid, o))
    assert [i["outpoint"] for i in funding["inputs"]] == order
    assert all(i["script_sig"] == b"" and i["sequence"] == 0xFFFFFFFD for i in funding["inputs"])
    keys = [o["raw"] for o in funding["outputs"]]
    assert keys == sorted(keys, key=lambda raw: th("joinstr/v2/output_order", pid, raw))
    pool_out = funding["outputs"][exp["funding"]["pool_vout"]]
    assert pool_out["value"] == exp["pool_values"][0]
    if not structured:
        assert pool_out["value"] == pools[0]
    assert pool_out["spk"] == b"\x51\x20" + bytes.fromhex(exp["pool_output_keys"][0])
    changes = sorted((p["change"]["amount"], bech32_spk(p["change"]["address"])) for p in peers if p["change"])
    others = sorted((o["value"], o["spk"]) for k, o in enumerate(funding["outputs"]) if k != exp["funding"]["pool_vout"])
    assert changes == others

    assert [bech32_spk(a) for a in exp["payout_order"]] == payouts
    if structured:
        check_structure(v, pid, payouts, ordered_peers, funding, locktime)
        return

    prev = outpoint(funding["txid"], exp["funding"]["pool_vout"])
    start = 0
    assert len(exp["exits"]) == len(exits)
    for k, e in enumerate(exp["exits"], start=1):
        tx = parse_tx(e["unsigned_hex"])
        assert tx["txid"] == e["txid"] and tx["version"] == 2 and tx["locktime"] == locktime
        assert len(tx["inputs"]) == 1 and tx["inputs"][0]["outpoint"] == prev
        assert tx["inputs"][0]["sequence"] == 0xFFFFFFFD
        a = exit_amounts[k - 1]
        expected = list(zip(a["payouts"], payouts[start:start + len(a["payouts"])]))
        pool_spk = None
        if a["pool"] is not None:
            pool_spk = b"\x51\x20" + bytes.fromhex(exp["pool_output_keys"][k])
            expected.append((a["pool"], pool_spk))
        if anchor:
            expected.append((anchor, bytes.fromhex("51024e73")))
        raw = lambda value, spk: value.to_bytes(8, "little") + bytes([len(spk)]) + spk
        expected = sorted((raw(*o) for o in expected),
                          key=lambda r: th("joinstr/v2/exit_output_order", pid, k.to_bytes(4, "little"), r))
        assert [o["raw"] for o in tx["outputs"]] == expected
        start += len(a["payouts"])
        if pool_spk:
            vout = [o["spk"] for o in tx["outputs"]].index(pool_spk)
            prev = outpoint(tx["txid"], vout)


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "tests" / "vectors.json")
    vectors = json.loads(path.read_text())["vectors"]
    for v in vectors:
        check(v)
        print(f"ok: vector {v['name']} ({v['pool']['peers']} peers, {len(v['expected']['exits'])} exits)")


if __name__ == "__main__":
    main()
