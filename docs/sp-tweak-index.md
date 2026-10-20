# The silent-payment tweak index — what a LIJOX box serves, and why (S50, 2026-09-28)

Status: LIVE on the UM890 since 2026-09-28 17:48 PDT (start height 969,075 = that moment's tip; coincurve 21.0.0;
`/sp/info` through the tunnel); the Umbrel stays without it (DP). The wallet side (SP receive)
is not built yet — this document is the box half of the LIJOX standard for silent payments.

## 1. The problem in plain words

A silent-payment address (sp1…) is one reusable address, but every payment to it lands at a different
on-chain address that only the receiver can work out. To find its payments, a wallet has to look at every
transaction with a taproot output and do one piece of arithmetic per transaction: multiply a number that
depends on that transaction's inputs (the "tweak") by its own secret scan key, and see whether the result
matches one of the transaction's outputs.

The tweak itself is public data, but a phone cannot compute it: for a taproot input, the public key needed is
in the coin being spent — in an older block — not in the transaction. A node can; a phone can't without every
block. So the box computes the tweak for every eligible transaction once and serves the list. The phone does
the secret half. The box never sees a key, an address or a match.

## 2. What is eligible (BIP-352)

A transaction is indexed when
- at least one output pays a taproot key (witness v1, a 32-byte program), and
- at least one input carries a readable public key: P2TR (the prevout's 32-byte key, lifted to even y — unless
  it is a script-path spend whose control block names the NUMS point H as the internal key), P2WPKH (the
  33-byte key in the witness), P2SH-P2WPKH (the same behind a `0014…` redeem script), P2PKH (the 33-byte key
  that hashes to the script; uncompressed keys are ignored). Coinbase transactions never.

The tweak: `A_sum` = the sum of those keys; `input_hash` = sha256-tagged("BIP0352/Inputs", smallest outpoint
(txid, 32 bytes as in the hash, ‖ vout, 4 bytes little-endian) ‖ A_sum compressed); `tweak = input_hash · A_sum`,
33 bytes compressed. A sum that lands on the point at infinity → not eligible.

Checked against the BIP's own test vectors (28 cases, including the NUMS script-path, the malleated P2PKH,
uncompressed keys, invalid P2SH, the zero-sum case), on libsecp256k1 and on the pure-Python fallback.

## 3. What the box keeps

One sqlite file (`SP_DB`, WAL). Per block: height, hash, the sorted tweak list, the count, the commitment and
the chain head. The mempool table: eligible unconfirmed transactions with their tweak and their taproot
outputs (vout, x-only key, value), a sequence number, and a "gone" mark when they leave the pool.

The commitment is the public **spcommit-v1** format (bitsagarob/silentpayments-measurements, SPCOMMIT.md):
`sha256("spcommit-v1\n" height "\n" blockhash "\n" count "\n" tweak1 "\n" tweak2 "\n" …)` with the tweaks as
66-character lowercase hex sorted as strings, every line ending in `\n`; the head chains as
`sha256(prev_head_hex ‖ commit_hex)` over the ASCII strings. Two boxes that indexed the same block honestly
have the same commitment — that is the wallet's cross-check before its scan cursor passes a block (a box
cannot forge a coin — a wrong tweak simply never matches — but it could leave one out; two boxes agreeing
close that door). The genesis head is the indexer's own fixed value until the measurement repo's vectors are
checked byte-for-byte (`spcommit-test-vectors.json`); the per-block commitment does not depend on it.

## 4. What the box serves (through the tier-2 filter server, same host, same CORS)

| Route | Answer |
|---|---|
| `GET /sp/info` | `{format:"spcommit-v1", start_height, indexed_to, tip, mempool_seq, dust_limit:0, filter_spent:"N/A"}` |
| `GET /tweaks/<height>` | the public BIP-352 index-server spec's shape: `{height, hash, dust_limit:0, filter_spent:0, tweaks:[hex33…]}` |
| `GET /sp/tweaks?start=H&count=N` | `{blocks:[{height, hash, count, commit, tweaks:[…]}]}` — N ≤ 500 |
| `GET /sp/commits?start=H&count=N` | `{commits:[{height, hash, count, commit, head}]}` — the cross-check, small |
| `GET /sp/mempool?since=S` | `{seq, tweaks:[{seq, txid, tweak, outputs:[{vout, key, value}]}], gone:[txid…]}` |

Without `SP_DB` the routes answer 404 `no silent-payment index on this box` — the wallet reads that as "this
provider does not serve silent payments" (an LSP-card item, like the kit holder and the Push Key).

**The index is optional per LSP** (DP, 2026-09-28: "SP is an option for LSPs, not just for wallets"): the UM890
serves it; the Umbrel (LSP-2) does not and is not expected to. A wallet on a provider without it can still send to
sp1 addresses (the sender needs no index) but cannot receive on its own sp1 address there; the LSP card says so.

Sizes: ~33 bytes per eligible transaction; at recent volumes ~9 KB per block, ~25 MB per week of index; a
500-block answer is ~4–5 MB.

## 5. The operator's setup (one box)

1. bitcoind ≥ 24 (`getblock <hash> 3` gives each input's prevout; `getrawtransaction … 2` the mempool's);
   `txindex` is not needed. `coincurve` (libsecp256k1; `python3 -m pip install --user --break-system-packages coincurve` — Ubuntu 24.04 has no apt package for it) — without it the indexer runs the pure-Python
   curve, correct but ~100× slower.
2. `lij-sp-index.py` as a systemd service beside `lij-tier2`: `BITCOIND_COOKIE_FILE`, `SP_DB` (a directory the
   service owns), `SP_START_HEIGHT` on the first run (the first block to index; lowering it later widens the
   index downward — the backfill runs first), `SP_MEMPOOL=1`.
3. `SP_DB` added to `lij-tier2`'s environment; restart. `curl /sp/info` is the receipt.

A lowered `SP_START_HEIGHT` (a backfill — DP, 2026-09-28 19:05: the UM890 to **840,000**, the block band in which the
first wallets that could receive a silent payment shipped; nothing older can exist) fills the gap a slice at a time
BEHIND the live head — new tip blocks and the mempool keep being served — and re-links the chain heads above the old
start once the gap closes (they were chained from the genesis value while the block below them was missing). The
journal's "indexed N block(s) … (M left)" lines are the progress. `/sp/info` shows the new start **once the gap has
closed** (2026-10-19, the silentpayments.xyz review, finding 2): `start_height`/`indexed_to` describe the gap-free run
of blocks that ends at the head, so a wallet is never pointed into a hole; until then it shows the old start.

**Re-index in place** (`SP_REINDEX=1` in the indexer's environment, 2026-10-19 — finding 1, the P2PKH scriptSig
parse): every already-indexed block from the start to the top at that moment is parsed again, oldest first, a slice
at a time behind the live head, each row replaced where it stands (the served range never has a hole; a block whose
tweak set changed gets a new commitment); when the last slice is done the chain heads are re-linked from the start.
The cursor is kept in the database, so a restart resumes where it was. The journal's "re-indexed A..B in Xs (N
changed; M left)" lines are the progress; "re-index complete" and "N chain head(s) re-linked" the end. Leave the
variable set: a finished re-index does not start again (the cursor is gone), and a later restart with it unset is
the same. The 2026-10-19 self-test (`--selftest send.json receive.json`) checks the parser against the BIP's own
per-case tweak, not against itself.

Start height (position put to DP): the tip on the day the index starts — no LiJ wallet can hold a silent
payment before LiJ ships receive; a seed that received silent payments in another wallet earlier is a
backfill decision, not a default. Indexing from taproot activation (block 709,632) is days of work on an RPi4
and hours on the UM890; from a recent height it is minutes.

## 6. What the wallet does with it (engine v287–v290, 2026-09-28 — `lij-core/src/sp_scan.rs`)

The words (DP, 21:10): the box builds the **index**; the wallet's engine on the phone runs the **scan** — it reads the
box's hints and the block filters and checks; it never moves a coin ("sweep" is the Black start kit's word, a
transaction that moves coins). The wallet has a say too: Privacy → Silent payments carries a switch (on by default;
off = no scan, no sp1 address shown; on again resumes where it stopped).

- Each sync the wallet reads `/sp/info`. A 404 means "no index here": nothing else happens, and the wallet
  can only send to sp1 addresses at that provider.
- The scan runs UPWARD, in batches of 100 blocks (200 once the m/84 walk is done), from its start to the
  m/84 walk's top: for each block it multiplies the served tweaks by the scan key on the phone, works out the
  taproot script each would have paid, and tests those — with the scripts of the silent-payment coins it
  already holds, so their spends are seen — against the block's BIP158 filter (fetched alongside the headers,
  as the walk does). Only a matching block is downloaded; it is bound to the PoW-checked header by hash and
  its merkle root; the coin lands on the ledger as chain 352 with its t_k; spends of known coins are marked by
  outpoint. Every batch's headers are PoW-checked and linked to the previous batch's last block, and at the top
  to the block the walk already trusts — one continuous chain from the start to the top.
- Because the scan goes upward, a coin is always met before its spend: no block is re-read for a spend (the
  "down-walk re-check" of DP's decision 3 is not needed in this shape; its cost is nil).
- The start (decision 1): a wallet already walked before v287 starts at that moment's top (no LiJ wallet could
  have received a silent payment before it showed an sp1 address); a fresh view — a restore, a rescan — starts
  at the later of the box's index start and the wallet's birthday.
- Decision 2 (one box): every served block's commitment is recomputed from the served tweaks (`spcommit_v1`);
  a mismatch refuses the box. The scan is marked `single_source` until a second box can be compared.
- The mempool leg runs once the scan stands at the top: `/sp/mempool?since=<seq>` — a match is
  "received · pending" until its block lands (the coin replaces it), or dropped when it leaves the pool.
- A reorg rollback of the m/84 walk rolls the scan back with it. Progress is saved after every batch, so a
  closed or backgrounded app resumes where it stopped.
- The summary's `sp` block carries: enabled (the wallet's switch), available, index_start, indexed_to, from, scanned_to, top, done,
  waiting_for_index (the box's index behind the chain), single_source, pending (+ pending_sats), coins, note.
- Cost (decision 4): the scan itself — ≈ 5–9 KB of tweaks per block on the wire and ~0.1 s of curve work per
  block on a phone (an estimate until measured); a fresh restore from 840,000 is a few hours in the background.
