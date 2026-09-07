> AUTHORITY NOTE (Session 22): docs/recovery-classes.md is the MASTER
> recovery document; this file is its mechanics appendix.

# LiJ recovery — the three outcomes

Axis: what you restore determines whether channels survive, and what
closes them — the recovery itself, or time.

## 1. Seed + current channel-state backup → channels ALIVE, no closes
The seed is the keys; the encrypted state backup (auto-backup sinks or
exported file) is the relationships. Restore both: the wallet
reestablishes with the LSP and channels resume where they were.
Recovery in minutes. Channel state is not derivable from a seed on any
Lightning wallet, by design — this is the only channel-preserving path.

## 2. Seed only → funds fully recovered; channels close BY the recovery
On first reconnect the LSP sees a peer that provably lost state and
force-closes from ITS latest commitment. Because the LSP broadcasts,
the user's balance rides the output paying the user's key with NO
delay clause (the force-close delay binds the broadcaster's funds).
Every close sweeps to the single recovery key the seed controls;
spendable on-chain after ~1 confirmation per close — typically within
the hour. Channels gone by design; new capacity via JIT.

## 3. No access → channels close BY TIME; money waits indefinitely
If any HTLC was in flight at loss time, its timelock FORCES on-chain
resolution within blocks-to-days. Otherwise the LSP closes inactive
channels on its own schedule (capital recycling). Either way the
user's balance lands on-chain at the user's key and sits there —
unspendable by anyone else, LSP included — until the seed returns,
next month or next decade.

## Stale-backup footnote
A wallet that detects it is behind refuses to broadcast (data-loss
protection; broadcasting an old state is what the honesty deposit
punishes), signals the LSP, and the LSP closes from its latest state —
Outcome 2 economics. Never run one state in two places.

## Golden line
The seed always recovers your money; only the state backup recovers
your channels; time never costs you anything but the channels.
