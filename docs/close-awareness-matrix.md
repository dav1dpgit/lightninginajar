# Close-Awareness Matrix (Session 23, DP-mandated: all scenarios, both sides)
Doctrine (DP, ratified 2026-07-12, verbatim): the wallet is accurate; when
something is off, reflect it to the user; the front screen always shows
correct balances. Money-safety note: every channel state change requires
BOTH signatures — a dead channel cannot move a sat regardless of display;
the matrix below is about AWARENESS and display honesty, never fund risk.

How a party learns of a close (the four channels of knowledge):
 K1 protocol message — coop closes only (shutdown ⇄ closing_signed);
    force closes have NO message BY DESIGN (must work vs dead/hostile peer).
    LND does try to answer a reestablish for closed channels from its
    closed-summary DB, but broadcast-but-unconfirmed closes aren't in it
    yet ("unable to find closed channel summary") — silent exactly in the
    mempool window. LND may also send an error to a CONNECTED peer at
    force-close time (matrix cell to verify live).
 K2 chain, confirmed — LDK monitor / LND chainwatcher see the funding
    spend at 1 conf. The floor. VERIFIED WORKING (T-CLOSE-1: eviction,
    balance fold, closed history all landed together at 1 conf).
 K3 chain, mempool — full-node LND sees instantly (channel left
    listchannels at broadcast). Light wallet compensator = the funding-
    spend walker (44d48bc) via Esplora: SAW the T-CLOSE-1 spend every
    pass, deliberately skipped ("not yet confirmed") — eviction is
    destructive and MUST stay confirmation-gated. v178 fix: the walker's
    unconfirmed branch now emits a NON-DESTRUCTIVE display signal
    (closing_seen_mempool + closing_txid in ChannelInfo).
 K4 LSP courtesy message (adapter custom msg) — accelerant, display-only
    trust. QUEUED (not in v178).

The matrix (initiator × wallet-state × phase → wallet display):
 A. Coop, wallet-initiated ....... K1 both sides pre-broadcast. Settled
    (#19 lifecycle, lijCloseInbound at initiation). TEST 3.
 B. Coop, LSP-initiated .......... requires wallet online (coop needs
    both); K1 informs LDK (shutdown recv → is_usable false → R3/closing
    UI). TEST 1. Wallet-offline variant IMPOSSIBLE — an LSP exiting
    against an offline wallet MUST force-close (⇒ D is the LSP's normal
    exit vs mobile wallets; DP's "kind of important" exactly right).
 C. Force, wallet-initiated ...... wallet knows (it acted; #19 marks at
    initiation); LND knows via K3-full-node instantly. TEST 2.
 D. Force, LSP-initiated, wallet OFFLINE (= T-CLOSE-1) ... K1 silent
    (LND pending-close hole), K2 at 1 conf, K3-walker saw-but-skipped.
    v178: walker sighting now paints amber "Closing — in the mempool",
    close note on the live card, spendable/receivable EXCLUDED, Closing
    card via lijCloseInbound. TEST 4 (retry).
 E. Force, LSP-initiated, wallet ONLINE ... unverified cell: LND may
    send a live error (K1) → LDK closes immediately. Verify during
    TEST 4 variant if convenient.

Open question carried (is_usable puzzle): LDK source says a restarted
wallet must report the unreestablished channel unusable (write path
forces PEER_DISCONNECTED; only a received reestablish clears it), yet
all surfaces showed usable through repeated force-stops. Evidence now
obtainable: v297 diag sheet exposes per-channel ready/usable — capture
during the matrix run. v178's closing_seen_mempool overrides the dot
and the sums regardless, so display honesty no longer depends on it.

DP test order (Android): 1) LSP coop close → 2) wallet force close →
3) wallet coop close → 4) LSP force close retry (+E variant).
