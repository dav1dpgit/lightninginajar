# Delegate payment — multi-spend (decisions, 2026-09-02, DP)

Vocabulary: the signed object is a **chit** (the adapter module's internal
name "slip" is legacy). Actors and the verified flow are in docs/session43.md
("Delegate actors, reconfirmed against code").

## What exists (verified in code, 2026-09-02)
- LSP (lijox-adapter delegate.js): the chit carries `cap_msat`,
  `per_pay_cap_msat` (≤ cap, required), `count` (integer ≥ 1, required),
  `not_after`, `nonce`; a spend is refused unless LIVE, bill ≤ per-pay cap,
  spent + bill + fee reserve ≤ cap, count not used up; after a settled spend
  the chit stays LIVE until `count_used ≥ count`. Void allowed while LIVE or
  EXPIRED, refused during IN_FLIGHT. Refund = cap − spent − refunded, on
  closed chits only, paid against an issuer-signed invoice.
- Page (pageapp): its own policy copy — `limitMsat`, `perPurchaseCapMsat`
  (defaults to limit), `purchases` (defaults to 1), deadline; HELD → PAYING →
  HELD/CLOSED; Ben's screen shows "= N sats Remaining" once anything is spent
  and a receipts list.
- Wallet: signs `count = 1` (pinned v558), `per_pay_cap = cap`, and never
  passes `purchases` to the Page.

## Decisions
1. **Spend count stays, default 1.** It is a safety limit ("buy one thing"):
   one purchase unless the funder says otherwise. An empty field, or 999,
   means "spend up to the cap in any number of purchases" — implemented as a
   large count (999) so neither side needs a code change to its ≥ 1 rule.
2. **No per-purchase cap in the UI.** `per_pay_cap_msat = cap_msat` always,
   as today.
3. **Void at any time stays** (except during an in-flight payment, as today);
   the remainder becomes refundable at once.
4. **The runner sees remaining sats only.** The receipts list on Ben's page
   goes; "= N sats Remaining" and the state stamp stay. Less is more.

## Build (when DP returns to it)
- Wallet mint screen: a "Purchases" field, default 1, empty = 999; the same
  number goes into the signed chit (`count`) and into the Page mint body
  (`purchases`), so both enforcers agree.
- Wallet chit list: show spent / remaining per live chit (from
  GET /delegate/slip/<nonce>: `spent_msat`, `count_used`, `count`).
- Page: hide the receipts list; keep the remaining line and the stamps.
- LSP: no change needed.
