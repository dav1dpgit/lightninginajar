// lij-wasm/src/lib.rs
// The WASM bindings layer. Everything marked #[wasm_bindgen] becomes a
// JavaScript function or class that the PWA can call directly.
//
// This is the complete API surface of Lightning-in-a-Jar from the PWA's perspective.
// The PWA imports this as an npm package and calls these functions.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use std::sync::Arc;

use lij_core::{
    storage::wasm_storage::LocalStorage,
    types::WalletConfig,
    wallet::LijWallet,
};

// Thread-local storage for internal WebSocket callbacks to reach the wallet
// without round-tripping through JS.
thread_local! {
    static CURRENT_WALLET_INNER: std::cell::RefCell<Option<Arc<std::sync::Mutex<LijWallet>>>>
        = std::cell::RefCell::new(None);
}

fn set_current_wallet_inner(inner: Arc<std::sync::Mutex<LijWallet>>) {
    // v219 (DEFECT B, F4): a replaced instance's sockets must not keep feeding
    // the new PeerManager. Close them first; WS_MAP entries leave via their
    // own on_close path.
    ws_transport::close_all_sockets();
    CURRENT_WALLET_INNER.with(|slot| *slot.borrow_mut() = Some(inner));
}

fn current_wallet_inner() -> Option<Arc<std::sync::Mutex<LijWallet>>> {
    CURRENT_WALLET_INNER.with(|slot| slot.borrow().clone())
}

/// v227 (S43, speed): the event pass, run on the turn after inbound bytes.
/// try_lock only — if a send or the tick holds the wallet, the tick catches
/// up within a second exactly as before. Events seen ⇒ write the resulting
/// messages (claim / fulfill) now and flag the manager dirty so the next
/// tick's persistence fires as if the tick had seen them.
thread_local! {
    /// v227: at most ONE early pass queued at a time — a burst of inbound
    /// frames schedules one pass, not one per frame.
    static EARLY_PASS_PENDING: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

fn schedule_early_event_pass() {
    if EARLY_PASS_PENDING.with(|c| c.replace(true)) { return; }
    wasm_bindgen_futures::spawn_local(async {
        EARLY_PASS_PENDING.with(|c| c.set(false));
        early_event_pass();
    });
}

fn early_event_pass() {
    let inner = match current_wallet_inner() {
        Some(i) => i,
        None => return,
    };
    let wallet = match inner.try_lock() {
        Ok(w) => w,
        Err(_) => return,
    };
    let node = wallet.node();
    match node.process_channel_events() {
        Ok(true) => {
            node.mark_manager_dirty();
            node.pump_outbound();
        }
        Ok(false) => {}
        Err(e) => log::debug!("early_event_pass: skipped ({e})"),
    }
}

// ── Initialization ───────────────────────────────────────────────────────────

#[wasm_bindgen(start)]
pub fn lij_init() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();

    let dispatcher: std::sync::Arc<dyn lij_core::peer::SocketDispatcher> =
        std::sync::Arc::new(ws_transport::WsDispatcher);
    if let Err(e) = lij_core::peer::set_dispatcher(dispatcher) {
        log::error!("Failed to register WebSocket dispatcher: {e}");
    }

    log::info!("Lightning-in-a-Jar WASM initialized");
}

/// Build version of THIS compiled WASM binary. The frontend compares it to its
/// own LIJ_FRONTEND_VERSION; a mismatch means the deployed binary is stale
/// (an incremental build that skipped WASM regen). Bump on every WASM rebuild.
#[wasm_bindgen]
pub fn wasm_build_version() -> String {
    "phase11-v350".to_string()  // v350 (S61 Mon, DP 2026-10-19 21:31 "the wallet as a login … the scan flow recognizes the login QR, asks 'Log in to <site>?', done"): lnurl_auth_answer — LNURL-auth (LUD-04/05), the key per site from m/138'/…, the challenge signed; lij-core/src/lnurl_auth.rs, its linking keys pinned to an independent Python computation. · v349 (S61 Mon, DP 2026-10-19 "Get A done now" — Step A, THE DOORS INTO A PROVIDER; docs/design/routes/routes-r1.md): the registry record carries `routes` (lijox-register:v4; lij-worker 0.13.0, adapter 0.108.0) — every door into the same provider with the operator's signed word for what sits between the wallet and the box (direct: TLS ends on the operator's machine; cloudflare: Cloudflare's edge ends TLS). LspInfo.routes + LspInfo.reach (the word of the door applied). The wallet's Reach preference (WalletConfig.route_pref: direct-first (default) / never-cloudflare / cloudflare-first) is handed in at init and applied in ONE place, Node::connect_lsp — every path that connects a provider (the boot ladder, a switch, a restore) picks the first allowed door (lsp::pick_route: direct, then cloudflare, then a one-door record of unknown reach; never-cloudflare = direct only; a record with no allowed door is NOT connected and nothing is sent to it; tor is a word, never a door). The registry is a door too: under never-cloudflare a Cloudflare-reached registry (WalletConfig.worker_reach) is not read when the wallet has a persisted choice or a channel counterparty — a fresh wallet reads it once. New calls: switch_lsp_with(record_json) (no registry read), relink_active_lsp(endpoint) (another door of the active provider's own record: the addresses swapped, persisted, the peer link dropped so the monitor reconnects at the new wss_url), route_state_json() (the preference and the last connect's note). Tests v349_the_record_parses_with_and_without_routes, v349_the_preference_orders_the_doors, v349_a_one_door_record_is_used_last_and_refused_under_never, v349_apply_route_moves_the_three_addresses_and_keeps_the_list.
    // "phase11-v348".to_string()  // v348 (S60 Mon, DP 2026-10-19 "Go on 5-9" — the silentpayments.xyz review, sethforprivacy/silentpaymentsxyz#80, all four findings reproduced in the bytes): (1) THE RESTORE SWEPT FROM THE TIP — the sweep told a fresh view from an old one by the walk's position, but the walk opens at the tip before the sweep opens, so every restore looked like an old wallet; now the floor is RECORDED (Tier2View.sp_floor) at birth (tier2_wallet::birth) and by a rescan year (rescan_from), the sweep starts at the later of the index start and the floor, a sweep standing above its floor is pulled down once (coins stay), a view with no floor (walked before v287, or restored between v287 and v348) sweeps from SP_LAUNCH_HEIGHT 968,900 (DP: heal them all); (2) a height missing from the provider's tweak list is a gap, not an empty block — the batch is refused and the cursor holds; (3) K_max 2323 (was 10,000), the cap exercised by a test. Tests v348_a_restore_sweeps_from_its_birthday_even_though_the_walk_moved_first, v348_a_sweep_above_its_floor_is_pulled_down_once_and_never_up, v348_a_tweak_list_with_a_missing_height_holds_the_scan, v348_the_receiver_stops_at_k_max.
    // "phase11-v347".to_string()  // v347 (S59 Thu, DP 2026-10-15 17:56 — the relay listing: no pool named our network): THE WIRE NAME OF MAINNET. The public joinstr v2 code writes "mainnet" (peer.rs network_name) and refuses a pool whose network differs; this engine declared and announced "bitcoin" — a Joinstr user's mainnet pool was "another network" to us, and our rooms to them. caps::wire_network maps either spelling to "mainnet" on both sides of the check; the engine's own declaration and announcements say "mainnet"; the adapter 0.106.1 announces "mainnet"; the page compares the wire name. Test v347_mainnet_is_the_wire_name_and_bitcoin_still_reads. 474 green.
    // v346 (S59 Thu, DP 2026-10-15 17:13 "% loaded for the Black start"): the restore's progress — lij_core::progress reports each step of a restore from saved state (a monitor at a time, the manager, ready; the bytes of saved state read so far and in all) to window._lijRestoreProgress and pauses a timer tick so the page can paint; the Offline room shows "channel 3 of 18 · 17 %". Tests v346_steps_reach_the_sink_in_order_and_none_without_one, v346_a_restore_from_saved_state_reports_its_steps. 473 green.
    // v345 (S59 Thu — the 2b re-check, a): mix_public_join_again(attempt_id) — the join sent again (a fresh event, the same key) while it waits, so a host that dropped the first under its budget, or had not yet read the key named at `open`, hears it; eight sendings at most. // v344 (S59 Thu — the 2b security pass's engine fixes): the seat is claimed only once a public join or room is built (a refused announcement no longer locks the seat on the page — #1); mix_public_fits(seat, relay, event) = the full join check with no side effect, for the page's list; the v3 seat message carries the PROVIDER and the fee cap in THOUSANDTHS (the phone's own limit — #2, #7); a room that closes without this phone stops naming no one (#3); a "pool is full" from the pool key is advisory until the join's 90 s run out — a key holder could forge it (#4); stalled() never names this phone (#6); Notice::Room / MissedRoom (the hosted room's wake — #9); `open` for a room names the join key (open_room_body) so the join carries nothing — v342's token (P12) withdrawn (#4/#5); ws:// relays only on loopback. // v343 (S59 Thu, Phase 2b step 1b): mix_seat_new takes `public_ok` (the wallet's Public pools switch) — a provider's seat then signs the v3 seat message (public + its fee cap, 1.5× the rate at Join) for adapter 0.106.0's host; Seat.public_ok; store::seat_fee_cap. // v342 (S59 Thu, DP 2026-10-15 13:14 "Go" — Phase 2b step 1, the hosted join): mix_public_join takes an optional reserved-seat token (a 64-hex string from the provider's wake notice) and the join request carries it to the host (LiJ P12: Msg::JoinPool { lij_token }); without one the request is the public code's bytes. The adapter's host role and the page's wake handling follow. // v341 (S59 Thu morning, DP 2026-10-15 07:43 "Go on your suggestion for the coin check for public rooms" — the security review's recommendation 1): a public room's coin check (mix_attempt_coin_quorum) now needs TWO explorers that agree (independent::coin_check_agreed — each endpoint's own verdict from the transaction and its outspends; one voice or a split is no answer, and the attempt stops naming no one); it took the first explorer that answered. // v340 (S59, the security review at the close — DP 2026-10-14 23:45 "look for holes and doors"): (1) a message that fails to parse or check stops the pool only when a REGISTERED member sent it (then that member is named); from any other key — a stranger holding a public room's key, a one-time payout key — it is ignored (S1), where it used to stop everyone's attempt with no one named (machine.rs on()); a wrong-type payout is therefore ignored and the Payouts clock runs out; (2) funding signatures are taken only from the member that registered the input and only when they verify against the funding this phone built (phone.rs collect_witnesses + joinstr funding::verify_input; the record carries the prevouts) — they used to be taken from any key, unverified, first-wins; (3) a pool id this phone already holds a record for is refused at join (mix_refuse_known_pool) — a reused id would have replaced the record; (4) the phone's seen-set is bounded; (6) one seat runs one attempt at a time on this page (MIX_SEAT_OF). // v339 (S59, DP 2026-10-14 22:29 "can one leave a public pool before the hour is up?"): mix_attempt_leave — this phone leaves a running attempt on purpose before its coin signature (machine Input::Leave → the stop, an abort to the members who then move on at once; nothing moved, nobody named); the page offers it on a public room still filling. // v338 (S59, the clocks — DP 2026-10-14 21:39): a public room's registration phase lasts until its announcement's timeout + one step (machine.rs first_phase_until; phone.rs start), as the public code waits — not PHASE_S from this phone's own registration, which would have ended every public room this wallet opens or joins two minutes after the first registration. // v337 (S59, DP 2026-10-14 21:39 "Go ahead, let's build it" — the COMBINED list): a provider's on-chain seat may take a public room of its size (mix_public_join(seat_pk, relay, event) / mix_public_create(seat_pk, relay, rate, peers) take the relay the page watches; store::public_start no longer needs a public seat; AttemptStart.public marks the attempt); StoredRecord.public / RecordView.public (the record's "public pool" label, written by store::after from the phone); Out.members (the registrations in so far — a public room's "2 of 3"). // v336 (S59, DP 2026-10-14 20:21 "get busy with the next" — Phase 2a, public pools): the engine's public path. A PUBLIC SEAT (store Seat.public: no provider; `endpoint` the public relay; one per size; mix_seat_new {"public":true,"endpoint":"wss://…"} answers no provider body) joins a pool the page found on that relay by the public Joinstr code's handshake, inside the engine: mix_public_peek (the engine's strict read of an announcement — what the page lists), mix_public_join(seat_pk, pool_event) (the checks a LiJ join makes — size, fee limit, network, timeout; a provider's pool refused — BEFORE the join_pool request goes out under a key derived for this one pool; answers the request to post and the join's own filter), mix_public_event (the credentials → the phone, which then runs through mix_attempt_event/tick as any attempt; a reject or a replay reported), mix_public_timed_out (90 s, or the pool's own timeout), mix_public_create(seat_pk, rate, peers) (a public pool announced with no seats named; the phone answers join requests itself — credentials while seats remain, "pool is full" after, as the public code's creator; joiners never answer), mix_attempt_coin_quorum (a coin check with no provider: this wallet's own explorers — known and confirmed, the output as registered, unspent; no answer = no answer). The record is kept here as any pool's; there is no provider to back it up to and no forwarder: the payout rides the relay under its one-time key (the public code's way). The proof harness (jproof.rs) now drives this path: join at 2 and 1.5 sat/vB, create at 2 — complete. // v335 (S59, DP 2026-10-14 17:51 "Phase 2 … the compatibility proof with fractional fee rates first"): what the proof found, in the engine — (1) P11: the pool event's `public_key` is the pool's NOSTR key (32 bytes x-only), as the public Joinstr code writes and checks it; P8 had demanded a 33-byte point, so no public pool parsed and no LiJ pool would have been found by a public client (msg.rs parse_strict, phone.rs make_announcement/open_announcement, tests); (2) fee rates with up to three decimals are pool options (msg.rs, caps.rs phase1_pool, within_fee_limit_milli; the public demo runs at 1.5 sat/vB; DP 3(b)); (3) a public pool (machine.rs `public`, Common.public): other joinstr clients send no lij_view, so S3 covers the LiJ members' views, signing waits for every member's nonces, and a partial signature that does not verify names no one (tatara-engine-r2's "rule of their own — written then"); (4) the dead "close" route word of v334 is gone (adapter 0.105.1). The proof: the public Joinstr v2 code, built unchanged, as pool members through a capture relay against this engine — our seat joining its pool (rate 2 and 1.5) and its members joining ours (rate 2): every message type both ways, three funded pools, every exit chain complete (lij-core/src/tatara/jproof.rs, ignored tests). // v334 (S59, DP 2026-10-14 14:39 — the per-route sizes (item 20) and the RECENT line of a pool-funded channel): (1) mix_seat_new takes route "close" — a channel's coin, after its cooperative close, seated in the provider's close pools (adapter 0.105.0 TATARA_CLOSE_SIZES: their own queue and sizes, lifted from the on-chain list; channel sizes no longer need to be among the on-chain sizes either) — on-chain in every other respect, so the engine treats it as the chain route; (2) ChannelInfo.funding_height (the scid's block) and ClosedChannelRecord.pool_funded / funding_height, written at ChannelClosed from the UCID bit and the cached height: the page draws a pool-funded channel's "moved to Lightning" line from the channel records (the pool's exit pays no address of the wallet's, so the chain walk never sees it and no ChannelOpen row exists; the line used to be missing — DP: "Mixing from onchain into a lightning channel doesn't [show in RECENT]")
    // "phase11-v333".to_string()  // v333 (S59, DP 2026-10-14 "Bump stuck Mix exits is now-work"; spec v0.10 §6.4): SPEED UP A STUCK POOL — lij_core::tatara::bump: a child spending this phone's payout alone (P2TR key-path, the payout's own m/86 key) to a fresh m/86 address of this wallet's (marked mixed, as the payout was), with a fee that lifts every unconfirmed transaction of the chain up to this phone's exit — the funding and the exits before it — to the target rate (miners take a transaction by its ancestor fee rate, so the whole pool moves and every member benefits; the fee comes out of this phone's new coin). mix_bump_quote(id, sat_vb) asks the chain servers about each transaction of the chain and prices the child (the exits' fees exact from the record's bytes, the funding's from the pool's rate, now kept on the record — StoredRecord.rate_sat_vb; an older record reads it from its first exit); mix_bump(id, sat_vb) takes the quote afresh, builds, signs, broadcasts and records the child among the sends still confirming (TxKind::MixSpeedUp; the record view carries sped_up_txid/sped_up_fee_sats). Refused in words: a channel pool (its payout is a 2-of-2), another wallet's payout, an exit already in a block, a rate below today's, a coin too small, a funding not on the network, a speed-up already on its way. The settle check is untouched (the payout's exit settles the pool). Tests b1–b4 (the child's exact size 111 vB measured; the Schnorr signature verified against the payout's key). lij-core 451 + 1 ignored.
    // "phase11-v332".to_string()  // v332 (S58, DP's first channel pool 2026-10-13 23:27 "Go"): (1) the creating phone's strict parse of its own announcement (P8's allowlist) takes `payout_type` — a channel pool's event carries "p2wsh" and the list lacked it, so every create stopped with "unknown field in the pool event" (phone test p1b: the announcement round trip for a channel pool). (2) A seat keeps its coins' ledger rows (Seat.coin_rows) when it is taken; an attempt's start uses the ledger's row when the list holds it and the seat's copy when it does not (a rebuild or a reorg rollback rewrites the list and re-derives a coin within a minute — one phone's "the seat's coin is not in the wallet's ledger" cost the pool a retry); mix_attempt_create / mix_attempt_join answer a "note" for the Mix log when the copy was used.
    // "phase11-v331".to_string()  // v331 (S58, Phase 1b step 11c's engine half): the seat's route in the signed seat request — mix_seat_new takes "route" ("chain" | "channel"); seat_message_v1 / seat_body_v1 / ring_seat_digest / ring_seat_body carry the route (a chain seat signs exactly what it signed before; adapter 0.103.0 checks the same); ChannelInfo.pool_funded (the UCID bit) so Connections can say "Opening — waiting for the pool". lij-core 445 + 1 ignored.
    // "phase11-v330".to_string()  // v330 (S58, DP 2026-10-13 18:08 "Proceed with onchain to pool to channel (1b) now" — steps 11a/11b): THE CHANNEL ROUTE — joinstr P1 payout_type (p2tr | p2wsh; the vendored diff regenerated, the gate green); the pool machine's Channel phase (OpenChannel → PayoutGiven → the ring-signed registration; every payout checked against the pool's declared type; FundChannel names the exit that pays this phone's channel exactly the size; the coin signature waits for ChannelSaved; ChannelFailed stops with nobody named); the node's pool channels (UCID_POOL_FUNDED_BIT: open_pool_channel with the provider — static remote key, no anchors, private, a fresh nonce per attempt; FundingGenerationReady keeps the funding script for the pool instead of building a transaction; fund_pool_channel hands LDK the exit's outpoint (unsafe_manual_funding_transaction_generated); FundingTxBroadcastSafe = the provider's signature, saved once the manager is written; a stop before the coin signature drops the half-open channel, never filed as a close; a channel record wiped for "the coin went elsewhere" drops its channel); the wasm: mix_attempt_channel_open / mix_attempt_payout / mix_attempt_channel_saved / mix_attempt_channel, the tick carries the channel's news into the attempt. StoredRecord.channel, channel_id() = LDK's v1 id of the exit's outpoint (test r0); a channel record puts the funding row only. Tests c1–c3, r0, s1b. lij-core 445 + 1 ignored.
    // "phase11-v329".to_string()  // v329 (S58, DP 2026-10-13 17:12 — his first mainnet pool, three phones, in a block): THE POOL IS SEEN LIKE ANY SEND OF THIS WALLET'S, AND ITS RECORD NAMES ITS TRANSACTIONS — store::record_save puts the funding (this phone's coins reserved, its change back) and this phone's exit (received) among the sends still confirming (PendingTx, TxKind::Mix) the moment the record is written, so ONCHAIN RECENT and ONCHAIN COINS show the pool before its block; the rows go with the record, or at once when "Keep my coin out" spends the coin elsewhere (drop_pool_rows_for); records_view names the funding txid, every exit's txid, this phone's exit and output, the payout's address and the change (and a record's own funding row is not a keep-out); mix_tx_status asks the quorum whether a txid is known (tx_known: true / false / null) and, when known, whether it is in a block — the Mix screen's "Pull my coin back" shows only for a funding the network has not seen. The record keeps the change script and index (StoredRecord v329). Test s1b. lij-core 441 + 1 ignored.
    // "phase11-v328".to_string()  // v328 (S58, DP's first real pools 2026-10-13 11:44/11:55 — the cellular phone's coin checks never reached the second provider; the page counted "no answer" as "the coin failed", the phone blamed both members, refused their coins in every retry and its abort stopped the others; the boxes' journals, no phone log yet): A COIN CHECK WITH NO ANSWER BLAMES NO ONE — mix_attempt_coin takes an empty answer as "no provider answered" (Phone::coin_result Option<bool>; machine Input::CoinsChecked { bad, unanswered }): the attempt stops with "the coin checks got no answer from any provider", names nobody (nothing is refused later), and its abort stops the others without blame; the final re-check of one's own coin refuses to sign without an answer. Test p5b. lij-core 440 + 1 ignored.
    // "phase11-v327".to_string()  // v327 (S58, step 8 — the Mix screen's Confirming card): (1) mix_records answers each record's coins (inputs), their value (coin_sats) and its state from the wallet's own ledger and its sends still confirming — "waiting" (the funding is not in a block and nothing else spent the coin: "Keep my coin out of this pool" may be offered while no setup is running), "funded" (the funding spent it: the exits go out), "kept_out" (this wallet's own send took it: the pool can never use it; wiped once 6 deep). (2) mix_keep_out_quote(req) — what "Keep my coin out" costs before the person confirms: the coins' value, the fee for them alone to one address of this wallet's own (coin_quote's one-output Max of exactly those coins — the send's own arithmetic), what arrives; the same checks as the send, nothing written. (3) From Channel's quote: mix_quote with "close_sats" in place of "coins" quotes the coin a cooperative close of a channel with that balance will pay (the wallet's whole balance, to its own m/84 shutdown address — P2WPKH; LiJ's channels are provider-funded, the provider pays the close fee), with the no-change band (the balances that cover the pool at the fee limit and leave no change at today's rate — "bring this channel to between … and … sats first"); every quote names what goes to the miners when there is no change (to_miners_sats — v0.10 §5.3's "180 sats go to the miners"). (4) From Channel's waiting step: mix_close_join_add / mix_close_joins / mix_close_join_drop — a channel this phone is closing so its coin joins a pool ("Close channel and join"), sealed and on this phone only (never in a backup: after a restore the close's coin is an ordinary coin), one per channel and, like a seat, one per pool size. lij-core 439 + 1 ignored.
    // "phase11-v326".to_string()  // v326 (S58, step 8): (1) "Keep my coin out of this pool" (v0.10 §8 rule 10) — mix_keep_out sends a coin a signed pool's record holds (the funding never came), alone, to a new address of this wallet's own (the next change address, marked), which ends that attempt for good; the record is wiped once that send is 6 deep (the settle check: "the coin went elsewhere"). A seat's coin is not sent: leaving the seat frees it. (2) Every send's change now goes past the change indexes a pool's funding was given (next_change_index_marked — §5.3, §8 rule 1): no send puts its change on an address a pool's members saw. lij-core 435 + 1 ignored.
    // "phase11-v325".to_string()  // v325 (S58, step 8 — the Mix screen's engine needs): mix_quote (what Join shows: the pool size, the fee on top — rederive's own arithmetic at today's rate for the provider's largest pool — the change or none, and whether the coin covers the pool at the fee limit, 1.5 × today's rate); mix_records (the signed pools' records as the screen's "Confirming" cards — the size is the payout's own value); mix_send (a complete pool sent in order: the funding, then each exit — "already known" counts as sent, a refusal stops it); the ledger's coin rows say mix_held (a Mix pool holds the coin). lij-core 434 + 1 ignored.
    // "phase11-v324".to_string()  // v324 (S58, DP 2026-10-13 00:33 "Go ahead with Step 8" — the Mix's engine half; docs/design/mix/tatara-phone-r1.md): ONE PHONE'S ATTEMPT, FOR THE PAGE. The seats (sealed, this phone only, never in a backup): mix_seat_new (a fresh seat key, its coins held from Join, the /tatara/seat body signed by the node key), mix_seat_confirm, mix_seat_drop (the coins freed unless a record names one), mix_seats, mix_seat_body (check-in, leave, pause, resume, open, report, announce, backup — signed by the seat key), mix_notice (a provider's notice checked against its node key before anything in it is read). The attempt: mix_attempt_create — the pool made, its announcement carrying the pool's secret key sealed to each other opened seat's key (the provider passes it on and never holds the key; adapter 0.102.0 names the seats' keys) — and mix_attempt_join (the announcement opened and checked: its signature and author, this seat's copy, Phase 1's options and the provider's, the start's size, people and relay, the fee within the person's limit); then mix_attempt_event / _coin / _tick / _end, each answering what the page does next (the relay posts, the payout for the forwarder, the coin checks, funding signed, the complete funding, the stop and its report). The record is written before the funding signature; a stop before it wipes the record at once; the backup is marked dirty on either. A phone reads only what the relay holds, its own posts included (fed early, a lost payout carried it a step ahead and its timeout named members who did nothing wrong — found by a test). The payout is exactly the pool size; each member's change is what its coin leaves over the pool size, its exit-fee share and its funding fee (rederive's one arithmetic). lij-core 433 + 1 ignored: whole pools of 3 and 6 from the announcement to the complete funding, three wallets from Join to settlement.
    // "phase11-v323".to_string()  // v323 (S58, DP 2026-10-12 23:21 "I am good go proceed on Step 7. Go" — THE MIX'S WALLET SIDE, tatara-rollout-r3 step 7; spec v0.10 §5, §8, §9, §13; docs/design/mix/tatara-explained-r1.md): the engine room for the Mix, nothing on screen yet (step 8). (1) The Tatara key from the 12 words on a path of its own (HKDF "LiJ-Tatara-key-v1", pinned) — mix_tatara_pub(ts) answers its public half and the ring join message the node key signs. (2) A pool's payout: this wallet's next m/86 address, marked Mixed when handed out and never past index 479 (inside what a words-only restore watches), or another wallet's taproot address (the room DP asked for) — and its change at the next m/84 change index, marked so no later send or open reuses an address the pool saw: mix_hand_out(choice). (3) The coin hold (§8 rule 4): CoinMarks.mix_locks, read by every picker (Send, Max, chosen coins, quotes, channel opens), a held coin refused in its own words, Max reporting mix_locked_sats apart from the freezes; mix_hold(req), mix_reconcile(seat_coins) (§9 rule 7). (4) The attempt records (tatara_records): sealed at rest, in every backup while unsettled, the key deleted when none is left; the chain decides — mix_settle() sends a funded pool's exits in order (at most every 10 minutes), wipes a settled record (the payout 6 deep, or the coin spent elsewhere 6 deep) and frees its coins, marks the backup dirty; mix_record_wipe(id); mix_records_count(). (5) The Black start kit carries each unsettled attempt's signed exits alone (mix_exits; never carried from another copy's kit). (6) §13: mixed coins (any BIP86 coin) are in Send, Max and channel opens — last, alone when one is enough — and every quote flags a mixed coin beside another coin (MaxQuote/MultiQuote mixed_inputs+links_mixed, CoinQuote spend_mixed+spend_links_mixed, lsp_channel_open_pick). Inert today: no wallet holds a BIP86 coin and no record exists until the Mix screen (step 8). lij-core 424 + 1 ignored.
    // "phase11-v322".to_string()  // v322 (S58, DP 2026-10-12 20:18 "Go on Proposals 1, 2, and 3" — the CHAIN dot): THE CONNECTION OPENS WHILE THE CHECKS RUN. His v981 reports: connect started → socket open ~1 s (Cloudflare, the tunnel, TLS and the WebSocket upgrade), all of it after the provider check and the cloud check had finished. Now ws_preopen(url) opens the WebSocket to the provider as the checks start; it sends nothing (no Lightning handshake — the unknown-channel safety is untouched: LND only re-establishes channels after the Init exchange); connect_to_peer adopts it when it is still open or opening and under 60 s old (else it is closed and a fresh one opened, as before), and sends the handshake's first bytes at once. The adapter (0.96.0) opens its TCP connection to LND only when those first bytes arrive, so a pre-opened socket holds nothing at LND (LND drops a connection that sends no act one within 5 s — brontide handshakeReadTimeout). ws_preopen_drop() for a start the checks stop.
    // "phase11-v321".to_string()  // v321 (S58, DP 2026-10-12 16:42 — the CHAIN dot still slow on v978; his Performance report: socket open → first chain bundle 2,567 ms): THE CHAIN STREAM NO LONGER WAITS FOR THE TICK. FOUND in background_tick: (1) send what is queued, (2) handle arrived chain messages, (3) not subscribed → queue SubscribeChainData — so the subscribe went out on the NEXT tick and the provider's answer (12 ms at the provider) sat in the inbound queue until the tick after. Now: (a) the handler keeps the last SubscribeChainData and sends it again the moment the provider's peer connects (peer_connected runs inside the socket read, which is followed at once by process_events) — the tick still sends a fresh snapshot after, as before; (b) chain messages are handled right after the socket read (dispatch only updates the stream's state; funding confirmations still go to the tick). Tests v321_* (handler).
    // "phase11-v320".to_string()  // v320 (S57, DP 2026-10-08 22:53 "for Fixes we choose (a)… the note on the row should say self-claimed Push Key, and just show the transaction fee. (b)… put that in, too"): THE SELF-CLAIMED PUSH KEY IS PROVEN DURABLY. FOUND: a Push Key minted and claimed on the same wallet showed "Pushed · taken −1,003" and no incoming row — the lock and the delivery share the key's hash, and the page wrote a claimed payment's row only when no row of any kind carried the hash (two of DP's three 1,000-sat keys; the provider's journal shows both delivered over the existing channel, fee 0, taken, fee kept 3,000 msat — net −3 each; the third went to another wallet). The engine's part: push_in_json marks an accepted push "claimed" when its key has LEFT the preimage pool (push_accept puts it in; only the claim takes it out) — not only when this session saw PaymentClaimed — so the page can tell a self-claim on this phone, in a later session, or after a restore (the pool and the accepted list ride the blob). Test v320_an_accepted_push_whose_key_left_the_pool_reads_claimed (370 green). The page (v974) merges the two legs into one row: "Self-claimed Push Key", the delivery fee alone; and the claim sheet says when a key is the wallet's own and offers to cancel it instead (everything comes back, fee included).
    // "phase11-v319".to_string()  // v319 (S57, DP 2026-10-08 14:40 "Agreed on the fix for the cloud copy fingerprint. Go"): THE PHONE KNOWS ITS OWN UPLOAD. FOUND (DP's phone, 14:33 — "Your cloud copy is newer than this phone: cloud no. 6142, this phone no. 6141"): the phone had uploaded 6142 itself, the cloud stored it, the app was put away before the OK arrived, so the number was never committed (v309 commits on the OK alone) and at the next open the cloud's 6142 read as another copy's. Now: before each upload the phone NOTES the number and the fingerprint (sha256 of the sealed bytes) of the copy it sends (storage::backup_inflight_note, KEY_BACKUP_INFLIGHT); the cloud keeps the fingerprint of the copy it stores (worker 0.10.0) and answers it with the number; cloud_backup_meta adds "fingerprint" and "own" (backup_meta_is_own: number AND fingerprint equal the note); backup_adopt_own() takes the noted number (never one from the page) and clears the note. The note is cleared when the cloud answers (accepted or refused as older); a lost answer keeps it. The worker also accepts a resend of the very same copy as an OK, so the retry after a lost OK while the app is open is no false conflict. Tests v319_the_fingerprint_is_the_sha256_of_the_sealed_bytes_as_the_worker_takes_it, v319_the_note_is_made_before_the_upload_and_read_back_whole, v319_the_clouds_copy_is_this_phones_own_only_when_number_and_fingerprint_both_match, v319_meta_reads_the_fingerprint_when_the_worker_answers_one
    // "phase11-v318".to_string()  // v314–v318 (S57, DP 2026-10-07 21:36 "start building the wallet side now", 21:53 "Go on 1 & 2", 22:58 "Proceed with the scanner fix" + the kit sweeps, 23:10 the Mix mark): v314 lij_core::bip86 (BIP86 addresses, vectors); v315 lij_core::musig (the MuSig2 signer, musig2 0.4.1 vendored — not exported); v316 a BIP86 coin signs on the key path (held out of the automatic pick for DP's postmix rule); v317 THE WALK FINDS TAPROOT COINS AND THEIR SPENDS — both BIP86 branches in the net at a fifth of its width, tier2::tr_hits names a BIP86 script in a matched block's filter, a TrHint per (script, block), resolve_tr_spends re-reads the hinted block when the coin is met (a key-path witness names no key: before this a spent taproot coin read unspent after a words-only restore), the widen rule per branch; v318 the Black start kit's taproot leg (one pre-signed sweep per BIP86 coin to its own m/84 address; merged and trimmed with the silent-payment leg; the fingerprint counts them) and CoinMarks::mix_exits (DP: Mix exits on the main branch, marked; the marks ride the backup blob)
    // "phase11-v313".to_string()  // v313 (S57, DP 2026-10-07 17:55 on the recovery recheck item 1: "it's not just fewer channels, it is where anything is different. Let's not wear blinders. Write it well and thoughtfully — Go"): THE BLACK START KIT ACROSS COPIES — kit_merge (docs/design/black-start/kit-merge-r1.md): black_start_merge_plan_json / black_start_bundle_merged_json open the held kits with the kit key and merge them with this copy's kit entry by entry (carry a channel only a held kit has while its funding or delayed output is unspent; keep a held entry whose commitment number is higher than this copy's; unite silent-payment coins while unspent; seq = max(now, held + 1)); every kit entry carries its commitment_number; the patched LDK reader lij_commitment_obscure_factor
    // "phase11-v312".to_string()  // v312 (S57, DP 2026-10-07 17:55, ruling (a): "If a new LSP arrives to the marketplace and that LSP requires ANCHORS, it knows upfront, the user is aware, and JIT channels fail in plain sight"): the wallet refuses an inbound open whose channel type is not static remote key without anchors (node::channel_type_words_recoverable); the last refusal is readable (anchors_refused_json) so the page says why
    // "phase11-v311".to_string()  // v311 (S57, DP 2026-10-07 16:03 "Agreed", the recovery recheck item 4): the closed-channel log rides every backup (cloud copy and device file) — node::BUNDLE_SINGLE_KEYS gains closed_channel_log::KEY_CLOSED_CHANNELS. A restore while a cooperative close was still unconfirmed lost the coop hold, so LDK could broadcast its commitment over the cooperative close (the 2026-09-03 incident); the closed history and the saved cooperative-close transaction were lost too. Older copies without the key still load. Test v311_the_closed_channel_log_rides_every_backup.
    // "phase11-v310".to_string()  // v310 (S57, DP 2026-10-07 15:10 "Go with all other proposals (1, 3, etc.)"): cloud_backup_meta() — the cloud copy's number and date only (worker 0.9.0 POST /backup/meta, the same signed "backup-read" challenge), so the page can compare the cloud's number with this phone's before its first connection to the provider (Proposal 1) without pulling the whole sealed copy (~1.4 MB) at every unlock; storage::KvBackupClient::meta + parse_backup_meta (a worker without the route answers 404 = an error, never "no copy"); wallet::cloud_backup_meta. Tests v310_* ×2.
    // "phase11-v309".to_string()  // v309 (S56, DP 2026-10-06 17:47 "Go" on the cloud-copy guard — after the SA tester's channels vanished on a file load): THE CLOUD COPY IS GUARDED. (1) A copy's number is committed on the phone only once the cloud ACCEPTED it (or a device file was written with it) — storage::backup_version_peek / _commit; until now every snapshot wrote the next number first and a refused upload was retried 30 s later with the next one, so a phone that had loaded an older backup file counted past the cloud's number in about an hour and replaced newer channel state with older. (2) A refusal ("Stale backup rejected: existing vN") is read for the cloud's number (parse_stale_refusal), kept in BACKUP_CONFLICT, and STOPS the uploads until the person decides: backup_conflict() for the page, backup_replace_cloud() to take the cloud's number and upload this phone's state on purpose. (3) The cloud copy can be taken BEFORE any wallet is built — adopt_cloud_backup(words, cfg): pull + inject, the errors kinded NO_COPY / FETCH / CORRUPT — the restore screen's Continue and "Use the cloud copy" run it at the passphrase, like a device file (v952). (4) cloud_backup_info() — what the cloud holds for the running wallet (channels, number, date), nothing written; backup_probe adds saved_at_ms. (5) StateBlob carries saved_at_ms, plain — the date a warning shows for a file and for the cloud copy. (6) The cloud copy is marked out of date only when the channel manager's bytes CHANGED (cm_bytes_changed) — the 10-second save had marked it every time, so a full copy went up every 30 s the wallet was open. Tests v309_the_number_is_only_peeked_until_the_cloud_accepts_it, v309_a_refusal_names_the_clouds_number_and_nothing_else_does, v309_an_older_copy_without_a_date_still_opens_and_a_new_one_carries_its_date, v309_the_cloud_copy_is_marked_out_of_date_only_when_the_manager_changed (337 green).
    // "phase11-v308".to_string()  // v308 (S54, DP 2026-10-03 23:44 "This transaction did not have any change, but I did not use MAX … What happened with that first one? Can you track it from the code?" — 2026-10-04 00:03 "Go."): the send was right; the quote was not. With no coins chosen, coin_quote's fee_sats is what EVERY coin would need (650 at 2 sat/vB on DP's wallet) and Review showed it, while the send paid the picked coin's fee (282); and a leftover under 294 sats goes to the fee in silence (1fffda67…: 1,501 − 1,002 − 282 = 217 → fee 499, no change). Now one rule for what is left (onchain_send::settle_change) is shared by the builder and the quote; coin_quote reports send_fee_sats (exactly what the send pays, any leftover included) and folded_sats; change_sats is the change output itself (0 when folded); multi_quote reports folded_sats. fee_sats keeps its meaning. Tests v308_the_quote_shows_the_fee_the_send_pays_and_the_leftover_it_adds (DP's two sends replayed), v308_the_several_recipients_quote_names_the_leftover_too, v308_settle_change_is_one_rule.
    // "phase11-v307".to_string()  // v307 (S54, DP 2026-10-03 23:07 "What happens if someone sends a second subsequent payment to the address that was derived from a Silent Payment? Will it be seen?" — 23:09 "Yes, go ahead. Good coverage."): it was not — BIP-352's sum over a new transaction's inputs never gives that address again, and the scan watched the UNSPENT coins' scripts only, for their spends. Now the scan watches the script of every silent-payment coin it has found, spent or not (sp_scan::known_coin_scripts): an output paying one is a coin, spent with the same key (its stored tweak); the mempool leg checks the same keys (SpPending.reused); derive_history marks the line `reused` (a coin with the same tweak and label as an earlier one). Test v307_a_second_payment_to_a_found_silent_payment_address_is_found_even_after_the_first_was_spent.
    // "phase11-v306".to_string()  // v306 (S54, DP 2026-10-03 13:59 "Agreed" + 15:30 "It is a go to implement fully" — THE PAYMENT LINES: send = one line per transaction; receive = one line per address (or silent-payment label) per transaction; tap = the parts): the history keeps ONE row per transaction and a received row (Received, Onchain) carries `lines` — one per own address (chain, index) or sp1 label, each with its parts (vout, sats) in output order (tier2_wallet::recv_lines in derive_history); the sync names each ordinary line's address from the wallet's own scripts (name_line_addresses). A send to several keeps every recipient AS TYPED by txid (CoinMarks.send_dests — the marks ride the backup blob; the fee bump carries them to the replacement); tx_details answers "recipients" [{dest, value, sp}] (the record, else the pending send's dests). Tests v306_*.
    // "phase11-v305".to_string()  // v305 (S54, DP 2026-10-02 13:50 "Go ahead" — SEVERAL RECIPIENTS IN ONE SEND): one builder for every on-chain send (onchain_send::build_send_tx — plan_send → the outputs → the one signer; build_and_send / _all / _pinned are its one-recipient case, unchanged in what they do): up to 20 recipients (MAX_RECIPIENTS), each an address or an sp1 with an amount, or — the LAST only — no amount = everything left after the others and the fee (DP's Max rule); the recipients in order at vout 0 …, the change after them; DP's coin pick for the total (+ the fee for n + 1 outputs) or exactly the chosen coins; a recipient below the 294-sat output minimum refused when there are several. Silent payments: silent_payment::derive_output_scripts — one group per scan key, k = 0, 1 … in recipient order (two payments to one wallet, or to two of its labels, are two outputs it finds with one scan); the input arithmetic once. PendingTx.dests (every recipient, in order) → the RBF bump rebuilds every output from the same inputs (same k, same scripts); change at vout n. wasm: send_onchain_multi(req), onchain_multi_quote(req) (the builder's own plan: the amounts — the Max on the last —, the fee, the change, the coins, or the refusal in plain words). Gate: the BIP's SENDING vectors with several recipients (same recipient twice, several wallets, a plain + a labelled address, the change label) + v305_* (exact amounts and change last, the silent payment found by its receiver, k0/k1 to one wallet, Max on the last with no change and with chosen coins, the refusals, one recipient unchanged, the bump's re-derivation). 325 green.
    // "phase11-v304".to_string()  // v304 (S54, DP 2026-10-02 13:50 "Go ahead" — SILENT-PAYMENT LABELS): a label m (1..=10, SP_LABEL_MAX) is the BIP-352 labelled address B_m = B_spend + hash("BIP0352/Label", b_scan ‖ m)·G with the same scan key (SpKeys::label_tweak / label_address; m = 0, the change label, is never handed out). The scan checks the change label, every label made or found, and — after a restore from the words with no backup behind it (wallet.rs sets CoinMarks.sp_labels_unknown) — all ten: one more candidate per tweak per label at the filter stage. A coin found under a label carries it (OnchainUtxo.sp_label; its stored t already includes the label, so the spend, the RBF bump and the Black start kit sweep are unchanged); the derived history row lists the labels paid (sp_labels); a number found with no entry is kept nameless ("Label m"). The names, hidden flags and the unknown flag live in the marks record (sealed, rides the backup blob and survives a rescan); the Black start kit carries number + name (silent_payment_labels). FIXED: the change label was added to the even-y point of x(P_k) — wrong for half of all tweaks; a label is now added to the full point (the BIP's "label with odd parity"). wasm: sp_labels(), sp_label_create(name), sp_label_update({m,name?,hidden?}). Gate: the BIP's RECEIVING vectors (testdata/bip352_receive_vectors.json, 28 cases bar K_max: labels even/odd parity, a large label number, several outputs to a labelled address, the change label) + v304_* tests.
    // "phase11-v303".to_string()  // v303 (S54, DP 2026-10-02 10:11 "Fix all of these … Go."): bolt11_facts(bolt11) — a BOLT11 invoice's payee (the n field, else recovered from the signature), amount, payment hash, network and expiry, signature-checked by lightning-invoice (lij_core::invoice_facts); the page checks the chit's funding invoice with it before paying (amount = the chit's, payee = the provider). A free function: no wallet state, no lock. Tests v303_reads_payee_amount_hash_and_expiry, v303_amountless_and_refusals.
    // "phase11-v302".to_string()  // v302 (S54, DP 2026-10-01 22:34 "wire it in so it is robust and any fail has fallbacks" + 22:47 "Correct and agreed" to the "Only my server" switch): THE ADDRESS WATCHER IS WIRED. Until v302 the row saved a server the receive watch never read (since v118, 2026-06-13). watch_address_inbound(address, own_base, own_only) → IndependentClient::fetch_address_utxos_watch_via: the user's own Esplora first (cleaned by the filter-base rule: https, a host, optional port and path); if it does not answer (refusal, 404, unreadable, unreachable) the same check asks the public explorers in turn, and the own server rests 60 s (OWN_WATCH_REST_MS) so a dead server cannot cost every check its timeout; an answer ends the rest; a newly saved server is asked at once. own_only = no fallback (the check is an error, no explorer asked). A 404 is now "did not answer" everywhere in the watch (Blockstream and btcscan.org answer an unused address 200 [] — read 2026-10-01; the project's block-filter server answers the path 404 because it has no address route, and the old rule read that as "nothing paid"). watch_report() = how the last check went (answered_by own|public|"", own_error, own_resting); check_watch_server(base) = the row's Save check (/blocks/tip/height is a height, /address/<a never-funded probe>/utxo answers a list). Old pages call with one argument → no own server, as before. Tests v302_* (10).
    // "phase11-v301".to_string()  // v301 (S53, DP 2026-10-01 21:54 "go for 1-4"): the receive watch's address check (watch_address_inbound) asks ONE explorer per check, in turn, moving to the next only when one refuses or cannot be reached, and never touches an explorer's standing — a refused address check is most often "too many requests", not a wrong answer; trust stays with the tip-height rounds. Before: all four explorers on every check, every refusal counted towards demotion — ten watched addresses every 3 s talked the quorum down to one source and greyed the on-chain face's Send / Receive. fetch_address_utxos (all four, counted) unchanged. Tests: v301_watch_asks_one_explorer_and_takes_turns, v301_watch_refusal_moves_on_and_demotes_no_one, v301_watch_all_refuse_is_an_error_and_still_no_demotion.
    // "phase11-v300".to_string()  // v300 (S52, DP 00:23 "not a hard cap, unless it is super high and never will be hit unless there is something malicious" + 00:25 "if a wallet approaches 1000 transactions, some notification … delete old data or expand the size"): the kept transactions are stored COMPACTLY — the transaction without its signatures (the witness; the txid does not cover it, the check holds) plus its full weight (the fee rate stays exact), binary (LTX2), ~0.12 KB for an ordinary transaction (v298/v299: ~0.6 KB as hex in JSON; their store is read and rewritten). v299's 96 KB budget is gone: the ceiling is 1,000 transactions by default (~125 KB, ~0.5 MB of the browser's 5 MB on Safari) — a normal wallet never reaches it, spam could — with 256 KB per 1,000 as the size backstop and 16 KB per transaction. The user's ceiling (CoinMarks.tx_keep_cap; steps 1,000 / 2,000 / 4,000; rides the backup) and the page's notice at 90 %: tx_keep_status (count, cap, near, bytes, oldest_height, steps), tx_keep_set_cap, tx_keep_drop_before (the ledger untouched). drill_tx takes the kept weight. Tests: kept_compactly_checked_by_txid_weight_exact_heights_filled, v300_a_normal_wallet_never_reaches_the_ceiling_spam_does, v300_the_wallet_is_told_near_the_ceiling_and_can_expand_or_drop_old, v300_the_v298_json_store_is_read_and_kept_compactly. 296 green.
    // "phase11-v299".to_string()  // v299 (S52, DP 2026-10-01 00:21 "make sure the additional block data kept doesn't fill up the memory space"): the kept-transaction store (tier2_txs) is held to TX_STORE_BUDGET_BYTES = 96 KB of JSON (~190 K characters in localStorage — hex of the encrypted bytes — about 160 ordinary transactions); v298 capped only the count (5,000 ≈ 3 MB of JSON ≈ 6 M characters, past the 5 MB a site gets on Safari, beside the channel state). A transaction larger than TX_MAX_HEX (4 KB) is not kept; past the budget the lowest heights go first, never the entries being added; a write that fails deletes the store outright. Whatever is dropped reads its block again when tapped. Tests v299_the_store_never_grows_past_its_budget, v299_a_write_that_fails_removes_the_store. 294 green.
    // "phase11-v298".to_string()  // v298 (S52, DP 23:43 "Go on #2 and #3" — THE DRILL-DOWN FROM THE WALLET'S OWN DATA; THE sp1 OF A SEND): lij_core::tx_store — every own transaction (it creates a coin of ours, spends one, or is a spend the newest-first walk met first) is kept whole from the block the walk or the scan already downloads (capture_own_txs in fetch_and_apply and scan_batch; Tier2View.fresh_txs, never persisted with the view — save_view hands them to the store under tier2_txs, encrypted at rest; 5,000 kept, lowest heights dropped first); a send is kept at broadcast (SendResult.raw_hex, never sent to the page; the bump too). tx_details(txid, filter_base) asks NO explorer (until v298 every tap sent the txid to four): the kept transaction (checked against its txid), else for a ledger row from before v298 its block read once more from the wallet's block-filter server (reread_own_tx: the header's work checked, the block bound to it, every own transaction in it kept), else a pending transaction's bytes or a pending send's record; a transaction the ledger does not hold is looked up nowhere. drill_tx builds the details from the bytes and the ledger (an input's value from the ledger coin or the kept parent; someone else's input → no fee). #3: CoinMarks.sp_sends (txid → the sp1 a send was typed to; the marks ride the backup blob) → tx_details.sp_address. Tests: kept_whole_checked_by_txid_heights_filled_capped, v298_capture_keeps_only_the_wallets_own_transactions, v298_the_drill_down_reads_the_wallets_own_data. 292 green.
    // "phase11-v297".to_string()  // v297 (S52, found while wiring v296 — THREE REPAIRS TO THE SILENT-PAYMENT SCAN, each shown failing on the v296 bytes): (1) the scan opens ONCE (sp.from == 0): a server that answered 404 for a while (an index away, or another provider's server) re-opened a walked view's scan at the walk's top, so every block between where it stood and that top was never read; (2) a ledger rebuild (a new schema, a widened net) cleared every coin, the silent-payment coins too, and the scan kept its place, so they were never read again — rebuild_from_birthday now sends the scan back to its own start; (3) scan_batch tested every filter of a batch against the coins held at the batch's start: a coin paid and spent inside one batch of a catch-up (restore, rescan, resume) kept showing as unspent — now block by block, in order, a coin found joins the scripts from the next block on (and a coin paid and spent inside one block is read). Tests v297_a_scan_paused_by_a_server_without_the_index_resumes_where_it_was, v297_a_ledger_rebuild_reads_the_silent_payments_again, v297_a_coin_paid_and_spent_inside_one_batch_is_seen_spent. 289 green.
    // "phase11-v296".to_string()  // v296 (S52, DP 23:09 "#1: Go. Now, here" — EACH LIJOX PROVIDER MAY RUN ITS OWN BLOCK-FILTER SERVER): tier2_onchain_sync(birthday, filter_base, sp_base) — the walk reads the server the page passes (its own provider's when the directory lists one), the silent-payment scan reads sp_base (none = the walk's); a missing or unclean address = the project's server (tier2_sync::DEFAULT_FILTER_BASE, clean_filter_base: https, a host and an optional :port and path, 200 characters at most); until v296 one constant served every wallet. The summary names the servers read (filter_server, sp_server); the tape notes a change once; "block-filter server unreachable" names the host. Test filter_base_is_passed_in_or_the_default.
    // "phase11-v295".to_string()  // v295 (S52, DP 22:21 "All yes for 1-4" — the CHAIN tile stayed blocks behind after the iPhone woke): the provider's chain stream is asked again (1) on every (re)connect, never throttled, and a request that cannot be sent yet is kept (v249 dropped it under the 60-tick throttle); (2) when the app is in front again (note_foreground → a lock-free flag the tick takes) or after a 2-minute tick gap; (3) a check with no chain message within 5 s on a connection that still looks up drops the connection at once (at most once a minute) — the monitor reconnects and the reconnect re-subscribes — instead of waiting 10-20 s for LDK's keep-alive to notice; (4) the independent tip above the stream's for a minute → a check. node.rs background_tick (the stream block), StreamWatch, stream_behind_due; tests stream_watch_tests.
    // "phase11-v294".to_string()  // v294 (S52, DP 21:49 — "a silent-payment receive's ADDRESS in the drill-down says reading… and never fills"): tx_details counted as ours only the scripts of the m/84 net, so a silent-payment coin (m/352, a one-time taproot output) was nobody's — its receive had no address of record, and a send FROM it read as a receive with our change as the address. Now ours = the net's scripts OR an outpoint the wallet's own ledger holds as a coin (spent or not, the scan's unconfirmed ones too); inputs carry the outpoint they spend (Esplora's vin txid/vout). lij_core::tier2_wallet::tx_ownership; test drill_down_ownership_knows_silent_payment_coins.
    // "phase11-v293".to_string()  // v293 (S51, DP 22:57 "Go with O1" — THE SCAN YIELDS BY TIME): the silent-payment scan hands the screen back whenever 40 ms of work has passed (tier2_sync::YIELD_BUDGET_MS, checked before every block and between groups of 32 tweaks) instead of every 8 blocks; same work, same order, same results — the iPhone X readout showed every stall (longest 6.4 s) inside tier2_onchain_sync's scan runs. Test: candidate_scripts_in_groups_equal_the_whole.
    // "phase11-v292".to_string()  // v292 (S51, DP 16:43 "Go, run the gate and the cut" — THE 64-BIT MULTIPLY PATH): no Rust change; lij/.cargo/config.toml now hands the wasm32 C build USE_FORCE_WIDEMUL_INT64, so libsecp256k1 (pristine in vendor/) uses its 10x26 field / 8x32 scalar with native i64 products instead of the 5x52 / 4x64 path whose 128-bit products WebAssembly has to emulate through __multi3. Same results (gated: six builds, one identical output over every operation the wallet uses + BIP-340 vector 0); every curve operation ~2x faster in the browser — the silent-payment scan, the address walk's derivations, signing, ECDH, the kit. Reversible by deleting the [env] line.
    // "phase11-v291".to_string()  // v291 (S50, DP 23:04 "Go on Black start v291 engine" — THE BLACK START KIT'S SILENT-PAYMENT SWEEPS): for every unspent silent-payment coin the kit carries ONE pre-signed transaction moving that coin alone (never combined — DP) to a fresh m/84 receive address of the wallet's own (one address per coin: the kit's destination index + 1 + i, on the chain any BIP-84 wallet derives from the 12 words), at the kit's two rates (10 and 40 sat/vB; a coin too small for a rate gets nothing at that rate), signed by the one signer every spend shares (Schnorr on the taproot key-path), RBF-signalled so the high variant can replace the normal one, valid the moment it is broadcast; the kit's `silent_payments` list (+ a note when the ledger could not be read — the channels' half always exports); the push fingerprint includes the unspent silent-payment outpoints, so a coin arriving or leaving makes a push due (`silent_payments` count on the fingerprint). Test: two coins → two sweeps to consecutive fresh addresses, the small one normal-rate only, the Schnorr signature verifies, the high variant a replacement, spent and m/84 coins excluded. 281 green.
    // "phase11-v290".to_string()  // v290 (S50, DP's Nostur field test 21:52 — "NWC request from Nostur refused: this wallet speaks NIP-44 v2 only"): NIP-04 beside NIP-44. Nostur (and most NWC apps today) encrypt requests with the older scheme — AES-256-CBC under the raw ECDH x, base64 with "?iv=" — which v286 refused. Now the content's shape decides (a "?iv=" payload is NIP-04; a tag that names another scheme is refused as UNSUPPORTED_ENCRYPTION naming both), the request is decrypted either way, `Opened.encryption` says which, and the reply goes back in kind (a NIP-04 reply carries no encryption tag, per NIP-47); the info event lists "nip44_v2 nip04". AES-CBC rides the vendored `aes` (aes-gcm's) — no new crate; gated by the NIST SP 800-38A CBC-AES256 vector, a round trip, a wrong-key refusal, and an end-to-end NIP-04 request/reply. The wasm nwc_reply takes `encryption`. Also carries v289 (the row marker), which CI never shipped — its build's flip collided with v288's. 280 green.
    // "phase11-v289".to_string()  // v289 (S50, the SP receive page cut's one engine need): a derived ONCHAIN RECENT row carries `silent_payment_sats` — the sats that transaction paid to the wallet's sp1 address (its chain-352 coins), 0 on an ordinary row — so the face says "silent payment" on the row itself, spent or not, without matching coins. Test: the scan's found coin derives a row with 184,000 of 184,000. 279 green.
    // "phase11-v288".to_string()  // v288 (S50, DP 2026-09-28 21:10 on v287's words — "the wallet has a say", and "is it sweeping or scanning"): (1) the wallet-side SILENT-PAYMENT SWITCH — CoinMarks::sp_enabled (on by default; kept in the marks store, its own encrypted key, so a sync in flight cannot clobber it and a rescan keeps it), sp_set_enabled(bool) on the wasm surface, the sync still asks the provider what it offers but scans nothing while off, the summary's sp block carries `enabled`; (2) the words — the box builds the INDEX, the wallet's engine on the phone runs the SCAN (it reads hints and filters and checks; it never moves a coin — "sweep" stays the Black start kit's word): sp_scan::scan / scan_batch, SpScan.scanned_to / scanned_hash / scanned_filter_header (serde aliases read v287's swept_* names), the summary's `scanned_to`, every log line and note. 279 green.
    // "phase11-v287".to_string()  // v287 (S50, DP 2026-09-28 "When will receive silent payments be operational?" — SILENT PAYMENTS: RECEIVE, the walk; DP's five decisions 17:22): lij-core::sp_scan — the provider is asked once per sync whether it serves a tweak index (/sp/info, spcommit-v1; 404 = none, the wallet does nothing; "SP is an option for LSPs"); the sweep runs UPWARD from its start to the walk's top: the box's per-block tweaks × the wallet's scan key give the taproot scripts each could have paid, tested — with the scripts of the SP coins already held, so their spends are seen — against the same BIP158 filters the m/84 walk reads; a matching block is fetched hash-bound and merkle-checked, its coins land as chain 352 with their t_k, spends of known coins are marked by outpoint; every batch's headers are PoW-checked and linked to the previous batch and, at the top, to the walk's known block hash and filter header (one continuous chain); every served block's commitment is recomputed from its tweaks and a mismatch refuses the box (decision 2: one box = single_source); the start (decision 1): a fresh view sweeps from the later of the index start and the birthday, a wallet walked before v287 from today's top; the mempool leg once the sweep stands at the top (unconfirmed silent payments pending, dropped when they leave the pool, replaced by the coin when their block lands); a reorg rollback rolls the sweep back with the walk; 100 blocks per sync call (200 once the walk is done), the view saved after every batch so a closed app resumes; the summary carries `sp` (available, index_start, indexed_to, from, swept_to, top, done, waiting_for_index, single_source, pending, pending_sats, coins, note). No down-walk re-check is needed in this shape (decision 3's cost is nil; decision 4's is the sweep itself). Tests: a real silent payment mined into a PoW-valid block found through the filter, its spend seen in the next block, the mempool leg, a tampered commitment refused, a provider without the index, the rollback. 279 green. Page cut next (the sp1 address on Receive, the Privacy row, the bar's wording).
    // "phase11-v286".to_string()  // v286 (S50, DP 17:50 "start on NWC … separate and isolated work" — NWC CUT N1, THE ENGINE; nothing on the page yet): lij-core::nwc — NIP-44 v2 (ChaCha20 written out per RFC 8439 and gated by its vectors — no new crate; HMAC-SHA256 under HKDF; the padding; base64) gated by the official NIP-44 vectors (35 conversation keys, 32 message-key sets, 24 padded lengths, 10 encrypt/decrypt cases, 3 long messages, 24 must-fail cases); Nostr events (NIP-01 id, BIP-340 sign/verify); the connections — one per Nostr app, the service secret kept (lij_nwc, encrypted at rest with the coin ledger and riding the state blob so a restore on the same LSP keeps them), the client's public key only, the connection string handed out once; DP's limits (5,000 sats per payment, 20,000 per rolling day across every connection, 90-day expiry, 10-min request age; 10 connections) and the paid list; the duplicate check (same payee within 10 min, strongest with the amount); open_request (kind, author, `p`, signature, ±10-min skew, expiration tag, NIP-44 only → decrypt → pay_invoice checked against the invoice's network, expiry and amount and the limits — every refusal with its NIP-47 code; get_info passed through), the replies (23195), the info event (13194: pay_invoice, nip44_v2) and NIP-42 AUTH (22242). Wasm: nwc_list / nwc_add / nwc_end / nwc_forget / nwc_set_limits / nwc_open / nwc_reply / nwc_info_event / nwc_auth_event / nwc_record_paid. 273 tests green.
    // "phase11-v285".to_string()  // v285 (S50, DP 2026-09-28 17:22 "5. This cut" — CHANNEL OPENS FROM SILENT-PAYMENT COINS): a chain-352 coin with its t_k is a funding candidate like an m/84 coin (spendable_utxos / build_funding_tx_with / Max / the estimate / chosen coins); the funding transaction signs through the one signer every spend shares (onchain_send::sign_inputs — Schnorr on the taproot key-path sighash for the SP coin, BIP143 ECDSA for m/84; channel_open's own P2WPKH loop retired); the fee counts each input at its real size (58 vB taproot, 68 P2WPKH) in the estimate, the Max and the transaction; the AUTOMATIC pick tries the silent-payment coins alone first by DP's rule (his SP design ruling: "SP coins are prioritized as inputs to self-funded channel opens") and falls back to the rule over every coin when they cannot cover; chosen coins are exactly the chosen set as before. Tests: an open that takes the 50k SP coin over the larger 60k m/84 coin and whose Schnorr signature verifies; the fallback to the m/84 coin; a chosen mixed pair signed both ways; Max at real sizes. 266 green. No page change.
    // "phase11-v284".to_string()  // v284 (S50, SILENT PAYMENTS — RECEIVE, the engine groundwork; held until DP's decisions): the wallet's own SP keys (SpKeys: scan m/352'/{coin}'/0'/1'/0, spend /0'/0 — Cake's and Sparrow's paths; sp_address(); the change label; the receiver arithmetic — candidate scripts for a block's tweaks, find_in_block for k = 0, 1, 2 …, script_for / spend_secret from a stored t_k); chain 352 (CHAIN_SP) coins on the ledger carry their t_k (OnchainUtxo.sp_tweak) and the summary tags them silent_payment; a chain-352 coin SPENDS: gathered like any other, counted at its real 58-vB taproot size in every quote and the send itself, its key b_spend + t_k (negated for an odd P_k), signed Schnorr on the taproot key-path sighash (SIGHASH_DEFAULT, Prevouts::All) by the one signer every path now shares (a plain send, all-out, chosen coins, and the RBF bump); a spend FROM an SP coin to an SP address counts it as a taproot input in the BIP-352 sender arithmetic. Tests: the mixed-input signing (Schnorr + ECDSA both verified), the gather with a tweak, the sizes. No page change; the receive walk (tweaks → filter → block), the two-box commitment check and the down-walk rule come after the talk.
    // "phase11-v283".to_string()  // v283 (S50, coin control, cut 3b — the dust warning's numbers): onchain_quote also answers what the send WOULD spend for an amount (the chosen set, or the automatic pick) and the change it would leave — tiny_change when that change is a coin (≥ the 294-sat dust floor) worth less than max(1,000 sats, five times one input's cost at this rate); the page warns before the confirm (DP 2026-09-28: "dust as an output should have a warning before proceeding").
    // "phase11-v282".to_string()  // v282 (S50, coin control, cut 3 — CHOSEN COINS): a send from exactly the coins the user chose (send_onchain_with: an amount with change, or all in one output; a frozen, unknown or short set is refused in plain words, nothing spent); the picker's quote (onchain_quote: chosen / needed / covered / short, and "Fill the rest for me" by DP's rule over the coins not chosen); a channel open from exactly the chosen coins (open_lsp_channel_with parks them under the open's nonce; FundingGenerationReady takes them by that nonce → build_funding_tx_with) and its estimate (lsp_channel_open_estimate_with). DP 2026-09-28: chosen = exact; the top-up is the user's tap, never silent.
    // "phase11-v281".to_string()  // v281 (S50, DP GO 2026-09-28 15:29 — COIN CONTROL, cut 1, the engine): the marks store (tier2_marks — frozen + note per coin, keyed by outpoint, its own encrypted key beside the view so a walk in flight cannot clobber it; packed in the backup blob; never rebuilt — a rescan keeps freezes, Erase wipes them); coin_mark(json); summary rows are CoinRow (tag received/change/channel_return/legacy + frozen + note) with frozen_sats / sendable_sats / frozen_count beside the unchanged spendable_sats; DP's pick rule in coin_select (the smallest single coin that covers amount + fee, else largest first) for plain sends AND self-funded opens, frozen coins never candidates; onchain_max (the exact one-output Max from the builder's own arithmetic; frozen figures) and send_onchain_all (everything sendable, one output, no change) — the page's Max moves onto them in cut 2.
    // "phase11-v280".to_string()  // v280 (S49, DP GO 2026-09-25 00:53 — PUSH KEY, step A, the engine): push module (the link fragment v1.<amount>.<expiry>.<lsp16>.<key b64url>, the pair check, the two records); RootKey::push_preimage (HKDF, own salt — derived, never stored); push_prepare (the pair at the next index, the record, the fragment), push_lock (pay the provider's hold invoice for the hash on the internal self-hop and RETURN once the HTLC is out — no 30-s wait; the record turns locked with its payment_id), push_mark (void), push_out_json (LDK's word folded in: taken / returned), push_out_preimage (Copy link re-derives), push_accept (a link's key against its hash, the hash registered inbound for the window, the key into the LNURLp pool so the one claim path claims the delivery), push_in_json; PaymentSent/PaymentFailed latch a push's fate; the three keys ride in the state blob. DP rulings: 72 h, recipient gets the exact amount (the sender's lock carries the delivery fee), void by node-key signature (adapter step).
    // "phase11-v279".to_string()  // v279 (S49, 2026-09-23 22:54 — the six refused address invoices, 0x400f from the UM890): the LSP route's LAST hop always carries the invoice's final CLTV delta — the one-hop case (the LSP is the destination's direct peer, e.g. an LSP-2 wallet paying an @address held at LSP-1) used to take the first-hop rule and lock the LSP's forwarding delta (80) where the hold invoice asked 144. parse_lnd_route_response; a native test.
    // "phase11-v278".to_string()  // v278 (S48, DP 2026-09-23 00:20 — the 724-sat gap): the owned-at-close backfill reads "we funded" from the scanner's history too and redoes v277 backfills once (owned_backfill_ver); the event's figure is never redone. v277 (S48, DP 2026-09-22 23:37): the cancelled-open sweep's honest proof (history + a definitive quorum 404 + a persisted two-hour floor); ClosedChannelRecord.our_owned_msat_at_close from Event::ChannelClosed (+ the watcher's backfill from the closing tx); IndependentClient::tx_known. Was: v276 (S48, Black Start): black_start_fingerprint_json — SHA-256 of the sorted latest holder commitment txids (a read-only monitor accessor, no signing) so the page pushes a kit only when a channel's state moved
    // "phase11-v275".to_string()  // v275 (S48, DP GO 2026-09-22 18:15, BLACK START BS1): black_start module — the kit key (HKDF of the master key), the NIP-06 identity, the sealed envelope (AES-256-GCM, AAD-bound to the npub), the ECDSA holder body, the BIP-340 NIP-78 relay event; black_start_identity_json + black_start_bundle_json exports (read-only, from escape_export)
    // "phase11-v274".to_string()  // v274 (S48, DP GO 2026-09-22 14:58, the Sendable book): per channel inflight_out_msat + pending_out (hash, msat); sent_parts_json — the channel(s) each settled send left by (PaymentPathSuccessful); the closed-channel record keeps our_reserve_sats; owned_msat's doc corrected (an outbound HTLC in flight is still inside it)
    // "phase11-v273".to_string()  // v273 (S48, DP GO 2026-09-22 14:22, items 2 + 4): a claimed receive is recorded in msat with the counterparty skim and the HTLCs' channels (claimed_payments_json: msat, skim_msat, parts) — the page's ledger records the exact amount; sats stays
    // "phase11-v272".to_string()  // v272 (S48, DP GO 22:10, symmetric with v271): the scanner also keeps the node's record of CLOSING txids (closed-channel log + live sightings, noted at every sync, never cleared by a rebuild) and walks with log ∪ record — the log does not ride the cloud copy, so a reloaded phone's later rebuild would have tagged its opens but not its closes.
    // "phase11-v271".to_string()  // v271 (S48, DP GO 2026-09-21, running totals — "no patchwork"): the scanner keeps the node's record of funding txids (closed-channel log + live channels, noted at every sync, never cleared by a rebuild) and derives any net-outgoing funding tx as ChannelOpen under any walk — the S46 rebuild had dropped those tags, so pre-rebuild self-funded opens read as plain sends and the Lightning book lost its "+moved to Lightning" rows. Retroactive at the next sync.
    // "phase11-v270".to_string()  // v270 (S48, DP GO 2026-09-21, running totals): a send result carries fee_msat — LDK's fee_paid_msat, exact — beside the floored fee_sats, so the Lightning book keeps whole-msat rows and foots against owned_msat to the sat.
    // "phase11-v269".to_string()  // v269 (S48, DP GO 2026-09-21, running totals): every channel now reports owned_msat — LDK's exact value_to_self_msat (our side before the commitment fee, anchors and reserve are carved out; HTLCs in flight excluded), carried out through the vendored ChannelDetails (lij_value_to_self_msat), get_channels and the dump (with is_outbound). The Lightning running-total book foots against Σ owned_msat; the old outbound+reserve gross undercounted a channel we funded by the fee buffer. Read-only.
    // "phase11-v268".to_string()  // v268 (S48, DP): the words screen asks the cloud copy service BEFORE anything is written (backup_probe: found + channel count / none / no answer), and a device backup file can be loaded with the words alone (import_backup_file: no node, no network) so a phone with no connection can still reach its offline room and escape kit.
    // v267 (S47, DP GO): a self-funded open whose funding tx cannot be built is closed at once (force_close_without_broadcasting_txn on the temp channel; no funds moved, no close record) instead of dangling until LDK's unfunded timeout — and the failure (temp id, value, reason, time) is kept for the page (open_failures_json), so the retry loop stops and the "moving to Lightning" marks clear.
    // v266 (S47, DP: quorum stuck at 0/4 after a long phone sleep until a restart): a demoted independent endpoint was never asked again (rounds asked healthy endpoints only), so once all four were demoted nothing could reinstate one. Rounds now also ask demoted endpoints 60 s after their last failure, and all of them when none is healthy; broadcasts use the same list.
    // v265 (S47, DP GO): identify_own_output (the recover-close watch) searches the walk's 2,500-address net first, then the old window above the frontier; each outcome is one [recover-watch] line on the tape (not at the sources yet / our output #n, sats, chain, index / no output pays this wallet).
    // v264 (S47, DP's #20 run — the tape read "timeout after 5s" on every 501-filter batch; one batch = 18.8 MB): the walk's requests get their own 60 s limit (the 5 s stays for the independent height checks); 100 blocks per request, 5 per call; a call that fails part-way still returns the summary (balance + rows read so far) with `sync_error`; the walk's errors say "block-filter server:" instead of "LSP error:".
    // v263 (S47, DP field: on-chain sends failed "tier2 view parse" on both phones; the channel sheet said "Could not load balance"): v256 encrypted the on-chain view but four readers stayed on plain storage — send_onchain, bump_onchain_send, lsp_channel_open_estimate and the funding build (FundingGenerationReady). All four now read through tier2_wallet::encrypted (one key list).
    // v262 (DP's second dots read): the 7,500-key net is derived in slices with yields — the one-time 1–2 s boot freeze (the waiting dots standing still) is gone.
    // v261 (DP: the on-chain drill-down): tx_details(txid) — fee (sats, sat/vB), our inputs/outputs, the address of record, the output type, mempool or block + header time (recorded into the ledger so the face's row gains its clock).
    // v260 (DP's frozen-dots read): the walk yields to the browser between every 16 filters — a 500-filter batch against the 7,500-key net was seconds of unbroken CPU on the main thread, freezing every timer on the page (the balance's waiting dots since v256). Same work, the phone breathes.
    // v259 (DP: clock time under each on-chain amount): the walk records every fetched block's header time; derived rows carry `time` (unix seconds) so the face can show the clock without another read.
    // v258 (S46, DP's iOS read): the page's birthday is the ceiling on the ledger's birthday — a stored one above it (v744's first-channel bound) is lowered and the downward walk resumes; that bound hid 51,067 sats on the iOS below block 965,586.
    // v257 (S46, DP GO — the new process): ONE walk, newest-first, from the tip down to the birthday (a spend seen before its coin is held by the spender's own witness pubkey and lands when the coin appears; new blocks read forward at the top; reorg-checked every call); every sync call writes a note (ok or the failure reason) to the tape and the ledger for the face; rescan = an explicit rebuild from the tip down to the chosen year; the head/historic walk and its merge are gone.
    // v256 (S46, DP GO — ONE LEDGER): the on-chain ledger is rebuilt once from the birthday under a fixed 2,500-address net per branch (widened and rewalked when a coin sits within 100 of the edge); rows derived from the coins only (the old row list retired; kind tags in a txid map); rows ordered by height then txid; the ledger and the pending list encrypted at rest under the wallet's persistence key; a daily re-walk of the newest 144 blocks re-confirms spends by block filters (no coin or address ever queried); invariants checked on every summary.
    // v255 (S46, DP: "it doesn't make sense that the balance can be right but the rows wrong"): ONCHAIN RECENT rows are DERIVED from the output set the balance is summed from (every held or spent output yields its row; spent_txid recorded from now on; the persisted list supplies only kind tags and pre-v255 spends) — the two cannot disagree again, and a view damaged by v251's merge shows its rows without a rescan.
    // v254 (S46, DP's field read): the head/historic merge rolls the head range back (outputs, spend marks, rows) and replays it in height order — v251's merge dropped the head range's history rows while keeping its outputs (balance right, ONCHAIN RECENT missing the close return). A Rescan from Transaction tools regenerates a view damaged by v251–v253.
    // v253 (S46, DP's field read): the v252 widen-and-rewalk edge sat at the frontier, so every completed walk reset to 0 and walked again (the start-stop DP saw, and the rows it never reached); now the trigger is a used index in the window's last ten slots, once per frontier value. The summary carries the walk's shape (birthday, head_active, head_start, head_scanned_to) so the face can say which phase it is in and when it is done.
    // v252 (S46): identify_own_output(txid) — the wallet finds its own output in a transaction (a 200-wide window over its chains), so a recover-close return can be watched in the mempool by address without knowing the pin index.
    // v251 (S46, DP GO, the #20 run): the on-chain walk (1) keeps a used-index frontier that counts SPENT outputs — the unspent-only frontier left a restored wallet scanning 0..50 while its activity sat past 50 (DP's "large gap" vs BlueWallet); (2) scans the newest 1,500 blocks FIRST after a restore and merges with the historic walk (replaying the head's blocks so spends resolve); (3) walks at most 8 batches per call so the face can say "block X of Y"; (4) a fresh restore uses a 4× discovery window and rewalks wider if a used index reaches the window's edge.
    // v250 (S46, DP GO): forget_cloud_backup() — the wallet deletes its own cloud copy at the worker (POST /backup/forget, the same signed challenge as push/read); local state untouched. For the Privacy switch (Off = delete, "off means off") and the Erase gate's "delete the cloud copy too".
    // v249 (S46, DP GO — the stale-tip cause + the double connect): (1) the wallet re-subscribes to the LSP's chain stream on every LSP (re)connect and after 20 min of silence while connected — the LSP forgets a subscriber whose sends failed while the phone slept, and nothing here ever subscribed again (mark_disconnected was dead code), so the Android sat six blocks behind while open; (2) ONE SOCKET PER PEER — connect_to_peer refuses a second socket while one is handshaking or an LDK peer is up (the boot double-connect), and the read_event error path closes without freeing its own closure (the boot throw); (3) internal sends raise the self-hop CLTV by the lag between LND's height (adapter 0.76.1's /v1/outcome) and this wallet's tip.
    // v248 (S46, DP): quote_route_fee answers 0 for an INTERNAL destination (invoice minted on the active LSP's node — the static-address rail) — the same v222 test the send uses; the quote had applied the first-hop policy (~0.1%) to a payment the self-hop delivers for nothing.
    // v247 (S46): invoices carry a 144-block final CLTV — LDK 0.2.6 will not accept less than 42 and the 24 carried from 0.0.123 made every v241–v246 invoice unpayable by LND/WoS/the chit rail (LiJ senders use 144 regardless and hid it).
    // v246 (S46): the hold verdict is logged whatever it says (the tape carried nothing for a live answer); adapter 0.75.1 answers with two fresh liveness signals.
    // v245 (S46): the hold-verdict GET carries the route token (v244 sent it bare → Unauthorized → the old 30-s path; DP's curl receipt).
    // v244 (S46, DP GO): hold verdict for INTERNAL (LNURL pool-hash) sends — one GET to the LSP's /v1/outcome before the self-hop; owner offline → the page narrates HELD from the first second instead of a 30-s wait booked "failed". Adapter 0.75.0 answers owner_live + hold_cap_s.
    // v243 (S46, 2026-09-12): close-kind classification — HolderForceClosed is a struct variant since LDK 0.1; the bare-name pattern was a catch-all binding, so v241/v242 filed EVERY closure (cooperative ones included) as Force in CHANNELS. `{ .. }` restores the match. Records already written as Force by v241/v242 are re-labelled at the next boot (see fix_close_kind_v243).
    // v242 (S46, 2026-09-12): the wasm32 CLOCK SHIMS re-ported — v241 shipped without them; LDK 0.2.6's first SystemTime::now() in the tick panicked ("time not implemented on this platform"), the engine's lock stayed held, every later call failed (desktop F12 receipt). Every wall-clock read in the lightning crate now goes through util::time::lij_now / lij_since_epoch (browser clock on wasm32), and util::time::Instant is a browser-clock Instant on wasm32.
    // v241 (S46, DP GO 2026-09-12): LDK 0.0.123 → 0.2.6, bitcoin 0.30 → 0.32, toolchain stable 1.90.0, size-first release profile (7.9 MB). All ten LiJ hunks re-ported + force_close_without_broadcasting_txn re-exposed (lij_no_broadcast). Monitor keys, the pinned m/84 payment point and the old remote-key derivation preserved; inbound splices rejected (docs/ldk-0.2-splice-readiness.md). ONE-WAY: state written by v241 is unreadable by v240 and earlier.
    // v240 (S45, DP: #14): BIP-352 silent payments, SEND side — an sp1q… destination in send_onchain (and its RBF bump) pays a one-time taproot output derived from the selected inputs (lij_core::silent_payment; gated by the BIP's own vectors natively). Receiving not yet.
    // v239 (S45): ChannelInfo.spendable_msat — the spendable lens in millisats for the exact Max. // v238 (S45, DP "truly 0"): send_payment_with_retries takes an exact millisat override for a no-amount invoice (single path; MPP parts stay whole sats) via prepare_lsp_route_request_msat. // v237 (S45, DP): quote_route_fee_to_pubkey — a route quote to a node key with no invoice, so Max can price an LNURL address served by another LSP before any invoice is minted. // v236 (S45, DP): CPFP is a user dial — automatic mode default OFF (set_coop_cpfp_auto), manual Speed up via coop_cpfp(channel_id, send) with a plan mode that shows the fee before the tap; the shared coop_cpfp() applies the automatic gates for the hold loop. // v235 (S45, DP GO): CPFP for a slow cooperative close — after 3 blocks pending, when the sweep rate is well above what the coop tx pays, the wallet spends the coop tx's output to itself with a child that lifts the package (one attempt per 6 blocks; records carry cpfp_txid_hex / cpfp_last_height). // v234 (S45): the watcher also recognises our commitment by shape for records that predate v233 (a cooperative record whose confirmed spend is not its intended tx and pays none of our addresses). // v233 (S45, DP GO): cooperative-close hold — LDK's startup rule (monitor without a manager channel → broadcast the holder commitment) held for cooperative closes this wallet signed that are still pending; rebroadcast; 144-block ceiling; records carry the coop tx + holder commitment txid; the watcher keeps polling until a spend CONFIRMS (intended → actual), relabels a lost race as Force, follows the sweep. // v232 (S43, DP GO): a ProcessingError closure is filed as CloseKind::Force — LDK force-closes on it — so the page's close-inbound bridge shows the returning sats in the mempool as for every other force-close (0a80ac8d had shown nothing until the closing tx confirmed). Prior — v231 (S43, DP GO after the 0a80ac8d force-close was read from the tape): background_tick now hands LDK the LSP\u2019s tip BEFORE the confirmations, holds any confirmation from a block above the accepted tip in the bridge until the tip reaches it, and persists on the tip advance (manager_dirty) — the stored best block can no longer sit one below a funding block, the state that made a later boot\u2019s replay of an older funding block force-close a ready channel. Prior — v230 (S43, DP field 2026-09-02 — "Add to Lightning" at Max twice, the second while the first funding tx sat in the mempool): channel_open::spendable_utxos now excludes outpoints reserved by a pending open/send, exactly as build_funding_tx has since v191, so spendable_total and max_channel_value (the sheet's Available and Max) drop to what is truly fundable the moment a tx is broadcast. Prior — v229 (S43, DP GO — the robust static-address design, replacing the v228 patch): (1) LNURLp preimages are DERIVED from the master key by index (RootKey::lnurlp_preimage, HKDF-SHA256, own salt) — nothing to back up, a wallet restored from its words recomputes every preimage; the local pool is a cache, and a claim that misses the cache searches derived indices (8192+) before failing back. (2) Each hash is registered in this engine for 30 YEARS (was 30 days — the cliff that killed every static address older than a month) and the same `expires` rides to the LSP in the registration JSON so the two sides can never disagree; `index` rides too, and the page passes the LSP's next_index back as a start hint so a restored wallet continues the sequence. Pairs with adapter 0.67.0 (honors expires, cancels the held original on a definitive refusal, reads LND for in-flight truth). Prior — v228 (S43, DP field 2026-09-02 — a same-LSP send to a wallet restored on a new iPhone hung twice, "payment failed"; the UM890 journal showed the LSP's 4 s belt bumping its own in-flight HTLCs): ROOT — the LNURLp preimage pool (lij_lnurlp_preimages, random per device, v195) was never in the backup bundle, so a restore on another device carried the channels and the registered hashes but not the preimages; every payment to the static address then arrived as a PaymentClaimable the wallet could not claim, and it hung until LDK's own expiry. FIX (1) the pool rides in the bundle (gather_state_blob; restores through the generic inject path). FIX (2) a readable pool that lacks the hash fails the HTLC back at once (fail_htlc_backwards after the closure) so the sender learns in a second; an unreadable pool keeps holding and looks again. Not caused by S43's speed work — the same hang existed on any version. Prior — v227 (S43, DP GO — same-LSP speed, engine half, under "extra careful nothing breaks at all"): (i) an internal send (dest == the active LSP) skips the route ask — the v222 self-hop never read the answer and adapter 0.62.1 answered a fixed empty body, which the engine now hands over verbatim; external destinations fetch exactly as before. (ii) a dispatched HTLC (every send_payment_with_route Ok arm: internal, external, MPP) is written to the wire immediately (pump_outbound = the tick's own pm.process_events) instead of waiting for the next tick. (iii) the ChannelManager event pass is extracted VERBATIM from background_tick into process_channel_events and ALSO run on the turn after inbound bytes (never inside the socket callback; try_lock, tick catches up otherwise) — a receiver claims when its HTLC lands, a sender learns "paid" when the fulfill arrives; events seen there flag manager_dirty so the next tick persists as before. Prior — v226 (S43, DP agreed — speed item 0, the cold-open first send): the boot's independent quorum round asked the four chain endpoints ONE AFTER ANOTHER with NO enforced timeout, and the Ready rule waited for the whole round, so the first send after a cold open failed "prepare" and retried on Ready ~2 s later (DP + Dan, 2026-09-01). Now: the four are asked concurrently (independent.rs query_all_each, FuturesUnordered), every WASM GET races a real 5 s timeout (REQUEST_TIMEOUT_SECS finally enforced), and the FIRST endpoint to answer reports early (SingleSource when nothing better stands, consensus height if empty, cold-start marked queried via a hook node.rs installs) so Ready lands on the first source that agrees with the LSP feed — the v225 floor — instead of after the slowest endpoint. Page v655 pairs (Ready retry poll 2 s → 0.5 s). Prior — v225 (S42, DP RULED — the v476 floor lands in the ENGINE): the send/Ready rule required 2 healthy independent chain sources; a phone at 1/4 (VPN, field 2026-09-01) could never reach Ready and every send sat at "finishing its chain check". Now ONE healthy source whose height agrees with the LSP's feed is enough for Ready (two agreeing sources); zero stays ReadOnly/dark. New QuorumState::SingleSource; the page keeps the on-chain face at 2-of-4. // v224 (S41, tester-zero DP): SELECTION LADDER — boot NEVER re-decides a provider (old auto_select re-ranked every boot; two tying providers broke on registry order and flipped funded wallets unpressed). Choice persisted by switch_lsp (full snapshot, registry-outage-proof) > channel counterparty > LiJ-Node default for fresh wallets > top viable listing only when the default is absent; LOYALTY OVER AVAILABILITY (a chosen/channeled provider down = no provider this session, never a substitute); connect failures no longer fail wallet BOOT; list_lsps stickiness armed (was comparing the wallet's own pubkey — never fired once). Prior — v223 (S39): escape-kit truth fields (per-monitor open + claimable_sats \u2014 the kit stops quoting dead commitments); archiver ungated from reconcile_done + resolved monitors leave the spend walk; dest_is_lsp on send silence events (0.57.0 item h). Prior \u2014 v222 internal LNURLp single-hop: dest==LSP ⇒ the prepend IS the route; LND's out-and-back same-channel answer to a self-dest+public-hints query is never parsed (DP field 5/5 cured). Prior — v221 device-file import (import_backup_blob → LijWallet::import_state_blob via node accessors — the cloud-restore inject path made public). Prior — v220 RECOVERY ARC: D3 blob carries on-chain view/pendings/counters (instant blob restores); tier2_rescan_from for imported foreign seeds (SegWit-activation floor 481,824 — wpkh cannot predate it, so 2009-era picks are honored, empty years skipped, failure impossible). Prior: v219 socket-id realm fix.
}

// ── Seed vault (passphrase-wrapped mnemonic) ─────────────────────────────────
//
// Wrap/unwrap the BIP39 mnemonic under a user-chosen passphrase. The passphrase
// is a local convenience lock — it does NOT modify the mnemonic or derived keys
// (see seed_vault module docs). Argon2id cost runs ~400 ms in browser; calls
// block the JS thread for that duration.


/// Wrap `mnemonic` under `passphrase`. Returns a hex-encoded blob suitable for
// ── Phase B (S32): OFFLINE START — engine-side courtesy flag. When set
// before construction: the Step-8a esplora swap is skipped (the stub
// stays — zero chain queries) and the backup client is hard-silenced at
// BOTH entries. Keys, derivation, and persisted state remain fully live.
pub static OFFLINE_START: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// v346 (S59 Thu, DP 2026-10-15 17:13 — "% loaded for the Black start"): the restore's progress, for the page. Each step
/// of a restore from saved state (lij_core::progress: "channels" per monitor, "manager", "ready", with the bytes of saved
/// state read so far and in all) calls `window._lijRestoreProgress(stage, done, total)` when the page defines it, then
/// waits one timer tick so the page can paint — the restore runs on the page's own thread and would otherwise show
/// nothing until the end. No function on the page: the steps cost a timer tick each and nothing else.
struct PageProgress;
impl lij_core::progress::RestoreProgress for PageProgress {
    fn report(&self, stage: &str, done: u64, total: u64) {
        let g = js_sys::global();
        if let Ok(f) = js_sys::Reflect::get(&g, &JsValue::from_str("_lijRestoreProgress")) {
            if let Some(f) = wasm_bindgen::JsCast::dyn_ref::<js_sys::Function>(&f) {
                let _ = f.call3(&JsValue::NULL, &JsValue::from_str(stage), &JsValue::from_f64(done as f64), &JsValue::from_f64(total as f64));
            }
        }
    }
    fn pause(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>> {
        Box::pin(async {
            let p = js_sys::Promise::new(&mut |res, _rej| {
                let fired = match web_sys::window() { Some(w) => w.set_timeout_with_callback_and_timeout_and_arguments_0(&res, 0).is_ok(), None => false };
                if !fired { let _ = res.call0(&JsValue::NULL); }
            });
            let _ = wasm_bindgen_futures::JsFuture::from(p).await;
        })
    }
}
fn arm_restore_progress() { lij_core::progress::set_sink(Some(std::rc::Rc::new(PageProgress))); }
#[wasm_bindgen]
pub fn set_offline_start(v: bool) {
    OFFLINE_START.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// v322 (S58, DP 2026-10-12 20:18 — the CHAIN dot): open the WebSocket to the provider at `wss_url` now, while the
/// start-up checks run; nothing is sent on it until connect_to_peer adopts it. Best-effort: an error is only logged by
/// the page, which then connects as before.
#[wasm_bindgen]
pub fn ws_preopen(wss_url: &str) -> Result<(), JsValue> {
    ws_transport::preopen(wss_url)
}

/// v322: close the pre-opened socket (the start-up checks stopped the start).
#[wasm_bindgen]
pub fn ws_preopen_drop() {
    ws_transport::drop_preopen();
}

/// v303 (S54, DP): what a BOLT11 invoice says, read and signature-checked — {"payee","amount_msat"|null,"payment_hash",
/// "network","expires_at"}; an error names why it does not decode. The page checks an invoice with it before paying.
#[wasm_bindgen]
pub fn bolt11_facts(bolt11: &str) -> Result<String, JsValue> {
    let f = lij_core::invoice_facts::invoice_facts(bolt11).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&f).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// v208: broadcast routing — true routes each tx to one endpoint at a time
/// (rotating, stop at first acceptance); false fans to all healthy endpoints.
#[wasm_bindgen]
pub fn set_broadcast_one(v: bool) {
    lij_core::independent::BROADCAST_ONE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// v209: standalone cloud-backup gate (DP privacy pane). true silences the
/// backup client at every entry — nothing leaves the device — independent of
/// offline_start. Mirrors the OFFLINE_START pattern.
pub static BACKUP_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// v309 (S56): the cloud's number when it refused this phone's copy as older (0 = no refusal). While set, the
/// automatic uploads stop; the page shows it and the person decides (adopt the cloud copy, or replace it).
pub static BACKUP_CONFLICT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// v309: one sink's answer read for a refusal — the cloud's number kept, the uploads stopped. true = refused as older.
fn note_push_refusal(err: &str) -> bool {
    match lij_core::storage::parse_stale_refusal(err) {
        Some(n) => { BACKUP_CONFLICT.store(n, std::sync::atomic::Ordering::Relaxed); true }
        None => false,
    }
}
/// v319 (S57, DP 2026-10-08 14:40 "Go"): before a copy goes up, its number and fingerprint are noted on the phone — if
/// the OK never comes back (the app put away mid-upload), the next open can tell the cloud's copy is this phone's own.
fn note_inflight(blob: &lij_core::storage::StateBlob) {
    let fp = lij_core::storage::backup_fingerprint(blob);
    if let Err(e) = lij_core::storage::backup_inflight_note(&LocalStorage, blob.version, &fp) {
        log::warn!("[v319] in-flight note not written: {e}");
    }
}
/// v302 (S54): the last receive-watch check's report (watch_report) — kept outside the wallet lock.
static WATCH_REPORT: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
/// v256 (S46, DP: "Encrypt it"): the tier-2 ledger and the pending list live encrypted
/// at rest under the wallet's persistence key — the same key the channel blobs use.
fn t2_storage(root_key: &lij_core::key::RootKey) -> Arc<dyn lij_core::storage::LijStorage> {
    Arc::new(lij_core::tier2_wallet::encrypted(LocalStorage, root_key.encryption_key()))   // v263: one key list, shared with node.rs
}

thread_local! {
    /// Step 8 (S58): the attempts running on this page, by the provider's attempt id — memory only (their secret numbers
    /// are never written: §9 rule 1); a reload ends them (§8 rule 0: never resume).
    static MIX_PHONES: std::cell::RefCell<std::collections::HashMap<String, lij_core::tatara::phone::Phone>> = std::cell::RefCell::new(std::collections::HashMap::new());
    /// Phase 1b (step 11b): the pool channel of each running attempt — the node's nonce (LijNode::pool_channels).
    static MIX_POOL_CHANNELS: std::cell::RefCell<std::collections::HashMap<String, u32>> = std::cell::RefCell::new(std::collections::HashMap::new());
    /// v336 (Phase 2a): public joins waiting for their credentials, by attempt id; the phone replaces the join once
    /// the credentials come (then it lives in MIX_PHONES).
    static MIX_JOINS: std::cell::RefCell<std::collections::HashMap<String, lij_core::tatara::phone::PublicJoin>> = std::cell::RefCell::new(std::collections::HashMap::new());
    /// v340 (S59 security review, finding 6): the seat each live attempt or join belongs to — one seat runs ONE attempt
    /// at a time (a provider pool and a public room for the same coin can never both be signed).
    static MIX_SEAT_OF: std::cell::RefCell<std::collections::HashMap<String, String>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// v340: refuse a second live attempt for a seat; remember this one.
fn mix_seat_claim(attempt_id: &str, seat_pk: &str) -> Result<(), JsValue> {
    MIX_SEAT_OF.with(|m| {
        let mut m = m.borrow_mut();
        if m.iter().any(|(a, s)| s == seat_pk && a != attempt_id) {
            return Err(JsValue::from_str("this seat is already in a pool on this page"));
        }
        m.insert(attempt_id.to_string(), seat_pk.to_string());
        Ok(())
    })
}

/// v340: a pool id this phone already holds a record for is refused (finding 3).
fn mix_refuse_known_pool(storage: &dyn lij_core::storage::LijStorage, pool_id: &str) -> Result<(), JsValue> {
    if lij_core::tatara::store::record_exists(storage, pool_id).map_err(|e| JsValue::from_str(&e.to_string()))? {
        return Err(JsValue::from_str("a pool with this id is already on this phone's record — refused"));
    }
    Ok(())
}

/// Step 8: the sealed store.
fn mix_storage(inner: &Arc<std::sync::Mutex<LijWallet>>) -> Result<Arc<dyn lij_core::storage::LijStorage>, JsValue> {
    let (root_key, _independent, _network) = {
        let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.onchain_handles()
    };
    Ok(t2_storage(&root_key))
}

/// Step 8: the root key, the sealed store and the backup's dirty flag.
fn mix_handles(inner: &Arc<std::sync::Mutex<LijWallet>>) -> Result<(Arc<lij_core::key::RootKey>, Arc<dyn lij_core::storage::LijStorage>, Arc<std::sync::atomic::AtomicBool>), JsValue> {
    let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
    let (root_key, _independent, _network) = wallet.onchain_handles();
    let storage = t2_storage(&root_key);
    Ok((root_key, storage, wallet.node().backup_dirty_handle()))
}

/// v333: the speed-up quote with the chain servers asked about each transaction of the chain (tx_known, then fetch_tx
/// for its block) — and a speed-up already confirming for this payout answered as a problem.
async fn mix_bump_quote_inner(storage: &dyn lij_core::storage::LijStorage, independent: Arc<lij_core::independent::IndependentClient>, id: &str, target_sat_vb: u64) -> Result<lij_core::tatara::bump::BumpQuote, JsValue> {
    let rec = lij_core::tatara::records::load(storage).map_err(|e| JsValue::from_str(&e.to_string()))?
        .into_iter().find(|r| r.id == id).ok_or_else(|| JsValue::from_str("no such pool"))?;
    // what the servers say about each transaction of the chain up to this phone's exit
    let mut seen: std::collections::HashMap<String, Option<bool>> = std::collections::HashMap::new();
    let ids: Vec<String> = {
        let mut v = vec![rec.funding().map_err(|e| JsValue::from_str(&e.to_string()))?.compute_txid().to_string()];
        let (mine, _) = rec.my_exit().map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mine = mine.compute_txid().to_string();
        for e in rec.exits().map_err(|e| JsValue::from_str(&e.to_string()))? { let t = e.compute_txid().to_string(); v.push(t.clone()); if t == mine { break; } }
        v
    };
    for t in &ids {
        let known = independent.tx_known(t).await;
        let c = match known {
            Some(true) => match independent.fetch_tx(t).await { Ok(x) => Some(x.confirmed), Err(_) => None },
            Some(false) => Some(false),
            None => None,
        };
        seen.insert(t.clone(), c);
    }
    let mut q = lij_core::tatara::bump::bump_quote(&rec, &|t: &str| seen.get(t).copied().flatten(), target_sat_vb).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if q.problem.is_none() {
        if seen.get(&ids[0]).copied().flatten().is_none() && independent.tx_known(&ids[0]).await == Some(false) {
            q.problem = Some("The pool's funding is not on the network, so a speed-up cannot help. If it never arrives, you can pull your coin back.".into());
        } else {
            let pending = lij_core::tier2_wallet::load_pending(storage);
            if let Some(p) = pending.iter().find(|p| p.kind == lij_core::tier2_wallet::TxKind::MixSpeedUp && p.spent_outpoints.iter().any(|(t, v)| t.eq_ignore_ascii_case(&q.exit_txid) && *v == q.exit_vout)) {
                q.problem = Some(format!("A speed-up is already on its way ({}).", &p.txid[..12]));
            }
        }
    }
    Ok(q)
}

fn mix_now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Step 8: one step of a running attempt, then its saves (store::after — the record written before the signature); the
/// backup marked dirty when a record was written or wiped. Phase 1b (step 11b): the pool channel's side of the step —
/// the exit the machine named is handed to LDK as the channel's funding (fund_channel; a refusal stops the attempt),
/// and a stop before this phone's coin signature drops the half-open channel (§6.2.4).
fn mix_step<E: std::fmt::Display>(attempt_id: &str, storage: &dyn lij_core::storage::LijStorage, dirty: &std::sync::atomic::AtomicBool, inner: &Arc<std::sync::Mutex<LijWallet>>,
    f: impl FnOnce(&mut lij_core::tatara::phone::Phone, u64) -> Result<lij_core::tatara::phone::Out, E>) -> Result<String, JsValue> {
    let now = mix_now();
    MIX_PHONES.with(|m| {
        let mut m = m.borrow_mut();
        let p = m.get_mut(attempt_id).ok_or_else(|| JsValue::from_str("no such attempt on this page"))?;
        let mut out = f(p, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let nonce = MIX_POOL_CHANNELS.with(|c| c.borrow().get(attempt_id).copied());
        if let (Some((txid, vout)), Some(n)) = (out.fund_channel.clone(), nonce) {
            let r = inner.lock().map_err(|e| format!("Lock error: {e}")).and_then(|w| w.node().fund_pool_channel(n, &txid, vout).map_err(|e| e.to_string()));
            if let Err(e) = r {
                log::warn!("[mix] the pool's exit could not fund the channel: {e}");
                let o2 = p.channel_failed(&format!("the exit could not fund it: {e}"), now).map_err(|e| JsValue::from_str(&e.to_string()))?;
                out.merge(o2);
            }
        }
        if let (Some(st), Some(n)) = (out.stopped.as_ref(), nonce) {
            if st.channel_opened && !p.signed() {
                match inner.lock().map_err(|e| format!("Lock error: {e}")).and_then(|w| w.node().drop_pool_channel(n, "the pool stopped before this phone signed").map_err(|e| e.to_string())) {
                    Ok(dropped) => log::info!("[mix] the attempt stopped: its channel {}", if dropped { "dropped" } else { "was already gone" }),
                    Err(e) => log::warn!("[mix] the attempt stopped, but its channel could not be dropped: {e}"),
                }
                MIX_POOL_CHANNELS.with(|c| { c.borrow_mut().remove(attempt_id); });
            }
        }
        let (out, d) = lij_core::tatara::store::after(storage, p, out, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if d { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
        serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
    })
}

thread_local! {
    /// v323 (Mix step 7): when this page last sent each funded pool's exits (ms) — again at most every 10 minutes.
    static MIX_LAST_SEND: std::cell::RefCell<std::collections::HashMap<String, f64>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

thread_local! {
    /// v296: the block-filter servers the last sync read — a change is written to the tape once, not every 15 s.
    static T2_SERVERS: std::cell::RefCell<(String, String)> = std::cell::RefCell::new((String::new(), String::new()));
}
/// v296: write the servers to the tape when they change (the first sync of a page load included).
fn t2_note_servers(base: &str, sp_base: &str) {
    T2_SERVERS.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != base || c.1 != sp_base {
            let def = lij_core::tier2_sync::DEFAULT_FILTER_BASE;
            log::info!("[tier2] v296 block-filter server: {base}{} · silent-payment index: {sp_base}{}",
                if base == def { " (the default)" } else { "" }, if sp_base == def { " (the default)" } else { "" });
            *c = (base.to_string(), sp_base.to_string());
        }
    });
}

/// v298 (S52, DP #2 and #3): a send this wallet has just broadcast — its raw bytes into the tx store (the drill-down
/// reads them while it is unconfirmed and after), and, when it was typed to an sp1 address, that address into the
/// marks by txid (the chain shows only the one-time taproot output the sp1 address made).
fn t2_note_send(storage: &dyn lij_core::storage::LijStorage, txid: &str, raw_hex: &str, dest: Option<&str>, dests: &[(String, u64)]) {
    if dests.len() > 1 {   // v306: a send to several — every recipient as typed, for the drill-down after the block
        let mut m = lij_core::tier2_wallet::load_marks(storage).unwrap_or_default();
        m.send_dests.insert(txid.to_string(), dests.to_vec());
        if let Err(e) = lij_core::tier2_wallet::save_marks(storage, &m) { log::warn!("[tier2] v306 recipients record ({txid}): {e}"); }
    }
    if !raw_hex.is_empty() {
        if let Err(e) = lij_core::tx_store::put(storage, &[(txid.to_string(), 0, raw_hex.to_string())]) {
            log::warn!("[tier2] v298 tx store (send {txid}): {e}");
        }
    }
    if let Some(d) = dest.map(|d| d.trim()) {
        let low = d.to_ascii_lowercase();
        if low.starts_with("sp1") || low.starts_with("tsp1") {
            let mut m = lij_core::tier2_wallet::load_marks(storage).unwrap_or_default();
            m.sp_sends.insert(txid.to_string(), d.to_string());
            if let Err(e) = lij_core::tier2_wallet::save_marks(storage, &m) { log::warn!("[tier2] v298 sp1 record ({txid}): {e}"); }
        }
    }
}

thread_local! {
    /// v256: the derived script net (2,500 per branch = 7,500 keys) is built once per net
    /// width per page, not on every 15-second sync.
    static T2_SCRIPTS: std::cell::RefCell<Option<(u32, Arc<lij_core::tier2::WalletScripts>)>> = std::cell::RefCell::new(None);
}
async fn t2_scripts(root_key: &lij_core::key::RootKey, network: bitcoin::Network, width: u32) -> Result<Arc<lij_core::tier2::WalletScripts>, JsValue> {
    if let Some(hit) = T2_SCRIPTS.with(|c| c.borrow().as_ref().filter(|(w, _)| *w == width).map(|(_, s)| s.clone())) {
        return Ok(hit);
    }
    // v262: derived in slices with yields — the one-time 1–2 s freeze at boot is gone
    let built = Arc::new(
        lij_core::tier2::WalletScripts::build_fixed_async(root_key, network, width)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
    );
    T2_SCRIPTS.with(|c| *c.borrow_mut() = Some((width, built.clone())));
    Ok(built)
}

#[wasm_bindgen]
pub fn set_backup_off(v: bool) {
    BACKUP_OFF.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// localStorage. Throws on empty mnemonic or Argon2 failure.
#[wasm_bindgen]
pub fn wrap_mnemonic(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    let blob = lij_core::seed_vault::wrap(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(blob))
}

/// Unwrap a hex-encoded blob produced by [`wrap_mnemonic`]. Returns the
/// mnemonic string. Throws on bad hex, short blob, wrong passphrase,
/// tampered data, or version mismatch — error messages disambiguate.
#[wasm_bindgen]
pub fn unwrap_mnemonic(blob_hex: &str, passphrase: &str) -> Result<String, JsValue> {
    let blob = hex::decode(blob_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))?;
    lij_core::seed_vault::unwrap(&blob, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}



/// Suggest BIP39 English words matching a prefix. Returns up to `max` matches,
/// lexicographically sorted (the wordlist is pre-sorted). Case-insensitive.
/// Returns empty vec for empty prefix or no matches.
#[wasm_bindgen]
pub fn bip39_suggest(prefix: &str, max: usize) -> Vec<JsValue> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let needle = prefix.to_lowercase();
    let words = bip39::Language::English.word_list();
    words.iter()
        .filter(|w| w.starts_with(&needle))
        .take(max)
        .map(|w| JsValue::from_str(w))
        .collect()
}



/// Validate a full BIP39 mnemonic string (word validity + checksum).
/// Accepts 12, 15, 18, 21, or 24-word phrases. Returns Ok on valid, Err with
/// descriptive message on invalid word, wrong count, or checksum mismatch.
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> Result<(), JsValue> {
    let trimmed = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse_normalized(&trimmed)
        .map(|_| ())
        .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Given 11 valid BIP39 words and 7 binary bits ("0"s and "1"s), compute the
/// 12th (checksum) word that completes a valid mnemonic.
///
/// BIP39 encodes a 12-word mnemonic as 128 bits entropy + 4-bit checksum,
/// packed as 12 × 11-bit word indices. The 12th word's 11 bits are
/// [7 user bits] || [4 checksum bits], where the checksum is the first 4
/// bits of SHA256(entropy).
///
/// This exposes the "secret binary path" for seed reset: a user who types
/// 7 bits into the 12th field gets the deterministic checksum word back.
#[wasm_bindgen]
pub fn checksum_word_for_bits(
    first_eleven: Vec<JsValue>,
    seven_bits: &str,
) -> Result<String, JsValue> {
    use sha2::{Digest, Sha256};

    // Validate input shape
    if first_eleven.len() != 11 {
        return Err(JsValue::from_str(&format!(
            "expected 11 words, got {}", first_eleven.len()
        )));
    }
    if seven_bits.len() != 7 {
        return Err(JsValue::from_str(&format!(
            "expected 7 bits, got {} characters", seven_bits.len()
        )));
    }
    if !seven_bits.chars().all(|c| c == '0' || c == '1') {
        return Err(JsValue::from_str("bits must be 0 or 1"));
    }

    let wordlist = bip39::Language::English.word_list();

    // Extract each word's index (0..2048) from the wordlist
    let mut indices: Vec<u16> = Vec::with_capacity(11);
    for (i, v) in first_eleven.iter().enumerate() {
        let word = v.as_string()
            .ok_or_else(|| JsValue::from_str(&format!("word {} not a string", i + 1)))?;
        let idx = wordlist.iter().position(|w| *w == word.as_str())
            .ok_or_else(|| JsValue::from_str(&format!(
                "word {} (\"{}\") is not in BIP39 English wordlist", i + 1, word
            )))?;
        indices.push(idx as u16);
    }

    // Build the 121 bits of word indices, then append 7 user bits → 128 bits entropy.
    // Pack indices MSB-first, 11 bits each.
    let mut bits: Vec<u8> = Vec::with_capacity(128);
    for idx in &indices {
        for shift in (0..11).rev() {
            bits.push(((idx >> shift) & 1) as u8);
        }
    }
    for c in seven_bits.chars() {
        bits.push(if c == '1' { 1 } else { 0 });
    }
    // We now have exactly 128 bits = 16 bytes of entropy
    debug_assert_eq!(bits.len(), 128);
    let mut entropy = [0u8; 16];
    for (i, bit) in bits.iter().enumerate() {
        entropy[i / 8] |= bit << (7 - (i % 8));
    }

    // Checksum = first 4 bits of SHA256(entropy)
    let mut hasher = Sha256::new();
    hasher.update(&entropy);
    let hash = hasher.finalize();
    let checksum_nibble = (hash[0] >> 4) & 0x0F;

    // 12th-word index = (7 user bits << 4) | 4 checksum bits
    let mut user_bits_val: u16 = 0;
    for c in seven_bits.chars() {
        user_bits_val = (user_bits_val << 1) | (if c == '1' { 1 } else { 0 });
    }
    let word_idx = (user_bits_val << 4) | checksum_nibble as u16;

    Ok(wordlist[word_idx as usize].to_string())
}



/// Derive the authoritative Lightning node pubkey from a BIP39 mnemonic.
/// Mirrors what LijNode does in ~3ms instead of ~3s — skips LDK setup,
/// LSP registry fetch, chain monitor init. Used for seed-verification in
/// the forgot-passphrase reset flow.
#[wasm_bindgen]
pub fn pubkey_from_mnemonic(mnemonic: &str, network: &str) -> Result<String, JsValue> {
    use lij_core::key::RootKey;
    use lightning::sign::{KeysManager, NodeSigner, Recipient};

    let mnemonic_parsed: bip39::Mnemonic = mnemonic.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {e}")))?;

    let btc_network = match network {
        "bitcoin" => bitcoin::Network::Bitcoin,
        "testnet" => bitcoin::Network::Testnet,
        "signet"  => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(JsValue::from_str(&format!("Unknown network: {network}"))),
    };

    let root_key = RootKey::from_mnemonic(&mnemonic_parsed, btc_network)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {e}")))?;

    let seed = root_key.lightning_node_key()
        .map_err(|e| JsValue::from_str(&format!("Lightning key derivation failed: {e}")))?
        .private_key.secret_bytes();

    // Timestamps don't affect node_id (KeysManager derives it from seed alone),
    // but the API requires them. Use a fixed value for determinism.
    let keys_manager = KeysManager::new(&seed, 0, 0, false /* 0.2: old remote-key derivation — LiJ pins to_remote itself */);

    let node_id = keys_manager.get_node_id(Recipient::Node)
        .map_err(|_| JsValue::from_str("Failed to get node pubkey"))?;

    Ok(hex::encode(node_id.serialize()))
}

// ── LSPS2 client (Phase B — v0.16 adapter compatible) ──────────────────────

/// Fetch LSPS2 service terms from an LSP endpoint.
///
/// JS receives the parsed [Lsps2GetInfoResponse] as a JSON string.
/// Errors (HTTP failure, parse failure) are thrown as JS exceptions.
///
/// # Example (JS)
/// ```javascript
/// const json = await window.lij_wasm.lsps2_get_info(
///   "https://lijox-lsp.lightning-mod.com",
///   route_macaroon_from_registry,
/// );
/// const info = JSON.parse(json);
/// console.log(info.human_summary);
/// ```
#[wasm_bindgen]
pub fn lsps2_get_info(endpoint: &str, route_macaroon: &str) -> js_sys::Promise {
    let endpoint = endpoint.to_string();
    let route_macaroon = route_macaroon.to_string();
    future_to_promise(async move {
        let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &route_macaroon)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let json = serde_json::to_string(&info)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsValue::from_str(&json))
    })
}

/// Buy an LSPS2 JIT channel promise for inbound `payment_size_msat`.
///
/// JS receives the parsed [Lsps2BuyResponse] as a JSON string. The
/// returned `jit_channel_scid` must be embedded as a route_hint in the
/// BOLT11 invoice the wallet generates for the upcoming receive (Phase C).
/// Promise expires after `promise_expires_at` ms — wallet must call again
/// if expired.
///
/// # Example (JS)
/// ```javascript
/// const json = await window.lij_wasm.lsps2_buy_promise(
///   endpoint, route_macaroon, BigInt(50_000_000)
/// );
/// const promise = JSON.parse(json);
/// embedRouteHint(promise.jit_channel_scid, promise.lsp_pubkey);
/// ```
#[wasm_bindgen]
/// v0.16 Phase B + Phase A.1: free-function wrapper for LSPS2 /buy.
/// client_pubkey is REQUIRED — adapter v0.18+ uses it to determine where
/// to open the JIT channel when a matching HTLC arrives. Must be the
/// wallet's 66-hex-char node pubkey.
pub fn lsps2_buy_promise(
    endpoint: &str,
    route_macaroon: &str,
    payment_size_msat: u64,
    client_pubkey: &str,
) -> js_sys::Promise {
    let endpoint = endpoint.to_string();
    let route_macaroon = route_macaroon.to_string();
    let client_pubkey = client_pubkey.to_string();
    future_to_promise(async move {
        let resp = lij_core::lsps2::lsps2_buy(&endpoint, &route_macaroon, Some(payment_size_msat), &client_pubkey)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let json = serde_json::to_string(&resp)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsValue::from_str(&json))
    })
}

// ── Wallet handle ────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct LijWalletHandle {
    inner: Arc<std::sync::Mutex<LijWallet>>,
}

#[wasm_bindgen]
impl LijWalletHandle {
    #[wasm_bindgen(static_method_of = LijWalletHandle)]
    pub fn create(config_json: &str) -> js_sys::Promise {
        let config_json = config_json.to_string();

        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;

            let storage = Arc::new(LocalStorage);

            let (wallet, created) = LijWallet::create(config, storage)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let handle = LijWalletHandle {
                inner: Arc::new(std::sync::Mutex::new(wallet)),
            };

            set_current_wallet_inner(handle.inner.clone());
            // Step 8a: swap StubEsploraHttp for the real WasmEsploraHttp now
            // that the wallet is fully constructed.
            {
                let w = handle.inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                if !OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed) {
                    w.node().set_independent_http(std::sync::Arc::new(WasmEsploraHttp::new()));
                } // Phase B: offline_start keeps the stub — zero network
            }

            let result_json = serde_json::to_string(&created)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let global = js_sys::global();
            let handle_val = JsValue::from(handle);
            js_sys::Reflect::set(
                &global,
                &JsValue::from_str("_lijWalletInstance"),
                &handle_val,
            ).map_err(|e| JsValue::from_str(&format!("Failed to store handle: {:?}", e)))?;

            Ok(JsValue::from_str(&result_json))
        })
    }

    #[wasm_bindgen(static_method_of = LijWalletHandle)]
    pub fn restore(mnemonic: &str, config_json: &str) -> js_sys::Promise {
        let mnemonic = mnemonic.to_string();
        let config_json = config_json.to_string();

        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;

            let storage = Arc::new(LocalStorage);

            arm_restore_progress();   // v346: the page hears each step of the read of the saved state
            let (wallet, restored) = LijWallet::restore(&mnemonic, config, storage)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let handle = LijWalletHandle {
                inner: Arc::new(std::sync::Mutex::new(wallet)),
            };

            set_current_wallet_inner(handle.inner.clone());
            // Step 8a: swap StubEsploraHttp for the real WasmEsploraHttp now
            // that the wallet is fully constructed.
            {
                let w = handle.inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                if !OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed) {
                    w.node().set_independent_http(std::sync::Arc::new(WasmEsploraHttp::new()));
                } // Phase B: offline_start keeps the stub — zero network
            }

            let result_json = serde_json::to_string(&restored)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let global = js_sys::global();
            let handle_val = JsValue::from(handle);
            js_sys::Reflect::set(
                &global,
                &JsValue::from_str("_lijWalletInstance"),
                &handle_val,
            ).map_err(|e| JsValue::from_str(&format!("Failed to store handle: {:?}", e)))?;

            Ok(JsValue::from_str(&result_json))
        })
    }

    /// v268 (S48, DP): the words screen's question, asked BEFORE anything is written — see
    /// LijWallet::backup_probe. Resolves to {"found":true,"channels":n,"version":v} or
    /// {"found":false}; REJECTS with the reason when the service gave no answer (no
    /// connection, service down) — the page treats that as a third outcome, never as "none".
    #[wasm_bindgen]
    pub fn backup_probe(mnemonic: &str, config_json: &str) -> js_sys::Promise {
        let mnemonic = mnemonic.to_string();
        let config_json = config_json.to_string();
        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
            let r = LijWallet::backup_probe(&mnemonic, &config)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = match r {
                Some((channels, version, saved_at_ms)) => format!("{{\"found\":true,\"channels\":{channels},\"version\":{version},\"saved_at_ms\":{saved_at_ms}}}"),
                None => "{\"found\":false}".to_string(),
            };
            Ok(JsValue::from_str(&json))
        })
    }

    /// v309 (S56, DP 2026-10-06 "Go"): the cloud copy for these words, pulled and written with the words alone — no
    /// node built, nothing running that could write over it. The restore screen's Continue and "Use the cloud copy"
    /// run it at the passphrase, the way a device file is loaded (v952). Resolves to
    /// {"channels":n,"version":v,"saved_at_ms":t}; REJECTS with "NO_COPY", "FETCH: …" (no answer — nothing was changed)
    /// or "CORRUPT: …" (the copy does not open — nothing was written).
    #[wasm_bindgen]
    pub fn adopt_cloud_backup(mnemonic: &str, config_json: &str) -> js_sys::Promise {
        let mnemonic = mnemonic.to_string();
        let config_json = config_json.to_string();
        future_to_promise(async move {
            let config: WalletConfig = serde_json::from_str(&config_json)
                .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
            let storage = LocalStorage;
            let (channels, version, saved_at_ms) = LijWallet::adopt_cloud_backup(&mnemonic, &config, &storage)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            BACKUP_CONFLICT.store(0, std::sync::atomic::Ordering::Relaxed);
            Ok(JsValue::from_str(&format!("{{\"channels\":{channels},\"version\":{version},\"saved_at_ms\":{saved_at_ms}}}")))
        })
    }

    /// v268 (S48, DP): a device backup file opened with the words only — no node built, no
    /// network — so the restore flow can take a file before any state exists on the device,
    /// and a phone with no connection can still reach its offline room. Writes the file's
    /// channel state; the page reloads after. Returns {"channels":n}.
    #[wasm_bindgen]
    pub fn import_backup_file(mnemonic: &str, config_json: &str, blob_json: &str) -> Result<String, JsValue> {
        let config: WalletConfig = serde_json::from_str(config_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
        let blob: lij_core::storage::StateBlob = serde_json::from_str(blob_json)
            .map_err(|_e| JsValue::from_str("Not a LiJ backup file."))?;
        let storage = LocalStorage;
        let n = LijWallet::import_backup_file(mnemonic, &config, &storage, &blob)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"channels\":{n}}}"))
    }

    #[wasm_bindgen]
    pub fn get_balance(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let balance = wallet.get_balance()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&balance)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    #[wasm_bindgen]
    pub fn send_payment(&self, bolt11: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let result = wallet.send_payment(&bolt11)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Manually push the current encrypted wallet state to all enabled backup
    /// sinks (scenario-A backup). Returns `{"ok":true}`. This is the "Back up
    /// now" action and our round-trip test entrypoint; automatic triggers will
    /// reuse the same `LijWallet::backup()` path.
    #[wasm_bindgen]
    pub fn backup_now(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            // Snapshot what the push needs while holding the lock, then RELEASE
            // it before any network I/O. Holding the wallet mutex across the
            // push's `.await` lets a background tick re-enter and panic the
            // single-threaded WASM mutex.
            let prep = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet
                    .prepare_backup()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            let (blob, signer, sinks) = match prep {
                Some(t) => t,
                None => return Ok(JsValue::from_str("{\"ok\":true,\"pushed\":0}")),
            };
            // Network push happens with NO wallet lock held.
            note_inflight(&blob);   // v319: the number and fingerprint of the copy on its way, before it goes
            let mut ok = 0u32;
            let mut last_err: Option<String> = None;
            let mut refused = false;
            for sink in &sinks {
                match sink.push(&blob, &*signer).await {
                    Ok(()) => ok += 1,
                    Err(e) => { let s = e.to_string(); if note_push_refusal(&s) { refused = true; } last_err = Some(s); }
                }
            }
            if ok > 0 {
                // v309: the number is the phone's only once the cloud accepted it
                let _ = lij_core::storage::backup_version_commit(&LocalStorage, blob.version);
                BACKUP_CONFLICT.store(0, std::sync::atomic::Ordering::Relaxed);
            }
            if ok > 0 || refused { let _ = lij_core::storage::backup_inflight_clear(&LocalStorage); }   // v319: the cloud answered
            if ok == 0 {
                if let Some(e) = last_err {
                    return Err(JsValue::from_str(&format!("backup: all sinks failed: {e}")));
                }
            }
            Ok(JsValue::from_str(&format!("{{\"ok\":true,\"pushed\":{ok}}}")))
        })
    }

    /// v309 (S56): the cloud's number when it refused this phone's copy as older; 0 = no refusal. The page shows it
    /// once and offers "Use the cloud copy" (adopt_cloud_backup at the next unlock) or "Replace the cloud copy with this
    /// phone" (backup_replace_cloud).
    #[wasm_bindgen]
    pub fn backup_conflict(&self) -> u64 {
        BACKUP_CONFLICT.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// v309 (S56): the person's decision to replace a newer cloud copy with this phone's state — the cloud's number
    /// is taken as the phone's (the next copy is one above it) and one upload runs now.
    #[wasm_bindgen]
    pub fn backup_replace_cloud(&self) -> js_sys::Promise {
        let n = BACKUP_CONFLICT.load(std::sync::atomic::Ordering::Relaxed);
        if n > 0 { let _ = lij_core::storage::backup_version_commit(&LocalStorage, n); }
        BACKUP_CONFLICT.store(0, std::sync::atomic::Ordering::Relaxed);
        self.backup_now()
    }

    /// v309 (S56): what the cloud holds for this wallet — {"found":true,"channels":n,"version":v,"saved_at_ms":t} or
    /// {"found":false}; REJECTS when the service gave no answer. Nothing is written. The warning before a device file
    /// is loaded compares the file's date and number with these.
    #[wasm_bindgen]
    pub fn cloud_backup_info(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (client, signer) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.backup_client_and_signer()
            };
            let r = LijWallet::cloud_backup_info(&client, &*signer)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = match r {
                Some((channels, version, saved_at_ms)) => format!("{{\"found\":true,\"channels\":{channels},\"version\":{version},\"saved_at_ms\":{saved_at_ms}}}"),
                None => "{\"found\":false}".to_string(),
            };
            Ok(JsValue::from_str(&json))
        })
    }

    /// v310 (S57, DP 2026-10-07 "Go with … 1"): the cloud copy's number and date only — {"found":true,"version":v,
    /// "saved_at_ms":t} or {"found":false}; REJECTS when the service gave no answer (or has no /backup/meta). The page
    /// compares the number with this phone's before the first connection to the provider; nothing is pulled or written.
    /// v319 (S57, DP 2026-10-08 14:40 "Go"): the answer adds "fingerprint" (the stored copy's, or null) and "own" —
    /// true when the cloud's copy is THIS PHONE'S OWN UPLOAD: its number and fingerprint are the ones this phone noted
    /// before an upload whose OK never arrived (the app put away mid-upload). The page then takes the number
    /// (backup_adopt_own) and connects with no warning; a copy this phone never sent reads own:false as before.
    #[wasm_bindgen]
    pub fn cloud_backup_meta(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (client, signer) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.backup_client_and_signer()
            };
            let r = LijWallet::cloud_backup_meta(&client, &*signer)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = match r {
                Some(m) => {
                    let note = lij_core::storage::backup_inflight(&LocalStorage).unwrap_or(None);
                    let own = lij_core::storage::backup_meta_is_own(&m, note.as_ref());
                    let fp = match &m.fingerprint { Some(f) => format!("\"{f}\""), None => "null".to_string() };
                    if own { log::info!("[v319] the cloud copy no. {} is this phone's own upload (its OK never arrived)", m.version); }
                    format!("{{\"found\":true,\"version\":{},\"saved_at_ms\":{},\"fingerprint\":{fp},\"own\":{own}}}", m.version, m.saved_at_ms)
                }
                None => "{\"found\":false}".to_string(),
            };
            Ok(JsValue::from_str(&json))
        })
    }

    /// v319: take the number of this phone's own outstanding upload as the phone's (the cloud holds that copy; its OK
    /// was lost) — the note is read, its number committed (upward only), the note cleared. Returns the number taken,
    /// 0 when no note stands. Never takes a number from the page: only the one this phone itself sent.
    #[wasm_bindgen]
    pub fn backup_adopt_own(&self) -> u64 {
        match lij_core::storage::backup_inflight(&LocalStorage) {
            Ok(Some((version, _fp))) => {
                let _ = lij_core::storage::backup_version_commit(&LocalStorage, version);
                let _ = lij_core::storage::backup_inflight_clear(&LocalStorage);
                BACKUP_CONFLICT.store(0, std::sync::atomic::Ordering::Relaxed);
                log::info!("[v319] took no. {version} — this phone's own upload");
                version
            }
            _ => 0,
        }
    }

    /// Auto-backup tick: if channel state changed since the last push, snapshot
    /// it under the lock, release, then push to enabled sinks UNLOCKED. Cheap
    /// no-op when nothing changed; the frontend calls this on a slow debounce
    /// interval. Never holds the wallet mutex across the push's `.await`.
    /// v250 (S46, DP GO): delete this wallet's cloud copy at every enabled sink.
    /// Local state is untouched; the caller decides what follows (the Privacy
    /// switch turning Off, or the Erase gate's "delete the cloud copy too").
    /// Answers {"ok":true,"forgotten":N,"existed":bool}; an error if every sink refused.
    #[wasm_bindgen]
    pub fn forget_cloud_backup(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (signer, sinks) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.backup_sinks_and_signer()
            };
            if sinks.is_empty() {
                return Ok(JsValue::from_str("{\"ok\":true,\"forgotten\":0,\"existed\":false}"));
            }
            let mut ok = 0u32;
            let mut existed = false;
            let mut last_err: Option<String> = None;
            for sink in &sinks {
                match sink.forget(&*signer).await {
                    Ok(e) => { ok += 1; existed |= e; }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            if ok == 0 {
                if let Some(e) = last_err {
                    return Err(JsValue::from_str(&format!("forget: all sinks failed: {e}")));
                }
            }
            log::info!("[v250] cloud backup forgotten at {ok} sink(s), existed={existed}");
            Ok(JsValue::from_str(&format!("{{\"ok\":true,\"forgotten\":{ok},\"existed\":{existed}}}")))
        })
    }

    #[wasm_bindgen]
    pub fn maybe_backup(&self) -> js_sys::Promise {
        // Phase B: offline_start hard-silences the backup client.
        if OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed)
            || BACKUP_OFF.load(std::sync::atomic::Ordering::Relaxed) {   // v209
            return js_sys::Promise::resolve(&JsValue::UNDEFINED);
        }
        // v309: a refused upload (the cloud holds a newer copy) stops the automatic uploads until the person decides
        let conflict = BACKUP_CONFLICT.load(std::sync::atomic::Ordering::Relaxed);
        if conflict > 0 {
            return js_sys::Promise::resolve(&JsValue::from_str(&format!("{{\"ok\":false,\"conflict\":{conflict}}}")));
        }
        let inner = self.inner.clone();
        future_to_promise(async move {
            let prep = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet
                    .prepare_backup_if_dirty()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            let (blob, signer, sinks, dirty) = match prep {
                Some(t) => t,
                None => return Ok(JsValue::from_str("{\"ok\":true,\"pushed\":0}")),
            };
            // Push with NO wallet lock held. On failure re-mark dirty to retry
            // next tick; on success leave it as cleared at snapshot (a concurrent
            // state change during the push will already have re-dirtied it).
            note_inflight(&blob);   // v319: the number and fingerprint of the copy on its way, before it goes
            let mut ok = 0u32;
            let mut refused = false;
            for sink in &sinks {
                match sink.push(&blob, &*signer).await {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        // v309: a refusal as older is NOT retried — the person decides; anything else is retried next tick
                        if note_push_refusal(&e.to_string()) { refused = true; }
                        else { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
                    }
                }
            }
            if ok > 0 {
                let _ = lij_core::storage::backup_version_commit(&LocalStorage, blob.version);   // v309: accepted — the number is the phone's now
                BACKUP_CONFLICT.store(0, std::sync::atomic::Ordering::Relaxed);
            }
            if ok > 0 || refused { let _ = lij_core::storage::backup_inflight_clear(&LocalStorage); }   // v319: the cloud answered; a lost answer keeps the note
            let conflict = if refused { BACKUP_CONFLICT.load(std::sync::atomic::Ordering::Relaxed) } else { 0 };
            Ok(JsValue::from_str(&format!("{{\"ok\":true,\"pushed\":{ok},\"conflict\":{conflict}}}")))
        })
    }

    /// Abandon all channels WITHOUT broadcasting (safe recovery from a stale
    /// restore). Call this BEFORE reconnecting to peers to avoid the
    /// data-loss-protect panic on channel_reestablish. Returns channels closed.
    #[wasm_bindgen]
    pub fn force_close_all_without_broadcasting(&self) -> Result<u32, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet
            .force_close_all_without_broadcasting()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Read-only on-chain wallet summary (D, increment 1): scans the BIP84
    /// spendable chain + legacy m/525 residue and returns balance, UTXOs, and a
    /// fresh receive address as JSON. Snapshots handles under the lock, then
    /// runs the scan UNLOCKED (network I/O), like the backup path.
    #[wasm_bindgen]
    pub fn onchain_summary(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let summary =
                lij_core::onchain_scan::onchain_summary(&root_key, independent, network)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = summary
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Tier 2 (privacy-default) on-chain sync: pull compact block filters from
    /// the node, match them LOCALLY against our scripts, fetch and verify only
    /// the blocks that hit, and assemble the UTXO set + history + balances
    /// entirely client-side — the node never learns which scripts are ours.
    /// Persists across sessions and resumes from the saved cursor. `birthday`
    /// is the wallet's creation height, used only when no cursor exists yet.
    /// Returns Tier2Summary JSON.
    /// v296 (S52, DP 23:09 "#1: Go"): `filter_base` = the block-filter server the walk reads (the page passes its
    /// own provider's when the LIJOX directory lists one); `sp_base` = the server whose silent-payment index the
    /// scan reads (none = the walk's server). Either missing or not a plain https address = the project's server
    /// (tier2_sync::DEFAULT_FILTER_BASE). Servers are interchangeable: filters and headers are the chain's own
    /// (PoW-checked, linked to the walk's record), blocks are hash-bound — a change of server mid-walk is safe.
    /// The summary names the two servers used (`filter_server`, `sp_server`).
    #[wasm_bindgen]
    pub fn tier2_onchain_sync(&self, birthday: f64, filter_base: Option<String>, sp_base: Option<String>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, network, live_funding, live_closing) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let (rk, _independent, net) = wallet.onchain_handles();
                // v271: the live channels' funding txids — the node's record, read under the
                // same lock the handles come from (no second lock later, across awaits)
                // v272: and a live channel's closing txid once its funding spend is sighted
                let (lf, lc): (Vec<String>, Vec<String>) = wallet.node().get_channels().map(|cs| {
                    let mut f = Vec::new(); let mut c = Vec::new();
                    for ch in cs { if let Some(t) = ch.funding_txid { f.push(t); } if let Some(t) = ch.closing_txid { c.push(t); } }
                    (f, c)
                }).unwrap_or_default();
                (rk, net, lf, lc)
            };
            // v296: the servers come from the page per call (was one constant, the project's server, for every wallet)
            let base_owned = lij_core::tier2_sync::filter_base_or_default(filter_base.as_deref());
            let sp_base_owned = match sp_base.as_deref() { Some(s) => lij_core::tier2_sync::filter_base_or_default(Some(s)), None => base_owned.clone() };
            let base: &str = base_owned.as_str();
            let sp_base: &str = sp_base_owned.as_str();
            t2_note_servers(base, sp_base);
            let http: Arc<dyn lij_core::independent::EsploraHttp> =
                Arc::new(WasmEsploraHttp::for_filter_walk());   // v264: 60 s per request, errors name the filter server
            let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);   // v256: encrypted at rest

            let mut view = lij_core::tier2_wallet::load_view(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if lij_core::tier2_wallet::birth(&mut view, birthday as u32) {   // v348: the silent-payment floor is written at birth, before the walk moves
                log::info!("[tier2] v348 a new view: birthday {} (the silent-payment sweep may start there)", view.cursor.birthday);
            }
            // v258 (DP's iOS read): the page's birthday is the CEILING. A stored birthday above it
            // (v744's first-channel bound raised one to 965,586 and hid 51,067 sats below it) is
            // lowered, and a walk that had reported complete resumes from its low block down.
            let ceiling = birthday as u32;
            if ceiling > 0 && view.cursor.birthday > ceiling {
                log::warn!("[tier2] v258 birthday {} is above the page's {}: lowering it; the walk resumes downward", view.cursor.birthday, ceiling);
                view.cursor.birthday = ceiling;
            }
            if let Some(d) = view.down.as_mut() {
                if d.done && d.low > view.cursor.birthday { d.done = false; }
            }
            let now_ms = js_sys::Date::now() as u64;
            // v256 (DP: one ledger): a view built under older rules is rebuilt from scratch —
            // coins, spend marks, rows and tags re-derived by the walk; only the birthday kept.
            if view.schema < lij_core::tier2_wallet::VIEW_SCHEMA {
                log::info!("[tier2] v256 ledger rebuild: schema {} -> {}, walking again from {} under the {}-address net",
                    view.schema, lij_core::tier2_wallet::VIEW_SCHEMA, view.cursor.birthday, lij_core::tier2_wallet::NET_WIDTH);
                lij_core::tier2_wallet::rebuild_from_birthday(&mut view, now_ms);
                lij_core::tier2_wallet::save_view(storage.as_ref(), &view).map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            if view.net_width < lij_core::tier2_wallet::NET_WIDTH { view.net_width = lij_core::tier2_wallet::NET_WIDTH; }
            // v271: note every funding txid the node knows (closed-channel log + live channels) so a
            // funding tx this wallet paid for derives as ChannelOpen under any walk — the S46 rebuild
            // had dropped those tags and the Lightning book lost its "+moved to Lightning" rows.
            {
                let mut fund = lij_core::closed_channel_log::ClosedChannelLog::funding_txids(storage.as_ref());
                fund.extend(live_funding.iter().cloned());
                let grew_f = lij_core::tier2_wallet::note_funding_txids(&mut view, fund);
                let grew_c = lij_core::tier2_wallet::note_closing_txids(&mut view, live_closing.iter().cloned());   // v272 (the log's own closing txids are noted inside sync_down)
                if grew_f || grew_c {
                    log::info!("[tier2] v271/v272: records now hold {} funding / {} closing txids", view.funding_txids.len(), view.closing_txids.len());
                    lij_core::tier2_wallet::save_view(storage.as_ref(), &view).map_err(|e| JsValue::from_str(&e.to_string()))?;
                }
            }

            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            // v256: the fixed net — every branch watched from index 0 to net_width (2,500).
            let scripts = t2_scripts(&root_key, network, view.net_width).await?;

            let tip = match lij_core::tier2_sync::fetch_tip(&http, base).await {
                Ok(t) => t,
                Err(e) => {
                    // v257: the failure is written down where the face and the tape can read it
                    let msg = format!("block-filter server unreachable ({}): {}", base.trim_start_matches("https://"), e.to_string().trim_start_matches("Network error: "));   // v296: names the server
                    log::warn!("[tier2] sync failed: {msg}");
                    view.last_sync = Some(lij_core::tier2_wallet::SyncNote { at_ms: now_ms, ok: false, note: msg.clone() });
                    let _ = lij_core::tier2_wallet::save_view(storage.as_ref(), &view);
                    return Err(JsValue::from_str(&msg));
                }
            };

            // v256: the daily tail verification — once a day, when caught up, the newest 144
            // blocks are rolled back and re-walked, so every recent spend is re-confirmed
            // against the chain. Filters are fetched by block; no address or coin leaves the phone.
            // v257: the daily tail verification — once a day, when the walk is complete, the
            // newest 144 blocks are rolled back and re-read (the forward step re-walks them).
            let walk_done = view.down.as_ref().map(|d| d.done).unwrap_or(false) && view.cursor.scanned_to >= tip.height;
            if walk_done && view.last_tail_verify_ms > 0 && now_ms.saturating_sub(view.last_tail_verify_ms) >= 86_400_000 {
                let to = tip.height.saturating_sub(lij_core::tier2_wallet::TAIL_VERIFY_BLOCKS).max(view.cursor.birthday);
                log::info!("[tier2] v257 tail verify: re-reading blocks {}..{}", to + 1, tip.height);
                lij_core::tier2_wallet::rollback(&mut view, to);
                view.last_tail_verify_ms = now_ms;
                lij_core::tier2_wallet::save_view(storage.as_ref(), &view).map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            if view.last_tail_verify_ms == 0 { view.last_tail_verify_ms = now_ms; }

            // v257: ONE walk, newest-first; up to 8 batches per call; every call leaves a note
            // (the tape and the face read it), success or failure.
            let t0 = js_sys::Date::now();
            let walked = lij_core::tier2_wallet::sync_down(
                &http,
                base,
                &*scripts,
                &mut view,
                storage.as_ref(),
                tip.height,
                &tip.hash,
                lij_core::tier2_sync::DEFAULT_BATCH,
                lij_core::tier2_sync::BATCHES_PER_CALL,   // v264: 5 × 100 blocks (was 8 × 500)
            )
            .await;
            let took = (js_sys::Date::now() - t0) as u64;
            // v264 (S47): a walk that fails part-way no longer withholds what it has read — the
            // batches before the failure are already saved; the summary goes to the page with the
            // reason in `sync_error`, and the page paints the balance and rows under "Paused".
            let mut walk_error: Option<String> = None;
            match walked {
                Ok((_b, n)) => {
                    log::info!("[tier2] sync ok: {n} · {took} ms");
                    view.last_sync = Some(lij_core::tier2_wallet::SyncNote { at_ms: now_ms, ok: true, note: n });
                }
                Err(e) => {
                    let msg = e.to_string().trim_start_matches("Network error: ").to_string();
                    log::warn!("[tier2] sync failed: {msg} · {took} ms");
                    view.last_sync = Some(lij_core::tier2_wallet::SyncNote { at_ms: now_ms, ok: false, note: msg.clone() });
                    let _ = lij_core::tier2_wallet::save_view(storage.as_ref(), &view);
                    walk_error = Some(msg);
                }
            };

            // v287 (S50, SILENT PAYMENTS — RECEIVE): the silent-payment SCAN rides the same call, after
            // the walk. The provider is asked once per call whether it serves a tweak index (/sp/info;
            // 404 = no silent-payment receive here, nothing else happens); then up to 100 blocks (200
            // once the walk is done) are scanned upward from the scan's start towards the walk's top —
            // the box's tweaks × the scan key against the block filters the walk already reads; a
            // matching block is fetched (hash-bound, merkle-checked) and its coins land on the
            // ledger as chain 352 with their t_k. When the scan stands at the top the mempool leg
            // runs (unconfirmed payments → "received · pending"). Never fatal: a failure is noted
            // where the face reads it (sp.note) and the next call tries again.
            // v288 (DP: "the wallet has a say"): the wallet's own switch (marks.sp_enabled) — off = the
            // provider is still asked (so the face can say what it offers) but nothing is scanned.
            if walk_error.is_none() {
                let t1 = js_sys::Date::now();
                let sp_on = lij_core::tier2_wallet::load_marks(storage.as_ref()).map(|m| m.sp_enabled).unwrap_or(true);
                match lij_core::sp_scan::refresh_info(&http, sp_base, &mut view).await {
                    Ok(()) => {
                        let available = view.sp.as_ref().map(|s| s.available).unwrap_or(false);
                        if available && sp_on {
                            let walk_done = view.down.as_ref().map(|d| d.done).unwrap_or(false);
                            let max_batches = if walk_done { 2 } else { 1 };
                            match lij_core::sp_scan::scan(&http, sp_base, &root_key, &mut view, storage.as_ref(), 100, max_batches).await {
                                Ok((b, n)) => {
                                    if b > 0 { log::info!("[sp] {n} · {} ms", (js_sys::Date::now() - t1) as u64); }
                                    let at_top = view.sp.as_ref().map(|s| s.scanned_to >= view.cursor.scanned_to.min(s.indexed_to)).unwrap_or(false);
                                    if at_top {
                                        match lij_core::sp_scan::mempool(&http, sp_base, &root_key, &mut view, storage.as_ref(), now_ms).await {
                                            Ok(found) => { if found > 0 { log::info!("[sp] {found} silent payment(s) pending in the mempool"); } }
                                            Err(e) => {
                                                let msg = format!("silent payments: mempool: {}", e.to_string().trim_start_matches("Network error: "));
                                                log::warn!("[sp] {msg}");
                                                if let Some(sp) = view.sp.as_mut() { sp.last_note = msg; }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    let msg = format!("silent payments: scan paused: {}", e.to_string().trim_start_matches("Network error: "));
                                    log::warn!("[sp] {msg} · {} ms", (js_sys::Date::now() - t1) as u64);
                                    if let Some(sp) = view.sp.as_mut() { sp.last_note = msg; }
                                    let _ = lij_core::tier2_wallet::save_view(storage.as_ref(), &view);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!("silent payments: {}", e.to_string().trim_start_matches("Network error: "));
                        log::warn!("[sp] {msg}");
                        if let Some(sp) = view.sp.as_mut() { sp.last_note = msg; }
                    }
                }
            }

            // v257: the widen rule — a coin within NET_WIDEN_MARGIN of the net's far edge on any
            // branch means blocks already read may hold coins past it: widen and rebuild.
            let walk_done = view.down.as_ref().map(|d| d.done).unwrap_or(false);
            if walk_done {
                let hot = lij_core::tier2_wallet::net_is_hot(&view);   // v317: each branch at its own width (m/86 at a fifth)
                if hot {
                    log::warn!("[tier2] a coin sits within {} of the net's edge ({}): widening to {} and reading again",
                        lij_core::tier2_wallet::NET_WIDEN_MARGIN, view.net_width, view.net_width + lij_core::tier2_wallet::NET_WIDTH);
                    view.net_width += lij_core::tier2_wallet::NET_WIDTH;
                    lij_core::tier2_wallet::rebuild_from_birthday(&mut view, now_ms);
                    lij_core::tier2_wallet::save_view(storage.as_ref(), &view).map_err(|e| JsValue::from_str(&e.to_string()))?;
                }
            }
            lij_core::tier2_wallet::reconcile_pending(storage.as_ref(), &mut view)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // v191 (S29): CONFLICT-DEAD RELEASE — zombie pendings whose
            // input the chain shows spent can never confirm; their folded
            // change is phantom balance. Release + witness each.
            let conflicts = lij_core::tier2_wallet::release_conflicted_pending(
                storage.as_ref(),
                &view,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            for (dead_txid, phantom_chg) in &conflicts {
                log::warn!(
                    "[CONFLICT-AUDIT] released dead pending {} (phantom change {} sats)",
                    &dead_txid[..16.min(dead_txid.len())],
                    phantom_chg
                );
            }

            // v102: reconcile the OutputSweeper against confirmed sweep txs.
            //
            // The sweeper regenerates each unconfirmed sweep every block (locktime
            // = current height -> a new txid each time), so it never recognizes its
            // own sweep landing and sits at "sweeping" forever, double-counting the
            // swept funds (already in spendable) in the maturing alert. Feed it the
            // REAL confirmed sweep txs from the blocks this scan covers:
            // is_spent_in() on the sweeper matches each to the source descriptor it
            // spends (no txid/value heuristic) and advances sweeping -> confirming,
            // which the UI excludes. Gated on there actually being a "sweeping"
            // output, so the common path costs nothing. Non-fatal: a transient
            // block-fetch failure must never fail the sync (the next one retries).
            let needs_sweeper_reconcile = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().sweeper_pending_first_count() > 0
            };
            if needs_sweeper_reconcile {
                // Candidate sweep destinations: unspent chain-0 view UTXOs (the
                // sweeper always sweeps to m/84'/0'/0'/0/n = CHAIN_RECEIVE). We
                // accept only txs whose txid is one of these already-validated
                // rows, so a bad block server cannot inject a false confirmation.
                let mut wanted: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut heights: Vec<u32> = Vec::new();
                for u in &view.utxos {
                    if u.spent_height.is_none() && u.chain == lij_core::tier2::CHAIN_RECEIVE {
                        wanted.insert(u.txid.clone());
                        heights.push(u.height);
                    }
                }
                heights.sort_unstable();
                heights.dedup();
                if !wanted.is_empty() {
                    if let Ok(confirmed) = lij_core::tier2_wallet::fetch_confirmed_txs(
                        &http, base, &heights, &wanted,
                    )
                    .await
                    {
                        if !confirmed.is_empty() {
                            if let Ok(wallet) = inner.lock() {
                                wallet.node().reconcile_sweeper_confirmations(&confirmed);
                            }
                        }
                    }
                }
            }
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());

            // v190 (S29): UTXO-set invariant — heal duplicates (keep first),
            // witness-log the cull, persist the healed view, and surface the
            // count to the audit line. A clean view is a no-op.
            let view_dupes = lij_core::tier2_wallet::dedupe_utxos(&mut view);
            if view_dupes > 0 {
                log::warn!(
                    "[VIEW-AUDIT] healed {} duplicate utxo entr(ies) — persisted",
                    view_dupes
                );
                lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }

            let marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).unwrap_or_default();   // v281: freezes and notes onto the rows
            let mut sum = lij_core::tier2_wallet::summary(&view, &pending, tip.height, &marks);
            // v306: each received line's address, named from the wallet's own scripts (cached per width)
            if let Ok(sc) = t2_scripts(&root_key, network, view.net_width).await {
                lij_core::tier2_wallet::name_line_addresses(&mut sum.history, &sc, network);
            }
            let json = sum
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = json.replacen(
                '{',
                &format!(
                    "{{\"view_dupes\":{},\"conflicts\":{},\"sync_error\":{},\"filter_server\":{},\"sp_server\":{},",
                    view_dupes,
                    conflicts.len(),
                    serde_json::to_string(&walk_error).unwrap_or_else(|_| "null".into()),   // v264
                    serde_json::to_string(base).unwrap_or_else(|_| "null".into()),      // v296: the servers this call read
                    serde_json::to_string(sp_base).unwrap_or_else(|_| "null".into())
                ),
                1,
            );
            Ok(JsValue::from_str(&json))
        })
    }

    /// On-chain send (option D, increment 2): P2WPKH spend from the m/84
    /// spendable chain, change to m/84'/{coin}'/0'/1/0. `amount_sats` is a JS
    /// number (f64 is exact up to 2^53, far above the 2.1e15-sat supply cap);
    /// `fee_rate_sat_per_kw` is LDK sat/kilo-weight (use FeeQuote::on_chain_sweep).
    /// S45 (DP): plan (send=false) or send (send=true) a CPFP child for a
    /// pending cooperative close — the user's Speed up on the on-chain face.
    /// Always forced (the user's tap skips the automatic mode's gates).
    /// Returns JSON {ok, can, reason, child_fee_sats, parent_rate_vb, target_vb, txid}.
    #[wasm_bindgen]
    pub fn coop_cpfp(&self, channel_id_hex: &str, send: bool) -> js_sys::Promise {
        let inner = self.inner.clone();
        let cid = channel_id_hex.to_string();
        future_to_promise(async move {
            let h = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().coop_cpfp_handles()
            };
            let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&h.root_key);   // v256
            let j = lij_core::node::coop_cpfp(storage, h, &cid, send, true)
                .await
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            Ok(JsValue::from_str(&j))
        })
    }

    /// Lock-prepare-unlock: snapshot handles under the lock, then build/sign/
    /// broadcast with the lock released (network I/O). Returns SendResult JSON.
    #[wasm_bindgen]
    pub fn send_onchain(
        &self,
        dest: &str,
        amount_sats: f64,
        fee_rate_sat_per_kw: u32,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let dest = dest.to_string();
        future_to_promise(async move {
            if !(amount_sats.is_finite() && amount_sats >= 1.0) {
                return Err(JsValue::from_str(
                    "amount must be a positive whole number of sats",
                ));
            }
            let amount = amount_sats as u64;
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            // Plain-send coins now come from the canonical Tier-2 view (the same
            // source as channel funding and the displayed balance), not a live
            // scan. Load the view + pending once: they pick the next change index
            // (rotation) AND supply the spendable set to build_and_send.
            let (view, pending, marks) = {
                let storage = t2_storage(&root_key);   // v263: the view is encrypted at rest (v256) — plain storage could not parse it
                let view = lij_core::tier2_wallet::load_view(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
                let marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;   // v281: a freeze the send must honour
                (view, pending, marks)
            };
            let change_index = lij_core::tier2_wallet::next_change_index_marked(&view, &pending, &marks);   // v326 (Mix step 8): past every change index a pool was given
            let result = lij_core::onchain_send::build_and_send(
                &root_key,
                independent,
                network,
                &dest,
                amount,
                fee_rate_sat_per_kw,
                change_index,
                &view,
                &pending,
                &marks,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Own-send immediate view: reserve the spent inputs so spendable
            // drops now (before confirmation); reconciled when Tier-2 sees it.
            // Written to the dedicated pending key (decoupled from the synced
            // view, so a concurrent sync can't clobber it).
            {
                let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);   // v256
                let delta = -((result.amount_sats as i64) + (result.fee_sats as i64));
                if let Err(e) = lij_core::tier2_wallet::record_pending(
                    storage.as_ref(),
                    lij_core::tier2_wallet::PendingTx {
                        txid: result.txid.clone(),
                        spent_outpoints: result.spent_outpoints.clone(),
                        delta_sats: delta,
                        direction: lij_core::tier2_wallet::TxDirection::Sent,
                        kind: lij_core::tier2_wallet::TxKind::Onchain,
                        created_at_ms: lij_core::tier2_wallet::now_ms(),
                        change_outpoint: result.change_outpoint.clone(),
                        change_value_sats: result.change_sats,
                        change_index: result.change_index,
                        broadcast_seen: false,
                        // Build #4: sends rebuild from v166 metadata; byte
                        // persistence for sends is staged separately.
                        raw_tx_hex: None,
                        dest_addr: Some(dest.clone()),
                        dest_sats: Some(amount),
                        fee_sats: Some(result.fee_sats),
                        fee_rate_sat_per_kw: Some(fee_rate_sat_per_kw),
                        dests: Vec::new(),
                    },
                ) {
                    log::error!("record pending on-chain send failed: {e}");
                }
                t2_note_send(storage.as_ref(), &result.txid, &result.raw_hex, Some(dest.as_str()), &[]);   // v298
            }

            let json = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v281 (S50, coin control — Max): send everything sendable to `dest` in one output
    /// (every unfrozen, unreserved coin; amount = total − the one-output fee; no change).
    /// The page's Max calls this instead of guessing an amount for send_onchain.
    #[wasm_bindgen]
    pub fn send_onchain_all(&self, dest: &str, fee_rate_sat_per_kw: u32) -> js_sys::Promise {
        let inner = self.inner.clone();
        let dest = dest.to_string();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let (view, pending, marks) = {
                let storage = t2_storage(&root_key);
                let view = lij_core::tier2_wallet::load_view(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
                let marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                (view, pending, marks)
            };
            let change_index = lij_core::tier2_wallet::next_change_index_marked(&view, &pending, &marks);   // v326 (Mix step 8): past every change index a pool was given
            let result = lij_core::onchain_send::build_and_send_all(
                &root_key,
                independent,
                network,
                &dest,
                fee_rate_sat_per_kw,
                change_index,
                &view,
                &pending,
                &marks,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            // The same immediate-view record as send_onchain: reserve the inputs now.
            {
                let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);
                let delta = -((result.amount_sats as i64) + (result.fee_sats as i64));
                if let Err(e) = lij_core::tier2_wallet::record_pending(
                    storage.as_ref(),
                    lij_core::tier2_wallet::PendingTx {
                        txid: result.txid.clone(),
                        spent_outpoints: result.spent_outpoints.clone(),
                        delta_sats: delta,
                        direction: lij_core::tier2_wallet::TxDirection::Sent,
                        kind: lij_core::tier2_wallet::TxKind::Onchain,
                        created_at_ms: lij_core::tier2_wallet::now_ms(),
                        change_outpoint: None,
                        change_value_sats: 0,
                        change_index: result.change_index,
                        broadcast_seen: false,
                        raw_tx_hex: None,
                        dest_addr: Some(dest.clone()),
                        dest_sats: Some(result.amount_sats),
                        fee_sats: Some(result.fee_sats),
                        fee_rate_sat_per_kw: Some(fee_rate_sat_per_kw),
                        dests: Vec::new(),
                    },
                ) {
                    log::error!("record pending on-chain send-all failed: {e}");
                }
                t2_note_send(storage.as_ref(), &result.txid, &result.raw_hex, Some(dest.as_str()), &[]);   // v298
            }
            let json = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v282 (S50, coin control cut 3 — chosen coins): a send from EXACTLY the coins the user
    /// chose. `req` is JSON {"dest", "fee_rate_sat_per_kw", "inputs": [{"txid","vout"}, …],
    /// and either "amount_sats" (change to m/84) or "all": true (everything in those coins,
    /// one output)}. A frozen or unknown coin, or coins that do not cover amount + fee, is an
    /// error in plain words — nothing is spent. Returns SendResult JSON like send_onchain.
    #[wasm_bindgen]
    pub fn send_onchain_with(&self, req: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let req = req.to_string();
        future_to_promise(async move {
            #[derive(serde::Deserialize)]
            struct Pin { txid: String, vout: u32 }
            #[derive(serde::Deserialize)]
            struct Req { dest: String, fee_rate_sat_per_kw: u32, #[serde(default)] amount_sats: Option<f64>, #[serde(default)] all: bool, #[serde(default)] inputs: Vec<Pin> }
            let r: Req = serde_json::from_str(&req).map_err(|e| JsValue::from_str(&format!("send_onchain_with: bad request: {e}")))?;
            let pins: Vec<(String, u32)> = r.inputs.iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect();
            if pins.is_empty() {
                return Err(JsValue::from_str("send_onchain_with: no coins chosen"));
            }
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let (view, pending, marks) = {
                let storage = t2_storage(&root_key);
                let view = lij_core::tier2_wallet::load_view(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
                let marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                (view, pending, marks)
            };
            let change_index = lij_core::tier2_wallet::next_change_index_marked(&view, &pending, &marks);   // v326 (Mix step 8): past every change index a pool was given
            let result = if r.all {
                lij_core::onchain_send::build_and_send_all_pinned(&root_key, independent, network, &r.dest, r.fee_rate_sat_per_kw, change_index, &view, &pending, &marks, &pins).await
            } else {
                let amount = match r.amount_sats { Some(a) if a.is_finite() && a >= 1.0 => a as u64, _ => return Err(JsValue::from_str("amount must be a positive whole number of sats")) };
                lij_core::onchain_send::build_and_send_pinned(&root_key, independent, network, &r.dest, amount, r.fee_rate_sat_per_kw, change_index, &view, &pending, &marks, Some(&pins)).await
            }
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            {
                let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);
                let delta = -((result.amount_sats as i64) + (result.fee_sats as i64));
                if let Err(e) = lij_core::tier2_wallet::record_pending(
                    storage.as_ref(),
                    lij_core::tier2_wallet::PendingTx {
                        txid: result.txid.clone(),
                        spent_outpoints: result.spent_outpoints.clone(),
                        delta_sats: delta,
                        direction: lij_core::tier2_wallet::TxDirection::Sent,
                        kind: lij_core::tier2_wallet::TxKind::Onchain,
                        created_at_ms: lij_core::tier2_wallet::now_ms(),
                        change_outpoint: result.change_outpoint.clone(),
                        change_value_sats: result.change_sats,
                        change_index: result.change_index,
                        broadcast_seen: false,
                        raw_tx_hex: None,
                        dest_addr: Some(r.dest.clone()),
                        dest_sats: Some(result.amount_sats),
                        fee_sats: Some(result.fee_sats),
                        fee_rate_sat_per_kw: Some(r.fee_rate_sat_per_kw),
                        dests: Vec::new(),
                    },
                ) {
                    log::error!("record pending on-chain chosen-coin send failed: {e}");
                }
                t2_note_send(storage.as_ref(), &result.txid, &result.raw_hex, Some(r.dest.as_str()), &[]);   // v298
            }
            let json = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v305 (S54, DP 2026-10-02 13:50 "Go ahead" — SEVERAL RECIPIENTS IN ONE SEND): `req` is JSON {"recipients":
    /// [{"dest","amount_sats"?}], "fee_rate_sat_per_kw", "inputs"?: [{"txid","vout"}]} — a missing amount on the LAST
    /// recipient = everything left after the others and the fee (Max); chosen coins = exactly those. One transaction:
    /// the recipients in order (vout 0 …), then the change. Returns SendResult JSON with "recipients" [{dest,
    /// amount_sats}]. The pending record carries every recipient so a fee bump rebuilds them all.
    #[wasm_bindgen]
    pub fn send_onchain_multi(&self, req: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let req = req.to_string();
        future_to_promise(async move {
            #[derive(serde::Deserialize)]
            struct Pin { txid: String, vout: u32 }
            #[derive(serde::Deserialize)]
            struct R { dest: String, #[serde(default)] amount_sats: Option<f64> }
            #[derive(serde::Deserialize)]
            struct Req { recipients: Vec<R>, fee_rate_sat_per_kw: u32, #[serde(default)] inputs: Option<Vec<Pin>> }
            let r: Req = serde_json::from_str(&req).map_err(|e| JsValue::from_str(&format!("send_onchain_multi: bad request: {e}")))?;
            let mut recipients = Vec::with_capacity(r.recipients.len());
            for (i, x) in r.recipients.iter().enumerate() {
                let amount = match x.amount_sats {
                    None => None,
                    Some(a) if a.is_finite() && a >= 1.0 && a.fract() == 0.0 => Some(a as u64),
                    Some(_) => return Err(JsValue::from_str(&format!("recipient {}: the amount must be a positive whole number of sats", i + 1))),
                };
                recipients.push(lij_core::onchain_send::Recipient { dest: x.dest.trim().to_string(), amount_sats: amount });
            }
            let pins: Option<Vec<(String, u32)>> = r.inputs.map(|v| v.into_iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect());
            if matches!(pins.as_ref(), Some(p) if p.is_empty()) {
                return Err(JsValue::from_str("send_onchain_multi: no coins chosen"));
            }
            let (root_key, independent, network) = {
                let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let (view, pending, marks) = {
                let storage = t2_storage(&root_key);
                let view = lij_core::tier2_wallet::load_view(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
                let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
                let marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
                (view, pending, marks)
            };
            let change_index = lij_core::tier2_wallet::next_change_index_marked(&view, &pending, &marks);   // v326 (Mix step 8): past every change index a pool was given
            let result = lij_core::onchain_send::build_and_send_multi(&root_key, independent, network, &recipients, r.fee_rate_sat_per_kw, change_index, &view, &pending, &marks, pins.as_deref())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            {
                let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);
                let first = result.recipients.first().cloned();
                if let Err(e) = lij_core::tier2_wallet::record_pending(
                    storage.as_ref(),
                    lij_core::tier2_wallet::PendingTx {
                        txid: result.txid.clone(),
                        spent_outpoints: result.spent_outpoints.clone(),
                        delta_sats: -((result.amount_sats as i64) + (result.fee_sats as i64)),
                        direction: lij_core::tier2_wallet::TxDirection::Sent,
                        kind: lij_core::tier2_wallet::TxKind::Onchain,
                        created_at_ms: lij_core::tier2_wallet::now_ms(),
                        change_outpoint: result.change_outpoint.clone(),
                        change_value_sats: result.change_sats,
                        change_index: result.change_index,
                        broadcast_seen: false,
                        raw_tx_hex: None,
                        dest_addr: first.as_ref().map(|f| f.dest.clone()),
                        dest_sats: first.as_ref().map(|f| f.amount_sats),
                        fee_sats: Some(result.fee_sats),
                        fee_rate_sat_per_kw: Some(r.fee_rate_sat_per_kw),
                        dests: if result.recipients.len() > 1 { result.recipients.iter().map(|p| (p.dest.clone(), p.amount_sats)).collect() } else { Vec::new() },
                    },
                ) {
                    log::error!("record pending on-chain send to several failed: {e}");
                }
                // v298: kept whole; the first sp1 recipient (if any) noted for the drill-down
                let sp1 = result.recipients.iter().map(|p| p.dest.clone()).find(|d| { let l = d.to_ascii_lowercase(); l.starts_with("sp1") || l.starts_with("tsp1") });
                let all: Vec<(String, u64)> = result.recipients.iter().map(|p| (p.dest.clone(), p.amount_sats)).collect();   // v306
                t2_note_send(storage.as_ref(), &result.txid, &result.raw_hex, sp1.as_deref(), &all);
            }
            let json = result.to_json().map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v305: the quote for send_onchain_multi — the SAME plan the builder makes (no keys, no network): {"amounts" (the
    /// last = its Max when its amount is missing), "total_sats", "fee_sats", "change_sats", "inputs", "spend",
    /// "sat_per_vb", "problem" (the builder's refusal in plain words, else null)}. `req` as send_onchain_multi's.
    #[wasm_bindgen]
    pub fn onchain_multi_quote(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Pin { txid: String, vout: u32 }
        #[derive(serde::Deserialize)]
        struct R { dest: String, #[serde(default)] amount_sats: Option<f64> }
        #[derive(serde::Deserialize)]
        struct Req { recipients: Vec<R>, fee_rate_sat_per_kw: u32, #[serde(default)] inputs: Option<Vec<Pin>> }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("onchain_multi_quote: bad request: {e}")))?;
        let recipients: Vec<lij_core::onchain_send::Recipient> = r.recipients.iter().map(|x| lij_core::onchain_send::Recipient {
            dest: x.dest.trim().to_string(),
            amount_sats: x.amount_sats.filter(|a| a.is_finite() && *a >= 0.0).map(|a| a as u64),
        }).collect();
        let pins: Option<Vec<(String, u32)>> = r.inputs.map(|v| v.into_iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect());
        let (root_key, _independent, network) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let view = lij_core::tier2_wallet::load_view(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
        let marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::onchain_send::multi_quote(&recipients, network, r.fee_rate_sat_per_kw, &view, &pending, &marks, pins.as_deref())
            .to_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v282 (S50, coin control cut 3): the picker's quote. `req` is JSON {"dest", "fee_rate_sat_per_kw",
    /// "inputs"?: [{"txid","vout"}], "amount_sats"?, "fill"?: bool} → CoinQuote JSON (chosen, chosen_sats,
    /// max_sats, need_sats, covered, short_sats, fill [...], fill_covers, sendable_sats, frozen_sats,
    /// problem). Storage only, no network.
    #[wasm_bindgen]
    pub fn onchain_quote(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Pin { txid: String, vout: u32 }
        #[derive(serde::Deserialize)]
        struct Req { #[serde(default)] dest: String, fee_rate_sat_per_kw: u32, #[serde(default)] inputs: Option<Vec<Pin>>, #[serde(default)] amount_sats: Option<f64>, #[serde(default)] fill: bool }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("onchain_quote: bad request: {e}")))?;
        let pins: Option<Vec<(String, u32)>> = r.inputs.map(|v| v.into_iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect());
        let amount = r.amount_sats.filter(|a| a.is_finite() && *a >= 1.0).map(|a| a as u64);
        let (root_key, _independent, network) = {
            let wallet = self
                .inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let view = lij_core::tier2_wallet::load_view(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
        let marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::onchain_send::coin_quote(&r.dest, network, r.fee_rate_sat_per_kw, &view, &pending, &marks, pins.as_deref(), amount, r.fill)
            .to_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v281 (S50, coin control): the exact Max at this fee rate — what a one-output send
    /// of every sendable coin delivers, from the builder's own candidate set and fee
    /// arithmetic (MaxQuote JSON: max_sats, fee_sats, inputs, total_sats, frozen_sats,
    /// frozen_count, sat_per_vb). `dest` may be empty while the user is still typing.
    /// Storage only, no network.
    #[wasm_bindgen]
    pub fn onchain_max(&self, dest: &str, fee_rate_sat_per_kw: u32) -> Result<String, JsValue> {
        let (root_key, _independent, network) = {
            let wallet = self
                .inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let view = lij_core::tier2_wallet::load_view(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
        let marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::onchain_send::max_sendable(dest, network, fee_rate_sat_per_kw, &view, &pending, &marks)
            .to_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v281 (S50, coin control): mark one coin. `req` is JSON {"txid","vout", "frozen"?:
    /// bool, "note"?: string} — a field left out is left alone; a note is cleaned and
    /// capped at 120 code points in the engine. Answers the coin's mark as stored (JSON
    /// {"txid","vout","frozen","note","ts_ms"}) plus "frozen_count". Written to the
    /// marks store (its own encrypted key — a sync in flight cannot clobber it).
    #[wasm_bindgen]
    pub fn coin_mark(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { txid: String, vout: u32, frozen: Option<bool>, note: Option<String> }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("coin_mark: bad request: {e}")))?;
        if r.txid.len() != 64 || !r.txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(JsValue::from_str("coin_mark: txid must be 64 hex characters"));
        }
        let (root_key, _independent, _network) = {
            let wallet = self
                .inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let mut marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let now = lij_core::tier2_wallet::now_ms();
        if let Some(f) = r.frozen {
            marks.set_frozen(&r.txid, r.vout, f, now);
        }
        if let Some(n) = r.note.as_deref() {
            marks.set_note(&r.txid, r.vout, n, now);
        }
        lij_core::tier2_wallet::save_marks(storage.as_ref(), &marks)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let m = marks.get(&r.txid, r.vout).cloned().unwrap_or_default();
        log::info!("[coin] mark {}:{} frozen={} note={}ch", &r.txid[..12], r.vout, m.frozen, m.note.chars().count());
        let out = serde_json::json!({
            "txid": r.txid.to_ascii_lowercase(),
            "vout": r.vout,
            "frozen": m.frozen,
            "note": m.note,
            "ts_ms": m.ts_ms,
            "frozen_count": marks.frozen_count(),
        });
        Ok(out.to_string())
    }

    // ── v323 (S58, Mix step 7 — tatara-rollout-r3 step 7; spec v0.10 §5, §8, §9, §13): the wallet's side of a Mix. The
    // engine room only: the page drives an attempt in step 8. Every call below works on the sealed store (t2_storage). ──

    /// The Tatara key's public half (33 bytes, hex) — what Mix on registers with the provider (door 1). From the 12 words
    /// on a path of its own (DP 23:21), never stored. Answers JSON {"tatara_pk", "join_message"} for `ts` (seconds): the
    /// page has the node key sign join_message (sign_message) and sends both.
    #[wasm_bindgen]
    pub fn mix_tatara_pub(&self, ts: u64) -> Result<String, JsValue> {
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let pk = lij_core::tatara::client::tatara_pk(&root_key.tatara_key()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pk_hex = hex::encode(pk);
        Ok(serde_json::json!({ "tatara_pk": pk_hex, "join_message": lij_core::tatara::client::ring_join_message(&pk_hex, ts) }).to_string())
    }

    /// A new attempt's payout and change, handed out and marked together. `choice` is JSON {"to":"this_wallet"} or
    /// {"to":"outside","address":"bc1p…"} (another wallet's taproot address — the room DP asked for; the screen comes
    /// later). Answers {"payout_address","payout_spk_hex","payout_index","change_index","change_spk_hex"} or a refusal
    /// in plain words.
    #[wasm_bindgen]
    pub fn mix_hand_out(&self, choice: &str) -> Result<String, JsValue> {
        let c: lij_core::tatara::wallet::PayoutChoice = serde_json::from_str(choice).map_err(|e| JsValue::from_str(&format!("mix_hand_out: bad request: {e}")))?;
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let h = lij_core::tatara::store::hand_out(storage.as_ref(), &root_key, &c).map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[mix] handed out payout {} and change {}", h.payout_index.map(|i| format!("m/86 #{i}")).unwrap_or_else(|| "to another wallet".into()), h.change_index);
        serde_json::to_string(&h).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Hold coins for a Mix, or free them. `req` JSON {"coins":[["txid",vout],…],"hold":true|false}. Freeing leaves a coin
    /// an unsettled attempt record names held (only its settlement frees it). Answers {"held","freed"}.
    #[wasm_bindgen]
    pub fn mix_hold(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { coins: Vec<(String, u32)>, hold: bool }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("mix_hold: bad request: {e}")))?;
        if r.coins.iter().any(|(t, _)| t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit())) {
            return Err(JsValue::from_str("mix_hold: each txid must be 64 hex characters"));
        }
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let (held, freed) = if r.hold {
            lij_core::tatara::store::lock(storage.as_ref(), &r.coins, lij_core::tier2_wallet::now_ms()).map_err(|e| JsValue::from_str(&e.to_string()))?;
            (r.coins.len(), 0)
        } else {
            (0, lij_core::tatara::store::unlock(storage.as_ref(), &r.coins).map_err(|e| JsValue::from_str(&e.to_string()))?.len())
        };
        log::info!("[mix] hold: {held} held, {freed} freed");
        Ok(serde_json::json!({ "held": held, "freed": freed }).to_string())
    }

    /// Wipe an attempt record and free its coins — at once for an attempt that ended before this phone's coin
    /// signature (§9 rule 3). Marks the backup dirty (a record wiped is an upload trigger); the page pushes a clean kit
    /// twice when this answers true.
    #[wasm_bindgen]
    pub fn mix_record_wipe(&self, id: &str) -> Result<bool, JsValue> {
        let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let (root_key, _independent, _network) = wallet.onchain_handles();
        let storage = t2_storage(&root_key);
        let gone = lij_core::tatara::store::record_wipe(storage.as_ref(), id).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if gone {
            wallet.node().backup_dirty_handle().store(true, std::sync::atomic::Ordering::Relaxed);
            log::info!("[mix] record wiped (ended before the coin signature)");
        }
        Ok(gone)
    }

    /// How many attempt records this phone keeps (0 = the settle pass has nothing to do).
    #[wasm_bindgen]
    pub fn mix_records_count(&self) -> Result<u32, JsValue> {
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        Ok(lij_core::tatara::records::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?.len() as u32)
    }

    /// At start and after a restore (§9 rule 7): the holds become exactly the coins a seat on this phone
    /// (`seat_coins` JSON [["txid",vout],…]) or an unsettled record names. Answers {"freed","added"}.
    #[wasm_bindgen]
    pub fn mix_reconcile(&self, seat_coins: &str) -> Result<String, JsValue> {
        let coins: Vec<(String, u32)> = serde_json::from_str(seat_coins).map_err(|e| JsValue::from_str(&format!("mix_reconcile: bad request: {e}")))?;
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let (freed, added) = lij_core::tatara::store::reconcile(storage.as_ref(), &coins, lij_core::tier2_wallet::now_ms()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if !freed.is_empty() || !added.is_empty() { log::info!("[mix] holds reconciled: {} freed, {} added", freed.len(), added.len()); }
        Ok(serde_json::json!({ "freed": freed.len(), "added": added.len() }).to_string())
    }

    /// The chain decides (§8 rule 6; §9 rule 4 — a restored record is watched, never resumed): every record is checked
    /// against the wallet's ledger — its exits SENT, in order, once its funding spent this phone's coin (again at most
    /// every 10 minutes until the payout is settled; "already known" is fine), WIPED once settled (its coins freed, the
    /// backup marked dirty), or watched. A payout to another wallet's address is not in this wallet's ledger: the depth
    /// of EVERY exit of that pool is asked of the chain servers, so the question does not single out the payout. Answers
    /// the report JSON {"send":[[id,[hex…]]…],"wiped":[[id,why]…],"watching","unreadable","sent":[[id,accepted,refused]…]};
    /// the page pushes a clean kit twice when "wiped" is not empty.
    #[wasm_bindgen]
    pub fn mix_settle(&self) -> js_sys::Promise {
        let (root_key, independent, dirty) = match self.inner.try_lock() {
            Ok(w) => { let (r, i, _n) = w.onchain_handles(); (r, i, w.node().backup_dirty_handle()) }
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        let inner = self.inner.clone();
        future_to_promise(async move {
            let storage = t2_storage(&root_key);
            let recs = lij_core::tatara::records::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
            if recs.is_empty() {
                return Ok(JsValue::from_str(&serde_json::to_string(&lij_core::tatara::store::SettleReport::default()).unwrap_or_default()));
            }
            let first = lij_core::tatara::store::settle_pass(storage.as_ref(), &|_| None).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let mut wiped = first.wiped.clone();
            // another wallet's payout: ask the depth of every exit of its pool
            let outside: Vec<&lij_core::tatara::records::StoredRecord> = recs.iter()
                .filter(|r| r.payout_index.is_none() && first.send.iter().any(|(id, _)| *id == r.id))
                .collect();
            let report = if outside.is_empty() { first } else {
                let mut depths: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
                if let Ok(tip) = independent.fetch_tip_height().await {
                    for r in &outside {
                        for h in &r.exits_hex {
                            let Ok(tx) = bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(h) else { continue };
                            let txid = tx.compute_txid().to_string();
                            if let Ok(t) = independent.fetch_tx(&txid).await {
                                if let (true, Some(bh)) = (t.confirmed, t.block_height) { depths.insert(txid, tip.saturating_sub(bh).saturating_add(1)); }
                            }
                        }
                    }
                }
                let second = lij_core::tatara::store::settle_pass(storage.as_ref(), &|t| depths.get(t).copied()).map_err(|e| JsValue::from_str(&e.to_string()))?;
                wiped.extend(second.wiped.clone());
                lij_core::tatara::store::SettleReport { wiped: wiped.clone(), ..second }
            };
            let now = js_sys::Date::now();
            let mut sent: Vec<(String, usize, usize)> = Vec::new();
            for (id, txs) in &report.send {
                let due = MIX_LAST_SEND.with(|m| m.borrow().get(id).map_or(true, |t| now - *t >= 600_000.0));
                if !due { continue; }
                MIX_LAST_SEND.with(|m| { m.borrow_mut().insert(id.clone(), now); });
                let (mut ok, mut no) = (0usize, 0usize);
                for h in txs {
                    let Ok(bytes) = hex::decode(h) else { no += 1; continue };
                    match independent.broadcast_raw_tx(&bytes).await {
                        Ok(()) => ok += 1,
                        Err(e) if e.to_string().to_ascii_lowercase().contains("already") => ok += 1,
                        Err(e) => { no += 1; log::warn!("[mix] an exit was refused: {e}"); }
                    }
                }
                log::info!("[mix] exits sent for a funded pool: {ok} accepted, {no} refused");
                sent.push((id.clone(), ok, no));
            }
            if !report.wiped.is_empty() {
                dirty.store(true, std::sync::atomic::Ordering::Relaxed);
                for (id, why) in &report.wiped {
                    log::info!("[mix] record wiped — {why}");
                    // Phase 1b (§6.3.4): a channel record whose coin went elsewhere — the pool's funding can never reach
                    // the chain, so the channel it would have funded is dropped (closed without broadcasting)
                    if why.contains("went elsewhere") {
                        if let Some(cid) = recs.iter().find(|r| r.id == *id).and_then(|r| r.channel_id()) {
                            match inner.lock().map_err(|e| format!("Lock error: {e}")).and_then(|w| w.node().drop_pool_channel_by_id(&cid, "the pool's coin went elsewhere, 6 blocks deep").map_err(|e| e.to_string())) {
                                Ok(true) => log::info!("[mix] the pool channel {cid} dropped with its record"),
                                Ok(false) => log::info!("[mix] the pool channel {cid} is not a channel to drop (open, or gone)"),
                                Err(e) => log::warn!("[mix] the pool channel {cid} could not be dropped: {e}"),
                            }
                        }
                    }
                }
            }
            let mut out = serde_json::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))?;
            if let Some(o) = out.as_object_mut() { o.insert("sent".into(), serde_json::json!(sent)); }
            Ok(JsValue::from_str(&out.to_string()))
        })
    }

    /// v323 (§13): what an open WOULD spend — `req` JSON {"channel_sats","fee_rate_sat_per_vb","inputs"?:[{"txid","vout"}]}
    /// — answers {"inputs","fee_sats","mixed_inputs","links_mixed"} (the sheet's mixed-coin warning: links_mixed) or
    /// {"problem"} in plain words. The open's own pick.
    #[wasm_bindgen]
    pub fn lsp_channel_open_pick(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Pin { txid: String, vout: u32 }
        #[derive(serde::Deserialize)]
        struct Req { channel_sats: u64, fee_rate_sat_per_vb: f64, #[serde(default)] inputs: Option<Vec<Pin>> }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("lsp_channel_open_pick: bad request: {e}")))?;
        let pins: Option<Vec<(String, u32)>> = r.inputs.map(|v| v.into_iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect());
        let (root_key, _independent, _network) = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let rate = ((r.fee_rate_sat_per_vb * 250.0).round() as u32).max(250);
        match lij_core::channel_open::funding_pick_quote(storage.as_ref(), r.channel_sats, rate, pins.as_deref()) {
            Ok(q) => serde_json::to_string(&q).map_err(|e| JsValue::from_str(&e.to_string())),
            Err(e) => Ok(serde_json::json!({ "problem": e.to_string() }).to_string()),
        }
    }

    // ── step 8 (S58, DP 2026-10-13 00:33 "Go ahead with Step 8"): the Mix's seats and attempts, for the page. The logic
    // is lij-core's (tatara::store, tatara::phone — tested natively as whole pools of 3 and 6 and three wallets from Join
    // to settlement); these only carry JSON. ──

    /// Join: a seat on the provider's waiting list. `req` JSON {"provider_pk","endpoint","size","coins":[["txid",vout]…],
    /// "payout":{"to":"this_wallet"}|{"to":"outside","address"},"rate_at_join","ts"}. The seat's key is fresh; the coins
    /// are held from now. Answers {"seat_pk","body"} — POST body to the provider's /tatara/seat, signed by the node key.
    #[wasm_bindgen]
    pub fn mix_seat_new(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { #[serde(default)] provider_pk: String, endpoint: String, size: u64, coins: Vec<(String, u32)>, payout: lij_core::tatara::wallet::PayoutChoice, rate_at_join: u64, ts: u64, #[serde(default)] route: Option<String>, #[serde(default)] public: bool, #[serde(default)] public_ok: bool }   // v336: `public` + `endpoint` the relay · v343: `public_ok` — a provider's seat may take a room the provider hosts
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("mix_seat_new: bad request: {e}")))?;
        // Phase 1b: the route — "chain" (the payout on-chain) or "channel" (the payout this wallet's channel's funding)
        // v335 (S59, DP 16:19 — the close pools were stepped back; a closed channel's coin sits in the on-chain pools): the
        // route is "chain" or "channel"; v334's "close" word is gone with adapter 0.105.1 (which answers it 400)
        let route = match r.route.as_deref().unwrap_or("chain") { "chain" => "chain", "channel" => "channel", other => return Err(JsValue::from_str(&format!("mix_seat_new: no such route: {other}"))) }.to_string();
        let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let (root_key, _independent, _network) = wallet.onchain_handles();
        let storage = t2_storage(&root_key);
        let seat = lij_core::tatara::store::Seat {
            seat_id: String::new(), seat_secret_hex: String::new(), seat_pk: String::new(),
            provider_pk: r.provider_pk.to_ascii_lowercase(), endpoint: r.endpoint, size: r.size, route,
            coins: r.coins.into_iter().map(|(t, v)| (t.to_ascii_lowercase(), v)).collect(), coin_rows: vec![], payout: r.payout, rate_at_join: r.rate_at_join, since_ms: 0,
            public: r.public,   // v336   // v332: seat_new copies the rows
            public_ok: r.public_ok && !r.public,   // v343
        };
        let seat = lij_core::tatara::store::seat_new(storage.as_ref(), seat, &lij_core::tatara::store::fresh32(), lij_core::tier2_wallet::now_ms())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if seat.public {
            // v336: no provider to ask — the seat stands on its own; the page watches the relay for a pool of its size
            log::info!("[mix] a public seat taken for {} sats on {} — its coin held", seat.size, seat.endpoint);
            return Ok(serde_json::json!({ "seat_pk": seat.seat_pk, "body": serde_json::Value::Null }).to_string());
        }
        let node_pk = wallet.node_pubkey().map_err(|e| JsValue::from_str(&e.to_string()))?;
        let body = lij_core::tatara::store::seat_request(&seat, &node_pk, r.ts, &|m| wallet.sign_message(m))
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[mix] seat taken for {} sats{} — its coin held", seat.size, if seat.route == "channel" { " (a channel pool)" } else { "" });
        Ok(serde_json::json!({ "seat_pk": seat.seat_pk, "body": body }).to_string())
    }

    /// The provider answered the seat request: its id.
    #[wasm_bindgen]
    pub fn mix_seat_confirm(&self, seat_pk: &str, seat_id: &str) -> Result<(), JsValue> {
        let storage = mix_storage(&self.inner)?;
        lij_core::tatara::store::seat_confirm(storage.as_ref(), seat_pk, seat_id).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Leave (or a refused or removed seat): the seat goes, its coins are freed (unless an unsettled record names one).
    #[wasm_bindgen]
    pub fn mix_seat_drop(&self, seat_pk: &str) -> Result<bool, JsValue> {
        let storage = mix_storage(&self.inner)?;
        let gone = lij_core::tatara::store::seat_drop(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if gone.is_some() { log::info!("[mix] seat left — its coin freed"); }
        Ok(gone.is_some())
    }

    /// This phone's seats, without their secrets: [{"seat_pk","seat_id","provider_pk","endpoint","size","route","coins",
    /// "payout","rate_at_join","since_ms"}…].
    #[wasm_bindgen]
    pub fn mix_seats(&self) -> Result<String, JsValue> {
        let storage = mix_storage(&self.inner)?;
        let all = lij_core::tatara::store::seats(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let v: Vec<serde_json::Value> = all.iter().map(|s| serde_json::json!({
            "seat_pk": s.seat_pk, "seat_id": s.seat_id, "provider_pk": s.provider_pk, "endpoint": s.endpoint, "size": s.size,
            "route": s.route, "coins": s.coins, "payout": s.payout, "rate_at_join": s.rate_at_join, "since_ms": s.since_ms,
        })).collect();
        Ok(serde_json::Value::Array(v).to_string())
    }

    /// A seat's request to its provider, signed by the seat key: `ask` JSON {"action": checkin|leave|pause|resume|open|
    /// report|announce|backup, "attempt_id"?, "outcome"?, "announcement"?, "funding_hex"?, "exits"?}. Answers the POST body.
    #[wasm_bindgen]
    pub fn mix_seat_body(&self, seat_pk: &str, ask: &str, ts: u64) -> Result<String, JsValue> {
        let a: lij_core::tatara::store::SeatAsk = serde_json::from_str(ask).map_err(|e| JsValue::from_str(&format!("mix_seat_body: bad request: {e}")))?;
        let storage = mix_storage(&self.inner)?;
        let seat = lij_core::tatara::store::seat_by_pk(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let b = lij_core::tatara::store::seat_body(&seat, &a, ts).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(b.to_string())
    }

    /// A provider's notice {body, sig} for a seat, checked against the seat's provider's node key before anything in it
    /// is read. Answers the notice (JSON, "type" first) or an error.
    #[wasm_bindgen]
    pub fn mix_notice(&self, seat_pk: &str, body: &str, sig: &str) -> Result<String, JsValue> {
        let storage = mix_storage(&self.inner)?;
        let seat = lij_core::tatara::store::seat_by_pk(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let n = lij_core::tatara::store::read_notice(&seat, body, sig).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&n).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The creating phone ("create" notice): `start` JSON {"seat_pk","attempt_id","size","peers","relay","sizes",
    /// "max_fee_sat_vb","refused"?}, the pool's fee rate, and the other opened seats' keys (JSON array). Answers {"out",
    /// "announcement","relay_filter","pool_pk"} — the page hands the announcement to the provider (announce), then joins
    /// the relay with the token.
    #[wasm_bindgen]
    pub fn mix_attempt_create(&self, start: &str, fee_rate_sat_vb: u32, seat_pks: &str) -> Result<String, JsValue> {
        let st: lij_core::tatara::store::AttemptStart = serde_json::from_str(start).map_err(|e| JsValue::from_str(&format!("mix_attempt_create: bad request: {e}")))?;
        let others: Vec<String> = serde_json::from_str(seat_pks).map_err(|e| JsValue::from_str(&format!("mix_attempt_create: bad seat keys: {e}")))?;
        let (root_key, storage, dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        mix_seat_claim(&st.attempt_id, &st.seat_pk)?;   // v340
        let (_seat, c, note) = lij_core::tatara::store::attempt_common(storage.as_ref(), &root_key, &st, now).map_err(|e| JsValue::from_str(&e.to_string()))?;   // v332: the ledger note
        let (mut phone, ann, out) = lij_core::tatara::phone::Phone::create(c, fee_rate_sat_vb as u64, &others).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (out, d) = lij_core::tatara::store::after(storage.as_ref(), &mut phone, out, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if d { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
        let filter = phone.relay_filter();
        let pool_pk = phone.pool_pk().to_string();
        MIX_PHONES.with(|m| { m.borrow_mut().insert(st.attempt_id.clone(), phone); });
        log::info!("[mix] pool created for attempt {}", &st.attempt_id[..8.min(st.attempt_id.len())]);
        Ok(serde_json::json!({ "out": out, "announcement": ann, "relay_filter": filter, "pool_pk": pool_pk, "note": note }).to_string())
    }

    /// A joining phone ("announcement" notice): `start` as for create, and the announcement. Answers {"out",
    /// "relay_filter","pool_pk"} — or the refusal in plain words (a pool not the provider's, fees above the limit…).
    #[wasm_bindgen]
    pub fn mix_attempt_join(&self, start: &str, announcement: &str) -> Result<String, JsValue> {
        let st: lij_core::tatara::store::AttemptStart = serde_json::from_str(start).map_err(|e| JsValue::from_str(&format!("mix_attempt_join: bad request: {e}")))?;
        let (root_key, storage, dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        mix_seat_claim(&st.attempt_id, &st.seat_pk)?;   // v340
        if let Ok(ev) = serde_json::from_str::<lij_core::nwc::Event>(announcement) { if let Ok(pe) = serde_json::from_str::<serde_json::Value>(&ev.content) { if let Some(id) = pe.get("id").and_then(|x| x.as_str()) { mix_refuse_known_pool(storage.as_ref(), id)?; } } }   // v340 (finding 3)
        let (seat, c, note) = lij_core::tatara::store::attempt_common(storage.as_ref(), &root_key, &st, now).map_err(|e| JsValue::from_str(&e.to_string()))?;   // v332: the ledger note
        let sk = lij_core::tatara::store::seat_secret(&seat).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (mut phone, out) = lij_core::tatara::phone::Phone::join(c, announcement, &sk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (out, d) = lij_core::tatara::store::after(storage.as_ref(), &mut phone, out, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if d { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
        let filter = phone.relay_filter();
        let pool_pk = phone.pool_pk().to_string();
        MIX_PHONES.with(|m| { m.borrow_mut().insert(st.attempt_id.clone(), phone); });
        log::info!("[mix] joined the pool of attempt {}", &st.attempt_id[..8.min(st.attempt_id.len())]);
        Ok(serde_json::json!({ "out": out, "relay_filter": filter, "pool_pk": pool_pk, "note": note }).to_string())
    }

    /// v336 (Phase 2a): a public seat joins a pool the page found on its relay (a signed kind-2022 event: the public
    /// Joinstr code's, or another LiJ's public pool). The engine checks the pool against the seat before anything is
    /// sent (its size, the fee limit, the network, its timeout; a provider's pool is refused — that goes through the
    /// provider), then answers {"out" (the join request to post), "relay_filter" (the join's own key: subscribe to it),
    /// "attempt_id", "pool_id", "pool_pk", "note"}. The credentials then come through mix_public_event.
    #[wasm_bindgen]
    pub fn mix_public_join(&self, seat_pk: &str, relay: &str, pool_event: &str) -> Result<String, JsValue> {   // v344: the hosted room's join carries nothing — the join key is named to the provider at `open` (v342's token withdrawn, review 2b #4/#5)
        let (root_key, storage, _dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        let seat = lij_core::tatara::store::seat_by_pk(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        // v337 (DP 21:39, the combined list): any on-chain seat may take a public room — a provider's seat included;
        // `relay` is the public relay the page found the room on (a public seat's own endpoint when it is one)
        let relay = if seat.public { seat.endpoint.clone() } else { relay.trim().to_string() };
        let pe = lij_core::tatara::phone::public_pool_summary(pool_event).map_err(|e| JsValue::from_str(&format!("mix_public_join: {e:#}")))?;
        let st = lij_core::tatara::store::public_start(&seat, &relay, &pe.id, pe.peers).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let attempt_id = st.attempt_id.clone();
        let busy = MIX_JOINS.with(|m| m.borrow().contains_key(&attempt_id)) || MIX_PHONES.with(|m| m.borrow().contains_key(&attempt_id));
        if busy { return Err(JsValue::from_str("mix_public_join: this pool is already being joined")); }
        mix_refuse_known_pool(storage.as_ref(), &pe.id)?;   // v340 (finding 3)
        // v344 (review 2b #1): the seat is claimed only once the join is built — a refused announcement (a stranger's
        // room of the wrong shape) used to leave the claim behind and lock the seat out of every later pool on this page
        let (_seat, c, note) = lij_core::tatara::store::attempt_common(storage.as_ref(), &root_key, &st, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (join, out) = lij_core::tatara::phone::PublicJoin::new(c, pool_event).map_err(|e| JsValue::from_str(&format!("{e:#}")))?;
        mix_seat_claim(&attempt_id, &st.seat_pk)?;          // v340 (finding 6)
        let filter = join.relay_filter();
        let (pool_id, pool_pk) = (join.pool_id().to_string(), join.pool_pk().to_string());
        let join_pk = join.join_pk().to_string();
        MIX_JOINS.with(|m| { m.borrow_mut().insert(attempt_id.clone(), join); });
        log::info!("[mix] a public join request goes out for pool {}", &pool_id[..8.min(pool_id.len())]);
        Ok(serde_json::json!({ "out": out, "relay_filter": filter, "attempt_id": attempt_id, "pool_id": pool_id, "pool_pk": pool_pk, "join_pk": join_pk, "note": note }).to_string())   // v344: `join_pk` — named to the provider at `open` for a hosted room
    }

    /// v345: the join sent again (a fresh event from the same key) while it waits — every 20 s or so within the 90 s.
    /// Answers {"out"} to post, or an error when the join is gone or was sent enough.
    #[wasm_bindgen]
    pub fn mix_public_join_again(&self, attempt_id: &str) -> Result<String, JsValue> {
        let now = mix_now();
        let out = MIX_JOINS.with(|m| { let mut m = m.borrow_mut(); match m.get_mut(attempt_id) { Some(j) => j.again(now).map_err(|e| JsValue::from_str(&format!("{e:#}"))), None => Err(JsValue::from_str("no such public join on this page")) } })?;
        Ok(serde_json::json!({ "out": out }).to_string())
    }

    /// v344 (review 2b #1): would this seat take this room? The full check a join runs (the announcement's signature and
    /// options, the size, the fee against the seat's limit, the route, the network) with no side effect — the page lists
    /// and auto-joins only rooms that pass, so a stranger's odd-shaped announcement never costs a seat anything.
    #[wasm_bindgen]
    pub fn mix_public_fits(&self, seat_pk: &str, relay: &str, pool_event: &str) -> Result<String, JsValue> {
        let (root_key, storage, _dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        let seat = lij_core::tatara::store::seat_by_pk(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let relay = if seat.public { seat.endpoint.clone() } else { relay.trim().to_string() };
        let verdict = (|| -> Result<(), String> {
            let pe = lij_core::tatara::phone::public_pool_summary(pool_event).map_err(|e| format!("{e:#}"))?;
            let st = lij_core::tatara::store::public_start(&seat, &relay, &pe.id, pe.peers).map_err(|e| e.to_string())?;
            if lij_core::tatara::store::record_exists(storage.as_ref(), &pe.id).map_err(|e| e.to_string())? { return Err("a pool this wallet already holds a record for".into()); }
            let (_seat, c, _note) = lij_core::tatara::store::attempt_common(storage.as_ref(), &root_key, &st, now).map_err(|e| e.to_string())?;
            lij_core::tatara::phone::public_pool_fits(&c, pool_event).map_err(|e| format!("{e:#}"))
        })();
        Ok(match verdict { Ok(()) => serde_json::json!({ "fits": true }), Err(why) => serde_json::json!({ "fits": false, "why": why }) }.to_string())
    }

    /// v336: what a pool announcement the page found on a public relay says (the engine's strict parse: a pool it would
    /// refuse is an error here, so the page lists only pools it can join) — {"id","pool_pk","peers","denomination",
    /// "fee_rate","timeout","network","lij"}.
    #[wasm_bindgen]
    pub fn mix_public_peek(&self, pool_event: &str) -> Result<String, JsValue> {
        let s = lij_core::tatara::phone::public_pool_summary(pool_event).map_err(|e| JsValue::from_str(&format!("{e:#}")))?;
        Ok(serde_json::to_string(&s).map_err(|e| JsValue::from_str(&e.to_string()))?)
    }

    /// v336: an event read under a public join's filter. Answers {"joined": bool, "rejected": bool, "out", and when
    /// joined "relay_filter" (the pool's — switch the subscription) and "pool_pk"}; once joined the attempt runs through
    /// mix_attempt_event / mix_attempt_tick as any other. A join that is neither is still waiting.
    #[wasm_bindgen]
    pub fn mix_public_event(&self, attempt_id: &str, event: &str) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        let join = MIX_JOINS.with(|m| m.borrow_mut().remove(attempt_id)).ok_or_else(|| JsValue::from_str("no such public join on this page"))?;
        match join.relay_event(event, now).map_err(|e| JsValue::from_str(&format!("{e:#}")))? {
            lij_core::tatara::phone::Joined::Waiting(j) => { let refused = j.was_refused(); MIX_JOINS.with(|m| { m.borrow_mut().insert(attempt_id.to_string(), j); }); Ok(serde_json::json!({ "joined": false, "rejected": false, "refused_heard": refused }).to_string()) }   // v344: a refusal is advisory — the join waits its 90 s (mix_public_timed_out then says "the pool said it is full")
            lij_core::tatara::phone::Joined::Rejected => { MIX_SEAT_OF.with(|m| { m.borrow_mut().remove(attempt_id); }); log::info!("[mix] the public pool refused the join"); Ok(serde_json::json!({ "joined": false, "rejected": true }).to_string()) }
            lij_core::tatara::phone::Joined::Phone(mut phone, out) => {
                let (out, d) = lij_core::tatara::store::after(storage.as_ref(), &mut phone, out, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
                if d { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
                let filter = phone.relay_filter();
                let pool_pk = phone.pool_pk().to_string();
                MIX_PHONES.with(|m| { m.borrow_mut().insert(attempt_id.to_string(), phone); });
                log::info!("[mix] joined the public pool of attempt {}", &attempt_id[..16.min(attempt_id.len())]);
                Ok(serde_json::json!({ "joined": true, "rejected": false, "out": out, "relay_filter": filter, "pool_pk": pool_pk }).to_string())
            }
        }
    }

    /// v339 (DP 2026-10-14 22:29): this phone leaves a running attempt on purpose — before its coin signature. The
    /// members are told at once (an abort), the attempt stops with nothing moved and nobody named; the record, if
    /// written, is wiped. Answers the Out JSON (its `stopped`). After the coin signature nothing happens.
    #[wasm_bindgen]
    pub fn mix_attempt_leave(&self, attempt_id: &str) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.leave(now))
    }

    /// v336: a public join's clock — answers the reason (and forgets the join) when it has waited too long or the pool's
    /// own time ran out; null while it may still be answered.
    #[wasm_bindgen]
    pub fn mix_public_timed_out(&self, attempt_id: &str) -> Result<JsValue, JsValue> {
        let now = mix_now();
        let why = MIX_JOINS.with(|m| m.borrow().get(attempt_id).and_then(|j| j.timed_out(now)));
        match why {
            Some(w) => { MIX_JOINS.with(|m| { m.borrow_mut().remove(attempt_id); }); MIX_SEAT_OF.with(|m| { m.borrow_mut().remove(attempt_id); }); Ok(JsValue::from_str(&w)) }
            None => Ok(JsValue::NULL),
        }
    }

    /// v336: a public seat creates a pool on its relay — `peers` people, `fee_rate_sat_vb` (within the seat's own fee
    /// limit). Answers {"out", "announcement" (post it on the relay as ["EVENT", e]), "relay_filter", "attempt_id",
    /// "pool_id", "pool_pk", "note"}; the phone answers the join requests itself through mix_attempt_event.
    #[wasm_bindgen]
    pub fn mix_public_create(&self, seat_pk: &str, relay: &str, fee_rate_sat_vb: u32, peers: u32) -> Result<String, JsValue> {
        let (root_key, storage, dirty) = mix_handles(&self.inner)?;
        let now = mix_now();
        let seat = lij_core::tatara::store::seat_by_pk(storage.as_ref(), seat_pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let relay = if seat.public { seat.endpoint.clone() } else { relay.trim().to_string() };   // v337: any on-chain seat
        if !(2..=12).contains(&peers) { return Err(JsValue::from_str("mix_public_create: a pool is 2 to 12 people")); }
        let pool_tag = hex::encode(&lij_core::tatara::store::fresh32()[..8]);
        let st = lij_core::tatara::store::public_start(&seat, &relay, &pool_tag, peers as usize).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (_seat, c, note) = lij_core::tatara::store::attempt_common(storage.as_ref(), &root_key, &st, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (mut phone, ann, out) = lij_core::tatara::phone::Phone::create_public(c, fee_rate_sat_vb as u64).map_err(|e| JsValue::from_str(&format!("{e:#}")))?;
        mix_seat_claim(&st.attempt_id, &st.seat_pk)?;   // v340 · v344: after the pool is built (review 2b #1)
        let (out, d) = lij_core::tatara::store::after(storage.as_ref(), &mut phone, out, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if d { dirty.store(true, std::sync::atomic::Ordering::Relaxed); }
        let filter = phone.relay_filter();
        let (pool_id, pool_pk) = (phone.record_id().to_string(), phone.pool_pk().to_string());
        let attempt_id = st.attempt_id.clone();
        MIX_PHONES.with(|m| { m.borrow_mut().insert(attempt_id.clone(), phone); });
        log::info!("[mix] a public pool created ({peers} people) for attempt {}", &attempt_id[..16.min(attempt_id.len())]);
        Ok(serde_json::json!({ "out": out, "announcement": ann, "relay_filter": filter, "attempt_id": attempt_id, "pool_id": pool_id, "pool_pk": pool_pk, "note": note }).to_string())
    }

    /// v336 (Phase 2a): a coin check with no provider — this wallet's own explorers (the independent quorum) answer
    /// for one coin the Out asked about: known and confirmed, the output as registered (value and script), unspent.
    /// No answer from the explorers = no answer (the attempt stops naming no one, as with a provider's silence).
    /// Answers the Out JSON after the result reaches the attempt.
    #[wasm_bindgen]
    pub fn mix_attempt_coin_quorum(&self, attempt_id: &str, ask: &str) -> js_sys::Promise {
        let a: lij_core::tatara::phone::CoinAsk = match serde_json::from_str(ask) { Ok(a) => a, Err(e) => return js_sys::Promise::reject(&JsValue::from_str(&format!("mix_attempt_coin_quorum: bad ask: {e}"))) };
        let independent = match self.inner.try_lock() {
            Ok(w) => w.onchain_handles().1,
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        let inner = self.inner.clone();
        let attempt_id = attempt_id.to_string();
        future_to_promise(async move {
            let txid = a.txid.to_ascii_lowercase();
            // v341 (the security review's recommendation 1): two explorers must agree; one alone, or a split, is no answer
            let ok: Option<bool> = independent.coin_check_agreed(&txid, a.vout, a.amount_sat, &a.script_pubkey_hex).await;
            match ok {
                Some(false) => log::warn!("[mix] a member's coin failed the wallet's own coin check (two explorers agree)"),
                None => log::warn!("[mix] the coin check got no agreed answer from the explorers"),
                _ => {}
            }
            let (_root_key, storage, dirty) = mix_handles(&inner)?;
            let s = mix_step(&attempt_id, storage.as_ref(), &dirty, &inner, |p, now| p.coin_result(&a.txid, a.vout, ok, now))?;
            Ok(JsValue::from_str(&s))
        })
    }

    /// An event the page read from the pool's relay. Answers the Out JSON ({"relay","payout","checks","save"(null),
    /// "funding_signed","complete","stopped","phase"}).
    #[wasm_bindgen]
    pub fn mix_attempt_event(&self, attempt_id: &str, event: &str) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.relay_event(event, now))
    }

    /// A coin check's answer (the filter server's /coin JSON through a provider) for one coin the Out asked about. v328:
    /// an empty answer (or "{}") = no provider answered — the attempt stops without naming anyone (a phone that cannot
    /// reach an answerer is the one with the problem); only an answer that came back can fail a coin.
    #[wasm_bindgen]
    pub fn mix_attempt_coin(&self, attempt_id: &str, ask: &str, answer: &str) -> Result<String, JsValue> {
        let a: lij_core::tatara::phone::CoinAsk = serde_json::from_str(ask).map_err(|e| JsValue::from_str(&format!("mix_attempt_coin: bad ask: {e}")))?;
        let t = answer.trim();
        let ok = if t.is_empty() || t == "{}" { log::warn!("[mix] a coin check got no answer"); None } else { Some(lij_core::tatara::phone::coin_answer_ok(&a, answer)) };
        if ok == Some(false) { log::warn!("[mix] a member's coin failed the coin check"); }
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.coin_result(&a.txid, a.vout, ok, now))
    }

    /// Phase 1b (v0.10 §6.2.1; step 11a): the answer to an Out's `open_channel` — the opened channel's funding script
    /// (P2WSH, hex) is this phone's payout; the registration goes out.
    #[wasm_bindgen]
    pub fn mix_attempt_payout(&self, attempt_id: &str, funding_spk_hex: &str) -> Result<String, JsValue> {
        let spk = bitcoin::ScriptBuf::from_bytes(hex::decode(funding_spk_hex.trim()).map_err(|e| JsValue::from_str(&format!("mix_attempt_payout: not hex: {e}")))?);
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.payout_given(spk.clone(), now))
    }

    /// Phase 1b (§6.2.3; step 11a): the answer to an Out's `fund_channel` — the channel is saved with the provider's
    /// first-commitment signature; the coin signature may follow.
    #[wasm_bindgen]
    pub fn mix_attempt_channel_saved(&self, attempt_id: &str) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.channel_saved(now))
    }

    /// The clock, every second or so while the attempt runs. Phase 1b: and the pool channel's news from the node —
    /// its funding script (→ the payout registered), the provider's signature with the manager written (→ the coin
    /// signature may follow), a close (→ the attempt stops).
    #[wasm_bindgen]
    pub fn mix_attempt_tick(&self, attempt_id: &str) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        let nonce = MIX_POOL_CHANNELS.with(|c| c.borrow().get(attempt_id).copied());
        let pc: Option<lij_core::node::PoolChannel> = match nonce {
            Some(n) => { let w = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?; serde_json::from_str(&w.node().pool_channel_json(n)).ok() }
            None => None,
        };
        mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| -> Result<lij_core::tatara::phone::Out, String> {
            let mut out = p.tick(now).map_err(|e| e.to_string())?;
            if let Some(pc) = pc {
                let phase = out.phase.clone();
                if let Some(why) = pc.closed.as_ref().filter(|_| !p.signed() && phase != "stopped" && phase != "done") {
                    out.merge(p.channel_failed(&format!("the channel closed ({why})"), now).map_err(|e| e.to_string())?);
                } else if phase == "opening_channel" {
                    if let Some(h) = pc.script.as_ref() {
                        let spk = bitcoin::ScriptBuf::from_bytes(hex::decode(h).map_err(|e| e.to_string())?);
                        out.merge(p.payout_given(spk, now).map_err(|e| e.to_string())?);
                    }
                } else if phase == "funding" && pc.saved {
                    out.merge(p.channel_saved(now).map_err(|e| e.to_string())?);
                }
            }
            Ok(out)
        })
    }

    /// Phase 1b (§6.2.1; step 11b): the answer to an Out's `open_channel` — open a channel of that size with the
    /// provider for this attempt (the node's pool channel; its funding script reaches the attempt on the next tick).
    /// A refusal (no provider connection, LDK's) stops the attempt; answers the Out JSON either way.
    #[wasm_bindgen]
    pub fn mix_attempt_channel_open(&self, attempt_id: &str, sats: u64) -> Result<String, JsValue> {
        let (_root_key, storage, dirty) = mix_handles(&self.inner)?;
        let opened = { let w = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?; w.node().open_pool_channel(sats) };
        match opened {
            Ok(n) => {
                MIX_POOL_CHANNELS.with(|c| { c.borrow_mut().insert(attempt_id.to_string(), n); });
                log::info!("[mix] attempt {}: pool channel #{n} opening ({sats} sats)", &attempt_id[..8.min(attempt_id.len())]);
                mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.tick(now))
            }
            Err(e) => {
                log::warn!("[mix] the channel for the pool could not be opened: {e}");
                mix_step(attempt_id, storage.as_ref(), &dirty, &self.inner, |p, now| p.channel_failed(&e.to_string(), now))
            }
        }
    }

    /// Phase 1b: the attempt's pool channel as the node sees it (PoolChannel JSON), or null — for the Mix screen.
    #[wasm_bindgen]
    pub fn mix_attempt_channel(&self, attempt_id: &str) -> Result<String, JsValue> {
        let nonce = MIX_POOL_CHANNELS.with(|c| c.borrow().get(attempt_id).copied());
        match nonce {
            Some(n) => { let w = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?; Ok(w.node().pool_channel_json(n)) }
            None => Ok("null".into()),
        }
    }

    /// The attempt is over for this page (done, stopped, or the app moved on): its keys leave memory.
    #[wasm_bindgen]
    pub fn mix_attempt_end(&self, attempt_id: &str) -> bool {
        MIX_JOINS.with(|m| { m.borrow_mut().remove(attempt_id); });   // v336: a waiting public join ends too
        MIX_SEAT_OF.with(|m| { m.borrow_mut().remove(attempt_id); });   // v340: the seat is free for another attempt
        MIX_POOL_CHANNELS.with(|c| { c.borrow_mut().remove(attempt_id); });   // the channel itself stays in the manager
        MIX_PHONES.with(|m| m.borrow_mut().remove(attempt_id).is_some())
    }

    /// v325: what Join shows — `req` JSON {"size","coins":[["txid",vout]…],"fee_rate_sat_vb","peers"}: {"size","coin_sats",
    /// "fee_sats","change_sats","covers","need_at_limit_sats","peers","fee_rate_sat_vb"} (covers = the coins cover the
    /// pool at the fee limit, 1.5 × today's rate) — or {"problem"} in plain words. v327: and "to_miners_sats" (with no
    /// change, what is left of the coin goes to the miners — named); and From Channel: {"size","close_sats",…} in place
    /// of "coins" quotes the coin a cooperative close of a channel with that balance will pay, with "no_change_band"
    /// ([low, top] — the balance that covers the pool at the limit and leaves no change at today's rate) when one exists.
    #[wasm_bindgen]
    pub fn mix_quote(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { size: u64, #[serde(default)] coins: Vec<(String, u32)>, #[serde(default)] close_sats: Option<u64>, fee_rate_sat_vb: u64, peers: usize }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("mix_quote: bad request: {e}")))?;
        if let (Some(v), true) = (r.close_sats, r.coins.is_empty()) {
            return match lij_core::tatara::store::quote_close(r.size, v, r.fee_rate_sat_vb, r.peers.clamp(3, 6)) {
                Ok(q) => serde_json::to_string(&q).map_err(|e| JsValue::from_str(&e.to_string())),
                Err(e) => Ok(serde_json::json!({ "problem": e.to_string() }).to_string()),
            };
        }
        let (root_key, storage, _dirty) = mix_handles(&self.inner)?;
        match lij_core::tatara::store::quote(storage.as_ref(), &root_key, r.size, &r.coins, r.fee_rate_sat_vb, r.peers.clamp(3, 6)) {
            Ok(q) => serde_json::to_string(&q).map_err(|e| JsValue::from_str(&e.to_string())),
            Err(e) => Ok(serde_json::json!({ "problem": e.to_string() }).to_string()),
        }
    }

    /// v326 (v0.10 §8 rule 10): "Keep my coin out of this pool" — `req` JSON {"coins":[["txid",vout]…],"fee_rate_sat_per_kw"}:
    /// a coin a signed pool's record holds (the funding never came) is sent, alone, to a new address of this wallet's own
    /// (the next change address), which ends that attempt for good; the record is wiped once that send is 6 deep. Only
    /// when no setup is running (the page offers it then). Answers the send's result (SendResult JSON).
    #[wasm_bindgen]
    pub fn mix_keep_out(&self, req: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let req = req.to_string();
        future_to_promise(async move {
            #[derive(serde::Deserialize)]
            struct Req { coins: Vec<(String, u32)>, fee_rate_sat_per_kw: u32 }
            let r: Req = serde_json::from_str(&req).map_err(|e| JsValue::from_str(&format!("mix_keep_out: bad request: {e}")))?;
            let pins: Vec<(String, u32)> = r.coins.iter().map(|(t, v)| (t.to_ascii_lowercase(), *v)).collect();
            let (root_key, independent, network) = {
                let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let storage = t2_storage(&root_key);
            let (dest, change_index, free) = lij_core::tatara::store::keep_out_plan(storage.as_ref(), &root_key, &pins)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let view = lij_core::tier2_wallet::load_view(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            let result = lij_core::onchain_send::build_and_send_all_pinned(&root_key, independent, network, &dest, r.fee_rate_sat_per_kw, change_index, &view, &pending, &free, &pins)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let delta = -(result.fee_sats as i64);
            if let Err(e) = lij_core::tier2_wallet::record_pending(
                storage.as_ref(),
                lij_core::tier2_wallet::PendingTx {
                    txid: result.txid.clone(),
                    spent_outpoints: result.spent_outpoints.clone(),
                    delta_sats: delta,
                    direction: lij_core::tier2_wallet::TxDirection::SelfTransfer,
                    kind: lij_core::tier2_wallet::TxKind::Onchain,
                    created_at_ms: lij_core::tier2_wallet::now_ms(),
                    change_outpoint: result.change_outpoint.clone(),
                    change_value_sats: result.change_sats,
                    change_index: result.change_index,
                    broadcast_seen: false,
                    raw_tx_hex: None,
                    dest_addr: Some(dest.clone()),
                    dest_sats: Some(result.amount_sats),
                    fee_sats: Some(result.fee_sats),
                    fee_rate_sat_per_kw: Some(r.fee_rate_sat_per_kw),
                    dests: Vec::new(),
                },
            ) {
                log::error!("record pending keep-out send failed: {e}");
            }
            t2_note_send(storage.as_ref(), &result.txid, &result.raw_hex, Some(dest.as_str()), &[]);
            match lij_core::tatara::store::drop_pool_rows_for(storage.as_ref(), &pins) {   // v329: the pool's rows leave ONCHAIN RECENT at once
                Ok(n) => log::info!("[mix] a signed pool's coin kept out: sent to a new address of this wallet ({n} pool's rows dropped)"),
                Err(e) => log::warn!("[mix] kept out, but the pool's rows could not be dropped: {e}"),
            }
            let json = result.to_json().map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v327 (From Channel — "Close channel and join"): a channel this phone is closing so that its coin joins a pool —
    /// `req` JSON {"channel_id","provider_pk","endpoint","size","payout":{"to":"this_wallet"},"rate_at_join","balance_sats"}.
    /// Sealed, this phone only; one per channel and, like a seat, one per pool size. The page starts the cooperative close
    /// itself and, once the close is in a block, takes the seat with its coin (mix_seat_new) and drops this.
    #[wasm_bindgen]
    pub fn mix_close_join_add(&self, req: &str) -> Result<(), JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { channel_id: String, provider_pk: String, endpoint: String, size: u64, payout: lij_core::tatara::wallet::PayoutChoice, rate_at_join: u64, balance_sats: u64 }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("mix_close_join_add: bad request: {e}")))?;
        let (_root, storage, _dirty) = mix_handles(&self.inner)?;
        let cj = lij_core::tatara::store::CloseJoin { channel_id: r.channel_id, provider_pk: r.provider_pk, endpoint: r.endpoint, size: r.size, payout: r.payout, rate_at_join: r.rate_at_join, balance_sats: r.balance_sats, since_ms: lij_core::tier2_wallet::now_ms() };
        lij_core::tatara::store::close_join_add(storage.as_ref(), cj).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v327: the close-joins on this phone, JSON [{"channel_id","provider_pk","endpoint","size","payout","rate_at_join",
    /// "balance_sats","since_ms"}…].
    #[wasm_bindgen]
    pub fn mix_close_joins(&self) -> Result<String, JsValue> {
        let (_root, storage, _dirty) = mix_handles(&self.inner)?;
        let all = lij_core::tatara::store::close_joins(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&all).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v327: drop a close-join (its seat taken, the person left, or the coin cannot cover the pool) — true if it existed.
    #[wasm_bindgen]
    pub fn mix_close_join_drop(&self, channel_id: &str) -> Result<bool, JsValue> {
        let (_root, storage, _dirty) = mix_handles(&self.inner)?;
        lij_core::tatara::store::close_join_drop(storage.as_ref(), channel_id).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v327: what "Keep my coin out of this pool" costs — `req` JSON {"coins":[["txid",vout]…],"fee_rate_sat_per_kw"} →
    /// {"coin_sats","fee_sats","arrives_sats","sat_per_vb"} or {"problem"} in plain words; nothing written (the send itself,
    /// mix_keep_out, hands out the address).
    #[wasm_bindgen]
    pub fn mix_keep_out_quote(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { coins: Vec<(String, u32)>, fee_rate_sat_per_kw: u32 }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("mix_keep_out_quote: bad request: {e}")))?;
        let (root_key, storage, _dirty) = mix_handles(&self.inner)?;
        match lij_core::tatara::store::keep_out_quote(storage.as_ref(), &root_key, &r.coins, r.fee_rate_sat_per_kw) {
            Ok(q) => serde_json::to_string(&q).map_err(|e| JsValue::from_str(&e.to_string())),
            Err(e) => Ok(serde_json::json!({ "problem": e.to_string() }).to_string()),
        }
    }

    /// v333 (S59, DP 2026-10-14 "Bump stuck Mix exits is now-work"; spec v0.10 §6.4): what a speed-up of a record's pool
    /// costs at `target_sat_vb` — the unconfirmed part of the chain (the funding and the exits up to this phone's, each
    /// asked of the chain servers), the fee it carries, the child's fee that lifts it to the target, and what the new
    /// coin carries. Nothing written. Answers the quote JSON (tatara::bump::BumpQuote; "problem" set when no child can
    /// be offered — a channel pool, another wallet's payout, an exit already in a block, a rate below today's, a coin too
    /// small, a speed-up already on its way).
    #[wasm_bindgen]
    pub fn mix_bump_quote(&self, record_id: &str, target_sat_vb: u64) -> js_sys::Promise {
        let id = record_id.to_string();
        let (root_key, independent) = match self.inner.try_lock() {
            Ok(w) => { let (r, i, _) = w.onchain_handles(); (r, i) },
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let storage = t2_storage(&root_key);
            let q = mix_bump_quote_inner(storage.as_ref(), independent, &id, target_sat_vb).await?;
            Ok(JsValue::from_str(&serde_json::to_string(&q).map_err(|e| JsValue::from_str(&e.to_string()))?))
        })
    }

    /// v333: the speed-up itself — the quote taken afresh, this phone's payout spent alone to a fresh m/86 address of
    /// this wallet's (marked mixed, as the payout was), signed with the payout's own key, broadcast, and recorded among
    /// the sends still confirming (TxKind::MixSpeedUp — the row reads "Mix speed-up"). The record's settle check is
    /// untouched: the payout's exit still settles the pool. Answers {"txid","child_fee_sats","arrives_sats","address"}.
    #[wasm_bindgen]
    pub fn mix_bump(&self, record_id: &str, target_sat_vb: u64) -> js_sys::Promise {
        let id = record_id.to_string();
        let (root_key, independent, network, dirty) = match self.inner.try_lock() {
            Ok(w) => { let (r, i, n) = w.onchain_handles(); (r, i, n, w.node().backup_dirty_handle()) },
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let storage = t2_storage(&root_key);
            let q = mix_bump_quote_inner(storage.as_ref(), independent.clone(), &id, target_sat_vb).await?;
            if let Some(p) = &q.problem { return Err(JsValue::from_str(p)); }
            let rec = lij_core::tatara::records::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?
                .into_iter().find(|r| r.id == id).ok_or_else(|| JsValue::from_str("no such pool"))?;
            // the new coin's address: the next m/86 receive index, marked mixed (the payout's own rule — wallet::next_payout)
            let view = lij_core::tier2_wallet::load_view(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let mut marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let p = lij_core::tatara::wallet::next_payout(&root_key, &view, &mut marks).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let (tx, raw) = lij_core::tatara::bump::build_bump(&root_key, &rec, &q, &p.script).map_err(|e| JsValue::from_str(&e.to_string()))?;
            independent.broadcast_raw_tx(&raw).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            lij_core::tier2_wallet::save_marks(storage.as_ref(), &marks).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let txid = tx.compute_txid().to_string();
            let raw_hex = hex::encode(&raw);
            if let Err(e) = lij_core::tier2_wallet::record_pending(
                storage.as_ref(),
                lij_core::tier2_wallet::PendingTx {
                    txid: txid.clone(),
                    spent_outpoints: vec![(q.exit_txid.clone(), q.exit_vout)],
                    delta_sats: -(q.child_fee_sats as i64),
                    direction: lij_core::tier2_wallet::TxDirection::SelfTransfer,
                    kind: lij_core::tier2_wallet::TxKind::MixSpeedUp,
                    created_at_ms: lij_core::tier2_wallet::now_ms(),
                    change_outpoint: None,
                    change_value_sats: 0,
                    change_index: 0,
                    broadcast_seen: false,
                    raw_tx_hex: Some(raw_hex.clone()),
                    dest_addr: Some(p.address.clone()),
                    dest_sats: Some(q.arrives_sats),
                    fee_sats: Some(q.child_fee_sats),
                    fee_rate_sat_per_kw: Some((target_sat_vb as u32).saturating_mul(250)),
                    dests: Vec::new(),
                },
            ) {
                log::error!("record pending speed-up failed: {e}");
            }
            t2_note_send(storage.as_ref(), &txid, &raw_hex, Some(p.address.as_str()), &[]);
            dirty.store(true, std::sync::atomic::Ordering::Relaxed);   // the marks moved (a new mixed index)
            let _ = network;
            log::info!("[mix] speed-up {txid}: the payout of pool {} spent to m/86 #{} with a {}-sat fee (the chain lifted to {} sat/vB)", id, p.index.unwrap_or(0), q.child_fee_sats, target_sat_vb);
            Ok(JsValue::from_str(&serde_json::json!({ "txid": txid, "child_fee_sats": q.child_fee_sats, "arrives_sats": q.arrives_sats, "address": p.address }).to_string()))
        })
    }

    /// v325: the attempt records as the Mix screen shows them: [{"id","size","payout_index","saved_ms"}…]. v327: and
    /// "inputs" (this phone's coins in the pool), "coin_sats", "state" ("waiting" | "funded" | "kept_out").
    #[wasm_bindgen]
    pub fn mix_records(&self) -> Result<String, JsValue> {
        let storage = mix_storage(&self.inner)?;
        let network = { let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?; wallet.onchain_handles().2 };
        let v = lij_core::tatara::store::records_view(storage.as_ref(), network).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v329: is this transaction known to the network? Asks the independent quorum (tx_known): {"known": true}
    /// with "confirmed" and "height" (null in the mempool) — {"known": false} when a reachable server said definitively
    /// that it has no such transaction — {"known": null} when the quorum could not answer (proves nothing). The Mix
    /// screen offers "Pull my coin back" only on a definite false.
    #[wasm_bindgen]
    pub fn mix_tx_status(&self, txid: &str) -> js_sys::Promise {
        let txid = txid.trim().to_ascii_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) { return js_sys::Promise::reject(&JsValue::from_str("mix_tx_status: not a txid")); }
        let independent = match self.inner.try_lock() {
            Ok(w) => w.onchain_handles().1,
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let known = independent.tx_known(&txid).await;
            let (confirmed, height) = if known == Some(true) {
                match independent.fetch_tx(&txid).await { Ok(t) => (t.confirmed, t.block_height), Err(_) => (false, None) }
            } else { (false, None) };
            Ok(JsValue::from_str(&serde_json::json!({ "known": known, "confirmed": confirmed, "height": height }).to_string()))
        })
    }

    /// v325: send a complete pool — the funding, then each exit, in order (`txs` JSON ["hex"…]); "already known" counts as
    /// sent; stops at the first refusal (the next spends it). Answers [{"ok","error"}…].
    #[wasm_bindgen]
    pub fn mix_send(&self, txs: &str) -> js_sys::Promise {
        let list: Vec<String> = match serde_json::from_str(txs) { Ok(v) => v, Err(e) => return js_sys::Promise::reject(&JsValue::from_str(&format!("mix_send: bad request: {e}"))) };
        let independent = match self.inner.try_lock() {
            Ok(w) => w.onchain_handles().1,
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let mut out: Vec<serde_json::Value> = Vec::new();
            for h in &list {
                let Ok(bytes) = hex::decode(h) else { out.push(serde_json::json!({ "ok": false, "error": "not hex" })); break };
                match independent.broadcast_raw_tx(&bytes).await {
                    Ok(()) => out.push(serde_json::json!({ "ok": true })),
                    Err(e) if e.to_string().to_ascii_lowercase().contains("already") => out.push(serde_json::json!({ "ok": true, "already": true })),
                    Err(e) => { out.push(serde_json::json!({ "ok": false, "error": e.to_string() })); break; }
                }
            }
            let n_ok = out.iter().filter(|v| v["ok"] == true).count();
            log::info!("[mix] sent {n_ok} of {} pool transactions", list.len());
            Ok(JsValue::from_str(&serde_json::Value::Array(out).to_string()))
        })
    }

    /// v284 (S50, silent payments — receive, the engine groundwork): the wallet's own
    /// silent-payment address (BIP-352, keys m/352'/{coin}'/0'/1'/0 scan and /0'/0 spend —
    /// Cake's and Sparrow's paths, so the 12 words restore the coins anywhere). Derived on
    /// the spot from the words, never stored. Answers JSON {"address","scan_pub","spend_pub"}.
    /// Not surfaced on the page until the receive walk ships (DP: nothing pushed before the
    /// remaining decisions are talked through).
    #[wasm_bindgen]
    pub fn sp_address(&self) -> Result<String, JsValue> {
        let (root_key, _independent, _network) = {
            let wallet = self
                .inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let keys = lij_core::silent_payment::SpKeys::from_root(&root_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let out = serde_json::json!({
            "address": keys.address(),
            "scan_pub": hex::encode(keys.scan_pub.serialize()),
            "spend_pub": hex::encode(keys.spend_pub.serialize()),
        });
        Ok(out.to_string())
    }

    /// v304 (S54, DP 2026-10-02 13:50 "Go ahead"): the silent-payment labels — number, name, hidden, the label's own
    /// sp1 address, and what it has received (coins paid to it, spent or not). JSON {"labels":[{m,name,hidden,
    /// created_ms,address,payments,received_sats}],"max":10,"used":n,"unknown":bool} — `unknown` = a words-only
    /// restore checking all ten; a nameless label (found after that restore) shows as "Label m".
    #[wasm_bindgen]
    pub fn sp_labels(&self) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let view = lij_core::tier2_wallet::load_view(storage.as_ref()).unwrap_or_default();
        let keys = lij_core::silent_payment::SpKeys::from_root(&root_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let labels: Vec<serde_json::Value> = marks.sp_labels.iter().map(|l| {
            let paid: Vec<&lij_core::tier2_wallet::OnchainUtxo> = view.utxos.iter().filter(|u| u.sp_label == Some(l.m)).collect();
            serde_json::json!({
                "m": l.m, "name": l.name, "hidden": l.hidden, "created_ms": l.created_ms,
                "address": keys.label_address(&secp, l.m).unwrap_or_default(),
                "payments": paid.len(),
                "received_sats": paid.iter().map(|u| u.value_sats).sum::<u64>(),
            })
        }).collect();
        let main: Vec<&lij_core::tier2_wallet::OnchainUtxo> = view.utxos.iter().filter(|u| u.chain == lij_core::tier2::CHAIN_SP && u.sp_label.is_none()).collect();
        Ok(serde_json::json!({
            "labels": labels,
            "max": lij_core::silent_payment::SP_LABEL_MAX,
            "used": marks.sp_labels.len(),
            "unknown": marks.sp_labels_unknown,
            "main": { "address": keys.address(), "payments": main.len(), "received_sats": main.iter().map(|u| u.value_sats).sum::<u64>() },
        }).to_string())
    }

    /// v304: make a label — the next number (never reused), a cleaned name (40 code points at most), ten at most.
    /// Answers {"m","name","address"}. Saved in the marks (they ride the backup); the scan checks it from the next sync.
    #[wasm_bindgen]
    pub fn sp_label_create(&self, name: &str) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let m = marks.sp_label_create(name, lij_core::tier2_wallet::now_ms()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::tier2_wallet::save_marks(storage.as_ref(), &marks).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let keys = lij_core::silent_payment::SpKeys::from_root(&root_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let address = keys.label_address(&bitcoin::secp256k1::Secp256k1::new(), m).map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[sp] label {m} made");
        Ok(serde_json::json!({ "m": m, "name": marks.sp_label(m).map(|l| l.name.clone()).unwrap_or_default(), "address": address }).to_string())
    }

    /// v304: rename and/or hide a label — `req` JSON {"m", "name"?, "hidden"?}. No delete (a label handed out can still be
    /// paid; a hidden one is still checked and its payments still tagged). Answers {"m","name","hidden"}.
    #[wasm_bindgen]
    pub fn sp_label_update(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { m: u32, name: Option<String>, hidden: Option<bool> }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("sp_label_update: bad request: {e}")))?;
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let l = marks.sp_label_update(r.m, r.name.as_deref(), r.hidden).map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::tier2_wallet::save_marks(storage.as_ref(), &marks).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_json::json!({ "m": l.m, "name": l.name, "hidden": l.hidden }).to_string())
    }

    /// v288 (S50, DP 21:10 "the wallet has a say"): the wallet-side silent-payment switch. Lives in
    /// the marks store (its own encrypted key — a sync in flight cannot clobber it; a rescan keeps
    /// it). Off = the engine runs no silent-payment scan and the page shows no sp1 address; on = the
    /// scan resumes where it stopped at the next sync. Answers JSON {"enabled"}.
    #[wasm_bindgen]
    pub fn sp_set_enabled(&self, enabled: bool) -> Result<String, JsValue> {
        let (root_key, _independent, _network) = {
            let wallet = self
                .inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.onchain_handles()
        };
        let storage = t2_storage(&root_key);
        let mut marks = lij_core::tier2_wallet::load_marks(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        marks.sp_enabled = enabled;
        lij_core::tier2_wallet::save_marks(storage.as_ref(), &marks)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[sp] the silent-payment switch is now {}", if enabled { "on" } else { "off" });
        Ok(serde_json::json!({ "enabled": enabled }).to_string())
    }

    // ── v286 (S50, NWC cut N1): the engine's NWC surface. The page owns the relay websocket
    // and the UI; every key, every decrypt and every signature stays here. The store lives
    // under the ledger's encryption at rest and rides the state blob. ──

    /// The connections and limits, for Dials → NWC. JSON {"conns":[{id,name,service_pk,
    /// client_pk,relay,created_ms,expires_ms,last_used_ms,ended}], "limits":{…},
    /// "paid_today_sats", "live"}. Secrets never appear.
    #[wasm_bindgen]
    pub fn nwc_list(&self) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let now = lij_core::tier2_wallet::now_ms();
        if s.expire(now) > 0 { let _ = lij_core::nwc::save(storage.as_ref(), &s); }
        let conns: Vec<serde_json::Value> = s.conns.iter().map(|c| serde_json::json!({
            "id": c.id, "name": c.name, "service_pk": c.service_pk, "client_pk": c.client_pk, "relay": c.relay,
            "created_ms": c.created_ms, "expires_ms": c.expires_ms, "last_used_ms": c.last_used_ms, "ended": c.ended,
        })).collect();
        Ok(serde_json::json!({
            "conns": conns,
            "limits": s.limits(),
            "paid_today_sats": (s.paid_today_msat(now) + 999) / 1000,
            "live": s.live(now).count(),
        }).to_string())
    }

    /// A new connection for one app: `req` = JSON {"name","relay"}. Answers {id,name,
    /// service_pk,client_pk,uri,info_event} — the uri carries the client secret and is shown
    /// once; the info event (13194) is what the page publishes to the relay.
    #[wasm_bindgen]
    pub fn nwc_add(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { name: String, relay: String }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("nwc_add: bad request: {e}")))?;
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let now = lij_core::tier2_wallet::now_ms();
        s.expire(now);
        let added = s.add(&r.name, &r.relay, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::nwc::save(storage.as_ref(), &s).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let c = s.get(added.id).ok_or_else(|| JsValue::from_str("nwc_add: lost"))?;
        let info = lij_core::nwc::info_event(c, now / 1000).map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[nwc] connection {} added ({})", added.id, added.name);
        Ok(serde_json::json!({
            "id": added.id, "name": added.name, "service_pk": added.service_pk, "client_pk": added.client_pk,
            "uri": added.uri, "info_event": info,
        }).to_string())
    }

    /// End a connection: `reason` = "revoked" (the user), "switched" (an LSP switch — pass id 0
    /// to end every live one). The secret is dropped at once.
    #[wasm_bindgen]
    pub fn nwc_end(&self, id: u32, reason: &str) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let n = if id == 0 { s.end_all(reason) } else { s.end(id, reason).map_err(|e| JsValue::from_str(&e.to_string()))?; 1 };
        lij_core::nwc::save(storage.as_ref(), &s).map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[nwc] {n} connection(s) ended: {reason}");
        Ok(serde_json::json!({ "ended": n }).to_string())
    }

    /// Drop an ended connection's row from the list.
    #[wasm_bindgen]
    pub fn nwc_forget(&self, id: u32) -> Result<(), JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        s.forget(id);
        lij_core::nwc::save(storage.as_ref(), &s).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The Dials: JSON {"per_payment_sats","per_day_sats","connection_days","request_ttl_secs"}.
    #[wasm_bindgen]
    pub fn nwc_set_limits(&self, req: &str) -> Result<String, JsValue> {
        let l: lij_core::nwc::Limits = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("nwc_set_limits: bad request: {e}")))?;
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        s.set_limits(l).map_err(|e| JsValue::from_str(&e.to_string()))?;
        lij_core::nwc::save(storage.as_ref(), &s).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&s.limits()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Open a request event (kind 23194) fetched from the relay. The connection is found by
    /// the event's `p` tag. Answers the `Opened` record (the request's method, invoice, amount,
    /// payee, and either `refusal` {code,message} or nothing — then the page fills Send), or
    /// an error when the event is not ours / malformed / too old (the page drops it).
    #[wasm_bindgen]
    pub fn nwc_open(&self, event_json: &str) -> Result<String, JsValue> {
        let ev: lij_core::nwc::Event = serde_json::from_str(event_json).map_err(|e| JsValue::from_str(&format!("nwc_open: not an event: {e}")))?;
        let (root_key, _i, network) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let now = lij_core::tier2_wallet::now_ms();
        let p = ev.tags.iter().find(|t| t.len() >= 2 && t[0] == "p").map(|t| t[1].clone()).unwrap_or_default();
        let c = s.by_service_pk(&p, now).ok_or_else(|| JsValue::from_str("nwc_open: no live connection for this request"))?;
        let opened = lij_core::nwc::open_request(&s, c, &ev, network, now / 1000).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&opened).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// A reply (kind 23195) for the page to publish: `req` = JSON {"conn_id","request_id",
    /// "result_type", "result": {…} | null, "error": {"code","message"} | null, "encryption"?}.
    /// v290: `encryption` is the opened request's ("nip44_v2" | "nip04") — the reply goes back in kind.
    #[wasm_bindgen]
    pub fn nwc_reply(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { conn_id: u32, request_id: String, result_type: String, result: Option<serde_json::Value>, error: Option<serde_json::Value>, #[serde(default)] encryption: Option<String> }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("nwc_reply: bad request: {e}")))?;
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let c = s.get(r.conn_id).ok_or_else(|| JsValue::from_str("nwc_reply: no such connection"))?;
        let content = match (r.error, r.result) {
            (Some(e), _) => lij_core::nwc::error_json(&r.result_type, e.get("code").and_then(|v| v.as_str()).unwrap_or("OTHER"), e.get("message").and_then(|v| v.as_str()).unwrap_or("")),
            (None, Some(v)) => lij_core::nwc::result_json(&r.result_type, v),
            (None, None) => return Err(JsValue::from_str("nwc_reply: neither result nor error")),
        };
        let enc = r.encryption.as_deref().unwrap_or(lij_core::nwc::ENCRYPTION);
        let ev = lij_core::nwc::reply_event(c, &r.request_id, &content, lij_core::tier2_wallet::now_ms() / 1000, enc).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&ev).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The info event (13194) for a connection, re-signed now (the page republishes it when
    /// the relay lost it).
    #[wasm_bindgen]
    pub fn nwc_info_event(&self, id: u32) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let c = s.get(id).ok_or_else(|| JsValue::from_str("nwc_info_event: no such connection"))?;
        let ev = lij_core::nwc::info_event(c, lij_core::tier2_wallet::now_ms() / 1000).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&ev).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The NIP-42 AUTH event (22242) answering the relay's challenge as connection `id`.
    #[wasm_bindgen]
    pub fn nwc_auth_event(&self, id: u32, relay: &str, challenge: &str) -> Result<String, JsValue> {
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let c = s.get(id).ok_or_else(|| JsValue::from_str("nwc_auth_event: no such connection"))?;
        let ev = lij_core::nwc::auth_event(c, relay, challenge, lij_core::tier2_wallet::now_ms() / 1000).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&ev).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Record an NWC payment once its preimage is in hand: `req` = JSON {"conn_id","msat",
    /// "payee","payment_hash"}. Feeds the daily total and the duplicate check.
    #[wasm_bindgen]
    pub fn nwc_record_paid(&self, req: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        struct Req { conn_id: u32, msat: u64, payee: String, payment_hash: String }
        let r: Req = serde_json::from_str(req).map_err(|e| JsValue::from_str(&format!("nwc_record_paid: bad request: {e}")))?;
        let (root_key, _i, _n) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let storage = t2_storage(&root_key);
        let mut s = lij_core::nwc::load(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let now = lij_core::tier2_wallet::now_ms();
        s.record_paid(r.conn_id, r.msat, &r.payee, &r.payment_hash, now);
        lij_core::nwc::save(storage.as_ref(), &s).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_json::json!({ "paid_today_sats": (s.paid_today_msat(now) + 999) / 1000 }).to_string())
    }

    /// v166 (#29-4b): raw pending list for the bump UI (storage-only).
    pub fn list_pending_json(&self) -> Result<String, JsValue> {
        let storage = LocalStorage;
        let pending = lij_core::tier2_wallet::load_pending(&storage);
        serde_json::to_string(&pending).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v166 (#29-4b): RBF-replace one of OUR pending on-chain sends at a
    /// higher fee. Same inputs, same destination; the delta comes out of the
    /// change. The engine enforces BIP-125 economics and answers with
    /// actionable minimum/maximum sat/vB messages on violation.
    pub fn bump_onchain_send(&self, old_txid: String, new_fee_rate_sat_per_kw: u32) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let storage = t2_storage(&root_key);   // v263: the view is encrypted at rest (v256)
            let view = lij_core::tier2_wallet::load_view(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            let prev = pending
                .iter()
                .find(|p| p.txid == old_txid)
                .ok_or_else(|| JsValue::from_str(
                    "that send is not pending anymore — it may have confirmed; refresh",
                ))?;
            let result = lij_core::onchain_send::build_and_send_bump(
                &root_key,
                independent,
                network,
                prev,
                new_fee_rate_sat_per_kw,
                &view,
                &pending,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let dest_addr_keep = prev.dest_addr.clone();
            let dest_sats_keep = prev.dest_sats;
            let dests_keep = prev.dests.clone();   // v305: every recipient rides the replacement's record
            {
                let storage2: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);   // v256
                t2_note_send(storage2.as_ref(), &result.txid, &result.raw_hex, dest_addr_keep.as_deref(), &dests_keep);   // v298: the replacement, kept whole; its sp1 too · v306: its recipients
                let mut list = lij_core::tier2_wallet::load_pending(storage2.as_ref());
                list.retain(|p| p.txid != old_txid);
                list.push(lij_core::tier2_wallet::PendingTx {
                    txid: result.txid.clone(),
                    spent_outpoints: result.spent_outpoints.clone(),
                    delta_sats: -((result.amount_sats as i64) + (result.fee_sats as i64)),
                    direction: lij_core::tier2_wallet::TxDirection::Sent,
                    kind: lij_core::tier2_wallet::TxKind::Onchain,
                    created_at_ms: lij_core::tier2_wallet::now_ms(),
                    broadcast_seen: false,
                    raw_tx_hex: None,
                    change_outpoint: result.change_outpoint.clone(),
                    change_value_sats: result.change_sats,
                    change_index: result.change_index,
                    dest_addr: dest_addr_keep,
                    dest_sats: dest_sats_keep,
                    fee_sats: Some(result.fee_sats),
                    fee_rate_sat_per_kw: Some(new_fee_rate_sat_per_kw),
                    dests: dests_keep,
                });
                lij_core::tier2_wallet::save_pending(storage2.as_ref(), &list)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            let body = result
                .to_json()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&format!(
                "{{\"replaced\":\"{}\",\"result\":{}}}",
                old_txid, body
            )))
        })
    }

    /// v105 dev/recovery tool: roll the Tier-2 scan cursor back so the next
    /// background sync re-walks blocks from `from_height` (inclusive) to tip.
    /// Use when a block was scanned before its matching script entered the
    /// watch window (e.g. a sweep paid an address past the old gap) — the
    /// counter-aware window above makes the re-walk actually match this time.
    /// Pure storage operation (no wallet lock). Floors at the birthday; no-op
    /// if the cursor is already at or below the target. Returns the persisted
    /// cursor as JSON. Balances/history may look odd for the few seconds the
    /// re-walk takes; the next completed sync restores full truth.
    #[wasm_bindgen]
    pub fn tier2_rescan_from(&self, from_height: f64) -> Result<String, JsValue> {
        // v257 (DP: rescan = rebuild, explicit): clear the ledger and read again from the tip
        // down to the chosen height (or the existing birthday if it is lower). The next sync
        // call opens the walk; the face shows it from the first batch.
        if !(from_height.is_finite() && from_height >= 1.0) {
            return Err(JsValue::from_str("from_height must be a positive block height"));
        }
        let storage: Arc<dyn lij_core::storage::LijStorage> = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            t2_storage(&wallet.onchain_handles().0)
        };
        let mut view = lij_core::tier2_wallet::load_view(storage.as_ref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let h = from_height as u32;
        let old_birthday = lij_core::tier2_wallet::rescan_from(&mut view, h, js_sys::Date::now() as u64);   // v348: the silent-payment floor follows the chosen height
        lij_core::tier2_wallet::save_view(storage.as_ref(), &view)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        log::info!("[tier2] v257 rescan: ledger cleared; reading again from the tip down to {} (was {})", view.cursor.birthday, old_birthday);
        Ok(format!(r#"{{"ok":true,"birthday":{},"previous_birthday":{}}}"#, view.cursor.birthday, old_birthday))
    }

    #[wasm_bindgen]
    pub fn peek_channel_index(&self) -> Result<f64, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let v = wallet
            .node()
            .signer_provider()
            .peek_index()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(v as f64)
    }

    /// Session 23 Option B (allocator unification, the other direction):
    /// the frontend reserves receive-index territory. Raises the shared
    /// allocator floor to index+1 on the LIVE counter instance, so the
    /// signer can never issue an index at or below a shown/used receive
    /// address. No-op when the allocator is already past it.
    #[wasm_bindgen]
    pub fn reserve_onchain_index(&self, index: f64) -> Result<(), JsValue> {
        if !(index.is_finite() && index >= 0.0) {
            return Err(JsValue::from_str("index must be a non-negative integer"));
        }
        let idx = index as u32;
        let floor = idx
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("index overflow"))?;
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet
            .node()
            .signer_provider()
            .raise_index_floor(floor)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Session 23 (1b engine half): version of the last vault push, read
    /// from KEY_BACKUP_VERSION (u64 BE). Returns 0 when no push has ever
    /// happened. Feeds the standing Backup drilldown row
    /// ("vault · vNNN · synced").
    #[wasm_bindgen]
    pub fn last_backup_version(&self) -> Result<f64, JsValue> {
        match lij_core::storage::LijStorage::get(
            &LocalStorage,
            lij_core::storage::KEY_BACKUP_VERSION,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(buf) as f64)
            }
            Some(_) => Err(JsValue::from_str("backup version malformed")),
            None => Ok(0.0),
        }
    }

    /// Network-free receive address at `index` (BIP84 m/84'/{coin}'/0'/0/index).
    /// Synchronous + offline: derives from the seed only, so receiving never
    /// depends on a chain scan. The frontend persists the index and reconciles
    /// it upward whenever a scan succeeds, advancing per receive to avoid reuse.
    #[wasm_bindgen]
    pub fn next_receive_address(&self, index: f64) -> Result<String, JsValue> {
        if !(index.is_finite() && index >= 0.0) {
            return Err(JsValue::from_str("index must be a non-negative integer"));
        }
        let idx = index as u32;
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let (root_key, _independent, network) = wallet.onchain_handles();
        lij_core::onchain_scan::receive_address_at(&root_key, idx, network)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Chunk 1 (receive watcher): query a single watched address for incoming
    /// outputs — INCLUDING 0-conf mempool ones — via the independent Esplora
    /// quorum. The confirmed-block BIP158 scanner is mempool-blind by design, so
    /// this is the ONLY mempool-aware path, deliberately narrow: it is called
    /// only for an address the user is actively awaiting payment on (an open
    /// expectation row), never across the whole wallet. Returns a JSON array of
    /// { txid, vout, value_sats, confirmed } — the frontend turns unconfirmed
    /// entries into a pending-inbound alert-bar amount and flips the awaiting
    /// row; confirmed entries are left for the scanner to fold in normally.
    ///
    /// Privacy note: this reveals the queried address to the quorum endpoints.
    /// That address was just shown to a payer, the query only fires for actively
    /// awaited addresses, and the endpoint is user-configurable (own node →
    /// zero leak). The wallet-wide BIP158 model is untouched.
    ///
    /// v302 (S54): `own_base` = the Address watcher row's own Esplora server (None = the public explorers in
    /// turn, as v301); `own_only` = the row's "Only my server" switch (no fallback). The report of each check is
    /// kept for watch_report(). A page from before v302 passes the address alone — no own server, as before.
    #[wasm_bindgen]
    pub fn watch_address_inbound(&self, address: String, own_base: Option<String>, own_only: Option<bool>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let independent = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let (_rk, independent, _net) = wallet.onchain_handles();
                independent
            };
            let res = independent
                .fetch_address_utxos_watch_via(&address, own_base.as_deref(), own_only.unwrap_or(false))   // v302: own server first, the explorers as the fallback
                .await;
            if let Ok(mut r) = WATCH_REPORT.lock() { *r = independent.last_watch_report().to_json(); }
            let utxos = res.map_err(|e| JsValue::from_str(&e.to_string()))?;
            // Hand the frontend the raw per-output truth; it owns the
            // pending-inbound bookkeeping and dedup against the scanner.
            let items: Vec<String> = utxos
                .iter()
                .map(|u| {
                    format!(
                        "{{\"txid\":\"{}\",\"vout\":{},\"value_sats\":{},\"confirmed\":{}}}",
                        u.txid, u.vout, u.value_sats, u.confirmed
                    )
                })
                .collect();
            Ok(JsValue::from_str(&format!("[{}]", items.join(","))))
        })
    }

    /// v302 (S54): how the last receive-watch check went — {"answered_by":"own"|"public"|"","own_set",
    /// "own_error"|null,"own_resting","at_ms"}; "{}" before the first check. Read without the wallet lock.
    #[wasm_bindgen]
    pub fn watch_report(&self) -> String {
        WATCH_REPORT.lock().map(|r| if r.is_empty() { "{}".to_string() } else { r.clone() }).unwrap_or_else(|_| "{}".to_string())
    }

    /// v302 (S54): the Address watcher row's Save check — resolves to the server's tip height when `base` is a
    /// clean https address answering as an Esplora server (/blocks/tip/height, then /address/<a never-funded probe
    /// address>/utxo); rejects with the reason otherwise. Nothing of the user's is sent.
    #[wasm_bindgen]
    pub fn check_watch_server(&self, base: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let (_rk, independent, network) = wallet.onchain_handles();
                (independent, network)
            };
            let tip = independent
                .check_watch_server(&base, network)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_f64(tip as f64))
        })
    }

    /// On-chain transaction history for the RECENT list. The trusted-node source
    /// was removed with the shim; this returns an empty list until Tier 2
    /// (client-side BIP158 filter matching) reconstructs history locally. Kept so
    /// the frontend RECENT wiring stays stable across the transition.
    /// v252 (S46, DP's #20 run): given a transaction id, find the output that pays one of
    /// THIS wallet's addresses (receive/change/legacy chains, a 200-wide window from the
    /// used frontier) and answer {"found":true,"address":..,"vout":n,"value_sats":..}. Used
    /// after recover-close: the LSP names the closing txid, the wallet finds its own
    /// output and opens a receive expectation on that address, so the 0-conf watcher shows
    /// the return in the mempool and the confirmed card on the block. A words-only restore
    /// does not know the pin index; this finds it from the transaction itself.
    #[wasm_bindgen]
    pub fn identify_own_output(&self, txid: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);   // v256
            let view = lij_core::tier2_wallet::load_view(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            let short = txid.get(..12).unwrap_or(&txid).to_string();
            let tx = match independent.fetch_tx(&txid).await {
                Ok(t) => t,
                Err(e) => {
                    // v265 (S47, DP): every step of the recover-close watch is on the tape
                    log::warn!("[recover-watch] closing tx {short}…: not at the independent sources yet ({e})");
                    return Err(JsValue::from_str(&e.to_string()));
                }
            };
            // v265 (S47, DP): search the walk's fixed net first (every branch, 0..2,500 — the same
            // addresses the walk watches, cached), then the old sliding window above the frontier.
            let fixed = t2_scripts(&root_key, network, view.net_width.max(lij_core::tier2_wallet::NET_WIDTH)).await?;
            let sliding = lij_core::tier2::WalletScripts::build_sliding(
                &root_key,
                network,
                view.net_width.max(lij_core::tier2_wallet::NET_WIDTH),
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_RECEIVE)
                    .max(lij_core::persisted_counter::peek_persisted(storage.as_ref())),
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_CHANGE),
                lij_core::tier2_wallet::next_index_for_chain(&view, &pending, lij_core::tier2::CHAIN_LEGACY),
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            for (i, v) in tx.vouts.iter().enumerate() {
                let bytes = match hex::decode(&v.scriptpubkey) { Ok(b) => b, Err(_) => continue };
                let spk = bitcoin::ScriptBuf::from_bytes(bytes);
                if let Some((chain, index)) = fixed.owner_of(&spk).or_else(|| sliding.owner_of(&spk)) {
                    let addr = bitcoin::Address::from_script(&spk, network)
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    log::info!("[recover-watch] closing tx {short}…: our output #{i}, {} sats (chain {chain}, index {index})", v.value);
                    return Ok(JsValue::from_str(&format!(
                        r#"{{"found":true,"address":"{}","vout":{},"value_sats":{}}}"#, addr, i, v.value)));
                }
            }
            log::warn!("[recover-watch] closing tx {short}…: no output pays this wallet ({} outputs checked against {} addresses per branch)", tx.vouts.len(), view.net_width.max(lij_core::tier2_wallet::NET_WIDTH));
            Ok(JsValue::from_str(r#"{"found":false}"#))
        })
    }

    /// v261 (DP: the on-chain drill-down): everything the panel shows for one transaction — fee (sats,
    /// sat/vB), the inputs and outputs with which are ours, the counterparty address, the output type, mempool
    /// or block (with the header time). Answers JSON:
    /// {"txid","fee_sats","vsize","sat_vb","confirmed","height","time","our_in","our_out",
    ///  "address","address_type","outputs":[{"address","value","ours","type"}],"source","sp_address"}
    /// v298 (S52, DP 22:48 "build the drill-down from the block the wallet already downloaded" + 23:43 "Go on #2 and
    /// #3"): the details come from the wallet's own data — NO explorer is asked (until v298 every tap sent the txid
    /// to four public explorers). In order: the transaction kept whole (the walk and the scan keep every own
    /// transaction from its block; a send is kept at broadcast); else, for a ledger row from before v298, its block
    /// read once more from the wallet's block-filter server (`filter_base`: the page's lijFilterBases().walk; the
    /// header's work checked, the block bound to it, the transaction authentic by its txid; every own transaction in
    /// that block kept); else a pending transaction's own bytes, or a pending send's record (destination, fee). A
    /// transaction the ledger does not hold is looked up nowhere. `source` says which; `fee_sats` is 0 when an input
    /// is someone else's (its value is not the wallet's to know). `sp_address` (#3): the sp1 address a send from
    /// this phone was typed to — the chain shows only the taproot output it made.
    #[wasm_bindgen]
    pub fn tx_details(&self, txid: String, filter_base: Option<String>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (root_key, _independent, network) = {
                let wallet = inner
                    .lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.onchain_handles()
            };
            let storage: Arc<dyn lij_core::storage::LijStorage> = t2_storage(&root_key);
            let txid = txid.trim().to_ascii_lowercase();
            let mut view = lij_core::tier2_wallet::load_view(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pending = lij_core::tier2_wallet::load_pending(storage.as_ref());
            let pend = pending.iter().find(|p| p.txid == txid).cloned();
            let marks = lij_core::tier2_wallet::load_marks(storage.as_ref()).unwrap_or_default();
            let is_sp1 = |d: &str| { let l = d.trim().to_ascii_lowercase(); l.starts_with("sp1") || l.starts_with("tsp1") };
            let sp_address: Option<String> = marks.sp_sends.get(&txid).cloned()
                .or_else(|| pend.as_ref().and_then(|p| p.dest_addr.clone()).filter(|d| is_sp1(d)));
            // v306: a send to several — every recipient as typed (the record, else the pending send's)
            let recipients: Vec<serde_json::Value> = marks.send_dests.get(&txid).cloned()
                .or_else(|| pend.as_ref().map(|p| p.dests.clone()).filter(|d| !d.is_empty()))
                .unwrap_or_default()
                .iter()
                .map(|(d, v)| serde_json::json!({ "dest": d, "value": v, "sp": is_sp1(d) }))
                .collect();
            let ledger_h = lij_core::tier2_wallet::ledger_height_of(&view, &txid);
            let mut source = "ledger";
            // v300: a kept transaction comes without its signatures, its full weight beside it
            let mut found: Option<(bitcoin::Transaction, u32, Option<u64>)> = lij_core::tx_store::get(storage.as_ref(), &txid).map(|k| (k.tx, k.height, Some(k.weight)));
            if found.is_none() {
                if let Some(h) = ledger_h {
                    let base = lij_core::tier2_sync::filter_base_or_default(filter_base.as_deref());
                    let http: Arc<dyn lij_core::independent::EsploraHttp> = Arc::new(WasmEsploraHttp::for_filter_walk());
                    found = lij_core::tier2_wallet::reread_own_tx(&http, &base, storage.as_ref(), &txid, h)
                        .await
                        .map_err(|e| JsValue::from_str(&e.to_string()))?
                        .map(|(t, h)| (t, h, None));
                    source = "block";
                    view = lij_core::tier2_wallet::load_view(storage.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;   // the block time the re-read noted
                }
            }
            if found.is_none() {
                if let Some(p) = pend.as_ref() {
                    if let Some(t) = p.raw_tx_hex.as_deref().and_then(|hx| lij_core::tx_store::decode_checked(hx, &txid)) {
                        found = Some((t, 0, None)); source = "pending";
                    }
                }
            }
            let (tx, kept_h, kept_w) = match found {
                Some(x) => x,
                None => {
                    // a pending send recorded before v298 (no bytes kept): what this phone wrote down when it sent
                    if let Some(p) = pend.as_ref() {
                        let dest = p.dest_addr.clone().filter(|d| !is_sp1(d));
                        let out = serde_json::json!({
                            "txid": txid, "fee_sats": p.fee_sats.unwrap_or(0), "vsize": 0, "sat_vb": 0.0,
                            "confirmed": false, "height": null, "time": null, "our_in": 0, "our_out": 0,
                            "address": dest, "address_type": "", "outputs": [], "source": "pending-record", "sp_address": sp_address, "recipients": recipients,
                        });
                        return Ok(JsValue::from_str(&out.to_string()));
                    }
                    return Err(JsValue::from_str("not in this wallet's ledger — no lookup made"));
                }
            };
            let width = view.net_width.max(lij_core::tier2_wallet::NET_WIDTH);
            let scripts = t2_scripts(&root_key, network, width).await?;
            let ours = |spk_hex: &str| -> bool {
                match hex::decode(spk_hex) {
                    Ok(b) if !b.is_empty() => scripts.owner_of(&bitcoin::ScriptBuf::from_bytes(b)).is_some(),
                    _ => false,
                }
            };
            let store = lij_core::tx_store::load(storage.as_ref());
            let parents = |id: &str| -> Option<bitcoin::Transaction> {
                store.tx(id)
                    .or_else(|| pending.iter().find(|q| q.txid == id).and_then(|q| q.raw_tx_hex.as_deref()).and_then(|hx| lij_core::tx_store::decode_checked(hx, id)))
            };
            let height = ledger_h.or(if kept_h > 0 { Some(kept_h) } else { None });
            let (etx, fee_known) = lij_core::tier2_wallet::drill_tx(&view, &pending, &parents, &tx, network, height, kept_w);
            // v294 (S52, DP 21:49): ours = the m/84 net's scripts OR an outpoint the ledger holds as a coin — a
            // silent-payment coin (m/352) is never in the net (lij_core::tier2_wallet::tx_ownership).
            let own = lij_core::tier2_wallet::tx_ownership(&view, &etx, &ours);
            let (our_in, our_out) = (own.our_in, own.our_out);
            let mut outs = Vec::new();
            for (n, o) in etx.vouts.iter().enumerate() {
                outs.push(serde_json::json!({ "address": o.address, "value": o.value, "ours": own.outs_ours.get(n).copied().unwrap_or(false), "type": o.script_type }));
            }
            let fee = if fee_known { etx.fee } else { 0 };
            let vsize = if etx.weight > 0 { (etx.weight + 3) / 4 } else { 0 };
            let sat_vb = if vsize > 0 && fee > 0 { (fee as f64) / (vsize as f64) } else { 0.0 };
            // the address of record: a send → the output that isn't ours; a receive → our output;
            // a self-move (channel funding) → our funding output
            let pick = own.pick.and_then(|n| etx.vouts.get(n));
            let (address, address_type) = match pick { Some(o) => (o.address.clone(), o.script_type.clone()), None => (None, String::new()) };
            let out = serde_json::json!({
                "txid": etx.txid, "fee_sats": fee, "vsize": vsize, "sat_vb": (sat_vb * 10.0).round() / 10.0,
                "confirmed": etx.confirmed, "height": etx.block_height, "time": etx.block_time,
                "our_in": our_in, "our_out": our_out, "address": address, "address_type": address_type, "outputs": outs,
                "source": source, "sp_address": sp_address, "recipients": recipients,
            });
            Ok(JsValue::from_str(&out.to_string()))
        })
    }

    /// v300 (S52, DP 00:25 "if a wallet approaches 1000 transactions, some notification to the user should happen that
    /// lets them either delete old data or expand the size"): the kept transactions' state for the page —
    /// {"count","cap","near","bytes","oldest_height","steps"}; `near` = 90 % of the ceiling.
    #[wasm_bindgen]
    pub fn tx_keep_status(&self) -> Result<String, JsValue> {
        let storage: Arc<dyn lij_core::storage::LijStorage> = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            t2_storage(&wallet.onchain_handles().0)
        };
        serde_json::to_string(&lij_core::tx_store::status(storage.as_ref())).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v300: "expand the size" — the ceiling, one of the offered steps (1,000 / 2,000 / 4,000); a lower one trims the
    /// oldest at once. Answers the new status.
    #[wasm_bindgen]
    pub fn tx_keep_set_cap(&self, cap: u32) -> Result<String, JsValue> {
        let storage: Arc<dyn lij_core::storage::LijStorage> = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            t2_storage(&wallet.onchain_handles().0)
        };
        let st = lij_core::tx_store::set_cap(storage.as_ref(), cap as usize).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&st).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v300: "delete old data" — the kept transactions from blocks below `height` go (their rows read their block again
    /// when tapped); coins, balance and history are not touched. Answers how many went.
    #[wasm_bindgen]
    pub fn tx_keep_drop_before(&self, height: u32) -> Result<u32, JsValue> {
        let storage: Arc<dyn lij_core::storage::LijStorage> = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            t2_storage(&wallet.onchain_handles().0)
        };
        lij_core::tx_store::drop_before(storage.as_ref(), height).map(|n| n as u32).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn onchain_history(&self) -> js_sys::Promise {
        future_to_promise(async move { Ok::<JsValue, JsValue>(JsValue::from_str("[]")) })
    }

    /// Phase 10b — Send via LSP-provided route (Routing as a Service).
    ///
    /// Today's signature takes route_endpoint and route_macaroon as parameters.
    /// JS callers must look these up themselves (e.g., from a hardcoded test
    /// constant or from the wallet's active LSP record).
    ///
    /// FUTURE — LIJOX MARKETPLACE INTEGRATION:
    /// When the LIJOX marketplace UI ships and the user selects an LSP, the
    /// active LSP record will carry `route_endpoint` and `route_macaroon`
    /// (already added to LspInfo struct). At that point this method should be
    /// changed to:
    ///   pub fn send_payment_via_lsp_route(&self, bolt11: &str) -> js_sys::Promise
    /// and read the credentials from `wallet.active_lsp()` internally.
    /// See lsp.rs LspInfo for the field definitions.
    ///
    /// v8: refactored to release the wallet mutex during the HTTP fetch.
    /// Pattern: lock-prepare-unlock, fetch (no lock), lock-apply-unlock. Mirrors
    /// open_channel's structure. Required to prevent the mutex_no_threads panic
    /// observed in session 14 when LDK background_tick tried to acquire the
    /// wallet lock during a long-running Phase 10b POST.
    #[wasm_bindgen]
    pub fn send_payment_via_lsp_route(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        future_to_promise(async move {
            // Phase 1: lock, prepare, release
            let prep = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node()
                    .prepare_lsp_route_request(&bolt11, &route_endpoint, &[], None)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // mutex released here

            // Phase 2: HTTP fetch WITHOUT the wallet lock held
            let response_text = lij_core::node::fetch_post_with_macaroon(
                &prep.url,
                &route_macaroon_hex,
                &prep.request_body,
            )
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Phase 3: lock, apply, release
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node()
                    .apply_lsp_route_and_send(&response_text, &prep)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v8: Send a Lightning payment via Phase 10b LSP routing with automatic
    /// retry-on-path-failure. On each attempt, the wallet asks the LSP for a
    /// route, submits the HTLC with a FRESH PaymentId, then polls the per-
    /// payment outcome map for the final result. If the result is PathFailed
    /// (a hop bounced the HTLC with temporary_channel_failure or similar), the
    /// failed (from, to) pubkey pair is appended to the excluded-pairs list,
    /// the old PaymentId is abandoned in LDK's OutboundPayments, and the next
    /// attempt asks the LSP to route around the failed hop with a new id.
    ///
    /// Up to `max_retries` attempts. Returns the final PaymentResult — either
    /// success (Sent), permanent failure (Failed or PathFailed with
    /// payment_failed_permanently=true), or "retries exhausted" if all
    /// max_retries attempts had path failures.
    ///
    /// Mutex discipline: the wallet lock is acquired briefly for prepare,
    /// apply, and abandon, then released for the HTTP fetch AND for the
    /// outcome polling loop. Background_tick and WS handlers can run while we
    /// wait, which is required for LDK to process the PaymentSent/PathFailed/
    /// Failed events from the peer messages and populate the outcome map.
    #[wasm_bindgen]
    pub fn send_payment_with_retries(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        max_retries: u32,
        progress_callback: &js_sys::Function,
        amount_sats_override: Option<u64>,
        amount_msat_override: Option<u64>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        let max_retries = max_retries.max(1); // at least one attempt
        // S45 (DP, "truly 0"): an exact millisat amount for a no-amount invoice.
        // It rides the single-path prepare only; MPP parts stay whole sats. The
        // sats override is derived from it when the page gives only msat.
        let amount_sats_override: Option<u64> = amount_sats_override.or(amount_msat_override.map(|m| m / 1000));
        let progress_callback = progress_callback.clone();
        future_to_promise(async move {
            use lij_core::node::PaymentOutcome;

            // v10: emit progress events to JS so the wallet UI can render
            // per-attempt telemetry (attempt number, exclusion count, outcome).
            // The callback receives a single JSON string argument; JS parses
            // and renders. Errors from the callback are swallowed so a buggy
            // UI handler can never break the payment flow.
            let emit = |json: String| {
                let _ = progress_callback.call1(
                    &wasm_bindgen::JsValue::NULL,
                    &wasm_bindgen::JsValue::from_str(&json),
                );
            };

            // ── MPP gate (v158) ───────────────────────────────────────────────
            // Decide single-path vs multipath up front. `Single` falls through to
            // the unchanged retry loop below; every other outcome is handled and
            // RETURNS here. Multipath assembles one shard per usable channel and
            // submits a single send_payment_with_route (one payment_hash).
            let mpp_decision = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.node().mpp_decision(&bolt11, amount_sats_override)
            };
            match mpp_decision {
                Ok(lij_core::node::MppDecision::Single) => {
                    // fall through to the single-path retry loop below.
                }
                Ok(lij_core::node::MppDecision::NoMppSupport) => {
                    emit(r#"{"phase":"no_mpp_support"}"#.to_string());
                    return Ok(payment_result_json(false, None, None, Some(
                        "recipient does not support split (MPP) payments — consolidate liquidity or request a smaller invoice".to_string())));
                }
                Ok(lij_core::node::MppDecision::ExceedsTotal { sendable_msat }) => {
                    let sendable_sats = sendable_msat / 1000;
                    emit(format!(r#"{{"phase":"exceeds_total","sendable_sats":{}}}"#, sendable_sats));
                    return Ok(payment_result_json(false, None, None, Some(format!(
                        "amount exceeds your total sendable across all channels (~{} sats)", sendable_sats))));
                }
                Ok(lij_core::node::MppDecision::Multi(parts)) => {
                    let shard_count = parts.len();
                    log::info!("[MPP] multipath send: {} shard(s)", shard_count);
                    emit(format!(r#"{{"phase":"mpp_start","shards":{}}}"#, shard_count));
                    let mut responses: Vec<(String, u64)> = Vec::with_capacity(shard_count);
                    for (i, part) in parts.iter().enumerate() {
                        let part_sats = part.part_msat / 1000;
                        emit(format!(
                            r#"{{"phase":"mpp_shard","shard":{},"shards":{},"sats":{}}}"#,
                            i + 1, shard_count, part_sats));
                        // lock: build THIS shard's route-build body (part amount)
                        let (url, body) = {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            match wallet.node().prepare_lsp_route_request(
                                &bolt11, &route_endpoint, &[], Some(part_sats))
                            {
                                Ok(p) => (p.url, p.request_body),
                                Err(e) => {
                                    emit(r#"{"phase":"mpp_error"}"#.to_string());
                                    return Ok(payment_result_json(false, None, None, Some(
                                        format!("MPP shard {} prepare failed: {}", i + 1, e))));
                                }
                            }
                        };
                        // fetch (lock released)
                        let resp = match lij_core::node::fetch_post_with_macaroon(
                            &url, &route_macaroon_hex, &body).await
                        {
                            Ok(t) => t,
                            Err(e) => {
                                emit(r#"{"phase":"mpp_error"}"#.to_string());
                                return Ok(payment_result_json(false, None, None, Some(
                                    format!("MPP shard {} HTTP error: {}", i + 1, e))));
                            }
                        };
                        responses.push((resp, part.scid));
                    }
                    // lock: assemble all shards + send as ONE payment.
                    // v160: also grab the outcomes handle — submission is NOT
                    // success (review 1.1); truth comes from LDK events.
                    let (result, outcomes_handle) = {
                        let wallet = inner.lock()
                            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                        (
                            wallet.node().send_mpp_from_responses(responses, &bolt11),
                            wallet.node().payment_outcomes_handle(),
                        )
                    };
                    let payment_id = match result {
                        Ok((r, pid)) if r.success => pid,
                        Ok((r, _)) => {
                            // synchronous rejection — abandon already ran in core
                            emit(r#"{"phase":"mpp_failed","stage":"submit"}"#.to_string());
                            return Ok(payment_result_json(false, None, None, r.error));
                        }
                        Err(e) => {
                            emit(r#"{"phase":"mpp_failed","stage":"submit"}"#.to_string());
                            return Ok(payment_result_json(false, None, None, Some(
                                format!("MPP send failed: {}", e))));
                        }
                    };

                    // Settlement poll: the recipient must assemble ALL shards
                    // before claiming; its MPP window (~60s) plus fail-back
                    // propagation bounds the wait — 120s covers the envelope.
                    emit(format!(r#"{{"phase":"mpp_settling","shards":{}}}"#, shard_count));
                    let outcome = wait_for_outcome(
                        outcomes_handle.clone(), payment_id, 120_000).await;
                    return match outcome {
                        Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                            log::info!("[MPP] settled: all shards claimed by recipient");
                            emit(r#"{"phase":"mpp_settled"}"#.to_string());
                            Ok(payment_result_json(true, preimage_hex,
                                fee_paid_msat, None))   // v270: msat through
                        }
                        Some(PaymentOutcome::PathFailed { failed_scid, is_permanent, .. }) => {
                            let scid_str = failed_scid.map(|s| s.to_string())
                                .unwrap_or_else(|| "none".into());
                            log::warn!("[MPP] shard path failed at scid={} permanent={}",
                                scid_str, is_permanent);
                            emit(format!(
                                r#"{{"phase":"mpp_failed","stage":"shard","scid":"{}","permanent":{}}}"#,
                                scid_str, is_permanent));
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[MPP] abandon_payment warning: {}", e);
                                }
                                outcomes_handle.lock().unwrap().remove(&payment_id);
                            }
                            Ok(payment_result_json(false, None, None, Some(format!(
                                "MPP shard failed at scid={} — nothing was delivered; funds returned to you",
                                scid_str))))
                        }
                        Some(PaymentOutcome::Failed { reason }) => {
                            log::warn!("[MPP] payment terminally failed: {}", reason);
                            emit(r#"{"phase":"mpp_failed","stage":"terminal"}"#.to_string());
                            Ok(payment_result_json(false, None, None, Some(
                                format!("MPP payment failed: {}", reason))))
                        }
                        None => {
                            log::warn!("[MPP] settlement unconfirmed after 120s — abandoning, then waiting for the verdict (6a discipline)");
                            emit(r#"{"phase":"mpp_timeout"}"#.to_string());
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[MPP] abandon_payment warning: {}", e);
                                }
                            }
                            // 6a (S36, sender concurrent-retry redesign): the
                            // same abandon-then-wait as single-path — shards
                            // may sit held and abandon cannot recall them; a
                            // blind user resend is the same-hash duplicate
                            // class. Wait for the verdict before reporting.
                            emit(r#"{"phase":"awaiting_release","mpp":true}"#.to_string());
                            let verdict = wait_for_outcome(
                                outcomes_handle.clone(), payment_id, 600_000).await;
                            match verdict {
                                Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                                    log::info!("[MPP] late settle after timeout — payment succeeded");
                                    emit(r#"{"phase":"mpp_settled"}"#.to_string());
                                    Ok(payment_result_json(true, preimage_hex,
                                        fee_paid_msat, None))   // v270: msat through
                                }
                                Some(_) => Ok(payment_result_json(false, None, None, Some(
                                    "split payment failed back — nothing was delivered; funds returned to you; safe to retry".to_string()))),
                                None => Ok(payment_result_json(false, None, None, Some(
                                    "split payment still unresolved after 10 more minutes — your sats are locked in flight, not lost; do NOT resend (check Activity)".to_string()))),
                            }
                        }
                    };
                }
                Err(e) => {
                    return Ok(payment_result_json(false, None, None, Some(
                        format!("MPP planning failed: {}", e))));
                }
            }

            // ── 6a (S36, sender concurrent-retry redesign) m2: pre-dispatch
            // in-flight probe. If LDK still tracks a PENDING outbound payment
            // for this invoice's hash (e.g. a page reload mid-hold), JOIN THE
            // WAIT — dispatching now would create a same-hash duplicate HTLC
            // (the S35 stacking class: one revealed preimage claims every
            // sibling). Poll until it resolves (≤10 min), then stop with
            // honest words: the in-loop verdict logic below only governs
            // attempts THIS call dispatched; an inherited in-flight payment
            // resolves to Activity, never to an auto-resend.
            {
                let preexisting = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    wallet.node().pending_payment_for_bolt11(&bolt11)
                };
                if let Some(pid_hex) = preexisting {
                    log::warn!("[6a-guard] in-flight HTLC already tracked for this invoice (payment_id={}) — waiting, not dispatching", pid_hex);
                    emit(r#"{"phase":"awaiting_release","inherited":true}"#.to_string());
                    use wasm_timer::Delay as GuardDelay;
                    let guard_started = js_sys::Date::now();
                    loop {
                        let _ = GuardDelay::new(std::time::Duration::from_millis(2000)).await;
                        let still = {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            wallet.node().pending_payment_for_bolt11(&bolt11)
                        };
                        if still.is_none() { break; }
                        if js_sys::Date::now() - guard_started > 600_000.0 {
                            return Ok(payment_result_json(false, None, None, Some(
                                "a previous attempt for this invoice is still in flight after 10 minutes — your sats are locked, not lost; do NOT resend; it will settle or fail back on its own (check Activity)".to_string())));
                        }
                    }
                    // Resolved — but WHICH way is not knowable from here
                    // (this call has no outcomes entry for an inherited id).
                    // Never auto-resend on ambiguity.
                    return Ok(payment_result_json(false, None, None, Some(
                        "a previous attempt for this invoice just resolved — check Activity before sending again (if the recipient was paid, the invoice is settled)".to_string())));
                }
            }

            let mut excluded_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut last_error: Option<String> = None;

            for attempt in 1..=max_retries {
                log::info!("[Phase10b-retry] attempt {}/{}, {} excluded pair(s) so far",
                    attempt, max_retries, excluded_pairs.len());
                emit(format!(
                    r#"{{"phase":"attempt_start","attempt":{},"max_retries":{},"excluded":{}}}"#,
                    attempt, max_retries, excluded_pairs.len()
                ));

                // ── Phase 1: lock, prepare (new PaymentId), release ──────────
                let mut prep = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    match wallet.node()
                        .prepare_lsp_route_request_msat(&bolt11, &route_endpoint, &excluded_pairs, amount_msat_override.or(amount_sats_override.map(|s| s.saturating_mul(1000)))) // B1: open-invoice amount ride; S45: msat-exact when the page gives its the single path
                    {
                        Ok(p) => p,
                        Err(e) => {
                            // Prepare failure (e.g. invoice decode) — terminal.
                            emit(format!(
                                r#"{{"phase":"prepare_error","attempt":{},"max_retries":{}}}"#,
                                attempt, max_retries
                            ));
                            return Ok(payment_result_json(false, None, None,
                                Some(format!("prepare failed: {}", e))));
                        }
                    }
                };

                // v223 (S39, 0.57.0 item h): held-claim internal sends have
                // dest == the active LSP; stamp the silence-phase events so
                // the page narrates a HELD payment instead of a search.
                let dest_is_lsp = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    wallet.node().dest_is_active_lsp(&prep.dest_pubkey_hex)
                };

                let payment_id = prep.payment_id;
                let mut lsp_height: Option<u32> = None;   // v249: LND's height from the hold verdict (internal sends)

                // ── Phase 2: HTTP fetch WITHOUT lock ──────────────────────
                // v227 (S43, speed): an INTERNAL send (dest == the active LSP)
                // never needed the answer — apply_lsp_route_and_send's v222
                // branch builds the wallet→LSP self-hop before reading it, and
                // since adapter 0.62.1 the LSP answered this exact body. Skip
                // the round trip and hand that body over verbatim; everything
                // downstream (lsp_hold parse, apply) sees what it saw before.
                // External destinations take the fetch exactly as before.
                let response_text = if dest_is_lsp {
                    log::info!("[Phase10b-retry] internal send (dest == active LSP) — route ask skipped (v227)");
                    // v244 (S46, DP): the hold verdict for an INTERNAL send. The invoice was
                    // minted by the LSP (an LNURL pool hash), so route/build never sees it and
                    // no lsp_hold ever reached the page — the sender waited 30 s and booked
                    // "failed" while the HTLC was held. One small GET to the LSP's outcome
                    // oracle: owner offline → the same lsp_hold shape the external path gets,
                    // and the page narrates HELD from the first second. Any failure of the
                    // ask falls back to the old body (no verdict, the timeout narrates).
                    let hash_hex = hex::encode(prep.payment_hash.0);
                    let base = prep.url.split("/v1/").next().unwrap_or("").to_string();
                    let verdict = if base.is_empty() { None } else {
                        match lij_core::node::fetch_get_with_macaroon(&format!("{base}/v1/outcome?hash={hash_hex}"), &route_macaroon_hex).await {
                            Ok(t) => serde_json::from_str::<serde_json::Value>(&t).ok(),
                            Err(e) => { log::warn!("[v244] hold verdict ask failed: {e}"); None }
                        }
                    };
                    // v246: the verdict is logged whatever it says (v245 logged only the offline
                    // case, so a 'live' answer left no trace on the tape).
                    if let Some(v) = verdict.as_ref() {
                        log::info!("[v244] hold verdict: owner_live={:?} peer={:?} heard_s={:?} cap_s={:?} height={:?}",
                            v.get("owner_live"), v.get("owner_peer"), v.get("owner_heard_s"), v.get("hold_cap_s"), v.get("height"));
                        lsp_height = v.get("height").and_then(|h| h.as_u64()).map(|h| h as u32);   // v249 (adapter 0.76.1)
                    }
                    match verdict.as_ref().and_then(|v| v.get("owner_live")).and_then(|b| b.as_bool()) {
                        Some(false) => {
                            let cap = verdict.as_ref().and_then(|v| v.get("hold_cap_s")).and_then(|c| c.as_u64()).unwrap_or(3600);
                            log::info!("[v244] internal send: the hash's owner is offline — HOLD from the start (cap {cap}s)");
                            format!(r#"{{"ok":false,"error":"destination_is_lsp","routes":[],"internal":true,"lsp_hold":{{"active":true,"kind":"lnurlp","cap_s":{cap}}}}}"#)
                        }
                        _ => String::from(r#"{"ok":false,"error":"destination_is_lsp","routes":[],"internal":true}"#),
                    }
                } else { match lij_core::node::fetch_post_with_macaroon(
                    &prep.url,
                    &route_macaroon_hex,
                    &prep.request_body,
                ).await {
                    Ok(t) => t,
                    Err(e) => {
                        last_error = Some(format!("HTTP error: {}", e));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"http_error","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        continue;
                    }
                } };

                // #29-hold (v167): adapter-signaled bounded hold — recipient
                // offline, LSP parks the HTLC (B-1/B-7). One HTLC, patient
                // wait, and NEVER a second attempt: retries against a held
                // payment stack duplicate HTLCs and manufacture false
                // failures while the money quietly settles (M3 evidence).
                let lsp_hold_cap_s: Option<u64> = (|| {
                    let parsed: serde_json::Value = serde_json::from_str(&response_text).ok()?;
                    let hold = parsed.get("lsp_hold")?;
                    if hold.get("active")?.as_bool()? { hold.get("cap_s")?.as_u64() } else { None }
                })();

                // ── Phase 3: lock, apply (submit HTLC), get outcomes handle, release ──
                let (apply_result, outcomes_handle) = {
                    let wallet = inner.lock()
                        .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                    // v249 (S46, DP GO): an INTERNAL send builds its HTLC expiry from THIS wallet's
                    // LDK tip + 1 + the invoice's final CLTV (144); LND requires its OWN height +
                    // 144. DP's Android sat six blocks behind (the stream loss fixed alongside)
                    // and every internal send came back "recipient rejected". With the LSP's
                    // height in the verdict, raise the self-hop delta by the lag so the HTLC
                    // clears LND's floor whatever the phone's tip says — more expiry on a direct
                    // channel only widens the LSP's room to hold.
                    if let (true, Some(h), Some(b)) = (dest_is_lsp, lsp_height, wallet.node().ldk_best_block_height()) {
                        if h > b {
                            let lag = h - b;
                            prep.final_cltv_delta += lag;
                            log::warn!("[v249] LSP height {} is {} block(s) ahead of this wallet's tip {} — self-hop CLTV raised to {}", h, lag, b, prep.final_cltv_delta);
                        }
                    }
                    let result = wallet.node()
                        .apply_lsp_route_and_send(&response_text, &prep)
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    let handle = wallet.node().payment_outcomes_handle();
                    (result, handle)
                };

                if !apply_result.success {
                    // Synchronous failure from cm.send_payment_with_route —
                    // typically means an immediate validation rejection
                    // (insufficient capacity, route_not_found, etc.). No
                    // outcome event will fire for this attempt.
                    last_error = apply_result.error.clone();
                    log::warn!("[Phase10b-retry] synchronous send rejection: {:?}", last_error);
                    emit(format!(
                        r#"{{"phase":"sync_reject","attempt":{},"max_retries":{}}}"#,
                        attempt, max_retries
                    ));
                    if attempt >= max_retries {
                        return Ok(payment_result_json(false, None, None, last_error));
                    }
                    continue;
                }

                // ── Phase 4: poll outcomes map WITHOUT lock ────────────────
                // Normal: 30s per attempt. HELD: the LSP told us it parked the
                // HTLC (recipient offline) — wait the full hold cap + 60s
                // grace; the upstream settle or watchdog-fail decides.
                let wait_ms = match lsp_hold_cap_s {
                    Some(cap) => {
                        emit(format!(
                            r#"{{"phase":"held","attempt":{},"cap_s":{}}}"#,
                            attempt, cap));
                        cap.saturating_add(60) * 1000
                    }
                    None => 30000,
                };
                let outcome = wait_for_outcome(outcomes_handle.clone(), payment_id, wait_ms).await;

                match outcome {
                    Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                        log::info!("[Phase10b-retry] PAYMENT SUCCEEDED on attempt {}/{}",
                            attempt, max_retries);
                        emit(format!(
                            r#"{{"phase":"succeeded","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        return Ok(payment_result_json(
                            true,
                            preimage_hex,
                            fee_paid_msat,   // v270: msat through
                            None,
                        ));
                    }
                    Some(PaymentOutcome::PathFailed {
                        failed_scid,
                        failed_from_pubkey,
                        failed_to_pubkey,
                        is_permanent,
                    }) => {
                        let scid_str = failed_scid.map(|s| s.to_string()).unwrap_or_else(|| "none".into());
                        last_error = Some(format!(
                            "path failed at scid={} (attempt {}/{}{})",
                            scid_str, attempt, max_retries,
                            if is_permanent { ", permanent" } else { "" }
                        ));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"path_failed","attempt":{},"max_retries":{},"scid":"{}","permanent":{}}}"#,
                            attempt, max_retries, scid_str, is_permanent
                        ));

                        if lsp_hold_cap_s.is_some() {
                            // Held payments never retry: the failure IS the
                            // hold's verdict (recipient stayed offline past
                            // the window); the sats are already returned.
                            log::warn!("[Phase10b-retry] held payment failed — recipient stayed offline; not retrying");
                            return Ok(payment_result_json(false, None, None, Some(
                                "recipient stayed offline — the held payment expired and your sats were returned".to_string())));
                        }
                        if is_permanent {
                            log::warn!("[Phase10b-retry] permanent failure — not retrying");
                            return Ok(payment_result_json(false, None, None, last_error));
                        }

                        if let (Some(from), Some(to)) = (failed_from_pubkey, failed_to_pubkey) {
                            log::info!("[Phase10b-retry] adding exclusion: from={}… to={}…",
                                hex::encode(&from[..8.min(from.len())]),
                                hex::encode(&to[..8.min(to.len())]));
                            excluded_pairs.push((from, to));
                        } else {
                            log::warn!("[Phase10b-retry] no exclusion data (failed scid=0 or self-channel) — retry may hit same path");
                        }

                        // Abandon the old payment_id in LDK so its Retryable
                        // state is cleaned up. This fires PaymentFailed for
                        // the old id (our handler records it, then we drain
                        // it below). Without abandon, the OutboundPayments
                        // map grows by one entry per retry attempt.
                        {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                log::warn!("[Phase10b-retry] abandon_payment warning: {}", e);
                            }
                            // Also drop the old outcome entry to prevent map growth
                            outcomes_handle.lock().unwrap().remove(&payment_id);
                        }

                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        // continue loop for next attempt
                    }
                    Some(PaymentOutcome::Failed { reason }) => {
                        // v9: RetriesExhausted is LDK's internal retry budget,
                        // not a terminal payment failure. node.rs PaymentFailed
                        // handler preserves the prior PathFailed in this case,
                        // so we usually take the PathFailed arm above. This is
                        // a safety net for cases where Failed somehow arrives
                        // without a prior PathFailed (shouldn't happen in
                        // practice but defensive coding here costs nothing).
                        if reason.contains("RetriesExhausted") && attempt < max_retries && lsp_hold_cap_s.is_none() {
                            last_error = Some(format!(
                                "LDK retries exhausted (attempt {}/{}) — retrying without specific exclusion",
                                attempt, max_retries));
                            log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                            {
                                let wallet = inner.lock()
                                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                                if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                    log::warn!("[Phase10b-retry] abandon_payment warning: {}", e);
                                }
                                outcomes_handle.lock().unwrap().remove(&payment_id);
                            }
                            continue;
                        }
                        log::warn!("[Phase10b-retry] PaymentFailed (terminal): {}", reason);
                        emit(format!(
                            r#"{{"phase":"terminal_failure","attempt":{},"max_retries":{}}}"#,
                            attempt, max_retries
                        ));
                        return Ok(payment_result_json(false, None, None,
                            Some(format!("terminal failure: {}", reason))));
                    }
                    None => {
                        if lsp_hold_cap_s.is_some() {
                            // Held wait elapsed without any event — treat as
                            // the hold expiring; never a second attempt.
                            emit(format!(r#"{{"phase":"held_expired","attempt":{}}}"#, attempt));
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            let _ = wallet.node().abandon_payment(payment_id);
                            outcomes_handle.lock().unwrap().remove(&payment_id);
                            return Ok(payment_result_json(false, None, None, Some(
                                "hold window elapsed — recipient did not return; your sats return automatically".to_string())));
                        }
                        last_error = Some(format!(
                            "timeout waiting for outcome (attempt {}/{}, 30s elapsed)",
                            attempt, max_retries));
                        log::warn!("[Phase10b-retry] {}", last_error.as_ref().unwrap());
                        emit(format!(
                            r#"{{"phase":"timeout","attempt":{},"max_retries":{},"dest_is_lsp":{}}}"#,
                            attempt, max_retries, dest_is_lsp
                        ));

                        // ── 6a (S36, sender concurrent-retry redesign) m1:
                        // ABANDON-THEN-WAIT. Silence ≠ failure: the HTLC may
                        // be parked at an interceptor (unsignaled hold), and
                        // abandon_payment cannot recall an in-flight HTLC —
                        // it only stops LDK's own retries; the terminal
                        // PaymentFailed fires ONLY once every HTLC has
                        // actually failed back. The old code deleted its map
                        // entry and re-dispatched immediately — a fresh
                        // full-amount HTLC per 30s of silence (the S35
                        // five-sibling stack; one revealed preimage claims
                        // every sibling). Now: abandon, KEEP the entry, wait
                        // for the verdict; only a confirmed fail-back
                        // permits a retry.
                        {
                            let wallet = inner.lock()
                                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                            if let Err(e) = wallet.node().abandon_payment(payment_id) {
                                log::warn!("[Phase10b-retry] abandon_payment (timeout) warning: {}", e);
                            }
                            // outcomes entry deliberately NOT removed — it is
                            // the release signal we are about to wait on.
                        }
                        emit(format!(
                            r#"{{"phase":"awaiting_release","attempt":{},"max_retries":{},"dest_is_lsp":{}}}"#,
                            attempt, max_retries, dest_is_lsp
                        ));
                        let verdict = wait_for_outcome(
                            outcomes_handle.clone(), payment_id, 600_000).await;
                        match verdict {
                            Some(PaymentOutcome::Sent { preimage_hex, fee_paid_msat }) => {
                                // Late settle: the "stuck" HTLC was a held
                                // payment that completed — success, and the
                                // exact case where a blind retry double-pays.
                                log::info!("[6a-guard] late settle after timeout — payment succeeded");
                                emit(format!(r#"{{"phase":"late_settle","attempt":{}}}"#, attempt));
                                return Ok(payment_result_json(true, preimage_hex,
                                    fee_paid_msat, None));   // v270: msat through
                            }
                            Some(PaymentOutcome::PathFailed { .. }) => {
                                // PaymentPathFailed IS the fail-back receipt:
                                // the HTLC came home. Drain the trailing
                                // PaymentFailed(UserAbandoned) the abandon
                                // above will fire for this id, then retry.
                                log::info!("[6a-guard] fail-back confirmed after timeout — retry permitted");
                                emit(format!(r#"{{"phase":"release_confirmed","attempt":{}}}"#, attempt));
                                {
                                    use wasm_timer::Delay as DrainDelay;
                                    for _ in 0..15 {
                                        let _ = DrainDelay::new(std::time::Duration::from_millis(100)).await;
                                        if outcomes_handle.lock().unwrap().remove(&payment_id).is_some() { break; }
                                    }
                                }
                            }
                            Some(PaymentOutcome::Failed { .. }) => {
                                // Terminal PaymentFailed: every HTLC for this
                                // id resolved failed. Retry is safe.
                                log::info!("[6a-guard] terminal fail-back confirmed after timeout — retry permitted");
                                emit(format!(r#"{{"phase":"release_confirmed","attempt":{}}}"#, attempt));
                            }
                            None => {
                                // Ten further minutes and the HTLC is STILL
                                // neither settled nor failed back. Honest
                                // stop — the invariant forbids another
                                // dispatch while it hangs.
                                return Ok(payment_result_json(false, None, None, Some(
                                    "previous attempt still unresolved after 10 minutes — your sats are locked in flight, not lost; do NOT resend; it will settle or fail back on its own (check Activity)".to_string())));
                            }
                        }

                        if attempt >= max_retries {
                            return Ok(payment_result_json(false, None, None, last_error));
                        }
                        // continue — retry without specific exclusion
                    }
                }
            }

            // Loop fell through (shouldn't happen — every branch returns).
            Ok(payment_result_json(false, None, None,
                last_error.or_else(|| Some("retry loop exhausted".into()))))
        })
    }

    /// S45 (DP): the same quote for a PUBKEY destination with no invoice —
    /// Max pricing a route to another LSP's node (an LNURL address that LSP
    /// serves) before any invoice is minted. Records any lsp_first_hop_policy
    /// sighting like quote_route_fee. Resolves to the same JSON shape.
    #[wasm_bindgen]
    pub fn quote_route_fee_to_pubkey(
        &self,
        dest_pubkey_hex: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        amount_sats: u64,
    ) -> js_sys::Promise {
        let dest = dest_pubkey_hex.to_string();
        let endpoint = route_endpoint.to_string();
        let mac = route_macaroon_hex.to_string();
        future_to_promise(async move {
            let (url, body) = lij_core::node::prepare_route_quote_to_pubkey(&dest, &endpoint, amount_sats)
                .map_err(|e| JsValue::from_str(&format!("{e}")))?;
            let response_text = lij_core::node::fetch_post_with_macaroon(&url, &mac, &body).await
                .map_err(|e| JsValue::from_str(&format!("quote fetch: {}", e)))?;
            let amount_msat = amount_sats.saturating_mul(1000);
            let fee_msat = lij_core::node::quote_total_fee_msat_from_response(&response_text, amount_msat);
            let synth = serde_json::from_str::<serde_json::Value>(&response_text).ok()
                .and_then(|v| v.get("_synth").and_then(|s| s.as_bool()))
                .unwrap_or(false);
            let policy_seen = lij_core::node::LSP_FEE_SEEN.load(std::sync::atomic::Ordering::Relaxed);
            Ok(JsValue::from_str(&format!(
                r#"{{"fee_msat":{},"fee_sats":{},"amount_msat":{},"policy_seen":{},"synth":{}}}"#,
                fee_msat, (fee_msat + 999) / 1000, amount_msat, policy_seen, synth)))
        })
    }

    /// v216 (S36, O6 fee headroom → exact-fee): the scan-time quote. Runs the
    /// SAME route-build the send path uses (pure QueryRoutes proxy — verified
    /// side-effect-free in adapter code), records any lsp_first_hop_policy
    /// sighting into the exact-fee cache, and returns the total sender fee
    /// for this invoice/amount. The throwaway PaymentId from prepare is never
    /// applied. Resolves to JSON:
    ///   {"fee_msat":N,"fee_sats":N,"amount_msat":N,"policy_seen":bool,"synth":bool}
    #[wasm_bindgen]
    pub fn quote_route_fee(
        &self,
        bolt11: &str,
        route_endpoint: &str,
        route_macaroon_hex: &str,
        amount_sats_override: Option<u64>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        future_to_promise(async move {
            // Amount first: invoice-fixed or override (open invoices) — core
            // helper, lij-wasm carries no lightning-invoice dep of its own.
            let amount_msat: u64 = lij_core::node::invoice_amount_msat(&bolt11, amount_sats_override)
                .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
            // Prepare under lock (brief), release before network — v8 discipline.
            let (prep, internal) = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let prep = wallet.node()
                    .prepare_lsp_route_request(&bolt11, &route_endpoint, &[], amount_sats_override)
                    .map_err(|e| JsValue::from_str(&format!("quote prepare: {}", e)))?;
                // v248 (S46, DP): an INTERNAL destination (the invoice was minted on the active LSP's
                // own node — the static-address rail) is paid over the single wallet→LSP hop with
                // ZERO routing fee (v222: the self-hop's fee_msat is the delivered amount). The quote
                // applied the LSP's first-hop policy to it and showed ~0.1% for a payment that costs
                // nothing; the send itself was always right. Same test the send uses (v222_self_dest).
                let internal = wallet.node().active_lsp()
                    .map(|a| a.info.pubkey.eq_ignore_ascii_case(&prep.dest_pubkey_hex))
                    .unwrap_or(false);
                (prep, internal)
            };
            if internal {
                let policy_seen = lij_core::node::LSP_FEE_SEEN
                    .load(std::sync::atomic::Ordering::Relaxed);
                return Ok(JsValue::from_str(&format!(
                    r#"{{"fee_msat":0,"fee_sats":0,"amount_msat":{},"policy_seen":{},"synth":false,"internal":true}}"#,
                    amount_msat, policy_seen)));
            }
            let response_text = lij_core::node::fetch_post_with_macaroon(
                &prep.url, &route_macaroon_hex, &prep.request_body).await
                .map_err(|e| JsValue::from_str(&format!("quote fetch: {}", e)))?;
            let fee_msat = lij_core::node::quote_total_fee_msat_from_response(
                &response_text, amount_msat);
            let synth = serde_json::from_str::<serde_json::Value>(&response_text).ok()
                .and_then(|v| v.get("_synth").and_then(|s| s.as_bool()))
                .unwrap_or(false);
            let policy_seen = lij_core::node::LSP_FEE_SEEN
                .load(std::sync::atomic::Ordering::Relaxed);
            Ok(JsValue::from_str(&format!(
                r#"{{"fee_msat":{},"fee_sats":{},"amount_msat":{},"policy_seen":{},"synth":{}}}"#,
                fee_msat, (fee_msat + 999) / 1000, amount_msat, policy_seen, synth)))
        })
    }

    #[wasm_bindgen]
    pub fn create_invoice(
        &self,
        amount_sats: Option<u64>,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: Option<String>,
        lsp_route_macaroon: Option<String>,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        future_to_promise(async move {
            // Build under lock (sync, brief), release before any network I/O
            // -- the v8 mutex discipline.
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                wallet.create_invoice(amount_sats, &memo, expiry_seconds)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };
            // v168: best-effort hash-keyed secret registration so held
            // forwards can trampoline (B-10) with the sender offline. NEVER
            // fails the invoice -- a miss just means legacy RESUME semantics.
            if let (Some(ep), Some(mac), Some(amt)) = (lsp_endpoint, lsp_route_macaroon, amount_sats) {
                if let Err(e) = lij_core::lsps2::lsps2_register_invoice_secret(
                    &ep, &mac, &result.payment_hash, &result.payment_secret, amt * 1000,
                ).await {
                    log::warn!("v168: invoice-secret registration failed (non-fatal): {}", e);
                }
            }
            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v0.16 Phase C: create a Lightning invoice with an LSPS2 JIT channel
    /// route_hint.
    ///
    /// Three-phase flow with proper mutex discipline (matches v8 send-path
    /// pattern that fixed mutex_no_threads panics):
    ///   1. lsps2 get_info — network round-trip, NO wallet lock held
    ///   2. lsps2 buy      — network round-trip, NO wallet lock held
    ///   3. build invoice  — sync, wallet lock held briefly
    ///
    /// JS receives the parsed InvoiceWithJitResult as a JSON string. Errors
    /// (network failure, validation failure, lock failure) are thrown as JS
    /// exceptions.
    ///
    /// # Example (JS)
    /// ```javascript
    /// const r = await wallet.create_invoice_with_jit(
    ///   BigInt(50000), "Coffee", BigInt(600),
    ///   "https://lijox-lsp.lightning-mod.com", route_macaroon,
    /// );
    /// const result = JSON.parse(r);
    /// displayInvoice(result.invoice.bolt11);
    /// displayFeeBreakdown(result.jit.human_summary);
    /// ```
    #[wasm_bindgen]
    pub fn create_invoice_with_jit(
        &self,
        amount_sats: u64,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: &str,
        lsp_route_macaroon: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        let endpoint = lsp_endpoint.to_string();
        let macaroon = lsp_route_macaroon.to_string();
        future_to_promise(async move {
            // Phase 0 (NEW for D.2): fetch wallet pubkey BRIEFLY under lock,
            // then release before any network I/O. Pubkey is needed by the
            // adapter v0.18+ /lsps2/buy endpoint to know where to open the
            // JIT channel when a matching HTLC arrives.
            let client_pubkey = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (pubkey): {e}")))?;
                wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // lock released

            // Phase 1: fetch service terms WITHOUT wallet lock
            let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &macaroon)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Phase 2: buy the JIT promise WITHOUT wallet lock (passing our pubkey)
            // v217 (S36, O5 full balance availability): the prefund rides INSIDE
            // payment_size — sized from get_info's ADVISORY, verified against the
            // buy's BINDING stamp. Loose overage instead would strand an MPP
            // payer's last shard beyond the completeness gross and our own A6
            // (duplicate-retry shard guard) would bounce it. A governor flip
            // between the two calls = one rebuy at the stamped value; a second
            // disagreement = final fallback with no prefund. Abandoned promises
            // simply expire adapter-side.
            let amount_msat = amount_sats * 1000;
            let mut prefund_msat = info.prefund_msat_u64();
            let mut buy = lij_core::lsps2::lsps2_buy(
                &endpoint, &macaroon, Some(amount_msat + prefund_msat), &client_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if buy.prefund_msat_u64() != prefund_msat {
                let stamped = buy.prefund_msat_u64();
                log::warn!("[O5] prefund advisory {} != binding stamp {} — rebuying at the stamp", prefund_msat, stamped);
                prefund_msat = stamped;
                buy = lij_core::lsps2::lsps2_buy(
                    &endpoint, &macaroon, Some(amount_msat + prefund_msat), &client_pubkey)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                if buy.prefund_msat_u64() != prefund_msat {
                    log::warn!("[O5] stamp moved again — final fallback: no prefund this invoice");
                    prefund_msat = 0;
                    buy = lij_core::lsps2::lsps2_buy(
                        &endpoint, &macaroon, Some(amount_msat), &client_pubkey)
                        .await
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    if buy.prefund_msat_u64() != 0 { buy.prefund_msat = Some("0".to_string()); }
                }
            }

            // Phase 3: build invoice WITH wallet lock (sync, brief)
            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (build): {e}")))?;
                wallet.build_invoice_with_jit_promise(amount_sats, &memo, expiry_seconds, &info, buy)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }; // lock released

            // Phase 4 (Option B): register the invoice's payment_secret with the
            // LSP BEFORE returning, so it is in place before the payer can pay.
            // The LSP needs it to rebuild the final hop in sendToRouteV2 (it can't
            // read it from the onion -- penultimate hop). total_msat is the NET the
            // wallet will receive (== amount_msat); the LSP deducts its open fee
            // from the inflated invoice and forwards exactly this.
            // v217 (O5): the registered total is the NET the wallet will receive
            // — amount + prefund — the adapter rebuilds the final hop's mpp
            // total from THIS number, so it must match create_inbound exactly.
            lij_core::lsps2::lsps2_register_secret(
                &endpoint,
                &macaroon,
                &result.jit.jit_channel_scid,
                &result.payment_secret_hex,
                amount_msat + prefund_msat,
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// v188 (S27): OPEN-AMOUNT JIT invoice — zero-amount sibling of
    /// create_invoice_with_jit. Same Phase 0-4 choreography; buy carries
    /// NO payment_size (variable mode); register_secret sends total_msat=0
    /// (the variable sentinel — adapter fills the real total at flush).
    #[wasm_bindgen]
    /// v195 (S30): LNURLp hash pool — generates preimages inside the wallet,
    /// persists them, and returns JSON [{hash, secret}] for LSP registration.
    /// Preimages never cross this boundary.
    /// v229: `start_hint` = the LSP's next_index for this name (the page passes
    /// it from the register probe; undefined/None when the LSP is older).
    // ── v280 (S49, DP GO — Push Key, step A) ─────────────────────────────────────────────────
    /// The sender's first step. JSON {index, hash, preimage, amount_sats, expiry, window_secs, fragment}.
    pub fn push_prepare(&self, amount_sats: u64, window_secs: u64, lsp_pubkey_hex: &str) -> Result<String, JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        wallet.node().push_prepare(amount_sats, window_secs, lsp_pubkey_hex).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The sender pays the provider's hold invoice for the push's hash — the INTERNAL self-hop (the
    /// invoice is the active provider's own) — and returns as soon as the HTLC is out: the lock is
    /// meant to sit for the window, so there is nothing to wait for here. LDK's later word (settled =
    /// taken, failed back = returned) reaches the record through the event latch and push_out_json.
    /// JSON {ok, payment_id, hash} or {ok:false, error}.
    pub fn push_lock(&self, bolt11: &str, route_endpoint: &str, route_macaroon_hex: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let bolt11 = bolt11.to_string();
        let route_endpoint = route_endpoint.to_string();
        let route_macaroon_hex = route_macaroon_hex.to_string();
        future_to_promise(async move {
            let fail = |m: String| Ok(JsValue::from_str(&serde_json::json!({ "ok": false, "error": m }).to_string()));
            let (mut prep, dest_is_lsp, hash_hex) = {
                let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let prep = match wallet.node().prepare_lsp_route_request_msat(&bolt11, &route_endpoint, &[], None) {
                    Ok(p) => p,
                    Err(e) => return fail(format!("prepare failed: {e}")),
                };
                let dest_is_lsp = wallet.node().dest_is_active_lsp(&prep.dest_pubkey_hex);
                let hash_hex = hex::encode(prep.payment_hash.0);
                (prep, dest_is_lsp, hash_hex)
            };
            if !dest_is_lsp { return fail("the lock invoice is not from this wallet's provider".into()); }
            // the record must exist and be ours (prepared) — a foreign invoice is refused
            {
                let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                let out: Vec<serde_json::Value> = serde_json::from_str(&wallet.node().push_out_json()).unwrap_or_default();
                let known = out.iter().any(|r| r.get("hash").and_then(|h| h.as_str()) == Some(hash_hex.as_str()));
                if !known { return fail("this invoice is not for a push this wallet prepared".into()); }
            }
            // v249: the provider's height, so the self-hop clears LND's floor whatever the phone's tip says
            let base = prep.url.split("/v1/").next().unwrap_or("").to_string();
            let lsp_height: Option<u32> = if base.is_empty() { None } else {
                match lij_core::node::fetch_get_with_macaroon(&format!("{base}/v1/outcome?hash={hash_hex}"), &route_macaroon_hex).await {
                    Ok(t) => serde_json::from_str::<serde_json::Value>(&t).ok().and_then(|v| v.get("height").and_then(|h| h.as_u64()).map(|h| h as u32)),
                    Err(_) => None,
                }
            };
            let payment_id_hex = hex::encode(prep.payment_id.0);
            let result = {
                let wallet = inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
                if let (Some(h), Some(b)) = (lsp_height, wallet.node().ldk_best_block_height()) {
                    if h > b { prep.final_cltv_delta += h - b; }
                }
                let r = match wallet.node().apply_lsp_route_and_send(r#"{"ok":false,"error":"destination_is_lsp","routes":[],"internal":true}"#, &prep) {
                    Ok(r) => r,
                    Err(e) => return fail(format!("send failed: {e}")),
                };
                if r.success {
                    if let Err(e) = wallet.node().push_mark(&hash_hex, "locked", Some(&payment_id_hex)) { log::warn!("[push] mark locked failed: {e}"); }
                }
                r
            };
            if !r_success(&result) { return fail(result.error.clone().unwrap_or_else(|| "send rejected".into())); }
            Ok(JsValue::from_str(&serde_json::json!({ "ok": true, "payment_id": payment_id_hex, "hash": hash_hex }).to_string()))
        })
    }

    /// The page reports a void (the provider failed the unclaimed HTLC back on the sender's signed ask).
    pub fn push_mark(&self, hash_hex: &str, status: &str, payment_id_hex: Option<String>) -> Result<(), JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        wallet.node().push_mark(hash_hex, status, payment_id_hex.as_deref()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn push_out_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        Ok(wallet.node().push_out_json())
    }

    /// "Copy link" later: the key re-derived from the record's index.
    pub fn push_out_preimage(&self, hash_hex: &str) -> Result<String, JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        wallet.node().push_out_preimage(hash_hex).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The recipient: a pasted or opened link. JSON {hash, secret, expires, amount_sats, lsp_prefix};
    /// the page registers (hash, secret) with this wallet's provider and asks the holder to deliver.
    pub fn push_accept(&self, fragment: &str) -> Result<String, JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        wallet.node().push_accept(fragment).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn push_in_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.try_lock().map_err(|_| JsValue::from_str("WALLET_BUSY"))?;
        Ok(wallet.node().push_in_json())
    }

    /// A link's facts without accepting it (the claim sheet before the tap). JSON or an error string.
    pub fn push_link_parse(fragment: &str) -> Result<String, JsValue> {
        let l = lij_core::push::parse_fragment(fragment).map_err(|e| JsValue::from_str(&e))?;
        Ok(serde_json::json!({ "amount_sats": l.amount_sats, "expiry": l.expiry, "lsp_prefix": l.lsp_prefix, "hash": l.hash_hex }).to_string())
    }

    pub fn lnurlp_prepare_hashes(&self, count: u32, start_hint: Option<u32>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error (lnurlp): {e}")))?;
            wallet
                .lnurlp_prepare_hashes(count, start_hint)
                .map(|s| JsValue::from_str(&s))
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    }

    pub fn create_open_invoice_with_jit(
        &self,
        memo: &str,
        expiry_seconds: u64,
        lsp_endpoint: &str,
        lsp_route_macaroon: &str,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        let memo = memo.to_string();
        let endpoint = lsp_endpoint.to_string();
        let macaroon = lsp_route_macaroon.to_string();
        future_to_promise(async move {
            let client_pubkey = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (pubkey): {e}")))?;
                wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            let info = lij_core::lsps2::fetch_lsps2_info(&endpoint, &macaroon)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let buy = lij_core::lsps2::lsps2_buy(&endpoint, &macaroon, None, &client_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let result = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error (build): {e}")))?;
                wallet.build_open_invoice_with_jit_promise(&memo, expiry_seconds, &info, buy)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            lij_core::lsps2::lsps2_register_secret(
                &endpoint,
                &macaroon,
                &result.jit.jit_channel_scid,
                &result.payment_secret_hex,
                0, // VARIABLE SENTINEL — adapter fills real total at quiescence flush
            )
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let json = serde_json::to_string(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    #[wasm_bindgen]
    pub fn node_pubkey(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node_pubkey()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v184: node-key message signing (LND signmessage-compatible zbase32).
    /// Serves the LIJOX delegate slip/void digests. Sync, no I/O.
    #[wasm_bindgen]
    pub fn sign_message(&self, msg: &str) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.sign_message(msg)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn list_lsps(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let lsps = wallet.list_lsps()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&lsps)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }

    /// Step 3.6 (F4): synchronous accessor for the currently-active LSP.
    /// Returns the LSP's info as a JSON string, or None when no LSP is set.
    ///
    /// Unlike list_lsps(), this does NOT do an HTTP fetch — it reads from
    /// in-memory state under the wallet mutex, then releases the lock before
    /// returning. Safe to call from polling loops without risking the
    /// "cannot recursively acquire mutex" panic that hit Step 3.5's hot-fix
    /// when getActiveLsp() tried list_lsps() as a fallback.
    ///
    /// The frontend's getActiveLsp() helper already calls this binding; once
    /// this method ships, the LSP fields on Cards 2 and 3 will populate and
    /// the LSP relationship card on the Connection screen will render.
    #[wasm_bindgen]
    pub fn active_lsp_json(&self) -> Result<Option<String>, JsValue> {
        // Phase 3.8.B: try_lock to avoid recursive-mutex panic when an async
        // user action is holding the lock. JS treats WALLET_BUSY as a
        // skip-this-tick signal; UI keeps last-known state.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        match wallet.active_lsp() {
            Some(active) => {
                let json = serde_json::to_string(&active.info)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                Ok(Some(json))
            }
            None => Ok(None),
        }
    }

    // ── Channel close operations ────────────────────────────────────────

    /// Initiate a cooperative close. Synchronous from JS perspective —
    /// returns once shutdown is sent. Actual close confirmation arrives
    /// later via the closed-channels list.
    #[wasm_bindgen]
    pub fn close_channel(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.close_channel(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Force close a channel. Destructive — UI must confirm first.
    #[wasm_bindgen]
    pub fn force_close(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.force_close(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Force-close ONE channel without broadcasting any tx. For a stranded
    /// open whose funding never confirmed (LDK's no-progress watchdog keeps
    /// dropping the peer over it). Broadcasts nothing — safe for an
    /// unconfirmed funding. Destructive — UI must confirm first.
    #[wasm_bindgen]
    pub fn force_close_without_broadcasting(&self, channel_id_hex: &str) -> Result<(), JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.force_close_without_broadcasting(channel_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Step 3 (S30): drop a tier-2 pending tx by txid — the dead-funding
    /// janitor's executioner. The UI judges (Esplora outspend verdicts on the
    /// record's spent_outpoints); this removes the record so
    /// rebroadcast-until-seen stops and its input reservation releases.
    /// Returns {"removed":bool}.
    #[wasm_bindgen]
    pub fn drop_pending_tx(&self, txid_hex: &str) -> Result<String, JsValue> {
        let storage: std::sync::Arc<dyn lij_core::storage::LijStorage> = {
            let wallet = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            t2_storage(&wallet.onchain_handles().0)   // v256
        };
        let removed = lij_core::tier2_wallet::drop_pending_tx(storage.as_ref(), txid_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"removed\":{}}}", removed))
    }

    /// End relationship with an LSP. Returns JSON array of per-channel
    /// outcomes: [{ "channel_id_hex": "...", "ok": true/false, "error": "..." }, ...]
    #[wasm_bindgen]
    pub fn end_lsp_relationship(&self, lsp_pubkey_hex: &str) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let results = wallet.end_lsp_relationship(lsp_pubkey_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mapped: Vec<serde_json::Value> = results.into_iter().map(|(cid, r)| {
            match r {
                Ok(()) => serde_json::json!({
                    "channel_id_hex": cid,
                    "ok": true,
                }),
                Err(e) => serde_json::json!({
                    "channel_id_hex": cid,
                    "ok": false,
                    "error": e.to_string(),
                }),
            }
        }).collect();
        serde_json::to_string(&mapped)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return the closed-channel log as JSON.
    #[wasm_bindgen]
    pub fn list_closed_channels(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let records = wallet.list_closed_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&records)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Maturing on-chain outputs from channel closes still tracked by the
    /// OutputSweeper. Each entry is a force-close to_local (or other spendable)
    /// output that has not yet fully landed in the spendable balance. The UI
    /// sums these for the balance-card "maturing" subtext and groups them by
    /// channel for per-close detail. Returns a JSON array; "[]" before the
    /// sweeper is initialized (the narrow pre-init window) or when nothing is
    /// maturing.
    ///
    /// Each entry: { value_sats, status, delayed_until_height, confirmation_height, channel_id }
    ///   status "pending_broadcast" — sweep tx not yet broadcast. CSV-locked
    ///     while delayed_until_height is in the future; blocks-remaining =
    ///     delayed_until_height - tip (the UI computes this against its tip).
    ///   status "sweeping"          — sweep tx broadcast, awaiting first
    ///     confirmation (≈1 block out).
    ///   status "confirming"        — sweep tx confirmed; the funds are landing
    ///     in the spendable balance via the normal Tier-2 scan, so the UI does
    ///     NOT count these as still-maturing (avoids double-counting).
    #[wasm_bindgen]
    pub fn maturing_outputs(&self) -> Result<String, JsValue> {
        use lightning::sign::SpendableOutputDescriptor as SOD;
        use lightning::util::sweep::OutputSpendStatus as OSS;
        use serde_json::json;
        // try_lock: this is called from the balance refresh path, which runs
        // alongside the background tick — never block it (mirrors get_channels
        // / active_lsp_json). A momentary WALLET_BUSY just retries next refresh.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let sweeper = match wallet.node().output_sweeper() {
            Some(s) => s,
            None => return Ok("[]".to_string()),
        };
        let outputs = sweeper.tracked_spendable_outputs();
        let arr: Vec<serde_json::Value> = outputs
            .iter()
            .map(|o| {
                // bitcoin 0.30: TxOut.value is u64 sats across all descriptor variants.
                // Also surface the variant + destination scriptPubKey (hex) so we
                // can tell a coop StaticOutput paying m/84 from one paying the
                // m/525 P2WSH anchor script (the v128-exclusion diagnosis).
                let (value_sats, descriptor_type, dest_spk): (u64, &str, String) = match &o.descriptor {
                    SOD::StaticOutput { output, .. } =>
                        (output.value.to_sat(), "StaticOutput", hex::encode(output.script_pubkey.as_bytes())),
                    SOD::DelayedPaymentOutput(d) =>
                        (d.output.value.to_sat(), "DelayedPaymentOutput", hex::encode(d.output.script_pubkey.as_bytes())),
                    SOD::StaticPaymentOutput(d) =>
                        (d.output.value.to_sat(), "StaticPaymentOutput", hex::encode(d.output.script_pubkey.as_bytes())),
                };
                let (status, delayed_until_height, confirmation_height): (&str, Option<u32>, Option<u32>) =
                    match &o.status {
                        OSS::PendingInitialBroadcast { delayed_until_height } => {
                            ("pending_broadcast", *delayed_until_height, None)
                        }
                        OSS::PendingFirstConfirmation { .. } => ("sweeping", None, None),
                        OSS::PendingThresholdConfirmations { confirmation_height, .. } => {
                            ("confirming", None, Some(*confirmation_height))
                        }
                    };
                json!({
                    "value_sats": value_sats,
                    "descriptor_type": descriptor_type,
                    "dest_spk": dest_spk,
                    "status": status,
                    "delayed_until_height": delayed_until_height,
                    "confirmation_height": confirmation_height,
                    // ChannelId Display is lowercase hex — matches get_channels'
                    // channel_id / closed-record channel_id_hex for UI linkage.
                    "channel_id": o.channel_id.as_ref().map(|c| c.to_string()),
                })
            })
            .collect();
        serde_json::to_string(&arr).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// TEMP diagnostic: dump the SpendableOutputs event log — every descriptor
    /// (incl. v128-excluded StaticOutputs) seen at the event handler, with
    /// variant + value + destination script. Confirms what an anchors coop
    /// close emits. Returns a JSON array of objects. No wallet lock needed
    /// (thread_local). Remove with the rest of the temp diagnostics.
    #[wasm_bindgen]
    pub fn spendable_outputs_log(&self) -> String {
        let lines = lij_core::node::spendable_log_dump();
        format!("[{}]", lines.join(","))
    }

    /// TEMP diagnostic: dump the close-event log — every ChannelClosed reason and
    /// every coop/force close invocation, with timestamps, so the close SEQUENCE
    /// for a channel is visible. Remove with the rest of the temp diagnostics.
    #[wasm_bindgen]
    pub fn close_event_log(&self) -> String {
        let lines = lij_core::node::close_event_dump();
        format!("[{}]", lines.join(","))
    }

    /// TEMP diagnostic: why matured sweeps aren't broadcasting — broadcaster queue
    /// depth + failures, and the sweeper's internal height vs the real tip.
    #[wasm_bindgen]
    pub fn sweeper_broadcast_diag(&self, real_tip: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().sweeper_broadcast_diag(real_tip))
    }

    /// TEMP diagnostic: replicate the sweeper's spend_outputs to find which step
    /// fails (fee / change-script / signing) and the fee-vs-value numbers.
    #[wasm_bindgen]
    pub fn sweeper_spend_attempt_diag(&self, real_tip: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().sweeper_spend_attempt_diag(real_tip))
    }
    #[wasm_bindgen]
    pub fn outstanding_close_attempts(&self) -> Result<String, JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let snapshot = wallet.outstanding_close_attempts_snapshot()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&snapshot)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Pre-maturity closing funds (ChannelMonitor claimable, CSV-locked).
    /// See node::maturing_balances_json.
    #[wasm_bindgen]
    pub fn maturing_balances_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().maturing_balances_json())
    }

    /// v206: payments CLAIMED this session, as `[{"hash":"<hex>","sats":N}]`.
    /// The frontend ledger completes a pending receive only when its
    /// payment_hash appears here — an authoritative claim signal that replaces
    /// the balance-delta heuristic. See node::claimed_payments_json.
    #[wasm_bindgen]
    /// v267: self-funded opens whose funding tx could not be built this session (see
    /// node::open_failures_json). try_lock — the page asks again on WALLET_BUSY.
    pub fn open_failures_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().open_failures_json())
    }

    #[wasm_bindgen]
    /// v274: the channel(s) each settled outbound payment left by (see node::sent_parts_json).
    /// try_lock — the page asks again on WALLET_BUSY.
    pub fn sent_parts_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().sent_parts_json())
    }

    pub fn claimed_payments_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().claimed_payments_json())
    }

    /// S21 build #1 (ledger reconciler): expose LDK's recent outbound
    /// payments for the startup RECENT backfill. JSON array of
    /// {state, payment_id, payment_hash?, total_msat?}. try_lock — the
    /// frontend retries on a stagger, never blocks the UI thread.
    /// v189 (S29): abandon a stuck outbound payment by PaymentId hex, as
    /// reported by list_recent_payments_json. Makes ledger retirement
    /// terminal in LDK, so Pass-2 backfill can never resurrect a ghost
    /// after a history clear.
    #[wasm_bindgen]
    pub fn abandon_payment_by_id(&self, payment_id_hex: &str) -> Result<(), JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().abandon_payment_by_id_hex(payment_id_hex)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn list_recent_payments_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().recent_payments_json())
    }

    /// S21 item 2 (persistence audit): true when load-time stamps showed the
    /// manager stale vs monitors (interrupted save). Frontend surfaces honest
    /// copy; LDK's protective FC is expected behavior in this state.
    #[wasm_bindgen]
    pub fn persist_skew_at_load(&self) -> bool {
        match self.inner.try_lock() {
            Ok(w) => w.node().persist_skew_at_load(),
            Err(_) => false,
        }
    }

    /// Build #4 confirmation instrument: pending-record audit vs the
    /// independent quorum. Async — the wallet lock is dropped before any
    /// network I/O.
    #[wasm_bindgen]
    pub async fn pending_onchain_audit_json(&self) -> Result<String, JsValue> {
        let (storage, indep) = {
            let wallet = match self.inner.try_lock() {
                Ok(w) => w,
                Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
            };
            wallet.node().audit_handles()
        };
        Ok(lij_core::node::pending_onchain_audit(storage, indep).await)
    }

    /// v173: the planner's own sendable ceiling — the ONE number every send
    /// surface quotes (identical math to mpp_plan's total_usable_sats).
    #[wasm_bindgen]
    pub fn max_sendable_sats(&self) -> u64 {
        match self.inner.try_lock() {
            Ok(w) => w.node().max_sendable_sats(),
            Err(_) => 0,
        }
    }

    /// FOREGROUND HINT: force the next background tick to re-scan for closes,
    /// regardless of cadence phase. Best-effort — silently skips if the wallet
    /// is busy (a walk is likely already in flight). See node::note_foreground.
    #[wasm_bindgen]
    pub fn note_foreground(&self) {
        lij_core::node::request_stream_check();   // v295 (S52): the stream check, lock-free — taken by the next tick
        if let Ok(wallet) = self.inner.try_lock() {
            wallet.node().note_foreground();
        }
    }

    /// BACKGROUND HINT (D-1 JIT safety): clears the channel-acceptance gate so a
    /// backgrounded/offline wallet refuses inbound JIT opens it couldn't claim
    /// into. The wallet lock is never held across an await, so try_lock is free
    /// at the visibilitychange callback boundary; the event also fires before any
    /// grace-period background tick can process an OpenChannelRequest.
    #[wasm_bindgen]
    pub fn note_background(&self) {
        if let Ok(wallet) = self.inner.try_lock() {
            wallet.node().note_background();
        }
    }

    /// DIAGNOSTICS: monitor census + spend-walker liveness for the on-device
    /// status pane (iOS has no console). See node::diagnostics_json.
    #[wasm_bindgen]
    pub fn diagnostics_json(&self) -> Result<String, JsValue> {
        // try_lock — called from the status-pane refresh alongside the
        // background tick; never block it (mirrors maturing_outputs).
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        Ok(wallet.node().diagnostics_json())
    }

    #[wasm_bindgen]
    pub fn switch_lsp(&self, lsp_pubkey: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let lsp_pubkey = lsp_pubkey.to_string();
        future_to_promise(async move {
            let mut wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.switch_lsp(&lsp_pubkey)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::undefined())
        })
    }

    /// v349 (S61, Step A — routes-r1 §3/§6.3): switch to a provider from a record the page holds (one registry
    /// record as GET /lsps serves it, JSON) — no registry read by the engine; the door is chosen in connect_lsp by the
    /// Reach preference. Rejects with the plain reason when no door is allowed.
    #[wasm_bindgen]
    pub fn switch_lsp_with(&self, lsp_json: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let parsed: Result<lij_core::lsp::LspInfo, _> = serde_json::from_str(lsp_json);
        future_to_promise(async move {
            let target = parsed.map_err(|e| JsValue::from_str(&format!("not a provider record: {e}")))?;
            let mut wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.switch_lsp_with(target)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::undefined())
        })
    }

    /// v349: move the active provider to another of its own doors — the one with this `endpoint` (from the stored
    /// record's `routes`, allowed by the preference). Swaps the addresses in the active record, persists, drops the
    /// peer link so the page's monitor reconnects at the new `wss_url`. Answers the applied record (JSON). Synchronous
    /// (no network); WALLET_BUSY when the engine cannot be asked this instant.
    #[wasm_bindgen]
    pub fn relink_active_lsp(&self, endpoint: &str) -> Result<String, JsValue> {
        let mut wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let applied = wallet.relink_active_lsp(endpoint).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&applied).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// v349: the Reach preference the engine is applying (`direct-first` / `never-cloudflare` / `cloudflare-first`)
    /// and what the last connect decided about doors — `{"pref": "...", "note": "..."|null}`. The page's card reads
    /// the note when the engine named no provider.
    #[wasm_bindgen]
    pub fn route_state_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let n = wallet.node();
        Ok(serde_json::json!({ "pref": n.route_pref(), "note": n.route_note() }).to_string())
    }

    /// v350 (S61, DP 2026-10-19: the wallet as a login — LNURL-auth): the answer for a site's login challenge. `login_url`
    /// is the URL the LNURL decoded to (https, carrying tag=login and k1); the key is made for that site's host alone
    /// (LUD-05, m/138'/…), the challenge signed with it (LUD-04). Returns JSON {"domain", "key", "sig"} — the page
    /// fetches `login_url&sig=…&key=…` itself. Nothing is paid, nothing else leaves the wallet.
    pub fn lnurl_auth_answer(&self, login_url: &str, k1_hex: &str) -> Result<String, JsValue> {
        let domain = lij_core::lnurl_auth::domain_of(login_url).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let (root_key, _independent, _network) = self.inner.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?.onchain_handles();
        let a = lij_core::lnurl_auth::sign(&root_key, &domain, k1_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_json::json!({ "domain": domain, "key": a.key, "sig": a.sig }).to_string())
    }

    /// Register a Web Push wake subscription (D-1 2c offline-receive). Takes the
    /// browser PushSubscription serialized to JSON; signs the `push-subscribe`
    /// challenge with the node key and POSTs to the active LSP. The returned
    /// Promise resolves on success and rejects with the error string on failure.
    #[wasm_bindgen]
    pub fn register_push_subscription(&self, subscription_json: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            wallet.register_push_subscription(&subscription_json)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::undefined())
        })
    }

    #[wasm_bindgen]
    pub fn backup(&self) -> js_sys::Promise {
        // Delegate to the lock-safe path (snapshot under lock, push unlocked).
        // The frontend may call this automatically after payments/channel events,
        // so it must not hold the wallet mutex across the push's .await.
        self.backup_now()
    }

    #[wasm_bindgen]
    /// v209: the SAME ciphertext the cloud sink receives, returned to the page
    /// for a manual device download. Forces a fresh snapshot via the dirty
    /// handle; state is unchanged, so the next auto-backup is a cheap no-op.
    #[wasm_bindgen]
    pub fn export_backup_blob(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node().backup_dirty_handle().store(true, std::sync::atomic::Ordering::Relaxed);
        let prep = wallet.prepare_backup_if_dirty()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        match prep {
            Some((blob, _signer, _sinks, _dirty)) => {
                let _ = wallet.node().commit_backup_version(blob.version);   // v309: a device file carries this number — it is the phone's
                serde_json::to_string(&blob).map_err(|e| JsValue::from_str(&e.to_string()))
            }
            None => Err(JsValue::from_str("no backup state yet")),
        }
    }

    /// v221 (DP fire-and-forget): device-file backup import — parses the v209
    /// export's StateBlob JSON and injects through the same generic path the
    /// cloud restore uses (wrong-seed files fail decryption). Returns
    /// {"keys":N}; the page gates live channels and reloads — state applies
    /// on the reboot.
    #[wasm_bindgen]
    pub fn import_backup_blob(&self, blob_json: &str) -> Result<String, JsValue> {
        let blob: lij_core::storage::StateBlob = serde_json::from_str(blob_json)
            .map_err(|_e| JsValue::from_str("Not a LiJ backup file."))?;
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        let n = wallet.import_state_blob(&blob)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(format!("{{\"keys\":{n}}}"))
    }

    /// v210 (quorum wiring): set the independent quorum endpoint list at
    /// runtime. urls_json = JSON array of https base URLs (LSP defaults ∪
    /// wallet additions, page-merged, additive-only). Empty = rejected.
    #[wasm_bindgen]
    pub fn set_quorum_endpoints(&self, urls_json: &str) -> Result<(), JsValue> {
        let urls: Vec<String> = serde_json::from_str(urls_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if urls.is_empty() { return Err(JsValue::from_str("empty endpoint list")); }
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().set_independent_endpoints(urls);
        Ok(())
    }

    /// v211 (ESCAPE KIT): per-channel signed latest holder commitment
    /// ("THE CLOSE") + pre-signed to_local sweep ("THE COLLECT",
    /// nSequence = to_self_delay, two feerates — no RBF after the fact),
    /// destination = PEEKED m/84 allocator index. Read-only by
    /// constitution: nothing broadcast, nothing queued, counter not
    /// advanced, state unchanged. Runs on the offline read-only instance.
    /// Returns the kit as a JSON string.
    #[wasm_bindgen]
    /// v275 (Black Start): the NIP-06 identity — {"npub","pubkey"}. try_lock — WALLET_BUSY.
    pub fn black_start_identity_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().black_start_identity_json().map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    /// v276 (Black Start): the kit's fingerprint — {"fp","channels"}; cheap, no signing. try_lock.
    pub fn black_start_fingerprint_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().black_start_fingerprint_json().map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    /// v275 (Black Start): the sealed, signed push — see node::black_start_bundle_json. Read-only.
    pub fn black_start_bundle_json(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().black_start_bundle_json().map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    /// v313 (the kit across copies): which outpoints the chain must be asked about before a merge — see
    /// node::black_start_merge_plan_json. Read-only.
    pub fn black_start_merge_plan_json(&self, held_json: String) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().black_start_merge_plan_json(&held_json).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    /// v313: the merged, sealed, signed push — see node::black_start_bundle_merged_json. Read-only.
    pub fn black_start_bundle_merged_json(&self, held_json: String, chain_json: String) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().black_start_bundle_merged_json(&held_json, &chain_json).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn escape_export(&self) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().escape_export()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn get_channels(&self) -> Result<String, JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let channels = wallet.get_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&channels)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Step 3.6 diagnostic: returns full LDK ChannelDetails as a JSON
    /// string. Use from F12 console for inspection when the slim
    /// get_channels() output isn't enough.
    #[wasm_bindgen]
    pub fn dump_channel_details_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node().dump_channel_details_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// S24 Build 13: per-channel close values (see lij-core close_values_json).
    #[wasm_bindgen]
    pub fn close_values_json(&self) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        Ok(wallet.node().close_values_json())
    }

    #[wasm_bindgen]
    pub fn get_chain_status(&self) -> Result<String, JsValue> {
        use serde_json::json;

        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };

        let sync_state = wallet.node().get_sync_state();
        let overall_color = match sync_state.dot_color() {
            lij_core::sync_state::DotColor::Green => "green",
            lij_core::sync_state::DotColor::Yellow => "yellow",
            lij_core::sync_state::DotColor::Red => "red",
        };

        let coop_subscribed = wallet.node().cooperative_subscribed();
        let coop_height = wallet.node().cooperative_block_height();
        let coop_last_update_ts = wallet.node().cooperative_last_update_ts();  // Step 3.6 (F7)
        let coop_color = if coop_subscribed && coop_height.is_some() {
            "green"
        } else if coop_subscribed {
            "yellow"
        } else {
            "red"
        };

        let healthy = wallet.node().independent_healthy_count();
        let total = wallet.node().independent_total_count();
        let indep_height = wallet.node().independent_block_height();  // Step 3.6 (F5)
        let quorum_state = wallet.node().independent_quorum_state();
        let quorum_str = match quorum_state {
            lij_core::independent::QuorumState::Healthy => "Healthy",
            lij_core::independent::QuorumState::SlightDisagreement => "SlightDisagreement",
            lij_core::independent::QuorumState::SingleSource => "SingleSource",   // v225
            lij_core::independent::QuorumState::NoQuorum => "NoQuorum",
            lij_core::independent::QuorumState::TotalDisagreement => "TotalDisagreement",
            lij_core::independent::QuorumState::InsufficientEndpoints => "InsufficientEndpoints",
        };
        // Two-layer dot color (step 8d):
        //   1. Quorum state hard-overrides — TotalDisagreement is always red.
        //   2. Otherwise, percentage of healthy endpoints determines color:
        //      ≥80% healthy → green
        //      50-79% healthy → yellow
        //      <50% healthy → red
        // This way a path with 3/5 healthy endpoints reads as "degraded but
        // working" rather than "all good".
        let healthy_pct = if total > 0 {
            (healthy * 100) / total
        } else {
            0
        };
        let indep_color = if matches!(quorum_state, lij_core::independent::QuorumState::TotalDisagreement) {
            // Adversarial disagreement always trumps percentage — never green.
            "red"
        } else if healthy_pct >= 80 {
            "green"
        } else if healthy_pct >= 50 {
            "yellow"
        } else {
            "red"
        };

        let endpoint_status = wallet.node().independent_endpoint_status();
        // Step 3.6 (F6): destructure the 4-tuple including latency_ms.
        let endpoints_json: Vec<_> = endpoint_status.iter().map(|(url, h, f, l)| {
            json!({
                "url": url,
                "healthy": h,
                "failures": f,
                "latency_ms": l,
            })
        }).collect();

        let result = json!({
            "overall": {
                "state": format!("{:?}", sync_state),
                "color": overall_color,
                "display": sync_state.display(),
            },
            "cooperative": {
                "subscribed": coop_subscribed,
                "block_height": coop_height,
                "color": coop_color,
                "last_update_ts": coop_last_update_ts,  // Step 3.6 (F7)
            },
            "independent": {
                "healthy_count": healthy,
                "total_count": total,
                "quorum": quorum_str,
                "color": indep_color,
                "endpoints": endpoints_json,
                "block_height": indep_height,  // Step 3.6 (F5)
            },
        });

        Ok(result.to_string())
    }


    /// Request a channel from the active LSP via LSPS1.
    /// Returns JSON with channel_point (funding txid:output_index) once adapter replies.
    ///
    /// @param inbound_sats - Channel capacity in satoshis (adapter enforces min/max)
    /// @returns Promise<string> - JSON { channel_id, confirmations_required }
    ///
    /// Implementation note: extracts all needed data from the wallet INSIDE the mutex
    /// (synchronous, fast), then releases the lock BEFORE doing the HTTP call.
    /// Holding the lock across an `.await` deadlocks with background_tick.
    #[wasm_bindgen]
    pub fn open_channel(&self, inbound_sats: u64) -> js_sys::Promise {
        let inner = self.inner.clone();

        future_to_promise(async move {
            // Step 1 — extract channel request data while holding the lock (no await inside)
            let (worker_url, lsp_info, client_pubkey) = {
                let wallet = inner.lock()
                    .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;

                let active = wallet.active_lsp()
                    .ok_or_else(|| JsValue::from_str("No active LSP — call auto_select_lsp first"))?;

                let worker_url = wallet.worker_url().to_string();
                let lsp_info = active.info.clone();
                let client_pubkey = wallet.node_pubkey()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;

                (worker_url, lsp_info, client_pubkey)
            };  // <-- mutex released here

            // Step 2 — build request and make HTTP call WITHOUT holding the lock
            use lij_core::lsp::{Lsps1ChannelRequest, LspClient};
            let request = Lsps1ChannelRequest {
                inbound_liquidity_sats: inbound_sats,
                client_pubkey,
                client_host: "wss://lijox-ws.lightning-mod.com".to_string(),
                is_browser_node: true,
                refund_onchain_address: None,
            };

            let client = LspClient::new(lsp_info);
            let response = client.request_channel(&worker_url, request)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let result = serde_json::json!({
                "channel_id": response.channel_id,
                "confirmations_required": response.confirmations_required,
                "status": "opening"
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Open an OUTBOUND channel to the active LSP, funded from on-chain balance.
    /// `amount_sats` is the channel capacity; `fee_rate_sat_per_vb` is the
    /// on-chain fee rate for the funding transaction. Returns a status JSON
    /// immediately; the channel opens asynchronously (watch background_tick /
    /// channel list for ChannelReady). The funding tx is built + signed by the
    /// wallet from its Tier-2 UTXOs and broadcast by LDK — not the adapter.
    #[wasm_bindgen]
    pub fn open_lsp_channel(&self, amount_sats: u64, fee_rate_sat_per_vb: f64) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let status = wallet
                .open_channel_to_lsp(amount_sats, fee_rate_sat_per_vb)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&status))
        })
    }

    /// v282 (S50, coin control cut 3): the same open, funded from EXACTLY the chosen coins.
    /// `req` is JSON {"amount_sats", "fee_rate_sat_per_vb", "inputs": [{"txid","vout"}, …]}.
    /// The coins wait under the open's nonce for LDK's funding event (seconds); a frozen,
    /// unknown or short set fails the open there, in plain words, and nothing is spent.
    #[wasm_bindgen]
    pub fn open_lsp_channel_with(&self, req: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let req = req.to_string();
        future_to_promise(async move {
            #[derive(serde::Deserialize)]
            struct Pin { txid: String, vout: u32 }
            #[derive(serde::Deserialize)]
            struct Req { amount_sats: f64, fee_rate_sat_per_vb: f64, #[serde(default)] inputs: Vec<Pin> }
            let r: Req = serde_json::from_str(&req).map_err(|e| JsValue::from_str(&format!("open_lsp_channel_with: bad request: {e}")))?;
            let pins: Vec<(String, u32)> = r.inputs.iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect();
            if pins.is_empty() {
                return Err(JsValue::from_str("open_lsp_channel_with: no coins chosen"));
            }
            if !(r.amount_sats.is_finite() && r.amount_sats >= 1.0) {
                return Err(JsValue::from_str("channel size must be a positive whole number of sats"));
            }
            let wallet = inner
                .lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let status = wallet
                .open_channel_to_lsp_with(r.amount_sats as u64, r.fee_rate_sat_per_vb, Some(pins))
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&status))
        })
    }

    /// v282: the + Add channel estimate for the CHOSEN coins — `req` JSON {"fee_rate_sat_per_vb",
    /// "inputs"?: [{"txid","vout"}]}; max_channel_sats is what exactly those coins can open.
    /// A frozen or unknown choice answers {"problem": "…"} with max_channel_sats 0.
    #[wasm_bindgen]
    pub fn lsp_channel_open_estimate_with(&self, req: &str) -> js_sys::Promise {
        #[derive(serde::Deserialize)]
        struct Pin { txid: String, vout: u32 }
        #[derive(serde::Deserialize)]
        struct Req { fee_rate_sat_per_vb: f64, #[serde(default)] inputs: Option<Vec<Pin>> }
        let r: Req = match serde_json::from_str(req) { Ok(r) => r, Err(e) => return js_sys::Promise::reject(&JsValue::from_str(&format!("lsp_channel_open_estimate_with: bad request: {e}"))) };
        let pins: Option<Vec<(String, u32)>> = r.inputs.map(|v| v.into_iter().map(|p| (p.txid.to_ascii_lowercase(), p.vout)).collect());
        let root_key = match self.inner.try_lock() {
            Ok(w) => w.onchain_handles().0,
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let storage = t2_storage(&root_key);
            let fee_rate_sat_per_kw = ((r.fee_rate_sat_per_vb * 250.0).round() as u32).max(250);
            let spendable = lij_core::channel_open::spendable_total(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let (max, problem) = match lij_core::channel_open::max_channel_value_with(storage.as_ref(), fee_rate_sat_per_kw, pins.as_deref()) {
                Ok(m) => (m, None),
                Err(e) if pins.is_some() => (0u64, Some(e.to_string())),
                Err(e) => return Err(JsValue::from_str(&e.to_string())),
            };
            let result = serde_json::json!({
                "spendable_sats": spendable,
                "max_channel_sats": max,
                "anchor_reserve_sats": lij_core::channel_open::ANCHOR_FEE_RESERVE_SATS,
                "min_channel_sats": lij_core::channel_open::LDK_MIN_CHANNEL_SATS,
                "chosen": pins.as_ref().map(|p| p.len()).unwrap_or(0),
                "problem": problem,
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// v165 (#29-4a): current fee-rate tiers for the speed picker (JSON).
    pub fn get_fee_rates(&self) -> Result<String, JsValue> {
        let wallet = self
            .inner
            .lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        Ok(wallet.fee_rates_json())
    }

    /// Estimate for the + Add channel UI: spendable on-chain, the MAX channel
    /// value openable at this fee rate (spendable − funding fee − anchor
    /// reserve), and the floor/reserve constants. Reads the Tier-2 view from
    /// local storage; needs no wallet lock.
    #[wasm_bindgen]
    pub fn lsp_channel_open_estimate(&self, fee_rate_sat_per_vb: f64) -> js_sys::Promise {
        // v263: the view is encrypted at rest (v256) — the key comes from the wallet (try_lock:
        // a busy wallet answers WALLET_BUSY and the page asks again).
        let root_key = match self.inner.try_lock() {
            Ok(w) => w.onchain_handles().0,
            Err(_) => return js_sys::Promise::reject(&JsValue::from_str("WALLET_BUSY")),
        };
        future_to_promise(async move {
            let storage = t2_storage(&root_key);
            let fee_rate_sat_per_kw = ((fee_rate_sat_per_vb * 250.0).round() as u32).max(250);
            let spendable = lij_core::channel_open::spendable_total(storage.as_ref())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let max = lij_core::channel_open::max_channel_value(storage.as_ref(), fee_rate_sat_per_kw)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let result = serde_json::json!({
                "spendable_sats": spendable,
                "max_channel_sats": max,
                "anchor_reserve_sats": lij_core::channel_open::ANCHOR_FEE_RESERVE_SATS,
                "min_channel_sats": lij_core::channel_open::LDK_MIN_CHANNEL_SATS,
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Connect to a Lightning peer over WebSocket.
    #[wasm_bindgen]
    pub fn connect_to_peer(&self, pubkey_hex: &str, wss_url: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let pubkey_hex = pubkey_hex.to_string();
        let wss_url = wss_url.to_string();

        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;

            // v249 (S46, DP): ONE SOCKET PER PEER. The page's boot path and the pulse's
            // peer wave both called this within a second, so every boot opened two sockets
            // to the LSP; LDK closed the second ("Got second connection … closing"), the
            // read_event error path then freed the executing closure (the boot-time
            // "closure invoked recursively or after being dropped"), and LND, which keeps
            // the NEWER connection, could be left holding the socket LDK had just closed.
            // Now: an LDK peer already connected -> nothing to do; a socket to this peer
            // still CONNECTING, or OPEN for under 20 s (handshake in flight) -> nothing to
            // do; an OPEN socket older than that with no LDK peer behind it is a zombie ->
            // closed here, and a fresh socket is opened.
            let pk_lower = pubkey_hex.to_lowercase();
            let pk_short = pk_lower[..16.min(pk_lower.len())].to_string();
            if let Ok(peers) = wallet.list_peers() {
                if peers.iter().any(|p| p.eq_ignore_ascii_case(&pk_lower)) {
                    log::info!("connect_to_peer: {pk_short}… already connected (LDK peer up) — no second socket");
                    return Ok(JsValue::from_str(r#"{"status":"already_connected"}"#));
                }
            }
            match ws_transport::socket_state_for_peer(&pk_lower) {
                Some((id, ready_state, age_ms)) if ready_state == web_sys::WebSocket::CONNECTING || (ready_state == web_sys::WebSocket::OPEN && age_ms < 20_000.0) => {
                    log::info!("connect_to_peer: socket {id} to {pk_short}… still handshaking ({} ms) — no second socket", age_ms as u64);
                    return Ok(JsValue::from_str(&format!(r#"{{"socket_id":{id},"status":"connecting"}}"#)));
                }
                Some((id, ready_state, age_ms)) if ready_state == web_sys::WebSocket::OPEN => {
                    log::warn!("connect_to_peer: socket {id} to {pk_short}… open {} s with no LDK peer behind it — closing the zombie, opening fresh", (age_ms / 1000.0) as u64);
                    ws_transport::close_socket(id);
                }
                _ => {}
            }

            let (socket_id, first_bytes) = wallet.begin_peer_connection(&pubkey_hex)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            ws_transport::open_websocket(&wss_url, socket_id, first_bytes, &pubkey_hex)?;

            let result = serde_json::json!({
                "socket_id": socket_id,
                "status": "connecting",
                "note": "Noise_XK handshake in progress. Call list_peers() after a moment to verify."
            });
            Ok(JsValue::from_str(&result.to_string()))
        })
    }

    /// Background tick — JS calls every second to keep LDK alive.
    /// Handles peer keepalives, channel maintenance, and event processing.
    #[wasm_bindgen]
    /// S30 (v199): read the chain flight recorder — the ChainCoordinator's
    /// event ledger (tip advances, stale drops, confirmations, independent
    /// observations, with heights). Read-only diagnosis surface.
    #[wasm_bindgen]
    pub fn chain_events_json(&self, limit: u32) -> Result<String, JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().chain_events_json(limit as usize)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// S30 (v197) fix-probe: explicit outbound pump. The codebase pumps
    /// process_events after inbound bytes, after disconnects, and on the
    /// background tick — but never immediately after locally INITIATING an
    /// action. A channel open is the one purely self-initiated message in
    /// the system; it must not wait for borrowed timing to reach the wire.
    /// `do_timer` also fires the peer keepalive tick, extending short iOS
    /// sessions through the multi-message funding handshake.
    #[wasm_bindgen]
    pub fn pump_peer(&self, do_timer: bool) -> Result<(), JsValue> {
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        let pm = wallet.node().peer_manager()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if do_timer { pm.timer_tick_occurred(); }
        pm.process_events();
        Ok(())
    }

    pub fn background_tick(&self, tick_count: u64) -> Result<(), JsValue> {
        // Phase 3.8.B: try_lock — see active_lsp_json comment.
        let wallet = match self.inner.try_lock() {
            Ok(w) => w,
            Err(_) => return Err(JsValue::from_str("WALLET_BUSY")),
        };
        wallet.node().background_tick(tick_count)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Dev tool: manually mark a funding transaction as confirmed at a
    /// given height. Synthesizes block headers and notifies LDK's chain
    /// listeners — pre-Neutrino workaround for the stuck-channel case.
    /// Returns the channels list as JSON after the confirmation is processed.
    #[wasm_bindgen]
    pub fn mark_funding_confirmed(
        &self,
        funding_tx_hex: &str,
        confirmed_at_height: u32,
    ) -> Result<String, JsValue> {
        let wallet = self.inner.lock()
            .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
        wallet.node()
            .mark_funding_confirmed(funding_tx_hex, confirmed_at_height)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let channels = wallet.node().get_channels()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&channels)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List currently connected Lightning peers.
    #[wasm_bindgen]
    pub fn list_peers(&self) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let wallet = inner.lock()
                .map_err(|e| JsValue::from_str(&format!("Lock error: {e}")))?;
            let peers = wallet.list_peers()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let json = serde_json::to_string(&peers)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&json))
        })
    }
}

// ── HTTP fetch helper ────────────────────────────────────────────────────────

pub mod fetch {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    pub async fn get(url: &str, auth_token: Option<&str>) -> Result<String, String> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        if let Some(token) = auth_token {
            request.headers()
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|e| format!("Header error: {:?}", e))?;
        }

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        text.as_string().ok_or("Response is not a string".into())
    }

    pub async fn post(url: &str, body: &str, auth_token: Option<&str>) -> Result<String, String> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| format!("Header error: {:?}", e))?;

        if let Some(token) = auth_token {
            request.headers()
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|e| format!("Header error: {:?}", e))?;
        }

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        text.as_string().ok_or("Response is not a string".into())
    }

    /// Like get() but returns (status, body) so callers can distinguish
    /// 4xx tx-validity rejects from network failures. Used by the
    /// EsploraHttp trait impl which needs the status code.
    pub async fn get_with_status(url: &str) -> Result<(u16, String), String> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let status = resp.status();
        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        let body = text.as_string().ok_or("Response is not a string".to_string())?;
        Ok((status, body))
    }

    pub async fn post_with_status(
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<(u16, String), String> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request build error: {:?}", e))?;

        request.headers()
            .set("Content-Type", content_type)
            .map_err(|e| format!("Header error: {:?}", e))?;

        let window = web_sys::window().ok_or("No window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch error: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "Response cast error".to_string())?;

        let status = resp.status();
        let text = JsFuture::from(
            resp.text().map_err(|e| format!("Text error: {:?}", e))?
        )
        .await
        .map_err(|e| format!("Text await error: {:?}", e))?;

        let body = text.as_string().ok_or("Response is not a string".to_string())?;
        Ok((status, body))
    }
}

// ── Core HTTP bridge ─────────────────────────────────────────────────────────

#[wasm_bindgen]
pub async fn fetch_lsp_registry(worker_url: &str) -> Result<String, JsValue> {
    let url = format!("{}/lsps", worker_url);
    fetch::get(&url, None).await.map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn push_backup(worker_url: &str, auth_token: &str, blob_json: &str) -> Result<(), JsValue> {
    // Phase B: belt+suspenders — no backup HTTP in offline_start, ever.
    // v209: BACKUP_OFF silences the same choke — every backup path exits here.
    if OFFLINE_START.load(std::sync::atomic::Ordering::Relaxed)
        || BACKUP_OFF.load(std::sync::atomic::Ordering::Relaxed) { return Ok(()); }
    let url = format!("{}/backup", worker_url);
    fetch::post(&url, blob_json, Some(auth_token))
        .await.map(|_| ()).map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn pull_backup(worker_url: &str, auth_token: &str, pubkey_hex: &str) -> Result<String, JsValue> {
    let url = format!("{}/backup/{}", worker_url, pubkey_hex);
    fetch::get(&url, Some(auth_token)).await.map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn register_lsp(worker_url: &str, registration_json: &str) -> Result<(), JsValue> {
    let url = format!("{}/lsps/register", worker_url);
    fetch::post(&url, registration_json, None)
        .await.map(|_| ()).map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub async fn health_check_lsp(endpoint: &str) -> bool {
    let url = format!("{}/health", endpoint);
    fetch::get(&url, None).await.is_ok()
}

// ── WebSocket transport ──────────────────────────────────────────────────────

pub mod ws_transport {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

    use lij_core::peer::SocketDispatcher;

    pub struct WsEntry {
        pub ws: WebSocket,
        /// v249: the peer this socket was opened toward (lowercase hex) and when — the
        /// connect guard refuses a second socket to the same peer while one is still
        /// handshaking or already serves an LDK peer.
        pub pubkey: String,
        pub opened_ms: f64,
        pub _on_open: Closure<dyn FnMut()>,
        pub _on_message: Closure<dyn FnMut(MessageEvent)>,
        pub _on_close: Closure<dyn FnMut(CloseEvent)>,
        pub _on_error: Closure<dyn FnMut(ErrorEvent)>,
    }

    thread_local! {
        pub static WS_MAP: RefCell<HashMap<u64, WsEntry>> = RefCell::new(HashMap::new());
    }

    /// v322 (S58, DP 2026-10-12 20:18 — the CHAIN dot): one WebSocket opened toward the provider while the start-up checks
    /// run. It carries nothing until connect_to_peer adopts it (open_websocket below) and sends the handshake's first bytes.
    pub struct Preopen {
        pub url: String,
        pub ws: WebSocket,
        pub opened_ms: f64,
        pub closed: std::rc::Rc<std::cell::Cell<bool>>,
        pub _on_open: Closure<dyn FnMut()>,
        pub _on_close: Closure<dyn FnMut(CloseEvent)>,
        pub _on_error: Closure<dyn FnMut(ErrorEvent)>,
    }

    thread_local! {
        pub static PREOPEN: RefCell<Option<Preopen>> = RefCell::new(None);
    }

    /// A pre-opened socket older than this is not adopted (it is closed and a fresh one opened).
    pub const PREOPEN_MAX_AGE_MS: f64 = 60_000.0;

    /// Unset a pre-opened socket's handlers before its closures are dropped, so the browser never calls a dropped one.
    fn unhook(p: &Preopen) {
        p.ws.set_onopen(None);
        p.ws.set_onclose(None);
        p.ws.set_onerror(None);
        p.ws.set_onmessage(None);
    }

    pub fn preopen(url: &str) -> Result<(), JsValue> {
        if !(url.starts_with("wss://") || url.starts_with("ws://127.0.0.1")) {
            return Err(JsValue::from_str("ws_preopen: not a wss:// address"));
        }
        let keep = PREOPEN.with(|x| {
            x.borrow().as_ref().map_or(false, |p| p.url == url && !p.closed.get() && js_sys::Date::now() - p.opened_ms < PREOPEN_MAX_AGE_MS)
        });
        if keep {
            return Ok(());
        }
        drop_preopen();
        let ws = WebSocket::new(url).map_err(|e| JsValue::from_str(&format!("WebSocket::new failed: {:?}", e)))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let opened_ms = js_sys::Date::now();
        let closed = std::rc::Rc::new(std::cell::Cell::new(false));
        let on_open = Closure::wrap(Box::new(move || {
            log::info!("WebSocket pre-opened to the provider in {} ms (waiting for the start-up checks)", (js_sys::Date::now() - opened_ms) as u64);
        }) as Box<dyn FnMut()>);
        let c2 = closed.clone();
        let on_close = Closure::wrap(Box::new(move |e: CloseEvent| {
            c2.set(true);
            log::info!("pre-opened WebSocket closed before use: code={}", e.code());
        }) as Box<dyn FnMut(CloseEvent)>);
        let on_error = Closure::wrap(Box::new(move |_e: ErrorEvent| {
            log::warn!("pre-opened WebSocket error (a fresh socket will be opened at connect)");
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        PREOPEN.with(|x| {
            *x.borrow_mut() = Some(Preopen { url: url.to_string(), ws, opened_ms, closed, _on_open: on_open, _on_close: on_close, _on_error: on_error });
        });
        Ok(())
    }

    /// Close and forget the pre-opened socket, if any (a start the checks stopped, or a stale one).
    pub fn drop_preopen() {
        if let Some(p) = PREOPEN.with(|x| x.borrow_mut().take()) {
            unhook(&p);
            let _ = p.ws.close();
            drop(p);
        }
    }

    /// Take the pre-opened socket for `url` when it can still be used: (the socket, already open, its age in ms).
    fn adopt_preopen(url: &str) -> Option<(WebSocket, bool, f64)> {
        let now = js_sys::Date::now();
        let taken = PREOPEN.with(|x| {
            let mut b = x.borrow_mut();
            let usable = b.as_ref().map_or(false, |p| {
                let rs = p.ws.ready_state();
                p.url == url && !p.closed.get() && now - p.opened_ms < PREOPEN_MAX_AGE_MS && (rs == WebSocket::OPEN || rs == WebSocket::CONNECTING)
            });
            if usable { b.take() } else { None }
        });
        match taken {
            Some(p) => {
                unhook(&p);
                let ws = p.ws.clone();
                let open = ws.ready_state() == WebSocket::OPEN;
                let age = now - p.opened_ms;
                drop(p);
                Some((ws, open, age))
            }
            None => {
                drop_preopen();
                None
            }
        }
    }

    pub struct WsDispatcher;

    impl SocketDispatcher for WsDispatcher {
        fn send(&self, id: u64, data: &[u8]) -> usize {
            WS_MAP.with(|map| {
                if let Some(entry) = map.borrow().get(&id) {
                    match entry.ws.send_with_u8_array(data) {
                        Ok(_) => data.len(),
                        Err(e) => {
                            log::warn!("WebSocket send failed for id {id}: {:?}", e);
                            0
                        }
                    }
                } else {
                    log::warn!("WebSocket send for unknown id {id}");
                    0
                }
            })
        }

        fn disconnect(&self, id: u64) {
            // Don't remove the WsEntry here — that would drop the closures
            // (on_open/on_message/on_close/on_error) before the browser fires
            // on_close, causing "closure invoked after being dropped" when
            // the asynchronous close event arrives. Just close the WebSocket;
            // the on_close handler (which defers WS_MAP removal via
            // spawn_local — see open_websocket below) is the sole removal
            // path. Pre-Phase-13 this method did `remove` then `close`,
            // which raced the browser.
            let ws_opt = WS_MAP.with(|map| {
                map.borrow().get(&id).map(|e| e.ws.clone())
            });
            if let Some(ws) = ws_opt {
                let _ = ws.close();
                log::info!("WebSocket {id} disconnected by LDK");
            }
        }
    }

    pub fn open_websocket(url: &str, id: u64, first_bytes: Vec<u8>, pubkey_hex: &str) -> Result<(), JsValue> {
        // v322: the socket opened while the start-up checks ran, when it is still usable; else a fresh one, as before
        let (ws, already_open, preopened_ms) = match adopt_preopen(url) {
            Some((ws, open, age)) => (ws, open, Some(age)),
            None => (
                WebSocket::new(url).map_err(|e| JsValue::from_str(&format!("WebSocket::new failed: {:?}", e)))?,
                false,
                None,
            ),
        };
        ws.set_binary_type(BinaryType::Arraybuffer);

        let ws_clone_open = ws.clone();
        let first_bytes_clone = first_bytes.clone();
        let on_open = Closure::wrap(Box::new(move || {
            log::info!("WebSocket {id} opened, sending {} initial bytes", first_bytes_clone.len());
            if let Err(e) = ws_clone_open.send_with_u8_array(&first_bytes_clone) {
                log::error!("Failed to send initial bytes: {:?}", e);
            }
        }) as Box<dyn FnMut()>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            let data = match e.data().dyn_into::<js_sys::ArrayBuffer>() {
                Ok(buf) => js_sys::Uint8Array::new(&buf).to_vec(),
                Err(_) => {
                    log::warn!("WebSocket {id} received non-binary frame, ignoring");
                    return;
                }
            };
            handle_incoming_bytes(id, data);
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let on_close = Closure::wrap(Box::new(move |e: CloseEvent| {
            log::info!("WebSocket {id} closed: code={}, reason={}", e.code(), e.reason());
            handle_disconnect(id);
            // Defer the WS_MAP removal out of this closure: removing the
            // WsEntry would drop the very closure currently executing
            // (_on_close field owns this Box<dyn FnMut>), which wasm-bindgen
            // detects as a use-after-free and throws "closure invoked
            // recursively or after being dropped". spawn_local queues the
            // removal as a microtask so the closure can return cleanly first.
            wasm_bindgen_futures::spawn_local(async move {
                WS_MAP.with(|map| { map.borrow_mut().remove(&id); });
            });
        }) as Box<dyn FnMut(CloseEvent)>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        let on_error = Closure::wrap(Box::new(move |e: ErrorEvent| {
            // v164: browsers fire a PLAIN Event on ws.onerror — the ErrorEvent
            // typing is a lie, so e.message() returns undefined and the
            // wasm-bindgen string glue crashes (passStringToWasm0 reading
            // .length of undefined) on every WS handshake failure. Read the
            // field defensively; the CloseEvent that follows carries the
            // actionable code/reason anyway.
            let msg = js_sys::Reflect::get(e.as_ref(), &wasm_bindgen::JsValue::from_str("message"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "(no message)".to_string());
            log::error!("WebSocket {id} error: {msg}");
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let entry = WsEntry {
            ws,
            pubkey: pubkey_hex.to_lowercase(),
            opened_ms: js_sys::Date::now(),
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
            _on_error: on_error,
        };
        // v219 (DEFECT B, F2 belt): under realm-global ids a collision is
        // impossible by construction — but if one EVER appears, never drop the
        // old quartet synchronously (its socket's async events may still be in
        // flight). Take it out, close the socket, defer the drop past this
        // turn, and shout.
        WS_MAP.with(|map| {
            if let Some(old) = map.borrow_mut().remove(&id) {
                log::error!("WS_MAP collision on id {id} — should be impossible under realm-global ids; closing stale socket, deferring drop. Investigate.");
                let _ = old.ws.close();
                wasm_bindgen_futures::spawn_local(async move { drop(old); });
            }
        });
        let ws_now = entry.ws.clone();
        WS_MAP.with(|map| { map.borrow_mut().insert(id, entry); });
        if already_open {
            // v322: adopted open — the open event has passed, so the handshake's first bytes go now (the line keeps the
            // page's "socket open" bookend)
            log::info!("WebSocket {id} opened, sending {} initial bytes (pre-opened {} ms before)", first_bytes.len(), preopened_ms.unwrap_or(0.0) as u64);
            if let Err(e) = ws_now.send_with_u8_array(&first_bytes) {
                log::error!("Failed to send initial bytes: {:?}", e);
            }
        } else if let Some(age) = preopened_ms {
            log::info!("WebSocket {id} adopts the socket pre-opened {} ms before (still opening)", age as u64);
        }
        Ok(())
    }

    /// v249: the newest socket toward a peer — (id, readyState, age ms) — or None.
    pub fn socket_state_for_peer(pubkey_lower: &str) -> Option<(u64, u16, f64)> {
        WS_MAP.with(|map| {
            map.borrow().iter()
                .filter(|(_, e)| e.pubkey == pubkey_lower)
                .max_by(|a, b| a.1.opened_ms.partial_cmp(&b.1.opened_ms).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(id, e)| (*id, e.ws.ready_state(), js_sys::Date::now() - e.opened_ms))
        })
    }

    /// v249: close one socket; it leaves WS_MAP via its own on_close (the sanctioned path).
    pub fn close_socket(id: u64) {
        let ws_opt = WS_MAP.with(|map| map.borrow().get(&id).map(|e| e.ws.clone()));
        if let Some(ws) = ws_opt { let _ = ws.close(); }
    }

    /// v219 (DEFECT B, F4 hygiene): close every open socket. Called before a
    /// new wallet instance is installed in the slot, so a replaced instance's
    /// sockets stop routing bytes into the NEW PeerManager. Each entry leaves
    /// WS_MAP via its own on_close path — the sanctioned removal — so no
    /// closure is dropped while its events are in flight.
    pub fn close_all_sockets() {
        let sockets: Vec<web_sys::WebSocket> = WS_MAP.with(|map| {
            map.borrow().values().map(|e| e.ws.clone()).collect()
        });
        if !sockets.is_empty() {
            log::info!("Closing {} lingering WebSocket(s) before wallet install", sockets.len());
        }
        for ws in sockets { let _ = ws.close(); }
    }

    fn handle_incoming_bytes(id: u64, bytes: Vec<u8>) {
        use lij_core::peer::LijSocketDescriptor;

        let inner = match crate::current_wallet_inner() {
            Some(i) => i,
            None => {
                log::error!("Received bytes for id {id} but no wallet instance");
                return;
            }
        };

        // Phase 3.8.D v1 (band-aid): try_lock instead of blocking lock.
        // Prevents recursive-mutex panic when Phase 10b's send_payment_via_lsp_route
        // holds the wallet lock during its HTTP fetch .await. Dropped WS messages
        // during the (short) fetch window are recovered via LDK's auto-reconnect.
        // TODO post-3.D: remove once user-action bindings release lock before await.
        let wallet = match inner.try_lock() {
            Ok(w) => w,
            Err(std::sync::TryLockError::Poisoned(e)) => {
                log::error!("Wallet lock poisoned: {e}"); return;
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                log::warn!("WS id {id}: wallet busy, dropping {} bytes (Phase 3.8.D band-aid)", bytes.len());
                return;
            }
        };

        let pm = match wallet.node().peer_manager() {
            Ok(p) => p,
            Err(e) => { log::error!("PeerManager unavailable: {e}"); return; }
        };

        let mut descriptor = LijSocketDescriptor::new(id);
        match pm.read_event(&mut descriptor, &bytes) {
            Ok(_pause_read) => {}
            Err(e) => {
                log::warn!("read_event error on id {id}: {:?}", e);
                // v249: CLOSE ONLY. This runs inside the socket's own on_message closure;
                // removing the WsEntry here dropped that closure while it executed — the
                // "closure invoked recursively or after being dropped" throw on every boot
                // that opened two sockets. The on_close handler removes the entry on a
                // later microtask (the v219 rule); LDK's socket_disconnected for a
                // descriptor it already dropped is a no-op by its own contract.
                let ws_opt = WS_MAP.with(|map| map.borrow().get(&id).map(|e| e.ws.clone()));
                if let Some(ws) = ws_opt { let _ = ws.close(); }
                return;
            }
        }

        pm.process_events();
        // v321 (S58, DP 2026-10-12 — the CHAIN dot): the provider's chain messages are handled now, not on the next tick
        // (the first ChainDataBundle waited up to a second in the inbound queue — DP's Performance report: socket open →
        // bundle handled 2,567 ms while the provider answers the subscribe in 12 ms).
        wallet.node().cooperative_process_inbound_now();
        drop(wallet);

        // v227 (S43, speed): run the ChannelManager event pass on the NEXT
        // turn — never inside this socket callback — so a receiver claims the
        // moment its HTLC lands and a sender learns "paid" the moment the
        // fulfill arrives, instead of on the 1-second tick. Same routine the
        // tick runs (process_channel_events); it only runs sooner.
        crate::schedule_early_event_pass();
    }

    fn handle_disconnect(id: u64) {
        use lij_core::peer::LijSocketDescriptor;

        let inner = match crate::current_wallet_inner() {
            Some(i) => i,
            None => return,
        };

        // Phase 3.8.D v1 (band-aid): try_lock instead of blocking lock.
        // See handle_incoming_bytes for rationale.
        let wallet = match inner.try_lock() {
            Ok(w) => w,
            Err(std::sync::TryLockError::Poisoned(_)) => return,
            Err(std::sync::TryLockError::WouldBlock) => {
                log::warn!("WS id {id}: wallet busy, deferring disconnect notification (Phase 3.8.D band-aid)");
                return;
            }
        };

        if let Ok(pm) = wallet.node().peer_manager() {
            let descriptor = LijSocketDescriptor::new(id);
            pm.socket_disconnected(&descriptor);
            pm.process_events();
        }
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// Step 8a: WasmEsploraHttp — real EsploraHttp implementation using web_sys::fetch
// ─────────────────────────────────────────────────────────────────────────────

pub struct WasmEsploraHttp {
    /// v264: per-client request limit — 5 s for the independent sources, 60 s for the
    /// on-chain walk against the block-filter server.
    timeout_secs: u64,
    /// v264: the walk's client names itself in its errors ("block-filter server: …").
    filter_walk: bool,
}

impl WasmEsploraHttp {
    pub fn new() -> Self { Self { timeout_secs: lij_core::independent::REQUEST_TIMEOUT_SECS, filter_walk: false } }
    /// v264 (S47, DP's #20 run: "timeout after 5s" on every 501-filter batch): the walk's client.
    pub fn for_filter_walk() -> Self { Self { timeout_secs: lij_core::tier2_sync::WALK_TIMEOUT_SECS, filter_walk: true } }
}

impl lij_core::independent::EsploraHttp for WasmEsploraHttp {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = lij_core::error::LijResult<lij_core::independent::HttpResponse>> + 'a>> {
        Box::pin(async move {
            // v226 (S43, speed item 0): the trait promises REQUEST_TIMEOUT_SECS
            // and this impl never enforced it — a stalled endpoint held a
            // quorum round (and the cold-start Ready rule behind it) until the
            // browser gave up. Race the fetch against a 5 s delay; on timeout
            // the fetch future is dropped and the endpoint records a failure.
            use futures::future::{select, Either};
            let secs = self.timeout_secs;
            let timeout = wasm_timer::Delay::new(std::time::Duration::from_secs(secs));
            let walk = self.filter_walk;
            // v264: the walk's errors name the block-filter server (the "LSP error:" label was wrong there)
            let fail = |why: String| {
                if walk {
                    lij_core::error::LijError::Network(format!("block-filter server: {why} ({})", url.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or_default()))
                } else {
                    lij_core::error::LijError::Lsp(format!("WasmEsploraHttp GET {url}: {why}"))
                }
            };
            match select(Box::pin(fetch::get_with_status(url)), Box::pin(timeout)).await {
                Either::Left((Ok((status, body)), _)) => Ok(lij_core::independent::HttpResponse { status, body }),
                Either::Left((Err(e), _)) => Err(fail(format!("{e}"))),
                Either::Right((_, _)) => Err(fail(format!("no answer within {secs} s"))),
            }
        })
    }

    fn post<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        content_type: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = lij_core::error::LijResult<lij_core::independent::HttpResponse>> + 'a>> {
        Box::pin(async move {
            // Esplora's POST /tx accepts hex-encoded text. The body is already
            // hex from independent.rs::broadcast_to_quorum (which calls hex::encode).
            let body_str = std::str::from_utf8(body)
                .map_err(|e| lij_core::error::LijError::Lsp(format!("body utf8: {e}")))?;
            match fetch::post_with_status(url, body_str, content_type).await {
                Ok((status, resp)) => Ok(lij_core::independent::HttpResponse { status, body: resp }),
                Err(e) => Err(lij_core::error::LijError::Lsp(format!("WasmEsploraHttp POST {url}: {e}"))),
            }
        })
    }
}

// ============================================================================
// Phase 3.7.J — wasm binding for zombie monitor cleanup
// ============================================================================
//
// Exposes LijNode::purge_force_closed_monitor (defined in lij-core, added in
// Phase 3.7.H) to JavaScript so the wallet's DevTools console can clean up
// zombie ChannelMonitor entries — force-closed channels whose underlying
// outputs were already swept on chain but whose persistence records cause
// redundant chain_filter re-registration and broadcaster claim re-attempts
// on each wallet restart.
//
// JS usage:
//   await wallet.purge_force_closed_monitor("<funding_txid_hex>", <vout>);
//   // returns true if archived, false if no monitor existed.
#[wasm_bindgen]
impl LijWalletHandle {
    /// Archive a force-closed ChannelMonitor by funding outpoint.
    /// Returns true if a monitor was archived, false if none existed at the
    /// given outpoint. Throws on invalid txid hex or storage failure.
    #[wasm_bindgen]
    pub fn purge_force_closed_monitor(
        &self,
        funding_txid_hex: &str,
        output_index: u32,
    ) -> Result<bool, JsValue> {
        let txid = funding_txid_hex
            .parse::<bitcoin::Txid>()
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Invalid funding_txid_hex (expected 64 hex chars): {e}"
                ))
            })?;
        let wallet = self.inner.lock().map_err(|e| {
            JsValue::from_str(&format!("Lock error: {e}"))
        })?;
        wallet
            .node()
            .purge_force_closed_monitor(txid, output_index)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}


// ── v8 module-level helpers ───────────────────────────────────────────────
//
// Both used by send_payment_with_retries:
//   - wait_for_outcome: poll the per-payment outcome map with timeout, no
//     wallet lock held (event handler populates the map; we just observe).
//   - payment_result_json: serialize a PaymentResult to a JsValue, the shape
//     doSend() in wallet/index.html v8 expects.

/// Poll the outcome map for the given PaymentId, sleeping briefly between
/// checks. Returns Some(outcome) when an entry is found (and removes it from
/// the map), or None on timeout.
///
/// The lock is held ONLY during the map check (microseconds), then released
/// for the sleep — keeps background_tick free to run.
async fn wait_for_outcome(
    outcomes: std::sync::Arc<std::sync::Mutex<
        std::collections::HashMap<
            lightning::ln::channelmanager::PaymentId,
            lij_core::node::PaymentOutcome,
        >,
    >>,
    payment_id: lightning::ln::channelmanager::PaymentId,
    timeout_ms: u64,
) -> Option<lij_core::node::PaymentOutcome> {
    use wasm_timer::Delay;
    use std::time::Duration;

    let start_ms = js_sys::Date::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        // Brief lock: check + remove if present.
        {
            let mut map = match outcomes.lock() {
                Ok(m) => m,
                Err(_) => return None, // poisoned mutex — treat as timeout
            };
            if let Some(outcome) = map.remove(&payment_id) {
                return Some(outcome);
            }
        } // mutex released before sleep

        let elapsed = js_sys::Date::now() - start_ms;
        if elapsed >= timeout_ms as f64 {
            return None;
        }

        // Sleep before next poll. Ignore Delay errors (shouldn't happen in
        // WASM).
        let _ = Delay::new(poll_interval).await;
    }
}

/// Convenience: serialize a PaymentResult to a JsValue for return to JS.
/// v270 (running totals): the fee arrives in MILLISATS (LDK's fee_paid_msat) and goes out both
/// ways — fee_msat exact for the Lightning book, fee_sats (floored) for every older reader.
/// v280: PaymentResult's success flag, read without moving the struct.
fn r_success(r: &lij_core::types::PaymentResult) -> bool { r.success }

fn payment_result_json(
    success: bool,
    preimage: Option<String>,
    fee_msat: Option<u64>,
    error: Option<String>,
) -> JsValue {
    let result = lij_core::types::PaymentResult {
        success,
        preimage,
        fee_sats: fee_msat.map(|m| m / 1000),
        fee_msat,
        error,
    };
    match serde_json::to_string(&result) {
        Ok(s) => JsValue::from_str(&s),
        Err(_) => JsValue::from_str(
            r#"{"success":false,"preimage":null,"fee_sats":null,"fee_msat":null,"error":"serde_json failure"}"#,
        ),
    }
}


// ── Phase C-1 (S32): AIRGAPPED PSBT SIGNER — pure key math, no wallet
// state, fully functional under offline_start. A coordinator (Sparrow
// watch-only over our xpub) builds the PSBT with bip32_derivation hints;
// we sign every input whose fingerprint+path derive to this seed's keys
// and hand the rest back untouched. BIP39 passphrase empty (house
// standard). PSBT travels as HEX both ways (page converts base64↔hex,
// sidestepping the crate's base64 feature gate).
#[wasm_bindgen]
pub fn sign_psbt_hex(mnemonic: &str, psbt_hex: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::Secp256k1;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&format!("xprv: {e}")))?;
    // Hand-rolled hex (DP-confirmed): no trait dependence — the pinned
    // toolchain's hashes generation dropped ToHex (E0432/E0599 in CI).
    let ph = psbt_hex.trim();
    if ph.is_empty() || ph.len() % 2 != 0 || !ph.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(JsValue::from_str("hex: invalid"));
    }
    let bytes: Vec<u8> = (0..ph.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&ph[i..i + 2], 16).unwrap_or(0))
        .collect();
    let mut psbt = Psbt::deserialize(&bytes)
        .map_err(|e| JsValue::from_str(&format!("psbt: {e}")))?;
    let mut signed_inputs = match psbt.sign(&root, &secp) {
        Ok(map) => map.len(),
        Err((map, _errs)) => map.len(),
    };
    // v205 FALLBACK: some coordinators (BlueWallet watch-only) write a NULL
    // or foreign master fingerprint (DP field: 00000000 vs ours), so the
    // fingerprint match finds nothing. Trust the PATH: derive our child at
    // the hint path; if its pubkey equals the hint pubkey it is provably our
    // input, and we sign the p2wpkh input manually.
    {
        use bitcoin::sighash::{SighashCache, EcdsaSighashType};
        let txclone = psbt.unsigned_tx.clone();
        let mut adds: Vec<(usize, bitcoin::PublicKey, bitcoin::secp256k1::ecdsa::Signature)> = Vec::new();
        {
            let mut cache = SighashCache::new(&txclone);
            for i in 0..psbt.inputs.len() {
                let hints: Vec<(bitcoin::secp256k1::PublicKey, bitcoin::bip32::DerivationPath)> =
                    psbt.inputs[i].bip32_derivation.iter().map(|(pk, (_fp, path))| (*pk, path.clone())).collect();
                let wu = match psbt.inputs[i].witness_utxo.as_ref() { Some(o) => o.clone(), None => continue };
                if !wu.script_pubkey.is_p2wpkh() { continue; }
                for (hint_pk, path) in hints.iter() {
                    let child = match root.derive_priv(&secp, path) { Ok(c) => c, Err(_) => continue };
                    let sk = child.private_key;
                    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
                    let our_wph = bitcoin::WPubkeyHash::from_raw_hash(bitcoin::hashes::Hash::hash(&pk.inner.serialize()));
                    let sb = wu.script_pubkey.as_bytes();
                    let spk_ok = sb.len() == 22 && &sb[2..22] == &our_wph[..];  // v206: match by witness program hash of the derived key
                    let _ = hint_pk;
                    if !spk_ok { continue; }
                    if psbt.inputs[i].partial_sigs.contains_key(&pk) { continue; }
                    // v205c: VENDORED API AS-READ — spk.p2wpkh_script_code()
                    // builds the BIP143 scriptCode; segwit_signature_hash is
                    // the cache method this crate actually ships.
                    // 0.32: the sighash helper takes the scriptPubKey and derives the BIP143 script code
                    let sh = match cache.p2wpkh_signature_hash(i, &wu.script_pubkey, wu.value, EcdsaSighashType::All) {
                        Ok(s) => s, Err(_) => continue };
                    let msg = match bitcoin::secp256k1::Message::from_slice(sh.as_ref()) { Ok(m2) => m2, Err(_) => continue };
                    let sig = secp.sign_ecdsa(&msg, &sk);
                    adds.push((i, pk, sig));
                }
            }
        }
        for (i, pk, sig) in adds.into_iter() {
            let esig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };   // 0.32 field names
            psbt.inputs[i].partial_sigs.insert(pk, esig);
            signed_inputs += 1;
        }
    }
    if signed_inputs == 0 {
        return Err(JsValue::from_str("no inputs matched this seed's keys (checked fingerprint and derived pubkey)"));
    }
    Ok(psbt.serialize().iter().map(|b| format!("{:02x}", b)).collect::<String>())
}


// ── Phase C-3 (S32): OFFLINE RECEIVE ADDRESS — pure key math. Derives the
// standard house path m/84'/0'/0'/0/{index} to a p2wpkh address. The page
// owns index continuity via lij_onchain_recv_index (the same key the
// online wallet already reads). BIP39 passphrase empty (house standard).
#[wasm_bindgen]
pub fn derive_receive_address(mnemonic: &str, index: u32) -> Result<String, JsValue> {
    use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{index}"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let child = root.derive_priv(&secp, &path)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk = bitcoin::PublicKey::new(child.private_key.public_key(&secp));
    let addr = bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(pk.inner), bitcoin::Network::Bitcoin);   // 0.32: infallible
    Ok(addr.to_string())
}


// ── S33 B2 rider: ACCOUNT ZPUB EXPORT — pure key math, no state. Derives the
// account node m/84'/0'/0', serializes the xpub, and re-versions the four
// prefix bytes to zpub (0x04b24746) so watch-only coordinators (Sparrow,
// BlueWallet, Electrum) import it directly. Kills the golden-gate step-0:
// no more typing the 12 words into an offline machine to build a watcher.
/// v213 (evil-LSP reserve dial): the reserve the user demands the LSP keep
/// on its side, ppm, NEW channels only. Clamped 0..=50_000 (5% cap); 0 =
/// LDK's 1,000-sat floor. Free fn — callable before any wallet exists so
/// the boot re-apply lands ahead of create/restore (JIT accepts read the
/// ChannelManager config captured at construction). Returns the APPLIED
/// (clamped) value.
#[wasm_bindgen]
pub fn set_lsp_reserve_ppm(ppm: u32) -> u32 {
    let clamped = ppm.min(50_000);
    lij_core::node::LSP_RESERVE_PPM.store(clamped, std::sync::atomic::Ordering::Relaxed);
    clamped
}

/// v216 (S36, O6 fee headroom → exact-fee): the user's fee-race margin in
/// sats — subtracted once at the aggregate inside max_sendable_sats. Page
/// persists (WALLET → Controls dial) and boot-applies before any wallet
/// exists (free fn, LSP-reserve pattern). Clamped 0..=5,000. Returns applied.
/// S45 (DP): Dials → Speed up slow closes — Off / Automatic (default Off).
#[wasm_bindgen]
pub fn set_coop_cpfp_auto(on: bool) -> bool {
    lij_core::node::COOP_CPFP_AUTO.store(on, std::sync::atomic::Ordering::Relaxed);
    on
}

/// v312 (S57, DP ruling (a)): the last inbound open refused because its channel type was anchors —
/// {"at_ms": n, "funding_sats": n}; at_ms 0 = none since this page loaded.
#[wasm_bindgen]
pub fn anchors_refused_json() -> String {
    format!("{{\"at_ms\":{},\"funding_sats\":{}}}",
        lij_core::node::ANCHORS_REFUSED_AT_MS.load(std::sync::atomic::Ordering::Relaxed),
        lij_core::node::ANCHORS_REFUSED_SATS.load(std::sync::atomic::Ordering::Relaxed))
}

#[wasm_bindgen]
pub fn set_fee_margin_sats(sats: u32) -> u32 {
    let clamped = sats.min(5_000);
    lij_core::node::FEE_MARGIN_SATS.store(clamped as u64, std::sync::atomic::Ordering::Relaxed);
    clamped
}

#[wasm_bindgen]
pub fn derive_account_zpub(mnemonic: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let path = DerivationPath::from_str("m/84'/0'/0'")
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let acct = root.derive_priv(&secp, &path)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let xpub = ExtendedPubKey::from_priv(&secp, &acct);
    let mut data = xpub.encode();
    // zpub version bytes per SLIP-132 (BIP84 mainnet public).
    data[0] = 0x04; data[1] = 0xb2; data[2] = 0x47; data[3] = 0x46;
    Ok(bitcoin::base58::encode_check(&data))   // 0.32 name
}


// ── S32 FORENSICS: PSBT KEY-MATCH PROBE — no signing, no state. Reports
// our master fingerprint and, per input, every bip32_derivation keysource
// (fingerprint + path) the coordinator recorded, with a match flag. Built
// because a sign attempt returned byte-identical output while claiming
// success — the data, not a theory, will name the mechanism.
#[wasm_bindgen]
pub fn psbt_probe(mnemonic: &str, psbt_hex: &str) -> Result<String, JsValue> {
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::Secp256k1;
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| JsValue::from_str(&format!("mnemonic: {e}")))?;
    let seed = m.to_seed("");
    let secp = Secp256k1::new();
    let root = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let our_fp = root.fingerprint(&secp).to_string();
    let ph = psbt_hex.trim();
    if ph.is_empty() || ph.len() % 2 != 0 || !ph.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(JsValue::from_str("hex: invalid"));
    }
    let bytes: Vec<u8> = (0..ph.len()).step_by(2)
        .map(|i| u8::from_str_radix(&ph[i..i + 2], 16).unwrap_or(0)).collect();
    let psbt = Psbt::deserialize(&bytes)
        .map_err(|e| JsValue::from_str(&format!("psbt: {e}")))?;
    let mut inputs = Vec::new();
    for (idx, inp) in psbt.inputs.iter().enumerate() {
        let mut entries = Vec::new();
        for (pk, (fp, path)) in inp.bip32_derivation.iter() {
            let derived = root.derive_priv(&secp, path).ok()
                .map(|c| bitcoin::PublicKey::new(c.private_key.public_key(&secp)).inner.to_string())
                .unwrap_or_else(|| "derive_failed".to_string());
            entries.push(serde_json::json!({
                "pubkey": pk.to_string(),
                "derived_pubkey": derived,
                "derived_matches_hint": derived == pk.to_string(),
                "fingerprint": fp.to_string(),
                "path": path.to_string(),
                "fp_matches_ours": fp.to_string() == our_fp,
            }));
        }
        let has_wu = inp.witness_utxo.is_some();
        let is_wpkh = inp.witness_utxo.as_ref().map(|o| o.script_pubkey.is_p2wpkh()).unwrap_or(false);
        inputs.push(serde_json::json!({
            "input": idx,
            "partial_sigs": inp.partial_sigs.len(),
            "has_witness_utxo": has_wu,
            "is_p2wpkh": is_wpkh,
            "derivations": entries,
        }));
    }
    let out = serde_json::json!({ "our_master_fp": our_fp, "inputs": inputs });
    Ok(out.to_string())
}
