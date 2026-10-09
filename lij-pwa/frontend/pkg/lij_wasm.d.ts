/* tslint:disable */
/* eslint-disable */

export class LijWalletHandle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * S21 build #1 (ledger reconciler): expose LDK's recent outbound
     * payments for the startup RECENT backfill. JSON array of
     * {state, payment_id, payment_hash?, total_msat?}. try_lock — the
     * frontend retries on a stagger, never blocks the UI thread.
     * v189 (S29): abandon a stuck outbound payment by PaymentId hex, as
     * reported by list_recent_payments_json. Makes ledger retirement
     * terminal in LDK, so Pass-2 backfill can never resurrect a ghost
     * after a history clear.
     */
    abandon_payment_by_id(payment_id_hex: string): void;
    /**
     * Step 3.6 (F4): synchronous accessor for the currently-active LSP.
     * Returns the LSP's info as a JSON string, or None when no LSP is set.
     *
     * Unlike list_lsps(), this does NOT do an HTTP fetch — it reads from
     * in-memory state under the wallet mutex, then releases the lock before
     * returning. Safe to call from polling loops without risking the
     * "cannot recursively acquire mutex" panic that hit Step 3.5's hot-fix
     * when getActiveLsp() tried list_lsps() as a fallback.
     *
     * The frontend's getActiveLsp() helper already calls this binding; once
     * this method ships, the LSP fields on Cards 2 and 3 will populate and
     * the LSP relationship card on the Connection screen will render.
     */
    active_lsp_json(): string | undefined;
    /**
     * v309 (S56, DP 2026-10-06 "Go"): the cloud copy for these words, pulled and written with the words alone — no
     * node built, nothing running that could write over it. The restore screen's Continue and "Use the cloud copy"
     * run it at the passphrase, the way a device file is loaded (v952). Resolves to
     * {"channels":n,"version":v,"saved_at_ms":t}; REJECTS with "NO_COPY", "FETCH: …" (no answer — nothing was changed)
     * or "CORRUPT: …" (the copy does not open — nothing was written).
     */
    static adopt_cloud_backup(mnemonic: string, config_json: string): Promise<any>;
    background_tick(tick_count: bigint): void;
    backup(): Promise<any>;
    /**
     * v319: take the number of this phone's own outstanding upload as the phone's (the cloud holds that copy; its OK
     * was lost) — the note is read, its number committed (upward only), the note cleared. Returns the number taken,
     * 0 when no note stands. Never takes a number from the page: only the one this phone itself sent.
     */
    backup_adopt_own(): bigint;
    /**
     * v309 (S56): the cloud's number when it refused this phone's copy as older; 0 = no refusal. The page shows it
     * once and offers "Use the cloud copy" (adopt_cloud_backup at the next unlock) or "Replace the cloud copy with this
     * phone" (backup_replace_cloud).
     */
    backup_conflict(): bigint;
    /**
     * Manually push the current encrypted wallet state to all enabled backup
     * sinks (scenario-A backup). Returns `{"ok":true}`. This is the "Back up
     * now" action and our round-trip test entrypoint; automatic triggers will
     * reuse the same `LijWallet::backup()` path.
     */
    backup_now(): Promise<any>;
    /**
     * v268 (S48, DP): the words screen's question, asked BEFORE anything is written — see
     * LijWallet::backup_probe. Resolves to {"found":true,"channels":n,"version":v} or
     * {"found":false}; REJECTS with the reason when the service gave no answer (no
     * connection, service down) — the page treats that as a third outcome, never as "none".
     */
    static backup_probe(mnemonic: string, config_json: string): Promise<any>;
    /**
     * v309 (S56): the person's decision to replace a newer cloud copy with this phone's state — the cloud's number
     * is taken as the phone's (the next copy is one above it) and one upload runs now.
     */
    backup_replace_cloud(): Promise<any>;
    /**
     * v275 (Black Start): the sealed, signed push — see node::black_start_bundle_json. Read-only.
     */
    black_start_bundle_json(): string;
    /**
     * v313: the merged, sealed, signed push — see node::black_start_bundle_merged_json. Read-only.
     */
    black_start_bundle_merged_json(held_json: string, chain_json: string): string;
    /**
     * v276 (Black Start): the kit's fingerprint — {"fp","channels"}; cheap, no signing. try_lock.
     */
    black_start_fingerprint_json(): string;
    /**
     * v211 (ESCAPE KIT): per-channel signed latest holder commitment
     * ("THE CLOSE") + pre-signed to_local sweep ("THE COLLECT",
     * nSequence = to_self_delay, two feerates — no RBF after the fact),
     * destination = PEEKED m/84 allocator index. Read-only by
     * constitution: nothing broadcast, nothing queued, counter not
     * advanced, state unchanged. Runs on the offline read-only instance.
     * Returns the kit as a JSON string.
     * v275 (Black Start): the NIP-06 identity — {"npub","pubkey"}. try_lock — WALLET_BUSY.
     */
    black_start_identity_json(): string;
    /**
     * v313 (the kit across copies): which outpoints the chain must be asked about before a merge — see
     * node::black_start_merge_plan_json. Read-only.
     */
    black_start_merge_plan_json(held_json: string): string;
    /**
     * v166 (#29-4b): RBF-replace one of OUR pending on-chain sends at a
     * higher fee. Same inputs, same destination; the delta comes out of the
     * change. The engine enforces BIP-125 economics and answers with
     * actionable minimum/maximum sat/vB messages on violation.
     */
    bump_onchain_send(old_txid: string, new_fee_rate_sat_per_kw: number): Promise<any>;
    /**
     * Background tick — JS calls every second to keep LDK alive.
     * Handles peer keepalives, channel maintenance, and event processing.
     * S30 (v199): read the chain flight recorder — the ChainCoordinator's
     * event ledger (tip advances, stale drops, confirmations, independent
     * observations, with heights). Read-only diagnosis surface.
     */
    chain_events_json(limit: number): string;
    /**
     * v302 (S54): the Address watcher row's Save check — resolves to the server's tip height when `base` is a
     * clean https address answering as an Esplora server (/blocks/tip/height, then /address/<a never-funded probe
     * address>/utxo); rejects with the reason otherwise. Nothing of the user's is sent.
     */
    check_watch_server(base: string): Promise<any>;
    claimed_payments_json(): string;
    /**
     * Initiate a cooperative close. Synchronous from JS perspective —
     * returns once shutdown is sent. Actual close confirmation arrives
     * later via the closed-channels list.
     */
    close_channel(channel_id_hex: string): void;
    /**
     * TEMP diagnostic: dump the close-event log — every ChannelClosed reason and
     * every coop/force close invocation, with timestamps, so the close SEQUENCE
     * for a channel is visible. Remove with the rest of the temp diagnostics.
     */
    close_event_log(): string;
    /**
     * S24 Build 13: per-channel close values (see lij-core close_values_json).
     */
    close_values_json(): string;
    /**
     * v309 (S56): what the cloud holds for this wallet — {"found":true,"channels":n,"version":v,"saved_at_ms":t} or
     * {"found":false}; REJECTS when the service gave no answer. Nothing is written. The warning before a device file
     * is loaded compares the file's date and number with these.
     */
    cloud_backup_info(): Promise<any>;
    /**
     * v310 (S57, DP 2026-10-07 "Go with … 1"): the cloud copy's number and date only — {"found":true,"version":v,
     * "saved_at_ms":t} or {"found":false}; REJECTS when the service gave no answer (or has no /backup/meta). The page
     * compares the number with this phone's before the first connection to the provider; nothing is pulled or written.
     * v319 (S57, DP 2026-10-08 14:40 "Go"): the answer adds "fingerprint" (the stored copy's, or null) and "own" —
     * true when the cloud's copy is THIS PHONE'S OWN UPLOAD: its number and fingerprint are the ones this phone noted
     * before an upload whose OK never arrived (the app put away mid-upload). The page then takes the number
     * (backup_adopt_own) and connects with no warning; a copy this phone never sent reads own:false as before.
     */
    cloud_backup_meta(): Promise<any>;
    /**
     * v281 (S50, coin control): mark one coin. `req` is JSON {"txid","vout", "frozen"?:
     * bool, "note"?: string} — a field left out is left alone; a note is cleaned and
     * capped at 120 code points in the engine. Answers the coin's mark as stored (JSON
     * {"txid","vout","frozen","note","ts_ms"}) plus "frozen_count". Written to the
     * marks store (its own encrypted key — a sync in flight cannot clobber it).
     */
    coin_mark(req: string): string;
    /**
     * Connect to a Lightning peer over WebSocket.
     */
    connect_to_peer(pubkey_hex: string, wss_url: string): Promise<any>;
    /**
     * On-chain send (option D, increment 2): P2WPKH spend from the m/84
     * spendable chain, change to m/84'/{coin}'/0'/1/0. `amount_sats` is a JS
     * number (f64 is exact up to 2^53, far above the 2.1e15-sat supply cap);
     * `fee_rate_sat_per_kw` is LDK sat/kilo-weight (use FeeQuote::on_chain_sweep).
     * S45 (DP): plan (send=false) or send (send=true) a CPFP child for a
     * pending cooperative close — the user's Speed up on the on-chain face.
     * Always forced (the user's tap skips the automatic mode's gates).
     * Returns JSON {ok, can, reason, child_fee_sats, parent_rate_vb, target_vb, txid}.
     */
    coop_cpfp(channel_id_hex: string, send: boolean): Promise<any>;
    static create(config_json: string): Promise<any>;
    create_invoice(amount_sats: bigint | null | undefined, memo: string, expiry_seconds: bigint, lsp_endpoint?: string | null, lsp_route_macaroon?: string | null): Promise<any>;
    /**
     * v0.16 Phase C: create a Lightning invoice with an LSPS2 JIT channel
     * route_hint.
     *
     * Three-phase flow with proper mutex discipline (matches v8 send-path
     * pattern that fixed mutex_no_threads panics):
     *   1. lsps2 get_info — network round-trip, NO wallet lock held
     *   2. lsps2 buy      — network round-trip, NO wallet lock held
     *   3. build invoice  — sync, wallet lock held briefly
     *
     * JS receives the parsed InvoiceWithJitResult as a JSON string. Errors
     * (network failure, validation failure, lock failure) are thrown as JS
     * exceptions.
     *
     * # Example (JS)
     * ```javascript
     * const r = await wallet.create_invoice_with_jit(
     *   BigInt(50000), "Coffee", BigInt(600),
     *   "https://lijox-lsp.lightning-mod.com", route_macaroon,
     * );
     * const result = JSON.parse(r);
     * displayInvoice(result.invoice.bolt11);
     * displayFeeBreakdown(result.jit.human_summary);
     * ```
     */
    create_invoice_with_jit(amount_sats: bigint, memo: string, expiry_seconds: bigint, lsp_endpoint: string, lsp_route_macaroon: string): Promise<any>;
    create_open_invoice_with_jit(memo: string, expiry_seconds: bigint, lsp_endpoint: string, lsp_route_macaroon: string): Promise<any>;
    /**
     * DIAGNOSTICS: monitor census + spend-walker liveness for the on-device
     * status pane (iOS has no console). See node::diagnostics_json.
     */
    diagnostics_json(): string;
    /**
     * Step 3 (S30): drop a tier-2 pending tx by txid — the dead-funding
     * janitor's executioner. The UI judges (Esplora outspend verdicts on the
     * record's spent_outpoints); this removes the record so
     * rebroadcast-until-seen stops and its input reservation releases.
     * Returns {"removed":bool}.
     */
    drop_pending_tx(txid_hex: string): string;
    /**
     * Step 3.6 diagnostic: returns full LDK ChannelDetails as a JSON
     * string. Use from F12 console for inspection when the slim
     * get_channels() output isn't enough.
     */
    dump_channel_details_json(): string;
    /**
     * End relationship with an LSP. Returns JSON array of per-channel
     * outcomes: [{ "channel_id_hex": "...", "ok": true/false, "error": "..." }, ...]
     */
    end_lsp_relationship(lsp_pubkey_hex: string): string;
    escape_export(): string;
    /**
     * v209: the SAME ciphertext the cloud sink receives, returned to the page
     * for a manual device download. Forces a fresh snapshot via the dirty
     * handle; state is unchanged, so the next auto-backup is a cheap no-op.
     */
    export_backup_blob(): string;
    /**
     * Force close a channel. Destructive — UI must confirm first.
     */
    force_close(channel_id_hex: string): void;
    /**
     * Abandon all channels WITHOUT broadcasting (safe recovery from a stale
     * restore). Call this BEFORE reconnecting to peers to avoid the
     * data-loss-protect panic on channel_reestablish. Returns channels closed.
     */
    force_close_all_without_broadcasting(): number;
    /**
     * Force-close ONE channel without broadcasting any tx. For a stranded
     * open whose funding never confirmed (LDK's no-progress watchdog keeps
     * dropping the peer over it). Broadcasts nothing — safe for an
     * unconfirmed funding. Destructive — UI must confirm first.
     */
    force_close_without_broadcasting(channel_id_hex: string): void;
    /**
     * Auto-backup tick: if channel state changed since the last push, snapshot
     * it under the lock, release, then push to enabled sinks UNLOCKED. Cheap
     * no-op when nothing changed; the frontend calls this on a slow debounce
     * interval. Never holds the wallet mutex across the push's `.await`.
     * v250 (S46, DP GO): delete this wallet's cloud copy at every enabled sink.
     * Local state is untouched; the caller decides what follows (the Privacy
     * switch turning Off, or the Erase gate's "delete the cloud copy too").
     * Answers {"ok":true,"forgotten":N,"existed":bool}; an error if every sink refused.
     */
    forget_cloud_backup(): Promise<any>;
    get_balance(): Promise<any>;
    get_chain_status(): string;
    get_channels(): string;
    /**
     * v165 (#29-4a): current fee-rate tiers for the speed picker (JSON).
     */
    get_fee_rates(): string;
    /**
     * On-chain transaction history for the RECENT list. The trusted-node source
     * was removed with the shim; this returns an empty list until Tier 2
     * (client-side BIP158 filter matching) reconstructs history locally. Kept so
     * the frontend RECENT wiring stays stable across the transition.
     * v252 (S46, DP's #20 run): given a transaction id, find the output that pays one of
     * THIS wallet's addresses (receive/change/legacy chains, a 200-wide window from the
     * used frontier) and answer {"found":true,"address":..,"vout":n,"value_sats":..}. Used
     * after recover-close: the LSP names the closing txid, the wallet finds its own
     * output and opens a receive expectation on that address, so the 0-conf watcher shows
     * the return in the mempool and the confirmed card on the block. A words-only restore
     * does not know the pin index; this finds it from the transaction itself.
     */
    identify_own_output(txid: string): Promise<any>;
    /**
     * v221 (DP fire-and-forget): device-file backup import — parses the v209
     * export's StateBlob JSON and injects through the same generic path the
     * cloud restore uses (wrong-seed files fail decryption). Returns
     * {"keys":N}; the page gates live channels and reloads — state applies
     * on the reboot.
     */
    import_backup_blob(blob_json: string): string;
    /**
     * v268 (S48, DP): a device backup file opened with the words only — no node built, no
     * network — so the restore flow can take a file before any state exists on the device,
     * and a phone with no connection can still reach its offline room. Writes the file's
     * channel state; the page reloads after. Returns {"channels":n}.
     */
    static import_backup_file(mnemonic: string, config_json: string, blob_json: string): string;
    /**
     * Session 23 (1b engine half): version of the last vault push, read
     * from KEY_BACKUP_VERSION (u64 BE). Returns 0 when no push has ever
     * happened. Feeds the standing Backup drilldown row
     * ("vault · vNNN · synced").
     */
    last_backup_version(): number;
    /**
     * Return the closed-channel log as JSON.
     */
    list_closed_channels(): string;
    list_lsps(): Promise<any>;
    /**
     * List currently connected Lightning peers.
     */
    list_peers(): Promise<any>;
    /**
     * v166 (#29-4b): raw pending list for the bump UI (storage-only).
     */
    list_pending_json(): string;
    list_recent_payments_json(): string;
    lnurlp_prepare_hashes(count: number, start_hint?: number | null): Promise<any>;
    /**
     * Estimate for the + Add channel UI: spendable on-chain, the MAX channel
     * value openable at this fee rate (spendable − funding fee − anchor
     * reserve), and the floor/reserve constants. Reads the Tier-2 view from
     * local storage; needs no wallet lock.
     */
    lsp_channel_open_estimate(fee_rate_sat_per_vb: number): Promise<any>;
    /**
     * v282: the + Add channel estimate for the CHOSEN coins — `req` JSON {"fee_rate_sat_per_vb",
     * "inputs"?: [{"txid","vout"}]}; max_channel_sats is what exactly those coins can open.
     * A frozen or unknown choice answers {"problem": "…"} with max_channel_sats 0.
     */
    lsp_channel_open_estimate_with(req: string): Promise<any>;
    /**
     * Dev tool: manually mark a funding transaction as confirmed at a
     * given height. Synthesizes block headers and notifies LDK's chain
     * listeners — pre-Neutrino workaround for the stuck-channel case.
     * Returns the channels list as JSON after the confirmation is processed.
     */
    mark_funding_confirmed(funding_tx_hex: string, confirmed_at_height: number): string;
    /**
     * Pre-maturity closing funds (ChannelMonitor claimable, CSV-locked).
     * See node::maturing_balances_json.
     */
    maturing_balances_json(): string;
    /**
     * Maturing on-chain outputs from channel closes still tracked by the
     * OutputSweeper. Each entry is a force-close to_local (or other spendable)
     * output that has not yet fully landed in the spendable balance. The UI
     * sums these for the balance-card "maturing" subtext and groups them by
     * channel for per-close detail. Returns a JSON array; "[]" before the
     * sweeper is initialized (the narrow pre-init window) or when nothing is
     * maturing.
     *
     * Each entry: { value_sats, status, delayed_until_height, confirmation_height, channel_id }
     *   status "pending_broadcast" — sweep tx not yet broadcast. CSV-locked
     *     while delayed_until_height is in the future; blocks-remaining =
     *     delayed_until_height - tip (the UI computes this against its tip).
     *   status "sweeping"          — sweep tx broadcast, awaiting first
     *     confirmation (≈1 block out).
     *   status "confirming"        — sweep tx confirmed; the funds are landing
     *     in the spendable balance via the normal Tier-2 scan, so the UI does
     *     NOT count these as still-maturing (avoids double-counting).
     */
    maturing_outputs(): string;
    /**
     * v173: the planner's own sendable ceiling — the ONE number every send
     * surface quotes (identical math to mpp_plan's total_usable_sats).
     */
    max_sendable_sats(): bigint;
    maybe_backup(): Promise<any>;
    /**
     * Network-free receive address at `index` (BIP84 m/84'/{coin}'/0'/0/index).
     * Synchronous + offline: derives from the seed only, so receiving never
     * depends on a chain scan. The frontend persists the index and reconciles
     * it upward whenever a scan succeeds, advancing per receive to avoid reuse.
     */
    next_receive_address(index: number): string;
    node_pubkey(): string;
    /**
     * BACKGROUND HINT (D-1 JIT safety): clears the channel-acceptance gate so a
     * backgrounded/offline wallet refuses inbound JIT opens it couldn't claim
     * into. The wallet lock is never held across an await, so try_lock is free
     * at the visibilitychange callback boundary; the event also fires before any
     * grace-period background tick can process an OpenChannelRequest.
     */
    note_background(): void;
    /**
     * FOREGROUND HINT: force the next background tick to re-scan for closes,
     * regardless of cadence phase. Best-effort — silently skips if the wallet
     * is busy (a walk is likely already in flight). See node::note_foreground.
     */
    note_foreground(): void;
    /**
     * A new connection for one app: `req` = JSON {"name","relay"}. Answers {id,name,
     * service_pk,client_pk,uri,info_event} — the uri carries the client secret and is shown
     * once; the info event (13194) is what the page publishes to the relay.
     */
    nwc_add(req: string): string;
    /**
     * The NIP-42 AUTH event (22242) answering the relay's challenge as connection `id`.
     */
    nwc_auth_event(id: number, relay: string, challenge: string): string;
    /**
     * End a connection: `reason` = "revoked" (the user), "switched" (an LSP switch — pass id 0
     * to end every live one). The secret is dropped at once.
     */
    nwc_end(id: number, reason: string): string;
    /**
     * Drop an ended connection's row from the list.
     */
    nwc_forget(id: number): void;
    /**
     * The info event (13194) for a connection, re-signed now (the page republishes it when
     * the relay lost it).
     */
    nwc_info_event(id: number): string;
    /**
     * The connections and limits, for Dials → NWC. JSON {"conns":[{id,name,service_pk,
     * client_pk,relay,created_ms,expires_ms,last_used_ms,ended}], "limits":{…},
     * "paid_today_sats", "live"}. Secrets never appear.
     */
    nwc_list(): string;
    /**
     * Open a request event (kind 23194) fetched from the relay. The connection is found by
     * the event's `p` tag. Answers the `Opened` record (the request's method, invoice, amount,
     * payee, and either `refusal` {code,message} or nothing — then the page fills Send), or
     * an error when the event is not ours / malformed / too old (the page drops it).
     */
    nwc_open(event_json: string): string;
    /**
     * Record an NWC payment once its preimage is in hand: `req` = JSON {"conn_id","msat",
     * "payee","payment_hash"}. Feeds the daily total and the duplicate check.
     */
    nwc_record_paid(req: string): string;
    /**
     * A reply (kind 23195) for the page to publish: `req` = JSON {"conn_id","request_id",
     * "result_type", "result": {…} | null, "error": {"code","message"} | null, "encryption"?}.
     * v290: `encryption` is the opened request's ("nip44_v2" | "nip04") — the reply goes back in kind.
     */
    nwc_reply(req: string): string;
    /**
     * The Dials: JSON {"per_payment_sats","per_day_sats","connection_days","request_ttl_secs"}.
     */
    nwc_set_limits(req: string): string;
    onchain_history(): Promise<any>;
    /**
     * v281 (S50, coin control): the exact Max at this fee rate — what a one-output send
     * of every sendable coin delivers, from the builder's own candidate set and fee
     * arithmetic (MaxQuote JSON: max_sats, fee_sats, inputs, total_sats, frozen_sats,
     * frozen_count, sat_per_vb). `dest` may be empty while the user is still typing.
     * Storage only, no network.
     */
    onchain_max(dest: string, fee_rate_sat_per_kw: number): string;
    /**
     * v305: the quote for send_onchain_multi — the SAME plan the builder makes (no keys, no network): {"amounts" (the
     * last = its Max when its amount is missing), "total_sats", "fee_sats", "change_sats", "inputs", "spend",
     * "sat_per_vb", "problem" (the builder's refusal in plain words, else null)}. `req` as send_onchain_multi's.
     */
    onchain_multi_quote(req: string): string;
    /**
     * v282 (S50, coin control cut 3): the picker's quote. `req` is JSON {"dest", "fee_rate_sat_per_kw",
     * "inputs"?: [{"txid","vout"}], "amount_sats"?, "fill"?: bool} → CoinQuote JSON (chosen, chosen_sats,
     * max_sats, need_sats, covered, short_sats, fill [...], fill_covers, sendable_sats, frozen_sats,
     * problem). Storage only, no network.
     */
    onchain_quote(req: string): string;
    /**
     * Read-only on-chain wallet summary (D, increment 1): scans the BIP84
     * spendable chain + legacy m/525 residue and returns balance, UTXOs, and a
     * fresh receive address as JSON. Snapshots handles under the lock, then
     * runs the scan UNLOCKED (network I/O), like the backup path.
     */
    onchain_summary(): Promise<any>;
    /**
     * Request a channel from the active LSP via LSPS1.
     * Returns JSON with channel_point (funding txid:output_index) once adapter replies.
     *
     * @param inbound_sats - Channel capacity in satoshis (adapter enforces min/max)
     * @returns Promise<string> - JSON { channel_id, confirmations_required }
     *
     * Implementation note: extracts all needed data from the wallet INSIDE the mutex
     * (synchronous, fast), then releases the lock BEFORE doing the HTTP call.
     * Holding the lock across an `.await` deadlocks with background_tick.
     */
    open_channel(inbound_sats: bigint): Promise<any>;
    /**
     * v206: payments CLAIMED this session, as `[{"hash":"<hex>","sats":N}]`.
     * The frontend ledger completes a pending receive only when its
     * payment_hash appears here — an authoritative claim signal that replaces
     * the balance-delta heuristic. See node::claimed_payments_json.
     * v267: self-funded opens whose funding tx could not be built this session (see
     * node::open_failures_json). try_lock — the page asks again on WALLET_BUSY.
     */
    open_failures_json(): string;
    /**
     * Open an OUTBOUND channel to the active LSP, funded from on-chain balance.
     * `amount_sats` is the channel capacity; `fee_rate_sat_per_vb` is the
     * on-chain fee rate for the funding transaction. Returns a status JSON
     * immediately; the channel opens asynchronously (watch background_tick /
     * channel list for ChannelReady). The funding tx is built + signed by the
     * wallet from its Tier-2 UTXOs and broadcast by LDK — not the adapter.
     */
    open_lsp_channel(amount_sats: bigint, fee_rate_sat_per_vb: number): Promise<any>;
    /**
     * v282 (S50, coin control cut 3): the same open, funded from EXACTLY the chosen coins.
     * `req` is JSON {"amount_sats", "fee_rate_sat_per_vb", "inputs": [{"txid","vout"}, …]}.
     * The coins wait under the open's nonce for LDK's funding event (seconds); a frozen,
     * unknown or short set fails the open there, in plain words, and nothing is spent.
     */
    open_lsp_channel_with(req: string): Promise<any>;
    outstanding_close_attempts(): string;
    peek_channel_index(): number;
    /**
     * Build #4 confirmation instrument: pending-record audit vs the
     * independent quorum. Async — the wallet lock is dropped before any
     * network I/O.
     */
    pending_onchain_audit_json(): Promise<string>;
    /**
     * S21 item 2 (persistence audit): true when load-time stamps showed the
     * manager stale vs monitors (interrupted save). Frontend surfaces honest
     * copy; LDK's protective FC is expected behavior in this state.
     */
    persist_skew_at_load(): boolean;
    /**
     * S30 (v197) fix-probe: explicit outbound pump. The codebase pumps
     * process_events after inbound bytes, after disconnects, and on the
     * background tick — but never immediately after locally INITIATING an
     * action. A channel open is the one purely self-initiated message in
     * the system; it must not wait for borrowed timing to reach the wire.
     * `do_timer` also fires the peer keepalive tick, extending short iOS
     * sessions through the multi-message funding handshake.
     */
    pump_peer(do_timer: boolean): void;
    /**
     * Archive a force-closed ChannelMonitor by funding outpoint.
     * Returns true if a monitor was archived, false if none existed at the
     * given outpoint. Throws on invalid txid hex or storage failure.
     */
    purge_force_closed_monitor(funding_txid_hex: string, output_index: number): boolean;
    /**
     * The recipient: a pasted or opened link. JSON {hash, secret, expires, amount_sats, lsp_prefix};
     * the page registers (hash, secret) with this wallet's provider and asks the holder to deliver.
     */
    push_accept(fragment: string): string;
    push_in_json(): string;
    /**
     * A link's facts without accepting it (the claim sheet before the tap). JSON or an error string.
     */
    static push_link_parse(fragment: string): string;
    /**
     * The sender pays the provider's hold invoice for the push's hash — the INTERNAL self-hop (the
     * invoice is the active provider's own) — and returns as soon as the HTLC is out: the lock is
     * meant to sit for the window, so there is nothing to wait for here. LDK's later word (settled =
     * taken, failed back = returned) reaches the record through the event latch and push_out_json.
     * JSON {ok, payment_id, hash} or {ok:false, error}.
     */
    push_lock(bolt11: string, route_endpoint: string, route_macaroon_hex: string): Promise<any>;
    /**
     * The page reports a void (the provider failed the unclaimed HTLC back on the sender's signed ask).
     */
    push_mark(hash_hex: string, status: string, payment_id_hex?: string | null): void;
    push_out_json(): string;
    /**
     * "Copy link" later: the key re-derived from the record's index.
     */
    push_out_preimage(hash_hex: string): string;
    /**
     * v188 (S27): OPEN-AMOUNT JIT invoice — zero-amount sibling of
     * create_invoice_with_jit. Same Phase 0-4 choreography; buy carries
     * NO payment_size (variable mode); register_secret sends total_msat=0
     * (the variable sentinel — adapter fills the real total at flush).
     * v195 (S30): LNURLp hash pool — generates preimages inside the wallet,
     * persists them, and returns JSON [{hash, secret}] for LSP registration.
     * Preimages never cross this boundary.
     * v229: `start_hint` = the LSP's next_index for this name (the page passes
     * it from the register probe; undefined/None when the LSP is older).
     * The sender's first step. JSON {index, hash, preimage, amount_sats, expiry, window_secs, fragment}.
     */
    push_prepare(amount_sats: bigint, window_secs: bigint, lsp_pubkey_hex: string): string;
    /**
     * v216 (S36, O6 fee headroom → exact-fee): the scan-time quote. Runs the
     * SAME route-build the send path uses (pure QueryRoutes proxy — verified
     * side-effect-free in adapter code), records any lsp_first_hop_policy
     * sighting into the exact-fee cache, and returns the total sender fee
     * for this invoice/amount. The throwaway PaymentId from prepare is never
     * applied. Resolves to JSON:
     *   {"fee_msat":N,"fee_sats":N,"amount_msat":N,"policy_seen":bool,"synth":bool}
     */
    quote_route_fee(bolt11: string, route_endpoint: string, route_macaroon_hex: string, amount_sats_override?: bigint | null): Promise<any>;
    /**
     * S45 (DP): the same quote for a PUBKEY destination with no invoice —
     * Max pricing a route to another LSP's node (an LNURL address that LSP
     * serves) before any invoice is minted. Records any lsp_first_hop_policy
     * sighting like quote_route_fee. Resolves to the same JSON shape.
     */
    quote_route_fee_to_pubkey(dest_pubkey_hex: string, route_endpoint: string, route_macaroon_hex: string, amount_sats: bigint): Promise<any>;
    /**
     * Register a Web Push wake subscription (D-1 2c offline-receive). Takes the
     * browser PushSubscription serialized to JSON; signs the `push-subscribe`
     * challenge with the node key and POSTs to the active LSP. The returned
     * Promise resolves on success and rejects with the error string on failure.
     */
    register_push_subscription(subscription_json: string): Promise<any>;
    /**
     * Session 23 Option B (allocator unification, the other direction):
     * the frontend reserves receive-index territory. Raises the shared
     * allocator floor to index+1 on the LIVE counter instance, so the
     * signer can never issue an index at or below a shown/used receive
     * address. No-op when the allocator is already past it.
     */
    reserve_onchain_index(index: number): void;
    static restore(mnemonic: string, config_json: string): Promise<any>;
    /**
     * Lock-prepare-unlock: snapshot handles under the lock, then build/sign/
     * broadcast with the lock released (network I/O). Returns SendResult JSON.
     */
    send_onchain(dest: string, amount_sats: number, fee_rate_sat_per_kw: number): Promise<any>;
    /**
     * v281 (S50, coin control — Max): send everything sendable to `dest` in one output
     * (every unfrozen, unreserved coin; amount = total − the one-output fee; no change).
     * The page's Max calls this instead of guessing an amount for send_onchain.
     */
    send_onchain_all(dest: string, fee_rate_sat_per_kw: number): Promise<any>;
    /**
     * v305 (S54, DP 2026-10-02 13:50 "Go ahead" — SEVERAL RECIPIENTS IN ONE SEND): `req` is JSON {"recipients":
     * [{"dest","amount_sats"?}], "fee_rate_sat_per_kw", "inputs"?: [{"txid","vout"}]} — a missing amount on the LAST
     * recipient = everything left after the others and the fee (Max); chosen coins = exactly those. One transaction:
     * the recipients in order (vout 0 …), then the change. Returns SendResult JSON with "recipients" [{dest,
     * amount_sats}]. The pending record carries every recipient so a fee bump rebuilds them all.
     */
    send_onchain_multi(req: string): Promise<any>;
    /**
     * v282 (S50, coin control cut 3 — chosen coins): a send from EXACTLY the coins the user
     * chose. `req` is JSON {"dest", "fee_rate_sat_per_kw", "inputs": [{"txid","vout"}, …],
     * and either "amount_sats" (change to m/84) or "all": true (everything in those coins,
     * one output)}. A frozen or unknown coin, or coins that do not cover amount + fee, is an
     * error in plain words — nothing is spent. Returns SendResult JSON like send_onchain.
     */
    send_onchain_with(req: string): Promise<any>;
    send_payment(bolt11: string): Promise<any>;
    /**
     * Phase 10b — Send via LSP-provided route (Routing as a Service).
     *
     * Today's signature takes route_endpoint and route_macaroon as parameters.
     * JS callers must look these up themselves (e.g., from a hardcoded test
     * constant or from the wallet's active LSP record).
     *
     * FUTURE — LIJOX MARKETPLACE INTEGRATION:
     * When the LIJOX marketplace UI ships and the user selects an LSP, the
     * active LSP record will carry `route_endpoint` and `route_macaroon`
     * (already added to LspInfo struct). At that point this method should be
     * changed to:
     *   pub fn send_payment_via_lsp_route(&self, bolt11: &str) -> js_sys::Promise
     * and read the credentials from `wallet.active_lsp()` internally.
     * See lsp.rs LspInfo for the field definitions.
     *
     * v8: refactored to release the wallet mutex during the HTTP fetch.
     * Pattern: lock-prepare-unlock, fetch (no lock), lock-apply-unlock. Mirrors
     * open_channel's structure. Required to prevent the mutex_no_threads panic
     * observed in session 14 when LDK background_tick tried to acquire the
     * wallet lock during a long-running Phase 10b POST.
     */
    send_payment_via_lsp_route(bolt11: string, route_endpoint: string, route_macaroon_hex: string): Promise<any>;
    /**
     * v8: Send a Lightning payment via Phase 10b LSP routing with automatic
     * retry-on-path-failure. On each attempt, the wallet asks the LSP for a
     * route, submits the HTLC with a FRESH PaymentId, then polls the per-
     * payment outcome map for the final result. If the result is PathFailed
     * (a hop bounced the HTLC with temporary_channel_failure or similar), the
     * failed (from, to) pubkey pair is appended to the excluded-pairs list,
     * the old PaymentId is abandoned in LDK's OutboundPayments, and the next
     * attempt asks the LSP to route around the failed hop with a new id.
     *
     * Up to `max_retries` attempts. Returns the final PaymentResult — either
     * success (Sent), permanent failure (Failed or PathFailed with
     * payment_failed_permanently=true), or "retries exhausted" if all
     * max_retries attempts had path failures.
     *
     * Mutex discipline: the wallet lock is acquired briefly for prepare,
     * apply, and abandon, then released for the HTTP fetch AND for the
     * outcome polling loop. Background_tick and WS handlers can run while we
     * wait, which is required for LDK to process the PaymentSent/PathFailed/
     * Failed events from the peer messages and populate the outcome map.
     */
    send_payment_with_retries(bolt11: string, route_endpoint: string, route_macaroon_hex: string, max_retries: number, progress_callback: Function, amount_sats_override?: bigint | null, amount_msat_override?: bigint | null): Promise<any>;
    /**
     * v274: the channel(s) each settled outbound payment left by (see node::sent_parts_json).
     * try_lock — the page asks again on WALLET_BUSY.
     */
    sent_parts_json(): string;
    /**
     * v210 (quorum wiring): set the independent quorum endpoint list at
     * runtime. urls_json = JSON array of https base URLs (LSP defaults ∪
     * wallet additions, page-merged, additive-only). Empty = rejected.
     */
    set_quorum_endpoints(urls_json: string): void;
    /**
     * v184: node-key message signing (LND signmessage-compatible zbase32).
     * Serves the LIJOX delegate slip/void digests. Sync, no I/O.
     */
    sign_message(msg: string): string;
    /**
     * v284 (S50, silent payments — receive, the engine groundwork): the wallet's own
     * silent-payment address (BIP-352, keys m/352'/{coin}'/0'/1'/0 scan and /0'/0 spend —
     * Cake's and Sparrow's paths, so the 12 words restore the coins anywhere). Derived on
     * the spot from the words, never stored. Answers JSON {"address","scan_pub","spend_pub"}.
     * Not surfaced on the page until the receive walk ships (DP: nothing pushed before the
     * remaining decisions are talked through).
     */
    sp_address(): string;
    /**
     * v304: make a label — the next number (never reused), a cleaned name (40 code points at most), ten at most.
     * Answers {"m","name","address"}. Saved in the marks (they ride the backup); the scan checks it from the next sync.
     */
    sp_label_create(name: string): string;
    /**
     * v304: rename and/or hide a label — `req` JSON {"m", "name"?, "hidden"?}. No delete (a label handed out can still be
     * paid; a hidden one is still checked and its payments still tagged). Answers {"m","name","hidden"}.
     */
    sp_label_update(req: string): string;
    /**
     * v304 (S54, DP 2026-10-02 13:50 "Go ahead"): the silent-payment labels — number, name, hidden, the label's own
     * sp1 address, and what it has received (coins paid to it, spent or not). JSON {"labels":[{m,name,hidden,
     * created_ms,address,payments,received_sats}],"max":10,"used":n,"unknown":bool} — `unknown` = a words-only
     * restore checking all ten; a nameless label (found after that restore) shows as "Label m".
     */
    sp_labels(): string;
    /**
     * v288 (S50, DP 21:10 "the wallet has a say"): the wallet-side silent-payment switch. Lives in
     * the marks store (its own encrypted key — a sync in flight cannot clobber it; a rescan keeps
     * it). Off = the engine runs no silent-payment scan and the page shows no sp1 address; on = the
     * scan resumes where it stopped at the next sync. Answers JSON {"enabled"}.
     */
    sp_set_enabled(enabled: boolean): string;
    /**
     * TEMP diagnostic: dump the SpendableOutputs event log — every descriptor
     * (incl. v128-excluded StaticOutputs) seen at the event handler, with
     * variant + value + destination script. Confirms what an anchors coop
     * close emits. Returns a JSON array of objects. No wallet lock needed
     * (thread_local). Remove with the rest of the temp diagnostics.
     */
    spendable_outputs_log(): string;
    /**
     * TEMP diagnostic: why matured sweeps aren't broadcasting — broadcaster queue
     * depth + failures, and the sweeper's internal height vs the real tip.
     */
    sweeper_broadcast_diag(real_tip: number): string;
    /**
     * TEMP diagnostic: replicate the sweeper's spend_outputs to find which step
     * fails (fee / change-script / signing) and the fee-vs-value numbers.
     */
    sweeper_spend_attempt_diag(real_tip: number): string;
    switch_lsp(lsp_pubkey: string): Promise<any>;
    /**
     * Tier 2 (privacy-default) on-chain sync: pull compact block filters from
     * the node, match them LOCALLY against our scripts, fetch and verify only
     * the blocks that hit, and assemble the UTXO set + history + balances
     * entirely client-side — the node never learns which scripts are ours.
     * Persists across sessions and resumes from the saved cursor. `birthday`
     * is the wallet's creation height, used only when no cursor exists yet.
     * Returns Tier2Summary JSON.
     * v296 (S52, DP 23:09 "#1: Go"): `filter_base` = the block-filter server the walk reads (the page passes its
     * own provider's when the LIJOX directory lists one); `sp_base` = the server whose silent-payment index the
     * scan reads (none = the walk's server). Either missing or not a plain https address = the project's server
     * (tier2_sync::DEFAULT_FILTER_BASE). Servers are interchangeable: filters and headers are the chain's own
     * (PoW-checked, linked to the walk's record), blocks are hash-bound — a change of server mid-walk is safe.
     * The summary names the two servers used (`filter_server`, `sp_server`).
     */
    tier2_onchain_sync(birthday: number, filter_base?: string | null, sp_base?: string | null): Promise<any>;
    /**
     * v105 dev/recovery tool: roll the Tier-2 scan cursor back so the next
     * background sync re-walks blocks from `from_height` (inclusive) to tip.
     * Use when a block was scanned before its matching script entered the
     * watch window (e.g. a sweep paid an address past the old gap) — the
     * counter-aware window above makes the re-walk actually match this time.
     * Pure storage operation (no wallet lock). Floors at the birthday; no-op
     * if the cursor is already at or below the target. Returns the persisted
     * cursor as JSON. Balances/history may look odd for the few seconds the
     * re-walk takes; the next completed sync restores full truth.
     */
    tier2_rescan_from(from_height: number): string;
    /**
     * v261 (DP: the on-chain drill-down): everything the panel shows for one transaction — fee (sats,
     * sat/vB), the inputs and outputs with which are ours, the counterparty address, the output type, mempool
     * or block (with the header time). Answers JSON:
     * {"txid","fee_sats","vsize","sat_vb","confirmed","height","time","our_in","our_out",
     *  "address","address_type","outputs":[{"address","value","ours","type"}],"source","sp_address"}
     * v298 (S52, DP 22:48 "build the drill-down from the block the wallet already downloaded" + 23:43 "Go on #2 and
     * #3"): the details come from the wallet's own data — NO explorer is asked (until v298 every tap sent the txid
     * to four public explorers). In order: the transaction kept whole (the walk and the scan keep every own
     * transaction from its block; a send is kept at broadcast); else, for a ledger row from before v298, its block
     * read once more from the wallet's block-filter server (`filter_base`: the page's lijFilterBases().walk; the
     * header's work checked, the block bound to it, the transaction authentic by its txid; every own transaction in
     * that block kept); else a pending transaction's own bytes, or a pending send's record (destination, fee). A
     * transaction the ledger does not hold is looked up nowhere. `source` says which; `fee_sats` is 0 when an input
     * is someone else's (its value is not the wallet's to know). `sp_address` (#3): the sp1 address a send from
     * this phone was typed to — the chain shows only the taproot output it made.
     */
    tx_details(txid: string, filter_base?: string | null): Promise<any>;
    /**
     * v300: "delete old data" — the kept transactions from blocks below `height` go (their rows read their block again
     * when tapped); coins, balance and history are not touched. Answers how many went.
     */
    tx_keep_drop_before(height: number): number;
    /**
     * v300: "expand the size" — the ceiling, one of the offered steps (1,000 / 2,000 / 4,000); a lower one trims the
     * oldest at once. Answers the new status.
     */
    tx_keep_set_cap(cap: number): string;
    /**
     * v300 (S52, DP 00:25 "if a wallet approaches 1000 transactions, some notification to the user should happen that
     * lets them either delete old data or expand the size"): the kept transactions' state for the page —
     * {"count","cap","near","bytes","oldest_height","steps"}; `near` = 90 % of the ceiling.
     */
    tx_keep_status(): string;
    /**
     * Chunk 1 (receive watcher): query a single watched address for incoming
     * outputs — INCLUDING 0-conf mempool ones — via the independent Esplora
     * quorum. The confirmed-block BIP158 scanner is mempool-blind by design, so
     * this is the ONLY mempool-aware path, deliberately narrow: it is called
     * only for an address the user is actively awaiting payment on (an open
     * expectation row), never across the whole wallet. Returns a JSON array of
     * { txid, vout, value_sats, confirmed } — the frontend turns unconfirmed
     * entries into a pending-inbound alert-bar amount and flips the awaiting
     * row; confirmed entries are left for the scanner to fold in normally.
     *
     * Privacy note: this reveals the queried address to the quorum endpoints.
     * That address was just shown to a payer, the query only fires for actively
     * awaited addresses, and the endpoint is user-configurable (own node →
     * zero leak). The wallet-wide BIP158 model is untouched.
     *
     * v302 (S54): `own_base` = the Address watcher row's own Esplora server (None = the public explorers in
     * turn, as v301); `own_only` = the row's "Only my server" switch (no fallback). The report of each check is
     * kept for watch_report(). A page from before v302 passes the address alone — no own server, as before.
     */
    watch_address_inbound(address: string, own_base?: string | null, own_only?: boolean | null): Promise<any>;
    /**
     * v302 (S54): how the last receive-watch check went — {"answered_by":"own"|"public"|"","own_set",
     * "own_error"|null,"own_resting","at_ms"}; "{}" before the first check. Read without the wallet lock.
     */
    watch_report(): string;
}

/**
 * v312 (S57, DP ruling (a)): the last inbound open refused because its channel type was anchors —
 * {"at_ms": n, "funding_sats": n}; at_ms 0 = none since this page loaded.
 */
export function anchors_refused_json(): string;

/**
 * Suggest BIP39 English words matching a prefix. Returns up to `max` matches,
 * lexicographically sorted (the wordlist is pre-sorted). Case-insensitive.
 * Returns empty vec for empty prefix or no matches.
 */
export function bip39_suggest(prefix: string, max: number): any[];

/**
 * v303 (S54, DP): what a BOLT11 invoice says, read and signature-checked — {"payee","amount_msat"|null,"payment_hash",
 * "network","expires_at"}; an error names why it does not decode. The page checks an invoice with it before paying.
 */
export function bolt11_facts(bolt11: string): string;

/**
 * Given 11 valid BIP39 words and 7 binary bits ("0"s and "1"s), compute the
 * 12th (checksum) word that completes a valid mnemonic.
 *
 * BIP39 encodes a 12-word mnemonic as 128 bits entropy + 4-bit checksum,
 * packed as 12 × 11-bit word indices. The 12th word's 11 bits are
 * [7 user bits] || [4 checksum bits], where the checksum is the first 4
 * bits of SHA256(entropy).
 *
 * This exposes the "secret binary path" for seed reset: a user who types
 * 7 bits into the 12th field gets the deterministic checksum word back.
 */
export function checksum_word_for_bits(first_eleven: any[], seven_bits: string): string;

export function derive_account_zpub(mnemonic: string): string;

export function derive_receive_address(mnemonic: string, index: number): string;

export function fetch_lsp_registry(worker_url: string): Promise<string>;

export function health_check_lsp(endpoint: string): Promise<boolean>;

export function lij_init(): void;

/**
 * Buy an LSPS2 JIT channel promise for inbound `payment_size_msat`.
 *
 * JS receives the parsed [Lsps2BuyResponse] as a JSON string. The
 * returned `jit_channel_scid` must be embedded as a route_hint in the
 * BOLT11 invoice the wallet generates for the upcoming receive (Phase C).
 * Promise expires after `promise_expires_at` ms — wallet must call again
 * if expired.
 *
 * # Example (JS)
 * ```javascript
 * const json = await window.lij_wasm.lsps2_buy_promise(
 *   endpoint, route_macaroon, BigInt(50_000_000)
 * );
 * const promise = JSON.parse(json);
 * embedRouteHint(promise.jit_channel_scid, promise.lsp_pubkey);
 * ```
 * v0.16 Phase B + Phase A.1: free-function wrapper for LSPS2 /buy.
 * client_pubkey is REQUIRED — adapter v0.18+ uses it to determine where
 * to open the JIT channel when a matching HTLC arrives. Must be the
 * wallet's 66-hex-char node pubkey.
 */
export function lsps2_buy_promise(endpoint: string, route_macaroon: string, payment_size_msat: bigint, client_pubkey: string): Promise<any>;

/**
 * Fetch LSPS2 service terms from an LSP endpoint.
 *
 * JS receives the parsed [Lsps2GetInfoResponse] as a JSON string.
 * Errors (HTTP failure, parse failure) are thrown as JS exceptions.
 *
 * # Example (JS)
 * ```javascript
 * const json = await window.lij_wasm.lsps2_get_info(
 *   "https://lijox-lsp.lightning-mod.com",
 *   route_macaroon_from_registry,
 * );
 * const info = JSON.parse(json);
 * console.log(info.human_summary);
 * ```
 */
export function lsps2_get_info(endpoint: string, route_macaroon: string): Promise<any>;

export function psbt_probe(mnemonic: string, psbt_hex: string): string;

/**
 * Derive the authoritative Lightning node pubkey from a BIP39 mnemonic.
 * Mirrors what LijNode does in ~3ms instead of ~3s — skips LDK setup,
 * LSP registry fetch, chain monitor init. Used for seed-verification in
 * the forgot-passphrase reset flow.
 */
export function pubkey_from_mnemonic(mnemonic: string, network: string): string;

export function pull_backup(worker_url: string, auth_token: string, pubkey_hex: string): Promise<string>;

export function push_backup(worker_url: string, auth_token: string, blob_json: string): Promise<void>;

export function register_lsp(worker_url: string, registration_json: string): Promise<void>;

export function set_backup_off(v: boolean): void;

/**
 * v208: broadcast routing — true routes each tx to one endpoint at a time
 * (rotating, stop at first acceptance); false fans to all healthy endpoints.
 */
export function set_broadcast_one(v: boolean): void;

/**
 * v216 (S36, O6 fee headroom → exact-fee): the user's fee-race margin in
 * sats — subtracted once at the aggregate inside max_sendable_sats. Page
 * persists (WALLET → Controls dial) and boot-applies before any wallet
 * exists (free fn, LSP-reserve pattern). Clamped 0..=5,000. Returns applied.
 * S45 (DP): Dials → Speed up slow closes — Off / Automatic (default Off).
 */
export function set_coop_cpfp_auto(on: boolean): boolean;

export function set_fee_margin_sats(sats: number): number;

/**
 * v213 (evil-LSP reserve dial): the reserve the user demands the LSP keep
 * on its side, ppm, NEW channels only. Clamped 0..=50_000 (5% cap); 0 =
 * LDK's 1,000-sat floor. Free fn — callable before any wallet exists so
 * the boot re-apply lands ahead of create/restore (JIT accepts read the
 * ChannelManager config captured at construction). Returns the APPLIED
 * (clamped) value.
 */
export function set_lsp_reserve_ppm(ppm: number): number;

export function set_offline_start(v: boolean): void;

export function sign_psbt_hex(mnemonic: string, psbt_hex: string): string;

/**
 * Unwrap a hex-encoded blob produced by [`wrap_mnemonic`]. Returns the
 * mnemonic string. Throws on bad hex, short blob, wrong passphrase,
 * tampered data, or version mismatch — error messages disambiguate.
 */
export function unwrap_mnemonic(blob_hex: string, passphrase: string): string;

/**
 * Validate a full BIP39 mnemonic string (word validity + checksum).
 * Accepts 12, 15, 18, 21, or 24-word phrases. Returns Ok on valid, Err with
 * descriptive message on invalid word, wrong count, or checksum mismatch.
 */
export function validate_mnemonic(phrase: string): void;

/**
 * Build version of THIS compiled WASM binary. The frontend compares it to its
 * own LIJ_FRONTEND_VERSION; a mismatch means the deployed binary is stale
 * (an incremental build that skipped WASM regen). Bump on every WASM rebuild.
 */
export function wasm_build_version(): string;

/**
 * localStorage. Throws on empty mnemonic or Argon2 failure.
 */
export function wrap_mnemonic(mnemonic: string, passphrase: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_lijwallethandle_free: (a: number, b: number) => void;
    readonly anchors_refused_json: () => [number, number];
    readonly bip39_suggest: (a: number, b: number, c: number) => [number, number];
    readonly bolt11_facts: (a: number, b: number) => [number, number, number, number];
    readonly checksum_word_for_bits: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derive_account_zpub: (a: number, b: number) => [number, number, number, number];
    readonly derive_receive_address: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fetch_lsp_registry: (a: number, b: number) => any;
    readonly health_check_lsp: (a: number, b: number) => any;
    readonly lij_init: () => void;
    readonly lijwallethandle_abandon_payment_by_id: (a: number, b: number, c: number) => [number, number];
    readonly lijwallethandle_active_lsp_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_adopt_cloud_backup: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_background_tick: (a: number, b: bigint) => [number, number];
    readonly lijwallethandle_backup: (a: number) => any;
    readonly lijwallethandle_backup_adopt_own: (a: number) => bigint;
    readonly lijwallethandle_backup_conflict: (a: number) => bigint;
    readonly lijwallethandle_backup_now: (a: number) => any;
    readonly lijwallethandle_backup_probe: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_backup_replace_cloud: (a: number) => any;
    readonly lijwallethandle_black_start_bundle_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_black_start_bundle_merged_json: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly lijwallethandle_black_start_fingerprint_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_black_start_identity_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_black_start_merge_plan_json: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_bump_onchain_send: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_chain_events_json: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_check_watch_server: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_claimed_payments_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_close_channel: (a: number, b: number, c: number) => [number, number];
    readonly lijwallethandle_close_event_log: (a: number) => [number, number];
    readonly lijwallethandle_close_values_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_cloud_backup_info: (a: number) => any;
    readonly lijwallethandle_cloud_backup_meta: (a: number) => any;
    readonly lijwallethandle_coin_mark: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_connect_to_peer: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly lijwallethandle_coop_cpfp: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_create: (a: number, b: number) => any;
    readonly lijwallethandle_create_invoice: (a: number, b: number, c: bigint, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly lijwallethandle_create_invoice_with_jit: (a: number, b: bigint, c: number, d: number, e: bigint, f: number, g: number, h: number, i: number) => any;
    readonly lijwallethandle_create_open_invoice_with_jit: (a: number, b: number, c: number, d: bigint, e: number, f: number, g: number, h: number) => any;
    readonly lijwallethandle_diagnostics_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_drop_pending_tx: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_dump_channel_details_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_end_lsp_relationship: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_escape_export: (a: number) => [number, number, number, number];
    readonly lijwallethandle_export_backup_blob: (a: number) => [number, number, number, number];
    readonly lijwallethandle_force_close: (a: number, b: number, c: number) => [number, number];
    readonly lijwallethandle_force_close_all_without_broadcasting: (a: number) => [number, number, number];
    readonly lijwallethandle_force_close_without_broadcasting: (a: number, b: number, c: number) => [number, number];
    readonly lijwallethandle_forget_cloud_backup: (a: number) => any;
    readonly lijwallethandle_get_balance: (a: number) => any;
    readonly lijwallethandle_get_chain_status: (a: number) => [number, number, number, number];
    readonly lijwallethandle_get_channels: (a: number) => [number, number, number, number];
    readonly lijwallethandle_get_fee_rates: (a: number) => [number, number, number, number];
    readonly lijwallethandle_identify_own_output: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_import_backup_blob: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_import_backup_file: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly lijwallethandle_last_backup_version: (a: number) => [number, number, number];
    readonly lijwallethandle_list_closed_channels: (a: number) => [number, number, number, number];
    readonly lijwallethandle_list_lsps: (a: number) => any;
    readonly lijwallethandle_list_peers: (a: number) => any;
    readonly lijwallethandle_list_pending_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_list_recent_payments_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_lnurlp_prepare_hashes: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_lsp_channel_open_estimate: (a: number, b: number) => any;
    readonly lijwallethandle_lsp_channel_open_estimate_with: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_mark_funding_confirmed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly lijwallethandle_maturing_balances_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_maturing_outputs: (a: number) => [number, number, number, number];
    readonly lijwallethandle_max_sendable_sats: (a: number) => bigint;
    readonly lijwallethandle_maybe_backup: (a: number) => any;
    readonly lijwallethandle_next_receive_address: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_node_pubkey: (a: number) => [number, number, number, number];
    readonly lijwallethandle_note_background: (a: number) => void;
    readonly lijwallethandle_note_foreground: (a: number) => void;
    readonly lijwallethandle_nwc_add: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_auth_event: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_end: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_forget: (a: number, b: number) => [number, number];
    readonly lijwallethandle_nwc_info_event: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_list: (a: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_open: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_record_paid: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_reply: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_nwc_set_limits: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_onchain_history: (a: number) => any;
    readonly lijwallethandle_onchain_max: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly lijwallethandle_onchain_multi_quote: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_onchain_quote: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_onchain_summary: (a: number) => any;
    readonly lijwallethandle_open_channel: (a: number, b: bigint) => any;
    readonly lijwallethandle_open_failures_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_open_lsp_channel: (a: number, b: bigint, c: number) => any;
    readonly lijwallethandle_open_lsp_channel_with: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_outstanding_close_attempts: (a: number) => [number, number, number, number];
    readonly lijwallethandle_peek_channel_index: (a: number) => [number, number, number];
    readonly lijwallethandle_pending_onchain_audit_json: (a: number) => any;
    readonly lijwallethandle_persist_skew_at_load: (a: number) => number;
    readonly lijwallethandle_pump_peer: (a: number, b: number) => [number, number];
    readonly lijwallethandle_purge_force_closed_monitor: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly lijwallethandle_push_accept: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_push_in_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_push_link_parse: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_push_lock: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly lijwallethandle_push_mark: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly lijwallethandle_push_out_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_push_out_preimage: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_push_prepare: (a: number, b: bigint, c: bigint, d: number, e: number) => [number, number, number, number];
    readonly lijwallethandle_quote_route_fee: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => any;
    readonly lijwallethandle_quote_route_fee_to_pubkey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint) => any;
    readonly lijwallethandle_register_push_subscription: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_reserve_onchain_index: (a: number, b: number) => [number, number];
    readonly lijwallethandle_restore: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_send_onchain: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly lijwallethandle_send_onchain_all: (a: number, b: number, c: number, d: number) => any;
    readonly lijwallethandle_send_onchain_multi: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_send_onchain_with: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_send_payment: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_send_payment_via_lsp_route: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly lijwallethandle_send_payment_with_retries: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: any, j: number, k: bigint, l: number, m: bigint) => any;
    readonly lijwallethandle_sent_parts_json: (a: number) => [number, number, number, number];
    readonly lijwallethandle_set_quorum_endpoints: (a: number, b: number, c: number) => [number, number];
    readonly lijwallethandle_sign_message: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_sp_address: (a: number) => [number, number, number, number];
    readonly lijwallethandle_sp_label_create: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_sp_label_update: (a: number, b: number, c: number) => [number, number, number, number];
    readonly lijwallethandle_sp_labels: (a: number) => [number, number, number, number];
    readonly lijwallethandle_sp_set_enabled: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_spendable_outputs_log: (a: number) => [number, number];
    readonly lijwallethandle_sweeper_broadcast_diag: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_sweeper_spend_attempt_diag: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_switch_lsp: (a: number, b: number, c: number) => any;
    readonly lijwallethandle_tier2_onchain_sync: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly lijwallethandle_tier2_rescan_from: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_tx_details: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly lijwallethandle_tx_keep_drop_before: (a: number, b: number) => [number, number, number];
    readonly lijwallethandle_tx_keep_set_cap: (a: number, b: number) => [number, number, number, number];
    readonly lijwallethandle_tx_keep_status: (a: number) => [number, number, number, number];
    readonly lijwallethandle_watch_address_inbound: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly lijwallethandle_watch_report: (a: number) => [number, number];
    readonly lsps2_buy_promise: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => any;
    readonly lsps2_get_info: (a: number, b: number, c: number, d: number) => any;
    readonly psbt_probe: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pubkey_from_mnemonic: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pull_backup: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly push_backup: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly register_lsp: (a: number, b: number, c: number, d: number) => any;
    readonly set_backup_off: (a: number) => void;
    readonly set_broadcast_one: (a: number) => void;
    readonly set_coop_cpfp_auto: (a: number) => number;
    readonly set_fee_margin_sats: (a: number) => number;
    readonly set_lsp_reserve_ppm: (a: number) => number;
    readonly set_offline_start: (a: number) => void;
    readonly sign_psbt_hex: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly unwrap_mnemonic: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly validate_mnemonic: (a: number, b: number) => [number, number];
    readonly wasm_build_version: () => [number, number];
    readonly wrap_mnemonic: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly rustsecp256k1_v0_11_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_11_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_11_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_11_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h4e6bce1ec0492195: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__hd7c589fa23e48fed: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h4e5bbd474c38391c: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h4e5bbd474c38391c_161: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h4e5bbd474c38391c_162: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h3ad6878d23cf0c0f: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
