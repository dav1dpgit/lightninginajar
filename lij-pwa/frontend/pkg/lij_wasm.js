/* @ts-self-types="./lij_wasm.d.ts" */

export class LijWalletHandle {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(LijWalletHandle.prototype);
        obj.__wbg_ptr = ptr;
        LijWalletHandleFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        LijWalletHandleFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_lijwallethandle_free(ptr, 0);
    }
    /**
     * S21 build #1 (ledger reconciler): expose LDK's recent outbound
     * payments for the startup RECENT backfill. JSON array of
     * {state, payment_id, payment_hash?, total_msat?}. try_lock — the
     * frontend retries on a stagger, never blocks the UI thread.
     * v189 (S29): abandon a stuck outbound payment by PaymentId hex, as
     * reported by list_recent_payments_json. Makes ledger retirement
     * terminal in LDK, so Pass-2 backfill can never resurrect a ghost
     * after a history clear.
     * @param {string} payment_id_hex
     */
    abandon_payment_by_id(payment_id_hex) {
        const ptr0 = passStringToWasm0(payment_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_abandon_payment_by_id(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
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
     * @returns {string | undefined}
     */
    active_lsp_json() {
        const ret = wasm.lijwallethandle_active_lsp_json(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {bigint} tick_count
     */
    background_tick(tick_count) {
        const ret = wasm.lijwallethandle_background_tick(this.__wbg_ptr, tick_count);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {Promise<any>}
     */
    backup() {
        const ret = wasm.lijwallethandle_backup(this.__wbg_ptr);
        return ret;
    }
    /**
     * Manually push the current encrypted wallet state to all enabled backup
     * sinks (scenario-A backup). Returns `{"ok":true}`. This is the "Back up
     * now" action and our round-trip test entrypoint; automatic triggers will
     * reuse the same `LijWallet::backup()` path.
     * @returns {Promise<any>}
     */
    backup_now() {
        const ret = wasm.lijwallethandle_backup_now(this.__wbg_ptr);
        return ret;
    }
    /**
     * v166 (#29-4b): RBF-replace one of OUR pending on-chain sends at a
     * higher fee. Same inputs, same destination; the delta comes out of the
     * change. The engine enforces BIP-125 economics and answers with
     * actionable minimum/maximum sat/vB messages on violation.
     * @param {string} old_txid
     * @param {number} new_fee_rate_sat_per_kw
     * @returns {Promise<any>}
     */
    bump_onchain_send(old_txid, new_fee_rate_sat_per_kw) {
        const ptr0 = passStringToWasm0(old_txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_bump_onchain_send(this.__wbg_ptr, ptr0, len0, new_fee_rate_sat_per_kw);
        return ret;
    }
    /**
     * Background tick — JS calls every second to keep LDK alive.
     * Handles peer keepalives, channel maintenance, and event processing.
     * S30 (v199): read the chain flight recorder — the ChainCoordinator's
     * event ledger (tip advances, stale drops, confirmations, independent
     * observations, with heights). Read-only diagnosis surface.
     * @param {number} limit
     * @returns {string}
     */
    chain_events_json(limit) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_chain_events_json(this.__wbg_ptr, limit);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * v206: payments CLAIMED this session, as `[{"hash":"<hex>","sats":N}]`.
     * The frontend ledger completes a pending receive only when its
     * payment_hash appears here — an authoritative claim signal that replaces
     * the balance-delta heuristic. See node::claimed_payments_json.
     * @returns {string}
     */
    claimed_payments_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_claimed_payments_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Initiate a cooperative close. Synchronous from JS perspective —
     * returns once shutdown is sent. Actual close confirmation arrives
     * later via the closed-channels list.
     * @param {string} channel_id_hex
     */
    close_channel(channel_id_hex) {
        const ptr0 = passStringToWasm0(channel_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_close_channel(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * TEMP diagnostic: dump the close-event log — every ChannelClosed reason and
     * every coop/force close invocation, with timestamps, so the close SEQUENCE
     * for a channel is visible. Remove with the rest of the temp diagnostics.
     * @returns {string}
     */
    close_event_log() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.lijwallethandle_close_event_log(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * S24 Build 13: per-channel close values (see lij-core close_values_json).
     * @returns {string}
     */
    close_values_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_close_values_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Connect to a Lightning peer over WebSocket.
     * @param {string} pubkey_hex
     * @param {string} wss_url
     * @returns {Promise<any>}
     */
    connect_to_peer(pubkey_hex, wss_url) {
        const ptr0 = passStringToWasm0(pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wss_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_connect_to_peer(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * On-chain send (option D, increment 2): P2WPKH spend from the m/84
     * spendable chain, change to m/84'/{coin}'/0'/1/0. `amount_sats` is a JS
     * number (f64 is exact up to 2^53, far above the 2.1e15-sat supply cap);
     * `fee_rate_sat_per_kw` is LDK sat/kilo-weight (use FeeQuote::on_chain_sweep).
     * S45 (DP): plan (send=false) or send (send=true) a CPFP child for a
     * pending cooperative close — the user's Speed up on the on-chain face.
     * Always forced (the user's tap skips the automatic mode's gates).
     * Returns JSON {ok, can, reason, child_fee_sats, parent_rate_vb, target_vb, txid}.
     * @param {string} channel_id_hex
     * @param {boolean} send
     * @returns {Promise<any>}
     */
    coop_cpfp(channel_id_hex, send) {
        const ptr0 = passStringToWasm0(channel_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_coop_cpfp(this.__wbg_ptr, ptr0, len0, send);
        return ret;
    }
    /**
     * @param {string} config_json
     * @returns {Promise<any>}
     */
    static create(config_json) {
        const ptr0 = passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_create(ptr0, len0);
        return ret;
    }
    /**
     * @param {bigint | null | undefined} amount_sats
     * @param {string} memo
     * @param {bigint} expiry_seconds
     * @param {string | null} [lsp_endpoint]
     * @param {string | null} [lsp_route_macaroon]
     * @returns {Promise<any>}
     */
    create_invoice(amount_sats, memo, expiry_seconds, lsp_endpoint, lsp_route_macaroon) {
        const ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(lsp_endpoint) ? 0 : passStringToWasm0(lsp_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(lsp_route_macaroon) ? 0 : passStringToWasm0(lsp_route_macaroon, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_create_invoice(this.__wbg_ptr, !isLikeNone(amount_sats), isLikeNone(amount_sats) ? BigInt(0) : amount_sats, ptr0, len0, expiry_seconds, ptr1, len1, ptr2, len2);
        return ret;
    }
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
     * @param {bigint} amount_sats
     * @param {string} memo
     * @param {bigint} expiry_seconds
     * @param {string} lsp_endpoint
     * @param {string} lsp_route_macaroon
     * @returns {Promise<any>}
     */
    create_invoice_with_jit(amount_sats, memo, expiry_seconds, lsp_endpoint, lsp_route_macaroon) {
        const ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(lsp_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(lsp_route_macaroon, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_create_invoice_with_jit(this.__wbg_ptr, amount_sats, ptr0, len0, expiry_seconds, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} memo
     * @param {bigint} expiry_seconds
     * @param {string} lsp_endpoint
     * @param {string} lsp_route_macaroon
     * @returns {Promise<any>}
     */
    create_open_invoice_with_jit(memo, expiry_seconds, lsp_endpoint, lsp_route_macaroon) {
        const ptr0 = passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(lsp_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(lsp_route_macaroon, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_create_open_invoice_with_jit(this.__wbg_ptr, ptr0, len0, expiry_seconds, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * DIAGNOSTICS: monitor census + spend-walker liveness for the on-device
     * status pane (iOS has no console). See node::diagnostics_json.
     * @returns {string}
     */
    diagnostics_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_diagnostics_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Step 3 (S30): drop a tier-2 pending tx by txid — the dead-funding
     * janitor's executioner. The UI judges (Esplora outspend verdicts on the
     * record's spent_outpoints); this removes the record so
     * rebroadcast-until-seen stops and its input reservation releases.
     * Returns {"removed":bool}.
     * @param {string} txid_hex
     * @returns {string}
     */
    drop_pending_tx(txid_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.lijwallethandle_drop_pending_tx(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Step 3.6 diagnostic: returns full LDK ChannelDetails as a JSON
     * string. Use from F12 console for inspection when the slim
     * get_channels() output isn't enough.
     * @returns {string}
     */
    dump_channel_details_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_dump_channel_details_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * End relationship with an LSP. Returns JSON array of per-channel
     * outcomes: [{ "channel_id_hex": "...", "ok": true/false, "error": "..." }, ...]
     * @param {string} lsp_pubkey_hex
     * @returns {string}
     */
    end_lsp_relationship(lsp_pubkey_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(lsp_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.lijwallethandle_end_lsp_relationship(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * v211 (ESCAPE KIT): per-channel signed latest holder commitment
     * ("THE CLOSE") + pre-signed to_local sweep ("THE COLLECT",
     * nSequence = to_self_delay, two feerates — no RBF after the fact),
     * destination = PEEKED m/84 allocator index. Read-only by
     * constitution: nothing broadcast, nothing queued, counter not
     * advanced, state unchanged. Runs on the offline read-only instance.
     * Returns the kit as a JSON string.
     * @returns {string}
     */
    escape_export() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_escape_export(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * v209: the SAME ciphertext the cloud sink receives, returned to the page
     * for a manual device download. Forces a fresh snapshot via the dirty
     * handle; state is unchanged, so the next auto-backup is a cheap no-op.
     * @returns {string}
     */
    export_backup_blob() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_export_backup_blob(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Force close a channel. Destructive — UI must confirm first.
     * @param {string} channel_id_hex
     */
    force_close(channel_id_hex) {
        const ptr0 = passStringToWasm0(channel_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_force_close(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Abandon all channels WITHOUT broadcasting (safe recovery from a stale
     * restore). Call this BEFORE reconnecting to peers to avoid the
     * data-loss-protect panic on channel_reestablish. Returns channels closed.
     * @returns {number}
     */
    force_close_all_without_broadcasting() {
        const ret = wasm.lijwallethandle_force_close_all_without_broadcasting(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * Force-close ONE channel without broadcasting any tx. For a stranded
     * open whose funding never confirmed (LDK's no-progress watchdog keeps
     * dropping the peer over it). Broadcasts nothing — safe for an
     * unconfirmed funding. Destructive — UI must confirm first.
     * @param {string} channel_id_hex
     */
    force_close_without_broadcasting(channel_id_hex) {
        const ptr0 = passStringToWasm0(channel_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_force_close_without_broadcasting(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {Promise<any>}
     */
    get_balance() {
        const ret = wasm.lijwallethandle_get_balance(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string}
     */
    get_chain_status() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_get_chain_status(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get_channels() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_get_channels(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * v165 (#29-4a): current fee-rate tiers for the speed picker (JSON).
     * @returns {string}
     */
    get_fee_rates() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_get_fee_rates(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * v221 (DP fire-and-forget): device-file backup import — parses the v209
     * export's StateBlob JSON and injects through the same generic path the
     * cloud restore uses (wrong-seed files fail decryption). Returns
     * {"keys":N}; the page gates live channels and reloads — state applies
     * on the reboot.
     * @param {string} blob_json
     * @returns {string}
     */
    import_backup_blob(blob_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(blob_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.lijwallethandle_import_backup_blob(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Session 23 (1b engine half): version of the last vault push, read
     * from KEY_BACKUP_VERSION (u64 BE). Returns 0 when no push has ever
     * happened. Feeds the standing Backup drilldown row
     * ("vault · vNNN · synced").
     * @returns {number}
     */
    last_backup_version() {
        const ret = wasm.lijwallethandle_last_backup_version(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0];
    }
    /**
     * Return the closed-channel log as JSON.
     * @returns {string}
     */
    list_closed_channels() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_list_closed_channels(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {Promise<any>}
     */
    list_lsps() {
        const ret = wasm.lijwallethandle_list_lsps(this.__wbg_ptr);
        return ret;
    }
    /**
     * List currently connected Lightning peers.
     * @returns {Promise<any>}
     */
    list_peers() {
        const ret = wasm.lijwallethandle_list_peers(this.__wbg_ptr);
        return ret;
    }
    /**
     * v166 (#29-4b): raw pending list for the bump UI (storage-only).
     * @returns {string}
     */
    list_pending_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_list_pending_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    list_recent_payments_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_list_recent_payments_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
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
     * @param {number} count
     * @param {number | null} [start_hint]
     * @returns {Promise<any>}
     */
    lnurlp_prepare_hashes(count, start_hint) {
        const ret = wasm.lijwallethandle_lnurlp_prepare_hashes(this.__wbg_ptr, count, isLikeNone(start_hint) ? 0x100000001 : (start_hint) >>> 0);
        return ret;
    }
    /**
     * Estimate for the + Add channel UI: spendable on-chain, the MAX channel
     * value openable at this fee rate (spendable − funding fee − anchor
     * reserve), and the floor/reserve constants. Reads the Tier-2 view from
     * local storage; needs no wallet lock.
     * @param {number} fee_rate_sat_per_vb
     * @returns {Promise<any>}
     */
    lsp_channel_open_estimate(fee_rate_sat_per_vb) {
        const ret = wasm.lijwallethandle_lsp_channel_open_estimate(this.__wbg_ptr, fee_rate_sat_per_vb);
        return ret;
    }
    /**
     * Dev tool: manually mark a funding transaction as confirmed at a
     * given height. Synthesizes block headers and notifies LDK's chain
     * listeners — pre-Neutrino workaround for the stuck-channel case.
     * Returns the channels list as JSON after the confirmation is processed.
     * @param {string} funding_tx_hex
     * @param {number} confirmed_at_height
     * @returns {string}
     */
    mark_funding_confirmed(funding_tx_hex, confirmed_at_height) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(funding_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.lijwallethandle_mark_funding_confirmed(this.__wbg_ptr, ptr0, len0, confirmed_at_height);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Pre-maturity closing funds (ChannelMonitor claimable, CSV-locked).
     * See node::maturing_balances_json.
     * @returns {string}
     */
    maturing_balances_json() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_maturing_balances_json(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
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
     * @returns {string}
     */
    maturing_outputs() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_maturing_outputs(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * v173: the planner's own sendable ceiling — the ONE number every send
     * surface quotes (identical math to mpp_plan's total_usable_sats).
     * @returns {bigint}
     */
    max_sendable_sats() {
        const ret = wasm.lijwallethandle_max_sendable_sats(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Auto-backup tick: if channel state changed since the last push, snapshot
     * it under the lock, release, then push to enabled sinks UNLOCKED. Cheap
     * no-op when nothing changed; the frontend calls this on a slow debounce
     * interval. Never holds the wallet mutex across the push's `.await`.
     * @returns {Promise<any>}
     */
    maybe_backup() {
        const ret = wasm.lijwallethandle_maybe_backup(this.__wbg_ptr);
        return ret;
    }
    /**
     * Network-free receive address at `index` (BIP84 m/84'/{coin}'/0'/0/index).
     * Synchronous + offline: derives from the seed only, so receiving never
     * depends on a chain scan. The frontend persists the index and reconciles
     * it upward whenever a scan succeeds, advancing per receive to avoid reuse.
     * @param {number} index
     * @returns {string}
     */
    next_receive_address(index) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_next_receive_address(this.__wbg_ptr, index);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    node_pubkey() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_node_pubkey(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * BACKGROUND HINT (D-1 JIT safety): clears the channel-acceptance gate so a
     * backgrounded/offline wallet refuses inbound JIT opens it couldn't claim
     * into. The wallet lock is never held across an await, so try_lock is free
     * at the visibilitychange callback boundary; the event also fires before any
     * grace-period background tick can process an OpenChannelRequest.
     */
    note_background() {
        wasm.lijwallethandle_note_background(this.__wbg_ptr);
    }
    /**
     * FOREGROUND HINT: force the next background tick to re-scan for closes,
     * regardless of cadence phase. Best-effort — silently skips if the wallet
     * is busy (a walk is likely already in flight). See node::note_foreground.
     */
    note_foreground() {
        wasm.lijwallethandle_note_foreground(this.__wbg_ptr);
    }
    /**
     * On-chain transaction history for the RECENT list. The trusted-node source
     * was removed with the shim; this returns an empty list until Tier 2
     * (client-side BIP158 filter matching) reconstructs history locally. Kept so
     * the frontend RECENT wiring stays stable across the transition.
     * @returns {Promise<any>}
     */
    onchain_history() {
        const ret = wasm.lijwallethandle_onchain_history(this.__wbg_ptr);
        return ret;
    }
    /**
     * Read-only on-chain wallet summary (D, increment 1): scans the BIP84
     * spendable chain + legacy m/525 residue and returns balance, UTXOs, and a
     * fresh receive address as JSON. Snapshots handles under the lock, then
     * runs the scan UNLOCKED (network I/O), like the backup path.
     * @returns {Promise<any>}
     */
    onchain_summary() {
        const ret = wasm.lijwallethandle_onchain_summary(this.__wbg_ptr);
        return ret;
    }
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
     * @param {bigint} inbound_sats
     * @returns {Promise<any>}
     */
    open_channel(inbound_sats) {
        const ret = wasm.lijwallethandle_open_channel(this.__wbg_ptr, inbound_sats);
        return ret;
    }
    /**
     * Open an OUTBOUND channel to the active LSP, funded from on-chain balance.
     * `amount_sats` is the channel capacity; `fee_rate_sat_per_vb` is the
     * on-chain fee rate for the funding transaction. Returns a status JSON
     * immediately; the channel opens asynchronously (watch background_tick /
     * channel list for ChannelReady). The funding tx is built + signed by the
     * wallet from its Tier-2 UTXOs and broadcast by LDK — not the adapter.
     * @param {bigint} amount_sats
     * @param {number} fee_rate_sat_per_vb
     * @returns {Promise<any>}
     */
    open_lsp_channel(amount_sats, fee_rate_sat_per_vb) {
        const ret = wasm.lijwallethandle_open_lsp_channel(this.__wbg_ptr, amount_sats, fee_rate_sat_per_vb);
        return ret;
    }
    /**
     * @returns {string}
     */
    outstanding_close_attempts() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_outstanding_close_attempts(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Session 23 Option B (allocator unification): next-to-issue value of
     * the shared channel-index allocator, without advancing. The frontend
     * maxes this into getOnchainRecvIndex() so receive minting can never
     * collide with signer-issued indices (shutdown pins, sweep
     * destinations, and — post-terminus — pinned to_remote keys) that
     * haven't landed on-chain yet. Reads the LIVE counter instance.
     * @returns {number}
     */
    peek_channel_index() {
        const ret = wasm.lijwallethandle_peek_channel_index(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0];
    }
    /**
     * Build #4 confirmation instrument: pending-record audit vs the
     * independent quorum. Async — the wallet lock is dropped before any
     * network I/O.
     * @returns {Promise<string>}
     */
    pending_onchain_audit_json() {
        const ret = wasm.lijwallethandle_pending_onchain_audit_json(this.__wbg_ptr);
        return ret;
    }
    /**
     * S21 item 2 (persistence audit): true when load-time stamps showed the
     * manager stale vs monitors (interrupted save). Frontend surfaces honest
     * copy; LDK's protective FC is expected behavior in this state.
     * @returns {boolean}
     */
    persist_skew_at_load() {
        const ret = wasm.lijwallethandle_persist_skew_at_load(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * S30 (v197) fix-probe: explicit outbound pump. The codebase pumps
     * process_events after inbound bytes, after disconnects, and on the
     * background tick — but never immediately after locally INITIATING an
     * action. A channel open is the one purely self-initiated message in
     * the system; it must not wait for borrowed timing to reach the wire.
     * `do_timer` also fires the peer keepalive tick, extending short iOS
     * sessions through the multi-message funding handshake.
     * @param {boolean} do_timer
     */
    pump_peer(do_timer) {
        const ret = wasm.lijwallethandle_pump_peer(this.__wbg_ptr, do_timer);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Archive a force-closed ChannelMonitor by funding outpoint.
     * Returns true if a monitor was archived, false if none existed at the
     * given outpoint. Throws on invalid txid hex or storage failure.
     * @param {string} funding_txid_hex
     * @param {number} output_index
     * @returns {boolean}
     */
    purge_force_closed_monitor(funding_txid_hex, output_index) {
        const ptr0 = passStringToWasm0(funding_txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_purge_force_closed_monitor(this.__wbg_ptr, ptr0, len0, output_index);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * v216 (S36, O6 fee headroom → exact-fee): the scan-time quote. Runs the
     * SAME route-build the send path uses (pure QueryRoutes proxy — verified
     * side-effect-free in adapter code), records any lsp_first_hop_policy
     * sighting into the exact-fee cache, and returns the total sender fee
     * for this invoice/amount. The throwaway PaymentId from prepare is never
     * applied. Resolves to JSON:
     *   {"fee_msat":N,"fee_sats":N,"amount_msat":N,"policy_seen":bool,"synth":bool}
     * @param {string} bolt11
     * @param {string} route_endpoint
     * @param {string} route_macaroon_hex
     * @param {bigint | null} [amount_sats_override]
     * @returns {Promise<any>}
     */
    quote_route_fee(bolt11, route_endpoint, route_macaroon_hex, amount_sats_override) {
        const ptr0 = passStringToWasm0(bolt11, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(route_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(route_macaroon_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_quote_route_fee(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, !isLikeNone(amount_sats_override), isLikeNone(amount_sats_override) ? BigInt(0) : amount_sats_override);
        return ret;
    }
    /**
     * S45 (DP): the same quote for a PUBKEY destination with no invoice —
     * Max pricing a route to another LSP's node (an LNURL address that LSP
     * serves) before any invoice is minted. Records any lsp_first_hop_policy
     * sighting like quote_route_fee. Resolves to the same JSON shape.
     * @param {string} dest_pubkey_hex
     * @param {string} route_endpoint
     * @param {string} route_macaroon_hex
     * @param {bigint} amount_sats
     * @returns {Promise<any>}
     */
    quote_route_fee_to_pubkey(dest_pubkey_hex, route_endpoint, route_macaroon_hex, amount_sats) {
        const ptr0 = passStringToWasm0(dest_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(route_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(route_macaroon_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_quote_route_fee_to_pubkey(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, amount_sats);
        return ret;
    }
    /**
     * Register a Web Push wake subscription (D-1 2c offline-receive). Takes the
     * browser PushSubscription serialized to JSON; signs the `push-subscribe`
     * challenge with the node key and POSTs to the active LSP. The returned
     * Promise resolves on success and rejects with the error string on failure.
     * @param {string} subscription_json
     * @returns {Promise<any>}
     */
    register_push_subscription(subscription_json) {
        const ptr0 = passStringToWasm0(subscription_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_register_push_subscription(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Session 23 Option B (allocator unification, the other direction):
     * the frontend reserves receive-index territory. Raises the shared
     * allocator floor to index+1 on the LIVE counter instance, so the
     * signer can never issue an index at or below a shown/used receive
     * address. No-op when the allocator is already past it.
     * @param {number} index
     */
    reserve_onchain_index(index) {
        const ret = wasm.lijwallethandle_reserve_onchain_index(this.__wbg_ptr, index);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} mnemonic
     * @param {string} config_json
     * @returns {Promise<any>}
     */
    static restore(mnemonic, config_json) {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_restore(ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Lock-prepare-unlock: snapshot handles under the lock, then build/sign/
     * broadcast with the lock released (network I/O). Returns SendResult JSON.
     * @param {string} dest
     * @param {number} amount_sats
     * @param {number} fee_rate_sat_per_kw
     * @returns {Promise<any>}
     */
    send_onchain(dest, amount_sats, fee_rate_sat_per_kw) {
        const ptr0 = passStringToWasm0(dest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_send_onchain(this.__wbg_ptr, ptr0, len0, amount_sats, fee_rate_sat_per_kw);
        return ret;
    }
    /**
     * @param {string} bolt11
     * @returns {Promise<any>}
     */
    send_payment(bolt11) {
        const ptr0 = passStringToWasm0(bolt11, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_send_payment(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
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
     * @param {string} bolt11
     * @param {string} route_endpoint
     * @param {string} route_macaroon_hex
     * @returns {Promise<any>}
     */
    send_payment_via_lsp_route(bolt11, route_endpoint, route_macaroon_hex) {
        const ptr0 = passStringToWasm0(bolt11, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(route_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(route_macaroon_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_send_payment_via_lsp_route(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
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
     * @param {string} bolt11
     * @param {string} route_endpoint
     * @param {string} route_macaroon_hex
     * @param {number} max_retries
     * @param {Function} progress_callback
     * @param {bigint | null} [amount_sats_override]
     * @param {bigint | null} [amount_msat_override]
     * @returns {Promise<any>}
     */
    send_payment_with_retries(bolt11, route_endpoint, route_macaroon_hex, max_retries, progress_callback, amount_sats_override, amount_msat_override) {
        const ptr0 = passStringToWasm0(bolt11, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(route_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(route_macaroon_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_send_payment_with_retries(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, max_retries, progress_callback, !isLikeNone(amount_sats_override), isLikeNone(amount_sats_override) ? BigInt(0) : amount_sats_override, !isLikeNone(amount_msat_override), isLikeNone(amount_msat_override) ? BigInt(0) : amount_msat_override);
        return ret;
    }
    /**
     * v210 (quorum wiring): set the independent quorum endpoint list at
     * runtime. urls_json = JSON array of https base URLs (LSP defaults ∪
     * wallet additions, page-merged, additive-only). Empty = rejected.
     * @param {string} urls_json
     */
    set_quorum_endpoints(urls_json) {
        const ptr0 = passStringToWasm0(urls_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_set_quorum_endpoints(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * v184: node-key message signing (LND signmessage-compatible zbase32).
     * Serves the LIJOX delegate slip/void digests. Sync, no I/O.
     * @param {string} msg
     * @returns {string}
     */
    sign_message(msg) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(msg, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.lijwallethandle_sign_message(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * TEMP diagnostic: dump the SpendableOutputs event log — every descriptor
     * (incl. v128-excluded StaticOutputs) seen at the event handler, with
     * variant + value + destination script. Confirms what an anchors coop
     * close emits. Returns a JSON array of objects. No wallet lock needed
     * (thread_local). Remove with the rest of the temp diagnostics.
     * @returns {string}
     */
    spendable_outputs_log() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.lijwallethandle_spendable_outputs_log(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * TEMP diagnostic: why matured sweeps aren't broadcasting — broadcaster queue
     * depth + failures, and the sweeper's internal height vs the real tip.
     * @param {number} real_tip
     * @returns {string}
     */
    sweeper_broadcast_diag(real_tip) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_sweeper_broadcast_diag(this.__wbg_ptr, real_tip);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * TEMP diagnostic: replicate the sweeper's spend_outputs to find which step
     * fails (fee / change-script / signing) and the fee-vs-value numbers.
     * @param {number} real_tip
     * @returns {string}
     */
    sweeper_spend_attempt_diag(real_tip) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_sweeper_spend_attempt_diag(this.__wbg_ptr, real_tip);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {string} lsp_pubkey
     * @returns {Promise<any>}
     */
    switch_lsp(lsp_pubkey) {
        const ptr0 = passStringToWasm0(lsp_pubkey, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_switch_lsp(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Tier 2 (privacy-default) on-chain sync: pull compact block filters from
     * the node, match them LOCALLY against our scripts, fetch and verify only
     * the blocks that hit, and assemble the UTXO set + history + balances
     * entirely client-side — the node never learns which scripts are ours.
     * Persists across sessions and resumes from the saved cursor. `birthday`
     * is the wallet's creation height, used only when no cursor exists yet.
     * Returns Tier2Summary JSON.
     * @param {number} birthday
     * @returns {Promise<any>}
     */
    tier2_onchain_sync(birthday) {
        const ret = wasm.lijwallethandle_tier2_onchain_sync(this.__wbg_ptr, birthday);
        return ret;
    }
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
     * @param {number} from_height
     * @returns {string}
     */
    tier2_rescan_from(from_height) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.lijwallethandle_tier2_rescan_from(this.__wbg_ptr, from_height);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
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
     * @param {string} address
     * @returns {Promise<any>}
     */
    watch_address_inbound(address) {
        const ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.lijwallethandle_watch_address_inbound(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) LijWalletHandle.prototype[Symbol.dispose] = LijWalletHandle.prototype.free;

/**
 * Suggest BIP39 English words matching a prefix. Returns up to `max` matches,
 * lexicographically sorted (the wordlist is pre-sorted). Case-insensitive.
 * Returns empty vec for empty prefix or no matches.
 * @param {string} prefix
 * @param {number} max
 * @returns {any[]}
 */
export function bip39_suggest(prefix, max) {
    const ptr0 = passStringToWasm0(prefix, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.bip39_suggest(ptr0, len0, max);
    var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v2;
}

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
 * @param {any[]} first_eleven
 * @param {string} seven_bits
 * @returns {string}
 */
export function checksum_word_for_bits(first_eleven, seven_bits) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArrayJsValueToWasm0(first_eleven, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(seven_bits, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.checksum_word_for_bits(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {string} mnemonic
 * @returns {string}
 */
export function derive_account_zpub(mnemonic) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.derive_account_zpub(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * @param {string} mnemonic
 * @param {number} index
 * @returns {string}
 */
export function derive_receive_address(mnemonic, index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.derive_receive_address(ptr0, len0, index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * @param {string} worker_url
 * @returns {Promise<string>}
 */
export function fetch_lsp_registry(worker_url) {
    const ptr0 = passStringToWasm0(worker_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.fetch_lsp_registry(ptr0, len0);
    return ret;
}

/**
 * @param {string} endpoint
 * @returns {Promise<boolean>}
 */
export function health_check_lsp(endpoint) {
    const ptr0 = passStringToWasm0(endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.health_check_lsp(ptr0, len0);
    return ret;
}

export function lij_init() {
    wasm.lij_init();
}

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
 * @param {string} endpoint
 * @param {string} route_macaroon
 * @param {bigint} payment_size_msat
 * @param {string} client_pubkey
 * @returns {Promise<any>}
 */
export function lsps2_buy_promise(endpoint, route_macaroon, payment_size_msat, client_pubkey) {
    const ptr0 = passStringToWasm0(endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(route_macaroon, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(client_pubkey, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.lsps2_buy_promise(ptr0, len0, ptr1, len1, payment_size_msat, ptr2, len2);
    return ret;
}

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
 * @param {string} endpoint
 * @param {string} route_macaroon
 * @returns {Promise<any>}
 */
export function lsps2_get_info(endpoint, route_macaroon) {
    const ptr0 = passStringToWasm0(endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(route_macaroon, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.lsps2_get_info(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * @param {string} mnemonic
 * @param {string} psbt_hex
 * @returns {string}
 */
export function psbt_probe(mnemonic, psbt_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(psbt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.psbt_probe(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Derive the authoritative Lightning node pubkey from a BIP39 mnemonic.
 * Mirrors what LijNode does in ~3ms instead of ~3s — skips LDK setup,
 * LSP registry fetch, chain monitor init. Used for seed-verification in
 * the forgot-passphrase reset flow.
 * @param {string} mnemonic
 * @param {string} network
 * @returns {string}
 */
export function pubkey_from_mnemonic(mnemonic, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.pubkey_from_mnemonic(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {string} worker_url
 * @param {string} auth_token
 * @param {string} pubkey_hex
 * @returns {Promise<string>}
 */
export function pull_backup(worker_url, auth_token, pubkey_hex) {
    const ptr0 = passStringToWasm0(worker_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(auth_token, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.pull_backup(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * @param {string} worker_url
 * @param {string} auth_token
 * @param {string} blob_json
 * @returns {Promise<void>}
 */
export function push_backup(worker_url, auth_token, blob_json) {
    const ptr0 = passStringToWasm0(worker_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(auth_token, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(blob_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.push_backup(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * @param {string} worker_url
 * @param {string} registration_json
 * @returns {Promise<void>}
 */
export function register_lsp(worker_url, registration_json) {
    const ptr0 = passStringToWasm0(worker_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(registration_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.register_lsp(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * @param {boolean} v
 */
export function set_backup_off(v) {
    wasm.set_backup_off(v);
}

/**
 * v208: broadcast routing — true routes each tx to one endpoint at a time
 * (rotating, stop at first acceptance); false fans to all healthy endpoints.
 * @param {boolean} v
 */
export function set_broadcast_one(v) {
    wasm.set_broadcast_one(v);
}

/**
 * v216 (S36, O6 fee headroom → exact-fee): the user's fee-race margin in
 * sats — subtracted once at the aggregate inside max_sendable_sats. Page
 * persists (WALLET → Controls dial) and boot-applies before any wallet
 * exists (free fn, LSP-reserve pattern). Clamped 0..=5,000. Returns applied.
 * S45 (DP): Dials → Speed up slow closes — Off / Automatic (default Off).
 * @param {boolean} on
 * @returns {boolean}
 */
export function set_coop_cpfp_auto(on) {
    const ret = wasm.set_coop_cpfp_auto(on);
    return ret !== 0;
}

/**
 * @param {number} sats
 * @returns {number}
 */
export function set_fee_margin_sats(sats) {
    const ret = wasm.set_fee_margin_sats(sats);
    return ret >>> 0;
}

/**
 * v213 (evil-LSP reserve dial): the reserve the user demands the LSP keep
 * on its side, ppm, NEW channels only. Clamped 0..=50_000 (5% cap); 0 =
 * LDK's 1,000-sat floor. Free fn — callable before any wallet exists so
 * the boot re-apply lands ahead of create/restore (JIT accepts read the
 * ChannelManager config captured at construction). Returns the APPLIED
 * (clamped) value.
 * @param {number} ppm
 * @returns {number}
 */
export function set_lsp_reserve_ppm(ppm) {
    const ret = wasm.set_lsp_reserve_ppm(ppm);
    return ret >>> 0;
}

/**
 * @param {boolean} v
 */
export function set_offline_start(v) {
    wasm.set_offline_start(v);
}

/**
 * @param {string} mnemonic
 * @param {string} psbt_hex
 * @returns {string}
 */
export function sign_psbt_hex(mnemonic, psbt_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(psbt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.sign_psbt_hex(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Unwrap a hex-encoded blob produced by [`wrap_mnemonic`]. Returns the
 * mnemonic string. Throws on bad hex, short blob, wrong passphrase,
 * tampered data, or version mismatch — error messages disambiguate.
 * @param {string} blob_hex
 * @param {string} passphrase
 * @returns {string}
 */
export function unwrap_mnemonic(blob_hex, passphrase) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(blob_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.unwrap_mnemonic(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Validate a full BIP39 mnemonic string (word validity + checksum).
 * Accepts 12, 15, 18, 21, or 24-word phrases. Returns Ok on valid, Err with
 * descriptive message on invalid word, wrong count, or checksum mismatch.
 * @param {string} phrase
 */
export function validate_mnemonic(phrase) {
    const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validate_mnemonic(ptr0, len0);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Build version of THIS compiled WASM binary. The frontend compares it to its
 * own LIJ_FRONTEND_VERSION; a mismatch means the deployed binary is stale
 * (an incremental build that skipped WASM regen). Bump on every WASM rebuild.
 * @returns {string}
 */
export function wasm_build_version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.wasm_build_version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * localStorage. Throws on empty mnemonic or Argon2 failure.
 * @param {string} mnemonic
 * @param {string} passphrase
 * @returns {string}
 */
export function wrap_mnemonic(mnemonic, passphrase) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wrap_mnemonic(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_debug_string_8baecc377ad92880: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_d4c2480b46f29e33: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_e04e3a51a90cde43: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_3db04af369717583: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_5957b329897cc39c: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_ae6081df8158aa73: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_bd5a70920abf0236: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_207c541c2d58dfb3: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_call_1aea13500fe8ff6c: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_close_5e419dfc1ae8215f: function() { return handleError(function (arg0) {
            arg0.close();
        }, arguments); },
        __wbg_code_11fb21cd37684275: function(arg0) {
            const ret = arg0.code;
            return ret;
        },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_data_bb968bbd5316b66f: function(arg0) {
            const ret = arg0.data;
            return ret;
        },
        __wbg_debug_ef8dfe310f3fb972: function(arg0, arg1, arg2, arg3) {
            console.debug(arg0, arg1, arg2, arg3);
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_error_e5addbe627bf89e5: function(arg0, arg1, arg2, arg3) {
            console.error(arg0, arg1, arg2, arg3);
        },
        __wbg_fetch_d5b79bbd1cdfa075: function(arg0, arg1) {
            const ret = arg0.fetch(arg1);
            return ret;
        },
        __wbg_getItem_dd0194ffb8abcfea: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getItem(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_d8a3d51a73d14c8a: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_headers_38964af605485595: function(arg0) {
            const ret = arg0.headers;
            return ret;
        },
        __wbg_info_9714e40f3b0b0bb0: function(arg0, arg1, arg2, arg3) {
            console.info(arg0, arg1, arg2, arg3);
        },
        __wbg_instanceof_ArrayBuffer_046631d47961f5fe: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Response_b11437cbbe8c9041: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Response;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_4bfad3a9470c25c9: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_key_6e48c6d7ae0f47ec: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg1.key(arg2 >>> 0);
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_length_090b6aa6235450ba: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_a16a988a33d3c2ad: function() { return handleError(function (arg0) {
            const ret = arg0.length;
            return ret;
        }, arguments); },
        __wbg_lijwallethandle_new: function(arg0) {
            const ret = LijWalletHandle.__wrap(arg0);
            return ret;
        },
        __wbg_localStorage_35d0825b8c30139a: function() { return handleError(function (arg0) {
            const ret = arg0.localStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_log_f6601207d615a1cf: function(arg0, arg1, arg2, arg3) {
            console.log(arg0, arg1, arg2, arg3);
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_4774b8d4db1224e4: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_838cc12c8f578c76: function() { return handleError(function (arg0, arg1) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_e4597c3f125a2038: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_typed_5101eada2c6754de: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h57c0e248f13a99cc(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_length_a90559ebda3954f8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_new_with_str_and_init_f420a9ad6aaedb54: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new Request(getStringFromWasm0(arg0, arg1), arg2);
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_1925e14eb84a904c: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_now_cd850b0a28a6e656: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_ok_61e571b7fedb8af7: function(arg0) {
            const ret = arg0.ok;
            return ret;
        },
        __wbg_performance_6c4d39832e915483: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_7dca54d31cb9d2dc: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_queueMicrotask_1f50b4bdf2c98605: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_queueMicrotask_805204511f79bee8: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_reason_9c34280f8984a42b: function(arg0, arg1) {
            const ret = arg1.reason;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_removeItem_4342c43371bfa90a: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_bb4df27803d377b2: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_send_c7f0923095158c77: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.send(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_setItem_0707664297606df0: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_setTimeout_b5154d023ff780d5: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.setTimeout(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_05b085c909633819: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_7680cae2d713f38d: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.set(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_binaryType_e414aca918d25a0d: function(arg0, arg1) {
            arg0.binaryType = __wbindgen_enum_BinaryType[arg1];
        },
        __wbg_set_body_44749a7f105b35d6: function(arg0, arg1) {
            arg0.body = arg1;
        },
        __wbg_set_method_6c51b627d66b223f: function(arg0, arg1, arg2) {
            arg0.method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_mode_b3a032fdfee82cfd: function(arg0, arg1) {
            arg0.mode = __wbindgen_enum_RequestMode[arg1];
        },
        __wbg_set_onclose_e31ee8859ca07159: function(arg0, arg1) {
            arg0.onclose = arg1;
        },
        __wbg_set_onerror_50321b56750dfd40: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onmessage_ad90102236e810df: function(arg0, arg1) {
            arg0.onmessage = arg1;
        },
        __wbg_set_onopen_a1f2b9a183f6ab5b: function(arg0, arg1) {
            arg0.onopen = arg1;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_44bef9fa6011e260: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_13002645baf43d84: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_91d0abd4d035416c: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_513f857c65724fc7: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_statusText_e1b7df82e6e7f1e5: function(arg0, arg1) {
            const ret = arg1.statusText;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_status_b5e005082e72a873: function(arg0) {
            const ret = arg0.status;
            return ret;
        },
        __wbg_subarray_fb60755cb1b4a498: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_text_6a11a037389e6a04: function() { return handleError(function (arg0) {
            const ret = arg0.text();
            return ret;
        }, arguments); },
        __wbg_then_d9ebfadd74ddfbb2: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_then_f6dedb0d880db23a: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_warn_fa670c34f9e47569: function(arg0, arg1, arg2, arg3) {
            console.warn(arg0, arg1, arg2, arg3);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 1882, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h2345594a796ea04f);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("CloseEvent")], shim_idx: 794, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h30a83671176f857a);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("ErrorEvent")], shim_idx: 794, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_2);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("MessageEvent")], shim_idx: 794, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_3);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 1702, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__he12e2585bd268995);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./lij_wasm_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__he12e2585bd268995(arg0, arg1) {
    wasm.wasm_bindgen__convert__closures_____invoke__he12e2585bd268995(arg0, arg1);
}

function wasm_bindgen__convert__closures_____invoke__h30a83671176f857a(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h30a83671176f857a(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_2(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_2(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_3(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h30a83671176f857a_3(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h2345594a796ea04f(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h2345594a796ea04f(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h57c0e248f13a99cc(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h57c0e248f13a99cc(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_BinaryType = ["blob", "arraybuffer"];


const __wbindgen_enum_RequestMode = ["same-origin", "no-cors", "cors", "navigate"];
const LijWalletHandleFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_lijwallethandle_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('lij_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
