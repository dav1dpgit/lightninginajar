// LiJ (engine v376, S70 — DP 2026-11-18 "Go"; docs/design/htlc/offline-sender-r1.md §4 B and r2).
//
// Tests for the LIJ PATCH v376 in `chain/channelmonitor.rs`
// (`ChannelMonitorImpl::should_broadcast_holder_commitment_txn`): a payment this node sent itself
// (`HTLCSource::OutboundRoute`) gets the grace upstream gives an async payment — 4,032 blocks —
// before the node closes the channel on-chain over it. Upstream closes 3 blocks past the HTLC's
// expiry (`LATENCY_GRACE_PERIOD_BLOCKS`).
//
// In these tests node 0 is the wallet and node 1 is its provider.
//
// Without the patch `lij_own_send_past_expiry_takes_the_late_fail`,
// `lij_own_dust_send_past_expiry_takes_the_late_fail` and
// `lij_own_send_past_expiry_takes_the_late_settle` fail (the wallet has closed the channel before
// the reconnect), and `lij_own_send_closes_when_the_grace_has_run` fails (the close comes 4,029
// blocks sooner). `lij_forwarded_htlc_keeps_the_three_block_rule` passes with and without it.

use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::events::{ClosureReason, HTLCHandlingFailureType};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ErrorAction, MessageSendEvent};
use crate::types::payment::PaymentHash;

/// The grace the patch gives a payment this node sent: upstream's
/// `ASYNC_PAYMENT_GRACE_PERIOD_BLOCKS`, which is private to the function it is used in.
const LIJ_OWN_SEND_GRACE_BLOCKS: u32 = 4032;

/// The expiry block of the HTLC `node` sent for `payment_hash`, read from its own channel.
fn sent_htlc_expiry(node: &Node, payment_hash: PaymentHash) -> u32 {
	node.node
		.list_channels()
		.iter()
		.flat_map(|c| c.pending_outbound_htlcs.clone())
		.find(|htlc| htlc.payment_hash == payment_hash)
		.expect("the HTLC is on a channel")
		.cltv_expiry
}

/// Nothing was broadcast, nothing was closed, nothing is waiting to be sent or stored.
fn assert_quiet(node: &Node) {
	assert!(node.tx_broadcaster.txn_broadcast().is_empty());
	assert!(node.node.get_and_clear_pending_events().is_empty());
	assert!(node.node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(node, 0);
}

fn do_own_send_past_expiry_takes_the_late_fail(dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// The wallet sends; the provider holds the payment.
	let amt_msat = if dust { 50_000 } else { 3_000_000 };
	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], amt_msat);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	// The wallet goes offline. The provider fails the payment back while it is away: the fail
	// cannot leave the provider until the wallet is there to sign.
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);

	// The wallet's chain reaches 3 blocks past the expiry — where upstream closes — and then goes
	// 1,000 blocks further. It closes nothing.
	connect_blocks(&nodes[0], expiry + LATENCY_GRACE_PERIOD_BLOCKS - nodes[0].best_block_info().1);
	assert_eq!(nodes[0].best_block_info().1, expiry + LATENCY_GRACE_PERIOD_BLOCKS);
	assert_quiet(&nodes[0]);
	connect_blocks(&nodes[0], 1000);
	assert_quiet(&nodes[0]);

	// The provider sees the same chain and closes nothing either: it has nothing to claim.
	connect_blocks(&nodes[1], nodes[0].best_block_info().1 - nodes[1].best_block_info().1);
	assert_quiet(&nodes[1]);

	// The wallet reconnects. The provider's fail is delivered, the payment reads as failed, the
	// HTLC is gone and the channel is open.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_fails.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_failed!(nodes[0], payment_hash, true);
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.is_empty());
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	assert!(nodes[1].tx_broadcaster.txn_broadcast().is_empty());

	// ... and the same channel carries the next payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn lij_own_send_past_expiry_takes_the_late_fail() {
	do_own_send_past_expiry_takes_the_late_fail(false);
}

#[test]
fn lij_own_dust_send_past_expiry_takes_the_late_fail() {
	// Upstream counts an HTLC below the dust limit in the same rule (its own comment in
	// `should_broadcast_holder_commitment_txn`), so the patch must cover it too.
	do_own_send_past_expiry_takes_the_late_fail(true);
}

#[test]
fn lij_own_send_past_expiry_takes_the_late_settle() {
	// The provider has the preimage while the wallet is away. (A real provider collects on-chain
	// before the expiry if the wallet stays away — that rule is the provider's and is not changed;
	// here the provider's own chain is held back so that only the wallet's rule is in play.) The
	// wallet returns 3 blocks and more past the expiry: it does not close, and the reconnect
	// delivers the settle — the payment reads as sent.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	nodes[1].node.claim_funds(preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[0], expiry + LATENCY_GRACE_PERIOD_BLOCKS + 500 - nodes[0].best_block_info().1);
	assert_quiet(&nodes[0]);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_sent(&nodes[0], preimage, None, true, true);
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.is_empty());
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
}

#[test]
fn lij_own_send_closes_when_the_grace_has_run() {
	// The provider never answers. One block short of the grace the wallet has closed nothing; at
	// the grace it closes the channel on-chain over the payment, as upstream does at 3 blocks.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_b_id = nodes[1].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[0], payment_hash);

	connect_blocks(&nodes[0], expiry + LIJ_OWN_SEND_GRACE_BLOCKS - 1 - nodes[0].best_block_info().1);
	assert_eq!(nodes[0].best_block_info().1, expiry + LIJ_OWN_SEND_GRACE_BLOCKS - 1);
	assert_quiet(&nodes[0]);

	connect_blocks(&nodes[0], 1);
	assert!(!nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(msg_events.iter().any(|ev| matches!(
		ev,
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { .. }, .. }
			| MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, .. }
	)));
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event!(nodes[0], 1, reason, [node_b_id], 100000);
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn lij_forwarded_htlc_keeps_the_three_block_rule() {
	// Node 1 forwards a payment from node 0 to node 2, and node 2 never answers. A forwarded HTLC
	// has an inbound HTLC behind it, so node 1 still closes its channel with node 2 on-chain 3
	// blocks past the HTLC's expiry — the patch does not reach it.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_c_id = nodes[2].node.get_our_node_id();
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let expiry = sent_htlc_expiry(&nodes[1], payment_hash);

	connect_blocks(&nodes[1], expiry + LATENCY_GRACE_PERIOD_BLOCKS - 1 - nodes[1].best_block_info().1);
	assert!(nodes[1].tx_broadcaster.txn_broadcast().is_empty());
	assert_eq!(nodes[1].node.list_channels().len(), 2);

	connect_blocks(&nodes[1], 1);
	assert!(!nodes[1].tx_broadcaster.txn_broadcast().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event!(nodes[1], 1, reason, [node_c_id], 100000);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
}
