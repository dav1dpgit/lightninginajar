// LiJ (S73, 2026-11-26 — DP: "Write Round 2 and the test file"; docs/design/balance-transfer/balance-transfer-r2.md).
//
// TESTS ONLY. No line of the library is changed by this file; it is compiled only under `cfg(test)`.
//
// The balance transfer between providers, the way called "pay across": a wallet moves everything it can send
// over Lightning from its old provider to a new provider.
//
//   1. the wallet holds a preimage and hands its hash to the new provider;
//   2. the new provider makes an invoice on that hash — it can pass the payment on or fail it, never take it;
//   3. the wallet pays that invoice from its channel with the old provider (wallet → old provider → new provider);
//   4. the new provider holds the payment, opens a channel to the wallet at zero confirmations and passes the
//      payment on over it, less its opening fee, ON THE SAME HASH;
//   5. the wallet releases the preimage on the new channel; with it the new provider collects from the old
//      provider, and the old provider from the wallet's old channel.
//
// So for a moment ONE payment hash is both a payment this wallet SENT (pending, through the old provider) and a
// payment this wallet is RECEIVING (through the new provider). Nothing in the library was known to forbid that;
// nothing had shown it works. These tests show it, written with upstream's own test tools.
//
// Node 0 is the wallet, node 1 the old provider, node 2 the new provider. Both of the wallet's channels are
// opened by the provider at zero confirmations, as a JIT channel is.
//
//   `lij_move_whole_balance_out_through_the_old_provider_in_through_the_new`
//       the move completes: the wallet's channel with the old provider can send nothing more, and the amount,
//       less the new provider's fee, is on the wallet's side of the new channel.
//   `lij_move_not_taken_returns_in_full`
//       the wallet does not release the preimage: the new provider's payment fails back, then the wallet's own
//       payment fails back, and the wallet's channel with the old provider holds exactly what it held before.

use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{PaymentId, RecentPaymentDetails, RecipientOnionFields};
use crate::ln::functional_test_utils::*;
use crate::routing::router::{PaymentParameters, Route, RouteParameters};
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::config::UserConfig;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

/// The new provider's opening fee in these tests (100 sats, the fee LiJ-Node lists).
const OPENING_FEE_MSAT: u64 = 100_000;

/// The tests' settings for every node: one payment may fill a channel (LDK's own default stops a single
/// incoming payment at a tenth of the channel; the wallet and the providers do not run with that).
fn move_config() -> UserConfig {
	let mut cfg = test_default_channel_config();
	cfg.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	cfg
}

/// The one channel `node` has with `peer`.
fn chan_with(node: &Node, peer: &PublicKey) -> ChannelDetails {
	let mut chans: Vec<ChannelDetails> =
		node.node.list_channels().into_iter().filter(|c| c.counterparty.node_id == *peer).collect();
	assert_eq!(chans.len(), 1, "exactly one channel with that peer");
	chans.pop().unwrap()
}

/// A route for `amt_msat` from `from` to `to`.
fn route_to(from: &Node, to: &Node, amt_msat: u64) -> Route {
	let payment_params = PaymentParameters::from_node_id(to.node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_bolt11_features(to.node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	get_route(from, &route_params).unwrap()
}

fn do_move(wallet_takes_the_payment: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	// The wallet decides on every channel a peer opens to it, as the LiJ engine does.
	let mut wallet_cfg = move_config();
	wallet_cfg.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(wallet_cfg), Some(move_config()), Some(move_config())],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let old_id = nodes[1].node.get_our_node_id();
	let new_id = nodes[2].node.get_our_node_id();

	// The two providers share a public channel; the old provider can send over it.
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 15_000_000, 0);
	// The wallet's chain is brought level with theirs.
	let behind = nodes[1].best_block_info().1 - nodes[0].best_block_info().1;
	if behind > 0 {
		connect_blocks(&nodes[0], behind);
	}

	// The wallet's channel with its old provider: 1,000,000 sats, 900,000 of them the wallet's.
	open_zero_conf_channel_with_value(&nodes[1], &nodes[0], None, 1_000_000, 900_000_000);
	let old_before = chan_with(&nodes[0], &old_id);
	let limit = old_before.next_outbound_htlc_limit_msat;
	assert!(limit > 0);

	// THE AMOUNT: everything the wallet can send. The old provider's routing fee comes out of the same
	// channel, so the amount is the limit less that fee.
	let mut amt = limit - 10_000;
	for _ in 0..3 {
		amt = limit - route_to(&nodes[0], &nodes[2], amt).get_total_fees();
	}
	let route_out = route_to(&nodes[0], &nodes[2], amt);
	assert_eq!(route_out.paths.len(), 1);
	assert_eq!(route_out.paths[0].hops.len(), 2, "wallet -> old provider -> new provider");
	assert_eq!(route_out.paths[0].hops[0].pubkey, old_id);
	assert_eq!(route_out.paths[0].hops[1].pubkey, new_id);
	assert_eq!(route_out.get_total_amount() + route_out.get_total_fees(), limit);

	// The wallet holds the preimage and will take a payment on its hash...
	let preimage = PaymentPreimage([0x73; 32]);
	let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
	let wallet_secret =
		nodes[0].node.create_inbound_payment_for_hash(payment_hash, None, 7200, None).unwrap();
	// ...and the new provider holds an invoice on the same hash. It does not know the preimage.
	let new_secret =
		nodes[2].node.create_inbound_payment_for_hash(payment_hash, Some(amt), 7200, None).unwrap();

	// The wallet pays the new provider's invoice from its channel with the old provider.
	nodes[0]
		.node
		.send_payment_with_route(
			route_out,
			payment_hash,
			RecipientOnionFields::secret_only(new_secret),
			PaymentId(payment_hash.0),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], amt, payment_hash, new_secret);
	// The new provider holds the payment now. The wallet's old channel can send nothing more.
	assert_eq!(chan_with(&nodes[0], &old_id).next_outbound_htlc_limit_msat, 0);

	// The new provider opens a channel to the wallet at zero confirmations, nothing on the wallet's side...
	open_zero_conf_channel_with_value(&nodes[2], &nodes[0], None, 1_200_000, 0);
	// ...and passes the payment on over it, less its opening fee, on the SAME hash.
	let delivered = amt - OPENING_FEE_MSAT;
	let route_in = route_to(&nodes[2], &nodes[0], delivered);
	assert_eq!(route_in.paths.len(), 1);
	assert_eq!(route_in.paths[0].hops.len(), 1, "new provider -> wallet, over the new channel");
	nodes[2]
		.node
		.send_payment_with_route(
			route_in,
			payment_hash,
			RecipientOnionFields::secret_only(wallet_secret),
			PaymentId([0x42; 32]),
		)
		.unwrap();
	check_added_monitors(&nodes[2], 1);
	// This helper fails the test unless the wallet reports the payment as one it can take.
	pass_along_route(&nodes[2], &[&[&nodes[0]]], delivered, payment_hash, wallet_secret);

	// THE STATE UNDER TEST: one hash, sent and being received, at the same wallet.
	let old_mid = chan_with(&nodes[0], &old_id);
	assert_eq!(old_mid.pending_outbound_htlcs.len(), 1);
	assert_eq!(old_mid.pending_outbound_htlcs[0].payment_hash, payment_hash);
	let new_mid = chan_with(&nodes[0], &new_id);
	assert_eq!(new_mid.pending_inbound_htlcs.len(), 1);
	assert_eq!(new_mid.pending_inbound_htlcs[0].payment_hash, payment_hash);
	assert_eq!(new_mid.pending_inbound_htlcs[0].amount_msat, delivered);
	assert!(nodes[0]
		.node
		.list_recent_payments()
		.iter()
		.any(|p| matches!(p, RecentPaymentDetails::Pending { payment_hash: h, .. } if *h == payment_hash)));

	if wallet_takes_the_payment {
		// The wallet releases the preimage on the new channel: the amount is the wallet's there.
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[2], &[&[&nodes[0]]], preimage));
		// With that preimage the new provider collects from the old provider, and the old provider from the
		// wallet's old channel. This helper fails the test unless the wallet reports its own payment as sent.
		claim_payment_along_route(ClaimAlongRouteArgs::new(
			&nodes[0],
			&[&[&nodes[1], &nodes[2]]],
			preimage,
		));

		// Everything the wallet could send has left the old channel: what is left is the reserve.
		let old_after = chan_with(&nodes[0], &old_id);
		assert!(old_after.pending_outbound_htlcs.is_empty());
		assert_eq!(old_after.next_outbound_htlc_limit_msat, 0);
		assert_eq!(old_after.outbound_capacity_msat, 0);
		// It is on the wallet's side of the new channel, less the new provider's fee.
		let new_after = chan_with(&nodes[0], &new_id);
		assert!(new_after.pending_inbound_htlcs.is_empty());
		let new_reserve_msat = new_after.unspendable_punishment_reserve.unwrap() * 1000;
		assert_eq!(new_after.outbound_capacity_msat, delivered - new_reserve_msat);
		// No payment of the wallet's is left waiting.
		assert!(nodes[0]
			.node
			.list_recent_payments()
			.iter()
			.all(|p| !matches!(p, RecentPaymentDetails::Pending { .. })));
	} else {
		// The wallet does not take the payment: the new provider's payment to it fails back...
		fail_payment_along_route(&nodes[2], &[&[&nodes[0]]], false, payment_hash);
		// ...the new provider lets go of the payment it held, and the wallet's own payment fails back.
		fail_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_hash);

		// The wallet's old channel holds exactly what it held before.
		let old_after = chan_with(&nodes[0], &old_id);
		assert!(old_after.pending_outbound_htlcs.is_empty());
		assert_eq!(old_after.next_outbound_htlc_limit_msat, limit);
		assert_eq!(old_after.outbound_capacity_msat, old_before.outbound_capacity_msat);
		// Nothing is on the wallet's side of the new channel.
		let new_after = chan_with(&nodes[0], &new_id);
		assert!(new_after.pending_inbound_htlcs.is_empty());
		assert_eq!(new_after.outbound_capacity_msat, 0);
		assert!(nodes[0]
			.node
			.list_recent_payments()
			.iter()
			.all(|p| !matches!(p, RecentPaymentDetails::Pending { .. })));
	}
}

#[test]
fn lij_move_whole_balance_out_through_the_old_provider_in_through_the_new() {
	do_move(true);
}

#[test]
fn lij_move_not_taken_returns_in_full() {
	do_move(false);
}
