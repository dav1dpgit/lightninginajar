// LiJ (S73, 2026-11-27 — engine v395; DP 2026-11-26 13:50 "Agreed on 1, 2 & 3", 2026-11-27 15:38 "Go on the next
// items in the order"; docs/design/balance-transfer/balance-transfer-r3.md §7).
//
// TESTS ONLY. No line of the library is changed by this file; it is compiled only under `cfg(test)`.
//
// THE CLOSING ADDRESS IS CHOSEN AT THE CLOSE. Until engine v394 the wallet opened and accepted channels with LDK's
// default `commit_upfront_shutdown_pubkey = true`: the address a cooperative close pays was taken from the signer
// at the OPENING and fixed in the channel for its life. From engine v395 the wallet sets that to false. LDK then asks
// the signer for the address when a cooperative close begins — whichever side begins it. The wallet's signer answers
// with the next address of the 12 words (the same counter as before), so the coin of a close is found by a restore
// from the words as it was before; what changes is WHEN the address is taken, which is what a close into a new
// channel (way 2) needs.
//
// Node 0 is the wallet, node 1 the provider. The provider opens the channel, as a JIT channel is opened.
// The test signer hands out the addresses a test lists, in order, and panics when it is asked for one that no test
// listed — so "asked at the opening" and "asked at the close" cannot be mistaken for one another.
//
//   `lij_close_address_is_asked_for_at_the_close_wallet_starts`
//   `lij_close_address_is_asked_for_at_the_close_provider_starts`
//       nothing is asked of the wallet's signer at the opening; the cooperative close pays the address the signer
//       hands out when the close begins.
//   `lij_close_address_of_a_channel_the_wallet_opened_is_asked_for_at_the_close`
//       the same for a channel the WALLET opens (the open a pool pays for — Mix, From → Channel — and the open its
//       own coins pay for): nothing asked at the opening, the close pays the address handed out when it begins.
//   `lij_close_address_fixed_at_the_opening_stays`
//       a channel opened the old way (every channel open before v395): asked once, at the opening; the close pays
//       that address and the signer is not asked again.
//   `lij_close_by_force_does_not_ask_for_a_close_address`
//       the wallet's own commitment transaction published (the Black start kit's CLOSE): its balance comes back as
//       the delayed output, to be collected after the delay (the kit's COLLECT) — the signer is never asked for a
//       close address.

use crate::events::Event;
use crate::ln::channelmanager::BREAKDOWN_TIMEOUT;
use crate::ln::functional_test_utils::*;
use crate::ln::script::ShutdownScript;
use crate::sign::{SignerProvider, SpendableOutputDescriptor};
use crate::util::config::UserConfig;
use crate::util::test_utils::OnGetShutdownScriptpubkey;

use bitcoin::hashes::Hash;
use bitcoin::{Transaction, WPubkeyHash};

fn address(n: u8) -> ShutdownScript {
	ShutdownScript::new_p2wpkh(&WPubkeyHash::hash(&[n]))
}

fn pays(tx: &Transaction, to: &ShutdownScript) -> bool {
	let spk = to.clone().into_inner();
	tx.output.iter().any(|o| o.script_pubkey == spk)
}

fn wallet_config(fixed_at_the_opening: bool) -> UserConfig {
	// the test tools' own settings (as the provider's side has them), and the one this file is about
	let mut c = test_default_channel_config();
	c.channel_handshake_config.commit_upfront_shutdown_pubkey = fixed_at_the_opening;
	c
}

fn do_close(fixed_at_the_opening: bool, wallet_starts: bool, wallet_opens: bool) {
	let user_cfgs = [Some(wallet_config(fixed_at_the_opening)), None];
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let wallet_signer = &chanmon_cfgs[0].keys_manager;

	let at_the_opening = address(1);
	let at_the_close = address(2);
	if fixed_at_the_opening {
		// the old way: the one address this channel will ever ask for
		wallet_signer.expect(OnGetShutdownScriptpubkey { returns: at_the_opening.clone() });
	} else {
		// the list is made empty: an ask during the opening would panic
		wallet_signer.expect(OnGetShutdownScriptpubkey { returns: address(9) });
		let _ = wallet_signer.get_shutdown_scriptpubkey().unwrap();
	}
	// 100,000 sats from the provider, 40,000 of them the wallet's — so the close has an output for the wallet
	// (when the wallet opens it — the open a pool pays for, or its own coins — the 100,000 are the wallet's and 40,000 go to the provider)
	let chan = if wallet_opens {
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 40_000_000)
	} else {
		create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 40_000_000)
	};
	if !fixed_at_the_opening {
		wallet_signer.expect(OnGetShutdownScriptpubkey { returns: at_the_close.clone() });
	}

	// the helper takes the side that opened the channel first; its last word says whether the OTHER side begins
	let (_, _, closing_tx) = if wallet_opens {
		close_channel(&nodes[0], &nodes[1], &chan.2, chan.3.clone(), !wallet_starts)
	} else {
		close_channel(&nodes[1], &nodes[0], &chan.2, chan.3.clone(), wallet_starts)
	};
	let _ = nodes[0].node.get_and_clear_pending_events();
	let _ = nodes[1].node.get_and_clear_pending_events();
	if !fixed_at_the_opening {
		// the address chosen at the close is written into the wallet's record of the channel at that moment:
		// exactly one write (a channel of the old way has it there since its opening, and writes nothing now)
		check_added_monitors(&nodes[0], 1);
	}

	if fixed_at_the_opening {
		assert!(pays(&closing_tx, &at_the_opening), "a channel opened the old way pays the address fixed at its opening");
		assert!(!pays(&closing_tx, &at_the_close));
	} else {
		assert!(pays(&closing_tx, &at_the_close), "the close pays the address the signer handed out when the close began");
		assert!(!pays(&closing_tx, &at_the_opening));
		assert!(!pays(&closing_tx, &address(9)));
	}
	// (the test signer panics when it is dropped with an address listed and never asked for, and when it is asked
	// for one more than was listed: each address above was asked for exactly once, at the moment the test says)
}

#[test]
fn lij_close_address_is_asked_for_at_the_close_wallet_starts() {
	do_close(false, true, false);
}

#[test]
fn lij_close_address_is_asked_for_at_the_close_provider_starts() {
	do_close(false, false, false);
}

#[test]
fn lij_close_address_fixed_at_the_opening_stays() {
	do_close(true, true, false);
	do_close(true, false, false);
	do_close(true, true, true);
}

#[test]
fn lij_close_address_of_a_channel_the_wallet_opened_is_asked_for_at_the_close() {
	// the open a pool pays for (Mix, From → Channel) and the open the wallet's own coins pay for
	do_close(false, true, true);
	do_close(false, false, true);
}

#[test]
fn lij_close_by_force_does_not_ask_for_a_close_address() {
	let user_cfgs = [Some(wallet_config(false)), None];
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let wallet_signer = &chanmon_cfgs[0].keys_manager;
	// the list is made empty for the whole test: any ask for a close address panics
	wallet_signer.expect(OnGetShutdownScriptpubkey { returns: address(9) });
	let _ = wallet_signer.get_shutdown_scriptpubkey().unwrap();

	// 100,000 sats from the provider, 40,000 of them the wallet's
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 40_000_000);
	let provider_id = nodes[1].node.get_our_node_id();
	nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &provider_id, "the kit's CLOSE".to_owned()).unwrap();
	check_closed_broadcast!(nodes[0], true);
	let _ = nodes[0].node.get_and_clear_pending_events();
	nodes[0].chain_monitor.added_monitors.lock().unwrap().clear();

	let close = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(close.len(), 1, "the wallet's own commitment transaction, and nothing else");
	mine_transaction(&nodes[0], &close[0]);
	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32);

	let mut delayed = 0;
	for ev in nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events() {
		if let Event::SpendableOutputs { outputs, .. } = ev {
			for o in outputs {
				match o {
					SpendableOutputDescriptor::DelayedPaymentOutput(_) => delayed += 1,
					SpendableOutputDescriptor::StaticOutput { .. } => panic!("a close by force paid a fixed address"),
					_ => {},
				}
			}
		}
	}
	assert_eq!(delayed, 1, "the wallet's balance is the delayed output — collected after the delay, with the 12 words");

	// the provider's side of the same close, so the test ends clean
	mine_transaction(&nodes[1], &close[0]);
	check_closed_broadcast!(nodes[1], true);
	nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
	let _ = nodes[1].node.get_and_clear_pending_events();
	let _ = nodes[1].tx_broadcaster.txn_broadcast();
	let _ = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
}
