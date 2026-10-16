//! One phone's part of one attempt (tatara-engine-r1 "The states"; the NIP's flow; review r1 §5 S1–S10). A pure state
//! machine: messages in, messages and actions out. The page carries the messages (the relay's WebSocket; the payout
//! through the forwarder), answers coin checks, saves the attempt record, and drives time with `Input::Tick`.
//!
//! Joined → Inputs (ours posted) → [Channel — a channel pool only (v0.10 §6.2, Phase 1b): the page opens a channel of
//! the pool size with the provider and hands back its funding script, the payout] → Payouts (every registration in and
//! every coin checked; ours sent through the forwarder) → View (every payout in; the transactions built, checked — S4,
//! S5, S10, the fee limit — and our view hash and nonces posted; a channel pool: the exit paying our channel named for
//! the page, which hands LDK that outpoint) → Signing (every view equal — S3; our partial signatures posted) → Funding
//! (every exit signed and verified — P7 names a bad signer; the record saved, our coins re-checked unspent — S5, and in
//! a channel pool the channel saved with the provider's first-commitment signature — §6.3.3) → FundingSigned (our
//! funding signature posted; the phone's part ends, v0.10 §5.5). Any stop before FundingSigned: nothing moved.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, ensure, Context, Result};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use joinstr_v2::funding::{ownership_msg, prove, sign_input, verify_proof};
use joinstr_v2::keys::{point_from_hex, PoolKeys};
use joinstr_v2::msg::{ChangeMsg, Envelope, InputMsg, Msg, WitnessMsg};
use joinstr_v2::pool::{build, check_input_registrations, payout_msg, InputRegistration, Params, Payout, PayoutType, PoolTxs};
use joinstr_v2::ring::{sign as ring_sign, Ring};
use joinstr_v2::sign::{aggregate, attach, exit_messages, make_nonces, nonce_from_hex, nonce_hex, partial_sign, psig_from_hex, psig_hex, ExitMessage, ExitNonces};
use musig2::secp::{Point, Scalar};
use musig2::{PartialSignature, PubNonce};

use super::caps;
use super::checks::{mine_in_funding, my_payout_once, same_as_rederived, scripts_apart};
use super::rederive::{rederive, Member};
use super::tagged;

/// This phone's part, fixed when it joins.
pub struct MyPart {
    /// The coins it puts in, with their keys (P2WPKH or P2TR key path).
    pub coins: Vec<(OutPoint, TxOut, SecretKey)>,
    pub change: Option<TxOut>,
    /// Its chain tip (the registration's height; the 100-block locktime rule).
    pub tip: u32,
    /// Its payout: the next unused m/86 address's script (v0.10 §5.2) — or None in a channel pool (§6.2): the payout is
    /// the channel's funding script, given by the page once the channel is opened (`Input::PayoutGiven`).
    pub payout: Option<ScriptBuf>,
    /// The nostr key that authors this phone's pool messages (x-only).
    pub session: [u8; 32],
    /// Fresh secret keys for this attempt only (v0.10 §8 rule 1).
    pub musig: Scalar,
    pub ring: Scalar,
    /// 32 fresh random bytes from the engine's source; every random byte of the attempt is derived from them (P4).
    pub entropy: [u8; 32],
    /// The fee rate shown when the person joined (sat/vB) — the fee limit's base (v0.10 §8.7).
    pub rate_at_join: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Inputs,
    /// A channel pool: registration is complete and the page is opening the channel (§6.2.1).
    Channel,
    Payouts,
    View,
    Signing,
    Funding,
    FundingSigned,
    Stopped,
}

/// What the page does next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Post on the pool's relay under this phone's session key.
    Post(String),
    /// Send through the forwarding provider under a one-time key (the payout registration, v0.10 §5.1).
    PostPayout(String),
    /// Check these coins exist, are confirmed and unspent (v0.10 §7) and answer with `Input::CoinsChecked`.
    CheckCoins(Vec<(OutPoint, TxOut)>),
    /// Save the attempt record (encrypted at rest, v0.10 §9) and answer with `Input::RecordSaved` — before the funding
    /// signature (§8 rule 3).
    SaveRecord(Record),
    /// The phone's part is done: its funding signature is posted.
    FundingSigned,
    /// The attempt stopped; nothing of this phone's moved. `named` lists the session keys the rules can blame (P7, S1);
    /// empty at the anonymous step (S2, S3).
    Stopped { reason: String, named: Vec<[u8; 32]> },
    /// A channel pool (v0.10 §6.2.1): registration is complete — open a channel of exactly `sats` with the provider
    /// (static remote key, no anchors) and answer with `Input::PayoutGiven` (its funding script, from both funding keys).
    OpenChannel { sats: u64 },
    /// A channel pool (§6.2.2): the exit that pays this phone's channel, checked — exactly its script, exactly the pool
    /// size, at this output. Hand LDK the outpoint (unsafe_manual_funding_transaction_generated) and, once the provider's
    /// first-commitment signature is saved with the channel (§6.3.3), answer with `Input::ChannelSaved`.
    FundChannel { txid: String, vout: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub funding: Transaction,
    pub exits: Vec<Transaction>,
    pub payout: ScriptBuf,
    pub inputs: Vec<OutPoint>,
    /// A channel pool: the payout is this phone's channel's funding (§6.2) — the exit paying it is the channel's funding
    /// transaction; the channel id is derived from that outpoint.
    pub channel: bool,
    /// v333 (S59): the pool's fee rate (milli-sat per vB, the pool event's), kept so a speed-up can price the chain.
    pub rate_milli: u64,
    /// v340: the funding's prevouts, in input order — the phone verifies every member's funding signature against them.
    pub prevouts: Vec<TxOut>,
}

pub enum Input {
    /// A pool message (the nostr event's id and signature already checked by the wire layer, §15.5.1), with the key
    /// that authored it.
    Msg { from: [u8; 32], json: String },
    /// The answer to `Action::CheckCoins`: the coins found bad (an empty list: all good), and — v328 (DP's first real
    /// pools, 2026-10-13) — the coins NO provider answered for. No answer says nothing about a coin: the attempt stops
    /// without naming anyone (a phone that cannot reach a coin-check answerer is the one with the problem).
    CoinsChecked { bad: Vec<OutPoint>, unanswered: Vec<OutPoint> },
    RecordSaved,
    /// The answer to `Action::OpenChannel`: the channel's funding script (P2WSH, both funding keys).
    PayoutGiven(ScriptBuf),
    /// The answer to `Action::FundChannel`: the channel is saved with the provider's signature.
    ChannelSaved,
    /// A channel pool: the channel could not be opened, funded or kept (the provider refused, closed it, or the wallet
    /// could not reach it) — the attempt stops, nothing moved, nobody named.
    ChannelFailed(String),
    Tick { now: u64 },
    /// v339 (DP 2026-10-14 22:29 "can one leave a public pool before the hour is up?"): this phone leaves on purpose
    /// before its coin signature — the attempt stops (an abort goes to the members if this phone had registered: the
    /// room cannot go on without its registration, so they learn at once instead of waiting out the clock), nothing has
    /// moved, nobody is named. After the coin signature there is no leaving (the exit is signed; the record watches).
    Leave,
}

/// Seconds each phase may take before the attempt stops.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub phase_s: u64,
}

pub struct Attempt {
    id: String,
    params: Params,
    network: Network,
    d: u64,
    rate_milli: u64,
    me: MyPart,
    aux_n: u32,
    phase: Phase,
    /// The phase the deadline belongs to: a new phase's clock starts at the first tick it sees.
    clock_phase: Phase,
    deadline: u64,
    timeouts: Timeouts,
    regs: BTreeMap<[u8; 32], (InputRegistration, String)>,
    coins_asked: bool,
    payouts: Vec<(ScriptBuf, u8)>,
    images: HashMap<String, (ScriptBuf, String)>,
    built: Option<PoolTxs>,
    keys: Option<PoolKeys>,
    msgs: Option<Vec<ExitMessage>>,
    my_nonces: Option<ExitNonces>,
    my_view: Option<[u8; 32]>,
    views: HashMap<[u8; 32], [u8; 32]>,
    nonces: HashMap<[u8; 32], (Vec<PubNonce>, String)>,
    psigs: HashMap<[u8; 32], (Vec<PartialSignature>, String)>,
    record_saved: bool,
    recheck_ok: bool,
    /// A channel pool: the channel is saved with the provider's signature (§6.3.3) — the funding signature waits for it.
    channel_saved: bool,
    /// Coins this phone refuses (v0.10 §8 rule 2; the NIP's "Failure handling"): coins of sessions that stalled or sent
    /// a bad message in an earlier attempt.
    refused: HashSet<OutPoint>,
    /// v335 (S59, Phase 2 — the compatibility proof): a public pool, with other joinstr clients at the table. They send
    /// no `lij_view`, so S3's check covers the members who sent one (every LiJ member) and signing waits for every
    /// member's nonces only; a partial signature that does not verify then names no one — a public member never
    /// confirmed its view, so a bad signature cannot be told from a different view of the pool (the mis-blame S3 was
    /// written against, review finding 2). A LiJ pool keeps S3 whole: a view from every member, or no signing.
    public: bool,
}

fn post(msg: Msg) -> Action {
    Action::Post(Envelope::json(msg))
}

const VIEW_TYPE: &str = "lij_view";

impl Attempt {
    /// Join: post this phone's input registration. `params` comes from `caps::phase1_pool`.
    pub fn new(params: Params, network: Network, me: MyPart, now: u64, timeouts: Timeouts) -> Result<(Self, Vec<Action>)> {
        ensure!(params.classes.len() == 1, "one denomination");
        caps::registration_inputs(me.coins.len())?;
        let d = params.classes[0].amount;
        let mut a = Attempt {
            id: params.id.clone(),
            rate_milli: params.fee_rate_milli,
            params,
            network,
            d,
            me,
            aux_n: 0,
            phase: Phase::Inputs,
            clock_phase: Phase::Inputs,
            deadline: now + timeouts.phase_s,
            timeouts,
            regs: BTreeMap::new(),
            coins_asked: false,
            payouts: Vec::new(),
            images: HashMap::new(),
            built: None,
            keys: None,
            msgs: None,
            my_nonces: None,
            my_view: None,
            views: HashMap::new(),
            nonces: HashMap::new(),
            psigs: HashMap::new(),
            record_saved: false,
            recheck_ok: false,
            channel_saved: false,
            refused: HashSet::new(),
            public: false,
        };
        ensure!(a.me.payout.is_some() == (a.params.payout_type == PayoutType::P2tr), "a channel pool takes its payout from the channel; an on-chain pool brings its own");
        let msg = a.my_registration()?;
        Ok((a, vec![post(msg)]))
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    /// v336: the pool's number of people.
    pub fn peers(&self) -> usize {
        self.params.peers
    }

    /// v337: the registrations in so far (this phone's once the relay echoed it).
    pub fn registered(&self) -> usize {
        self.regs.len()
    }

    /// Refuse these coins (from earlier attempts' stops): a registration that carries one stops this attempt and names
    /// its session.
    pub fn refusing(mut self, coins: impl IntoIterator<Item = OutPoint>) -> Self {
        self.refused.extend(coins);
        self
    }

    /// v335: a public pool (other joinstr clients at the table) — see `public`.
    pub fn public(mut self, public: bool) -> Self {
        self.public = public;
        self
    }

    /// v338 (the clocks, DP 2026-10-14 21:39): the registration phase's own deadline — a public room fills while its
    /// announcement is open (the public code's join window, then one step for the last registrations), not within
    /// PHASE_S of this phone's own registration. Every later phase keeps the phase clock.
    pub fn first_phase_until(mut self, deadline: u64) -> Self {
        if self.phase == Phase::Inputs && deadline > self.deadline {
            self.deadline = deadline;
        }
        self
    }

    /// The coins registered by these sessions — what a stop's `named` sessions put in, to refuse in later pools.
    pub fn coins_of(&self, sessions: &[[u8; 32]]) -> Vec<OutPoint> {
        self.regs
            .iter()
            .filter(|(k, _)| sessions.contains(k))
            .flat_map(|(_, (r, _))| r.inputs.iter().map(|(op, _)| *op))
            .collect()
    }

    /// At a timeout, the registered sessions that did not send what this phase waits for (the NIP's "Failure handling":
    /// a session that does not send a message identifies its coins). Missing payouts name no one (they are anonymous).
    fn stalled(&self) -> Vec<[u8; 32]> {
        // v344 (review 2b #6): never this phone — its own nonces and signatures reach the machine only as the relay's
        // echo, and a relay that drops one echo must not make the phone refuse its own coin
        let me = self.me.session;
        match self.phase {
            Phase::View => self
                .regs
                .keys()
                .filter(|s| **s != me && ((!self.public && !self.views.contains_key(*s)) || !self.nonces.contains_key(*s)))   // v335: a public member owes no view
                .copied()
                .collect(),
            Phase::Signing => self.regs.keys().filter(|s| **s != me && !self.psigs.contains_key(*s)).copied().collect(),
            _ => vec![],
        }
    }

    fn aux(&mut self) -> [u8; 32] {
        self.aux_n += 1;
        tagged("lij/tatara/aux/v1", &[&self.me.entropy, &self.aux_n.to_le_bytes()])
    }

    fn my_registration(&mut self) -> Result<Msg> {
        let mut inputs = Vec::new();
        let coins: Vec<(OutPoint, TxOut, SecretKey)> = self.me.coins.clone();
        for (op, out, sk) in coins {
            let m = ownership_msg(&self.id, &self.me.session, &op);
            let aux = self.aux();
            inputs.push(InputMsg {
                txid: op.txid.to_string(),
                vout: op.vout,
                amount: out.value.to_sat(),
                script_pubkey: hex::encode(out.script_pubkey.as_bytes()),
                proof: prove(&sk, &out.script_pubkey, m, &aux)?,
            });
        }
        let change = match &self.me.change {
            Some(c) => Some(ChangeMsg {
                address: Address::from_script(&c.script_pubkey, self.network)?.to_string(),
                amount: c.value.to_sat(),
            }),
            None => None,
        };
        Ok(Msg::Inputs {
            musig_pubkey: hex::encode(self.me.musig.base_point_mul().serialize()),
            ring_pubkey: hex::encode(self.me.ring.base_point_mul().serialize()),
            inputs,
            change,
            height: self.me.tip,
            denomination: Some(self.d),
        })
    }

    /// Feed one event; get what to do next.
    pub fn on(&mut self, input: Input) -> Vec<Action> {
        if self.phase == Phase::Stopped || self.phase == Phase::FundingSigned {
            return vec![];
        }
        // v340 (S59 security review, finding 1): a message that fails to parse or check is NOT a reason to stop the pool
        // unless a REGISTERED member sent it — then it is that member's doing and it is named (its coin refused next
        // time, v0.10 §8 rule 2). Anything from a key that is not a registered session (a stranger holding the pool key
        // in a public room, a one-time payout key, random ciphertext that happens to decrypt) is ignored, as S1 says —
        // it used to stop every member's attempt with no one named: a free, unattributable kill switch.
        let from_msg = match &input { Input::Msg { from, .. } => Some(*from), _ => None };
        match self.step(input) {
            Ok(acts) => acts,
            Err(e) => match from_msg {
                Some(from) if self.regs.contains_key(&from) && from != self.me.session => self.stop(&e.to_string(), vec![from]),
                Some(_) => vec![],
                None => self.stop(&e.to_string(), vec![]),
            },
        }
    }

    /// v340 (finding 2): does this registered session own this funding input?
    pub fn owns(&self, session: &[u8; 32], op: &OutPoint) -> bool {
        self.regs.get(session).map_or(false, |(r, _)| r.inputs.iter().any(|(o, _)| o == op))
    }

    fn stop(&mut self, reason: &str, named: Vec<[u8; 32]>) -> Vec<Action> {
        self.phase = Phase::Stopped;
        self.my_nonces = None; // the secret nonces are dropped (r7 §8)
        let mut acts = Vec::new();
        if self.regs.contains_key(&self.me.session) {
            acts.push(post(Msg::Abort { reason: "stopped".into() })); // S7: our own text never carries detail
        }
        acts.push(Action::Stopped { reason: reason.to_string(), named });
        acts
    }

    fn enter(&mut self, p: Phase) {
        self.phase = p;
    }

    fn step(&mut self, input: Input) -> Result<Vec<Action>> {
        match input {
            Input::Tick { now } => {
                if self.clock_phase != self.phase {
                    self.clock_phase = self.phase.clone();
                    self.deadline = now + self.timeouts.phase_s;
                    return Ok(vec![]);
                }
                if now > self.deadline {
                    let named = self.stalled();
                    if self.phase == Phase::Funding && self.params.payout_type == PayoutType::P2wsh && !self.channel_saved && self.record_saved && self.recheck_ok {
                        return Ok(self.stop("the provider's channel signature did not arrive in time", vec![]));   // §6.2.4
                    }
                    if self.phase == Phase::Channel {
                        return Ok(self.stop("the channel could not be opened in time", vec![]));
                    }
                    return Ok(self.stop(&format!("timed out at {:?}", self.phase), named));
                }
                Ok(vec![])
            }
            Input::CoinsChecked { bad, unanswered } => self.on_coins(bad, unanswered),
            Input::RecordSaved => {
                if self.phase != Phase::Funding {
                    return Ok(vec![]);
                }
                self.record_saved = true;
                self.try_fund()
            }
            Input::PayoutGiven(spk) => {
                if self.phase != Phase::Channel {
                    return Ok(vec![]); // late or repeated
                }
                ensure!(spk.is_p2wsh(), "the channel's funding script is not P2WSH");
                self.me.payout = Some(spk);
                self.register_payout()
            }
            Input::ChannelSaved => {
                if self.params.payout_type != PayoutType::P2wsh || !matches!(self.phase, Phase::View | Phase::Signing | Phase::Funding) {
                    return Ok(vec![]);
                }
                self.channel_saved = true;
                if self.phase == Phase::Funding { self.try_fund() } else { Ok(vec![]) }
            }
            Input::ChannelFailed(why) => {
                if self.params.payout_type != PayoutType::P2wsh { return Ok(vec![]); }
                Ok(self.stop(&format!("the channel for this pool failed: {why}"), vec![]))
            }
            Input::Leave => {
                if matches!(self.phase, Phase::FundingSigned | Phase::Stopped) { return Ok(vec![]); }
                Ok(self.stop("you left the pool", vec![]))
            }
            Input::Msg { from, json } => self.on_msg(from, json),
        }
    }

    fn on_msg(&mut self, from: [u8; 32], json: String) -> Result<Vec<Action>> {
        caps::message_size(json.as_bytes())?;
        // our own view message (S3) — a LiJ pool's extension, parsed before joinstr's envelope
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            if v.get("type").and_then(|t| t.as_str()) == Some(VIEW_TYPE) {
                return self.on_view(from, &v);
            }
        }
        let env = Envelope::parse_strict(&json)?;
        let registered = self.regs.contains_key(&from);
        match env.msg {
            Msg::Inputs { .. } => self.on_inputs(from, env.msg, json),
            Msg::Output { address, ring_sig, priority, denomination } => self.on_output(address, ring_sig, priority, denomination, json),
            Msg::Nonces { offset, nonces } if registered => self.on_nonces(from, offset, nonces, json),
            Msg::PartialSigs { offset, sigs } if registered => self.on_psigs(from, offset, sigs, json),
            Msg::FundingSigs { .. } => Ok(vec![]), // others' witnesses: the broadcaster's business, not this machine's
            Msg::Abort { .. } if registered && from != self.me.session => {
                // S7: a peer's reason is never shown; the attempt is over for everyone
                Ok(self.stop("a member stopped the pool", vec![]))
            }
            _ => Ok(vec![]), // S1: anything else, or from a key that is not registered — ignored
        }
    }

    fn on_inputs(&mut self, from: [u8; 32], msg: Msg, json: String) -> Result<Vec<Action>> {
        if let Some((_, seen)) = self.regs.get(&from) {
            ensure!(*seen == json, "a member sent two different registrations");
            return Ok(vec![]);
        }
        if self.phase != Phase::Inputs || self.regs.len() >= self.params.peers {
            return Ok(vec![]); // S1: registration is closed — late inputs are ignored
        }
        let Msg::Inputs { musig_pubkey, ring_pubkey, inputs, change, height, denomination } = msg else { unreachable!() };
        ensure!(denomination.unwrap_or(self.d) == self.d, "another denomination");
        caps::registration_inputs(inputs.len())?;
        let mut ins = Vec::new();
        for i in &inputs {
            let op0 = OutPoint::new(Txid::from_str(&i.txid).context("bad txid")?, i.vout);
            if self.refused.contains(&op0) {
                return Ok(self.stop("a member brought a coin refused after an earlier pool", vec![from]));
            }
            ensure!(i.txid.len() == 64 && i.txid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "bad txid");
            let op = OutPoint::new(Txid::from_str(&i.txid)?, i.vout);
            let spk = ScriptBuf::from_bytes(joinstr_v2::util::strict_hex_range(&i.script_pubkey, 22, 34)?);
            ensure!(spk.is_p2wpkh() || spk.is_p2tr(), "an input is neither P2WPKH nor P2TR");
            verify_proof(&spk, ownership_msg(&self.id, &from, &op), &i.proof).context("ownership proof")?;
            ins.push((op, TxOut { value: Amount::from_sat(i.amount), script_pubkey: spk }));
        }
        let change = match change {
            Some(c) => Some(TxOut {
                value: Amount::from_sat(c.amount),
                script_pubkey: Address::from_str(&c.address)?.require_network(self.network)?.script_pubkey(),
            }),
            None => None,
        };
        let reg = InputRegistration {
            session: from,
            amount: self.d,
            musig: point_from_hex(&musig_pubkey)?,
            ring: point_from_hex(&ring_pubkey)?,
            inputs: ins,
            change,
            height,
        };
        self.regs.insert(from, (reg, json));
        if self.regs.len() < self.params.peers {
            return Ok(vec![]);
        }
        // registration complete: the NIP's checks, then every other member's coins checked through the coin check
        let regs: Vec<InputRegistration> = self.regs.values().map(|(r, _)| r.clone()).collect();
        check_input_registrations(&self.params, &regs)?;
        // v344 (review 2b #3): a room that filled without this phone (a key holder's extra registrations) stops naming
        // NO ONE — an Err here would have named the Nth registrant, an honest member as often as not
        if !self.regs.contains_key(&self.me.session) {
            return Ok(self.stop("the pool closed without this phone", vec![]));
        }
        let others: Vec<(OutPoint, TxOut)> = regs.iter().filter(|r| r.session != self.me.session).flat_map(|r| r.inputs.clone()).collect();
        self.coins_asked = true;
        Ok(vec![Action::CheckCoins(others)])
    }

    fn on_coins(&mut self, bad: Vec<OutPoint>, unanswered: Vec<OutPoint>) -> Result<Vec<Action>> {
        if self.phase == Phase::Funding {
            // the re-check of our own coins just before the funding signature (S5)
            ensure!(unanswered.is_empty(), "my coin could not be re-checked: no provider answered");
            ensure!(bad.is_empty(), "one of my coins is no longer spendable");
            self.recheck_ok = true;
            return self.try_fund();
        }
        if self.phase != Phase::Inputs || !self.coins_asked {
            return Ok(vec![]); // a repeated or late answer changes nothing
        }
        if !unanswered.is_empty() {
            // v328: this phone could not get the checks made — nobody's coin is to blame
            return Ok(self.stop(&format!("the coin checks got no answer from any provider ({} coin(s))", unanswered.len()), vec![]));
        }
        if !bad.is_empty() {
            let named: Vec<[u8; 32]> = self
                .regs
                .iter()
                .filter(|(_, (r, _))| r.inputs.iter().any(|(op, _)| bad.contains(op)))
                .map(|(k, _)| *k)
                .collect();
            return Ok(self.stop("a member's coin failed the coin check", named));
        }
        if self.me.payout.is_none() {
            // a channel pool (§6.2.1): the channel is opened now — not at Join, not at the wake — and its funding script
            // is the payout
            self.enter(Phase::Channel);
            return Ok(vec![Action::OpenChannel { sats: self.d }]);
        }
        self.register_payout()
    }

    /// Our payout, ring-signed over the members' ring keys, through the forwarder.
    fn register_payout(&mut self) -> Result<Vec<Action>> {
        let payout = self.me.payout.clone().context("no payout")?;
        let mut ring: Vec<Point> = self.regs.values().map(|(r, _)| r.ring).collect();
        ring.sort_by_key(|p| p.serialize());
        let m = payout_msg(&self.id, 0, self.d, &payout);
        let aux = self.aux();
        let sig = ring_sign(&ring, self.me.ring, &m, &aux)?;
        let address = Address::from_script(&payout, self.network)?.to_string();
        self.enter(Phase::Payouts);
        Ok(vec![Action::PostPayout(Envelope::json(Msg::Output { address, ring_sig: sig, priority: 0, denomination: Some(self.d) }))])
    }

    fn on_output(&mut self, address: String, ring_sig: joinstr_v2::ring::RingSig, priority: u8, denomination: Option<u64>, json: String) -> Result<Vec<Action>> {
        if !matches!(self.phase, Phase::Payouts | Phase::Inputs | Phase::Channel) {
            return Ok(vec![]);
        }
        if self.regs.len() < self.params.peers {
            return Ok(vec![]); // payouts before registration closed are not counted
        }
        ensure!(priority == 0, "Phase 1 payouts have priority 0");
        ensure!(denomination.unwrap_or(self.d) == self.d, "another denomination");
        let spk = Address::from_str(&address)?.require_network(self.network)?.script_pubkey();
        // P1: every payout is what the pool declared — P2TR, or a channel's 2-of-2 (P2WSH) in a channel pool
        match self.params.payout_type {
            PayoutType::P2tr => ensure!(spk.is_p2tr(), "a payout that is not P2TR"),
            PayoutType::P2wsh => ensure!(spk.is_p2wsh(), "a payout that is not a channel's P2WSH"),
        }
        let mut ring: Vec<Point> = self.regs.values().map(|(r, _)| r.ring).collect();
        ring.sort_by_key(|p| p.serialize());
        let image = Ring::new(&ring)?.verify(&payout_msg(&self.id, 0, self.d, &spk), &ring_sig)?;
        let key = image.to_string();
        if let Some((seen, seen_json)) = self.images.get(&key) {
            if *seen_json == json {
                return Ok(vec![]);
            }
            // S2: one key image, two different payouts — stop, blame no one
            let _ = seen;
            return Ok(self.stop("two payouts under one key image", vec![]));
        }
        ensure!(!self.payouts.iter().any(|(s, _)| *s == spk), "a payout address registered twice");
        self.images.insert(key, (spk.clone(), json));
        self.payouts.push((spk, 0));
        if self.payouts.len() < self.params.peers {
            return Ok(vec![]);
        }
        ensure!(self.phase == Phase::Payouts, "every payout is in, but ours is not registered yet");
        self.build_and_check()
    }

    fn members(&self) -> Vec<Member> {
        self.regs
            .values()
            .map(|(r, _)| Member { musig: r.musig.serialize(), inputs: r.inputs.clone(), change: r.change.clone(), height: r.height })
            .collect()
    }

    fn build_and_check(&mut self) -> Result<Vec<Action>> {
        let regs: Vec<InputRegistration> = self.regs.values().map(|(r, _)| r.clone()).collect();
        let members = self.members();
        // the fee limit (v0.10 §8.7)
        let rate = self.rate_milli / 1000;
        ensure!(caps::within_fee_limit(rate, self.me.rate_at_join, u64::MAX), "fees rose since you joined");
        // S10 our own re-derivation; S4 scripts apart; S5 the build is exactly it, my payout once, my coins as registered
        let r = rederive(&self.id, self.d, self.rate_milli, &members, &self.payouts, self.me.tip)?;
        let pay: Vec<ScriptBuf> = self.payouts.iter().map(|(s, _)| s.clone()).collect();
        scripts_apart(&r, &members, &pay)?;
        let keys = PoolKeys::new(regs.iter().map(|r| r.musig).collect())?;
        let payouts: Vec<Payout> = self.payouts.iter().map(|(s, p)| Payout { script: s.clone(), amount: self.d, priority: *p }).collect();
        let built = build(&self.params, &regs, &payouts, &keys)?;
        same_as_rederived(&built, &r)?;
        let my_payout = self.me.payout.clone().context("no payout")?;
        my_payout_once(&built.exits, &my_payout, self.d)?;
        let me = members.iter().zip(regs.iter()).find(|(_, r)| r.session == self.me.session).map(|(m, _)| m.clone()).context("me")?;
        mine_in_funding(&built.funding, &me)?;
        // a channel pool (§6.2.2): the exit that pays our channel — exactly its script, exactly the size, at this output
        let fund_channel = if self.params.payout_type == PayoutType::P2wsh {
            let (exit, vout) = built
                .exits
                .iter()
                .find_map(|e| e.output.iter().position(|o| o.script_pubkey == my_payout && o.value.to_sat() == self.d).map(|v| (e, v as u32)))
                .context("no exit pays my channel exactly the pool size")?;
            Some(Action::FundChannel { txid: exit.compute_txid().to_string(), vout })
        } else { None };
        // S3: a hash of this phone's view, posted with its nonces
        let msgs = exit_messages(&keys, &built)?;
        let view = self.view_hash(&built, &msgs);
        let aux = self.aux();
        let (secs, pubs) = make_nonces(self.me.musig, &keys, &msgs, &self.id, &aux)?;
        self.my_nonces = Some(secs);
        self.my_view = Some(view);
        self.built = Some(built);
        self.keys = Some(keys);
        self.msgs = Some(msgs);
        self.enter(Phase::View);
        let view_json = serde_json::json!({ "version": "2", "type": VIEW_TYPE, "hash": hex::encode(view) }).to_string();
        let mut acts = vec![Action::Post(view_json), post(Msg::Nonces { offset: 0, nonces: pubs.iter().map(nonce_hex).collect() })];
        acts.extend(fund_channel);
        Ok(acts)
    }

    fn view_hash(&self, built: &PoolTxs, msgs: &[ExitMessage]) -> [u8; 32] {
        let mut sessions: Vec<[u8; 32]> = self.regs.keys().copied().collect();
        sessions.sort();
        let mut rings: Vec<[u8; 33]> = self.regs.values().map(|(r, _)| r.ring.serialize()).collect();
        rings.sort();
        let mut parts: Vec<Vec<u8>> = vec![self.id.as_bytes().to_vec(), built.funding.compute_txid().to_string().into_bytes()];
        parts.extend(msgs.iter().map(|m| m.msg().to_vec()));
        parts.extend(sessions.iter().map(|s| s.to_vec()));
        parts.extend(rings.iter().map(|r| r.to_vec()));
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        tagged("lij/tatara/view/v1", &refs)
    }

    fn on_view(&mut self, from: [u8; 32], v: &serde_json::Value) -> Result<Vec<Action>> {
        if !self.regs.contains_key(&from) {
            return Ok(vec![]); // S1
        }
        let o = v.as_object().context("view")?;
        ensure!(o.len() == 3 && o.get("version").and_then(|x| x.as_str()) == Some("2"), "bad view message");
        let h = joinstr_v2::util::strict_hex(o.get("hash").and_then(|x| x.as_str()).unwrap_or(""), 32)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&h);
        if let Some(seen) = self.views.get(&from) {
            ensure!(*seen == hash, "a member sent two different views");
            return Ok(vec![]);
        }
        self.views.insert(from, hash);
        self.try_sign()
    }

    fn on_nonces(&mut self, from: [u8; 32], offset: usize, nonces: Vec<String>, json: String) -> Result<Vec<Action>> {
        if let Some((_, seen)) = self.nonces.get(&from) {
            ensure!(*seen == json, "a member sent two different nonce messages");
            return Ok(vec![]);
        }
        ensure!(offset == 0, "nonces in parts are not used by LiJ pools");
        let exits = self.msgs.as_ref().map_or(self.params.peers - 1, |m| m.len());
        caps::one_per_exit(nonces.len(), exits)?;
        let parsed = nonces.iter().map(|n| nonce_from_hex(n)).collect::<Result<Vec<_>>>()?;
        self.nonces.insert(from, (parsed, json));
        self.try_sign()
    }

    fn try_sign(&mut self) -> Result<Vec<Action>> {
        let n = self.params.peers;
        if self.phase != Phase::View || (!self.public && self.views.len() < n) || self.nonces.len() < n {
            return Ok(vec![]);
        }
        // S3: every member's view must be ours (v335: in a public pool, every view that came — the public members send none)
        let mine = self.my_view.context("no view")?;
        if self.views.values().any(|v| *v != mine) {
            return Ok(self.stop("the members do not see the same pool", vec![]));
        }
        let secs = self.my_nonces.take().context("my nonces were used")?;
        let signers = self.signer_order();
        let order: Vec<&[PubNonce]> = signers.iter().map(|s| self.nonces[s].0.as_slice()).collect();
        let keys = self.keys.as_ref().context("keys")?;
        let msgs = self.msgs.as_ref().context("msgs")?;
        let psigs = partial_sign(self.me.musig, keys, msgs, secs, &order)?;
        self.enter(Phase::Signing);
        Ok(vec![post(Msg::PartialSigs { offset: 0, sigs: psigs.iter().map(psig_hex).collect() })])
    }

    /// The registered sessions in a fixed order (the nonce aggregation does not depend on it, but every list must line
    /// up with its signer).
    fn signer_order(&self) -> Vec<[u8; 32]> {
        self.regs.keys().copied().collect()
    }

    fn on_psigs(&mut self, from: [u8; 32], offset: usize, sigs: Vec<String>, json: String) -> Result<Vec<Action>> {
        if let Some((_, seen)) = self.psigs.get(&from) {
            ensure!(*seen == json, "a member sent two different partial signatures");
            return Ok(vec![]);
        }
        ensure!(offset == 0, "signatures in parts are not used by LiJ pools");
        let exits = self.msgs.as_ref().map_or(self.params.peers - 1, |m| m.len());
        caps::one_per_exit(sigs.len(), exits)?;
        let parsed = sigs.iter().map(|s| psig_from_hex(s)).collect::<Result<Vec<_>>>()?;
        self.psigs.insert(from, (parsed, json));
        if self.phase != Phase::Signing || self.psigs.len() < self.params.peers {
            return Ok(vec![]);
        }
        let keys = self.keys.as_ref().context("keys")?;
        let msgs = self.msgs.as_ref().context("msgs")?;
        let order = self.signer_order();
        let signers: Vec<(Point, &[PubNonce], &[PartialSignature])> = order
            .iter()
            .map(|s| (self.regs[s].0.musig, self.nonces[s].0.as_slice(), self.psigs[s].0.as_slice()))
            .collect();
        let sigs = match aggregate(keys, msgs, &signers) {
            Ok(s) => s,
            Err(e) => {
                // P7 names every bad signer by its musig key; map them back to session keys
                let text = e.to_string();
                let named: Vec<[u8; 32]> = order.iter().filter(|s| text.contains(&self.regs[*s].0.musig.to_string())).copied().collect();
                if self.public {
                    return Ok(self.stop("a member's partial signature is invalid", vec![]));   // v335: no view from the public members — blame no one
                }
                return Ok(self.stop("a member's partial signature is invalid", named));
            }
        };
        let mut built = self.built.take().context("built")?;
        attach(&mut built, &sigs)?;
        let record = Record {
            id: self.id.clone(),
            funding: built.funding.clone(),
            exits: built.exits.clone(),
            payout: self.me.payout.clone().context("no payout")?,
            inputs: self.me.coins.iter().map(|(op, _, _)| *op).collect(),
            channel: self.params.payout_type == PayoutType::P2wsh,
            rate_milli: self.rate_milli,
            prevouts: built.funding_prevouts.clone(),
        };
        let mine: Vec<(OutPoint, TxOut)> = self.me.coins.iter().map(|(op, o, _)| (*op, o.clone())).collect();
        self.built = Some(built);
        self.enter(Phase::Funding);
        // write before signing (§8 rule 3), and our coins re-checked unspent just before the funding signature (S5)
        Ok(vec![Action::SaveRecord(record), Action::CheckCoins(mine)])
    }

    fn try_fund(&mut self) -> Result<Vec<Action>> {
        // a channel pool signs its coin only once the channel is saved with the provider's signature (§6.2.3, §6.3.3)
        let channel_ok = self.params.payout_type == PayoutType::P2tr || self.channel_saved;
        if !(self.record_saved && self.recheck_ok && channel_ok) {
            return Ok(vec![]);
        }
        let built = self.built.as_ref().context("built")?;
        let tx = built.funding.clone();
        let prevouts = built.funding_prevouts.clone();
        let coins: Vec<(OutPoint, TxOut, SecretKey)> = self.me.coins.clone();
        let mut witnesses = Vec::new();
        for (op, _, sk) in &coins {
            let idx = tx.input.iter().position(|i| i.previous_output == *op).ok_or_else(|| anyhow!("my input is not in the funding"))?;
            let aux = self.aux();
            let w = sign_input(&tx, idx, &prevouts, sk, &aux)?;
            witnesses.push(WitnessMsg { txid: op.txid.to_string(), vout: op.vout, witness: w.iter().map(hex::encode).collect() });
        }
        self.phase = Phase::FundingSigned;
        Ok(vec![post(Msg::FundingSigs { witnesses }), Action::FundingSigned])
    }

    /// The funding transaction as built (no witnesses) — for the record and the broadcaster.
    pub fn funding_hex(&self) -> Option<String> {
        self.built.as_ref().map(|b| serialize_hex(&b.funding))
    }
}
