// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Per-peer session state machine — `spec/phreatic-v1.md` §2.4, §10.
//!
//! Drives a peer from idle through handshake to an established session, then
//! through rekeying and expiry. **Sans-io**: it consumes datagrams and a clock
//! reading and emits [`Action`]s; it never touches a socket, a timer, or an
//! RNG. Randomness arrives as caller-supplied seeds.
//!
//! That is what makes the deterministic simulation harness possible — the same
//! code runs against a real socket and against a virtual network with injected
//! loss and reordering, and a failing seed replays exactly.

use std::sync::Arc;

use karst_crypto::{SuiteId, SuitePolicy};
use karst_noise::handshake::{
    initiate, respond, HandshakeError, Initiator, InitiatorRandomness, PeerPublic,
    ResponderRandomness, SessionParams, StaticKeys,
};
use karst_noise::symmetric::TransportKeys;
use karst_noise::transport::{Role, TransportError, TransportSession, REJECT_AFTER_MS};
use karst_proto::dos::{mac1_key, mac2_key, open_cookie_reply, FragMacKey};
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler, SourceKey};
use karst_proto::{fragment, split_datagram, FragmentHeader, MessageType};

/// First handshake retransmission delay — §10, `HANDSHAKE_RETRY_INITIAL`.
pub const RETRY_INITIAL_MS: u64 = 300;

/// Ceiling on the retransmission interval — §10, `HANDSHAKE_RETRY_MAX`.
///
/// Without a cap, doubling from 300 ms reaches minutes within a handful of
/// attempts, so a bounded give-up window yields very few tries. Measured in the
/// simulation harness: uncapped doubling allowed only **6 attempts in 15 s**,
/// and 2 of 25 seeds failed to connect through 40% loss. Capping at 5 s — the
/// same interval `WireGuard` uses — gives ~20 attempts in 90 s.
pub const RETRY_MAX_MS: u64 = 5_000;

/// Abandon a handshake after this long and return to idle — §10.
///
/// 90 s matches `WireGuard`'s `REKEY_ATTEMPT_TIME`. At 40% per-datagram loss each
/// attempt succeeds with probability 0.6² = 36%, so ~20 attempts leave a
/// failure probability near 1e-4 rather than 7%.
pub const HANDSHAKE_GIVE_UP_MS: u64 = 90_000;

/// What the caller should do. The session never acts on the world itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Transmit this datagram to the peer.
    Send(Vec<u8>),
    /// A session is now established and usable.
    Established,
    /// The peer's payload, recovered from a transport message.
    Deliver(Vec<u8>),
    /// The handshake failed or the session expired; the peer is idle again.
    Closed(CloseReason),
}

/// Why a session ended. Local diagnostics only — never sent on the wire (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// No response within `HANDSHAKE_GIVE_UP_MS`.
    HandshakeTimeout,
    /// Past `REJECT_AFTER_TIME` (§10).
    Expired,
    /// A peer message failed authentication.
    Rejected,
}

/// A handshake in flight, retransmitting on a capped backoff.
struct Handshake {
    initiator: Box<Initiator>,
    msg1: Vec<u8>,
    started_ms: u64,
    next_retry_ms: u64,
    backoff_ms: u64,
}

impl Handshake {
    /// Whether the give-up window has passed — §13.5.
    fn abandoned(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_ms) >= HANDSHAKE_GIVE_UP_MS
    }

    /// Whether a retransmission is due, advancing the backoff if so.
    fn retry_due(&mut self, now_ms: u64) -> bool {
        if now_ms < self.next_retry_ms {
            return false;
        }
        // Exponential backoff, capped. Real deployments MUST jitter this to
        // avoid synchronised retry storms after a shared outage; the simulation
        // keeps it deterministic on purpose.
        self.backoff_ms = self.backoff_ms.saturating_mul(2).min(RETRY_MAX_MS);
        self.next_retry_ms = now_ms.saturating_add(self.backoff_ms);
        true
    }
}

enum State {
    Idle,
    /// First handshake for this peer; nothing to carry traffic yet.
    Handshaking(Box<Handshake>),
    Established {
        session: Arc<TransportSession>,
        /// Whether **we** initiated the handshake that produced this session.
        ///
        /// Only the initiator rekeys. If both sides did, they race: each starts
        /// a handshake, each then adopts the *other's* as responder — discarding
        /// its own in flight — and the two sessions end up derived from
        /// different handshakes, so neither can decrypt the other. Traffic then
        /// stops silently, because an AEAD failure is a drop rather than a
        /// counted error, until `REJECT_AFTER_TIME` expires both sides and the
        /// re-dial produces one clean handshake.
        ///
        /// Measured before this rule existed: **9 stalls in 7.8 hours, 253–765
        /// seconds each, 13% of samples**, with the session reporting
        /// `established` throughout. `WireGuard` avoids it the same way — the
        /// responder never initiates a rekey, and if the initiator goes away the
        /// responder's session simply expires and it dials out itself.
        initiated: bool,
        /// A **rekey** handshake in flight, if one is.
        ///
        /// §2.4 rekeys by running a fresh handshake, and the established
        /// session must stay usable throughout. Replacing it at the moment the
        /// rekey *starts* would stall traffic for a full round trip every
        /// `REKEY_AFTER_TIME` — and for up to `HANDSHAKE_GIVE_UP` if the
        /// handshake were then lost, even though the old session had another
        /// minute of validity left. The rekey therefore lives alongside the
        /// session it will replace, and swaps in only once it completes.
        rekey: Option<Box<Handshake>>,
        /// Keys derived as **responder** while `session` was still carrying
        /// traffic — `phreatic-v1.md` §12.6.
        ///
        /// "The responder has no assurance until the first transport message":
        /// a `HandshakeInit` is forgeable by anyone holding this node's public
        /// keys (§12.5), so §12.6 forbids emitting a `HandshakeResponse` from
        /// tearing down a working session. Until something authenticates under
        /// these keys they are a claim, not a session. Without this slot a
        /// single forged `HandshakeInit` — one datagram, no secrets, off-path
        /// — silently breaks a live tunnel, which is the denial of service
        /// §12.5 warns the unauthenticated handshake invites.
        pending: Option<Arc<TransportSession>>,
        /// The session a **rekey** replaced, kept for decryption only.
        ///
        /// The two ends switch at different moments: the initiator seals with
        /// the new keys as soon as its rekey completes, while the responder
        /// keeps using the old ones until a message proves the new ones. Every
        /// datagram already in flight, in either direction, was sealed under
        /// the keys that were current when it left. Dropping them at the swap
        /// discards exactly that traffic — invisibly, since an AEAD failure is
        /// a drop.
        previous: Option<Arc<TransportSession>>,
    },
}

/// The keys an inbound transport message may have been sealed under.
///
/// Cloned out from under the session's lock — three `Arc` bumps at most — so
/// the AEAD runs without holding it, which is the property PLAN.md §3.4
/// measured and the reason [`Session::transport`] hands out an `Arc` too.
#[derive(Debug, Clone)]
pub struct Inbound {
    current: Arc<TransportSession>,
    pending: Option<Arc<TransportSession>>,
    previous: Option<Arc<TransportSession>>,
}

/// Which keys opened a transport message.
///
/// The distinction is not bookkeeping: [`Opened::Pending`] is §12.6's "first
/// authenticated transport message", the evidence a responder was waiting for,
/// and the caller **must** answer it with [`Session::promote`].
#[derive(Debug)]
pub enum Opened {
    /// The live session.
    Current(Vec<u8>),
    /// The session a rekey replaced, still inside its validity.
    Previous(Vec<u8>),
    /// Keys this node derived as responder and had no assurance about until
    /// now. The peer completed that handshake, which a forged `HandshakeInit`
    /// cannot fake.
    Pending(Vec<u8>),
}

impl Opened {
    /// The plaintext, whichever keys carried it.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        match self {
            Self::Current(p) | Self::Previous(p) | Self::Pending(p) => p,
        }
    }
}

impl Inbound {
    /// Try the live keys, then the ones a rekey replaced, then the ones
    /// awaiting assurance.
    ///
    /// In that order because that is their frequency: the ordinary packet costs
    /// one AEAD operation and the others are reached only when it fails. A
    /// failed `open` leaves no state behind — the replay window is touched only
    /// after the AEAD has decided (§8) — so trying several is safe.
    ///
    /// # Errors
    /// [`TransportError`] from the live session when none of them opens it, so
    /// an expired session is still reported as expired rather than as a forgery.
    pub fn open(&self, datagram: &[u8], now_ms: u64) -> Result<Opened, TransportError> {
        let first = match self.current.open(datagram, now_ms) {
            Ok(payload) => return Ok(Opened::Current(payload)),
            Err(e) => e,
        };
        if let Some(previous) = &self.previous {
            if let Ok(payload) = previous.open(datagram, now_ms) {
                return Ok(Opened::Previous(payload));
            }
        }
        if let Some(pending) = &self.pending {
            if let Ok(payload) = pending.open(datagram, now_ms) {
                return Ok(Opened::Pending(payload));
            }
        }
        Err(first)
    }
}

/// A session with one peer.
///
/// Borrows the local keys and the peer's netmap entry rather than owning them:
/// the netmap is the source of truth and a session must never outlive it.
pub struct Session {
    /// This node's long-term keys, and the peer's public half.
    ///
    /// Shared by `Arc` rather than borrowed. They were `&'a`, which propagated
    /// a lifetime up through the daemon's engine and so pinned the entire peer
    /// set to one owner for the life of the process — a netmap that added a
    /// peer could then only be applied by restarting. `Arc` rather than owned
    /// copies because `StaticKeys` holds this node's private key, and cloning
    /// it once per peer would put the same secret in N places to be zeroized.
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
    policy: SuitePolicy,
    suite: SuiteId,
    psk_epoch: u32,
    index: u32,
    state: State,
    /// Monotonic counter so each retry uses fresh ephemerals.
    attempt: u32,
    /// Inbound fragment reassembly (§9.1). Bounded at construction.
    reasm: Reassembler,
    /// `mac1` key for fragments **we send**: keyed by the recipient's public
    /// static key, so the peer can verify with the one key it already has.
    /// A scanning filter, not an authenticator (§9.2).
    ///
    /// Pre-keyed once here rather than per packet — see [`FragMacKey`].
    out_mac_key: FragMacKey,
    /// `mac1` key for fragments **we receive**: keyed by our own public static
    /// key. Every inbound fragment on this node uses this key regardless of
    /// sender or session role, which is what lets a receiver discard a flood
    /// before identifying anybody — see §13.7.
    in_mac_key: FragMacKey,
    /// Distinguishes successive outbound messages for reassembly.
    reassembly_id: u32,
    /// The last `HandshakeInit` this session answered, and the
    /// `HandshakeResponse` it sent for it.
    ///
    /// **The same question gets the same answer.** An initiator retransmits the
    /// *identical* `HandshakeInit` until it hears back (§10), and answering the
    /// retransmission afresh derives new keys — which discards the session the
    /// initiator has already completed under the first answer. Both ends then
    /// report `established`, neither can decrypt the other, and nothing
    /// re-handshakes because neither has any reason to: the pair is wedged
    /// until the keys expire. It takes only a path slow enough that a
    /// retransmission crosses the response, which any relayed path can be.
    ///
    /// Replaying the response instead is also the cheaper answer — a repeated
    /// `HandshakeInit` costs no ML-KEM decapsulation at all.
    answered: Option<(Vec<u8>, Vec<u8>)>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self.state {
            State::Idle => "Idle",
            State::Handshaking(_) => "Handshaking",
            State::Established { rekey: None, .. } => "Established",
            State::Established { rekey: Some(_), .. } => "Established+rekeying",
        };
        f.debug_struct("Session")
            .field("state", &s)
            .field("index", &self.index)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Create an idle session for a peer.
    #[must_use]
    pub fn new(
        keys: Arc<StaticKeys>,
        peer: Arc<PeerPublic>,
        policy: SuitePolicy,
        suite: SuiteId,
        psk_epoch: u32,
        index: u32,
    ) -> Self {
        // Both MAC keys are derived before the two `Arc`s are moved into the
        // struct, so neither has to be re-read afterwards.
        let out_mac_key = FragMacKey::new(&mac1_key(&peer.kem_pk.to_bytes()));
        let in_mac_key = FragMacKey::new(&mac1_key(&keys.kem_pk.to_bytes()));
        Self {
            keys,
            peer,
            policy,
            suite,
            psk_epoch,
            index,
            state: State::Idle,
            attempt: 0,
            reasm: Reassembler::new(ReasmConfig::default()),
            out_mac_key,
            in_mac_key,
            reassembly_id: 0,
            answered: None,
        }
    }

    /// Split an outbound message into MTU-sized authenticated fragments (§5).
    ///
    /// The session emits **datagrams**, never whole messages: a 2378-byte
    /// `HandshakeInit` cannot cross a link with a 1280-byte MTU, and a caller
    /// handed an over-sized buffer has no way to know it must fragment.
    fn emit(&mut self, ty: MessageType, msg: &[u8]) -> Vec<Action> {
        self.reassembly_id = self.reassembly_id.wrapping_add(1);
        match fragment(ty, self.reassembly_id, msg, &self.out_mac_key) {
            Some(frags) => frags.into_iter().map(Action::Send).collect(),
            // Only possible past the 4-fragment cap, which no defined suite
            // reaches; treat as a local fault rather than emitting a bad packet.
            None => vec![Action::Closed(CloseReason::Rejected)],
        }
    }

    /// Point this session at a refreshed view of its peer.
    ///
    /// Used when the netmap changes something about a peer that does not
    /// invalidate the session already running — in practice a **PSK epoch
    /// rotation**, where §7.3 requires the rotation to complete "with no
    /// session interruption".
    ///
    /// So this deliberately does **not** touch the established session, or any
    /// handshake in flight. An established session's keys were derived from the
    /// old PSK and stay valid until it expires; a handshake already running
    /// holds its own `Arc` to the peer it started with, so it completes against
    /// the PSK both ends agreed on rather than one that changed underneath it.
    /// Only the *next* handshake uses the new material.
    ///
    /// Tearing the session down instead would turn every epoch rotation into a
    /// fleet-wide reconnect — the outage §7.3 exists to avoid.
    ///
    /// The caller must not use this to swap in a *different peer*: the KEM key
    /// identifies the peer, and changing it means the session is talking to
    /// somebody else. `Engine::reconfigure` builds a fresh session for that.
    pub fn rearm(&mut self, peer: Arc<PeerPublic>, psk_epoch: u32) {
        // The outbound fragment MAC is keyed by the recipient's static key, so
        // it only changes if the peer's KEM key did — which is not this path.
        self.peer = peer;
        self.psk_epoch = psk_epoch;
    }

    /// Whether traffic can flow right now.
    ///
    /// True during a rekey: that is the entire point of keeping the old session
    /// alive while the new handshake runs.
    #[must_use]
    pub fn established(&self) -> bool {
        matches!(self.state, State::Established { .. })
    }

    /// The live transport session, if there is one.
    ///
    /// Handing out an `Arc` is what lets a caller encrypt and decrypt **without
    /// holding this session's lock**: [`TransportSession`] synchronises itself,
    /// and the expensive part — the AEAD — needs no exclusive access at all.
    /// A caller clones this under the lock (one refcount bump) and then does the
    /// work outside it. See PLAN.md §3.4 for what holding the lock cost.
    #[must_use]
    pub fn transport(&self) -> Option<Arc<TransportSession>> {
        match &self.state {
            State::Established { session, .. } => Some(Arc::clone(session)),
            _ => None,
        }
    }

    /// The `mac1` key for fragments this session sends, so a caller framing a
    /// datagram outside the lock can authenticate it.
    #[must_use]
    pub fn out_mac_key(&self) -> FragMacKey {
        self.out_mac_key.clone()
    }

    /// A fresh reassembly identifier for an outbound message.
    pub fn next_reassembly_id(&mut self) -> u32 {
        self.reassembly_id = self.reassembly_id.wrapping_add(1);
        self.reassembly_id
    }

    /// Whether a rekey handshake is in flight — for `karst status` and tests.
    #[must_use]
    pub fn rekeying(&self) -> bool {
        matches!(self.state, State::Established { rekey: Some(_), .. })
    }

    /// This session's suite policy, as distributed in the netmap.
    #[must_use]
    pub fn policy(&self) -> &SuitePolicy {
        &self.policy
    }

    /// The suite bound into this session's handshake parameters. It is exposed
    /// for authenticated control-plane posture reporting, never inferred from
    /// a display string.
    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }

    /// Begin a handshake. No-op if one is already in flight or established.
    ///
    /// Refuses outright if the configured suite is below the local floor: an
    /// initiator chooses its own suite, so nothing else would catch a
    /// misconfiguration that offers something the node itself rejects
    /// (ADR-0006).
    pub fn connect(&mut self, now_ms: u64, seed: [u8; 32]) -> Vec<Action> {
        if !matches!(self.state, State::Idle) {
            return Vec::new();
        }
        if !self.policy.accepts(self.suite) {
            return vec![Action::Closed(CloseReason::Rejected)];
        }
        self.start_handshake(now_ms, seed)
    }

    /// Build a fresh handshake without deciding where it belongs.
    ///
    /// Returning the handshake rather than installing it is what lets a rekey
    /// sit beside a live session instead of replacing it.
    fn new_handshake(&mut self, now_ms: u64, seed: [u8; 32]) -> Option<Handshake> {
        self.attempt = self.attempt.wrapping_add(1);
        let rand = derive_initiator_randomness(&seed, self.attempt);
        let params = SessionParams {
            suite: self.suite,
            psk_epoch: self.psk_epoch,
            sender_index: self.index,
        };
        let (initiator, msg1) = initiate(
            Arc::clone(&self.keys),
            Arc::clone(&self.peer),
            params,
            &rand,
        )
        .ok()?;
        Some(Handshake {
            initiator: Box::new(initiator),
            msg1,
            started_ms: now_ms,
            next_retry_ms: now_ms.saturating_add(RETRY_INITIAL_MS),
            backoff_ms: RETRY_INITIAL_MS,
        })
    }

    fn start_handshake(&mut self, now_ms: u64, seed: [u8; 32]) -> Vec<Action> {
        let Some(hs) = self.new_handshake(now_ms, seed) else {
            return vec![Action::Closed(CloseReason::Rejected)];
        };
        let msg1 = hs.msg1.clone();
        self.state = State::Handshaking(Box::new(hs));
        self.emit(MessageType::HandshakeInit, &msg1)
    }

    /// Advance timers. Call regularly; it is cheap and idempotent.
    pub fn poll(&mut self, now_ms: u64, seed: [u8; 32]) -> Vec<Action> {
        match &mut self.state {
            State::Idle => Vec::new(),

            State::Handshaking(hs) => {
                if hs.abandoned(now_ms) {
                    self.state = State::Idle;
                    return vec![Action::Closed(CloseReason::HandshakeTimeout)];
                }
                if hs.retry_due(now_ms) {
                    let msg = hs.msg1.clone();
                    return self.emit(MessageType::HandshakeInit, &msg);
                }
                Vec::new()
            }

            State::Established {
                session,
                rekey,
                initiated,
                pending,
                previous,
            } => {
                // Expiry outranks everything: past `REJECT_AFTER_TIME` the keys
                // must not be used, rekey in flight or not.
                if session.expired(now_ms) {
                    self.state = State::Idle;
                    return vec![Action::Closed(CloseReason::Expired)];
                }
                // Let go of keys that can no longer be used. **This is hygiene
                // rather than the refusal itself** — `TransportSession::open`
                // rejects an expired session whoever holds it, which is why
                // removing these two lines fails no test — but key material
                // that cannot serve any purpose should not sit in memory
                // waiting to be zeroized by a state change that may not come
                // for minutes.
                if pending.as_ref().is_some_and(|p| p.expired(now_ms)) {
                    *pending = None;
                }
                if previous.as_ref().is_some_and(|p| p.expired(now_ms)) {
                    *previous = None;
                }

                match rekey {
                    // A rekey is running. Retransmit it, and abandon it if the
                    // window passes — but keep the live session, which is still
                    // valid until `REJECT_AFTER_TIME`. Dropping to Idle here
                    // would tear down a working tunnel because a *replacement*
                    // failed, which is strictly worse than not rekeying.
                    Some(hs) => {
                        if hs.abandoned(now_ms) {
                            *rekey = None;
                            return Vec::new();
                        }
                        if hs.retry_due(now_ms) {
                            let msg = hs.msg1.clone();
                            return self.emit(MessageType::HandshakeInit, &msg);
                        }
                        Vec::new()
                    }
                    // §2.4: rekey by running a fresh handshake alongside the
                    // session it will replace, so traffic never stalls.
                    //
                    // **Only if we initiated this session.** See `initiated`.
                    None if *initiated && session.needs_rekey(now_ms) => {
                        let Some(hs) = self.new_handshake(now_ms, seed) else {
                            // The session is still good; a failed *rekey* is not
                            // a reason to close it.
                            return Vec::new();
                        };
                        let msg1 = hs.msg1.clone();
                        if let State::Established { rekey, .. } = &mut self.state {
                            *rekey = Some(Box::new(hs));
                        }
                        self.emit(MessageType::HandshakeInit, &msg1)
                    }
                    None => Vec::new(),
                }
            }
        }
    }

    /// Feed a **datagram** received from this peer.
    ///
    /// Datagrams are fragments (§5). This verifies the fragment MAC, reassembles,
    /// and dispatches only complete messages. Anything malformed is discarded
    /// silently (§11).
    pub fn handle(&mut self, datagram: &[u8], source: SourceKey, now_ms: u64) -> Vec<Action> {
        let Ok((hdr, payload)) = split_datagram(datagram) else {
            return Vec::new();
        };
        // Type lives in the first payload byte of fragment 0; for later
        // fragments we cannot know it yet, so authenticate against both
        // plausible types and let reassembly + AEAD settle it.
        let ty = payload.first().copied().unwrap_or(0);
        let mac_ok = [ty, 0x02, 0x04].iter().any(|t| {
            self.in_mac_key
                .verify(*t, hdr.reassembly_id, hdr.idx, hdr.count, &hdr.frag_mac)
        });
        if !mac_ok {
            return Vec::new(); // §9.2 — dropped before touching a buffer
        }

        // Address validation is the caller's; a session only ever talks to a
        // peer it already initiated toward, so it passes `true` here.
        let Accept::Complete(msg) = self.reasm.push(source, true, &hdr, payload, now_ms) else {
            return Vec::new();
        };
        let msg = msg.to_vec();
        match msg.first() {
            Some(0x02) => self.handle_response(&msg, now_ms),
            Some(0x04) => self.handle_transport(&msg, now_ms),
            _ => Vec::new(),
        }
    }

    /// Complete a handshake — the first one, or a rekey.
    ///
    /// A response that does not authenticate is discarded and the handshake
    /// continues. `frag_mac` is keyed by a *public* key (§9.2), so anyone can
    /// produce fragments that reach here; treating a bad response as fatal would
    /// hand an off-path attacker a way to cancel every connection attempt on the
    /// network. [`Initiator::try_finish`] is what makes surviving it possible.
    fn handle_response(&mut self, datagram: &[u8], now_ms: u64) -> Vec<Action> {
        // Borrow the in-flight handshake wherever it lives. A rekey and a first
        // handshake complete identically; only the destination differs.
        let in_flight = match &self.state {
            State::Handshaking(hs) => Some(hs),
            State::Established { rekey, .. } => rekey.as_ref(),
            State::Idle => None,
        };
        // Nothing outstanding: unsolicited or late, so drop it.
        let Some(hs) = in_flight else {
            return Vec::new();
        };
        let Ok(keys) = hs.initiator.try_finish(datagram) else {
            return Vec::new(); // not ours, or forged — keep retrying
        };

        // `now_ms`, not zero: `established_ms` is what `REKEY_AFTER_TIME` and
        // `REJECT_AFTER_TIME` are measured from. Anchoring it at zero would make
        // every session appear to expire 180 s after the *daemon* started,
        // whatever time it was actually created — so a node could not hold a
        // session beyond three minutes of uptime.
        // **The keys being replaced are kept for decryption.** A rekey swaps
        // the sending key here, but the peer has not switched yet — it does so
        // only when a message under the new keys reaches it — and everything
        // already in flight was sealed under the old ones. Dropping them at
        // this instant discards that traffic silently, and leaves this node
        // unable to read the peer's replies until it catches up.
        // **Keys awaiting §12.6's assurance survive this too.** They are an
        // independent claim — the peer's own handshake, answered but not yet
        // proven — and completing a handshake of *ours* says nothing about it.
        // Dropping them here breaks the simultaneous rekey, which is not a rare
        // case but the expected one: two sessions created in the same second
        // reach `REKEY_AFTER_TIME` in the same second, so both ends dial, both
        // answer, and each then discards the answer it owes the other. The
        // symptom is the one `initiated` documents — both ends reporting
        // `established` while nothing decrypts.
        let (replaced, waiting) = match &self.state {
            State::Established {
                session, pending, ..
            } => (Some(Arc::clone(session)), pending.clone()),
            _ => (None, None),
        };
        self.state = State::Established {
            // The negotiated suite's AEAD — ADR-0015 item 2. Before this, every
            // suite ran ChaCha20-Poly1305 and a `KARST_2` session would have
            // reported an AEAD it was not using.
            session: Arc::new(TransportSession::for_suite(
                &keys,
                Role::Initiator,
                self.index,
                now_ms,
                self.suite,
            )),
            rekey: None,
            initiated: true,
            pending: waiting,
            previous: replaced,
        };
        vec![Action::Established]
    }

    fn handle_transport(&mut self, datagram: &[u8], now_ms: u64) -> Vec<Action> {
        let Some(inbound) = self.inbound() else {
            return Vec::new();
        };
        match inbound.open(datagram, now_ms) {
            Ok(Opened::Pending(payload)) => {
                // §12.6's first authenticated transport message: the peer
                // completed the handshake this node answered, so the keys it
                // was holding become the session.
                self.promote(&inbound);
                vec![Action::Deliver(payload)]
            }
            Ok(opened) => vec![Action::Deliver(opened.into_payload())],
            Err(TransportError::Expired) => {
                self.state = State::Idle;
                vec![Action::Closed(CloseReason::Expired)]
            }
            // Replay and forgery are dropped, never fatal: making them fatal
            // would hand an off-path attacker a session-teardown primitive.
            Err(_) => Vec::new(),
        }
    }

    /// Seal a payload for transmission.
    ///
    /// # Errors
    /// [`TransportError`] if no session is established or the session is spent.
    pub fn send(&mut self, payload: &[u8], now_ms: u64) -> Result<Vec<Vec<u8>>, TransportError> {
        let sealed = match &mut self.state {
            // A rekey in flight does not stop the live session sending — that
            // is exactly why it is kept.
            State::Established { session, .. } => session.seal(payload, now_ms)?,
            _ => return Err(TransportError::Expired),
        };
        self.reassembly_id = self.reassembly_id.wrapping_add(1);
        fragment(
            MessageType::TransportData,
            self.reassembly_id,
            &sealed,
            &self.out_mac_key,
        )
        .ok_or(TransportError::Malformed)
    }

    /// Accept an inbound handshake, becoming the responder.
    ///
    /// # Errors
    /// [`HandshakeError`] on malformed input, refused suite, unknown peer, or
    /// failed authentication.
    pub fn accept(
        keys: &StaticKeys,
        policy: &SuitePolicy,
        datagram: &[u8],
        peer: &PeerPublic,
        rand: &ResponderRandomness,
        index: u32,
        now_ms: u64,
    ) -> Result<(Vec<u8>, TransportSession), HandshakeError> {
        let expected = karst_noise::handshake::peer_id_hint(&peer.kem_pk.to_bytes());
        let (msg2, pending, suite) = respond(
            keys,
            policy,
            datagram,
            |h, _epoch| {
                if *h != expected {
                    return None;
                }
                Some(PeerPublic {
                    kem_pk: peer.kem_pk.clone(),
                    dh_pk: peer.dh_pk,
                    psk: peer.psk,
                })
            },
            rand,
            index,
        )?;
        // §12.6: the responder has no assurance until a transport message
        // authenticates, so `confirm()` is the caller's to call.
        let keys = pending.confirm();
        Ok((
            msg2,
            TransportSession::for_suite(&keys, Role::Responder, index, now_ms, suite),
        ))
    }

    /// This session's local index, which the peer echoes as `receiver_index`.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Install a responder session the caller negotiated itself.
    ///
    /// A daemon resolves `peer_id_hint` across the whole roster in one call to
    /// [`karst_noise::handshake::respond`], which is the O(1) lookup §4 exists
    /// to enable. Offering the message to each session in turn would instead
    /// cost one ML-KEM decapsulation *per peer* for every unrecognized
    /// `HandshakeInit` — a denial-of-service amplifier that grows with the
    /// roster. Having resolved the peer, the caller hands the result here.
    ///
    /// Returns the `HandshakeResponse` fragments followed by
    /// [`Action::Established`].
    pub fn adopt_responder(
        &mut self,
        init: &[u8],
        keys: &TransportKeys,
        msg2: &[u8],
        now_ms: u64,
        suite: SuiteId,
    ) -> Vec<Action> {
        self.answered = Some((init.to_vec(), msg2.to_vec()));
        let mut actions = self.emit(MessageType::HandshakeResponse, msg2);
        // The suite the *initiator* chose, not this session's configured one:
        // a responder adopts what it was offered and its policy accepted.
        let derived = Arc::new(TransportSession::for_suite(
            keys,
            Role::Responder,
            self.index,
            now_ms,
            suite,
        ));
        // §12.6: a working session is not torn down on the strength of a
        // `HandshakeInit`, which anyone can fabricate. The keys wait beside it
        // until a transport message authenticates under them — see
        // [`Session::promote`] — and the session in use carries traffic
        // meanwhile. Nothing is announced as established, because from this
        // node's side nothing has changed yet.
        if let State::Established { pending, .. } = &mut self.state {
            *pending = Some(derived);
            return actions;
        }
        // Nothing is carrying traffic yet, so these keys become the session —
        // but **a handshake this node started may still be outstanding**, and
        // it is carried across rather than discarded.
        //
        // Dropping it is what breaks a *simultaneous open*, which every pair
        // that knows both endpoints performs at startup: each side dials, each
        // side then answers the other's `HandshakeInit`, and the answer
        // overwrites the state holding its own attempt. The peer's
        // `HandshakeResponse` then arrives with nothing left to complete, and
        // the two ends settle on key sets that cannot read each other — both
        // reporting `established`, nothing decrypting, exactly the stall
        // `initiated` documents for the rekey race. It survives here in the
        // slot that already means "a handshake in flight beside a live
        // session"; §12.6 is untouched, because there is no working session to
        // protect at this point.
        let outstanding = match core::mem::replace(&mut self.state, State::Idle) {
            State::Handshaking(hs) => Some(hs),
            _ => None,
        };
        self.state = State::Established {
            session: derived,
            rekey: outstanding,
            initiated: false,
            pending: None,
            previous: None,
        };
        actions.push(Action::Established);
        actions
    }

    /// The keys an inbound transport message may be sealed under.
    #[must_use]
    pub fn inbound(&self) -> Option<Inbound> {
        match &self.state {
            State::Established {
                session,
                pending,
                previous,
                ..
            } => Some(Inbound {
                current: Arc::clone(session),
                pending: pending.clone(),
                previous: previous.clone(),
            }),
            _ => None,
        }
    }

    /// Adopt the keys a responder was holding, because a transport message
    /// authenticated under them — §12.6's "first authenticated transport
    /// message".
    ///
    /// That message is the assurance: the peer decapsulated `ct_ss` and
    /// computed `dh_se`, neither of which a forged `HandshakeInit` can produce.
    /// The keys being replaced become [`Opened::Previous`] rather than being
    /// dropped, because the peer may still have traffic in flight under them.
    ///
    /// **The keys adopted are the ones that opened the message, not whatever is
    /// waiting when this is called.** The AEAD runs outside this session's
    /// lock, so another handshake can land in between — a forged
    /// `HandshakeInit` is one datagram and its timing is the attacker's to
    /// choose. Adopting what happens to be there now would install keys nothing
    /// has proven, by a race, which is the property §12.6 exists to keep;
    /// refusing outright instead would drop a set that *was* proven and leave
    /// this node sealing for a peer that has moved on.
    pub fn promote(&mut self, proven: &Inbound) {
        let Some(proven) = proven.pending.as_ref() else {
            return;
        };
        let State::Established {
            session,
            rekey,
            initiated,
            pending,
            previous,
        } = &mut self.state
        else {
            return;
        };
        if Arc::ptr_eq(session, proven) {
            return; // already adopted, by an earlier message under the same keys
        }
        // A newer handshake may be waiting behind this one. It stays waiting:
        // it has proven nothing yet, and it may still.
        if pending.as_ref().is_some_and(|p| Arc::ptr_eq(p, proven)) {
            *pending = None;
        }
        *previous = Some(core::mem::replace(session, Arc::clone(proven)));
        // The peer handshaked from its side, so this node is the responder for
        // this session: any rekey of its own is abandoned, and only the
        // initiator rekeys.
        *rekey = None;
        *initiated = false;
    }

    /// The response already sent for this exact `HandshakeInit`, if it is the
    /// retransmission of one this session has answered.
    ///
    /// Callers MUST try this before deriving anything: see [`Self::answered`]
    /// for what answering a retransmission afresh costs. `None` means the
    /// `HandshakeInit` is new and must be handled normally.
    pub fn repeat_response(&mut self, init: &[u8]) -> Option<Vec<Action>> {
        let (answered, response) = self.answered.as_ref()?;
        if answered != init {
            return None;
        }
        let response = response.clone();
        Some(self.emit(MessageType::HandshakeResponse, &response))
    }

    /// A `CookieReply` arrived answering a `HandshakeInit` this session sent —
    /// §6.3, §9.1, §9.3.
    ///
    /// Dispatched apart from [`Self::handle`]: the reply's fragment MAC is
    /// keyed by the **peer's** own static key (the same key [`Self::out_mac_key`]
    /// already is), not this node's — the responder that issued it had not
    /// resolved anything about this session yet, so it could only sign with a
    /// key it already had. `Engine` verifies that half before calling this;
    /// `open_cookie_reply` and the `receiver_index` correlation below are
    /// this method's own checks. See the divergence from §13.7's general
    /// table recorded at `spec/phreatic-v1.md` §13.10.
    ///
    /// On success, retransmits the outstanding `HandshakeInit` **once**,
    /// immediately, under `mac2` keyed by the cookie — proof this address can
    /// receive at the address it claims. Deliberately not persisted: a later
    /// retry (if this one is also lost) falls back to the ordinary `mac1`
    /// path and may be challenged again, rather than keeping a cookie whose
    /// validity outlives the responder's own rotation (§9.3) and silently
    /// wedging every future attempt on a key nothing will accept any more.
    ///
    /// Returns `None` only when the reply's own fragment MAC does not verify
    /// — the caller's cue to count it as an ordinary MAC failure (§9.2), the
    /// same as any other unverified fragment. Every other outcome (a `Some`,
    /// possibly carrying no actions) means the MAC *did* verify and whatever
    /// followed — a decrypt failure, a stale correlation, nothing currently
    /// outstanding to retry — is not evidence of forgery, just of a reply
    /// that arrived too late or for the wrong attempt to act on.
    pub fn handle_cookie_reply(
        &mut self,
        payload: &[u8],
        hdr: &FragmentHeader,
    ) -> Option<Vec<Action>> {
        if !self
            .out_mac_key
            .verify(0x03, hdr.reassembly_id, hdr.idx, hdr.count, &hdr.frag_mac)
        {
            return None;
        }
        let Some((receiver_index, cookie)) =
            open_cookie_reply(&self.peer.kem_pk.to_bytes(), payload)
        else {
            return Some(Vec::new());
        };
        // Correlates to the fragment that triggered it: the `reassembly_id`
        // this session most recently sent a `HandshakeInit` fragment under.
        if receiver_index != self.reassembly_id {
            return Some(Vec::new());
        }
        let msg1 = match &self.state {
            State::Handshaking(hs)
            | State::Established {
                rekey: Some(hs), ..
            } => hs.msg1.clone(),
            _ => return Some(Vec::new()), // nothing outstanding to retry
        };
        self.reassembly_id = self.reassembly_id.wrapping_add(1);
        let key = FragMacKey::new(&mac2_key(&cookie));
        Some(
            match fragment(MessageType::HandshakeInit, self.reassembly_id, &msg1, &key) {
                Some(frags) => frags.into_iter().map(Action::Send).collect(),
                None => Vec::new(),
            },
        )
    }

    /// Accept an inbound handshake into *this* session, becoming the responder.
    ///
    /// The initiator side has [`Session::connect`]; this is its counterpart, and
    /// without it a node could only ever start conversations, never answer one.
    /// [`Session::accept`] exists too, but it is an associated function that
    /// hands back a bare [`TransportSession`] — fine for a test driving one
    /// exchange, no use to a daemon that must then route traffic through the
    /// peer's session.
    ///
    /// Returns the actions to take: the `HandshakeResponse` fragments followed
    /// by [`Action::Established`]. An unacceptable handshake yields no actions
    /// at all — §11 requires a silent discard, and in particular a node must not
    /// reveal whether the initiator is on its roster.
    ///
    /// Note the response is fragmented with the **initiator's** MAC key, not
    /// this session's usual outbound key, because at this point the two are the
    /// same thing: `self.peer` is the initiator. See §13.7.
    pub fn respond_to(
        &mut self,
        datagram: &[u8],
        rand: &ResponderRandomness,
        now_ms: u64,
    ) -> Vec<Action> {
        // The retransmission of a `HandshakeInit` already answered gets the
        // answer already given, rather than a second set of keys — see
        // [`Self::answered`].
        if let Some(actions) = self.repeat_response(datagram) {
            return actions;
        }
        // An established session is not torn down by an inbound handshake:
        // otherwise anyone able to replay a recorded `HandshakeInit` could reset
        // a working tunnel at will. The new session simply replaces the old once
        // it completes.
        let expected = karst_noise::handshake::peer_id_hint(&self.peer.kem_pk.to_bytes());
        let peer = Arc::clone(&self.peer);
        let result = respond(
            &self.keys,
            &self.policy,
            datagram,
            |h, _epoch| {
                if *h != expected {
                    return None;
                }
                Some(PeerPublic {
                    kem_pk: peer.kem_pk.clone(),
                    dh_pk: peer.dh_pk,
                    psk: peer.psk,
                })
            },
            rand,
            self.index,
        );
        let Ok((msg2, pending, suite)) = result else {
            return Vec::new(); // §11 — silent discard
        };
        // §12.6: no assurance until a transport message authenticates. The
        // session is usable for sending, but `Established` here means "keys
        // agreed", not "peer verified".
        self.adopt_responder(datagram, &pending.confirm(), &msg2, now_ms, suite)
    }

    /// Dispatch an already-reassembled message.
    ///
    /// [`Session::handle`] reassembles per session, which suits a caller that
    /// already knows which peer a datagram came from. A daemon does not: an
    /// inbound `HandshakeInit` cannot be attributed to a peer until it has been
    /// reassembled *and* decrypted, so reassembly has to happen once at the node
    /// level, above any session. This is the entry point for that caller.
    ///
    /// Unknown or unexpected message types are discarded silently (§11).
    pub fn deliver(&mut self, msg: &[u8], now_ms: u64) -> Vec<Action> {
        match msg.first() {
            Some(0x02) => self.handle_response(msg, now_ms),
            Some(0x04) => self.handle_transport(msg, now_ms),
            _ => Vec::new(),
        }
    }
}

/// Derive per-attempt ephemeral seeds from one caller-supplied seed.
///
/// Every retry must use fresh ephemerals — reusing them across attempts would
/// reuse the KEM encapsulation randomness, which is a real key-recovery risk,
/// not merely untidy.
fn derive_initiator_randomness(seed: &[u8; 32], attempt: u32) -> InitiatorRandomness {
    // Truncating the attempt counter is intentional and safe: it only needs to
    // differ between consecutive attempts, and the give-up window bounds the
    // count far below 256. The seed supplies the entropy.
    let att = attempt.to_le_bytes();
    let a0 = att.first().copied().unwrap_or(0);

    let mut e_kem_seed = [0u8; 64];
    for (i, b) in e_kem_seed.iter_mut().enumerate() {
        let s = seed.get(i % 32).copied().unwrap_or(0);
        *b = s ^ a0.wrapping_add(u8::try_from(i % 251).unwrap_or(0));
    }
    let mut e_dh_seed = [0u8; 32];
    let mut encap_rand = [0u8; 32];
    for i in 0..32 {
        let s = seed.get(i).copied().unwrap_or(0);
        if let Some(b) = e_dh_seed.get_mut(i) {
            *b = s.wrapping_add(a0).wrapping_add(0x11);
        }
        if let Some(b) = encap_rand.get_mut(i) {
            *b = s.wrapping_add(a0).wrapping_add(0x22);
        }
    }
    InitiatorRandomness {
        e_kem_seed,
        e_dh_seed,
        encap_rand,
        timestamp: [0; 12],
    }
}

/// Re-exported so callers need not depend on `karst-noise` directly.
pub use karst_noise::transport::REJECT_AFTER_MS as SESSION_LIFETIME_MS;

const _: () = assert!(REJECT_AFTER_MS > HANDSHAKE_GIVE_UP_MS);
