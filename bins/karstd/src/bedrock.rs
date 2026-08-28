// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The node's replicated copy of the Bedrock log — `spec/bedrock-v1.md` §5.
//!
//! The node fetches entries forward from its last verified sequence and
//! verifies the whole chain from genesis every time. It never adopts a state it
//! could not verify, and it never discards one it could.
//!
//! # Failing closed here means keeping what you had
//!
//! The instinct with a fetch that fails is to fall back to "no policy". For a
//! network lock that is precisely backwards: no policy means no coverage
//! requirement, so a server that simply stops answering would disable
//! enforcement everywhere by doing nothing at all.
//!
//! So [`Log::extend`] leaves the previously verified state in place when an
//! extension does not verify, and reports the failure. The node goes on
//! enforcing what it last established, which is what §4 requires.
//!
//! # The log is not secret, and is stored unsealed
//!
//! The netmap cache is encrypted because it carries a per-pair PSK for every
//! peer. This file carries signatures, public keys and handles — all of it
//! published to every node in the network by construction, and none of it worth
//! an attacker's time to read. Storing it in the clear also means an operator
//! can point `karst-bedrock verify` straight at it when something is wrong,
//! which is worth more than encrypting a file whose contents an attacker can
//! obtain by enrolling a node.

use karst_bedrock::{decode_log, encode_log, verify_log, Entry, PeerKeys, State};

/// How strictly a node acts on the log — `spec/bedrock-v1.md` §6.
///
/// Ordered, and the ordering is load-bearing: a node takes the **maximum** of
/// its own configured floor and whatever the server advertises, so the server
/// can raise enforcement but never lower it. That is ADR-0006's rule for cipher
/// suites applied here, and for the same reason — Bedrock exists because the
/// coordination server may be compromised, so a server that could select `Off`
/// would switch the mechanism off by saying so.
///
/// Turning enforcement off *cryptographically* needs a root-signed `disable`
/// entry (§3.1), which requires `k` offline root keys and is permanently
/// visible in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Mode {
    /// No verification. The default until an operator turns it on.
    #[default]
    Off,
    /// Verify and report, but drop nothing. The mode that makes this
    /// deployable: an operator sees exactly which nodes would be cut off
    /// before any are.
    Advisory,
    /// Drop uncovered peers.
    Enforcing,
}

impl Mode {
    /// Parse a configuration spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "advisory" => Some(Self::Advisory),
            "enforcing" => Some(Self::Enforcing),
            _ => None,
        }
    }

    /// The configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Advisory => "advisory",
            Self::Enforcing => "enforcing",
        }
    }

    /// The mode a server advertised, from the wire enum.
    ///
    /// An unrecognised value is treated as [`Mode::Off`] rather than as an
    /// error: it can only come from a server newer than this node, and guessing
    /// *upward* would let a future value silently cut a node off from its
    /// network. The local floor still applies, so an operator who configured
    /// enforcement keeps it.
    #[must_use]
    pub fn from_wire(v: i32) -> Self {
        match v {
            1 => Self::Advisory,
            2 => Self::Enforcing,
            _ => Self::Off,
        }
    }
}

/// What enforcement decided about one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub handle: String,
    pub reason: Reason,
}

/// Why a peer is not covered. Distinguished so an operator reading a console or
/// a log line can tell "never countersigned" from "countersigned, then the
/// server handed me different keys" — the first is an administrative gap, the
/// second is an attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No `node-sign` for this handle at all.
    NotCountersigned,
    /// Countersigned, but the netmap presents different datapath keys.
    KeyMismatch,
    /// Countersigned, but outside the signed validity window.
    OutsideWindow,
    /// Revoked.
    Revoked,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotCountersigned => "not countersigned",
            Self::KeyMismatch => "the netmap presents keys the log does not cover",
            Self::OutsideWindow => "outside its signed validity window",
            Self::Revoked => "revoked",
        })
    }
}

/// Why a Bedrock update was refused.
#[derive(Debug)]
pub enum Error {
    /// The bytes were not a log.
    Malformed(String),
    /// The chain did not verify. The previously verified state is retained.
    Broken(String),
    /// The server's entries did not continue from where this node had reached.
    NotContiguous { expected: u64, got: u64 },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed bedrock log: {e}"),
            Self::Broken(e) => write!(f, "bedrock chain does not verify: {e}"),
            Self::NotContiguous { expected, got } => {
                write!(f, "bedrock entries start at {got}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// What a fetch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The server has no log for this account.
    Absent,
    /// Nothing new.
    UpToDate,
    /// The chain advanced to this sequence.
    Advanced { to: u64 },
}

/// A node's verified copy of the log.
///
/// `Clone` so the datapath can be handed a snapshot: the engine compares peer
/// head claims on the inbound path and must not take a lock the control worker
/// holds across a network fetch. The log is small by construction, and a clone
/// happens once per refresh rather than per packet.
#[derive(Debug, Default, Clone)]
pub struct Log {
    entries: Vec<Entry>,
    state: Option<State>,
}

impl Log {
    /// An empty log — a node that has verified nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The sequence this node has verified up to. Zero when it holds nothing,
    /// which is also what its first fetch asks from.
    #[must_use]
    pub fn verified_seq(&self) -> u64 {
        self.state.as_ref().map_or(0, |s| s.head_seq)
    }

    /// The verified head hash, empty when nothing is held.
    #[must_use]
    pub fn head(&self) -> &[u8] {
        self.state.as_ref().map_or(&[], |s| s.head.as_slice())
    }

    /// The verified state, or `None` if nothing has verified yet.
    #[must_use]
    pub fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// Whether this node has a verified log at all.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.state.is_some()
    }

    /// Append fetched entries and re-verify from genesis.
    ///
    /// On failure the previously verified state is retained and the new entries
    /// are discarded — see the module docs.
    ///
    /// # Errors
    ///
    /// [`Error::NotContiguous`] if the entries do not continue this node's
    /// chain, and [`Error::Broken`] if the combined chain does not verify.
    pub fn extend(&mut self, fetched: Vec<Entry>) -> Result<Outcome, Error> {
        if fetched.is_empty() {
            return Ok(Outcome::UpToDate);
        }

        let expected = self.entries.len() as u64 + 1;
        let first = fetched.first().map_or(0, |e| e.seq);
        if first != expected {
            return Err(Error::NotContiguous {
                expected,
                got: first,
            });
        }

        // Verify a *candidate* before touching held state, so a rejected
        // extension cannot leave this node holding a half-applied chain.
        let mut candidate = self.entries.clone();
        candidate.extend(fetched);
        let state = verify_log(&candidate).map_err(|e| Error::Broken(e.to_string()))?;

        let to = state.head_seq;
        self.entries = candidate;
        self.state = Some(state);
        Ok(Outcome::Advanced { to })
    }

    /// Serialise for the on-disk copy.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_log(&self.entries)
    }

    /// Read back an on-disk copy, verifying it.
    ///
    /// The stored copy is re-verified rather than trusted: it is a plain file
    /// that anything with write access to the state directory could have
    /// edited, and a node that trusted it would enforce whatever that file
    /// said.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the bytes are not a log, [`Error::Broken`] if
    /// the chain does not verify.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let entries = decode_log(bytes).map_err(|e| Error::Malformed(e.to_string()))?;
        if entries.is_empty() {
            return Ok(Self::new());
        }
        let state = verify_log(&entries).map_err(|e| Error::Broken(e.to_string()))?;
        Ok(Self {
            entries,
            state: Some(state),
        })
    }

    /// Classify a peer against the verified log at time `t`.
    ///
    /// `None` means covered. Returning *why* rather than a bare boolean is what
    /// lets a log line and a console distinguish an administrative gap from an
    /// attack: "never countersigned" is someone forgetting a step, while
    /// "presents keys the log does not cover" is a server handing out a key it
    /// controls, which is the thing Bedrock exists to catch.
    #[must_use]
    pub fn classify(&self, handle: &str, keys: PeerKeys<'_>, t: i64) -> Option<Reason> {
        let Some(state) = self.state.as_ref() else {
            // Nothing verified: everything is uncovered. Callers gate on the
            // mode before reaching here.
            return Some(Reason::NotCountersigned);
        };
        if state.is_covered(handle, keys, t) {
            return None;
        }
        let Some(c) = state.covered.get(handle) else {
            return Some(Reason::NotCountersigned);
        };
        if c.kem_public_key != keys.kem_public_key || c.dh_public_key != keys.dh_public_key {
            return Some(Reason::KeyMismatch);
        }
        if state.revoked.get(handle).is_some_and(|&eff| eff <= t) {
            return Some(Reason::Revoked);
        }
        Some(Reason::OutsideWindow)
    }

    /// Whether a head reported by the server matches what this node verified.
    ///
    /// A mismatch is not by itself proof of misbehaviour — the server may
    /// simply be ahead — so this reports only equality, and the caller decides
    /// what a difference means. Divergence at a *common* sequence is the thing
    /// that proves equivocation, and that comparison belongs with the peer
    /// exchange in §5 layer 3.
    #[must_use]
    pub fn matches_head(&self, hash: &[u8], seq: u64) -> bool {
        self.verified_seq() == seq && self.head() == hash
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use karst_bedrock::{genesis_body, node_sign_body, Builder, Op, Signature};
    use karst_crypto::sign::{AuthorityKey, RootKey, ROOT_SEED};

    fn root() -> RootKey {
        RootKey::from_seed(&[7u8; ROOT_SEED]).unwrap()
    }

    fn authority() -> AuthorityKey {
        AuthorityKey::from_seed(&[9u8; 32]).unwrap()
    }

    /// The three keys a node-sign covers — spec §6.1.
    pub(super) struct NodeKeys {
        pub(super) identity: Vec<u8>,
        pub(super) kem: Vec<u8>,
        pub(super) dh: Vec<u8>,
    }

    impl NodeKeys {
        /// The handle this node's identity key derives to. Never a literal:
        /// chain verification requires the two to agree.
        pub(super) fn handle(&self) -> String {
            karst_bedrock::log::node_handle(&self.identity)
        }

        pub(super) fn keys(&self) -> karst_bedrock::PeerKeys<'_> {
            karst_bedrock::PeerKeys {
                kem_public_key: &self.kem,
                dh_public_key: &self.dh,
            }
        }
    }

    /// A two-entry log: genesis, then a countersignature for `alice`.
    pub(super) fn sample() -> (Vec<Entry>, NodeKeys) {
        let r = root();
        let a = authority();
        // The identity key is a pattern: nothing verifies a signature under a
        // node's identity key, so the chain checks its length and that the
        // handle derives to it, and a pattern satisfies both.
        let node = NodeKeys {
            identity: vec![0x33; karst_crypto::sign::NODE_IDENTITY_KEY],
            kem: vec![0x33; 1184],
            dh: vec![0x34; 32],
        };

        let mut b = Builder::new();
        let (e, input) = b.prepare(
            1000,
            Op::Genesis,
            genesis_body("z.karst.", &[r.public_key()], 1, &[a.public_key()], 1),
        );
        let sig = r.sign(&input).unwrap();
        b.commit(
            e,
            vec![Signature {
                signer_index: 0,
                sig,
            }],
        )
        .unwrap();

        let (e, input) = b.prepare(
            1100,
            Op::NodeSign,
            node_sign_body(
                &karst_bedrock::log::node_handle(&node.identity),
                &node.identity,
                &node.kem,
                &node.dh,
                0,
                0,
            ),
        );
        let sig = a.sign(&input).unwrap();
        b.commit(
            e,
            vec![Signature {
                signer_index: 0,
                sig,
            }],
        )
        .unwrap();

        (b.into_entries(), node)
    }

    #[test]
    fn an_empty_log_verifies_nothing_and_asks_from_zero() {
        let log = Log::new();
        assert_eq!(log.verified_seq(), 0);
        assert!(!log.is_present());
        assert!(log.state().is_none());
    }

    #[test]
    fn entries_are_adopted_once_verified() {
        let (entries, node) = sample();
        let mut log = Log::new();
        assert_eq!(log.extend(entries).unwrap(), Outcome::Advanced { to: 2 });
        assert_eq!(log.verified_seq(), 2);
        assert!(log
            .state()
            .expect("state")
            .is_covered(&node.handle(), node.keys(), 2000));
    }

    #[test]
    fn a_fetch_can_be_incremental() {
        let (entries, _) = sample();
        let mut log = Log::new();
        log.extend(vec![entries[0].clone()]).unwrap();
        assert_eq!(log.verified_seq(), 1);
        assert_eq!(
            log.extend(vec![entries[1].clone()]).unwrap(),
            Outcome::Advanced { to: 2 }
        );
    }

    /// The property the module exists for: a bad extension must not cost the
    /// node the policy it had already established.
    #[test]
    fn a_broken_extension_leaves_the_previous_state_intact() {
        let (entries, node) = sample();
        let mut log = Log::new();
        log.extend(vec![entries[0].clone()]).unwrap();

        let mut tampered = entries[1].clone();
        tampered.body[0] ^= 0x01;
        let err = log.extend(vec![tampered]).expect_err("must be refused");
        assert!(matches!(err, Error::Broken(_)), "{err}");

        // Still holding genesis, still enforcing on it.
        assert_eq!(log.verified_seq(), 1);
        assert!(log.state().is_some());
        assert!(!log
            .state()
            .expect("state")
            .is_covered(&node.handle(), node.keys(), 2000));
    }

    #[test]
    fn a_gap_is_refused() {
        let (entries, _) = sample();
        let mut log = Log::new();
        // Entry 2 without entry 1.
        let err = log
            .extend(vec![entries[1].clone()])
            .expect_err("must be refused");
        assert!(
            matches!(
                err,
                Error::NotContiguous {
                    expected: 1,
                    got: 2
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn the_on_disk_copy_round_trips_and_is_re_verified() {
        let (entries, _) = sample();
        let mut log = Log::new();
        log.extend(entries).unwrap();

        let restored = Log::decode(&log.encode()).expect("decode");
        assert_eq!(restored.verified_seq(), 2);
        assert_eq!(restored.head(), log.head());
    }

    #[test]
    fn a_tampered_on_disk_copy_is_refused_rather_than_trusted() {
        let (entries, _) = sample();
        let mut log = Log::new();
        log.extend(entries).unwrap();

        let mut bytes = log.encode();
        let n = bytes.len();
        bytes[n / 2] ^= 0x01;
        assert!(Log::decode(&bytes).is_err(), "an edited cache was trusted");
    }

    #[test]
    fn head_comparison_needs_both_hash_and_sequence() {
        let (entries, _) = sample();
        let mut log = Log::new();
        log.extend(entries).unwrap();

        let head = log.head().to_vec();
        assert!(log.matches_head(&head, 2));
        assert!(!log.matches_head(&head, 3), "sequence is not compared");
        assert!(!log.matches_head(b"other", 2), "hash is not compared");
    }
}

#[cfg(test)]
mod mode_tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::tests::sample;
    use super::*;

    /// The ordering is what makes "the server may raise, never lower" a `max`.
    #[test]
    fn modes_are_ordered_by_strictness() {
        assert!(Mode::Off < Mode::Advisory);
        assert!(Mode::Advisory < Mode::Enforcing);
        assert_eq!(Mode::default(), Mode::Off);
    }

    /// A node takes the stronger of its floor and the server's advertisement.
    ///
    /// The second half is the security-relevant one: a compromised server
    /// selecting `off` must not switch enforcement off on a node whose operator
    /// asked for it. Bedrock exists because the server may be compromised, so a
    /// mode the server alone controlled would be a bypass with extra steps.
    #[test]
    fn the_server_may_raise_the_floor_and_never_lower_it() {
        for (floor, advertised, want) in [
            (Mode::Off, Mode::Off, Mode::Off),
            (Mode::Off, Mode::Advisory, Mode::Advisory),
            (Mode::Off, Mode::Enforcing, Mode::Enforcing),
            (Mode::Enforcing, Mode::Off, Mode::Enforcing),
            (Mode::Enforcing, Mode::Advisory, Mode::Enforcing),
            (Mode::Advisory, Mode::Off, Mode::Advisory),
            (Mode::Advisory, Mode::Enforcing, Mode::Enforcing),
        ] {
            assert_eq!(
                floor.max(advertised),
                want,
                "floor {floor:?} with advertised {advertised:?}"
            );
        }
    }

    /// An unrecognised wire value means `Off`, never something stronger.
    ///
    /// It can only come from a server newer than this node, and guessing upward
    /// would let a future enum value cut a node off from its own network. The
    /// local floor still applies, so an operator who asked for enforcement
    /// keeps it.
    #[test]
    fn an_unknown_wire_mode_does_not_escalate() {
        assert_eq!(Mode::from_wire(0), Mode::Off);
        assert_eq!(Mode::from_wire(1), Mode::Advisory);
        assert_eq!(Mode::from_wire(2), Mode::Enforcing);
        assert_eq!(Mode::from_wire(3), Mode::Off);
        assert_eq!(Mode::from_wire(-1), Mode::Off);
        assert_eq!(Mode::from_wire(9999), Mode::Off);
    }

    #[test]
    fn modes_round_trip_through_configuration() {
        for m in [Mode::Off, Mode::Advisory, Mode::Enforcing] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("ENFORCING"), None);
        assert_eq!(Mode::parse(""), None);
        assert_eq!(Mode::parse("on"), None);
    }

    /// Classification distinguishes an administrative gap from an attack.
    #[test]
    fn classification_names_why_a_peer_is_excluded() {
        let (entries, node) = sample();
        let mut log = Log::new();
        log.extend(entries).unwrap();

        assert_eq!(log.classify(&node.handle(), node.keys(), 2000), None);
        assert_eq!(
            log.classify("nobody", node.keys(), 2000),
            Some(Reason::NotCountersigned)
        );

        // Right handle, keys the log does not cover: this is the substitution
        // Bedrock exists to catch, and it must not be reported as a mere gap.
        let other = vec![0xEE; 1184];
        assert_eq!(
            log.classify(
                &node.handle(),
                PeerKeys {
                    kem_public_key: &other,
                    dh_public_key: &node.dh,
                },
                2000
            ),
            Some(Reason::KeyMismatch)
        );
    }

    /// With nothing verified, everything is uncovered — never the reverse.
    #[test]
    fn an_empty_log_covers_nothing() {
        let log = Log::new();
        let keys = PeerKeys {
            kem_public_key: &[0u8; 1184],
            dh_public_key: &[0u8; 32],
        };
        assert_eq!(
            log.classify("anyone", keys, 2000),
            Some(Reason::NotCountersigned)
        );
    }
}

// ── peer-to-peer head comparison — spec §5, layer 3 ─────────────────────────
//
// A hash chain proves the server did not *edit* history. It does not prove the
// server told everyone the *same* history: a compromised server can maintain
// two valid chains and hand a different one to each node, and every check in
// §4 passes on both. Layers 1 and 2 cannot see that, because both get their
// idea of the head from the server being checked.
//
// Two peers comparing heads *with each other* can. This must ride the PHREATIC
// session and nothing else: the coordination server knows each pair's PSK
// (PLAN.md §2.6), but not the ephemeral ML-KEM and X25519 secrets, so a
// PHREATIC session is the only channel between two nodes that is confidential
// from the party being audited.

/// The marker byte for a Karst inner control frame.
///
/// Zero is not a legal IP version, so it cannot collide with a tunnelled
/// packet: `karst_tun::ip::addresses` already returns `None` for it and the
/// engine already drops such payloads. That makes this a discriminator with no
/// ambiguity to resolve rather than a reserved value someone has to remember.
///
/// It lives **inside** the AEAD. The transport's outer type byte is written
/// before the ciphertext with an empty AAD and is therefore unauthenticated;
/// discriminating on it would let anyone who can flip one bit in flight
/// redirect a tunnelled packet into the control handler.
pub const CONTROL_MARKER: u8 = 0x00;

/// Control frame kind: a claim about the sender's verified Bedrock head.
pub const CONTROL_BEDROCK_HEAD: u8 = 0x01;

/// Encode a head claim — `CONTROL_MARKER || 0x01 || BE64(seq) || BE32(len) || hash`.
///
/// Length-prefixed because the transport pads its plaintext and carries no
/// length of its own (`phreatic-v1.md` §8); without the prefix a receiver could
/// not tell the hash from the padding after it.
#[must_use]
pub fn encode_head_claim(hash: &[u8], seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + hash.len());
    out.push(CONTROL_MARKER);
    out.push(CONTROL_BEDROCK_HEAD);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&u32::try_from(hash.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(hash);
    out
}

/// Decode a head claim from a decrypted, padded plaintext.
///
/// Returns `None` for anything that is not a well-formed claim, including a
/// tunnelled IP packet — the caller uses that to route between the two.
#[must_use]
pub fn decode_head_claim(plaintext: &[u8]) -> Option<(Vec<u8>, u64)> {
    if plaintext.first() != Some(&CONTROL_MARKER) || plaintext.get(1) != Some(&CONTROL_BEDROCK_HEAD)
    {
        return None;
    }
    let seq = u64::from_be_bytes(plaintext.get(2..10)?.try_into().ok()?);
    let len = u32::from_be_bytes(plaintext.get(10..14)?.try_into().ok()?) as usize;
    // A hash is 64 bytes; anything else is malformed rather than merely
    // unexpected, and refusing it here keeps a peer from steering this node's
    // allocator with a length prefix.
    if len != 64 {
        return None;
    }
    Some((plaintext.get(14..14 + len)?.to_vec(), seq))
}

/// What comparing a peer's head against this node's log established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadComparison {
    /// The peer agrees with this node at the sequence they have in common.
    Agrees,
    /// **Proof of equivocation.** At a sequence both nodes hold, they hold
    /// different hashes. Since each verified its own chain from genesis, and a
    /// chain hash commits to every entry before it, two different hashes at one
    /// sequence mean two different histories — which one server produced.
    Diverges { seq: u64 },
    /// The peer is further along than this node. Not evidence of anything: the
    /// peer may simply have polled more recently.
    PeerAhead { peer_seq: u64, local_seq: u64 },
    /// This node has nothing verified, so there is nothing to compare.
    Unknown,
}

impl Log {
    /// The chain hash of the entry at `seq`, if this node holds it.
    ///
    /// Recomputed rather than stored: the log is small by construction, and a
    /// stored hash is a second source of truth that could disagree with the
    /// entries it was derived from.
    #[must_use]
    pub fn hash_at(&self, seq: u64) -> Option<Vec<u8>> {
        if seq == 0 || seq > self.entries.len() as u64 {
            return None;
        }
        let mut prev: Vec<u8> = Vec::new();
        for e in &self.entries {
            let h = e.signing_input(&prev);
            if e.seq == seq {
                return Some(h);
            }
            prev = h;
        }
        None
    }

    /// Compare a peer's claimed head against this node's verified chain —
    /// spec §5, layer 3.
    ///
    /// Comparison happens at the **lower** of the two sequences, which is the
    /// only place both nodes have an opinion. Comparing heads directly would
    /// report divergence every time one node had polled more recently than the
    /// other, and an alarm that fires constantly is one nobody reads.
    #[must_use]
    pub fn compare_head(&self, peer_hash: &[u8], peer_seq: u64) -> HeadComparison {
        let local_seq = self.verified_seq();
        if local_seq == 0 || peer_seq == 0 {
            return HeadComparison::Unknown;
        }
        if peer_seq > local_seq {
            return HeadComparison::PeerAhead {
                peer_seq,
                local_seq,
            };
        }
        // peer_seq <= local_seq, so this node holds an entry there.
        match self.hash_at(peer_seq) {
            Some(mine) if mine == peer_hash => HeadComparison::Agrees,
            Some(_) => HeadComparison::Diverges { seq: peer_seq },
            None => HeadComparison::Unknown,
        }
    }
}

#[cfg(test)]
mod head_tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::tests::sample;
    use super::*;

    fn loaded() -> Log {
        let (entries, _) = sample();
        let mut log = Log::new();
        log.extend(entries).unwrap();
        log
    }

    #[test]
    fn a_head_claim_round_trips() {
        let hash = vec![0xAB; 64];
        let (got, seq) = decode_head_claim(&encode_head_claim(&hash, 7)).expect("decode");
        assert_eq!(got, hash);
        assert_eq!(seq, 7);
    }

    /// The frame must survive the transport's padding, which is why it carries
    /// its own length — `phreatic-v1.md` §8 pads and carries no length field.
    #[test]
    fn trailing_padding_is_ignored() {
        let mut framed = encode_head_claim(&[0xCD; 64], 3);
        framed.resize(1280, 0);
        let (got, seq) = decode_head_claim(&framed).expect("decode");
        assert_eq!(got, vec![0xCD; 64]);
        assert_eq!(seq, 3);
    }

    /// A tunnelled IP packet must never be mistaken for a control frame. The
    /// marker is zero precisely because zero is not a legal IP version.
    #[test]
    fn ip_packets_are_not_control_frames() {
        for first in [0x45u8, 0x60, 0x4F, 0x69] {
            let mut packet = vec![first];
            packet.extend_from_slice(&[0u8; 60]);
            assert!(
                decode_head_claim(&packet).is_none(),
                "an IP packet starting {first:#04x} decoded as a control frame"
            );
        }
    }

    #[test]
    fn malformed_frames_are_refused_not_panicked_on() {
        for case in [
            vec![],
            vec![CONTROL_MARKER],
            vec![CONTROL_MARKER, 0x99], // unknown control type
            vec![CONTROL_MARKER, CONTROL_BEDROCK_HEAD], // truncated
            {
                // A length prefix that is not 64: refused rather than trusted,
                // so a peer cannot steer this node's allocator with it.
                let mut v = vec![CONTROL_MARKER, CONTROL_BEDROCK_HEAD];
                v.extend_from_slice(&1u64.to_be_bytes());
                v.extend_from_slice(&u32::MAX.to_be_bytes());
                v
            },
        ] {
            assert!(decode_head_claim(&case).is_none(), "accepted {case:02x?}");
        }
    }

    #[test]
    fn a_peer_holding_the_same_chain_agrees() {
        let log = loaded();
        let head = log.head().to_vec();
        assert_eq!(
            log.compare_head(&head, log.verified_seq()),
            HeadComparison::Agrees
        );
        // And at an earlier sequence they both hold.
        let at_one = log.hash_at(1).expect("genesis hash");
        assert_eq!(log.compare_head(&at_one, 1), HeadComparison::Agrees);
    }

    /// **The property this layer exists for.** Two different hashes at one
    /// sequence is proof that one server produced two histories.
    #[test]
    fn a_different_hash_at_a_common_sequence_is_divergence() {
        let log = loaded();
        assert_eq!(
            log.compare_head(&[0xFF; 64], 1),
            HeadComparison::Diverges { seq: 1 }
        );
        assert_eq!(
            log.compare_head(&[0xFF; 64], log.verified_seq()),
            HeadComparison::Diverges {
                seq: log.verified_seq()
            }
        );
    }

    /// A peer that has polled more recently is not evidence of anything.
    ///
    /// Comparing heads directly rather than at the common sequence would report
    /// divergence every time two nodes were at different points in the same
    /// chain — which is most of the time, and an alarm that fires constantly is
    /// one nobody reads.
    #[test]
    fn a_peer_further_along_is_not_divergence() {
        let log = loaded();
        assert_eq!(
            log.compare_head(&[0xFF; 64], log.verified_seq() + 5),
            HeadComparison::PeerAhead {
                peer_seq: log.verified_seq() + 5,
                local_seq: log.verified_seq(),
            }
        );
    }

    #[test]
    fn nothing_verified_means_nothing_to_compare() {
        let log = Log::new();
        assert_eq!(log.compare_head(&[0u8; 64], 3), HeadComparison::Unknown);
        // And a peer with nothing is equally uninformative.
        assert_eq!(loaded().compare_head(&[], 0), HeadComparison::Unknown);
    }

    #[test]
    fn hash_at_is_bounded_by_what_is_held() {
        let log = loaded();
        assert!(log.hash_at(0).is_none());
        assert!(log.hash_at(1).is_some());
        assert!(log.hash_at(log.verified_seq()).is_some());
        assert!(log.hash_at(log.verified_seq() + 1).is_none());
        assert!(log.hash_at(u64::MAX).is_none());
    }

    /// `hash_at(head)` must equal the head the chain verification produced,
    /// or the two ways of naming the same entry disagree.
    #[test]
    fn the_recomputed_head_matches_the_verified_one() {
        let log = loaded();
        assert_eq!(
            log.hash_at(log.verified_seq()).expect("head"),
            log.head().to_vec()
        );
    }
}

#[cfg(test)]
mod multiplex_tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// The other half of the multiplexing property.
    ///
    /// `ip_packets_are_not_control_frames` proves a packet never decodes as a
    /// claim. This proves a claim is never routed as a packet: the engine drops
    /// anything `karst_tun::ip::addresses` refuses, so if a control frame
    /// somehow reached the IP path it would be counted as a source violation
    /// rather than delivered — but it must not reach that path at all, and the
    /// marker byte is what guarantees it.
    #[test]
    fn a_control_frame_is_not_a_valid_ip_packet() {
        let framed = encode_head_claim(&[0x11; 64], 42);
        assert!(
            karst_tun::ip::addresses(&framed).is_none(),
            "a control frame parsed as IP, so the two paths can collide"
        );
        assert_eq!(framed.first(), Some(&CONTROL_MARKER));
    }

    /// Zero is not a legal IP version. That is the whole reason the marker can
    /// be a discriminator rather than a reserved value someone has to police.
    #[test]
    fn the_marker_is_not_a_legal_ip_version() {
        for len in [1usize, 20, 40, 64] {
            let candidate = vec![CONTROL_MARKER; len];
            assert!(karst_tun::ip::addresses(&candidate).is_none());
        }
    }
}
