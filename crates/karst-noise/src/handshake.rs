// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `PHREATIC` handshake — `spec/phreatic-v1.md` §6 and §7.1.
//!
//! Sans-io and deterministic: every source of randomness is a caller-supplied
//! seed, so a handshake replays exactly. There is no clock and no socket here.
//!
//! Three KEM encapsulations pair with three Diffie–Hellman operations:
//!
//! | Pair | Property |
//! |---|---|
//! | `ss_s` / `dh_es` | authenticates the responder |
//! | `ss_e` / `dh_ee` | forward secrecy |
//! | `ss_ss` / `dh_se` | authenticates the initiator |
//!
//! Each property therefore survives a break of *either* cryptographic family,
//! which is the claim of ADR-0002. The static X25519 key exists solely for this
//! — see spec §13.1 for why an ephemeral-only hybrid was insufficient.
//!
//! # `KARST_2` has no classical half, and that is not a weakening
//!
//! The CNSA 2.0 suite carries no X25519 (spec §3, ADR-0015 item 6): the profile
//! does not call for a classical hybrid, so the three DH operations above are
//! simply absent and `HandshakeInit` loses its 32-byte `e_dh_pk`. The hedge
//! ADR-0002 buys is real and `KARST_2` deliberately does not buy it — a
//! deployment under the mandate has been told which algorithms it may run, and
//! a hybrid it is not permitted to count on is 32 bytes of transcript for
//! nothing. What survives is the PSK, which is mixed last under every suite.
//!
//! # One node, one static KEM key
//!
//! The parameter set of a node's static KEM key is a deployment property, not a
//! per-session one: `peer_id_hint` is derived from that key (§4), so a node
//! holding both a Category 3 and a Category 5 static key would have two
//! identities. [`initiate`] and [`respond`] therefore refuse a suite whose KEM
//! is not the one this node's keys are — a `KARST_1` node and a `KARST_2` node
//! do not interoperate, which is exactly what a mandate means.

use std::sync::Arc;

use karst_crypto::hash;
use karst_crypto::kem::{keypair_from_seed, KemKind, KemPublicKey, KemSecretKey};
use karst_crypto::{SuiteId, SuitePolicy};
use x25519_dalek::{PublicKey as DhPublic, StaticSecret as DhSecret};

use crate::symmetric::{SymmetricState, TransportKeys};

// A compile-time guarantee, not a runtime one — this crate forbids
// `unsafe_code`, which rules out inspecting freed memory directly. `x25519
// -dalek`'s `zeroize(drop)` attribute predates the crate's `ZeroizeOnDrop`
// marker trait and does not implement it, so this checks for drop glue
// directly (`T: Drop` as a bound is a lint-flagged anti-pattern; `needs_drop`
// is the sanctioned way to ask the same question) rather than the marker —
// drop glue is what the fix actually needs, and `StaticSecret` has no other
// reason to carry any. If `Cargo.toml`'s `zeroize` feature on `x25519-dalek`
// is ever dropped, the build fails here rather than every static and
// ephemeral X25519 secret this crate holds silently going unzeroized again —
// see `StaticKeys`'s doc.
const _: () = assert!(core::mem::needs_drop::<DhSecret>());

/// `peer_id_hint` length — §4.
pub const HINT_LEN: usize = 32;
/// TAI64N timestamp — §6.1.
pub const TIMESTAMP_LEN: usize = 12;

/// Everything that can go wrong. Deliberately coarse: §11 mandates silent
/// discard, and a distinguishable error would be an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// Wrong length, bad framing, or an unparseable key.
    Malformed,
    /// Suite identifier absent from the allowlist (ADR-0006).
    UnsupportedSuite,
    /// `peer_id_hint` resolved to nothing. **Discard silently** — answering
    /// would make this node a roster-membership oracle (§11, ADR-0005).
    UnknownPeer,
    /// AEAD authentication failed: tampering, a transcript mismatch, wrong
    /// keys, or a wrong PSK. Indistinguishable on purpose.
    AuthenticationFailed,
}

/// A node's long-term keys — §4. The ML-DSA identity key is not used by
/// `PHREATIC` and is deliberately absent.
///
/// `kem_sk` and `dh_sk` zeroize on drop via their own crates' `Drop` impls —
/// `Cargo.toml`'s `zeroize` features on `ml-kem` and `x25519-dalek`, not
/// anything in this struct, is what makes that true (Phase 6 internal review;
/// see `karst-crypto::aead`'s module note for the AEAD half of the same gap).
pub struct StaticKeys {
    /// ML-KEM decapsulation key. Its parameter set fixes which suites this node
    /// can speak; see the module docs.
    pub kem_sk: KemSecretKey,
    /// ML-KEM encapsulation key — the input to `peer_id_hint`.
    pub kem_pk: KemPublicKey,
    /// X25519 static secret. Unused under `KARST_2`, which has no classical
    /// half; kept so one key file serves every profile.
    pub dh_sk: DhSecret,
    /// X25519 static public key.
    pub dh_pk: DhPublic,
}

// Hand-written and redacting. Deriving `Debug` here would print decapsulation
// and X25519 secret keys into any log line or diagnostics bundle that formatted
// the struct — a tracked leakage path (THREAT-MODEL R5).
impl core::fmt::Debug for StaticKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticKeys")
            .field("hint", &hex32(&self.hint()))
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for PeerPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The PSK is secret; the public keys are not, but printing 1184 bytes
        // helps nobody.
        f.debug_struct("PeerPublic")
            .field("hint", &hex32(&peer_id_hint(&self.kem_pk.to_bytes())))
            .field("kem", &self.kem_pk.kind().name())
            .field("psk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Initiator(<in-flight handshake>)")
    }
}

/// First eight bytes of a 32-byte value, for identifying keys in logs without
/// disclosing them.
fn hex32(v: &[u8; HINT_LEN]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(16);
    for b in v.iter().take(8) {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl StaticKeys {
    /// Derive a node's long-term keys deterministically, at ML-KEM-768.
    ///
    /// The shipping profile — `KARST_1` and `KARST_2`. A deployment under
    /// CNSA 2.0 wants [`Self::from_seed_of_kind`] with
    /// [`KemKind::MlKem1024`]; the same seed yields a *different* key there,
    /// and therefore a different `peer_id_hint`, because they are different
    /// identities.
    #[must_use]
    pub fn from_seed(kem_seed: &[u8; 64], dh_seed: &[u8; 32]) -> Self {
        Self::from_seed_of_kind(KemKind::MlKem768, kem_seed, dh_seed)
    }

    /// Derive a node's long-term keys at a chosen KEM parameter set.
    #[must_use]
    pub fn from_seed_of_kind(kind: KemKind, kem_seed: &[u8; 64], dh_seed: &[u8; 32]) -> Self {
        let (kem_sk, kem_pk) = keypair_from_seed(kind, kem_seed);
        let dh_sk = DhSecret::from(*dh_seed);
        let dh_pk = DhPublic::from(&dh_sk);
        Self {
            kem_sk,
            kem_pk,
            dh_sk,
            dh_pk,
        }
    }

    /// The KEM parameter set this node's static key belongs to, and so the one
    /// every suite it speaks must name.
    #[must_use]
    pub const fn kem_kind(&self) -> KemKind {
        self.kem_pk.kind()
    }

    /// This node's `peer_id_hint`.
    #[must_use]
    pub fn hint(&self) -> [u8; HINT_LEN] {
        peer_id_hint(&self.kem_pk.to_bytes())
    }
}

/// What the netmap supplies about a peer — §4.
#[derive(Clone)]
pub struct PeerPublic {
    /// Peer's ML-KEM encapsulation key. Its parameter set is the peer's, and
    /// must match the suite in use.
    pub kem_pk: KemPublicKey,
    /// Peer's X25519 static public key. Unused under `KARST_2`.
    pub dh_pk: DhPublic,
    /// Per-pair PSK for the current epoch (§2.6). All-zero means the
    /// lattice-only fallback, which callers MUST surface (§7.3).
    pub psk: [u8; 32],
}

/// `peer_id_hint = SHA-512("Karst peer-id v1" ‖ S_pk)[0..32]` — §4.
///
/// Unsalted and session-independent, so a responder can precompute a lookup
/// table. Binding it to the session would make lookup O(N) per handshake.
///
/// **SHA-512 under every suite, including the SHA-384 one.** This is a roster
/// lookup label, computed before any suite is known — a responder resolving an
/// inbound handshake has one table, not one per suite. The peer's static key
/// *is* bound to the session, at step 3, through the suite hash; that binding
/// is what the transcript rests on and this value is not part of it.
#[must_use]
pub fn peer_id_hint(kem_pk_bytes: &[u8]) -> [u8; HINT_LEN] {
    let out = hash::Algorithm::Sha512.digest(&[b"Karst peer-id v1", kem_pk_bytes]);
    let mut hint = [0u8; HINT_LEN];
    if let Some(head) = out.as_bytes().get(..HINT_LEN) {
        hint.copy_from_slice(head);
    }
    hint
}

/// Panic-free reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], HandshakeError> {
        let end = self.pos.checked_add(n).ok_or(HandshakeError::Malformed)?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or(HandshakeError::Malformed)?;
        self.pos = end;
        Ok(out)
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Session keys the **responder** has derived but not yet confirmed.
///
/// Having sent `HandshakeResponse` a responder has no evidence the initiator
/// exists — `HandshakeInit` is forgeable by anyone holding its public keys
/// (§12.5). Assurance arrives only with the first authenticated transport
/// message (§12.6), which `ProVerif` shows sharply: the agreement query is false
/// if the responder claims completion earlier and true if it waits.
///
/// This type makes that structural. Reaching [`TransportKeys`] requires calling
/// [`Unconfirmed::confirm`], so a responder cannot accidentally treat sending a
/// response as session establishment — it must not tear down an existing
/// session, record establishment in audit, or count quota before then.
#[derive(Debug)]
pub struct Unconfirmed<T>(T);

impl<T> Unconfirmed<T> {
    /// Consume on receipt of the first transport message that authenticates
    /// under these keys.
    pub fn confirm(self) -> T {
        self.0
    }

    /// Borrow the keys to *attempt* that authentication, without confirming.
    pub fn peek(&self) -> &T {
        &self.0
    }
}

/// Per-session parameters an initiator chooses — §6.1 header fields.
#[derive(Debug, Clone, Copy)]
pub struct SessionParams {
    /// Negotiated cipher suite (ADR-0006).
    pub suite: SuiteId,
    /// PSK epoch this handshake uses (§7.3).
    pub psk_epoch: u32,
    /// Local session index, for demultiplexing.
    pub sender_index: u32,
}

/// Randomness an initiator must supply.
///
/// This crate is sans-io and generates **no** randomness itself: every seed
/// comes from the caller, which is what makes a handshake replay exactly from a
/// recorded failure.
#[derive(Debug, Clone, Copy)]
pub struct InitiatorRandomness {
    /// Seed for the ephemeral ML-KEM keypair.
    pub e_kem_seed: [u8; 64],
    /// Seed for the ephemeral X25519 keypair.
    pub e_dh_seed: [u8; 32],
    /// Encapsulation randomness for `ct_s`.
    pub encap_rand: [u8; 32],
    /// TAI64N timestamp, for replay rejection.
    pub timestamp: [u8; TIMESTAMP_LEN],
}

/// Randomness a responder must supply.
#[derive(Debug, Clone, Copy)]
pub struct ResponderRandomness {
    /// Seed for the responder's ephemeral X25519 keypair.
    pub e_dh_seed: [u8; 32],
    /// Encapsulation randomness for `ct_e` (to the initiator's ephemeral).
    pub encap_rand_e: [u8; 32],
    /// Encapsulation randomness for `ct_ss` (to the initiator's static key).
    pub encap_rand_s: [u8; 32],
}

/// Initiator state between sending `HandshakeInit` and receiving the response.
///
/// # Why the two long-term inputs are shared rather than borrowed
///
/// They were `&'a StaticKeys` and `&'a PeerPublic`, which propagated a lifetime
/// all the way up through `Session` to the daemon's engine — and so pinned the
/// whole peer set to one owner for the life of the process. A netmap that adds
/// a peer could then only be applied by restarting.
///
/// `Arc` rather than owned copies: `StaticKeys` holds this node's private key,
/// and cloning it once per peer would put the same secret in N places to be
/// zeroized, for no benefit.
pub struct Initiator {
    state: SymmetricState,
    /// The suite agreed at [`initiate`]. Carried because it decides how long
    /// the response's fields are and whether it has an `e_dh_pk` at all —
    /// re-deriving it from the response would be reading an attacker-supplied
    /// field a second time, free to disagree with the transcript.
    suite: SuiteId,
    e_kem_sk: KemSecretKey,
    /// `None` under a suite with no classical half.
    e_dh_sk: Option<DhSecret>,
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
}

/// Build `HandshakeInit` and the state needed to finish — §7.1 steps 1–7.
///
/// Under a suite with `dh: None` — `KARST_2` — steps 6, 10 and 11 do not exist
/// and `e_dh_pk` is absent from both messages.
///
/// # Errors
/// [`HandshakeError::UnsupportedSuite`] if `suite` is not in the allowlist, or
/// if its KEM is not the parameter set this node's static key and this peer's
/// netmap entry are.
pub fn initiate(
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
    params: SessionParams,
    rand: &InitiatorRandomness,
) -> Result<(Initiator, Vec<u8>), HandshakeError> {
    let SessionParams {
        suite,
        psk_epoch,
        sender_index,
    } = params;
    if SuiteId::from_wire(suite.to_wire()).is_none() {
        return Err(HandshakeError::UnsupportedSuite);
    }
    let kem = KemKind::for_suite(suite);
    if kem != keys.kem_kind() || kem != peer.kem_pk.kind() {
        return Err(HandshakeError::UnsupportedSuite);
    }
    let uses_dh = suite.params().dh.is_some();

    let (e_kem_sk, e_kem_pk) = keypair_from_seed(kem, &rand.e_kem_seed);
    let e_kem_pk_bytes = e_kem_pk.to_bytes();
    let e_dh_sk = uses_dh.then(|| DhSecret::from(rand.e_dh_seed));
    let e_dh_pk = e_dh_sk.as_ref().map(DhPublic::from);

    // The full 14-byte header prefix, bound as a unit (§13.4). Binding only
    // suite_id and psk_epoch would leave type, reserved and sender_index
    // unauthenticated.
    let mut prefix = Vec::with_capacity(14);
    prefix.push(0x01);
    prefix.extend_from_slice(&[0, 0, 0]);
    prefix.extend_from_slice(&sender_index.to_le_bytes());
    prefix.extend_from_slice(&suite.to_wire().to_le_bytes());
    prefix.extend_from_slice(&psk_epoch.to_le_bytes());

    // The suite's AEAD and hash, not hardcoded ones — ADR-0015 items 2 and 1.
    // The suite id is already in `prefix` and so mixed into the transcript
    // before any secret material, which means the two ends cannot disagree
    // about either algorithm without every tag failing.
    let mut state = SymmetricState::for_suite(suite);
    // Steps 2–3: bind the header and the responder's identity before any
    // secret material (§13.2, §13.4).
    state.mix_hash(&prefix);
    let s_r = state.hash().digest(&[&peer.kem_pk.to_bytes()]);
    state.mix_hash(s_r.as_bytes());
    // Step 4.
    state.mix_hash(&e_kem_pk_bytes);
    if let Some(pk) = &e_dh_pk {
        state.mix_hash(pk.as_bytes());
    }

    // Step 5 — PQ authentication of the responder.
    let (ct_s, ss_s) = peer.kem_pk.encapsulate(&rand.encap_rand);
    state.mix_key(&ss_s);
    state.mix_hash(&ct_s);

    // Step 6 — classical authentication of the responder. Absent under a suite
    // with no classical half.
    if let Some(sk) = &e_dh_sk {
        state.mix_key(sk.diffie_hellman(&peer.dh_pk).as_bytes());
    }

    // Step 7.
    let mut ident = Vec::with_capacity(HINT_LEN + TIMESTAMP_LEN);
    ident.extend_from_slice(&keys.hint());
    ident.extend_from_slice(&rand.timestamp);
    let enc_ident = state
        .encrypt_and_hash(&ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    let mut msg = Vec::with_capacity(suite.params().message_sizes().handshake_init);
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(&e_kem_pk_bytes);
    if let Some(pk) = &e_dh_pk {
        msg.extend_from_slice(pk.as_bytes());
    }
    msg.extend_from_slice(&ct_s);
    msg.extend_from_slice(&enc_ident);

    Ok((
        Initiator {
            state,
            suite,
            e_kem_sk,
            e_dh_sk,
            keys,
            peer,
        },
        msg,
    ))
}

impl Initiator {
    /// Consume `HandshakeResponse` and derive transport keys — §7.1 steps 8–13.
    ///
    /// Takes `self` by value for callers that have exactly one response to try.
    /// A caller that must survive a *wrong* response wants [`Self::try_finish`].
    ///
    /// # Errors
    /// [`HandshakeError`] on malformed input or failed authentication.
    pub fn finish(self, msg: &[u8]) -> Result<TransportKeys, HandshakeError> {
        self.try_finish(msg)
    }

    /// Try to complete the handshake **without consuming the initiator**.
    ///
    /// The key schedule is advanced on a clone, so a response that fails to
    /// authenticate leaves this `Initiator` exactly as it was and the handshake
    /// can continue retrying.
    ///
    /// That matters because `frag_mac` is *not* an authenticator (§9.2): its key
    /// derives from a public static key, so anyone can produce fragments that
    /// pass it. If a failed response destroyed the handshake, an off-path
    /// attacker could cancel every connection attempt on the network by spraying
    /// well-formed garbage — no cryptographic break required. The AEAD tag is
    /// what decides, and until it does, nothing may be discarded.
    ///
    /// # Errors
    /// [`HandshakeError`] on malformed input or failed authentication.
    pub fn try_finish(&self, msg: &[u8]) -> Result<TransportKeys, HandshakeError> {
        // Work on a copy: `mix_key` and `mix_hash` below run *before* the only
        // step that can reject, so mutating in place would corrupt the schedule
        // for any subsequent attempt.
        let mut state = self.state.clone();
        let ct_len = KemKind::for_suite(self.suite).ciphertext_len();
        let in_prefix = msg.get(..12).ok_or(HandshakeError::Malformed)?;
        let mut r = Reader::new(msg);
        if r.take(1)?.first() != Some(&0x02) {
            return Err(HandshakeError::Malformed);
        }
        let _reserved = r.take(3)?;
        let _sender_index = r.take(4)?;
        let _receiver_index = r.take(4)?;
        let ct_e = r.take(ct_len)?;
        let ct_ss = r.take(ct_len)?;
        let e_dh_r = match &self.e_dh_sk {
            Some(_) => Some(r.take(32)?),
            None => None,
        };
        let enc_empty = r.take(16)?;
        if !r.done() {
            return Err(HandshakeError::Malformed);
        }

        // Steps 8–9.
        let ss_e = self
            .e_kem_sk
            .decapsulate(ct_e)
            .ok_or(HandshakeError::Malformed)?;
        state.mix_key(&ss_e);
        state.mix_hash(ct_e);
        let ss_ss = self
            .keys
            .kem_sk
            .decapsulate(ct_ss)
            .ok_or(HandshakeError::Malformed)?;
        state.mix_key(&ss_ss);
        state.mix_hash(ct_ss);

        // Steps 10–11, absent under a suite with no classical half.
        if let (Some(e_dh_sk), Some(e_dh_r)) = (&self.e_dh_sk, e_dh_r) {
            let mut dh_bytes = [0u8; 32];
            dh_bytes.copy_from_slice(e_dh_r);
            let e_dh_r_pk = DhPublic::from(dh_bytes);
            state.mix_key(e_dh_sk.diffie_hellman(&e_dh_r_pk).as_bytes());
            state.mix_hash(e_dh_r);
            state.mix_key(self.keys.dh_sk.diffie_hellman(&e_dh_r_pk).as_bytes());
        }

        // Step 12 — PSK last, gating the final key.
        state.mix_key_and_hash(&self.peer.psk);

        // §13.4 — bind the response header as received.
        state.mix_hash(in_prefix);

        // Step 13.
        state
            .decrypt_and_hash(enc_empty)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        Ok(state.split())
    }
}

/// A parsed `HandshakeInit`, borrowed from the datagram — §6.1.
///
/// Separate from [`respond`] because parsing and the key schedule answer
/// different questions, and the ordering inside this one matters: the suite is
/// resolved and *accepted* before a single length-dependent field is read, so a
/// refused suite costs nothing and cannot steer how the rest is interpreted.
struct Init<'a> {
    /// The 14 header bytes, bound verbatim (§13.4) — reserved bytes included,
    /// so tampering with any of them invalidates the transcript.
    prefix: &'a [u8],
    suite: SuiteId,
    kem: KemKind,
    psk_epoch: u32,
    e_kem_pk_bytes: &'a [u8],
    /// `None` under a suite with no classical half.
    e_dh_pk_bytes: Option<&'a [u8]>,
    ct_s: &'a [u8],
    enc_ident: &'a [u8],
}

impl<'a> Init<'a> {
    fn parse(
        keys: &StaticKeys,
        policy: &SuitePolicy,
        msg: &'a [u8],
    ) -> Result<Self, HandshakeError> {
        let prefix = msg.get(..14).ok_or(HandshakeError::Malformed)?;

        let mut r = Reader::new(msg);
        if r.take(1)?.first() != Some(&0x01) {
            return Err(HandshakeError::Malformed);
        }
        let _reserved = r.take(3)?;
        let _sender_index = r.take(4)?;
        let suite_bytes = r.take(2)?;
        let psk_epoch_bytes = r.take(4)?;

        let suite_wire = u16::from_le_bytes(
            suite_bytes
                .try_into()
                .map_err(|_| HandshakeError::Malformed)?,
        );
        let suite = SuiteId::from_wire(suite_wire).ok_or(HandshakeError::UnsupportedSuite)?;
        // Downgrade protection, enforced locally (ADR-0006).
        if !policy.accepts(suite) {
            return Err(HandshakeError::UnsupportedSuite);
        }
        let kem = KemKind::for_suite(suite);
        // A suite this node's own static key cannot serve. A policy consistent
        // with the key makes this unreachable; it is here because the two are
        // configured separately and a mismatch must not become a decapsulation
        // failure that looks like an attack.
        if kem != keys.kem_kind() {
            return Err(HandshakeError::UnsupportedSuite);
        }

        let e_kem_pk_bytes = r.take(kem.public_key_len())?;
        let e_dh_pk_bytes = match suite.params().dh {
            Some(_) => Some(r.take(32)?),
            None => None,
        };
        let ct_s = r.take(kem.ciphertext_len())?;
        let enc_ident = r.take(HINT_LEN + TIMESTAMP_LEN + 16)?;
        if !r.done() {
            return Err(HandshakeError::Malformed);
        }

        Ok(Self {
            prefix,
            suite,
            kem,
            psk_epoch: u32::from_le_bytes(
                psk_epoch_bytes
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?,
            ),
            e_kem_pk_bytes,
            e_dh_pk_bytes,
            ct_s,
            enc_ident,
        })
    }
}

/// Consume `HandshakeInit`, produce `HandshakeResponse` and unconfirmed keys.
///
/// `policy` enforces the minimum acceptable suite **at the node** — a
/// compromised coordination server can raise the floor but never lower it
/// (ADR-0006).
///
/// `lookup` resolves a `peer_id_hint` *and a PSK epoch* to that peer's netmap
/// entry. Returning `None` yields [`HandshakeError::UnknownPeer`], which the
/// caller MUST discard silently. Epoch acceptance is the caller's policy: §7.3
/// requires accepting epoch *n* and *n−1* and rejecting anything else, which
/// this signature expresses by letting the resolver refuse.
///
/// # Errors
/// [`HandshakeError`] on malformed input, a refused suite, an unknown peer, or
/// failed authentication. [`HandshakeError::UnsupportedSuite`] also covers a
/// suite whose KEM parameter set is not the one this node's static key — or the
/// resolved peer's netmap entry — belongs to.
pub fn respond<F>(
    keys: &StaticKeys,
    policy: &SuitePolicy,
    msg: &[u8],
    lookup: F,
    rand: &ResponderRandomness,
    sender_index: u32,
) -> Result<(Vec<u8>, Unconfirmed<TransportKeys>, SuiteId), HandshakeError>
where
    F: FnOnce(&[u8; HINT_LEN], u32) -> Option<PeerPublic>,
{
    let Init {
        prefix,
        suite,
        kem,
        psk_epoch,
        e_kem_pk_bytes,
        e_dh_pk_bytes,
        ct_s,
        enc_ident,
    } = Init::parse(keys, policy, msg)?;

    let e_kem_pk =
        KemPublicKey::from_bytes(kem, e_kem_pk_bytes).ok_or(HandshakeError::Malformed)?;
    let e_dh_pk = e_dh_pk_bytes.map(|b| {
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(b);
        DhPublic::from(dh_bytes)
    });
    // Mirror steps 2–4, with the AEAD and hash the *offered* suite selects —
    // which the policy check has already accepted.
    let mut state = SymmetricState::for_suite(suite);
    state.mix_hash(prefix);
    let s_r = state.hash().digest(&[&keys.kem_pk.to_bytes()]);
    state.mix_hash(s_r.as_bytes());
    state.mix_hash(e_kem_pk_bytes);
    if let Some(b) = e_dh_pk_bytes {
        state.mix_hash(b);
    }

    // Step 5 mirrored.
    let ss_s = keys
        .kem_sk
        .decapsulate(ct_s)
        .ok_or(HandshakeError::Malformed)?;
    state.mix_key(&ss_s);
    state.mix_hash(ct_s);

    // Step 6 mirrored.
    if let Some(pk) = &e_dh_pk {
        state.mix_key(keys.dh_sk.diffie_hellman(pk).as_bytes());
    }

    // Step 7 mirrored — fails closed if the transcript differs at all.
    let ident = state
        .decrypt_and_hash(enc_ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;
    let hint_slice = ident.get(..HINT_LEN).ok_or(HandshakeError::Malformed)?;
    let mut hint = [0u8; HINT_LEN];
    hint.copy_from_slice(hint_slice);

    let peer = lookup(&hint, psk_epoch).ok_or(HandshakeError::UnknownPeer)?;
    // A roster entry at the wrong category for the offered suite. Refused
    // rather than encapsulated to, which would produce a `ct_ss` the initiator
    // could not decapsulate and an unexplainable tag failure at step 13.
    if peer.kem_pk.kind() != kem {
        return Err(HandshakeError::UnsupportedSuite);
    }

    // Steps 8–12 from the responder's side.
    let r_dh_sk = e_dh_pk.as_ref().map(|_| DhSecret::from(rand.e_dh_seed));
    let r_dh_pk = r_dh_sk.as_ref().map(DhPublic::from);

    let (ct_e, ss_e) = e_kem_pk.encapsulate(&rand.encap_rand_e);
    state.mix_key(&ss_e);
    state.mix_hash(&ct_e);
    let (ct_ss, ss_ss) = peer.kem_pk.encapsulate(&rand.encap_rand_s);
    state.mix_key(&ss_ss);
    state.mix_hash(&ct_ss);

    if let (Some(sk), Some(pk), Some(e_dh_pk)) = (&r_dh_sk, &r_dh_pk, &e_dh_pk) {
        state.mix_key(sk.diffie_hellman(e_dh_pk).as_bytes());
        state.mix_hash(pk.as_bytes());
        state.mix_key(sk.diffie_hellman(&peer.dh_pk).as_bytes());
    }

    state.mix_key_and_hash(&peer.psk);

    // Bind HandshakeResponse's own header before sealing (§13.4).
    let mut out_prefix = Vec::with_capacity(12);
    out_prefix.push(0x02);
    out_prefix.extend_from_slice(&[0, 0, 0]);
    out_prefix.extend_from_slice(&sender_index.to_le_bytes());
    out_prefix.extend_from_slice(&0u32.to_le_bytes());
    state.mix_hash(&out_prefix);

    let enc_empty = state
        .encrypt_and_hash(&[])
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(suite.params().message_sizes().handshake_response);
    out.extend_from_slice(&out_prefix);
    out.extend_from_slice(&ct_e);
    out.extend_from_slice(&ct_ss);
    if let Some(pk) = &r_dh_pk {
        out.extend_from_slice(pk.as_bytes());
    }
    out.extend_from_slice(&enc_empty);

    // The suite comes back with the keys because the *responder* does not
    // choose it — the initiator does, in a header this function parsed. A
    // caller that had to re-parse the datagram to learn which AEAD to use
    // would be a second reading of an attacker-supplied field, free to
    // disagree with the one the transcript was built from.
    Ok((out, Unconfirmed(state.split()), suite))
}
