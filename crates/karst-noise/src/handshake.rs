// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `PHREATIC` handshake — `spec/phreatic-v1.md` §6 and §7.1.
//!
//! Sans-io and deterministic: every source of randomness is a caller-supplied
//! seed, so a handshake replays exactly. There is no clock and no socket here.
//!
//! Three ML-KEM-1024 encapsulations authenticate the responder and initiator
//! and provide forward secrecy. The per-pair PSK is mixed last.
//! PHREATIC accepts only the fixed CNSA 2.0 suite (ADR-0018).

use std::sync::Arc;

use karst_crypto::hash;
use karst_crypto::kem::{keypair_from_seed, KemKind, KemPublicKey, KemSecretKey};
use karst_crypto::{accepts_suite, message_sizes, KEM_CIPHERTEXT, SUITE_ID};

use crate::symmetric::{SymmetricState, TransportKeys};

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
/// `kem_sk` zeroizes on drop through the required `ml-kem/zeroize` feature.
pub struct StaticKeys {
    /// ML-KEM-1024 decapsulation key.
    pub kem_sk: KemSecretKey,
    /// ML-KEM encapsulation key — the input to `peer_id_hint`.
    pub kem_pk: KemPublicKey,
}

// Hand-written and redacting. Deriving `Debug` here would print decapsulation
// secret keys into any log line or diagnostics bundle that formatted
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
        // The PSK is secret; the public keys are not, but printing 1568 bytes
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
    /// Derive a node's ML-KEM-1024 keypair deterministically.
    #[must_use]
    pub fn from_seed(kem_seed: &[u8; 64]) -> Self {
        Self::from_seed_of_kind(KemKind::MlKem1024, kem_seed)
    }

    /// Derive a node's long-term keys at a chosen KEM parameter set.
    #[must_use]
    pub fn from_seed_of_kind(kind: KemKind, kem_seed: &[u8; 64]) -> Self {
        let (kem_sk, kem_pk) = keypair_from_seed(kind, kem_seed);
        Self { kem_sk, kem_pk }
    }

    /// The fixed KEM parameter set of this node's static key.
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
    /// Peer's ML-KEM-1024 encapsulation key.
    pub kem_pk: KemPublicKey,
    /// Per-pair PSK for the current epoch (§2.6). All-zero means the
    /// lattice-only fallback, which callers MUST surface (§7.3).
    pub psk: [u8; 32],
}

/// `peer_id_hint = SHA-512("Karst peer-id v1" ‖ S_pk)[0..32]` — §4.
///
/// Unsalted and session-independent, so a responder can precompute a lookup
/// table. Binding it to the session would make lookup O(N) per handshake.
///
/// Uses SHA-512 independently of the SHA-384 transcript. The static key is
/// also bound into the transcript at step 3 through SHA-384.
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
    /// Encapsulation randomness for `ct_s`.
    pub encap_rand: [u8; 32],
    /// TAI64N timestamp, for replay rejection.
    pub timestamp: [u8; TIMESTAMP_LEN],
}

/// Randomness a responder must supply.
#[derive(Debug, Clone, Copy)]
pub struct ResponderRandomness {
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
    e_kem_sk: KemSecretKey,
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
}

/// Build `HandshakeInit` and the state needed to finish — §7.1 steps 1–6.
///
/// # Errors
/// Returns an authentication error if encrypting the identity fails.
///
pub fn initiate(
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
    params: SessionParams,
    rand: &InitiatorRandomness,
) -> Result<(Initiator, Vec<u8>), HandshakeError> {
    let SessionParams {
        psk_epoch,
        sender_index,
    } = params;
    let kem = KemKind::MlKem1024;

    let (e_kem_sk, e_kem_pk) = keypair_from_seed(kem, &rand.e_kem_seed);
    let e_kem_pk_bytes = e_kem_pk.to_bytes();

    // The full 14-byte header prefix, bound as a unit (§13.4). Binding only
    // suite_id and psk_epoch would leave type, reserved and sender_index
    // unauthenticated.
    let mut prefix = Vec::with_capacity(14);
    prefix.push(0x01);
    prefix.extend_from_slice(&[0, 0, 0]);
    prefix.extend_from_slice(&sender_index.to_le_bytes());
    prefix.extend_from_slice(&SUITE_ID.to_le_bytes());
    prefix.extend_from_slice(&psk_epoch.to_le_bytes());

    let mut state = SymmetricState::new();
    // Steps 2–3: bind the header and the responder's identity before any
    // secret material (§13.2, §13.4).
    state.mix_hash(&prefix);
    let s_r = state.hash().digest(&[&peer.kem_pk.to_bytes()]);
    state.mix_hash(s_r.as_bytes());
    // Step 4.
    state.mix_hash(&e_kem_pk_bytes);
    // Step 5 — PQ authentication of the responder.
    let (ct_s, ss_s) = peer.kem_pk.encapsulate(&rand.encap_rand);
    state.mix_key(&ss_s);
    state.mix_hash(&ct_s);

    // Step 6.
    let mut ident = Vec::with_capacity(HINT_LEN + TIMESTAMP_LEN);
    ident.extend_from_slice(&keys.hint());
    ident.extend_from_slice(&rand.timestamp);
    let enc_ident = state
        .encrypt_and_hash(&ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    let mut msg = Vec::with_capacity(message_sizes().handshake_init);
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(&e_kem_pk_bytes);
    msg.extend_from_slice(&ct_s);
    msg.extend_from_slice(&enc_ident);

    Ok((
        Initiator {
            state,
            e_kem_sk,
            keys,
            peer,
        },
        msg,
    ))
}

impl Initiator {
    /// Consume `HandshakeResponse` and derive transport keys — §7.1 steps 7–10.
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
        let ct_len = KEM_CIPHERTEXT;
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
        let enc_empty = r.take(16)?;
        if !r.done() {
            return Err(HandshakeError::Malformed);
        }

        // Steps 7–8.
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

        // Step 9 — PSK last, gating the final key.
        state.mix_key_and_hash(&self.peer.psk);

        // §13.4 — bind the response header as received.
        state.mix_hash(in_prefix);

        // Step 10.
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
    kem: KemKind,
    psk_epoch: u32,
    e_kem_pk_bytes: &'a [u8],
    ct_s: &'a [u8],
    enc_ident: &'a [u8],
}

impl<'a> Init<'a> {
    fn parse(msg: &'a [u8]) -> Result<Self, HandshakeError> {
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
        if !accepts_suite(suite_wire) {
            return Err(HandshakeError::UnsupportedSuite);
        }
        let kem = KemKind::MlKem1024;

        let e_kem_pk_bytes = r.take(kem.public_key_len())?;
        let ct_s = r.take(kem.ciphertext_len())?;
        let enc_ident = r.take(HINT_LEN + TIMESTAMP_LEN + 16)?;
        if !r.done() {
            return Err(HandshakeError::Malformed);
        }

        Ok(Self {
            prefix,
            kem,
            psk_epoch: u32::from_le_bytes(
                psk_epoch_bytes
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?,
            ),
            e_kem_pk_bytes,
            ct_s,
            enc_ident,
        })
    }
}

/// Consume `HandshakeInit`, produce `HandshakeResponse` and unconfirmed keys.
///
/// `lookup` resolves a `peer_id_hint` *and a PSK epoch* to that peer's netmap
/// entry. Returning `None` yields [`HandshakeError::UnknownPeer`], which the
/// caller MUST discard silently. Epoch acceptance is the caller's policy: §7.3
/// requires accepting epoch *n* and *n−1* and rejecting anything else, which
/// this signature expresses by letting the resolver refuse.
///
/// # Errors
/// [`HandshakeError`] on malformed input, a refused suite, an unknown peer, or
/// failed authentication.
pub fn respond<F>(
    keys: &StaticKeys,
    msg: &[u8],
    lookup: F,
    rand: &ResponderRandomness,
    sender_index: u32,
) -> Result<(Vec<u8>, Unconfirmed<TransportKeys>), HandshakeError>
where
    F: FnOnce(&[u8; HINT_LEN], u32) -> Option<PeerPublic>,
{
    let Init {
        prefix,
        kem,
        psk_epoch,
        e_kem_pk_bytes,
        ct_s,
        enc_ident,
    } = Init::parse(msg)?;

    let e_kem_pk =
        KemPublicKey::from_bytes(kem, e_kem_pk_bytes).ok_or(HandshakeError::Malformed)?;
    let mut state = SymmetricState::new();
    state.mix_hash(prefix);
    let s_r = state.hash().digest(&[&keys.kem_pk.to_bytes()]);
    state.mix_hash(s_r.as_bytes());
    state.mix_hash(e_kem_pk_bytes);
    // Step 5 mirrored.
    let ss_s = keys
        .kem_sk
        .decapsulate(ct_s)
        .ok_or(HandshakeError::Malformed)?;
    state.mix_key(&ss_s);
    state.mix_hash(ct_s);

    // Step 6 mirrored — fails closed if the transcript differs at all.
    let ident = state
        .decrypt_and_hash(enc_ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;
    let hint_slice = ident.get(..HINT_LEN).ok_or(HandshakeError::Malformed)?;
    let mut hint = [0u8; HINT_LEN];
    hint.copy_from_slice(hint_slice);

    let peer = lookup(&hint, psk_epoch).ok_or(HandshakeError::UnknownPeer)?;
    // Steps 7–9 from the responder's side.

    let (ct_e, ss_e) = e_kem_pk.encapsulate(&rand.encap_rand_e);
    state.mix_key(&ss_e);
    state.mix_hash(&ct_e);
    let (ct_ss, ss_ss) = peer.kem_pk.encapsulate(&rand.encap_rand_s);
    state.mix_key(&ss_ss);
    state.mix_hash(&ct_ss);

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

    let mut out = Vec::with_capacity(message_sizes().handshake_response);
    out.extend_from_slice(&out_prefix);
    out.extend_from_slice(&ct_e);
    out.extend_from_slice(&ct_ss);
    out.extend_from_slice(&enc_empty);

    Ok((out, Unconfirmed(state.split())))
}
