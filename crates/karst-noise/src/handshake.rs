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

use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as DhPublic, StaticSecret as DhSecret};

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
pub struct StaticKeys {
    /// ML-KEM-768 decapsulation key.
    pub kem_sk: <MlKem as Kem>::SecretKey,
    /// ML-KEM-768 encapsulation key.
    pub kem_pk: <MlKem as Kem>::PublicKey,
    /// X25519 static secret.
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
            .field(
                "hint",
                &hex32(&peer_id_hint(&MlKem::public_key_bytes(&self.kem_pk))),
            )
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
    /// Derive a node's long-term keys deterministically.
    #[must_use]
    pub fn from_seed(kem_seed: &[u8; 64], dh_seed: &[u8; 32]) -> Self {
        let (kem_sk, kem_pk) = MlKem::keypair_from_seed(kem_seed);
        let dh_sk = DhSecret::from(*dh_seed);
        let dh_pk = DhPublic::from(&dh_sk);
        Self {
            kem_sk,
            kem_pk,
            dh_sk,
            dh_pk,
        }
    }

    /// This node's `peer_id_hint`.
    #[must_use]
    pub fn hint(&self) -> [u8; HINT_LEN] {
        peer_id_hint(&MlKem::public_key_bytes(&self.kem_pk))
    }
}

/// What the netmap supplies about a peer — §4.
#[derive(Clone)]
pub struct PeerPublic {
    /// Peer's ML-KEM-768 encapsulation key.
    pub kem_pk: <MlKem as Kem>::PublicKey,
    /// Peer's X25519 static public key.
    pub dh_pk: DhPublic,
    /// Per-pair PSK for the current epoch (§2.6). All-zero means the
    /// lattice-only fallback, which callers MUST surface (§7.3).
    pub psk: [u8; 32],
}

/// `peer_id_hint = HASH("Karst peer-id v1" ‖ S_pk)[0..32]` — §4.
///
/// Unsalted and session-independent, so a responder can precompute a lookup
/// table. Binding it to the session would make lookup O(N) per handshake.
#[must_use]
pub fn peer_id_hint(kem_pk_bytes: &[u8]) -> [u8; HINT_LEN] {
    let mut d = Sha512::new();
    d.update(b"Karst peer-id v1");
    d.update(kem_pk_bytes);
    let out = d.finalize();
    let mut hint = [0u8; HINT_LEN];
    if let Some(head) = out.get(..HINT_LEN) {
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
    e_kem_sk: <MlKem as Kem>::SecretKey,
    e_dh_sk: DhSecret,
    keys: Arc<StaticKeys>,
    peer: Arc<PeerPublic>,
}

/// Build `HandshakeInit` and the state needed to finish — §7.1 steps 1–7.
///
/// # Errors
/// [`HandshakeError::UnsupportedSuite`] if `suite` is not in the allowlist.
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

    let (e_kem_sk, e_kem_pk) = MlKem::keypair_from_seed(&rand.e_kem_seed);
    let e_dh_sk = DhSecret::from(rand.e_dh_seed);
    let e_dh_pk = DhPublic::from(&e_dh_sk);
    let e_kem_pk_bytes = MlKem::public_key_bytes(&e_kem_pk);

    // The full 14-byte header prefix, bound as a unit (§13.4). Binding only
    // suite_id and psk_epoch would leave type, reserved and sender_index
    // unauthenticated.
    let mut prefix = Vec::with_capacity(14);
    prefix.push(0x01);
    prefix.extend_from_slice(&[0, 0, 0]);
    prefix.extend_from_slice(&sender_index.to_le_bytes());
    prefix.extend_from_slice(&suite.to_wire().to_le_bytes());
    prefix.extend_from_slice(&psk_epoch.to_le_bytes());

    let mut state = SymmetricState::new();
    // Steps 2–3: bind the header and the responder's identity before any
    // secret material (§13.2, §13.4).
    state.mix_hash(&prefix);
    let mut d = Sha512::new();
    d.update(MlKem::public_key_bytes(&peer.kem_pk));
    state.mix_hash(&d.finalize());
    // Step 4.
    state.mix_hash(&e_kem_pk_bytes);
    state.mix_hash(e_dh_pk.as_bytes());

    // Step 5 — PQ authentication of the responder.
    let (ct_s, ss_s) = MlKem::encapsulate(&peer.kem_pk, &rand.encap_rand);
    state.mix_key(&ss_s);
    state.mix_hash(&ct_s);

    // Step 6 — classical authentication of the responder.
    let dh_es = e_dh_sk.diffie_hellman(&peer.dh_pk);
    state.mix_key(dh_es.as_bytes());

    // Step 7.
    let mut ident = Vec::with_capacity(HINT_LEN + TIMESTAMP_LEN);
    ident.extend_from_slice(&keys.hint());
    ident.extend_from_slice(&rand.timestamp);
    let enc_ident = state
        .encrypt_and_hash(&ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    let mut msg = Vec::with_capacity(2378);
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(&e_kem_pk_bytes);
    msg.extend_from_slice(e_dh_pk.as_bytes());
    msg.extend_from_slice(&ct_s);
    msg.extend_from_slice(&enc_ident);

    Ok((
        Initiator {
            state,
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
        let in_prefix = msg.get(..12).ok_or(HandshakeError::Malformed)?;
        let mut r = Reader::new(msg);
        if r.take(1)?.first() != Some(&0x02) {
            return Err(HandshakeError::Malformed);
        }
        let _reserved = r.take(3)?;
        let _sender_index = r.take(4)?;
        let _receiver_index = r.take(4)?;
        let ct_e = r.take(MlKem::CIPHERTEXT_LEN)?;
        let ct_ss = r.take(MlKem::CIPHERTEXT_LEN)?;
        let e_dh_r = r.take(32)?;
        let enc_empty = r.take(16)?;
        if !r.done() {
            return Err(HandshakeError::Malformed);
        }

        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(e_dh_r);
        let e_dh_r_pk = DhPublic::from(dh_bytes);

        // Steps 8–9.
        let ss_e = MlKem::decapsulate(&self.e_kem_sk, ct_e).ok_or(HandshakeError::Malformed)?;
        state.mix_key(&ss_e);
        state.mix_hash(ct_e);
        let ss_ss =
            MlKem::decapsulate(&self.keys.kem_sk, ct_ss).ok_or(HandshakeError::Malformed)?;
        state.mix_key(&ss_ss);
        state.mix_hash(ct_ss);

        // Steps 10–11.
        state.mix_key(self.e_dh_sk.diffie_hellman(&e_dh_r_pk).as_bytes());
        state.mix_hash(e_dh_r);
        state.mix_key(self.keys.dh_sk.diffie_hellman(&e_dh_r_pk).as_bytes());

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
/// failed authentication.
pub fn respond<F>(
    keys: &StaticKeys,
    policy: &SuitePolicy,
    msg: &[u8],
    lookup: F,
    rand: &ResponderRandomness,
    sender_index: u32,
) -> Result<(Vec<u8>, Unconfirmed<TransportKeys>), HandshakeError>
where
    F: FnOnce(&[u8; HINT_LEN], u32) -> Option<PeerPublic>,
{
    // Bind the received header prefix verbatim (§13.4): whatever the peer
    // actually sent, including reserved bytes, must match our transcript.
    let prefix = msg.get(..14).ok_or(HandshakeError::Malformed)?;

    let mut r = Reader::new(msg);
    if r.take(1)?.first() != Some(&0x01) {
        return Err(HandshakeError::Malformed);
    }
    let _reserved = r.take(3)?;
    let _sender_index = r.take(4)?;
    let suite_bytes = r.take(2)?;
    let psk_epoch_bytes = r.take(4)?;
    let e_kem_pk_bytes = r.take(MlKem::PUBLIC_KEY_LEN)?;
    let e_dh_pk_bytes = r.take(32)?;
    let ct_s = r.take(MlKem::CIPHERTEXT_LEN)?;
    let enc_ident = r.take(HINT_LEN + TIMESTAMP_LEN + 16)?;
    if !r.done() {
        return Err(HandshakeError::Malformed);
    }

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
    let psk_epoch = u32::from_le_bytes(
        psk_epoch_bytes
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?,
    );

    let e_kem_pk = MlKem::public_key_from_bytes(e_kem_pk_bytes).ok_or(HandshakeError::Malformed)?;
    let mut dh_bytes = [0u8; 32];
    dh_bytes.copy_from_slice(e_dh_pk_bytes);
    let e_dh_pk = DhPublic::from(dh_bytes);

    // Mirror steps 2–4.
    let mut state = SymmetricState::new();
    state.mix_hash(prefix);
    let mut d = Sha512::new();
    d.update(MlKem::public_key_bytes(&keys.kem_pk));
    state.mix_hash(&d.finalize());
    state.mix_hash(e_kem_pk_bytes);
    state.mix_hash(e_dh_pk_bytes);

    // Step 5 mirrored.
    let ss_s = MlKem::decapsulate(&keys.kem_sk, ct_s).ok_or(HandshakeError::Malformed)?;
    state.mix_key(&ss_s);
    state.mix_hash(ct_s);

    // Step 6 mirrored.
    state.mix_key(keys.dh_sk.diffie_hellman(&e_dh_pk).as_bytes());

    // Step 7 mirrored — fails closed if the transcript differs at all.
    let ident = state
        .decrypt_and_hash(enc_ident)
        .map_err(|_| HandshakeError::AuthenticationFailed)?;
    let hint_slice = ident.get(..HINT_LEN).ok_or(HandshakeError::Malformed)?;
    let mut hint = [0u8; HINT_LEN];
    hint.copy_from_slice(hint_slice);

    let peer = lookup(&hint, psk_epoch).ok_or(HandshakeError::UnknownPeer)?;

    // Steps 8–12 from the responder's side.
    let r_dh_sk = DhSecret::from(rand.e_dh_seed);
    let r_dh_pk = DhPublic::from(&r_dh_sk);

    let (ct_e, ss_e) = MlKem::encapsulate(&e_kem_pk, &rand.encap_rand_e);
    state.mix_key(&ss_e);
    state.mix_hash(&ct_e);
    let (ct_ss, ss_ss) = MlKem::encapsulate(&peer.kem_pk, &rand.encap_rand_s);
    state.mix_key(&ss_ss);
    state.mix_hash(&ct_ss);

    state.mix_key(r_dh_sk.diffie_hellman(&e_dh_pk).as_bytes());
    state.mix_hash(r_dh_pk.as_bytes());
    state.mix_key(r_dh_sk.diffie_hellman(&peer.dh_pk).as_bytes());

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

    let mut out = Vec::with_capacity(2236);
    out.extend_from_slice(&out_prefix);
    out.extend_from_slice(&ct_e);
    out.extend_from_slice(&ct_ss);
    out.extend_from_slice(r_dh_pk.as_bytes());
    out.extend_from_slice(&enc_empty);

    Ok((out, Unconfirmed(state.split())))
}
