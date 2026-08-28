// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Entry types, the hash chain, and the encoding — `spec/bedrock-v1.md` §3.
//!
//! # Bodies are opaque here, on purpose
//!
//! An entry's body is a `Vec<u8>`. This module builds bodies (for the offline
//! signer) and parses them (for display and policy), but it never
//! *re-serialises* one it was given: the bytes that were signed are the bytes
//! that are hashed.
//!
//! A parse-then-reserialise round trip is where canonicalisation bugs live, and
//! §3.3 exists to ensure this code has none. If a `fn encode(&self)` on a
//! parsed body ever appears on the verification path, that is the bug this
//! comment is here to prevent.

use sha2::{Digest, Sha512};

use crate::codec::{put_lp, put_u32, put_u64, Cursor};
use crate::Error;

use karst_crypto::sign::{
    AUTHORITY_PUBLIC_KEY, NODE_IDENTITY_KEY, ROOT_PUBLIC_KEY, ROOT_SIGNATURE,
};

/// Domain separator for the Bedrock chain. Written bare; every field after it
/// is length-prefixed.
pub const CHAIN_LABEL: &[u8] = b"karst-bedrock-v1";

/// Bounds a signature count and a key-list length. A sanity limit, not policy.
pub(crate) const MAX_SIGNERS: u32 = 64;

/// Bounds a decoded log, so a four-byte count is not an allocation primitive.
const MAX_LOG_ENTRIES: u32 = 1 << 20;

/// An entry's operation.
///
/// The set is closed: §4 rule 5 makes an unknown op a hard verification failure
/// rather than a skipped entry, because a verifier that ignores what it does
/// not understand can be handed a log whose meaning it does not share with its
/// peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Genesis,
    AuthorityList,
    NodeSign,
    NodeRevoke,
    QuorumChange,
    Anchor,
    Disable,
}

impl Op {
    /// The wire spelling. These strings are hashed, so they are part of the
    /// protocol and not a display choice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::AuthorityList => "authority-list",
            Self::NodeSign => "node-sign",
            Self::NodeRevoke => "node-revoke",
            Self::QuorumChange => "quorum-change",
            Self::Anchor => "anchor",
            Self::Disable => "disable",
        }
    }

    /// Parse a wire spelling. `None` is a hard failure at the call site.
    ///
    /// Deliberately not `FromStr`: that trait's `Err` would have to carry the
    /// unknown op, and every caller here wants the `Option` so it can turn the
    /// miss into [`Error::UnknownOp`] with the original string attached.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "genesis" => Some(Self::Genesis),
            "authority-list" => Some(Self::AuthorityList),
            "node-sign" => Some(Self::NodeSign),
            "node-revoke" => Some(Self::NodeRevoke),
            "quorum-change" => Some(Self::QuorumChange),
            "anchor" => Some(Self::Anchor),
            "disable" => Some(Self::Disable),
            _ => None,
        }
    }

    /// Which key list this op's signatures index into.
    #[must_use]
    pub const fn tier(self) -> Tier {
        match self {
            Self::Genesis | Self::AuthorityList | Self::Disable => Tier::Root,
            Self::NodeSign | Self::NodeRevoke | Self::QuorumChange | Self::Anchor => {
                Tier::Authority
            }
        }
    }
}

/// Which tier signs an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The offline root list, threshold `k`.
    Root,
    /// The authority list, threshold `q`.
    Authority,
}

/// One signer's signature over an entry hash, carried with the index of the key
/// that produced it.
///
/// An index rather than a public key: the log already defines the list, and
/// four bytes cost 1 948 fewer than repeating an ML-DSA-65 key on every entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub signer_index: u32,
    pub sig: Vec<u8>,
}

/// One record in the log.
///
/// `hash` is not carried on the wire and is not part of the encoding; it is
/// computed during verification. Carrying it would create a second source of
/// truth and the question of which one to believe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// Unix **seconds** — §3.2.
    pub time: i64,
    pub op: Op,
    pub body: Vec<u8>,
    pub sigs: Vec<Signature>,
}

impl Entry {
    /// What a signer signs: this entry's chain hash.
    ///
    /// Takes `prev` explicitly because an entry does not know its own
    /// predecessor — which is the point. A signature is over a position in a
    /// specific history, so the same `node-sign` at a different point in a
    /// different chain is a different signature.
    #[must_use]
    pub fn signing_input(&self, prev: &[u8]) -> Vec<u8> {
        chain_hash(prev, self.seq, self.time, self.op, &self.body)
    }

    /// Serialise this entry — see [`encode_log`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_lp(&mut out, &self.seq.to_be_bytes());
        #[allow(clippy::cast_sign_loss)] // the encoding is a fixed 64-bit field
        put_lp(&mut out, &(self.time as u64).to_be_bytes());
        put_lp(&mut out, self.op.as_str().as_bytes());
        put_lp(&mut out, &self.body);
        put_u32(&mut out, u32::try_from(self.sigs.len()).unwrap_or(u32::MAX));
        for s in &self.sigs {
            put_u32(&mut out, s.signer_index);
            put_lp(&mut out, &s.sig);
        }
        out
    }

    /// Parse one encoded entry — §3.6.
    ///
    /// Separate from [`decode_log`] because the control plane carries entries
    /// individually (`KarstBedrockResponse.entries`), so a caller reassembling
    /// a fetch has one entry at a time and no surrounding log framing.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on truncation or trailing bytes, and
    /// [`Error::UnknownOp`] on an op this version does not know.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(buf);
        let seq_raw = c.lp()?;
        let time_raw = c.lp()?;
        let op_raw = c.lp_str()?;
        let body = c.lp()?.to_vec();

        let seq = u64::from_be_bytes(seq_raw.try_into().map_err(|_| Error::Malformed)?);
        let time_bits = u64::from_be_bytes(time_raw.try_into().map_err(|_| Error::Malformed)?);
        #[allow(clippy::cast_possible_wrap)] // round-trips the Go encoding
        let time = time_bits as i64;

        // An unknown op fails here rather than being carried as an opaque
        // string: §4 rule 5.
        let op = Op::parse(&op_raw).ok_or(Error::UnknownOp(op_raw))?;

        let n = c.u32()?;
        if n > MAX_SIGNERS {
            return Err(Error::Malformed);
        }
        let mut sigs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let signer_index = c.u32()?;
            let sig = c.lp()?.to_vec();
            sigs.push(Signature { signer_index, sig });
        }
        c.finish()?;

        Ok(Self {
            seq,
            time,
            op,
            body,
            sigs,
        })
    }
}

/// Compute an entry's hash from its content and its predecessor.
///
/// ```text
/// SHA-512(CHAIN_LABEL ‖ LP(prev) ‖ LP(BE64(seq)) ‖ LP(BE64(time))
///                     ‖ LP(op) ‖ LP(body))
/// ```
///
/// Every field is length-prefixed, including `op`. PLAN.md's sketch left `op`
/// bare; a bare variable-length field followed by a length prefix is exactly
/// the ambiguity §3.3 exists to remove, so the prefix was added and spec §3.2
/// records the deviation.
#[must_use]
pub fn chain_hash(prev: &[u8], seq: u64, time: i64, op: Op, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    put_lp(&mut buf, prev);
    put_lp(&mut buf, &seq.to_be_bytes());
    #[allow(clippy::cast_sign_loss)] // the encoding is a fixed 64-bit field
    put_lp(&mut buf, &(time as u64).to_be_bytes());
    put_lp(&mut buf, op.as_str().as_bytes());
    put_lp(&mut buf, body);

    let mut h = Sha512::new();
    h.update(CHAIN_LABEL);
    h.update(&buf);
    h.finalize().to_vec()
}

// ── log encoding ────────────────────────────────────────────────────────────
//
// One encoder serves storage, the offline signer's bundles, the node's cache,
// and the control-plane wire (carried as opaque `bytes` in the proto message).
// Protobuf is not canonical, so putting the entry *inside* a bytes field rather
// than modelling it as a message is what keeps the two implementations from
// having to agree on a protobuf serialiser's field ordering.

/// Serialise a whole log: `BE32(count) ‖ count × LP(entry)`.
#[must_use]
pub fn encode_log(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, u32::try_from(entries.len()).unwrap_or(u32::MAX));
    for e in entries {
        put_lp(&mut out, &e.encode());
    }
    out
}

/// Parse a whole log.
///
/// # Errors
///
/// Returns [`Error::Malformed`] on truncation, trailing bytes, or an absurd
/// entry count, and [`Error::UnknownOp`] on an op this version does not know.
pub fn decode_log(buf: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut c = Cursor::new(buf);
    let n = c.u32()?;
    if n > MAX_LOG_ENTRIES {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        out.push(Entry::decode(c.lp()?)?);
    }
    c.finish()?;
    Ok(out)
}

// ── bodies ──────────────────────────────────────────────────────────────────

/// A parsed `genesis` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub zone: String,
    pub roots: Vec<Vec<u8>>,
    pub k: u32,
    pub authorities: Vec<Vec<u8>>,
    pub q: u32,
}

/// A parsed `node-sign` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSign {
    pub handle: String,
    /// The ML-DSA-65 control-channel key the handle derives from.
    pub identity_key: Vec<u8>,
    /// The static keys PHREATIC authenticates against — spec §6.1.
    pub kem_public_key: Vec<u8>,
    pub dh_public_key: Vec<u8>,
    pub not_before: i64,
    /// Zero means no expiry.
    pub expiry: i64,
}

/// Derive the stable handle for an ML-DSA-65 identity key.
///
/// The same construction as `karst-control-client`'s `handle::handle` and the
/// Go side's `node.Handle`. Duplicated here rather than depended upon: this
/// crate sits below the control client by design (no I/O, no transport), and
/// six lines of hashing is a smaller cost than the layering inversion.
#[must_use]
pub fn node_handle(identity_key: &[u8]) -> String {
    use base64ct::{Base64, Encoding as _};
    use sha2::Sha256;
    let mut h = Sha256::new();
    h.update(b"karst-node-handle-v1");
    h.update(identity_key);
    Base64::encode_string(&h.finalize())
}

/// ML-KEM-768 static public key size (`S_pk`).
pub const KEM_PUBLIC_KEY: usize = 1184;
/// X25519 static public key size (`D_pk`).
pub const DH_PUBLIC_KEY: usize = 32;

/// A parsed `node-revoke` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRevoke {
    pub handle: String,
    pub reason: String,
    pub effective: i64,
}

/// A parsed `authority-list` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityList {
    pub authorities: Vec<Vec<u8>>,
    pub q: u32,
}

/// A parsed `anchor` body: an audit-log head published into a log the server
/// cannot rewrite. This is what closes `audit.go`'s tail-truncation gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub audit_head: Vec<u8>,
    pub audit_seq: u64,
}

#[allow(clippy::cast_possible_wrap)] // times round-trip the Go encoding
fn read_time(c: &mut Cursor<'_>) -> Result<i64, Error> {
    Ok(c.u64()? as i64)
}

/// Parse a `genesis` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on any layout violation.
pub fn parse_genesis(body: &[u8]) -> Result<Genesis, Error> {
    let mut c = Cursor::new(body);
    let zone = c.lp_str()?;
    let roots = c.keys(ROOT_PUBLIC_KEY, MAX_SIGNERS)?;
    let k = c.u32()?;
    let authorities = c.keys(AUTHORITY_PUBLIC_KEY, MAX_SIGNERS)?;
    let q = c.u32()?;
    c.finish()?;
    Ok(Genesis {
        zone,
        roots,
        k,
        authorities,
        q,
    })
}

/// Parse an `authority-list` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on any layout violation.
pub fn parse_authority_list(body: &[u8]) -> Result<AuthorityList, Error> {
    let mut c = Cursor::new(body);
    let authorities = c.keys(AUTHORITY_PUBLIC_KEY, MAX_SIGNERS)?;
    let q = c.u32()?;
    c.finish()?;
    Ok(AuthorityList { authorities, q })
}

/// Parse a `node-sign` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on a wrong-sized key, an empty handle, or slack.
pub fn parse_node_sign(body: &[u8]) -> Result<NodeSign, Error> {
    let mut c = Cursor::new(body);
    let handle = c.lp_str()?;
    let identity_key = c.lp()?.to_vec();
    let kem_public_key = c.lp()?.to_vec();
    let dh_public_key = c.lp()?.to_vec();
    let not_before = read_time(&mut c)?;
    let expiry = read_time(&mut c)?;
    c.finish()?;
    if identity_key.len() != NODE_IDENTITY_KEY
        || kem_public_key.len() != KEM_PUBLIC_KEY
        || dh_public_key.len() != DH_PUBLIC_KEY
        || handle.is_empty()
    {
        return Err(Error::Malformed);
    }
    Ok(NodeSign {
        handle,
        identity_key,
        kem_public_key,
        dh_public_key,
        not_before,
        expiry,
    })
}

/// Parse a `node-revoke` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on an empty handle or slack.
pub fn parse_node_revoke(body: &[u8]) -> Result<NodeRevoke, Error> {
    let mut c = Cursor::new(body);
    let handle = c.lp_str()?;
    let reason = c.lp_str()?;
    let effective = read_time(&mut c)?;
    c.finish()?;
    if handle.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(NodeRevoke {
        handle,
        reason,
        effective,
    })
}

/// Parse a `quorum-change` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on slack.
pub fn parse_quorum_change(body: &[u8]) -> Result<u32, Error> {
    let mut c = Cursor::new(body);
    let q = c.u32()?;
    c.finish()?;
    Ok(q)
}

/// Parse an `anchor` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on slack.
pub fn parse_anchor(body: &[u8]) -> Result<Anchor, Error> {
    let mut c = Cursor::new(body);
    let audit_head = c.lp()?.to_vec();
    let audit_seq = c.u64()?;
    c.finish()?;
    Ok(Anchor {
        audit_head,
        audit_seq,
    })
}

/// Parse a `disable` body — §3.4.
///
/// # Errors
///
/// [`Error::Malformed`] on slack.
pub fn parse_disable(body: &[u8]) -> Result<String, Error> {
    let mut c = Cursor::new(body);
    let reason = c.lp_str()?;
    c.finish()?;
    Ok(reason)
}

// ── body builders ───────────────────────────────────────────────────────────
//
// For the offline signer. Nothing on the verification path calls these.

/// Build a `genesis` body — §3.4.
#[must_use]
pub fn genesis_body(
    zone: &str,
    roots: &[Vec<u8>],
    k: u32,
    authorities: &[Vec<u8>],
    q: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_lp(&mut out, zone.as_bytes());
    put_u32(&mut out, u32::try_from(roots.len()).unwrap_or(u32::MAX));
    for r in roots {
        put_lp(&mut out, r);
    }
    put_u32(&mut out, k);
    put_u32(
        &mut out,
        u32::try_from(authorities.len()).unwrap_or(u32::MAX),
    );
    for a in authorities {
        put_lp(&mut out, a);
    }
    put_u32(&mut out, q);
    out
}

/// Build an `authority-list` body — §3.4.
#[must_use]
pub fn authority_list_body(authorities: &[Vec<u8>], q: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(
        &mut out,
        u32::try_from(authorities.len()).unwrap_or(u32::MAX),
    );
    for a in authorities {
        put_lp(&mut out, a);
    }
    put_u32(&mut out, q);
    out
}

/// Build a `node-sign` body — §3.4.
///
/// All three keys, not just the identity key. See spec §6.1: the identity key
/// is not used by PHREATIC, so covering only it would authorise a node to exist
/// without constraining which session keys are its.
#[must_use]
#[allow(clippy::cast_sign_loss)] // times are a fixed 64-bit field
pub fn node_sign_body(
    handle: &str,
    identity_key: &[u8],
    kem_public_key: &[u8],
    dh_public_key: &[u8],
    not_before: i64,
    expiry: i64,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_lp(&mut out, handle.as_bytes());
    put_lp(&mut out, identity_key);
    put_lp(&mut out, kem_public_key);
    put_lp(&mut out, dh_public_key);
    put_u64(&mut out, not_before as u64);
    put_u64(&mut out, expiry as u64);
    out
}

/// Build a `node-revoke` body — §3.4.
#[must_use]
#[allow(clippy::cast_sign_loss)] // times are a fixed 64-bit field
pub fn node_revoke_body(handle: &str, reason: &str, effective: i64) -> Vec<u8> {
    let mut out = Vec::new();
    put_lp(&mut out, handle.as_bytes());
    put_lp(&mut out, reason.as_bytes());
    put_u64(&mut out, effective as u64);
    out
}

/// Build a `quorum-change` body — §3.4.
#[must_use]
pub fn quorum_change_body(q: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, q);
    out
}

/// Build an `anchor` body — §3.4.
#[must_use]
pub fn anchor_body(audit_head: &[u8], audit_seq: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_lp(&mut out, audit_head);
    put_u64(&mut out, audit_seq);
    out
}

/// Build a `disable` body — §3.4.
#[must_use]
pub fn disable_body(reason: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_lp(&mut out, reason.as_bytes());
    out
}

/// The size of a root signature, re-exported so a caller sizing a buffer does
/// not have to reach into `karst-crypto`.
pub const ROOT_SIGNATURE_SIZE: usize = ROOT_SIGNATURE;
