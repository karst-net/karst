// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Peer-to-peer file transfer — GitHub issue #212,
//! `docs/adr/0041-peer-to-peer-file-transfer.md`.
//!
//! Two mesh peers that already hold a live PHREATIC session (`spec/phreatic-v1.md`)
//! are already mutually authenticated and, by the time either one may act on
//! anything the other sends, already policy-checked by [`crate::filter`]. This
//! module adds an offer/accept protocol riding that session rather than
//! standing up a parallel transport or a parallel permission model.
//!
//! # Wire framing
//!
//! Every frame here is a **Karst inner control frame** — the same
//! multiplexing [`crate::bedrock`]'s peer-to-peer head comparison uses: a
//! leading [`crate::bedrock::CONTROL_MARKER`] byte (`0x00`) inside the
//! PHREATIC transport's AEAD, which cannot collide with a tunnelled IP packet
//! (zero is not a legal IP version — `karst_tun::ip::addresses` already
//! returns `None` for it) and is authenticated because it lives inside the
//! ciphertext, unlike the transport's own cleartext type byte
//! (`spec/phreatic-v1.md` §8, §13.13). A second byte, this module's own
//! `KIND_*` constants, tells a file-transfer frame apart from a Bedrock head
//! claim.
//!
//! Every frame is **explicitly length-prefixed** wherever it carries a
//! variable-length field, for the reason `crate::bedrock::encode_head_claim`
//! gives: the transport pads its plaintext to a multiple of 16 bytes and
//! carries no length of its own (§8), so a frame that is not self-describing
//! cannot tell its own content from trailing padding.
//!
//! # State machine
//!
//! [`PeerTransfers`] holds one peer's outstanding transfers in both
//! directions. An inbound `Offer` is **not** admitted to receive bytes the
//! moment it arrives — it sits in `pending` until [`PeerTransfers::accept`]
//! is called, which is this node's own user or agent saying yes. A `Chunk` or
//! `Complete` for an id that was never accepted is simply dropped; nothing
//! here writes attacker-controlled bytes anywhere before a local decision
//! admitted them.
//!
//! # What this module does not do
//!
//! No retransmission, no flow control, no resumption. A chunk that never
//! arrives, or arrives out of order, stalls the transfer rather than being
//! recovered — acceptable for the protocol/plumbing landing this issue scopes
//! (see the ADR's "Not in this change" section); real reliability is a
//! follow-up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use karst_crypto::hash;

use crate::bedrock::CONTROL_MARKER;
use crate::routing::PeerIndex;

/// `CONTROL_MARKER`'s second byte for each file-transfer frame kind. `0x01`
/// is `crate::bedrock::CONTROL_BEDROCK_HEAD`; these start at `0x02` so the
/// two frame families can never collide on the wire.
const KIND_OFFER: u8 = 0x02;
const KIND_ACCEPT: u8 = 0x03;
const KIND_REJECT: u8 = 0x04;
const KIND_CHUNK: u8 = 0x05;
const KIND_COMPLETE: u8 = 0x06;
const KIND_RECEIPT: u8 = 0x07;

/// The virtual admission port a file-transfer offer is checked against in the
/// general ingress/egress ACL (`server/management/internals/karst/policy/schema.go`'s
/// `acls`) — the same trick the independent SSH gate
/// (`plans/phase-6/07-acl-gated-ssh.md`) uses for a control-plane concern
/// with no real socket of its own: [`crate::filter::PacketFilter`] is a
/// peer-and-port matcher, and a file offer has a peer but no IP packet to
/// read a port from. See the ADR for why this reuses the general ACL rather
/// than adding a second policy surface.
pub const SERVICE_PORT: u16 = 50440;

/// Digest algorithm for a transfer's integrity check — the suite's own
/// transcript hash (`spec/phreatic-v1.md` §2), for the reason §9.2 gives for
/// the fragment MAC: one hash primitive per suite is worth more than a
/// marginally cheaper second one.
const CHECKSUM_ALG: hash::Algorithm = hash::Algorithm::Sha384;
/// `CHECKSUM_ALG`'s output length.
const CHECKSUM_LEN: usize = 48;

const TRANSFER_ID_LEN: usize = 16;
/// A sender-chosen, CSPRNG-drawn identifier for one transfer — scoped to the
/// pair, not globally unique, the same discipline `reassembly_id` uses (§5).
pub type TransferId = [u8; TRANSFER_ID_LEN];

/// Render a [`TransferId`] as lowercase hex — the IPC/CLI surface's wire
/// form for an id, since the binary form has no place in a line-oriented
/// text command.
#[must_use]
pub fn id_to_hex(id: &TransferId) -> String {
    use std::fmt::Write as _;
    id.iter()
        .fold(String::with_capacity(TRANSFER_ID_LEN * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Parse [`id_to_hex`]'s output back into a [`TransferId`]. `None` for
/// anything that is not exactly `TRANSFER_ID_LEN * 2` hex digits.
#[must_use]
pub fn id_from_hex(s: &str) -> Option<TransferId> {
    if s.len() != TRANSFER_ID_LEN * 2 {
        return None;
    }
    let mut out = [0u8; TRANSFER_ID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Largest plaintext a single `Chunk` frame carries.
///
/// Held comfortably under `karst_proto::consts::TUNNEL_MTU` (1280 B, the
/// largest plaintext a transport message may seal unfragmented —
/// `spec/phreatic-v1.md` §8) so this frame's own header (18 bytes) never
/// pushes a sealed chunk over the transport's one-datagram budget.
pub const MAX_CHUNK_DATA: usize = 1024;

/// Largest name this end will encode or accept. Generous for a filename,
/// small enough that a hostile peer cannot use it to force a large
/// allocation — bounded further by the frame's own length prefix anyway, but
/// a sender-side cap keeps this end from ever proposing something a length
/// prefix this narrow (`u16`) could not even carry.
pub const MAX_NAME_LEN: usize = 255;

fn checksum_of(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = CHECKSUM_ALG.digest(&[data]);
    let mut out = [0u8; CHECKSUM_LEN];
    if let Some(src) = digest.as_bytes().get(..CHECKSUM_LEN) {
        out.copy_from_slice(src);
    }
    out
}

// ── wire codec ───────────────────────────────────────────────────────────

/// A decoded `Offer` — sender's name/size/checksum claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub id: TransferId,
    pub name: String,
    pub size: u64,
    checksum: [u8; CHECKSUM_LEN],
}

/// Why a peer declined an offer this node sent — carried on the wire so the
/// sender's own audit receipt can say more than "no".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The receiving user/agent said no.
    Declined,
    /// The receiving node is not willing to hold a file this large.
    TooLarge,
    /// The receiving node already has a transfer in flight with this peer.
    Busy,
}

impl RejectReason {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Declined => 0x00,
            Self::TooLarge => 0x01,
            Self::Busy => 0x02,
        }
    }

    const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Declined),
            0x01 => Some(Self::TooLarge),
            0x02 => Some(Self::Busy),
            _ => None,
        }
    }

    /// Parse the IPC/CLI surface's spelling of a reason. Unrecognized text
    /// — including an absent `[REASON]` argument — falls back to
    /// [`Self::Declined`] rather than refusing the command over it: the
    /// wire already carries no free-text reason for the peer to read, so an
    /// operator's typo here costs nothing more than the more specific of
    /// two ways to say no.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "too-large" => Self::TooLarge,
            "busy" => Self::Busy,
            _ => Self::Declined,
        }
    }
}

/// How a transfer this node sent was finally resolved, per the receiver's
/// own `Receipt` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Every byte arrived and the checksum matched.
    Ok,
    /// `Complete` arrived but the assembled bytes did not hash to the
    /// offered checksum.
    ChecksumMismatch,
    /// `Complete` arrived before every offered byte did — a dropped chunk,
    /// with no retransmission to recover it (see the module doc).
    Incomplete,
}

impl ReceiptStatus {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Ok => 0x00,
            Self::ChecksumMismatch => 0x01,
            Self::Incomplete => 0x02,
        }
    }

    const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::ChecksumMismatch),
            0x02 => Some(Self::Incomplete),
            _ => None,
        }
    }
}

fn header(kind: u8, id: &TransferId, cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + TRANSFER_ID_LEN + cap);
    out.push(CONTROL_MARKER);
    out.push(kind);
    out.extend_from_slice(id);
    out
}

/// `marker || KIND_OFFER || id || name_len(u16) || name || size(u64) || checksum`.
#[must_use]
pub fn encode_offer(
    id: &TransferId,
    name: &str,
    size: u64,
    checksum: &[u8; CHECKSUM_LEN],
) -> Vec<u8> {
    let name = name.as_bytes();
    let mut out = header(KIND_OFFER, id, 2 + name.len() + 8 + CHECKSUM_LEN);
    out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(checksum);
    out
}

/// # Errors
/// `None` for anything that is not a well-formed `Offer` — including every
/// other frame kind and every tunnelled IP packet, which the caller uses to
/// route between them.
#[must_use]
pub fn decode_offer(p: &[u8]) -> Option<Offer> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_OFFER) {
        return None;
    }
    let id: TransferId = p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()?;
    let mut at = 2 + TRANSFER_ID_LEN;
    let name_len = usize::from(u16::from_be_bytes(p.get(at..at + 2)?.try_into().ok()?));
    at += 2;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return None;
    }
    let name = std::str::from_utf8(p.get(at..at + name_len)?)
        .ok()?
        .to_owned();
    at += name_len;
    let size = u64::from_be_bytes(p.get(at..at + 8)?.try_into().ok()?);
    at += 8;
    let checksum: [u8; CHECKSUM_LEN] = p.get(at..at + CHECKSUM_LEN)?.try_into().ok()?;
    Some(Offer {
        id,
        name,
        size,
        checksum,
    })
}

/// `marker || KIND_ACCEPT || id`.
#[must_use]
pub fn encode_accept(id: &TransferId) -> Vec<u8> {
    header(KIND_ACCEPT, id, 0)
}

#[must_use]
pub fn decode_accept(p: &[u8]) -> Option<TransferId> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_ACCEPT) {
        return None;
    }
    p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()
}

/// `marker || KIND_REJECT || id || reason`.
#[must_use]
pub fn encode_reject(id: &TransferId, reason: RejectReason) -> Vec<u8> {
    let mut out = header(KIND_REJECT, id, 1);
    out.push(reason.to_wire());
    out
}

#[must_use]
pub fn decode_reject(p: &[u8]) -> Option<(TransferId, RejectReason)> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_REJECT) {
        return None;
    }
    let id: TransferId = p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()?;
    let reason = RejectReason::from_wire(*p.get(2 + TRANSFER_ID_LEN)?)?;
    Some((id, reason))
}

/// `marker || KIND_CHUNK || id || offset(u64) || len(u32) || data`.
#[must_use]
pub fn encode_chunk(id: &TransferId, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = header(KIND_CHUNK, id, 8 + 4 + data.len());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(data);
    out
}

#[must_use]
pub fn decode_chunk(p: &[u8]) -> Option<(TransferId, u64, &[u8])> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_CHUNK) {
        return None;
    }
    let id: TransferId = p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()?;
    let mut at = 2 + TRANSFER_ID_LEN;
    let offset = u64::from_be_bytes(p.get(at..at + 8)?.try_into().ok()?);
    at += 8;
    let len = u32::from_be_bytes(p.get(at..at + 4)?.try_into().ok()?) as usize;
    at += 4;
    if len > MAX_CHUNK_DATA {
        return None;
    }
    Some((id, offset, p.get(at..at + len)?))
}

/// `marker || KIND_COMPLETE || id`.
#[must_use]
pub fn encode_complete(id: &TransferId) -> Vec<u8> {
    header(KIND_COMPLETE, id, 0)
}

#[must_use]
pub fn decode_complete(p: &[u8]) -> Option<TransferId> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_COMPLETE) {
        return None;
    }
    p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()
}

/// `marker || KIND_RECEIPT || id || status`.
#[must_use]
pub fn encode_receipt(id: &TransferId, status: ReceiptStatus) -> Vec<u8> {
    let mut out = header(KIND_RECEIPT, id, 1);
    out.push(status.to_wire());
    out
}

#[must_use]
pub fn decode_receipt(p: &[u8]) -> Option<(TransferId, ReceiptStatus)> {
    if p.first() != Some(&CONTROL_MARKER) || p.get(1) != Some(&KIND_RECEIPT) {
        return None;
    }
    let id: TransferId = p.get(2..2 + TRANSFER_ID_LEN)?.try_into().ok()?;
    let status = ReceiptStatus::from_wire(*p.get(2 + TRANSFER_ID_LEN)?)?;
    Some((id, status))
}

/// Whether `p` is any file-transfer frame at all, checked before a caller
/// tries each decoder in turn — mirrors `crate::bedrock`'s own marker check.
#[must_use]
pub fn is_file_transfer_frame(p: &[u8]) -> bool {
    p.first() == Some(&CONTROL_MARKER)
        && matches!(
            p.get(1),
            Some(
                &(KIND_OFFER
                    | KIND_ACCEPT
                    | KIND_REJECT
                    | KIND_CHUNK
                    | KIND_COMPLETE
                    | KIND_RECEIPT)
            )
        )
}

// ── per-peer state machine ──────────────────────────────────────────────

#[derive(Debug)]
struct Outgoing {
    name: String,
    data: Vec<u8>,
    sent_accept: bool,
}

/// An inbound offer awaiting this node's own accept/reject decision.
#[derive(Debug, Clone)]
pub struct PendingOffer {
    pub name: String,
    pub size: u64,
    checksum: [u8; CHECKSUM_LEN],
}

#[derive(Debug)]
struct Incoming {
    name: String,
    size: u64,
    checksum: [u8; CHECKSUM_LEN],
    buffer: Vec<u8>,
}

/// A transfer this node received, verified and ready to land.
#[derive(Debug)]
pub struct CompletedTransfer {
    pub name: String,
    pub bytes: Vec<u8>,
    pub status: ReceiptStatus,
}

/// Summary of a transfer this node sent, for the audit receipt once it
/// resolves (accepted-and-delivered, rejected, or answered with a receipt).
#[derive(Debug)]
pub struct OutgoingSummary {
    pub name: String,
    pub size: u64,
}

/// One peer's file-transfer state, in both directions. Lives behind a
/// per-peer lock in `Engine`'s `PeerSlot`, the same granularity every other
/// piece of per-peer state in the datapath uses.
#[derive(Debug, Default)]
pub struct PeerTransfers {
    /// Transfers this node offered, keyed by the id it chose.
    outgoing: HashMap<TransferId, Outgoing>,
    /// Offers from the peer awaiting this node's own decision.
    pending: HashMap<TransferId, PendingOffer>,
    /// Offers this node accepted, receiving chunks.
    incoming: HashMap<TransferId, Incoming>,
}

impl PeerTransfers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin sending: record the outgoing transfer and return the checksum
    /// to put in the `Offer` frame. The caller (`Engine::offer_file`) has
    /// already checked the ACL and the session.
    pub fn begin_outgoing(
        &mut self,
        id: TransferId,
        name: String,
        data: Vec<u8>,
    ) -> [u8; CHECKSUM_LEN] {
        let checksum = checksum_of(&data);
        self.outgoing.insert(
            id,
            Outgoing {
                name,
                data,
                sent_accept: false,
            },
        );
        checksum
    }

    /// The peer accepted a transfer this node offered. Returns the `Chunk`
    /// frames and the trailing `Complete` frame to send, in order — or
    /// `None` for an id this node has no outgoing offer for (unknown,
    /// already resolved, or a duplicate `Accept`), which the caller drops
    /// silently.
    pub fn on_accept(&mut self, id: &TransferId) -> Option<Vec<Vec<u8>>> {
        let t = self.outgoing.get_mut(id)?;
        if t.sent_accept {
            return None; // duplicate Accept — already answered once
        }
        t.sent_accept = true;
        let mut frames: Vec<Vec<u8>> = t
            .data
            .chunks(MAX_CHUNK_DATA)
            .enumerate()
            .map(|(i, chunk)| encode_chunk(id, (i * MAX_CHUNK_DATA) as u64, chunk))
            .collect();
        frames.push(encode_complete(id));
        Some(frames)
    }

    /// The peer rejected a transfer this node offered. Removes it and
    /// returns a summary for the audit receipt.
    pub fn on_reject(&mut self, id: &TransferId) -> Option<OutgoingSummary> {
        let t = self.outgoing.remove(id)?;
        Some(OutgoingSummary {
            size: t.data.len() as u64,
            name: t.name,
        })
    }

    /// The peer's final word on a transfer this node sent. Removes it either
    /// way — a transfer resolves exactly once.
    pub fn on_receipt(&mut self, id: &TransferId) -> Option<OutgoingSummary> {
        let t = self.outgoing.remove(id)?;
        Some(OutgoingSummary {
            size: t.data.len() as u64,
            name: t.name,
        })
    }

    /// An `Offer` arrived. The caller has already ACL-checked the peer;
    /// this only tracks state. Returns `false` for an id already known in
    /// either direction (replay or a genuine collision), which the caller
    /// leaves unanswered.
    pub fn on_offer(&mut self, offer: Offer) -> bool {
        if self.pending.contains_key(&offer.id) || self.incoming.contains_key(&offer.id) {
            return false;
        }
        self.pending.insert(
            offer.id,
            PendingOffer {
                name: offer.name,
                size: offer.size,
                checksum: offer.checksum,
            },
        );
        true
    }

    /// The pending offers awaiting a local decision, oldest first is not
    /// guaranteed — callers needing order should key off their own receipt
    /// log instead.
    pub fn pending_offers(&self) -> impl Iterator<Item = (&TransferId, &PendingOffer)> {
        self.pending.iter()
    }

    /// This node's own decision: accept `id`. Moves it from `pending` to
    /// `incoming`, ready to receive chunks, and returns the size (for the
    /// caller building the `Accept` frame's counterpart nothing further is
    /// needed — the frame carries only the id). `None` if `id` names no
    /// pending offer.
    pub fn accept(&mut self, id: &TransferId) -> Option<()> {
        let offer = self.pending.remove(id)?;
        self.incoming.insert(
            *id,
            Incoming {
                name: offer.name,
                size: offer.size,
                checksum: offer.checksum,
                buffer: Vec::new(),
            },
        );
        Some(())
    }

    /// This node's own decision: reject `id`. Removes it from `pending` and
    /// returns its summary for the local audit receipt. `None` if `id`
    /// names no pending offer.
    pub fn reject(&mut self, id: &TransferId) -> Option<OutgoingSummary> {
        let offer = self.pending.remove(id)?;
        Some(OutgoingSummary {
            name: offer.name,
            size: offer.size,
        })
    }

    /// A `Chunk` arrived. Applied only against an **accepted** transfer
    /// (`incoming`) — one still in `pending`, or unknown entirely, is
    /// dropped without writing anything: nothing here buffers a byte this
    /// node has not already said yes to. Out-of-order or duplicate chunks
    /// are dropped too (no reassembly, no retransmission — see the module
    /// doc); `offset` must exactly match the bytes already held.
    pub fn on_chunk(&mut self, id: &TransferId, offset: u64, data: &[u8]) -> bool {
        let Some(t) = self.incoming.get_mut(id) else {
            return false;
        };
        let Ok(have) = u64::try_from(t.buffer.len()) else {
            return false;
        };
        if offset != have {
            return false;
        }
        let Some(new_total) = have.checked_add(data.len() as u64) else {
            return false;
        };
        if new_total > t.size {
            return false;
        }
        t.buffer.extend_from_slice(data);
        true
    }

    /// `Complete` arrived for an accepted transfer. Verifies the assembled
    /// bytes against the offered size and checksum and removes the
    /// transfer either way — it resolves exactly once, however it turned
    /// out. `None` if `id` names no accepted, still-open transfer.
    pub fn on_complete(&mut self, id: &TransferId) -> Option<CompletedTransfer> {
        let t = self.incoming.remove(id)?;
        let status = if t.buffer.len() as u64 != t.size {
            ReceiptStatus::Incomplete
        } else if checksum_of(&t.buffer) != t.checksum {
            ReceiptStatus::ChecksumMismatch
        } else {
            ReceiptStatus::Ok
        };
        Some(CompletedTransfer {
            name: t.name,
            bytes: t.buffer,
            status,
        })
    }
}

// ── audit trail ──────────────────────────────────────────────────────────

/// Which side of the transfer this node was on, for the receipt log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sent,
    Received,
}

/// How a transfer this node participated in was finally resolved, for the
/// receipt log — a superset of [`ReceiptStatus`], which only the wire
/// carries: a transfer can also be refused locally before anything is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    ChecksumMismatch,
    Incomplete,
    /// The local or remote user/agent said no.
    Declined,
    /// This node's own policy refused to send or receive it — no frame
    /// naming the other side's policy state ever crosses the wire.
    DeniedByPolicy,
}

impl From<ReceiptStatus> for Outcome {
    fn from(s: ReceiptStatus) -> Self {
        match s {
            ReceiptStatus::Ok => Self::Completed,
            ReceiptStatus::ChecksumMismatch => Self::ChecksumMismatch,
            ReceiptStatus::Incomplete => Self::Incomplete,
        }
    }
}

/// One resolved transfer, for `karst status`/IPC and for
/// `Engine::file_transfer_receipts` — consistent in spirit with
/// `server/management/internals/karst/node/node.go`'s `SessionObservation`:
/// a self-reported fact, not key material, kept for as long as the bounded
/// local log holds it. Reporting this to the coordination server for
/// account-level audit is future work — see the ADR.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub peer: PeerIndex,
    pub transfer: TransferId,
    pub name: String,
    pub size: u64,
    pub direction: TransferDirection,
    pub outcome: Outcome,
    pub at_ms: u64,
}

/// A transfer this node received, verified and ready to land on disk — the
/// engine's counterpart to `Output::packets`: the engine decrypts and
/// validates, the caller (`run.rs`'s `dispatch`) performs the actual I/O, the
/// same split the TUN write already uses.
#[derive(Debug, Clone)]
pub struct ReceivedFile {
    pub peer_name: String,
    pub name: String,
    pub bytes: Vec<u8>,
}

// ── landing a received file ─────────────────────────────────────────────

/// Where this node's own conventions and the OS's should land an incoming
/// file. `KARST_INCOMING_DIR` overrides everything else, for a deployment
/// that wants received files somewhere specific (or a test that wants them
/// somewhere disposable) without adding a netmap-wire config surface for it
/// — see the ADR's "Not in this change" section. Otherwise: the ordinary
/// per-user downloads folder, `$HOME/Downloads` on Unix and
/// `%USERPROFILE%\Downloads` on Windows, which is what every desktop OS
/// already treats as "where things a person downloaded show up."
#[must_use]
pub fn default_incoming_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KARST_INCOMING_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok();
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok();
    home.map(|h| Path::new(&h).join("Downloads").join("Karst"))
}

/// Strip everything from an offered name that could make it anything other
/// than one plain file in the target directory.
///
/// The name arrives from the sending peer in an `Offer` frame and is
/// therefore untrusted: `../../etc/passwd` or an absolute path must land as
/// a file literally called that, never be interpreted as a path. Every
/// component separator this node's own `Path` would honor is replaced, both
/// platforms' at once — a Windows peer's `\` must not become a Unix peer's
/// directory separator, and vice versa — and a name left empty by that is
/// replaced outright rather than writing to the directory itself.
#[must_use]
pub fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_start_matches('.').trim();
    if cleaned.is_empty() {
        "karst-transfer".to_owned()
    } else {
        // `MAX_NAME_LEN` already bounds the sender's own claim, but cap again
        // here so a pathological byte sequence cannot produce an OS-rejected
        // filename this node accepted on the wire.
        cleaned.chars().take(MAX_NAME_LEN).collect()
    }
}

/// Write `bytes` under `dir` as `name`, sanitized by [`safe_filename`]. If
/// that name is already taken, a numeric suffix is appended before the
/// extension until a free one is found (bounded, so a directory full of
/// collisions fails rather than loops).
///
/// # Errors
/// Any [`std::io::Error`] from creating the directory or writing the file.
pub fn save_received_file(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let clean = safe_filename(name);
    let path = Path::new(&clean);
    let stem = path
        .file_stem()
        .map_or_else(|| clean.clone(), |s| s.to_string_lossy().into_owned());
    let ext = path.extension().map(|e| e.to_string_lossy().into_owned());

    for attempt in 0..1000 {
        let candidate = if attempt == 0 {
            clean.clone()
        } else {
            ext.as_ref().map_or_else(
                || format!("{stem} ({attempt})"),
                |e| format!("{stem} ({attempt}).{e}"),
            )
        };
        let full = dir.join(&candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&full)
        {
            Ok(mut f) => {
                use std::io::Write as _;
                f.write_all(bytes)?;
                return Ok(full);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "too many same-named transfers pending in the incoming directory",
    ))
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

    fn id(b: u8) -> TransferId {
        [b; TRANSFER_ID_LEN]
    }

    #[test]
    fn an_offer_round_trips() {
        let checksum = checksum_of(b"hello world");
        let bytes = encode_offer(&id(1), "report.pdf", 11, &checksum);
        let offer = decode_offer(&bytes).expect("decode");
        assert_eq!(offer.id, id(1));
        assert_eq!(offer.name, "report.pdf");
        assert_eq!(offer.size, 11);
        assert_eq!(offer.checksum, checksum);
    }

    #[test]
    fn trailing_transport_padding_is_ignored() {
        // §8: the transport pads plaintext to a multiple of 16 and carries no
        // length of its own, so every frame here must survive trailing zero
        // bytes the way `crate::bedrock`'s head claim does.
        let checksum = checksum_of(b"x");
        let mut framed = encode_offer(&id(2), "a", 1, &checksum);
        framed.resize(framed.len() + 37, 0);
        let offer = decode_offer(&framed).expect("decode through padding");
        assert_eq!(offer.name, "a");
    }

    #[test]
    fn accept_reject_complete_round_trip() {
        assert_eq!(decode_accept(&encode_accept(&id(3))), Some(id(3)));
        assert_eq!(decode_complete(&encode_complete(&id(3))), Some(id(3)));
        assert_eq!(
            decode_reject(&encode_reject(&id(3), RejectReason::TooLarge)),
            Some((id(3), RejectReason::TooLarge))
        );
        for status in [
            ReceiptStatus::Ok,
            ReceiptStatus::ChecksumMismatch,
            ReceiptStatus::Incomplete,
        ] {
            assert_eq!(
                decode_receipt(&encode_receipt(&id(4), status)),
                Some((id(4), status))
            );
        }
    }

    #[test]
    fn a_chunk_round_trips_with_its_data() {
        let data = vec![0xAB; 200];
        let bytes = encode_chunk(&id(5), 1024, &data);
        let (got_id, offset, got_data) = decode_chunk(&bytes).expect("decode");
        assert_eq!(got_id, id(5));
        assert_eq!(offset, 1024);
        assert_eq!(got_data, data.as_slice());
    }

    #[test]
    fn a_chunk_over_the_cap_is_refused() {
        // Constructed by hand: `encode_chunk` itself would never build one
        // this large, so the receiver-side bound is what is under test.
        let mut bytes = header(KIND_CHUNK, &id(6), 0);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        let len = u32::try_from(MAX_CHUNK_DATA + 1).unwrap();
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend(std::iter::repeat_n(0u8, MAX_CHUNK_DATA + 1));
        assert_eq!(decode_chunk(&bytes), None);
    }

    #[test]
    fn frame_kind_is_detected_before_decoding() {
        let checksum = checksum_of(b"y");
        assert!(is_file_transfer_frame(&encode_offer(
            &id(7),
            "n",
            1,
            &checksum
        )));
        assert!(is_file_transfer_frame(&encode_accept(&id(7))));
        assert!(!is_file_transfer_frame(&crate::bedrock::encode_head_claim(
            &[0u8; 64], 1
        )));
        assert!(!is_file_transfer_frame(&[0x45, 0x00, 0x00, 0x28])); // an IP packet
    }

    #[test]
    fn a_chunk_before_accept_is_dropped() {
        let mut t = PeerTransfers::new();
        let offer = Offer {
            id: id(8),
            name: "n".to_owned(),
            size: 4,
            checksum: checksum_of(b"data"),
        };
        assert!(t.on_offer(offer));
        // Not yet accepted: the chunk must not be buffered anywhere.
        assert!(!t.on_chunk(&id(8), 0, b"data"));
        assert!(t.on_complete(&id(8)).is_none());
    }

    #[test]
    fn a_full_incoming_transfer_verifies() {
        let mut t = PeerTransfers::new();
        let data = b"the quick brown fox".to_vec();
        let offer = Offer {
            id: id(9),
            name: "fox.txt".to_owned(),
            size: data.len() as u64,
            checksum: checksum_of(&data),
        };
        assert!(t.on_offer(offer));
        assert!(t.accept(&id(9)).is_some());
        assert!(t.on_chunk(&id(9), 0, &data[..10]));
        assert!(t.on_chunk(&id(9), 10, &data[10..]));
        let completed = t.on_complete(&id(9)).expect("resolved");
        assert_eq!(completed.bytes, data);
        assert_eq!(completed.status, ReceiptStatus::Ok);
        assert_eq!(completed.name, "fox.txt");
    }

    #[test]
    fn a_tampered_transfer_fails_the_checksum_not_the_size() {
        let mut t = PeerTransfers::new();
        let real = b"authentic bytes".to_vec();
        let offer = Offer {
            id: id(10),
            name: "n".to_owned(),
            size: real.len() as u64,
            checksum: checksum_of(&real),
        };
        assert!(t.on_offer(offer));
        assert!(t.accept(&id(10)).is_some());
        let substituted = b"not-the-real-one".to_vec();
        assert!(t.on_chunk(&id(10), 0, &substituted[..real.len()]));
        let completed = t.on_complete(&id(10)).expect("resolved");
        assert_eq!(completed.status, ReceiptStatus::ChecksumMismatch);
    }

    #[test]
    fn an_out_of_order_chunk_is_dropped_not_reordered() {
        let mut t = PeerTransfers::new();
        let offer = Offer {
            id: id(11),
            name: "n".to_owned(),
            size: 8,
            checksum: checksum_of(b"abcdefgh"),
        };
        assert!(t.on_offer(offer));
        assert!(t.accept(&id(11)).is_some());
        // Offered at 4, but nothing has arrived at 0 yet.
        assert!(!t.on_chunk(&id(11), 4, b"efgh"));
    }

    #[test]
    fn an_oversend_past_the_offered_size_is_refused() {
        let mut t = PeerTransfers::new();
        let offer = Offer {
            id: id(12),
            name: "n".to_owned(),
            size: 4,
            checksum: checksum_of(b"abcd"),
        };
        assert!(t.on_offer(offer));
        assert!(t.accept(&id(12)).is_some());
        assert!(t.on_chunk(&id(12), 0, b"abcd"));
        assert!(!t.on_chunk(&id(12), 4, b"extra"));
    }

    #[test]
    fn duplicate_offers_for_one_id_are_refused() {
        let mut t = PeerTransfers::new();
        let offer = |n: &str| Offer {
            id: id(13),
            name: n.to_owned(),
            size: 1,
            checksum: checksum_of(b"a"),
        };
        assert!(t.on_offer(offer("first")));
        assert!(
            !t.on_offer(offer("second")),
            "a replayed id must not overwrite the first offer"
        );
    }

    #[test]
    fn a_full_outgoing_transfer_produces_chunks_then_complete() {
        let mut t = PeerTransfers::new();
        let data = vec![7u8; (MAX_CHUNK_DATA * 2) + 10]; // spans three chunks
        let _ = t.begin_outgoing(id(14), "big.bin".to_owned(), data.clone());
        let frames = t.on_accept(&id(14)).expect("known outgoing transfer");
        assert_eq!(frames.len(), 4); // 3 chunks + Complete
        let (_, offset0, chunk0) = decode_chunk(&frames[0]).expect("chunk 0");
        assert_eq!(offset0, 0);
        assert_eq!(chunk0.len(), MAX_CHUNK_DATA);
        let (_, offset2, chunk2) = decode_chunk(&frames[2]).expect("chunk 2");
        assert_eq!(offset2, (MAX_CHUNK_DATA * 2) as u64);
        assert_eq!(chunk2.len(), 10);
        assert_eq!(decode_complete(&frames[3]), Some(id(14)));
    }

    #[test]
    fn a_duplicate_accept_is_answered_once() {
        let mut t = PeerTransfers::new();
        let _ = t.begin_outgoing(id(15), "n".to_owned(), vec![1, 2, 3]);
        assert!(t.on_accept(&id(15)).is_some());
        assert!(
            t.on_accept(&id(15)).is_none(),
            "a second Accept must not resend"
        );
    }

    #[test]
    fn rejecting_a_pending_offer_removes_it() {
        let mut t = PeerTransfers::new();
        let offer = Offer {
            id: id(16),
            name: "n".to_owned(),
            size: 1,
            checksum: checksum_of(b"a"),
        };
        assert!(t.on_offer(offer));
        let summary = t.reject(&id(16)).expect("was pending");
        assert_eq!(summary.name, "n");
        assert!(
            t.accept(&id(16)).is_none(),
            "a rejected offer cannot later be accepted"
        );
    }

    // ── filename safety ─────────────────────────────────────────────────

    #[test]
    fn path_traversal_is_neutralized() {
        // Separators become `_` and leading dots are stripped — the result
        // has no path meaning left in it at all, on either platform's
        // separator.
        assert_eq!(safe_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(
            safe_filename("..\\..\\Windows\\win.ini"),
            "_.._Windows_win.ini"
        );
    }

    #[test]
    fn an_absolute_path_is_neutralized() {
        assert_eq!(safe_filename("/etc/passwd"), "_etc_passwd");
    }

    #[test]
    fn an_empty_or_dot_only_name_gets_a_fallback() {
        assert_eq!(safe_filename(""), "karst-transfer");
        assert_eq!(safe_filename("."), "karst-transfer");
        assert_eq!(safe_filename(".."), "karst-transfer");
    }

    #[test]
    fn saving_creates_the_directory_and_writes_the_file() {
        let base = std::env::temp_dir().join(format!("karst-ft-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let path = save_received_file(&base, "notes.txt", b"hello").expect("save");
        assert_eq!(std::fs::read(&path).expect("read back"), b"hello");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_name_collision_gets_a_numeric_suffix_rather_than_overwriting() {
        let base =
            std::env::temp_dir().join(format!("karst-ft-test-collide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let first = save_received_file(&base, "notes.txt", b"first").expect("save 1");
        let second = save_received_file(&base, "notes.txt", b"second").expect("save 2");
        assert_ne!(first, second);
        assert_eq!(std::fs::read(&first).expect("read 1"), b"first");
        assert_eq!(std::fs::read(&second).expect("read 2"), b"second");
        let _ = std::fs::remove_dir_all(&base);
    }

    // ── IPC/CLI wire helpers ────────────────────────────────────────────

    #[test]
    fn a_transfer_id_round_trips_through_hex() {
        let tid = id(0xAB);
        assert_eq!(id_from_hex(&id_to_hex(&tid)), Some(tid));
    }

    #[test]
    fn hex_of_the_wrong_length_or_content_is_rejected() {
        assert_eq!(id_from_hex("ab"), None);
        assert_eq!(id_from_hex(&"zz".repeat(TRANSFER_ID_LEN)), None);
    }

    #[test]
    fn reject_reason_parses_known_strings_and_falls_back_to_declined() {
        assert_eq!(RejectReason::parse("too-large"), RejectReason::TooLarge);
        assert_eq!(RejectReason::parse("busy"), RejectReason::Busy);
        assert_eq!(RejectReason::parse("declined"), RejectReason::Declined);
        assert_eq!(RejectReason::parse("anything-else"), RejectReason::Declined);
    }

    #[test]
    fn a_traversal_attempt_still_lands_inside_the_target_directory() {
        let base = std::env::temp_dir().join(format!("karst-ft-test-trav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let path = save_received_file(&base, "../../../etc/passwd", b"not passwd").expect("save");
        assert!(
            path.starts_with(&base),
            "escaped the target directory: {path:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
