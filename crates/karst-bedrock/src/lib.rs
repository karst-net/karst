// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Bedrock — the network lock. `spec/bedrock-v1.md`, PLAN.md §4.5.
//!
//! Karst's control server distributes policy but cannot read traffic. It *does*
//! tell every node which public keys belong to which peers, so a compromised
//! server can hand node A a key it controls and claim it is node B — and every
//! cryptographic property below the control plane holds perfectly while A talks
//! to the attacker.
//!
//! Bedrock closes that. Node identity keys are countersigned by a quorum of
//! authority keys whose lineage traces to offline roots, and **the node
//! verifies the chain itself and refuses to peer outside it, regardless of what
//! the netmap says.**
//!
//! # What this crate is
//!
//! Log parsing, chain verification, quorum evaluation, and the coverage query.
//! No I/O, no async, no clock: [`verify_log`] takes bytes and
//! [`State::is_covered`] takes the time as an argument. That keeps the whole
//! fail-closed decision in pure functions that the same vectors can check in
//! both languages.
//!
//! The Go mirror is `server/management/internals/karst/bedrock/`. Where the two
//! must agree byte-for-byte, `spec/vectors/bedrock-v1.json` holds them to it.
//!
//! # What it does not do
//!
//! - It does not stop a compromised server **denying** service. The server can
//!   drop a node from the netmap, refuse enrollment, or serve a stale log.
//!   Bedrock makes lying detectable, not impossible.
//! - It does not detect equivocation on its own. A hash chain proves history
//!   was not edited, not that everyone was told the same history; that needs
//!   the head comparison in spec §5, which lives above this crate.
//! - It does not protect a node whose own key is stolen. That is revocation,
//!   and revocation propagates at the speed of the log.

mod codec;

pub mod builder;
pub mod bundle;
pub mod log;
pub mod verify;

pub use builder::Builder;
pub use bundle::{Pending, Request, Response, VerifiedRequest, BUNDLE_VERSION};
pub use log::{
    anchor_body, authority_list_body, chain_hash, decode_log, disable_body, encode_log,
    genesis_body, node_revoke_body, node_sign_body, parse_anchor, parse_authority_list,
    parse_disable, parse_genesis, parse_node_revoke, parse_node_sign, parse_quorum_change,
    quorum_change_body, Anchor, AuthorityList, Entry, Genesis, NodeRevoke, NodeSign, Op, Signature,
    Tier, CHAIN_LABEL,
};
pub use verify::{verify_log, NodeCoverage, PeerKeys, State};

/// Why a log was refused.
///
/// Every variant is a refusal. There is deliberately no "verified with
/// warnings" outcome: this type is returned from the path that decides whether
/// a peer may be talked to, and a caller that wanted to proceed anyway would
/// have to write that intent out in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Bytes did not decode.
    Malformed,
    /// An op this version does not know. A hard failure rather than a skip —
    /// spec §4 rule 5.
    UnknownOp(String),
    /// The chain does not verify, at this sequence number.
    Broken { seq: u64, why: String },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed encoding"),
            Self::UnknownOp(op) => write!(f, "unknown op {op:?}"),
            Self::Broken { seq, why } => write!(f, "chain broken at entry {seq}: {why}"),
        }
    }
}

impl std::error::Error for Error {}
