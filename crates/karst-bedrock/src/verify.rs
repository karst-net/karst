// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Chain verification and the coverage query — `spec/bedrock-v1.md` §4 and §6.
//!
//! This is the node's fail-closed path. Every rule in spec §4 is checked in the
//! order the spec lists, because the order is load-bearing: a body is parsed
//! only after the signatures over it have verified.
//!
//! The Go implementation in `server/management/internals/karst/bedrock/verify.go`
//! is the mirror of this file. Where they must agree, they are held to it by
//! `spec/vectors/bedrock-v1.json`.

use std::collections::HashMap;

use karst_crypto::sign::{verify_anchor_key, verify_authority, verify_root};

use crate::log::{
    chain_hash, parse_anchor, parse_authority_list, parse_disable, parse_genesis,
    parse_node_revoke, parse_node_sign, Anchor, Entry, Op, Tier, MAX_SIGNERS,
};
use crate::Error;

/// What a `node-sign` established: a handle bound to a specific key, for a
/// window.
///
/// The binding is to the handle **and the key together**. A `node-sign` for a
/// handle does not cover a different key later presented under the same handle,
/// which is precisely what stops a compromised server substituting a key it
/// controls while keeping the name (spec §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCoverage {
    pub handle: String,
    /// The ML-DSA-65 control-channel key.
    pub identity_key: Vec<u8>,
    /// The static keys PHREATIC actually authenticates against — spec §6.1.
    /// Covering these is what makes the mechanism more than a formality.
    pub kem_public_key: Vec<u8>,
    pub not_before: i64,
    /// Zero means no expiry.
    pub expiry: i64,
}

/// What a netmap presents for a peer, as the coverage query sees it.
///
/// The identity key is deliberately absent. A netmap carries a peer's handle,
/// KEM key and DH key — never its ML-DSA identity key — so a predicate that took
/// one could only be handed the value already in the log, and comparing the log
/// to itself proves nothing. The identity binding is checked once, during chain
/// verification, as the invariant `handle == handle(identity_key)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerKeys<'a> {
    pub kem_public_key: &'a [u8],
}

/// The result of verifying a log: everything a node needs to make an
/// enforcement decision, and nothing else.
#[derive(Debug, Clone, Default)]
pub struct State {
    pub zone: String,
    pub roots: Vec<Vec<u8>>,
    pub k: u32,
    pub authorities: Vec<Vec<u8>>,
    pub q: u32,
    /// ADR-0016's anchor tier: keys permitted to sign `anchor` and nothing
    /// else. Replaced atomically by whichever of genesis or the latest
    /// authority-list carried a trailing anchor-key block — empty means no
    /// anchor key is enabled and only a full authority may anchor.
    pub anchor_keys: Vec<Vec<u8>>,

    /// The latest `node-sign` per handle.
    pub covered: HashMap<String, NodeCoverage>,
    /// The effective time of the latest `node-revoke` per handle.
    pub revoked: HashMap<String, i64>,

    /// A root-signed `disable`. Enforcement stops; that it stopped is
    /// permanently in the log.
    pub disabled: bool,
    pub disabled_reason: String,

    /// The most recent audit-log head committed to the chain.
    pub anchor: Option<Anchor>,

    /// The verified tip, for the netmap and for peer head comparison (§5).
    pub head: Vec<u8>,
    pub head_seq: u64,

    last_time: i64,
}

impl State {
    /// Whether a handle presenting these keys may be peered with at time `t` —
    /// spec §6.
    ///
    /// **The datapath keys are what is compared.** Checking the identity key
    /// here would not do: it is not used by PHREATIC (`phreatic-v1.md` §4) and
    /// does not appear in a netmap, so a check that ignored the static KEM
    /// key would authorize a node to exist without constraining which
    /// session keys are its — and a compromised server would still substitute
    /// the keys a handshake actually runs against. Spec §6.1. The identity key
    /// is bound to the handle during chain verification instead.
    /// DH session keys no longer exist (ADR-0018); binding the remaining KEM
    /// input preserves coverage of every static session-key input.
    ///
    /// This is the whole enforcement decision, in one total function with no
    /// I/O, so that the node's datapath filter and the console's "who would be
    /// cut off" list cannot drift apart by being computed two different ways.
    #[must_use]
    pub fn is_covered(&self, handle: &str, keys: PeerKeys<'_>, t: i64) -> bool {
        let Some(c) = self.covered.get(handle) else {
            return false;
        };
        // Not constant time — every value here is public — but comparing the
        // datapath keys at all is the entire point of the mechanism.
        if c.kem_public_key != keys.kem_public_key {
            return false;
        }
        if t < c.not_before {
            return false;
        }
        if c.expiry != 0 && t >= c.expiry {
            return false;
        }
        if let Some(&eff) = self.revoked.get(handle) {
            if eff <= t {
                return false;
            }
        }
        true
    }

    /// Those of `peers` that would be dropped under enforcement at time `t`.
    ///
    /// The console renders this as the confirmation list before an operator
    /// moves an aquifer to enforcing; the node uses [`State::is_covered`]
    /// directly. Both go through the same predicate on purpose.
    #[must_use]
    pub fn uncovered<'a, I>(&self, peers: I, t: i64) -> Vec<String>
    where
        I: IntoIterator<Item = (&'a str, PeerKeys<'a>)>,
    {
        let mut out: Vec<String> = peers
            .into_iter()
            .filter(|(h, keys)| !self.is_covered(h, *keys, t))
            .map(|(h, _)| h.to_owned())
            .collect();
        out.sort();
        out
    }
}

/// Walk a log from genesis and return the state it establishes.
///
/// The whole chain is verified every time rather than trusting a stored result.
/// A node does this on every fetch and on every boot from cache: the cost is
/// linear in a log that is small by construction, and the alternative is a
/// stored `State` that anyone with filesystem access can edit.
///
/// # Errors
///
/// Returns [`Error::Broken`] with the failing sequence number for any violation
/// of spec §4, or [`Error::Malformed`] if a body does not decode.
pub fn verify_log(entries: &[Entry]) -> Result<State, Error> {
    if entries.is_empty() {
        return Err(Error::Broken {
            seq: 0,
            why: "empty log".into(),
        });
    }

    let mut st = State::default();
    let mut prev: Vec<u8> = Vec::new();

    for (i, e) in entries.iter().enumerate() {
        let expect_seq = (i as u64).saturating_add(1);
        let broken = |why: String| Error::Broken { seq: e.seq, why };

        // §4.1 — contiguous sequence from 1.
        if e.seq != expect_seq {
            return Err(broken(format!(
                "expected seq {expect_seq}, found {}",
                e.seq
            )));
        }

        // §4.3 — time does not go backwards. A chain whose times move backwards
        // cannot be reasoned about with not-before and expiry.
        if e.time < st.last_time {
            return Err(broken("entry moves time backwards".into()));
        }

        // §4 — genesis is first and appears once.
        if (e.seq == 1) != (e.op == Op::Genesis) {
            return Err(broken(
                "genesis must be the first entry and only the first".into(),
            ));
        }

        // §4.2 and §4.4 — the chain hash, computed rather than trusted.
        let h = chain_hash(&prev, e.seq, e.time, e.op, &e.body);

        // genesis defines the very key list its own signatures index into, so
        // its body must be read before they can be checked. This is the single
        // exception to "parse only after verifying", and it is unavoidable: the
        // alternative is a root list delivered out of band, which is the thing
        // Bedrock exists to remove.
        let mut genesis = None;
        if e.op == Op::Genesis {
            let g = parse_genesis(&e.body)?;
            if g.roots.is_empty() {
                return Err(broken("genesis with no roots".into()));
            }
            if g.k == 0 || g.k as usize > g.roots.len() {
                return Err(broken(format!(
                    "root threshold {} is unreachable with {} roots",
                    g.k,
                    g.roots.len()
                )));
            }
            if g.authorities.is_empty() {
                return Err(broken("genesis with no authorities".into()));
            }
            if g.q == 0 || g.q as usize > g.authorities.len() {
                return Err(broken(format!(
                    "quorum {} is unreachable with {} authorities",
                    g.q,
                    g.authorities.len()
                )));
            }
            validate_anchor_keys(&g.anchor_keys, &g.roots, &g.authorities).map_err(broken)?;
            st.roots.clone_from(&g.roots);
            st.k = g.k;
            genesis = Some(g);
        }

        // §4.6, §4.7, §4.8 — signatures.
        let tier = e.op.tier();
        let (keys, mut threshold) = match tier {
            Tier::Root => (&st.roots, st.k),
            Tier::Authority => (&st.authorities, st.q),
        };
        // anchor_keys is Some only for Op::Anchor, which is what keeps rule 6
        // unchanged everywhere else: an index at or past keys.len() is out of
        // range for node-sign, node-revoke, quorum-change. Only anchor uses
        // ADR-0016's concatenated signer-index space — §3.5.
        let anchor_keys = if e.op == Op::Anchor {
            // An anchor is a claim about the audit log, not a policy change.
            // One authority is enough to make truncation detectable, and
            // requiring q would mean anchors stop being written exactly when
            // the authorities are hardest to assemble.
            threshold = 1;
            Some(st.anchor_keys.as_slice())
        } else {
            None
        };
        verify_signatures(e, &h, tier, keys, anchor_keys, threshold).map_err(broken)?;

        // §4.9 — only now is the body trusted enough to act on.
        apply(&mut st, e, genesis).map_err(|why| Error::Broken { seq: e.seq, why })?;

        st.last_time = e.time;
        st.head_seq = e.seq;
        st.head.clone_from(&h);
        prev = h;
    }

    Ok(st)
}

/// Rules §4.6 through §4.8 for one entry.
///
/// `anchor_keys` is `Some` only when `e.op` is `Op::Anchor`, and it carries
/// ADR-0016's concatenated signer-index space: `signer_index < keys.len()`
/// selects the authority list under `AUTHORITY_CONTEXT`, and
/// `signer_index - keys.len()` selects the anchor list under
/// `ANCHOR_CONTEXT`. For every other op it is `None`, so an index at or past
/// `keys.len()` falls straight through to the out-of-range error — spec §4
/// rule 6, unchanged.
fn verify_signatures(
    e: &Entry,
    entry_hash: &[u8],
    tier: Tier,
    keys: &[Vec<u8>],
    anchor_keys: Option<&[Vec<u8>]>,
    threshold: u32,
) -> Result<(), String> {
    if threshold == 0 {
        return Err("no threshold established for this tier".into());
    }
    // Saturating rather than casting: MAX_SIGNERS already bounds the decoded
    // count, and a saturating conversion cannot wrap a huge length down into a
    // small number that appears to meet the threshold.
    if u32::try_from(e.sigs.len()).unwrap_or(u32::MAX) < threshold {
        return Err(format!("{} signatures, need {threshold}", e.sigs.len()));
    }

    // §3.5 — duplicate signer indices are rejected. Without this a single
    // compromised authority reaches any quorum by repeating itself, which
    // silently reduces q to 1 for every operation in the log.
    let mut seen: Vec<u32> = Vec::with_capacity(e.sigs.len());
    for s in &e.sigs {
        if seen.contains(&s.signer_index) {
            return Err(format!("signer {} appears twice", s.signer_index));
        }
        seen.push(s.signer_index);

        let idx = s.signer_index as usize;
        let ok = if let Some(key) = keys.get(idx) {
            match tier {
                Tier::Root => verify_root(key, entry_hash, &s.sig),
                Tier::Authority => verify_authority(key, entry_hash, &s.sig),
            }
        } else {
            let anchor_key = anchor_keys.and_then(|anchor_keys| {
                idx.checked_sub(keys.len()).and_then(|i| anchor_keys.get(i))
            });
            let Some(key) = anchor_key else {
                return Err(format!(
                    "signer index {} is out of range for {} keys",
                    s.signer_index,
                    keys.len()
                ));
            };
            verify_anchor_key(key, entry_hash, &s.sig)
        };
        if !ok {
            return Err(format!(
                "signature from signer {} does not verify",
                s.signer_index
            ));
        }
    }
    Ok(())
}

/// ADR-0016's two new §4 rules for a body's optional anchor-key block:
///
/// - the combined authority+anchor list stays within `MAX_SIGNERS`, which is
///   the concatenated signer-index space §3.5 defines for `anchor`;
/// - an anchor key MUST NOT also appear in the root or authority list of the
///   same body. A key in two lists answers under two context strings, and
///   copying an authority key into the anchor slot is the exact footgun this
///   tier exists to prevent — rejecting it at verification turns an
///   operational mistake into a failed ceremony rather than a live one.
///
/// `roots` is empty when validating an authority-list body, which carries no
/// root list of its own.
fn validate_anchor_keys(
    anchor_keys: &[Vec<u8>],
    roots: &[Vec<u8>],
    authorities: &[Vec<u8>],
) -> Result<(), String> {
    if authorities.len() + anchor_keys.len() > MAX_SIGNERS as usize {
        return Err(format!(
            "{} authorities plus {} anchor keys exceeds the {MAX_SIGNERS}-signer limit",
            authorities.len(),
            anchor_keys.len()
        ));
    }
    for ak in anchor_keys {
        if roots.contains(ak) {
            return Err("an anchor key must not also appear in the root list".into());
        }
        if authorities.contains(ak) {
            return Err("an anchor key must not also appear in the authority list".into());
        }
    }
    Ok(())
}

/// Fold a verified entry into the state.
fn apply(st: &mut State, e: &Entry, genesis: Option<crate::log::Genesis>) -> Result<(), String> {
    match e.op {
        Op::Genesis => {
            let g = genesis.ok_or("genesis body missing")?;
            st.zone = g.zone;
            st.authorities = g.authorities;
            st.q = g.q;
            st.anchor_keys = g.anchor_keys;
        }
        Op::AuthorityList => {
            let a = parse_authority_list(&e.body).map_err(|err| err.to_string())?;
            if a.authorities.is_empty() {
                return Err("authority-list with no authorities".into());
            }
            if a.q == 0 || a.q as usize > a.authorities.len() {
                return Err(format!(
                    "quorum {} is unreachable with {} authorities",
                    a.q,
                    a.authorities.len()
                ));
            }
            validate_anchor_keys(&a.anchor_keys, &[], &a.authorities)?;
            // §7's recovery story depends on this being a replacement, not a
            // merge: "the roots sign a new authority-list" must replace the
            // anchor keys atomically along with the authorities, or authority
            // compromise recovery would take two ceremonies and could
            // silently skip one — ADR-0016.
            st.authorities = a.authorities;
            st.q = a.q;
            st.anchor_keys = a.anchor_keys;
        }
        Op::NodeSign => {
            let n = parse_node_sign(&e.body).map_err(|err| err.to_string())?;
            if n.expiry != 0 && n.expiry <= n.not_before {
                return Err(format!(
                    "node-sign for {:?} expires before it begins",
                    n.handle
                ));
            }
            // A re-signature supersedes an earlier revocation: an operator who
            // countersigns a handle again after revoking it means to readmit it.
            st.revoked.remove(&n.handle);
            st.covered.insert(
                n.handle.clone(),
                NodeCoverage {
                    handle: n.handle,
                    identity_key: n.identity_key,
                    kem_public_key: n.kem_public_key,
                    not_before: n.not_before,
                    expiry: n.expiry,
                },
            );
        }
        Op::NodeRevoke => {
            let r = parse_node_revoke(&e.body).map_err(|err| err.to_string())?;
            st.revoked.insert(r.handle, r.effective);
        }
        Op::QuorumChange => {
            let q = crate::log::parse_quorum_change(&e.body).map_err(|err| err.to_string())?;
            if q == 0 || q as usize > st.authorities.len() {
                return Err(format!(
                    "quorum {q} is unreachable with {} authorities",
                    st.authorities.len()
                ));
            }
            // The entry was verified against the OLD q in verify_log — §4.8.
            st.q = q;
        }
        Op::Anchor => {
            let a = parse_anchor(&e.body).map_err(|err| err.to_string())?;
            // ADR-0016's new §4 rule: audit_seq must strictly increase.
            // Harmless while the server holds no anchor key — it does not
            // today — and load-bearing the moment it does: without this, a
            // server that truncates its own audit log can anchor the
            // truncated head and every node accepts the rewind.
            if let Some(prev) = &st.anchor {
                if a.audit_seq <= prev.audit_seq {
                    return Err(format!(
                        "anchor audit_seq {} does not advance past the previous anchor's {}",
                        a.audit_seq, prev.audit_seq
                    ));
                }
            }
            st.anchor = Some(a);
        }
        Op::Disable => {
            st.disabled_reason = parse_disable(&e.body).map_err(|err| err.to_string())?;
            st.disabled = true;
        }
    }
    Ok(())
}
