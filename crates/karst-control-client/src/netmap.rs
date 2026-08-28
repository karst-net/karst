// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Node-side PSK selection.
//!
//! The netmap hands a node two PSKs per peer — the current epoch and the one
//! before it. `phreatic-v1.md` §7.3 says what to do with them:
//!
//! > `psk_epoch` selects the per-pair PSK. Responders MUST accept epoch *n* and
//! > *n−1* and MUST reject any other. […] If a node holds no PSK for a peer it
//! > MUST use 32 zero bytes and MUST mark the session **lattice-only**. […]
//! > Implementations MUST NOT silently treat a zero PSK as equivalent to a
//! > real one.
//!
//! That last sentence is the reason [`PskChoice`] is an enum rather than a
//! `Psk`. A function returning bytes lets a caller fall back to zeros and
//! forget to flag it; the flagging is the whole security property, since a
//! lattice-only session is one where a break of ML-KEM is a break of the
//! session. Making the two cases different types means the caller cannot
//! reach the bytes without having seen which one it got.

use crate::psk::Psk;

/// What a node ended up using for a peer, and whether that is the real thing.
#[derive(Debug)]
pub enum PskChoice<'a> {
    /// A real per-pair PSK. The session has the assumption-diversity hedge.
    Derived(&'a Psk),
    /// No PSK was available, so 32 zero bytes are used and the session is
    /// **lattice-only**: its confidentiality rests on ML-KEM alone.
    ///
    /// §7.3 requires this to be reported to the coordination server for the
    /// crypto posture view and surfaced locally. It is not an error and must
    /// not be treated as one — connectivity is preserved deliberately — but it
    /// must never pass unremarked.
    LatticeOnly,
}

impl PskChoice<'_> {
    /// The bytes to mix into the handshake.
    ///
    /// Takes the zero PSK by value for the fallback, so the caller has already
    /// had to name [`PskChoice::LatticeOnly`] to get here.
    #[must_use]
    pub fn bytes(&self) -> [u8; crate::psk::PSK_LEN] {
        match self {
            Self::Derived(p) => *p.as_bytes(),
            Self::LatticeOnly => [0u8; crate::psk::PSK_LEN],
        }
    }

    /// Whether this session must be reported as lattice-only.
    #[must_use]
    pub fn is_lattice_only(&self) -> bool {
        matches!(self, Self::LatticeOnly)
    }
}

/// The PSKs a node holds for one peer.
#[derive(Debug)]
pub struct PeerPsks {
    /// The epoch `current` belongs to.
    pub epoch: u32,
    /// PSK at `epoch`.
    pub current: Option<Psk>,
    /// PSK at `epoch - 1`. Absent when `epoch` is 0, which has no predecessor.
    pub previous: Option<Psk>,
}

impl PeerPsks {
    /// The epoch and PSK to use when *initiating* a handshake.
    ///
    /// Always the current epoch: an initiator has no reason to reach back, and
    /// doing so would keep a retired generation alive.
    #[must_use]
    pub fn initiating(&self) -> (u32, PskChoice<'_>) {
        match &self.current {
            Some(p) => (self.epoch, PskChoice::Derived(p)),
            None => (self.epoch, PskChoice::LatticeOnly),
        }
    }

    /// The PSK to use when *responding* to a handshake that declared `epoch`.
    ///
    /// Returns `None` — meaning the handshake MUST be rejected — for any epoch
    /// other than *n* and *n−1*. That is a rejection, not a fallback: a peer
    /// claiming an epoch we have never held is not a peer missing a key, and
    /// treating it as one would let an attacker pick the epoch and so steer
    /// every session into the lattice-only fallback.
    #[must_use]
    pub fn responding(&self, epoch: u32) -> Option<PskChoice<'_>> {
        if epoch == self.epoch {
            return Some(match &self.current {
                Some(p) => PskChoice::Derived(p),
                None => PskChoice::LatticeOnly,
            });
        }
        if self.epoch > 0 && epoch == self.epoch - 1 {
            return Some(match &self.previous {
                Some(p) => PskChoice::Derived(p),
                None => PskChoice::LatticeOnly,
            });
        }
        None
    }
}

// ── peer digests, for delta push ────────────────────────────────────────────

use sha2::{Digest, Sha256};

/// One peer entry as this node holds it, for computing a digest.
///
/// Only the fields the digest covers. The PSKs are deliberately absent: a
/// value the node computes and *sends to the server* must not be a function of
/// secret material, and because a PSK is determined by (pair, epoch, master),
/// covering the epoch detects a rotation anyway.
#[derive(Debug, Default)]
pub struct PeerEntry<'a> {
    pub node_id: &'a [u8],
    pub kem_public_key: &'a [u8],
    pub dh_public_key: &'a [u8],
    pub dns_name: &'a str,
    pub endpoint: &'a str,
    /// The relay this peer holds a connection to — `ponor-v1.md` §9.1.
    ///
    /// Routable content, so it is covered by the digest: a peer that moved
    /// relay whose digest did not change would never be delivered, and every
    /// other node would keep dialling a relay it had left.
    pub home_relay: &'a [u8],
    pub allowed_ips: &'a [String],
}

fn push(h: &mut Sha256, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    h.update(len.to_be_bytes());
    h.update(field);
}

/// Summarise a peer entry so the server can be told what this node already has.
///
/// Delta push works by the *request* carrying the state rather than the server
/// remembering it, which is what keeps server state O(1). Both ends must
/// compute this identically — the node from what it stored, the server from
/// what it would send — and a disagreement means either endless resending of
/// unchanged entries or a change that is never delivered because both sides
/// believe it already arrived. Pinned by
/// `spec/vectors/karst-control-v1.json`.
#[must_use]
pub fn peer_digest(entry: &PeerEntry<'_>, epoch: u32) -> u64 {
    let mut h = Sha256::new();
    h.update(b"karst-peer-digest-v1");
    push(&mut h, &epoch.to_be_bytes());
    push(&mut h, entry.node_id);
    push(&mut h, entry.kem_public_key);
    push(&mut h, entry.dh_public_key);
    push(&mut h, entry.dns_name.as_bytes());
    push(&mut h, entry.endpoint.as_bytes());
    push(&mut h, entry.home_relay);
    for ip in entry.allowed_ips {
        push(&mut h, ip.as_bytes());
    }
    // Take the leading 8 bytes without slicing: the digest is fixed-width, so
    // an index here can only fail if the hash changes, and the lint is right
    // that a panic in a node's steady-state path is not an acceptable way to
    // find that out.
    let out = h.finalize();
    leading_u64(&out)
}

/// One compiled filter rule, as the version hash sees it.
///
/// Serves both directions: `nodes` are sources in the inbound filter and
/// destinations in the outbound one. Which it is comes from the field the rule
/// appears in — which is exactly why the hash writes a separator between the
/// two lists.
#[derive(Debug, Default)]
pub struct FilterRuleView<'a> {
    pub nodes: &'a [String],
    /// Inclusive `(first, last)` port ranges.
    pub ports: &'a [(u32, u32)],
}

/// One pinned Ponor relay entry as the version hash sees it.
#[derive(Debug, Default)]
pub struct RelayView<'a> {
    pub address: &'a str,
    pub tls_server_name: &'a str,
    pub relay_id: &'a [u8],
    pub identity_key: &'a [u8],
    pub region: &'a str,
}

/// One split-DNS suffix and the mesh-reachable resolvers for it.
#[derive(Debug, Default)]
pub struct DNSRouteView<'a> {
    pub match_domain: &'a str,
    pub resolvers: &'a [String],
}

/// The DNS portion of a netmap, as the version hash sees it.
///
/// DNS configuration is separate from the node's short DNS label. The latter
/// names this node in the mesh zone; this controls how questions outside that
/// authoritative zone are handled.
#[derive(Debug, Default)]
pub struct DNSConfigView<'a> {
    pub nameservers: &'a [String],
    pub search_domains: &'a [String],
    pub routes: &'a [DNSRouteView<'a>],
    pub zone: &'a str,
    pub magic_dns: bool,
}

/// A whole netmap, for [`netmap_version`].
///
/// Borrowed rather than owned, and listing only the fields the hash covers, so
/// that a caller cannot accidentally include the PSK bytes: they are not in
/// this struct to be passed.
#[derive(Debug, Default)]
pub struct NetmapContent<'a> {
    pub psk_epoch: u32,
    pub node_id: &'a [u8],
    pub dns_name: &'a str,
    pub addresses: &'a [String],
    pub peers: &'a [PeerEntry<'a>],
    /// Who may reach this node.
    pub packet_filter: &'a [FilterRuleView<'a>],
    /// Whom this node may reach.
    pub egress_filter: &'a [FilterRuleView<'a>],
    pub relays: &'a [RelayView<'a>],
    /// Authenticated resolver policy. Changes must move the netmap version so
    /// a node cannot keep forwarding with an obsolete upstream list.
    pub dns: DNSConfigView<'a>,
    /// The tip of the Bedrock log the server is serving. Part of the content
    /// hash so a log that has moved cannot be reported as `unchanged`.
    pub bedrock_head: BedrockHeadView<'a>,
}

/// The Bedrock log tip as the version hash sees it — `bedrock-v1.md` §5.
///
/// The default (empty hash, sequence zero) is what an account with no log
/// hashes as. It is unambiguous: sequence numbering starts at one, so no real
/// head is ever at zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BedrockHeadView<'a> {
    pub hash: &'a [u8],
    pub seq: u64,
    /// The advertised enforcement mode, as the wire enum's numeric value.
    ///
    /// Hashed, so enabling enforcement from a console reaches nodes on their
    /// next poll rather than waiting for some other part of the netmap to
    /// change. Without it, turning on the network lock would be a change the
    /// server could not deliver.
    pub mode: u32,
}

/// The netmap's content hash — `NetmapVersion` in `control/netmap.go`.
///
/// A content hash rather than a counter, so identical netmaps always yield the
/// same value and the server can answer "nothing changed" without keeping
/// per-node history. Both ends compute it: the server to label what it sends,
/// the node to check that what it assembled is what the server believes it
/// sent. A silent disagreement would be **permanent and invisible** — the node
/// would report a version describing a netmap it does not hold, the server
/// would answer `unchanged` forever, and a peer added afterwards would never
/// be delivered. Pinned by `spec/vectors/karst-control-v1.json`.
///
/// The PSK bytes are deliberately not hashed. A PSK is determined by (pair,
/// epoch, master), so hashing the peer set and the epoch detects exactly the
/// same changes without making a value sent in clear a function of secret
/// material.
#[must_use]
pub fn netmap_version(content: &NetmapContent<'_>) -> u64 {
    let mut h = Sha256::new();
    h.update(b"karst-netmap-version-v1");
    h.update(content.psk_epoch.to_be_bytes());
    push(&mut h, content.node_id);
    push(&mut h, content.dns_name.as_bytes());
    for a in content.addresses {
        push(&mut h, a.as_bytes());
    }
    for p in content.peers {
        push(&mut h, p.node_id);
        push(&mut h, p.kem_public_key);
        push(&mut h, p.dh_public_key);
        push(&mut h, p.dns_name.as_bytes());
        push(&mut h, p.endpoint.as_bytes());
        push(&mut h, p.home_relay);
        for ip in p.allowed_ips {
            push(&mut h, ip.as_bytes());
        }
    }
    // Both filters are part of the content. Without them, editing a policy
    // would leave the version identical, every node would be told "unchanged",
    // and the new rules would never arrive — a policy edit that appears to
    // apply and does not.
    push_rules(&mut h, content.packet_filter);
    // A separator, not decoration. Concatenating the two rule lists without one
    // makes them indistinguishable: a rule moving from "who may reach me" to
    // "whom may I reach" produces the identical byte stream, the version does
    // not move, and the inverted policy is never delivered.
    push(&mut h, b"karst-egress-filter");
    push_rules(&mut h, content.egress_filter);
    push(&mut h, b"karst-relays");
    for relay in content.relays {
        push(&mut h, relay.address.as_bytes());
        push(&mut h, relay.tls_server_name.as_bytes());
        push(&mut h, relay.relay_id);
        push(&mut h, relay.identity_key);
        push(&mut h, relay.region.as_bytes());
    }
    push(&mut h, b"karst-dns");
    push(&mut h, content.dns.zone.as_bytes());
    h.update(u32::from(content.dns.magic_dns).to_be_bytes());
    for nameserver in content.dns.nameservers {
        push(&mut h, nameserver.as_bytes());
    }
    for domain in content.dns.search_domains {
        push(&mut h, domain.as_bytes());
    }
    for route in content.dns.routes {
        push(&mut h, route.match_domain.as_bytes());
        for resolver in route.resolvers {
            push(&mut h, resolver.as_bytes());
        }
    }
    // The Bedrock head, so a server that advances its log cannot answer
    // "unchanged" and leave a node enforcing on a policy that has moved. An
    // absent head hashes as its all-zero default, exactly as an absent DNS
    // config does, so there is one construction rather than two.
    push(&mut h, b"karst-bedrock");
    push(&mut h, content.bedrock_head.hash);
    push(&mut h, &content.bedrock_head.seq.to_be_bytes());
    h.update(content.bedrock_head.mode.to_be_bytes());

    let v = leading_u64(&h.finalize());
    // Zero means "I hold no netmap" on the request side, so it must never be a
    // legitimate version — a node holding it would be told nothing changed.
    if v == 0 {
        1
    } else {
        v
    }
}

fn push_rules(h: &mut Sha256, rules: &[FilterRuleView<'_>]) {
    for r in rules {
        for node in r.nodes {
            push(h, node.as_bytes());
        }
        for (first, last) in r.ports {
            let mut pr = [0u8; 8];
            let (a, b) = pr.split_at_mut(4);
            a.copy_from_slice(&first.to_be_bytes());
            b.copy_from_slice(&last.to_be_bytes());
            push(h, &pr);
        }
    }
}

/// The leading 8 bytes of a digest, without slicing.
///
/// The digest is fixed-width, so an index here could only fail if the hash
/// changed — and a panic in a node's steady-state path is not an acceptable way
/// to find that out.
fn leading_u64(digest: &[u8]) -> u64 {
    let mut first = [0u8; 8];
    for (dst, src) in first.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    u64::from_be_bytes(first)
}
