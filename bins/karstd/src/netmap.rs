// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The node's assembled view of the network.
//!
//! The server sends three shapes of answer to one request, and confusing any
//! two of them is a correctness bug with no visible symptom until much later:
//!
//! | `unchanged` | `delta` | Meaning |
//! |---|---|---|
//! | true | — | keep everything; `peers` is empty because nothing moved |
//! | false | true | `peers` are the entries that changed, `removed_peers` those to drop |
//! | false | false | `peers` is the **complete** set; anything absent is gone |
//!
//! The trap is that all three can arrive carrying an empty peer list, and each
//! one means something different by it. A node alone in its network gets a full
//! netmap with no peers and must drop everyone; a node whose netmap has not
//! moved gets `unchanged` with no peers and must drop nobody. Reading one as
//! the other either strands a removed peer forever or tears down a working
//! network. That is why `karst_control.proto` carries both flags explicitly
//! rather than letting either be inferred from emptiness.
//!
//! # Secrets
//!
//! Every peer entry carries two per-pair PSKs. They are zeroized on drop and
//! neither [`Netmap`] nor [`Peer`] will print them — see the hand-written
//! `Debug` implementations, and `karst_control_client::cache` for why the
//! on-disk copy is encrypted.

use std::collections::BTreeMap;
use std::fmt;

use karst_control_client::netmap::{
    netmap_version, peer_digest, BedrockHeadView, DNSConfigView, DNSRouteView, FilterRuleView,
    NetmapContent, PeerEntry, RelayView,
};
use karst_control_client::transport::pb;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

/// Length of a per-pair PSK.
pub const PSK_LEN: usize = 32;

const RELAY_ID_LEN: usize = 32;
const RELAY_IDENTITY_KEY_LEN: usize = 2592;

/// Authenticated resolver policy supplied with a netmap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub routes: Vec<DNSRoute>,
    pub zone: String,
    pub magic_dns: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSRoute {
    pub match_domain: String,
    pub resolvers: Vec<String>,
}

/// The tip of the Bedrock log the server reported — `bedrock-v1.md` §5.
///
/// The default (empty hash, sequence zero) means the account has no log. That
/// is unambiguous rather than merely conventional: Bedrock sequence numbering
/// starts at one, so no real head is ever at zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BedrockHead {
    /// SHA-512 chain hash of the tip entry, 64 bytes, or empty for no log.
    pub hash: Vec<u8>,
    pub seq: u64,
    /// The enforcement mode the operator selected, as the server advertises it.
    ///
    /// A **floor the server may raise, never one it may lower** — the node
    /// takes the maximum of this and its own configured minimum. See
    /// `crate::bedrock::Mode`.
    pub mode: crate::bedrock::Mode,
}

impl BedrockHead {
    /// Whether the advertised mode is enforcing. For tests that need to assert
    /// what the *server* said, distinct from what the node decided.
    #[must_use]
    pub fn mode_is_enforcing(&self) -> bool {
        self.mode == crate::bedrock::Mode::Enforcing
    }

    /// Whether the server claims to have a log at all.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.seq != 0 && !self.hash.is_empty()
    }

    fn from_wire(head: Option<&pb::KarstBedrockHead>) -> Self {
        head.map_or_else(Self::default, |h| Self {
            hash: h.hash.clone(),
            seq: h.seq,
            mode: crate::bedrock::Mode::from_wire(h.mode),
        })
    }

    /// The wire form.
    ///
    /// `None` for an absent head rather than a zero-valued message, so that
    /// re-encoding a netmap into the on-disk cache reproduces the bytes the
    /// server sent — and therefore the same content hash. A `Some` full of
    /// zeroes would hash identically but would not round-trip as the same
    /// message.
    fn to_wire(&self) -> Option<pb::KarstBedrockHead> {
        if self.is_present() {
            Some(pb::KarstBedrockHead {
                hash: self.hash.clone(),
                seq: self.seq,
                mode: self.mode as i32,
            })
        } else {
            None
        }
    }
}

impl DNSConfig {
    fn from_wire(config: Option<pb::KarstDnsConfig>) -> Self {
        let Some(config) = config else {
            return Self::default();
        };
        Self {
            nameservers: config.nameservers,
            search_domains: config.search_domains,
            routes: config
                .routes
                .into_iter()
                .map(|route| DNSRoute {
                    match_domain: route.match_domain,
                    resolvers: route.resolvers,
                })
                .collect(),
            zone: config.zone,
            magic_dns: config.magic_dns,
        }
    }

    fn to_wire(&self) -> pb::KarstDnsConfig {
        pb::KarstDnsConfig {
            nameservers: self.nameservers.clone(),
            search_domains: self.search_domains.clone(),
            routes: self
                .routes
                .iter()
                .map(|route| pb::KarstDnsRoute {
                    match_domain: route.match_domain.clone(),
                    resolvers: route.resolvers.clone(),
                })
                .collect(),
            zone: self.zone.clone(),
            magic_dns: self.magic_dns,
        }
    }
}

/// A validated relay registry entry, pinned for the Ponor handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct Relay {
    pub address: String,
    /// DNS name for TLS SNI and certificate validation; Ponor identity remains
    /// pinned by `identity_key` and `relay_id`.
    pub tls_server_name: String,
    pub relay_id: [u8; RELAY_ID_LEN],
    pub identity_key: Vec<u8>,
    pub region: String,
}

impl fmt::Debug for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relay")
            .field("address", &self.address)
            .field("tls_server_name", &self.tls_server_name)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Relay {
    fn from_wire(relay: &pb::KarstRelay) -> Result<Self, Error> {
        if relay.address.parse::<std::net::SocketAddr>().is_err() {
            return Err(Error::Relay("address is not a socket address".to_owned()));
        }
        if relay.tls_server_name.is_empty()
            || !relay.tls_server_name.is_ascii()
            || relay
                .tls_server_name
                .bytes()
                .any(|b| b.is_ascii_whitespace())
        {
            return Err(Error::Relay(
                "tls_server_name is not a usable ASCII DNS name".to_owned(),
            ));
        }
        let relay_id: [u8; RELAY_ID_LEN] = relay
            .relay_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Relay("relay_id is not 32 bytes".to_owned()))?;
        if relay.identity_key.len() != RELAY_IDENTITY_KEY_LEN {
            return Err(Error::Relay(
                "identity_key is not an ML-DSA-87 public key".to_owned(),
            ));
        }
        // ponor-v1.md §5.2 defines the relay ID as a digest of its pinned
        // identity key. Checking that relation while the authenticated netmap
        // is decoded makes a malformed registry entry fail closed here rather
        // than later as an inexplicable handshake failure.
        let mut h = Sha256::new();
        h.update(b"karst-relay-id-v1");
        h.update(&relay.identity_key);
        let derived: [u8; RELAY_ID_LEN] = h.finalize().into();
        if relay_id != derived {
            return Err(Error::Relay(
                "relay_id does not match identity_key".to_owned(),
            ));
        }
        Ok(Self {
            address: relay.address.clone(),
            tls_server_name: relay.tls_server_name.clone(),
            relay_id,
            identity_key: relay.identity_key.clone(),
            region: relay.region.clone(),
        })
    }

    fn to_wire(&self) -> pb::KarstRelay {
        pb::KarstRelay {
            address: self.address.clone(),
            tls_server_name: self.tls_server_name.clone(),
            relay_id: self.relay_id.to_vec(),
            identity_key: self.identity_key.clone(),
            region: self.region.clone(),
        }
    }
}

/// A TURN (RFC 8656) fallback server, with the ephemeral credential minted for
/// this netmap response — `spec/aven-v1.md` §7.8, ADR-0008 §4.
///
/// **Not pinned, unlike [`Relay`].** A TURN server authenticates the *client*
/// by a shared credential; there is no server identity for this node to check,
/// so validation here is limited to the wire shape being usable at all.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// A `turn:` or `turns:` URI (RFC 8656 / RFC 7065), e.g.
    /// `turn:turn.example.com:3478`.
    pub uri: String,
    pub region: String,
    /// A unix expiry timestamp, per the TURN-REST scheme.
    pub username: String,
    /// `base64(HMAC-SHA1(shared_secret, username))`. A real secret, like a PSK,
    /// even though it is short-lived — see [`Credential`].
    pub password: TurnCredential,
    /// Unix seconds. Redundant with `username` but explicit.
    pub expires_at: u64,
}

impl fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnServer")
            .field("uri", &self.uri)
            .field("region", &self.region)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl TurnServer {
    fn from_wire(server: &pb::KarstTurnServer) -> Result<Self, Error> {
        if server.uri.is_empty()
            || !(server.uri.starts_with("turn:") || server.uri.starts_with("turns:"))
        {
            return Err(Error::Turn("uri is not a turn: or turns: URI".to_owned()));
        }
        if server.username.is_empty() || server.password.is_empty() {
            return Err(Error::Turn(
                "a minted TURN credential is missing its username or password".to_owned(),
            ));
        }
        Ok(Self {
            uri: server.uri.clone(),
            region: server.region.clone(),
            username: server.username.clone(),
            password: TurnCredential(server.password.clone()),
            expires_at: server.expires_at,
        })
    }
}

/// A minted TURN password. Like [`Psk`], a real secret that does not print —
/// `turncred.Credential`'s doc comment on the Go side explains why: Phase 3's
/// exit criterion is an automated scan for secret bytes in logs, traces and
/// bugreports, and that only reliably holds if the type refuses to render
/// rather than every call site remembering to redact it.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnCredential(String);

impl TurnCredential {
    /// The password, for building a `turn::client::ClientConfig`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build one directly, for a test that needs a [`TurnServer`] but is not
    /// itself testing decode from the wire (`crate::turn`'s unit tests, and
    /// this module's own).
    #[cfg(test)]
    pub(crate) fn for_tests(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl fmt::Debug for TurnCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("turn_password(redacted)")
    }
}

/// Why a netmap could not be applied or decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The cached bytes are not a `KarstNetmapResponse`.
    Malformed(String),
    /// A PSK field was present but not 32 bytes.
    PskLength {
        /// Which peer, as a lossy handle.
        peer: String,
        /// What arrived.
        len: usize,
    },
    /// A discovery-key field was present but not 32 bytes.
    DiscoKeyLength {
        /// Which peer, as a lossy handle.
        peer: String,
        /// What arrived.
        len: usize,
    },
    Relay(String),
    /// A `KarstTurnServer` entry could not be used — `spec/aven-v1.md` §7.8.
    Turn(String),
    /// The assembled state does not hash to the version the server reported.
    ///
    /// See [`Netmap::apply`] for why this is worth detecting rather than
    /// tolerating.
    VersionMismatch {
        /// What the server said the netmap hashes to.
        server: u64,
        /// What this node's assembled state hashes to.
        local: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed netmap: {m}"),
            Self::PskLength { peer, len } => {
                write!(f, "peer {peer}: psk is {len} bytes, expected {PSK_LEN}")
            }
            Self::DiscoKeyLength { peer, len } => {
                write!(
                    f,
                    "peer {peer}: disco key is {len} bytes, expected {PSK_LEN}"
                )
            }
            Self::Relay(message) => write!(f, "invalid relay: {message}"),
            Self::Turn(message) => write!(f, "invalid turn server: {message}"),
            Self::VersionMismatch { server, local } => write!(
                f,
                "assembled netmap hashes to {local:016x} but the server called it \
                 {server:016x}; the local view is not what the server believes it sent"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A per-pair PSK, which does not print and does not linger in memory.
pub struct Psk([u8; PSK_LEN]);

impl Psk {
    /// The bytes, for mixing into a PHREATIC handshake.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }
}

impl Drop for Psk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// The single most valuable byte string a node holds for a pair. It does not
// render, in any format, for any verb — see `psk.Key` on the server for the
// same treatment.
impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("psk(redacted)")
    }
}

/// A per-pair AVEN key. It is separate from the PHREATIC PSK and must not
/// render or remain in memory after its peer is dropped.
pub struct DiscoKey([u8; PSK_LEN]);

impl DiscoKey {
    /// The bytes for the AVEN authenticator.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }
}

impl Drop for DiscoKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DiscoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("disco_key(redacted)")
    }
}

/// One peer as this node holds it.
pub struct Peer {
    /// The server-assigned handle. The map key, and what the packet filter
    /// names sources by.
    pub node_id: Vec<u8>,
    /// Address ranges this peer owns, as written by the server.
    pub allowed_ips: Vec<String>,
    /// Short DNS label.
    pub dns_name: String,
    /// Where to reach it, if the server knows.
    pub endpoint: String,
    /// The relay this peer holds a connection to — `ponor-v1.md` §9.1.
    ///
    /// §9.1's second rule: how to reach a peer with no direct path that is not
    /// on this node's own relay or its mesh. Empty means the peer has not
    /// reported one, which is "no second option" rather than an invitation to
    /// guess — a guess sends a handshake to a relay the peer is not connected
    /// to and then waits out the timeout.
    pub home_relay: Vec<u8>,
    /// ML-KEM-768 encapsulation key, 1184 B.
    pub kem_public_key: Vec<u8>,
    /// X25519 static public key, 32 B.
    pub dh_public_key: Vec<u8>,
    /// PSK for the current epoch. Absent means the §7.3 lattice-only fallback.
    pub psk: Option<Psk>,
    /// PSK for the previous epoch, so a rotation is answerable in both
    /// directions (§7.3). Absent when the epoch is 0.
    pub psk_previous: Option<Psk>,
    /// AVEN path-discovery key. Absent means keep the relay path.
    pub disco_key: Option<DiscoKey>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("node_id", &lossy(&self.node_id))
            .field("dns_name", &self.dns_name)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            // Whether a PSK exists is diagnostic and must be visible; the bytes
            // are not. A peer with no PSK is a lattice-only session, which §7.3
            // requires be surfaced rather than assumed.
            .field("psk", &self.psk.as_ref().map(|_| "psk(redacted)"))
            .field(
                "psk_previous",
                &self.psk_previous.as_ref().map(|_| "psk(redacted)"),
            )
            .field(
                "disco_key",
                &self.disco_key.as_ref().map(|_| "disco_key(redacted)"),
            )
            .finish_non_exhaustive()
    }
}

impl Peer {
    fn from_wire(p: pb::KarstNetmapPeer) -> Result<Self, Error> {
        let psk = optional_psk(&p.psk, &p.node_id)?;
        let psk_previous = optional_psk(&p.psk_previous, &p.node_id)?;
        let disco_key = optional_disco_key(&p.disco_key, &p.node_id)?;
        Ok(Self {
            node_id: p.node_id,
            allowed_ips: p.allowed_ips,
            dns_name: p.dns_name,
            endpoint: p.endpoint,
            home_relay: p.home_relay,
            kem_public_key: p.kem_public_key,
            dh_public_key: p.dh_public_key,
            psk,
            psk_previous,
            disco_key,
        })
    }

    fn to_wire(&self) -> pb::KarstNetmapPeer {
        pb::KarstNetmapPeer {
            node_id: self.node_id.clone(),
            allowed_ips: self.allowed_ips.clone(),
            dns_name: self.dns_name.clone(),
            endpoint: self.endpoint.clone(),
            home_relay: self.home_relay.clone(),
            kem_public_key: self.kem_public_key.clone(),
            dh_public_key: self.dh_public_key.clone(),
            psk: self.psk.as_ref().map(|p| p.0.to_vec()).unwrap_or_default(),
            psk_previous: self
                .psk_previous
                .as_ref()
                .map(|p| p.0.to_vec())
                .unwrap_or_default(),
            disco_key: self
                .disco_key
                .as_ref()
                .map(|k| k.0.to_vec())
                .unwrap_or_default(),
        }
    }

    /// The digest the server will compare against.
    #[must_use]
    pub fn digest(&self, epoch: u32) -> u64 {
        peer_digest(
            &PeerEntry {
                node_id: &self.node_id,
                kem_public_key: &self.kem_public_key,
                dh_public_key: &self.dh_public_key,
                dns_name: &self.dns_name,
                endpoint: &self.endpoint,
                home_relay: &self.home_relay,
                allowed_ips: &self.allowed_ips,
            },
            epoch,
        )
    }
}

/// An empty PSK field is the §7.3 fallback, not a zero key.
///
/// Returning `None` rather than `Some([0u8; 32])` is the whole point: a caller
/// holding `Option<Psk>` cannot reach zero bytes without first having named the
/// absent case, so the "MUST mark the session lattice-only" obligation cannot
/// be discharged by accident.
fn optional_psk(bytes: &[u8], node_id: &[u8]) -> Result<Option<Psk>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut key = [0u8; PSK_LEN];
    let Some(src) = bytes.get(..PSK_LEN).filter(|_| bytes.len() == PSK_LEN) else {
        return Err(Error::PskLength {
            peer: lossy(node_id),
            len: bytes.len(),
        });
    };
    key.copy_from_slice(src);
    Ok(Some(Psk(key)))
}

fn optional_disco_key(bytes: &[u8], node_id: &[u8]) -> Result<Option<DiscoKey>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut key = [0u8; PSK_LEN];
    let Some(src) = bytes.get(..PSK_LEN).filter(|_| bytes.len() == PSK_LEN) else {
        return Err(Error::DiscoKeyLength {
            peer: lossy(node_id),
            len: bytes.len(),
        });
    };
    key.copy_from_slice(src);
    Ok(Some(DiscoKey(key)))
}

/// What applying a response did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The server confirmed the node's version; nothing was touched.
    Unchanged,
    /// The full peer set was replaced.
    Replaced {
        /// How many peers the node now holds.
        peers: usize,
    },
    /// Only the named entries moved.
    Delta {
        /// Entries added or updated.
        changed: usize,
        /// Entries dropped.
        removed: usize,
    },
}

/// The node's assembled network view.
pub struct Netmap {
    /// Content hash of the whole netmap, as computed by the server. Zero means
    /// "I hold nothing", which is what a first request sends.
    pub version: u64,
    /// Which PSK generation the keys below belong to.
    pub psk_epoch: u32,
    /// This node's handle.
    pub node_id: Vec<u8>,
    /// This node's addresses.
    pub addresses: Vec<String>,
    /// This node's short DNS label.
    pub dns_name: String,
    /// Resolver policy for mesh, global, and split DNS questions.
    pub dns_config: DNSConfig,
    /// Who may reach this node. **An empty list is default deny, not
    /// "unfiltered"** — see [`crate::filter`].
    pub packet_filter: Vec<pb::KarstFilterRule>,
    /// Whom this node may reach. Also default deny when empty, and not
    /// derivable from `packet_filter`: Karst's ACLs are unidirectional grants,
    /// so a node's inbound rules say nothing about what it may send.
    pub egress_filter: Vec<pb::KarstEgressRule>,
    /// Pinned relay choices, replaced wholesale with every netmap.
    pub relays: Vec<Relay>,
    /// TURN fallback servers, each with a credential minted fresh for the
    /// response that carried it — `spec/aven-v1.md` §7.8, ADR-0008 §4.
    ///
    /// **Updated on every response, including an `unchanged` one.** Unlike
    /// every other field here, the server mints a fresh credential regardless
    /// of whether anything else moved (`karst_control.proto`'s doc comment on
    /// `turn_servers`: "Never `unchanged`-cached: a stale minted credential is
    /// an expired one, not a reusable one") — and confirmed on the Go side,
    /// `NetmapVersion` never reads this field, so it is not part of what
    /// `unchanged` even means. [`Netmap::apply`] applies it before the
    /// `unchanged` early return for exactly this reason.
    pub turn_servers: Vec<TurnServer>,
    /// The tip of the Bedrock log the server reported — `bedrock-v1.md` §5.
    ///
    /// Held so the node can compare it against what it has verified, and
    /// against what a peer reports at session setup. Part of the netmap content
    /// hash, so a server that advances its log cannot report `unchanged`.
    pub bedrock_head: BedrockHead,
    /// Peers, keyed by handle. Ordered, so digests and the re-encoded form are
    /// deterministic rather than dependent on hash iteration order.
    peers: BTreeMap<Vec<u8>, Peer>,
}

impl Default for Netmap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Netmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Netmap")
            .field("version", &format_args!("{:016x}", self.version))
            .field("psk_epoch", &self.psk_epoch)
            .field("node_id", &lossy(&self.node_id))
            .field("addresses", &self.addresses)
            .field("peers", &self.peers.len())
            .field("filter_rules", &self.packet_filter.len())
            .field("egress_rules", &self.egress_filter.len())
            .field("turn_servers", &self.turn_servers.len())
            .finish_non_exhaustive()
    }
}

impl Netmap {
    /// A node that holds nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 0,
            psk_epoch: 0,
            node_id: Vec::new(),
            addresses: Vec::new(),
            dns_name: String::new(),
            dns_config: DNSConfig::default(),
            bedrock_head: BedrockHead::default(),
            packet_filter: Vec::new(),
            egress_filter: Vec::new(),
            relays: Vec::new(),
            turn_servers: Vec::new(),
            peers: BTreeMap::new(),
        }
    }

    /// The peers this node holds, in handle order.
    #[must_use]
    pub fn peers(&self) -> impl ExactSizeIterator<Item = &Peer> {
        self.peers.values()
    }

    #[cfg(test)]
    pub(crate) fn insert_test_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.node_id.clone(), peer);
    }

    /// One peer by handle.
    #[must_use]
    pub fn peer(&self, node_id: &[u8]) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    /// What to put in the next request's `holds`, so the server can answer with
    /// a delta.
    ///
    /// Computed from what this node actually stored rather than remembered from
    /// what arrived: if the two ever differed, remembering would report a peer
    /// as held that was in fact dropped, and the server would never resend it.
    #[must_use]
    pub fn holds(&self) -> Vec<pb::KarstPeerDigest> {
        self.peers
            .values()
            .map(|p| pb::KarstPeerDigest {
                node_id: p.node_id.clone(),
                digest: p.digest(self.psk_epoch),
            })
            .collect()
    }

    /// Merge a server response into this view.
    ///
    /// # The version check
    ///
    /// After applying, the node recomputes the content hash over its assembled
    /// state and compares it with the version the server reported. They must
    /// agree, because that version is exactly what the node will send back as
    /// `known_version` next time.
    ///
    /// If they silently disagreed the failure would be **permanent and
    /// invisible**: the node reports a version describing a netmap it does not
    /// hold, the server answers `unchanged` forever, and a peer added
    /// afterwards is never delivered. Nothing errors, no counter moves, and the
    /// only symptom is a peer that cannot be reached. Detecting it costs one
    /// hash over data already in hand, and the recovery is to ask again from
    /// scratch — which [`Netmap::reset`] exists for.
    ///
    /// # Errors
    ///
    /// [`Error::PskLength`] for a malformed PSK, and [`Error::VersionMismatch`]
    /// if the assembled state does not reproduce the server's version.
    pub fn apply(&mut self, resp: pb::KarstNetmapResponse) -> Result<Outcome, Error> {
        // **Before the `unchanged` check, deliberately.** A minted TURN
        // credential is fresh on every response the server sends — including
        // one that reports `unchanged` for everything else — so applying it
        // only on the non-`unchanged` path would leave this node holding a
        // credential that ages toward its own expiry on every poll that
        // changed nothing, which on a quiet netmap is most of them. See the
        // field's own doc comment.
        self.turn_servers = resp
            .turn_servers
            .iter()
            .map(TurnServer::from_wire)
            .collect::<Result<_, _>>()?;

        // Read the flags before anything else is mutated. `unchanged` wins over
        // `delta`: the server sets only one, and treating an unchanged response
        // as an empty delta would be harmless while treating it as a full
        // netmap would drop every peer.
        if resp.unchanged {
            return Ok(Outcome::Unchanged);
        }

        // Node-level fields are complete in every non-`unchanged` response, so
        // they are replaced rather than merged.
        self.psk_epoch = resp.psk_epoch;
        self.node_id = resp.node_id;
        self.addresses = resp.addresses;
        self.dns_name = resp.dns_name;
        self.dns_config = DNSConfig::from_wire(resp.dns_config);
        self.bedrock_head = BedrockHead::from_wire(resp.bedrock_head.as_ref());
        // The filter is shipped whole even in a delta — it is small, and a rule
        // set assembled from fragments would be a second thing to keep in step.
        // If that ever changes, replacing wholesale here would empty the filter
        // instead of updating it, and an empty filter is default deny: the
        // failure would be an outage, not an opening.
        self.packet_filter = resp.packet_filter;
        self.egress_filter = resp.egress_filter;
        self.relays = resp
            .relays
            .iter()
            .map(Relay::from_wire)
            .collect::<Result<_, _>>()?;

        let outcome = if resp.delta {
            let changed = resp.peers.len();
            for p in resp.peers {
                let peer = Peer::from_wire(p)?;
                // Insert replaces. A changed entry is the entry, not a patch to
                // merge into the one held — a peer whose key rotated must not
                // keep the old key alongside the new.
                self.peers.insert(peer.node_id.clone(), peer);
            }
            let mut removed = 0;
            for id in &resp.removed_peers {
                if self.peers.remove(id).is_some() {
                    removed += 1;
                }
            }
            Outcome::Delta { changed, removed }
        } else {
            // A full netmap is authoritative: peers absent from it are gone.
            // `removed_peers` is deliberately ignored here — the proto says it
            // is meaningful only under `delta`, and acting on it in both cases
            // would make a server bug in one field corrupt the other path.
            let mut peers = BTreeMap::new();
            for p in resp.peers {
                let peer = Peer::from_wire(p)?;
                peers.insert(peer.node_id.clone(), peer);
            }
            let count = peers.len();
            self.peers = peers;
            Outcome::Replaced { peers: count }
        };

        let local = self.content_version();
        if local != resp.version {
            return Err(Error::VersionMismatch {
                server: resp.version,
                local,
            });
        }
        self.version = resp.version;
        Ok(outcome)
    }

    /// Forget everything, so the next request asks for a full netmap.
    ///
    /// The recovery from any inconsistency: a node that cannot trust its view
    /// throws it away rather than trying to repair it, because a repaired view
    /// is one whose relationship to the server's is unknown.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// The content hash of the assembled state, by the same construction the
    /// server uses.
    ///
    /// Both ends must agree on this byte for byte, so the function itself lives
    /// in `karst_control_client` beside the digest and is pinned by
    /// `spec/vectors/karst-control-v1.json`.
    #[must_use]
    pub fn content_version(&self) -> u64 {
        // `NetmapContent` borrows, and deliberately has no field for the PSK
        // bytes — they are not in the struct to be passed by mistake.
        let entries: Vec<PeerEntry<'_>> = self
            .peers
            .values()
            .map(|p| PeerEntry {
                node_id: &p.node_id,
                kem_public_key: &p.kem_public_key,
                dh_public_key: &p.dh_public_key,
                dns_name: &p.dns_name,
                endpoint: &p.endpoint,
                home_relay: &p.home_relay,
                allowed_ips: &p.allowed_ips,
            })
            .collect();
        let in_ports: Vec<Vec<(u32, u32)>> = self
            .packet_filter
            .iter()
            .map(|r| r.ports.iter().map(|p| (p.first, p.last)).collect())
            .collect();
        let out_ports: Vec<Vec<(u32, u32)>> = self
            .egress_filter
            .iter()
            .map(|r| r.ports.iter().map(|p| (p.first, p.last)).collect())
            .collect();
        let rules: Vec<FilterRuleView<'_>> = self
            .packet_filter
            .iter()
            .zip(in_ports.iter())
            .map(|(r, ports)| FilterRuleView {
                nodes: &r.srcs,
                ports,
            })
            .collect();
        let egress: Vec<FilterRuleView<'_>> = self
            .egress_filter
            .iter()
            .zip(out_ports.iter())
            .map(|(r, ports)| FilterRuleView {
                nodes: &r.dsts,
                ports,
            })
            .collect();
        let relays: Vec<RelayView<'_>> = self
            .relays
            .iter()
            .map(|r| RelayView {
                address: &r.address,
                tls_server_name: &r.tls_server_name,
                relay_id: &r.relay_id,
                identity_key: &r.identity_key,
                region: &r.region,
            })
            .collect();
        let dns_routes: Vec<DNSRouteView<'_>> = self
            .dns_config
            .routes
            .iter()
            .map(|route| DNSRouteView {
                match_domain: &route.match_domain,
                resolvers: &route.resolvers,
            })
            .collect();

        netmap_version(&NetmapContent {
            psk_epoch: self.psk_epoch,
            node_id: &self.node_id,
            dns_name: &self.dns_name,
            addresses: &self.addresses,
            peers: &entries,
            packet_filter: &rules,
            egress_filter: &egress,
            relays: &relays,
            dns: DNSConfigView {
                nameservers: &self.dns_config.nameservers,
                search_domains: &self.dns_config.search_domains,
                routes: &dns_routes,
                zone: &self.dns_config.zone,
                magic_dns: self.dns_config.magic_dns,
            },
            bedrock_head: BedrockHeadView {
                hash: &self.bedrock_head.hash,
                seq: self.bedrock_head.seq,
                mode: self.bedrock_head.mode as u32,
            },
        })
    }

    /// Re-encode as a complete, non-delta response.
    ///
    /// This is what goes into the encrypted on-disk cache. Storing the
    /// assembled state rather than the last response received is not a choice:
    /// the last response is usually a delta, which is meaningless without the
    /// state it was applied to. Re-encoding into the same message the wire uses
    /// means the cache is read back through the *same* decoder as a live
    /// netmap, rather than a second format that could drift from it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        use prost::Message as _;
        self.to_wire_full().encode_to_vec()
    }

    /// Read back a cached netmap.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the bytes are not a `KarstNetmapResponse`, and
    /// the errors of [`Netmap::apply`] otherwise — including the version check,
    /// which here catches a cache written by a different build.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        use prost::Message as _;
        let resp =
            pb::KarstNetmapResponse::decode(bytes).map_err(|e| Error::Malformed(e.to_string()))?;
        let mut map = Self::new();
        map.apply(resp)?;
        Ok(map)
    }

    fn to_wire_full(&self) -> pb::KarstNetmapResponse {
        pb::KarstNetmapResponse {
            version: self.version,
            psk_epoch: self.psk_epoch,
            node_id: self.node_id.clone(),
            addresses: self.addresses.clone(),
            dns_name: self.dns_name.clone(),
            dns_config: Some(self.dns_config.to_wire()),
            bedrock_head: self.bedrock_head.to_wire(),
            peers: self.peers.values().map(Peer::to_wire).collect(),
            packet_filter: self.packet_filter.clone(),
            egress_filter: self.egress_filter.clone(),
            relays: self.relays.iter().map(Relay::to_wire).collect(),
            // **Deliberately absent.** This is what goes into the on-disk
            // cache, and a minted TURN credential belongs there even less than
            // it belongs in `content_version()` — writing it to disk would
            // have this node try a credential that may already be expired the
            // next time it starts, for no benefit: `crate::run` never treats a
            // cached netmap as a substitute for the first live one, and a
            // credential is worthless until the control client reaches the
            // server anyway.
            turn_servers: Vec::new(),
            delta: false,
            removed_peers: Vec::new(),
            unchanged: false,
        }
    }
}

/// A handle is base64 and so printable, but it arrives as bytes and a corrupt
/// one must not panic a `Debug` implementation.
fn lossy(id: &[u8]) -> String {
    String::from_utf8_lossy(id).into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn wire_peer(id: &str, ip: &str) -> pb::KarstNetmapPeer {
        pb::KarstNetmapPeer {
            home_relay: Vec::new(),
            node_id: id.as_bytes().to_vec(),
            allowed_ips: vec![format!("{ip}/32")],
            dns_name: id.to_owned(),
            endpoint: String::new(),
            kem_public_key: vec![0x11; 1184],
            dh_public_key: vec![0x22; 32],
            psk: vec![0x33; PSK_LEN],
            psk_previous: vec![0x44; PSK_LEN],
            disco_key: vec![0x55; PSK_LEN],
        }
    }

    /// Build a response and set `version` to whatever the content actually
    /// hashes to, which is what a correct server does.
    fn sealed(mut resp: pb::KarstNetmapResponse, held: &Netmap) -> pb::KarstNetmapResponse {
        // The version covers the *complete* netmap, so compute it from the
        // state the node will end up in rather than from the delta itself.
        let mut projected = Netmap::new();
        projected.psk_epoch = resp.psk_epoch;
        projected.node_id = resp.node_id.clone();
        projected.addresses = resp.addresses.clone();
        projected.dns_name = resp.dns_name.clone();
        projected.dns_config = DNSConfig::from_wire(resp.dns_config.clone());
        projected.bedrock_head = BedrockHead::from_wire(resp.bedrock_head.as_ref());
        projected.packet_filter = resp.packet_filter.clone();
        projected.egress_filter = resp.egress_filter.clone();
        projected.relays = resp
            .relays
            .iter()
            .map(Relay::from_wire)
            .collect::<Result<_, _>>()
            .expect("test relay must be valid");
        if resp.delta {
            for p in held.peers.values() {
                projected
                    .peers
                    .insert(p.node_id.clone(), Peer::from_wire(p.to_wire()).unwrap());
            }
            for p in &resp.peers {
                projected
                    .peers
                    .insert(p.node_id.clone(), Peer::from_wire(p.clone()).unwrap());
            }
            for id in &resp.removed_peers {
                projected.peers.remove(id);
            }
        } else {
            for p in &resp.peers {
                projected
                    .peers
                    .insert(p.node_id.clone(), Peer::from_wire(p.clone()).unwrap());
            }
        }
        resp.version = projected.content_version();
        resp
    }

    fn full(peers: Vec<pb::KarstNetmapPeer>) -> pb::KarstNetmapResponse {
        pb::KarstNetmapResponse {
            psk_epoch: 7,
            node_id: b"self".to_vec(),
            addresses: vec!["100.64.0.1".to_owned()],
            dns_name: "self".to_owned(),
            peers,
            ..pb::KarstNetmapResponse::default()
        }
    }

    fn loaded() -> Netmap {
        let mut map = Netmap::new();
        let resp = sealed(full(vec![wire_peer("aaa", "100.64.0.2")]), &map);
        map.apply(resp).expect("a full netmap must apply");
        map
    }

    fn wire_relay(identity_byte: u8) -> pb::KarstRelay {
        let identity_key = vec![identity_byte; RELAY_IDENTITY_KEY_LEN];
        let mut h = Sha256::new();
        h.update(b"karst-relay-id-v1");
        h.update(&identity_key);
        pb::KarstRelay {
            address: "127.0.0.1:443".to_owned(),
            tls_server_name: "relay.test".to_owned(),
            relay_id: h.finalize().to_vec(),
            identity_key,
            region: "test".to_owned(),
        }
    }

    fn wire_turn_server(uri: &str) -> pb::KarstTurnServer {
        pb::KarstTurnServer {
            uri: uri.to_owned(),
            region: "test".to_owned(),
            username: "1700000000".to_owned(),
            password: "test-fixture-turn-password".to_owned(),
            expires_at: 1_700_000_000,
        }
    }

    // ── the three shapes ────────────────────────────────────────────────────

    #[test]
    fn a_full_netmap_replaces_the_peer_set() {
        let mut map = loaded();
        let resp = sealed(full(vec![wire_peer("bbb", "100.64.0.3")]), &map);
        assert_eq!(map.apply(resp), Ok(Outcome::Replaced { peers: 1 }));
        assert!(
            map.peer(b"aaa").is_none(),
            "the absent peer must be dropped"
        );
        assert!(map.peer(b"bbb").is_some());
    }

    /// **A node alone in its network.** An empty *full* netmap is a real state
    /// and must clear the roster. Reading it as "nothing changed" would leave a
    /// deprovisioned peer configured forever.
    #[test]
    fn an_empty_full_netmap_clears_every_peer() {
        let mut map = loaded();
        let resp = sealed(full(vec![]), &map);
        assert_eq!(map.apply(resp), Ok(Outcome::Replaced { peers: 0 }));
        assert_eq!(map.peers().len(), 0);
    }

    /// **The mirror image.** `unchanged` also carries no peers, and must drop
    /// nobody. Conflating the two tears down a working network on every poll.
    #[test]
    fn unchanged_keeps_every_peer() {
        let mut map = loaded();
        let before = map.version;
        let resp = pb::KarstNetmapResponse {
            unchanged: true,
            ..pb::KarstNetmapResponse::default()
        };
        assert_eq!(map.apply(resp), Ok(Outcome::Unchanged));
        assert_eq!(map.peers().len(), 1, "an unchanged netmap drops nobody");
        assert_eq!(map.version, before, "and does not move the version");
    }

    /// An `unchanged` response carries no node-level fields either, so applying
    /// them would blank the node's own address and filter.
    #[test]
    fn unchanged_does_not_blank_the_node_fields() {
        let mut map = loaded();
        map.apply(pb::KarstNetmapResponse {
            unchanged: true,
            ..pb::KarstNetmapResponse::default()
        })
        .expect("apply");
        assert_eq!(map.addresses, vec!["100.64.0.1".to_owned()]);
        assert_eq!(map.node_id, b"self");
        assert_eq!(map.psk_epoch, 7);
    }

    // ── TURN — `spec/aven-v1.md` §7.8 ───────────────────────────────────────

    /// **The one field `unchanged` does not mean "keep".** A minted TURN
    /// credential is fresh on every response, including one that reports
    /// `unchanged` for everything else, so it must be applied before the
    /// early return — see `Netmap::apply`'s own doc comment on why.
    #[test]
    fn turn_servers_are_replaced_even_when_the_response_is_unchanged() {
        let mut map = loaded();
        map.apply(sealed(
            pb::KarstNetmapResponse {
                turn_servers: vec![wire_turn_server("turn:turn.example.com:3478")],
                ..full(vec![])
            },
            &map,
        ))
        .expect("first apply");
        assert_eq!(map.turn_servers.len(), 1);

        let resp = pb::KarstNetmapResponse {
            unchanged: true,
            turn_servers: vec![wire_turn_server("turn:turn2.example.com:3478")],
            ..pb::KarstNetmapResponse::default()
        };
        assert_eq!(map.apply(resp), Ok(Outcome::Unchanged));
        assert_eq!(
            map.turn_servers.len(),
            1,
            "the field is replaced, not appended"
        );
        assert_eq!(
            map.turn_servers.first().map(|s| s.uri.as_str()),
            Some("turn:turn2.example.com:3478")
        );
        // Nothing else moved — the whole point of `unchanged`.
        assert_eq!(map.peers().len(), 0);
    }

    #[test]
    fn turn_server_from_wire_rejects_a_non_turn_uri() {
        let mut map = loaded();
        let resp = pb::KarstNetmapResponse {
            turn_servers: vec![wire_turn_server("https://turn.example.com")],
            ..full(vec![])
        };
        assert!(matches!(map.apply(resp), Err(Error::Turn(_))));
    }

    #[test]
    fn turn_server_from_wire_rejects_an_empty_credential() {
        let mut map = loaded();
        let mut server = wire_turn_server("turn:turn.example.com:3478");
        server.password.clear();
        let resp = pb::KarstNetmapResponse {
            turn_servers: vec![server],
            ..full(vec![])
        };
        assert!(matches!(map.apply(resp), Err(Error::Turn(_))));
    }

    #[test]
    fn turn_credential_does_not_print() {
        let cred = TurnCredential::for_tests("super-secret-password");
        assert_eq!(format!("{cred:?}"), "turn_password(redacted)");
    }

    #[test]
    fn a_delta_adds_without_dropping_what_is_held() {
        let mut map = loaded();
        let resp = sealed(
            pb::KarstNetmapResponse {
                delta: true,
                peers: vec![wire_peer("bbb", "100.64.0.3")],
                ..full(vec![])
            },
            &map,
        );
        assert_eq!(
            map.apply(resp),
            Ok(Outcome::Delta {
                changed: 1,
                removed: 0
            })
        );
        assert_eq!(map.peers().len(), 2, "the held peer must survive a delta");
    }

    #[test]
    fn a_delta_removes_only_what_it_names() {
        let mut map = loaded();
        let mut resp = pb::KarstNetmapResponse {
            delta: true,
            removed_peers: vec![b"aaa".to_vec()],
            ..full(vec![])
        };
        resp.peers = vec![wire_peer("bbb", "100.64.0.3")];
        let resp = sealed(resp, &map);
        assert_eq!(
            map.apply(resp),
            Ok(Outcome::Delta {
                changed: 1,
                removed: 1
            })
        );
        assert!(map.peer(b"aaa").is_none());
        assert!(map.peer(b"bbb").is_some());
    }

    /// `removed_peers` is meaningful only under `delta`. Acting on it in a full
    /// netmap would let a bug in one field corrupt the other path — and a full
    /// netmap already says everything about who is gone by omission.
    #[test]
    fn removed_peers_is_ignored_when_the_netmap_is_not_a_delta() {
        let mut map = loaded();
        let mut resp = full(vec![wire_peer("aaa", "100.64.0.2")]);
        resp.removed_peers = vec![b"aaa".to_vec()];
        let resp = sealed(resp, &map);
        map.apply(resp).expect("apply");
        assert!(
            map.peer(b"aaa").is_some(),
            "a full netmap listing a peer must keep it, whatever removed_peers says"
        );
    }

    /// A changed entry replaces the one held rather than merging into it: a
    /// peer whose key rotated must not keep the old key alongside the new.
    #[test]
    fn a_delta_entry_replaces_rather_than_merges() {
        let mut map = loaded();
        let mut updated = wire_peer("aaa", "100.64.0.9");
        updated.kem_public_key = vec![0xAB; 1184];
        let resp = sealed(
            pb::KarstNetmapResponse {
                delta: true,
                peers: vec![updated],
                ..full(vec![])
            },
            &map,
        );
        map.apply(resp).expect("apply");
        let peer = map.peer(b"aaa").expect("still held");
        assert_eq!(peer.kem_public_key, vec![0xAB; 1184]);
        assert_eq!(peer.allowed_ips, vec!["100.64.0.9/32".to_owned()]);
    }

    // ── the version check ───────────────────────────────────────────────────

    /// **The silent, permanent failure this check exists to stop.** If the
    /// node's assembled state does not hash to the version it will send back,
    /// the server answers `unchanged` forever and a peer added later is never
    /// delivered — with no error and no counter to notice.
    #[test]
    fn a_version_that_does_not_describe_the_assembled_state_is_refused() {
        let mut map = Netmap::new();
        let mut resp = full(vec![wire_peer("aaa", "100.64.0.2")]);
        resp.version = 0xDEAD_BEEF;
        match map.apply(resp) {
            Err(Error::VersionMismatch { server, .. }) => assert_eq!(server, 0xDEAD_BEEF),
            other => panic!("expected a version mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_reset_asks_for_everything_again() {
        let mut map = loaded();
        map.reset();
        assert_eq!(map.version, 0, "zero is what requests a full netmap");
        assert_eq!(map.peers().len(), 0);
        assert!(map.holds().is_empty());
    }

    /// The version must not depend on the order peers arrived in, or two nodes
    /// holding the same network would disagree about whether it changed.
    #[test]
    fn the_version_is_independent_of_arrival_order() {
        let a = wire_peer("aaa", "100.64.0.2");
        let b = wire_peer("bbb", "100.64.0.3");

        let mut forward = Netmap::new();
        forward
            .apply(sealed(full(vec![a.clone(), b.clone()]), &forward))
            .expect("apply");
        let mut reverse = Netmap::new();
        reverse
            .apply(sealed(full(vec![b, a]), &reverse))
            .expect("apply");

        assert_eq!(forward.version, reverse.version);
    }

    /// A policy edit changes nothing else about the netmap, so if the filter
    /// were not hashed the version would be identical, every node would be told
    /// "unchanged", and the new rules would never arrive.
    #[test]
    fn changing_only_the_filter_changes_the_version() {
        let mut plain = Netmap::new();
        plain
            .apply(sealed(full(vec![wire_peer("aaa", "100.64.0.2")]), &plain))
            .expect("apply");

        let mut filtered = Netmap::new();
        let mut resp = full(vec![wire_peer("aaa", "100.64.0.2")]);
        resp.packet_filter = vec![pb::KarstFilterRule {
            srcs: vec!["aaa".to_owned()],
            ports: vec![pb::KarstPortRange {
                first: 22,
                last: 22,
            }],
        }];
        filtered.apply(sealed(resp, &filtered)).expect("apply");

        assert_ne!(plain.version, filtered.version);
    }

    /// Relay pins are mutable control-plane state. If they were omitted from
    /// the version, a node would keep attempting a retired or compromised
    /// relay while every poll said its netmap was current.
    #[test]
    fn changing_only_the_relay_registry_changes_the_version() {
        let mut without = Netmap::new();
        without
            .apply(sealed(full(vec![wire_peer("aaa", "100.64.0.2")]), &without))
            .expect("apply");

        let mut with = Netmap::new();
        let mut resp = full(vec![wire_peer("aaa", "100.64.0.2")]);
        resp.relays = vec![wire_relay(0x91)];
        with.apply(sealed(resp, &with)).expect("apply");

        assert_eq!(with.relays.len(), 1);
        assert_ne!(without.version, with.version);

        let before = with.version;
        let mut renamed = full(vec![wire_peer("aaa", "100.64.0.2")]);
        renamed.relays = vec![wire_relay(0x91)];
        let relay = renamed.relays.first_mut().expect("one relay");
        relay.tls_server_name = "replacement-relay.test".to_owned();
        with.apply(sealed(renamed, &with)).expect("apply");
        assert_ne!(with.version, before, "TLS name must move the version");
    }

    #[test]
    fn changing_only_dns_config_changes_the_version_and_replaces_it() {
        let mut without = Netmap::new();
        without
            .apply(sealed(full(vec![wire_peer("aaa", "100.64.0.2")]), &without))
            .expect("apply");

        let mut with = Netmap::new();
        let mut response = full(vec![wire_peer("aaa", "100.64.0.2")]);
        response.dns_config = Some(pb::KarstDnsConfig {
            zone: "aquifer.karst".to_owned(),
            magic_dns: true,
            nameservers: vec!["1.1.1.1:53".to_owned()],
            search_domains: vec![],
            routes: vec![],
        });
        with.apply(sealed(response, &with)).expect("apply");
        assert_ne!(without.version, with.version);
        assert_eq!(with.dns_config.nameservers, vec!["1.1.1.1:53"]);
    }

    // ── digests ─────────────────────────────────────────────────────────────

    #[test]
    fn holds_reports_one_digest_per_peer() {
        let map = loaded();
        let holds = map.holds();
        assert_eq!(holds.len(), 1);
        assert_eq!(holds.first().expect("one").node_id, b"aaa");
        assert_ne!(holds.first().expect("one").digest, 0);
    }

    /// A digest must move when the entry moves, or a change is never delivered.
    #[test]
    fn a_changed_entry_changes_its_digest() {
        let base = Peer::from_wire(wire_peer("aaa", "100.64.0.2")).expect("valid");
        let moved = Peer::from_wire(wire_peer("aaa", "100.64.0.9")).expect("valid");
        assert_ne!(base.digest(7), moved.digest(7));
    }

    /// And it must move when the epoch does, because a PSK is determined by
    /// (pair, epoch, master) and the bytes themselves are deliberately not
    /// hashed.
    #[test]
    fn a_new_epoch_changes_every_digest() {
        let peer = Peer::from_wire(wire_peer("aaa", "100.64.0.2")).expect("valid");
        assert_ne!(peer.digest(7), peer.digest(8));
    }

    /// The digest must not cover the PSK bytes: it is computed by the node and
    /// **sent to the server in clear**.
    #[test]
    fn the_digest_does_not_depend_on_the_psk_bytes() {
        let mut other = wire_peer("aaa", "100.64.0.2");
        other.psk = vec![0x99; PSK_LEN];
        other.psk_previous = vec![0x98; PSK_LEN];
        let a = Peer::from_wire(wire_peer("aaa", "100.64.0.2")).expect("valid");
        let b = Peer::from_wire(other).expect("valid");
        assert_eq!(a.digest(7), b.digest(7));
    }

    // ── PSKs ────────────────────────────────────────────────────────────────

    /// §7.3: an absent PSK is the lattice-only fallback, and must be
    /// distinguishable from a PSK that happens to be zero.
    #[test]
    fn an_absent_psk_is_none_rather_than_zeros() {
        let mut wire = wire_peer("aaa", "100.64.0.2");
        wire.psk = Vec::new();
        wire.psk_previous = Vec::new();
        let peer = Peer::from_wire(wire).expect("valid");
        assert!(peer.psk.is_none());
        assert!(peer.psk_previous.is_none());
    }

    #[test]
    fn a_psk_of_the_wrong_length_is_refused() {
        let mut wire = wire_peer("aaa", "100.64.0.2");
        wire.psk = vec![0x33; 16];
        match Peer::from_wire(wire) {
            Err(Error::PskLength { len, .. }) => assert_eq!(len, 16),
            other => panic!("expected a length error, got {other:?}"),
        }
    }

    #[test]
    fn a_disco_key_of_the_wrong_length_is_refused() {
        let mut wire = wire_peer("aaa", "100.64.0.2");
        wire.disco_key = vec![0x55; 16];
        match Peer::from_wire(wire) {
            Err(Error::DiscoKeyLength { len, .. }) => assert_eq!(len, 16),
            other => panic!("expected a length error, got {other:?}"),
        }
    }

    #[test]
    fn a_relay_with_an_unpinned_identity_is_refused() {
        let relay = pb::KarstRelay {
            address: "127.0.0.1:443".to_owned(),
            tls_server_name: "relay.test".to_owned(),
            relay_id: vec![0x11; RELAY_ID_LEN],
            identity_key: vec![0x22; 32],
            region: "test".to_owned(),
        };
        assert!(matches!(Relay::from_wire(&relay), Err(Error::Relay(_))));
    }

    #[test]
    fn a_relay_without_a_tls_server_name_is_refused() {
        let mut relay = wire_relay(0x91);
        relay.tls_server_name.clear();
        assert!(matches!(Relay::from_wire(&relay), Err(Error::Relay(_))));
    }

    #[test]
    fn a_relay_id_must_be_derived_from_its_pinned_key() {
        let relay = pb::KarstRelay {
            address: "127.0.0.1:443".to_owned(),
            tls_server_name: "relay.test".to_owned(),
            relay_id: vec![0x11; RELAY_ID_LEN],
            identity_key: vec![0x22; RELAY_IDENTITY_KEY_LEN],
            region: "test".to_owned(),
        };
        assert!(
            matches!(Relay::from_wire(&relay), Err(Error::Relay(message)) if message.contains("does not match"))
        );
    }

    /// THREAT-MODEL R5. A `Debug` that printed a PSK would put it in every log
    /// line and bug report that formatted a netmap.
    #[test]
    fn debug_output_never_contains_secret_bytes() {
        let map = loaded();
        let peer = map.peer(b"aaa").expect("held");
        let rendered = format!("{map:?} {peer:?}");
        assert!(
            !rendered.contains("33, 33") && !rendered.contains("3333"),
            "PSK bytes leaked into Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("55, 55") && !rendered.contains("5555"),
            "disco key bytes leaked into Debug output: {rendered}"
        );
        assert!(rendered.contains("psk(redacted)"));
        assert!(rendered.contains("disco_key(redacted)"));
        assert!(rendered.contains("aaa"), "but it must still be useful");
    }

    // ── the cache round trip ────────────────────────────────────────────────

    /// The cache stores the *assembled* state, because the last response is
    /// usually a delta and is meaningless without what it was applied to.
    #[test]
    fn a_netmap_round_trips_through_the_cache_encoding() {
        let mut map = loaded();
        let resp = sealed(
            pb::KarstNetmapResponse {
                delta: true,
                peers: vec![wire_peer("bbb", "100.64.0.3")],
                ..full(vec![])
            },
            &map,
        );
        map.apply(resp).expect("apply");

        let restored = Netmap::decode(&map.encode()).expect("the cache must read back");
        assert_eq!(restored.version, map.version);
        assert_eq!(restored.psk_epoch, map.psk_epoch);
        assert_eq!(restored.addresses, map.addresses);
        assert_eq!(restored.peers().len(), 2);
        assert_eq!(restored.holds().len(), map.holds().len());
        for (a, b) in restored.peers().zip(map.peers()) {
            assert_eq!(a.node_id, b.node_id);
            assert_eq!(a.kem_public_key, b.kem_public_key);
            assert_eq!(
                a.psk.as_ref().map(Psk::as_bytes),
                b.psk.as_ref().map(Psk::as_bytes),
                "the PSK must survive the cache, or every peer becomes lattice-only"
            );
        }
    }

    /// A cache written by a build with a different version function must be
    /// rejected rather than adopted — the same check that guards the wire.
    #[test]
    fn a_cache_whose_version_does_not_match_its_contents_is_refused() {
        use prost::Message as _;
        let map = loaded();
        let mut wire = pb::KarstNetmapResponse::decode(map.encode().as_slice()).expect("decode");
        wire.version ^= 1;
        assert!(matches!(
            Netmap::decode(&wire.encode_to_vec()),
            Err(Error::VersionMismatch { .. })
        ));
    }

    #[test]
    fn garbage_is_not_a_cache() {
        assert!(matches!(
            Netmap::decode(&[0xFF; 32]),
            Err(Error::Malformed(_))
        ));
    }
}
