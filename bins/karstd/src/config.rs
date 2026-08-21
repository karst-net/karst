// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The peer roster, from either of its two sources.
//!
//! Phase 2 had no control server, so the roster was a hand-written TOML file.
//! Phase 3 adds the other source: [`Config::from_netmap`] builds the *same*
//! types out of what the coordination server sent. That was the promise this
//! module made in Phase 2 and it held — nothing downstream can tell where a
//! peer came from, and the datapath did not change to accommodate the second
//! source.
//!
//! The two are mutually exclusive. A file naming both `[[peer]]` and
//! `[control]` is refused rather than merged: two sources defining the peer set
//! makes "which one wins" an interesting question, and it has no good answer.
//!
//! # Secrets
//!
//! This file names two kinds of secret: the node's own private key and the
//! per-pair PSKs. Both are covered by THREAT-MODEL R5, so:
//!
//! - Files carrying secrets are refused if they are readable beyond their
//!   owner. A permissive mode is not a warning to be scrolled past — it is the
//!   difference between a secret and a published file.
//! - Every type here has a hand-written `Debug` that redacts key material. A
//!   derived `Debug` would print private keys into any log line or bug report
//!   that formatted a config.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_noise::handshake::{PeerPublic, StaticKeys};
use x25519_dalek::PublicKey as DhPublic;

use crate::filter::PacketFilter;
use crate::netmap::Netmap;
use crate::routing::{AllowedIps, InterfaceAddress, Prefix};

/// Bytes of seed material a node's private key file carries: 64 for ML-KEM-768
/// plus 32 for X25519.
pub const PRIVATE_KEY_LEN: usize = 96;

/// Where `karstd` obtains and delivers bare IP packets.
///
/// TUN remains the default so existing services and host routing are unchanged.
/// Userspace mode is for an explicitly configured unprivileged sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// A Linux TUN device and host routes; requires `CAP_NET_ADMIN`.
    Tun,
    /// The pure-Rust IP stack; no host network configuration is attempted.
    Userspace,
}

impl Default for NetworkMode {
    fn default() -> Self {
        Self::Tun
    }
}

/// Anything that stopped a configuration from loading.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Read {
        /// Which file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The file parsed as TOML but not as a Karst configuration.
    Parse {
        /// Which file.
        path: PathBuf,
        /// The parser's message.
        message: String,
    },
    /// A file holding secrets is readable by more than its owner.
    Permissions {
        /// Which file.
        path: PathBuf,
        /// The mode found, as octal.
        mode: u32,
    },
    /// A hex field was not valid hex, or was the wrong length.
    Hex {
        /// Which field.
        field: String,
        /// What was wrong.
        reason: String,
    },
    /// A key was syntactically fine but not a valid encoding.
    InvalidKey {
        /// Which peer.
        peer: String,
        /// Which field.
        field: &'static str,
    },
    /// An `allowed_ips` entry was malformed.
    Prefix {
        /// Which peer.
        peer: String,
        /// The parse error.
        source: crate::routing::PrefixError,
    },
    /// Two peers claim the same address range.
    Conflict(crate::routing::Conflict),
    /// Two peers share a name, so log lines and `karst status` could not tell
    /// them apart.
    DuplicatePeerName(String),
    /// The roster is empty or otherwise unusable.
    Unusable(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse { path, message } => write!(f, "parsing {}: {message}", path.display()),
            Self::Permissions { path, mode } => write!(
                f,
                "{} is mode {mode:04o}; it holds key material and must not be \
                 readable by group or other (chmod 600)",
                path.display()
            ),
            Self::Hex { field, reason } => write!(f, "field {field}: {reason}"),
            Self::InvalidKey { peer, field } => {
                write!(f, "peer {peer:?}: {field} is not a valid key encoding")
            }
            Self::Prefix { peer, source } => write!(f, "peer {peer:?}: {source}"),
            Self::Conflict(c) => write!(f, "{c}"),
            Self::DuplicatePeerName(n) => write!(f, "two peers are both named {n:?}"),
            Self::Unusable(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ── the on-disk shape ───────────────────────────────────────────────────────

/// The whole file.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// This node.
    pub node: NodeSection,
    /// The roster. `#[serde(default)]` so a node with no peers still loads —
    /// that is a valid, if lonely, state and a clearer error comes later.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerSection>,
    /// Where to fetch a netmap from, if this node is server-managed.
    ///
    /// Mutually exclusive with `[[peer]]`. Two sources both defining the peer
    /// set is two sources of truth, and the interesting question would become
    /// which one wins — a question with no good answer, so it is refused at
    /// load time instead.
    pub control: Option<ControlSection>,
}

/// The `[node]` table.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// UDP address to bind.
    pub listen: SocketAddr,
    /// Whether this node should ask its default gateway for an explicit port
    /// mapping on the datapath port.
    #[serde(default = "default_port_mapping")]
    pub port_mapping: bool,
    /// TUN interface name.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// Packet attachment mode. Omitted keeps the privileged TUN default.
    #[serde(default)]
    pub network_mode: NetworkMode,
    /// Loopback SOCKS5 endpoint for userspace mode. Workloads use this to
    /// reach overlay TCP addresses without a TUN device.
    pub userspace_socks5_listen: Option<SocketAddr>,
    /// Overlay TCP ports this node answers on, and where each one goes.
    ///
    /// The inbound half of userspace mode's attachment; see [`crate::publish`].
    /// Empty is the default and means nothing on this node is reachable from
    /// the mesh.
    #[serde(default)]
    pub userspace_publish: Vec<PublishSection>,
    /// Addresses to assign to the interface.
    ///
    /// Required for a roster; ignored, and refused if present, for a
    /// server-managed node, whose addresses are assigned by the server.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// File holding the 96-byte hex private key seed.
    pub private_key_file: PathBuf,
    /// PSK epoch these PSKs belong to (§2.6).
    #[serde(default = "default_epoch")]
    pub psk_epoch: u32,
    /// How this node reaches IPv4 if it has no IPv4 of its own.
    ///
    /// `"auto"` — the default — discovers a NAT64 prefix by RFC 7050, and only
    /// on a node that both listens on IPv6 and holds no IPv4 address. `"off"`
    /// never synthesises. A prefix such as `"64:ff9b::/96"` uses that one.
    /// See [`crate::nat64`] for what each gate is protecting against.
    #[serde(default)]
    pub nat64: crate::nat64::Mode,
}

/// The `[control]` table: how to reach the coordination server.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSection {
    /// Server URL, e.g. `https://karst.example.com:443`.
    pub server: String,
    /// The server's static ML-KEM-768 key, hex. Pinned at enrolment.
    pub server_kem_pin: String,
    /// The server's ML-DSA-65 verification key, hex.
    ///
    /// **Both pins are required.** The KEM key authenticates the server
    /// implicitly; the verification key is what makes the per-connection
    /// ephemeral trustworthy, and so what makes forward secrecy real. A node
    /// given only the first has a channel that authenticates and does not
    /// protect recorded traffic against later compromise of the server's
    /// static key — see `spec/karst-control-v1.md` §9.
    pub server_verify_pin: String,
    /// File holding the node's 32-byte ML-DSA-65 identity seed, hex.
    ///
    /// Distinct from `private_key_file`: that one holds the PHREATIC data-plane
    /// keys, and phreatic-v1.md §4 is explicit that the control identity is
    /// **not** used by PHREATIC. One file per role, so a leak of one does not
    /// hand over the other.
    pub identity_key_file: PathBuf,
    /// Pre-shared auth key, for the first registration.
    pub setup_key: Option<String>,
    /// Where to keep the encrypted netmap cache.
    ///
    /// Absent means no cache: the node fetches a full netmap on every start and
    /// cannot come up at all while the server is unreachable.
    pub cache_file: Option<PathBuf>,
    /// Extra PEM certificate authorities to trust for relay TLS, in addition to
    /// the operating system's.
    ///
    /// **`ponor-v1.md` §4.2 names three realistic self-hosted deployments, and
    /// the system trust store covers only one of them.** An internal CA can be
    /// installed as a system root; a *self-signed* relay certificate cannot be,
    /// not without making that one host a trust anchor for every TLS connection
    /// the machine makes. This narrows that to the relay connection alone.
    ///
    /// It does not weaken relay authentication and cannot: §4.2 makes the
    /// certificate insufficient on its own, and the ML-DSA-65 identity pinned
    /// by the netmap is what actually names the relay. What this changes is
    /// only which certificates the *hop* will accept.
    ///
    /// Absent means the system roots alone, which is the right default for a
    /// relay with a public certificate.
    pub relay_ca_file: Option<PathBuf>,
}

fn default_interface() -> String {
    karst_tun::DEFAULT_NAME.to_owned()
}

/// A `[[node.userspace_publish]]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSection {
    /// The overlay TCP port peers connect to.
    pub port: u16,
    /// Where connections to it are forwarded, on this host.
    pub to: SocketAddr,
}

fn validate_userspace(
    mode: NetworkMode,
    socks5_listen: Option<SocketAddr>,
    publish: &[PublishSection],
) -> Result<(), ConfigError> {
    if mode == NetworkMode::Tun {
        if socks5_listen.is_some() {
            return Err(ConfigError::Unusable(
                "node.userspace_socks5_listen requires network_mode = \"userspace\"".to_owned(),
            ));
        }
        if !publish.is_empty() {
            // TUN mode publishes nothing because it does not have to: the node
            // has a real interface, and a service bound to its overlay address
            // is reachable by the host's own listener.
            return Err(ConfigError::Unusable(
                "node.userspace_publish requires network_mode = \"userspace\"; in TUN mode a \
                 service reachable from the mesh is one bound to the interface address"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    // **Either attachment will do, but not neither.** A node with a userspace
    // stack and no way in or out of it carries packets nothing can read: it
    // establishes with its peers, reports healthy, and is useless. Requiring
    // the SOCKS listener specifically would be worse than requiring nothing —
    // an inbound-only sidecar would have to open an outbound surface it does
    // not want in order to start.
    if socks5_listen.is_none() && publish.is_empty() {
        return Err(ConfigError::Unusable(
            "network_mode = \"userspace\" requires node.userspace_socks5_listen or at least \
             one [[node.userspace_publish]] entry; without one the stack has no attachment"
                .to_owned(),
        ));
    }
    let mut ports = BTreeSet::new();
    for entry in publish {
        if entry.port == 0 {
            return Err(ConfigError::Unusable(
                "node.userspace_publish has an entry on port 0, which nothing can connect to"
                    .to_owned(),
            ));
        }
        if !ports.insert(entry.port) {
            // Two entries for one port is two answers to "where does this go",
            // and resolving it by file order would send a peer's traffic
            // somewhere nobody chose.
            return Err(ConfigError::Unusable(format!(
                "node.userspace_publish names overlay port {} twice",
                entry.port
            )));
        }
    }
    Ok(())
}
const fn default_port_mapping() -> bool {
    true
}
const fn default_epoch() -> u32 {
    1
}

/// A `[[peer]]` table.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSection {
    /// Name, for logs and `karst status`.
    pub name: String,
    /// Peer's ML-KEM-768 encapsulation key, hex.
    pub kem_public_key: String,
    /// Peer's X25519 static public key, hex.
    pub dh_public_key: String,
    /// Per-pair PSK, hex. Absent selects the lattice-only fallback of §7.3,
    /// which is reported at startup rather than assumed.
    pub psk: Option<String>,
    /// Where to reach the peer. Absent means wait to be contacted.
    pub endpoint: Option<SocketAddr>,
    /// Address ranges this peer owns.
    pub allowed_ips: Vec<String>,
}

// A derived `Debug` would print the PSK. See the module note.
impl fmt::Debug for PeerSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSection")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("psk", &self.psk.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

// ── the validated shape ─────────────────────────────────────────────────────

/// A peer, ready to use.
pub struct Peer {
    /// Name, for logs.
    pub name: String,
    /// Server-assigned node handle, used to bind AVEN tags to this peer.
    pub node_id: Vec<u8>,
    /// Cryptographic material.
    ///
    /// Shared rather than owned so a `Session` can hold it without borrowing
    /// the whole `Config` — which is what pinned the peer set to one owner for
    /// the life of the process and made a netmap change a restart.
    pub public: Arc<PeerPublic>,
    /// Where to reach it, if known.
    pub endpoint: Option<SocketAddr>,
    /// Ranges it owns.
    pub allowed_ips: Vec<Prefix>,
    /// Whether the PSK is the all-zero fallback (§7.3).
    pub psk_is_fallback: bool,
    /// AVEN key for this pair. Static TOML peers have none and stay direct-only.
    pub disco_key: Option<[u8; 32]>,
    /// The relay this peer published as its home — `ponor-v1.md` §9.1.
    ///
    /// `None` for a static TOML roster, which has no coordination server to
    /// publish through, and for a peer that has not chosen one. Only a
    /// registry id of the right width survives: a value of any other length
    /// names no relay in `relays` and could only be dialled by guessing.
    pub home_relay: Option<[u8; karst_relay_proto::consts::ID_LEN]>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("psk_is_fallback", &self.psk_is_fallback)
            .finish_non_exhaustive()
    }
}

/// A loaded, validated configuration.
pub struct Config {
    /// This node's long-term keys.
    ///
    /// One copy, shared: cloning them per peer would put the same private key
    /// in N places to be zeroized, for no benefit.
    pub keys: Arc<StaticKeys>,
    /// Where to bind.
    pub listen: SocketAddr,
    /// Whether explicit NAT port mapping is enabled for this node.
    pub port_mapping: bool,
    /// TUN interface name.
    pub interface: String,
    /// Packet attachment mode.
    pub network_mode: NetworkMode,
    /// Optional userspace SOCKS5 endpoint.
    pub userspace_socks5_listen: Option<SocketAddr>,
    /// Overlay ports this node publishes to the mesh. See [`crate::publish`].
    pub userspace_publish: Vec<PublishSection>,
    /// The NAT64 prefix this node reaches IPv4 through, if it is on such a
    /// network. Resolved once at startup by [`crate::nat64::resolve`] — the
    /// mode an operator writes lives in [`NodeSection::nat64`], and by the time
    /// a datapath exists the question has been settled.
    pub nat64: Option<karst_transport::Nat64Prefix>,
    /// Interface addresses — host addresses, not networks. See
    /// [`InterfaceAddress`].
    pub addresses: Vec<InterfaceAddress>,
    /// PSK epoch.
    pub psk_epoch: u32,
    /// This node's server-assigned handle. Empty for a static TOML roster.
    pub node_id: Vec<u8>,
    /// Authenticated relay choices from the netmap.
    pub relays: Vec<crate::netmap::Relay>,
    /// Extra trust anchors for relay TLS, from `[control] relay_ca_file`.
    ///
    /// Local configuration rather than netmap content, deliberately: which
    /// certificates this host will accept is a property of this host, and a
    /// server that could add trust anchors to its nodes would be a server that
    /// could redirect the hop. The relay's *identity* comes from the netmap and
    /// is post-quantum; this is only the TLS layer beneath it.
    pub relay_ca_file: Option<PathBuf>,
    /// The roster.
    pub peers: Vec<Peer>,
    /// Cryptokey routing table over the roster.
    pub routes: AllowedIps,
    /// Peers the netmap carried that this node could not use.
    ///
    /// Kept rather than discarded so `karst status` can show them: a peer that
    /// is simply absent looks like a server that has not been told about it,
    /// which is a completely different problem.
    pub skipped: Vec<SkippedPeer>,
    /// The compiled ACLs.
    ///
    /// A TOML roster has no notion of a policy, so this is
    /// [`PacketFilter::unrestricted`] on that path — *not* an empty rule set,
    /// which would be default deny and would break a working roster on
    /// upgrade. A netmap-sourced configuration compiles the real thing.
    pub filter: PacketFilter,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("port_mapping", &self.port_mapping)
            .field("interface", &self.interface)
            .field("network_mode", &self.network_mode)
            .field("userspace_socks5_listen", &self.userspace_socks5_listen)
            .field("userspace_publish", &self.userspace_publish)
            .field("nat64", &self.nat64)
            .field("addresses", &self.addresses)
            .field("psk_epoch", &self.psk_epoch)
            .field("skipped", &self.skipped)
            .field("filter", &self.filter)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Load and validate a configuration.
    ///
    /// # Errors
    /// [`ConfigError`] for anything that would leave the daemon in a state it
    /// could not route from.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let file: File = toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path.to_owned(),
            message: e.to_string(),
        })?;
        // The roster carries PSKs, so the config is as sensitive as the key.
        let has_psk = file.peers.iter().any(|p| p.psk.is_some());
        if has_psk {
            check_permissions(path)?;
        }
        Self::from_file(file, path)
    }

    fn from_file(file: File, config_path: &Path) -> Result<Self, ConfigError> {
        if file.control.is_some() {
            return Err(ConfigError::Unusable(
                "this configuration names a [control] server, so its peers come from a \
                 netmap; load it with Config::from_netmap"
                    .to_owned(),
            ));
        }
        let key_path = resolve(&file.node.private_key_file, config_path);
        check_permissions(&key_path)?;
        let seed = std::fs::read_to_string(&key_path).map_err(|source| ConfigError::Read {
            path: key_path.clone(),
            source,
        })?;
        let seed = decode_hex(seed.trim(), PRIVATE_KEY_LEN, "private_key_file")?;
        let (kem_seed, dh_seed) = split_seed(&seed)?;
        let keys = Arc::new(StaticKeys::from_seed(&kem_seed, &dh_seed));

        let addresses = file
            .node
            .addresses
            .iter()
            .map(|s| {
                s.parse::<InterfaceAddress>()
                    .map_err(|source| ConfigError::Prefix {
                        peer: "node".to_owned(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if addresses.is_empty() {
            return Err(ConfigError::Unusable(
                "node.addresses is empty; the interface would have no address".to_owned(),
            ));
        }

        let mut names = BTreeSet::new();
        let mut peers = Vec::with_capacity(file.peers.len());
        let mut pairs = Vec::new();
        for (index, section) in file.peers.into_iter().enumerate() {
            if !names.insert(section.name.clone()) {
                return Err(ConfigError::DuplicatePeerName(section.name));
            }
            let peer = Peer::from_section(section, index, &mut pairs)?;
            peers.push(peer);
        }

        let routes = AllowedIps::build(pairs).map_err(ConfigError::Conflict)?;
        validate_userspace(
            file.node.network_mode,
            file.node.userspace_socks5_listen,
            &file.node.userspace_publish,
        )?;
        Ok(Self {
            keys,
            listen: file.node.listen,
            port_mapping: file.node.port_mapping,
            interface: file.node.interface,
            network_mode: file.node.network_mode,
            userspace_socks5_listen: file.node.userspace_socks5_listen,
            userspace_publish: file.node.userspace_publish,
            // Left unresolved here on purpose: settling it means a DNS query,
            // and `Config::from_file` is called by tests and by `karst
            // showconf`, neither of which should touch the network. The daemon
            // resolves it in `control::load_config`, which is the one path a
            // datapath is ever built from.
            nat64: None,
            addresses,
            psk_epoch: file.node.psk_epoch,
            node_id: Vec::new(),
            relays: Vec::new(),
            relay_ca_file: None,
            peers,
            routes,
            skipped: Vec::new(),
            filter: PacketFilter::unrestricted(),
        })
    }

    /// Index of the peer named `name`.
    #[must_use]
    pub fn peer_index(&self, name: &str) -> Option<usize> {
        self.peers.iter().position(|p| p.name == name)
    }

    /// Assemble a datapath configuration from a netmap.
    ///
    /// The other half of [`Config::load`]: same output type, different source.
    /// Nothing below this function can tell where a peer came from, which is
    /// what the roster's module note promised in Phase 2.
    ///
    /// `local` supplies what the server does not and should not know — where to
    /// bind, what to call the interface, and this node's private keys.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a netmap that would leave the daemon unable to
    /// route: no address of its own, a malformed key, or two peers claiming one
    /// range.
    pub fn from_netmap(local: LocalSettings, netmap: &Netmap) -> Result<Self, ConfigError> {
        validate_userspace(
            local.network_mode,
            local.userspace_socks5_listen,
            &local.userspace_publish,
        )?;
        // The node's own addresses carry the *on-link* prefix, so peers are
        // reachable over the interface. A bare address parses as a /32 here,
        // which brings the interface up with nothing on-link — the server is
        // required to send the prefix for exactly this reason.
        let mut addresses = Vec::with_capacity(netmap.addresses.len());
        for s in &netmap.addresses {
            addresses.push(s.parse::<InterfaceAddress>().map_err(|source| {
                ConfigError::Prefix {
                    peer: "node".to_owned(),
                    source,
                }
            })?);
        }
        if addresses.is_empty() {
            return Err(ConfigError::Unusable(
                "the netmap assigned this node no address, so the interface would \
                 have none and every packet it originated would be unanswerable"
                    .to_owned(),
            ));
        }

        // **One unusable peer must not cost the whole netmap.** A peer entry
        // that cannot be parsed is skipped, not fatal — and the difference
        // matters more than it looks. The server validates a registered node's
        // data-plane keys by *length*, so a node that registers 1184 bytes of
        // anything ends up in every other node's netmap; refusing the netmap
        // over it would let one bad registration take down every node in the
        // account. Dropping the entry costs reachability to that one peer,
        // which is what it costs anyway — nobody can handshake with a key that
        // does not parse.
        //
        // A conflict over address ranges is still fatal, because it is a
        // statement about the *network* rather than about one peer, and
        // resolving it by arrival order would send traffic somewhere nobody
        // chose.
        let mut peers = Vec::with_capacity(netmap.peers().len());
        let mut handles = Vec::with_capacity(netmap.peers().len());
        let mut skipped = Vec::new();
        let mut pairs = Vec::new();
        for entry in netmap.peers() {
            let index = peers.len();
            match Peer::from_netmap(entry, index, &mut pairs) {
                Ok(peer) => {
                    peers.push(peer);
                    handles.push(entry.node_id.clone());
                }
                Err(reason) => skipped.push(SkippedPeer {
                    handle: String::from_utf8_lossy(&entry.node_id).into_owned(),
                    dns_name: entry.dns_name.clone(),
                    reason: reason.to_string(),
                }),
            }
        }

        let routes = AllowedIps::build(pairs).map_err(ConfigError::Conflict)?;
        // Compiled against the same peer order the datapath indexes by, since a
        // rule names peers by handle and the engine knows them by position.
        let filter = PacketFilter::compile(&netmap.packet_filter, &netmap.egress_filter, &handles);

        Ok(Self {
            keys: local.keys,
            listen: local.listen,
            port_mapping: local.port_mapping,
            interface: local.interface,
            network_mode: local.network_mode,
            userspace_socks5_listen: local.userspace_socks5_listen,
            userspace_publish: local.userspace_publish,
            nat64: local.nat64,
            addresses,
            psk_epoch: netmap.psk_epoch,
            node_id: netmap.node_id.clone(),
            // **The relay is the one address a node cannot fix for itself.**
            // The control server comes from a file an operator can edit and a
            // peer's endpoint is a hint that discovery can replace, but the
            // relay arrives from the netmap as an IPv4 literal and is the
            // node's only way onto the mesh. Rewriting it here, once, means
            // every consumer — the first connection, §9.1's measurements,
            // §9.2's moves — dials an address this host can reach without any
            // of them knowing why.
            relays: netmap
                .relays
                .iter()
                .cloned()
                .map(|mut relay| {
                    relay.address = crate::nat64::rewrite_authority(local.nat64, &relay.address);
                    relay
                })
                .collect(),
            relay_ca_file: local.relay_ca_file,
            peers,
            routes,
            skipped,
            filter,
        })
    }
}

/// A peer the netmap carried that this node could not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedPeer {
    /// The peer's handle, as a lossy string.
    pub handle: String,
    /// Its DNS label, if it had one.
    pub dns_name: String,
    /// Why it was unusable.
    pub reason: String,
}

impl fmt::Display for SkippedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.dns_name.is_empty() {
            &self.handle
        } else {
            &self.dns_name
        };
        write!(f, "{name}: {}", self.reason)
    }
}

/// What a server-managed node still configures locally.
///
/// Deliberately small. Everything here is something the coordination server has
/// no business deciding — a UDP port, an interface name, and private key
/// material that must never leave the node.
pub struct LocalSettings {
    /// This node's PHREATIC long-term keys.
    pub keys: Arc<StaticKeys>,
    /// Where to bind.
    pub listen: SocketAddr,
    /// Whether explicit NAT port mapping is enabled for this node.
    pub port_mapping: bool,
    /// TUN interface name.
    pub interface: String,
    /// Packet attachment mode.
    pub network_mode: NetworkMode,
    /// Optional userspace SOCKS5 endpoint.
    pub userspace_socks5_listen: Option<SocketAddr>,
    /// Overlay ports this node publishes to the mesh. See [`crate::publish`].
    pub userspace_publish: Vec<PublishSection>,
    /// The NAT64 prefix this node reaches IPv4 through, if it is on such a
    /// network. Resolved once at startup by [`crate::nat64::resolve`] — the
    /// mode an operator writes lives in [`NodeSection::nat64`], and by the time
    /// a datapath exists the question has been settled.
    pub nat64: Option<karst_transport::Nat64Prefix>,
    /// Extra trust anchors for relay TLS — see [`Config::relay_ca_file`].
    pub relay_ca_file: Option<PathBuf>,
}

impl fmt::Debug for LocalSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSettings")
            .field("listen", &self.listen)
            .field("port_mapping", &self.port_mapping)
            .field("interface", &self.interface)
            .field("network_mode", &self.network_mode)
            .field("userspace_socks5_listen", &self.userspace_socks5_listen)
            .field("userspace_publish", &self.userspace_publish)
            .field("nat64", &self.nat64)
            .finish_non_exhaustive()
    }
}

/// Load only this node's keys, ignoring the roster.
///
/// A node that has just been created has no peers: its operator needs to read
/// its public key in order to *put it somewhere else*. Requiring a valid roster
/// first would make that impossible without writing a placeholder peer, so
/// `karstd pubkey` uses this path.
///
/// # Errors
/// [`ConfigError`] if the file cannot be read, parsed, or the key is unusable.
pub fn load_keys(path: &Path) -> Result<Arc<StaticKeys>, ConfigError> {
    /// Just enough of the file to find the key. Unknown fields are allowed
    /// here, precisely because this deliberately ignores most of the document.
    #[derive(serde::Deserialize)]
    struct KeyOnly {
        node: NodeKey,
    }
    #[derive(serde::Deserialize)]
    struct NodeKey {
        private_key_file: PathBuf,
    }

    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    let parsed: KeyOnly = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;

    let key_path = resolve(&parsed.node.private_key_file, path);
    check_permissions(&key_path)?;
    let seed = std::fs::read_to_string(&key_path).map_err(|source| ConfigError::Read {
        path: key_path,
        source,
    })?;
    let seed = decode_hex(seed.trim(), PRIVATE_KEY_LEN, "private_key_file")?;
    let (kem_seed, dh_seed) = split_seed(&seed)?;
    Ok(Arc::new(StaticKeys::from_seed(&kem_seed, &dh_seed)))
}

impl Peer {
    /// Build a roster entry from a netmap peer.
    ///
    /// The name is the peer's DNS label rather than its handle: a 44-character
    /// base64 string in every log line and every row of `karst status` is
    /// unreadable, and the label is what an operator recognises. A peer with no
    /// label falls back to a short prefix of the handle, which is ugly but
    /// unambiguous — inventing a name like "peer-3" would make two different
    /// peers look the same across restarts.
    fn from_netmap(
        entry: &crate::netmap::Peer,
        index: usize,
        pairs: &mut Vec<(Prefix, usize)>,
    ) -> Result<Self, ConfigError> {
        let name = if entry.dns_name.is_empty() {
            let id = String::from_utf8_lossy(&entry.node_id);
            format!("node-{}", id.chars().take(8).collect::<String>())
        } else {
            entry.dns_name.clone()
        };

        let kem_pk = MlKem::public_key_from_bytes(&entry.kem_public_key).ok_or_else(|| {
            ConfigError::InvalidKey {
                peer: name.clone(),
                field: "kem_public_key",
            }
        })?;
        let dh: [u8; 32] =
            entry
                .dh_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ConfigError::InvalidKey {
                    peer: name.clone(),
                    field: "dh_public_key",
                })?;

        // §7.3: an absent PSK is the lattice-only fallback, and the netmap
        // models it as `None` rather than as zeros precisely so that reaching
        // the zero key requires naming the case.
        let psk_is_fallback = entry.psk.is_none();
        let psk = entry
            .psk
            .as_ref()
            .map_or([0u8; 32], |k| *crate::netmap::Psk::as_bytes(k));

        if entry.allowed_ips.is_empty() {
            return Err(ConfigError::Unusable(format!(
                "the netmap gave peer {name:?} no allowed_ips, so no traffic could reach it"
            )));
        }
        let mut allowed_ips = Vec::with_capacity(entry.allowed_ips.len());
        for s in &entry.allowed_ips {
            let prefix = s.parse::<Prefix>().map_err(|source| ConfigError::Prefix {
                peer: name.clone(),
                source,
            })?;
            allowed_ips.push(prefix);
            pairs.push((prefix, index));
        }

        // An endpoint the server does not know is not an error: a peer behind
        // NAT is expected to contact us rather than be dialled.
        let endpoint = if entry.endpoint.is_empty() {
            None
        } else {
            entry.endpoint.parse().ok()
        };

        Ok(Self {
            name,
            node_id: entry.node_id.clone(),
            public: Arc::new(PeerPublic {
                kem_pk,
                dh_pk: DhPublic::from(dh),
                psk,
            }),
            endpoint,
            allowed_ips,
            psk_is_fallback,
            disco_key: entry.disco_key.as_ref().map(|key| *key.as_bytes()),
            // §9.1. Empty is the ordinary case — a peer that holds no relay —
            // and any other wrong width is a server this node cannot follow.
            // Both become `None`, which costs the on-demand path and leaves the
            // peer reachable by every other route, rather than failing the
            // whole netmap over one unusable field.
            home_relay: entry
                .home_relay
                .as_slice()
                .first_chunk::<{ karst_relay_proto::consts::ID_LEN }>()
                .filter(|_| entry.home_relay.len() == karst_relay_proto::consts::ID_LEN)
                .copied(),
        })
    }

    fn from_section(
        section: PeerSection,
        index: usize,
        pairs: &mut Vec<(Prefix, usize)>,
    ) -> Result<Self, ConfigError> {
        let name = section.name;
        let kem_bytes = decode_hex(
            &section.kem_public_key,
            MlKem::PUBLIC_KEY_LEN,
            "kem_public_key",
        )?;
        let kem_pk =
            MlKem::public_key_from_bytes(&kem_bytes).ok_or_else(|| ConfigError::InvalidKey {
                peer: name.clone(),
                field: "kem_public_key",
            })?;

        let dh_bytes = decode_hex(&section.dh_public_key, 32, "dh_public_key")?;
        let mut dh = [0u8; 32];
        dh.copy_from_slice(dh_bytes.get(..32).ok_or_else(|| ConfigError::InvalidKey {
            peer: name.clone(),
            field: "dh_public_key",
        })?);

        let psk_is_fallback = section.psk.is_none();
        let mut psk = [0u8; 32];
        if let Some(hex) = &section.psk {
            let bytes = decode_hex(hex, 32, "psk")?;
            psk.copy_from_slice(bytes.get(..32).ok_or_else(|| ConfigError::InvalidKey {
                peer: name.clone(),
                field: "psk",
            })?);
        }

        if section.allowed_ips.is_empty() {
            return Err(ConfigError::Unusable(format!(
                "peer {name:?} has no allowed_ips, so no traffic could ever reach it"
            )));
        }
        let mut allowed_ips = Vec::with_capacity(section.allowed_ips.len());
        for s in &section.allowed_ips {
            let prefix = s.parse::<Prefix>().map_err(|source| ConfigError::Prefix {
                peer: name.clone(),
                source,
            })?;
            allowed_ips.push(prefix);
            pairs.push((prefix, index));
        }

        Ok(Self {
            name,
            node_id: Vec::new(),
            public: Arc::new(PeerPublic {
                kem_pk,
                dh_pk: DhPublic::from(dh),
                psk,
            }),
            endpoint: section.endpoint,
            allowed_ips,
            psk_is_fallback,
            disco_key: None,
            // A static roster has no coordination server, so no peer publishes
            // anything — the same reason `node_id` and `disco_key` are empty.
            home_relay: None,
        })
    }
}

/// Resolve a path relative to the config file's directory, so a roster can be
/// moved without rewriting absolute paths.
fn resolve(path: &Path, config_path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_owned();
    }
    config_path
        .parent()
        .map_or_else(|| path.to_owned(), |dir| dir.join(path))
}

/// Refuse a secret-bearing file that anyone but its owner can read.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ConfigError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

/// Decode a hex string of an exact expected length.
///
/// Written here rather than pulled in as a dependency: it is fifteen lines, it
/// sits on the path that parses key material, and the dependency policy in
/// LICENSING.md asks that additions earn their place.
pub(crate) fn decode_hex_public(s: &str, expect_len: usize) -> Result<Vec<u8>, ConfigError> {
    decode_hex(s, expect_len, "key")
}

fn decode_hex(s: &str, expect_len: usize, field: &str) -> Result<Vec<u8>, ConfigError> {
    let s = s.trim();
    let bad = |reason: String| ConfigError::Hex {
        field: field.to_owned(),
        reason,
    };
    if s.len() != expect_len * 2 {
        return Err(bad(format!(
            "expected {} hex characters ({expect_len} bytes), found {}",
            expect_len * 2,
            s.len()
        )));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(expect_len);
    for pair in bytes.chunks_exact(2) {
        let (hi, lo) = match pair {
            [hi, lo] => (nibble(*hi), nibble(*lo)),
            _ => return Err(bad("odd length".to_owned())),
        };
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Err(bad("contains a non-hexadecimal character".to_owned())),
        }
    }
    Ok(out)
}

const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn split_seed(seed: &[u8]) -> Result<([u8; 64], [u8; 32]), ConfigError> {
    let bad = || ConfigError::Hex {
        field: "private_key_file".to_owned(),
        reason: format!("expected {PRIVATE_KEY_LEN} bytes of seed"),
    };
    let kem: [u8; 64] = seed
        .get(..64)
        .ok_or_else(bad)?
        .try_into()
        .map_err(|_| bad())?;
    let dh: [u8; 32] = seed
        .get(64..96)
        .ok_or_else(bad)?
        .try_into()
        .map_err(|_| bad())?;
    Ok((kem, dh))
}

/// Render bytes as lower-case hex — for generating a key file or printing a
/// public key.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    pub(super) fn write(dir: &Path, name: &str, contents: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write test file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set test mode");
        path
    }

    pub(super) use crate::scratch::Scratch;

    fn keys_hex() -> String {
        encode_hex(&[0x11u8; PRIVATE_KEY_LEN])
    }

    fn peer_keys() -> (String, String) {
        let (_, pk) = MlKem::keypair_from_seed(&[0x22; 64]);
        let dh = DhPublic::from(&x25519_dalek::StaticSecret::from([0x33u8; 32]));
        (
            encode_hex(&MlKem::public_key_bytes(&pk)),
            encode_hex(dh.as_bytes()),
        )
    }

    fn roster(dir: &Path, extra_peer: &str) -> PathBuf {
        let (kem, dh) = peer_keys();
        write(dir, "node.key", &keys_hex(), 0o600);
        let toml = format!(
            r#"
[node]
listen = "0.0.0.0:51820"
interface = "karst0"
addresses = ["10.99.0.1/24", "fd7a:5ea5::1/64"]
private_key_file = "node.key"
psk_epoch = 7

[[peer]]
name = "bob"
kem_public_key = "{kem}"
dh_public_key = "{dh}"
endpoint = "192.0.2.20:51820"
allowed_ips = ["10.99.0.2/32"]
{extra_peer}
"#
        );
        write(dir, "karstd.toml", &toml, 0o600)
    }

    #[test]
    fn loads_a_valid_roster() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        let cfg = Config::load(&path).expect("valid roster must load");

        assert_eq!(cfg.listen.port(), 51820);
        assert_eq!(cfg.interface, "karst0");
        assert_eq!(cfg.network_mode, NetworkMode::Tun);
        assert_eq!(cfg.psk_epoch, 7);
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peer_index("bob"), Some(0));
        assert_eq!(
            cfg.routes.route("10.99.0.2".parse().unwrap()),
            Some(0),
            "the peer's address must route to it"
        );
    }

    #[test]
    fn userspace_mode_is_an_explicit_configuration_choice() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        let source = std::fs::read_to_string(&path).expect("read roster");
        std::fs::write(
            &path,
            source.replace(
                "interface = \"karst0\"",
                "interface = \"karst0\"\nnetwork_mode = \"userspace\"\nuserspace_socks5_listen = \"127.0.0.1:1080\"",
            ),
        )
        .expect("write roster");

        let cfg = Config::load(&path).expect("load userspace roster");
        assert_eq!(cfg.network_mode, NetworkMode::Userspace);
        assert_eq!(
            cfg.userspace_socks5_listen.expect("SOCKS listener").port(),
            1080
        );
        assert!(
            cfg.userspace_publish.is_empty(),
            "nothing is published unless it is asked for"
        );
    }

    /// Load a roster with `[node]` extended by `keys` and `tables` appended to
    /// the document.
    ///
    /// Two arguments rather than one because TOML says so: an array of tables
    /// ends the table it is written inside, so `[[node.userspace_publish]]` has
    /// to follow every plain key of `[node]`.
    fn node_with(dir: &Path, keys: &str, tables: &str) -> Result<Config, ConfigError> {
        let path = roster(dir, "");
        let source = std::fs::read_to_string(&path).expect("read roster");
        let text = format!(
            "{}\n{tables}\n",
            source.replace(
                "interface = \"karst0\"",
                &format!("interface = \"karst0\"\n{keys}")
            )
        );
        std::fs::write(&path, text).expect("write roster");
        Config::load(&path)
    }

    /// The inbound half of ADR-0012 §9's sidecar: an overlay port and where it
    /// goes, both named by the operator and neither inferred.
    #[test]
    fn a_published_port_names_one_overlay_port_and_one_destination() {
        let dir = Scratch::new("cfg");
        let cfg = node_with(
            dir.path(),
            "network_mode = \"userspace\"\nuserspace_socks5_listen = \"127.0.0.1:1080\"\n",
            "[[node.userspace_publish]]\nport = 8080\nto = \"127.0.0.1:80\"\n\
             [[node.userspace_publish]]\nport = 5432\nto = \"127.0.0.1:5432\"\n",
        )
        .expect("load");
        let ports: Vec<u16> = cfg.userspace_publish.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8080, 5432]);
        assert_eq!(
            cfg.userspace_publish.first().expect("first").to,
            "127.0.0.1:80".parse::<SocketAddr>().expect("address")
        );
    }

    /// **An inbound-only sidecar is a real deployment**, and requiring it to
    /// open a SOCKS listener it does not want in order to start would be
    /// requiring it to widen its own surface.
    #[test]
    fn publishing_alone_is_enough_to_attach_a_userspace_node() {
        let dir = Scratch::new("cfg");
        let cfg = node_with(
            dir.path(),
            "network_mode = \"userspace\"\n",
            "[[node.userspace_publish]]\nport = 8080\nto = \"127.0.0.1:80\"\n",
        )
        .expect("load");
        assert_eq!(cfg.userspace_socks5_listen, None);
        assert_eq!(cfg.userspace_publish.len(), 1);
    }

    /// A userspace stack nothing can reach and nothing can leave carries
    /// packets no process will ever read: it establishes, reports healthy, and
    /// is useless. Refused at load time rather than discovered in production.
    #[test]
    fn a_userspace_node_with_no_attachment_at_all_is_refused() {
        let dir = Scratch::new("cfg");
        let err = node_with(dir.path(), "network_mode = \"userspace\"\n", "")
            .expect_err("an unattached userspace node must be refused");
        let message = err.to_string();
        assert!(
            message.contains("userspace_socks5_listen") && message.contains("userspace_publish"),
            "the refusal does not say what would fix it: {message}"
        );
    }

    #[test]
    fn publishing_is_refused_for_the_configurations_that_cannot_honour_it() {
        for (label, keys, tables, expect) in [
            (
                "TUN mode has an interface and does not need this",
                "",
                "[[node.userspace_publish]]\nport = 8080\nto = \"127.0.0.1:80\"\n",
                "requires network_mode",
            ),
            (
                "port 0 is not a port anything connects to",
                "network_mode = \"userspace\"\n",
                "[[node.userspace_publish]]\nport = 0\nto = \"127.0.0.1:80\"\n",
                "port 0",
            ),
            (
                "one port, two destinations",
                "network_mode = \"userspace\"\n",
                "[[node.userspace_publish]]\nport = 8080\nto = \"127.0.0.1:80\"\n\
                 [[node.userspace_publish]]\nport = 8080\nto = \"127.0.0.1:81\"\n",
                "twice",
            ),
        ] {
            let dir = Scratch::new("cfg");
            let message = match node_with(dir.path(), keys, tables) {
                Ok(_) => panic!("{label}: accepted"),
                Err(e) => e.to_string(),
            };
            assert!(
                message.contains(expect),
                "{label}: the refusal does not mention {expect:?}: {message}"
            );
        }
    }

    /// An absent PSK is the §7.3 fallback. It must be recorded, not silently
    /// treated as a configured all-zero key — an operator needs to know the
    /// classical half of the handshake is carrying no shared secret.
    #[test]
    fn an_absent_psk_is_reported_as_the_fallback() {
        let dir = Scratch::new("cfg");
        let cfg = Config::load(&roster(dir.path(), "")).expect("load");
        assert!(cfg.peers.first().expect("one peer").psk_is_fallback);
        assert_eq!(cfg.peers.first().expect("one peer").public.psk, [0u8; 32]);
    }

    /// A world-readable key file is refused. This is the check that stops a
    /// `chmod 644` from quietly publishing the node's identity.
    #[test]
    fn refuses_a_key_file_others_can_read() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        write(dir.path(), "node.key", &keys_hex(), 0o644);
        match Config::load(&path) {
            Err(ConfigError::Permissions { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected a permissions error, got {other:?}"),
        }
    }

    /// A config carrying PSKs is as sensitive as the key file itself.
    #[test]
    fn refuses_a_readable_config_when_it_carries_psks() {
        let dir = Scratch::new("cfg");
        let psk = encode_hex(&[0x44u8; 32]);
        let path = roster(dir.path(), &format!("psk = \"{psk}\""));
        write(
            dir.path(),
            "karstd.toml",
            &std::fs::read_to_string(&path).expect("read back"),
            0o640,
        );
        assert!(
            matches!(Config::load(&path), Err(ConfigError::Permissions { .. })),
            "a group-readable config holding PSKs must be refused"
        );
    }

    #[test]
    fn rejects_unknown_fields_rather_than_ignoring_them() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        let text = std::fs::read_to_string(&path).expect("read");
        let path = write(
            dir.path(),
            "typo.toml",
            &text.replace("psk_epoch", "psk_epock"),
            0o600,
        );
        assert!(
            matches!(Config::load(&path), Err(ConfigError::Parse { .. })),
            "a mistyped key must fail loudly, not fall back to a default"
        );
    }

    #[test]
    fn rejects_a_peer_with_no_allowed_ips() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        let text = std::fs::read_to_string(&path).expect("read");
        let path = write(
            dir.path(),
            "empty.toml",
            &text.replace(r#"allowed_ips = ["10.99.0.2/32"]"#, "allowed_ips = []"),
            0o600,
        );
        assert!(matches!(Config::load(&path), Err(ConfigError::Unusable(_))));
    }

    #[test]
    fn rejects_two_peers_claiming_one_range() {
        let dir = Scratch::new("cfg");
        let (kem, dh) = peer_keys();
        let path = roster(
            dir.path(),
            &format!(
                r#"
[[peer]]
name = "carol"
kem_public_key = "{kem}"
dh_public_key = "{dh}"
allowed_ips = ["10.99.0.2/32"]
"#
            ),
        );
        assert!(matches!(Config::load(&path), Err(ConfigError::Conflict(_))));
    }

    #[test]
    fn rejects_duplicate_peer_names() {
        let dir = Scratch::new("cfg");
        let (kem, dh) = peer_keys();
        let path = roster(
            dir.path(),
            &format!(
                r#"
[[peer]]
name = "bob"
kem_public_key = "{kem}"
dh_public_key = "{dh}"
allowed_ips = ["10.99.0.3/32"]
"#
            ),
        );
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::DuplicatePeerName(_))
        ));
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length() {
        let dir = Scratch::new("cfg");
        let path = roster(dir.path(), "");
        write(dir.path(), "node.key", "aabbcc", 0o600);
        assert!(matches!(Config::load(&path), Err(ConfigError::Hex { .. })));
    }

    #[test]
    fn hex_decoding_is_strict() {
        assert!(decode_hex("00ff", 2, "f").is_ok());
        assert!(decode_hex("00FF", 2, "f").is_ok(), "upper case is accepted");
        assert!(decode_hex("00f", 2, "f").is_err(), "wrong length");
        assert!(decode_hex("00gg", 2, "f").is_err(), "non-hex");
        assert!(decode_hex("00 f", 2, "f").is_err(), "embedded space");
        assert_eq!(decode_hex("0aff", 2, "f").expect("valid"), vec![0x0a, 0xff]);
    }

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let hex = encode_hex(&bytes);
        assert_eq!(decode_hex(&hex, 256, "f").expect("round trip"), bytes);
    }

    /// A `Debug` that printed the PSK would leak it into every log line and bug
    /// report that formatted a config — THREAT-MODEL R5.
    #[test]
    fn debug_output_never_contains_key_material() {
        let dir = Scratch::new("cfg");
        let psk = encode_hex(&[0x44u8; 32]);
        let path = roster(dir.path(), &format!("psk = \"{psk}\""));
        let cfg = Config::load(&path).expect("load");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains(&psk), "PSK leaked into Debug output");
        assert!(
            !rendered.contains(&keys_hex()),
            "private key leaked into Debug output"
        );
        assert!(rendered.contains("karst0"), "but it must still be useful");
    }
}

#[cfg(test)]
mod netmap_tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use karst_control_client::transport::pb;

    pub(super) fn wire_peer(id: &str, dns: &str, ip: &str) -> pb::KarstNetmapPeer {
        let (_, kem_pk) = MlKem::keypair_from_seed(&[0x22; 64]);
        let dh = DhPublic::from(&x25519_dalek::StaticSecret::from([0x33u8; 32]));
        pb::KarstNetmapPeer {
            home_relay: Vec::new(),
            node_id: id.as_bytes().to_vec(),
            allowed_ips: vec![format!("{ip}/32")],
            dns_name: dns.to_owned(),
            endpoint: String::new(),
            kem_public_key: MlKem::public_key_bytes(&kem_pk).clone(),
            dh_public_key: dh.as_bytes().to_vec(),
            psk: vec![0x44; 32],
            psk_previous: vec![0x45; 32],
            disco_key: vec![0x46; 32],
        }
    }

    /// A netmap with `version` already set to what its content hashes to, as a
    /// correct server would send.
    pub(super) fn netmap(
        addresses: Vec<String>,
        peers: Vec<pb::KarstNetmapPeer>,
        filter: Vec<pb::KarstFilterRule>,
    ) -> Netmap {
        let mut map = Netmap::new();
        let mut resp = pb::KarstNetmapResponse {
            psk_epoch: 5,
            node_id: b"self".to_vec(),
            addresses,
            dns_name: "self".to_owned(),
            peers,
            packet_filter: filter,
            ..pb::KarstNetmapResponse::default()
        };
        let mut projected = Netmap::new();
        projected
            .apply(pb::KarstNetmapResponse {
                version: 0,
                ..resp.clone()
            })
            .ok();
        resp.version = projected.content_version();
        map.apply(resp).expect("the fixture netmap must apply");
        map
    }

    pub(super) fn local() -> LocalSettings {
        LocalSettings {
            relay_ca_file: None,
            keys: Arc::new(StaticKeys::from_seed(&[0x11; 64], &[0x12; 32])),
            listen: "0.0.0.0:51820".parse().expect("addr"),
            port_mapping: true,
            interface: "karst0".to_owned(),
            network_mode: NetworkMode::Tun,
            userspace_socks5_listen: None,
            userspace_publish: Vec::new(),
            nat64: None,
        }
    }

    /// §9.1's published relay reaches the datapath, which is the point of
    /// carrying it: the netmap decoded it before this and the roster dropped
    /// it, so every peer looked like a peer that had published nothing and the
    /// second rule could never fire.
    #[test]
    fn a_peers_published_home_relay_reaches_the_roster() {
        let mut peer = wire_peer("aaa", "alpha", "100.64.0.2");
        peer.home_relay = vec![0x7C; 32];
        let map = netmap(vec!["100.64.0.1/16".to_owned()], vec![peer], vec![]);
        let cfg = Config::from_netmap(local(), &map).expect("load");
        assert_eq!(cfg.peers[0].home_relay, Some([0x7C; 32]));
    }

    /// A peer holding no relay is the ordinary case and must not look like one
    /// holding a relay named by zero bytes.
    #[test]
    fn a_peer_that_published_no_relay_has_none() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.0.2")],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");
        assert_eq!(cfg.peers[0].home_relay, None);
    }

    /// A relay id of the wrong width names nothing in the registry. The peer
    /// keeps every other route rather than the netmap being refused over one
    /// unusable field — but it must not be truncated or padded into an id that
    /// happens to match something.
    #[test]
    fn a_home_relay_of_the_wrong_width_is_dropped() {
        for width in [1_usize, 31, 33, 64] {
            let mut peer = wire_peer("aaa", "alpha", "100.64.0.2");
            peer.home_relay = vec![0x7C; width];
            let map = netmap(vec!["100.64.0.1/16".to_owned()], vec![peer], vec![]);
            let cfg = Config::from_netmap(local(), &map).expect("load");
            assert_eq!(
                cfg.peers[0].home_relay, None,
                "a {width}-byte relay id was accepted"
            );
        }
    }

    #[test]
    fn a_netmap_becomes_a_routable_configuration() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.0.2")],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("a netmap must configure a datapath");

        assert_eq!(cfg.psk_epoch, 5, "the epoch comes from the netmap");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peer_index("alpha"), Some(0), "named by its DNS label");
        assert_eq!(
            cfg.routes.route("100.64.0.2".parse().unwrap()),
            Some(0),
            "the peer's address must route to it"
        );
        assert!(
            cfg.routes.permits(0, "100.64.0.2".parse().unwrap()),
            "and it must be entitled to source from it"
        );
        assert!(!cfg.peers[0].psk_is_fallback);
    }

    /// **The bug a bare address would cause.** An address with the on-link
    /// prefix puts peers on the interface's network; a `/32` leaves the node
    /// with an address and no route to anyone, which looks like a handshake
    /// failure and is not one. The server is required to send the prefix, and
    /// this is what consumes it.
    #[test]
    fn the_interface_address_keeps_the_prefix_the_server_sent() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.9.9")],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");

        let addr = cfg.addresses.first().expect("one address");
        assert_eq!(addr.prefix_len, 16, "the on-link prefix must survive");
        assert_eq!(
            addr.addr,
            "100.64.0.1".parse::<std::net::IpAddr>().unwrap(),
            "and the host bits must not be masked off"
        );
        assert!(
            addr.network().contains("100.64.9.9".parse().unwrap()),
            "a peer must be on-link, or nothing routes"
        );
    }

    /// A netmap with no address is refused rather than accepted as a node with
    /// an unnumbered interface, which cannot originate a packet anyone will
    /// answer.
    #[test]
    fn a_netmap_with_no_address_is_refused() {
        let map = netmap(
            vec![],
            vec![wire_peer("aaa", "alpha", "100.64.0.2")],
            vec![],
        );
        assert!(matches!(
            Config::from_netmap(local(), &map),
            Err(ConfigError::Unusable(_))
        ));
    }

    /// §7.3. A peer the server shipped without a PSK is lattice-only, and that
    /// has to be visible: `karstd` reports it at startup, and a session whose
    /// confidentiality rests on ML-KEM alone must never pass unremarked.
    #[test]
    fn a_peer_without_a_psk_is_flagged_as_lattice_only() {
        let mut wire = wire_peer("aaa", "alpha", "100.64.0.2");
        wire.psk = Vec::new();
        wire.psk_previous = Vec::new();
        let map = netmap(vec!["100.64.0.1/16".to_owned()], vec![wire], vec![]);
        let cfg = Config::from_netmap(local(), &map).expect("load");

        assert!(cfg.peers[0].psk_is_fallback);
        assert_eq!(cfg.peers[0].public.psk, [0u8; 32]);
    }

    /// The filter is compiled against the peer order the datapath indexes by. A
    /// rule names peers by handle; the engine knows them by position, and a
    /// mismatch would enforce the right policy against the wrong peer.
    #[test]
    fn the_filter_is_compiled_against_the_peer_order() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![
                wire_peer("aaa", "alpha", "100.64.0.2"),
                wire_peer("bbb", "beta", "100.64.0.3"),
            ],
            vec![pb::KarstFilterRule {
                srcs: vec!["bbb".to_owned()],
                ports: vec![pb::KarstPortRange {
                    first: 22,
                    last: 22,
                }],
            }],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");

        // Peers are ordered by handle, so "bbb" is index 1.
        assert_eq!(cfg.peer_index("beta"), Some(1));

        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&24u16.to_be_bytes());
        packet[9] = 6;
        packet[22..24].copy_from_slice(&22u16.to_be_bytes());

        assert!(
            cfg.filter.ingress(1, &packet).permitted(),
            "the rule names beta, which is peer 1"
        );
        assert!(
            !cfg.filter.ingress(0, &packet).permitted(),
            "and must not apply to alpha, which is peer 0"
        );
    }

    /// A netmap that ships no rules is a policy granting nothing — the opposite
    /// of a roster, which has no policy at all. Both configurations are valid
    /// and they must not behave alike.
    #[test]
    fn a_netmap_always_enforces_even_with_no_rules() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.0.2")],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");
        assert!(
            cfg.filter.is_enforcing(),
            "a server-managed node always enforces; an empty rule set is deny-all"
        );
    }

    /// A peer with no label still gets a stable name. Numbering them would make
    /// two different peers look like the same one across restarts.
    #[test]
    fn a_peer_without_a_dns_label_is_named_from_its_handle() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("handle-xyz", "", "100.64.0.2")],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");
        assert_eq!(cfg.peers[0].name, "node-handle-x");
    }

    /// Two peers claiming one range is a server bug, and it must be refused
    /// rather than resolved by whichever happened to come first.
    #[test]
    fn two_peers_claiming_one_range_is_refused() {
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![
                wire_peer("aaa", "alpha", "100.64.0.2"),
                wire_peer("bbb", "beta", "100.64.0.2"),
            ],
            vec![],
        );
        assert!(matches!(
            Config::from_netmap(local(), &map),
            Err(ConfigError::Conflict(_))
        ));
    }

    /// A configuration naming a control server has no roster of its own, and
    /// loading it as one would produce a node with no peers that looks fine.
    #[test]
    fn a_control_configuration_is_not_loadable_as_a_roster() {
        let dir = tests::Scratch::new("cfg");
        tests::write(
            dir.path(),
            "node.key",
            &encode_hex(&[0x11u8; PRIVATE_KEY_LEN]),
            0o600,
        );
        let toml = r#"
[node]
listen = "0.0.0.0:51820"
private_key_file = "node.key"

[control]
server = "https://karst.example.com"
server_kem_pin = "aabb"
server_verify_pin = "ccdd"
identity_key_file = "identity.key"
"#;
        let path = tests::write(dir.path(), "control.toml", toml, 0o600);
        match Config::load(&path) {
            Err(ConfigError::Unusable(m)) => assert!(m.contains("from_netmap"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod skip_tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use karst_control_client::transport::pb;

    use super::netmap_tests::{local, netmap, wire_peer};
    use super::*;

    /// **One bad peer must not cost the whole netmap.**
    ///
    /// The server validates a registered node's data-plane keys, but a node
    /// enrolled before that check — or through any other path — leaves an entry
    /// nobody can parse. Refusing the netmap over it would let a single bad
    /// registration take every node in the account off the network. Dropping
    /// the entry costs reachability to that one peer, which is what it costs
    /// anyway: nobody can handshake with a key that does not parse.
    #[test]
    fn an_unusable_peer_is_skipped_rather_than_taking_the_netmap_down() {
        let mut broken = wire_peer("bbb", "broken", "100.64.0.3");
        broken.kem_public_key = vec![0xFF; 1184]; // right length, not a key

        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.0.2"), broken],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("one bad peer must not be fatal");

        assert_eq!(cfg.peers.len(), 1, "the usable peer must survive");
        assert_eq!(cfg.peers[0].name, "alpha");
        assert_eq!(cfg.skipped.len(), 1);
        assert_eq!(cfg.skipped[0].dns_name, "broken");
        assert!(cfg.skipped[0].reason.contains("kem_public_key"));

        assert_eq!(
            cfg.routes.route("100.64.0.2".parse().unwrap()),
            Some(0),
            "and the surviving peer must still route"
        );
        assert_eq!(
            cfg.routes.route("100.64.0.3".parse().unwrap()),
            None,
            "while the skipped peer claims nothing"
        );
    }

    /// Skipping must not shift the indices the filter was compiled against. A
    /// rule about a peer that is still present must still apply to it, and one
    /// about a peer that was dropped must apply to nobody.
    #[test]
    fn skipping_a_peer_does_not_misalign_the_filter() {
        let mut broken = wire_peer("aaa", "broken", "100.64.0.2");
        broken.dh_public_key = vec![0x01; 8]; // too short

        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            // "aaa" sorts first, so the broken peer is the one that would have
            // been index 0 — the case where a naive skip shifts everything.
            vec![broken, wire_peer("bbb", "beta", "100.64.0.3")],
            vec![
                pb::KarstFilterRule {
                    srcs: vec!["bbb".to_owned()],
                    ports: vec![pb::KarstPortRange {
                        first: 22,
                        last: 22,
                    }],
                },
                pb::KarstFilterRule {
                    srcs: vec!["aaa".to_owned()],
                    ports: vec![pb::KarstPortRange {
                        first: 80,
                        last: 80,
                    }],
                },
            ],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");

        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peer_index("beta"), Some(0), "beta moved up to index 0");

        let tcp = |port: u16| {
            let mut p = vec![0u8; 24];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&24u16.to_be_bytes());
            p[9] = 6;
            p[22..24].copy_from_slice(&port.to_be_bytes());
            p
        };

        assert!(
            cfg.filter.ingress(0, &tcp(22)).permitted(),
            "the rule naming beta must follow it to its new index"
        );
        assert!(
            !cfg.filter.ingress(0, &tcp(80)).permitted(),
            "and the rule naming the dropped peer must not apply to beta"
        );
    }

    /// The netmap itself keeps the entry even though the datapath skips it, so
    /// the node still reports holding it and the server does not resend it on
    /// every poll.
    #[test]
    fn a_skipped_peer_is_still_reported_as_held() {
        let mut broken = wire_peer("bbb", "broken", "100.64.0.3");
        broken.kem_public_key = vec![0xFF; 1184];
        let map = netmap(
            vec!["100.64.0.1/16".to_owned()],
            vec![wire_peer("aaa", "alpha", "100.64.0.2"), broken],
            vec![],
        );
        let cfg = Config::from_netmap(local(), &map).expect("load");

        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(
            map.holds().len(),
            2,
            "the node holds the entry even though it cannot use it; \
             claiming otherwise would make the server resend it for ever"
        );
    }
}
