// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Talking to the coordination server.
//!
//! Registers the node, fetches its netmap, and keeps it current. Everything
//! cryptographic is in `karst_control_client`; this is the part that owns a
//! connection, a key file and a cache.
//!
//! # Why this is the only async code in the daemon
//!
//! The datapath is threads and blocking syscalls, deliberately — `run.rs`
//! explains why. But `tonic` is async and reimplementing HTTP/2 to avoid a
//! runtime would be a poor trade. So the control plane gets a **current-thread
//! runtime on its own thread**, and hands the datapath a finished [`Config`].
//! No future ever touches the packet path, and the executor cannot be starved
//! by a busy tunnel because it does not share a thread with one.
//!
//! # The node holds three long-term keys
//!
//! phreatic-v1.md §4: an ML-DSA-65 identity, an ML-KEM-768 static key and an
//! X25519 static key. The identity authenticates *this* channel and is
//! deliberately **not** used by PHREATIC; the other two are what peers actually
//! handshake with, and are registered here so peers can be given them.
//!
//! They live in separate files. A single file would mean that leaking the
//! control identity also leaks the data-plane keys, which are the ones that
//! decrypt traffic.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use karst_control_client::cache::{self, SealKey};
use karst_control_client::transport::pb;
use karst_control_client::transport::{Connection, EncapRandomness, ServerPins, Signer, Verifier};

use crate::config::{Config, ControlSection, LocalSettings};
use crate::netmap::{Netmap, Outcome};

/// Bytes in an ML-DSA-65 seed.
pub const IDENTITY_SEED_LEN: usize = 32;

/// Request kinds, matching `bootstrap.KindLogin` and `KindNetmap` on the
/// server. These are on the wire, so their values may not drift.
const KIND_LOGIN: u8 = 1;
const KIND_NETMAP: u8 = 2;

/// How often the netmap is refetched.
///
/// A poll rather than a server push, for now. The request is cheap when nothing
/// has changed — the node sends its version, the server answers `unchanged`,
/// and no peer entry crosses the wire — which is exactly what the content-hash
/// version was designed to make cheap.
pub const REFRESH: Duration = Duration::from_secs(60);

/// Anything that stopped the node from reaching the server.
#[derive(Debug)]
pub enum Error {
    /// A file could not be read or written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A key file was not the right shape.
    Key(String),
    /// A file holding secrets is readable beyond its owner.
    Permissions { path: PathBuf, mode: u32 },
    /// The server refused, or could not be reached.
    Server(String),
    /// The server's answer did not make sense.
    Protocol(String),
    /// The netmap could not be applied.
    Netmap(crate::netmap::Error),
    /// The assembled netmap could not configure a datapath.
    Config(crate::config::ConfigError),
    /// The on-disk cache could not be read.
    Cache(cache::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Key(m) => write!(f, "key: {m}"),
            Self::Permissions { path, mode } => write!(
                f,
                "{} is mode {mode:04o}; it holds key material and must not be \
                 readable by group or other (chmod 600)",
                path.display()
            ),
            Self::Server(m) => write!(f, "server: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Netmap(e) => write!(f, "netmap: {e}"),
            Self::Config(e) => write!(f, "configuration: {e}"),
            Self::Cache(e) => write!(f, "cache: {e}"),
        }
    }
}

impl std::error::Error for Error {}

// ── the node's control identity ─────────────────────────────────────────────

/// The node's ML-DSA-65 signing key.
pub struct Identity {
    signing: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
    public: Vec<u8>,
    /// Secret material for deriving local-at-rest keys. This is derived once
    /// from the seed rather than from `public`: an encryption key made from a
    /// public verification key protects nothing from a reader of the cache.
    cache_key: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The handle, not the key: it identifies the node in a log line without
        // printing 1952 bytes, and the private half never renders at all.
        f.debug_struct("Identity")
            .field("handle", &self.handle())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Derive a key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; IDENTITY_SEED_LEN]) -> Self {
        use sha2::{Digest as _, Sha256};

        let signing = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&(*seed).into());
        let public = signing.verifying_key().encode().to_vec();
        let mut h = Sha256::new();
        h.update(b"karst-netmap-cache-key-v1");
        h.update(seed);
        let cache_key: [u8; 32] = h.finalize().into();
        Self {
            signing,
            public,
            cache_key,
        }
    }

    /// Load a seed, or create one on first run.
    ///
    /// Creating it here rather than requiring an operator to generate one is
    /// deliberate: the node's identity is not a secret anyone else needs to
    /// know, and a step that must be done by hand before enrolment is a step
    /// that gets done badly.
    ///
    /// # Errors
    ///
    /// [`Error::Permissions`] if an existing file is readable beyond its owner,
    /// and [`Error::Io`] if it cannot be read or created.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                check_permissions(path)?;
                let seed = decode_hex(text.trim(), IDENTITY_SEED_LEN)?;
                let seed: [u8; IDENTITY_SEED_LEN] = seed
                    .try_into()
                    .map_err(|_| Error::Key("identity seed is the wrong length".to_owned()))?;
                Ok(Self::from_seed(&seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let seed = crate::random_seed();
                write_secret(path, &encode_hex(&seed))?;
                Ok(Self::from_seed(&seed))
            }
            Err(source) => Err(Error::Io {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// The server-assigned handle this key produces.
    #[must_use]
    pub fn handle(&self) -> String {
        karst_control_client::handle(&self.public)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.cache_key.zeroize();
    }
}

impl Signer for Identity {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
        // The FIPS 204 context string must match the server's, or the signature
        // will not verify — and the failure would look like a wrong key.
        let sig = self
            .signing
            .sign_deterministic(message, b"karst-control-v1")
            .map_err(|_| "signing the handshake failed")?;
        Ok(sig.encode().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
}

// Ponor shares the node identity key but not the control-channel signature
// context. A relay signature must never be reusable as a control signature.
impl karst_relay_proto::Signer for Identity {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
        let sig = self
            .signing
            .sign_deterministic(message, b"ponor-v1")
            .map_err(|_| "signing the relay handshake failed")?;
        Ok(sig.encode().to_vec())
    }
}

/// Verifies the server's hello against the pinned key.
#[derive(Debug)]
pub struct ServerVerifier;

impl Verifier for ServerVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 1952]>::try_from(public_key) else {
            return false;
        };
        let Ok(sg) = <[u8; 3309]>::try_from(signature) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk.into());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sg.into()) else {
            return false;
        };
        vk.verify_with_context(message, b"karst-control-v1", &sig)
    }
}

/// Verifies a Ponor relay identity pinned by the netmap.
#[derive(Debug)]
pub struct RelayVerifier;

impl karst_relay_proto::Verifier for RelayVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 1952]>::try_from(public_key) else {
            return false;
        };
        let Ok(sg) = <[u8; 3309]>::try_from(signature) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk.into());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sg.into()) else {
            return false;
        };
        vk.verify_with_context(message, b"ponor-v1", &sig)
    }
}

// ── the client ──────────────────────────────────────────────────────────────

/// A node's relationship with its coordination server.
pub struct Client {
    endpoint: String,
    pins: ServerPins,
    identity: Arc<Identity>,
    setup_key: Option<String>,
    cache_file: Option<PathBuf>,
    seal: Option<SealKey>,
    /// The node's PHREATIC public keys, registered so peers can be given them.
    kem_public: Vec<u8>,
    dh_public: Vec<u8>,
    /// Empty until the first registration completes.
    node_id: Vec<u8>,
    netmap: Netmap,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("identity", &self.identity)
            .field("registered", &!self.node_id.is_empty())
            .field("netmap", &self.netmap)
            // Not the setup key: it is a bearer credential that enrols a node.
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A shared signing identity for relay authentication.
    #[must_use]
    pub fn relay_identity(&self) -> Arc<Identity> {
        Arc::clone(&self.identity)
    }

    /// Build a client from the `[control]` section.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] for a malformed pin, and the errors of
    /// [`Identity::load_or_create`].
    pub fn new(
        section: &ControlSection,
        config_dir: &Path,
        keys: &karst_noise::handshake::StaticKeys,
    ) -> Result<Self, Error> {
        use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};

        let identity = Arc::new(Identity::load_or_create(&resolve(
            &section.identity_key_file,
            config_dir,
        ))?);
        let pins = ServerPins {
            static_kem: decode_hex_any(&section.server_kem_pin, "server_kem_pin")?,
            verify_key: decode_hex_any(&section.server_verify_pin, "server_verify_pin")?,
        };
        // Checked here rather than at the first handshake: a mistyped pin
        // should stop the daemon at startup with the field name in the message,
        // not surface later as an authentication failure against a server that
        // is behaving perfectly.
        if pins.verify_key.len() != 1952 {
            return Err(Error::Key(format!(
                "server_verify_pin is {} bytes, expected 1952 (ML-DSA-65)",
                pins.verify_key.len()
            )));
        }
        if pins.static_kem.len() != 1184 {
            return Err(Error::Key(format!(
                "server_kem_pin is {} bytes, expected 1184 (ML-KEM-768)",
                pins.static_kem.len()
            )));
        }

        // The cache key. Derived from the node's own identity seed for now,
        // which ties it to a file already protected as a secret; PLAN.md §2.6
        // asks for an OS keystore, and that is a per-platform change confined
        // to this one binding.
        let cache_file = section.cache_file.as_ref().map(|p| resolve(p, config_dir));
        let seal = cache_file
            .as_ref()
            .map(|_| SealKey::new(cache_seal_key(&identity)));

        Ok(Self {
            endpoint: section.server.clone(),
            pins,
            identity,
            setup_key: section.setup_key.clone(),
            cache_file,
            seal,
            kem_public: MlKem::public_key_bytes(&keys.kem_pk).clone(),
            dh_public: keys.dh_pk.as_bytes().to_vec(),
            node_id: Vec::new(),
            netmap: Netmap::new(),
        })
    }

    /// The netmap this client currently holds.
    #[must_use]
    pub fn netmap(&self) -> &Netmap {
        &self.netmap
    }

    /// Load a cached netmap, so the node can come up while the server is
    /// unreachable.
    ///
    /// A missing cache is **not an error**: it means a cold start, which is a
    /// normal state. A cache that exists but cannot be read, opened, or safely
    /// permission-checked is reported so an operator can distinguish it from a
    /// cold start.
    pub fn load_cache(&mut self) -> Option<Result<Outcome, Error>> {
        let path = self.cache_file.as_ref()?;
        let seal = self.seal.as_ref()?;
        let sealed = match std::fs::read(path) {
            Ok(sealed) => sealed,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return None,
            Err(source) => {
                return Some(Err(Error::Io {
                    path: path.clone(),
                    source,
                }));
            }
        };
        if let Err(err) = check_permissions(path) {
            return Some(Err(err));
        }

        let plain = match cache::open(seal, &sealed) {
            Ok(p) => p,
            Err(e) => return Some(Err(Error::Cache(e))),
        };
        Some(match Netmap::decode(&plain) {
            Ok(map) => {
                let peers = map.peers().len();
                self.node_id.clone_from(&map.node_id);
                self.netmap = map;
                Ok(Outcome::Replaced { peers })
            }
            Err(e) => Err(Error::Netmap(e)),
        })
    }

    /// Write the current netmap to the encrypted cache.
    ///
    /// The netmap carries a per-pair PSK for every peer, so a plaintext cache
    /// would hand an attacker with read access the assumption-diversity hedge
    /// for the whole aquifer (PLAN.md §2.6).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file cannot be written, and [`Error::Cache`] if
    /// sealing fails.
    pub fn save_cache(&self) -> Result<(), Error> {
        let (Some(path), Some(seal)) = (self.cache_file.as_ref(), self.seal.as_ref()) else {
            return Ok(());
        };
        let sealed = cache::seal(seal, &nonce(), &self.netmap.encode()).map_err(Error::Cache)?;
        write_secret_bytes(path, &sealed)
    }

    /// Register with the server and fetch a netmap.
    ///
    /// # Errors
    ///
    /// [`Error::Server`] if the server refuses or cannot be reached.
    pub async fn sync(&mut self) -> Result<Outcome, Error> {
        let registering = self.node_id.is_empty();
        let mut conn = Connection::open(
            self.endpoint.clone(),
            &self.pins,
            self.node_id.clone(),
            &*self.identity,
            &ServerVerifier,
            // A node the server already knows must not present its key: that is
            // identity substitution, not re-registration.
            registering,
            &randomness(),
        )
        .await
        .map_err(|e| Error::Server(e.to_string()))?;

        if registering {
            self.login(&mut conn).await?;
        }
        self.fetch(&mut conn).await
    }

    async fn login(&mut self, conn: &mut Connection) -> Result<(), Error> {
        use prost::Message as _;

        let req = pb::KarstLoginRequest {
            setup_key: self.setup_key.clone().unwrap_or_default(),
            meta: Some(pb::PeerSystemMeta {
                hostname: hostname(),
                ..pb::PeerSystemMeta::default()
            }),
            // Registered here because peers cannot handshake without them:
            // phreatic-v1.md requires every node to know its peers' S_pk and
            // D_pk, and the netmap is where they are distributed from.
            kem_public_key: self.kem_public.clone(),
            dh_public_key: self.dh_public.clone(),
            ..pb::KarstLoginRequest::default()
        };

        let raw = self.request(conn, KIND_LOGIN, &req.encode_to_vec()).await?;
        let resp = pb::KarstLoginResponse::decode(raw.as_slice())
            .map_err(|e| Error::Protocol(format!("login response: {e}")))?;

        if resp.node_id.is_empty() {
            return Err(Error::Protocol(
                "the server registered this node without giving it an identifier".to_owned(),
            ));
        }
        // Checked, not trusted. The handle is a function of the key this node
        // proved possession of, so a server returning a different one is either
        // broken or answering for someone else — and adopting it would make
        // every later request ask for another node's netmap.
        let expected = self.identity.handle();
        if resp.node_id != expected.as_bytes() {
            return Err(Error::Protocol(format!(
                "the server assigned handle {:?}, but this node's identity derives {expected:?}",
                String::from_utf8_lossy(&resp.node_id)
            )));
        }
        self.node_id = resp.node_id;
        Ok(())
    }

    async fn fetch(&mut self, conn: &mut Connection) -> Result<Outcome, Error> {
        use prost::Message as _;

        let req = pb::KarstNetmapRequest {
            known_version: self.netmap.version,
            holds: self.netmap.holds(),
        };
        let raw = self
            .request(conn, KIND_NETMAP, &req.encode_to_vec())
            .await?;
        let resp = pb::KarstNetmapResponse::decode(raw.as_slice())
            .map_err(|e| Error::Protocol(format!("netmap response: {e}")))?;

        match self.netmap.apply(resp) {
            Ok(outcome) => Ok(outcome),
            Err(e @ crate::netmap::Error::VersionMismatch { .. }) => {
                // The node's view is not what the server believes it sent, so
                // every later request would carry a version describing a netmap
                // it does not hold — and the server would answer `unchanged`
                // for ever. Throw the view away rather than trying to repair
                // it: a repaired view is one whose relationship to the server's
                // is unknown.
                self.netmap.reset();
                Err(Error::Netmap(e))
            }
            Err(e) => Err(Error::Netmap(e)),
        }
    }

    async fn request(
        &self,
        conn: &mut Connection,
        kind: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::with_capacity(body.len() + 1);
        payload.push(kind);
        payload.extend_from_slice(body);
        conn.request(&payload)
            .await
            .map_err(|e| Error::Server(e.to_string()))
    }

    /// Turn the held netmap into a datapath configuration.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if the netmap would leave the daemon unable to route.
    pub fn to_config(&self, local: LocalSettings) -> Result<Config, Error> {
        Config::from_netmap(local, &self.netmap).map_err(Error::Config)
    }
}

// ── bringing a server-managed node up ───────────────────────────────────────

/// What a configuration file resolved to.
#[derive(Debug)]
pub enum Source {
    /// A static roster. No control server is involved.
    Roster,
    /// A netmap from the coordination server.
    Server {
        /// Where the netmap came from.
        origin: Origin,
        /// How many peers it carries.
        peers: usize,
    },
}

/// Whether a netmap arrived from the server or from the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Fetched from the coordination server.
    Server,
    /// Read from the encrypted on-disk cache, because the server could not be
    /// reached. The node comes up with what it last knew.
    Cache,
}

/// Build a datapath configuration from whichever source the file names.
///
/// A file with `[[peer]]` loads as a roster. A file with `[control]` registers
/// with the server, fetches a netmap and assembles the same [`Config`] from it.
///
/// # Coming up without the server
///
/// If the server cannot be reached but a cache can be opened, the node comes up
/// on the cached netmap and says so. That is the point of the cache: a
/// coordination server outage should not take every tunnel down with it, and a
/// netmap goes stale slowly — a peer that moved becomes unreachable, which is
/// no worse than the node being down.
///
/// If neither works, this fails. A node with no peers is not a degraded node,
/// it is a node that silently carries no traffic.
///
/// # Errors
///
/// [`Error`] for an unreachable server with no usable cache, a malformed key,
/// or a netmap that cannot configure a datapath.
pub fn load_config(path: &Path) -> Result<(Config, Source, Option<Client>), Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    let file: crate::config::File =
        toml::from_str(&text).map_err(|e| Error::Protocol(format!("parsing config: {e}")))?;

    let Some(section) = file.control.as_ref() else {
        let config = Config::load(path).map_err(Error::Config)?;
        return Ok((config, Source::Roster, None));
    };

    if !file.peers.is_empty() {
        return Err(Error::Protocol(
            "this configuration names both [[peer]] and [control]; the peer set has \
             one source or the other, and which wins has no good answer"
                .to_owned(),
        ));
    }
    if !file.node.addresses.is_empty() {
        // A server-managed node is *assigned* its address. Honouring a local
        // one would give the interface an address the server does not know
        // about, and every packet it originated would be dropped by a peer's
        // cryptokey routing check.
        return Err(Error::Protocol(
            "node.addresses is set on a server-managed node; its addresses are \
             assigned by the coordination server"
                .to_owned(),
        ));
    }

    let dir = path.parent().unwrap_or(Path::new("."));
    let keys = crate::config::load_keys(path).map_err(Error::Config)?;
    let mut client = Client::new(section, dir, &keys)?;

    let local = LocalSettings {
        keys,
        listen: file.node.listen,
        port_mapping: file.node.port_mapping,
        interface: file.node.interface.clone(),
        // Resolved against the config directory like every other path here, so
        // a relative one means what an operator editing the file expects.
        relay_ca_file: section.relay_ca_file.as_ref().map(|p| resolve(p, dir)),
    };

    // A current-thread runtime, created and dropped here. The datapath is
    // threads and blocking syscalls; nothing below this call is async.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })?;

    // The cache first, so a node with a stale netmap still sends its digests
    // and gets a delta rather than the whole thing.
    let cached = client.load_cache();
    if let Some(Err(e)) = &cached {
        // A cache that exists and will not open is worth saying loudly: the
        // sealing key changed, and every subsequent start will do the same.
        eprintln!("karstd: the netmap cache could not be opened ({e}); ignoring it");
    }
    let had_cache = matches!(cached, Some(Ok(_)));

    let origin = match runtime.block_on(client.sync()) {
        Ok(_) => {
            if let Err(e) = client.save_cache() {
                // Not fatal. The node has a netmap and can carry traffic; it
                // will simply have to refetch on the next start.
                eprintln!("karstd: could not write the netmap cache ({e})");
            }
            Origin::Server
        }
        Err(e) if had_cache => {
            eprintln!(
                "karstd: the coordination server is unreachable ({e}); \
                 coming up on the cached netmap, which may be stale"
            );
            Origin::Cache
        }
        Err(e) => return Err(e),
    };

    let config = client.to_config(local)?;
    let peers = config.peers.len();
    Ok((config, Source::Server { origin, peers }, Some(client)))
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// The key sealing the on-disk netmap cache.
///
/// Derived from the node's *secret* identity seed, so a cache copied to another
/// machine is unreadable there. The domain label separates this local-at-rest
/// use from the signing operation.
fn cache_seal_key(identity: &Identity) -> [u8; 32] {
    identity.cache_key
}

/// A fresh nonce for each cache write.
///
/// Random rather than a counter: a counter would have to survive a crash
/// between the write and the counter's own persistence, and repeating a nonce
/// under one key is a total loss of confidentiality for both messages.
fn nonce() -> [u8; 12] {
    let seed = crate::random_seed();
    let mut n = [0u8; 12];
    for (dst, src) in n.iter_mut().zip(seed.iter()) {
        *dst = *src;
    }
    n
}

fn randomness() -> EncapRandomness {
    EncapRandomness {
        statik: crate::random_seed(),
        ephemeral: crate::random_seed(),
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_or_else(|_| "karst-node".to_owned(), |s| s.trim().to_owned())
}

fn resolve(path: &Path, dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        dir.join(path)
    }
}

/// Write a file only its owner can read, creating it with those permissions
/// **before** anything is written to it, then atomically replacing the old
/// file.
///
/// The order matters. Creating the file and then tightening the mode leaves a
/// window in which the secret exists on disk and is world-readable, which is
/// exactly the window an attacker with local access is waiting for. Writing a
/// sibling temporary file also means a crash cannot truncate the previous
/// cache, and replacement repairs a pre-existing permissive mode.
fn write_secret(path: &Path, contents: &str) -> Result<(), Error> {
    write_secret_bytes(path, contents.as_bytes())
}

fn write_secret_bytes(path: &Path, contents: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().ok_or_else(|| Error::Io {
        path: path.to_owned(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secret path has no file name",
        ),
    })?;

    // `create_new` makes a guessed temporary name harmless. It is deliberately
    // in the destination directory: rename is atomic only within one
    // filesystem.
    let mut temp = None;
    for _ in 0..16 {
        let mut name = std::ffi::OsString::from(".");
        name.push(file_name);
        name.push(format!(".karst-tmp-{}-", std::process::id()));
        let mut random = String::with_capacity(24);
        for byte in nonce() {
            use std::fmt::Write as _;
            let _ = write!(random, "{byte:02x}");
        }
        name.push(random);
        let candidate = parent.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(Error::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }
    let Some((temp_path, mut file)) = temp else {
        return Err(Error::Io {
            path: path.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate secret temporary file",
            ),
        });
    };

    let result = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(source) = result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(Error::Io {
            path: temp_path,
            source,
        });
    }
    if let Err(source) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(Error::Io {
            path: path.to_owned(),
            source,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), Error> {
    Ok(())
}

fn decode_hex(s: &str, expect: usize) -> Result<Vec<u8>, Error> {
    let bytes =
        crate::config::decode_hex_public(s, expect).map_err(|e| Error::Key(e.to_string()))?;
    Ok(bytes)
}

/// A pin of whatever length the field carries; the length check is the
/// caller's, so its error can name the algorithm.
fn decode_hex_any(s: &str, field: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Error::Key(format!(
            "{field} has an odd number of hex digits"
        )));
    }
    crate::config::decode_hex_public(s, s.len() / 2)
        .map_err(|e| Error::Key(format!("{field}: {e}")))
}

fn encode_hex(bytes: &[u8]) -> String {
    crate::config::encode_hex(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    use crate::scratch::Scratch;

    /// **The identity must survive a restart.** The node's handle is derived
    /// from it, so a new key on every start would enrol a new node each time —
    /// filling the account with orphans and losing every ACL written about the
    /// old one.
    #[test]
    fn an_identity_is_created_once_and_reused() {
        let dir = Scratch::new("identity");
        let path = dir.join("identity.key");
        let _ = std::fs::remove_file(&path);

        let first = Identity::load_or_create(&path).expect("create");
        let second = Identity::load_or_create(&path).expect("reload");
        assert_eq!(
            first.handle(),
            second.handle(),
            "the node's handle changed across a restart"
        );
    }

    /// And it is created unreadable by anyone else, from the moment it exists.
    #[test]
    fn a_created_identity_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = Scratch::new("mode");
        let path = dir.join("mode.key");
        let _ = std::fs::remove_file(&path);
        Identity::load_or_create(&path).expect("create");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "identity key is mode {mode:04o}");
    }

    #[test]
    fn cache_key_is_not_derivable_from_the_public_identity() {
        use sha2::{Digest as _, Sha256};

        let identity = Identity::from_seed(&[0x42; IDENTITY_SEED_LEN]);
        let mut public_only = Sha256::new();
        public_only.update(b"karst-netmap-cache-key-v1");
        public_only.update(&identity.public);
        let public_only: [u8; 32] = public_only.finalize().into();

        assert_ne!(cache_seal_key(&identity), public_only);
    }

    /// An existing key file others can read is refused, for the same reason the
    /// roster's is: a permissive mode is the difference between a secret and a
    /// published file.
    #[test]
    fn a_readable_identity_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = Scratch::new("readable");
        let path = dir.join("readable.key");
        std::fs::write(&path, encode_hex(&[0x11; IDENTITY_SEED_LEN])).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        assert!(matches!(
            Identity::load_or_create(&path),
            Err(Error::Permissions { .. })
        ));
    }

    /// Replacing a cache must not inherit an insecure mode from an older file.
    /// The fresh sibling is created `0600`, then atomically renamed into place.
    #[cfg(unix)]
    #[test]
    fn overwriting_a_readable_secret_repairs_its_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = Scratch::new("cache-permissions");
        let path = dir.join("netmap.bin");
        std::fs::write(&path, b"old secret").expect("seed cache");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        write_secret_bytes(&path, b"new secret").expect("atomic replacement");

        assert_eq!(std::fs::read(&path).expect("read cache"), b"new secret");
        let mode = std::fs::metadata(&path)
            .expect("stat cache")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0, "cache mode is {mode:04o}");
    }

    /// A cache holding PSKs is subject to the same read-side permission check
    /// as the identity key; otherwise a pre-existing `0644` cache leaks until
    /// the next successful refresh happens to overwrite it.
    #[cfg(unix)]
    #[test]
    fn a_readable_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = Scratch::new("readable-cache");
        let path = dir.join("netmap.bin");
        let _ = std::fs::remove_file(dir.join("id.key"));
        std::fs::write(&path, b"not important: permissions fail first").expect("seed cache");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        let mut client = Client::new(
            &section(dir.path(), Some("netmap.bin")),
            dir.path(),
            &keys(),
        )
        .expect("client");

        assert!(matches!(
            client.load_cache(),
            Some(Err(Error::Permissions { .. }))
        ));
    }

    #[test]
    fn a_handle_is_a_function_of_the_seed() {
        let a = Identity::from_seed(&[0x07; IDENTITY_SEED_LEN]);
        let b = Identity::from_seed(&[0x07; IDENTITY_SEED_LEN]);
        let c = Identity::from_seed(&[0x08; IDENTITY_SEED_LEN]);
        assert_eq!(a.handle(), b.handle());
        assert_ne!(a.handle(), c.handle());
        assert_eq!(a.handle().len(), 44, "a handle is a 44-character base64");
    }

    /// The identity signs the control channel and nothing else prints it.
    #[test]
    fn debug_output_carries_the_handle_and_no_key_material() {
        let id = Identity::from_seed(&[0x09; IDENTITY_SEED_LEN]);
        let rendered = format!("{id:?}");
        assert!(rendered.contains(&id.handle()));
        assert!(
            !rendered.contains("signing"),
            "the private half must not render: {rendered}"
        );
    }

    fn section(dir: &Path, cache: Option<&str>) -> ControlSection {
        ControlSection {
            relay_ca_file: None,
            server: "http://127.0.0.1:1".to_owned(),
            server_kem_pin: encode_hex(&[0x01; 1184]),
            server_verify_pin: encode_hex(&[0x02; 1952]),
            identity_key_file: dir.join("id.key"),
            setup_key: Some("setup".to_owned()),
            cache_file: cache.map(|c| dir.join(c).to_string_lossy().into_owned().into()),
        }
    }

    fn keys() -> karst_noise::handshake::StaticKeys {
        karst_noise::handshake::StaticKeys::from_seed(&[0x21; 64], &[0x22; 32])
    }

    /// A mistyped pin must stop the daemon at startup with the field name in
    /// the message — not surface later as an authentication failure against a
    /// server that is behaving perfectly.
    #[test]
    fn a_pin_of_the_wrong_length_is_refused_at_startup() {
        let dir = Scratch::new("pins");
        let _ = std::fs::remove_file(dir.join("id.key"));

        let mut short = section(dir.path(), None);
        short.server_verify_pin = encode_hex(&[0x02; 32]);
        match Client::new(&short, dir.path(), &keys()) {
            Err(Error::Key(m)) => assert!(m.contains("server_verify_pin"), "{m}"),
            other => panic!("expected a key error, got {other:?}"),
        }

        let mut short = section(dir.path(), None);
        short.server_kem_pin = encode_hex(&[0x01; 32]);
        match Client::new(&short, dir.path(), &keys()) {
            Err(Error::Key(m)) => assert!(m.contains("server_kem_pin"), "{m}"),
            other => panic!("expected a key error, got {other:?}"),
        }
    }

    /// **The cache must be unreadable without the node's key**, because it
    /// carries a per-pair PSK for every peer (PLAN.md §2.6).
    #[test]
    fn the_cache_round_trips_and_is_not_plaintext() {
        use karst_control_client::transport::pb;

        let dir = Scratch::new("cache");
        let _ = std::fs::remove_file(dir.join("id.key"));
        let _ = std::fs::remove_file(dir.join("netmap.bin"));
        let mut client = Client::new(
            &section(dir.path(), Some("netmap.bin")),
            dir.path(),
            &keys(),
        )
        .expect("client");

        // A netmap with a recognisable PSK.
        let psk = vec![0xAB; 32];
        let mut resp = pb::KarstNetmapResponse {
            psk_epoch: 4,
            node_id: b"self".to_vec(),
            addresses: vec!["100.64.0.1/16".to_owned()],
            dns_name: "self".to_owned(),
            peers: vec![pb::KarstNetmapPeer {
                node_id: b"aaa".to_vec(),
                allowed_ips: vec!["100.64.0.2/32".to_owned()],
                dns_name: "alpha".to_owned(),
                endpoint: String::new(),
                kem_public_key: vec![0x11; 1184],
                dh_public_key: vec![0x12; 32],
                psk: psk.clone(),
                psk_previous: Vec::new(),
                disco_key: vec![0xCD; 32],
            }],
            ..pb::KarstNetmapResponse::default()
        };
        let mut projected = Netmap::new();
        projected.apply(resp.clone()).ok();
        resp.version = projected.content_version();
        client.netmap.apply(resp).expect("apply");

        client.save_cache().expect("save");

        let raw = std::fs::read(dir.join("netmap.bin")).expect("read back");
        assert!(
            !raw.windows(32).any(|w| w == psk.as_slice()),
            "the PSK is on disk in plaintext"
        );

        let mut reloaded = Client::new(
            &section(dir.path(), Some("netmap.bin")),
            dir.path(),
            &keys(),
        )
        .expect("client");
        let outcome = reloaded
            .load_cache()
            .expect("a cache exists")
            .expect("open");
        assert_eq!(outcome, Outcome::Replaced { peers: 1 });
        assert_eq!(reloaded.netmap().version, client.netmap().version);
        assert_eq!(
            reloaded
                .netmap()
                .peer(b"aaa")
                .expect("held")
                .psk
                .as_ref()
                .map(crate::netmap::Psk::as_bytes),
            Some(&[0xAB; 32]),
            "the PSK must survive, or every peer becomes lattice-only after a restart"
        );
    }

    /// A cache written under a different identity must not open. It is bound to
    /// the node's key, so copying one to another machine gains nothing.
    #[test]
    fn a_cache_from_another_node_does_not_open() {
        let dir = Scratch::new("foreign");
        let _ = std::fs::remove_file(dir.join("id.key"));
        let _ = std::fs::remove_file(dir.join("nm.bin"));
        let client =
            Client::new(&section(dir.path(), Some("nm.bin")), dir.path(), &keys()).expect("client");
        client.save_cache().expect("save");

        // A different node: new identity file, same cache.
        let other = Scratch::new("foreign-other");
        let _ = std::fs::remove_file(other.join("id.key"));
        let mut moved = section(other.path(), None);
        moved.cache_file = Some(dir.join("nm.bin"));
        let mut foreign = Client::new(&moved, other.path(), &keys()).expect("client");

        match foreign.load_cache() {
            Some(Err(Error::Cache(_))) => {}
            other => panic!("a foreign cache opened: {other:?}"),
        }
    }

    /// A missing cache is a cold start, which is normal — not an error to be
    /// reported as a failure.
    #[test]
    fn a_missing_cache_is_not_an_error() {
        let dir = Scratch::new("cold");
        let _ = std::fs::remove_file(dir.join("id.key"));
        let _ = std::fs::remove_file(dir.join("absent.bin"));
        let mut client = Client::new(
            &section(dir.path(), Some("absent.bin")),
            dir.path(),
            &keys(),
        )
        .expect("client");
        assert!(
            client.load_cache().is_none(),
            "a cold start is not a failure"
        );
    }

    /// Configured with no cache file, nothing is written — a node that opts out
    /// must not leave PSKs on disk anyway.
    #[test]
    fn no_cache_file_means_nothing_is_written() {
        let dir = Scratch::new("nocache");
        let _ = std::fs::remove_file(dir.join("id.key"));
        let mut client =
            Client::new(&section(dir.path(), None), dir.path(), &keys()).expect("client");
        client.save_cache().expect("a no-op save must succeed");
        assert!(client.load_cache().is_none());
    }

    /// The request kinds are on the wire and shared with the Go server's
    /// `bootstrap.KindLogin` and `KindNetmap`. Changing either breaks every
    /// deployed node.
    #[test]
    fn request_kinds_are_pinned() {
        assert_eq!(KIND_LOGIN, 1);
        assert_eq!(KIND_NETMAP, 2);
    }
}
