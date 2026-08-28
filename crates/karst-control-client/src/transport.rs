// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The gRPC transport for KARST-CONTROL v1.
//!
//! Everything else in this crate is deliberately transport-free — the
//! cryptographic core is pinned against the Go server by vectors and needs no
//! sockets to be correct. This module is the part that opens a connection and
//! drives the bidirectional stream.
//!
//! The protobuf types are generated at build time from **the same `.proto` the
//! Go server compiles**, so there is one definition of the wire format rather
//! than two that must be kept in step by hand.

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel as TonicChannel;
use tonic::Streaming;

use crate::channel::{self, Keys, Record};

/// Generated from `server/shared/management/proto/karst_control.proto`.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::indexing_slicing,
    missing_debug_implementations,
    unreachable_pub
)]
pub mod pb {
    tonic::include_proto!("management");
}

use pb::karst_control_service_client::KarstControlServiceClient;
use pb::{karst_client_message, karst_server_message, KarstClientMessage, KarstEnvelope};

/// Errors from the transport.
#[derive(Debug)]
pub enum Error {
    /// The connection could not be established or was lost.
    Transport(tonic::transport::Error),
    /// The server returned a gRPC status.
    Status(tonic::Status),
    /// The stream ended when a message was expected.
    Closed,
    /// The server sent something out of order — an envelope before the hello,
    /// or a second hello on an established channel.
    Protocol(&'static str),
    /// The record layer or handshake rejected a message.
    Channel(channel::Error),
    /// The server offered a control suite this node will not accept — unknown,
    /// unimplemented, or below the configured floor.
    Suite(String),
    /// The server's hello did not verify against the pinned identity.
    ///
    /// Distinct from [`Error::Channel`] because it means something specific:
    /// either the pin is wrong or something is impersonating the server. It
    /// must never be retried against the same endpoint in the hope it passes.
    ServerAuth,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Status(s) => write!(f, "server returned {}: {}", s.code(), s.message()),
            Self::Closed => f.write_str("the stream closed unexpectedly"),
            Self::Protocol(m) => write!(f, "protocol violation: {m}"),
            Self::Channel(e) => write!(f, "channel: {e}"),
            Self::Suite(m) => write!(f, "control suite: {m}"),
            Self::ServerAuth => {
                f.write_str("the server's hello did not verify against the pinned identity")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<tonic::Status> for Error {
    fn from(s: tonic::Status) -> Self {
        Self::Status(s)
    }
}

/// What a node must be given out of band at enrolment.
///
/// Both halves are required. The KEM key authenticates the server implicitly;
/// the verification key is what makes the per-connection ephemeral
/// trustworthy, and so what makes forward secrecy real. Handing out only the
/// first silently downgrades the channel — see `spec/karst-control-v1.md` §9.
#[derive(Debug, Clone)]
pub struct ServerPins {
    pub static_kem: Vec<u8>,
    pub verify_key: Vec<u8>,
    /// The lowest control suite this node will accept — ADR-0015 item 4.
    ///
    /// Here rather than as a separate argument because it is the same kind of
    /// thing as the two pins: what this node has decided in advance to accept
    /// from its server. `Suite::check_pins` ties all three together, since a
    /// pin's length *is* its algorithm.
    pub minimum_version: u32,
}

/// Randomness for the two encapsulations.
///
/// Supplied by the caller rather than drawn here, matching the rest of this
/// crate: it has no RNG dependency, and a library that quietly picks its own
/// entropy source is one whose behaviour under a seeded or restricted RNG is
/// invisible. Both fields MUST come from a CSPRNG and MUST NOT be reused —
/// repeating either would repeat the corresponding shared secret.
#[derive(Clone)]
pub struct EncapRandomness {
    pub statik: [u8; 32],
    pub ephemeral: [u8; 32],
}

impl core::fmt::Debug for EncapRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncapRandomness(redacted)")
    }
}

impl Drop for EncapRandomness {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.statik.zeroize();
        self.ephemeral.zeroize();
    }
}

/// Signs the handshake with the node's ML-DSA-65 identity.
pub trait Signer {
    /// # Errors
    /// Returns an error if the signing key is unavailable.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>>;
    fn public_key(&self) -> Vec<u8>;
}

/// Verifies the server's hello signature.
pub trait Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// An established control channel.
pub struct Connection {
    tx: mpsc::Sender<KarstClientMessage>,
    rx: Streaming<pb::KarstServerMessage>,
    send: Record,
    recv: Record,
    node_id: Vec<u8>,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("node_id", &String::from_utf8_lossy(&self.node_id))
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Open a channel to `endpoint` and complete the handshake.
    ///
    /// `present_identity` must be true only when registering: a node the server
    /// already knows is looked up by `node_id`, and presenting a key for it
    /// would be an identity substitution attempt rather than a re-registration.
    ///
    /// # Errors
    ///
    /// [`Error::ServerAuth`] if the server's hello does not verify against the
    /// pinned verification key — which means the pin is wrong or something is
    /// impersonating the server, and retrying will not help.
    pub async fn open<S, V>(
        endpoint: String,
        pins: &ServerPins,
        node_id: Vec<u8>,
        signer: &S,
        verifier: &V,
        present_identity: bool,
        randomness: &EncapRandomness,
    ) -> Result<Self, Error>
    where
        S: Signer,
        V: Verifier,
    {
        let channel = TonicChannel::from_shared(endpoint)
            .map_err(|_| Error::Protocol("endpoint is not a valid URI"))?
            .connect()
            .await
            .map_err(Error::Transport)?;
        let mut client = KarstControlServiceClient::new(channel);

        // A modest buffer: the node sends one request at a time and waits, so
        // anything larger only delays discovering that the server has gone.
        let (tx, out_rx) = mpsc::channel::<KarstClientMessage>(8);
        let mut rx = client
            .session(ReceiverStream::new(out_rx))
            .await?
            .into_inner();

        // The server speaks first. That ordering is what makes a captured
        // ChannelInit useless on another connection: the node signs over
        // server_random, which it has not seen until now.
        let hello = match rx.message().await?.and_then(|m| m.msg) {
            Some(karst_server_message::Msg::Hello(h)) => h,
            Some(karst_server_message::Msg::Envelope(_)) => {
                return Err(Error::Protocol("server sent an envelope before its hello"));
            }
            None => return Err(Error::Closed),
        };

        // **The suite the server states, against this node's floor.** Checked
        // before the signature and before any key derivation: if the version is
        // one this node will not accept, nothing it says is worth verifying,
        // and a server must not be able to talk a node down to a weaker suite
        // by offering one (ADR-0015 item 4).
        crate::suite::negotiate(hello.version, pins.minimum_version)
            .map_err(|e| Error::Suite(e.to_string()))?;

        // Verify before deriving keys and before sending anything. Skipping
        // this costs forward secrecy against an attacker holding no key
        // material of their own.
        if !verifier.verify(
            &pins.verify_key,
            &channel::hello_signing_input(&hello.server_random, &hello.eph_kem_pk),
            &hello.signature,
        ) {
            return Err(Error::ServerAuth);
        }

        let (init, keys) =
            build_init(&hello, pins, &node_id, signer, present_identity, randomness)?;
        tx.send(KarstClientMessage {
            msg: Some(karst_client_message::Msg::Init(init)),
        })
        .await
        .map_err(|_| Error::Closed)?;

        Ok(Self {
            tx,
            rx,
            send: Record::new(&keys.c2s),
            recv: Record::new(&keys.s2c),
            node_id,
        })
    }

    /// Send one request and wait for its response.
    ///
    /// # Errors
    ///
    /// [`Error::Channel`] if the response fails to authenticate, which on an
    /// ordered stream means tampering rather than loss.
    pub async fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let (seq, body) = self
            .send
            .seal(&self.node_id, payload)
            .map_err(Error::Channel)?;

        self.tx
            .send(KarstClientMessage {
                msg: Some(karst_client_message::Msg::Envelope(KarstEnvelope {
                    node_id: self.node_id.clone(),
                    body,
                    seq,
                    version: channel::VERSION,
                })),
            })
            .await
            .map_err(|_| Error::Closed)?;

        match self.rx.message().await?.and_then(|m| m.msg) {
            Some(karst_server_message::Msg::Envelope(env)) => self
                .recv
                .open(&env.node_id, env.seq, &env.body)
                .map_err(Error::Channel),
            Some(karst_server_message::Msg::Hello(_)) => Err(Error::Protocol(
                "server sent a second hello on an established channel",
            )),
            None => Err(Error::Closed),
        }
    }
}

/// Builds `ChannelInit` and derives the channel keys.
///
/// Split out so the KEM work is testable without a socket.
fn build_init<S: Signer>(
    hello: &pb::ChannelHello,
    pins: &ServerPins,
    node_id: &[u8],
    signer: &S,
    present_identity: bool,
    randomness: &EncapRandomness,
) -> Result<(pb::ChannelInit, Keys), Error> {
    use karst_crypto::kem::{Kem, MlKem768Backend};

    let static_pk = MlKem768Backend::public_key_from_bytes(&pins.static_kem)
        .ok_or(Error::Protocol("pinned server KEM key is malformed"))?;
    let eph_pk = MlKem768Backend::public_key_from_bytes(&hello.eph_kem_pk)
        .ok_or(Error::Protocol("server ephemeral key is malformed"))?;

    let (ct_static, ss_static) = MlKem768Backend::encapsulate(&static_pk, &randomness.statik);
    let (ct_eph, ss_eph) = MlKem768Backend::encapsulate(&eph_pk, &randomness.ephemeral);

    let signature = signer
        .sign(&channel::init_signing_input(
            &hello.server_random,
            &ct_static,
            &ct_eph,
            node_id,
        ))
        .map_err(|_| Error::Protocol("signing the handshake failed"))?;

    let keys = channel::derive_keys(
        &ss_static,
        &ss_eph,
        &hello.server_random,
        &ct_static,
        &ct_eph,
    )
    .map_err(Error::Channel)?;

    Ok((
        pb::ChannelInit {
            ct_static,
            ct_eph,
            // A node the server already knows must not present a key: that is
            // identity substitution, not re-registration.
            identity_pk: if present_identity {
                signer.public_key()
            } else {
                Vec::new()
            },
            node_id: node_id.to_vec(),
            signature,
            version: channel::VERSION,
        },
        keys,
    ))
}
