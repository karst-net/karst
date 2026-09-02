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

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
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

/// What a node must be given out of band at enrollment.
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
/// entropy source is one whose behavior under a seeded or restricted RNG is
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

/// The decrypted payload that marks an unprompted server push rather than a
/// reply — `spec/karst-control-v1.md` §5.3.1, FINDINGS.md 67/68.
///
/// Lives here, not alongside `karstd`'s `KIND_LOGIN`/`KIND_NETMAP`/
/// `KIND_BEDROCK` request kinds, because [`Connection::open`] is the one place
/// that has to know it: everything else those three kinds select between is
/// opaque to this crate. The Go side cannot share a Rust constant across the
/// language boundary and duplicates the value instead (`bootstrap.go`,
/// `testserver/netmap.go`); this crate and every one of its Rust callers can,
/// so `control.rs` imports this rather than keeping its own copy.
pub const KIND_PUSH: u8 = 4;

/// An established control channel.
///
/// Held open across many [`request`](Connection::request) calls rather than
/// being opened and dropped per request (FINDINGS.md 67/68): a connection
/// that closes the instant its caller is done with it gives the server
/// nothing to push a deprovisioning notice *to* between polls. A background
/// task owns the read half for exactly this reason — it has to keep reading
/// even while nothing is waiting on a reply, or an unprompted push arriving
/// between requests is silently dropped on the floor.
pub struct Connection {
    tx: mpsc::Sender<KarstClientMessage>,
    send: Record,
    node_id: Vec<u8>,
    /// Answers to requests this connection has sent, one per `request()` call.
    /// Never carries a push — the reader task diverts those to `pushed`
    /// instead, since nothing is waiting on them the way a request's caller
    /// is.
    responses: mpsc::Receiver<Result<Vec<u8>, Error>>,
    /// Signaled by the reader task whenever it decodes a push envelope. A
    /// [`Notify`] rather than a channel: a push carries nothing to queue, and
    /// coalescing a burst of them into "at least one refresh is due" is
    /// exactly the semantics the caller wants.
    pushed: Arc<Notify>,
    /// Aborted on drop — see the `Drop` impl below.
    reader: tokio::task::JoinHandle<()>,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("node_id", &String::from_utf8_lossy(&self.node_id))
            .finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Dropping `tx` also drops the outbound half of the gRPC stream, which
        // should eventually make the reader's `rx.message()` return on its
        // own — but "eventually" is not "now", and a background task reading
        // a stream nothing else references is a leak until it does. Abort it
        // explicitly rather than wait it out.
        self.reader.abort();
    }
}

impl Connection {
    /// Open a channel to `endpoint` and complete the handshake.
    ///
    /// `present_identity` must be true only when registering: a node the server
    /// already knows is looked up by `node_id`, and presenting a key for it
    /// would be an identity substitution attempt rather than a re-registration.
    ///
    /// `push_marker` is the one-byte decrypted payload that means "this
    /// envelope is an unprompted push, not a reply" (`spec/karst-control-v1.md`
    /// §5.3.1) — a plain byte rather than a classifier closure, so this module
    /// stays free of the request-kind numbering `control.rs` owns; it only
    /// needs to recognize the one reserved value, never interpret the rest.
    ///
    /// `pushed` is supplied rather than created here so a caller that
    /// reconnects — the whole point of holding one `Connection` across many
    /// requests — can keep selecting on the same `Notify` across the
    /// reconnect instead of having to notice a new one exists each time.
    ///
    /// # Errors
    ///
    /// [`Error::ServerAuth`] if the server's hello does not verify against the
    /// pinned verification key — which means the pin is wrong or something is
    /// impersonating the server, and retrying will not help.
    #[allow(clippy::too_many_arguments)]
    pub async fn open<S, V>(
        endpoint: String,
        pins: &ServerPins,
        node_id: Vec<u8>,
        signer: &S,
        verifier: &V,
        present_identity: bool,
        randomness: &EncapRandomness,
        push_marker: u8,
        pushed: Arc<Notify>,
    ) -> Result<Self, Error>
    where
        S: Signer,
        V: Verifier,
    {
        let channel = TonicChannel::from_shared(endpoint)
            .map_err(|_| Error::Protocol("endpoint is not a valid URI"))?
            // A held-open connection needs its own keepalive: nothing else on
            // this stream is periodic once a push can make a poll arrive late,
            // so an idle NAT or load balancer timeout is otherwise indistin-
            // guishable from the server having gone away. Configuring tonic's
            // built-in HTTP/2 ping is the whole fix — no application-level
            // ping message is needed on top of it.
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
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

        // Capacity 1: at most one reply is ever outstanding, because the
        // caller never issues a second `request()` before the first returns.
        // A push never enters this channel at all — see `read_loop`.
        let (responses_tx, responses) = mpsc::channel(1);
        let reader = tokio::spawn(read_loop(
            rx,
            Record::new(&keys.s2c),
            push_marker,
            responses_tx,
            Arc::clone(&pushed),
        ));

        Ok(Self {
            tx,
            send: Record::new(&keys.c2s),
            node_id,
            responses,
            pushed,
            reader,
        })
    }

    /// Adopt a server-assigned handle once registration completes.
    ///
    /// A connection opened to register carries no handle at all
    /// (`spec/karst-control-v1.md` §5.3: `KarstEnvelope.node_id` is "empty
    /// only on the very first ... of a registration, before an ID exists"),
    /// which was fine when a connection was single-use — the fresh one the
    /// next sync opened already knew it. A connection now held open across
    /// many requests would otherwise keep tagging every envelope on it with
    /// an empty handle forever, since nothing else here ever revisits
    /// `node_id` after `open`. The caller is expected to call this exactly
    /// once, immediately after a login response assigns a handle.
    pub fn set_node_id(&mut self, node_id: Vec<u8>) {
        self.node_id = node_id;
    }

    /// Send one request and wait for its response.
    ///
    /// A push that arrives while this is waiting never satisfies it — the
    /// reader task diverts pushes to the signal [`push_signal`](Self::push_signal)
    /// exposes and keeps reading, so this always resolves with the actual
    /// reply to `payload`.
    ///
    /// # Errors
    ///
    /// [`Error::Channel`] if the response fails to authenticate, which on an
    /// ordered stream means tampering rather than loss. [`Error::Closed`] if
    /// the reader task ended first, which after the first error it reports is
    /// permanent — open a new `Connection`.
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

        self.responses.recv().await.ok_or(Error::Closed)?
    }

    /// A signal the reader task notifies whenever it decodes an unprompted
    /// push. Cloned rather than borrowed so the caller can hold it across a
    /// `select!` without also holding `&Connection` — `request` needs `&mut
    /// self` and a live borrow here would make the two mutually exclusive.
    #[must_use]
    pub fn push_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.pushed)
    }
}

/// Reads server messages for the lifetime of one [`Connection`], routing each
/// decrypted envelope to whichever of `responses`/`pushed` it belongs to.
///
/// Split out of `request` because it must keep running between requests, not
/// only during one — that is the entire fix FINDINGS.md 68 asked for: a
/// connection that only reads while a request is outstanding has nothing
/// listening in the gap a push needs to land in.
async fn read_loop(
    mut rx: Streaming<pb::KarstServerMessage>,
    mut recv: Record,
    push_marker: u8,
    responses: mpsc::Sender<Result<Vec<u8>, Error>>,
    pushed: Arc<Notify>,
) {
    loop {
        let msg = match rx.message().await {
            Ok(Some(m)) => m,
            Ok(None) => {
                let _ = responses.send(Err(Error::Closed)).await;
                return;
            }
            Err(status) => {
                let _ = responses.send(Err(Error::Status(status))).await;
                return;
            }
        };
        match msg.msg {
            Some(karst_server_message::Msg::Envelope(env)) => {
                match recv.open(&env.node_id, env.seq, &env.body) {
                    // A push is exactly one byte, the reserved marker, and
                    // carries nothing else to trust (spec §5.3.1) — anything
                    // else is a reply some `request()` call is waiting on.
                    Ok(payload) if payload == [push_marker] => {
                        pushed.notify_one();
                    }
                    Ok(payload) => {
                        if responses.send(Ok(payload)).await.is_err() {
                            return; // the Connection was dropped
                        }
                    }
                    Err(e) => {
                        // Not a lost packet — the stream is ordered and
                        // authenticated, so this means tampering or a bug.
                        // Same call as the pre-persistent-connection code:
                        // end the channel rather than try to recover it.
                        let _ = responses.send(Err(Error::Channel(e))).await;
                        return;
                    }
                }
            }
            Some(karst_server_message::Msg::Hello(_)) => {
                let _ = responses
                    .send(Err(Error::Protocol(
                        "server sent a second hello on an established channel",
                    )))
                    .await;
                return;
            }
            None => {
                let _ = responses
                    .send(Err(Error::Protocol("empty server message")))
                    .await;
                return;
            }
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
