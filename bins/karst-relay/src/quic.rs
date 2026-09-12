// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! QUIC as an alternate carrier for the Ponor connection — ADR-0020.
//!
//! This module only ever builds `quinn` configuration and drives its accept
//! loop. Everything past "here is a bidirectional stream" — the Ponor
//! handshake, admission, forwarding — is [`crate::server`]'s, unchanged,
//! because it already only needs `AsyncRead + AsyncWrite`.
//!
//! # Why there is no HTTP upgrade here
//!
//! TCP's Ponor listener negotiates the protocol with an HTTP/1.1
//! `Upgrade: ponor` (`crate::http`) because a bare TCP accept has no
//! negotiation of its own. QUIC does: ALPN is exactly this negotiation,
//! settled inside the TLS handshake before any stream opens, so [`ALPN`]
//! replaces the upgrade rather than sitting on top of it.
//!
//! # Why one stream, and why no adapter type
//!
//! A Ponor connection is one ordered byte stream, on TCP and now on QUIC —
//! ADR-0020 is explicit that per-peer multiplexing is a different, larger
//! change and not this one. `quinn::Connection::accept_bi`/`open_bi` hand
//! back a [`quinn::SendStream`]/[`quinn::RecvStream`] pair rather than one
//! duplex value; [`tokio::io::join`] combines them into a single
//! `AsyncRead + AsyncWrite` type, which is all [`crate::server::Stream`]
//! requires — no bespoke adapter needed.
//!
//! # Who opens the stream
//!
//! A QUIC stream carries no data — and is therefore invisible to the peer's
//! `accept_bi` — until whoever opened it writes to it. Ponor's relay always
//! speaks first (`RelayHandshake` sends `RelayHello` unprompted), so the
//! relay always **opens** the bidirectional stream and the other side always
//! **accepts** it, regardless of which side dialled the QUIC connection.
//! Getting this backwards deadlocks silently: each side waits to read what
//! the other is waiting to be allowed to write.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use karst_relay_proto::consts::{HANDSHAKE_TIMEOUT_SECS, QUIC_ALPN as ALPN};
use karst_relay_proto::{Admitted, Roster as _};

use crate::server::Ctx;

/// One QUIC-carried Ponor connection: a joined send/receive stream pair.
pub type BiStream = tokio::io::Join<quinn::RecvStream, quinn::SendStream>;

/// Errors adapting an already-built `rustls` config for QUIC.
#[derive(Debug)]
pub enum Error {
    /// `rustls` requires TLS 1.3 to derive QUIC's initial keys, which
    /// [`crate::tls::server_config`]/`client_config` already enforce — this
    /// should not occur in practice.
    NoInitialCipherSuite,
    /// The UDP socket could not be bound, or the endpoint could not start.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInitialCipherSuite => f.write_str(
                "quic: the TLS configuration cannot derive QUIC's initial keys; \
                 it must negotiate TLS 1.3",
            ),
            Self::Io(e) => write!(f, "quic: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Build the QUIC listener's server config from the relay's own TLS config.
///
/// The `rustls::ServerConfig` is cloned rather than shared: TCP's listener
/// sets no ALPN (the HTTP upgrade does that job instead), and setting it on
/// the shared config would make the TCP listener negotiate `ponor/1` too,
/// which nothing there expects to see.
///
/// # Errors
/// [`Error::NoInitialCipherSuite`] if the config does not offer TLS 1.3 —
/// `crate::tls::server_config` always does, so this is defensive.
pub fn server_config(tls: &Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, Error> {
    let mut tls = (**tls).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| Error::NoInitialCipherSuite)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_tls)))
}

/// Build a QUIC client config for dialling a mesh peer over QUIC —
/// ADR-0020's mesh dial path.
///
/// # Errors
/// [`Error::NoInitialCipherSuite`], defensively; see [`server_config`].
pub fn client_config(tls: &Arc<rustls::ClientConfig>) -> Result<quinn::ClientConfig, Error> {
    let mut tls = (**tls).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| Error::NoInitialCipherSuite)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
}

/// Bind the relay's QUIC listener.
///
/// # Errors
/// [`Error::Io`] if the UDP socket cannot be bound.
pub fn bind(addr: SocketAddr, config: quinn::ServerConfig) -> Result<quinn::Endpoint, Error> {
    quinn::Endpoint::server(config, addr).map_err(Error::Io)
}

/// Run the QUIC accept loop until the endpoint closes or the process is asked
/// to stop.
///
/// Mirrors `server::serve_on`'s shape: accept, spawn, and one `ctrl_c` arm.
/// `tokio::signal::ctrl_c` may be awaited from more than one task — each
/// completes independently — so this listener shuts down on the same signal
/// as the TCP one without the two coordinating.
pub async fn serve_on(endpoint: quinn::Endpoint, ctx: Arc<Ctx>) {
    let Ok(addr) = endpoint.local_addr() else {
        return;
    };
    eprintln!(
        "karst-relay: listening (quic) on {addr} (relay_id {})",
        crate::server::hex(&ctx.identity.relay_id())
    );
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    // The endpoint was closed — process shutdown.
                    return;
                };
                let ctx = Arc::clone(&ctx);
                tokio::spawn(Box::pin(async move { serve(incoming, ctx).await }));
            }
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    eprintln!("karst-relay: shutting down (quic)");
                }
                return;
            }
        }
    }
}

async fn serve(incoming: quinn::Incoming, ctx: Arc<Ctx>) {
    let deadline = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let Ok(Some((stream, buf, admitted, peer))) =
        tokio::time::timeout(deadline, establish(incoming, &ctx)).await
    else {
        return;
    };
    crate::server::after_established(stream, buf, admitted, peer, ctx).await;
}

/// The QUIC handshake, the first bidirectional stream, and the Ponor
/// handshake. Every failure is a silent close — §10, same as the TCP path.
async fn establish(
    incoming: quinn::Incoming,
    ctx: &Arc<Ctx>,
) -> Option<(BiStream, Vec<u8>, Admitted, SocketAddr)> {
    let connection = incoming.await.ok()?;
    let peer = connection.remote_address();
    // The relay opens the stream, not the peer: `RelayHandshake` speaks
    // first (`establish_ponor` below), and a QUIC stream carries no data —
    // so is invisible to the other side's `accept_bi` — until its opener
    // writes to it. Accepting here would deadlock waiting for a write the
    // peer is waiting on us to make first.
    let (send, recv) = connection.open_bi().await.ok()?;
    let stream = tokio::io::join(recv, send);
    let (stream, buf, admitted) = crate::server::establish_ponor(stream, ctx, Vec::new()).await?;
    Some((stream, buf, admitted, peer))
}

/// Dial a mesh peer over QUIC — ADR-0020, the QUIC counterpart of
/// `server::dial_mesh`.
///
/// # Errors
/// Any QUIC, framing, or Ponor authentication failure. The caller discards
/// the connection and retries with backoff, exactly as the TCP dial does.
pub async fn dial_mesh(
    ctx: &Arc<Ctx>,
    client_config: &quinn::ClientConfig,
    peer_id: crate::mesh::Id,
    addr: &str,
    name: &str,
) -> Result<(), String> {
    let entry = ctx
        .roster()
        .mesh_peer(&peer_id)
        .ok_or_else(|| "peer is not in the roster".to_owned())?;

    let socket_addr: SocketAddr = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("resolve: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr} resolved to no address"))?;

    let mut endpoint =
        quinn::Endpoint::client(unspecified_like(socket_addr)).map_err(|e| format!("bind: {e}"))?;
    endpoint.set_default_client_config(client_config.clone());

    let connection = endpoint
        .connect(socket_addr, name)
        .map_err(|e| format!("connect: {e}"))?
        .await
        .map_err(|e| format!("quic: {e}"))?;
    let remote = connection.remote_address();

    // The dialled relay speaks first here too — it runs `RelayHandshake`
    // regardless of which side dialled — so this side accepts the stream the
    // same way a node accepts one from a relay it dialled over TCP.
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| format!("accept_bi: {e}"))?;
    let mut stream = tokio::io::join(recv, send);

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| format!("no entropy: {e}"))?;
    let mut client = karst_relay_proto::ClientHandshake::new(
        karst_relay_proto::Role::Mesh,
        ctx.identity.relay_id(),
        peer_id,
        entry.identity_pk.clone(),
        nonce,
    );

    let mut buf = Vec::new();
    let hello = crate::server::next_frame(&mut stream, &mut buf).await?;
    let (hello, _) = karst_relay_proto::frame::decode(&hello)
        .map_err(|e| format!("hello: {e:?}"))?
        .ok_or_else(|| "hello incomplete".to_owned())?;
    let auth = client
        .on_relay_hello(&hello, ctx.identity.as_ref())
        .map_err(|e| format!("sign: {e:?}"))?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &auth)
        .await
        .map_err(|e| format!("auth: {e}"))?;

    let reply = crate::server::next_frame(&mut stream, &mut buf).await?;
    let (reply, _) = karst_relay_proto::frame::decode(&reply)
        .map_err(|e| format!("relay auth: {e:?}"))?
        .ok_or_else(|| "relay auth incomplete".to_owned())?;
    client
        .on_relay_auth(&reply, &crate::sign::PonorVerifier)
        .map_err(|e| format!("verify: {e:?}"))?;
    if !client.may_send() {
        return Err("handshake did not establish".to_owned());
    }

    eprintln!("karst-relay: meshed with {addr} (quic)");
    crate::server::drive(
        stream,
        buf,
        Admitted::Mesh { relay_id: peer_id },
        remote,
        Arc::clone(ctx),
    )
    .await;
    Ok(())
}

/// `quinn::Endpoint::client` needs a local bind address of the same family as
/// what it will dial. `connect`'s target decides the family; there is no
/// address to reuse from, since the endpoint does not exist yet.
fn unspecified_like(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    }
}
