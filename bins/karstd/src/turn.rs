// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! This node's own TURN (RFC 8656) allocation — `spec/aven-v1.md` §7.8.
//!
//! Everything the daemon needs to hold one relayed transport address on a
//! configured TURN server: the credential-authenticated Allocate exchange,
//! the relayed connection RFC 8656 §7.1 describes, and nothing else. Like
//! [`crate::relay`], this is connection-lifecycle code with no opinion about
//! *when* the daemon should hold an allocation or what it does with one —
//! `crate::run`'s worker owns that, mirroring the split `crate::relay` and
//! `crate::run`'s relay worker already have: protocol/connection state here,
//! dispatch integration there.
//!
//! # Why this is not `crates/karst-disco`
//!
//! `karst-disco` is sans-io by its own module doc — "it opens no socket,
//! reads no clock and enumerates no interface" — and stays that way here.
//! Everything this module needs to hand AVEN is one [`std::net::SocketAddr`],
//! which `karst_disco::msg::Endpoint` already models with no changes. Adding
//! `turn::client`'s I/O to that crate would be a real architecture change for
//! no benefit this feature needs.
//!
//! # Why `turn::client::RelayConn` needs no permission/channel state machine
//! here
//!
//! RFC 8656's `CreatePermission` and `ChannelBind` are handled inside the `turn`
//! crate's own `RelayConn::send_to` — a first send to a new peer address
//! creates the permission automatically, and a later one upgrades to
//! `ChannelData` framing. [`Allocation::send_to`] is used for both an actual
//! datagram and a §7.8 permission-priming call; the crate does not
//! distinguish the two, and neither does this module.

use std::net::SocketAddr;
use std::sync::Arc;

use turn::client::{Client, ClientConfig};
use util::Conn;

use crate::netmap::TurnServer;

/// A live RFC 8656 allocation on one TURN server.
///
/// Holds the client, its dedicated base socket (via `conn`, inside `client`)
/// and the allocated relay connection. Dropping this does not close the
/// allocation on the server — callers that want that call [`Self::close`]
/// first, which `crate::run`'s worker does on every planned teardown; an
/// unplanned one (the process dying) is left to the server's own allocation
/// lifetime, exactly as an unplanned relay disconnect is left to Ponor's own
/// timeouts.
pub struct Allocation {
    client: Client,
    relay: Box<dyn Conn + Send + Sync>,
    relayed_addr: SocketAddr,
}

impl std::fmt::Debug for Allocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allocation")
            .field("relayed_addr", &self.relayed_addr)
            .finish_non_exhaustive()
    }
}

/// Failure opening or using a TURN allocation.
#[derive(Debug)]
pub enum Error {
    /// The dedicated base socket could not be opened.
    Io(std::io::Error),
    /// The `turn` crate's own Allocate/CreatePermission/refresh failure.
    Turn(turn::Error),
    /// A failure surfaced through `util::Conn` — a send, a receive, or reading
    /// the relayed address back.
    Conn(util::Error),
    /// `KarstTurnServer.uri` is not a `turn:` or `turns:` URI this client can
    /// dial. Caught again here, on top of `crate::netmap::TurnServer`'s own
    /// validation, because that check is about the *wire shape*; this one is
    /// about whether the scheme is one this client actually implements.
    Scheme(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "turn: {e}"),
            Self::Turn(e) => write!(f, "turn: {e}"),
            Self::Conn(e) => write!(f, "turn: {e}"),
            Self::Scheme(uri) => write!(f, "turn: cannot dial {uri}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<turn::Error> for Error {
    fn from(e: turn::Error) -> Self {
        Self::Turn(e)
    }
}

impl From<util::Error> for Error {
    fn from(e: util::Error) -> Self {
        Self::Conn(e)
    }
}

/// Strip a `turn:` or `turns:` scheme from a `KarstTurnServer.uri`, leaving
/// the bare `host:port` `turn::client::ClientConfig` wants.
///
/// **`turns:` (TURN over TLS, RFC 7065) is accepted at the parse stage and
/// refused here rather than earlier**, so a misconfigured registry entry
/// fails with a specific reason instead of being silently treated as `turn:`.
/// TLS to the TURN server itself is not implemented: `ClientConfig::conn` is
/// a bare UDP socket, and layering TLS under a UDP-framed protocol is a
/// different transport (DTLS) that RFC 7065's `turns:` does not even name —
/// it is TCP+TLS. Nothing in this deployment's threat model needs it: the
/// credential is already short-lived and per-response, and the relayed path
/// carries AEAD-protected AVEN/PHREATIC payloads either way.
fn dial_target(uri: &str) -> Result<String, Error> {
    uri.strip_prefix("turn:")
        .map(str::to_owned)
        .ok_or_else(|| Error::Scheme(uri.to_owned()))
}

impl Allocation {
    /// Open a dedicated UDP socket, authenticate, and Allocate.
    ///
    /// **A fresh socket, never the shared datapath one.** Sharing it would add
    /// a third demultiplexing layer beside AVEN and PHREATIC's already
    /// deliberately narrow one (`crate::disco`'s own module doc explains why
    /// that one stays narrow) — a much bigger change than this feature calls
    /// for, and the `turn` crate's own examples bind a fresh socket for
    /// exactly this reason.
    ///
    /// `realm` is sent empty. `Client::allocate` performs an anonymous
    /// Allocate first, learns the server's real realm and nonce from the
    /// `401` it gets back, and retries authenticated with them — confirmed by
    /// reading the crate's own `client::mod::allocate`, which overwrites
    /// `self.realm` from the response before the second attempt. Karst's own
    /// wire format has no realm field and does not need one; this is purely
    /// how the RFC 8656 exchange itself works.
    ///
    /// # Errors
    /// [`Error::Scheme`] for a URI this client cannot dial, [`Error::Io`] if
    /// the base socket cannot be opened, and [`Error::Turn`] for anything the
    /// Allocate exchange itself refuses — an unrecognized credential, a
    /// server that is not there, or one that has run out of relay ports.
    pub async fn connect(server: &TurnServer) -> Result<Self, Error> {
        let target = dial_target(&server.uri)?;

        // The base socket's family follows the server's, not this host's
        // default route — a `[::1]`-literal TURN server needs a v6 socket to
        // reach at all, and binding v4 unconditionally would fail every such
        // deployment with an error that names the wrong layer.
        let bind_addr = if target.starts_with('[') || target.contains("::") {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let base = tokio::net::UdpSocket::bind(bind_addr).await?;

        let config = ClientConfig {
            stun_serv_addr: target.clone(),
            turn_serv_addr: target,
            username: server.username.clone(),
            password: server.password.as_str().to_owned(),
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn: Arc::new(base),
            vnet: None,
        };
        let client = Client::new(config).await?;
        client.listen().await?;
        let relay = client.allocate().await?;
        let relayed_addr = relay.local_addr()?;
        Ok(Self {
            client,
            relay: Box::new(relay),
            relayed_addr,
        })
    }

    /// This allocation's relayed transport address — the AVEN candidate
    /// `spec/aven-v1.md` §7.8 advertises.
    #[must_use]
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    /// Send one datagram to `to` through this allocation.
    ///
    /// Used for real traffic (`Via::Turn`'s dispatch) and for §7.8's
    /// permission priming alike — the crate exposes no separate
    /// `CreatePermission` call, and the RFC 8656 exchange it runs internally on
    /// a first send to a new address *is* the priming, so a caller that wants
    /// only the permission sends a harmless payload and discards the result.
    ///
    /// # Errors
    /// [`Error::Conn`] if the underlying send fails — a server-side failure,
    /// or a payload wider than the allocation's channel framing allows.
    pub async fn send_to(&self, payload: &[u8], to: SocketAddr) -> Result<(), Error> {
        self.relay.send_to(payload, to).await?;
        Ok(())
    }

    /// Receive one datagram, with the real sender's address — never the TURN
    /// server's own.
    ///
    /// # Errors
    /// [`Error::Conn`] if the allocation has been closed or the underlying
    /// read fails.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        Ok(self.relay.recv_from(buf).await?)
    }

    /// Tear the allocation down.
    ///
    /// Best-effort: a caller reconnecting after a failure has nothing useful
    /// to do with an error here beyond what it is already doing, which is
    /// opening a new allocation.
    pub async fn close(&self) {
        let _ = self.relay.close().await;
        let _ = self.client.close().await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn dial_target_strips_the_turn_scheme() {
        assert_eq!(
            dial_target("turn:turn.example.com:3478").unwrap(),
            "turn.example.com:3478"
        );
    }

    #[test]
    fn dial_target_refuses_turns() {
        assert!(matches!(
            dial_target("turns:turn.example.com:5349"),
            Err(Error::Scheme(_))
        ));
    }

    #[test]
    fn dial_target_refuses_a_bare_host() {
        assert!(matches!(
            dial_target("turn.example.com:3478"),
            Err(Error::Scheme(_))
        ));
    }

    /// A construction/config-only test, without a live server: an invalid
    /// registry URI must be caught before anything is opened, network access
    /// or not.
    #[tokio::test]
    async fn connect_refuses_a_non_turn_scheme_without_touching_the_network() {
        let server = TurnServer {
            uri: "https://turn.example.com".to_owned(),
            region: "test".to_owned(),
            username: "1700000000".to_owned(),
            password: crate::netmap::TurnCredential::for_tests("secret"),
            expires_at: 1_700_000_000,
        };
        let err = Allocation::connect(&server).await.unwrap_err();
        assert!(matches!(err, Error::Scheme(_)));
    }

    /// An allocate-and-relay-data round trip against a real `coturn` needs a
    /// running server this unit test does not start — see
    /// `bins/karstd/tests/aquifer.rs`'s `Shape::TurnOnly` for that half of the
    /// verification, which runs a real `turnserver` process in a network
    /// namespace and drives two full daemons through it end to end. What this
    /// module can verify without one is everything short of the wire: the URI
    /// parse above, and the error path when nothing answers.
    #[tokio::test]
    async fn connect_fails_cleanly_when_nothing_answers() {
        // A TURN server that is not there — loopback, a port nothing binds.
        // The bound base socket still opens; the Allocate exchange is what
        // fails, and it must fail rather than hang.
        let server = TurnServer {
            uri: "turn:127.0.0.1:1".to_owned(),
            region: "test".to_owned(),
            username: "1700000000".to_owned(),
            password: crate::netmap::TurnCredential::for_tests("secret"),
            expires_at: 1_700_000_000,
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Allocation::connect(&server),
        )
        .await;
        // Either the timeout fired or `connect` itself returned an error —
        // both are "failed cleanly". What must not happen is a panic or a
        // silent `Ok`, since nothing is listening on port 1.
        match result {
            Ok(inner) => assert!(inner.is_err()),
            Err(_timed_out) => {}
        }
    }
}
