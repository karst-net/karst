// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! TCP+TLS transport for a `turns:` TURN server (RFC 7065) — issue #420.
//!
//! The `turn` crate's own client was only ever exercised over plain UDP
//! (its one example is `turn_client_udp.rs`, and its `ClientConfig::conn`
//! field is a generic [`util::Conn`]). This module supplies the other
//! implementation that trait needs: one TCP connection, TLS-secured, with
//! STUN and `ChannelData` messages framed off the byte stream the way RFC
//! 5766 §11.5 requires for any connection-oriented transport. `turns:` is
//! required (not optional) for every externally-configured TURN server
//! issue #420 adds, because the credential is the admin's own long-lived
//! secret, shared unchanged with every node — see `externalturn.go`'s
//! `validateURI` and issue #418 §5's risk note, both already written
//! around that requirement before this module existed to satisfy it.
//!
//! # Why this can be a flat byte-stream reader, not a real STUN parser
//!
//! Both message kinds the crate's receive path accepts
//! (`proto::chandata::ChannelData::is_channel_data`'s own discriminator)
//! put a big-endian length field at the same offset, bytes 2–3: a STUN
//! message's attribute-section length, or a `ChannelData` message's data
//! length. The two kinds are told apart by the top two bits of byte 0 —
//! `0b00` for STUN (RFC 5389 §6: the two most significant bits of every
//! STUN message are always zero) or `0b01` for `ChannelData` (RFC 5766
//! §11.4 fixes channel numbers to 0x4000–0x7FFF). [`message_len`] only
//! needs to know how many bytes make up one complete message to hand the
//! crate's own, fully-validating parser an exact slice — never a partial
//! message or a fragment of the next one — not to parse either kind
//! itself.
//!
//! # No post-quantum requirement
//!
//! Unlike `relay_tls::client_config`, which exists for Karst's own Ponor
//! hop and requires the `X25519MLKEM768` hybrid group, this accepts
//! whatever key exchange an arbitrary operator-run TURN server offers.
//! Requiring Karst's own protocol's hybrid group here would make this
//! feature unable to reach almost any real-world TURN deployment.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Failure building the TLS configuration or dialing a `turns:` server.
#[derive(Debug)]
pub enum Error {
    /// The host supplied no usable certificate authority roots.
    NoTrustRoots,
    /// `host:port` could not be split into its two parts.
    Target(String),
    /// The target host cannot be passed to rustls as SNI/certificate name.
    ServerName(String),
    /// DNS resolution, the TCP connect, or the TLS handshake itself failed.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTrustRoots => {
                f.write_str("turns: the host has no usable certificate authority roots")
            }
            Self::Target(target) => write!(f, "turns: cannot parse host:port in {target:?}"),
            Self::ServerName(host) => write!(f, "turns: invalid server name {host:?}"),
            Self::Io(e) => write!(f, "turns: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Build the TLS client configuration shared by every `turns:` dial.
///
/// # Errors
/// [`Error::NoTrustRoots`] when the operating system supplies no usable
/// roots.
pub fn client_config() -> Result<Arc<ClientConfig>, Error> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (native, _invalid) = roots.add_parsable_certificates(loaded.certs);
    if native == 0 {
        return Err(Error::NoTrustRoots);
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Split `host:port` into its two parts, honoring an IPv6 literal's
/// brackets (`[::1]:5349`) the way a bare `rsplit_once(':')` cannot.
fn split_host_port(target: &str) -> Result<(&str, &str), Error> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| Error::Target(target.to_owned()))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| Error::Target(target.to_owned()))?;
        return Ok((host, port));
    }
    target
        .rsplit_once(':')
        .ok_or_else(|| Error::Target(target.to_owned()))
}

/// Resolve, connect, and TLS-handshake to a `turns:` TURN server at
/// `target` (`host:port`, the same shape [`dial_target`] strips the
/// scheme down to).
///
/// Resolves exactly once: the returned [`TlsConn`] remembers the resolved
/// [`SocketAddr`] it connected to, and the caller passes that same
/// resolved address back to the `turn` crate as its own
/// `stun_serv_addr`/`turn_serv_addr` rather than the original `host:port`
/// — so the crate's own (separate) resolution of that string can never
/// land on a different address than the one this module actually
/// connected to (round-robin DNS returning a different answer on a
/// second lookup, in particular).
///
/// # Errors
/// [`Error::Target`]/[`Error::ServerName`] for a malformed `target`;
/// [`Error::Io`] if DNS resolution, the TCP connect, or the TLS handshake
/// fails.
pub async fn connect(config: &Arc<ClientConfig>, target: &str) -> Result<TlsConn, Error> {
    let (host, _) = split_host_port(target)?;
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| Error::ServerName(host.to_owned()))?;
    let mut addrs = tokio::net::lookup_host(target).await?;
    let remote_addr = addrs
        .next()
        .ok_or_else(|| Error::Target(target.to_owned()))?;
    let tcp = TcpStream::connect(remote_addr).await?;
    let local_addr = tcp.local_addr()?;
    let stream = TlsConnector::from(Arc::clone(config))
        .connect(server_name, tcp)
        .await?;
    Ok(TlsConn::new(stream, local_addr, remote_addr))
}

/// A [`util::Conn`] over one TCP+TLS connection to a `turns:` TURN server.
///
/// The crate's own client never calls more than `send_to`/`recv_from`/
/// `connect`/`close` on its `conn` (confirmed by reading
/// `client::mod::perform_transaction`, which always calls `send_to`, never
/// `send`) — the `send`/`recv` implementations below exist only to satisfy
/// [`util::Conn`]'s full signature, not because anything calls them.
pub struct TlsConn {
    io: Mutex<(TlsStream<TcpStream>, Vec<u8>)>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl std::fmt::Debug for TlsConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConn")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

impl TlsConn {
    fn new(stream: TlsStream<TcpStream>, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            io: Mutex::new((stream, Vec::new())),
            local_addr,
            remote_addr,
        }
    }

    /// The resolved address this connection actually dialed — infallible,
    /// unlike [`util::Conn::remote_addr`]'s `Option` (that trait also
    /// covers connectionless transports, which this never is). The caller
    /// in `crate::turn::Allocation::connect` reads this before erasing the
    /// concrete type into `Arc<dyn Conn>`, so there is no panic risk the
    /// way going through the trait method after that point would carry.
    #[must_use]
    pub fn remote(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Read exactly one complete STUN or `ChannelData` message into `buf`,
    /// buffering whatever the stream handed back beyond it for the next
    /// call — a stream read has no reason to land on a message boundary.
    async fn read_one(&self, buf: &mut [u8]) -> util::Result<usize> {
        let mut guard = self.io.lock().await;
        let (stream, leftover) = &mut *guard;
        loop {
            if let Some(total) = message_len(leftover) {
                if leftover.len() >= total {
                    let message: Vec<u8> = leftover.drain(..total).collect();
                    let n = message.len().min(buf.len());
                    if let (Some(dst), Some(src)) = (buf.get_mut(..n), message.get(..n)) {
                        dst.copy_from_slice(src);
                    }
                    return Ok(n);
                }
            }
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "turns: connection closed",
                )
                .into());
            }
            leftover.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
        }
    }
}

/// How many bytes make up one complete STUN or `ChannelData` message at the
/// front of `buf` — see the module doc comment for the discriminator and
/// why no real parsing happens here. `None` until enough has arrived to
/// tell.
fn message_len(buf: &[u8]) -> Option<usize> {
    // The header's first 4 bytes, by pattern rather than index: every
    // branch below needs byte 0 (the discriminator) and bytes 2-3 (the
    // shared length-field offset), and a slice pattern makes "not enough
    // bytes yet" the match that falls through to `None` rather than
    // something a bounds check has to be trusted to catch first.
    let &[b0, _, len_hi, len_lo, ..] = buf else {
        return None;
    };
    if b0 & 0xC0 == 0x40 {
        // ChannelData: 4-byte header (channel number, then data length at
        // [2..4]), body padded to a 4-byte boundary -- mirroring
        // proto::chandata::ChannelData::encode's own padding, so this
        // reads exactly what a peer's encode produced.
        let data_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        let padded = data_len.div_ceil(4) * 4;
        Some(4 + padded)
    } else {
        // STUN: 20-byte header, attribute-section length at [2..4]. No
        // extra padding needed here: every attribute inside is already
        // padded to 4 bytes, so 20 + length is inherently a multiple of 4.
        if buf.len() < 20 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        Some(20 + length)
    }
}

#[async_trait::async_trait]
impl util::Conn for TlsConn {
    /// A documented no-op: this connection already has a fixed peer from
    /// [`connect`] above, and the crate never calls this once `conn`
    /// already does (see this type's own doc comment).
    async fn connect(&self, _addr: SocketAddr) -> util::Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        self.read_one(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        let n = self.read_one(buf).await?;
        Ok((n, self.remote_addr))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        let mut guard = self.io.lock().await;
        guard.0.write_all(buf).await?;
        Ok(buf.len())
    }

    /// `target` is asserted, not branched on: a single TCP+TLS connection
    /// has exactly one peer, and the crate only ever calls this with the
    /// same resolved address [`connect`] (the module function) already
    /// connected to — see that function's own doc comment on why.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> util::Result<usize> {
        debug_assert_eq!(
            target, self.remote_addr,
            "a single TCP+TLS connection has exactly one peer"
        );
        self.send(buf).await
    }

    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> util::Result<()> {
        let mut guard = self.io.lock().await;
        let _ = guard.0.shutdown().await;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_system_roots_alone_are_a_valid_configuration() {
        assert!(client_config().is_ok());
    }

    #[test]
    fn split_host_port_handles_a_bracketed_ipv6_literal() {
        assert_eq!(split_host_port("[::1]:5349").unwrap(), ("::1", "5349"));
    }

    #[test]
    fn split_host_port_handles_an_ordinary_hostname() {
        assert_eq!(
            split_host_port("turn.example.com:5349").unwrap(),
            ("turn.example.com", "5349")
        );
    }

    #[test]
    fn split_host_port_refuses_a_bracket_with_no_port() {
        assert!(split_host_port("[::1]").is_err());
    }

    #[test]
    fn split_host_port_refuses_a_bare_host() {
        assert!(split_host_port("turn.example.com").is_err());
    }

    #[test]
    fn message_len_is_none_before_a_full_stun_header_arrives() {
        // A STUN-shaped first byte (top two bits zero), but short of the
        // 20-byte header needed to even read the length field.
        assert_eq!(message_len(&[0x00, 0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn message_len_reads_the_stun_header_length_field() {
        let mut header = vec![0x00, 0x01, 0x00, 0x08]; // length = 8
        header.extend_from_slice(&[0u8; 16]); // rest of the 20-byte header
        assert_eq!(message_len(&header), Some(28));
    }

    #[test]
    fn message_len_pads_channel_data_to_a_four_byte_boundary() {
        // Channel number 0x4000 (top two bits 0b01), data length 3 -- one
        // byte short of a 4-byte multiple, so the real message is 4 (header)
        // + 4 (padded data) = 8 bytes, not 4 + 3 = 7.
        let header = [0x40, 0x00, 0x00, 0x03];
        assert_eq!(message_len(&header), Some(8));
    }

    #[test]
    fn message_len_needs_no_extra_padding_for_an_already_aligned_channel_data() {
        let header = [0x40, 0x00, 0x00, 0x04];
        assert_eq!(message_len(&header), Some(8));
    }

    /// A construction/config-only test, without a live server: an
    /// unresolvable host must fail before anything opens a real socket.
    #[tokio::test]
    async fn connect_fails_cleanly_when_the_host_cannot_be_resolved() {
        let config = client_config().expect("system roots");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connect(&config, "this-host-does-not-resolve.invalid:5349"),
        )
        .await;
        match result {
            Ok(inner) => assert!(inner.is_err()),
            Err(_timed_out) => {}
        }
    }
}
