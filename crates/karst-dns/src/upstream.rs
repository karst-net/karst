// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The resolvers a forwarded query may be sent to, and how.

use std::net::SocketAddr;

/// One resolver a forwarded query may be sent to, and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub addr: SocketAddr,
    pub transport: Transport,
}

/// How a query reaches an [`Upstream`] — ADR-0034.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Plain UDP/TCP DNS.
    Plain,
    /// DNS-over-TLS (RFC 7858). `server_name` is the SNI and certificate name
    /// verified against, distinct from `addr` since a bare IP rarely appears
    /// in a certificate. `pin`, when set, is the SHA-256 hash of the
    /// resolver's leaf certificate's SubjectPublicKeyInfo, checked in
    /// addition to ordinary chain validation.
    Dot {
        server_name: String,
        pin: Option<[u8; 32]>,
    },
}

impl Upstream {
    #[must_use]
    pub fn plain(addr: SocketAddr) -> Self {
        Self {
            addr,
            transport: Transport::Plain,
        }
    }
}
