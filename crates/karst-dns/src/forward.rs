// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Bounded forwarding for resolver-selected upstreams — plain UDP or DoT
//! (RFC 7858), per [`Transport`](crate::Transport) — ADR-0034.

mod dot;
mod tls;
mod udp;

use std::io;

use crate::{message, Transport, Upstream};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DNS query is malformed: {0}")]
    Query(String),
    #[error("DNS upstream did not return a valid matching response")]
    MismatchedResponse,
    #[error("all DNS upstreams failed: {0}")]
    Upstream(#[source] io::Error),
}

/// Send a query only to the supplied resolver set, returning the first valid
/// matching response. Callers choose this set from [`crate::service::Decision`]
/// and therefore cannot accidentally use global upstreams for a split route.
///
/// A DoT upstream that fails — handshake, certificate/pin verification, or a
/// transport error — is treated exactly like an unreachable plain upstream:
/// it counts against the same retry loop and never causes a fall back to a
/// different transport. ADR-0034.
pub fn query(query: &[u8], upstreams: &[Upstream]) -> Result<Vec<u8>, Error> {
    let request = message::decode(query).map_err(Error::Query)?;
    let mut last_error = None;
    for upstream in upstreams {
        let result = match &upstream.transport {
            Transport::Plain => udp::query_one(query, request.metadata.id, upstream.addr),
            Transport::Dot { server_name, pin } => dot::query_one(
                query,
                request.metadata.id,
                upstream.addr,
                server_name,
                pin.as_ref(),
            ),
        };
        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(Error::Upstream(last_error.unwrap_or_else(|| {
        io::Error::other("no DNS upstream configured")
    })))
}
