// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The HTTP/1.1 upgrade that opens a Ponor connection — `spec/ponor-v1.md` §4.1.
//!
//! Hand-rolled rather than delegated to an HTTP server, and the reason is
//! scope: this handles exactly one request shape, on a connection that becomes
//! a binary protocol immediately afterwards. Pulling in a full HTTP stack to
//! read one request line would add a routing layer, a body reader and a
//! connection-reuse state machine to a path that needs none of them, and every
//! one of those is on the pre-authentication surface.
//!
//! The parser is written accordingly: bounded, allocation-free until it
//! succeeds, and it never treats a header it does not recognise as
//! significant.

use std::fmt::Write as _;

/// The path a relay listens on. Chosen so a relay can share a host, a port and
/// a certificate with the coordination server, which is what makes ADR-0008's
/// co-location default free.
pub const PATH: &str = "/ponor";

/// The `Upgrade` token.
pub const TOKEN: &str = "ponor";

/// Largest request head accepted, in bytes.
///
/// A client sends about 120 bytes here. The cap exists because a peer that
/// never sends `\r\n\r\n` would otherwise buy unbounded memory for the price
/// of a TCP connection.
pub const HEAD_MAX: usize = 4096;

/// Why an upgrade request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Not a `GET`.
    Method,
    /// Not [`PATH`].
    Path,
    /// No `Upgrade: ponor`, or no `Connection: Upgrade`.
    NotAnUpgrade,
    /// `Ponor-Version` names a version this relay does not speak.
    Version,
    /// The head exceeded [`HEAD_MAX`], or is not valid HTTP.
    Malformed,
}

impl Reject {
    /// The status line to answer with.
    ///
    /// Deliberately coarse. A relay is not a web server and its 4xx codes are
    /// for whoever is holding a packet capture, not for content negotiation.
    #[must_use]
    pub const fn status(self) -> &'static str {
        match self {
            Self::Path => "404 Not Found",
            Self::Method => "405 Method Not Allowed",
            Self::Version => "426 Upgrade Required",
            Self::NotAnUpgrade | Self::Malformed => "400 Bad Request",
        }
    }

    /// A complete response, connection closed.
    #[must_use]
    pub fn response(self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            self.status()
        );
        s
    }
}

/// The 101 that hands the connection to Ponor.
#[must_use]
pub fn accepted() -> &'static str {
    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ponor\r\n\r\n"
}

/// What a complete, valid request head yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upgrade {
    /// Bytes of `buf` the head occupied. **Everything after this is already
    /// Ponor framing** and must not be discarded — a client that writes its
    /// request and its first frame into one segment is ordinary, not
    /// pathological, and dropping the tail would hang the connection.
    pub head_len: usize,
}

/// Parse an upgrade request from the front of `buf`.
///
/// Returns `Ok(None)` when the head is not yet complete.
///
/// # Errors
/// [`Reject`] describing why the request is not a Ponor upgrade.
pub fn parse(buf: &[u8]) -> Result<Option<Upgrade>, Reject> {
    let Some(end) = find_head_end(buf) else {
        // Bound the wait, not just the buffer: without this a peer that never
        // finishes its head holds a connection slot indefinitely.
        if buf.len() > HEAD_MAX {
            return Err(Reject::Malformed);
        }
        return Ok(None);
    };
    if end > HEAD_MAX {
        return Err(Reject::Malformed);
    }

    let head = buf.get(..end).ok_or(Reject::Malformed)?;
    let text = core::str::from_utf8(head).map_err(|_| Reject::Malformed)?;

    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(Reject::Malformed)?;

    let mut parts = request.split(' ');
    let method = parts.next().ok_or(Reject::Malformed)?;
    let path = parts.next().ok_or(Reject::Malformed)?;
    let version = parts.next().ok_or(Reject::Malformed)?;
    if parts.next().is_some() {
        return Err(Reject::Malformed);
    }
    if !version.starts_with("HTTP/1.") {
        return Err(Reject::Malformed);
    }
    if method != "GET" {
        return Err(Reject::Method);
    }
    // Query strings and fragments are not a thing here. An exact match keeps
    // the surface at one path rather than at "whatever a router would accept".
    if path != PATH {
        return Err(Reject::Path);
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut declared_version: Option<&str> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(Reject::Malformed)?;
        let value = value.trim();
        // Field names are case-insensitive (RFC 9110 §5.1), and a client that
        // sends `upgrade:` in lower case is correct rather than hostile.
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.eq_ignore_ascii_case(TOKEN);
        } else if name.eq_ignore_ascii_case("connection") {
            // Comma-separated list; `Connection: keep-alive, Upgrade` is legal
            // and is what several proxies emit.
            connection_upgrade = value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("ponor-version") {
            declared_version = Some(value);
        }
        // Everything else is ignored, and ignoring it is safe precisely
        // because nothing here is authorisation: admission is §5.3's job and
        // happens after the 101, against the roster.
    }

    if !upgrade || !connection_upgrade {
        return Err(Reject::NotAnUpgrade);
    }
    // Absent means 1 — the header is advisory, since the version byte in
    // `RelayHello`/`ClientAuth` is what actually governs. Present and wrong is
    // an error rather than something to ignore, so a future v2 client gets
    // told rather than failing three frames later.
    if let Some(v) = declared_version {
        if v != "1" {
            return Err(Reject::Version);
        }
    }

    Ok(Some(Upgrade { head_len: end }))
}

/// Byte offset just past the terminating `\r\n\r\n`.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i.saturating_add(4))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;

    const GOOD: &str = "GET /ponor HTTP/1.1\r\n\
         Host: relay.example.com\r\n\
         Connection: Upgrade\r\n\
         Upgrade: ponor\r\n\
         Ponor-Version: 1\r\n\r\n";

    #[test]
    fn a_well_formed_request_is_accepted() {
        let up = parse(GOOD.as_bytes()).expect("valid").expect("complete");
        assert_eq!(up.head_len, GOOD.len());
    }

    #[test]
    fn frames_arriving_with_the_head_are_preserved() {
        // A client that writes its request and its first bytes into one
        // segment is ordinary. Discarding the tail would hang the connection
        // on a frame that had already been sent.
        let mut buf = GOOD.as_bytes().to_vec();
        buf.extend_from_slice(&[0x02, 0, 0, 0xff]);
        let up = parse(&buf).expect("valid").expect("complete");
        assert_eq!(up.head_len, GOOD.len());
        assert_eq!(&buf[up.head_len..], &[0x02, 0, 0, 0xff]);
    }

    #[test]
    fn an_incomplete_head_is_not_an_error() {
        for n in 0..GOOD.len() {
            assert_eq!(
                parse(&GOOD.as_bytes()[..n]),
                Ok(None),
                "prefix of {n} bytes"
            );
        }
    }

    #[test]
    fn an_endless_head_is_bounded() {
        // Otherwise a peer that never sends the terminator buys unbounded
        // memory for the price of a TCP connection.
        let junk = vec![b'x'; HEAD_MAX + 1];
        assert_eq!(parse(&junk), Err(Reject::Malformed));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let lower = "GET /ponor HTTP/1.1\r\nconnection: upgrade\r\nupgrade: PONOR\r\n\r\n";
        assert!(parse(lower.as_bytes()).expect("valid").is_some());
    }

    #[test]
    fn a_connection_header_with_a_list_is_accepted() {
        // `Connection: keep-alive, Upgrade` is legal and several proxies emit
        // it. Requiring an exact match would reject them.
        let listed =
            "GET /ponor HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: ponor\r\n\r\n";
        assert!(parse(listed.as_bytes()).expect("valid").is_some());
    }

    #[test]
    fn an_unrelated_header_is_ignored() {
        // Safe because nothing here is authorisation — admission happens after
        // the 101, against the roster.
        let extra = "GET /ponor HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1\r\n\
             Connection: Upgrade\r\nUpgrade: ponor\r\n\r\n";
        assert!(parse(extra.as_bytes()).expect("valid").is_some());
    }

    #[test]
    fn the_version_header_may_be_omitted() {
        let none = "GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\n\r\n";
        assert!(parse(none.as_bytes()).expect("valid").is_some());
    }

    #[test]
    fn a_future_version_is_told_rather_than_ignored() {
        let two = "GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\n\
             Upgrade: ponor\r\nPonor-Version: 2\r\n\r\n";
        assert_eq!(parse(two.as_bytes()), Err(Reject::Version));
    }

    #[test]
    fn a_plain_get_is_not_an_upgrade() {
        // The case that matters operationally: a health checker or a scanner
        // hitting the path must be refused, not handed a binary protocol.
        let plain = "GET /ponor HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(parse(plain.as_bytes()), Err(Reject::NotAnUpgrade));
    }

    #[test]
    fn an_upgrade_to_something_else_is_refused() {
        let ws = "GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(parse(ws.as_bytes()), Err(Reject::NotAnUpgrade));
    }

    #[test]
    fn another_path_is_not_this_one() {
        // Exactness keeps the surface at one path rather than at whatever a
        // router would accept. A relay shares its listener with the
        // coordination server; overlapping loosely would be worse than 404.
        for path in ["/", "/ponor/", "/ponor?x=1", "/Ponor", "/ponorx"] {
            let req =
                format!("GET {path} HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\n\r\n");
            assert_eq!(parse(req.as_bytes()), Err(Reject::Path), "{path}");
        }
    }

    #[test]
    fn another_method_is_refused() {
        let post = "POST /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\n\r\n";
        assert_eq!(parse(post.as_bytes()), Err(Reject::Method));
    }

    #[test]
    fn malformed_input_is_rejected_not_panicked_on() {
        // This runs before TLS has told us anything about who is calling, so
        // it sees arbitrary bytes.
        for junk in [
            "\r\n\r\n",
            "GET\r\n\r\n",
            "GET /ponor\r\n\r\n",
            "GET /ponor HTTP/1.1 extra\r\n\r\n",
            "GET /ponor HTTP/9\r\n\r\n",
            "GET /ponor HTTP/1.1\r\nnocolon\r\n\r\n",
        ] {
            assert!(parse(junk.as_bytes()).is_err(), "{junk:?}");
        }
        // Invalid UTF-8, and a body of raw binary.
        assert_eq!(
            parse(&[0xff, 0xfe, b'\r', b'\n', b'\r', b'\n']),
            Err(Reject::Malformed)
        );
    }

    #[test]
    fn every_rejection_produces_a_closing_response() {
        for r in [
            Reject::Method,
            Reject::Path,
            Reject::NotAnUpgrade,
            Reject::Version,
            Reject::Malformed,
        ] {
            let resp = r.response();
            assert!(resp.starts_with("HTTP/1.1 "), "{resp}");
            assert!(resp.contains("Connection: close"), "{resp}");
            assert!(resp.ends_with("\r\n\r\n"), "{resp}");
        }
    }

    #[test]
    fn the_acceptance_is_a_well_formed_101() {
        let a = accepted();
        assert!(a.starts_with("HTTP/1.1 101 "));
        assert!(a.contains("Upgrade: ponor"));
        assert!(a.ends_with("\r\n\r\n"));
    }
}
