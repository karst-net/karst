// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Deciding whether this node is behind NAT64, and finding the prefix if it is.
//!
//! [`karst_transport::Nat64Prefix`] knows how to embed an IPv4 address in a
//! prefix. This module answers the two questions that come before that: whether
//! the prefix should be used at all, and what it is.
//!
//! # Why the first question is not obvious
//!
//! Synthesis is not free to apply speculatively. A host that has working IPv4
//! *and* a NAT64 translator would, if it synthesised, send every IPv4 flow
//! through the translator — and so learn a reflexive address belonging to the
//! translator rather than to itself, advertise it, and be reached there by
//! peers that could have reached it directly. That is slower and more fragile
//! than the path it replaced.
//!
//! So [`Mode::Auto`] applies two gates before it will even ask:
//!
//! 1. **The datapath socket must be IPv6.** `node.listen` decides the address
//!    family — §4 gives the datapath one shared socket — and an `AF_INET`
//!    socket cannot send to an IPv6 address at all. A prefix on such a node is
//!    not merely useless, it would rewrite every reachable destination into an
//!    unreachable one.
//! 2. **The host must have no IPv4 address of its own.** That is what "behind
//!    NAT64" means; a host with both does not need the translator and should
//!    not be routed through it.
//!
//! A prefix written into the configuration skips the second gate and not the
//! first, because the first is a hard incompatibility and the second is a
//! judgement the operator is entitled to overrule.
//!
//! # Discovery
//!
//! RFC 7050: resolve `ipv4only.arpa` for AAAA. The name has two A records and
//! no AAAA of its own, so an AAAA answer can only have been synthesised by a
//! DNS64 resolver — and the prefix is what remains once the well-known address
//! is taken back out.
//!
//! **This is a heuristic and the RFC says so** (§3, §6). It requires a DNS64
//! resolver on the path, which a NAT64 network normally has and is not obliged
//! to; it trusts an unauthenticated answer, so a resolver that lies can make
//! this node send its traffic somewhere of the resolver's choosing. That is
//! bounded by what Karst already assumes — the node's traffic is authenticated
//! and encrypted end to end, so a hostile prefix costs reachability and not
//! confidentiality — but it is the reason discovery is a gated fallback rather
//! than something this daemon does eagerly.
//!
//! RFC 8781's PREF64 router-advertisement option is the better mechanism and is
//! not implemented: reading router advertisements needs a raw `ICMPv6` socket,
//! and so `CAP_NET_RAW` in a daemon that otherwise wants only `CAP_NET_ADMIN`.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karst_transport::Nat64Prefix;

/// How long to wait for a resolver. Startup blocks on this, and a node on a
/// network with no DNS64 waits it out once per configured nameserver.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// RFC 7050 §3's name. The trailing dot is implied by the encoding.
const IPV4ONLY_ARPA: &str = "ipv4only.arpa";

/// What the operator asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Never synthesise. A node that knows it is not behind a translator, or
    /// one whose operator would rather it failed visibly than reached the mesh
    /// through a path they did not choose.
    Off,
    /// Use the prefix only where it is needed, and find it by RFC 7050.
    #[default]
    Auto,
    /// This exact prefix, whatever the host looks like.
    Fixed(Nat64Prefix),
}

impl std::str::FromStr for Mode {
    type Err = karst_transport::PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" | "false" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            other => other.parse().map(Self::Fixed),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Mode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(|e: karst_transport::PrefixError| {
            serde::de::Error::custom(format!(
                "{e} — `nat64` takes \"off\", \"auto\", or a prefix such as \
                 \"64:ff9b::/96\""
            ))
        })
    }
}

/// The prefix this node should synthesise through, or `None` for none.
///
/// Reports what it decided and why on the way, because every outcome here is
/// invisible otherwise: a node that quietly declined to discover a prefix and a
/// node that quietly found none are the same silence, and they need different
/// fixes.
#[must_use]
pub fn resolve(mode: Mode, listen: SocketAddr) -> Option<Nat64Prefix> {
    match mode {
        Mode::Off => None,
        Mode::Fixed(prefix) => {
            if !listen.is_ipv6() {
                eprintln!(
                    "karstd: nat64 = \"{prefix}\" is configured but the datapath \
                     listens on {listen}, which is IPv4 — an AF_INET socket \
                     cannot send to an IPv6 address, so the prefix is ignored. \
                     Set node.listen to an IPv6 address, or \"[::]\"."
                );
                return None;
            }
            eprintln!("karstd: reaching IPv4 through the configured NAT64 prefix {prefix}");
            Some(prefix)
        }
        Mode::Auto => auto(listen),
    }
}

/// Rewrite a `host:port` so this node can reach it — the relay's address form.
///
/// **A name is left alone, and that is not a shortcut.** DNS64 synthesises for
/// names already; that is what it is for. Only a literal arrives at a node
/// unsynthesised, because nothing looked it up. So a relay named
/// `relay.example.com` needs nothing from this function and a relay named
/// `51.75.10.10` needs everything.
#[must_use]
pub fn rewrite_authority(prefix: Option<Nat64Prefix>, address: &str) -> String {
    let Some(prefix) = prefix else {
        return address.to_owned();
    };
    match address.parse::<SocketAddr>() {
        Ok(addr) if addr.is_ipv4() => prefix.synthesise_socket(addr).to_string(),
        _ => address.to_owned(),
    }
}

/// The same, for the `scheme://host:port/…` the control server is named by.
#[must_use]
pub fn rewrite_url(prefix: Option<Nat64Prefix>, url: &str) -> String {
    let Some(prefix) = prefix else {
        return url.to_owned();
    };
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    // The authority runs to the first `/`, `?` or `#`; everything after it is
    // carried through untouched.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let Some((host, port)) = authority.rsplit_once(':') else {
        // No port. A bare IPv4 literal still needs synthesising, and the result
        // has to be bracketed or it is not a URL.
        return match authority.parse::<std::net::Ipv4Addr>() {
            Ok(v4) => format!("{scheme}://[{}]{tail}", prefix.synthesise(v4)),
            Err(_) => url.to_owned(),
        };
    };
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(v4) => format!("{scheme}://[{}]:{port}{tail}", prefix.synthesise(v4)),
        Err(_) => url.to_owned(),
    }
}

/// [`Mode::Auto`]'s two gates, then discovery.
fn auto(listen: SocketAddr) -> Option<Nat64Prefix> {
    if !listen.is_ipv6() {
        // Silent: this is the ordinary IPv4 node, and it is not a situation
        // anybody needs told about.
        return None;
    }
    if has_ipv4() {
        return None;
    }
    let prefix = discover();
    match prefix {
        Some(p) => eprintln!(
            "karstd: this host has no IPv4 address; reaching IPv4 through the \
             NAT64 prefix {p}, discovered from {IPV4ONLY_ARPA} (RFC 7050)"
        ),
        None => eprintln!(
            "karstd: this host has no IPv4 address and no NAT64 prefix could be \
             discovered from {IPV4ONLY_ARPA} — every IPv4 relay, server or peer \
             will be unreachable. If this network runs NAT64 without DNS64, set \
             node.nat64 to its prefix."
        ),
    }
    prefix
}

/// Whether this host holds an IPv4 address it could send from.
///
/// Loopback does not count: a node whose only IPv4 is 127.0.0.1 reaches
/// nothing, and it is exactly the shape an IPv6-only host has.
fn has_ipv4() -> bool {
    karst_tun::local_addresses().is_ok_and(|addresses| {
        addresses
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified()))
    })
}

/// Ask every configured resolver for `ipv4only.arpa`, and take the first
/// synthesised answer.
fn discover() -> Option<Nat64Prefix> {
    for server in nameservers() {
        match query_aaaa(server, IPV4ONLY_ARPA) {
            Ok(answers) => {
                if let Some(prefix) = answers
                    .iter()
                    .copied()
                    .find_map(Nat64Prefix::from_ipv4only_arpa)
                {
                    return Some(prefix);
                }
            }
            Err(e) => eprintln!("karstd: {IPV4ONLY_ARPA} lookup via {server} failed: {e}"),
        }
    }
    None
}

/// The nameservers in `/etc/resolv.conf`.
///
/// Read directly rather than through the system resolver, because `getaddrinfo`
/// hides which server answered and — on a host running `systemd-resolved` —
/// answers from a cache that may predate the move onto this network. It also
/// keeps this off a blocking libc call in a daemon that has its own timeouts.
fn nameservers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let rest = line.strip_prefix("nameserver")?.trim();
            let ip: IpAddr = rest.split_whitespace().next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .collect()
}

/// One AAAA query, one datagram, one answer.
///
/// A deliberately small DNS client: no EDNS, no TCP fallback, no retry. It asks
/// one question whose answer is a handful of bytes, so a truncated response is
/// not a case that arises, and a resolver that does not answer in
/// [`DNS_TIMEOUT`] is one this node should stop waiting for.
fn query_aaaa(server: SocketAddr, name: &str) -> io::Result<Vec<Ipv6Addr>> {
    let bind: SocketAddr = if server.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(DNS_TIMEOUT))?;

    // A fresh id per query. It is checked on the way back, which with a random
    // source port is the whole of what an unauthenticated DNS client can do
    // about an off-path forgery.
    let id: u16 = u16::from_ne_bytes(rand_bytes());
    let query = encode_query(id, name);
    socket.send_to(&query, server)?;

    let mut buf = [0u8; 1232];
    loop {
        let (n, from) = socket.recv_from(&mut buf)?;
        if from != server {
            continue;
        }
        let response = buf.get(..n).unwrap_or_default();
        if let Some(answers) = decode_aaaa(response, id) {
            return Ok(answers);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the resolver's answer did not parse as a DNS response to this query",
        ));
    }
}

/// Two bytes from the OS, for the query id.
///
/// A failure here falls back to a fixed id rather than refusing to look up a
/// prefix. The id defends against an off-path forgery and nothing more — the
/// prefix it protects buys reachability, not confidentiality — so trading it
/// for "this node cannot reach the mesh at all" would be the wrong way round.
fn rand_bytes() -> [u8; 2] {
    let mut b = [0u8; 2];
    if getrandom::fill(&mut b).is_err() {
        return 0x4B53u16.to_be_bytes();
    }
    b
}

/// Build a standard recursive AAAA query.
fn encode_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0, OPCODE=0, RD=1.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR
    for label in name.split('.').filter(|l| !l.is_empty()) {
        // A label over 63 bytes cannot be encoded. The only name this module
        // asks for is a constant, so truncating here is unreachable in practice
        // and still better than emitting a length byte that means something
        // else entirely.
        let bytes = label.as_bytes().get(..label.len().min(63)).unwrap_or(&[]);
        out.push(u8::try_from(bytes.len()).unwrap_or(0));
        out.extend_from_slice(bytes);
    }
    out.push(0); // root
    out.extend_from_slice(&28u16.to_be_bytes()); // QTYPE = AAAA
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    out
}

/// Pull the AAAA records out of a response, or `None` if it is not one.
///
/// **Compression pointers are skipped, not followed.** Every name in the answer
/// section is a name this function does not need — it is looking for records of
/// a type and a length, and the owner name is already known from the question.
/// Following pointers is where DNS parsers acquire their decompression loops
/// and their CVEs, and there is nothing here to gain by it.
fn decode_aaaa(msg: &[u8], want_id: u16) -> Option<Vec<Ipv6Addr>> {
    let id = u16::from_be_bytes([*msg.first()?, *msg.get(1)?]);
    if id != want_id {
        return None;
    }
    let flags = u16::from_be_bytes([*msg.get(2)?, *msg.get(3)?]);
    if flags & 0x8000 == 0 {
        return None; // not a response
    }
    if flags & 0x000F != 0 {
        return Some(Vec::new()); // NXDOMAIN or any other RCODE: no answers
    }
    let qdcount = u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]);
    let ancount = u16::from_be_bytes([*msg.get(6)?, *msg.get(7)?]);

    let mut at = 12usize;
    for _ in 0..qdcount {
        at = skip_name(msg, at)?;
        at = at.checked_add(4)?; // QTYPE + QCLASS
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        at = skip_name(msg, at)?;
        let rtype = u16::from_be_bytes([*msg.get(at)?, *msg.get(at.checked_add(1)?)?]);
        let rdlength = usize::from(u16::from_be_bytes([
            *msg.get(at.checked_add(8)?)?,
            *msg.get(at.checked_add(9)?)?,
        ]));
        let rdata = at.checked_add(10)?;
        let end = rdata.checked_add(rdlength)?;
        // **A record cannot claim more data than the message holds.** Without
        // this the walk steps past the end and every later record is read from
        // nowhere; the parse would not panic — the reads are all checked — it
        // would quietly return the wrong answers, which is worse.
        if end > msg.len() {
            return None;
        }
        if rtype == 28 && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(msg.get(rdata..end)?);
            out.push(Ipv6Addr::from(octets));
        }
        at = end;
    }
    Some(out)
}

/// Advance past a wire-format name, whether it ends in a root label or a
/// compression pointer.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        if len & 0xC0 == 0xC0 {
            // A pointer is two bytes and always terminates the name.
            return at.checked_add(2);
        }
        at = at.checked_add(1)?.checked_add(usize::from(len))?;
        if len == 0 {
            return Some(at);
        }
    }
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
    use std::net::Ipv4Addr;

    fn mode(s: &str) -> Mode {
        s.parse().expect("parse")
    }

    #[test]
    fn the_three_spellings_of_the_setting_mean_what_they_say() {
        assert_eq!(mode("off"), Mode::Off);
        assert_eq!(mode("auto"), Mode::Auto);
        assert_eq!(mode("64:ff9b::/96"), Mode::Fixed(Nat64Prefix::well_known()));
        // And a prefix that is not one is refused here rather than at the first
        // packet, with the standard's own reason.
        let err = "64:ff9b::/80".parse::<Mode>().unwrap_err();
        assert!(err.to_string().contains("RFC 6052"), "{err}");
    }

    /// **The gate that matters.** A prefix on an `AF_INET` datapath rewrites
    /// every reachable destination into one the socket cannot send to at all,
    /// so a node that has both must ignore the prefix — and say so, because the
    /// operator asked for something that cannot be honoured.
    #[test]
    fn a_prefix_is_refused_on_an_ipv4_datapath() {
        let listen: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(resolve(mode("64:ff9b::/96"), listen), None);
        // The same prefix on an IPv6 datapath is used.
        let v6: SocketAddr = "[::]:51820".parse().unwrap();
        assert_eq!(
            resolve(mode("64:ff9b::/96"), v6),
            Some(Nat64Prefix::well_known())
        );
    }

    /// `off` means off, on any datapath, and does not go near the network.
    #[test]
    fn off_never_synthesises() {
        for listen in ["0.0.0.0:51820", "[::]:51820"] {
            assert_eq!(resolve(Mode::Off, listen.parse().unwrap()), None);
        }
    }

    /// Auto does not discover on an IPv4 datapath — no DNS query, no wait.
    #[test]
    fn auto_is_a_no_op_on_an_ipv4_datapath() {
        let listen: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let started = std::time::Instant::now();
        assert_eq!(resolve(Mode::Auto, listen), None);
        assert!(
            started.elapsed() < DNS_TIMEOUT,
            "auto blocked on a resolver for a socket that could never use the \
             answer"
        );
    }

    /// A whole response, byte for byte, as a DNS64 resolver would send it.
    fn response(id: u16, rcode: u16, answers: &[Ipv6Addr]) -> Vec<u8> {
        let mut m = encode_query(id, IPV4ONLY_ARPA);
        m[2] = 0x81; // QR=1, RD=1
        m[3] = 0x80 | u8::try_from(rcode).unwrap(); // RA + RCODE
        let count = u16::try_from(answers.len()).unwrap();
        m[6..8].copy_from_slice(&count.to_be_bytes());
        for a in answers {
            m.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question's name
            m.extend_from_slice(&28u16.to_be_bytes()); // AAAA
            m.extend_from_slice(&1u16.to_be_bytes()); // IN
            m.extend_from_slice(&60u32.to_be_bytes()); // TTL
            m.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
            m.extend_from_slice(&a.octets());
        }
        m
    }

    #[test]
    fn a_dns64_answer_yields_the_prefix_it_was_synthesised_with() {
        let prefix: Nat64Prefix = "64:ff9b::/96".parse().unwrap();
        let synthesised = prefix.synthesise(karst_transport::WKA);
        let msg = response(0x1234, 0, &[synthesised]);
        let answers = decode_aaaa(&msg, 0x1234).expect("a well-formed response");
        assert_eq!(answers, vec![synthesised]);
        assert_eq!(
            answers
                .iter()
                .copied()
                .find_map(Nat64Prefix::from_ipv4only_arpa),
            Some(prefix)
        );
    }

    /// A response to somebody else's question is not an answer to this one.
    /// With a random source port this is most of what an unauthenticated
    /// resolver client can do about forgery, so it is checked rather than
    /// assumed.
    #[test]
    fn a_response_with_the_wrong_id_is_rejected() {
        let msg = response(0x1234, 0, &[Ipv6Addr::LOCALHOST]);
        assert_eq!(decode_aaaa(&msg, 0x9999), None);
    }

    /// The ordinary answer on a network with no DNS64: the name resolves, and
    /// has no AAAA.
    #[test]
    fn a_network_without_dns64_yields_no_prefix() {
        let empty = response(7, 0, &[]);
        assert_eq!(decode_aaaa(&empty, 7), Some(Vec::new()));
        let nxdomain = response(7, 3, &[]);
        assert_eq!(decode_aaaa(&nxdomain, 7), Some(Vec::new()));
    }

    /// A truncated or malformed message must return rather than index past the
    /// end — the input is a datagram from the network and nothing has vouched
    /// for it.
    #[test]
    fn a_truncated_response_is_refused_without_panicking() {
        let full = response(1, 0, &[Ipv6Addr::LOCALHOST]);
        for cut in 0..full.len() {
            let _ = decode_aaaa(&full[..cut], 1);
        }
        // A record claiming more data than the message holds.
        let mut lying = full.clone();
        let len = lying.len();
        lying[len - 18..len - 16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(decode_aaaa(&lying, 1), None);
    }

    /// The question section is skipped by walking labels, so a name that is
    /// itself a compression pointer must not send the walk backwards forever.
    #[test]
    fn a_pointer_terminates_the_name_it_appears_in() {
        let msg = [0xC0u8, 0x0C, 0, 0];
        assert_eq!(skip_name(&msg, 0), Some(2));
        // A pointer to itself would loop if it were followed rather than
        // skipped.
        let loopy = [0xC0u8, 0x00];
        assert_eq!(skip_name(&loopy, 0), Some(2));
    }

    #[test]
    fn the_query_asks_for_what_it_says_it_asks_for() {
        let q = encode_query(0xBEEF, IPV4ONLY_ARPA);
        assert_eq!(&q[0..2], &0xBEEFu16.to_be_bytes());
        assert_eq!(&q[4..6], &1u16.to_be_bytes(), "one question");
        // `\x08ipv4only\x04arpa\x00`, then AAAA and IN.
        assert_eq!(&q[12..13], b"\x08");
        assert_eq!(&q[13..21], b"ipv4only");
        assert_eq!(&q[21..22], b"\x04");
        assert_eq!(&q[22..26], b"arpa");
        assert_eq!(q[26], 0);
        assert_eq!(&q[27..29], &28u16.to_be_bytes());
        assert_eq!(&q[29..31], &1u16.to_be_bytes());
    }

    /// The relay's address form and the control server's URL form, both of
    /// which arrive as text and must come back as text a connect can use.
    #[test]
    fn literals_are_rewritten_and_names_are_not() {
        let p = Some(Nat64Prefix::well_known());
        assert_eq!(
            rewrite_authority(p, "51.75.10.10:8443"),
            "[64:ff9b::334b:a0a]:8443"
        );
        assert_eq!(
            rewrite_url(p, "http://51.75.10.10:9443"),
            "http://[64:ff9b::334b:a0a]:9443"
        );
        assert_eq!(
            rewrite_url(p, "https://51.75.10.10:9443/v1/session?x=1"),
            "https://[64:ff9b::334b:a0a]:9443/v1/session?x=1",
            "the path and query belong to the server, not to us"
        );
        assert_eq!(
            rewrite_url(p, "https://51.75.10.10/v1"),
            "https://[64:ff9b::334b:a0a]/v1",
            "a URL with no port still names a host"
        );

        // **A name is left alone**: DNS64 already synthesises for names, and
        // rewriting one here would be both wrong and impossible.
        assert_eq!(
            rewrite_authority(p, "relay.example.com:8443"),
            "relay.example.com:8443"
        );
        assert_eq!(
            rewrite_url(p, "https://karst.example.com:443"),
            "https://karst.example.com:443"
        );
        // An address that is already IPv6 is already reachable.
        assert_eq!(
            rewrite_authority(p, "[2001:db8::1]:8443"),
            "[2001:db8::1]:8443"
        );
        assert_eq!(
            rewrite_url(p, "https://[2001:db8::1]:443"),
            "https://[2001:db8::1]:443"
        );
    }

    /// With no prefix, every form is returned exactly as it came in. This is
    /// the path every ordinary node takes, so it is the one worth pinning.
    #[test]
    fn without_a_prefix_nothing_is_rewritten() {
        for s in [
            "51.75.10.10:8443",
            "relay.example.com:8443",
            "[2001:db8::1]:8443",
        ] {
            assert_eq!(rewrite_authority(None, s), s);
        }
        for s in ["http://51.75.10.10:9443", "https://karst.example.com"] {
            assert_eq!(rewrite_url(None, s), s);
        }
    }

    /// `/etc/resolv.conf` parsing, including the lines that are not
    /// nameservers.
    #[test]
    fn only_nameserver_lines_name_a_server() {
        // Exercised through the real file, which must at least not panic, and
        // through the parser's shape below.
        let _ = nameservers();
        let sample = "# a comment\n\
                      search example.com\n\
                      nameserver 192.0.2.1\n\
                      nameserver fd00:11::1 # inline comment\n\
                      options edns0\n\
                      nameserverbroken 10.0.0.1\n";
        let parsed: Vec<SocketAddr> = sample
            .lines()
            .filter_map(|line| {
                let line = line.split('#').next()?.trim();
                let rest = line.strip_prefix("nameserver")?.trim();
                let ip: IpAddr = rest.split_whitespace().next()?.parse().ok()?;
                Some(SocketAddr::new(ip, 53))
            })
            .collect();
        assert_eq!(
            parsed,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53),
                SocketAddr::new("fd00:11::1".parse::<Ipv6Addr>().unwrap().into(), 53),
            ],
            "`nameserverbroken` is not a nameserver line"
        );
    }
}
