// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::canonical_name;

/// The record kinds KarstDNS treats specially in its mesh zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordType {
    A,
    Aaaa,
    Ptr,
    Other,
}

/// A mesh record returned by the authoritative zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
}

/// DNS response semantics, separated from codec-specific wire flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseKind {
    Answer,
    NxDomain,
    NoData,
}

/// An authoritative mesh response with a fixed, short TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub kind: ResponseKind,
    pub records: Vec<Record>,
    pub ttl: u32,
}

impl Response {
    #[must_use]
    pub fn answer(records: Vec<Record>) -> Self {
        Self {
            kind: ResponseKind::Answer,
            records,
            ttl: 60,
        }
    }

    #[must_use]
    pub fn nxdomain() -> Self {
        Self {
            kind: ResponseKind::NxDomain,
            records: Vec::new(),
            ttl: 60,
        }
    }

    #[must_use]
    pub fn nodata() -> Self {
        Self {
            kind: ResponseKind::NoData,
            records: Vec::new(),
            ttl: 60,
        }
    }
}

/// One netmap peer's mesh addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshPeer {
    pub hostname: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

impl MeshPeer {
    #[must_use]
    pub fn new(
        hostname: impl Into<String>,
        ipv4: impl IntoIterator<Item = Ipv4Addr>,
        ipv6: impl IntoIterator<Item = Ipv6Addr>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            ipv4: ipv4.into_iter().collect(),
            ipv6: ipv6.into_iter().collect(),
        }
    }
}

/// Authoritative mesh zone, including reverse maps for the allocated addresses.
#[derive(Clone, Debug)]
pub struct MeshZone {
    zone: String,
    names: BTreeMap<String, MeshPeer>,
    reverse: BTreeMap<IpAddr, String>,
}

impl MeshZone {
    #[must_use]
    pub fn new(zone: String, peers: impl IntoIterator<Item = MeshPeer>) -> Self {
        let mut names = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        for mut peer in peers {
            peer.hostname = canonical_name(&peer.hostname).unwrap_or_default();
            let name = if peer.hostname.is_empty() {
                String::new()
            } else {
                format!("{}.{}", peer.hostname, zone)
            };
            if name.is_empty() {
                continue;
            }
            for address in &peer.ipv4 {
                reverse.insert(IpAddr::V4(*address), name.clone());
            }
            for address in &peer.ipv6 {
                reverse.insert(IpAddr::V6(*address), name.clone());
            }
            names.insert(name, peer);
        }
        Self {
            zone,
            names,
            reverse,
        }
    }

    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        name == self.zone || name.ends_with(&format!(".{}", self.zone))
    }

    #[must_use]
    pub fn contains_reverse_name(&self, name: &str) -> bool {
        parse_reverse(name).is_some_and(is_mesh_reverse)
    }

    #[must_use]
    pub fn lookup(&self, name: &str, kind: RecordType) -> Response {
        if let Some(address) = parse_reverse(name) {
            return match self.reverse.get(&address) {
                Some(peer) if kind == RecordType::Ptr => {
                    Response::answer(vec![Record::Ptr(format!("{peer}."))])
                }
                Some(_) => Response::nodata(),
                None => Response::nxdomain(),
            };
        }
        let Some(peer) = self.names.get(name) else {
            return Response::nxdomain();
        };
        match kind {
            RecordType::A => Response::answer(peer.ipv4.iter().copied().map(Record::A).collect()),
            RecordType::Aaaa => {
                Response::answer(peer.ipv6.iter().copied().map(Record::Aaaa).collect())
            }
            _ => Response::nodata(),
        }
    }
}

fn parse_reverse(name: &str) -> Option<IpAddr> {
    if let Some(v4) = name.strip_suffix(".in-addr.arpa") {
        let labels: Vec<_> = v4.split('.').collect();
        if labels.len() != 4 {
            return None;
        }
        return Some(IpAddr::V4(Ipv4Addr::new(
            labels.get(3)?.parse().ok()?,
            labels.get(2)?.parse().ok()?,
            labels.get(1)?.parse().ok()?,
            labels.first()?.parse().ok()?,
        )));
    }
    let v6 = name.strip_suffix(".ip6.arpa")?;
    let labels: Vec<_> = v6.split('.').collect();
    if labels.len() != 32 || labels.iter().any(|label| label.len() != 1) {
        return None;
    }
    let mut value = String::with_capacity(32);
    for label in labels.iter().rev() {
        if !label.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        value.push_str(label);
    }
    u128::from_str_radix(&value, 16)
        .ok()
        .map(Ipv6Addr::from)
        .map(IpAddr::V6)
}

fn is_mesh_reverse(address: IpAddr) -> bool {
    match address {
        // Karst's IPv4 allocations are /16s within the shared CGNAT block.
        IpAddr::V4(address) => {
            address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1])
        }
        // IPv6 mesh addresses are ULA allocations. The exact /64 belongs to
        // the account, but retaining the ULA boundary here avoids forwarding
        // an unknown mesh PTR while leaving public reverse DNS to the host.
        IpAddr::V6(address) => address.octets()[0] == 0xfd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_answers_the_canonical_name() {
        let zone = MeshZone::new(
            "aquifer.karst".to_owned(),
            [MeshPeer::new("alpha", [Ipv4Addr::new(100, 64, 0, 2)], [])],
        );
        assert_eq!(
            zone.lookup("2.0.64.100.in-addr.arpa", RecordType::Ptr),
            Response::answer(vec![Record::Ptr("alpha.aquifer.karst.".to_owned())])
        );
    }

    #[test]
    fn ipv6_reverse_answers_the_canonical_name() {
        let address = "fd00::2".parse::<Ipv6Addr>().expect("IPv6 address");
        let zone = MeshZone::new(
            "aquifer.karst".to_owned(),
            [MeshPeer::new("alpha", [], [address])],
        );
        assert_eq!(
            zone.lookup(
                "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
                RecordType::Ptr
            ),
            Response::answer(vec![Record::Ptr("alpha.aquifer.karst.".to_owned())])
        );
    }
}
