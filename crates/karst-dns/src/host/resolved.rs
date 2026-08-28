// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Direct `systemd-resolved` integration.
//!
//! This deliberately talks to resolved's system-bus API instead of invoking
//! `resolvectl`: there is no child-process parsing and `RevertLink` returns
//! the link exactly to resolved's prior policy on shutdown or disable.

use std::net::{IpAddr, SocketAddr};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

const DESTINATION: &str = "org.freedesktop.resolve1";
const PATH: &str = "/org/freedesktop/resolve1";
const INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_INTERFACE: &str = "org.freedesktop.resolve1.Link";
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
type DnsAddresses = Vec<(i32, Vec<u8>)>;
type Domains = Vec<(String, bool)>;

/// A system-bus client for the DNS state attached to one tunnel interface.
#[derive(Debug)]
pub struct Resolved {
    connection: Connection,
    ifindex: i32,
    expected: Option<(DnsAddresses, Domains)>,
}

/// Errors applying a resolved link configuration.
#[derive(Debug, thiserror::Error)]
pub enum ResolvedError {
    #[error("a tunnel interface index must be positive")]
    InvalidInterface,
    #[error("systemd-resolved only accepts DNS port 53")]
    UnsupportedPort,
    #[error("D-Bus call to systemd-resolved failed: {0}")]
    Bus(#[from] zbus::Error),
}

impl Resolved {
    /// Connect to the system bus for one already-created tunnel interface.
    pub fn connect(ifindex: i32) -> Result<Self, ResolvedError> {
        if ifindex <= 0 {
            return Err(ResolvedError::InvalidInterface);
        }
        Ok(Self {
            connection: Connection::system()?,
            ifindex,
            expected: None,
        })
    }

    /// Install the KarstDNS stub and scope it to the mesh zone.
    ///
    /// The link is explicitly not a default route: non-mesh names therefore
    /// remain with the host's normal resolver configuration.
    pub fn apply(
        &mut self,
        stub: SocketAddr,
        zone: &str,
        search_domains: &[String],
    ) -> Result<(), ResolvedError> {
        if stub.port() != 53 {
            return Err(ResolvedError::UnsupportedPort);
        }
        let dns = vec![dns_address(stub.ip())];
        let expected_domains = domains(zone, search_domains);
        {
            let proxy = self.proxy()?;
            proxy.call::<_, _, ()>("SetLinkDNS", &(self.ifindex, dns))?;
            proxy.call::<_, _, ()>("SetLinkDomains", &(self.ifindex, expected_domains.clone()))?;
            proxy.call::<_, _, ()>("SetLinkDefaultRoute", &(self.ifindex, false))?;
        }
        self.expected = Some((vec![dns_address(stub.ip())], expected_domains));
        Ok(())
    }

    /// Remove only DNS state that KarstDNS put on this tunnel link.
    pub fn revert(&mut self) -> Result<(), ResolvedError> {
        self.proxy()?
            .call::<_, _, ()>("RevertLink", &self.ifindex)?;
        self.expected = None;
        Ok(())
    }

    /// Compare the current resolved link properties against the state Karst
    /// applied. This is read-only and catches a resolver manager that has
    /// subsequently replaced link DNS policy.
    pub fn observe(&self) -> Result<bool, ResolvedError> {
        let Some((expected_dns, expected_domains)) = &self.expected else {
            return Ok(false);
        };
        let path: OwnedObjectPath = self.proxy()?.call("GetLink", &self.ifindex)?;
        let link = Proxy::new(&self.connection, DESTINATION, path, LINK_INTERFACE)?;
        let dns: DnsAddresses = link.get_property("DNS")?;
        let domains: Domains = link.get_property("Domains")?;
        let default_route: bool = link.get_property("DefaultRoute")?;
        Ok(matches_expected(
            &dns,
            &domains,
            default_route,
            expected_dns,
            expected_domains,
        ))
    }

    fn proxy(&self) -> Result<Proxy<'_>, ResolvedError> {
        Ok(Proxy::new(&self.connection, DESTINATION, PATH, INTERFACE)?)
    }
}

fn dns_address(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (AF_INET, address.octets().to_vec()),
        IpAddr::V6(address) => (AF_INET6, address.octets().to_vec()),
    }
}

fn domains(zone: &str, search_domains: &[String]) -> Domains {
    let mut result = Vec::with_capacity(search_domains.len() + 1);
    // resolved uses `route_only=true` rather than the `~` presentation syntax.
    result.push((zone.trim_end_matches('.').to_owned(), true));
    result.extend(
        search_domains
            .iter()
            .map(|domain| (domain.trim_end_matches('.').to_owned(), false)),
    );
    result
}

fn matches_expected(
    dns: &[(i32, Vec<u8>)],
    domains: &[(String, bool)],
    default_route: bool,
    expected_dns: &[(i32, Vec<u8>)],
    expected_domains: &[(String, bool)],
) -> bool {
    dns == expected_dns && domains == expected_domains && !default_route
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_ifindex() -> Option<i32> {
        let interface = std::env::var("KARST_DNS_HOST_TEST_INTERFACE").ok()?;
        std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    #[test]
    fn encodes_both_address_families_for_resolved() {
        assert_eq!(
            dns_address(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))),
            (AF_INET, vec![100, 100, 100, 100])
        );
        assert_eq!(
            dns_address(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            (AF_INET6, Ipv6Addr::LOCALHOST.octets().to_vec())
        );
    }

    #[test]
    fn mesh_zone_is_a_route_only_domain() {
        assert_eq!(
            domains("aquifer.karst.", &["corp.example.".to_owned()]),
            vec![
                ("aquifer.karst".to_owned(), true),
                ("corp.example".to_owned(), false),
            ]
        );
    }

    #[test]
    fn observation_requires_dns_domains_and_no_default_route() {
        let dns = vec![dns_address(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)))];
        let domains = domains("aquifer.karst.", &[]);
        assert!(matches_expected(&dns, &domains, false, &dns, &domains));
        assert!(!matches_expected(&dns, &domains, true, &dns, &domains));
    }

    #[test]
    #[ignore = "requires a disposable host interface named by KARST_DNS_HOST_TEST_INTERFACE"]
    fn applies_observes_and_reverts_a_real_resolved_link() {
        let ifindex = test_ifindex().expect("test interface requested");
        let mut resolved = Resolved::connect(ifindex).expect("connect resolved");
        resolved
            .apply(
                "100.100.100.100:53".parse().expect("stub"),
                "karst-test.invalid.",
                &["search.karst-test.invalid".to_owned()],
            )
            .expect("apply link DNS");
        assert!(resolved.observe().expect("observe applied link"));
        resolved.revert().expect("revert link DNS");
        assert!(!resolved.observe().expect("observe reverted link"));
    }
}
