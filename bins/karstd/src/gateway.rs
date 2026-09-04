// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Linux forwarding policy for authenticated subnet and exit-route grants.
//!
//! The kernel may forward only traffic that has already crossed the encrypted
//! datapath and still matches a gateway offer in the current netmap. Rules live
//! in one Karst-owned nftables table; operator tables are never flushed.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::config::Config;
use crate::route_offer::Role;
use crate::routing::Prefix;

pub const TABLE: &str = "karst_routes";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub route_id: String,
    pub destination: Prefix,
    pub sources: Vec<Prefix>,
    pub masquerade: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ruleset {
    pub grants: Vec<Grant>,
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Ruleset {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let mut grants = Vec::new();
        for offer in config
            .route_offers
            .iter()
            .filter(|offer| offer.role == Role::Gateway)
        {
            let family = offer.prefix.base().is_ipv4();
            let sources: Vec<Prefix> = config
                .addresses
                .iter()
                .map(crate::routing::InterfaceAddress::network)
                .filter(|source| source.base().is_ipv4() == family)
                .collect();
            if sources.is_empty() {
                continue;
            }
            grants.push(Grant {
                route_id: offer.route_id.clone(),
                destination: offer.prefix,
                sources,
                masquerade: offer.masquerade,
            });
        }
        grants.sort_by(|a, b| a.route_id.cmp(&b.route_id));
        Self {
            ipv4: grants
                .iter()
                .any(|grant| grant.destination.base().is_ipv4()),
            ipv6: grants
                .iter()
                .any(|grant| grant.destination.base().is_ipv6()),
            grants,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// A complete replacement for Karst's table after it has been created.
    /// `flush table` plus every add is one nft transaction when sent with
    /// `nft -f -`, so a failed update leaves no half-applied grant set.
    #[must_use]
    pub fn nft_batch(&self, interface: &str) -> String {
        let interface = nft_string(interface);
        let mut out = format!(
            "flush table inet {TABLE}\n\
             add chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}\n\
             add chain inet {TABLE} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n"
        );
        for grant in &self.grants {
            let family = family(grant.destination.base());
            for source in &grant.sources {
                let _ = writeln!(
                    out,
                    "add rule inet {TABLE} forward iifname {interface} {family} saddr {source} {family} daddr {} counter accept comment {}",
                    grant.destination,
                    nft_string(&grant.route_id),
                );
                if grant.masquerade {
                    let _ = writeln!(
                        out,
                        "add rule inet {TABLE} postrouting iifname {interface} oifname != {interface} {family} saddr {source} {family} daddr {} counter masquerade comment {}",
                        grant.destination,
                        nft_string(&grant.route_id),
                    );
                }
            }
        }
        // Replies are admitted only for tracked flows that one of the rules
        // above admitted. Anything else arriving from the TUN is stopped here;
        // the base-chain accept policy deliberately leaves unrelated host
        // forwarding to the operator's own rules.
        let _ = writeln!(
            out,
            "add rule inet {TABLE} forward oifname {interface} ct state established,related counter accept"
        );
        let _ = writeln!(
            out,
            "add rule inet {TABLE} forward iifname {interface} counter drop"
        );
        out
    }
}

fn family(address: IpAddr) -> &'static str {
    if address.is_ipv4() {
        "ip"
    } else {
        "ip6"
    }
}

fn nft_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

trait Backend {
    fn read(&mut self, path: &str) -> std::io::Result<String>;
    fn write(&mut self, path: &str, value: &str) -> std::io::Result<()>;
    fn nft(&mut self, args: &[&str], input: Option<&str>) -> std::io::Result<()>;
}

#[derive(Debug, Default)]
struct Host;

impl Backend for Host {
    fn read(&mut self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write(&mut self, path: &str, value: &str) -> std::io::Result<()> {
        std::fs::write(path, value)
    }

    fn nft(&mut self, args: &[&str], input: Option<&str>) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut command = Command::new("nft");
        command.args(args);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("nft stdin unavailable"))?
                .write_all(input.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }
}

#[derive(Debug)]
struct State<B> {
    backend: B,
    table: bool,
    changed_v4: bool,
    changed_v6: bool,
}

impl<B: Backend> State<B> {
    fn reconcile(&mut self, rules: &Ruleset, interface: &str) -> std::io::Result<()> {
        if rules.is_empty() {
            return self.clear();
        }

        // Check the executable before changing either forwarding knob.
        self.backend.nft(&["--version"], None)?;
        if !self.table {
            match self.backend.nft(&["add", "table", "inet", TABLE], None) {
                Ok(()) => self.table = true,
                Err(error) if error.to_string().contains("File exists") => self.table = true,
                Err(error) => return Err(error),
            }
        }

        if rules.ipv4 {
            self.enable(IPV4_FORWARD, true)?;
        }
        if rules.ipv6 {
            self.enable(IPV6_FORWARD, false)?;
        }

        if let Err(error) = self
            .backend
            .nft(&["-f", "-"], Some(&rules.nft_batch(interface)))
        {
            self.restore_forwarding();
            return Err(error);
        }

        if !rules.ipv4 {
            self.restore_one(IPV4_FORWARD, true);
        }
        if !rules.ipv6 {
            self.restore_one(IPV6_FORWARD, false);
        }
        Ok(())
    }

    fn enable(&mut self, path: &str, ipv4: bool) -> std::io::Result<()> {
        let changed = if ipv4 {
            &mut self.changed_v4
        } else {
            &mut self.changed_v6
        };
        if *changed {
            return Ok(());
        }
        if self.backend.read(path)?.trim() == "1" {
            return Ok(());
        }
        self.backend.write(path, "1\n")?;
        *changed = true;
        Ok(())
    }

    fn restore_one(&mut self, path: &str, ipv4: bool) {
        let changed = if ipv4 {
            &mut self.changed_v4
        } else {
            &mut self.changed_v6
        };
        if *changed {
            if let Err(error) = self.backend.write(path, "0\n") {
                tracing::warn!(path, %error, "could not restore gateway forwarding sysctl");
                return;
            }
            *changed = false;
        }
    }

    fn restore_forwarding(&mut self) {
        self.restore_one(IPV4_FORWARD, true);
        self.restore_one(IPV6_FORWARD, false);
    }

    fn clear(&mut self) -> std::io::Result<()> {
        if self.table {
            match self.backend.nft(&["delete", "table", "inet", TABLE], None) {
                Ok(()) => self.table = false,
                Err(error) if error.to_string().contains("No such file") => self.table = false,
                Err(error) => return Err(error),
            }
        }
        self.restore_forwarding();
        Ok(())
    }
}

/// Owns the host state required by this node's current gateway offers.
/// Dropping it removes only Karst's table and restores forwarding only when
/// Karst was the process that enabled it.
#[derive(Debug)]
pub struct Manager(State<Host>);

impl Default for Manager {
    fn default() -> Self {
        Self(State {
            backend: Host,
            table: false,
            changed_v4: false,
            changed_v6: false,
        })
    }
}

impl Manager {
    /// Reconcile host forwarding state with authenticated gateway offers.
    ///
    /// # Errors
    /// If nftables or a required forwarding sysctl cannot be applied.
    pub fn reconcile(&mut self, config: &Config) -> std::io::Result<Ruleset> {
        let rules = Ruleset::from_config(config);
        if let Err(error) = self.0.reconcile(&rules, &config.interface) {
            // Retaining the previous grant after an authorization-changing
            // netmap would be a security failure. Best-effort removal is safer
            // than serving stale policy, and any cleanup failure is included in
            // the readiness error operators see.
            return match self.0.clear() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(std::io::Error::other(format!(
                    "{error}; stale-state cleanup also failed: {cleanup}"
                ))),
            };
        }
        Ok(rules)
    }

    #[must_use]
    pub fn active(&self) -> bool {
        self.0.table
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.0.clear() {
            tracing::warn!(%error, "could not remove gateway forwarding state");
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
    use karst_control_client::transport::pb;

    fn offer(
        id: &str,
        prefix: &str,
        role: pb::KarstRouteRole,
        masquerade: bool,
    ) -> crate::route_offer::Offer {
        crate::route_offer::Offer::from_wire(
            pb::KarstRouteOffer {
                route_id: id.to_owned(),
                prefix: prefix.to_owned(),
                gateway_id: if role == pb::KarstRouteRole::Gateway {
                    vec![7]
                } else {
                    vec![8]
                },
                metric: 100,
                kind: if prefix.ends_with("/0") {
                    pb::KarstRouteKind::Exit as i32
                } else {
                    pb::KarstRouteKind::Subnet as i32
                },
                masquerade,
                keep_route: false,
                role: role as i32,
            },
            &[7],
        )
        .expect("offer")
    }

    fn config() -> Config {
        Config {
            relay_ca_file: None,
            route_offers: Vec::new(),
            exit_node_state_file: None,
            keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:51820".parse().unwrap(),
            port_mapping: false,
            interface: "karst0".to_owned(),
            network_mode: crate::config::NetworkMode::Tun,
            dns: crate::config::DnsSettings::default(),
            netmap_dns: crate::netmap::DNSConfig::default(),
            userspace_socks5_listen: None,
            userspace_publish: Vec::new(),
            nat64: None,
            addresses: vec![
                "100.64.0.7/16".parse().unwrap(),
                "fd7a:115c:a1e0::7/64".parse().unwrap(),
            ],
            psk_epoch: 1,
            node_id: vec![7],
            relays: Vec::new(),
            turn_servers: Vec::new(),
            peers: Vec::new(),
            routes: crate::routing::AllowedIps::build(Vec::<(Prefix, usize)>::new())
                .expect("empty routes"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
        }
    }

    #[test]
    fn only_gateway_offers_become_forwarding_grants() {
        let mut config = config();
        config.route_offers = vec![
            offer("lan", "192.168.50.0/24", pb::KarstRouteRole::Gateway, true),
            offer(
                "not-mine",
                "10.0.0.0/8",
                pb::KarstRouteRole::Recipient,
                true,
            ),
            offer("v6", "2001:db8:50::/64", pb::KarstRouteRole::Gateway, false),
        ];
        let rules = Ruleset::from_config(&config);
        assert_eq!(rules.grants.len(), 2);
        assert!(rules.ipv4 && rules.ipv6);
        assert_eq!(rules.grants[0].sources.len(), 1);
    }

    #[test]
    fn generated_rules_are_scoped_and_masquerade_only_when_requested() {
        let mut config = config();
        config.route_offers = vec![
            offer("lan", "192.168.50.0/24", pb::KarstRouteRole::Gateway, true),
            offer("v6", "2001:db8:50::/64", pb::KarstRouteRole::Gateway, false),
        ];
        let batch = Ruleset::from_config(&config).nft_batch("karst0");
        assert!(
            batch.contains("iifname \"karst0\" ip saddr 100.64.0.0/16 ip daddr 192.168.50.0/24")
        );
        assert!(batch.contains("ip daddr 192.168.50.0/24 counter masquerade"));
        assert!(!batch.contains("ip6 daddr 2001:db8:50::/64 counter masquerade"));
        assert!(batch.ends_with("iifname \"karst0\" counter drop\n"));
        assert!(!batch.contains("flush ruleset"));
    }

    #[test]
    fn nft_strings_cannot_inject_another_statement() {
        assert_eq!(
            nft_string("x\"; delete table inet filter"),
            "\"x\\\"; delete table inet filter\""
        );
    }

    #[derive(Default)]
    struct Mock {
        v4: bool,
        v6: bool,
        writes: Vec<(String, String)>,
        nft: Vec<(Vec<String>, Option<String>)>,
        fail_batch: bool,
    }

    impl Backend for Mock {
        fn read(&mut self, path: &str) -> std::io::Result<String> {
            let enabled = if path == IPV4_FORWARD {
                self.v4
            } else {
                self.v6
            };
            Ok(if enabled { "1\n" } else { "0\n" }.to_owned())
        }

        fn write(&mut self, path: &str, value: &str) -> std::io::Result<()> {
            if path == IPV4_FORWARD {
                self.v4 = value.trim() == "1";
            } else {
                self.v6 = value.trim() == "1";
            }
            self.writes.push((path.to_owned(), value.to_owned()));
            Ok(())
        }

        fn nft(&mut self, args: &[&str], input: Option<&str>) -> std::io::Result<()> {
            self.nft.push((
                args.iter().map(|arg| (*arg).to_owned()).collect(),
                input.map(str::to_owned),
            ));
            if self.fail_batch && input.is_some() {
                Err(std::io::Error::other("synthetic nft failure"))
            } else {
                Ok(())
            }
        }
    }

    fn state(backend: Mock) -> State<Mock> {
        State {
            backend,
            table: false,
            changed_v4: false,
            changed_v6: false,
        }
    }

    #[test]
    fn runtime_owns_only_forwarding_values_it_changed() {
        let mut config = config();
        config.route_offers = vec![offer(
            "lan",
            "192.168.50.0/24",
            pb::KarstRouteRole::Gateway,
            true,
        )];
        let rules = Ruleset::from_config(&config);
        let mut runtime = state(Mock {
            v4: true,
            ..Mock::default()
        });

        runtime.reconcile(&rules, "karst0").unwrap();
        assert!(
            runtime.backend.writes.is_empty(),
            "pre-existing v4 forwarding is not ours"
        );
        runtime.clear().unwrap();
        assert!(
            runtime.backend.v4,
            "cleanup preserves pre-existing forwarding"
        );
        assert!(runtime.backend.nft.iter().all(|(_, input)| {
            input
                .as_deref()
                .is_none_or(|batch| !batch.contains("flush ruleset"))
        }));
    }

    #[test]
    fn a_failed_atomic_batch_rolls_back_the_forwarding_knob() {
        let mut config = config();
        config.route_offers = vec![offer(
            "lan",
            "192.168.50.0/24",
            pb::KarstRouteRole::Gateway,
            false,
        )];
        let rules = Ruleset::from_config(&config);
        let mut runtime = state(Mock {
            fail_batch: true,
            ..Mock::default()
        });

        assert!(runtime.reconcile(&rules, "karst0").is_err());
        assert!(!runtime.backend.v4);
        assert_eq!(
            runtime.backend.writes,
            vec![
                (IPV4_FORWARD.to_owned(), "1\n".to_owned()),
                (IPV4_FORWARD.to_owned(), "0\n".to_owned()),
            ]
        );
    }
}
