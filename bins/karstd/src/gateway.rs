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
    pub input_guard: bool,
    pub local_addresses: Vec<IpAddr>,
    pub machine_access: Vec<(Prefix, u16, u16)>,
}

impl Ruleset {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let mut grants = Vec::new();
        for offer in config
            .route_offers
            .iter()
            .filter(|offer| config.gateway_forwarding && offer.role == Role::Gateway)
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
        // Most specific destination first, route_id as a deterministic
        // tiebreak. nftables `accept` is a terminating verdict per chain, so
        // whichever grant's rule is generated (and therefore matched) first
        // "wins" a packet whose destination falls under more than one
        // grant's prefix — e.g. an exit route (`0.0.0.0/0`) and a subnet
        // route (`10.0.0.0/8`) on the same gateway. Sorting by route_id
        // alone (as before) let that collision resolve alphabetically,
        // silently misattributing one route's traffic to the other once
        // these rules' counters are read back for per-route throughput
        // (issue #281). Ordering by specificity instead means the most
        // specific grant's rule always matches first, which is also the
        // only sound attribution: the fact that a `/8` is "inside" a `/0`
        // never flows the other way.
        grants.sort_by(|a, b| {
            b.destination
                .len()
                .cmp(&a.destination.len())
                .then_with(|| a.route_id.cmp(&b.route_id))
        });
        let input_guard = config.filter.has_scoped_ingress();
        let machine_access = config
            .peers
            .iter()
            .enumerate()
            .flat_map(|(index, peer)| {
                config
                    .filter
                    .machine_ports(index)
                    .into_iter()
                    .flat_map(move |(first, last)| {
                        peer.allowed_ips
                            .iter()
                            .map(move |source| (*source, first, last))
                    })
            })
            .collect();
        Self {
            input_guard,
            local_addresses: config.addresses.iter().map(|a| a.addr).collect(),
            machine_access,
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
        self.grants.is_empty() && !self.input_guard
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
        if self.input_guard {
            // The userspace datapath knows overlay addresses, while the kernel
            // also owns LAN/public addresses and aliases. A forwarding-only
            // grant must never turn into INPUT access through those addresses.
            let _ = writeln!(out, "add chain inet {TABLE} input {{ type filter hook input priority -10; policy accept; }}");
            for address in &self.local_addresses {
                let _ = writeln!(
                    out,
                    "add rule inet {TABLE} input iifname {interface} {} daddr {address} accept",
                    family(*address)
                );
            }
            for (source, first, last) in &self.machine_access {
                let family = family(source.base());
                if *first == 0 && *last == u16::MAX {
                    let _ = writeln!(out, "add rule inet {TABLE} input iifname {interface} {family} saddr {source} accept");
                } else {
                    let _ = writeln!(out, "add rule inet {TABLE} input iifname {interface} {family} saddr {source} meta l4proto {{ tcp, udp }} th dport {first}-{last} accept");
                    if *first == 0 {
                        let _ = writeln!(out, "add rule inet {TABLE} input iifname {interface} {family} saddr {source} meta l4proto != {{ tcp, udp }} accept");
                    }
                }
            }
            let _ = writeln!(
                out,
                "add rule inet {TABLE} input iifname {interface} counter drop"
            );
        }
        for grant in &self.grants {
            let family = family(grant.destination.base());
            for source in &grant.sources {
                let _ = writeln!(
                    out,
                    "add rule inet {TABLE} forward iifname {interface} {family} saddr {source} {family} daddr {} counter accept comment {}",
                    grant.destination,
                    nft_string(&grant.route_id),
                );
                // A specific non-NAT grant must terminate our NAT chain;
                // otherwise an overlapping default grant masquerades it.
                let verdict = if grant.masquerade {
                    "masquerade"
                } else {
                    "return"
                };
                let _ = writeln!(
                    out,
                    "add rule inet {TABLE} postrouting iifname {interface} oifname != {interface} {family} saddr {source} {family} daddr {} counter {verdict} comment {}",
                    grant.destination,
                    nft_string(&grant.route_id),
                );
            }
        }
        // Return-leg rules, one per (grant, source), mirroring the forward
        // loop above with saddr/daddr swapped: a reply's source is the
        // original destination prefix, its destination is back to the
        // original source range. Emitted in the same order as `self.grants`
        // (most-specific-destination-first, from `Ruleset::from_config`) —
        // that field is matched via `daddr` on the forward leg above but via
        // `saddr` here, so reusing the existing order (rather than
        // re-deriving one) is what keeps both legs' attribution consistent
        // for a gateway serving overlapping routes (e.g. a `/0` exit route
        // and a `/8` subnet route). Replacing the old shared, uncommented
        // `established,related` rule entirely: every packet it admitted is
        // the reply to a flow one of the per-grant forward rules above
        // already admitted, so these rules cover the same traffic with
        // attribution and nothing is left for a fallback to catch.
        for grant in &self.grants {
            let family = family(grant.destination.base());
            for source in &grant.sources {
                let _ = writeln!(
                    out,
                    "add rule inet {TABLE} forward oifname {interface} ct state established,related {family} saddr {} {family} daddr {source} counter accept comment {}",
                    grant.destination,
                    nft_string(&grant.route_id),
                );
            }
        }
        // Anything else arriving from the TUN that didn't match a grant
        // above is stopped here; the base-chain accept policy deliberately
        // leaves unrelated host forwarding to the operator's own rules.
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
    /// Like [`Backend::nft`], but for a read-only query whose stdout is the
    /// point of the call — `nft`'s own discards it (`Stdio::null()`), since
    /// every other caller is a write applied for its side effect.
    fn nft_output(&mut self, args: &[&str]) -> std::io::Result<String>;
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

    fn nft_output(&mut self, args: &[&str]) -> std::io::Result<String> {
        use std::process::{Command, Stdio};

        let output = Command::new("nft")
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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

    fn remove_owned_table(&mut self) -> std::io::Result<()> {
        match self.backend.nft(&["delete", "table", "inet", TABLE], None) {
            Ok(()) => self.table = false,
            Err(error) if error.to_string().contains("No such file") => self.table = false,
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn clear(&mut self) -> std::io::Result<()> {
        if self.table {
            self.remove_owned_table()?;
        }
        self.restore_forwarding();
        Ok(())
    }
}

/// Owns the host state required by this node's current gateway offers.
/// Dropping it removes only Karst's table and restores forwarding only when
/// Karst was the process that enabled it.
#[derive(Debug)]
pub struct Manager {
    state: State<Host>,
    input_guard_required: bool,
    ready: bool,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            state: State {
                backend: Host,
                table: false,
                changed_v4: false,
                changed_v6: false,
            },
            input_guard_required: false,
            ready: false,
        }
    }
}

impl Manager {
    /// Reconcile host forwarding state with authenticated gateway offers.
    ///
    /// # Errors
    /// If nftables or a required forwarding sysctl cannot be applied.
    pub fn reconcile(&mut self, config: &Config) -> std::io::Result<Ruleset> {
        let mut rules = Ruleset::from_config(config);
        // Keep INPUT protection until shutdown once used. Packets already
        // queued to the TUN must not lose their guard during withdrawal.
        self.input_guard_required |= rules.input_guard;
        rules.input_guard = self.input_guard_required;
        self.ready = false;
        if !config.gateway_forwarding && cfg!(target_os = "linux") && !self.input_guard_required {
            // Explicit refusal also removes our table left by a prior crash.
            // Never reset host sysctls whose ownership this process cannot know.
            self.state.remove_owned_table()?;
        }
        if let Err(error) = self.state.reconcile(&rules, &config.interface) {
            if self.input_guard_required {
                // Never remove INPUT protection on an apply error. The
                // datapath readiness gate blocks transit before flow lookup,
                // including established flows, until a later successful apply.
                return Err(error);
            }
            // Retaining the previous grant after an authorization-changing
            // netmap would be a security failure. Best-effort removal is safer
            // than serving stale policy, and any cleanup failure is included in
            // the readiness error operators see.
            return match self.state.clear() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(std::io::Error::other(format!(
                    "{error}; stale-state cleanup also failed: {cleanup}"
                ))),
            };
        }
        self.ready = true;
        Ok(rules)
    }

    #[must_use]
    pub fn input_guard_required(&self) -> bool {
        self.input_guard_required
    }

    #[must_use]
    pub fn active(&self) -> bool {
        self.state.table && self.ready
    }

    /// Egress and ingress bytes/packets this gateway has forwarded per
    /// route, for NOC visibility (issues #281, #371) — never for
    /// planner/scaling input, settled out of scope by #282. Read back from
    /// `karst_routes`'s own live counters rather than tracked separately,
    /// so this can never drift from what the kernel actually forwarded.
    ///
    /// # Errors
    /// If `nft` is unavailable or its JSON output cannot be parsed. Treat
    /// this the same as a failed anchor-RTT probe: advisory telemetry, log
    /// and skip rather than fail whatever triggered the read.
    pub fn route_bytes(&mut self) -> std::io::Result<Vec<RouteBytes>> {
        let output = self
            .state
            .backend
            .nft_output(&["-j", "list", "table", "inet", TABLE])?;
        parse_route_bytes(&output)
            .map_err(|error| std::io::Error::other(format!("parse nft -j output: {error}")))
    }
}

/// One route's egress and ingress byte/packet counts, read back from its
/// forward-accept rules' own nftables counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteBytes {
    pub route_id: String,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
}

/// True if a comment-tagged `forward`-chain rule is the egress (forward)
/// leg — matched on `iifname` — rather than the ingress (return) leg,
/// matched on `oifname`. `Ruleset::nft_batch` emits exactly one or the
/// other for every comment-tagged rule, never both.
fn is_egress_rule(rule: &serde_json::Value) -> bool {
    rule.get("expr")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|expr| expr.get("match"))
        .any(|m| {
            m.get("left")
                .and_then(|left| left.get("meta"))
                .and_then(|meta| meta.get("key"))
                .and_then(serde_json::Value::as_str)
                == Some("iifname")
        })
}

/// Sums every `forward`-chain, comment-tagged rule's counter by comment
/// (the `route_id` `Ruleset::nft_batch` writes there), split into egress vs.
/// ingress by [`is_egress_rule`]. The catch-all drop rule carries no comment
/// and is excluded by that alone; the `postrouting` chain's masquerade rule
/// is excluded by chain name, since it counts the same packets the
/// `forward` rule already did and would double the total if summed too.
///
/// Reads `nft -j`'s own JSON as a generic [`serde_json::Value`] rather than
/// strongly-typed structs: nft's schema tags each `expr` entry by a single
/// object key (`"match"`, `"counter"`, `"accept"`, ...), which a `Value`
/// walk tolerates far better than a struct would if a future nft version
/// adds a field this code does not know about.
fn parse_route_bytes(output: &str) -> Result<Vec<RouteBytes>, serde_json::Error> {
    use std::collections::HashMap;

    let root: serde_json::Value = serde_json::from_str(output)?;
    let mut totals: HashMap<String, RouteBytes> = HashMap::new();
    let items = root
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten();
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule.get("chain").and_then(serde_json::Value::as_str) != Some("forward") {
            continue;
        }
        let Some(route_id) = rule.get("comment").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let egress = is_egress_rule(rule);
        let exprs = rule
            .get("expr")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten();
        for expr in exprs {
            let Some(counter) = expr.get("counter") else {
                continue;
            };
            let bytes = counter
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let packets = counter
                .get("packets")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let entry = totals
                .entry(route_id.to_owned())
                .or_insert_with(|| RouteBytes {
                    route_id: route_id.to_owned(),
                    ..RouteBytes::default()
                });
            if egress {
                entry.egress_bytes += bytes;
                entry.egress_packets += packets;
            } else {
                entry.ingress_bytes += bytes;
                entry.ingress_packets += packets;
            }
        }
    }
    let mut totals: Vec<RouteBytes> = totals.into_values().collect();
    totals.sort_by(|a, b| a.route_id.cmp(&b.route_id));
    Ok(totals)
}

impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.state.clear() {
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
            prefer_quic_relay: false,
            metrics_listen: None,
            tracing_collector: None,
            route_offers: Vec::new(),
            exit_node_state_file: None,
            gateway_forwarding: true,
            keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(&[0x11; 64])),
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
            peers: Vec::new(),
            routes: crate::routing::AllowedIps::build(Vec::<(Prefix, usize)>::new())
                .expect("empty routes"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
            ssh_filter: crate::filter::SshFilter::absent(),
            datapath_workers: 1,
            anchor_probe_enabled: false,
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
    fn local_forwarding_switch_gates_both_behaviors_and_families() {
        let mut config = config();
        config.route_offers = vec![
            offer("lan", "192.168.50.0/24", pb::KarstRouteRole::Gateway, true),
            offer("internet", "0.0.0.0/0", pb::KarstRouteRole::Gateway, true),
            offer("internet-v6", "::/0", pb::KarstRouteRole::Gateway, true),
        ];
        assert_eq!(Ruleset::from_config(&config).grants.len(), 3);
        config.gateway_forwarding = false;
        let rules = Ruleset::from_config(&config);
        assert!(rules.is_empty());
        assert!(!rules.ipv4 && !rules.ipv6);
        assert_eq!(
            config.route_offers.len(),
            3,
            "offers remain visible for diagnostics"
        );
    }

    #[test]
    fn scoped_ingress_installs_an_input_guard_even_without_route_offers() {
        let mut config = config();
        config.filter = crate::filter::PacketFilter::compile(
            &[pb::KarstFilterRule {
                srcs: vec!["client".to_owned()],
                dst_cidrs: vec!["0.0.0.0/0".to_owned()],
                ports: vec![pb::KarstPortRange {
                    first: 0,
                    last: 65535,
                }],
            }],
            &[],
            &[b"client".to_vec()],
        );
        let rules = Ruleset::from_config(&config);
        assert!(
            !rules.is_empty(),
            "local-address protection cannot depend on route publication"
        );
        assert!(
            rules.machine_access.is_empty(),
            "forwarding scope cannot authorize machine INPUT"
        );
        let batch = rules.nft_batch("karst0");
        assert!(batch.contains("type filter hook input priority -10; policy accept;"));
        assert!(batch.contains("input iifname \"karst0\" ip daddr 100.64.0.7 accept"));
        assert!(batch.contains("input iifname \"karst0\" ip6 daddr fd7a:115c:a1e0::7 accept"));
        assert!(batch.contains("input iifname \"karst0\" counter drop"));
        assert!(!batch.contains("ct state established,related accept"));
    }

    /// Run under root (or `CAP_SYS_ADMIN/CAP_NET_ADMIN`). The child owns a fresh
    /// network namespace, so no host interfaces, routes or firewall are changed.
    #[test]
    #[ignore = "requires root, unshare, nft, ip, python3 and /dev/net/tun"]
    fn scoped_input_guard_blocks_gateway_aliases_in_the_kernel() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let rules = Ruleset {
            input_guard: true,
            local_addresses: vec!["100.64.0.7".parse().unwrap(), "fd00::7".parse().unwrap()],
            machine_access: vec![
                ("100.64.0.2/32".parse().unwrap(), 8443, 8443),
                ("fd00::2/128".parse().unwrap(), 8443, 8443),
            ],
            ..Default::default()
        };
        let batch = format!("add table inet {TABLE}\n{}", rules.nft_batch("karst0"));
        let script = r"
import fcntl, os, socket, struct, subprocess, sys
batch = sys.stdin.read()
fd = os.open('/dev/net/tun', os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', b'karst0', 0x1001))
def ip(*args): subprocess.run(['ip', *args], check=True)
ip('link', 'set', 'lo', 'up')
ip('link', 'set', 'karst0', 'up')
ip('addr', 'add', '100.64.0.7/24', 'dev', 'karst0')
ip('addr', 'add', 'fd00::7/64', 'dev', 'karst0', 'nodad')
ip('addr', 'add', '192.0.2.7/32', 'dev', 'lo')
ip('addr', 'add', '2001:db8::7/128', 'dev', 'lo', 'nodad')
subprocess.run(['nft', '-f', '-'], input=batch, text=True, check=True)
def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535
def packet(destination, port):
    v6 = ':' in destination
    family = socket.AF_INET6 if v6 else socket.AF_INET
    source = socket.inet_pton(family, 'fd00::2' if v6 else '100.64.0.2')
    dest = socket.inet_pton(family, destination)
    udp = struct.pack('!HHHH', 40000, port, 9, 0) + b'x'
    pseudo = source + dest + (struct.pack('!I3xB', len(udp), 17) if v6 else struct.pack('!BBH', 0, 17, len(udp)))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo+udp) or 65535) + udp[8:]
    if v6: return struct.pack('!IHBB', 6 << 28, len(udp), 17, 64) + source + dest + udp
    header = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0) + source + dest
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + udp
def check(destination, port, allowed):
    family = socket.AF_INET6 if ':' in destination else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as listener:
        listener.bind((destination, port)); listener.settimeout(0.2)
        os.write(fd, packet(destination, port))
        try: data = listener.recv(8)
        except TimeoutError: data = None
        assert (data == b'x') == allowed, (destination, port, allowed, data)
for overlay, alias in [('100.64.0.7','192.0.2.7'), ('fd00::7','2001:db8::7')]:
    check(overlay, 9443, True) # overlay admission is checked in the datapath
    check(alias, 9443, False) # scope must not become local-service access
    check(alias, 8443, True) # explicit machine grants remain additive
print('IPv4/IPv6 local aliases denied; explicit machine ports preserved')
";
        let mut child = Command::new("unshare")
            .args(["--net", "--", "python3", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(batch.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
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
        assert!(batch.contains(
            "oifname \"karst0\" ct state established,related ip saddr 192.168.50.0/24 \
             ip daddr 100.64.0.0/16 counter accept comment \"lan\""
        ));
        assert!(batch.contains(
            "oifname \"karst0\" ct state established,related ip6 saddr 2001:db8:50::/64 \
             ip6 daddr fd7a:115c:a1e0::/64 counter accept comment \"v6\""
        ));
        assert!(
            !batch.contains("oifname \"karst0\" ct state established,related counter accept"),
            "the old shared, uncommented return-leg rule must not be reintroduced \
             alongside the per-grant ones, or it would again count return \
             traffic without attribution"
        );
        assert!(batch.ends_with("iifname \"karst0\" counter drop\n"));
        assert!(!batch.contains("flush ruleset"));
    }

    #[test]
    fn specific_non_nat_prefixes_bypass_overlapping_default_nat_in_both_families() {
        let mut config = config();
        config.route_offers = vec![
            offer("v4-exit", "0.0.0.0/0", pb::KarstRouteRole::Gateway, true),
            offer("v6-exit", "::/0", pb::KarstRouteRole::Gateway, true),
            offer("v4-lan", "10.99.0.0/24", pb::KarstRouteRole::Gateway, false),
            offer("v6-lan", "fd99::/64", pb::KarstRouteRole::Gateway, false),
        ];
        let batch = Ruleset::from_config(&config).nft_batch("karst0");
        for (specific, default) in [
            (
                "ip daddr 10.99.0.0/24 counter return",
                "ip daddr 0.0.0.0/0 counter masquerade",
            ),
            (
                "ip6 daddr fd99::/64 counter return",
                "ip6 daddr ::/0 counter masquerade",
            ),
        ] {
            assert!(batch.find(specific).unwrap() < batch.find(default).unwrap());
        }
    }

    #[test]
    fn grants_are_ordered_most_specific_destination_first() {
        // "wide" (a /0 exit route) and "narrow" (a /8 subnet route) on the
        // same gateway overlap: every address "narrow" covers is also
        // inside "wide". nftables `accept` is a terminating verdict, so
        // whichever grant's forward-accept rule is generated first claims
        // any packet destined within the overlap. Alphabetical route_id
        // order ("narrow" < "wide") would happen to get this right here,
        // so the offers are named to fail that way round and only pass
        // under genuine specificity ordering.
        let mut config = config();
        config.route_offers = vec![
            offer("z-wide", "0.0.0.0/0", pb::KarstRouteRole::Gateway, true),
            offer("a-narrow", "10.0.0.0/8", pb::KarstRouteRole::Gateway, true),
        ];
        let rules = Ruleset::from_config(&config);
        assert_eq!(
            rules
                .grants
                .iter()
                .map(|g| g.route_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-narrow", "z-wide"]
        );
        let batch = rules.nft_batch("karst0");
        let narrow = batch.find("comment \"a-narrow\"").expect("narrow rule");
        let wide = batch.find("comment \"z-wide\"").expect("wide rule");
        assert!(
            narrow < wide,
            "the /8 grant's rule must be generated before the /0 grant's, \
             or the wide route's rule would claim every packet the narrow \
             route is actually authorized for"
        );
    }

    #[test]
    fn return_leg_rules_are_ordered_most_specific_destination_first() {
        // Same overlap as `grants_are_ordered_most_specific_destination_first`,
        // but for the return leg: a reply from an address inside both
        // "narrow"'s and "wide"'s destination prefix matches the return
        // rule's `saddr` (the original forward rule's `daddr`), so the same
        // most-specific-first ordering must hold there too, or the wide
        // route's return rule would claim a reply that actually belongs to
        // the narrow route.
        let mut config = config();
        config.route_offers = vec![
            offer("z-wide", "0.0.0.0/0", pb::KarstRouteRole::Gateway, true),
            offer("a-narrow", "10.0.0.0/8", pb::KarstRouteRole::Gateway, true),
        ];
        let batch = Ruleset::from_config(&config).nft_batch("karst0");
        let narrow = batch
            .find("oifname \"karst0\" ct state established,related ip saddr 10.0.0.0/8")
            .expect("narrow return rule");
        let wide = batch
            .find("oifname \"karst0\" ct state established,related ip saddr 0.0.0.0/0")
            .expect("wide return rule");
        assert!(
            narrow < wide,
            "the /8 grant's return rule must be generated before the /0 \
             grant's, or the wide route's rule would claim every reply the \
             narrow route is actually authorized for"
        );
    }

    #[test]
    fn route_bytes_sums_egress_and_ingress_separately() {
        // A trimmed, real `nft -j list table inet karst_routes` shape
        // (captured live against this crate's own ruleset): a forward-chain,
        // `iifname`-matched rule with a comment and counter (the per-route
        // egress accept), a forward-chain, `oifname`-matched rule with the
        // *same* comment and its own counter (the per-route ingress/return
        // accept — must be summed separately, not merged into egress), a
        // postrouting-chain rule that DOES carry the same comment (the
        // masquerade rule — must be excluded by chain, or egress would be
        // doubled), an uncommented `oifname`-matched forward rule (must be
        // excluded by the comment check alone, regardless of direction),
        // and the catch-all drop (no comment, no counter contribution).
        let output = r#"{
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {"table": {"family": "inet", "name": "karst_routes", "handle": 1}},
                {"rule": {
                    "family": "inet", "table": "karst_routes", "chain": "forward",
                    "handle": 2, "comment": "route-a",
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "karst0"}},
                        {"counter": {"packets": 10, "bytes": 1000}},
                        {"accept": null}
                    ]
                }},
                {"rule": {
                    "family": "inet", "table": "karst_routes", "chain": "forward",
                    "handle": 6, "comment": "route-a",
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "karst0"}},
                        {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "established,related"}},
                        {"counter": {"packets": 5, "bytes": 500}},
                        {"accept": null}
                    ]
                }},
                {"rule": {
                    "family": "inet", "table": "karst_routes", "chain": "postrouting",
                    "handle": 3, "comment": "route-a",
                    "expr": [
                        {"counter": {"packets": 10, "bytes": 1000}},
                        {"masquerade": null}
                    ]
                }},
                {"rule": {
                    "family": "inet", "table": "karst_routes", "chain": "forward",
                    "handle": 4,
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "karst0"}},
                        {"counter": {"packets": 999, "bytes": 99900}},
                        {"accept": null}
                    ]
                }},
                {"rule": {
                    "family": "inet", "table": "karst_routes", "chain": "forward",
                    "handle": 5,
                    "expr": [
                        {"counter": {"packets": 0, "bytes": 0}},
                        {"drop": null}
                    ]
                }}
            ]
        }"#;
        assert_eq!(
            parse_route_bytes(output).expect("parse"),
            vec![RouteBytes {
                route_id: "route-a".to_owned(),
                egress_bytes: 1000,
                egress_packets: 10,
                ingress_bytes: 500,
                ingress_packets: 5,
            }]
        );
    }

    #[test]
    fn is_egress_rule_distinguishes_iifname_from_oifname_match() {
        let iifname_rule: serde_json::Value = serde_json::from_str(
            r#"{"expr": [{"match": {"left": {"meta": {"key": "iifname"}}, "right": "karst0"}}]}"#,
        )
        .expect("parse");
        let oifname_rule: serde_json::Value = serde_json::from_str(
            r#"{"expr": [{"match": {"left": {"meta": {"key": "oifname"}}, "right": "karst0"}}]}"#,
        )
        .expect("parse");
        assert!(is_egress_rule(&iifname_rule));
        assert!(!is_egress_rule(&oifname_rule));
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
        nft_output: String,
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

        fn nft_output(&mut self, _args: &[&str]) -> std::io::Result<String> {
            Ok(self.nft_output.clone())
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
    fn explicit_disable_removes_an_owned_table_without_in_memory_ownership() {
        let mut runtime = state(Mock {
            v4: true,
            ..Mock::default()
        });
        assert!(!runtime.table);
        runtime.remove_owned_table().unwrap();
        assert!(runtime
            .backend
            .nft
            .iter()
            .any(|(args, _)| args == &["delete", "table", "inet", TABLE]));
        assert!(
            runtime.backend.writes.is_empty(),
            "pre-existing host forwarding is not ours to reset"
        );
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
