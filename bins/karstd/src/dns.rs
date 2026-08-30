// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Turn authenticated netmap DNS data into the resolver's typed configuration.

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]
#![cfg_attr(
    test,
    allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)
)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use karst_dns::{Config, MeshPeer, Resolver, Route};

use crate::netmap::Netmap;

/// The selected host resolver mechanism. It is owned beside the listeners so
/// the host is changed only after a live stub has successfully bound.
#[derive(Debug)]
pub enum HostRuntime {
    None,
    Resolved(karst_dns::host::Resolved),
    NetworkManager(karst_dns::host::NetworkManager),
    ResolvConf(karst_dns::host::Controller),
    /// macOS's `/etc/resolver` directory. The variant is compiled on every
    /// platform even though only macOS selects it, so a Linux build type-checks
    /// this path rather than discovering it on the release runner.
    Macos(karst_dns::host::Macos),
}

impl HostRuntime {
    /// Select one mechanism. `Auto` prefers resolved because its link routing
    /// domains preserve the host's normal DNS behavior; NetworkManager is the
    /// next choice only when resolved is unavailable.
    pub fn new(
        settings: &crate::config::DnsSettings,
        ifindex: Option<u32>,
        interface: &str,
    ) -> Result<Self, String> {
        use crate::config::HostIntegration;

        let resolved = || {
            let index =
                ifindex.ok_or_else(|| "DNS host integration requires a kernel TUN".to_owned())?;
            let index =
                i32::try_from(index).map_err(|_| "TUN interface index is too large".to_owned())?;
            karst_dns::host::Resolved::connect(index).map_err(|error| error.to_string())
        };
        let network_manager = || {
            karst_dns::host::NetworkManager::connect(interface).map_err(|error| error.to_string())
        };
        let resolvconf = || {
            let controller =
                karst_dns::host::Controller::new(karst_dns::host::ResolvConf::system());
            controller.recover().map_err(|error| error.to_string())?;
            Ok::<_, String>(Self::ResolvConf(controller))
        };
        // `/etc/resolver` files are the whole split-DNS story on macOS: one
        // file per domain, longest suffix wins, and non-mesh names keep the
        // resolvers the host already had. Recovering first is what consumes a
        // record left by a killed daemon before this run can write its own.
        //
        // **`karst-dns` compiles this mechanism everywhere**, so the closure is
        // not `cfg`-gated and every platform type-checks it. Whether it is
        // *selected* is the question below, and off macOS the answer is never.
        #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
        let macos = || {
            let mut host = karst_dns::host::Macos::system();
            host.recover().map_err(|error| error.to_string())?;
            Ok::<_, String>(Self::Macos(host))
        };
        match settings.host_integration {
            HostIntegration::None => Ok(Self::None),
            HostIntegration::Resolved => resolved().map(Self::Resolved),
            HostIntegration::Networkmanager => network_manager().map(Self::NetworkManager),
            HostIntegration::Resolvconf => resolvconf(),
            #[cfg(target_os = "macos")]
            HostIntegration::Macos => macos(),
            // Refused rather than quietly accepted. Writing `/etc/resolver`
            // files on Linux would leave real state on the host and change no
            // resolution whatsoever, which is the worst of both outcomes.
            #[cfg(not(target_os = "macos"))]
            HostIntegration::Macos => Err(
                "dns.host_integration = \"macos\" is the /etc/resolver mechanism \
                 and only macOS reads that directory"
                    .to_owned(),
            ),
            // macOS: `/etc/resolver` files, which make every mesh name resolve
            // system-wide. The resolver search list is not part of this and is
            // not implemented — see `karst_dns::host::Macos` for why a `scutil`
            // child process cannot supply it — so a bare hostname still needs
            // its domain. `karst status` reports the mechanism either way.
            #[cfg(target_os = "macos")]
            HostIntegration::Auto => macos(),
            // Neither Linux nor macOS. Every mechanism Karst implements belongs
            // to one of those two, so `Auto` selects nothing rather than
            // falling through to `resolvconf`.
            //
            // **That fall-through would be worse than doing nothing.** It would
            // leave a modified system file, and a revert file for it, on a
            // machine whose resolver may never consult either. Announcing the
            // gap is the honest outcome, and the daemon's DNS resolver still
            // listens for anything pointed at it explicitly.
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            HostIntegration::Auto => {
                eprintln!(
                    "karstd: host DNS integration is not implemented on this \
                     platform; mesh names will not resolve system-wide. Set \
                     dns.host_integration explicitly to override."
                );
                Ok(Self::None)
            }
            #[cfg(target_os = "linux")]
            HostIntegration::Auto => {
                if let Ok(value) = resolved() {
                    return Ok(Self::Resolved(value));
                }
                if let Ok(value) = network_manager() {
                    return Ok(Self::NetworkManager(value));
                }
                resolvconf()
            }
        }
    }

    /// Apply the current MagicDNS state, or restore host DNS immediately when
    /// the control plane turns it off.
    pub fn update(&mut self, config: &crate::config::Config) -> Result<(), String> {
        let enabled = config.dns.enabled && config.netmap_dns.magic_dns;
        match self {
            Self::None => Ok(()),
            Self::Resolved(resolved) => {
                if enabled {
                    resolved
                        .apply(
                            config.dns.stub_address,
                            &config.netmap_dns.zone,
                            &config.netmap_dns.search_domains,
                        )
                        .map_err(|error| error.to_string())
                } else {
                    resolved.revert().map_err(|error| error.to_string())
                }
            }
            Self::NetworkManager(network_manager) => {
                if enabled {
                    network_manager
                        .apply(
                            config.dns.stub_address,
                            &config.netmap_dns.zone,
                            &config.netmap_dns.search_domains,
                        )
                        .map_err(|error| error.to_string())
                } else {
                    network_manager.revert().map_err(|error| error.to_string())
                }
            }
            Self::ResolvConf(controller) => controller
                .update(
                    enabled,
                    &config.dns.stub_address.ip().to_string(),
                    &config.netmap_dns.search_domains,
                )
                .map_err(|error| error.to_string()),
            Self::Macos(macos) => {
                if enabled {
                    macos.apply(
                        config.dns.stub_address,
                        &config.netmap_dns.zone,
                        &config.netmap_dns.search_domains,
                    )
                } else {
                    macos.revert()
                }
                .map_err(|error| error.to_string())?;
                // The resolver files are already correct when this is set; the
                // flush that follows them is what stops `mDNSResponder` serving
                // the answers it cached before the change. Reporting it as an
                // apply failure would say the opposite of what happened, so it
                // is a warning on its own.
                if let Some(detail) = macos.flush_error() {
                    eprintln!(
                        "karstd: resolver files applied, but the DNS cache was \
                         not flushed ({detail}); names may resolve to their \
                         previous answers until the cache expires"
                    );
                }
                Ok(())
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        match self {
            Self::None => Ok(()),
            Self::Resolved(resolved) => resolved.revert().map_err(|error| error.to_string()),
            Self::NetworkManager(network_manager) => {
                network_manager.revert().map_err(|error| error.to_string())
            }
            Self::ResolvConf(controller) => {
                controller.shutdown().map_err(|error| error.to_string())
            }
            Self::Macos(macos) => macos.revert().map_err(|error| error.to_string()),
        }
    }

    /// Read current host ownership without altering host state.
    pub fn observe(&self) -> Result<&'static str, String> {
        match self {
            Self::None => Ok("not configured"),
            Self::Resolved(resolved) => resolved
                .observe()
                .map(|applied| {
                    if applied {
                        "configured"
                    } else {
                        "not configured"
                    }
                })
                .map_err(|error| error.to_string()),
            Self::NetworkManager(network_manager) => network_manager
                .observe()
                .map(|applied| {
                    if applied {
                        "configured"
                    } else {
                        "not configured"
                    }
                })
                .map_err(|error| error.to_string()),
            Self::ResolvConf(controller) => controller
                .observe()
                .map(|applied| {
                    if applied {
                        "configured"
                    } else {
                        "not configured"
                    }
                })
                .map_err(|error| error.to_string()),
            Self::Macos(macos) => macos
                .observe()
                .map(|applied| {
                    if applied {
                        "configured"
                    } else {
                        "not configured"
                    }
                })
                .map_err(|error| error.to_string()),
        }
    }

    #[must_use]
    pub const fn mechanism(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Resolved(_) => "systemd-resolved",
            Self::NetworkManager(_) => "networkmanager",
            Self::ResolvConf(_) => "resolv.conf",
            Self::Macos(_) => "/etc/resolver",
        }
    }
}

/// Undo whatever host DNS integration is currently applied, without a running
/// daemon. This is what `karst dns revert` calls — including from
/// `ExecStopPost=`, where the process that applied the change has already
/// exited and the TUN interface it used may already be gone with it.
///
/// Reconstructing a [`HostRuntime`] recovers the persisted mechanism the same
/// way daemon startup does, then [`HostRuntime::shutdown`] reverts it
/// unconditionally — independent of whether MagicDNS is currently on or off,
/// since the point of this path is a clean host regardless.
///
/// # Errors
/// A string describing the failure. A missing interface is not one: it means
/// the link-scoped mechanisms (`resolved`, NetworkManager) already lost their
/// state along with the interface, which is the outcome revert wants anyway.
pub fn revert_host(settings: &crate::config::DnsSettings, interface: &str) -> Result<(), String> {
    use crate::config::HostIntegration;

    let interface_exists = std::path::Path::new("/sys/class/net")
        .join(interface)
        .exists();
    match settings.host_integration {
        HostIntegration::None => Ok(()),
        // The opposite case to the link-scoped one below, and the reason it is
        // named rather than left to fall through: `/etc/resolver` files are not
        // attached to the interface and outlive it, which is precisely why they
        // must be reverted when the TUN is already gone. Constructing the
        // runtime is what recovers a record a killed daemon left behind.
        HostIntegration::Macos => HostRuntime::new(settings, None, interface)?.shutdown(),
        // A mechanism pinned to a link-scoped backend never touched
        // `resolv.conf`, and the link's own DNS state disappears with it —
        // there is nothing left for either to revert.
        HostIntegration::Resolved | HostIntegration::Networkmanager if !interface_exists => Ok(()),
        _ => {
            let ifindex = std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
                .ok()
                .and_then(|contents| contents.trim().parse().ok());
            HostRuntime::new(settings, ifindex, interface)?.shutdown()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("netmap DNS resolver {value:?} is not an IP socket address")]
    Resolver { value: String },
    #[error("netmap peer {peer:?} has invalid mesh address {value:?}")]
    Address { peer: String, value: String },
    #[error(transparent)]
    Config(#[from] karst_dns::Error),
}

/// UDP and TCP listeners owned together so a netmap replacement can stop the
/// old authoritative zone before installing the new one.
pub struct Runtime {
    stopping: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    resolver: Resolver,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Bind both DNS transports. The caller supplies an unprivileged address in
    /// tests/userspace mode or the socket-unit/TUN address in kernel mode.
    pub fn start(address: SocketAddr, resolver: Resolver) -> std::io::Result<Self> {
        let udp = UdpSocket::bind(address)?;
        let tcp = TcpListener::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        tcp.set_nonblocking(true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let tcp_resolver = resolver.clone();
        let runtime_resolver = resolver.clone();

        let udp_stop = Arc::clone(&stopping);
        let udp_worker = thread::spawn(move || {
            while !udp_stop.load(Ordering::Relaxed) {
                let _ = karst_dns::listener::serve_udp_once(&udp, &resolver);
            }
        });
        let tcp_stop = Arc::clone(&stopping);
        let tcp_worker = thread::spawn(move || {
            while !tcp_stop.load(Ordering::Relaxed) {
                match karst_dns::listener::serve_tcp_once(&tcp, &tcp_resolver) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    _ => {}
                }
            }
        });
        Ok(Self {
            stopping,
            workers: vec![udp_worker, tcp_worker],
            resolver: runtime_resolver,
        })
    }

    /// Serve DNS inside the userspace overlay stack. Unlike [`Self::start`],
    /// this opens no host socket and therefore needs neither an interface
    /// address nor `CAP_NET_BIND_SERVICE`.
    pub fn start_userspace(
        stack: karst_tun::Userspace,
        port: u16,
        resolver: Resolver,
    ) -> std::io::Result<Self> {
        let listener = stack
            .listen_udp(port)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let tcp_listener = stack
            .listen_tcp(port)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let upstream = stack
            .listen_udp(49_152)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let stopping = Arc::new(AtomicBool::new(false));
        let runtime_resolver = resolver.clone();
        let stop = Arc::clone(&stopping);
        let worker = thread::spawn(move || {
            let mut tcp_request = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let mut request = Vec::new();
                if let Some(from) = stack.udp_recv(listener, &mut request) {
                    let response = userspace_handle_wire(&stack, upstream, &resolver, &request)
                        .or_else(|_| {
                            karst_dns::service::servfail_wire(&request).ok_or_else(|| {
                                karst_dns::service::Error::Request("invalid DNS request".to_owned())
                            })
                        });
                    if let Ok(response) = response {
                        let _ = stack.udp_send(listener, &response, from);
                    }
                }

                if stack.tcp_can_recv(tcp_listener) {
                    let _ = stack.tcp_recv(tcp_listener, &mut tcp_request);
                    let Some(length) = tcp_request
                        .get(..2)
                        .and_then(|prefix| <[u8; 2]>::try_from(prefix).ok())
                        .map(u16::from_be_bytes)
                        .map(usize::from)
                    else {
                        continue;
                    };
                    let Some(request) = tcp_request.get(2..2 + length) else {
                        continue;
                    };
                    let response = userspace_handle_wire(&stack, upstream, &resolver, request)
                        .or_else(|_| {
                            karst_dns::service::servfail_wire(request).ok_or_else(|| {
                                karst_dns::service::Error::Request("invalid DNS request".to_owned())
                            })
                        });
                    if let Ok(response) = response {
                        if let Ok(length) = u16::try_from(response.len()) {
                            let mut framed = length.to_be_bytes().to_vec();
                            framed.extend_from_slice(&response);
                            let _ = stack.tcp_send(tcp_listener, &framed);
                            stack.tcp_close(tcp_listener);
                        }
                    }
                    tcp_request.clear();
                } else if !stack.tcp_is_listening(tcp_listener)
                    && !stack.tcp_is_active(tcp_listener)
                {
                    let _ = stack.tcp_listen_again(tcp_listener, port);
                }
            }
        });
        Ok(Self {
            stopping,
            workers: vec![worker],
            resolver: runtime_resolver,
        })
    }

    /// Stop both listeners and wait for their short bounded polling interval.
    pub fn stop(self) {
        self.stopping.store(true, Ordering::Relaxed);
        for worker in self.workers {
            let _ = worker.join();
        }
    }

    #[must_use]
    pub fn cache_stats(&self) -> karst_dns::cache::Stats {
        self.resolver.cache_stats()
    }

    #[must_use]
    pub fn recent_failures(&self) -> Vec<String> {
        self.resolver.recent_failures()
    }
}

fn userspace_handle_wire(
    stack: &karst_tun::Userspace,
    upstream: karst_tun::UdpHandle,
    resolver: &Resolver,
    request: &[u8],
) -> Result<Vec<u8>, karst_dns::service::Error> {
    match karst_dns::service::decide_wire(resolver, request)? {
        karst_dns::service::Decision::Respond(response) => response
            .to_vec()
            .map_err(|error| karst_dns::service::Error::Response(error.to_string())),
        karst_dns::service::Decision::Forward {
            resolvers,
            split: true,
        } => userspace_forward(stack, upstream, request, &resolvers).map_err(|error| {
            karst_dns::service::Error::Request(format!("userspace split-DNS upstream: {error}"))
        }),
        // Global upstreams are ordinary Internet nameservers, not mesh
        // services. Keep their existing host-socket path (including cache and
        // retry behavior); only a split route promises mesh reachability.
        karst_dns::service::Decision::Forward { split: false, .. } => {
            karst_dns::service::handle_wire(resolver, request)
        }
    }
}

fn userspace_forward(
    stack: &karst_tun::Userspace,
    socket: karst_tun::UdpHandle,
    request: &[u8],
    resolvers: &[SocketAddr],
) -> std::io::Result<Vec<u8>> {
    let _ = karst_dns::message::decode(request).map_err(std::io::Error::other)?;
    let mut last_error = None;
    for resolver in resolvers {
        if let Err(error) = stack.udp_send(socket, request, *resolver) {
            last_error = Some(std::io::Error::other(error.to_string()));
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut response = Vec::new();
        while Instant::now() < deadline {
            if let Some(source) = stack.udp_recv(socket, &mut response) {
                if source != *resolver {
                    response.clear();
                    continue;
                }
                if karst_dns::service::matching_response(request, &response) {
                    return Ok(response);
                }
                response.clear();
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        last_error = Some(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "userspace DNS upstream timed out",
        ));
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no DNS upstream configured")))
}

/// Replace the listener for a newly assembled netmap. Resolver construction is
/// validated before the old listener stops, so a malformed update cannot turn
/// a working DNS service into an outage. A same-address replacement still
/// requires a brief stop before it can bind, ensuring a withdrawn MagicDNS
/// suffix cannot keep answering from stale state.
pub fn reconcile(
    runtime: &mut Option<Runtime>,
    config: &crate::config::Config,
    userspace: Option<karst_tun::Userspace>,
) -> Result<(), String> {
    let resolver = from_config(config).map_err(|error| error.to_string())?;
    if let Some(old) = runtime.take() {
        old.stop();
    }
    if let Some(resolver) = resolver {
        let next = match userspace {
            Some(stack) => {
                Runtime::start_userspace(stack, config.dns.stub_address.port(), resolver)
            }
            None => Runtime::start(config.dns.stub_address, resolver),
        }
        .map_err(|error| error.to_string())?;
        *runtime = Some(next);
    }
    Ok(())
}

/// Construct the local resolver view from one fully assembled authenticated
/// netmap. This is intentionally rebuilt wholesale after every netmap change:
/// a deleted peer must immediately stop resolving, and a MagicDNS disable must
/// leave no stale mesh zone behind.
pub fn from_netmap(netmap: &Netmap) -> Result<Resolver, Error> {
    let config = &netmap.dns_config;
    let nameservers = parse_resolvers(&config.nameservers)?;
    let routes = config
        .routes
        .iter()
        .map(|route| {
            Ok(Route {
                match_domain: route.match_domain.clone(),
                resolvers: parse_resolvers(&route.resolvers)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let peers = netmap
        .peers()
        .map(|peer| {
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for address in &peer.allowed_ips {
                let bare = address.split('/').next().unwrap_or(address);
                if let Ok(value) = bare.parse::<Ipv4Addr>() {
                    ipv4.push(value);
                } else if let Ok(value) = bare.parse::<Ipv6Addr>() {
                    ipv6.push(value);
                } else {
                    return Err(Error::Address {
                        peer: peer.dns_name.clone(),
                        value: address.clone(),
                    });
                }
            }
            Ok(MeshPeer::new(peer.dns_name.clone(), ipv4, ipv6))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Resolver::new(
        Config::new(
            nameservers,
            config.search_domains.clone(),
            routes,
            &config.zone,
            config.magic_dns,
        )?,
        peers,
    ))
}

/// Build the same resolver from the daemon's assembled runtime configuration.
/// `None` is the static-roster/no-MagicDNS state, not an error.
pub fn from_config(config: &crate::config::Config) -> Result<Option<Resolver>, Error> {
    if !config.dns.enabled || !config.netmap_dns.magic_dns || config.netmap_dns.zone.is_empty() {
        return Ok(None);
    }
    let nameservers = if config.dns.upstream.is_empty() {
        let netmap = parse_resolvers(&config.netmap_dns.nameservers)?;
        if netmap.is_empty() {
            host_resolvers()?
        } else {
            netmap
        }
    } else {
        config.dns.upstream.clone()
    };
    let routes = if config.dns.accept_netmap_config {
        config
            .netmap_dns
            .routes
            .iter()
            .map(|route| {
                Ok(Route {
                    match_domain: route.match_domain.clone(),
                    resolvers: parse_resolvers(&route.resolvers)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
    } else {
        Vec::new()
    };
    let peers = config
        .peers
        .iter()
        .map(|peer| {
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for prefix in &peer.allowed_ips {
                let bare = prefix
                    .to_string()
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                if let Ok(value) = bare.parse::<Ipv4Addr>() {
                    ipv4.push(value);
                } else if let Ok(value) = bare.parse::<Ipv6Addr>() {
                    ipv6.push(value);
                } else {
                    return Err(Error::Address {
                        peer: peer.name.clone(),
                        value: bare,
                    });
                }
            }
            Ok(MeshPeer::new(peer.name.clone(), ipv4, ipv6))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Some(Resolver::new(
        Config::new(
            nameservers,
            config.netmap_dns.search_domains.clone(),
            routes,
            &config.netmap_dns.zone,
            true,
        )?,
        peers,
    )))
}

fn parse_resolvers(values: &[String]) -> Result<Vec<SocketAddr>, Error> {
    values
        .iter()
        .map(|value| {
            value.parse().map_err(|_| Error::Resolver {
                value: value.clone(),
            })
        })
        .collect()
}

/// Read normal host upstreams before a bare-file integration replaces them.
/// A persisted revert record takes precedence over the live file, which may
/// already name the KarstDNS stub after a prior netmap generation.
fn host_resolvers() -> Result<Vec<SocketAddr>, Error> {
    let host = karst_dns::host::ResolvConf::system();
    let contents = host.original_contents().map_err(|error| Error::Resolver {
        value: error.to_string(),
    })?;
    let mut resolvers = Vec::new();
    for line in String::from_utf8_lossy(&contents).lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            continue;
        };
        let ip = address.parse::<IpAddr>().map_err(|_| Error::Resolver {
            value: address.to_owned(),
        })?;
        let resolver = SocketAddr::new(ip, 53);
        if resolver.ip() != karst_dns::STUB_ADDRESS {
            resolvers.push(resolver);
        }
    }
    Ok(resolvers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netmap::{DNSConfig, Netmap, Peer};

    fn relay(from: &karst_tun::Userspace, to: &karst_tun::Userspace) {
        let mut buffer = vec![0; karst_proto::consts::TUNNEL_MTU];
        let mut packets = Vec::new();
        let _ = from
            .recv_segments(&mut buffer, &mut packets)
            .expect("packet");
        for packet in packets {
            to.send(&packet).expect("relay packet");
        }
    }

    #[test]
    fn revert_host_is_a_no_op_when_host_integration_is_none() {
        let settings = crate::config::DnsSettings {
            host_integration: crate::config::HostIntegration::None,
            ..crate::config::DnsSettings::default()
        };
        revert_host(&settings, "does-not-exist0").expect("no-op revert");
    }

    #[test]
    fn revert_host_is_a_no_op_for_a_link_scoped_mechanism_with_no_interface() {
        for host_integration in [
            crate::config::HostIntegration::Resolved,
            crate::config::HostIntegration::Networkmanager,
        ] {
            let settings = crate::config::DnsSettings {
                host_integration,
                ..crate::config::DnsSettings::default()
            };
            revert_host(&settings, "karst-test-missing0")
                .expect("a gone interface already lost its link-scoped DNS state");
        }
    }

    /// The `/etc/resolver` mechanism is compiled everywhere so that a Linux
    /// build type-checks it, which makes "compiled" and "selectable" two
    /// different questions. This is the second one, and off macOS the answer
    /// has to be a refusal rather than a daemon that writes real files into a
    /// directory no resolver on this host reads.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_resolver_directory_mechanism_is_refused_off_macos() {
        let settings = crate::config::DnsSettings {
            host_integration: crate::config::HostIntegration::Macos,
            ..crate::config::DnsSettings::default()
        };
        let error = HostRuntime::new(&settings, None, "karst0")
            .expect_err("/etc/resolver is not a mechanism on this platform");
        assert!(error.contains("/etc/resolver"), "{error}");
        assert!(
            revert_host(&settings, "karst0").is_err(),
            "and reverting it must not silently report success either"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn auto_selects_the_resolver_directory_on_macos() {
        let settings = crate::config::DnsSettings::default();
        let host = HostRuntime::new(&settings, None, "utun9").expect("auto-selected mechanism");
        assert_eq!(host.mechanism(), "/etc/resolver");
        assert_eq!(host.observe().expect("observe"), "not configured");
    }

    /// `karst status` prints this, and the walkthrough in
    /// `plans/phase-5/06-macos-client.md` §10 reads it to tell a machine with
    /// host DNS integration from one without.
    #[test]
    fn every_mechanism_names_itself() {
        assert_eq!(HostRuntime::None.mechanism(), "none");
        assert_eq!(
            HostRuntime::Macos(karst_dns::host::Macos::system()).mechanism(),
            "/etc/resolver"
        );
    }

    #[test]
    fn netmap_peer_addresses_become_mesh_records() {
        let mut netmap = Netmap::new();
        netmap.dns_config = DNSConfig {
            zone: "aquifer.karst".to_owned(),
            magic_dns: true,
            ..DNSConfig::default()
        };
        netmap.insert_test_peer(Peer {
            node_id: b"peer".to_vec(),
            allowed_ips: vec!["100.64.0.2/32".to_owned(), "fd00::2/128".to_owned()],
            dns_name: "beta".to_owned(),
            endpoint: String::new(),
            home_relay: vec![],
            kem_public_key: vec![],
            dh_public_key: vec![],
            psk: None,
            psk_previous: None,
            disco_key: None,
        });
        let resolver = from_netmap(&netmap).expect("resolver");
        assert!(matches!(
            resolver.resolve("beta.aquifer.karst", karst_dns::RecordType::A, true),
            Ok(karst_dns::Resolution::Authoritative(_))
        ));
    }

    #[test]
    fn runtime_binds_and_stops_both_transports() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        let address = probe.local_addr().expect("address");
        drop(probe);
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [],
        );
        Runtime::start(address, resolver).expect("start").stop();
    }

    #[test]
    fn live_listener_resolves_a_netmap_peer_in_both_families() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let mut netmap = Netmap::new();
        netmap.dns_config = DNSConfig {
            zone: "aquifer.karst".to_owned(),
            magic_dns: true,
            ..DNSConfig::default()
        };
        netmap.insert_test_peer(Peer {
            node_id: b"peer".to_vec(),
            allowed_ips: vec!["100.64.0.2/32".to_owned(), "fd00::2/128".to_owned()],
            dns_name: "beta".to_owned(),
            endpoint: String::new(),
            home_relay: vec![],
            kem_public_key: vec![],
            dh_public_key: vec![],
            psk: None,
            psk_previous: None,
            disco_key: None,
        });
        let resolver = from_netmap(&netmap).expect("resolver");
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        let address = probe.local_addr().expect("address");
        drop(probe);
        let runtime = Runtime::start(address, resolver).expect("runtime");
        for kind in [RecordType::A, RecordType::AAAA] {
            let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client");
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            let mut request = Message::new(11, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_ascii("beta.aquifer.karst.").expect("name"),
                kind,
            ));
            client
                .send_to(&request.to_vec().expect("query"), address)
                .expect("send");
            let mut response = [0u8; 512];
            let (length, _) = client.recv_from(&mut response).expect("answer");
            let response = karst_dns::message::decode(&response[..length]).expect("decode");
            assert_eq!(response.answers.len(), 1, "{kind:?} answer");
            assert_eq!(response.answers[0].record_type(), kind);
        }
        for reverse in [
            "2.0.64.100.in-addr.arpa.",
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
        ] {
            let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client");
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            let mut request = Message::new(12, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_ascii(reverse).expect("name"),
                RecordType::PTR,
            ));
            client
                .send_to(&request.to_vec().expect("query"), address)
                .expect("send");
            let mut response = [0u8; 512];
            let (length, _) = client.recv_from(&mut response).expect("answer");
            let response = karst_dns::message::decode(&response[..length]).expect("decode");
            assert_eq!(response.answers.len(), 1, "{reverse} answer");
            assert_eq!(response.answers[0].record_type(), RecordType::PTR);
        }
        runtime.stop();
    }

    #[test]
    fn userspace_listener_resolves_a_mesh_peer_without_a_host_socket() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let server =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("server stack");
        server
            .set_address("100.64.0.1".parse().expect("server address"), 24)
            .expect("server address");
        let client =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("client stack");
        client
            .set_address("100.64.0.2".parse().expect("client address"), 24)
            .expect("client address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [MeshPeer::new("atlas", [Ipv4Addr::new(100, 64, 0, 9)], [])],
        );
        let runtime = Runtime::start_userspace(server.clone(), 53, resolver).expect("runtime");
        let socket = client.listen_udp(49_153).expect("client UDP");
        let mut request = Message::new(41, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("atlas.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        client
            .udp_send(
                socket,
                &request.to_vec().expect("wire query"),
                "100.64.0.1:53".parse().expect("DNS endpoint"),
            )
            .expect("send query");
        relay(&client, &server);
        std::thread::sleep(Duration::from_millis(30));
        relay(&server, &client);
        let mut answer = Vec::new();
        let _ = client.udp_recv(socket, &mut answer).expect("DNS response");
        let response = karst_dns::message::decode(&answer).expect("decode response");
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        runtime.stop();
    }

    #[test]
    fn userspace_listener_serves_dns_over_tcp() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let server =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("server stack");
        server
            .set_address("100.64.0.1".parse().expect("server address"), 24)
            .expect("server address");
        let client =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("client stack");
        client
            .set_address("100.64.0.2".parse().expect("client address"), 24)
            .expect("client address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [MeshPeer::new("atlas", [Ipv4Addr::new(100, 64, 0, 9)], [])],
        );
        let runtime = Runtime::start_userspace(server.clone(), 53, resolver).expect("runtime");
        let connection = client
            .connect_tcp("100.64.0.1".parse().expect("server address"), 53)
            .expect("connect");
        relay(&client, &server);
        relay(&server, &client);
        relay(&client, &server);

        let mut request = Message::new(42, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("atlas.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        let request = request.to_vec().expect("wire query");
        let mut framed = u16::try_from(request.len())
            .expect("DNS query length")
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&request);
        client.tcp_send(connection, &framed).expect("send query");
        relay(&client, &server);
        std::thread::sleep(Duration::from_millis(30));
        relay(&server, &client);
        let mut response = Vec::new();
        assert!(client.tcp_can_recv(connection), "DNS TCP response arrived");
        client
            .tcp_recv(connection, &mut response)
            .expect("receive response");
        let length = response
            .get(..2)
            .and_then(|prefix| <[u8; 2]>::try_from(prefix).ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .expect("DNS TCP length");
        let message =
            karst_dns::message::decode(response.get(2..2 + length).expect("DNS response"))
                .expect("decode response");
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].record_type(), RecordType::A);
        runtime.stop();
    }

    #[test]
    fn userspace_split_dns_reaches_an_overlay_only_resolver() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let dns =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("DNS stack");
        let client =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("client stack");
        let upstream =
            karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("upstream stack");
        for (stack, address) in [
            (&dns, "100.64.0.1"),
            (&client, "100.64.0.2"),
            (&upstream, "100.64.0.3"),
        ] {
            stack
                .set_address(address.parse().expect("overlay address"), 24)
                .expect("set address");
        }
        let resolver = Resolver::new(
            Config::new(
                vec!["127.0.0.1:9".parse().expect("host-only global")],
                vec![],
                vec![Route {
                    match_domain: "internal.example".to_owned(),
                    resolvers: vec!["100.64.0.3:53".parse().expect("overlay resolver")],
                }],
                "aquifer.karst",
                true,
            )
            .expect("config"),
            [],
        );
        let runtime = Runtime::start_userspace(dns.clone(), 53, resolver).expect("DNS runtime");
        let upstream_socket = upstream.listen_udp(53).expect("upstream listener");
        let client_socket = client.listen_udp(49_153).expect("client socket");
        let mut request = Message::new(72, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("db.internal.example.").expect("name"),
            RecordType::A,
        ));
        client
            .udp_send(
                client_socket,
                &request.to_vec().expect("query"),
                "100.64.0.1:53".parse().expect("KarstDNS"),
            )
            .expect("send query");

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut answer = Vec::new();
        while Instant::now() < deadline {
            relay(&client, &dns);
            relay(&dns, &upstream);
            let mut forwarded = Vec::new();
            if let Some(source) = upstream.udp_recv(upstream_socket, &mut forwarded) {
                let query = karst_dns::message::decode(&forwarded).expect("forwarded DNS query");
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.add_queries(query.queries.iter().cloned());
                upstream
                    .udp_send(
                        upstream_socket,
                        &response.to_vec().expect("upstream response"),
                        source,
                    )
                    .expect("respond over overlay");
            }
            relay(&upstream, &dns);
            relay(&dns, &client);
            if client.udp_recv(client_socket, &mut answer).is_some() {
                break;
            }
        }
        let response = karst_dns::message::decode(&answer).expect("split DNS response");
        assert_eq!(response.metadata.id, 72);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        runtime.stop();
    }
}
