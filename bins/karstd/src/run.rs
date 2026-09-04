// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The I/O loop — the only part of the daemon that touches the world.
//!
//! Two blocking reads have to proceed independently: a packet from the host and
//! a datagram from a peer arrive on unrelated schedules, and neither may be
//! starved by the other. That is two threads plus a timer, sharing the engine
//! by reference — **not behind a lock**. The engine synchronises per peer
//! internally, and an outer mutex here would serialize the whole datapath,
//! which is precisely the bottleneck PLAN.md §3.4 measured.
//!
//! An async runtime would do the same job with more machinery. The engine is
//! sans-io, so it can be moved onto `epoll`, `io_uring` or a runtime later
//! without touching anything below this file — which is the point of the
//! separation, and why this file is small enough to replace.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karst_control_client::transport::pb;
use karst_disco::TxId;
use karst_noise::handshake::ResponderRandomness;
use karst_portmap::Protocol;
use karst_transport::{Received, UdpTransport, BATCH, MAX_DATAGRAM};
use karst_tun::{Tun, TunConfig, Userspace};

use crate::config::Config;
use crate::disco;
use crate::engine::{Engine, Output, Via};
use crate::ipc;
use crate::portmap;
use crate::random_seed;

/// How often timers are advanced. Handshake retransmission starts at 300 ms
/// (§10), so this has to be comfortably finer than that.
const TICK: Duration = Duration::from_millis(100);

/// Read timeout on the UDP socket, so the receive thread notices a shutdown
/// request rather than blocking on a socket that will never speak again.
const POLL_TIMEOUT: Duration = Duration::from_millis(250);

/// The only operations the I/O loop needs from its packet attachment.
///
/// TUN remains the default. The userspace variant deliberately has the same
/// bare-IP boundary, so `dispatch` and the engine do not know which mode chose
/// the packet and cannot accidentally weaken the established path.
#[derive(Debug)]
enum NetworkDevice {
    Tun(Tun),
    Userspace(Userspace),
}

impl NetworkDevice {
    fn name(&self) -> &str {
        match self {
            Self::Tun(tun) => tun.name(),
            Self::Userspace(stack) => stack.name(),
        }
    }

    fn mtu(&self) -> usize {
        match self {
            Self::Tun(tun) => tun.mtu(),
            Self::Userspace(stack) => stack.mtu(),
        }
    }

    fn offload(&self) -> bool {
        match self {
            Self::Tun(tun) => tun.offload(),
            Self::Userspace(stack) => stack.offload(),
        }
    }

    fn recv_segments(
        &self,
        buf: &mut [u8],
        out: &mut Vec<Vec<u8>>,
    ) -> Result<usize, karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.recv_segments(buf, out),
            Self::Userspace(stack) => stack.recv_segments(buf, out),
        }
    }

    fn send(&self, packet: &[u8]) -> Result<usize, karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.send(packet),
            Self::Userspace(stack) => stack.send(packet),
        }
    }

    fn set_address(
        &self,
        address: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<(), karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.set_address(address, prefix_len),
            Self::Userspace(stack) => stack.set_address(address, prefix_len),
        }
    }

    fn add_route(
        &self,
        address: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<(), karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.add_route(address, prefix_len),
            Self::Userspace(stack) => stack.add_route(address, prefix_len),
        }
    }

    fn remove_route(
        &self,
        address: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<(), karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.remove_route(address, prefix_len),
            Self::Userspace(stack) => stack.remove_route(address, prefix_len),
        }
    }

    fn userspace(&self) -> Option<Userspace> {
        match self {
            Self::Tun(_) => None,
            Self::Userspace(stack) => Some(stack.clone()),
        }
    }

    fn ifindex(&self) -> Result<Option<u32>, karst_tun::TunError> {
        match self {
            Self::Tun(tun) => tun.ifindex().map(Some),
            Self::Userspace(_) => Ok(None),
        }
    }
}

/// Signals shutdown to every thread.
#[derive(Debug, Default)]
pub struct Shutdown(AtomicBool);

impl Shutdown {
    /// Ask the daemon to stop.
    pub fn request(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    /// Whether a stop has been requested.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Fresh responder randomness for one handshake.
///
/// Every response must use fresh ephemerals: reusing KEM encapsulation
/// randomness across handshakes is a key-recovery risk, not untidiness.
fn responder_randomness() -> ResponderRandomness {
    ResponderRandomness {
        e_dh_seed: random_seed(),
        encap_rand_e: random_seed(),
        encap_rand_s: random_seed(),
    }
}

/// Milliseconds since the daemon started.
///
/// A monotonic clock, deliberately: every timeout in the protocol is a duration,
/// and none of them should be affected by an NTP step or a leap second.
fn now_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Bring up the interface and run until shutdown.
///
/// # Errors
/// Any failure creating the TUN device or binding the socket. Once running,
/// per-packet errors are counted and logged rather than fatal — a daemon that
/// exits on one bad packet is a denial-of-service primitive.
pub fn run(config: &Arc<Config>, shutdown: &Shutdown) -> io::Result<()> {
    run_with_socket(config, shutdown, &ipc::socket_path(None))
}

/// As [`run`], with an explicit control-socket path — for tests, and for
/// running more than one daemon on a host.
///
/// # Errors
/// As [`run`].
pub fn run_with_socket(
    config: &Arc<Config>,
    shutdown: &Shutdown,
    socket_path: &std::path::Path,
) -> io::Result<()> {
    run_with_control(config, shutdown, socket_path, None)
}

/// As [`run_with_socket`], with a control-server client that keeps the netmap
/// current.
///
/// # Errors
/// As [`run`].
#[allow(clippy::too_many_lines)]
pub fn run_with_control(
    config: &Arc<Config>,
    shutdown: &Shutdown,
    socket_path: &std::path::Path,
    control_client: Option<crate::control::Client>,
) -> io::Result<()> {
    let control_endpoint = control_client
        .as_ref()
        .map(|client| client.endpoint().to_owned());
    let tun = bring_up_interface(config)?;
    let gateway = Mutex::new(crate::gateway::Manager::default());
    let gateway_error = Mutex::new(None);
    apply_gateway(&gateway, &gateway_error, config);

    // DNS is an authenticated netmap service, not an ambient host service: a
    // static roster or MagicDNS-off map starts no listener. A failed bind is
    // reported but never changes host DNS, so it cannot turn daemon startup
    // into a machine-wide resolver outage.
    let dns_runtime = match crate::dns::from_config(config) {
        Ok(Some(resolver)) => match match tun.userspace() {
            Some(stack) => crate::dns::Runtime::start_userspace(
                stack,
                config.dns.stub_address.port(),
                resolver,
            ),
            None => crate::dns::Runtime::start(config.dns.stub_address, resolver),
        } {
            Ok(runtime) => Some(runtime),
            Err(error) => {
                eprintln!("karstd: DNS listener did not start: {error}");
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            eprintln!("karstd: DNS config rejected: {error}");
            None
        }
    };
    let dns_runtime = Mutex::new(dns_runtime);
    // The resolver must be listening before host DNS points at it. This is the
    // ordering that prevents a failed bind from becoming a machine-wide DNS
    // outage. A bare resolv.conf controller also recovers a stale state file
    // here before it can apply a fresh netmap.
    let mut dns_host = if tun.userspace().is_some() {
        // The userspace resolver is reachable only through the encrypted
        // overlay. Pointing the *host* resolver at its stub address would
        // replace working host DNS with an endpoint no host socket owns.
        crate::dns::HostRuntime::None
    } else {
        match crate::dns::HostRuntime::new(
            &config.dns,
            tun.ifindex()
                .map_err(|error| io::Error::other(error.to_string()))?,
            tun.name(),
        ) {
            Ok(host) => host,
            Err(error) => {
                eprintln!("karstd: DNS host integration unavailable: {error}");
                crate::dns::HostRuntime::None
            }
        }
    };
    if dns_runtime
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
    {
        if let Err(error) = dns_host.update(config) {
            eprintln!("karstd: DNS host integration was not applied: {error}");
        }
    }
    let dns_host = Mutex::new(dns_host);

    // Every peer endpoint the datapath is given is an IPv4 literal from a
    // netmap or a call-me-maybe. On a NAT64 node the socket is what turns those
    // into addresses it can reach, and turns the answers back — so the engine
    // above it goes on comparing plain IPv4 addresses and never learns that its
    // own network spells them differently.
    let socket = UdpTransport::bind_via_nat64(config.listen, config.nat64)?;
    socket.set_read_timeout(Some(POLL_TIMEOUT))?;

    // Routes for anything outside the interface's own on-link prefix — a
    // subnet router, say. Without them the kernel sends that traffic to the
    // default gateway rather than to the tunnel, which is worse than dropping
    // it.
    let routes = Mutex::new(Routes::default());
    let exit_policy = Mutex::new(crate::exit_policy::Manager::default());
    // When the control connection's push signal (GitHub issues #72/#73) last
    // actually fired — `bugreport`'s control-session-health section
    // (plans/phase-6/08-observability.md §5 W6 item 3). `None` until the
    // first one arrives, which `refresh_netmap` reports as absent rather
    // than a fabricated age.
    let last_push = Mutex::new(None::<Instant>);
    let exit_node = config
        .exit_node_state_file
        .as_ref()
        .map(crate::exit_node::Selection::load)
        .transpose()?
        .map(Mutex::new);
    let selected_exit = exit_node.as_ref().and_then(|selection| {
        selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active()
            .map(str::to_owned)
    });
    if let Err(error) = reconcile_exit(
        &routes,
        &exit_policy,
        &tun,
        config,
        None,
        control_endpoint.as_deref(),
        selected_exit.as_deref(),
    ) {
        eprintln!("karstd: persisted exit selection is dormant: {error}");
    }

    announce(config, &tun, &socket)?;

    let control = ipc::bind(socket_path)?;
    // A short accept timeout is what lets the control thread notice a shutdown
    // request; a blocking accept would hold the daemon open until someone
    // connected.
    control.set_nonblocking(true)?;

    let started = Instant::now();
    // No mutex. The engine locks per peer internally — see its module docs and
    // PLAN.md §3.4. Wrapping it in one here would undo all of that.
    let engine = Engine::new(config);

    // AVEN state, shared between the receive loop and the timer that drives
    // probing. A static roster has no server-issued handles or disco keys, so
    // reconciliation leaves it empty; a netmap roster immediately seeds its
    // direct endpoints as unconfirmed candidates.
    let disco = Mutex::new(disco::Disco::new(config.psk_epoch));
    let portmap = portmap::Shared::new(config.port_mapping);
    // The port the socket is *actually* bound to, which is not always the
    // configured one: a node listening on port 0 gets an ephemeral port, and a
    // candidate naming port 0 names nothing.
    let listen_port = socket
        .local_addr()
        .map_or(config.listen.port(), |a| a.port());
    {
        let mut state = disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reconcile(config, now_ms(started));
        state.set_interfaces(&gather_interfaces(config), listen_port);
    }

    let relay = config.relays.first().cloned();
    let relay_node_id = config.node_id.clone();
    let relay_ca = config.relay_ca_file.clone();
    // Present only when a relay is configured. `None` means anything the engine
    // routes over the relay is dropped where it is produced — which is correct
    // and already consistent: `Engine::via` returns a relay destination only
    // when `config.relays` is non-empty, so the two agree by construction.
    //
    // Built **before** the first handshakes, because for a peer with no
    // configured endpoint those handshakes are themselves relayed, and a queue
    // that did not exist yet would drop the one datagram that starts the
    // conversation.
    let relay_dropped = Arc::new(AtomicU64::new(0));
    let (relay_out, relay_in, on_demand_in) = match relay {
        Some(_) => {
            let (tx, rx) = tokio::sync::mpsc::channel(RELAY_QUEUE);
            // §9.1's second rule has its own queue. Sharing the home
            // connection's would let a peer on a relay this node has yet to
            // dial — a TLS and ML-DSA-87 handshake away — fill the queue that
            // every other peer's traffic is waiting in.
            let (on_demand_tx, on_demand_rx) = tokio::sync::mpsc::channel(RELAY_QUEUE);
            (
                Some(RelaySender {
                    queue: tx,
                    on_demand: on_demand_tx,
                    dropped: Arc::clone(&relay_dropped),
                }),
                Some(rx),
                Some(on_demand_rx),
            )
        }
        None => (None, None, None),
    };
    let relay_out = relay_out.as_ref();
    // §9.1. The engine routes by it, so it is set from the same value the relay
    // worker connects to rather than recomputed from the registry.
    engine.set_home_relay(relay.as_ref().map(|r| r.relay_id));

    // §7.8. Present only when the netmap this daemon started with already
    // names a TURN server — the same "first entry, decided once here" rule
    // `relay` above follows. A netmap that starts offering TURN only after
    // this daemon is already running is not picked up until the next
    // restart, which is the identical limitation `relay_out` already has for
    // a relay registry that starts empty; this feature does not introduce it.
    let turn_dropped = Arc::new(AtomicU64::new(0));
    let (turn_out, turn_in) = match config.turn_servers.first() {
        Some(_) => {
            let (tx, rx) = tokio::sync::mpsc::channel(TURN_QUEUE);
            (
                Some(TurnSender {
                    queue: tx,
                    dropped: Arc::clone(&turn_dropped),
                }),
                Some(rx),
            )
        }
        None => (None, None),
    };
    let turn_out = turn_out.as_ref();

    // §9.1. The probes are per-connection state and the selector is the node's;
    // both are held here so every relay worker and the timer thread see the same
    // ones, and so a reconnection clears one relay's probes without clearing the
    // choice or anything another relay is waiting on.
    let rtt_probes = Mutex::new(crate::home::Probes::default());
    let home_selector = Mutex::new(crate::home::Selector::new());
    // Per-relay/TURN-server reachability, keyed by address/URI —
    // `bugreport`'s [[relay]]/[[turn]] sections
    // (plans/phase-6/08-observability.md §5 W6 item 3), beyond the aggregate
    // relay_dropped counter: which specific one, and since when. Shared for
    // the same reason rtt_probes/home_selector are: every relay worker
    // (the home connection and whichever on-demand ones are live) writes
    // into the one map a report reads from.
    let relay_health: Mutex<HashMap<String, Reachability>> = Mutex::new(HashMap::new());
    let turn_health: Mutex<HashMap<String, Reachability>> = Mutex::new(HashMap::new());
    // §9.2. Which alternative is being measured, and when the next one's turn
    // comes. Only the timer thread touches it.
    let mut rotation = crate::home::Rotation::default();

    // Initial handshakes, before any thread starts.
    dispatch(
        engine.connect_all(now_ms(started), random_seed),
        &socket,
        &tun,
        relay_out,
        turn_out,
    );

    // The local settings the netmap does not supply. Cloned once here because
    // the refresh thread needs them on every reconfiguration and they never
    // change.
    let local = || crate::config::LocalSettings {
        keys: Arc::clone(&config.keys),
        listen: config.listen,
        port_mapping: config.port_mapping,
        interface: config.interface.clone(),
        network_mode: config.network_mode,
        dns: config.dns.clone(),
        userspace_socks5_listen: config.userspace_socks5_listen,
        userspace_publish: config.userspace_publish.clone(),
        nat64: config.nat64,
        metrics_listen: config.metrics_listen,
        relay_ca_file: config.relay_ca_file.clone(),
        exit_node_state_file: config.exit_node_state_file.clone(),
    };
    // The control client owns the ML-DSA identity. Clone its `Arc` before the
    // refresh worker takes ownership of the client, so the relay reader can
    // authenticate independently without reading the secret file again.
    let relay_identity = control_client
        .as_ref()
        .map(crate::control::Client::relay_identity);

    // Everything a Ponor connection needs that does not depend on *which* relay
    // it is. Built before the scope, because the on-demand connections of
    // §9.1's second rule are dialled while the daemon runs and each needs the
    // same set.
    let relay_common = relay_identity
        .zip(relay_out)
        .map(|(identity, relayed)| RelayCommon {
            shutdown,
            rtt: &rtt_probes,
            home: &home_selector,
            identity,
            node_id: relay_node_id,
            relay_ca_file: relay_ca,
            disco: &disco,
            engine: &engine,
            socket: &socket,
            tun: &tun,
            relayed,
            started,
            relay_health: &relay_health,
        });

    // Built the same way `relay_common` is, and for the same reason: the
    // worker needs `disco`/`engine`/`socket`/`tun` for the whole daemon
    // lifetime, so this is constructed before the scope rather than inside
    // the closure that spawns it.
    let turn_common = turn_out.map(|turned| TurnCommon {
        shutdown,
        disco: &disco,
        engine: &engine,
        socket: &socket,
        tun: &tun,
        relayed: relay_out,
        turned,
        started,
        turn_health: &turn_health,
    });

    std::thread::scope(|scope| {
        if let Some(listen) = config.metrics_listen {
            // Loopback-only is already enforced at config load time
            // (config::validate_metrics_listen) — this just starts the
            // listener an operator asked for.
            scope.spawn(move || {
                if let Err(e) = crate::metrics_http::serve(listen, socket_path, shutdown) {
                    tracing::error!(%listen, error = %e, "metrics HTTP listener stopped");
                }
            });
        }
        if let Some(listen) = config.userspace_socks5_listen {
            // Configuration validation guarantees this is the userspace
            // variant. Keep the endpoint inside the scoped daemon lifetime so
            // it cannot survive the packet engine it depends on.
            if let Some(stack) = tun.userspace() {
                scope.spawn(move || {
                    if let Err(e) = crate::socks5::serve(&stack, listen, shutdown) {
                        eprintln!("karstd: userspace SOCKS5 listener {listen} stopped: {e}");
                    }
                });
            }
        }
        // The inbound half. One thread per published port: each holds a
        // listening socket on the stack, and a port whose backend is down must
        // not stop the others being reachable.
        for entry in &config.userspace_publish {
            if let Some(stack) = tun.userspace() {
                let (port, to) = (entry.port, entry.to);
                // Named at startup, because a node's inbound surface is
                // something an operator should be able to read out of the log
                // rather than reconstruct from the configuration file.
                println!("karstd: publishing overlay port {port} to {to}");
                scope.spawn(move || crate::publish::serve(&stack, port, to, shutdown));
            }
        }

        // ── host → tunnel ──────────────────────────────────────────────────
        let engine_host = &engine;
        let socket_host = &socket;
        let tun_host = &tun;
        scope.spawn(move || {
            // Big enough for a coalesced read: the kernel may hand back up to
            // 64 KB behind one header.
            let mut buf = vec![0u8; 65_536 + 64];
            let mut packets: Vec<Vec<u8>> = Vec::new();
            while !shutdown.requested() {
                let Ok(count) = tun_host.recv_segments(&mut buf, &mut packets) else {
                    continue;
                };
                // One `Output` per read rather than per packet, so a coalesced
                // stream becomes one batched `sendmmsg`.
                let mut out = Output::default();
                for packet in packets.iter().take(count) {
                    let o = engine_host.outbound(packet, now_ms(started));
                    out.datagrams.extend(o.datagrams);
                    out.packets.extend(o.packets);
                }
                dispatch(out, socket_host, tun_host, relay_out, turn_out);
            }
        });

        // ── the relay ─────────────────────────────────────────────────────
        // Both protocols and both directions. AVEN's rendezvous made this
        // connection necessary; PHREATIC's fallback is what makes a peer with
        // no direct path reachable rather than merely known about.
        if let (Some(common), Some(relay), Some(relay_in), Some(on_demand_in)) =
            (relay_common.as_ref(), relay, relay_in, on_demand_in)
        {
            scope.spawn(move || {
                relay_worker(
                    RelayContext {
                        common,
                        relay,
                        role: RelayRole::Home,
                    },
                    relay_in,
                );
            });
            // §9.1's second rule. Its own thread, which dials the relays peers
            // published and closes them again when they fall idle — the home
            // connection must not be stalled behind a handshake with a relay
            // this node has never spoken to.
            scope.spawn(move || on_demand_hub(scope, common, on_demand_in));
        }

        // ── TURN ──────────────────────────────────────────────────────────
        // §7.8's last resort. Its own thread and its own dedicated socket —
        // see `crate::turn`'s module doc for why this must not share the
        // datapath socket's demultiplexing.
        if let (Some(common), Some(turn_in)) = (turn_common.as_ref(), turn_in) {
            scope.spawn(move || turn_worker(common, turn_in));
        }

        // ── tunnel → host ──────────────────────────────────────────────────
        let disco_rx = &disco;
        let engine_rx = &engine;
        let socket_rx = &socket;
        let tun_rx = &tun;
        scope.spawn(move || {
            // Allocated once. `recvmmsg` fills as many as have arrived, so a
            // busy link costs one syscall per 32 datagrams instead of 32.
            let mut buffers = vec![[0u8; MAX_DATAGRAM]; BATCH];
            let mut meta: Vec<Received> = Vec::with_capacity(BATCH);
            while !shutdown.requested() {
                // A timeout here is normal and expected — it is what lets this
                // thread observe a shutdown request.
                let Ok(count) = socket_rx.recv_batch(&mut buffers, &mut meta) else {
                    continue;
                };
                for i in 0..count {
                    let (Some(buf), Some(m)) = (buffers.get(i), meta.get(i)) else {
                        continue;
                    };
                    let Some(datagram) = buf.get(..m.len) else {
                        continue;
                    };
                    let out = demultiplex(datagram, m.from, now_ms(started), disco_rx, engine_rx);
                    dispatch(out, socket_rx, tun_rx, relay_out, turn_out);
                }
            }
        });

        // ── control socket ─────────────────────────────────────────────────
        let engine_ctl = &engine;
        let tun_ctl = &tun;
        let socket_ctl = &socket;
        let portmap_state = &portmap;
        let dns_runtime_ctl = &dns_runtime;
        let dns_host_ctl = &dns_host;
        let routes_ctl = &routes;
        let exit_node_ctl = exit_node.as_ref();
        let exit_policy_ctl = &exit_policy;
        let control_endpoint_ctl = control_endpoint.as_deref();
        let gateway_ctl = &gateway;
        let gateway_error_ctl = &gateway_error;
        let last_push_ctl = &last_push;
        let relay_health_ctl = &relay_health;
        let turn_health_ctl = &turn_health;
        scope.spawn(move || {
            while !shutdown.requested() {
                match control.accept() {
                    Ok((mut stream, _)) => {
                        // Back to blocking for the conversation itself: the
                        // non-blocking flag is inherited by accepted sockets,
                        // and a partial read here would be reported as an error
                        // rather than waited on.
                        let _ = stream.set_nonblocking(false);
                        let handled = ipc::serve(&mut stream, |command| {
                            if matches!(
                                command,
                                ipc::Command::ExitList
                                    | ipc::Command::ExitUse(_)
                                    | ipc::Command::ExitDisable
                            ) {
                                let current = engine_ctl.config();
                                return exit_node_command(
                                    &command,
                                    exit_node_ctl,
                                    &current,
                                    routes_ctl,
                                    exit_policy_ctl,
                                    tun_ctl,
                                    engine_ctl,
                                    control_endpoint_ctl,
                                );
                            }
                            if let ipc::Command::DnsQuery(name) = &command {
                                return dns_query_report(config, name);
                            }
                            if command == ipc::Command::DnsStatus {
                                let runtime = dns_runtime_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let listener_live = runtime.is_some();
                                let cache = runtime.as_ref().map(crate::dns::Runtime::cache_stats);
                                let failures = runtime
                                    .as_ref()
                                    .map(crate::dns::Runtime::recent_failures)
                                    .unwrap_or_default();
                                let host = dns_host_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let host_state = host.observe().unwrap_or("observation failed");
                                return dns_report(
                                    config,
                                    listener_live,
                                    host.mechanism(),
                                    host_state,
                                    host.search_list(),
                                    cache,
                                    &failures,
                                );
                            }
                            if command == ipc::Command::Metrics {
                                let current = engine_ctl.config();
                                let selected = exit_node_ctl.and_then(|state| {
                                    state
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .active()
                                        .map(str::to_owned)
                                });
                                let exit_route_active = exit_policy_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .active();
                                let gateway_active = gateway_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .active();
                                let active_exit = active_exit_route(
                                    &current,
                                    selected.as_deref(),
                                    exit_route_active,
                                );
                                return metrics_report(
                                    &engine_ctl.stats(),
                                    relay_dropped.load(Ordering::Relaxed),
                                    current.route_offers.len(),
                                    gateway_active,
                                    active_exit.is_some(),
                                );
                            }
                            let mut output = report(
                                &command,
                                config,
                                engine_ctl,
                                Attachment {
                                    name: tun_ctl.name(),
                                    mtu: tun_ctl.mtu(),
                                    sockets: tun_ctl.userspace().map(|stack| stack.socket_count()),
                                    unreachable_family: socket_ctl
                                        .is_ipv4_only()
                                        .then(|| socket_ctl.unreachable_family()),
                                },
                                started,
                                &relay_dropped,
                                Some(portmap_state.snapshot()),
                                BugReportExtras {
                                    since_last_push: last_push_ctl
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .map(|at| at.elapsed()),
                                    // Snapshotted regardless of which command
                                    // this is — cheap (a handful of entries,
                                    // an uncontended lock) and keeps `report`
                                    // itself free of a command-specific
                                    // branch that would otherwise have to
                                    // live here instead.
                                    relay_health: relay_health_ctl
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .iter()
                                        .map(|(k, v)| (k.clone(), *v))
                                        .collect(),
                                    turn_health: turn_health_ctl
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .iter()
                                        .map(|(k, v)| (k.clone(), *v))
                                        .collect(),
                                },
                            );
                            if matches!(command, ipc::Command::Status | ipc::Command::BugReport) {
                                let current = engine_ctl.config();
                                let selected = exit_node_ctl.and_then(|state| {
                                    state
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .active()
                                        .map(str::to_owned)
                                });
                                let exit_route_active = exit_policy_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .active();
                                let gateway_active = gateway_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .active();
                                let gateway_error = gateway_error_ctl
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .clone();
                                output.push_str(&routing_report(
                                    &current,
                                    selected.as_deref(),
                                    exit_route_active,
                                    gateway_active,
                                    gateway_error.as_deref(),
                                ));
                            }
                            output
                        });
                        if matches!(handled, Ok(Some(ipc::Command::Down))) {
                            shutdown.request();
                            stop(socket_path);
                        }
                    }
                    // Nothing waiting. Sleeping beats spinning, and the
                    // latency is irrelevant for an administrative socket.
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TICK);
                    }
                    Err(_) => std::thread::sleep(TICK),
                }
            }
        });

        // ── netmap refresh ─────────────────────────────────────────────────
        if let Some(client) = control_client {
            // Only `client` is moved; everything else is shared with the other
            // threads, so it is borrowed explicitly rather than captured.
            let engine_refresh = &engine;
            let socket_refresh = &socket;
            let tun_refresh = &tun;
            let local_refresh = &local;
            let routes_refresh = &routes;
            let disco_refresh = &disco;
            let home_refresh = &home_selector;
            let dns_refresh = &dns_runtime;
            let dns_host_refresh = &dns_host;
            let exit_node_refresh = exit_node.as_ref();
            let gateway_refresh = &gateway;
            let gateway_error_refresh = &gateway_error;
            let exit_policy_refresh = &exit_policy;
            let control_endpoint_refresh = control_endpoint.as_deref();
            let last_push_refresh = &last_push;
            scope.spawn(move || {
                refresh_netmap(
                    client,
                    shutdown,
                    engine_refresh,
                    socket_refresh,
                    tun_refresh,
                    started,
                    local_refresh,
                    routes_refresh,
                    disco_refresh,
                    home_refresh,
                    exit_policy_refresh,
                    control_endpoint_refresh,
                    dns_refresh,
                    exit_node_refresh,
                    dns_host_refresh,
                    gateway_refresh,
                    gateway_error_refresh,
                    relay_out,
                    turn_out,
                    last_push_refresh,
                );
            });
        }

        // ── explicit port mapping ──────────────────────────────────────────
        if config.port_mapping {
            let disco_pm = &disco;
            let portmap_state = &portmap;
            let listen = socket.local_addr().unwrap_or(config.listen);
            scope.spawn(move || {
                portmap::run(portmap_state, disco_pm, shutdown, listen, listen_port);
            });
        }

        // ── timers ─────────────────────────────────────────────────────────
        let mut next_scan = Instant::now() + INTERFACE_SCAN;
        // §9.1. First probe promptly: a node that has just started has nothing
        // published, and peers cannot reach it until it does.
        let mut next_probe = Instant::now() + Duration::from_secs(2);
        // A laptop that suspends comes back on a network its measurements do
        // not describe. This is what turns that into promptness rather than a
        // wait for whichever timer fires first — see `crate::wake`.
        let mut wake = crate::wake::Detector::new();
        while !shutdown.requested() {
            std::thread::sleep(TICK);
            let now = now_ms(started);
            // **Before the scan, deliberately.** Setting `next_scan` into the
            // past here is what makes the enumeration below happen on this tick
            // instead of up to fifteen seconds later, and re-enumerating is the
            // first thing a resumed machine needs: the addresses discovery is
            // about to advertise are the ones it has now.
            if let Some(gap) = wake.tick() {
                eprintln!(
                    "karstd: this machine did not run for {} s — re-enumerating \
                     interfaces and rediscovering every peer path",
                    gap.as_secs()
                );
                next_scan = Instant::now();
                // The relay is a path too, and the connection carrying it went
                // with the rest. Re-measuring promptly is what keeps a node
                // that woke on a worse network from staying on a relay it can
                // no longer reach.
                next_probe = Instant::now();
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .rediscover(now);
            }
            // Interfaces change — a laptop moves between networks, a VPN comes
            // up, DHCP renews. Re-enumerating on a slow timer rather than on
            // every tick keeps a netlink dump off the 100 ms path, and
            // `set_interfaces` schedules an advertisement only when the list
            // actually moved, so a stable host pays nothing for this.
            if Instant::now() >= next_scan {
                next_scan = Instant::now() + INTERFACE_SCAN;
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_interfaces(&gather_interfaces(config), listen_port);
            }
            dispatch(
                engine.poll(now, random_seed),
                &socket,
                &tun,
                relay_out,
                turn_out,
            );
            if Instant::now() >= next_probe {
                next_probe = Instant::now() + crate::home::PROBE_INTERVAL;
                probe_relays(
                    &rtt_probes,
                    &home_selector,
                    &mut rotation,
                    &engine,
                    relay_out,
                    now,
                    random_seed,
                );
            }
            dispatch(
                disco_poll(&disco, &engine, now, relay_out),
                &socket,
                &tun,
                relay_out,
                turn_out,
            );
            if apply_disco_paths(&disco, &engine) {
                let current = engine.config();
                let selected = exit_node.as_ref().and_then(|selection| {
                    selection
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .active()
                        .map(str::to_owned)
                });
                if let Err(error) = reconcile_exit(
                    &routes,
                    &exit_policy,
                    &tun,
                    &current,
                    Some(&engine),
                    control_endpoint.as_deref(),
                    selected.as_deref(),
                ) {
                    eprintln!(
                        "karstd: exit selection is dormant after an endpoint change: {error}"
                    );
                }
            }
            // §7.8's priming rule — every tick, regardless of whether the
            // path changes above fired. Not driven from `Disco::inbound`
            // itself: that runs on the receive thread, and priming an
            // allocation is `crate::turn`'s I/O, not something a
            // demultiplexer should block on.
            prime_turn_permissions(&disco, turn_out);
        }
    });

    // The socket file outlives the process unless removed. Leaving it behind
    // makes the next start look like a stale-socket recovery rather than a
    // clean one.
    let _ = std::fs::remove_file(socket_path);
    if let Some(runtime) = dns_runtime
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        runtime.stop();
    }
    if let Err(error) = dns_host
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .shutdown()
    {
        eprintln!("karstd: DNS host cleanup failed: {error}");
    }
    Ok(())
}

/// Advance AVEN's timers and turn its intents into I/O.
///
/// AVEN owns reachability discovery, while the run loop owns the shared socket;
/// keeping the conversion here prevents the sans-io discovery crate from
/// acquiring an I/O dependency.
///
/// Probes come back as ordinary UDP output. Candidate advertisements go over
/// the relay (§7.3) and are handed to `advertise`, which belongs to the relay
/// worker — the only thread that owns a Ponor connection.
fn disco_poll(
    disco: &Mutex<disco::Disco>,
    engine: &Engine,
    now_ms: u64,
    relay: Option<&RelaySender>,
) -> Output {
    let mut state = disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let out = state.poll(now_ms, || {
        let seed = random_seed();
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&seed[..12]);
        TxId(tx)
    });
    drop(state);

    if let Some(relay) = relay {
        for (destination, payload) in out.relayed {
            // A full queue drops rather than blocks. This is the timer thread:
            // waiting on a relay that has gone away would stop PHREATIC's own
            // timers, turning a relay outage into a tunnel outage. A dropped
            // advertisement costs one rendezvous attempt, and the next one is
            // five seconds away.
            //
            // **Routed like the data, by §9.1's rules.** A rendezvous sent to a
            // relay the peer is not on reaches nobody, and the direct path it
            // would have opened is the one thing that makes this connection
            // temporary — so an advertisement that took the wrong relay would
            // leave the pair on the relay path for as long as they both ran.
            relay.send_via(engine.relay_for(destination), destination, &payload);
        }
    }

    Output {
        // **Always direct.** A probe exists to prove a NAT binding on the
        // shared datapath socket (§4); one sent through the relay would prove
        // the relay is reachable, which was never in doubt.
        datagrams: out
            .datagrams
            .into_iter()
            .map(|(d, to)| (d, Via::Direct(to)))
            .collect(),
        packets: Vec::new(),
    }
}

/// How often the host's interface addresses are re-enumerated.
const INTERFACE_SCAN: Duration = Duration::from_secs(15);

/// Measure the relay this node holds and one alternative, and settle §9.1's
/// choice.
///
/// **Both halves are needed for §9.2 to be able to say anything.** The
/// incumbent's number alone can only confirm the choice already made; a
/// challenger needs its own, on the same rounds, or the sustained-margin rule
/// has nothing to compare. So one alternative at a time is dialled and measured
/// for a window long enough for the hysteresis to act ([`crate::home::Rotation`]),
/// and let go again — a Ponor connection to every relay in the registry would
/// cost a TLS and ML-DSA-87 handshake apiece and defeat the point of choosing
/// one.
fn probe_relays(
    rtt: &Mutex<crate::home::Probes>,
    home: &Mutex<crate::home::Selector>,
    rotation: &mut crate::home::Rotation,
    engine: &Engine,
    relay: Option<&RelaySender>,
    now_ms: u64,
    rand: impl Fn() -> [u8; 32],
) {
    let Some(relay) = relay else {
        return;
    };
    let registry: Vec<crate::home::RelayId> = engine.relays().iter().map(|r| r.relay_id).collect();

    // Settle whatever the last round measured before asking again, so the
    // choice reflects answers rather than questions.
    // The relay the connection is actually on, which is what a `Pong` arriving
    // on it will be credited to. Between a choice moving and the worker
    // following it these differ for a round, and recording the probe against
    // the wrong one would lose the measurement.
    let held = engine.home_relay();
    let (chosen, changed) = {
        let mut home = home
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A relay the netmap has withdrawn is not somewhere peers are told to
        // look, so it must not go on being held or measured.
        home.retain(&registry);
        // **The relay already held is an incumbent, not a blank slate.** A
        // daemon connects to one before anything has been measured, and
        // `select`'s first selection is immediate because there is normally
        // nothing to defend — so without this the first round would hand the
        // node to whichever alternative happened to answer faster once, and
        // every restart would be a coin toss paid for in netmap updates.
        if let Some(held) = held.filter(|_| home.chosen().is_none()) {
            if registry.contains(&held) {
                home.hold(held);
            }
        }
        home.select()
    };
    if changed {
        eprintln!(
            "karstd: home relay is now {}",
            chosen.map_or_else(|| "none".to_owned(), |id| hex_short(&id))
        );
    }

    if let Some(held) = held {
        send_probe(rtt, relay, None, held, now_ms, &rand);
    }

    // Everything but the relay already being measured on the home connection.
    // Probing it twice would compare it against itself.
    let candidates: Vec<crate::home::RelayId> = registry
        .into_iter()
        .filter(|id| Some(*id) != held)
        .collect();
    if let Some(candidate) = rotation.round(&candidates) {
        send_probe(rtt, relay, Some(candidate), candidate, now_ms, &rand);
    }
}

/// Mint a token, record it against `relay`, and send it — if that relay is
/// answering at all.
///
/// `queue` is `None` for the home connection and `Some` for one the on-demand
/// pool holds; `relay` is what the answer will be credited to, and the two are
/// separate because the home queue's connection is named by the worker rather
/// than by the caller.
fn send_probe(
    rtt: &Mutex<crate::home::Probes>,
    sender: &RelaySender,
    queue: Option<RelayId>,
    relay: crate::home::RelayId,
    now_ms: u64,
    rand: &impl Fn() -> [u8; 32],
) {
    let seed = rand();
    let Some(token) = seed
        .first_chunk::<{ crate::relay::PING_TOKEN_LEN }>()
        .copied()
    else {
        return;
    };
    let admitted = {
        let mut rtt = rtt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        rtt.sent(relay, token, now_ms)
    };
    // A relay with probes already outstanding is one that is not answering.
    // Sending more would measure this node's willingness to ask rather than
    // the relay's willingness to reply.
    if admitted {
        sender.ping(queue, token);
    }
}

/// Put one queued item on the wire.
async fn write_relayed(
    sender: &mut crate::relay::Sender,
    item: Relayed,
) -> Result<(), crate::relay::ConnectError> {
    match item {
        Relayed::Packet {
            destination,
            payload,
        } => sender.send_packet(destination, &payload).await,
        Relayed::Ping(token) => sender.ping(token).await,
        // The connection was the request. Nothing goes on the wire.
        Relayed::Hold => Ok(()),
    }
}

/// The first four bytes of an id, for a log line.
fn hex_short(id: &[u8]) -> String {
    use std::fmt::Write as _;
    id.iter().take(4).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The addresses this node offers as candidates — `spec/aven-v1.md` §7.3.
///
/// `karst_tun::local_addresses` has already dropped what a peer could not
/// reach at all — loopback, link-local, tentative, deprecated. What is left is
/// a *policy* question and is decided here, in the daemon that knows what the
/// tunnel is:
///
/// - **The node's own overlay addresses are removed.** They are reachable only
///   *through* the tunnel, so advertising one as a way to reach the tunnel is a
///   loop, and a peer that probed it would be sending discovery traffic into
///   the thing being discovered.
///
/// A private RFC 1918 address is deliberately **kept**. Two nodes on the same
/// LAN behind the same NAT have no other way to find each other, and that is
/// the case direct paths help most. §12.3 records the cost honestly — a
/// `CallMeMaybe` body is not encrypted, so the relay operator sees these — and
/// that is a protocol gap to close, not a reason to withhold the candidate that
/// makes local discovery work.
///
/// A failure here is not fatal. It costs candidates, which costs direct paths,
/// and the relay carries the traffic meanwhile.
fn gather_interfaces(config: &Config) -> Vec<std::net::IpAddr> {
    let addresses = match karst_tun::local_addresses() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "karstd: cannot enumerate local addresses ({e}); discovery will rely on \
                       what peers report seeing"
            );
            return Vec::new();
        }
    };
    addresses
        .into_iter()
        .filter(|ip| !config.addresses.iter().any(|own| own.addr == *ip))
        .collect()
}

/// One datagram waiting for the relay worker to put it on the wire.
///
/// Carries both AVEN advertisements and PHREATIC data, because to the relay
/// they are the same thing: opaque bytes for a named node. Ponor reads the
/// destination id and nothing else.
#[derive(Debug)]
enum Relayed {
    /// A PHREATIC or AVEN datagram for a peer.
    Packet {
        destination: [u8; karst_relay_proto::consts::ID_LEN],
        payload: Vec<u8>,
    },
    /// §9.1's latency probe, addressed to the relay itself rather than through
    /// it. It shares this queue so that it is measured behind whatever traffic
    /// is already waiting — a round trip taken past a full queue is the one the
    /// datapath would actually see, and one taken past it is not.
    Ping([u8; crate::relay::PING_TOKEN_LEN]),
    /// Nothing to write: a request that this connection exist, and go on
    /// existing while something keeps asking. It is how the relay this node is
    /// *leaving* stays reachable across a §9.2 move, and how an alternative
    /// under measurement is dialled before there is anything to send it.
    Hold,
}

/// The datapath's handle on the relay worker.
///
/// **Bounded, and it drops rather than blocks.** These calls happen on the
/// threads that carry the tunnel, and waiting for a relay that has gone away
/// would stop the TUN reader and PHREATIC's own timers — turning a relay outage
/// into a total outage, which is precisely what the relay path exists to
/// prevent. `ponor-v1.md` §7.3 makes the same choice one hop further on: the
/// relay's own queues are bounded and never apply backpressure to their source.
///
/// A dropped datagram is a dropped datagram. PHREATIC retransmits handshakes
/// and the traffic above the tunnel does its own recovery, which is the same
/// contract a full socket buffer already has.
#[derive(Debug)]
struct RelaySender {
    queue: tokio::sync::mpsc::Sender<Relayed>,
    /// Traffic for §9.1's second rule, handed to the thread that owns the
    /// on-demand connections.
    on_demand: tokio::sync::mpsc::Sender<(RelayId, Relayed)>,
    dropped: Arc<AtomicU64>,
}

impl RelaySender {
    /// Queue §9.1's latency probe for the relay this node holds, or for one
    /// being measured as an alternative.
    ///
    /// Dropped rather than blocked on, like everything else here: a probe lost
    /// to a full queue is a measurement not taken, and the selector treats a
    /// relay that says nothing as absent from the round rather than as fast.
    fn ping(&self, relay: Option<RelayId>, token: [u8; crate::relay::PING_TOKEN_LEN]) {
        let queued = match relay {
            None => self.queue.try_send(Relayed::Ping(token)).is_ok(),
            Some(relay) => self
                .on_demand
                .try_send((relay, Relayed::Ping(token)))
                .is_ok(),
        };
        if !queued {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Ask for a connection to `relay` to exist, without sending anything.
    ///
    /// Used where the connection itself is the point: the relay this node is
    /// leaving after a §9.2 move, which peers still believe it is on.
    fn hold(&self, relay: RelayId) {
        if self.on_demand.try_send((relay, Relayed::Hold)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queue a datagram on the relay `relay` names, or on the home connection
    /// when it names none — §9.1's two rules, as the engine decided them.
    fn send_via(&self, relay: Option<RelayId>, destination: RelayId, payload: &[u8]) {
        let relayed = Relayed::Packet {
            destination,
            payload: payload.to_vec(),
        };
        let queued = match relay {
            None => self.queue.try_send(relayed).is_ok(),
            Some(relay) => self.on_demand.try_send((relay, relayed)).is_ok(),
        };
        if !queued {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A Ponor identifier: a node id or a relay id, which are the same width and
/// derived the same way from different keys.
type RelayId = [u8; karst_relay_proto::consts::ID_LEN];

/// Reconnect delay bounds for the relay worker.
const RELAY_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RELAY_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Wait out a reconnect delay, then double it.
///
/// Slept in `TICK`-sized pieces so a shutdown is noticed promptly rather than
/// up to a minute later.
fn sleep_backoff(shutdown: &Shutdown, backoff: &mut Duration) {
    let deadline = Instant::now() + *backoff;
    while Instant::now() < deadline && !shutdown.requested() {
        std::thread::sleep(TICK);
    }
    *backoff = (*backoff * 2).min(RELAY_BACKOFF_MAX);
}

/// One relay or TURN server's most recently observed reachability —
/// `bugreport`'s [[relay]]/[[turn]] sections (plans/phase-6
/// /08-observability.md §5 W6 item 3).
///
/// Only a transition is recorded (see [`Reachability::record`]), not every
/// attempt: `since` is when the current state started, which is the number
/// worth reporting — "reachable for 3 hours" or "unreachable for 40
/// seconds" — not a timestamp of the last time a worker happened to check.
#[derive(Debug, Clone, Copy)]
struct Reachability {
    reachable: bool,
    since: Instant,
}

impl Reachability {
    /// Update `map[key]`, but only if `reachable` actually differs from what
    /// is already recorded there — repeated identical outcomes (a relay that
    /// stays up for hours, ticking the connect-success path once per
    /// session) must not reset `since` on every one.
    fn record(map: &Mutex<HashMap<String, Self>>, key: &str, reachable: bool) {
        let mut map = map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = map.get(key).is_none_or(|prev| prev.reachable != reachable);
        if changed {
            map.insert(
                key.to_owned(),
                Self {
                    reachable,
                    since: Instant::now(),
                },
            );
        }
    }
}

#[cfg(test)]
mod reachability_tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::Reachability;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The property `bug_report`'s "since Xs ago" reading depends on: an
    /// unchanged outcome must not look like a fresh transition.
    #[test]
    fn only_a_real_transition_resets_since() {
        let map = Mutex::new(HashMap::new());
        Reachability::record(&map, "relay-a", false);
        let first = map.lock().expect("lock")["relay-a"].since;

        std::thread::sleep(std::time::Duration::from_millis(5));
        Reachability::record(&map, "relay-a", false);
        let second = map.lock().expect("lock")["relay-a"].since;
        assert_eq!(first, second, "an unchanged outcome must not reset `since`");

        Reachability::record(&map, "relay-a", true);
        let third = map.lock().expect("lock")["relay-a"].since;
        assert_ne!(first, third, "a real transition must update `since`");
        assert!(map.lock().expect("lock")["relay-a"].reachable);
    }

    /// Two different keys (two relays, or a relay and a TURN server) do not
    /// interfere with each other's recorded state.
    #[test]
    fn independent_keys_are_recorded_independently() {
        let map = Mutex::new(HashMap::new());
        Reachability::record(&map, "relay-a", true);
        Reachability::record(&map, "relay-b", false);

        let locked = map.lock().expect("lock");
        assert!(locked["relay-a"].reachable);
        assert!(!locked["relay-b"].reachable);
    }
}

/// How many datagrams may wait for the relay worker.
///
/// Sized for a burst rather than a backlog. A relayed flow that outruns the TLS
/// stream should lose datagrams promptly and let the layer above notice, not
/// accumulate a queue whose only effect is latency — the classic bufferbloat
/// failure, and worse here because everything in it is already a fallback path.
const RELAY_QUEUE: usize = 256;

/// Everything the relay worker needs from the rest of the daemon.
///
/// A struct rather than nine parameters, and it is the same set the engine's
/// own threads borrow — the worker is a third datapath thread, not a side
/// channel.
struct RelayCommon<'a> {
    shutdown: &'a Shutdown,
    /// §9.1's outstanding latency probes, keyed by the relay each was sent to.
    /// Every connection this node holds may be being measured, so this is the
    /// node's state rather than any one worker's.
    rtt: &'a Mutex<crate::home::Probes>,
    /// §9.1's choice, fed by those probes.
    home: &'a Mutex<crate::home::Selector>,
    identity: Arc<crate::control::Identity>,
    node_id: Vec<u8>,
    disco: &'a Mutex<disco::Disco>,
    engine: &'a Engine,
    socket: &'a UdpTransport,
    tun: &'a NetworkDevice,
    /// Extra trust anchors for the TLS hop, from local configuration.
    relay_ca_file: Option<std::path::PathBuf>,
    /// Where a reply to a relayed datagram goes when it is itself relayed —
    /// which every response to a relayed handshake is, until a direct path
    /// exists. Sending is non-blocking, so the receive task may use it.
    relayed: &'a RelaySender,
    started: Instant,
    /// See [`Reachability`]. Keyed by `crate::netmap::Relay::address`.
    relay_health: &'a Mutex<HashMap<String, Reachability>>,
}

/// Which of §9.1's connections this worker is carrying.
///
/// **Both are measured**, because §9.2 cannot move this node's choice without
/// numbers for the alternatives; what differs is the lifetime. The home
/// connection is held for as long as the daemon runs and follows the choice
/// when it changes; the others are opened for a peer or for a measurement and
/// let go when the traffic stops.
#[derive(Debug)]
enum RelayRole {
    /// The relay this node chose and publishes.
    Home,
    /// A relay a *peer* published, or one being measured as an alternative.
    /// Closing it when the traffic stops is what §9.1 asks for.
    OnDemand {
        /// Engine milliseconds at the last inbound traffic, shared with the hub
        /// that decides when this connection has been idle long enough.
        activity: Arc<AtomicU64>,
    },
}

struct RelayContext<'a> {
    common: &'a RelayCommon<'a>,
    relay: crate::netmap::Relay,
    role: RelayRole,
}

impl RelayContext<'_> {
    /// Whether this is the connection §9.1 keeps up.
    fn is_home(&self) -> bool {
        matches!(self.role, RelayRole::Home)
    }
}

/// The relay this connection should be on now, if that is not the one it is on.
///
/// Only the home connection follows the choice. An on-demand connection was
/// opened to reach a particular relay — a peer's published home, or an
/// alternative under measurement — and re-pointing it at the selector's answer
/// would defeat both.
fn moved_home(context: &RelayContext<'_>) -> Option<crate::netmap::Relay> {
    if !context.is_home() {
        return None;
    }
    let chosen = context
        .common
        .home
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .chosen();
    home_target(
        chosen,
        context.relay.relay_id,
        &context.common.engine.relays(),
    )
}

/// Where the home connection belongs, given the choice and the registry.
///
/// Separated from the connection it moves so that it can be reasoned about: the
/// three inputs are the whole of it, and each of the cases below is a state a
/// running node reaches.
fn home_target(
    chosen: Option<RelayId>,
    current: RelayId,
    registry: &[crate::netmap::Relay],
) -> Option<crate::netmap::Relay> {
    match chosen {
        // Where it already is.
        Some(id) if id == current => None,
        // §9.2 moved it. A choice the registry no longer carries cannot be
        // dialled — `retain` keeps the selector from holding one, so this is
        // belt and braces, and staying put is the right answer to it anyway.
        Some(id) => registry.iter().find(|r| r.relay_id == id).cloned(),
        // No choice at all: either nothing has been measured yet, or the
        // netmap withdrew the relay this node was on and `retain` released it.
        // The second is worth acting on — **a node left on a withdrawn relay is
        // a node peers are no longer told to look for** — and the first is not,
        // because the relay held is exactly where it should be until something
        // has been measured.
        None if registry.iter().any(|r| r.relay_id == current) => None,
        None => registry.first().cloned(),
    }
}

/// How many attempts a relay gets before this node looks for another.
///
/// Three, which the backoff spreads over a few seconds. Fewer would abandon a
/// relay over a dropped SYN; more would leave a node that a relay will not admit
/// waiting on it, which is a wait with no end — §10.1 makes a roster miss
/// deliberately indistinguishable from a relay that is simply down, so the only
/// thing to do about either is to try somewhere else.
const HOME_RELAY_ATTEMPTS: u32 = 3;

/// The next relay to try after one that will not have this node.
///
/// **Registry order, wrapping.** A node with one relay has nowhere to go and
/// must keep trying the one it has: the roster it is missing from may be
/// updated, and abandoning the only relay would make that unrecoverable.
fn next_relay(current: RelayId, registry: &[crate::netmap::Relay]) -> Option<crate::netmap::Relay> {
    let at = registry.iter().position(|r| r.relay_id == current);
    match at {
        // Not in the registry at all — withdrawn while this node was on it.
        // Start from the top rather than from a position that no longer means
        // anything.
        None => registry.first().cloned(),
        Some(at) => registry
            .get((at + 1) % registry.len())
            .filter(|next| next.relay_id != current)
            .cloned(),
    }
}

/// Leave a relay this node cannot get onto, for the next one in the registry.
///
/// **A relay this node cannot get onto is not a relay it can be reached on**,
/// and waiting for one is a wait with no end: §10.1 makes a roster miss
/// deliberately indistinguishable from a relay that is down, so the only thing
/// to do about either is to try somewhere else. Without this a node whose
/// registry listed a relay it was not admitted to first would retry that one
/// for the life of the process, and the relays it *was* admitted to would never
/// be dialled — nothing measures a relay it has no connection to.
fn abandon_relay(context: &mut RelayContext<'_>) {
    let Some(next) = next_relay(context.relay.relay_id, &context.common.engine.relays()) else {
        return;
    };
    eprintln!(
        "karstd: giving up on relay {} for now; trying {}",
        context.relay.address, next.address
    );
    // The selector is told as well, or it would go on naming the relay just
    // abandoned and the next pass would move straight back to it. The abandoned
    // one stays in the registry, so the rotation will measure it again and it
    // can win its place back once it answers.
    context
        .common
        .home
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .hold(next.relay_id);
    context.common.engine.set_home_relay(Some(next.relay_id));
    context.relay = next;
}

/// Move the home connection, keeping the relay it is leaving reachable.
///
/// **The old relay is where every peer still believes this node is**, and will
/// go on believing until the netmap reaches them. The move is published at once
/// (`refresh_netmap`), but between the two a peer dialling the old relay finds
/// nobody there, and its packets are not late — they are delivered nowhere. So
/// the old relay is held as an on-demand connection: traffic arriving there
/// still lands, and the pool lets it go once none does. §9.2's argument, one
/// layer down — the cost of a move is not paid by the node that moves.
fn handover(
    engine: &Engine,
    relayed: &RelaySender,
    old: &crate::netmap::Relay,
    new: &crate::netmap::Relay,
) {
    eprintln!(
        "karstd: moving home relay from {} to {}",
        old.address, new.address
    );
    engine.set_home_relay(Some(new.relay_id));
    relayed.hold(old.relay_id);
}

/// Carry relayed traffic — AVEN rendezvous and PHREATIC data — over one
/// authenticated Ponor connection.
///
/// A dedicated current-thread runtime, because relay TCP reads must not occupy
/// the UDP receive loop. A relay outage must not take the tunnel down, so every
/// failure here is a reconnect rather than an error anyone else sees.
///
/// **The two directions run as separate tasks over a split connection.** They
/// share one TLS stream but must not share a scheduling point: a worker that
/// alternated between reading and draining the send queue would add its polling
/// interval to the latency of every relayed packet, and once this path carries
/// tunnel data rather than only rendezvous messages, that interval *is* the
/// tunnel's latency.
#[allow(clippy::needless_pass_by_value)] // owns data moved into the scoped worker
fn relay_worker(mut context: RelayContext<'_>, outbound: tokio::sync::mpsc::Receiver<Relayed>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("karstd: cannot start relay runtime; the relay path is disabled");
        return;
    };
    let tls = match crate::relay_tls::client_config(context.common.relay_ca_file.as_deref()) {
        Ok(tls) => tls,
        // Named rather than swallowed. The likeliest cause is a mistyped or
        // unreadable `relay_ca_file`, and "the relay path is disabled" without
        // the reason is the kind of message that costs an afternoon.
        Err(e) => {
            eprintln!("karstd: {e}; the relay path is disabled");
            return;
        }
    };

    let mut outbound = outbound;
    let mut backoff = RELAY_BACKOFF_MIN;
    let mut failures = 0u32;
    while !context.common.shutdown.requested() {
        // §9.2's decision, carried out. The home connection follows the
        // selector: this is the point where a choice that moved becomes a
        // connection that moved, and it is here rather than anywhere else
        // because a relay is changed by ending one connection and opening the
        // next, which is exactly what this loop already does.
        if let Some(next) = moved_home(&context) {
            handover(
                context.common.engine,
                context.common.relayed,
                &context.relay,
                &next,
            );
            context.relay = next;
        }
        // Whatever was outstanding belonged to a connection that no longer
        // exists, and can never be answered now.
        context
            .common
            .rtt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reset(context.relay.relay_id);
        let session = crate::relay::Session::from_control_handle(
            &context.common.node_id,
            &context.relay,
            random_seed(),
        );
        let Some(session) = session else {
            eprintln!("karstd: invalid node handle; the relay path is disabled");
            return;
        };
        let connected = runtime.block_on(crate::relay::Connection::connect(
            session,
            &*context.common.identity,
            &crate::control::RelayVerifier,
            Arc::clone(&tls),
            &context.relay,
        ));
        let connection = match connected {
            Ok(c) => c,
            // **Said once per outage, not once per attempt.** A relay that
            // cannot be reached produced no log line at all before this, so a
            // node with a mistyped CA path, an unreachable relay or a roster it
            // is absent from looked exactly like a node with nothing to say —
            // and the symptom, a peer stuck on `state = "connecting"`, names
            // none of those.
            Err(e) => {
                Reachability::record(context.common.relay_health, &context.relay.address, false);
                if backoff == RELAY_BACKOFF_MIN {
                    eprintln!(
                        "karstd: cannot reach relay {} ({e}); retrying",
                        context.relay.address
                    );
                }
                failures = failures.saturating_add(1);
                if context.is_home() && failures >= HOME_RELAY_ATTEMPTS {
                    failures = 0;
                    abandon_relay(&mut context);
                }
                // The backoff deliberately survives the move: a node whose
                // relays are all unreachable must slow down, not walk the
                // registry at full speed.
                sleep_backoff(context.common.shutdown, &mut backoff);
                continue;
            }
        };
        let Some((sender, receiver)) = connection.split() else {
            // Unreachable through `connect`, which loops until established.
            // Treated as a failed attempt rather than asserted, because this is
            // a daemon carrying traffic and the alternative to being wrong here
            // is a panic in a thread nothing restarts.
            Reachability::record(context.common.relay_health, &context.relay.address, false);
            sleep_backoff(context.common.shutdown, &mut backoff);
            continue;
        };
        // Reset only once a connection is actually established. Resetting on
        // the *attempt* would make a relay that accepts and immediately closes
        // — an overloaded one, or one mid-restart — into an unthrottled
        // reconnect loop from every node at once, which is the load pattern
        // most likely to keep it down.
        Reachability::record(context.common.relay_health, &context.relay.address, true);
        if backoff != RELAY_BACKOFF_MIN {
            eprintln!("karstd: relay {} reachable again", context.relay.address);
        }
        backoff = RELAY_BACKOFF_MIN;
        failures = 0;

        // Both directions stop together. Without this the receive loop would
        // outlive a send loop whose queue has been closed — which is exactly
        // how an on-demand connection ends — and the worker would sit in
        // `join!` holding a TLS stream nobody is using until the daemon exits.
        let closing = AtomicBool::new(false);
        runtime.block_on(async {
            tokio::join!(
                relay_send_loop(&context, &closing, sender, &mut outbound),
                relay_receive_loop(&context, &closing, receiver),
            )
        });

        // §7.7: the reflect key died with the connection. Keeping it would
        // mean probing a reflector that has already forgotten this node, and
        // advertising a mapping nothing is keeping alive.
        context
            .common
            .disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear_reflector(&context.relay.relay_id);

        // A closed queue is the hub saying this relay is no longer needed —
        // §9.1's "SHOULD be closed after a period with no traffic". Reconnecting
        // would undo the decision immediately.
        if outbound.is_closed() && outbound.is_empty() {
            return;
        }
    }
}

/// Drain the queue onto the relay until it breaks or the daemon stops.
async fn relay_send_loop(
    context: &RelayContext<'_>,
    closing: &AtomicBool,
    mut sender: crate::relay::Sender,
    outbound: &mut tokio::sync::mpsc::Receiver<Relayed>,
) {
    while !context.common.shutdown.requested() {
        // A short timeout rather than a bare `recv`, so a quiet connection
        // still notices a shutdown request.
        let Ok(next) = tokio::time::timeout(TICK, outbound.recv()).await else {
            if closing.load(Ordering::Relaxed) {
                return;
            }
            // §9.2 moved the choice. End this connection so the worker can open
            // the next one — checked on the idle path rather than per datagram,
            // because a relay change is a thing that happens in minutes and a
            // lock taken per packet is a thing that happens in nanoseconds.
            if moved_home(context).is_some() {
                closing.store(true, Ordering::Relaxed);
                return;
            }
            continue;
        };
        let Some(next) = next else {
            // The queue's last sender is gone, so nothing further can be sent
            // on this connection. Tell the reader as well: it has no other way
            // to learn that this connection is finished.
            closing.store(true, Ordering::Relaxed);
            return;
        };
        if write_relayed(&mut sender, next).await.is_err() {
            closing.store(true, Ordering::Relaxed);
            return;
        }
        // **Coalesce whatever else is already queued before flushing.** A
        // flush per datagram is a TLS record and a syscall each; a burst of
        // fragments belonging to one handshake should cost one of each.
        while let Ok(more) = outbound.try_recv() {
            if write_relayed(&mut sender, more).await.is_err() {
                closing.store(true, Ordering::Relaxed);
                return;
            }
        }
        if sender.flush().await.is_err() {
            closing.store(true, Ordering::Relaxed);
            return;
        }
    }
}

/// Deliver what the relay forwards to whichever protocol owns it.
async fn relay_receive_loop(
    context: &RelayContext<'_>,
    closing: &AtomicBool,
    mut receiver: crate::relay::Receiver,
) {
    while !context.common.shutdown.requested() && !closing.load(Ordering::Relaxed) {
        let received = tokio::time::timeout(
            TICK,
            receiver.receive(&*context.common.identity, &crate::control::RelayVerifier),
        )
        .await;
        let events = match received {
            Ok(Ok(events)) => events,
            // A timeout is the normal case, not a failure: it is what lets this
            // loop notice a shutdown on a connection that happens to be quiet.
            Err(_) => continue,
            Ok(Err(_)) => {
                closing.store(true, Ordering::Relaxed);
                return;
            }
        };
        if !events.is_empty() {
            if let RelayRole::OnDemand { activity } = &context.role {
                activity.store(now_ms(context.common.started), Ordering::Relaxed);
            }
        }
        for event in events {
            on_relay_event(context, event);
        }
    }
}

/// Act on one event from a relay, whichever of §9.1's two connections it
/// arrived on.
fn on_relay_event(context: &RelayContext<'_>, event: crate::relay::Event) {
    // §9.1's first rule, answered. The relay this node holds cannot
    // deliver to this peer, so anything further for it goes to the
    // relay the peer published — if it published one this node can
    // reach.
    //
    // **Only the home connection is believed.** An on-demand relay
    // saying a peer is not there means the peer's published home is
    // wrong or stale, and re-marking on that answer would send the next
    // packet back to the relay that has already refused it, and the one
    // after that here again.
    if let crate::relay::Event::Gone { peer_id, reason } = event {
        if context.is_home()
            && context
                .common
                .engine
                .relay_unreachable(peer_id, now_ms(context.common.started))
        {
            eprintln!(
                "karstd: relay {} cannot reach {} ({reason:?}); using the relay it \
                     published",
                context.relay.address,
                hex_short(&peer_id)
            );
        }
        return;
    }
    // §7.7: this relay runs a reflector, and here is the key. Handed
    // straight to discovery — the address inside is AVEN's encoding,
    // and `karst-disco` owns that.
    //
    // **Only from the home connection.** A reflector is a vantage point
    // AVEN probes over minutes; taking one from a connection that
    // closes as soon as its traffic stops would leave discovery
    // advertising a mapping nothing is keeping alive, which is the
    // failure `clear_reflector` exists to prevent.
    if let crate::relay::Event::Reflector { key, endpoint } = event {
        if !context.is_home() {
            return;
        }
        let Ok(endpoint) = karst_disco::Endpoint::from_wire(&endpoint) else {
            // A relay this node authenticated sent an endpoint it
            // cannot parse. Nothing to do but ignore the offer; the
            // connection is still good for carrying traffic, which is
            // what it is chiefly for.
            return;
        };
        let taken = context
            .common
            .disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_reflector(context.relay.relay_id, key, endpoint.0);
        // Once per connection, not per datagram. A node that never
        // learns its mapped address stays on the relay forever, and
        // "the relay offered no reflector" and "the reflector never
        // answered" are different problems that look identical from
        // `karst status` — which is finding 18's lesson applied one
        // subsystem over.
        eprintln!(
            "karstd: relay {} offers a reflector at {} ({})",
            context.relay.address,
            endpoint.0,
            if taken {
                "accepted"
            } else {
                "declined, too many"
            }
        );
        return;
    }
    // §9.1's measurement, answered on the connection it was sent on — and
    // credited to *this* relay. §9.2 needs numbers for the alternatives as well
    // as for the incumbent, so this runs on every connection; what makes it
    // safe is that the token was recorded against the relay it went to, so a
    // relay echoing something it did not answer resolves nothing.
    if let crate::relay::Event::Pong { token } = event {
        let resolved = context
            .common
            .rtt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve(
                context.relay.relay_id,
                token,
                now_ms(context.common.started),
            );
        if let Some(measured) = resolved {
            context
                .common
                .home
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .observe(context.relay.relay_id, measured);
        }
        return;
    }
    let crate::relay::Event::Packet { source_id, payload } = event else {
        return;
    };
    // §9.1's first rule, answered by the peer itself: it is on the relay this
    // node holds, whatever it published and whatever that relay said earlier.
    if context.is_home() {
        context.common.engine.seen_on_home_relay(source_id);
    }
    let now = now_ms(context.common.started);
    // **AVEN is asked first, exactly as on the UDP socket**, and for the
    // same reason: the two protocols share this transport too, and only
    // one of them can authenticate any given datagram. `Disco` reports
    // whether the payload was its own; anything else is PHREATIC's.
    let handled = context
        .common
        .disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .inbound_from_relay(source_id, &payload, now);
    if handled {
        return;
    }
    let out =
        context
            .common
            .engine
            .inbound_from_relay(source_id, &payload, now, &responder_randomness());
    // **The reply goes back over the relay**, and it has to: the
    // response to a relayed `HandshakeInit` is what completes the
    // handshake, and until it does there is no session and no direct
    // path to upgrade to. The engine has already chosen the transport,
    // so this only has to honor it — and the queue is non-blocking, so
    // handing work to the send task cannot stall this one.
    dispatch(
        out,
        context.common.socket,
        context.common.tun,
        Some(context.common.relayed),
        // `Engine::inbound_from_relay`'s own replies are always tagged
        // `Via::Relay`, back onto the connection the request arrived on —
        // never `Via::Turn`, which only ever answers a datagram that arrived
        // through this node's *own* allocation. `None` here costs nothing a
        // relay-delivered reply could ever need.
        None,
    );
}

/// How long an on-demand connection is kept after its last datagram.
///
/// §9.1 says these "SHOULD be closed after a period with no traffic" and does
/// not say how long. Two minutes: long enough that an interactive flow with
/// gaps in it — a shell session, a paused transfer — does not pay for a TLS and
/// ML-DSA-87 handshake every time the user stops typing, and short enough that a
/// peer this node spoke to once does not leave a connection on somebody else's
/// relay for the rest of the day.
const ON_DEMAND_IDLE_MS: u64 = 120_000;

/// Hold the connections §9.1's second rule needs, and only for as long as it
/// needs them.
///
/// One thread owning the whole set rather than a shared map: dialling a relay is
/// a TLS and ML-DSA-87 handshake, and the datapath thread that happened to send
/// the first packet to a peer must not be the thread that waits for it. Every
/// datagram arrives here already addressed to a relay — the engine decided that
/// — so all this does is find the connection or start one.
fn on_demand_hub<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    common: &'scope RelayCommon<'scope>,
    mut requests: tokio::sync::mpsc::Receiver<(RelayId, Relayed)>,
) {
    // A runtime only to wait on the queue: the connections themselves are
    // driven by their own threads and runtimes, so nothing here can be starved
    // by a slow relay.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!(
            "karstd: cannot start the on-demand relay runtime; peers on other relays will \
                   be unreachable"
        );
        return;
    };
    let mut open: crate::ondemand::Pool<tokio::sync::mpsc::Sender<Relayed>> =
        crate::ondemand::Pool::new(ON_DEMAND_IDLE_MS);
    let mut next_sweep = Instant::now() + TICK;

    while !common.shutdown.requested() {
        // On a timer rather than only when the queue goes quiet. A node with
        // one busy peer elsewhere and one that has gone silent must still close
        // the second connection, and a sweep that only ran between requests
        // would never reach it while the first peer keeps talking.
        if Instant::now() >= next_sweep {
            next_sweep = Instant::now() + TICK;
            // **The relay this node holds is never also in the pool.** A relay
            // measured as an alternative and then adopted as the home relay
            // would otherwise be reached by two connections at once, and a
            // relay replaces an older connection for the same node id with the
            // newer one — so the two would take turns, each killing the other,
            // losing whatever was in flight. That is how a fragmented message
            // loses its second fragment and a tunnel carries handshakes but no
            // data.
            if let Some(home) = common.engine.home_relay() {
                if open.close(home) {
                    eprintln!(
                        "karstd: letting go of the on-demand connection to the relay this \
                         node now holds"
                    );
                }
            }
            let closed = open.expire(now_ms(common.started));
            if closed > 0 {
                eprintln!("karstd: closed {closed} idle on-demand relay connection(s)");
            }
        }
        // **The timeout is built inside the runtime, not passed into it.**
        // `tokio::time::timeout` arms a timer as it is constructed, and doing
        // that on a plain thread panics with "there is no reactor running" —
        // which killed this thread the moment the daemon started and left every
        // peer on another relay unreachable, while every test of the pool
        // itself went on passing.
        let Ok(request) =
            runtime.block_on(async { tokio::time::timeout(TICK, requests.recv()).await })
        else {
            continue;
        };
        let Some((relay_id, item)) = request else {
            return;
        };
        // Anything addressed to the relay this node already holds goes on the
        // connection it already has, rather than opening a second one to the
        // same place. This is the same rule as the sweep above, applied to the
        // request that would otherwise create the duplicate.
        if common.engine.home_relay() == Some(relay_id) {
            match item {
                Relayed::Packet {
                    destination,
                    payload,
                } => common.relayed.send_via(None, destination, &payload),
                Relayed::Ping(token) => common.relayed.ping(None, token),
                // The connection was the request, and it exists.
                Relayed::Hold => {}
            }
            continue;
        }
        let now = now_ms(common.started);
        if open.route(relay_id, now).is_none() {
            // The registry is the only place a relay id becomes something
            // dialable. A peer publishing one this node does not have is
            // already filtered out when the roster is built, so reaching here
            // with an unknown id means the netmap changed underneath the packet
            // — drop it and let the next one be routed against the roster that
            // replaced it.
            let Some(relay) = common.engine.relay(relay_id) else {
                common.relayed.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // **Why, not just what.** All three of §9.1's on-demand reasons
            // share this queue, and "dialling a relay" without the reason is
            // the kind of line that looks like an explanation and answers
            // nothing — an operator reading it cannot tell a peer being
            // reached from a relay being measured.
            eprintln!(
                "karstd: dialling {} {}",
                relay.address,
                match item {
                    Relayed::Packet { .. } => "to reach a peer that published it as its home relay",
                    Relayed::Ping(_) => "to measure it against the relay this node holds",
                    Relayed::Hold => "to stay reachable there while peers learn this node moved",
                }
            );
            let (tx, rx) = tokio::sync::mpsc::channel(RELAY_QUEUE);
            let last = Arc::new(AtomicU64::new(now));
            let activity = Arc::clone(&last);
            scope.spawn(move || {
                relay_worker(
                    RelayContext {
                        common,
                        relay,
                        role: RelayRole::OnDemand { activity },
                    },
                    rx,
                );
            });
            open.insert(relay_id, tx, last);
        }
        let Some(queue) = open.route(relay_id, now) else {
            continue;
        };
        if queue.try_send(item).is_err() {
            common.relayed.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── TURN — `spec/aven-v1.md` §7.8 ───────────────────────────────────────────

/// How many operations may wait for the TURN worker.
///
/// `RELAY_QUEUE`'s reasoning, unchanged: this is a last-resort fallback path,
/// and an operation lost to a full queue costs a retry rather than
/// correctness — PHREATIC retransmits, and §7.8's priming rule fires again on
/// the next `CallMeMaybe`.
const TURN_QUEUE: usize = 256;

/// Whether `addr` is the kind of address a real TURN server, sitting on the
/// public internet, could plausibly have a route to at all.
///
/// Used only to filter §7.8's permission-priming targets before they reach a
/// real socket — see the call site in `turn_session`'s `TurnOp::Prime`
/// handling for why skipping these is not an optimization but a correctness
/// fix. Deliberately conservative (private, loopback, link-local, unique
/// local, unspecified, multicast, and IPv4 broadcast are all excluded): a
/// false negative here costs one un-primed candidate that was never going to
/// answer anyway, while a false positive risks the exact session-ending
/// server error this filter exists to avoid.
fn plausibly_reachable_via_turn(addr: std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast())
        }
        std::net::IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local, fc00::/7 — std's `is_unique_local` is not yet
                // stable.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local unicast, fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// One thing the TURN worker should do with its allocation.
#[derive(Debug)]
enum TurnOp {
    /// Send a datagram to a peer through the allocation — `Via::Turn`'s
    /// dispatch.
    Send {
        to: std::net::SocketAddr,
        payload: Vec<u8>,
    },
    /// Prime a permission for every named address — §7.8's one new protocol
    /// rule. Carries a whole `CallMeMaybe`'s worth of addresses so one
    /// advertisement costs one queue slot rather than up to sixteen.
    Prime(Vec<std::net::SocketAddr>),
}

/// The datapath's handle on the TURN worker.
///
/// `RelaySender`'s shape and the same reasoning: these calls happen on the
/// threads that carry the tunnel and AVEN's own timers, and must never block
/// on an allocation this node may not even hold.
#[derive(Debug)]
struct TurnSender {
    queue: tokio::sync::mpsc::Sender<TurnOp>,
    dropped: Arc<AtomicU64>,
}

impl TurnSender {
    /// Queue a datagram for `Via::Turn`'s dispatch.
    fn send_to(&self, to: std::net::SocketAddr, payload: &[u8]) {
        let queued = self
            .queue
            .try_send(TurnOp::Send {
                to,
                payload: payload.to_vec(),
            })
            .is_ok();
        if !queued {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queue §7.8's permission priming for every address a `CallMeMaybe` just
    /// named. A no-op when nothing was named, so a peer's advertisement with
    /// no TURN-relevant content — most of them, on a node with no TURN
    /// allocation at all — costs nothing here.
    fn prime(&self, addrs: Vec<std::net::SocketAddr>) {
        if addrs.is_empty() {
            return;
        }
        if self.queue.try_send(TurnOp::Prime(addrs)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Everything the TURN worker needs from the rest of the daemon.
///
/// `RelayCommon`'s shape, trimmed to what one unauthenticated-server
/// allocation needs: no home-relay selection and no on-demand pool, because
/// RFC 8656 has neither concept — a node holds at most one allocation, on the
/// first server the netmap names, for as long as it can reach it.
struct TurnCommon<'a> {
    shutdown: &'a Shutdown,
    disco: &'a Mutex<disco::Disco>,
    engine: &'a Engine,
    socket: &'a UdpTransport,
    tun: &'a NetworkDevice,
    /// Where a reply to a relay-delivered datagram would go if this worker's
    /// own inbound processing ever produced one — see `dispatch`'s own
    /// exhaustive `Via` match. In practice a datagram arriving through this
    /// node's own allocation only ever produces a `Via::Turn` reply, so this
    /// is here for the same reason `dispatch` takes it at every call site:
    /// completeness the compiler enforces rather than a case this path
    /// exercises.
    relayed: Option<&'a RelaySender>,
    /// This worker's own sender, so a reply this node's own inbound
    /// processing decides to send `Via::Turn` reaches the same allocation it
    /// arrived on rather than needing a second code path. `relay_worker`'s
    /// home connection does the identical thing with `RelayCommon::relayed`.
    turned: &'a TurnSender,
    started: Instant,
    /// See [`Reachability`]. Keyed by the server's URI.
    turn_health: &'a Mutex<HashMap<String, Reachability>>,
}

/// Reconnect delay floor for the TURN worker, shared with `sleep_backoff`'s
/// growth curve (`RELAY_BACKOFF_MIN`/`_MAX`) rather than duplicating it: this
/// is one more connection a node retries with exactly the same patience.
const TURN_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Hold this node's TURN allocation for the life of the daemon, reconnecting
/// with backoff, and feed the shared dispatch pipeline from its own read loop
/// — `spec/aven-v1.md` §7.8.
///
/// A dedicated current-thread runtime, mirroring `relay_worker`: this
/// allocation's control traffic and the datagrams it relays must not share a
/// thread with the shared UDP socket's own reads, or a slow TURN server would
/// add its latency to every packet on the direct path too.
fn turn_worker(common: &TurnCommon<'_>, mut ops: tokio::sync::mpsc::Receiver<TurnOp>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("karstd: cannot start the turn runtime; the turn fallback is disabled");
        return;
    };
    let mut backoff = TURN_BACKOFF_MIN;

    while !common.shutdown.requested() {
        // Read fresh on every (re)connect attempt, never cached separately —
        // `Engine::turn_servers`'s own doc comment is why: a credential is
        // never staler than the netmap already is, because this is the same
        // registry `refresh_netmap` replaces wholesale on every poll.
        let Some(server) = common.engine.turn_servers().into_iter().next() else {
            sleep_backoff(common.shutdown, &mut backoff);
            continue;
        };
        let connected = runtime.block_on(crate::turn::Allocation::connect(&server));
        let allocation = match connected {
            Ok(a) => a,
            Err(e) => {
                Reachability::record(common.turn_health, &server.uri, false);
                // Once per outage, not once per attempt — `relay_worker`'s own
                // argument for the identical line.
                if backoff == TURN_BACKOFF_MIN {
                    eprintln!(
                        "karstd: cannot reach turn server {} ({e}); retrying",
                        server.uri
                    );
                }
                sleep_backoff(common.shutdown, &mut backoff);
                continue;
            }
        };
        Reachability::record(common.turn_health, &server.uri, true);
        if backoff != TURN_BACKOFF_MIN {
            eprintln!("karstd: turn server {} reachable again", server.uri);
        }
        backoff = TURN_BACKOFF_MIN;

        let relayed_addr = allocation.relayed_addr();
        eprintln!(
            "karstd: turn allocation on {} is {relayed_addr}",
            server.uri
        );
        common.engine.set_turn_relay(Some(relayed_addr));
        common
            .disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_turn_candidate(Some(relayed_addr));

        runtime.block_on(turn_session(common, &allocation, &mut ops));
        runtime.block_on(allocation.close());

        // The allocation is gone — withdraw the candidate and the fallback
        // both, so neither AVEN nor `Engine::via` goes on offering an address
        // nothing is listening on any more.
        common.engine.set_turn_relay(None);
        common
            .disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_turn_candidate(None);
    }
}

/// Drive one allocation until it fails, the daemon shuts down, or the netmap
/// stops naming any TURN server at all.
async fn turn_session(
    common: &TurnCommon<'_>,
    allocation: &crate::turn::Allocation,
    ops: &mut tokio::sync::mpsc::Receiver<TurnOp>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if common.shutdown.requested() {
            return;
        }
        // The netmap withdrew every TURN server. Tearing this allocation down
        // rather than holding it open is what keeps `Engine::turn_servers`
        // meaning "what this node should be doing" rather than merely "what
        // it once was told" — the same reason `moved_home` acts on a relay
        // registry change instead of only a fresh dial.
        if common.engine.turn_servers().is_empty() {
            return;
        }
        let received = tokio::time::timeout(TICK, async {
            tokio::select! {
                op = ops.recv() => Ok(op),
                read = allocation.recv_from(&mut buf) => Err(read),
            }
        })
        .await;
        // A timeout is normal — it is what lets this loop notice a shutdown
        // or a withdrawn registry on an otherwise quiet allocation.
        let Ok(branch) = received else {
            continue;
        };
        match branch {
            Ok(op) => {
                let Some(op) = op else {
                    // The sender half is gone, which happens only at process
                    // teardown — nothing left to serve.
                    return;
                };
                match op {
                    TurnOp::Send { to, payload } => {
                        if let Err(e) = allocation.send_to(&payload, to).await {
                            eprintln!(
                                "karstd: turn send to {to} failed ({e}); rebuilding the allocation"
                            );
                            return;
                        }
                    }
                    TurnOp::Prime(addrs) => {
                        for addr in addrs {
                            // **Never toward an address a real TURN server has
                            // no route to.** §7.2's interface tier puts a
                            // node's private/RFC 1918 addresses in every
                            // `CallMeMaybe` right alongside the ones that
                            // matter, and §7.8's priming rule primes every
                            // address unconditionally — correctly, for
                            // `disco.rs`'s own sans-io purposes. But this is
                            // the boundary where that rule meets a real
                            // socket, and priming toward one is not merely
                            // wasted: confirmed against a real `coturn` while
                            // wiring this up, asking it to relay a Send
                            // indication toward an unroutable private address
                            // tears down the *entire* session — every
                            // permission this allocation holds, not just the
                            // one doomed destination — with "udp send: Network
                            // is unreachable". `plausibly_reachable_via_turn`
                            // is the filter that keeps priming from ever
                            // trying.
                            if !plausibly_reachable_via_turn(addr) {
                                continue;
                            }
                            // A harmless one-byte payload. This is what both
                            // creates the RFC 8656 permission (the crate's
                            // `RelayConn::send_to` does that on any first send
                            // to a new address — see this module's own doc
                            // comment) and, on arrival, is silently dropped by
                            // whichever protocol receives it: it matches
                            // neither AVEN's four-byte magic nor a PHREATIC
                            // fragment header, so `spec/aven-v1.md` §10 and
                            // `phreatic-v1.md`'s own malformed-input handling
                            // both discard it without a log line.
                            let _ = allocation.send_to(&[0u8], addr).await;
                        }
                    }
                }
            }
            Err(Ok((n, from))) => {
                let Some(datagram) = buf.get(..n) else {
                    continue;
                };
                let now = now_ms(common.started);
                let out = demultiplex_via_turn(datagram, from, now, common.disco, common.engine);
                dispatch(
                    out,
                    common.socket,
                    common.tun,
                    common.relayed,
                    Some(common.turned),
                );
            }
            Err(Err(e)) => {
                eprintln!("karstd: turn allocation on this node failed ({e}); rebuilding it");
                return;
            }
        }
    }
}

/// Like [`demultiplex`], for a datagram that arrived through this node's own
/// TURN allocation rather than the shared UDP socket — `spec/aven-v1.md` §7.8.
///
/// **Every reply `demultiplex`'s ordinary tagging produces answers the exact
/// address the request arrived from** — a `Pong` answers the address a `Ping`
/// came from, a handshake response answers the address its `HandshakeInit`
/// came from, and neither AVEN nor PHREATIC ever redirects a reply elsewhere.
/// So the one thing this needs to change is *how* such a reply leaves this
/// node: through the allocation it arrived on, because the shared socket
/// cannot reach a peer that could only be reached this way in the first
/// place. Rather than threading a second, TURN-aware reply path through
/// `karst_node::Session` and `karst_disco::Engine` — which would duplicate
/// `Engine::inbound`'s handshake and cookie logic a third time, beside
/// `inbound` and `inbound_from_relay` — this reuses `demultiplex` unchanged
/// and rewrites the one `Via` value the rewrite rule above guarantees is safe
/// to rewrite.
fn demultiplex_via_turn(
    datagram: &[u8],
    from: std::net::SocketAddr,
    now_ms: u64,
    disco: &Mutex<disco::Disco>,
    engine: &Engine,
) -> Output {
    let mut out = demultiplex(datagram, from, now_ms, disco, engine);
    for (_, via) in &mut out.datagrams {
        if *via == Via::Direct(from) {
            *via = Via::Turn(from);
        }
    }
    out
}

/// Prime a permission on this node's own TURN allocation for every address a
/// peer's `CallMeMaybe` has named since this was last asked — §7.8's one new
/// protocol rule.
fn prime_turn_permissions(disco: &Mutex<disco::Disco>, turn: Option<&TurnSender>) {
    let Some(turn) = turn else {
        return;
    };
    let addrs = disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take_turn_primes();
    turn.prime(addrs);
}

#[cfg(test)]
mod turn_tests {
    use super::plausibly_reachable_via_turn;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([a, b, c, d], 51820))
    }

    fn v6(a: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from((std::net::Ipv6Addr::new(a, 0, 0, 0, 0, 0, 0, 1), 51820))
    }

    /// The exact regression this filter exists for: a real `coturn` tore
    /// down the whole allocation, not merely refused the one send, when
    /// asked to prime a permission toward a private candidate address —
    /// `spec/aven-v1.md` §7.2's interface tier puts one in every
    /// `CallMeMaybe` a node with a private address sends.
    #[test]
    fn private_v4_is_refused() {
        assert!(!plausibly_reachable_via_turn(v4(10, 98, 1, 2)));
        assert!(!plausibly_reachable_via_turn(v4(192, 168, 1, 1)));
        assert!(!plausibly_reachable_via_turn(v4(172, 16, 0, 1)));
    }

    #[test]
    fn loopback_link_local_and_unspecified_v4_are_refused() {
        assert!(!plausibly_reachable_via_turn(v4(127, 0, 0, 1)));
        assert!(!plausibly_reachable_via_turn(v4(169, 254, 1, 1)));
        assert!(!plausibly_reachable_via_turn(v4(0, 0, 0, 0)));
        assert!(!plausibly_reachable_via_turn(v4(255, 255, 255, 255)));
        assert!(!plausibly_reachable_via_turn(v4(224, 0, 0, 1)));
    }

    /// A reflexive or TURN-relayed address — exactly what priming exists to
    /// reach — must not be caught by the same filter.
    #[test]
    fn a_public_v4_address_is_accepted() {
        assert!(plausibly_reachable_via_turn(v4(51, 75, 10, 2)));
    }

    #[test]
    fn unique_local_link_local_loopback_and_unspecified_v6_are_refused() {
        assert!(!plausibly_reachable_via_turn(v6(0xfc00)));
        assert!(!plausibly_reachable_via_turn(v6(0xfd12)));
        assert!(!plausibly_reachable_via_turn(v6(0xfe80)));
        assert!(!plausibly_reachable_via_turn(std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            51820
        ))));
        assert!(!plausibly_reachable_via_turn(std::net::SocketAddr::from((
            std::net::Ipv6Addr::UNSPECIFIED,
            51820
        ))));
    }

    #[test]
    fn a_global_v6_address_is_accepted() {
        assert!(plausibly_reachable_via_turn(v6(0x2001)));
    }
}

/// Apply only AVEN-confirmed paths to the PHREATIC roster. Candidates never
/// reach this boundary, so an unauthenticated endpoint cannot redirect data.
fn apply_disco_paths(disco: &Mutex<disco::Disco>, engine: &Engine) -> bool {
    let changes = disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .path_changes();
    let changed = !changes.is_empty();
    apply_path_changes(&changes, engine);
    changed
}

/// Perform the endpoint changes discovery asked for.
///
/// The two directions are not symmetric. An install displaces whatever was
/// there, because a confirmed direct path is better evidence than an address
/// learned from a handshake. A release is conditional on the installed address
/// still being in force, because a peer that rehandshakes teaches the datapath
/// its own endpoint, and discovery giving up is no reason to throw that away.
fn apply_path_changes(changes: &[disco::PathChange], engine: &Engine) {
    for change in changes {
        match *change {
            disco::PathChange::Install { peer, endpoint } => {
                let _ = engine.set_endpoint(peer, endpoint);
            }
            disco::PathChange::Release { peer, installed } => {
                let _ = engine.release_endpoint(peer, installed);
            }
        }
    }
}

/// Update the installed routes, recovering from a poisoned lock.
///
/// A poisoned lock means a thread panicked while holding it; the tracked set is
/// plain data rather than a half-written buffer, so continuing with it beats
/// taking the tunnel down for every peer.
fn apply_routes(
    routes: &Mutex<Routes>,
    tun: &NetworkDevice,
    config: &Config,
    selected_exit: Option<&str>,
) {
    routes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .apply(tun, config, selected_exit);
}

/// Apply gateway state fail-closed and retain the last readiness error for
/// status and diagnostics.
fn apply_gateway(
    gateway: &Mutex<crate::gateway::Manager>,
    status: &Mutex<Option<String>>,
    config: &Config,
) {
    let result = gateway
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reconcile(config);
    let error = match result {
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "gateway forwarding is not ready");
            Some(error.to_string())
        }
    };
    *status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = error;
}

fn underlay_addresses(
    config: &Config,
    engine: Option<&Engine>,
    control_endpoint: Option<&str>,
) -> io::Result<BTreeSet<IpAddr>> {
    let mut out = BTreeSet::new();
    for peer in &config.peers {
        if let Some(endpoint) = peer.endpoint {
            out.insert(endpoint.ip());
        }
    }
    if let Some(engine) = engine {
        for peer in engine.status() {
            if let Some(endpoint) = peer.endpoint {
                out.insert(endpoint.ip());
            }
        }
    }
    for relay in &config.relays {
        resolve_socket_name(&relay.address, &mut out)?;
    }
    if let Some(endpoint) = control_endpoint {
        let (host, port) = url_authority(endpoint)?;
        resolve_host_port(host, port, &mut out)?;
    }
    Ok(out)
}

fn resolve_socket_name(value: &str, out: &mut BTreeSet<IpAddr>) -> io::Result<()> {
    if let Ok(endpoint) = value.parse::<std::net::SocketAddr>() {
        out.insert(endpoint.ip());
        return Ok(());
    }
    let resolved: Vec<_> = value.to_socket_addrs()?.collect();
    if resolved.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("underlay endpoint {value:?} resolved to no addresses"),
        ));
    }
    out.extend(resolved.into_iter().map(|endpoint| endpoint.ip()));
    Ok(())
}

fn resolve_host_port(host: &str, port: u16, out: &mut BTreeSet<IpAddr>) -> io::Result<()> {
    if let Ok(address) = host.parse::<IpAddr>() {
        out.insert(address);
        return Ok(());
    }
    let resolved: Vec<_> = (host, port).to_socket_addrs()?.collect();
    if resolved.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("underlay host {host:?} resolved to no addresses"),
        ));
    }
    out.extend(resolved.into_iter().map(|endpoint| endpoint.ip()));
    Ok(())
}

fn url_authority(endpoint: &str) -> io::Result<(&str, u16)> {
    let (_, rest) = endpoint.split_once("://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "control endpoint has no URL scheme",
        )
    })?;
    let authority = rest.split('/').next().unwrap_or_default();
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, tail) = bracketed.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "control endpoint has invalid IPv6 authority",
            )
        })?;
        let port = tail.strip_prefix(':').map_or(Ok(443), |value| {
            value
                .parse::<u16>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })?;
        return Ok((host, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        ),
        _ => (authority, 443),
    };
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control endpoint has no host",
        ));
    }
    Ok((host, port))
}

fn reconcile_exit(
    routes: &Mutex<Routes>,
    policy: &Mutex<crate::exit_policy::Manager>,
    tun: &NetworkDevice,
    config: &Config,
    engine: Option<&Engine>,
    control_endpoint: Option<&str>,
    selected: Option<&str>,
) -> io::Result<()> {
    if tun.userspace().is_some() {
        policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disable();
        apply_routes(routes, tun, config, selected);
        return Ok(());
    }

    // Main-table routes never include /0 on a kernel TUN. Subnets are applied
    // normally; the selected default is owned by the dedicated policy manager.
    apply_routes(routes, tun, config, None);
    let offer = selected.and_then(|route_id| {
        config.route_offers.iter().find(|offer| {
            offer.route_id == route_id
                && offer.kind == crate::route_offer::Kind::Exit
                && offer.role == crate::route_offer::Role::Recipient
        })
    });
    let mut policy = policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(offer) = offer else {
        policy.disable();
        return Ok(());
    };
    let escapes = underlay_addresses(config, engine, control_endpoint)?;
    policy.activate(tun.name(), offer.prefix.base(), escapes)
}

/// Handle the three local-consent commands against the current authenticated
/// netmap. The server can offer an exit, but only this state transition can
/// install its kernel route.
#[allow(clippy::too_many_arguments)]
fn exit_node_command(
    command: &ipc::Command,
    selection: Option<&Mutex<crate::exit_node::Selection>>,
    config: &Config,
    routes: &Mutex<Routes>,
    policy: &Mutex<crate::exit_policy::Manager>,
    tun: &NetworkDevice,
    engine: &Engine,
    control_endpoint: Option<&str>,
) -> String {
    use std::fmt::Write as _;

    let eligible = |offer: &&crate::route_offer::Offer| {
        offer.kind == crate::route_offer::Kind::Exit
            && offer.role == crate::route_offer::Role::Recipient
    };
    match command {
        ipc::Command::ExitList => {
            let selected = selection.and_then(|state| {
                state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .active()
                    .map(str::to_owned)
            });
            let installed = tun.userspace().is_some()
                || policy
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .active();
            let mut out = String::new();
            let _ = writeln!(out, "selected = {selected:?}");
            for offer in config.route_offers.iter().filter(eligible) {
                let active = installed && selected.as_deref() == Some(offer.route_id.as_str());
                let _ = writeln!(out, "[[offers]]");
                let _ = writeln!(out, "route_id = {:?}", offer.route_id);
                let _ = writeln!(out, "prefix = {:?}", offer.prefix.to_string());
                let _ = writeln!(out, "metric = {}", offer.metric);
                let _ = writeln!(out, "active = {active}");
            }
            out
        }
        ipc::Command::ExitUse(route_id) => {
            if !config
                .route_offers
                .iter()
                .filter(eligible)
                .any(|offer| offer.route_id == *route_id)
            {
                return format!("error = {:?}\n", "unknown or ineligible exit route");
            }
            let Some(selection) = selection else {
                return format!("error = {:?}\n", "exit-node consent is unavailable");
            };
            let mut state = selection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = state.select(route_id) {
                return format!("error = {:?}\n", error.to_string());
            }
            if let Err(error) = reconcile_exit(
                routes,
                policy,
                tun,
                config,
                Some(engine),
                control_endpoint,
                Some(route_id),
            ) {
                return format!("error = {:?}\n", error.to_string());
            }
            format!("selected = {route_id:?}\n")
        }
        ipc::Command::ExitDisable => {
            let Some(selection) = selection else {
                return format!("error = {:?}\n", "exit-node consent is unavailable");
            };
            let mut state = selection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = state.disable() {
                return format!("error = {:?}\n", error.to_string());
            }
            if let Err(error) = reconcile_exit(
                routes,
                policy,
                tun,
                config,
                Some(engine),
                control_endpoint,
                None,
            ) {
                return format!("error = {:?}\n", error.to_string());
            }
            "selected = None\n".to_owned()
        }
        _ => unreachable!("only exit-node commands reach this handler"),
    }
}

/// The routes this node has installed, so a reconfiguration can diff them.
///
/// Tracked rather than recomputed from the kernel: reading the table back would
/// mean parsing `/proc` or speaking netlink in the other direction, and it
/// would also pick up routes somebody else installed — which are not ours to
/// remove.
#[derive(Debug, Default)]
struct Routes(std::collections::BTreeSet<(std::net::IpAddr, u8)>);

impl Routes {
    /// Which prefixes a configuration needs routed over the tunnel.
    ///
    /// A prefix already inside an interface address's on-link network is
    /// skipped: the kernel routes it for free from the address alone, and
    /// installing a second, identical route would be noise in `ip route` for no
    /// effect.
    fn wanted(
        config: &Config,
        selected_exit: Option<&str>,
    ) -> std::collections::BTreeSet<(std::net::IpAddr, u8)> {
        // A prefix this node itself gateways is never routed over its own
        // tunnel — it is reachable through the gateway's own local network
        // instead, and that route is not karstd's to manage.
        //
        // Checked against `route_offers` directly, not merely by the absence
        // of the prefix from a peer's `allowed_ips`: a role transition (this
        // node was a plain recipient of the prefix, pointed at a *different*
        // gateway, until an HA failover just made it the gateway itself)
        // leaves a stale `(prefix, some-other-peer)` entry installed for up
        // to one more reconciliation cycle after the netmap already agrees
        // this node is now the gateway. Withdrawing that stale entry only
        // undoes what karstd itself added — it cannot know to restore a
        // kernel route it never owned, such as the gateway's own connected
        // route to its local LAN, so the prefix must never be added here in
        // the first place once this node is the gateway for it.
        let gatewayed: std::collections::BTreeSet<(std::net::IpAddr, u8)> = config
            .route_offers
            .iter()
            .filter(|offer| offer.role == crate::route_offer::Role::Gateway)
            .map(|offer| (offer.prefix.base(), offer.prefix.len()))
            .collect();
        let mut out = std::collections::BTreeSet::new();
        for peer in &config.peers {
            for range in &peer.allowed_ips {
                // A default cryptokey route identifies an exit gateway. Kernel
                // routing is a separate, locally consented decision below.
                if range.len() == 0 {
                    continue;
                }
                if gatewayed.contains(&(range.base(), range.len())) {
                    continue;
                }
                let on_link = config
                    .addresses
                    .iter()
                    .any(|a| a.network().contains(range.base()));
                if !on_link {
                    out.insert((range.base(), range.len()));
                }
            }
        }
        if let Some(selected) = selected_exit {
            if let Some(offer) = config.route_offers.iter().find(|offer| {
                offer.route_id == selected
                    && offer.kind == crate::route_offer::Kind::Exit
                    && offer.role == crate::route_offer::Role::Recipient
            }) {
                out.insert((offer.prefix.base(), offer.prefix.len()));
            }
        }
        out
    }

    /// Install what is missing and withdraw what is no longer wanted.
    ///
    /// Failures are reported and skipped rather than fatal. A route that cannot
    /// be installed costs reachability to one peer; giving up would cost the
    /// whole tunnel, and the node is already carrying traffic for everybody
    /// else by the time this runs.
    fn apply(&mut self, tun: &NetworkDevice, config: &Config, selected_exit: Option<&str>) {
        let wanted = Self::wanted(config, selected_exit);

        for (dst, len) in self.0.difference(&wanted) {
            match tun.remove_route(*dst, *len) {
                Ok(()) => {}
                Err(e) => tracing::warn!(%dst, len, error = %e, "could not withdraw route"),
            }
        }
        let mut installed = std::collections::BTreeSet::new();
        for (dst, len) in &wanted {
            match tun.add_route(*dst, *len) {
                Ok(()) => {
                    installed.insert((*dst, *len));
                }
                Err(e) => tracing::warn!(
                    %dst, len, error = %e,
                    "could not route over the tunnel; that peer will be unreachable"
                ),
            }
        }
        self.0 = installed;
    }
}

/// Create the TUN device and give it its addresses.
/// The running kernel's release string, for `karst status`.
///
/// Not sensitive, and it explains an offload, netlink or `utun` difference
/// better than any amount of guessing — which is exactly what a bug report from
/// a platform the maintainers do not run needs to carry.
#[cfg(target_os = "linux")]
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| "unknown".to_owned(), |s| s.trim().to_owned())
}

/// As above, where there is no `/proc`. `uname(1)` is POSIX and this runs once
/// per status request.
#[cfg(not(target_os = "linux"))]
fn kernel_release() -> String {
    std::process::Command::new("/usr/bin/uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|release| !release.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn bring_up_interface(config: &Config) -> io::Result<NetworkDevice> {
    let attachment = TunConfig {
        name: config.interface.clone(),
        // Segmentation offload, if the kernel offers it. One read can then
        // return a coalesced TCP stream instead of a single packet, which is
        // the syscall the datapath was bound by (PLAN.md §3.4).
        offload: true,
        ..TunConfig::default()
    };
    let tun = match config.network_mode {
        crate::config::NetworkMode::Tun => Tun::create(&attachment)
            .map(NetworkDevice::Tun)
            .map_err(|e| io::Error::other(e.to_string()))?,
        crate::config::NetworkMode::Userspace => Userspace::create(&attachment)
            .map(NetworkDevice::Userspace)
            .map_err(|e| io::Error::other(e.to_string()))?,
    };

    for addr in &config.addresses {
        // `addr.addr`, not the network: assigning the masked base would leave
        // the node without an address of its own.
        tun.set_address(addr.addr, addr.prefix_len)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    // The stub is a local service address, not a peer allocation. The control
    // allocator reserves its containing /16, so adding this host route cannot
    // shadow a mesh node. Keep it on the kernel TUN; userspace attachment owns
    // its own sockets and must not claim a host address.
    //
    // **`add_secondary_address`, not `set_address`.** `set_address` assigns
    // through `SIOCSIFADDR`, which *replaces* an interface's address — calling
    // it again here for the stub would silently discard the overlay address
    // just assigned above, leaving the node holding only the DNS stub and
    // unreachable as a mesh peer. `add_secondary_address` uses the additive
    // `RTM_NEWADDR` netlink path instead, so both addresses coexist.
    if let NetworkDevice::Tun(inner) = &tun {
        if config.dns.enabled
            && config.netmap_dns.magic_dns
            && config.dns.stub_address.ip() == karst_dns::STUB_ADDRESS
        {
            inner
                .add_secondary_address(karst_dns::STUB_ADDRESS, 32)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
    }
    Ok(tun)
}

/// Stop the process, having been asked to.
///
/// **This exits rather than unwinding**, and the reason is worth stating.
/// The TUN reader is blocked in `read(2)` on a character device. There is no
/// safe way to wake it: a read timeout is not available on a TUN fd, and
/// `poll(2)` needs FFI, which ADR-0003 confines to `karst-tun`. Polling a
/// non-blocking device on a timer would work, but at the cost of adding that
/// timer's latency to every packet on the datapath — paying a permanent
/// throughput penalty to make one administrative command tidier.
///
/// Exiting is also *correct* rather than merely expedient: the interface is not
/// persistent, so the kernel removes it when this process's descriptor closes,
/// which happens on any exit. The only thing that would otherwise be left
/// behind is the socket file, removed here first.
fn stop(socket_path: &std::path::Path) -> ! {
    let _ = std::fs::remove_file(socket_path);
    std::process::exit(0)
}

/// Render a reply to a control command.
///
/// TOML, because the daemon already depends on a TOML parser and because a
/// human reading `karst status` output and a script parsing it should be
/// looking at the same bytes.
/// The `karst status` body, for tests that need to scan it.
#[must_use]
pub fn status_report(
    config: &Config,
    engine: &Engine,
    device: Attachment<'_>,
    uptime_secs: u64,
) -> String {
    let _ = uptime_secs;
    report(
        &ipc::Command::Status,
        config,
        engine,
        device,
        Instant::now(),
        &AtomicU64::new(0),
        Some(portmap::Snapshot::new(config.port_mapping)),
        BugReportExtras::default(),
    )
}

/// The `karst bugreport` body, for the leak scan.
///
/// Exported rather than reachable only over the control socket, because the
/// scan that proves it carries no key material must be able to render it
/// without standing up a daemon — and a check that is awkward to run is one
/// that stops being run.
#[must_use]
pub fn bug_report_for_test(
    config: &Config,
    engine: &Engine,
    device: Attachment<'_>,
    uptime_secs: u64,
) -> String {
    let _ = uptime_secs;
    bug_report(
        config,
        engine,
        device,
        Instant::now(),
        &AtomicU64::new(0),
        BugReportExtras::default(),
    )
}

/// The live packet device, as reporting sees it.
///
/// Name and MTU travel together because both belong to the **device** rather
/// than to the configuration, and userspace mode is where that stops being a
/// pedantic distinction: it creates no host interface at all, so reporting
/// `config.interface` sends an operator to look at an `ip link` entry that does
/// not exist — and makes the two modes indistinguishable in precisely the
/// output that exists to tell them apart.
#[derive(Debug, Clone, Copy)]
pub struct Attachment<'a> {
    /// The device's own name: a TUN interface, or `"userspace"`.
    pub name: &'a str,
    /// The tunnel MTU. §13.6 requires it be reportable, because a path that
    /// black-holes full-size packets is otherwise very hard to diagnose.
    pub mtu: usize,
    /// TCP sockets the userspace stack is holding, or `None` in TUN mode where
    /// the kernel owns them.
    ///
    /// Reported because in userspace mode the daemon *is* the TCP stack, so a
    /// number that only ever rises is the visible form of GitHub issue [#49](https://github.com/karst-net/karst/issues/49) — and
    /// nothing else in the status output would show it.
    pub sockets: Option<usize>,
    /// Datagrams refused because their destination is in an address family
    /// this datapath socket cannot reach, and whether that is possible at all.
    ///
    /// `None` on a dual-stack socket, where the question does not arise.
    /// `Some(n)` on an `AF_INET` one, where every IPv6 candidate is
    /// unreachable and *nothing else in the daemon says so* — the send paths
    /// drop errors on purpose, so the symptom is silence. GitHub issue [#56](https://github.com/karst-net/karst/issues/56).
    pub unreachable_family: Option<u64>,
}

/// Render `Engine::Stats` and route/gateway state as Prometheus text —
/// `Command::Metrics`'s payload (plans/phase-6/08-observability.md §3.1,
/// §5 W6 item 1).
///
/// Field names are `bug_report`'s `[stats]` section translated to
/// `karst_<field>`, not reinvented, so a support engineer reading both a
/// bugreport and a metrics dump recognizes the same numbers.
#[allow(clippy::too_many_lines)]
fn metrics_report(
    stats: &crate::engine::Stats,
    relay_dropped: u64,
    route_offers: usize,
    gateway_active: bool,
    exit_route_active: bool,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let counters: &[(&str, &str, u64)] = &[
        (
            "karst_tx_packets",
            "Packets encrypted and sent.",
            stats.tx_packets,
        ),
        (
            "karst_rx_packets",
            "Packets decrypted and delivered to the host.",
            stats.rx_packets,
        ),
        (
            "karst_unroutable",
            "Packets from the host with no peer owning the destination.",
            stats.unroutable,
        ),
        (
            "karst_source_violations",
            "Packets from a peer claiming a source address it does not own.",
            stats.source_violations,
        ),
        (
            "karst_mac_failures",
            "Datagrams discarded by the fragment MAC before any state was touched.",
            stats.mac_failures,
        ),
        (
            "karst_cookie_replies_issued",
            "CookieReply datagrams sent under load — §9.1's load-shedding path.",
            stats.cookie_replies_issued,
        ),
        (
            "karst_tx_dropped_no_session",
            "Packets dropped because no session was established yet.",
            stats.tx_dropped_no_session,
        ),
        (
            "karst_decrypt_failures",
            "Authenticated-decryption failures on inbound transport data.",
            stats.decrypt_failures,
        ),
        (
            "karst_malformed",
            "Inbound datagrams that could not even be parsed as a fragment.",
            stats.malformed,
        ),
        (
            "karst_bedrock_head_agreed",
            "Peer head claims that agreed with this node's verified Bedrock chain.",
            stats.bedrock_head_agreed,
        ),
        (
            "karst_bedrock_equivocation",
            "Peer head claims that diverged from this node's verified Bedrock chain \
             — any value above zero is an incident.",
            stats.bedrock_equivocation,
        ),
        (
            "karst_acl_denied_in",
            "Authenticated packets from a peer that the ACL refused.",
            stats.acl_denied_in,
        ),
        (
            "karst_acl_denied_out",
            "Packets from the host the ACL refused to send.",
            stats.acl_denied_out,
        ),
        (
            "karst_acl_unclassifiable",
            "Packets denied because their ports could not be established at all.",
            stats.acl_unclassifiable,
        ),
        (
            "karst_relay_dropped",
            "Packets dropped by the bounded queue to the relay worker.",
            relay_dropped,
        ),
    ];
    for (name, help, value) in counters {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        let _ = writeln!(out, "{name} {value}");
    }

    let gauges: &[(&str, &str, u64)] = &[
        (
            "karst_route_offers",
            "Route offers this node's netmap currently carries.",
            route_offers as u64,
        ),
        (
            "karst_gateway_active",
            "Whether this node is currently forwarding as a subnet/exit gateway.",
            u64::from(gateway_active),
        ),
        (
            "karst_exit_route_active",
            "Whether an exit-route offer is currently selected and installed.",
            u64::from(exit_route_active),
        ),
    ];
    for (name, help, value) in gauges {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {value}");
    }

    out
}

#[cfg(test)]
mod metrics_report_tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::metrics_report;
    use crate::engine::Stats;

    /// Every counter and gauge appears with its own `# HELP`/`# TYPE`
    /// preamble and the right value — the shape a Prometheus scraper
    /// requires, and the property `tests/leakscan.rs`'s denylist test
    /// depends on finding real `karst_*` lines to check in the first place.
    #[test]
    fn every_field_gets_help_type_and_value() {
        let stats = Stats {
            tx_packets: 11,
            rx_packets: 22,
            bedrock_equivocation: 3,
            ..Stats::default()
        };
        let out = metrics_report(&stats, 7, 2, true, false);

        assert!(out.contains("# TYPE karst_tx_packets counter"));
        assert!(out.contains("karst_tx_packets 11"));
        assert!(out.contains("karst_rx_packets 22"));
        assert!(out.contains("karst_bedrock_equivocation 3"));
        assert!(out.contains("karst_relay_dropped 7"));
        assert!(out.contains("# TYPE karst_route_offers gauge"));
        assert!(out.contains("karst_route_offers 2"));
        assert!(
            out.contains("karst_gateway_active 1"),
            "gateway_active=true must render as 1, not the word true"
        );
        assert!(out.contains("karst_exit_route_active 0"));
    }

    /// `# HELP`/`# TYPE` lines outnumber value lines only by their own count
    /// — i.e. every metric name appears exactly three times (HELP, TYPE,
    /// value), never a stray duplicate from copy-pasting the tuple table.
    #[test]
    fn no_metric_name_is_duplicated() {
        let out = metrics_report(&Stats::default(), 0, 0, false, false);
        for line in out.lines().filter(|l| l.starts_with("# TYPE ")) {
            let name = line
                .strip_prefix("# TYPE ")
                .and_then(|rest| rest.split(' ').next())
                .expect("TYPE line has a name");
            let occurrences = out.matches(name).count();
            assert_eq!(
                occurrences, 3,
                "{name} appears {occurrences} times, want 3 (HELP, TYPE, value)"
            );
        }
    }
}

/// The selected exit route, but only if it is still a real `Exit`/`Recipient`
/// offer in `config` *and* actually installed — the same three-way check
/// `routing_report`'s `[routing]` section and `metrics_report`'s
/// `karst_exit_route_active` gauge must agree on, so a stale selection
/// left over from a netmap that no longer offers it does not read as active
/// in one report and inactive in the other.
fn active_exit_route<'a>(
    config: &Config,
    selected_exit: Option<&'a str>,
    exit_route_installed: bool,
) -> Option<&'a str> {
    selected_exit
        .filter(|selected| {
            config.route_offers.iter().any(|offer| {
                offer.route_id == **selected
                    && offer.kind == crate::route_offer::Kind::Exit
                    && offer.role == crate::route_offer::Role::Recipient
            })
        })
        .filter(|_| exit_route_installed)
}

fn routing_report(
    config: &Config,
    selected_exit: Option<&str>,
    exit_route_installed: bool,
    gateway_active: bool,
    gateway_error: Option<&str>,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let active_exit = active_exit_route(config, selected_exit, exit_route_installed);
    let _ = writeln!(out, "\n[routing]");
    let _ = writeln!(out, "offers = {}", config.route_offers.len());
    let _ = writeln!(out, "selected_exit = {selected_exit:?}");
    let _ = writeln!(out, "exit_route_active = {}", active_exit.is_some());
    let _ = writeln!(out, "gateway_active = {gateway_active}");
    let _ = writeln!(out, "gateway_error = {gateway_error:?}");

    for offer in &config.route_offers {
        let kind = match offer.kind {
            crate::route_offer::Kind::Subnet => "subnet",
            crate::route_offer::Kind::Exit => "exit",
        };
        let role = match offer.role {
            crate::route_offer::Role::Recipient => "recipient",
            crate::route_offer::Role::Gateway => "gateway",
        };
        let active = role == "gateway" && gateway_active
            || kind == "exit"
                && role == "recipient"
                && active_exit == Some(offer.route_id.as_str());
        let _ = writeln!(out, "\n[[route]]");
        let _ = writeln!(out, "route_id = {:?}", offer.route_id);
        let _ = writeln!(out, "prefix = {:?}", offer.prefix.to_string());
        let _ = writeln!(out, "kind = {kind:?}");
        let _ = writeln!(out, "role = {role:?}");
        let _ = writeln!(out, "metric = {}", offer.metric);
        let _ = writeln!(out, "masquerade = {}", offer.masquerade);
        let _ = writeln!(out, "keep_route = {}", offer.keep_route);
        let _ = writeln!(out, "active = {active}");
    }
    out
}

/// Data only `Command::BugReport` needs, bundled so `report`'s own signature
/// does not keep growing one positional argument per new bugreport section —
/// `Status` and every other command ignore this entirely.
#[derive(Default)]
struct BugReportExtras {
    since_last_push: Option<Duration>,
    /// See [`Reachability`]. A snapshot (not the live `Mutex`) taken once at
    /// the point a report is requested, so rendering it never holds a lock a
    /// relay/TURN worker might also want.
    relay_health: Vec<(String, Reachability)>,
    turn_health: Vec<(String, Reachability)>,
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn report(
    command: &ipc::Command,
    config: &Config,
    engine: &Engine,
    device: Attachment<'_>,
    started: Instant,
    relay_dropped: &AtomicU64,
    portmap: Option<portmap::Snapshot>,
    bug_report_extras: BugReportExtras,
) -> String {
    use std::fmt::Write as _;

    match command {
        ipc::Command::Version => format!("version = \"{}\"\n", env!("CARGO_PKG_VERSION")),
        ipc::Command::Down => "stopping = true\n".to_owned(),
        ipc::Command::BugReport => bug_report(
            config,
            engine,
            device,
            started,
            relay_dropped,
            bug_report_extras,
        ),
        ipc::Command::DnsStatus
        | ipc::Command::DnsQuery(_)
        | ipc::Command::ExitList
        | ipc::Command::ExitUse(_)
        | ipc::Command::ExitDisable
        | ipc::Command::Metrics => {
            unreachable!("handled before general report")
        }
        ipc::Command::Status => {
            let stats = engine.stats();
            let peers = engine.status();

            let mut out = String::new();
            // Writing to a String is infallible; the `let _` keeps this
            // panic-free without an `unwrap` on every line.
            let _ = writeln!(out, "interface = \"{}\"", device.name);
            // §13.6 requires the tunnel MTU be reportable: a path that
            // black-holes full-size packets is otherwise very hard to diagnose.
            let _ = writeln!(out, "mtu = {}", device.mtu);
            let _ = writeln!(out, "listen = \"{}\"", config.listen);
            let _ = writeln!(out, "uptime_seconds = {}", started.elapsed().as_secs());
            let addrs: Vec<String> = config.addresses.iter().map(ToString::to_string).collect();
            let _ = writeln!(out, "addresses = {addrs:?}");
            let _ = writeln!(out, "psk_epoch = {}", config.psk_epoch);
            if let Some(sockets) = device.sockets {
                let _ = writeln!(out, "userspace_sockets = {sockets}");
            }
            if let Some(refused) = device.unreachable_family {
                // Printed on every IPv4-only node, not only when the count is
                // nonzero. "This node cannot use IPv6" is the fact an operator
                // needs, and it is true before the first peer advertises an
                // IPv6 candidate as well as after.
                let _ = writeln!(out, "ipv6 = \"unreachable (node.listen is IPv4)\"");
                let _ = writeln!(out, "ipv6_candidates_refused = {refused}");
            }

            let mapping = portmap.unwrap_or_else(|| portmap::Snapshot::new(config.port_mapping));
            let _ = writeln!(out, "\n[portmap]");
            let _ = writeln!(out, "portmap_enabled = {}", mapping.enabled);
            let _ = writeln!(out, "portmap_state = \"{}\"", mapping.state);
            let _ = writeln!(
                out,
                "portmap_gateway = \"{}\"",
                mapping
                    .gateway
                    .map_or_else(|| "-".to_owned(), |addr| addr.to_string())
            );
            let _ = writeln!(
                out,
                "portmap_protocol = \"{}\"",
                mapping.protocol.map_or("-", |protocol| match protocol {
                    Protocol::NatPmp => "natpmp",
                    Protocol::Pcp => "pcp",
                })
            );
            let _ = writeln!(
                out,
                "portmap_internal = \"{}\"",
                mapping
                    .internal
                    .map_or_else(|| "-".to_owned(), |addr| addr.to_string())
            );
            let _ = writeln!(
                out,
                "portmap_external = \"{}\"",
                mapping
                    .external
                    .map_or_else(|| "-".to_owned(), |addr| addr.to_string())
            );
            if let Some(renews) = mapping.renews_in_seconds() {
                let _ = writeln!(out, "portmap_renews_in_seconds = {renews}");
            }
            if let Some(reason) = mapping.reason {
                let _ = writeln!(out, "portmap_reason = \"{reason}\"");
            }
            if let Some(retry_in) = mapping.retry_in {
                let _ = writeln!(out, "portmap_retry_in_seconds = {}", retry_in.as_secs());
            }

            let _ = writeln!(out, "\n[stats]");
            let _ = writeln!(out, "tx_packets = {}", stats.tx_packets);
            let _ = writeln!(out, "rx_packets = {}", stats.rx_packets);
            let _ = writeln!(out, "unroutable = {}", stats.unroutable);
            let _ = writeln!(out, "source_violations = {}", stats.source_violations);
            let _ = writeln!(out, "mac_failures = {}", stats.mac_failures);
            let _ = writeln!(
                out,
                "tx_dropped_no_session = {}",
                stats.tx_dropped_no_session
            );
            let _ = writeln!(out, "malformed = {}", stats.malformed);
            let _ = writeln!(out, "decrypt_failures = {}", stats.decrypt_failures);
            let _ = writeln!(out, "acl_denied_in = {}", stats.acl_denied_in);
            let _ = writeln!(out, "acl_denied_out = {}", stats.acl_denied_out);
            let _ = writeln!(out, "acl_unclassifiable = {}", stats.acl_unclassifiable);
            // **Silent loss is the failure this line exists to prevent.** The
            // queue to the relay worker is bounded and drops rather than
            // blocking, which is the right trade — but a node quietly shedding
            // relayed traffic is indistinguishable from a node whose peers have
            // gone away, and those call for opposite responses.
            let _ = writeln!(
                out,
                "relay_dropped = {}",
                relay_dropped.load(Ordering::Relaxed)
            );

            // **Not a cosmetic line.** An operator debugging "why can I not
            // reach this host" has to be able to tell a node enforcing
            // deny-all from one enforcing nothing, and the two are
            // indistinguishable from outside in opposite directions.
            let _ = writeln!(out, "\n[policy]");
            match config.filter.rule_counts() {
                None => {
                    let _ = writeln!(out, "enforcing = false");
                    let _ = writeln!(out, "source = \"none (static roster)\"");
                }
                Some((inbound, outbound)) => {
                    let _ = writeln!(out, "enforcing = true");
                    let _ = writeln!(out, "ingress_rules = {inbound}");
                    let _ = writeln!(out, "egress_rules = {outbound}");
                    let _ = writeln!(out, "skipped_peers = {}", config.skipped.len());
                    if inbound == 0 && outbound == 0 {
                        let _ = writeln!(
                            out,
                            "note = \"no rules: this is default deny, not unfiltered\""
                        );
                    }
                }
            }

            for p in peers {
                let _ = writeln!(out, "\n[[peer]]");
                let _ = writeln!(out, "name = \"{}\"", p.name);
                let _ = writeln!(out, "hint = \"{}\"", p.hint);
                let _ = writeln!(
                    out,
                    "endpoint = \"{}\"",
                    p.endpoint.map_or_else(|| "-".to_owned(), |e| e.to_string())
                );
                let state = if !p.established {
                    "connecting"
                } else if p.rekeying {
                    "established (rekeying)"
                } else {
                    "established"
                };
                let _ = writeln!(out, "state = \"{state}\"");
                let _ = writeln!(out, "allowed_ips = {:?}", p.allowed_ips);
                let _ = writeln!(out, "psk_fallback = {}", p.psk_is_fallback);
                // §8.3: a relayed path is a working path, not a failure — but
                // it is slower and it discloses traffic timing to the relay, so
                // it is stated rather than left to be inferred from a latency
                // measurement. "none" is a third answer and a different problem.
                let _ = writeln!(out, "transport = \"{}\"", p.transport);
            }
            out
        }
    }
}

/// Current DNS state for `karst dns status`.
fn dns_report(
    config: &Config,
    listener_live: bool,
    host_integration: &str,
    host_state: &str,
    search_list: crate::dns::SearchList,
    cache: Option<karst_dns::cache::Stats>,
    failures: &[String],
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "enabled = {}", config.dns.enabled);
    let _ = writeln!(out, "listener = {listener_live}");
    let _ = writeln!(out, "stub_address = \"{}\"", config.dns.stub_address);
    let _ = writeln!(out, "magic_dns = {}", config.netmap_dns.magic_dns);
    let _ = writeln!(out, "host_integration = \"{host_integration}\"");
    let _ = writeln!(out, "host_state = \"{host_state}\"");
    let _ = writeln!(out, "zone = \"{}\"", config.netmap_dns.zone);
    let _ = writeln!(out, "upstreams = {:?}", config.netmap_dns.nameservers);
    let _ = writeln!(
        out,
        "search_domains = {:?}",
        config.netmap_dns.search_domains
    );
    // Directly under the list it qualifies, because the two are only meaningful
    // together: `/etc/resolver` routes every name below these domains to the
    // stub and still leaves a bare hostname unqualified.
    let _ = writeln!(out, "search_list = \"{}\"", search_list.as_str());
    let _ = writeln!(out, "split_routes = {}", config.netmap_dns.routes.len());
    let cache = cache.unwrap_or_default();
    let _ = writeln!(out, "cache_entries = {}", cache.entries);
    let _ = writeln!(out, "cache_hits = {}", cache.hits);
    let _ = writeln!(out, "cache_misses = {}", cache.misses);
    let _ = writeln!(out, "recent_failures = {failures:?}");
    out
}

/// Explain the resolver decision for `karst dns query` without emitting a DNS
/// request. The control command is deliberately diagnostic: forwarding an
/// arbitrary operator-supplied name would make a status check generate network
/// traffic and could leak a name while diagnosing a leak-prevention policy.
fn dns_query_report(config: &Config, name: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "name = {name:?}");
    match crate::dns::from_config(config) {
        Ok(None) => {
            let _ = writeln!(out, "path = \"disabled\"");
            let _ = writeln!(out, "reason = \"MagicDNS listener is not enabled\"");
        }
        Ok(Some(resolver)) => match resolver.resolve(name, karst_dns::RecordType::A, true) {
            Ok(karst_dns::Resolution::Authoritative(response)) => {
                let _ = writeln!(out, "path = \"authoritative\"");
                let _ = writeln!(out, "response = {:?}", response.kind);
                let _ = writeln!(out, "records = {:?}", response.records);
            }
            Ok(karst_dns::Resolution::Forward { resolvers, split }) => {
                let path = if split { "split-dns" } else { "upstream" };
                let _ = writeln!(out, "path = \"{path}\"");
                let _ = writeln!(out, "upstreams = {resolvers:?}");
            }
            Ok(karst_dns::Resolution::Refused) => {
                let _ = writeln!(out, "path = \"refused\"");
            }
            Err(error) => {
                let _ = writeln!(out, "path = \"invalid\"");
                let _ = writeln!(out, "error = {error:?}");
            }
        },
        Err(error) => {
            let _ = writeln!(out, "path = \"invalid\"");
            let _ = writeln!(out, "error = {error:?}");
        }
    }
    out
}

/// Perform the I/O an engine asked for.
/// Decide which protocol an arriving datagram belongs to, and handle it.
///
/// AVEN shares the datapath socket with PHREATIC — `aven-v1.md` §4, and it must,
/// because a path is only useful if it is the one PHREATIC will take and a NAT
/// binding proven on one port says nothing about another.
///
/// `Disco` is asked first and **falls through on anything it cannot
/// authenticate**, not merely on a missing magic. That distinction is the whole
/// of the demultiplexer's correctness: `phreatic-v1.md` §5 begins every datagram
/// with a CSPRNG-drawn `reassembly_id`, so roughly one in 2^32 starts with
/// AVEN's four bytes by chance, and a decision made on the magic alone would
/// discard a real fragment about once a day on a busy node with nothing in any
/// log to explain it.
fn demultiplex(
    datagram: &[u8],
    from: std::net::SocketAddr,
    now_ms: u64,
    disco: &Mutex<disco::Disco>,
    engine: &Engine,
) -> Output {
    let verdict = match disco.lock() {
        Ok(mut d) => d.inbound(datagram, from, now_ms),
        // A poisoned lock means another thread panicked holding it. Dropping
        // the datagram would be a silent connectivity failure; the discovery
        // state is a cache of reachability, so carrying on with it is safe.
        Err(poisoned) => poisoned.into_inner().inbound(datagram, from, now_ms),
    };
    match verdict {
        disco::Verdict::Handled(datagrams) => Output {
            // A `Pong` answers the socket the `Ping` arrived on, and this
            // function is only reached from that socket.
            datagrams: datagrams
                .into_iter()
                .map(|(d, to)| (d, Via::Direct(to)))
                .collect(),
            packets: Vec::new(),
        },
        disco::Verdict::NotAven => engine.inbound(datagram, from, now_ms, &responder_randomness()),
    }
}

/// Perform the I/O the engine asked for.
///
/// The two transports are split here rather than in the engine, which names a
/// destination and owns no socket. Direct datagrams keep the batched
/// `sendmmsg` path they had; relayed ones are handed to the worker that owns
/// the Ponor connection.
///
/// **The split is done without allocating on the common path.** Almost every
/// `Output` is entirely direct or entirely relayed, so the batch is built from
/// the direct ones in place and a separate pass only runs when a relayed
/// datagram is actually present.
fn dispatch(
    out: Output,
    socket: &UdpTransport,
    tun: &NetworkDevice,
    relay: Option<&RelaySender>,
    turn: Option<&TurnSender>,
) {
    let mut direct: Vec<(&[u8], std::net::SocketAddr)> = Vec::with_capacity(out.datagrams.len());
    for (datagram, via) in &out.datagrams {
        match via {
            Via::Direct(to) => direct.push((datagram.as_slice(), *to)),
            Via::Relay {
                relay: on,
                destination,
            } => {
                if let Some(relay) = relay {
                    relay.send_via(*on, *destination, datagram);
                }
            }
            Via::Turn(to) => {
                if let Some(turn) = turn {
                    turn.send_to(*to, datagram);
                }
            }
        }
    }

    match direct.len() {
        0 => {}
        // One datagram is the common case on a single flow; batching it would
        // cost an extra syscall's worth of setup for nothing.
        1 => {
            if let Some((datagram, to)) = direct.first() {
                // A send failure is per-datagram: a full buffer or an
                // unreachable host must not take the daemon down. The protocol
                // already retransmits.
                let _ = socket.send_to(datagram, *to);
            }
        }
        // A handshake is two fragments and a burst can be more. One syscall.
        _ => {
            let mut offset = 0;
            while offset < direct.len() {
                let Some(rest) = direct.get(offset..) else {
                    break;
                };
                match socket.send_batch(rest) {
                    // A short count is normal; resume from where it stopped.
                    Ok(0) | Err(_) => {
                        // A peer may honestly advertise a private address and
                        // a reachable public one in the same batch. If the
                        // first `sendmmsg` target is unroutable here, the one
                        // after it still has to be tried: one dead candidate
                        // must not suppress the working one beside it.
                        for (datagram, to) in rest {
                            let _ = socket.send_to(datagram, *to);
                        }
                        break;
                    }
                    Ok(n) => offset += n,
                }
            }
        }
    }
    for packet in out.packets {
        let _ = tun.send(&packet);
    }
}

/// Keep the netmap current, applying changes to the running datapath.
///
/// Its own thread, and the only async code in the daemon: `tonic` needs a
/// runtime, and a current-thread one here cannot be starved by a busy tunnel
/// because it does not share a thread with the datapath.
///
/// **Nothing here is fatal.** A server that has gone away, a netmap that will
/// not configure a datapath, a cache that cannot be written — each leaves the
/// node running on what it already had, which works. Taking the tunnel down
/// because the control plane hiccuped would turn a coordination-server outage
/// into a network outage, which is exactly what the cached netmap exists to
/// prevent.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn refresh_netmap(
    mut client: crate::control::Client,
    shutdown: &Shutdown,
    engine: &Engine,
    socket: &UdpTransport,
    tun: &NetworkDevice,
    started: Instant,
    local: &dyn Fn() -> crate::config::LocalSettings,
    routes: &Mutex<Routes>,
    disco: &Mutex<disco::Disco>,
    home: &Mutex<crate::home::Selector>,
    exit_policy: &Mutex<crate::exit_policy::Manager>,
    control_endpoint: Option<&str>,
    dns_runtime: &Mutex<Option<crate::dns::Runtime>>,
    exit_node: Option<&Mutex<crate::exit_node::Selection>>,
    dns_host: &Mutex<crate::dns::HostRuntime>,
    gateway: &Mutex<crate::gateway::Manager>,
    gateway_error: &Mutex<Option<String>>,
    relayed: Option<&RelaySender>,
    turned: Option<&TurnSender>,
    last_push: &Mutex<Option<Instant>>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        tracing::error!("cannot start the control runtime; the netmap will not refresh");
        return;
    };

    // A signal the held connection's background reader notifies on an
    // unprompted push (GitHub issues [#72](https://github.com/karst-net/karst/issues/72) and [#73](https://github.com/karst-net/karst/issues/73)) — stable across whatever reconnects
    // `client.sync()` does internally, so it only needs to be fetched once.
    let pushed = client.push_signal();
    let mut next = Instant::now() + crate::control::REFRESH;
    // What the server was last told, so a change can be published without
    // waiting for the refresh timer.
    let mut published: Option<[u8; 32]> = None;
    // How soon a failed sync is retried, growing on repeated failure and
    // reset on success — the same shape `sleep_backoff` gives relay
    // reconnects, reused here for the same reason.
    //
    // This matters more than it used to: with the connection held open across
    // polls (GitHub issues [#72](https://github.com/karst-net/karst/issues/72) and [#73](https://github.com/karst-net/karst/issues/73)), a sync failure now means the push mechanism
    // itself is down, not merely that one poll was late. Waiting out the rest
    // of a 60-second `REFRESH` before reconnecting — which is what simply
    // falling through to the next scheduled tick would do — would leave a
    // node that is, say, mid-restart on the server end back on poll-only
    // behavior for up to a minute after every blip. A quick retry is what
    // makes the connection "held open" mean something across a transient
    // failure rather than only across the quiet periods between them.
    let mut control_backoff = RELAY_BACKOFF_MIN;
    while !shutdown.requested() {
        // Races the ordinary tick against a push notification, so a
        // deprovisioning event does not wait out the rest of `REFRESH` once a
        // connection is up to receive it. Still a short wait rather than one
        // long one when neither fires, so a shutdown is noticed promptly.
        // `pushed` carries no payload to trust — a push only ever means
        // "re-fetch now" — so this branch's only job is to make `due` true.
        let due = runtime.block_on(async {
            tokio::select! {
                () = tokio::time::sleep(TICK) => false,
                () = pushed.notified() => true,
            }
        });
        if due {
            *last_push
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
        }
        let chosen = home
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chosen();
        // **A move is published at once rather than on the timer, and so is a
        // push.** Between the node changing relay and its peers hearing about
        // it, every peer is dialling a relay this node has left, so the
        // packets are not merely late — they are delivered nowhere. A whole
        // refresh interval of that is the one case where waiting for the next
        // tick is not free, and a deprovisioning notice is the other.
        if !due && Instant::now() < next && chosen == published {
            continue;
        }
        next = Instant::now() + crate::control::REFRESH;
        client.set_home_relay(chosen);
        let epoch = client.netmap().psk_epoch;
        let sessions = engine
            .status()
            .into_iter()
            .map(|status| pb::KarstSessionObservation {
                peer_id: status.node_id,
                path: match status.transport {
                    crate::engine::Transport::Direct => "direct",
                    crate::engine::Transport::Relay => "relay",
                    crate::engine::Transport::Turn => "turn",
                    crate::engine::Transport::Unreachable => "unreachable",
                }
                .to_owned(),
                endpoint: status
                    .endpoint
                    .map(|endpoint| endpoint.to_string())
                    .unwrap_or_default(),
                lattice_only: status.psk_is_fallback,
                psk_epoch: epoch,
                suite: status.suite,
            })
            .collect();
        client.set_session_observations(sessions);
        published = chosen;

        let synced = runtime.block_on(client.sync());
        // Publish the verified log before the `Unchanged` early return below.
        // The Bedrock fetch runs on every sync regardless of whether the netmap
        // moved, and the two advance independently — a log that grew while the
        // netmap stood still is the ordinary case after a countersignature.
        engine.set_bedrock(client.bedrock_snapshot());

        let outcome = match synced {
            // Nothing moved. The overwhelmingly common case, and the one the
            // content-hash version exists to make cheap: no peer entry crosses
            // the wire.
            Ok(crate::netmap::Outcome::Unchanged) => {
                control_backoff = RELAY_BACKOFF_MIN;
                continue;
            }
            Ok(outcome) => {
                control_backoff = RELAY_BACKOFF_MIN;
                outcome
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?control_backoff, "netmap refresh failed; session held open, retrying");
                // Retry soon rather than waiting out the rest of REFRESH — see
                // control_backoff's own comment for why that distinction now
                // matters.
                next = Instant::now() + control_backoff;
                control_backoff = (control_backoff * 2).min(RELAY_BACKOFF_MAX);
                continue;
            }
        };

        // The netmap arrived but cannot configure a datapath. Keeping the
        // previous roster is the right call: it works, and the alternative is a
        // node with no peers.
        let updated = match client.to_config(local()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "the new netmap is unusable, keeping the previous one");
                continue;
            }
        };

        let updated = Arc::new(updated);
        {
            let mut listener = dns_runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = crate::dns::reconcile(&mut listener, &updated, tun.userspace()) {
                eprintln!("karstd: DNS listener update failed: {error}");
            }
            let listener_live = listener.is_some();
            if !updated.netmap_dns.magic_dns || listener_live {
                if let Err(error) = dns_host
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .update(&updated)
                {
                    eprintln!("karstd: DNS host update failed: {error}");
                }
            }
        }
        // Routes before the roster: a peer that becomes reachable should have
        // somewhere for its packets to go by the time the datapath will accept
        // them.
        let selected_exit = exit_node.and_then(|selection| {
            selection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active()
                .map(str::to_owned)
        });
        if let Err(error) = reconcile_exit(
            routes,
            exit_policy,
            tun,
            &updated,
            Some(engine),
            control_endpoint,
            selected_exit.as_deref(),
        ) {
            eprintln!("karstd: exit selection is dormant after netmap refresh: {error}");
        }

        // Gateway grants are derived from the same verified snapshot. A failed
        // update removes stale Karst-owned grants and records failed readiness.
        apply_gateway(gateway, gateway_error, &updated);

        // **The whole roster swap happens under the discovery lock**, and the
        // ordering inside it is load-bearing. A roster index names a different
        // peer after `reconfigure`, so endpoints discovery installed are
        // withdrawn first, while the indices still mean what they meant when
        // they were written. Holding the lock across all three steps is what
        // stops the timer thread from applying a path in the middle and
        // pointing one peer's traffic at another's address.
        let mut discovery = disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        apply_path_changes(&discovery.release_all(), engine);
        let report = engine.reconfigure(&updated);
        discovery.reconcile(&updated, now_ms(started));
        drop(discovery);
        tracing::info!(
            outcome = ?outcome,
            added = report.added,
            removed = report.removed,
            kept = report.kept,
            epoch_rotated = report.epoch_rotated,
            "netmap updated"
        );
        if let Err(e) = client.save_cache() {
            eprintln!("karstd: could not write the netmap cache ({e})");
        }
        // Dial anyone new. A peer added while the daemon runs would otherwise
        // wait for the next timer sweep.
        dispatch(
            engine.connect_all(now_ms(started), random_seed),
            socket,
            tun,
            relayed,
            turned,
        );
    }
}

/// Say what came up, and what is degraded about it.
///
/// Two of these lines are obligations rather than decoration. §7.3 requires a
/// lattice-only session — one with no PSK, whose confidentiality rests on
/// ML-KEM alone — to be surfaced rather than assumed. And a peer the netmap
/// carried that this node could not use is, from the outside, indistinguishable
/// from a peer the server was never told about, which is a completely different
/// problem.
fn announce(config: &Config, tun: &NetworkDevice, socket: &UdpTransport) -> io::Result<()> {
    eprintln!(
        "karstd: {} up, mtu {}, listening on {}, {} peer(s){}",
        tun.name(),
        tun.mtu(),
        socket.local_addr()?,
        config.peers.len(),
        if tun.offload() { ", tso" } else { "" }
    );
    // A peer the netmap carried and this node could not use. Said loudly at
    // startup, because from the outside it is indistinguishable from a peer the
    // server was never told about — a completely different problem.
    for skipped in &config.skipped {
        eprintln!("karstd: skipping unusable peer from the netmap — {skipped}");
    }
    for peer in &config.peers {
        if peer.psk_is_fallback {
            // §7.3 requires this be surfaced, not assumed. Without a PSK the
            // handshake still has both key families, but loses the pre-shared
            // secret that would survive a break of both.
            eprintln!(
                "karstd: peer {} has no PSK — using the zero-PSK fallback (spec §7.3)",
                peer.name
            );
        }
    }

    Ok(())
}

/// Assemble a support bundle.
///
/// # The thing this must never do
///
/// A bug report is the artifact most likely to be pasted into an issue tracker,
/// a chat window, or a vendor's support portal. So it reports **facts about**
/// the node's configuration and never the configuration itself. The tempting
/// shortcut — "attach the config file so we can see what they set" — would ship
/// every per-pair PSK in a TOML roster and the setup key with it, and the
/// person pasting it would have no way to know.
///
/// Concretely, and checked by `tests/leakscan.rs`:
///
/// - **No PSK bytes**, in any encoding. Whether a peer *has* a PSK is reported,
///   because §7.3 requires a lattice-only session to be visible; the bytes are
///   not, because knowing they exist is the diagnostic and knowing their value
///   is the compromise.
/// - **No private keys and no identity seed.** A peer is identified by its name
///   and the first eight bytes of its `peer_id_hint` — enough to correlate two
///   nodes' reports, not enough to be a key.
/// - **No setup key**, which is a bearer credential that enrolls a node.
/// - **No file contents**, only paths and the facts derived from them.
#[allow(clippy::too_many_lines)]
fn bug_report(
    config: &Config,
    engine: &Engine,
    device: Attachment<'_>,
    started: Instant,
    relay_dropped: &AtomicU64,
    extras: BugReportExtras,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "# karst bug report");
    let _ = writeln!(
        out,
        "# Contains no key material: no PSKs, no private keys, no setup key."
    );
    let _ = writeln!(out, "# Safe to attach to an issue.\n");

    let _ = writeln!(out, "[karst]");
    let _ = writeln!(out, "version = \"{}\"", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "uptime_seconds = {}", started.elapsed().as_secs());

    let _ = writeln!(out, "\n[host]");
    // Kernel version explains an offload or netlink difference better than any
    // amount of guessing, and is not sensitive.
    let _ = writeln!(out, "kernel = \"{}\"", kernel_release());
    let _ = writeln!(out, "arch = \"{}\"", std::env::consts::ARCH);

    let _ = writeln!(out, "\n[interface]");
    let _ = writeln!(out, "name = \"{}\"", device.name);
    let _ = writeln!(out, "mtu = {}", device.mtu);
    let _ = writeln!(out, "listen = \"{}\"", config.listen);
    let addrs: Vec<String> = config.addresses.iter().map(ToString::to_string).collect();
    let _ = writeln!(out, "addresses = {addrs:?}");

    let _ = writeln!(out, "\n[control]");
    // Plaintext h2c, unconditionally: §8 of 04-pentest.md found the
    // control-channel client has no TLS support at all, a real architectural
    // gap worth stating here rather than only in that document — reporting
    // anything else would misrepresent what actually left the wire.
    let _ = writeln!(out, "transport = \"plaintext (h2c)\"");
    match extras.since_last_push {
        Some(elapsed) => {
            let _ = writeln!(out, "since_last_push_seconds = {}", elapsed.as_secs());
        }
        // Absent, not zero: no push has arrived yet in this process's life
        // (GitHub issues #72/#73's mechanism), which is a materially
        // different fact from "one just arrived".
        None => {
            let _ = writeln!(out, "since_last_push_seconds = \"never\"");
        }
    }

    let _ = writeln!(out, "\n[crypto]");
    // The epoch is a generation number, not a secret — and a mismatch between
    // two nodes' epochs is exactly the kind of thing a bug report exists to
    // make visible.
    let _ = writeln!(out, "psk_epoch = {}", config.psk_epoch);
    let lattice_only = config.peers.iter().filter(|p| p.psk_is_fallback).count();
    let _ = writeln!(out, "peers_total = {}", config.peers.len());
    // §7.3 requires a lattice-only session to be surfaced. A count here, and
    // the per-peer flag below, are how it reaches a maintainer.
    let _ = writeln!(out, "peers_lattice_only = {lattice_only}");

    let _ = writeln!(out, "\n[policy]");
    match config.filter.rule_counts() {
        None => {
            let _ = writeln!(out, "enforcing = false");
            let _ = writeln!(out, "source = \"none (static roster)\"");
        }
        Some((inbound, outbound)) => {
            let _ = writeln!(out, "enforcing = true");
            let _ = writeln!(out, "ingress_rules = {inbound}");
            let _ = writeln!(out, "egress_rules = {outbound}");
            if inbound == 0 && outbound == 0 {
                let _ = writeln!(
                    out,
                    "note = \"no rules: this is default deny, not unfiltered\""
                );
            }
        }
    }

    // Peers the netmap carried and this node could not use. From the outside
    // these are indistinguishable from peers the server was never told about,
    // which is a completely different problem — so they are named.
    if !config.skipped.is_empty() {
        let _ = writeln!(out, "\n[skipped]");
        for s in &config.skipped {
            let _ = writeln!(out, "peer = \"{s}\"");
        }
    }

    let stats = engine.stats();

    // **Bedrock, and the one counter here that means something is wrong with
    // the coordination server rather than with the network.**
    //
    write_bedrock(&mut out, &stats, engine.bedrock().as_deref());

    let _ = writeln!(out, "\n[stats]");
    let _ = writeln!(out, "tx_packets = {}", stats.tx_packets);
    let _ = writeln!(out, "rx_packets = {}", stats.rx_packets);
    let _ = writeln!(out, "unroutable = {}", stats.unroutable);
    let _ = writeln!(out, "source_violations = {}", stats.source_violations);
    let _ = writeln!(out, "mac_failures = {}", stats.mac_failures);
    let _ = writeln!(
        out,
        "tx_dropped_no_session = {}",
        stats.tx_dropped_no_session
    );
    let _ = writeln!(out, "malformed = {}", stats.malformed);
    let _ = writeln!(out, "decrypt_failures = {}", stats.decrypt_failures);
    let _ = writeln!(out, "acl_denied_in = {}", stats.acl_denied_in);
    let _ = writeln!(out, "acl_denied_out = {}", stats.acl_denied_out);
    let _ = writeln!(out, "acl_unclassifiable = {}", stats.acl_unclassifiable);
    let _ = writeln!(
        out,
        "relay_dropped = {}",
        relay_dropped.load(Ordering::Relaxed)
    );

    // Per-relay/per-TURN-server reachability, beyond the aggregate counter
    // above: which specific one, and since when — plans/phase-6
    // /08-observability.md §5 W6 item 3. Sorted so the report is
    // deterministic rather than reflecting HashMap iteration order.
    let mut relay_health = extras.relay_health;
    relay_health.sort_by(|a, b| a.0.cmp(&b.0));
    for (address, health) in relay_health {
        let _ = writeln!(out, "\n[[relay]]");
        let _ = writeln!(out, "address = \"{address}\"");
        let _ = writeln!(out, "reachable = {}", health.reachable);
        let _ = writeln!(out, "since_seconds = {}", health.since.elapsed().as_secs());
    }
    let mut turn_health = extras.turn_health;
    turn_health.sort_by(|a, b| a.0.cmp(&b.0));
    for (uri, health) in turn_health {
        let _ = writeln!(out, "\n[[turn]]");
        let _ = writeln!(out, "uri = \"{uri}\"");
        let _ = writeln!(out, "reachable = {}", health.reachable);
        let _ = writeln!(out, "since_seconds = {}", health.since.elapsed().as_secs());
    }

    for p in engine.status() {
        let _ = writeln!(out, "\n[[peer]]");
        let _ = writeln!(out, "name = \"{}\"", p.name);
        // Eight bytes of peer_id_hint: enough to correlate two nodes' reports
        // with each other, not enough to be a key.
        let _ = writeln!(out, "hint = \"{}\"", p.hint);
        let _ = writeln!(
            out,
            "endpoint = \"{}\"",
            p.endpoint.map_or_else(|| "-".to_owned(), |e| e.to_string())
        );
        let _ = writeln!(out, "established = {}", p.established);
        let _ = writeln!(out, "rekeying = {}", p.rekeying);
        let _ = writeln!(out, "allowed_ips = {:?}", p.allowed_ips);
        // Whether a PSK exists, never what it is.
        let _ = writeln!(out, "psk_fallback = {}", p.psk_is_fallback);
        let _ = writeln!(out, "transport = \"{}\"", p.transport);
    }

    out
}

#[cfg(test)]
mod route_tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::{
        dns_query_report, dns_report, routing_report, underlay_addresses, url_authority, Routes,
    };
    use crate::config::Config;
    use std::net::IpAddr;

    /// A config with the given interface addresses and peer ranges.
    fn config(addresses: &[&str], peer_ranges: &[&[&str]]) -> Config {
        let mut peers = Vec::new();
        let mut pairs = Vec::new();
        for (index, ranges) in peer_ranges.iter().enumerate() {
            let mut allowed = Vec::new();
            for r in *ranges {
                let prefix: crate::routing::Prefix = r.parse().expect("prefix");
                allowed.push(prefix);
                pairs.push((prefix, index));
            }
            peers.push(crate::config::Peer {
                name: format!("p{index}"),
                node_id: Vec::new(),
                public: std::sync::Arc::new(karst_noise::handshake::PeerPublic {
                    kem_pk: {
                        use karst_crypto::kem::{keypair_from_seed, KemKind};
                        let seed = u8::try_from(index).unwrap_or(0).wrapping_add(0x22);
                        let (_, pk) = keypair_from_seed(KemKind::MlKem768, &[seed; 64]);
                        pk
                    },
                    dh_pk: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                        [0x33u8; 32],
                    )),
                    psk: [0u8; 32],
                }),
                endpoint: None,
                allowed_ips: allowed,
                psk_is_fallback: true,
                psk_previous: None,
                disco_key: None,
                home_relay: None,
            });
        }
        Config {
            relay_ca_file: None,
            metrics_listen: None,
            route_offers: Vec::new(),
            exit_node_state_file: None,
            keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:51820".parse().expect("addr"),
            port_mapping: true,
            interface: "karst0".to_owned(),
            network_mode: crate::config::NetworkMode::Tun,
            dns: crate::config::DnsSettings::default(),
            netmap_dns: crate::netmap::DNSConfig::default(),
            userspace_socks5_listen: None,
            userspace_publish: Vec::new(),
            nat64: None,
            addresses: addresses
                .iter()
                .map(|a| a.parse().expect("interface address"))
                .collect(),
            psk_epoch: 1,
            node_id: Vec::new(),
            relays: Vec::new(),
            turn_servers: Vec::new(),
            peers,
            routes: crate::routing::AllowedIps::build(pairs).expect("no conflicts"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
        }
    }

    #[test]
    fn dns_status_reports_the_live_host_selection_and_netmap_policy() {
        let mut cfg = config(&["100.64.0.1/24"], &[]);
        cfg.netmap_dns = crate::netmap::DNSConfig {
            nameservers: vec!["9.9.9.9:53".to_owned()],
            search_domains: vec!["corp.example".to_owned()],
            routes: vec![crate::netmap::DNSRoute {
                match_domain: "internal.example".to_owned(),
                resolvers: vec!["100.64.0.2:53".to_owned()],
            }],
            zone: "aquifer.karst".to_owned(),
            magic_dns: true,
        };
        let report = dns_report(
            &cfg,
            true,
            "systemd-resolved",
            "configured",
            crate::dns::SearchList::Applied,
            None,
            &[],
        );
        assert!(report.contains("listener = true"));
        assert!(report.contains("host_integration = \"systemd-resolved\""));
        assert!(report.contains("magic_dns = true"));
        assert!(report.contains("split_routes = 1"));
        assert!(report.contains("search_list = \"applied\""));

        // The macOS mechanism prints the same search domains and does not
        // install them. An operator has to be able to tell the two apart from
        // the status output alone.
        let resolver_directory = dns_report(
            &cfg,
            true,
            "/etc/resolver",
            "configured",
            crate::dns::SearchList::NotApplied,
            None,
            &[],
        );
        assert!(resolver_directory.contains("search_domains = [\"corp.example\"]"));
        assert!(resolver_directory.contains("search_list = \"not applied\""));
    }

    #[test]
    fn dns_query_explains_authoritative_and_split_dns_paths() {
        let mut cfg = config(&["100.64.0.1/24"], &[&["100.64.0.2/32"]]);
        cfg.peers.first_mut().expect("one configured peer").name = "atlas".to_owned();
        cfg.netmap_dns = crate::netmap::DNSConfig {
            nameservers: vec!["9.9.9.9:53".to_owned()],
            search_domains: Vec::new(),
            routes: vec![crate::netmap::DNSRoute {
                match_domain: "internal.example".to_owned(),
                resolvers: vec!["100.64.0.53:53".to_owned()],
            }],
            zone: "aquifer.karst".to_owned(),
            magic_dns: true,
        };
        let authoritative = dns_query_report(&cfg, "atlas.aquifer.karst");
        assert!(authoritative.contains("path = \"authoritative\""));
        assert!(authoritative.contains("A(100.64.0.2)"));
        let split = dns_query_report(&cfg, "db.internal.example");
        assert!(split.contains("path = \"split-dns\""));
        assert!(split.contains("100.64.0.53:53"));
    }

    /// **A peer inside the interface's own prefix needs no route.** The address
    /// already gives the kernel a connected route covering it, and installing a
    /// second identical one would be noise in `ip route` for no effect.
    #[test]
    fn an_on_link_peer_needs_no_route() {
        let cfg = config(
            &["100.64.0.1/16"],
            &[&["100.64.0.2/32"], &["100.64.9.9/32"]],
        );
        assert!(
            Routes::wanted(&cfg, None).is_empty(),
            "both peers are inside the interface's /16"
        );
    }

    /// **The case routes exist for.** A subnet router advertises a range
    /// nowhere near the aquifer's own prefix; without a route the kernel sends
    /// that traffic to the default gateway instead of the tunnel.
    #[test]
    fn a_peer_outside_the_prefix_needs_one() {
        let cfg = config(
            &["100.64.0.1/16"],
            &[&["100.64.0.2/32"], &["192.168.1.0/24"]],
        );
        let wanted = Routes::wanted(&cfg, None);
        assert_eq!(wanted.len(), 1, "only the off-link range needs a route");
        assert!(wanted.contains(&("192.168.1.0".parse::<IpAddr>().unwrap(), 24)));
    }

    /// A node with both families routes each independently — an IPv6 range is
    /// not covered by an IPv4 interface address, whatever the numbers look like.
    #[test]
    fn the_two_families_do_not_cover_each_other() {
        let cfg = config(
            &["100.64.0.1/16"],
            &[&["fd7a:5ea5::2/128"], &["100.64.0.2/32"]],
        );
        let wanted = Routes::wanted(&cfg, None);
        assert_eq!(wanted.len(), 1);
        assert!(wanted.contains(&("fd7a:5ea5::2".parse::<IpAddr>().unwrap(), 128)));
    }

    /// One peer owning several ranges needs a route for each off-link one, and
    /// none for the rest.
    #[test]
    fn each_off_link_range_is_routed_separately() {
        let cfg = config(
            &["100.64.0.1/16"],
            &[&["100.64.0.2/32", "10.1.0.0/16", "172.16.0.0/12"]],
        );
        assert_eq!(Routes::wanted(&cfg, None).len(), 2);
    }

    /// A node with no peers routes nothing — and in particular does not install
    /// a default route, which is what a `/0` would silently become.
    #[test]
    fn an_empty_roster_routes_nothing() {
        assert!(Routes::wanted(&config(&["100.64.0.1/16"], &[]), None).is_empty());
    }

    fn exit_offer(route_id: &str) -> crate::route_offer::Offer {
        use karst_control_client::transport::pb;
        crate::route_offer::Offer::from_wire(
            pb::KarstRouteOffer {
                route_id: route_id.to_owned(),
                prefix: "0.0.0.0/0".to_owned(),
                gateway_id: vec![1],
                metric: 100,
                kind: pb::KarstRouteKind::Exit as i32,
                masquerade: true,
                keep_route: false,
                role: pb::KarstRouteRole::Recipient as i32,
            },
            &[],
        )
        .expect("exit offer")
    }

    #[test]
    fn an_exit_cryptokey_route_is_not_a_kernel_route_without_consent() {
        let mut cfg = config(&["100.64.0.1/16"], &[&["0.0.0.0/0"]]);
        cfg.route_offers.push(exit_offer("exit-eu"));

        assert!(Routes::wanted(&cfg, None).is_empty());
        assert!(Routes::wanted(&cfg, Some("not-offered")).is_empty());
    }

    fn gateway_offer(route_id: &str, prefix: &str) -> crate::route_offer::Offer {
        use karst_control_client::transport::pb;
        crate::route_offer::Offer::from_wire(
            pb::KarstRouteOffer {
                route_id: route_id.to_owned(),
                prefix: prefix.to_owned(),
                gateway_id: vec![1],
                metric: 100,
                kind: pb::KarstRouteKind::Subnet as i32,
                masquerade: true,
                keep_route: false,
                role: pb::KarstRouteRole::Gateway as i32,
            },
            &[1],
        )
        .expect("gateway offer")
    }

    /// **A prefix this node gateways is never routed over its own tunnel** —
    /// `plans/phase-6/06-subnet-routers-and-exit-nodes.md` §4's "Gateway
    /// nodes receive a corresponding forwarding grant but do not install
    /// their own advertised prefix into the TUN." Reachability to it is the
    /// gateway's own local network, a route karstd does not own and must not
    /// overwrite: an aquifer.rs namespace row (the failover topology) found
    /// this the hard way — an `ip route replace` for the same prefix a
    /// destination LAN's own connected route already covered silently
    /// destroyed that route, and nothing ever restored it, leaving the LAN
    /// unreachable even after the stale entry was withdrawn.
    ///
    /// A peer's `allowed_ips` still naming the prefix — as it would for one
    /// reconciliation cycle right after an HA failover reassigns the route to
    /// this node, before the peer table catches up — must not defeat this:
    /// `route_offers` is checked directly rather than trusted to have already
    /// been reflected everywhere else.
    #[test]
    fn a_route_this_node_gateways_is_never_installed_over_its_own_tunnel() {
        let mut cfg = config(&["100.64.0.1/16"], &[&["100.64.0.2/32", "10.99.0.0/24"]]);
        cfg.route_offers
            .push(gateway_offer("dest-lan", "10.99.0.0/24"));

        assert!(
            Routes::wanted(&cfg, None).is_empty(),
            "a prefix this node gateways must never be wanted over the tunnel, \
             even while a peer's allowed_ips still names it"
        );
    }

    #[test]
    fn consent_installs_only_the_matching_authenticated_exit_offer() {
        let mut cfg = config(&["100.64.0.1/16"], &[&["0.0.0.0/0"]]);
        cfg.route_offers.push(exit_offer("exit-eu"));

        let wanted = Routes::wanted(&cfg, Some("exit-eu"));
        assert_eq!(wanted.len(), 1);
        assert!(wanted.contains(&("0.0.0.0".parse().unwrap(), 0)));
    }

    #[test]
    fn routing_status_distinguishes_offered_selected_and_ready() {
        let mut cfg = config(&["100.64.0.1/16"], &[&["0.0.0.0/0"]]);
        cfg.route_offers.push(exit_offer("exit-eu"));

        let dormant = routing_report(
            &cfg,
            Some("withdrawn-id"),
            false,
            false,
            Some("nft unavailable"),
        );
        assert!(dormant.contains("selected_exit = Some(\"withdrawn-id\")"));
        assert!(dormant.contains("exit_route_active = false"));
        assert!(dormant.contains("gateway_error = Some(\"nft unavailable\")"));

        let active = routing_report(&cfg, Some("exit-eu"), true, false, None);
        assert!(active.contains("exit_route_active = true"));
        assert!(active.contains("route_id = \"exit-eu\""));
        assert!(active.contains("kind = \"exit\""));
        assert!(active.contains("role = \"recipient\""));
        assert!(active.contains("active = true"));
    }

    #[test]
    fn control_url_authorities_cover_names_literals_and_ipv6() {
        assert_eq!(
            url_authority("https://control.example/v1").unwrap(),
            ("control.example", 443)
        );
        assert_eq!(
            url_authority("http://192.0.2.8:8080").unwrap(),
            ("192.0.2.8", 8080)
        );
        assert_eq!(
            url_authority("https://[2001:db8::8]:8443").unwrap(),
            ("2001:db8::8", 8443)
        );
        assert!(url_authority("control.example:443").is_err());
    }

    #[test]
    fn configured_peer_and_control_addresses_become_underlay_escapes() {
        let mut cfg = config(&["100.64.0.1/16"], &[&["100.64.0.2/32"]]);
        cfg.peers.first_mut().unwrap().endpoint = Some("192.0.2.20:51820".parse().unwrap());

        let escapes = underlay_addresses(&cfg, None, Some("https://198.51.100.9:443")).unwrap();
        assert_eq!(
            escapes,
            [
                "192.0.2.20".parse().unwrap(),
                "198.51.100.9".parse().unwrap()
            ]
            .into_iter()
            .collect()
        );
    }

    // ── endpoints discovery installs and withdraws ────────────────────────

    use super::apply_path_changes;
    use crate::disco::PathChange;
    use crate::engine::Engine;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn addr(a: u8) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, a], 51820))
    }

    /// One peer whose netmap-configured endpoint is `configured`.
    fn one_peer_engine(configured: Option<SocketAddr>) -> Engine {
        let mut cfg = config(&["100.64.0.1/16"], &[&["192.168.1.0/24"]]);
        cfg.peers.first_mut().expect("one peer").endpoint = configured;
        Engine::new(&Arc::new(cfg))
    }

    #[test]
    fn a_confirmed_path_displaces_the_configured_endpoint() {
        let engine = one_peer_engine(Some(addr(1)));
        apply_path_changes(
            &[PathChange::Install {
                peer: 0,
                endpoint: addr(9),
            }],
            &engine,
        );
        assert_eq!(engine.endpoint(0), Some(addr(9)));
    }

    /// A release clears the endpoint rather than reverting to the configured
    /// one, so `Engine::via` falls through to the relay. Reverting would hand
    /// the datapath back the address discovery had just given up on — the
    /// configured endpoint is a candidate like any other.
    #[test]
    fn releasing_a_path_clears_the_endpoint_so_the_relay_takes_over() {
        let engine = one_peer_engine(Some(addr(1)));
        apply_path_changes(
            &[
                PathChange::Install {
                    peer: 0,
                    endpoint: addr(9),
                },
                PathChange::Release {
                    peer: 0,
                    installed: addr(9),
                },
            ],
            &engine,
        );
        assert_eq!(engine.endpoint(0), None);
    }

    /// **The endpoint has a second writer**: `inbound` learns one from a
    /// handshake that decrypted. A release must not clobber it, because
    /// discovery going quiet is weaker evidence than a peer that has just
    /// completed a handshake from somewhere else.
    #[test]
    fn a_release_does_not_clobber_an_endpoint_learned_since() {
        let engine = one_peer_engine(Some(addr(1)));
        apply_path_changes(
            &[PathChange::Install {
                peer: 0,
                endpoint: addr(9),
            }],
            &engine,
        );
        // Stands in for the handshake learning a different address.
        assert!(engine.set_endpoint(0, addr(7)));

        apply_path_changes(
            &[PathChange::Release {
                peer: 0,
                installed: addr(9),
            }],
            &engine,
        );
        assert_eq!(
            engine.endpoint(0),
            Some(addr(7)),
            "a stale discovery result overwrote a freshly learned endpoint"
        );
    }

    #[test]
    fn a_release_for_an_index_outside_the_roster_changes_nothing() {
        let engine = one_peer_engine(Some(addr(1)));
        assert!(!engine.release_endpoint(9, addr(9)));
        assert_eq!(engine.endpoint(0), Some(addr(1)));
    }

    // ── bugreport: control-session health, per-relay/TURN reachability ────

    /// §5 W6 items 3a/3c of the observability plan: `[control]`'s
    /// `since_last_push_seconds` and the `[[relay]]`/`[[turn]]` sections
    /// actually render what `BugReportExtras` was given.
    #[test]
    fn bug_report_lists_relay_and_turn_reachability() {
        let engine = one_peer_engine(None);
        let cfg = config(&["100.64.0.1/16"], &[]);
        let device = super::Attachment {
            name: "karst0",
            mtu: 1420,
            sockets: None,
            unreachable_family: None,
        };
        let extras = super::BugReportExtras {
            since_last_push: Some(std::time::Duration::from_secs(5)),
            relay_health: vec![(
                "relay.example:443".to_owned(),
                super::Reachability {
                    reachable: true,
                    since: std::time::Instant::now(),
                },
            )],
            turn_health: vec![(
                "turn:turn.example:3478".to_owned(),
                super::Reachability {
                    reachable: false,
                    since: std::time::Instant::now(),
                },
            )],
        };
        let report = super::bug_report(
            &cfg,
            &engine,
            device,
            std::time::Instant::now(),
            &std::sync::atomic::AtomicU64::new(0),
            extras,
        );

        assert!(
            report.contains("since_last_push_seconds = 5"),
            "control-session health missing: {report}"
        );
        assert!(report.contains("[[relay]]"), "{report}");
        assert!(
            report.contains("address = \"relay.example:443\""),
            "{report}"
        );
        assert!(report.contains("[[turn]]"), "{report}");
        assert!(
            report.contains("uri = \"turn:turn.example:3478\""),
            "{report}"
        );
    }
}

#[cfg(test)]
mod relay_queue_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn sender(
        depth: usize,
    ) -> (
        RelaySender,
        tokio::sync::mpsc::Receiver<Relayed>,
        tokio::sync::mpsc::Receiver<(RelayId, Relayed)>,
    ) {
        let (queue, home_rx) = tokio::sync::mpsc::channel(depth);
        let (on_demand, on_demand_rx) = tokio::sync::mpsc::channel(depth);
        (
            RelaySender {
                queue,
                on_demand,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            home_rx,
            on_demand_rx,
        )
    }

    /// §9.1's two rules are two connections, so they are two queues. A datagram
    /// for a peer's published relay put on the home connection would be
    /// addressed to a relay that has already said it cannot deliver it.
    #[test]
    fn each_rule_reaches_its_own_connection() {
        let (sender, mut home, mut on_demand) = sender(4);
        let peer = [0xAA; karst_relay_proto::consts::ID_LEN];
        let elsewhere = [0xBB; karst_relay_proto::consts::ID_LEN];

        sender.send_via(None, peer, b"first rule");
        sender.send_via(Some(elsewhere), peer, b"second rule");

        assert!(matches!(home.try_recv(), Ok(Relayed::Packet { .. })));
        assert!(home.try_recv().is_err(), "both datagrams took one queue");
        let (relay, item) = on_demand.try_recv().expect("the second rule's datagram");
        assert_eq!(relay, elsewhere, "queued for the wrong relay");
        assert!(matches!(item, Relayed::Packet { .. }));
    }

    /// **A peer on a relay this node has not dialled cannot stall every other
    /// peer.** Reaching it costs a TLS and ML-DSA-87 handshake before the first
    /// datagram moves, and if that backlog shared the home connection's queue it
    /// would be occupying the space the traffic that *does* have a connection is
    /// waiting in.
    #[test]
    fn a_relay_that_is_not_dialled_yet_cannot_fill_the_home_queue() {
        let (sender, mut home, _on_demand) = sender(2);
        let peer = [0xAA; karst_relay_proto::consts::ID_LEN];
        let elsewhere = [0xBB; karst_relay_proto::consts::ID_LEN];

        for _ in 0..8 {
            sender.send_via(Some(elsewhere), peer, b"backlog");
        }
        assert_eq!(
            sender.dropped.load(Ordering::Relaxed),
            6,
            "a bounded queue must drop rather than block the datapath"
        );

        sender.send_via(None, peer, b"and the home connection still has room");
        assert!(
            matches!(home.try_recv(), Ok(Relayed::Packet { .. })),
            "the home connection's queue was consumed by a relay nothing has dialled"
        );
    }
}

#[cfg(test)]
mod probe_tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    fn relay(tag: u8) -> crate::netmap::Relay {
        use sha2::{Digest as _, Sha256};
        let identity_key = vec![tag; 2592];
        let mut h = Sha256::new();
        h.update(b"karst-relay-id-v1");
        h.update(&identity_key);
        crate::netmap::Relay {
            address: format!("198.51.100.{tag}:443"),
            tls_server_name: "relay.test".to_owned(),
            relay_id: h.finalize().into(),
            identity_key,
            region: "test".to_owned(),
        }
    }

    /// An engine whose netmap carries `relays` and no peers.
    fn engine(relays: Vec<crate::netmap::Relay>) -> Engine {
        let config = Arc::new(crate::config::Config {
            relay_ca_file: None,
            metrics_listen: None,
            route_offers: Vec::new(),
            exit_node_state_file: None,
            keys: Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:0".parse().expect("addr"),
            port_mapping: false,
            interface: "karst0".to_owned(),
            network_mode: crate::config::NetworkMode::Tun,
            dns: crate::config::DnsSettings::default(),
            netmap_dns: crate::netmap::DNSConfig::default(),
            userspace_socks5_listen: None,
            userspace_publish: Vec::new(),
            nat64: None,
            addresses: vec!["100.64.0.1/16".parse().expect("address")],
            psk_epoch: 1,
            node_id: Vec::new(),
            relays,
            turn_servers: Vec::new(),
            peers: Vec::new(),
            routes: crate::routing::AllowedIps::build(Vec::new()).expect("no conflicts"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
        });
        Engine::new(&config)
    }

    struct Queues {
        sender: RelaySender,
        home: tokio::sync::mpsc::Receiver<Relayed>,
        on_demand: tokio::sync::mpsc::Receiver<(RelayId, Relayed)>,
    }

    fn queues() -> Queues {
        let (queue, home) = tokio::sync::mpsc::channel(64);
        let (on_demand_tx, on_demand) = tokio::sync::mpsc::channel(64);
        Queues {
            sender: RelaySender {
                queue,
                on_demand: on_demand_tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            home,
            on_demand,
        }
    }

    /// Distinct tokens, so two probes in one round are two probes.
    fn seeds() -> impl Fn() -> [u8; 32] {
        let n = std::sync::atomic::AtomicU8::new(0);
        move || [n.fetch_add(1, Ordering::Relaxed); 32]
    }

    fn pinged_home(q: &mut Queues) -> bool {
        matches!(q.home.try_recv(), Ok(Relayed::Ping(_)))
    }

    fn pinged_elsewhere(q: &mut Queues) -> Option<RelayId> {
        match q.on_demand.try_recv() {
            Ok((relay, Relayed::Ping(_))) => Some(relay),
            _ => None,
        }
    }

    /// One round measures the incumbent on the connection it is already on, and
    /// one alternative on a connection dialled for it. Both are needed: §9.2
    /// compares them against each other in the same round.
    #[test]
    fn a_round_measures_the_incumbent_and_one_alternative() {
        let engine = engine(vec![relay(1), relay(2), relay(3)]);
        engine.set_home_relay(Some(relay(1).relay_id));
        let mut q = queues();
        let rtt = Mutex::new(crate::home::Probes::default());
        let home = Mutex::new(crate::home::Selector::new());
        let mut rotation = crate::home::Rotation::default();

        probe_relays(
            &rtt,
            &home,
            &mut rotation,
            &engine,
            Some(&q.sender),
            1_000,
            seeds(),
        );

        assert!(
            pinged_home(&mut q),
            "the relay this node holds was not measured"
        );
        let candidate = pinged_elsewhere(&mut q).expect("no alternative was measured");
        assert_ne!(
            candidate,
            relay(1).relay_id,
            "the incumbent was measured twice, and would be compared against itself"
        );
        assert!([relay(2).relay_id, relay(3).relay_id].contains(&candidate));
    }

    /// A node whose registry holds one relay has no alternatives, and must not
    /// spend a Ponor handshake every round establishing that.
    #[test]
    fn a_lone_relay_is_not_measured_against_itself() {
        let engine = engine(vec![relay(1)]);
        engine.set_home_relay(Some(relay(1).relay_id));
        let mut q = queues();
        let rtt = Mutex::new(crate::home::Probes::default());
        let home = Mutex::new(crate::home::Selector::new());
        let mut rotation = crate::home::Rotation::default();

        for round in 0..6 {
            probe_relays(
                &rtt,
                &home,
                &mut rotation,
                &engine,
                Some(&q.sender),
                1_000 * (round + 1),
                seeds(),
            );
            // Drain the home probe so the table does not fill.
            let _ = q.home.try_recv();
            rtt.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .reset(relay(1).relay_id);
        }
        assert_eq!(
            pinged_elsewhere(&mut q),
            None,
            "a node with one relay dialled something"
        );
    }

    /// **A region does not narrow the candidates, and that is the design.**
    ///
    /// `ponor-v1.md` §9.1 selects a home relay by measuring RTT and §9.2 adds
    /// hysteresis; neither mentions the region, and this test exists so the
    /// omission reads as a decision rather than as something nobody got to.
    ///
    /// The reason is that **a region belongs to a relay and a node has none**.
    /// Nothing tells a node where it is, so a node filtering "its own region"
    /// would first have to infer one — and the only evidence available is
    /// latency, which is what selection already uses. Filtering would replace a
    /// direct measurement with a guess derived from it.
    ///
    /// Region is load-bearing elsewhere and untouched by this: §8 confines a
    /// mesh to one region, so two nodes whose home relays are in different
    /// regions reach each other by §9.1's second path — an on-demand connection
    /// to the peer's home relay — rather than through relay-to-relay
    /// forwarding. That is a cost of one connection, not a failure to connect.
    #[test]
    fn relays_from_another_region_are_measured_like_any_other() {
        let mut far = relay(2);
        far.region = "eu-west".to_owned();
        let mut farther = relay(3);
        farther.region = "ap-south".to_owned();
        let engine = engine(vec![relay(1), far.clone(), farther.clone()]);
        engine.set_home_relay(Some(relay(1).relay_id));

        // Every candidate is reached across enough rounds to rule out a filter
        // that merely happens to admit the first one.
        let mut seen = std::collections::BTreeSet::new();
        let mut q = queues();
        let rtt = Mutex::new(crate::home::Probes::default());
        let home = Mutex::new(crate::home::Selector::new());
        let mut rotation = crate::home::Rotation::default();
        for round in 0..40 {
            probe_relays(
                &rtt,
                &home,
                &mut rotation,
                &engine,
                Some(&q.sender),
                1_000 * (round + 1),
                seeds(),
            );
            let _ = q.home.try_recv();
            if let Some(id) = pinged_elsewhere(&mut q) {
                seen.insert(id);
            }
            // Clear the in-flight tokens, or MAX_OUTSTANDING_PROBES stops the
            // probes after two rounds and the test would conclude "filtered"
            // from a relay that was simply never asked again.
            let mut probes = rtt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for r in [&relay(1), &far, &farther] {
                probes.reset(r.relay_id);
            }
            drop(probes);
        }

        assert!(
            seen.contains(&far.relay_id) && seen.contains(&farther.relay_id),
            "a relay in another region was never measured; selection has grown a \
             region filter that §9.1 does not specify"
        );
    }

    /// **A relay that stops answering stops being asked.** The probe table is
    /// per relay, so this is measured as that relay's silence rather than as a
    /// node that ran out of patience with all of them.
    #[test]
    fn an_unanswered_relay_is_not_asked_forever() {
        let engine = engine(vec![relay(1), relay(2)]);
        engine.set_home_relay(Some(relay(1).relay_id));
        let mut q = queues();
        let rtt = Mutex::new(crate::home::Probes::default());
        let home = Mutex::new(crate::home::Selector::new());
        let mut rotation = crate::home::Rotation::default();

        let mut home_probes = 0;
        for round in 0..6 {
            probe_relays(
                &rtt,
                &home,
                &mut rotation,
                &engine,
                Some(&q.sender),
                1_000 * (round + 1),
                seeds(),
            );
            while pinged_home(&mut q) {
                home_probes += 1;
            }
        }
        assert_eq!(
            home_probes, 2,
            "nothing answered, so only the outstanding allowance should have been spent"
        );
    }

    /// The registry, not the configuration the daemon started with: a netmap
    /// that withdraws a relay must stop this node measuring it, or the choice
    /// could move onto somewhere peers are no longer told to look.
    #[test]
    fn a_withdrawn_relay_stops_being_a_candidate() {
        let engine = engine(vec![relay(1), relay(2)]);
        engine.set_home_relay(Some(relay(1).relay_id));
        let mut q = queues();
        let rtt = Mutex::new(crate::home::Probes::default());
        let home = Mutex::new(crate::home::Selector::new());
        let mut rotation = crate::home::Rotation::default();

        probe_relays(
            &rtt,
            &home,
            &mut rotation,
            &engine,
            Some(&q.sender),
            1_000,
            seeds(),
        );
        assert_eq!(pinged_elsewhere(&mut q), Some(relay(2).relay_id));

        // The netmap drops it.
        let smaller = Arc::new(crate::config::Config {
            relays: vec![relay(1)],
            ..engine_config(&engine)
        });
        let _ = engine.reconfigure(&smaller);
        probe_relays(
            &rtt,
            &home,
            &mut rotation,
            &engine,
            Some(&q.sender),
            2_000,
            seeds(),
        );
        assert_eq!(
            pinged_elsewhere(&mut q),
            None,
            "a relay the netmap withdrew was still being measured"
        );
    }

    // ── where the home connection belongs ───────────────────────────────

    #[test]
    fn a_choice_that_has_not_moved_moves_nothing() {
        let registry = vec![relay(1), relay(2)];
        assert!(
            home_target(Some(relay(1).relay_id), relay(1).relay_id, &registry).is_none(),
            "the connection was rebuilt for a choice that did not change"
        );
    }

    #[test]
    fn a_moved_choice_names_the_registry_entry_to_dial() {
        let registry = vec![relay(1), relay(2)];
        let target = home_target(Some(relay(2).relay_id), relay(1).relay_id, &registry)
            .expect("a relay to move to");
        assert_eq!(target.relay_id, relay(2).relay_id);
        assert_eq!(
            target.address,
            relay(2).address,
            "dialled without an address"
        );
    }

    /// A choice naming a relay the registry does not carry cannot be dialled:
    /// there is no address, TLS name or pinned key for it. Staying is the only
    /// answer that keeps this node reachable.
    #[test]
    fn a_choice_the_registry_lost_leaves_the_connection_where_it_is() {
        let registry = vec![relay(1)];
        assert!(home_target(Some(relay(2).relay_id), relay(1).relay_id, &registry).is_none());
    }

    /// **A node must not be left on a withdrawn relay.** `retain` releases the
    /// choice when the netmap drops it, and if nothing acted on that the node
    /// would sit on a relay its peers are no longer told to look at — reachable
    /// only by nodes that had not refreshed.
    #[test]
    fn a_withdrawn_relay_is_left_for_one_the_netmap_still_carries() {
        let registry = vec![relay(2), relay(3)];
        let target =
            home_target(None, relay(1).relay_id, &registry).expect("somewhere still listed");
        assert_eq!(target.relay_id, relay(2).relay_id);
    }

    /// Before anything has been measured the relay held is exactly where it
    /// should be. Moving then would be churn for its own sake.
    #[test]
    fn nothing_measured_yet_moves_nothing() {
        let registry = vec![relay(1), relay(2)];
        assert!(home_target(None, relay(1).relay_id, &registry).is_none());
    }

    // ── a relay that will not have this node ────────────────────────────

    /// **A node that cannot get onto its relay tries another.** §10.1 makes a
    /// roster miss indistinguishable from a relay that is down, so there is
    /// nothing to diagnose and nothing to wait for — and nothing else would
    /// ever dial the alternatives, since a relay with no connection is a relay
    /// with no measurements.
    #[test]
    fn a_relay_that_will_not_take_this_node_is_left_for_the_next() {
        let registry = vec![relay(1), relay(2), relay(3)];
        let next = next_relay(relay(1).relay_id, &registry).expect("somewhere else");
        assert_eq!(next.relay_id, relay(2).relay_id);
        let wrapped = next_relay(relay(3).relay_id, &registry).expect("back to the top");
        assert_eq!(wrapped.relay_id, relay(1).relay_id);
    }

    /// A node with one relay has nowhere to go and must keep trying: the roster
    /// it is missing from may be updated, and giving up on the only relay would
    /// make that unrecoverable.
    #[test]
    fn a_registry_of_one_leaves_nowhere_to_go() {
        assert!(next_relay(relay(1).relay_id, &[relay(1)]).is_none());
        assert!(next_relay(relay(1).relay_id, &[]).is_none());
    }

    /// A relay withdrawn while this node was on it has no position in the
    /// registry any more, so the search starts from the top rather than from
    /// somewhere that no longer means anything.
    #[test]
    fn a_relay_the_registry_dropped_starts_from_the_top() {
        let next = next_relay(relay(9).relay_id, &[relay(1), relay(2)]).expect("a relay");
        assert_eq!(next.relay_id, relay(1).relay_id);
    }

    /// Deliver a `Pong` for whatever was just asked, at `rtt_ms`, exactly as
    /// the receive loop does — token matched against the relay it went to, then
    /// handed to the selector.
    fn answer(
        rtt: &Mutex<crate::home::Probes>,
        home: &Mutex<crate::home::Selector>,
        relay: RelayId,
        item: &Relayed,
        now_ms: u64,
        rtt_ms: u64,
    ) {
        let Relayed::Ping(token) = *item else { return };
        let measured = rtt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve(relay, token, now_ms + rtt_ms);
        if let Some(measured) = measured {
            home.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .observe(relay, measured);
        }
    }

    /// **The whole of §9.2, driven a round at a time.** A relay four times
    /// faster is adopted, and not before the margin has been sustained.
    ///
    /// This is the daemon's own loop rather than the selector's: `home.rs`
    /// proves the rule and the rotation separately, and neither of them can see
    /// whether this file measures the same candidate on consecutive rounds. It
    /// did not have to — replacing the rotation with a fresh one each round
    /// leaves every unit test passing and makes every alternative permanently
    /// unadoptable, because a streak can never form.
    #[test]
    fn a_faster_relay_is_adopted_and_a_marginal_one_is_not() {
        for (challenger_rtt, adopted) in [(10, true), (85, false)] {
            let engine = engine(vec![relay(1), relay(2), relay(3)]);
            engine.set_home_relay(Some(relay(1).relay_id));
            let mut q = queues();
            let rtt = Mutex::new(crate::home::Probes::default());
            let home = Mutex::new(crate::home::Selector::new());
            let mut rotation = crate::home::Rotation::default();
            let mut measured = Vec::new();

            let rounds = 2 * u64::from(crate::home::PROBE_ROUNDS + crate::home::REST_ROUNDS);
            for round in 0..rounds {
                let now = 1_000 * (round + 1);
                probe_relays(
                    &rtt,
                    &home,
                    &mut rotation,
                    &engine,
                    Some(&q.sender),
                    now,
                    seeds(),
                );
                while let Ok(item) = q.home.try_recv() {
                    answer(&rtt, &home, relay(1).relay_id, &item, now, 100);
                }
                while let Ok((id, item)) = q.on_demand.try_recv() {
                    measured.push(id);
                    // Only relay(2) is fast. The other candidate is no better
                    // than the incumbent, so it must not move anything.
                    let rtt_ms = if id == relay(2).relay_id {
                        challenger_rtt
                    } else {
                        110
                    };
                    answer(&rtt, &home, id, &item, now, rtt_ms);
                }
            }

            let chosen = home
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .chosen();
            if adopted {
                assert_eq!(
                    chosen,
                    Some(relay(2).relay_id),
                    "a relay {challenger_rtt} ms against 100 ms was never adopted"
                );
            } else {
                assert_eq!(
                    chosen,
                    Some(relay(1).relay_id),
                    "switched on {challenger_rtt} ms against 100 ms, which is inside §9.2's margin"
                );
            }
            // Each candidate's turn is a run of consecutive rounds, long
            // enough for a margin to be sustained — and every candidate gets
            // one. A rotation that did not carry across rounds would keep
            // returning the first candidate and starve the rest, while looking
            // busy; one that moved every round would leave every alternative
            // permanently unadoptable.
            let mut runs: Vec<(RelayId, usize)> = Vec::new();
            for id in &measured {
                match runs.last_mut() {
                    Some((last, n)) if last == id => *n += 1,
                    _ => runs.push((*id, 1)),
                }
            }
            assert!(
                runs.iter()
                    .all(|(_, n)| *n >= karst_disco::consts::HYSTERESIS_SAMPLES as usize),
                "a candidate was measured for too few consecutive rounds to sustain a \
                 margin: {runs:?}"
            );
            if !adopted {
                let took_a_turn: std::collections::BTreeSet<_> =
                    runs.iter().map(|(id, _)| *id).collect();
                assert_eq!(
                    took_a_turn.len(),
                    2,
                    "a candidate never had a turn: {} of 2",
                    took_a_turn.len()
                );
            }
        }
    }

    /// **The relay this node is leaving stays reachable.** Peers go on dialling
    /// it until the netmap reaches them, and in that window their packets are
    /// not late — they are delivered nowhere. So the move hands the old relay
    /// to the on-demand pool, which lets it go once nothing arrives there.
    #[test]
    fn a_move_keeps_the_old_relay_reachable_meanwhile() {
        let engine = engine(vec![relay(1), relay(2)]);
        engine.set_home_relay(Some(relay(1).relay_id));
        let mut q = queues();

        handover(&engine, &q.sender, &relay(1), &relay(2));

        assert_eq!(
            engine.home_relay(),
            Some(relay(2).relay_id),
            "routing was not told where this node now is"
        );
        assert!(
            matches!(q.on_demand.try_recv(), Ok((id, Relayed::Hold)) if id == relay(1).relay_id),
            "the relay every peer still believes this node is on was dropped at once"
        );
    }

    /// The engine's current configuration, so a test can change one field of it.
    fn engine_config(engine: &Engine) -> crate::config::Config {
        let relays = engine.relays();
        crate::config::Config {
            relay_ca_file: None,
            metrics_listen: None,
            route_offers: Vec::new(),
            exit_node_state_file: None,
            keys: Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:0".parse().expect("addr"),
            port_mapping: false,
            interface: "karst0".to_owned(),
            network_mode: crate::config::NetworkMode::Tun,
            dns: crate::config::DnsSettings::default(),
            netmap_dns: crate::netmap::DNSConfig::default(),
            userspace_socks5_listen: None,
            userspace_publish: Vec::new(),
            nat64: None,
            addresses: vec!["100.64.0.1/16".parse().expect("address")],
            psk_epoch: 1,
            node_id: Vec::new(),
            relays,
            turn_servers: Vec::new(),
            peers: Vec::new(),
            routes: crate::routing::AllowedIps::build(Vec::new()).expect("no conflicts"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
        }
    }
}

/// The Bedrock section of a status report — `bedrock-v1.md` §5.
///
/// `equivocation_detected` above zero is the one counter in this report that
/// means something is wrong with the *coordination server* rather than with the
/// network: a peer holds a different log at a sequence this node also holds, so
/// the server has served two histories. §5 keeps the session up deliberately,
/// which means nothing else in the report would look unusual — and is exactly
/// why this is named in prose rather than left as a number in the counter
/// block.
///
/// Omitted entirely when no head exchange has happened, so a deployment not
/// running Bedrock is not told about a mechanism it does not use.
fn write_bedrock(
    out: &mut String,
    stats: &crate::engine::Stats,
    bedrock: Option<&crate::bedrock::Log>,
) {
    use std::fmt::Write as _;

    if stats.bedrock_equivocation == 0 && stats.bedrock_head_agreed == 0 && bedrock.is_none() {
        return;
    }
    let _ = writeln!(out, "\n[bedrock]");
    // Chain depth and anchor age mirror the server's own
    // management.karst.bedrock.chain.depth/.anchor.age.seconds
    // (plans/phase-6/08-observability.md §5 W6 item 3), so a node-side
    // report and a server-side scrape describe the same chain from two
    // vantage points.
    if let Some(log) = bedrock {
        let _ = writeln!(out, "chain_depth = {}", log.verified_seq());
        match log.last_anchored_at() {
            Some(anchored_at) => {
                let now = i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                )
                .unwrap_or(0);
                let _ = writeln!(
                    out,
                    "anchor_age_seconds = {}",
                    now.saturating_sub(anchored_at)
                );
            }
            None => {
                let _ = writeln!(out, "anchor_age_seconds = \"never anchored\"");
            }
        }
    }
    let _ = writeln!(out, "peers_agreeing = {}", stats.bedrock_head_agreed);
    let _ = writeln!(
        out,
        "equivocation_detected = {}",
        stats.bedrock_equivocation
    );
    if stats.bedrock_equivocation > 0 {
        let _ = writeln!(
            out,
            "note = \"EQUIVOCATION: a peer holds a different Bedrock log at a \
             sequence this node also holds. The coordination server has served \
             two histories. Sessions are left up deliberately; investigate \
             before trusting any coverage decision.\""
        );
    }
}
