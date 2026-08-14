// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The I/O loop — the only part of the daemon that touches the world.
//!
//! Two blocking reads have to proceed independently: a packet from the host and
//! a datagram from a peer arrive on unrelated schedules, and neither may be
//! starved by the other. That is two threads plus a timer, sharing the engine
//! by reference — **not behind a lock**. The engine synchronises per peer
//! internally, and an outer mutex here would serialise the whole datapath,
//! which is precisely the bottleneck PLAN.md §3.4 measured.
//!
//! An async runtime would do the same job with more machinery. The engine is
//! sans-io, so it can be moved onto `epoll`, `io_uring` or a runtime later
//! without touching anything below this file — which is the point of the
//! separation, and why this file is small enough to replace.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karst_noise::handshake::ResponderRandomness;
use karst_transport::{Received, UdpTransport, BATCH, MAX_DATAGRAM};
use karst_tun::{Tun, TunConfig};

use crate::config::Config;
use crate::engine::{Engine, Output};
use crate::ipc;
use crate::random_seed;

/// How often timers are advanced. Handshake retransmission starts at 300 ms
/// (§10), so this has to be comfortably finer than that.
const TICK: Duration = Duration::from_millis(100);

/// Read timeout on the UDP socket, so the receive thread notices a shutdown
/// request rather than blocking on a socket that will never speak again.
const POLL_TIMEOUT: Duration = Duration::from_millis(250);

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
pub fn run_with_control(
    config: &Arc<Config>,
    shutdown: &Shutdown,
    socket_path: &std::path::Path,
    control_client: Option<crate::control::Client>,
) -> io::Result<()> {
    let tun = bring_up_interface(config)?;

    let socket = UdpTransport::bind(config.listen)?;
    socket.set_read_timeout(Some(POLL_TIMEOUT))?;

    // Routes for anything outside the interface's own on-link prefix — a
    // subnet router, say. Without them the kernel sends that traffic to the
    // default gateway rather than to the tunnel, which is worse than dropping
    // it.
    let routes = Mutex::new(Routes::default());
    apply_routes(&routes, &tun, config);

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

    // Initial handshakes, before either thread starts.
    dispatch(
        engine.connect_all(now_ms(started), random_seed),
        &socket,
        &tun,
    );

    // The local settings the netmap does not supply. Cloned once here because
    // the refresh thread needs them on every reconfiguration and they never
    // change.
    let local = || crate::config::LocalSettings {
        keys: Arc::clone(&config.keys),
        listen: config.listen,
        interface: config.interface.clone(),
    };

    std::thread::scope(|scope| {
        // ── host → tunnel ──────────────────────────────────────────────────
        scope.spawn(|| {
            // Big enough for a coalesced read: the kernel may hand back up to
            // 64 KB behind one header.
            let mut buf = vec![0u8; 65_536 + 64];
            let mut packets: Vec<Vec<u8>> = Vec::new();
            while !shutdown.requested() {
                let Ok(count) = tun.recv_segments(&mut buf, &mut packets) else {
                    continue;
                };
                // One `Output` per read rather than per packet, so a coalesced
                // stream becomes one batched `sendmmsg`.
                let mut out = Output::default();
                for packet in packets.iter().take(count) {
                    let o = engine.outbound(packet, now_ms(started));
                    out.datagrams.extend(o.datagrams);
                    out.packets.extend(o.packets);
                }
                dispatch(out, &socket, &tun);
            }
        });

        // ── tunnel → host ──────────────────────────────────────────────────
        scope.spawn(|| {
            // Allocated once. `recvmmsg` fills as many as have arrived, so a
            // busy link costs one syscall per 32 datagrams instead of 32.
            let mut buffers = vec![[0u8; MAX_DATAGRAM]; BATCH];
            let mut meta: Vec<Received> = Vec::with_capacity(BATCH);
            while !shutdown.requested() {
                // A timeout here is normal and expected — it is what lets this
                // thread observe a shutdown request.
                let Ok(count) = socket.recv_batch(&mut buffers, &mut meta) else {
                    continue;
                };
                for i in 0..count {
                    let (Some(buf), Some(m)) = (buffers.get(i), meta.get(i)) else {
                        continue;
                    };
                    let Some(datagram) = buf.get(..m.len) else {
                        continue;
                    };
                    let out =
                        engine.inbound(datagram, m.from, now_ms(started), &responder_randomness());
                    dispatch(out, &socket, &tun);
                }
            }
        });

        // ── control socket ─────────────────────────────────────────────────
        scope.spawn(|| {
            while !shutdown.requested() {
                match control.accept() {
                    Ok((mut stream, _)) => {
                        // Back to blocking for the conversation itself: the
                        // non-blocking flag is inherited by accepted sockets,
                        // and a partial read here would be reported as an error
                        // rather than waited on.
                        let _ = stream.set_nonblocking(false);
                        let handled = ipc::serve(&mut stream, |command| {
                            report(command, config, &engine, tun.mtu(), started)
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
            let engine = &engine;
            let socket = &socket;
            let tun = &tun;
            let local = &local;
            let routes = &routes;
            scope.spawn(move || {
                refresh_netmap(
                    client, shutdown, engine, socket, tun, started, local, routes,
                );
            });
        }

        // ── timers ─────────────────────────────────────────────────────────
        while !shutdown.requested() {
            std::thread::sleep(TICK);
            dispatch(engine.poll(now_ms(started), random_seed), &socket, &tun);
        }
    });

    // The socket file outlives the process unless removed. Leaving it behind
    // makes the next start look like a stale-socket recovery rather than a
    // clean one.
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Update the installed routes, recovering from a poisoned lock.
///
/// A poisoned lock means a thread panicked while holding it; the tracked set is
/// plain data rather than a half-written buffer, so continuing with it beats
/// taking the tunnel down for every peer.
fn apply_routes(routes: &Mutex<Routes>, tun: &Tun, config: &Config) {
    routes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .apply(tun, config);
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
    fn wanted(config: &Config) -> std::collections::BTreeSet<(std::net::IpAddr, u8)> {
        let mut out = std::collections::BTreeSet::new();
        for peer in &config.peers {
            for range in &peer.allowed_ips {
                let on_link = config
                    .addresses
                    .iter()
                    .any(|a| a.network().contains(range.base()));
                if !on_link {
                    out.insert((range.base(), range.len()));
                }
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
    fn apply(&mut self, tun: &Tun, config: &Config) {
        let wanted = Self::wanted(config);

        for (dst, len) in self.0.difference(&wanted) {
            match tun.remove_route(*dst, *len) {
                Ok(()) => {}
                Err(e) => eprintln!("karstd: could not withdraw the route to {dst}/{len}: {e}"),
            }
        }
        let mut installed = std::collections::BTreeSet::new();
        for (dst, len) in &wanted {
            match tun.add_route(*dst, *len) {
                Ok(()) => {
                    installed.insert((*dst, *len));
                }
                Err(e) => eprintln!(
                    "karstd: could not route {dst}/{len} over the tunnel ({e}); \
                     that peer will be unreachable"
                ),
            }
        }
        self.0 = installed;
    }
}

/// Create the TUN device and give it its addresses.
fn bring_up_interface(config: &Config) -> io::Result<Tun> {
    let tun = Tun::create(&TunConfig {
        name: config.interface.clone(),
        // Segmentation offload, if the kernel offers it. One read can then
        // return a coalesced TCP stream instead of a single packet, which is
        // the syscall the datapath was bound by (PLAN.md §3.4).
        offload: true,
        ..TunConfig::default()
    })
    .map_err(|e| io::Error::other(e.to_string()))?;

    for addr in &config.addresses {
        // `addr.addr`, not the network: assigning the masked base would leave
        // the node without an address of its own.
        tun.set_address(addr.addr, addr.prefix_len)
            .map_err(|e| io::Error::other(e.to_string()))?;
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
pub fn status_report(config: &Config, engine: &Engine, mtu: usize, uptime_secs: u64) -> String {
    let _ = uptime_secs;
    report(ipc::Command::Status, config, engine, mtu, Instant::now())
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
    mtu: usize,
    uptime_secs: u64,
) -> String {
    let _ = uptime_secs;
    bug_report(config, engine, mtu, Instant::now())
}

fn report(
    command: ipc::Command,
    config: &Config,
    engine: &Engine,
    mtu: usize,
    started: Instant,
) -> String {
    use std::fmt::Write as _;

    match command {
        ipc::Command::Version => format!("version = \"{}\"\n", env!("CARGO_PKG_VERSION")),
        ipc::Command::Down => "stopping = true\n".to_owned(),
        ipc::Command::BugReport => bug_report(config, engine, mtu, started),
        ipc::Command::Status => {
            let stats = engine.stats();
            let peers = engine.status();

            let mut out = String::new();
            // Writing to a String is infallible; the `let _` keeps this
            // panic-free without an `unwrap` on every line.
            let _ = writeln!(out, "interface = \"{}\"", config.interface);
            // §13.6 requires the tunnel MTU be reportable: a path that
            // black-holes full-size packets is otherwise very hard to diagnose.
            let _ = writeln!(out, "mtu = {mtu}");
            let _ = writeln!(out, "listen = \"{}\"", config.listen);
            let _ = writeln!(out, "uptime_seconds = {}", started.elapsed().as_secs());
            let addrs: Vec<String> = config.addresses.iter().map(ToString::to_string).collect();
            let _ = writeln!(out, "addresses = {addrs:?}");
            let _ = writeln!(out, "psk_epoch = {}", config.psk_epoch);

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
            }
            out
        }
    }
}

/// Perform the I/O an engine asked for.
fn dispatch(out: Output, socket: &UdpTransport, tun: &Tun) {
    match out.datagrams.len() {
        0 => {}
        // One datagram is the common case on a single flow; batching it would
        // cost an extra `Vec` for nothing.
        1 => {
            if let Some((datagram, to)) = out.datagrams.first() {
                // A send failure is per-datagram: a full buffer or an
                // unreachable host must not take the daemon down. The protocol
                // already retransmits.
                let _ = socket.send_to(datagram, *to);
            }
        }
        // A handshake is two fragments and a burst can be more. One syscall.
        _ => {
            let batch: Vec<(&[u8], std::net::SocketAddr)> = out
                .datagrams
                .iter()
                .map(|(d, to)| (d.as_slice(), *to))
                .collect();
            let mut offset = 0;
            while offset < batch.len() {
                let Some(rest) = batch.get(offset..) else {
                    break;
                };
                match socket.send_batch(rest) {
                    // A short count is normal; resume from where it stopped.
                    Ok(0) | Err(_) => break,
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
#[allow(clippy::too_many_arguments)]
fn refresh_netmap(
    mut client: crate::control::Client,
    shutdown: &Shutdown,
    engine: &Engine,
    socket: &UdpTransport,
    tun: &Tun,
    started: Instant,
    local: &dyn Fn() -> crate::config::LocalSettings,
    routes: &Mutex<Routes>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("karstd: cannot start the control runtime; the netmap will not refresh");
        return;
    };

    let mut next = Instant::now() + crate::control::REFRESH;
    while !shutdown.requested() {
        // A short sleep rather than one long one, so a shutdown is noticed
        // promptly rather than a minute later.
        std::thread::sleep(TICK);
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + crate::control::REFRESH;

        let outcome = match runtime.block_on(client.sync()) {
            // Nothing moved. The overwhelmingly common case, and the one the
            // content-hash version exists to make cheap: no peer entry crosses
            // the wire.
            Ok(crate::netmap::Outcome::Unchanged) => continue,
            Ok(outcome) => outcome,
            Err(e) => {
                eprintln!("karstd: netmap refresh failed ({e}); retrying");
                continue;
            }
        };

        // The netmap arrived but cannot configure a datapath. Keeping the
        // previous roster is the right call: it works, and the alternative is a
        // node with no peers.
        let updated = match client.to_config(local()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("karstd: the new netmap is unusable ({e}); keeping the previous one");
                continue;
            }
        };

        let updated = Arc::new(updated);
        // Routes before the roster: a peer that becomes reachable should have
        // somewhere for its packets to go by the time the datapath will accept
        // them.
        apply_routes(routes, tun, &updated);
        let report = engine.reconfigure(&updated);
        eprintln!(
            "karstd: netmap updated ({outcome:?}): {} added, {} removed, {} kept{}",
            report.added,
            report.removed,
            report.kept,
            if report.epoch_rotated {
                ", psk epoch rotated"
            } else {
                ""
            }
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
fn announce(config: &Config, tun: &Tun, socket: &UdpTransport) -> io::Result<()> {
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
/// A bug report is the artefact most likely to be pasted into an issue tracker,
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
/// - **No setup key**, which is a bearer credential that enrols a node.
/// - **No file contents**, only paths and the facts derived from them.
fn bug_report(config: &Config, engine: &Engine, mtu: usize, started: Instant) -> String {
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
    let _ = writeln!(
        out,
        "kernel = \"{}\"",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|_| "unknown".to_owned(), |s| s.trim().to_owned())
    );
    let _ = writeln!(out, "arch = \"{}\"", std::env::consts::ARCH);

    let _ = writeln!(out, "\n[interface]");
    let _ = writeln!(out, "name = \"{}\"", config.interface);
    let _ = writeln!(out, "mtu = {mtu}");
    let _ = writeln!(out, "listen = \"{}\"", config.listen);
    let addrs: Vec<String> = config.addresses.iter().map(ToString::to_string).collect();
    let _ = writeln!(out, "addresses = {addrs:?}");

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
    }

    out
}

#[cfg(test)]
mod route_tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::Routes;
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
                public: std::sync::Arc::new(karst_noise::handshake::PeerPublic {
                    kem_pk: {
                        use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};
                        let seed = u8::try_from(index).unwrap_or(0).wrapping_add(0x22);
                        let (_, pk) = MlKem::keypair_from_seed(&[seed; 64]);
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
            });
        }
        Config {
            keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:51820".parse().expect("addr"),
            interface: "karst0".to_owned(),
            addresses: addresses
                .iter()
                .map(|a| a.parse().expect("interface address"))
                .collect(),
            psk_epoch: 1,
            peers,
            routes: crate::routing::AllowedIps::build(pairs).expect("no conflicts"),
            skipped: Vec::new(),
            filter: crate::filter::PacketFilter::unrestricted(),
        }
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
            Routes::wanted(&cfg).is_empty(),
            "both peers are inside the interface's /16"
        );
    }

    /// **The case routes exist for.** A subnet router advertises a range
    /// nowhere near the tailnet's own prefix; without a route the kernel sends
    /// that traffic to the default gateway instead of the tunnel.
    #[test]
    fn a_peer_outside_the_prefix_needs_one() {
        let cfg = config(
            &["100.64.0.1/16"],
            &[&["100.64.0.2/32"], &["192.168.1.0/24"]],
        );
        let wanted = Routes::wanted(&cfg);
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
        let wanted = Routes::wanted(&cfg);
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
        assert_eq!(Routes::wanted(&cfg).len(), 2);
    }

    /// A node with no peers routes nothing — and in particular does not install
    /// a default route, which is what a `/0` would silently become.
    #[test]
    fn an_empty_roster_routes_nothing() {
        assert!(Routes::wanted(&config(&["100.64.0.1/16"], &[])).is_empty());
    }
}
