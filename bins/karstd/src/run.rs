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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karst_disco::TxId;
use karst_noise::handshake::ResponderRandomness;
use karst_portmap::Protocol;
use karst_transport::{Received, UdpTransport, BATCH, MAX_DATAGRAM};
use karst_tun::{Tun, TunConfig};

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
    let (relay_out, relay_in) = match relay {
        Some(_) => {
            let (tx, rx) = tokio::sync::mpsc::channel(RELAY_QUEUE);
            (
                Some(RelaySender {
                    queue: tx,
                    dropped: Arc::clone(&relay_dropped),
                }),
                Some(rx),
            )
        }
        None => (None, None),
    };
    let relay_out = relay_out.as_ref();

    // Initial handshakes, before any thread starts.
    dispatch(
        engine.connect_all(now_ms(started), random_seed),
        &socket,
        &tun,
        relay_out,
    );

    // The local settings the netmap does not supply. Cloned once here because
    // the refresh thread needs them on every reconfiguration and they never
    // change.
    let local = || crate::config::LocalSettings {
        keys: Arc::clone(&config.keys),
        listen: config.listen,
        port_mapping: config.port_mapping,
        interface: config.interface.clone(),
        relay_ca_file: config.relay_ca_file.clone(),
    };
    // The control client owns the ML-DSA identity. Clone its `Arc` before the
    // refresh worker takes ownership of the client, so the relay reader can
    // authenticate independently without reading the secret file again.
    let relay_identity = control_client
        .as_ref()
        .map(crate::control::Client::relay_identity);

    std::thread::scope(|scope| {
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
                dispatch(out, socket_host, tun_host, relay_out);
            }
        });

        // ── the relay ─────────────────────────────────────────────────────
        // Both protocols and both directions. AVEN's rendezvous made this
        // connection necessary; PHREATIC's fallback is what makes a peer with
        // no direct path reachable rather than merely known about.
        if let (Some(identity), Some(relay), Some(relay_in), Some(relayed)) =
            (relay_identity, relay, relay_in, relay_out)
        {
            let disco = &disco;
            let engine = &engine;
            let socket = &socket;
            let tun = &tun;
            scope.spawn(move || {
                relay_worker(
                    RelayContext {
                        shutdown,
                        identity,
                        relay,
                        node_id: relay_node_id,
                        relay_ca_file: relay_ca,
                        disco,
                        engine,
                        socket,
                        tun,
                        relayed,
                        started,
                    },
                    relay_in,
                );
            });
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
                    dispatch(out, socket_rx, tun_rx, relay_out);
                }
            }
        });

        // ── control socket ─────────────────────────────────────────────────
        let engine_ctl = &engine;
        let tun_ctl = &tun;
        let portmap_state = &portmap;
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
                            report(
                                command,
                                config,
                                engine_ctl,
                                tun_ctl.mtu(),
                                started,
                                &relay_dropped,
                                Some(portmap_state.snapshot()),
                            )
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
                    relay_out,
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
        while !shutdown.requested() {
            std::thread::sleep(TICK);
            let now = now_ms(started);
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
            dispatch(engine.poll(now, random_seed), &socket, &tun, relay_out);
            dispatch(disco_poll(&disco, now, relay_out), &socket, &tun, relay_out);
            apply_disco_paths(&disco, &engine);
        }
    });

    // The socket file outlives the process unless removed. Leaving it behind
    // makes the next start look like a stale-socket recovery rather than a
    // clean one.
    let _ = std::fs::remove_file(socket_path);
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
fn disco_poll(disco: &Mutex<disco::Disco>, now_ms: u64, relay: Option<&RelaySender>) -> Output {
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
            relay.send(destination, &payload);
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
struct Relayed {
    destination: [u8; karst_relay_proto::consts::ID_LEN],
    payload: Vec<u8>,
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
    dropped: Arc<AtomicU64>,
}

impl RelaySender {
    fn send(&self, destination: [u8; karst_relay_proto::consts::ID_LEN], payload: &[u8]) {
        let relayed = Relayed {
            destination,
            payload: payload.to_vec(),
        };
        if self.queue.try_send(relayed).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

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
struct RelayContext<'a> {
    shutdown: &'a Shutdown,
    identity: Arc<crate::control::Identity>,
    relay: crate::netmap::Relay,
    node_id: Vec<u8>,
    disco: &'a Mutex<disco::Disco>,
    engine: &'a Engine,
    socket: &'a UdpTransport,
    tun: &'a Tun,
    /// Extra trust anchors for the TLS hop, from local configuration.
    relay_ca_file: Option<std::path::PathBuf>,
    /// Where a reply to a relayed datagram goes when it is itself relayed —
    /// which every response to a relayed handshake is, until a direct path
    /// exists. Sending is non-blocking, so the receive task may use it.
    relayed: &'a RelaySender,
    started: Instant,
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
fn relay_worker(context: RelayContext<'_>, outbound: tokio::sync::mpsc::Receiver<Relayed>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("karstd: cannot start relay runtime; the relay path is disabled");
        return;
    };
    let tls = match crate::relay_tls::client_config(context.relay_ca_file.as_deref()) {
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
    while !context.shutdown.requested() {
        let session = crate::relay::Session::from_control_handle(
            &context.node_id,
            &context.relay,
            random_seed(),
        );
        let Some(session) = session else {
            eprintln!("karstd: invalid node handle; the relay path is disabled");
            return;
        };
        let connected = runtime.block_on(crate::relay::Connection::connect(
            session,
            &*context.identity,
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
                if backoff == RELAY_BACKOFF_MIN {
                    eprintln!(
                        "karstd: cannot reach relay {} ({e}); retrying",
                        context.relay.address
                    );
                }
                sleep_backoff(context.shutdown, &mut backoff);
                continue;
            }
        };
        let Some((sender, receiver)) = connection.split() else {
            // Unreachable through `connect`, which loops until established.
            // Treated as a failed attempt rather than asserted, because this is
            // a daemon carrying traffic and the alternative to being wrong here
            // is a panic in a thread nothing restarts.
            sleep_backoff(context.shutdown, &mut backoff);
            continue;
        };
        // Reset only once a connection is actually established. Resetting on
        // the *attempt* would make a relay that accepts and immediately closes
        // — an overloaded one, or one mid-restart — into an unthrottled
        // reconnect loop from every node at once, which is the load pattern
        // most likely to keep it down.
        if backoff != RELAY_BACKOFF_MIN {
            eprintln!("karstd: relay {} reachable again", context.relay.address);
        }
        backoff = RELAY_BACKOFF_MIN;

        runtime.block_on(async {
            tokio::join!(
                relay_send_loop(context.shutdown, sender, &mut outbound),
                relay_receive_loop(&context, receiver),
            )
        });

        // §7.7: the reflect key died with the connection. Keeping it would
        // mean probing a reflector that has already forgotten this node, and
        // advertising a mapping nothing is keeping alive.
        context
            .disco
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear_reflector(&context.relay.relay_id);
    }
}

/// Drain the queue onto the relay until it breaks or the daemon stops.
async fn relay_send_loop(
    shutdown: &Shutdown,
    mut sender: crate::relay::Sender,
    outbound: &mut tokio::sync::mpsc::Receiver<Relayed>,
) {
    while !shutdown.requested() {
        // A short timeout rather than a bare `recv`, so a quiet connection
        // still notices a shutdown request.
        let Ok(next) = tokio::time::timeout(TICK, outbound.recv()).await else {
            continue;
        };
        let Some(next) = next else { return };
        if sender
            .send_packet(next.destination, &next.payload)
            .await
            .is_err()
        {
            return;
        }
        // **Coalesce whatever else is already queued before flushing.** A
        // flush per datagram is a TLS record and a syscall each; a burst of
        // fragments belonging to one handshake should cost one of each.
        while let Ok(more) = outbound.try_recv() {
            if sender
                .send_packet(more.destination, &more.payload)
                .await
                .is_err()
            {
                return;
            }
        }
        if sender.flush().await.is_err() {
            return;
        }
    }
}

/// Deliver what the relay forwards to whichever protocol owns it.
async fn relay_receive_loop(context: &RelayContext<'_>, mut receiver: crate::relay::Receiver) {
    while !context.shutdown.requested() {
        let received = tokio::time::timeout(
            TICK,
            receiver.receive(&*context.identity, &crate::control::RelayVerifier),
        )
        .await;
        let events = match received {
            Ok(Ok(events)) => events,
            // A timeout is the normal case, not a failure: it is what lets this
            // loop notice a shutdown on a connection that happens to be quiet.
            Err(_) => continue,
            Ok(Err(_)) => return,
        };
        for event in events {
            // §7.7: this relay runs a reflector, and here is the key. Handed
            // straight to discovery — the address inside is AVEN's encoding,
            // and `karst-disco` owns that.
            if let crate::relay::Event::Reflector { key, endpoint } = event {
                let Ok(endpoint) = karst_disco::Endpoint::from_wire(&endpoint) else {
                    // A relay this node authenticated sent an endpoint it
                    // cannot parse. Nothing to do but ignore the offer; the
                    // connection is still good for carrying traffic, which is
                    // what it is chiefly for.
                    continue;
                };
                let taken = context
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
                continue;
            }
            let crate::relay::Event::Packet { source_id, payload } = event else {
                continue;
            };
            let now = now_ms(context.started);
            // **AVEN is asked first, exactly as on the UDP socket**, and for the
            // same reason: the two protocols share this transport too, and only
            // one of them can authenticate any given datagram. `Disco` reports
            // whether the payload was its own; anything else is PHREATIC's.
            let handled = context
                .disco
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .inbound_from_relay(source_id, &payload, now);
            if handled {
                continue;
            }
            let out = context.engine.inbound_from_relay(
                source_id,
                &payload,
                now,
                &responder_randomness(),
            );
            // **The reply goes back over the relay**, and it has to: the
            // response to a relayed `HandshakeInit` is what completes the
            // handshake, and until it does there is no session and no direct
            // path to upgrade to. The engine has already chosen the transport,
            // so this only has to honour it — and the queue is non-blocking, so
            // handing work to the send task cannot stall this one.
            dispatch(out, context.socket, context.tun, Some(context.relayed));
        }
    }
}

/// Apply only AVEN-confirmed paths to the PHREATIC roster. Candidates never
/// reach this boundary, so an unauthenticated endpoint cannot redirect data.
fn apply_disco_paths(disco: &Mutex<disco::Disco>, engine: &Engine) {
    let changes = disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .path_changes();
    apply_path_changes(&changes, engine);
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
    report(
        ipc::Command::Status,
        config,
        engine,
        mtu,
        Instant::now(),
        &AtomicU64::new(0),
        Some(portmap::Snapshot::new(config.port_mapping)),
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
    mtu: usize,
    uptime_secs: u64,
) -> String {
    let _ = uptime_secs;
    bug_report(config, engine, mtu, Instant::now(), &AtomicU64::new(0))
}

#[allow(clippy::too_many_lines)]
fn report(
    command: ipc::Command,
    config: &Config,
    engine: &Engine,
    mtu: usize,
    started: Instant,
    relay_dropped: &AtomicU64,
    portmap: Option<portmap::Snapshot>,
) -> String {
    use std::fmt::Write as _;

    match command {
        ipc::Command::Version => format!("version = \"{}\"\n", env!("CARGO_PKG_VERSION")),
        ipc::Command::Down => "stopping = true\n".to_owned(),
        ipc::Command::BugReport => bug_report(config, engine, mtu, started, relay_dropped),
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
fn dispatch(out: Output, socket: &UdpTransport, tun: &Tun, relay: Option<&RelaySender>) {
    let mut direct: Vec<(&[u8], std::net::SocketAddr)> = Vec::with_capacity(out.datagrams.len());
    for (datagram, via) in &out.datagrams {
        match via {
            Via::Direct(to) => direct.push((datagram.as_slice(), *to)),
            Via::Relay(destination) => {
                if let Some(relay) = relay {
                    relay.send(*destination, datagram);
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
    disco: &Mutex<disco::Disco>,
    relayed: Option<&RelaySender>,
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
            relayed,
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
fn bug_report(
    config: &Config,
    engine: &Engine,
    mtu: usize,
    started: Instant,
    relay_dropped: &AtomicU64,
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
    let _ = writeln!(
        out,
        "relay_dropped = {}",
        relay_dropped.load(Ordering::Relaxed)
    );

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
                node_id: Vec::new(),
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
                disco_key: None,
            });
        }
        Config {
            relay_ca_file: None,
            keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(
                &[0x11; 64],
                &[0x12; 32],
            )),
            listen: "0.0.0.0:51820".parse().expect("addr"),
            port_mapping: true,
            interface: "karst0".to_owned(),
            addresses: addresses
                .iter()
                .map(|a| a.parse().expect("interface address"))
                .collect(),
            psk_epoch: 1,
            node_id: Vec::new(),
            relays: Vec::new(),
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
    /// nowhere near the aquifer's own prefix; without a route the kernel sends
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
}
