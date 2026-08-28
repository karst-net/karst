// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The listener and the per-connection driver.
//!
//! This is the only module in the crate that touches a socket or a clock.
//! Everything it decides has already been decided somewhere testable: framing
//! in `karst-relay-proto`, admission in [`crate::roster`], forwarding and
//! queueing in [`crate::hub`]. What is left here is genuinely I/O — accept,
//! upgrade, hand bytes to the hub, write what the hub produces.
//!
//! # Waking the right sockets
//!
//! The hub is pull-based and holds the queues, so a connection task has to be
//! told when there is something to write for it. [`Hub::take_dirty`] names the
//! connections whose queues grew, and this module maps those to per-connection
//! [`Notify`] handles. The alternative — waking every task after every frame —
//! makes a relay's cost quadratic in its client count, which is the wrong
//! shape for the component whose whole job is to carry other people's traffic.
//!
//! # Locking
//!
//! One `std::sync::Mutex` around the hub and the waker table, never held
//! across an `await`. A frame's worth of work under it is a map lookup and a
//! `VecDeque` push; an async mutex would add a scheduling hop to buy fairness
//! nothing here needs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use karst_relay_proto::consts::{
    FRAME_HEADER, FRAME_PAYLOAD_MAX, HANDSHAKE_TIMEOUT_SECS, IDLE_TIMEOUT_SECS,
};
use karst_relay_proto::{frame::decode, Admitted, Frame, Reason, RelayHandshake, Roster};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Notify};

use crate::config::Config;
use crate::http;
use crate::hub::{ConnId, Hub};
use crate::reflect::Reflector;
use crate::roster::{FileRoster, Source as RosterSource};
use crate::sign::{Identity, PonorVerifier};
use crate::tls;

/// Bytes read per syscall.
const CHUNK: usize = 8192;

/// Largest the read buffer may grow to.
///
/// A whole frame is at most `FRAME_HEADER + FRAME_PAYLOAD_MAX`, and a read can
/// overshoot by one chunk. Anything beyond that means the peer is sending
/// faster than the decoder consumes, which for a protocol with no frame larger
/// than 4 KB means it is not speaking Ponor.
const READ_BUF_MAX: usize = FRAME_HEADER + FRAME_PAYLOAD_MAX + 2 * CHUNK;
/// How often the trusted roster file is polled for an atomic replacement.
const ROSTER_POLL: Duration = Duration::from_secs(5);

// Asserted at compile time rather than in a test, so a future change to any of
// the three constants cannot produce a relay that stalls a valid peer.
const _: () = {
    // It has to hold the largest legal frame, or a peer sending one waits
    // forever for a decoder that will never see it whole.
    assert!(READ_BUF_MAX > FRAME_HEADER + FRAME_PAYLOAD_MAX);
    // And it must stay small, because it is per connection and allocated
    // before the peer has proved anything.
    assert!(READ_BUF_MAX < 64 * 1024);
    // An unauthenticated connection is worth less patience than an
    // authenticated one: it holds a slot and has proved nothing.
    assert!(HANDSHAKE_TIMEOUT_SECS < IDLE_TIMEOUT_SECS);
};

/// Shared mutable state. See the locking note above.
struct Shared {
    hub: Hub,
    wakers: HashMap<ConnId, Arc<Notify>>,
}

/// Everything a connection task needs.
///
/// Public so an integration test can build one and drive [`serve_on`]; its
/// fields stay private.
pub struct Ctx {
    shared: Mutex<Shared>,
    roster: RwLock<Arc<FileRoster>>,
    roster_updates: watch::Sender<u64>,
    identity: Arc<Identity>,
    tls: Arc<rustls::ServerConfig>,
    started: Instant,
    /// Which region this relay serves — §8.
    region: String,
    next_conn: AtomicU64,
    /// `None` unless the operator configured one — `config::Reflect`.
    ///
    /// Its own lock rather than a field in [`Shared`]: the reflector is driven
    /// by a UDP task that runs at AVEN's rate on every client at once, and the
    /// hub's lock is on the forwarding path. Sharing one would make a reflect
    /// datagram contend with every packet the relay carries, to protect two
    /// structures that never refer to each other.
    reflect: Option<Mutex<Reflector>>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Connection counts, not the roster and not the identity.
        let (clients, mesh) = self
            .shared
            .lock()
            .map_or((0, 0), |g| (g.hub.local_clients(), g.hub.mesh_peers()));
        f.debug_struct("Ctx")
            .field("clients", &clients)
            .field("mesh_peers", &mesh)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    /// Assemble the shared state a relay runs on.
    #[must_use]
    pub fn new(
        cfg: &Config,
        identity: Arc<Identity>,
        roster: Arc<FileRoster>,
        tls: Arc<rustls::ServerConfig>,
    ) -> Arc<Self> {
        let (roster_updates, _) = watch::channel(0);
        Arc::new(Self {
            shared: Mutex::new(Shared {
                hub: Hub::new(cfg.hub()),
                wakers: HashMap::new(),
            }),
            roster: RwLock::new(roster),
            roster_updates,
            identity,
            tls,
            started: Instant::now(),
            region: cfg.region.clone(),
            next_conn: AtomicU64::new(1),
            reflect: cfg
                .reflect
                .as_ref()
                .map(|r| Mutex::new(Reflector::new(r.advertised()))),
        })
    }

    fn now_ms(&self) -> u64 {
        // Monotonic and unaffected by wall-clock adjustment, which matters
        // because the rate limiter reads it: a clock step backwards must not
        // mint tokens, and a step forwards must not hand out a year of them.
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Wake every connection whose queue grew, then clear the list.
    fn wake_dirty(&self) {
        let handles: Vec<Arc<Notify>> = {
            let mut g = match self.shared.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let ids = g.hub.take_dirty();
            ids.iter()
                .filter_map(|id| g.wakers.get(id).cloned())
                .collect()
        };
        for h in handles {
            h.notify_one();
        }
    }

    fn with_reflector<T>(&self, f: impl FnOnce(&mut Reflector) -> T) -> Option<T> {
        let lock = self.reflect.as_ref()?;
        let mut g = match lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(f(&mut g))
    }

    /// The `ReflectOffer` to send this client, if this relay has a reflector.
    ///
    /// Mints on the way out, so the key exists only for a connection that has
    /// actually reached this point — past TLS, past the upgrade, past the
    /// handshake.
    fn reflect_offer(&self, admitted: &Admitted) -> Option<Vec<u8>> {
        // Clients only. §7.7 offers nothing to a mesh peer: a relay does not
        // discover paths, and a key minted for one would be a credential with
        // no user.
        let Admitted::Client { node_id, .. } = admitted else {
            return None;
        };
        let now = self.now_ms();
        let key = self.with_reflector(|r| r.mint(*node_id, now))?;
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                // Loud, and not fatal. A relay that cannot mint a reflect key
                // can still carry this node's traffic, which is the service it
                // exists for; refusing the connection would turn a degraded
                // reflector into an outage.
                eprintln!("karst-relay: {e}");
                return None;
            }
        };
        let endpoint = self.with_reflector(|r| r.wire_endpoint())?;
        Some(
            Frame::ReflectOffer {
                reflect_key: key,
                endpoint,
            }
            .to_vec(),
        )
    }

    /// A point-in-time view for the metrics endpoint.
    ///
    /// Takes the hub lock once and copies out, rather than holding it across a
    /// render: the lock is on the forwarding path, and a scrape must not make
    /// every client wait on string formatting.
    /// Whether a mesh peer serves this relay's region — §8.
    ///
    /// A peer absent from the roster cannot be admitted at all, so `false` here
    /// is a belt-and-braces answer rather than the load-bearing one.
    fn same_region(&self, relay_id: &crate::mesh::Id) -> bool {
        let roster = match self.roster.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        roster.mesh_region(relay_id) == Some(self.region.as_str())
    }

    fn snapshot(&self) -> crate::metrics::Snapshot {
        let (local_clients, mesh_peers, remote_clients, totals) = self.with_hub(|hub| {
            (
                hub.local_clients(),
                hub.mesh_peers(),
                hub.remote_clients(),
                hub.totals(),
            )
        });
        crate::metrics::Snapshot {
            local_clients,
            mesh_peers,
            remote_clients,
            totals,
            uptime_secs: self.started.elapsed().as_secs(),
        }
    }

    fn with_hub<T>(&self, f: impl FnOnce(&mut Hub) -> T) -> T {
        let mut g = match self.shared.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut g.hub)
    }

    fn roster(&self) -> Arc<FileRoster> {
        match self.roster.read() {
            Ok(roster) => Arc::clone(&roster),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Install a complete, already-validated roster and wake every connection.
    ///
    /// A reload is an admission boundary: existing clients removed from it (or
    /// moved to another aquifer) are closed, not grandfathered in.
    pub fn replace_roster(&self, roster: FileRoster) {
        match self.roster.write() {
            Ok(mut current) => *current = Arc::new(roster),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(roster),
        }
        self.roster_updates
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    fn remains_admitted(&self, admitted: &Admitted) -> bool {
        let roster = self.roster();
        match admitted {
            Admitted::Client { node_id, aquifer } => roster
                .client(node_id)
                .is_some_and(|entry| entry.aquifer == *aquifer),
            Admitted::Mesh { relay_id } => roster.mesh_peer(relay_id).is_some(),
        }
    }
}

/// Run the relay until the process is asked to stop.
///
/// # Errors
/// Anything that stops the listener from starting: a certificate that will not
/// load, a roster that will not parse, an address already in use.
pub async fn run(cfg: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity = Arc::new(Identity::load_or_create(&cfg.identity_key)?);
    let (roster_source, roster) = RosterSource::open(&cfg.roster)?;
    let roster = Arc::new(roster);
    let tls_config = tls::server_config(&cfg.tls_cert, &cfg.tls_key)?;

    let provider = tls::provider()?;
    if !tls::post_quantum_is_preferred(&provider) {
        // Offered-but-not-first is a real and weak configuration: the client
        // chooses, so one that prefers speed gets a classical exchange from a
        // relay whose operator believes it is post-quantum. Loud, not fatal.
        eprintln!(
            "karst-relay: warning: X25519MLKEM768 is offered but not preferred; \
             clients may negotiate a classical key exchange"
        );
    }

    let ctx = Ctx::new(cfg, identity, roster, tls_config);
    tokio::spawn(roster_loop(roster_source, Arc::clone(&ctx)));

    if let Some(r) = &cfg.reflect {
        // Bound before the TCP listener, and fatal if it fails. A relay
        // configured with a reflector that silently is not running hands every
        // client a `ReflectOffer` naming an address nothing answers, and the
        // symptom is nodes that never leave the relay — which looks exactly
        // like having no reflector configured at all.
        let socket = UdpSocket::bind(r.listen).await?;
        eprintln!(
            "karst-relay: reflector on {} (advertising {})",
            socket.local_addr()?,
            r.advertised()
        );
        tokio::spawn(reflect_loop(socket, Arc::clone(&ctx)));
    }

    if let Some(m) = &cfg.metrics {
        // Bound before the client listener and fatal on failure, for the same
        // reason the reflector is: a relay whose metrics endpoint silently is
        // not running looks, to whatever is scraping it, exactly like a relay
        // that has stopped.
        let listener = TcpListener::bind(m.listen).await?;
        eprintln!("karst-relay: metrics on {}", listener.local_addr()?);
        tokio::spawn(metrics_loop(listener, Arc::clone(&ctx)));
    }

    if let Some(mesh) = &cfg.mesh {
        // A trust anchor that cannot be read is a relay that will never mesh,
        // and finding that out at the first dial rather than at startup means
        // finding it out from a log line nobody is reading.
        let client_tls = crate::tls::client_config(&mesh.ca)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let dialler = crate::mesh::Dialler::new(ctx.identity.relay_id(), cfg.region.clone());
        eprintln!("karst-relay: mesh dialling enabled");
        tokio::spawn(mesh_loop(Arc::clone(&ctx), client_tls, dialler));
    }

    let listener = TcpListener::bind(cfg.listen).await?;
    serve_on(listener, ctx).await
}

/// Serve `GET /metrics` until the process ends.
///
/// **One request per connection, and a short read timeout.** This is an
/// unauthenticated listener: a client that connects and says nothing must cost
/// a socket for seconds rather than for ever, or a handful of them is a denial
/// of service against the operator's visibility at the moment they need it
/// most. Nothing here touches the roster or the identity, and a failure is
/// logged and dropped rather than propagated — metrics going away must never
/// take the relay with them.
pub async fn metrics_loop(listener: TcpListener, ctx: Arc<Ctx>) {
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            continue;
        };
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
            )
            .await;
            let n = match read {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
            let line = request.lines().next().unwrap_or_default();
            let body = if crate::metrics::wants_metrics(line) {
                crate::metrics::http_response(&crate::metrics::render(&ctx.snapshot()))
            } else {
                crate::metrics::http_not_found()
            };
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, body.as_bytes()).await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        });
    }
}

/// Keep admission current without making a relay restart an availability
/// dependency. Invalid replacements never become active; a missing refresh
/// eventually does, by replacing the roster with one that admits nobody.
async fn roster_loop(mut source: RosterSource, ctx: Arc<Ctx>) {
    let mut poll = tokio::time::interval(ROSTER_POLL);
    poll.tick().await; // interval's first tick is immediate; do not reload twice at start.
    let mut failed_closed = false;
    loop {
        poll.tick().await;
        match source.reload() {
            Ok(Some(roster)) => {
                ctx.replace_roster(roster);
                failed_closed = false;
                eprintln!("karst-relay: roster reloaded");
            }
            Ok(None) => {}
            Err(err) => eprintln!("karst-relay: roster reload failed: {err}"),
        }
        if source.expired() && !failed_closed {
            eprintln!("karst-relay: roster lease expired; admitting nobody until a valid reload");
            ctx.replace_roster(FileRoster::empty());
            failed_closed = true;
        }
    }
}

/// Answer `Reflect` datagrams — `aven-v1.md` §7.6.
///
/// Every decision is [`Reflector::handle`]'s; this is the socket around it.
/// The buffer is one AVEN datagram wide, so an over-long datagram is truncated
/// by the kernel and fails to parse rather than being read into memory this
/// task sized from an attacker's send.
pub async fn reflect_loop(socket: UdpSocket, ctx: Arc<Ctx>) {
    let mut buf = [0u8; karst_disco::consts::DATAGRAM_MAX];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            // A UDP receive error is per-datagram — ICMP unreachable from an
            // earlier send, most often. Continuing is right; returning would
            // end the reflector for every client because one of them went
            // away.
            continue;
        };
        let Some(datagram) = buf.get(..n) else {
            continue;
        };
        let now = ctx.now_ms();
        let Some(Ok(reply)) = ctx.with_reflector(|r| r.handle(datagram, from, now)) else {
            // §10: every failure is a silent drop, with no log line at default
            // verbosity. This runs on an unfiltered UDP port, where a line per
            // dropped datagram is a disk-filling primitive available to anyone
            // who can reach it.
            continue;
        };
        let _ = socket.send_to(&reply, from).await;
    }
}

/// Serve on an already-bound listener.
///
/// Split out from [`run`] so a test can bind port zero and learn which port it
/// got. A relay that can only be exercised on :443 is a relay whose accept
/// loop is never tested.
///
/// # Errors
/// If the listener cannot report its own address. A failed `accept` is logged
/// and skipped rather than returned: it is one client's problem, and exiting
/// would turn a transient descriptor shortage into an outage.
pub async fn serve_on(
    listener: TcpListener,
    ctx: Arc<Ctx>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "karst-relay: listening on {} (relay_id {})",
        listener.local_addr()?,
        hex(&ctx.identity.relay_id())
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    // A failed accept is one client's problem, not the
                    // relay's. Exiting here would turn a transient descriptor
                    // shortage into an outage.
                    Err(e) => { eprintln!("karst-relay: accept: {e}"); continue }
                };
                let ctx = Arc::clone(&ctx);
                // **Boxed.** `serve` runs the TLS handshake, the Ponor
                // handshake and then the connection loop, and an async fn's
                // future holds every local that lives across an await — so this
                // one is the sum of all three. It was close enough to a thread
                // stack's limit that doubling the frame cap for ML-DSA-87
                // (ADR-0015) overflowed it. Boxing moves the state machine to
                // the heap, where growing it is a bounded cost rather than a
                // cliff. FINDINGS 58.
                tokio::spawn(Box::pin(async move { serve(stream, peer, ctx).await }));
            }
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    eprintln!("karst-relay: shutting down");
                }
                return Ok(());
            }
        }
    }
}

async fn serve(stream: TcpStream, peer: SocketAddr, ctx: Arc<Ctx>) {
    // One deadline over TLS, the HTTP upgrade and the Ponor handshake
    // together. §7.1 bounds only the last of the three, but a connection slot
    // is the scarce resource and a peer that stalls in the first two consumes
    // one just as effectively.
    let deadline = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let Ok(Some((tls_stream, buf, admitted))) =
        tokio::time::timeout(deadline, establish(stream, &ctx)).await
    else {
        // Either the peer stalled or it was refused. Both close silently.
        return;
    };
    // §8's regional boundary, on the accepting side. Guarding only the dialler
    // would leave it holding on one side of every pair: an operator who put a
    // foreign relay in the list would simply be meshed *by* it instead.
    if let Admitted::Mesh { relay_id } = &admitted {
        if !ctx.same_region(relay_id) {
            eprintln!("karst-relay: refused a mesh peer from another region");
            return;
        }
    }
    let mut tls_stream = tls_stream;
    // §7.7: after `RelayAuth`, before any `RecvPacket`. Sent here rather than
    // through the hub's queue because the ordering is the security argument —
    // the client has verified `sig_relay` by now, so the key it is about to
    // receive comes from the ML-DSA-65 identity the netmap pinned.
    if let Some(offer) = ctx.reflect_offer(&admitted) {
        if tls_stream.write_all(&offer).await.is_err() {
            return;
        }
    }
    drive(tls_stream, buf, admitted, peer, ctx).await;
}

type Tls = tokio_rustls::server::TlsStream<TcpStream>;

/// What the post-handshake loop needs of a stream.
///
/// **Generic so an outbound mesh connection can use it.** `serve` accepts a
/// TLS *server* stream; a relay dialling a mesh peer holds a TLS *client*
/// stream, and everything after the handshake — framing, the hub, the write
/// queue — is identical. Duplicating the loop for the second type would give
/// the mesh path its own copy of the queue draining and the close handling,
/// free to drift from the one every client uses.
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

/// TLS, the HTTP upgrade, and the Ponor handshake.
///
/// Returns the stream, whatever bytes arrived after the handshake, and who was
/// admitted. Every failure is a silent close: §10 requires handshake
/// rejections to be uniform, because distinguishing "not in the roster" from
/// "bad signature" hands an unauthenticated caller a membership oracle.
async fn establish(stream: TcpStream, ctx: &Arc<Ctx>) -> Option<(Tls, Vec<u8>, Admitted)> {
    // Nagle off: the datapath sends small frames that are latency-sensitive,
    // and a relayed handshake that waits 40ms for a coalescing partner is a
    // connection that looks broken.
    let _ = stream.set_nodelay(true);

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&ctx.tls));
    let mut tls = acceptor.accept(stream).await.ok()?;

    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK);

    // ── HTTP upgrade — §4.1 ────────────────────────────────────────────────
    let head_len = loop {
        match http::parse(&buf) {
            Ok(Some(up)) => break up.head_len,
            Ok(None) => {
                if !read_more(&mut tls, &mut buf).await {
                    return None;
                }
            }
            Err(reject) => {
                // A rejected *upgrade* does get a reason, unlike a rejected
                // handshake: this is a scanner or a misconfigured proxy, not
                // an attempt to authenticate, so there is no membership to
                // leak and a 404 saves somebody an afternoon.
                let _ = tls.write_all(reject.response().as_bytes()).await;
                let _ = tls.flush().await;
                return None;
            }
        }
    };
    tls.write_all(http::accepted().as_bytes()).await.ok()?;
    // Bytes beyond the head are already Ponor framing.
    buf.drain(..head_len);

    // ── Ponor handshake — §7.1 ─────────────────────────────────────────────
    let mut relay_random = [0u8; 32];
    getrandom::fill(&mut relay_random).ok()?;
    let mut hs = RelayHandshake::new(ctx.identity.relay_id(), relay_random);

    // The relay speaks first, so the peer signs over a value it has not yet
    // seen and a captured ClientAuth is useless on any other connection.
    tls.write_all(&hs.hello().to_vec()).await.ok()?;

    loop {
        let outcome = match decode(&buf) {
            Ok(Some((frame, used))) => {
                let roster = ctx.roster();
                let r = hs.on_client_auth(&frame, &*roster, &PonorVerifier, &*ctx.identity);
                Some((r, used))
            }
            Ok(None) => None,
            Err(_) => return None,
        };
        match outcome {
            Some((Ok((admitted, reply)), used)) => {
                buf.drain(..used);
                tls.write_all(&reply).await.ok()?;
                return Some((tls, buf, admitted));
            }
            // Uniform: no Close frame, no reason, no distinction.
            Some((Err(_), _)) => return None,
            None => {
                if !read_more(&mut tls, &mut buf).await {
                    return None;
                }
            }
        }
    }
}

/// The steady state: read frames, hand them to the hub, write what it queues.
async fn drive(
    mut tls: impl Stream,
    mut buf: Vec<u8>,
    admitted: Admitted,
    peer: SocketAddr,
    ctx: Arc<Ctx>,
) {
    let id = ConnId(ctx.next_conn.fetch_add(1, Ordering::Relaxed));
    let notify = Arc::new(Notify::new());

    let replaced = {
        let mut g = match ctx.shared.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.wakers.insert(id, Arc::clone(&notify));
        g.hub.admit(id, admitted.clone(), ctx.now_ms())
    };
    // §7.6: newest wins. The old connection is told why and drains.
    if let Some(old) = replaced {
        ctx.with_hub(|hub| hub.begin_close(old, Some(Reason::Replaced)));
    }
    ctx.wake_dirty();

    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    let mut roster_updates = ctx.roster_updates.subscribe();
    let mut deadline = tokio::time::Instant::now() + idle;
    // **On the heap, not the stack.** This buffer lives across every `.await`
    // in the loop below, so a stack array would sit inside this function's
    // future — and these futures nest, so the cost compounds. Doubling
    // FRAME_PAYLOAD_MAX for ML-DSA-87 (ADR-0015) was enough to overflow a test
    // thread's stack, which is how close to the edge the stack version was.
    // One allocation per connection buys the margin back. FINDINGS 58.
    let mut chunk = vec![0u8; CHUNK];

    loop {
        // Write first, so a frame queued by another task on the previous
        // iteration is not held until this connection happens to read.
        if !flush(&mut tls, id, &ctx).await {
            break;
        }
        let closing = ctx.with_hub(|hub| (hub.close_reason(id), hub.pending(id)));
        if closing.0.is_some() && closing.1 == 0 {
            break;
        }

        tokio::select! {
            read = tls.read(&mut chunk) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break; // orderly close
                }
                let Some(bytes) = chunk.get(..n) else { break };
                buf.extend_from_slice(bytes);
                if buf.len() > READ_BUF_MAX {
                    break; // not speaking Ponor
                }
                deadline = tokio::time::Instant::now() + idle;
                if !consume(&mut buf, id, &admitted, &ctx) {
                    break;
                }
                ctx.wake_dirty();
            }
            () = notify.notified() => {}
            changed = roster_updates.changed() => {
                if changed.is_err() || !ctx.remains_admitted(&admitted) {
                    // A known member learning that it was revoked is allowed
                    // this reason; §10's uniform silence is only for the
                    // unauthenticated handshake.
                    ctx.with_hub(|hub| hub.begin_close(id, Some(Reason::NotAdmitted)));
                    ctx.wake_dirty();
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                // §7.5: three missed keepalives.
                break;
            }
        }
    }

    // Best effort: a peer that is already gone cannot be told anything.
    let _ = tls.shutdown().await;

    let released = {
        let mut g = match ctx.shared.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.wakers.remove(&id);
        // Emits the mesh gossip that retracts this node's presence — and only
        // if this connection still owns the id, so a replaced connection
        // closing later does not evict its successor.
        g.hub.disconnect(id)
    };
    // §7.7: the key's lifetime is the connection.
    //
    // Gated on what `disconnect` actually released, for the same reason it
    // gates its own gossip: a replaced connection closing later must not
    // retire its *successor's* key. `mint` keys by node, so the successor
    // overwrote this entry when it connected — releasing unconditionally would
    // take a live key away from a node that is still connected, and nothing
    // would report it but a node that quietly stopped getting reflections.
    if let Some(node_id) = released {
        ctx.with_reflector(|r| r.release(&node_id));
    }
    ctx.wake_dirty();
    let _ = peer;
}

/// Decode and dispatch every whole frame in `buf`.
///
/// Returns whether the connection may continue.
fn consume(buf: &mut Vec<u8>, id: ConnId, admitted: &Admitted, ctx: &Arc<Ctx>) -> bool {
    loop {
        if !ctx.remains_admitted(admitted) {
            return false;
        }
        let now = ctx.now_ms();
        let step = match decode(buf) {
            Ok(Some((frame, used))) => {
                let mut g = match ctx.shared.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let roster = ctx.roster();
                Some((g.hub.on_frame(id, &frame, &*roster, now), used))
            }
            Ok(None) => None,
            // §10: a malformed frame means tampering or a bug on an ordered,
            // authenticated transport. There is no recovery that does not
            // weaken the connection.
            Err(_) => return false,
        };
        match step {
            Some((result, used)) => {
                buf.drain(..used);
                if result.is_err() {
                    return false;
                }
            }
            None => return true,
        }
    }
}

/// Write everything the hub has queued for this connection.
async fn flush(tls: &mut impl Stream, id: ConnId, ctx: &Arc<Ctx>) -> bool {
    loop {
        let next = ctx.with_hub(|hub| hub.take_outbound(id));
        let Some(bytes) = next else { return true };
        if tls.write_all(&bytes).await.is_err() {
            return false;
        }
    }
}

/// Read one chunk onto the tail of `buf`.
///
/// Straight into `buf`'s own spare capacity rather than through a stack array:
/// that keeps 8 KB out of this function's future — see the comment on the
/// connection loop's buffer — and removes a copy from the read path at the same
/// time.
async fn read_more(tls: &mut impl Stream, buf: &mut Vec<u8>) -> bool {
    let start = buf.len();
    buf.resize(start.saturating_add(CHUNK), 0);
    let Some(tail) = buf.get_mut(start..) else {
        buf.truncate(start);
        return false;
    };
    match tls.read(tail).await {
        Ok(0) | Err(_) => {
            buf.truncate(start);
            false
        }
        Ok(n) => {
            buf.truncate(start.saturating_add(n));
            buf.len() <= READ_BUF_MAX
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The HTTP upgrade a dialling relay sends — §4.1, the same request a node
/// sends, because a mesh connection is an ordinary Ponor connection.
const MESH_UPGRADE: &str = "GET /ponor HTTP/1.1\r\n\
     Host: relay\r\n\
     Connection: Upgrade\r\n\
     Upgrade: ponor\r\n\
     Ponor-Version: 1\r\n\r\n";

/// Dial the mesh peers this relay is responsible for — §8.
///
/// **Only one side of a pair dials**, and `mesh::Dialler` decides which; see
/// its documentation for why, and for what happens if both do.
pub async fn mesh_loop(
    ctx: Arc<Ctx>,
    client_tls: Arc<rustls::ClientConfig>,
    mut dialler: crate::mesh::Dialler,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        dialler.set_peers(
            ctx.roster
                .read()
                .map_or_else(|p| p.into_inner().mesh_dial_list(), |g| g.mesh_dial_list()),
        );
        let now = ctx.now_ms();
        let connected = |id: &crate::mesh::Id| ctx.with_hub(|hub| hub.has_mesh(id));
        for due in dialler.due(now, &connected) {
            let ctx = Arc::clone(&ctx);
            let tls = Arc::clone(&client_tls);
            // Outcomes are reported through the hub rather than back into the
            // dialler: the task outlives this iteration, and `due` has already
            // marked the attempt so nothing dials it again meanwhile.
            // Boxed for the reason the inbound spawn is — `dial_mesh` runs the
            // same three stages and so carries the same large state machine.
            tokio::spawn(Box::pin(async move {
                if let Err(e) = dial_mesh(&ctx, &tls, due.id, &due.addr, &due.name).await {
                    eprintln!("karst-relay: mesh dial to {} failed: {e}", due.addr);
                }
            }));
        }
    }
}

/// One outbound mesh connection, from TCP to the steady state.
async fn dial_mesh(
    ctx: &Arc<Ctx>,
    tls: &Arc<rustls::ClientConfig>,
    peer_id: crate::mesh::Id,
    addr: &str,
    name: &str,
) -> Result<(), String> {
    let entry = ctx
        .roster
        .read()
        .map_or_else(
            |p| p.into_inner().mesh_peer(&peer_id),
            |g| g.mesh_peer(&peer_id),
        )
        .ok_or_else(|| "peer is not in the roster".to_owned())?;

    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let remote = stream.peer_addr().map_err(|e| format!("peer_addr: {e}"))?;

    // The name is only what TLS validates against the configured CA; §4.2 puts
    // the identity check on the ML-DSA-65 signature below, not here. It comes
    // from the roster rather than from the address, because a relay behind a
    // load balancer is dialled at one and presents the other.
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|e| format!("server name: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    stream
        .write_all(MESH_UPGRADE.as_bytes())
        .await
        .map_err(|e| format!("upgrade: {e}"))?;

    // Read until the end of the HTTP head, keeping whatever came after it: a
    // relay may coalesce its `RelayHello` with the 101, and discarding the tail
    // would lose the first frame of the handshake.
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(at) = find_head_end(&buf) {
            break at;
        }
        if buf.len() > 8192 {
            return Err("upgrade response too large".to_owned());
        }
        let mut chunk = [0u8; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("upgrade read: {e}"))?;
        if n == 0 {
            return Err("peer closed during upgrade".to_owned());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    let head = String::from_utf8_lossy(buf.get(..head_end).unwrap_or_default()).into_owned();
    if !head.starts_with("HTTP/1.1 101") {
        return Err(format!(
            "upgrade refused: {}",
            head.lines().next().unwrap_or_default()
        ));
    }
    let mut rest = buf.split_off(head_end);

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| format!("no entropy: {e}"))?;
    let mut client = karst_relay_proto::ClientHandshake::new(
        karst_relay_proto::Role::Mesh,
        ctx.identity.relay_id(),
        peer_id,
        entry.identity_pk.clone(),
        nonce,
    );

    let hello = next_frame(&mut stream, &mut rest).await?;
    let (hello, _) = karst_relay_proto::frame::decode(&hello)
        .map_err(|e| format!("hello: {e:?}"))?
        .ok_or_else(|| "hello incomplete".to_owned())?;
    let auth = client
        .on_relay_hello(&hello, ctx.identity.as_ref())
        .map_err(|e| format!("sign: {e:?}"))?;
    stream
        .write_all(&auth)
        .await
        .map_err(|e| format!("auth: {e}"))?;

    let reply = next_frame(&mut stream, &mut rest).await?;
    let (reply, _) = karst_relay_proto::frame::decode(&reply)
        .map_err(|e| format!("relay auth: {e:?}"))?
        .ok_or_else(|| "relay auth incomplete".to_owned())?;
    client
        .on_relay_auth(&reply, &crate::sign::PonorVerifier)
        .map_err(|e| format!("verify: {e:?}"))?;
    if !client.may_send() {
        return Err("handshake did not establish".to_owned());
    }

    eprintln!("karst-relay: meshed with {addr}");
    drive(
        stream,
        rest,
        Admitted::Mesh { relay_id: peer_id },
        remote,
        Arc::clone(ctx),
    )
    .await;
    Ok(())
}

/// The offset just past a complete HTTP head, if one has arrived.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Read one complete Ponor frame, using anything already buffered first.
async fn next_frame(stream: &mut impl Stream, buf: &mut Vec<u8>) -> Result<Vec<u8>, String> {
    loop {
        if let Ok(Some((_, used))) = karst_relay_proto::frame::decode(buf) {
            return Ok(buf.drain(..used).collect());
        }
        let mut chunk = [0u8; 2048];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("peer closed".to_owned());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
}
