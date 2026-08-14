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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karst_relay_proto::consts::{
    FRAME_HEADER, FRAME_PAYLOAD_MAX, HANDSHAKE_TIMEOUT_SECS, IDLE_TIMEOUT_SECS,
};
use karst_relay_proto::{frame::decode, Admitted, Reason, RelayHandshake};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::config::Config;
use crate::http;
use crate::hub::{ConnId, Hub};
use crate::roster::FileRoster;
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
    roster: Arc<FileRoster>,
    identity: Arc<Identity>,
    tls: Arc<rustls::ServerConfig>,
    started: Instant,
    next_conn: AtomicU64,
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
        Arc::new(Self {
            shared: Mutex::new(Shared {
                hub: Hub::new(cfg.hub()),
                wakers: HashMap::new(),
            }),
            roster,
            identity,
            tls,
            started: Instant::now(),
            next_conn: AtomicU64::new(1),
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

    fn with_hub<T>(&self, f: impl FnOnce(&mut Hub) -> T) -> T {
        let mut g = match self.shared.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut g.hub)
    }
}

/// Run the relay until the process is asked to stop.
///
/// # Errors
/// Anything that stops the listener from starting: a certificate that will not
/// load, a roster that will not parse, an address already in use.
pub async fn run(cfg: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity = Arc::new(Identity::load_or_create(&cfg.identity_key)?);
    let roster = Arc::new(FileRoster::load(&cfg.roster)?);
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

    let listener = TcpListener::bind(cfg.listen).await?;
    serve_on(listener, ctx).await
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
                tokio::spawn(async move { serve(stream, peer, ctx).await });
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
    drive(tls_stream, buf, admitted, peer, ctx).await;
}

type Tls = tokio_rustls::server::TlsStream<TcpStream>;

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
                let r = hs.on_client_auth(&frame, &*ctx.roster, &PonorVerifier, &*ctx.identity);
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
    mut tls: Tls,
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
        g.hub.admit(id, admitted, ctx.now_ms())
    };
    // §7.6: newest wins. The old connection is told why and drains.
    if let Some(old) = replaced {
        ctx.with_hub(|hub| hub.begin_close(old, Some(Reason::Replaced)));
    }
    ctx.wake_dirty();

    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    let mut deadline = tokio::time::Instant::now() + idle;
    let mut chunk = [0u8; CHUNK];

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
                if !consume(&mut buf, id, &ctx) {
                    break;
                }
                ctx.wake_dirty();
            }
            () = notify.notified() => {}
            () = tokio::time::sleep_until(deadline) => {
                // §7.5: three missed keepalives.
                break;
            }
        }
    }

    // Best effort: a peer that is already gone cannot be told anything.
    let _ = tls.shutdown().await;

    {
        let mut g = match ctx.shared.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.wakers.remove(&id);
        // Emits the mesh gossip that retracts this node's presence — and only
        // if this connection still owns the id, so a replaced connection
        // closing later does not evict its successor.
        g.hub.disconnect(id);
    }
    ctx.wake_dirty();
    let _ = peer;
}

/// Decode and dispatch every whole frame in `buf`.
///
/// Returns whether the connection may continue.
fn consume(buf: &mut Vec<u8>, id: ConnId, ctx: &Arc<Ctx>) -> bool {
    loop {
        let now = ctx.now_ms();
        let step = match decode(buf) {
            Ok(Some((frame, used))) => {
                let mut g = match ctx.shared.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                Some((g.hub.on_frame(id, &frame, &*ctx.roster, now), used))
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
async fn flush(tls: &mut Tls, id: ConnId, ctx: &Arc<Ctx>) -> bool {
    loop {
        let next = ctx.with_hub(|hub| hub.take_outbound(id));
        let Some(bytes) = next else { return true };
        if tls.write_all(&bytes).await.is_err() {
            return false;
        }
    }
}

async fn read_more(tls: &mut Tls, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; CHUNK];
    match tls.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => match chunk.get(..n) {
            Some(bytes) => {
                buf.extend_from_slice(bytes);
                buf.len() <= READ_BUF_MAX
            }
            None => false,
        },
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
