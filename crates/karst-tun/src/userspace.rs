// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A pure-Rust IP endpoint for containers that cannot create a TUN device.
//!
//! The queues here are deliberately bare IP packets, just like `IFF_TUN` with
//! `IFF_NO_PI`: Karst encrypts packets taken from `recv_segments`, and gives
//! decrypted packets back through `send`. Keeping this boundary identical is
//! what lets userspace mode share cryptokey routing and filtering with TUN
//! mode without making either policy depend on the host's privileges.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::{validate_mtu, TunConfig, TunError};

/// The name surfaced by status output for a userspace endpoint.
pub const USERSPACE_NAME: &str = "userspace";

/// Most packets [`Userspace::recv_segments`] returns from one call.
///
/// Matched to the privileged path's offloaded read, which delivers around
/// fifty packets at a time, so the datapath above sees batches of a similar
/// shape whichever device is under it. Bounded rather than "everything queued"
/// because the caller allocates per batch and a burst should not decide how
/// much.
///
/// **Worth recording that this bought nothing on its own.** It replaced a
/// version that returned exactly one packet per call, which looked like an
/// obvious throughput bug; measured, it moved the mode from 7.3 Mbps to
/// 7.3 Mbps. The queue almost never held a second packet, because the window
/// below was letting only one segment be in flight at a time. Kept because it
/// is strictly cheaper and because it will matter once something else is the
/// constraint — the same reasoning PLAN.md §3.4 records for pre-keying the
/// fragment MAC.
const MAX_BATCH: usize = 64;

/// The receive and transmit buffer given to each TCP socket.
///
/// **Deliberately not one MTU**, which is what this was and which reads
/// plausible until you remember what a receive buffer *is* on a TCP socket: the
/// window this stack advertises. An MTU-sized buffer advertises a 1280-byte
/// window, so the far end may have exactly one segment in flight and must wait
/// for an acknowledgement before sending the next — stop-and-wait, whatever the
/// path underneath could carry. The transmit side is the mirror: one segment of
/// application data at a time, so every write costs a round trip.
///
/// ADR-0012's gate-1 measurement is what surfaced it (FINDINGS.md 41): the mode
/// sat at ~7 Mbps with the datapath and the relay loop both idle, which is the
/// signature of a window and not of a cost.
///
/// 64 KiB is the ordinary starting window for a kernel socket and covers this
/// path's bandwidth-delay product with three orders of magnitude to spare. The
/// price is 128 KiB of buffer per connection, which is a real number for a
/// sidecar with thousands of connections and not one for a sidecar with tens —
/// against a resident set of ~6.6 MB, one connection is 2%.
const SOCKET_BUFFER: usize = 64 * 1024;

/// How long a retiring connection is given to finish closing.
///
/// [`Userspace::tcp_release`] is a graceful hand-back: the socket keeps being
/// polled so an in-flight `FIN`/`ACK` exchange can complete, and only then is
/// its memory reclaimed. Past this the far end is not answering, and continuing
/// to hold 128 KiB of buffers for it is the wrong trade — so the connection is
/// aborted, which sends a reset and lets the reaper take it on the next pass.
///
/// Five seconds because the path underneath may include a relay hop and a
/// PHREATIC rekey; it is a bound on a pathological peer, not a timeout anything
/// healthy will reach.
const RETIRE_GRACE: Duration = Duration::from_secs(5);

/// A handle to a TCP socket owned by [`Userspace`].
///
/// It is intentionally opaque: socket state remains serialised with polling,
/// so callers cannot accidentally mutate a socket while its packets are being
/// constructed.
///
/// **The generation is what makes [`Userspace::tcp_release`] safe.** smoltcp
/// identifies a socket by its index in the set, and a freed index is handed
/// straight back out to the next socket — so a handle kept past its release
/// would name a *different* connection, and would read or write somebody else's
/// bytes. Every handle carries the generation it was issued in, every lookup
/// checks it, and a stale one resolves to nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHandle {
    socket: SocketHandle,
    generation: u64,
}

/// A bound UDP socket inside the userspace overlay stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHandle {
    socket: SocketHandle,
    generation: u64,
}

/// A socket handed back by its owner, waiting to finish closing.
#[derive(Debug, Clone, Copy)]
struct Retiring {
    socket: SocketHandle,
    deadline: StdInstant,
}

#[derive(Debug, Default)]
struct Queues {
    inbound: Mutex<VecDeque<Vec<u8>>>,
    outbound: Mutex<VecDeque<Vec<u8>>>,
    ready: Condvar,
}

/// smoltcp's device adapter. It has no file descriptor and performs no syscalls.
#[derive(Debug, Clone)]
struct QueueDevice(Arc<Queues>);

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.0
            .inbound
            .lock()
            .ok()?
            .pop_front()
            .map(|packet| (QueueRx { packet }, QueueTx(Arc::clone(&self.0))))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(Arc::clone(&self.0)))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = karst_proto::consts::TUNNEL_MTU;
        capabilities
    }
}

#[derive(Debug)]
struct QueueRx {
    packet: Vec<u8>,
}

impl phy::RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Debug)]
struct QueueTx(Arc<Queues>);

impl phy::TxToken for QueueTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if let Ok(mut outbound) = self.0.outbound.lock() {
            outbound.push_back(packet);
            self.0.ready.notify_one();
        }
        result
    }
}

struct Stack {
    interface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    /// Which sockets are still owned by a caller, and in which generation.
    live: HashMap<SocketHandle, u64>,
    /// Handed back, not yet reclaimed. See [`Retiring`] and [`RETIRE_GRACE`].
    retiring: Vec<Retiring>,
    next_generation: u64,
    started: StdInstant,
    next_ephemeral_port: u16,
}

impl Stack {
    fn now(&self) -> Instant {
        Instant::from_millis(i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX))
    }

    fn poll(&mut self) {
        let now = self.now();
        let _ = self
            .interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.reap(StdInstant::now());
    }

    /// Add a socket and issue a handle for it.
    fn insert(&mut self, socket: tcp::Socket<'static>) -> TcpHandle {
        let handle = self.sockets.add(socket);
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.live.insert(handle, generation);
        TcpHandle {
            socket: handle,
            generation,
        }
    }

    fn insert_udp(&mut self, socket: udp::Socket<'static>) -> UdpHandle {
        let handle = self.sockets.add(socket);
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.live.insert(handle, generation);
        UdpHandle {
            socket: handle,
            generation,
        }
    }

    fn udp_socket(&mut self, handle: UdpHandle) -> Option<&mut udp::Socket<'static>> {
        if self.live.get(&handle.socket).copied() != Some(handle.generation) {
            return None;
        }
        Some(self.sockets.get_mut::<udp::Socket>(handle.socket))
    }

    /// Resolve a handle, or `None` if it has been released.
    ///
    /// Every accessor goes through this. smoltcp's own `get_mut` panics on a
    /// handle it does not recognise, and this crate's discipline is that no
    /// input reaches a panic — a released handle is a caller's bookkeeping
    /// mistake, and it should surface as "this socket can do nothing" rather
    /// than as a dead daemon.
    fn socket(&mut self, handle: TcpHandle) -> Option<&mut tcp::Socket<'static>> {
        if self.live.get(&handle.socket).copied() != Some(handle.generation) {
            return None;
        }
        Some(self.sockets.get_mut::<tcp::Socket>(handle.socket))
    }

    /// Hand a socket back, to be reclaimed once it has finished closing.
    fn retire(&mut self, handle: TcpHandle, now: StdInstant) {
        if self.live.get(&handle.socket).copied() != Some(handle.generation) {
            return;
        }
        self.retiring.push(Retiring {
            socket: handle.socket,
            deadline: now + RETIRE_GRACE,
        });
    }

    /// Reclaim retired sockets that have finished, and abort the ones that will
    /// not.
    ///
    /// **This is what stops the socket set growing without bound.** Every
    /// connection the sidecar handles adds a socket with 128 KiB of buffers,
    /// and until this existed nothing ever removed one: a daemon that had
    /// served a thousand connections held a thousand sockets, polled all of
    /// them on every packet, and had reclaimed none of the memory.
    fn reap(&mut self, now: StdInstant) {
        if self.retiring.is_empty() {
            return;
        }
        let mut finished = Vec::new();
        let mut expired = Vec::new();
        for entry in &self.retiring {
            let socket = self.sockets.get::<tcp::Socket>(entry.socket);
            // `is_open` is false in CLOSED and TIME-WAIT. A listening socket has
            // no connection to tear down, so it goes immediately — otherwise a
            // daemon shutting down would wait out the grace period per port.
            if !socket.is_open() || socket.is_listening() {
                finished.push(entry.socket);
            } else if now >= entry.deadline {
                expired.push(entry.socket);
            }
        }
        for handle in expired {
            // Sends a reset on this poll; the next pass sees CLOSED and frees it.
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
        }
        for handle in finished {
            self.retiring.retain(|e| e.socket != handle);
            self.live.remove(&handle);
            let _ = self.sockets.remove(handle);
        }
    }
}

/// An in-process userspace network stack connected to Karst by bare IP packets.
///
/// This endpoint is usable without `/dev/net/tun`, `CAP_NET_ADMIN`, raw
/// sockets, or any other host-network privilege. It is internally locked so a
/// packet arriving from a peer can be processed while the daemon's outbound
/// reader waits for a packet to encrypt.
#[derive(Clone)]
pub struct Userspace {
    queues: Arc<Queues>,
    stack: Arc<Mutex<Stack>>,
    mtu: usize,
}

impl std::fmt::Debug for Userspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Userspace")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl Userspace {
    /// Construct an empty IP endpoint. Addresses are configured with
    /// [`Self::set_address`], matching the TUN lifecycle.
    ///
    /// # Errors
    /// [`TunError::InvalidMtu`] if the requested MTU differs from Karst's
    /// protocol MTU.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        validate_mtu(config.mtu)?;
        let queues = Arc::new(Queues::default());
        let mut device = QueueDevice(Arc::clone(&queues));
        let mut cfg = Config::new(HardwareAddress::Ip);
        // TCP sequence numbers need only avoid accidental reuse within one
        // stack lifetime; the encrypted Karst transport has its own CSPRNG.
        cfg.random_seed = u64::try_from(StdInstant::now().elapsed().as_nanos()).unwrap_or(0);
        let interface = Interface::new(cfg, &mut device, Instant::ZERO);
        Ok(Self {
            queues,
            stack: Arc::new(Mutex::new(Stack {
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
                live: HashMap::new(),
                retiring: Vec::new(),
                next_generation: 0,
                started: StdInstant::now(),
                next_ephemeral_port: 49_152,
            })),
            mtu: config.mtu,
        })
    }

    /// Userspace mode has no host interface name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        USERSPACE_NAME
    }

    /// The protocol MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Userspace mode never requests kernel segmentation offload.
    #[must_use]
    pub fn offload(&self) -> bool {
        false
    }

    /// Add an address to the stack's local IP configuration.
    ///
    /// # Errors
    /// Returns an I/O error for a prefix longer than its address family allows.
    pub fn set_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("prefix length /{prefix_len} exceeds /{max} for this family"),
            )));
        }
        let cidr = IpCidr::new(IpAddress::from(addr), prefix_len);
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.interface.update_ip_addrs(|addrs| {
            if !addrs.contains(&cidr) {
                let _ = addrs.push(cidr);
            }
        });
        Ok(())
    }

    /// Userspace mode has no host route table to modify.
    ///
    /// # Errors
    /// This implementation does not fail.
    pub fn add_route(&self, _: IpAddr, _: u8) -> Result<(), TunError> {
        Ok(())
    }

    /// Userspace mode has no host route table to modify.
    ///
    /// # Errors
    /// This implementation does not fail.
    pub fn remove_route(&self, _: IpAddr, _: u8) -> Result<(), TunError> {
        Ok(())
    }

    /// Receive IP packets generated by the userspace stack for Karst to carry.
    ///
    /// # Errors
    /// Returns [`TunError::BufferTooSmall`] for a short buffer or an I/O error
    /// if the packet queue is poisoned.
    pub fn recv_segments(&self, buf: &mut [u8], out: &mut Vec<Vec<u8>>) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu,
            });
        }
        out.clear();
        loop {
            if let Ok(mut packets) = self.queues.outbound.lock() {
                // **Everything queued, not one packet.** The privileged path
                // returns ~52 packets per `read` through `IFF_VNET_HDR`
                // segmentation offload (PLAN.md §3.4), and the datapath above
                // was rebuilt around that batch. Returning a single packet per
                // call handed the same datapath one packet at a time and gave
                // up the batching for free — ADR-0012's gate-1 measurement is
                // where that showed up.
                while out.len() < MAX_BATCH {
                    let Some(packet) = packets.pop_front() else {
                        break;
                    };
                    if packet.len() > self.mtu {
                        return Err(TunError::PacketTooLarge {
                            len: packet.len(),
                            mtu: self.mtu,
                        });
                    }
                    out.push(packet);
                }
                if !out.is_empty() {
                    return Ok(out.len());
                }
            }
            if let Ok(mut stack) = self.stack.lock() {
                stack.poll();
            }
            let outbound =
                self.queues.outbound.lock().map_err(|_| {
                    TunError::Io(io::Error::other("userspace packet queue poisoned"))
                })?;
            let _ = self
                .queues
                .ready
                .wait_timeout(outbound, Duration::from_millis(20));
        }
    }

    /// Inject a decrypted packet from Karst into the userspace stack.
    ///
    /// # Errors
    /// Returns [`TunError::PacketTooLarge`] beyond the fixed MTU or an I/O
    /// error if the packet queue is poisoned.
    pub fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        self.queues
            .inbound
            .lock()
            .map_err(|_| TunError::Io(io::Error::other("userspace packet queue poisoned")))?
            .push_back(packet.to_vec());
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        Ok(packet.len())
    }

    /// Start a TCP listener on an overlay port.
    ///
    /// # Errors
    /// Returns an I/O error when the port cannot be listened on.
    pub fn listen_tcp(&self, port: u16) -> Result<TcpHandle, TunError> {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        );
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = stack.insert(socket);
        if let Err(e) = stack
            .sockets
            .get_mut::<tcp::Socket>(handle.socket)
            .listen(port)
        {
            stack.live.remove(&handle.socket);
            let _ = stack.sockets.remove(handle.socket);
            return Err(TunError::Io(io::Error::other(e.to_string())));
        }
        stack.poll();
        Ok(handle)
    }

    /// Bind a UDP listener inside the encrypted overlay, without opening a
    /// host socket. This is used by `KarstDNS` in userspace mode.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the port is invalid or already bound.
    pub fn listen_udp(&self, port: u16) -> Result<UdpHandle, TunError> {
        let packets = 16;
        let buffer = || {
            udp::PacketBuffer::new(
                (0..packets)
                    .map(|_| udp::PacketMetadata::EMPTY)
                    .collect::<Vec<_>>(),
                vec![0; 65_535],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket
            .bind(port)
            .map_err(|e| TunError::Io(io::Error::other(e.to_string())))?;
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = stack.insert_udp(socket);
        stack.poll();
        Ok(handle)
    }

    /// Take one datagram from an overlay UDP listener.
    pub fn udp_recv(&self, handle: UdpHandle, out: &mut Vec<u8>) -> Option<SocketAddr> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        let socket = stack.udp_socket(handle)?;
        let (packet, metadata) = socket.recv().ok()?;
        out.extend_from_slice(packet);
        Some(SocketAddr::new(
            metadata.endpoint.addr.into(),
            metadata.endpoint.port,
        ))
    }

    /// Send one UDP datagram through an overlay listener.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the handle was released or the packet cannot
    /// be queued by the userspace stack.
    pub fn udp_send(
        &self,
        handle: UdpHandle,
        bytes: &[u8],
        to: SocketAddr,
    ) -> Result<(), TunError> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let socket = stack
            .udp_socket(handle)
            .ok_or_else(|| TunError::Io(io::Error::other("UDP socket has been released")))?;
        socket
            .send_slice(bytes, IpEndpoint::new(IpAddress::from(to.ip()), to.port()))
            .map_err(|e| TunError::Io(io::Error::other(e.to_string())))?;
        stack.poll();
        Ok(())
    }

    /// Open a TCP connection over the userspace stack.
    ///
    /// # Errors
    /// Returns an I/O error for an unaddressable destination or invalid port.
    pub fn connect_tcp(&self, address: IpAddr, port: u16) -> Result<TcpHandle, TunError> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        );
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let local_port = stack.next_ephemeral_port;
        stack.next_ephemeral_port = if local_port == 65_535 {
            49_152
        } else {
            local_port + 1
        };
        if let Err(e) = socket.connect(
            stack.interface.context(),
            (IpAddress::from(address), port),
            local_port,
        ) {
            return Err(TunError::Io(io::Error::other(e.to_string())));
        }
        let handle = stack.insert(socket);
        stack.poll();
        Ok(handle)
    }

    /// Whether a socket has stopped merely listening — smoltcp's `accept`.
    ///
    /// A listening socket *becomes* the connection when one arrives, so there
    /// is no separate accepted handle: this is the edge that says the handle
    /// now names a conversation with a peer.
    #[must_use]
    pub fn tcp_is_active(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.socket(handle).is_some_and(|s| s.is_active())
    }

    /// Whether a TCP handle is awaiting an inbound connection.
    #[must_use]
    pub fn tcp_is_listening(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack
            .socket(handle)
            .is_some_and(|socket| socket.is_listening())
    }

    /// Reuse a closed TCP socket as a listener after its prior connection has
    /// finished. Reusing the allocation avoids retaining one 128 KiB pair of
    /// buffers per DNS client.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the socket is not closed or the port cannot be
    /// listened on.
    pub fn tcp_listen_again(&self, handle: TcpHandle, port: u16) -> Result<(), TunError> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let socket = stack
            .socket(handle)
            .ok_or_else(|| TunError::Io(io::Error::other("TCP socket has been released")))?;
        socket
            .listen(port)
            .map_err(|error| TunError::Io(io::Error::other(error.to_string())))?;
        stack.poll();
        Ok(())
    }

    /// The overlay address at the other end of a connection.
    ///
    /// `None` for a socket that has none — one still listening, one already
    /// released — because an inbound connection with no record of who made it
    /// is not something an operator can act on.
    #[must_use]
    pub fn tcp_remote(&self, handle: TcpHandle) -> Option<SocketAddr> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let endpoint = stack.socket(handle)?.remote_endpoint()?;
        Some(SocketAddr::new(endpoint.addr.into(), endpoint.port))
    }

    /// Hand a socket back for the stack to reclaim.
    ///
    /// Graceful: the connection keeps being polled until it has finished
    /// closing, so a `FIN` already in flight is not cut off. See
    /// [`RETIRE_GRACE`] for what happens to one that never finishes.
    ///
    /// **Callers must release every handle they take.** Nothing else frees a
    /// socket, and each holds two 64 KiB buffers and is polled with every
    /// packet the daemon carries.
    pub fn tcp_release(&self, handle: TcpHandle) {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.retire(handle, StdInstant::now());
        stack.poll();
    }

    /// Refuse a connection now: reset it and reclaim it.
    ///
    /// The difference from [`Self::tcp_release`] is who the deadline is for. A
    /// release is for a conversation that is over and can be given time to say
    /// so; this is for one the daemon has decided not to have — where waiting
    /// out the grace period would hold exactly the resource being refused.
    pub fn tcp_abort(&self, handle: TcpHandle) {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(socket) = stack.socket(handle) {
            socket.abort();
        }
        // Zero grace: the reset goes out on this poll and the reaper takes it
        // on the next. Expressed as an already-past deadline rather than as a
        // second code path, so an abort cannot drift from a release.
        let now = StdInstant::now();
        stack.retire(handle, now.checked_sub(RETIRE_GRACE).unwrap_or(now));
        stack.poll();
    }

    /// How many TCP sockets this stack is holding.
    ///
    /// Exists to be asserted on: "the sidecar reclaims what it opens" is a
    /// property no test of bytes can see, and FINDINGS.md 44 is what happens
    /// when nothing checks it.
    #[must_use]
    pub fn socket_count(&self) -> usize {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.live.len()
    }

    /// Whether a TCP socket has received bytes.
    #[must_use]
    pub fn tcp_can_recv(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.socket(handle).is_some_and(|s| s.can_recv())
    }

    /// Whether more bytes can still arrive on a TCP socket.
    ///
    /// **Not the same question as [`Self::tcp_can_recv`]**, and conflating them
    /// is how a proxy loses the last part of a reply. `tcp_can_recv` asks
    /// whether bytes are buffered *now*; this asks whether the far end might
    /// still send any — true while data is buffered, and true after that until
    /// the remote closes. A relay needs both: the first says when to copy, and
    /// only the second says when to stop.
    #[must_use]
    pub fn tcp_may_recv(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.socket(handle).is_some_and(|s| s.may_recv())
    }

    /// Whether a TCP socket may accept more application bytes.
    #[must_use]
    pub fn tcp_can_send(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.socket(handle).is_some_and(|s| s.can_send())
    }

    /// Close a TCP socket's transmit half.
    pub fn tcp_close(&self, handle: TcpHandle) {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(socket) = stack.socket(handle) {
            socket.close();
        }
        stack.poll();
    }

    /// Copy received TCP bytes into `out`.
    ///
    /// # Errors
    /// Returns an I/O error if the socket cannot receive.
    pub fn tcp_recv(&self, handle: TcpHandle, out: &mut Vec<u8>) -> Result<usize, TunError> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        let Some(socket) = stack.socket(handle) else {
            return Ok(0);
        };
        socket
            .recv(|bytes| {
                out.extend_from_slice(bytes);
                (bytes.len(), bytes.len())
            })
            .map_err(|e| TunError::Io(io::Error::other(e.to_string())))
    }

    /// Queue bytes for TCP transmission.
    ///
    /// # Errors
    /// Returns an I/O error if the socket cannot accept the bytes.
    pub fn tcp_send(&self, handle: TcpHandle, bytes: &[u8]) -> Result<usize, TunError> {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sent = stack
            .socket(handle)
            // A released handle is not a socket that is merely full: reporting
            // zero would spin a proxy loop forever on bytes that can never go
            // anywhere.
            .ok_or_else(|| TunError::Io(io::Error::other("TCP socket has been released")))?
            .send_slice(bytes)
            .map_err(|e| TunError::Io(io::Error::other(e.to_string())))?;
        stack.poll();
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn endpoint(address: &str) -> Userspace {
        let endpoint = Userspace::create(&TunConfig::default()).expect("valid MTU");
        endpoint
            .set_address(address.parse().expect("address"), 24)
            .expect("address accepted");
        endpoint
    }

    fn relay(from: &Userspace, to: &Userspace) {
        let mut buf = vec![0; karst_proto::consts::TUNNEL_MTU];
        let mut packets = Vec::new();
        let _ = from
            .recv_segments(&mut buf, &mut packets)
            .expect("packet emitted");
        for packet in packets {
            to.send(&packet).expect("packet accepted");
        }
    }

    /// This is intentionally a pure userspace test: it neither opens TUN nor
    /// requires a network capability. Removing the packet bridge makes the
    /// TCP handshake below time out rather than pass.
    #[test]
    fn tcp_conversation_needs_only_the_userspace_packet_bridge() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let listener = server.listen_tcp(8080).expect("listen");
        let connection = client
            .connect_tcp("10.0.0.2".parse().expect("address"), 8080)
            .expect("connect");

        // SYN → SYN-ACK → ACK. `relay` deliberately blocks like a TUN read,
        // so this sequence names only packets TCP is required to emit.
        relay(&client, &server);
        relay(&server, &client);
        relay(&client, &server);
        client.tcp_send(connection, b"hello").expect("send");
        relay(&client, &server);
        relay(&server, &client);
        let mut received = Vec::new();
        assert!(
            server.tcp_can_recv(listener),
            "server did not receive TCP data"
        );
        server.tcp_recv(listener, &mut received).expect("receive");
        assert_eq!(received, b"hello");
    }

    #[test]
    fn udp_conversation_needs_only_the_userspace_packet_bridge() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let client_socket = client.listen_udp(49_153).expect("client bind");
        let server_socket = server.listen_udp(53).expect("DNS bind");

        client
            .udp_send(
                client_socket,
                b"question",
                "10.0.0.2:53".parse().expect("server endpoint"),
            )
            .expect("send query");
        relay(&client, &server);
        let mut question = Vec::new();
        let source = server
            .udp_recv(server_socket, &mut question)
            .expect("server receives query");
        assert_eq!(source, "10.0.0.1:49153".parse().expect("client endpoint"));
        assert_eq!(question, b"question");

        server
            .udp_send(server_socket, b"answer", source)
            .expect("send answer");
        relay(&server, &client);
        let mut answer = Vec::new();
        assert_eq!(
            client.udp_recv(client_socket, &mut answer),
            Some("10.0.0.2:53".parse().expect("server endpoint"))
        );
        assert_eq!(answer, b"answer");
    }

    /// **Finding 41's defect, asserted where it is deterministic.**
    ///
    /// Every TCP socket was built with a one-MTU buffer, so one segment could
    /// be in flight and the mode ran at 7.3 Mbps while being entirely correct.
    /// The end-to-end row that catches it (`tests/userspace.rs`) can only see
    /// it as elapsed time, and a wall-clock budget turned out to be the wrong
    /// instrument: healthy varies more than six-fold across machines, so the
    /// budget has to sit in a window that a loaded runner can wander into.
    ///
    /// The window itself is machine-independent, so it is checked here. This
    /// costs microseconds, cannot flake, and fails for exactly one reason.
    #[test]
    fn a_tcp_socket_advertises_a_window_worth_having() {
        let server = endpoint("10.0.0.2");
        let listener = server.listen_tcp(8080).expect("listen");
        let mut stack = server
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let socket = stack.socket(listener).expect("a socket we just made");
        // Sixteen tunnel MTUs. The defect was one; the shipped value is fifty-
        // one. Anything in that range is a window rather than stop-and-wait, so
        // the bound names the property and not the constant — a future change
        // that halves the buffer for a good reason should not have to edit a
        // test that would still be telling the truth.
        let floor = 16 * karst_proto::consts::TUNNEL_MTU;
        assert!(
            socket.recv_capacity() >= floor,
            "receive buffer is {} B, under the {floor} B floor — at this size \
             the advertised window allows about one segment in flight, which is \
             FINDINGS.md 41 and is invisible to every assertion about bytes",
            socket.recv_capacity()
        );
        assert!(
            socket.send_capacity() >= floor,
            "send buffer is {} B, under the {floor} B floor",
            socket.send_capacity()
        );
    }

    /// **A socket mid-handshake is active and cannot yet receive**, and those
    /// two answers together are what FINDINGS.md 49 was made of.
    ///
    /// `is_active()` is true from `SYN-RECEIVED` onward, so a listener that has
    /// seen only a `SYN` already looks like a connection. `may_recv()` in that
    /// state is false — the same answer it gives once the peer has finished
    /// sending forever. An accept loop that waited on the first and a copy loop
    /// that trusted the second between them half-closed a backend before the
    /// request had arrived.
    ///
    /// Deterministic because `relay` moves exactly one side's packets: after
    /// the `SYN` and before the `ACK`, the server is in that state by
    /// construction rather than by timing.
    #[test]
    fn a_socket_that_has_only_seen_a_syn_is_active_but_cannot_receive() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let listener = server.listen_tcp(8080).expect("listen");
        let connection = client
            .connect_tcp("10.0.0.2".parse().expect("address"), 8080)
            .expect("connect");

        relay(&client, &server); // SYN
        assert!(
            server.tcp_is_active(listener),
            "a listener that has seen a SYN reports itself inactive, so the \
             accept loop would never pick this connection up"
        );
        assert!(
            !server.tcp_may_recv(listener),
            "the whole hazard is that `may_recv` is false here; if this ever \
             becomes true, the guards built on it are protecting nothing"
        );
        assert!(!server.tcp_can_recv(listener));

        relay(&server, &client); // SYN-ACK
        relay(&client, &server); // ACK
        assert!(
            server.tcp_may_recv(listener),
            "once established the socket must be able to receive, or the \
             accept loop would wait for a readiness that never comes"
        );
        // And the client end agrees, so neither side is a special case.
        assert!(client.tcp_may_recv(connection));
    }

    /// Move whatever either side has to say until neither has anything.
    ///
    /// `relay` blocks like a TUN read, which is right for a handshake whose
    /// packets are all required. Teardown is not like that — how many segments
    /// a close takes depends on what was in flight — so this drains instead.
    fn settle(a: &Userspace, b: &Userspace) {
        let mut packets = Vec::new();
        for _ in 0..64 {
            let mut moved = false;
            for (from, to) in [(a, b), (b, a)] {
                // Drained directly rather than through `recv_segments`, which
                // blocks until there is something: at the end of a teardown
                // there legitimately is not.
                if let Ok(mut queue) = from.queues.outbound.lock() {
                    packets.clear();
                    while let Some(packet) = queue.pop_front() {
                        packets.push(packet);
                    }
                }
                for packet in &packets {
                    to.send(packet).expect("packet accepted");
                    moved = true;
                }
                // Polls, which is what gives each side its chance to answer and
                // runs its reaper.
                let _ = from.socket_count();
            }
            if !moved {
                return;
            }
        }
    }

    /// Open, use and close a connection, and require the memory back.
    ///
    /// **FINDINGS.md 44.** Every connection the sidecar handled added a socket
    /// with 128 KiB of buffers and nothing ever removed one, so a long-running
    /// daemon grew without bound and polled every corpse on every packet. No
    /// test of bytes could see it: the conversations were all correct.
    #[test]
    fn a_finished_connection_is_reclaimed() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        assert_eq!(client.socket_count(), 0, "a fresh stack holds no sockets");

        for round in 0..8 {
            let listener = server.listen_tcp(8080).expect("listen");
            let connection = client
                .connect_tcp("10.0.0.2".parse().expect("address"), 8080)
                .expect("connect");
            relay(&client, &server);
            relay(&server, &client);
            relay(&client, &server);
            client.tcp_send(connection, b"hello").expect("send");
            settle(&client, &server);

            client.tcp_close(connection);
            server.tcp_close(listener);
            settle(&client, &server);
            client.tcp_release(connection);
            server.tcp_release(listener);
            settle(&client, &server);

            assert_eq!(
                (client.socket_count(), server.socket_count()),
                (0, 0),
                "round {round} left a socket behind"
            );
        }
    }

    /// A listening socket becomes the connection, and knows who made it.
    #[test]
    fn a_listener_reports_when_a_peer_has_taken_it_up() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let listener = server.listen_tcp(8080).expect("listen");
        assert!(
            !server.tcp_is_active(listener),
            "an untouched listener is not a connection"
        );
        assert_eq!(
            server.tcp_remote(listener),
            None,
            "an untouched listener has no peer"
        );

        let connection = client
            .connect_tcp("10.0.0.2".parse().expect("address"), 8080)
            .expect("connect");
        relay(&client, &server);
        assert!(
            server.tcp_is_active(listener),
            "the listener did not report the arriving connection"
        );
        let remote = server.tcp_remote(listener).expect("the peer's address");
        assert_eq!(
            remote.ip(),
            "10.0.0.1".parse::<IpAddr>().expect("address"),
            "the connection is attributed to the wrong overlay address"
        );
        client.tcp_release(connection);
        server.tcp_release(listener);
    }

    /// A released handle addresses nothing, including the socket that reuses
    /// its slot.
    ///
    /// smoltcp hands a freed index straight back out, so without the generation
    /// check a handle kept one line too long would read and write a stranger's
    /// connection.
    #[test]
    fn a_released_handle_cannot_reach_the_socket_that_replaces_it() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let first = server.listen_tcp(8080).expect("listen");
        server.tcp_release(first);
        assert_eq!(server.socket_count(), 0, "the listener was not reclaimed");

        let second = server.listen_tcp(8081).expect("listen again");
        let connection = client
            .connect_tcp("10.0.0.2".parse().expect("address"), 8081)
            .expect("connect");
        relay(&client, &server);
        relay(&server, &client);
        relay(&client, &server);
        client.tcp_send(connection, b"private").expect("send");
        settle(&client, &server);

        // Everything the stale handle can be asked, asked. None of it may
        // reach `second`, and none of it may panic.
        assert!(!server.tcp_can_recv(first), "a stale handle read a socket");
        assert!(!server.tcp_may_recv(first));
        assert!(!server.tcp_can_send(first));
        assert!(!server.tcp_is_active(first));
        assert_eq!(server.tcp_remote(first), None);
        let mut stolen = Vec::new();
        assert_eq!(
            server.tcp_recv(first, &mut stolen).expect("no panic"),
            0,
            "a stale handle received another connection's bytes"
        );
        assert!(stolen.is_empty(), "a stale handle copied out {stolen:?}");
        assert!(
            server.tcp_send(first, b"forged").is_err(),
            "a stale handle wrote into another connection"
        );
        server.tcp_close(first);

        // …and the real connection is untouched by all of it.
        assert!(
            server.tcp_can_recv(second),
            "the live connection was disturbed by use of a stale handle"
        );
        let mut received = Vec::new();
        server.tcp_recv(second, &mut received).expect("receive");
        assert_eq!(received, b"private");
    }

    /// A refused connection is reset rather than left to time out.
    #[test]
    fn an_aborted_connection_is_reset_and_reclaimed_at_once() {
        let client = endpoint("10.0.0.1");
        let server = endpoint("10.0.0.2");
        let listener = server.listen_tcp(8080).expect("listen");
        let connection = client
            .connect_tcp("10.0.0.2".parse().expect("address"), 8080)
            .expect("connect");
        relay(&client, &server);
        relay(&server, &client);
        relay(&client, &server);
        assert!(client.tcp_can_send(connection), "not established");

        server.tcp_abort(listener);
        settle(&client, &server);
        assert_eq!(
            server.socket_count(),
            0,
            "an aborted connection was not reclaimed"
        );
        assert!(
            !client.tcp_may_recv(connection),
            "the client was not told the connection had gone"
        );
        client.tcp_release(connection);
    }
}
