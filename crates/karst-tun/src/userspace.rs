// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A pure-Rust IP endpoint for containers that cannot create a TUN device.
//!
//! The queues here are deliberately bare IP packets, just like `IFF_TUN` with
//! `IFF_NO_PI`: Karst encrypts packets taken from `recv_segments`, and gives
//! decrypted packets back through `send`. Keeping this boundary identical is
//! what lets userspace mode share cryptokey routing and filtering with TUN
//! mode without making either policy depend on the host's privileges.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::{validate_mtu, TunConfig, TunError};

/// The name surfaced by status output for a userspace endpoint.
pub const USERSPACE_NAME: &str = "userspace";

/// A handle to a TCP socket owned by [`Userspace`].
///
/// It is intentionally opaque: socket state remains serialised with polling,
/// so callers cannot accidentally mutate a socket while its packets are being
/// constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHandle(SocketHandle);

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
                if let Some(packet) = packets.pop_front() {
                    if packet.len() > self.mtu {
                        return Err(TunError::PacketTooLarge {
                            len: packet.len(),
                            mtu: self.mtu,
                        });
                    }
                    out.push(packet);
                    return Ok(1);
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
            tcp::SocketBuffer::new(vec![0; self.mtu]),
            tcp::SocketBuffer::new(vec![0; self.mtu]),
        );
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = stack.sockets.add(socket);
        if let Err(e) = stack.sockets.get_mut::<tcp::Socket>(handle).listen(port) {
            let _ = stack.sockets.remove(handle);
            return Err(TunError::Io(io::Error::other(e.to_string())));
        }
        stack.poll();
        Ok(TcpHandle(handle))
    }

    /// Open a TCP connection over the userspace stack.
    ///
    /// # Errors
    /// Returns an I/O error for an unaddressable destination or invalid port.
    pub fn connect_tcp(&self, address: IpAddr, port: u16) -> Result<TcpHandle, TunError> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.mtu]),
            tcp::SocketBuffer::new(vec![0; self.mtu]),
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
        let handle = stack.sockets.add(socket);
        stack.poll();
        Ok(TcpHandle(handle))
    }

    /// Whether a TCP socket has received bytes.
    #[must_use]
    pub fn tcp_can_recv(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.sockets.get_mut::<tcp::Socket>(handle.0).can_recv()
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
        stack.sockets.get_mut::<tcp::Socket>(handle.0).may_recv()
    }

    /// Whether a TCP socket may accept more application bytes.
    #[must_use]
    pub fn tcp_can_send(&self, handle: TcpHandle) -> bool {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.poll();
        stack.sockets.get_mut::<tcp::Socket>(handle.0).can_send()
    }

    /// Close a TCP socket's transmit half.
    pub fn tcp_close(&self, handle: TcpHandle) {
        let mut stack = self
            .stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stack.sockets.get_mut::<tcp::Socket>(handle.0).close();
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
        let socket = stack.sockets.get_mut::<tcp::Socket>(handle.0);
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
            .sockets
            .get_mut::<tcp::Socket>(handle.0)
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
}
