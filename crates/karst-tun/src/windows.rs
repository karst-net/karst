// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The Windows adapter, over Wintun.
//!
//! Safe throughout — every FFI call goes through [`crate::sys_windows`],
//! following the same split [`crate::macos`] uses for `utun`: this module is
//! the shape `karstd` sees, `sys_windows` is where `unsafe` lives (ADR-0003).
//!
//! # How this differs from Linux and macOS, and where those differences stop
//!
//! [`Tun`]'s public surface matches [`crate::linux::Tun`] and
//! [`crate::macos::Tun`] exactly, so `NetworkDevice` in `bins/karstd` compiles
//! against one shape regardless of platform. Three things are absorbed here:
//!
//! 1. **No file descriptor.** Wintun is a ring buffer, not a character
//!    device: [`crate::sys_windows::Wintun::receive_packet`] and
//!    `send_packet` are the read and write, and there is no `AsFd` to expose
//!    — nothing above this crate has needed one on Windows so far (`grep` of
//!    `bins/karstd` turns up no `as_raw_fd`/`AsFd` use outside the two Unix
//!    modules).
//! 2. **The shutdown problem plan §3 calls out.** A blocking `read(2)` wakes
//!    when its fd closes; a blocking Wintun receive does not. [`Tun::recv`]
//!    waits on the session's read event *and* a shutdown event together via
//!    [`crate::sys_windows::wait_for_data_or_shutdown`], so
//!    [`Tun::request_shutdown`] is a real, first-class way to unstick the
//!    reader thread. `karstd`'s current `stop()` (`bins/karstd/src/run.rs`)
//!    exits the process rather than calling it — correct today, since
//!    process exit reclaims the wait unconditionally — but a Windows service
//!    (plan §5, unimplemented) needs a graceful path for
//!    `SERVICE_CONTROL_STOP`, and this is it.
//! 3. **Addressing and routing are IP Helper calls, not `netsh`.** Plan §4:
//!    `netsh`'s output is locale-dependent text; IP Helper is a stable,
//!    directly callable API. `SkipAsSource` is set on every address this
//!    assigns, so the tunnel address is never chosen as the source for
//!    off-mesh traffic — see `sys_windows::create_unicast_address`.
//!
//! There is no offload: like `utun`, a Wintun session yields one IP packet
//! per receive, so [`Tun::offload`] is always false and `recv_segments`
//! always yields exactly one packet.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::sys_windows::{self as sys, Wake};
use crate::{encode_name, validate_mtu, TunConfig, TunError};

/// Wintun's ring capacity, in bytes: a power of two between
/// `WINTUN_MIN_RING_CAPACITY` (128 KiB) and `WINTUN_MAX_RING_CAPACITY`
/// (64 MiB). 4 MiB is the plan's stated sane default (§3) — enough to absorb
/// a scheduling hiccup on the reader thread without either ring stalling the
/// datapath under ordinary load.
const RING_CAPACITY: u32 = 4 * 1024 * 1024;

/// The tunnel type Wintun records for the adapter. Cosmetic — it shows up in
/// `netsh interface show` and Windows' own adapter properties — but fixed
/// rather than configurable, since nothing downstream reads it back.
const TUNNEL_TYPE: &str = "Karst";

/// Largest packet Wintun will carry — `WINTUN_MAX_IP_PACKET_SIZE` in
/// `wintun.h`. Karst's own [`TunConfig::mtu`] is always far below this
/// (spec §13.6 bounds it to 1280–1500-ish), so this is a sanity bound on
/// `send`, not one `validate_mtu` needs to know about.
const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xFFFF;

/// An open Wintun adapter and session.
///
/// Dropping this ends the session, then closes the adapter — Wintun removes
/// a created adapter on close, so like `utun` (and unlike Linux's persistent
/// option) a crashed daemon does not leave a dead interface routing traffic
/// into a black hole.
pub struct Tun {
    // Declaration order is drop order: the session must end before the
    // adapter it was started on is closed.
    session: sys::Session,
    adapter: sys::Adapter,
    shutdown: sys::ShutdownEvent,
    name: String,
    mtu: usize,
    luid: sys::Luid,
    /// [`TunConfig::nonblocking`], carried through to [`Tun::recv`]: Wintun's
    /// ring has no blocking mode to configure at creation the way Linux's
    /// `O_NONBLOCK` does, so the distinction only exists at the point `recv`
    /// decides whether to wait for the read event.
    nonblocking: bool,
}

impl std::fmt::Debug for Tun {
    // Manual rather than `#[derive(Debug)]`: `sys::Luid` is a Win32 union
    // with no `Debug` impl of its own. `Value` is its 64-bit form — every
    // arm of the union agrees on it, so reading it back out is always valid
    // regardless of which arm was last written.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tun")
            .field("session", &self.session)
            .field("adapter", &self.adapter)
            .field("shutdown", &self.shutdown)
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("luid", &sys::luid_value(self.luid))
            .field("nonblocking", &self.nonblocking)
            .finish()
    }
}

impl Tun {
    /// Create a Wintun adapter and start a session on it.
    ///
    /// **`dll_path` must be an absolute path into the protected install
    /// directory.** ADR-0017: the DLL is never located by searching the
    /// working directory or `PATH`. `bins/karstd` is responsible for passing
    /// `%ProgramFiles%\Karst\wintun.dll` (plan §7) once the MSI lands; there
    /// is no default here to guess wrong silently.
    ///
    /// # Errors
    /// [`TunError::InvalidName`] or [`TunError::InvalidMtu`] for a
    /// configuration that cannot work up front, matching the other
    /// platforms; [`TunError::OpenDevice`] if `wintun.dll` cannot be loaded
    /// or its expected exports resolved; [`TunError::Ioctl`] if adapter
    /// creation or session start is refused — without Administrator, that is
    /// `ERROR_ACCESS_DENIED`.
    pub fn create(cfg: &TunConfig, dll_path: &Path) -> Result<Self, TunError> {
        encode_name(&cfg.name)?;
        validate_mtu(cfg.mtu)?;

        let wintun = sys::Wintun::load(dll_path).map_err(TunError::OpenDevice)?;
        let adapter = wintun
            .create_adapter(&cfg.name, TUNNEL_TYPE)
            .map_err(|source| TunError::Ioctl {
                op: "WintunCreateAdapter",
                source,
            })?;
        let luid = wintun.adapter_luid(&adapter);
        let session = wintun
            .start_session(&adapter, RING_CAPACITY)
            .map_err(|source| TunError::Ioctl {
                op: "WintunStartSession",
                source,
            })?;
        let shutdown = sys::ShutdownEvent::new().map_err(|source| TunError::Ioctl {
            op: "CreateEventW(shutdown)",
            source,
        })?;

        Ok(Self {
            session,
            adapter,
            shutdown,
            // Unlike macOS, Wintun honors the requested name outright rather
            // than allocating its own — `WintunCreateAdapter`'s `Name` is
            // authoritative, so this is a fact rather than an assumption.
            name: cfg.name.clone(),
            mtu: cfg.mtu,
            luid,
            nonblocking: cfg.nonblocking,
        })
    }

    /// Whether segmentation offload is active.
    ///
    /// Always false — see the module documentation.
    #[must_use]
    pub fn offload(&self) -> bool {
        false
    }

    /// The interface name. Always the one requested — see [`Tun::create`].
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Kernel interface index, looked up from the adapter's LUID.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if the LUID no longer names a live interface.
    pub fn ifindex(&self) -> Result<u32, TunError> {
        sys::luid_to_index(self.luid).map_err(|source| TunError::Ioctl {
            op: "ConvertInterfaceLuidToIndex",
            source,
        })
    }

    /// Signal the reader thread blocked in [`Tun::recv`] to stop.
    ///
    /// See the module documentation's point 2: this exists so a future
    /// Windows service (plan §5) has a graceful `SERVICE_CONTROL_STOP` path
    /// rather than only `ExitProcess`. Idempotent — safe to call more than
    /// once, including racing a power-resume handler against an operator
    /// stop.
    pub fn request_shutdown(&self) {
        self.shutdown.signal();
    }

    /// Read one outbound IP packet from the host, waiting for one if
    /// necessary.
    ///
    /// Blocks on the session's read-wait event and the shutdown event
    /// together (module documentation point 2) unless [`TunConfig::nonblocking`]
    /// was set, in which case an empty ring reports `WouldBlock` immediately
    /// — the same contract [`crate::linux::Tun::recv`] gives for
    /// `O_NONBLOCK`.
    ///
    /// # Errors
    /// [`TunError::BufferTooSmall`] for an undersized buffer;
    /// [`TunError::Io`] on a Wintun failure, a non-blocking device with
    /// nothing to read (`ErrorKind::WouldBlock`), or after
    /// [`Tun::request_shutdown`] (`ErrorKind::Interrupted` — the caller's
    /// loop is expected to check its own shutdown flag on any `Err`, exactly
    /// as `bins/karstd/src/run.rs`'s host-read loop already does for every
    /// platform).
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu,
            });
        }
        loop {
            match self.session.receive().map_err(TunError::Io)? {
                Some(packet) => {
                    let bytes = packet.bytes();
                    let n = bytes.len().min(buf.len());
                    if let Some(dst) = buf.get_mut(..n) {
                        if let Some(src) = bytes.get(..n) {
                            dst.copy_from_slice(src);
                        }
                    }
                    return Ok(n);
                }
                None if self.nonblocking => {
                    return Err(TunError::Io(io::Error::from(io::ErrorKind::WouldBlock)));
                }
                None => {
                    match sys::wait_for_data_or_shutdown(self.session.read_event(), &self.shutdown)
                        .map_err(TunError::Io)?
                    {
                        Wake::DataReady => {}
                        Wake::Shutdown => {
                            return Err(TunError::Io(io::Error::from(io::ErrorKind::Interrupted)))
                        }
                    }
                }
            }
        }
    }

    /// Read from the device, splitting a coalesced segment if there is one.
    ///
    /// There never is one: Wintun has no offload, so this always yields
    /// exactly one packet — as [`crate::macos::Tun::recv_segments`].
    ///
    /// # Errors
    /// As [`Tun::recv`].
    pub fn recv_segments(&self, buf: &mut [u8], out: &mut Vec<Vec<u8>>) -> Result<usize, TunError> {
        out.clear();
        let n = self.recv(buf)?;
        out.push(buf.get(..n).unwrap_or_default().to_vec());
        Ok(out.len())
    }

    /// Write one inbound IP packet to the host.
    ///
    /// # Errors
    /// [`TunError::PacketTooLarge`] if the packet exceeds the interface MTU
    /// or Wintun's own maximum; [`TunError::Io`] if the send ring is full
    /// (`ERROR_BUFFER_OVERFLOW`) or the adapter is terminating.
    pub fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.len() > self.mtu || packet.len() > WINTUN_MAX_IP_PACKET_SIZE {
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        self.session.send(packet).map_err(TunError::Io)?;
        Ok(packet.len())
    }

    /// Assign an IPv4 address with a prefix length.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `CreateUnicastIpAddressEntry` refuses.
    pub fn set_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        self.create_address(IpAddr::V4(addr), prefix_len)?;
        self.add_route(IpAddr::V4(addr), prefix_len)
    }

    /// Assign an IPv6 address with a prefix length.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `CreateUnicastIpAddressEntry` refuses.
    pub fn set_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> Result<(), TunError> {
        self.create_address(IpAddr::V6(addr), prefix_len)?;
        self.add_route(IpAddr::V6(addr), prefix_len)
    }

    /// Assign either family.
    ///
    /// # Errors
    /// As [`Tun::set_ipv4`] and [`Tun::set_ipv6`].
    pub fn set_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match addr {
            IpAddr::V4(a) => self.set_ipv4(a, prefix_len),
            IpAddr::V6(a) => self.set_ipv6(a, prefix_len),
        }
    }

    /// Add `addr/prefix_len` **without** displacing an address already
    /// assigned.
    ///
    /// Unlike `ifconfig`, `CreateUnicastIpAddressEntry` is always additive —
    /// see `sys_windows::create_unicast_address` — so this and
    /// [`Tun::set_address`] do the same thing on Windows. Both are kept as
    /// separate methods to match the shape `NetworkDevice` in
    /// `bins/karstd/src/run.rs` dispatches on for every platform.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `CreateUnicastIpAddressEntry` refuses.
    pub fn add_secondary_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        self.create_address(addr, prefix_len)
    }

    fn create_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        sys::create_unicast_address(self.luid, addr, prefix_len).map_err(|source| TunError::Ioctl {
            op: "CreateUnicastIpAddressEntry",
            source,
        })
    }

    /// Route `dst/prefix_len` over this interface, on-link with no gateway.
    ///
    /// Adding a route that already exists succeeds — see
    /// `sys_windows::create_forward_route` — for the same reason
    /// [`crate::macos::Tun::add_route`] tolerates it: a daemon restart must
    /// not fail on routes it left behind, and this must not collide with a
    /// netmap entry for the same prefix.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `CreateIpForwardEntry2` refuses for any other
    /// reason. Without Administrator that is `ERROR_ACCESS_DENIED`.
    pub fn add_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        sys::create_forward_route(self.luid, dst, prefix_len).map_err(|source| TunError::Ioctl {
            op: "CreateIpForwardEntry2",
            source,
        })
    }

    /// Stop routing `dst/prefix_len` over this interface.
    ///
    /// A route that is already absent is **not** an error — see
    /// `sys_windows::delete_forward_route`.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `DeleteIpForwardEntry2` refuses for any other
    /// reason.
    pub fn remove_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        sys::delete_forward_route(self.luid, dst, prefix_len).map_err(|source| TunError::Ioctl {
            op: "DeleteIpForwardEntry2",
            source,
        })
    }
}
