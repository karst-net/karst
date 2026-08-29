// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The macOS `utun` interface.
//!
//! Safe throughout — every syscall goes through [`crate::sys_macos`], and every
//! byte format through [`crate::macos_wire`].
//!
//! # How this differs from Linux, and where those differences stop
//!
//! The public surface here is deliberately identical to [`crate::linux::Tun`],
//! so `karstd` compiles against one type and the datapath never learns which
//! platform it is on. Four differences are absorbed inside this module:
//!
//! 1. **A four-byte address family prefixes every frame.** Read and write use
//!    vectored I/O with the header in its own slice, so the prefix is added and
//!    removed without copying the packet and without the caller seeing it.
//! 2. **The interface name is not ours to choose.** macOS assigns `utunN`.
//!    [`crate::TunConfig::name`] is therefore a *preference*: a `utunN` request
//!    is honored, anything else — including the `karst0` default — lets the
//!    kernel allocate, and [`Tun::name`] reports what it actually got.
//! 3. **There is no offload.** `utun` has no counterpart to `TUNSETOFFLOAD`,
//!    so [`Tun::offload`] is always false and `recv_segments` yields exactly
//!    one packet. That is the unaccelerated path, which already exists and is
//!    already correct — not a stub that pretends.
//! 4. **Addressing and routing go through `ifconfig` and `route`.**
//!
//! # On shelling out
//!
//! Point 4 is the one that looks wrong and is not. The in-process equivalents
//! are `SIOCAIFADDR` and `PF_ROUTE` sockets, both `unsafe` and both fiddly
//! enough to be a second module the size of `sys.rs` — 1 500 lines of ABI on
//! the critical path of a packaging phase, on an ABI nobody here can test
//! against until a Mac is in CI. `ifconfig` and `route` are present on every
//! macOS install, are the interface Apple documents for exactly this, and
//! report failures on stderr, which [`TunError::Tool`] passes through verbatim.
//!
//! The cost is real and is stated rather than hidden: two `fork`/`exec` pairs
//! per address and one per route change. None of that is on the datapath —
//! addresses are assigned at startup and routes change when the netmap does —
//! so it costs milliseconds at times measured in minutes.
//!
//! Phase 7 revisits it, because the mobile port needs the in-process version
//! behind `NEPacketTunnelProvider` anyway. See `plans/phase-5/06-macos-client.md` §2.

use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::process::Command;

use crate::macos_wire::{af_header, family_agrees, AF_HEADER_LEN};
use crate::sys_macos as sys;
use crate::{encode_name, validate_mtu, TunConfig, TunError};

/// The prefix macOS gives every `utun` interface.
const UTUN_PREFIX: &str = "utun";

/// An open `utun` interface.
///
/// Dropping this closes the descriptor, and the kernel removes the interface.
/// `utun` devices have no persistence flag at all, so unlike Linux this is not
/// a choice — but it is the same behavior, and for the same reason: a crashed
/// daemon must not leave a dead interface routing traffic into a black hole.
#[derive(Debug)]
pub struct Tun {
    dev: File,
    name: String,
    mtu: usize,
}

impl Tun {
    /// Create and configure a `utun` interface.
    ///
    /// The interface is created, its MTU set, and it is brought up. Addresses
    /// are assigned separately — see [`Tun::set_ipv4`] and [`Tun::set_ipv6`] —
    /// because the control plane supplies them later than interface creation.
    ///
    /// # Errors
    /// [`TunError::InvalidName`] or [`TunError::InvalidMtu`] for a
    /// configuration that cannot work; [`TunError::OpenDevice`] if the
    /// `PF_SYSTEM` socket cannot be opened; [`TunError::Ioctl`] if a step is
    /// refused, which without root means `connect` failing with `EPERM`;
    /// [`TunError::Tool`] if `ifconfig` refuses the MTU.
    pub fn create(cfg: &TunConfig) -> Result<Self, TunError> {
        // The name is a preference here, not a request — but an unusable one is
        // still worth refusing at the same point Linux refuses it, rather than
        // silently ignoring a typo the operator will spend an hour looking for.
        encode_name(&cfg.name)?;
        validate_mtu(cfg.mtu)?;

        let dev = sys::utun_socket().map_err(TunError::OpenDevice)?;
        let ctl_id = sys::utun_control_id(dev.as_fd()).map_err(|source| TunError::Ioctl {
            op: "CTLIOCGINFO(com.apple.net.utun_control)",
            source,
        })?;
        sys::utun_connect(dev.as_fd(), ctl_id, requested_unit(&cfg.name)).map_err(|source| {
            TunError::Ioctl {
                op: "connect(AF_SYS_CONTROL)",
                source,
            }
        })?;
        let name = sys::utun_name(dev.as_fd()).map_err(|source| TunError::Ioctl {
            op: "getsockopt(UTUN_OPT_IFNAME)",
            source,
        })?;

        if cfg.nonblocking {
            sys::set_nonblocking(dev.as_fd()).map_err(|source| TunError::Ioctl {
                op: "fcntl(O_NONBLOCK)",
                source,
            })?;
        }

        // MTU and link state in one call. `ifconfig` refuses both together only
        // if it would refuse either alone, so nothing is hidden by combining
        // them, and it halves the process spawns at startup.
        ifconfig(&[&name, "mtu", &cfg.mtu.to_string(), "up"])?;

        Ok(Self {
            dev: File::from(dev),
            name,
            mtu: cfg.mtu,
        })
    }

    /// Whether segmentation offload is active on this device.
    ///
    /// Always false: `utun` has no offload to enable. The batched paths exist
    /// and are correct without it — they simply carry one packet each.
    #[must_use]
    pub fn offload(&self) -> bool {
        false
    }

    /// The interface name the kernel assigned.
    ///
    /// **Not the configured name.** macOS names `utun` devices itself; see the
    /// module documentation.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Kernel interface index.
    ///
    /// Looked up when requested rather than cached, for the reason the Linux
    /// path gives: an interface may be removed and recreated under the same
    /// name by something outside this process.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] when the lookup fails, including when the interface
    /// disappeared concurrently.
    pub fn ifindex(&self) -> Result<u32, TunError> {
        sys::interface_index(&self.name).map_err(|source| TunError::Ioctl {
            op: "if_nametoindex",
            source,
        })
    }

    /// The raw descriptor, for registering with an event loop.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }

    /// Assign an IPv4 address with a prefix length.
    ///
    /// `utun` is a point-to-point interface, so `ifconfig` wants a destination
    /// as well as a source. Karst gives it the address itself — the far end of
    /// this link is not one peer but the whole mesh, and naming any single peer
    /// there would be a lie the routing table then has to work around.
    ///
    /// The on-link prefix route is added explicitly afterwards. Linux gets it
    /// for free from `SIOCSIFNETMASK`; macOS does not create it for a
    /// point-to-point interface, and without it the kernel hands the tunnel
    /// nothing but traffic for the single host address.
    ///
    /// # Errors
    /// [`TunError::Tool`] if `ifconfig` or `route` refuses.
    pub fn set_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        let mask = Ipv4Addr::from(
            u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0),
        );
        ifconfig(&[
            &self.name,
            "inet",
            &addr.to_string(),
            &addr.to_string(),
            "netmask",
            &mask.to_string(),
        ])?;
        self.add_route(IpAddr::V4(addr), prefix_len)
    }

    /// Assign an IPv6 address with a prefix length.
    ///
    /// # Errors
    /// [`TunError::Tool`] if `ifconfig` or `route` refuses.
    pub fn set_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> Result<(), TunError> {
        ifconfig(&[&self.name, "inet6", &format!("{addr}/{prefix_len}")])?;
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

    /// Add `addr/prefix_len` **without** displacing the address
    /// [`Tun::set_address`] already assigned.
    ///
    /// `alias` is what makes this additive. Without it `ifconfig` replaces the
    /// interface's address of that family, which is the same trap
    /// `SIOCSIFADDR` sets on Linux and has the same consequence: the node ends
    /// up holding only the `KarstDNS` stub address and is unreachable as a mesh
    /// peer.
    ///
    /// # Errors
    /// [`TunError::Tool`] if `ifconfig` refuses.
    pub fn add_secondary_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match addr {
            IpAddr::V4(a) => {
                let mask = Ipv4Addr::from(
                    u32::MAX
                        .checked_shl(32 - u32::from(prefix_len))
                        .unwrap_or(0),
                );
                ifconfig(&[
                    &self.name,
                    "inet",
                    &a.to_string(),
                    &a.to_string(),
                    "netmask",
                    &mask.to_string(),
                    "alias",
                ])
            }
            IpAddr::V6(a) => {
                ifconfig(&[&self.name, "inet6", &format!("{a}/{prefix_len}"), "alias"])
            }
        }
    }

    /// Route `dst/prefix_len` over this interface.
    ///
    /// On-link, with no gateway, for the reason the Linux path gives: a tunnel
    /// peer is not behind a next hop, it *is* the far end of the interface.
    ///
    /// Adding a route that already exists succeeds rather than failing, so a
    /// daemon restart does not come up missing routes it left behind — and so
    /// that [`Tun::set_ipv4`]'s connected route does not collide with a netmap
    /// entry for the same prefix.
    ///
    /// # Errors
    /// [`TunError::Tool`] if `route` refuses for any other reason. Without root
    /// that is `EPERM`, reported with the tool's own message.
    pub fn add_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match self.route("add", dst, prefix_len) {
            Err(TunError::Tool { detail, .. }) if mentions(&detail, &["file exists", "eexist"]) => {
                Ok(())
            }
            other => other,
        }
    }

    /// Stop routing `dst/prefix_len` over this interface.
    ///
    /// # Errors
    /// [`TunError::Tool`] if `route` refuses. A route that is already absent is
    /// **not** an error: the desired state is what matters, and something else
    /// having removed it first is not a failure.
    pub fn remove_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match self.route("delete", dst, prefix_len) {
            Err(TunError::Tool { detail, .. })
                if mentions(&detail, &["not in table", "esrch", "no such process"]) =>
            {
                Ok(())
            }
            other => other,
        }
    }

    fn route(&self, op: &str, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let max = if dst.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(TunError::Tool {
                tool: "route",
                detail: format!("prefix length /{prefix_len} exceeds /{max} for this family"),
            });
        }
        let family = if dst.is_ipv4() { "-inet" } else { "-inet6" };
        run(
            "route",
            &[
                "-q",
                "-n",
                op,
                family,
                &format!("{dst}/{prefix_len}"),
                "-interface",
                &self.name,
            ],
        )
    }

    /// Read one outbound IP packet from the host.
    ///
    /// The four-byte address family macOS prefixes is stripped here and never
    /// reaches the caller — `buf` receives a bare IP packet, exactly as on
    /// Linux.
    ///
    /// **`read_vectored`, not a read into a scratch buffer.** The kernel
    /// scatters the header into its own four-byte slice and the packet
    /// straight into `buf`, so the prefix costs no copy and no allocation per
    /// packet. It is also plain safe Rust — `IoSliceMut` is the standard
    /// library's own wrapper over `iovec`.
    ///
    /// # Errors
    /// [`TunError::BufferTooSmall`] for an undersized buffer; [`TunError::Io`]
    /// on a read failure, including `WouldBlock` on a non-blocking device, or
    /// on a frame whose declared family contradicts its contents.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu,
            });
        }
        let mut header = [0u8; AF_HEADER_LEN];
        // `&self`, not `&mut self`, for the reason `linux::Tun::recv` gives: a
        // blocking read must not hold a lock the write path needs.
        let n = (&self.dev)
            .read_vectored(&mut [IoSliceMut::new(&mut header), IoSliceMut::new(buf)])
            .map_err(TunError::Io)?;

        let payload = n.checked_sub(AF_HEADER_LEN).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "utun frame shorter than its address-family header",
            ))
        })?;
        // The header and the packet arrived in separate slices, so validating
        // them means checking the declared family against the version nibble
        // rather than re-splitting a buffer.
        //
        // **`buf[..payload]`, not `buf`.** `buf` is reused across calls, so on
        // a frame that carried a header and nothing else the first byte is
        // whatever the *previous* packet left there — and validating against
        // that would be reading one frame's family against another frame's
        // contents. Narrowing to what this read actually delivered makes an
        // empty payload fail as an empty payload.
        let packet = buf.get(..payload).unwrap_or_default();
        if family_agrees(header, packet) {
            Ok(payload)
        } else {
            Err(TunError::Io(std::io::Error::other(format!(
                "utun frame declares address family {} but carries {}",
                u32::from_be_bytes(header),
                packet.first().map_or_else(
                    || "no payload".to_owned(),
                    |b| format!("IP version {}", b >> 4)
                )
            ))))
        }
    }

    /// Read from the device, splitting a coalesced segment if there is one.
    ///
    /// There never is one: `utun` has no offload, so this always yields exactly
    /// one packet. It exists so the caller's loop is the same on both
    /// platforms, and it is the real single-packet path rather than a stub.
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
    /// The address-family header is prepended here. Getting this wrong in the
    /// other direction — omitting it — makes macOS discard the write silently,
    /// with no error to explain a tunnel that carries nothing.
    ///
    /// Takes `&self` for the reason given on [`Tun::recv`].
    ///
    /// # Errors
    /// [`TunError::PacketTooLarge`] if the packet exceeds the MTU;
    /// [`TunError::Io`] on a write failure or a payload that is not IP.
    pub fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        let header = af_header(packet).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "refusing to write a frame that is not an IPv4 or IPv6 packet: \
                 macOS would need an address family for it, and guessing one \
                 makes the kernel drop the write without an error",
            ))
        })?;
        let written = (&self.dev)
            .write_vectored(&[IoSlice::new(&header), IoSlice::new(packet)])
            .map_err(TunError::Io)?;
        Ok(written.saturating_sub(AF_HEADER_LEN))
    }
}

impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.dev.as_fd()
    }
}

/// The `sockaddr_ctl` unit a name preference asks for.
///
/// `utun3` is unit 4 — the unit is one greater than the number in the name —
/// and **unit 0 asks the kernel to allocate the first free interface**, which
/// is what anything not of the form `utunN` gets. That includes the `karst0`
/// default, deliberately: a Linux-shaped name is a preference macOS cannot
/// honor, and refusing to start over it would be worse than allocating.
fn requested_unit(preference: &str) -> u32 {
    preference
        .strip_prefix(UTUN_PREFIX)
        .and_then(|n| n.parse::<u32>().ok())
        .and_then(|n| n.checked_add(1))
        .unwrap_or(0)
}

/// Whether a tool's message names one of the conditions the caller tolerates.
///
/// Matched on text because that is what `route` gives: it reports `EEXIST` as
/// "File exists" on stderr and exits 1, with no distinguishing exit code. The
/// alternative is treating every failure alike, which would make a permission
/// error indistinguishable from a route that was already there.
fn mentions(detail: &str, needles: &[&str]) -> bool {
    let detail = detail.to_ascii_lowercase();
    needles.iter().any(|n| detail.contains(n))
}

/// Run `ifconfig` with the given arguments.
fn ifconfig(args: &[&str]) -> Result<(), TunError> {
    run("ifconfig", args)
}

/// Run one of the two system tools, reporting its own message on failure.
///
/// The tools are named absolutely. A `PATH` this daemon does not control is
/// not a good input to a process that runs as root, and both live in `/sbin`
/// on every macOS release.
fn run(tool: &'static str, args: &[&str]) -> Result<(), TunError> {
    let output = Command::new(format!("/sbin/{tool}"))
        .args(args)
        .output()
        .map_err(|source| TunError::Tool {
            tool,
            detail: source.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    // stderr first — it is where both tools put the reason — falling back to
    // the exit status when they said nothing at all.
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let detail = if stderr.is_empty() {
        format!("{} exited with {}", args.join(" "), output.status)
    } else {
        format!("{}: {stderr}", args.join(" "))
    };
    Err(TunError::Tool { tool, detail })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// The off-by-one is the whole point: `utun3` is unit 4, and getting it
    /// wrong opens the interface next to the one the operator asked for.
    #[test]
    fn a_utun_preference_maps_to_its_unit() {
        assert_eq!(requested_unit("utun0"), 1);
        assert_eq!(requested_unit("utun3"), 4);
        assert_eq!(requested_unit("utun17"), 18);
    }

    /// Anything else asks the kernel to allocate. `karst0` is the default and
    /// reaches here on every ordinary run, so this is the common path rather
    /// than the edge case it looks like.
    #[test]
    fn a_name_macos_cannot_honor_lets_the_kernel_choose() {
        for name in ["karst0", "", "utun", "utunx", "eth0", "utun-1"] {
            assert_eq!(requested_unit(name), 0, "{name:?} must not pin a unit");
        }
    }

    #[test]
    fn tolerated_conditions_are_recognized_case_insensitively() {
        assert!(mentions(
            "route: writing to routing socket: File exists",
            &["file exists"]
        ));
        assert!(mentions("not in table", &["not in table"]));
        assert!(!mentions(
            "route: writing to routing socket: Operation not permitted",
            &["file exists", "not in table"]
        ));
    }
}
