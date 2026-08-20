// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// ADR-0003 permits `unsafe` in this crate. It is confined to `sys`, which
// carries the sole `allow(unsafe_code)` and whose every block states its
// argument; the rest of the crate — including the packet parser that reads
// bytes decrypted from a peer — cannot contain any.
#![deny(unsafe_code)]

//! Linux TUN device: where Karst meets the host's network stack.
//!
//! A TUN interface in `IFF_TUN`/`IFF_NO_PI` mode is a file descriptor that
//! yields one bare IP packet per read and injects one per write. The kernel
//! routes to it like any other interface, so `karstd` reads outbound packets
//! here, encrypts them, and writes inbound plaintext back.
//!
//! # Privileges
//!
//! Creating an interface needs `CAP_NET_ADMIN`, and so does setting its MTU,
//! address, or flags. `/dev/net/tun` itself is usually world-accessible, so an
//! unprivileged process opens the device successfully and then fails at
//! `TUNSETIFF` — which is why [`TunError::Ioctl`] names the operation.
//!
//! # MTU
//!
//! The tunnel MTU is fixed at [`karst_proto::consts::TUNNEL_MTU`], and both
//! bounds are load-bearing (spec §13.6):
//!
//! - **Not lower.** Nodes carry a ULA IPv6 address, and RFC 8200 §5 requires
//!   1280 on any link that carries IPv6.
//! - **Not higher.** A larger packet would not fit one PHREATIC datagram, and
//!   §8 forbids fragmenting transport messages.
//!
//! [`validate_mtu`] therefore rejects any other value rather than accepting a
//! configuration that would fail later, on the data path, as lost packets.

pub mod ip;
pub mod userspace;
pub mod vnet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use linux::Tun;
pub use userspace::{TcpHandle, Userspace};

use std::fmt;
use std::io;

use karst_proto::consts::TUNNEL_MTU;

/// Interface names are at most 15 bytes plus a terminating NUL.
pub const MAX_NAME_LEN: usize = 15;

/// Default interface name.
pub const DEFAULT_NAME: &str = "karst0";

/// How to bring up a TUN interface.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Requested interface name. Empty asks the kernel to allocate one.
    pub name: String,
    /// Tunnel MTU. Must be [`TUNNEL_MTU`] — a field rather than a bare
    /// constant because path MTU discovery (PLAN.md Phase 6) is where this
    /// starts to vary, and that is the moment the checks here must be revisited
    /// rather than deleted.
    pub mtu: usize,
    /// Open the device non-blocking, for a poll-driven event loop.
    pub nonblocking: bool,
    /// Request `IFF_VNET_HDR` and segmentation offload.
    ///
    /// Best-effort: if the kernel declines, the device still comes up and
    /// returns one packet per read. Check [`Tun::offload`] for what actually
    /// happened rather than assuming this was honoured.
    pub offload: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_NAME.to_owned(),
            mtu: TUNNEL_MTU,
            nonblocking: false,
            offload: false,
        }
    }
}

/// Why a TUN operation failed.
#[derive(Debug)]
pub enum TunError {
    /// `/dev/net/tun` could not be opened. Usually the `tun` module is not
    /// loaded, or a container lacks the device node.
    OpenDevice(io::Error),
    /// An `ioctl` failed. `op` names it, because `EPERM` alone says nothing
    /// about which privilege was missing.
    Ioctl {
        /// The operation that failed.
        op: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The requested name is too long or contains bytes the kernel will not
    /// accept in an interface name.
    InvalidName(String),
    /// The requested MTU is not the one the protocol permits.
    InvalidMtu {
        /// What was asked for.
        requested: usize,
        /// The only permitted value.
        required: usize,
    },
    /// A packet handed to `Tun::send` exceeds the interface MTU. The kernel
    /// would drop it silently.
    PacketTooLarge {
        /// Packet length.
        len: usize,
        /// Interface MTU.
        mtu: usize,
    },
    /// A receive buffer smaller than the MTU. The kernel truncates a packet
    /// that does not fit and reports no error, so this is refused up front
    /// rather than corrupting traffic invisibly.
    BufferTooSmall {
        /// Buffer length.
        len: usize,
        /// Interface MTU.
        mtu: usize,
    },
    /// A read or write on the device failed.
    Io(io::Error),
    /// A netlink request failed. `op` names it, because `EPERM` alone says
    /// nothing about which privilege was missing — routes need `CAP_NET_ADMIN`
    /// just as interface creation does.
    Netlink {
        /// The request that failed.
        op: &'static str,
        /// The underlying error.
        source: io::Error,
    },
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenDevice(e) => write!(f, "opening /dev/net/tun: {e}"),
            Self::Ioctl { op, source } | Self::Netlink { op, source } => {
                write!(f, "{op}: {source}")
            }
            Self::InvalidName(n) => write!(
                f,
                "invalid interface name {n:?}: at most {MAX_NAME_LEN} bytes of \
                 ASCII alphanumerics, '-', '_' or '.'"
            ),
            Self::InvalidMtu {
                requested,
                required,
            } => write!(
                f,
                "MTU {requested} is not permitted; Karst requires exactly \
                 {required} (spec §13.6: below it IPv6 cannot run inside the \
                 tunnel, above it transport messages would fragment)"
            ),
            Self::PacketTooLarge { len, mtu } => {
                write!(f, "packet of {len} B exceeds the {mtu} B interface MTU")
            }
            Self::BufferTooSmall { len, mtu } => write!(
                f,
                "receive buffer of {len} B is smaller than the {mtu} B MTU; a \
                 larger packet would be truncated without an error"
            ),
            Self::Io(e) => write!(f, "tun I/O: {e}"),
        }
    }
}

impl std::error::Error for TunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenDevice(e)
            | Self::Io(e)
            | Self::Ioctl { source: e, .. }
            | Self::Netlink { source: e, .. } => Some(e),
            _ => None,
        }
    }
}

/// Validate an interface name and encode it for the kernel.
///
/// The kernel is stricter than it looks: a name containing `/` or `:` breaks
/// the sysfs paths every tool uses to inspect the interface, and the kernel
/// reports only `EINVAL`. Rejecting here gives an operator something to act on.
///
/// # Errors
/// [`TunError::InvalidName`] if the name cannot be used.
pub fn encode_name(name: &str) -> Result<[u8; 16], TunError> {
    let invalid = || TunError::InvalidName(name.to_owned());
    if name.len() > MAX_NAME_LEN || name == "." || name == ".." {
        return Err(invalid());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(invalid());
    }
    let mut out = [0u8; 16];
    if let Some(head) = out.get_mut(..name.len()) {
        head.copy_from_slice(name.as_bytes());
    }
    Ok(out)
}

/// Decode a NUL-padded kernel interface name.
#[must_use]
pub fn decode_name(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(raw.get(..end).unwrap_or_default()).into_owned()
}

/// Every global-scope unicast address this host currently holds.
///
/// **Not a tunnel operation, and here anyway.** AVEN needs the addresses a
/// peer might reach this node on (`spec/aven-v1.md` §7.3), which needs
/// `AF_NETLINK` and therefore `unsafe` — and ADR-0003 keeps every such call in
/// this crate. Putting it anywhere else would mean a second file with an
/// `unsafe` allow in it, which is the property that decision buys.
///
/// Loopback, link-local, tentative and deprecated addresses are already
/// excluded: a peer cannot reach any of them, so their absence is a fact about
/// the address rather than a policy choice. **The caller must still exclude
/// its own overlay addresses** — this reports what the host has, including the
/// tunnel's, and advertising a tunnel address as a way to reach the tunnel is
/// a loop.
///
/// # Errors
/// [`TunError::Netlink`] if the socket cannot be opened or the dump fails.
#[cfg(target_os = "linux")]
pub fn local_addresses() -> Result<Vec<std::net::IpAddr>, TunError> {
    use std::os::fd::AsFd as _;

    let sock = sys::netlink_socket().map_err(|source| TunError::Netlink {
        op: "socket(AF_NETLINK)",
        source,
    })?;
    sys::local_addresses(sock.as_fd(), 1).map_err(|source| TunError::Netlink {
        op: "RTM_GETADDR",
        source,
    })
}

/// The next hop of the main-table default route, if this host has one.
///
/// Karst uses this as the well-known port-mapping gateway when explicit NAT
/// traversal is enabled: NAT-PMP and PCP are spoken to the default gateway's
/// next hop rather than discovered by multicast.
///
/// # Errors
/// [`TunError::Netlink`] if the socket cannot be opened or the dump fails.
#[cfg(target_os = "linux")]
pub fn default_gateway() -> Result<Option<std::net::IpAddr>, TunError> {
    use std::os::fd::AsFd as _;

    let sock = sys::netlink_socket().map_err(|source| TunError::Netlink {
        op: "socket(AF_NETLINK)",
        source,
    })?;
    sys::default_gateway(sock.as_fd(), 2).map_err(|source| TunError::Netlink {
        op: "RTM_GETROUTE",
        source,
    })
}

/// Check a requested MTU against what the protocol permits.
///
/// # Errors
/// [`TunError::InvalidMtu`] for any value other than [`TUNNEL_MTU`].
pub fn validate_mtu(mtu: usize) -> Result<(), TunError> {
    if mtu == TUNNEL_MTU {
        Ok(())
    } else {
        Err(TunError::InvalidMtu {
            requested: mtu,
            required: TUNNEL_MTU,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn valid_names_round_trip() {
        for name in ["karst0", "k", "karst-1", "a.b_c", "abcdefghijklmno"] {
            let encoded = encode_name(name).expect("valid name");
            assert_eq!(decode_name(&encoded), name);
        }
    }

    /// A 16-byte name leaves no room for the terminating NUL.
    #[test]
    fn rejects_names_the_kernel_cannot_hold() {
        assert!(matches!(
            encode_name("abcdefghijklmnop"),
            Err(TunError::InvalidName(_))
        ));
    }

    #[test]
    fn rejects_names_that_break_sysfs() {
        for bad in ["karst/0", "karst:0", "karst 0", "karst\0", ".", ".."] {
            assert!(
                matches!(encode_name(bad), Err(TunError::InvalidName(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    /// An empty name is legal: it asks the kernel to allocate `tunN`.
    #[test]
    fn an_empty_name_asks_the_kernel_to_choose() {
        assert_eq!(encode_name("").expect("empty is valid"), [0u8; 16]);
    }

    #[test]
    fn decoding_tolerates_an_unterminated_name() {
        assert_eq!(decode_name(&[b'x'; 16]), "x".repeat(16));
    }

    /// Both bounds matter and both are enforced — §13.6.
    #[test]
    fn only_the_protocol_mtu_is_accepted() {
        assert!(validate_mtu(TUNNEL_MTU).is_ok());
        for bad in [0, 576, 1279, 1281, 1500, 9000] {
            assert!(
                matches!(validate_mtu(bad), Err(TunError::InvalidMtu { .. })),
                "MTU {bad} must be rejected"
            );
        }
    }

    /// The error has to explain itself: an operator who sets 1500 needs to know
    /// why the value they use everywhere else is refused here.
    #[test]
    fn the_mtu_error_explains_both_bounds() {
        let msg = validate_mtu(1500).unwrap_err().to_string();
        assert!(msg.contains("1280"), "must name the required value: {msg}");
        assert!(msg.contains("§13.6"), "must cite the spec: {msg}");
        assert!(
            msg.contains("IPv6"),
            "must give the lower-bound reason: {msg}"
        );
        assert!(
            msg.contains("fragment"),
            "must give the upper-bound reason: {msg}"
        );
    }

    #[test]
    fn the_default_config_is_the_one_the_protocol_requires() {
        let cfg = TunConfig::default();
        assert!(validate_mtu(cfg.mtu).is_ok());
        assert!(encode_name(&cfg.name).is_ok());
    }
}
