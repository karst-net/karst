// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The mobile TUN backend — iOS's `NEPacketTunnelProvider`, Android's
//! `VpnService` (PLAN.md §9, Phase 7, GitHub issue #117) — and, under the
//! `network-extension` feature, a macOS system extension's
//! `NEPacketTunnelProvider` (docs/adr/0026-macos-network-extension-backend.md).
//!
//! # Neither platform lets native code create the interface
//!
//! Every other backend in this crate opens or creates a device itself and
//! needs a privilege to do it — `CAP_NET_ADMIN`, root, or Administrator. On
//! iOS and Android, only the platform's own app-extension code
//! (`NEPacketTunnelProvider`/`VpnService`, which only Swift/Kotlin can drive)
//! is allowed to create the tunnel at all; the most a native library can ever
//! be given is the resulting file descriptor. A macOS system extension is
//! under the identical constraint — it is the same `NEPacketTunnelProvider`
//! API, just hosted by `launchd` instead of iOS's app-extension runtime — so
//! it needs the same adoption, not a variant of it. [`Tun::from_fd`] adopts
//! that fd rather than opening anything, which is the one structural way
//! this module differs from `linux`/`macos`/`windows` — everything
//! downstream of construction (`recv`, `send`, `mtu`, `offload`) is the same
//! shape.
//!
//! # Framing differs by platform, not by choice
//!
//! Android's fd is documented as a plain `IFF_TUN`-style descriptor — bare
//! IP packets, no header — exactly what `linux::Tun` reads and writes with
//! `IFF_NO_PI` set.
//!
//! iOS's `packetFlow` fd is a `utun` socket under the hood, the same kernel
//! primitive `macos::Tun` uses, obtained via the private (but stable, and
//! used in production by `WireGuard`'s and Tailscale's own iOS apps — there is
//! no public API for it) `socket.fileDescriptor` key-value lookup on
//! `NEPacketTunnelProvider.packetFlow`. **A macOS system extension's
//! `packetFlow` is the same API over the same kernel primitive**, so it
//! carries the identical four-byte address-family prefix and reuses the
//! same `impl Tun` block as iOS, not a third one. This module reuses
//! [`crate::macos_wire`] verbatim rather than re-deriving that framing —
//! that module compiles everywhere for exactly this reason.
//!
//! # Ownership
//!
//! This module never creates the interface, but dropping [`Tun`] still
//! closes the descriptor: Android's `ParcelFileDescriptor.detachFd()` and
//! iOS's private fd lookup both transfer ownership to native code once
//! called, and closing on drop is how a stopped tunnel tells the OS the
//! session ended — the same signal the other three platforms send by
//! removing their own interface.
//!
//! # What this slice does not attempt
//!
//! No interface index, no address/route assignment: both are the mobile
//! OS's own job (`NEPacketTunnelNetworkSettings` / `VpnService.Builder`),
//! driven from Swift/Kotlin before the fd this module adopts ever exists,
//! not from Rust. [`Tun::name`] is therefore cosmetic — see its own
//! documentation.

// This crate denies `unsafe_code` everywhere else (ADR-0003); the one use
// here is adopting a raw fd the platform side hands across the FFI boundary,
// which cannot be done safely by construction — `RawFd` is a plain `i32` any
// safe caller can invent, so *something* has to assert the fd is real,
// live, and ours alone. `Tun::from_fd` is `unsafe` for exactly that reason,
// and `set_nonblocking`'s `fcntl` pair is the same shape `sys_macos.rs`
// already uses.
#![allow(unsafe_code)]

use std::fs::File;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::io::{IoSlice, IoSliceMut};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

#[cfg(any(target_os = "ios", target_os = "macos"))]
use crate::macos_wire::{af_header, family_agrees, AF_HEADER_LEN};
use crate::{encode_name, validate_mtu, TunConfig, TunError};

/// An adopted mobile tunnel descriptor.
///
/// Dropping this closes the descriptor — see the module documentation's
/// "Ownership" section.
#[derive(Debug)]
pub struct Tun {
    dev: File,
    name: String,
    mtu: usize,
}

impl Tun {
    /// Adopt a tunnel file descriptor the platform side already created.
    ///
    /// **This creates nothing.** `fd` must already be a live tunnel: iOS's or
    /// a macOS system extension's `NEPacketTunnelProvider.packetFlow`
    /// socket, or the descriptor `ParcelFileDescriptor.detachFd()` returned
    /// from a completed `VpnService.Builder.establish()`. `cfg.name` is not
    /// the interface's real name — the platform chose that before this call
    /// and does not expose it here — it only satisfies [`Tun::name`]'s
    /// contract with the rest of the datapath, which reads it for logging,
    /// not for identity.
    ///
    /// # Safety
    /// `fd` must be a valid, open file descriptor whose ownership the caller
    /// is transferring to this `Tun`: nothing else may read it, write it,
    /// duplicate it, or close it afterward. This is the FFI boundary's own
    /// safety argument, carried across from the mobile app runtime that
    /// obtained `fd` — *exclusive ownership* is a whole-program invariant no
    /// local check can observe, which is why that half cannot be enforced
    /// here. *Openness* is a different, narrower claim this function does
    /// check, immediately, below: a caller that passes a closed, negative,
    /// or otherwise never-valid `fd` gets [`TunError::Ioctl`] instead of
    /// silently wrapping a bogus descriptor in a `File` and finding out only
    /// on the first `recv`/`send`.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if `fd` is not currently a valid, open descriptor,
    /// or if [`TunConfig::nonblocking`] was requested and the platform
    /// refuses it; [`TunError::InvalidName`] or [`TunError::InvalidMtu`] for
    /// a configuration that cannot work.
    pub unsafe fn from_fd(fd: RawFd, cfg: &TunConfig) -> Result<Self, TunError> {
        encode_name(&cfg.name)?;
        validate_mtu(cfg.mtu)?;

        // `F_GETFD` touches no memory and has no side effect beyond reading
        // the close-on-exec flag — it fails with `EBADF` for exactly the
        // fds this check exists to reject: negative, already-closed, or
        // never opened. It cannot detect a *live* fd this caller does not
        // actually own exclusively (a different process's socket number
        // reused by coincidence, say) — that half of the contract is still
        // the caller's alone, per this function's own `# Safety` section —
        // only that `fd` is some open descriptor, not garbage.
        //
        // SAFETY: `fd` is read, not dereferenced or assumed to point
        // anywhere — `fcntl(F_GETFD)` is defined for any `int` and simply
        // reports failure for one that names nothing open.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(TunError::Ioctl {
                op: "fcntl(F_GETFD)",
                source: std::io::Error::last_os_error(),
            });
        }

        // SAFETY: the caller's contract above — `fd` is ours alone from
        // here — and the check just above rules out the one part of it a
        // local call can actually verify.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if cfg.nonblocking {
            set_nonblocking(owned.as_raw_fd()).map_err(|source| TunError::Ioctl {
                op: "fcntl(O_NONBLOCK)",
                source,
            })?;
        }

        Ok(Self {
            dev: File::from(owned),
            name: cfg.name.clone(),
            mtu: cfg.mtu,
        })
    }

    /// Whether segmentation offload is active.
    ///
    /// Always false: neither platform's tunnel fd offers a coalesced-segment
    /// mode reachable from here.
    #[must_use]
    pub fn offload(&self) -> bool {
        false
    }

    /// The interface name — see [`Tun::from_fd`]: cosmetic, not the
    /// platform's own identity for this interface.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The raw descriptor, for registering with an event loop.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }

    /// Read from the device, splitting a coalesced segment if there is one.
    ///
    /// There never is one — see [`Tun::offload`] — so this always yields
    /// exactly one packet, as the other unaccelerated paths do.
    ///
    /// # Errors
    /// As [`Tun::recv`].
    pub fn recv_segments(&self, buf: &mut [u8], out: &mut Vec<Vec<u8>>) -> Result<usize, TunError> {
        out.clear();
        let n = self.recv(buf)?;
        out.push(buf.get(..n).unwrap_or_default().to_vec());
        Ok(out.len())
    }
}

#[cfg(target_os = "android")]
impl Tun {
    /// Read one outbound IP packet from the host.
    ///
    /// Android's tunnel fd carries bare IP packets, no header — the same
    /// contract Linux's `IFF_NO_PI` mode gives.
    ///
    /// # Errors
    /// [`TunError::BufferTooSmall`] for an undersized buffer; [`TunError::Io`]
    /// on a read failure, including `WouldBlock` on a non-blocking device.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu,
            });
        }
        // `&self`, not `&mut self` — see `linux::Tun::recv`'s identical note.
        (&self.dev).read(buf).map_err(TunError::Io)
    }

    /// Write one inbound IP packet to the host.
    ///
    /// # Errors
    /// [`TunError::PacketTooLarge`] if the packet exceeds the MTU;
    /// [`TunError::Io`] on a write failure.
    pub fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        (&self.dev).write(packet).map_err(TunError::Io)
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
impl Tun {
    /// Read one outbound IP packet from the host.
    ///
    /// iOS's and a macOS system extension's tunnel fd both prefix every
    /// frame with a four-byte address family, exactly as `macos::Tun::recv`
    /// reads — see that method and [`crate::macos_wire`] for the framing
    /// this mirrors verbatim.
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
        let n = (&self.dev)
            .read_vectored(&mut [IoSliceMut::new(&mut header), IoSliceMut::new(buf)])
            .map_err(TunError::Io)?;

        let payload = n.checked_sub(AF_HEADER_LEN).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "utun frame shorter than its address-family header",
            ))
        })?;
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

    /// Write one inbound IP packet to the host.
    ///
    /// The address-family header is prepended here — see
    /// `macos::Tun::send`, which this mirrors verbatim.
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
                 the kernel would need an address family for it, and guessing \
                 one makes it drop the write without an error",
            ))
        })?;
        let written = (&self.dev)
            .write_vectored(&[IoSlice::new(&header), IoSlice::new(packet)])
            .map_err(TunError::Io)?;
        Ok(written.saturating_sub(AF_HEADER_LEN))
    }
}

/// Set a raw descriptor non-blocking. The same `fcntl` pair
/// `sys_macos::set_nonblocking` uses — duplicated rather than shared because
/// that one takes a `BorrowedFd` tied to a lifetime this module's raw `fd`
/// (still `RawFd` at the point it is needed, inside [`Tun::from_fd`], before
/// an owning type exists) does not have.
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is open for the duration of both calls; `F_GETFL` and
    // `F_SETFL` take and return an int and touch no memory the caller owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cannot run in this crate's own CI today — the `karst-tun mobile
    /// targets (compile-only)` job's own name says why, and there is no
    /// macOS runner exercising `network-extension` test binaries either —
    /// but real coverage the moment a device, simulator, or a macOS runner
    /// with this feature enabled does run it, rather than something that
    /// only exists once `EngineHandle`'s own tests (issue #158/#159) reach
    /// this deep. `/dev/null` stands in for a real tunnel descriptor here
    /// deliberately: `from_fd`'s own `# Safety` section is explicit that
    /// exclusive ownership can never be checked, only openness — this test
    /// exercises exactly that narrower, real claim, nothing more.
    #[test]
    fn from_fd_refuses_a_closed_or_invalid_descriptor() {
        let cfg = TunConfig {
            name: "karsttest0".to_owned(),
            ..TunConfig::default()
        };

        // SAFETY: `-1` names no descriptor at all — this is exactly the
        // input `from_fd`'s new `fcntl(F_GETFD)` check exists to reject
        // before it ever reaches `OwnedFd::from_raw_fd`.
        let never_valid = unsafe { Tun::from_fd(-1, &cfg) };
        assert!(
            matches!(
                never_valid,
                Err(TunError::Ioctl {
                    op: "fcntl(F_GETFD)",
                    ..
                })
            ),
            "{never_valid:?}"
        );

        // SAFETY: opened then immediately closed by this test, so the
        // number is real but names nothing open by the time `from_fd` sees
        // it — the other case `fcntl(F_GETFD)` must reject.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw >= 0, "opening /dev/null for the fixture failed");
        unsafe { libc::close(raw) };
        let closed = unsafe { Tun::from_fd(raw, &cfg) };
        assert!(
            matches!(
                closed,
                Err(TunError::Ioctl {
                    op: "fcntl(F_GETFD)",
                    ..
                })
            ),
            "{closed:?}"
        );
    }

    /// The positive case: a real, currently-open descriptor is accepted,
    /// not just the two rejection cases above.
    #[test]
    fn from_fd_accepts_a_genuinely_open_descriptor() {
        let cfg = TunConfig {
            name: "karsttest1".to_owned(),
            ..TunConfig::default()
        };
        // SAFETY: freshly opened immediately above, not yet handed to
        // anything else — this test is the fd's only owner.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw >= 0, "opening /dev/null for the fixture failed");
        // SAFETY: as this test's own comment above.
        let tun = unsafe { Tun::from_fd(raw, &cfg) };
        assert!(tun.is_ok(), "{tun:?}");
    }
}
