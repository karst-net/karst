// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Safe `Listener`/`Stream` over the Win32 named-pipe FFI in
//! [`crate::sys_windows`], shaped to match `std::os::unix::net`'s
//! `UnixListener`/`UnixStream` closely enough that
//! `bins/karstd/src/ipc.rs` needs only a `#[cfg(windows)]` arm, not a
//! rewrite — see that module for the two access levels [`Listener::bind`]
//! and [`Listener::bind_unprivileged`] correspond to.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::sys_windows::{self, ConnectStatus, OwnedHandle, PendingOverlapped, SecurityDescriptor};

/// Administrative access only: Local System and the Builtin Administrators
/// group. No other principal is named, which for a non-null DACL means no
/// other principal has access — the named-pipe counterpart to a Unix socket
/// inside a `0700` directory (`bins/karstd/src/ipc.rs`'s module note).
const ADMIN_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

/// As [`ADMIN_SDDL`], plus read/write (not full control) for Authenticated
/// Users — the counterpart to `bind_unprivileged_status`'s `0666` socket:
/// any local user can connect, but only `SY`/`BA` get everything a full
/// control handle would allow.
const UNPRIVILEGED_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// A bound named-pipe listener.
///
/// Holds exactly one not-yet-connected pipe instance at a time, replaced by a
/// fresh one the moment [`Listener::accept`] hands the connected one to its
/// caller — see the module note on why a named pipe needs this where a Unix
/// socket does not.
pub struct Listener {
    name: Vec<u16>,
    security: SecurityDescriptor,
    pending: Mutex<Pending>,
}

impl std::fmt::Debug for Listener {
    // Manual rather than `#[derive(Debug)]`: `OVERLAPPED` (inside `Pending`,
    // behind the mutex) does not implement `Debug` — it is a Win32 FFI
    // struct with a union field.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

/// The one pipe instance not yet handed to a caller, and the overlapped
/// connect operation running against it.
///
/// `overlapped` is heap-allocated (inside [`PendingOverlapped`]) so its
/// address is stable for as long as the operation the kernel is tracking
/// against it might still be outstanding — moving `Pending` (as `accept`
/// does, swapping a fresh one in) must not move the `OVERLAPPED` itself
/// while a `ConnectNamedPipe` against it could still be pending.
struct Pending {
    handle: OwnedHandle,
    overlapped: PendingOverlapped,
    /// Set once `begin_connect` or `poll_connect` has confirmed a client is
    /// connected, so `accept` does not poll an operation it already knows is
    /// done.
    ready: bool,
}

impl Listener {
    /// Bind with administrative-only access — see [`ADMIN_SDDL`].
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error. A pipe of this name
    /// already bound by a live process surfaces as `ERROR_ACCESS_DENIED` —
    /// see [`sys_windows::create_instance`].
    pub fn bind(path: &Path) -> io::Result<Self> {
        Self::bind_with_sddl(path, ADMIN_SDDL)
    }

    /// Bind with any-local-user access — see [`UNPRIVILEGED_SDDL`] and
    /// `bins/karstd/src/ipc.rs`'s module note on the unprivileged status
    /// listener.
    ///
    /// # Errors
    /// As [`Listener::bind`].
    pub fn bind_unprivileged(path: &Path) -> io::Result<Self> {
        Self::bind_with_sddl(path, UNPRIVILEGED_SDDL)
    }

    fn bind_with_sddl(path: &Path, sddl: &str) -> io::Result<Self> {
        let name = sys_windows::wide_z(&path.to_string_lossy());
        let security = SecurityDescriptor::from_sddl(sddl)?;
        let pending = new_pending(&name, &security, true)?;
        Ok(Self {
            name,
            security,
            pending: Mutex::new(pending),
        })
    }

    /// Present for parity with `UnixListener::set_nonblocking` — always a
    /// no-op success. [`Listener::accept`] never blocks by construction (it
    /// polls, rather than waits, an in-flight connect), so there is no
    /// blocking mode to turn off.
    ///
    /// # Errors
    /// Never — the signature matches the Unix path's fallible one so
    /// `bins/karstd/src/ipc.rs`'s `?` reads the same on both platforms.
    #[allow(clippy::unnecessary_wraps)]
    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }

    /// Accept a connection, or report `WouldBlock` if none is ready yet.
    ///
    /// Returns `(Stream, ())` rather than `Stream` alone, matching
    /// `UnixListener::accept`'s `(UnixStream, SocketAddr)` shape closely
    /// enough that `let (mut stream, _) = listener.accept()?` — how every
    /// call site in `bins/karstd` already destructures it — needs no
    /// `#[cfg]` of its own. There is no peer address a named pipe can offer
    /// in that second slot's place.
    ///
    /// # Errors
    /// [`io::ErrorKind::WouldBlock`] if no client has connected; an
    /// [`io::Error`] from the last Win32 error for any other failure,
    /// including one while preparing the next pending instance — which
    /// leaves this listener unable to accept further connections, the same
    /// unrecoverable shape a Unix listener's `accept` failure has.
    pub fn accept(&self) -> io::Result<(Stream, ())> {
        let mut guard = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.ready {
            if !sys_windows::poll_connect(&guard.handle, &guard.overlapped)? {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            guard.ready = true;
        }
        let fresh = new_pending(&self.name, &self.security, false)?;
        let connected = std::mem::replace(&mut *guard, fresh);
        Ok((
            Stream {
                handle: connected.handle,
            },
            (),
        ))
    }
}

/// Create a fresh pipe instance and start its overlapped connect.
fn new_pending(name: &[u16], security: &SecurityDescriptor, first: bool) -> io::Result<Pending> {
    let handle = sys_windows::create_instance(name, security, first)?;
    let mut overlapped = PendingOverlapped::new();
    let status = sys_windows::begin_connect(&handle, &mut overlapped)?;
    Ok(Pending {
        handle,
        overlapped,
        ready: status == ConnectStatus::Connected,
    })
}

/// One connected named-pipe stream, server- or client-side.
#[derive(Debug)]
pub struct Stream {
    handle: OwnedHandle,
}

impl Stream {
    /// Connect to a listener bound at `path`.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error —
    /// [`io::ErrorKind::NotFound`] if nothing is bound at this name,
    /// `ERROR_PIPE_BUSY` in the narrow race
    /// [`sys_windows::connect_client`] documents and does not retry.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let name = sys_windows::wide_z(&path.to_string_lossy());
        let handle = sys_windows::connect_client(&name)?;
        Ok(Self { handle })
    }

    /// Present for parity with `UnixStream::set_nonblocking` — always a
    /// no-op success, for the same reason [`Listener::set_nonblocking`] is:
    /// [`read`](Read::read)/[`write`](Write::write) already block until
    /// Windows has finished the operation.
    ///
    /// # Errors
    /// Never — see [`Listener::set_nonblocking`].
    #[allow(clippy::unnecessary_wraps)]
    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        sys_windows::read(&self.handle, buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        sys_windows::write(&self.handle, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Every write already blocks until Windows has accepted it — see
        // `sys_windows::write` — so there is no buffered layer here to flush.
        Ok(())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Harmless on a client-side handle — `DisconnectNamedPipe` there
        // simply fails, which `sys_windows::disconnect` already ignores by
        // design (there is nothing a caller could do in `Drop` regardless).
        sys_windows::disconnect(&self.handle);
    }
}
