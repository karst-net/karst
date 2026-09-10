// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Win32 named-pipe FFI — the one place in this crate carrying
//! `allow(unsafe_code)`, matching the discipline `karst-tun`'s `sys_windows`
//! uses for the same reason (ADR-0003's argument for confining `unsafe` to
//! one audited module applies here too, even though this crate is not the
//! TUN datapath). Every block states its safety argument.
//!
//! # Why overlapped I/O
//!
//! `bins/karstd/src/ipc.rs`'s accept loop calls `set_nonblocking(true)` on
//! its Unix listener and polls `accept()` in a loop, so a shutdown request is
//! never more than one tick away — never blocking in `accept()` is the whole
//! point. A named pipe has no such flag: `ConnectNamedPipe` is a blocking
//! call unless the pipe handle was created with `FILE_FLAG_OVERLAPPED`, in
//! which case it becomes asynchronous and its completion is polled with
//! `GetOverlappedResult(..., bWait = FALSE)` instead of waited on — that poll
//! is what [`poll_connect`] does, and it is the only thing that makes
//! [`crate::Listener::accept`] non-blocking.
//!
//! One consequence carries through the whole file: a handle created with
//! `FILE_FLAG_OVERLAPPED` must pass an `OVERLAPPED` to *every* operation,
//! including the reads and writes `bins/karstd/src/ipc.rs::serve` and
//! `request` do once a connection exists — see [`read`] and [`write`], which
//! submit one and then wait on it synchronously, so the rest of this crate
//! sees a plain blocking `Read`/`Write` stream.

#![allow(unsafe_code)]

use std::io;
use std::mem;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
    ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

/// The pipe's buffer size hint. Not a cap: a byte-mode pipe streams, so a
/// larger message than this still transfers, just over more `ReadFile`
/// calls — see [`read`]. Control messages here are one line in and a short
/// report out, so this is generous rather than tuned.
const BUFFER_SIZE: u32 = 8192;

/// An owned Win32 handle, closed on drop. Used for both pipe instances
/// (server and client) — everything downstream only needs `HANDLE` plus RAII.
#[derive(Debug)]
pub(crate) struct OwnedHandle(HANDLE);

// SAFETY: a Win32 `HANDLE` has no thread affinity. Every operation in this
// module that takes one documents which are safe to call concurrently; the
// type itself carries no unsynchronized interior state beyond the handle
// value.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above. `ReadFile`/`WriteFile`/`GetOverlappedResult` on a single
// handle are not called concurrently from two threads at once anywhere in
// this crate — each `Stream` is used from one thread at a time by
// `bins/karstd/src/ipc.rs`, the same requirement a `std::fs::File` places on
// its caller.
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle this module created and not used again
        // after this call.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// A security descriptor built from an SDDL string, owned until dropped.
#[derive(Debug)]
pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is read-only after construction — every consumer
// only ever reads `self.0` to fill a `SECURITY_ATTRIBUTES` it passes by
// `*const` to a creation call, never mutates through it.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Parse an SDDL string (e.g. `"D:(A;;GA;;;SY)(A;;GA;;;BA)"`) into a
    /// security descriptor.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if the string is malformed.
    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = wide_z(sddl);
        let mut ptr: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is a live, NUL-terminated UTF-16 buffer for the
        // duration of the call. `ptr` is a live, uniquely borrowed output
        // slot; the size-out parameter is null, which the API documents as
        // valid when the caller does not need the descriptor's byte length
        // (this one only ever passes the pointer on, never inspects it).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut ptr,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(ptr))
    }

    /// A `SECURITY_ATTRIBUTES` pointing at this descriptor, for the lifetime
    /// of `&self`.
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            #[allow(clippy::cast_possible_truncation)]
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by `ConvertStringSecurityDescriptorTo…`
        // above, which documents `LocalFree` as the way to release it, and is
        // not used again after this call.
        unsafe {
            let _ = LocalFree(self.0);
        }
    }
}

/// Create one instance of the named pipe.
///
/// `first` must be true exactly once per pipe name, for the instance that
/// claims it — see [`crate::Listener::bind`]. Every operation on the
/// returned handle must pass an `OVERLAPPED`; see the module documentation.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error. With `first: true`, an
/// existing live instance of this name surfaces as `ERROR_ACCESS_DENIED` —
/// the same "a live socket is not stolen" refusal
/// `bins/karstd/src/ipc.rs::bind_at` document for the Unix path, for the same
/// reason.
pub(crate) fn create_instance(
    name: &[u16],
    security: &SecurityDescriptor,
    first: bool,
) -> io::Result<OwnedHandle> {
    let open_mode = windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let attrs = security.attributes();
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
    // duration of the call. `attrs` borrows `security` for the same
    // duration and is passed by `*const`, matching the documented
    // `lpSecurityAttributes` contract — the API only reads through it.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            &raw const attrs,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

/// A heap-allocated `OVERLAPPED`, boxed because its address must not move
/// while the kernel might still hold a pointer to it — see
/// [`begin_connect`]. Exists so [`crate::pipe::Pending`], which lives inside
/// a `Mutex` a background thread may lock, does not need `unsafe` of its own
/// to be `Send`/`Sync`: that argument belongs here, next to the FFI it is
/// about.
pub(crate) struct PendingOverlapped(Box<OVERLAPPED>);

impl std::fmt::Debug for PendingOverlapped {
    // Manual rather than `#[derive(Debug)]`: `OVERLAPPED` does not implement
    // `Debug` — it is a Win32 FFI struct with a union field.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PendingOverlapped").finish_non_exhaustive()
    }
}

// SAFETY: an `OVERLAPPED` is plain memory with no thread affinity; Win32
// only ever reads or writes through the pointer passed to `ConnectNamedPipe`/
// `GetOverlappedResult`, which this crate always pairs with the same
// `OwnedHandle` and serializes through `Mutex<Pending>` — see
// `crate::pipe::Listener`.
unsafe impl Send for PendingOverlapped {}
// SAFETY: as above.
unsafe impl Sync for PendingOverlapped {}

impl PendingOverlapped {
    pub(crate) fn new() -> Self {
        Self(Box::default())
    }
}

/// Whether an overlapped connect completed synchronously, or is still
/// pending — see [`begin_connect`] and [`poll_connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectStatus {
    /// A client is already connected; the handle is ready to use.
    Connected,
    /// No client yet. Poll [`poll_connect`] again later.
    Pending,
}

/// Start waiting for a client to connect to `handle`, without blocking.
///
/// `overlapped` must outlive every call to [`poll_connect`] against the same
/// operation — its `Box` is what gives it a stable address for that, since
/// the kernel holds a pointer to it until the operation completes and
/// nothing here may let that memory move.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, for any failure other than the
/// two success shapes overlapped `ConnectNamedPipe` documents (see
/// [`ConnectStatus`]).
pub(crate) fn begin_connect(
    handle: &OwnedHandle,
    overlapped: &mut PendingOverlapped,
) -> io::Result<ConnectStatus> {
    // SAFETY: `handle` is live for the duration of the call. `overlapped.0`
    // is a live, uniquely borrowed, heap-allocated `OVERLAPPED` whose address
    // the caller guarantees stays put (documented above) until this
    // operation is known complete.
    let ok = unsafe { ConnectNamedPipe(handle.raw(), overlapped.0.as_mut()) };
    if ok != 0 {
        // Documented as not expected for an overlapped handle, but handled
        // rather than assumed impossible: a nonzero return here still means
        // a client is connected.
        return Ok(ConnectStatus::Connected);
    }
    // SAFETY: no preconditions; reads the calling thread's last-error slot,
    // which `ConnectNamedPipe` just set.
    match unsafe { GetLastError() } {
        ERROR_IO_PENDING => Ok(ConnectStatus::Pending),
        ERROR_PIPE_CONNECTED => Ok(ConnectStatus::Connected),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Poll a pending connect started by [`begin_connect`], without blocking.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, for any failure other than
/// "still pending", which is `Ok(false)`.
pub(crate) fn poll_connect(
    handle: &OwnedHandle,
    overlapped: &PendingOverlapped,
) -> io::Result<bool> {
    let mut transferred = 0u32;
    // SAFETY: `handle` and `overlapped.0` are the same pair `begin_connect`
    // returned `Pending` for, both still live. `transferred` is a live,
    // uniquely borrowed `u32` the callee may write through. `bWait = FALSE`
    // is exactly the non-blocking poll this function exists to perform.
    let ok = unsafe {
        GetOverlappedResult(handle.raw(), overlapped.0.as_ref(), &raw mut transferred, 0)
    };
    if ok != 0 {
        return Ok(true);
    }
    // SAFETY: as `begin_connect`.
    match unsafe { GetLastError() } {
        ERROR_IO_INCOMPLETE => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Disconnect a server-side instance so its resources can be reused or
/// released. A no-op error is not surfaced: this runs from `Drop`, where
/// there is nothing a caller could do about a failure and nothing left to
/// clean up regardless.
pub(crate) fn disconnect(handle: &OwnedHandle) {
    // SAFETY: `handle` is live for the duration of the call, which is
    // `DisconnectNamedPipe`'s only requirement.
    unsafe {
        let _ = DisconnectNamedPipe(handle.raw());
    }
}

/// Open the client end of a named pipe.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error — `ERROR_FILE_NOT_FOUND` if no
/// server has bound this name, `ERROR_PIPE_BUSY` in the narrow window
/// between a server's `accept` consuming its ready instance and creating the
/// next one (not retried here — see [`crate::Stream::connect`]).
pub(crate) fn connect_client(name: &[u16]) -> io::Result<OwnedHandle> {
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
    // duration of the call. The security-attributes pointer is null, which
    // is documented as "use the default descriptor for this process" and is
    // what this side needs: access is enforced by the *server's* descriptor,
    // not this handle's.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

/// Read into `buf`, blocking until the read completes.
///
/// Submits one overlapped `ReadFile` and waits for it synchronously
/// (`GetOverlappedResult(..., bWait = TRUE)`) before returning, so the
/// caller sees ordinary blocking read semantics despite the handle being
/// overlapped — see the module documentation.
///
/// **`ERROR_BROKEN_PIPE` is `Ok(0)`, not an error.** `bins/karstd/src/ipc.rs`'s
/// `request` reads the reply to EOF — the Unix path gets that from the
/// server's `shutdown(Shutdown::Write)`-then-drop; a named pipe has no
/// half-close, so [`crate::Stream::drop`]'s `DisconnectNamedPipe` on the
/// server side is what the client's blocked read sees as the pipe breaking.
/// `Read::read`'s contract is that end-of-stream is a `0` return, not an
/// `Err`, and callers like `read_to_string` treat the two very differently
/// (`Ok(0)` stops cleanly; `Err` propagates as failure) — mapping this one
/// code is what makes that framing work at all on this platform.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, for any failure other than
/// the broken-pipe case above.
pub(crate) fn read(handle: &OwnedHandle, buf: &mut [u8]) -> io::Result<usize> {
    #[allow(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    let mut overlapped: OVERLAPPED = OVERLAPPED::default();
    let mut transferred = 0u32;
    // SAFETY: `handle` is live. `buf` is a live, uniquely borrowed slice of
    // exactly `len` bytes the callee writes into. `overlapped` is a live,
    // uniquely borrowed local that outlives the call below waiting on the
    // same operation — nothing returns until that wait completes, so its
    // address never needs to survive past this function, unlike the
    // longer-lived connect case.
    let ok = unsafe {
        ReadFile(
            handle.raw(),
            buf.as_mut_ptr(),
            len,
            &raw mut transferred,
            &raw mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(transferred as usize);
    }
    // SAFETY: as `begin_connect`.
    match unsafe { GetLastError() } {
        ERROR_BROKEN_PIPE => return Ok(0),
        ERROR_IO_PENDING => {}
        _ => return Err(io::Error::last_os_error()),
    }
    // SAFETY: `handle`/`overlapped` are the pair just submitted above, still
    // live; `bWait = TRUE` blocks until this specific operation completes.
    let ok = unsafe {
        GetOverlappedResult(handle.raw(), &raw const overlapped, &raw mut transferred, 1)
    };
    if ok != 0 {
        return Ok(transferred as usize);
    }
    // SAFETY: as `begin_connect`.
    match unsafe { GetLastError() } {
        ERROR_BROKEN_PIPE => Ok(0),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Write `buf`, blocking until the write completes. As [`read`], for the
/// write direction.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error.
pub(crate) fn write(handle: &OwnedHandle, buf: &[u8]) -> io::Result<usize> {
    #[allow(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    let mut overlapped: OVERLAPPED = OVERLAPPED::default();
    let mut transferred = 0u32;
    // SAFETY: as `read`, for the write direction — `buf` is a live,
    // immutably borrowed slice of exactly `len` bytes for the duration of
    // the call.
    let ok = unsafe {
        WriteFile(
            handle.raw(),
            buf.as_ptr(),
            len,
            &raw mut transferred,
            &raw mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(transferred as usize);
    }
    // SAFETY: as `begin_connect`.
    if unsafe { GetLastError() } != ERROR_IO_PENDING {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as `read`'s second `GetOverlappedResult` call.
    let ok = unsafe {
        GetOverlappedResult(handle.raw(), &raw const overlapped, &raw mut transferred, 1)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred as usize)
}

/// Encode a string as a NUL-terminated UTF-16 buffer for a `*const u16`
/// Win32 argument.
pub(crate) fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
