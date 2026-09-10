// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Win32 FFI — the one place in this crate carrying `allow(unsafe_code)`,
//! the same confinement `karst-tun`'s and `karst-ipc`'s `sys_windows`
//! modules use and for the same reason (ADR-0003). Every block states its
//! safety argument.
//!
//! Unlike `karst-ipc`'s pipes, nothing here is overlapped: a state file is
//! read and written synchronously, once, not held open across an
//! accept-style loop, so there is no non-blocking contract to build and no
//! `OVERLAPPED` to keep alive across calls.

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FlushFileBuffers, WriteFile, CREATE_NEW, FILE_SHARE_READ,
};

/// An owned Win32 handle, closed on drop.
#[derive(Debug)]
pub(crate) struct OwnedHandle(HANDLE);

// SAFETY: a Win32 `HANDLE` has no thread affinity, and `SecureFile` (the
// only owner) never shares one across threads concurrently — the same
// argument `karst-ipc::sys_windows::OwnedHandle` makes.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle this module created and not used
        // again after this call.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// A security descriptor built from an SDDL string, owned until dropped.
#[derive(Debug)]
pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is read-only after construction — the only
// consumer reads `self.0` to fill a `SECURITY_ATTRIBUTES` passed by
// `*const`, never mutating through it.
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
        // (this one only ever passes the pointer on).
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

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            #[allow(clippy::cast_possible_truncation)]
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` above,
        // which documents `LocalFree` as the way to release it, and is not
        // used again after this call.
        unsafe {
            let _ = windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

/// Create one directory (not its ancestors — see
/// [`crate::create_secure_dir`]) with `security` as its ACL from the moment
/// it exists, so there is no window in which a looser default applies.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, including
/// `ERROR_ALREADY_EXISTS` — left for the caller to tolerate or not, the same
/// way `std::fs::create_dir_all` leaves it, rather than assumed here.
pub(crate) fn create_directory(name: &[u16], security: &SecurityDescriptor) -> io::Result<()> {
    let attrs = security.attributes();
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
    // duration of the call. `attrs` borrows `security` for the same
    // duration and is passed by `*const`, matching the documented
    // `lpSecurityAttributes` contract.
    let ok = unsafe { CreateDirectoryW(name.as_ptr(), &raw const attrs) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a new file exclusively (failing if it already exists — the
/// `CREATE_NEW` disposition, matching `OpenOptions::create_new`'s POSIX
/// `O_EXCL` semantics), with `security` as its ACL from the moment it
/// exists.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, `ERROR_FILE_EXISTS` included.
pub(crate) fn create_file_exclusive(
    name: &[u16],
    security: &SecurityDescriptor,
) -> io::Result<OwnedHandle> {
    let attrs = security.attributes();
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
    // duration of the call. `attrs` borrows `security` for the same
    // duration and is passed by `*const`. No sharing is requested
    // (`dwShareMode = FILE_SHARE_READ` only, not `_WRITE`/`_DELETE`), and
    // the template-file handle is null, which the API documents as valid
    // when `dwCreationDisposition` does not copy attributes from a template.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &raw const attrs,
            CREATE_NEW,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

/// Write `buf`, blocking until Windows has accepted it. Ordinary
/// (non-overlapped) `WriteFile` — see the module documentation.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error.
pub(crate) fn write(handle: &OwnedHandle, buf: &[u8]) -> io::Result<usize> {
    #[allow(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    let mut written = 0u32;
    // SAFETY: `handle.0` is live. `buf` is a live, immutably borrowed slice
    // of exactly `len` bytes for the duration of the call. `written` is a
    // live, uniquely borrowed `u32` the callee writes through. The
    // overlapped parameter is null: this handle was never opened with
    // `FILE_FLAG_OVERLAPPED`, so `WriteFile` is synchronous and blocks until
    // done, which is exactly the semantics this function documents.
    let ok = unsafe {
        WriteFile(
            handle.0,
            buf.as_ptr(),
            len,
            &raw mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(written as usize)
}

/// Flush to stable storage — `std::fs::File::sync_all`'s Windows
/// counterpart.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error.
pub(crate) fn flush(handle: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `handle.0` is live, which is `FlushFileBuffers`'s only
    // requirement.
    let ok = unsafe { FlushFileBuffers(handle.0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Encode a string as a NUL-terminated UTF-16 buffer for a `*const u16`
/// Win32 argument.
pub(crate) fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
