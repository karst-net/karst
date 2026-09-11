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
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FlushFileBuffers, WriteFile, CREATE_NEW, FILE_SHARE_DELETE,
    FILE_SHARE_READ,
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

    /// Take ownership of a descriptor obtained some other way — currently
    /// only [`GetNamedSecurityInfoW`], in [`dacl_is_broadly_accessible`].
    /// Sound for that caller specifically because that API documents
    /// `LocalFree` as its own descriptor's release mechanism, the same
    /// convention [`Self::from_sddl`]'s already relies on.
    pub(crate) fn from_raw(ptr: PSECURITY_DESCRIPTOR) -> Self {
        Self(ptr)
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
/// `FILE_SHARE_DELETE` is part of the share mode even though nothing here
/// deletes the file directly: Windows also requires it of the *renamer's*
/// own internal open when a caller (`bins/karstd/src/exit_node.rs`'s
/// write-then-`fs::rename` pattern) renames this file while this handle is
/// still open on it — without it, `fs::rename` fails with
/// `ERROR_SHARING_VIOLATION` the moment a second `karstd` start ever
/// exercised the path, which no test caught until real `windows-latest` CI
/// ran `exit_node`'s own suite for the first time.
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
    // duration and is passed by `*const`. Sharing permits a concurrent
    // reader and a concurrent rename/delete of this same path
    // (`FILE_SHARE_READ | FILE_SHARE_DELETE`), not a concurrent writer, and
    // the template-file handle is null, which the API documents as valid
    // when `dwCreationDisposition` does not copy attributes from a template.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
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

/// `ACCESS_ALLOWED_ACE_TYPE` (winnt.h, value `0`). `windows-sys` exposes it
/// only under `Win32::System::SystemServices`, a module nothing else here
/// needs enabling for one integer literal, so it is named locally instead.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// The identities a default or careless Windows ACL grants access to —
/// Everyone (`S-1-1-0`), Authenticated Users (`S-1-5-11`), and the local
/// Users group (`S-1-5-32-545`) — checked against a file's DACL by
/// [`dacl_is_broadly_accessible`]. This is the Windows counterpart to
/// Unix's `mode & 0o077 != 0`: a *specific other* named account granted
/// access is out of scope here for the same reason Unix's 9-bit mode does
/// not distinguish one extra named grant from another either (POSIX ACLs
/// are not checked there, and are not the model this crate implements
/// here).
const WIDE_PRINCIPALS: [WELL_KNOWN_SID_TYPE; 3] =
    [WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid];

/// Whether `name`'s DACL grants any access at all to one of
/// [`WIDE_PRINCIPALS`] — i.e. whether the file is *not* restricted to its
/// owner and administrators.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error if the security descriptor
/// cannot be read, or a well-known SID cannot be constructed.
pub(crate) fn dacl_is_broadly_accessible(name: &[u16]) -> io::Result<bool> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
    // duration of the call. `dacl` and `descriptor` are live, uniquely
    // borrowed output slots; every other output pointer is null, which the
    // API documents as valid when the caller does not need that
    // information — this call asks only for the DACL.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        #[allow(clippy::cast_possible_wrap)]
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // `descriptor` owns the memory `dacl` points into for as long as this
    // function runs; dropping it any earlier would leave `dacl` dangling
    // for every read below.
    let _descriptor = SecurityDescriptor::from_raw(descriptor);

    // No DACL at all is Windows' "no protection" — the counterpart of Unix
    // mode `0777`, and certainly not restricted.
    if dacl.is_null() {
        return Ok(true);
    }

    let mut wide_sids = Vec::with_capacity(WIDE_PRINCIPALS.len());
    for kind in WIDE_PRINCIPALS {
        let mut buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: `buffer` is a live, uniquely borrowed output buffer sized
        // per `SECURITY_MAX_SID_SIZE`'s documented meaning (the largest any
        // SID can be). `size` is a live, uniquely borrowed `u32` the callee
        // both reads (as the buffer's capacity) and writes (the SID's
        // actual size). `domainsid` is null, which the API documents as
        // valid for every well-known SID this module asks for — none of
        // `WIDE_PRINCIPALS` is domain-relative.
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        wide_sids.push(buffer);
    }

    // SAFETY: `dacl` is a live pointer into `_descriptor`'s memory for the
    // remainder of this function. `AceCount` is the field the ACL header
    // itself documents as the number of entries that follow it.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `dacl` is valid as above; `index` is within
        // `0..AceCount`, which `GetAce` documents as the valid range. `ace`
        // is a live, uniquely borrowed output slot.
        let ok = unsafe { GetAce(dacl, index, &raw mut ace) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ace` was just filled by `GetAce` and points at a live
        // `ACE_HEADER` — every ACE type starts with one — for the duration
        // of this read.
        let ace_type = unsafe { (*ace.cast::<ACE_HEADER>()).AceType };
        if ace_type != ACCESS_ALLOWED_ACE_TYPE {
            // A DENY or audit ACE grants nothing by itself, so only ALLOW
            // entries can widen access and need checking.
            continue;
        }
        // SAFETY: `GetAce` documents an `ACCESS_ALLOWED_ACE_TYPE` entry's
        // memory as laid out exactly as `ACCESS_ALLOWED_ACE` — header, mask,
        // then the SID's bytes starting at `SidStart`.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask == 0 {
            continue;
        }
        let sid: PSID = (&raw const allowed.SidStart).cast_mut().cast();
        for wide in &mut wide_sids {
            let wide_sid: PSID = wide.as_mut_ptr().cast();
            // SAFETY: `sid` points into `dacl`'s live memory (valid for
            // this call); `wide_sid` points at a local buffer this
            // function just filled via `CreateWellKnownSid` above. Both are
            // well-formed SIDs for the duration of this call.
            let equal = unsafe { EqualSid(sid, wide_sid) };
            if equal != 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Encode a string as a NUL-terminated UTF-16 buffer for a `*const u16`
/// Win32 argument.
pub(crate) fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
