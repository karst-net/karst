// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Win32 FFI — the one place in this crate carrying `allow(unsafe_code)`,
//! the same confinement `karst-tun`'s, `karst-ipc`'s and
//! `karst-secure-storage`'s `sys_windows` modules use and for the same
//! reason (ADR-0003). Every block states its safety argument.

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, REPORT_EVENT_TYPE,
};

/// An owned event-source handle, deregistered on drop.
#[derive(Debug)]
pub(crate) struct OwnedEventSource(HANDLE);

// SAFETY: a Win32 `HANDLE` has no thread affinity, and every call below
// takes `&self`/`&mut self` rather than assuming exclusive access from a
// particular thread — the same argument `karst-secure-storage`'s
// `OwnedHandle` makes.
unsafe impl Send for OwnedEventSource {}
// SAFETY: as above.
unsafe impl Sync for OwnedEventSource {}

impl OwnedEventSource {
    /// Register this process as a source of events under `name`, on the
    /// local machine's Application log (a null server name, which the API
    /// documents as meaning local).
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub(crate) fn register(name: &[u16]) -> io::Result<Self> {
        // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
        // duration of the call. A null server name is documented as valid
        // and means the local machine.
        let handle = unsafe { RegisterEventSourceW(std::ptr::null(), name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    /// Write one event carrying `message` as its sole insertion string.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub(crate) fn report(&self, event_type: REPORT_EVENT_TYPE, message: &[u16]) -> io::Result<()> {
        let strings = [message.as_ptr()];
        // SAFETY: `self.0` is live. `strings` is a one-element array of a
        // live, NUL-terminated UTF-16 buffer, matching `wnumstrings = 1`;
        // both are borrowed only for the duration of the call. The user-SID
        // and raw-data pointers are null, which the API documents as valid
        // when neither is supplied.
        let ok = unsafe {
            ReportEventW(
                self.0,
                event_type,
                0,
                0,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for OwnedEventSource {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `RegisterEventSourceW` above and
        // is not used again after this call.
        unsafe {
            let _ = DeregisterEventSource(self.0);
        }
    }
}

/// Encode a string as a NUL-terminated UTF-16 buffer for a `*const u16`
/// Win32 argument.
pub(crate) fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
