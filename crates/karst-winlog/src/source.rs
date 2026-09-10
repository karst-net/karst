// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

use std::io;

use windows_sys::Win32::System::EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE};

use crate::sys_windows::{wide_z, OwnedEventSource};

/// A registered Event Log source, open for the life of the service.
#[derive(Debug)]
pub struct Source(OwnedEventSource);

impl Source {
    /// Register `name` as an Event Log source on the local machine's
    /// Application log.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub fn register(name: &str) -> io::Result<Self> {
        Ok(Self(OwnedEventSource::register(&wide_z(name))?))
    }

    /// Report an informational event — daemon start and stop.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub fn info(&self, message: &str) -> io::Result<()> {
        self.0.report(EVENTLOG_INFORMATION_TYPE, &wide_z(message))
    }

    /// Report an error event — a fatal startup or run failure.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub fn error(&self, message: &str) -> io::Result<()> {
        self.0.report(EVENTLOG_ERROR_TYPE, &wide_z(message))
    }
}
