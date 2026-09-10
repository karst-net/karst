// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(windows)]
// ADR-0003's reasoning — confine `unsafe` to one audited module rather than
// scatter it — applies here too: `sys_windows` carries the sole
// `allow(unsafe_code)`.
#![deny(unsafe_code)]

//! Windows Event Log reporting for `karstd`'s service lifecycle.
//!
//! Plan §5 gives the Event Log a narrow job: "start, stop, and fatal errors
//! only — an operator looks there first, and it is not where a packet log
//! belongs." Everything else the daemon logs goes through `tracing`
//! (`bins/karstd/src/main.rs::init_tracing`) to a log file under
//! `%ProgramData%\Karst\logs\`, not here.
//!
//! `RegisterEventSourceW`/`ReportEventW` need no message-table DLL to work —
//! they write an entry either way — but without one, Event Viewer shows a
//! generic "the description for Event ID ... cannot be found" notice above
//! the raw message text passed as an insertion string. That is an accepted,
//! documented rough edge for the beta: a proper message-file resource is
//! packaging work (criterion 4's MSI), not this crate's.
//!
//! `bins/karstd` `#![forbid(unsafe_code)]`, so the Win32 FFI this needs lives
//! here instead, following the same split as [`karst-ipc`](../karst_ipc) and
//! [`karst-secure-storage`](../karst_secure_storage).

mod source;
mod sys_windows;

pub use source::Source;
