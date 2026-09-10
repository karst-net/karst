// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against the **real** Windows Event Log, on the actual
//! `windows-latest` CI runner (`.github/workflows/ci.yml`'s `windows-core`
//! job) — this crate is only ever cross-checked from a machine with no
//! Windows to run it on, so this is what actually exercises it.
//!
//! Registering and reporting to the Application log needs no elevated
//! privilege for an ordinary source name (it is only a *new registry key
//! under `EventLog\Application`* that would need one, and
//! `RegisterEventSourceW` does not create that key — see the crate's module
//! docs on the accepted Event Viewer rough edge this implies).

#![cfg(windows)]
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use karst_winlog::Source;

/// A distinct name per test, so a slow CI runner cannot collide between
/// them — mirrors `karst-ipc`'s and `karst-secure-storage`'s per-instance
/// naming for the same reason.
fn source_name(case: &str) -> String {
    format!("karst-winlog-test-{case}-{}", std::process::id())
}

#[test]
fn a_source_registers_and_reports_an_info_event() {
    let source = Source::register(&source_name("info")).expect("register");
    source
        .info("karstd test: informational event")
        .expect("report info");
}

#[test]
fn a_source_registers_and_reports_an_error_event() {
    let source = Source::register(&source_name("error")).expect("register");
    source
        .error("karstd test: error event")
        .expect("report error");
}

#[test]
fn a_source_can_report_more_than_once() {
    let source = Source::register(&source_name("multi")).expect("register");
    source.info("karstd test: start").expect("first report");
    source.info("karstd test: stop").expect("second report");
}
