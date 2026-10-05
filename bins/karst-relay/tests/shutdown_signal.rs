// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The process signals a relay treats as "stop".
//!
//! Its own test binary, and a single test, on purpose: a signal is delivered to
//! the whole process, so any other test in the same binary with a handler
//! registered would hear it too.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use karst_relay::server::shutdown_signal;

fn signal_self(name: &str) {
    let status = std::process::Command::new("kill")
        .args([&format!("-{name}"), &std::process::id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success(), "kill -{name} failed");
}

/// SIGTERM is what `systemctl stop` and a container runtime send, so a relay
/// that only drained on Ctrl-C would drop its clients on every planned stop.
#[tokio::test]
async fn sigterm_and_sigint_both_mean_stop() {
    for name in ["TERM", "INT"] {
        // Created before the signal is sent: registration happens here, so the
        // signal cannot land in the gap and take the test process with it.
        let stop = shutdown_signal();
        signal_self(name);
        tokio::time::timeout(Duration::from_secs(5), stop)
            .await
            .unwrap_or_else(|_| panic!("SIG{name} did not stop the relay"));
    }
}
