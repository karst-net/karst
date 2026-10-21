// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Drive the real CLI against a one-request daemon socket. Timeouts keep an
/// incorrect CLI dispatch from leaving the test blocked in accept/read.
fn request(args: &[&str], response: &'static str) -> (Output, String) {
    // A short path also fits macOS sockaddr_un when TMPDIR is a long
    // per-session /var/folders path.
    let dir = std::path::Path::new("/tmp").join(format!(
        "karst-gateway-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("test directory");
    let path = dir.join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "CLI did not connect");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .expect("request");
        stream.write_all(response.as_bytes()).expect("reply");
        line
    });
    let output = Command::new(env!("CARGO_BIN_EXE_karst"))
        .args(args)
        .arg("--socket")
        .arg(&path)
        .output()
        .expect("run CLI");
    let line = server.join().expect("server");
    std::fs::remove_dir_all(dir).expect("cleanup");
    (output, line)
}

#[test]
fn gateway_status_uses_the_selected_socket_and_prints_the_route_report() {
    let report = "[routing]\noffers = 2\nselected_exit = None\nexit_route_active = false\n";
    let (output, line) = request(&["gateway", "status"], report);
    assert!(output.status.success());
    assert_eq!(line, "gateway-status\n");
    assert_eq!(String::from_utf8(output.stdout).expect("UTF-8"), report);
}

#[test]
fn an_older_daemon_rejecting_gateway_status_is_a_cli_failure() {
    let (output, line) = request(&["gateway", "status"], "error = \"unknown command\"\n");
    assert_eq!(line, "gateway-status\n");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command"));
}

#[test]
fn gateway_exit_and_legacy_commands_send_the_same_consent_request() {
    for (action, wire) in [
        (vec!["list"], "exit-list\n"),
        (vec!["use", "internet"], "exit-use internet\n"),
        (vec!["disable"], "exit-disable\n"),
    ] {
        for prefix in [vec!["gateway", "exit"], vec!["exit-node"]] {
            let mut args = prefix;
            args.extend(action.iter().copied());
            let (output, line) = request(&args, "selected = None\n");
            assert!(output.status.success());
            assert_eq!(line, wire);
        }
    }
}
