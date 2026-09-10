// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against **real named pipes**.
//!
//! `karst-ipc` exists to be cross-checked (`cargo check`/`clippy` against
//! `x86_64-pc-windows-gnu`) from a machine with no Windows to run it on —
//! these tests are what actually exercises it, on the real `windows-latest`
//! CI runner (`.github/workflows/ci.yml`'s `windows-core` job). Three things
//! here were corrected against exactly that gap once already this session
//! (`bins/karstd/src/ipc.rs`'s Windows port, and `karst-tun`'s own equivalent
//! lesson): a wrong assumption about which `io::ErrorKind` a Win32 code maps
//! to, caught only by a real run — so favor asserting behavior (a message
//! round-trips, a second bind is refused) over asserting exact error codes
//! wherever the two would test the same thing.
//!
//! No Administrator privilege is needed for any of this — creating a named
//! pipe, unlike a Wintun adapter, is an ordinary user operation.

#![cfg(windows)]
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karst_ipc::{Listener, Stream};

/// A distinct pipe name per test, so a slow CI runner running them
/// concurrently cannot collide — mirrors `bins/karstd`'s own per-instance
/// `Scratch` directories for the same reason on the Unix side.
fn pipe_name(case: &str) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\karst-ipc-test-{case}-{}",
        std::process::id()
    ))
}

/// [`Listener::accept`] never blocks — poll it the way
/// `bins/karstd/src/run.rs`'s real accept loop does, bounded so a bug here
/// fails the test instead of hanging the CI job.
fn accept_within(listener: &Listener, timeout: Duration) -> std::io::Result<(Stream, ())> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

/// The basic contract: what a client writes, the server reads, and back —
/// exercising `CreateNamedPipeW`, the overlapped connect and its poll,
/// `CreateFileW`, and `ReadFile`/`WriteFile` in both directions.
#[test]
fn a_message_round_trips_between_server_and_client() {
    let path = pipe_name("roundtrip");
    let listener = Listener::bind(&path).expect("bind");

    let server = std::thread::spawn(move || {
        let (mut stream, ()) = accept_within(&listener, Duration::from_secs(5)).expect("accept");
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).expect("server read");
        assert_eq!(&got, b"hello");
        stream.write_all(b"world").expect("server write");
    });

    // The listener starts its first pending connect inside `bind`, so a
    // client dialing immediately after should not need to wait for a
    // separate "start listening" step — this is itself part of what is
    // being tested, not just setup.
    let mut client = connect_retrying(&path, Duration::from_secs(5));
    client.write_all(b"hello").expect("client write");

    let mut got = [0u8; 5];
    client.read_exact(&mut got).expect("client read");
    assert_eq!(&got, b"world");

    server.join().expect("server thread");
}

/// `accept` must report `WouldBlock`, not hang, when nothing has connected
/// yet — the entire reason this crate exists rather than a plain blocking
/// `ConnectNamedPipe` call (`bins/karstd/src/run.rs`'s poll-and-check-
/// shutdown accept loop depends on this).
#[test]
fn accept_reports_would_block_before_a_client_connects() {
    let path = pipe_name("wouldblock");
    let listener = Listener::bind(&path).expect("bind");
    match listener.accept() {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "got {e:?}"),
        Ok(_) => panic!("accepted a connection nobody made"),
    }
}

/// The server dropping its end must look like end-of-stream to the client's
/// blocked read, not an error — `karst_ipc::sys_windows::read`'s
/// `ERROR_BROKEN_PIPE` → `Ok(0)` mapping, which
/// `bins/karstd/src/ipc.rs::request`'s `read_to_string` depends on to ever
/// return instead of hanging forever on a real daemon.
#[test]
fn dropping_the_server_stream_reports_eof_to_the_client() {
    let path = pipe_name("eof");
    let listener = Listener::bind(&path).expect("bind");

    let server = std::thread::spawn(move || {
        let (stream, ()) = accept_within(&listener, Duration::from_secs(5)).expect("accept");
        // Dropped here, deliberately, without writing anything: this is the
        // shape `bins/karstd/src/ipc.rs::serve` leaves behind once it
        // returns — its `Stream` goes out of scope in the caller's loop.
        drop(stream);
    });

    let mut client = connect_retrying(&path, Duration::from_secs(5));
    let mut got = Vec::new();
    client.read_to_end(&mut got).expect("read to EOF");
    assert!(got.is_empty(), "expected EOF with no bytes, got {got:?}");

    server.join().expect("server thread");
}

/// A pipe name already bound by a live listener must refuse a second bind —
/// the named-pipe counterpart to `bins/karstd/src/ipc.rs`'s
/// `a_live_socket_is_not_stolen`, so a second `karstd` cannot silently steal
/// the first's control channel.
#[test]
fn binding_an_already_live_name_fails() {
    let path = pipe_name("live");
    let first = Listener::bind(&path).expect("first bind");
    assert!(
        Listener::bind(&path).is_err(),
        "binding over a live listener must fail"
    );
    drop(first);
}

/// Connect, retrying briefly: a client can race a server's `bind` (which
/// starts listening asynchronously) in a way none of the assertions above
/// are about, so this is test plumbing, not part of what is under test.
fn connect_retrying(path: &Path, timeout: Duration) -> Stream {
    let deadline = Instant::now() + timeout;
    loop {
        match Stream::connect(path) {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("connect: {e}"),
        }
    }
}
