// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! End-to-end coverage for `--status-socket` —
//! plans/phase-6/13-macos-status-indicators.md's unprivileged status
//! listener, `ipc::bind_unprivileged_status`.
//!
//! A real `karstd` subprocess, `network_mode = "userspace"` so no
//! `CAP_NET_ADMIN` or TUN device is needed and this runs unprivileged like
//! the rest of the suite — no peers either, since this is about the socket,
//! not the datapath.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn root_dir() -> PathBuf {
    std::env::temp_dir().join(format!("karstd-status-socket-{}", std::process::id()))
}

struct Node {
    dir: PathBuf,
    socket: PathBuf,
    status_socket: Option<PathBuf>,
    child: Child,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Write a lone node's configuration and key, then start it.
///
/// `with_status_socket` mirrors what packaging actually does: pass
/// `--status-socket` or do not, nothing in between.
fn start(tag: &str, with_status_socket: bool) -> Node {
    let dir = root_dir().join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let key = dir.join("node.key");
    std::fs::write(&key, karstd::config::encode_hex(&[0x11; 64])).expect("write key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod key");

    // Userspace mode and no `[[peer]]` at all — `File::peers` defaults to
    // empty (config.rs), and this suite never needs a session, only the
    // control-socket layer above it.
    let toml = r#"
[node]
listen = "127.0.0.1:0"
interface = "karst-status-test"
addresses = ["10.99.0.1/24"]
private_key_file = "node.key"
network_mode = "userspace"
userspace_socks5_listen = "127.0.0.1:0"
"#;
    let config = dir.join("karstd.toml");
    std::fs::write(&config, toml).expect("write config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .expect("chmod config");

    let socket = dir.join("karstd.sock");
    let status_socket = with_status_socket.then(|| dir.join("status.sock"));
    let log = dir.join("karstd.log");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_karstd"));
    command
        .arg("--config")
        .arg(&config)
        .arg("--socket")
        .arg(&socket);
    if let Some(path) = &status_socket {
        command.arg("--status-socket").arg(path);
    }
    let child = command
        .current_dir(&dir)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn karstd");

    Node {
        dir,
        socket,
        status_socket,
        child,
    }
}

/// Send one line, shut down the write half, and read the reply to EOF —
/// `ipc::request`'s wire protocol, reimplemented here rather than imported so
/// this suite exercises the actual bytes on the wire, not the client library
/// that both `karst` and this test would otherwise share a bug with.
fn ask(socket: &std::path::Path, line: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    writeln!(stream, "{line}")?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

fn wait_for_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} never came up", path.display());
}

#[test]
fn the_status_socket_serves_status_and_refuses_everything_else() {
    let node = start("serves-status", true);
    let status_socket = node.status_socket.clone().expect("configured above");
    wait_for_socket(&node.socket);
    wait_for_socket(&status_socket);

    let mode = std::fs::metadata(&status_socket)
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o666,
        "status socket mode {mode:04o} must be reachable by any local user"
    );

    let status = ask(&status_socket, "status").expect("status");
    assert!(status.contains("interface ="), "got {status:?}");
    assert!(status.contains("[stats]"), "got {status:?}");

    // Anything but `status` must be refused, `down` above all — this socket
    // is reachable by any local user, and a refusal that only applied to some
    // other commands would leave the one that matters unprotected.
    let refused = ask(&status_socket, "down").expect("down");
    assert!(
        refused.contains("this socket serves status only"),
        "got {refused:?}"
    );

    // The refusal must be real, not cosmetic: the daemon must still answer.
    let still_up = ask(&node.socket, "status").expect("status after refused down");
    assert!(still_up.contains("interface ="), "got {still_up:?}");
}

#[test]
fn no_status_socket_exists_without_the_flag() {
    let node = start("no-flag", false);
    wait_for_socket(&node.socket);

    // Give a listener that should not exist a real chance to have come up
    // before asserting its absence.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !node.dir.join("status.sock").exists(),
        "no --status-socket was given; nothing should have been created"
    );
}
