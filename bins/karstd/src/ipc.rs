// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The local control socket.
//!
//! `karstd` listens on a Unix stream socket; `karst` connects, writes one
//! command line, shuts down its write half, and reads the reply to EOF. No
//! framing, no length prefixes, no partial-read state machine — the shutdown
//! *is* the frame.
//!
//! # Access control
//!
//! Anyone who can talk to this socket can read peer endpoints and traffic
//! counters, and stop the tunnel. That is administrative access.
//!
//! **The containing directory is the guard, not the socket's own mode.** A
//! socket is created with whatever the process `umask` allows, and setting its
//! mode afterwards leaves a window — however brief — in which it is reachable.
//! Closing that window with `umask(2)` would need `unsafe`, which ADR-0003
//! confines to `karst-tun`. So the directory is created `0700` *before* the
//! bind: without execute permission on it, no other user can reach the socket
//! at any point, whatever mode it briefly has. The socket is then set to `0600`
//! as well, which is defense in depth rather than the mechanism.
//!
//! **Nothing here reports key material.** Peer identities appear as names and
//! the first bytes of a `peer_id_hint`; PSKs and private keys never leave the
//! process (THREAT-MODEL R5). That holds for [`Command::BugReport`] too, which
//! is the command most likely to be pasted somewhere public — see
//! `run::bug_report`.
//!
//! # The unprivileged status listener
//!
//! [`bind_unprivileged_status`] opens a **second**, deliberately narrower
//! socket — plans/phase-6/13-macos-status-indicators.md. The admin socket
//! above is locked to whoever owns `karstd`'s directory (root, under the
//! `LaunchDaemon`/`systemd` units this ships), which is correct for a socket
//! that can issue [`Command::Down`] — but it also means a per-user menu-bar
//! app cannot reach it at all: `docs/GETTING-STARTED.md` already documents
//! `sudo karst status`, and a GUI asking for `sudo` on every poll is not a
//! menu-bar app. The fix is not to loosen the admin socket — that would hand
//! any local user the ability to stop the tunnel — but to open a second
//! listener that serves `Command::Status` and refuses everything else,
//! including `Down`, no matter what it is asked. It exists only when
//! `karstd` is started with `--status-socket PATH`; nothing binds it by
//! default, on any platform.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use std::os::unix::net::{UnixListener, UnixStream};

/// Where the socket lives unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/karst/karstd.sock";

/// Where a `--status-socket`-equipped packaging (the macOS `.pkg`, currently
/// the only one) points both `karstd` and its status client at. Not a
/// fallback the way [`DEFAULT_SOCKET`] is: the unprivileged listener binds
/// only when `--status-socket` names a path explicitly, and this constant is
/// that path's single source of truth so `karstd`'s flag default and the
/// menu-bar app's connect target cannot drift apart. Deliberately a sibling
/// directory of `DEFAULT_SOCKET`'s, not inside it — that directory is `0700`
/// (see the module note), and a socket inside it would inherit an
/// unreachable parent regardless of its own mode.
pub const DEFAULT_STATUS_SOCKET: &str = "/run/karst-status/karstd.sock";

/// Commands the CLI may send. Deliberately tiny and text-based: this is a
/// local administrative interface, not a protocol to grow features into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Report interface, MTU, listen address, and per-peer state.
    Status,
    /// Ask the daemon to shut down.
    Down,
    /// Report the daemon's version.
    Version,
    /// Emit a support bundle: everything a maintainer needs to diagnose a
    /// problem, and nothing that would compromise the node if pasted into an
    /// issue tracker.
    BugReport,
    /// Render `Engine::Stats` and route/gateway state as Prometheus text —
    /// plans/phase-6/08-observability.md §3.1/§5 W6. The IPC verb, not a
    /// listener: see the `[metrics] listen`-gated HTTP surface in
    /// `run::metrics_http`, which serves the identical text over loopback
    /// only, opt-in, for operators who want a normal scrape target instead
    /// of a `karst metrics` textfile collector.
    Metrics,
    /// Report the live `KarstDNS` policy and host integration selection.
    DnsStatus,
    /// Explain which resolver path the current policy selects for one name.
    DnsQuery(String),
    /// List exit-route offers and the locally selected one.
    ExitList,
    /// Persistently select one exit-route offer by stable id.
    ExitUse(String),
    /// Withdraw and forget local exit-route consent.
    ExitDisable,
}

impl Command {
    /// Parse a command line.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        match line {
            "status" => Some(Self::Status),
            "down" => Some(Self::Down),
            "version" => Some(Self::Version),
            "bugreport" => Some(Self::BugReport),
            "metrics" => Some(Self::Metrics),
            "dns-status" => Some(Self::DnsStatus),
            "exit-list" => Some(Self::ExitList),
            "exit-disable" => Some(Self::ExitDisable),
            _ => line
                .strip_prefix("dns-query ")
                .filter(|name| !name.is_empty() && !name.contains(char::is_whitespace))
                .map(|name| Self::DnsQuery(name.to_owned()))
                .or_else(|| {
                    line.strip_prefix("exit-use ")
                        .filter(|id| !id.is_empty() && !id.contains(char::is_whitespace))
                        .map(|id| Self::ExitUse(id.to_owned()))
                }),
        }
    }

    /// The wire form.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Status => "status".to_owned(),
            Self::Down => "down".to_owned(),
            Self::Version => "version".to_owned(),
            Self::BugReport => "bugreport".to_owned(),
            Self::Metrics => "metrics".to_owned(),
            Self::DnsStatus => "dns-status".to_owned(),
            Self::DnsQuery(name) => format!("dns-query {name}"),
            Self::ExitList => "exit-list".to_owned(),
            Self::ExitUse(id) => format!("exit-use {id}"),
            Self::ExitDisable => "exit-disable".to_owned(),
        }
    }
}

/// Bind the control socket with restrictive permissions.
///
/// Removes a stale socket left by a previous run: a Unix socket file outlives
/// the process that made it, and refusing to start because of one would mean a
/// crash requires manual cleanup before the tunnel can come back.
///
/// # Errors
/// Any failure creating the directory or binding.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    // The directory must be locked down *before* the socket exists inside it —
    // see the module note. This is the security boundary.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    bind_at(path, 0o600)
}

/// As [`bind`], but reachable by any local user — see the module note on the
/// unprivileged status listener.
///
/// The directory is `0755` rather than `0700` and the socket `0666` rather
/// than `0600`; both are the deliberate point of this function, not a laxer
/// copy of `bind`'s. Callers choose this over `bind` explicitly — nothing
/// calls it unless `karstd` was started with `--status-socket`.
///
/// # Errors
/// Any failure creating the directory or binding.
pub fn bind_unprivileged_status(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    bind_at(path, 0o666)
}

/// Remove a stale socket left by a previous run, then bind fresh at `mode`.
///
/// A stale socket is a leftover file, not a running daemon: a failing
/// `connect` is what distinguishes them. Unlinking one that *is* live would
/// silently steal the control interface from a running node.
fn bind_at(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    if path.exists() && UnixStream::connect(path).is_err() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Serve one connection.
///
/// Returns the command that was handled, so the caller can act on `down`.
///
/// # Errors
/// Any I/O failure on the accepted stream. A malformed command is answered with
/// an error line rather than closing silently: this is an interactive tool, and
/// a blank response is indistinguishable from a hung daemon.
pub fn serve(
    stream: &mut UnixStream,
    reply: impl FnOnce(Command) -> String,
) -> std::io::Result<Option<Command>> {
    let mut line = String::new();
    BufReader::new(&*stream).read_line(&mut line)?;

    let Some(command) = Command::parse(&line) else {
        writeln!(stream, "error = \"unknown command\"")?;
        stream.flush()?;
        return Ok(None);
    };
    let body = reply(command.clone());
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(Some(command))
}

/// Send a command and read the reply.
///
/// # Errors
/// Any failure connecting or reading. `ConnectionRefused` or `NotFound` means
/// the daemon is not running, which the CLI reports as such.
pub fn request(path: &Path, command: &Command) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    writeln!(stream, "{}", command.as_str())?;
    // Shutting down the write half is the frame: the daemon reads to end of
    // line, and this guarantees it is not waiting for more.
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut out = String::new();
    std::io::Read::read_to_string(&mut stream, &mut out)?;
    Ok(out)
}

/// The socket path to use, honoring an explicit override.
#[must_use]
pub fn socket_path(explicit: Option<&str>) -> PathBuf {
    explicit.map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    use crate::scratch::Scratch;

    #[test]
    fn commands_round_trip_through_their_wire_form() {
        for c in [
            Command::Status,
            Command::Down,
            Command::Version,
            Command::BugReport,
            Command::Metrics,
            Command::DnsStatus,
            Command::DnsQuery("atlas.aquifer.karst".to_owned()),
            Command::ExitList,
            Command::ExitUse("exit-eu".to_owned()),
            Command::ExitDisable,
        ] {
            assert_eq!(Command::parse(&c.as_str()), Some(c));
        }
        assert_eq!(Command::parse("  status\n"), Some(Command::Status));
        assert_eq!(Command::parse("statu"), None);
        assert_eq!(Command::parse(""), None);
        assert_eq!(Command::parse("dns-query two names"), None);
        assert_eq!(Command::parse("exit-use two routes"), None);
        assert_eq!(Command::parse("status; rm -rf /"), None);
    }

    #[test]
    fn a_request_reaches_the_daemon_and_the_reply_comes_back() {
        let dir = Scratch::new("rt");
        let path = dir.join("karstd.sock");
        let listener = bind(&path).expect("bind");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            serve(&mut stream, |c| format!("command = \"{}\"\n", c.as_str())).expect("serve")
        });

        let reply = request(&path, &Command::Status).expect("request");
        assert_eq!(reply, "command = \"status\"\n");
        assert_eq!(server.join().expect("join"), Some(Command::Status));
    }

    /// The socket carries administrative access, so it must not be reachable by
    /// other users.
    #[test]
    fn the_socket_is_not_readable_by_others() {
        let dir = Scratch::new("perm");
        let path = dir.join("karstd.sock");
        let _listener = bind(&path).expect("bind");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "socket mode {mode:04o} exposes the control interface"
        );
    }

    /// The unprivileged listener exists so a per-user client can reach it
    /// without `sudo` — so it must actually grant that, on both the
    /// directory and the socket, or a menu-bar app is back to `sudo karst
    /// status` with extra steps.
    #[test]
    fn the_unprivileged_status_socket_is_reachable_by_any_local_user() {
        let dir = Scratch::new("status-perm");
        let path = dir.join("status").join("karstd.sock");
        let _listener = bind_unprivileged_status(&path).expect("bind");

        let dir_mode = std::fs::metadata(path.parent().expect("has a parent"))
            .expect("stat dir")
            .permissions()
            .mode();
        assert_eq!(
            dir_mode & 0o777,
            0o755,
            "status directory mode {dir_mode:04o} must let any local user traverse it"
        );
        let socket_mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            socket_mode & 0o777,
            0o666,
            "status socket mode {socket_mode:04o} must be reachable by any local user"
        );
    }

    /// A socket file outlives its process. Refusing to start because of one
    /// would mean a crash requires manual cleanup before the tunnel returns.
    #[test]
    fn a_stale_socket_is_replaced_rather_than_fatal() {
        let dir = Scratch::new("stale");
        let path = dir.join("karstd.sock");
        drop(bind(&path).expect("first bind"));
        assert!(path.exists(), "the file survives the listener");
        let _second = bind(&path).expect("a stale socket must not block startup");
    }

    /// But a socket with a daemon actually listening must not be removed —
    /// that would silently steal the control interface from a running node.
    #[test]
    fn a_live_socket_is_not_stolen() {
        let dir = Scratch::new("live");
        let path = dir.join("karstd.sock");
        let first = bind(&path).expect("first bind");
        // Second bind must fail rather than unlink the live socket.
        assert!(
            bind(&path).is_err(),
            "binding over a live control socket must fail"
        );
        drop(first);
    }

    #[test]
    fn an_unknown_command_gets_an_answer_not_silence() {
        let dir = Scratch::new("unknown");
        let path = dir.join("karstd.sock");
        let listener = bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            serve(&mut stream, |_| String::new()).expect("serve")
        });

        let mut stream = UnixStream::connect(&path).expect("connect");
        writeln!(stream, "nonsense").expect("write");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");
        let mut out = String::new();
        std::io::Read::read_to_string(&mut stream, &mut out).expect("read");

        assert!(out.contains("error"), "got {out:?}");
        assert_eq!(server.join().expect("join"), None);
    }

    #[test]
    fn a_missing_daemon_is_reported_as_such() {
        let dir = Scratch::new("absent");
        let path = dir.join("karstd.sock");
        let err = request(&path, &Command::Status).expect_err("no daemon");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ));
    }
}
