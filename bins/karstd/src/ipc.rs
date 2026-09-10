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
//!
//! # Windows
//!
//! There is no Unix domain socket, so [`Listener`]/[`Stream`] are
//! [`karst_ipc`]'s named pipes there instead — see that crate for why the
//! Win32 FFI lives in its own crate rather than here (`karstd`
//! `#![forbid(unsafe_code)]`). The directory-then-socket permission dance
//! above has no Windows counterpart: a named pipe is identified by a kernel
//! namespace entry, not a filesystem path, so there is no directory to lock
//! down, and access is instead the security descriptor `karst_ipc::Listener`
//! bakes into the pipe itself at creation. There is also no stale-pipe
//! cleanup to do — unlike a Unix socket file, a named pipe simply ceases to
//! exist once its owning process's last handle to it closes, so
//! [`bind`]/[`bind_unprivileged_status`] need no counterpart to
//! [`bind_at`]'s stale-file check on that platform.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

/// The listener type this platform binds — a thin alias so [`bind`] and
/// friends read the same on every platform. See the module's Windows
/// section for what differs underneath it.
#[cfg(unix)]
type Listener = UnixListener;
#[cfg(windows)]
type Listener = karst_ipc::Listener;

/// The connected-stream type [`serve`] and [`request`] read and write.
#[cfg(unix)]
type Stream = UnixStream;
#[cfg(windows)]
type Stream = karst_ipc::Stream;

/// Where the socket lives unless told otherwise.
///
/// Not the same literal on every platform: `/run` is a Linux/systemd tmpfs
/// convention and does not exist at all on macOS, where the root volume is a
/// read-only, cryptographically sealed system volume (SSV, macOS 11+) that
/// `mkdir` cannot write to regardless of privilege. `/var/run` is the BSD/
/// Darwin equivalent — `/var` is on the writable Data volume — and is what
/// macOS has actually used for exactly this purpose since `NeXTSTEP`. Getting
/// this wrong does not fail loudly: `karstd` would fail to bind at startup
/// (caught immediately), but every *client* default — `karst status`, `karst
/// down`, and `karstd::setup::from_stdin`'s own readiness poll — would just
/// never find the socket and report the daemon as unreachable, which is a
/// much harder failure to place.
#[cfg(target_os = "linux")]
pub const DEFAULT_SOCKET: &str = "/run/karst/karstd.sock";
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/karst/karstd.sock";
/// A pipe name, not a filesystem path — see the module's Windows section.
/// `\\.\pipe\` is the fixed namespace prefix every named pipe lives under;
/// nothing else on the host can collide with it by using a real path that
/// happens to look like this one.
#[cfg(windows)]
pub const DEFAULT_SOCKET: &str = r"\\.\pipe\karst\karstd";

/// Where a `--status-socket`-equipped packaging (the macOS `.pkg`, currently
/// the only one) points both `karstd` and its status client at. Not a
/// fallback the way [`DEFAULT_SOCKET`] is: the unprivileged listener binds
/// only when `--status-socket` names a path explicitly, and this constant is
/// that path's single source of truth so `karstd`'s flag default and the
/// menu-bar app's connect target cannot drift apart. Deliberately a sibling
/// directory of `DEFAULT_SOCKET`'s, not inside it — that directory is `0700`
/// (see the module note), and a socket inside it would inherit an
/// unreachable parent regardless of its own mode. Same Linux-vs-macOS split
/// as `DEFAULT_SOCKET`, for the same reason.
#[cfg(target_os = "linux")]
pub const DEFAULT_STATUS_SOCKET: &str = "/run/karst-status/karstd.sock";
#[cfg(target_os = "macos")]
pub const DEFAULT_STATUS_SOCKET: &str = "/var/run/karst-status/karstd.sock";
/// As [`DEFAULT_SOCKET`]'s Windows form: a distinct pipe name, not a path
/// inside anything — there is no containing directory for it to be inside.
#[cfg(windows)]
pub const DEFAULT_STATUS_SOCKET: &str = r"\\.\pipe\karst-status\karstd";

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
/// crash requires manual cleanup before the tunnel can come back. Nothing
/// stale survives a crash on Windows — see the module's Windows section —
/// so [`karst_ipc::Listener::bind`] alone is the whole story there.
///
/// # Errors
/// Any failure creating the directory or binding (Unix); any failure
/// binding the pipe (Windows) — see [`karst_ipc::Listener::bind`].
#[cfg(unix)]
pub fn bind(path: &Path) -> std::io::Result<Listener> {
    // The directory must be locked down *before* the socket exists inside it —
    // see the module note. This is the security boundary.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    bind_at(path, 0o600)
}

/// As above, on Windows: the pipe's own security descriptor is the access
/// control — see the module's Windows section.
///
/// # Errors
/// Any failure binding the pipe — see [`karst_ipc::Listener::bind`].
#[cfg(windows)]
pub fn bind(path: &Path) -> std::io::Result<Listener> {
    karst_ipc::Listener::bind(path)
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
#[cfg(unix)]
pub fn bind_unprivileged_status(path: &Path) -> std::io::Result<Listener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    bind_at(path, 0o666)
}

/// As above, on Windows — see [`bind`]'s Windows arm.
///
/// # Errors
/// Any failure binding the pipe — see [`karst_ipc::Listener::bind_unprivileged`].
#[cfg(windows)]
pub fn bind_unprivileged_status(path: &Path) -> std::io::Result<Listener> {
    karst_ipc::Listener::bind_unprivileged(path)
}

/// Remove a stale socket left by a previous run, then bind fresh at `mode`.
///
/// A stale socket is a leftover file, not a running daemon: a failing
/// `connect` is what distinguishes them. Unlinking one that *is* live would
/// silently steal the control interface from a running node.
#[cfg(unix)]
fn bind_at(path: &Path, mode: u32) -> std::io::Result<Listener> {
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
    stream: &mut Stream,
    reply: impl FnOnce(Command) -> String,
) -> std::io::Result<Option<Command>> {
    let mut line = String::new();
    // `&mut *stream`, not `&*stream`: `karst_ipc::Stream::read` takes
    // `&mut self`, so only `&mut Stream` implements `Read` (via the standard
    // blanket impl) — unlike `UnixStream`, which also implements it for a
    // shared reference. Working through `&mut` here costs the Unix path
    // nothing and is what keeps this function itself unduplicated across
    // platforms.
    BufReader::new(&mut *stream).read_line(&mut line)?;

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
    let mut stream = Stream::connect(path)?;
    writeln!(stream, "{}", command.as_str())?;
    shutdown_write(&stream)?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

/// Signal that no more will be written, so the daemon's `read_line` is not
/// left waiting for more after the one line it wants.
///
/// A real half-close on Unix. A named pipe has none — see the module's
/// Windows section — so this is a no-op there; it does not need to be
/// anything else, because [`request`]'s own read-to-EOF (for the *reply*, in
/// the other direction) is satisfied differently on each platform too: on
/// Unix, the daemon's `serve` returning drops its `UnixStream`, closing the
/// socket and delivering EOF; on Windows, that same drop runs
/// `DisconnectNamedPipe` on the server's instance
/// (`karst_ipc::Stream::drop`), which is what turns this function's caller's
/// blocked read into `ERROR_BROKEN_PIPE` —
/// `karst_ipc::sys_windows::read`'s `Ok(0)` mapping for it.
#[cfg(unix)]
fn shutdown_write(stream: &UnixStream) -> std::io::Result<()> {
    stream.shutdown(std::net::Shutdown::Write)
}

/// As above — a no-op on Windows, per the module's Windows section. The
/// `Result` return stays so [`request`]'s `shutdown_write(&stream)?` reads
/// the same on both platforms.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn shutdown_write(_stream: &Stream) -> std::io::Result<()> {
    Ok(())
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
    /// other users. Unix mode bits only; the Windows equivalent is
    /// `karst_ipc`'s own security-descriptor construction, which cannot be
    /// asserted on from here without a Windows machine to run it on — see
    /// this crate's `tests/` for what did get validated on
    /// `windows-latest` CI.
    #[cfg(unix)]
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
    /// status` with extra steps. Unix mode bits only — see the note on
    /// [`the_socket_is_not_readable_by_others`].
    #[cfg(unix)]
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
    /// Unix-specific premise — see the module's Windows section on why a
    /// named pipe has no stale-file counterpart to test.
    #[cfg(unix)]
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

        let mut stream = Stream::connect(&path).expect("connect");
        writeln!(stream, "nonsense").expect("write");
        shutdown_write(&stream).expect("shutdown");
        let mut out = String::new();
        stream.read_to_string(&mut out).expect("read");

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
