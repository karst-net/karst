// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Embed a mesh node directly into a Rust application, with no `karstd`
//! sidecar process alongside it — GitHub issue #214, `docs/adr/0044-`.
//!
//! [`MeshNode`] is the same thin engine-lifecycle wrapper shape
//! `crates/karst-ffi::engine::EngineHandle` already uses for the mobile/
//! `NetworkExtension` case (ADR-0030) — a background thread running
//! `karstd::run::run_embedded` until told to stop, with a bounded channel
//! closing the startup race between "the thread exists" and "the thing it
//! was about to create exists." What differs is what the caller gets back:
//! there, a platform-owned `packetFlow` fd is adopted and nothing in the
//! extension process drives sockets itself; here, [`MeshNode`] hands back
//! `karst_tun::Userspace`'s own TCP/UDP socket API — already built for
//! "containers that cannot create a TUN device" (that module's own doc
//! comment) and reused verbatim, not reimplemented, because an embedding
//! backend process is exactly that kind of container.
//!
//! Every blocking call here (`Read`/`Write` on [`MeshTcpStream`],
//! [`MeshTcpListener::accept`], [`MeshUdpSocket::recv_from`]) is a plain
//! sleep-and-repoll loop over `Userspace`'s own non-blocking methods, not an
//! event loop or a waker registered anywhere — a known, named simplicity
//! trade for this minimal-viable pass, not an oversight. See
//! [`POLL_INTERVAL`].

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use karst_tun::{TcpHandle, UdpHandle, Userspace};

/// How often a blocking call here re-polls the underlying non-blocking
/// socket. Far under TCP's own retransmission timers, and cheap enough that
/// an embedding application built on this crate will be bound by its own
/// work long before it is bound by this poll.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Everything a [`MeshNode`] call can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// [`enroll`]/[`re_enroll`]'s failures. Carries the underlying message
    /// verbatim — `karstd::enrollment`'s own errors are already written to
    /// never echo a credential, so there is nothing to redact a second time
    /// here.
    #[error("{0}")]
    Enrollment(String),
    /// [`MeshNode::start`] and the traffic wrappers' failures — config
    /// loading, spawning the engine, or a `Userspace` socket operation.
    #[error("{0}")]
    Engine(String),
    /// [`identity_handle`]'s failures — a distinct case because "no identity
    /// file yet" is a normal, expected outcome a caller needs to tell apart
    /// from a real failure, not folded into [`Self::Enrollment`].
    #[error("{0}")]
    Identity(String),
    /// [`MeshNode::status_json`]'s control-socket round trip.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Provision this node from a pasted administrator invitation.
///
/// Duplicated from `crates/karst-ffi::enroll_invitation` rather than shared:
/// this crate must not depend on `karst-ffi`'s `UniFFI` scaffolding (ADR-0029
/// exists specifically for the mobile/Swift/Kotlin boundary), and the
/// wrapped call — `karstd::enrollment::enroll_invitation` — is already this
/// thin on both sides, so there is nothing of substance to share beyond it.
///
/// # Errors
/// Invitation, filesystem, credential and control-plane authentication
/// failures — see [`karstd::enrollment::enroll_invitation`].
pub fn enroll(invitation: &str, config_path: &Path, state_dir: &Path) -> Result<(), Error> {
    karstd::enrollment::enroll_invitation(invitation, config_path, state_dir)
        .map_err(Error::Enrollment)
}

/// As [`enroll`], but explicitly replaces an existing configuration instead
/// of refusing.
///
/// # Errors
/// As [`enroll`].
pub fn re_enroll(invitation: &str, config_path: &Path, state_dir: &Path) -> Result<(), Error> {
    karstd::enrollment::re_enroll_invitation(invitation, config_path, state_dir)
        .map_err(Error::Enrollment)
}

/// This device's identity handle, if it has ever been enrolled.
///
/// Returns `Ok(None)`, not an error, when `identity_key_path` does not
/// exist: "never enrolled" is this function's normal, expected outcome, not
/// a failure a caller needs to handle specially.
///
/// # Errors
/// [`Error::Identity`] if the file exists but cannot be read or is not a
/// valid seed.
pub fn identity_handle(identity_key_path: &Path) -> Result<Option<String>, Error> {
    match karstd::control::Identity::load(identity_key_path) {
        Ok(identity) => Ok(Some(identity.handle())),
        Err(karstd::control::Error::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(Error::Identity(error.to_string())),
    }
}

/// A running, embedded mesh node.
///
/// [`enroll`] or [`re_enroll`] must already have written `config_path`
/// before [`Self::start`]. Dropping a `MeshNode` without calling
/// [`Self::stop`] first only requests shutdown — see that method's own doc
/// comment on why it does not also join.
#[derive(Debug)]
pub struct MeshNode {
    userspace: Userspace,
    shutdown: Arc<karstd::run::Shutdown>,
    socket_path: PathBuf,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl MeshNode {
    /// Load the config [`enroll`] already wrote to `config_path`, then start
    /// the engine on a background thread.
    ///
    /// `config.network_mode` must already be `"userspace"` —
    /// `karstd::run::run_embedded`'s own requirement, since there is no
    /// kernel device for an embedding caller to drive. `socket_path` is this
    /// process's own private control socket; nothing outside it needs to
    /// reach it, the same reasoning `crates/karst-ffi`'s identically-shaped
    /// `EngineHandle::start` already documents for its own socket path.
    ///
    /// # Errors
    /// Any failure loading `config_path`, a `network_mode` other than
    /// `"userspace"`, or the engine not becoming ready within a few
    /// seconds — almost always because it failed before creating the
    /// interface, with the real cause only in the spawned thread's own
    /// `tracing::error!` output: there is no return value left to carry it
    /// once the thread is running independently, the identical limitation
    /// `EngineHandle::start` documents for the same reason.
    pub fn start(config_path: &Path, socket_path: &Path) -> Result<Self, Error> {
        let (config, _source, control_client) = karstd::control::load_config(config_path)
            .map_err(|error| Error::Engine(error.to_string()))?;
        let config = Arc::new(config);
        let shutdown = Arc::new(karstd::run::Shutdown::default());

        // Capacity 1, not 0: `run_engine`'s `try_send` must succeed whether
        // or not this thread has reached `recv_timeout` yet — the same
        // reasoning `crates/karst-ffi::engine::EngineHandle::start` already
        // gives for its own ready channel.
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Userspace>(1);

        let thread_config = Arc::clone(&config);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_socket_path = socket_path.to_path_buf();
        let thread = std::thread::spawn(move || {
            let result = karstd::run::run_embedded(
                &thread_config,
                &thread_shutdown,
                &thread_socket_path,
                control_client,
                ready_tx,
            );
            if let Err(error) = result {
                eprintln!("karst-embed: embedded engine exited with an error: {error}");
            }
        });

        let Ok(userspace) = ready_rx.recv_timeout(Duration::from_secs(5)) else {
            // The thread is left running detached rather than joined here —
            // the same reasoning `EngineHandle::start` already gives: the
            // caller waiting on this `Result` did not ask to block further,
            // and requesting shutdown is enough to make sure it does not run
            // forever unsupervised.
            shutdown.request();
            return Err(Error::Engine(
                "engine did not become ready in time; check that config.network_mode = \
                 \"userspace\" and see this process's own log output for why"
                    .to_owned(),
            ));
        };

        Ok(Self {
            userspace,
            shutdown,
            socket_path: socket_path.to_path_buf(),
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The same `status_json()` body `karst status --json` reads from a
    /// LaunchDaemon-packaged `karstd`, fetched over this node's own control
    /// socket.
    ///
    /// # Errors
    /// Any failure connecting to or reading from the control socket — see
    /// [`karstd::ipc::request`].
    pub fn status_json(&self) -> Result<String, Error> {
        karstd::ipc::request(&self.socket_path, &karstd::ipc::Command::StatusJson)
            .map_err(Error::Io)
    }

    /// Open a TCP connection to another mesh peer's overlay address.
    ///
    /// # Errors
    /// An unaddressable destination or invalid port.
    pub fn connect_tcp(&self, address: IpAddr, port: u16) -> Result<MeshTcpStream<'_>, Error> {
        let handle = self
            .userspace
            .connect_tcp(address, port)
            .map_err(|error| Error::Engine(error.to_string()))?;
        Ok(MeshTcpStream {
            node: self,
            handle,
            leftover: Vec::new(),
        })
    }

    /// Listen for inbound TCP connections on an overlay port.
    ///
    /// # Errors
    /// The port cannot be listened on.
    pub fn listen_tcp(&self, port: u16) -> Result<MeshTcpListener<'_>, Error> {
        let handle = self
            .userspace
            .listen_tcp(port)
            .map_err(|error| Error::Engine(error.to_string()))?;
        Ok(MeshTcpListener {
            node: self,
            port,
            handle,
        })
    }

    /// Bind a UDP socket on an overlay port.
    ///
    /// # Errors
    /// The port is invalid or already bound.
    pub fn bind_udp(&self, port: u16) -> Result<MeshUdpSocket<'_>, Error> {
        let handle = self
            .userspace
            .listen_udp(port)
            .map_err(|error| Error::Engine(error.to_string()))?;
        Ok(MeshUdpSocket { node: self, handle })
    }

    /// Ask the engine to stop, and wait for it to actually do so. Unlike
    /// [`Drop`], this joins the background thread: a caller that calls this
    /// explicitly both expects the node to be fully down before it returns
    /// and can afford to wait for that.
    pub fn stop(&self) {
        self.shutdown.request();
        if let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = thread.join();
        }
    }
}

impl Drop for MeshNode {
    /// A defensive fallback, not the intended path — see [`Self::stop`]'s
    /// own doc comment. Requests shutdown so a node nobody explicitly
    /// stopped does not run forever, but does not join: whatever dropped
    /// this did not ask to block, and `Drop` is not the place to decide it
    /// should have to.
    fn drop(&mut self) {
        self.shutdown.request();
    }
}

/// A TCP connection over the mesh, from [`MeshNode::connect_tcp`] or
/// [`MeshTcpListener::accept`].
#[derive(Debug)]
pub struct MeshTcpStream<'a> {
    node: &'a MeshNode,
    handle: TcpHandle,
    /// Bytes already drained from the underlying socket by a `tcp_recv` call
    /// but not yet handed to a caller whose buffer was smaller than what
    /// arrived. Without this, a short `read()` would silently drop them —
    /// `Read`'s contract permits returning fewer bytes than requested, but
    /// never permits losing ones already taken off the wire.
    leftover: Vec<u8>,
}

impl MeshTcpStream<'_> {
    /// The overlay address of the peer this stream is connected to, if any.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.node.userspace.tcp_remote(self.handle)
    }
}

impl Read for MeshTcpStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.leftover.is_empty() {
                let n = self.leftover.len().min(buf.len());
                if let (Some(dest), Some(src)) = (buf.get_mut(..n), self.leftover.get(..n)) {
                    dest.copy_from_slice(src);
                }
                self.leftover.drain(..n);
                return Ok(n);
            }
            if self.node.userspace.tcp_can_recv(self.handle) {
                self.node
                    .userspace
                    .tcp_recv(self.handle, &mut self.leftover)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                continue;
            }
            if !self.node.userspace.tcp_may_recv(self.handle) {
                return Ok(0);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Write for MeshTcpStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            if self.node.userspace.tcp_can_send(self.handle) {
                return self
                    .node
                    .userspace
                    .tcp_send(self.handle, buf)
                    .map_err(|error| io::Error::other(error.to_string()));
            }
            if !self.node.userspace.tcp_is_active(self.handle) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mesh TCP connection is no longer active",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for MeshTcpStream<'_> {
    fn drop(&mut self) {
        self.node.userspace.tcp_release(self.handle);
    }
}

/// A TCP listener over the mesh, from [`MeshNode::listen_tcp`].
#[derive(Debug)]
pub struct MeshTcpListener<'a> {
    node: &'a MeshNode,
    port: u16,
    handle: TcpHandle,
}

impl<'a> MeshTcpListener<'a> {
    /// Block until a peer connects, then hand back a stream for it.
    ///
    /// Each accepted connection gets a freshly `listen`ed socket for the
    /// next one, rather than reusing the just-accepted handle via
    /// `Userspace::tcp_listen_again` once it closes — simpler, at the cost
    /// of one extra socket briefly existing per accept. A named place to
    /// optimize later if a high-connection-rate embedder needs it; nothing
    /// here needs it yet.
    ///
    /// # Errors
    /// The next port cannot be listened on.
    pub fn accept(&mut self) -> Result<(MeshTcpStream<'a>, SocketAddr), Error> {
        loop {
            if self.node.userspace.tcp_is_active(self.handle) {
                let remote = self.node.userspace.tcp_remote(self.handle).ok_or_else(|| {
                    Error::Engine(
                        "accepted connection reported no remote overlay address".to_owned(),
                    )
                })?;
                let accepted = self.handle;
                self.handle = self
                    .node
                    .userspace
                    .listen_tcp(self.port)
                    .map_err(|error| Error::Engine(error.to_string()))?;
                return Ok((
                    MeshTcpStream {
                        node: self.node,
                        handle: accepted,
                        leftover: Vec::new(),
                    },
                    remote,
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for MeshTcpListener<'_> {
    fn drop(&mut self) {
        self.node.userspace.tcp_release(self.handle);
    }
}

/// A UDP socket over the mesh, from [`MeshNode::bind_udp`].
#[derive(Debug)]
pub struct MeshUdpSocket<'a> {
    node: &'a MeshNode,
    handle: UdpHandle,
}

impl MeshUdpSocket<'_> {
    /// Send one datagram to a peer's overlay address.
    ///
    /// # Errors
    /// The socket has been released, or the datagram cannot be queued.
    pub fn send_to(&self, buf: &[u8], to: SocketAddr) -> Result<(), Error> {
        self.node
            .userspace
            .udp_send(self.handle, buf, to)
            .map_err(|error| Error::Engine(error.to_string()))
    }

    /// Block until a datagram arrives, and return it with its sender's
    /// overlay address.
    #[must_use]
    pub fn recv_from(&self) -> (Vec<u8>, SocketAddr) {
        loop {
            let mut buf = Vec::new();
            if let Some(from) = self.node.userspace.udp_recv(self.handle, &mut buf) {
                return (buf, from);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for MeshUdpSocket<'_> {
    fn drop(&mut self) {
        self.node.userspace.udp_release(self.handle);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// This wrapper does not reimplement validation — an invitation
    /// `karstd::enrollment` itself rejects must still be rejected here, with
    /// the same posture that module's own tests hold: never echo the
    /// credential a malformed invitation carried. Mirrors
    /// `crates/karst-ffi`'s identically-named test for its own
    /// `enroll_invitation` wrapper.
    #[test]
    fn a_malformed_invitation_is_rejected_without_echoing_it() {
        let secret = "SECRET-DO-NOT-ECHO";
        let invitation = format!("not-a-real-invitation-{secret}");
        let error = enroll(
            &invitation,
            Path::new("/nonexistent/config.toml"),
            Path::new("/nonexistent/state"),
        )
        .expect_err("a malformed invitation must be refused");
        let Error::Enrollment(message) = &error else {
            unreachable!("enroll only ever returns Error::Enrollment")
        };
        assert!(!message.contains(secret), "{message}");
    }

    /// A short-lived directory this module owns, distinct per test run.
    fn scratch_dir(tag: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir =
            std::env::temp_dir().join(format!("karst-embed-{tag}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        dir
    }

    /// `Ok(None)`, not an error, is the contract a caller deciding between
    /// enrolling fresh and re-enrolling depends on for a never-enrolled
    /// install.
    #[test]
    fn identity_handle_is_none_when_never_enrolled() {
        let dir = scratch_dir("identity-missing");
        let path = dir.join("identity.key");
        assert_eq!(identity_handle(&path).expect("must not error"), None);
    }

    /// Once enrolled, the handle this returns must be the same one
    /// `karstd::control::Identity::handle()` would report for the same key
    /// — this wrapper reads, it does not re-derive.
    #[test]
    fn identity_handle_matches_the_underlying_identity_once_enrolled() {
        let dir = scratch_dir("identity-present");
        let path = dir.join("identity.key");
        let identity =
            karstd::control::Identity::load_or_create(&path).expect("create a fixture identity");

        let handle = identity_handle(&path)
            .expect("must not error")
            .expect("must find the identity just created");
        assert_eq!(handle, identity.handle());
    }

    /// `MeshNode::start` must fail promptly on a config it cannot even load,
    /// rather than panicking or hanging on the ready channel.
    #[test]
    fn start_reports_a_config_load_failure_without_spawning_anything() {
        let error = MeshNode::start(
            Path::new("/nonexistent/karst-embed-config.toml"),
            Path::new("/nonexistent/karst-embed.sock"),
        )
        .expect_err("a missing config file must be refused");
        let Error::Engine(message) = &error else {
            unreachable!("start only ever returns Error::Engine for a load failure")
        };
        assert!(!message.is_empty());
    }
}
