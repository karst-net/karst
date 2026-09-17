// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(all(target_os = "macos", feature = "network-extension"))]
//! Engine lifecycle and status over an adopted `packetFlow` fd — ADR-0030,
//! the slice of GitHub issue #158 that ADR-0029 explicitly deferred.
//!
//! [`EngineHandle`] wraps `karstd::run::run_with_adopted_fd` (ADR-0030) —
//! itself already a thin wrapper over `run_with_control`'s ~1000-line body
//! — so this module adds no new engine logic of its own, only the
//! background-thread lifecycle a synchronous `NEPacketTunnelProvider` call
//! needs around a function that otherwise blocks until told to stop.
//!
//! Status reuses the control socket verbatim
//! (`karstd::ipc::request`/`Command::StatusJson`) rather than avoiding it —
//! ADR-0030's course correction on why the socket was never the actual
//! problem `PacketTunnelProvider.swift`'s original `TODO(karst-ffi)`
//! comment was naming, only a second *process* would have been.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::FfiError;

/// A running engine, embedded over a `NEPacketTunnelProvider`'s adopted
/// tunnel descriptor.
///
/// Dropping this without calling [`Self::stop`] first only requests
/// shutdown — see that method's own doc comment on why it does not also
/// join here.
#[derive(Debug, uniffi::Object)]
pub struct EngineHandle {
    shutdown: Arc<karstd::run::Shutdown>,
    socket_path: PathBuf,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl EngineHandle {
    /// Load the config `enroll_invitation` already wrote to `config_path`
    /// (ADR-0029), then start the engine on a background thread over `fd` —
    /// `PacketTunnelProvider.startTunnel`'s call, once wired.
    ///
    /// `socket_path` is a path inside the extension's own sandboxed
    /// container, not `/var/run/karst`'s privileged one: this process is
    /// both ends of that socket (see [`Self::status_json`]), so it needs
    /// nowhere else to live.
    ///
    /// Returns once the engine has been handed its own thread — it does not
    /// wait for the engine to finish starting, since `run_with_adopted_fd`
    /// blocks for the tunnel's entire lifetime, which is the opposite of
    /// what a synchronous `startTunnel` call needs.
    ///
    /// # Safety
    /// `fd` must be a live tunnel descriptor — the extension's own
    /// `packetFlow` socket — whose exclusive ownership transfers to this
    /// call, exactly `karst_tun::Tun::from_fd`'s own contract, carried
    /// across this boundary rather than re-derived: this is the point
    /// where the raw value first enters this crate as untrusted data.
    ///
    /// # Errors
    /// Any failure loading `config_path` — see
    /// `karstd::control::load_config`. Nothing past that point is fallible
    /// here: the engine itself runs on its own thread, and a failure there
    /// surfaces as a `tracing::error!` log line, not through this return —
    /// there is no synchronous caller left by then to hand a `Result` to.
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    #[allow(unsafe_code)]
    pub fn start(config_path: String, socket_path: String, fd: i32) -> Result<Self, FfiError> {
        let (config, _source, control_client) =
            karstd::control::load_config(Path::new(&config_path))
                .map_err(|error| FfiError::Engine(error.to_string()))?;
        let config = Arc::new(config);
        let shutdown = Arc::new(karstd::run::Shutdown::default());
        let socket_path = PathBuf::from(socket_path);

        let thread_config = Arc::clone(&config);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_socket_path = socket_path.clone();
        let thread = std::thread::spawn(move || {
            // SAFETY: forwarded from this function's own contract above —
            // this closure is `start`'s only use of `fd`.
            let result = unsafe {
                karstd::run::run_with_adopted_fd(
                    &thread_config,
                    &thread_shutdown,
                    fd,
                    &thread_socket_path,
                    control_client,
                )
            };
            if let Err(error) = result {
                tracing::error!(%error, "karst-ffi: embedded engine exited with an error");
            }
        });

        Ok(Self {
            shutdown,
            socket_path,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The same `status_json()` body `karst status --json` reads on the
    /// `LaunchDaemon` build (`bins/karstd/src/run.rs`'s `status_json`),
    /// fetched over the control socket [`Self::start`] bound —
    /// `PacketTunnelProvider.handleAppMessage`'s `"status"` verb, once
    /// wired.
    ///
    /// # Errors
    /// Any failure connecting to or reading from the control socket — see
    /// [`karstd::ipc::request`].
    pub fn status_json(&self) -> Result<String, FfiError> {
        karstd::ipc::request(&self.socket_path, &karstd::ipc::Command::StatusJson)
            .map_err(|error| FfiError::Engine(error.to_string()))
    }

    /// Ask the engine to stop, and wait for it to actually do so —
    /// `PacketTunnelProvider.stopTunnel`'s call, once wired. Unlike
    /// [`Drop`], this joins the background thread: `stopTunnel` is the one
    /// caller that both expects the tunnel to be fully down before it
    /// returns and can afford to wait for that.
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

impl Drop for EngineHandle {
    /// A defensive fallback, not the intended path — see [`Self::stop`]'s
    /// own doc comment. Requests shutdown so a handle nobody explicitly
    /// stopped does not run forever, but does not join: whatever dropped
    /// this handle did not ask to block, and `Drop` is not the place to
    /// decide it should have to.
    fn drop(&mut self) {
        self.shutdown.request();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `start` checks the config before it ever touches `fd` — `-1` never
    /// reaches `adopt_tun`, so this needs no real tunnel descriptor. The
    /// load failure itself is `karstd::control::load_config`'s own to
    /// define and test; this only checks that `start` reports it as
    /// `FfiError::Engine` rather than panicking on a bad path or a
    /// not-yet-spawned thread.
    #[test]
    fn start_reports_a_config_load_failure_without_touching_fd() {
        let error = EngineHandle::start(
            "/nonexistent/karst-ffi-config.toml".to_owned(),
            "/nonexistent/karst-ffi.sock".to_owned(),
            -1,
        )
        .expect_err("a missing config file must be refused");
        let FfiError::Engine(message) = &error else {
            unreachable!("start only ever returns FfiError::Engine")
        };
        assert!(!message.is_empty());
    }
}
