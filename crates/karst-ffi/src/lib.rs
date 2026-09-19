// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// ADR-0030 permits `unsafe` in this crate, as narrowly as ADR-0003 already
// holds `karst-tun` and `karstd` to: confined to `engine::EngineHandle::start`,
// which carries its own `#[allow(unsafe_code)]` and states its own argument.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! The UniFFI-bound boundary mobile and macOS `NetworkExtension` clients link
//! against — ADR-0022's "not built yet" gap, ADR-0029's tool and scope
//! decision.
//!
//! Three slices so far:
//!
//! - [`enroll_invitation`]/[`re_enroll_invitation`] (ADR-0029) — thin
//!   wrappers, not a reimplementation: they call
//!   [`karstd::enrollment::enroll_invitation`]/`re_enroll_invitation`
//!   verbatim, so the bundle parsing, control-plane handshake and
//!   config-publishing behavior an operator already gets from
//!   `karst-setup`'s bash script is exactly what a linked extension gets
//!   too, not a second, divergent path.
//! - [`identity_handle`] — reads this device's own identity fingerprint
//!   without needing a running engine, for `Karst.app`'s "what am I
//!   enrolled as" display and its choice between "Enroll…" and
//!   "Re-enroll…".
//! - [`engine::EngineHandle`] (ADR-0030) — engine lifecycle and status over
//!   an adopted `packetFlow` fd, macOS-`network-extension`-only. Closes the
//!   `startTunnel`/`stopTunnel`/`"status"` `TODO(karst-ffi)` sites
//!   `packaging/macos/KarstPacketTunnel/Sources/KarstPacketTunnel/PacketTunnelProvider.swift`
//!   used to carry (#158, closed) — what remains is verifying that wiring
//!   on real hardware, tracked under
//!   <https://github.com/karst-net/karst/issues/161>.

pub mod engine;

uniffi::setup_scaffolding!();

/// Everything [`enroll_invitation`] can fail with, surfaced to Swift/Kotlin
/// as a typed error rather than a bare string — the one adaptation `UniFFI`
/// needs over `karstd::enrollment`'s own `Result<(), String>`, since a
/// `UniFFI` error type must implement `std::error::Error`.
///
/// Carries the underlying message verbatim. `karstd::enrollment`'s own
/// errors are already written to never echo a credential (see that module's
/// `parse_invitation`/`load_bundle`), so there is nothing to redact a second
/// time here — reformatting the text would only risk losing that guarantee,
/// not improve on it.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{0}")]
    Enrollment(String),
    /// [`engine::EngineHandle`]'s failures — config loading, spawning the
    /// engine, or the status-socket round trip. Same posture as
    /// `Enrollment` above: the message travels verbatim, not reformatted.
    #[error("{0}")]
    Engine(String),
    /// [`identity_handle`]'s failures — a distinct case rather than folding
    /// into `Enrollment`/`Engine` because "no identity file yet" (this
    /// device has never been enrolled) is a normal, expected outcome a
    /// caller needs to tell apart from a real failure, not a variant named
    /// after a concept (enrollment, the engine) this operation doesn't
    /// touch.
    #[error("{0}")]
    Identity(String),
}

/// Provision this device from a pasted administrator invitation —
/// ADR-0028 item 3's `"enroll"` app-message verb,
/// `PacketTunnelProvider.handleAppMessage`'s call through this boundary.
///
/// `config_path` and `state_dir` are plain strings at this boundary because
/// `UniFFI` has no native `Path`/`PathBuf` type; both must be absolute, the
/// same requirement `karstd::enrollment::enroll_bundle` already enforces.
/// Refuses if `config_path` already exists — this device is already
/// enrolled — see [`re_enroll_invitation`] for the explicit-replace
/// version.
///
/// # Errors
/// Invitation, filesystem, credential and control-plane authentication
/// failures — see [`karstd::enrollment::enroll_invitation`].
#[uniffi::export]
// `UniFFI`-exported functions take owned types crossing the FFI boundary —
// `&str` cannot borrow from the caller's Swift/Kotlin string across that
// edge — so every string parameter here is `String` by the tool's own
// convention, not an oversight `&str` would fix.
#[allow(clippy::needless_pass_by_value)]
pub fn enroll_invitation(
    invitation: String,
    config_path: String,
    state_dir: String,
) -> Result<(), FfiError> {
    karstd::enrollment::enroll_invitation(
        &invitation,
        std::path::Path::new(&config_path),
        std::path::Path::new(&state_dir),
    )
    .map_err(FfiError::Enrollment)
}

/// As [`enroll_invitation`], but explicitly replaces an existing
/// configuration instead of refusing — `Karst.app`'s "Re-enroll…" item.
/// See `karstd::enrollment::re_enroll_invitation`'s own doc comment for
/// what "replace" does and does not touch on disk.
///
/// # Errors
/// As [`enroll_invitation`], plus filesystem errors moving the existing
/// configuration aside or restoring it.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)]
pub fn re_enroll_invitation(
    invitation: String,
    config_path: String,
    state_dir: String,
) -> Result<(), FfiError> {
    karstd::enrollment::re_enroll_invitation(
        &invitation,
        std::path::Path::new(&config_path),
        std::path::Path::new(&state_dir),
    )
    .map_err(FfiError::Enrollment)
}

/// This device's identity handle, if it has ever been enrolled — the same
/// 44-character fingerprint `status_json`'s `[control]` section would
/// report from a running engine, computed here directly from the local
/// ML-DSA-87 identity key so `Karst.app` can show it without a tunnel
/// running. `identity_key_path` is `PacketTunnelProvider`'s own
/// `identityPath`, not a value the host app chooses.
///
/// Returns `Ok(None)`, not an error, when `identity_key_path` does not
/// exist: "never enrolled" is this function's normal, expected outcome for
/// a fresh install, not a failure a caller needs to handle specially.
///
/// # Errors
/// [`FfiError::Identity`] if the file exists but cannot be read, is
/// readable beyond its owner, or is not a valid seed.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)]
pub fn identity_handle(identity_key_path: String) -> Result<Option<String>, FfiError> {
    match karstd::control::Identity::load(std::path::Path::new(&identity_key_path)) {
        Ok(identity) => Ok(Some(identity.handle())),
        Err(karstd::control::Error::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(FfiError::Identity(error.to_string())),
    }
}

/// This device's control-plane-assigned name, if it has ever logged in —
/// `KarstLoginResponse.dns_name`, derived server-side from this node's own
/// reported hostname and written once by `Client::login`. A human-readable
/// complement to [`identity_handle`]'s opaque fingerprint for `Karst.app`'s
/// menu (#163) — **not** the admin-typed invitation label, which is
/// account-console bookkeeping the device never receives.
///
/// `None`, not an error, covers both "never logged in" and "logged in
/// before this was ever written" — a caller has exactly one thing to do
/// either way, so unlike [`identity_handle`] this has no error case of its
/// own to distinguish them with.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn device_name(identity_key_path: String) -> Option<String> {
    karstd::control::device_name(std::path::Path::new(&identity_key_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The FFI wrapper does not reimplement validation — an invitation that
    /// `karstd::enrollment` itself rejects must still be rejected here, with
    /// the same posture that module's own tests hold: never echo the
    /// credential a malformed invitation carried.
    #[test]
    fn a_malformed_invitation_is_rejected_without_echoing_it() {
        let secret = "SECRET-DO-NOT-ECHO";
        let invitation = format!("not-a-real-invitation-{secret}");
        let error = enroll_invitation(
            invitation,
            "/nonexistent/config.toml".to_owned(),
            "/nonexistent/state".to_owned(),
        )
        .expect_err("a malformed invitation must be refused");
        let FfiError::Enrollment(message) = &error else {
            unreachable!("enroll_invitation only ever returns FfiError::Enrollment")
        };
        assert!(!message.contains(secret), "{message}");
    }

    /// `karstd::enrollment::enroll_bundle` refuses a relative path before it
    /// touches the filesystem, or the network, at all — this boundary passes
    /// paths through unchanged, so that refusal must still surface, not be
    /// swallowed by a UniFFI-side panic on a bad `Path` conversion. The
    /// invitation itself must be well-formed enough to clear
    /// `parse_invitation`/`validate_bundle` first, or the path check is never
    /// reached — same fixture shape as `enrollment.rs`'s own
    /// `invitation_preserves_trust_and_requires_valid_pins`.
    #[test]
    fn a_relative_path_is_refused_rather_than_panicking() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let payload = serde_json::json!({
            "server": "https://control.example.test",
            "server_kem_pin": "01".repeat(1184),
            "server_verify_pin": "02".repeat(2592),
            "setup_key": "fixture",
            "control_minimum_version": 1,
        });
        let invitation = format!(
            "karst-invite-v1:{}",
            Base64UrlUnpadded::encode_string(payload.to_string().as_bytes())
        );

        let error = enroll_invitation(
            invitation,
            "relative/config.toml".to_owned(),
            "relative/state".to_owned(),
        )
        .expect_err("a relative path must be refused");
        let FfiError::Enrollment(message) = &error else {
            unreachable!("enroll_invitation only ever returns FfiError::Enrollment")
        };
        assert!(message.contains("absolute"), "{message}");
    }

    /// A short-lived directory this module owns, distinct per test run —
    /// `karstd`'s own `Scratch` fixture is `pub(crate)` to that crate and
    /// not reachable from here, so this crate gets its own minimal version
    /// rather than widening that visibility for two tests.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("karst-ffi-{tag}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        dir
    }

    /// `Ok(None)`, not an error, is the contract a caller deciding between
    /// "Enroll…" and "Re-enroll…" depends on for a fresh, never-enrolled
    /// install.
    #[test]
    fn identity_handle_is_none_when_never_enrolled() {
        let dir = scratch_dir("identity-missing");
        let path = dir.join("identity.key").to_string_lossy().into_owned();
        assert_eq!(identity_handle(path).expect("must not error"), None);
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

        let handle = identity_handle(path.to_string_lossy().into_owned())
            .expect("must not error")
            .expect("must find the identity just created");
        assert_eq!(handle, identity.handle());
    }

    #[test]
    fn device_name_is_none_before_any_login() {
        let dir = scratch_dir("device-name-missing");
        let path = dir.join("identity.key");
        assert_eq!(device_name(path.to_string_lossy().into_owned()), None);
    }

    /// `device_name`'s own doc comment on why this has no `Result` to
    /// unwrap, unlike `identity_handle` — this crosses the FFI boundary
    /// with the same `Option<String>`-only shape `karstd::control::device_name`
    /// already has.
    #[test]
    fn device_name_reads_what_login_would_have_written() {
        let dir = scratch_dir("device-name-present");
        let path = dir.join("identity.key");
        std::fs::write(dir.join("identity.key.dns_name"), "kestrel").expect("write fixture");
        assert_eq!(
            device_name(path.to_string_lossy().into_owned()).as_deref(),
            Some("kestrel")
        );
    }
}
