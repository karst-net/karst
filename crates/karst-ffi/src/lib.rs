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
//! Two slices so far:
//!
//! - [`enroll_invitation`] (ADR-0029) — a thin wrapper, not a
//!   reimplementation: it calls [`karstd::enrollment::enroll_invitation`]
//!   verbatim, so the bundle parsing, control-plane handshake and
//!   config-publishing behavior an operator already gets from
//!   `karst-setup`'s bash script is exactly what a linked extension gets
//!   too, not a second, divergent path.
//! - [`engine::EngineHandle`] (ADR-0030) — engine lifecycle and status over
//!   an adopted `packetFlow` fd, macOS-`network-extension`-only. Closes the
//!   other three `TODO(karst-ffi)` sites in
//!   `packaging/macos/KarstPacketTunnel/Sources/KarstPacketTunnel/PacketTunnelProvider.swift`
//!   (`startTunnel`'s engine bring-up, `stopTunnel`'s teardown, and the
//!   `"status"` app-message verb) that ADR-0029 explicitly deferred rather
//!   than guessed at. Track remaining wiring under
//!   <https://github.com/karst-net/karst/issues/158>.

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
}

/// Provision this device from a pasted administrator invitation —
/// ADR-0028 item 3's `"enroll"` app-message verb, once
/// `PacketTunnelProvider.handleAppMessage` is wired to call through this
/// boundary instead of answering its current honest
/// "not yet linked" refusal.
///
/// `config_path` and `state_dir` are plain strings at this boundary because
/// `UniFFI` has no native `Path`/`PathBuf` type; both must be absolute, the
/// same requirement `karstd::enrollment::enroll_bundle` already enforces.
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
}
