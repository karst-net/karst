// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against a **real `wintun.dll`**.
//!
//! Creating an adapter needs Administrator and the DLL itself, which CI's
//! `windows-core` job (`.github/workflows/ci.yml`) does not yet provision —
//! acquiring and pinning it is packaging work (plan §7), not this crate's.
//! Until then, these are the tests that need neither: what a caller must
//! observe when the DLL is missing, and that configuration is validated
//! before `Tun::create` ever tries to load it — the same split
//! `tests/device.rs` draws between what needs `CAP_NET_ADMIN` and what
//! doesn't, applied to the one privilege Windows adds on top: the DLL has to
//! be found at all.
//!
//! A real-adapter test (`#[ignore]`, run explicitly once CI can provision
//! `wintun.dll` and Administrator) belongs alongside these once that lands —
//! not invented here without a way to run it even once.

#![cfg(target_os = "windows")]
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use karst_tun::{Tun, TunConfig, TunError};

/// `LoadLibraryExW`'s documented failure for a missing module —
/// `ERROR_MOD_NOT_FOUND` — has no `io::ErrorKind` this Rust toolchain
/// recognizes; it comes back `Uncategorized`. Confirmed against the real
/// `windows-latest` CI runner rather than assumed: an `ErrorKind` guess here
/// (first `NotFound` on the theory it was `ERROR_PATH_NOT_FOUND`, then again
/// after routing around that) failed twice against the actual observed error
/// before landing on checking the raw code, which is what this asserts now.
const ERROR_MOD_NOT_FOUND: i32 = 126;

/// ADR-0017: the DLL is loaded by absolute path, never searched for. A path
/// that does not exist must fail as a named, clean `OpenDevice` error — not a
/// panic, and not a silent fallback to some other location.
#[test]
fn create_fails_cleanly_without_the_dll() {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let missing = std::path::PathBuf::from(system_root).join("karst-test-missing-wintun.dll");
    match Tun::create(&TunConfig::default(), &missing) {
        Err(TunError::OpenDevice(e)) => {
            assert_eq!(e.raw_os_error(), Some(ERROR_MOD_NOT_FOUND), "got {e:?}");
        }
        other => panic!("expected TunError::OpenDevice(ERROR_MOD_NOT_FOUND), got {other:?}"),
    }
}

/// Configuration errors must be caught before `LoadLibraryExW` runs, so a bad
/// config fails identically whether or not `wintun.dll` is even present —
/// exactly the property `tests/device.rs`'s Linux counterpart asserts.
#[test]
fn invalid_configuration_is_rejected_before_touching_wintun() {
    // Any path works here: validation must fail before it is ever used.
    let unchecked = Path::new(r"C:\unchecked\wintun.dll");

    let bad_mtu = Tun::create(
        &TunConfig {
            mtu: 1500,
            ..TunConfig::default()
        },
        unchecked,
    );
    assert!(matches!(bad_mtu, Err(TunError::InvalidMtu { .. })));

    let bad_name = Tun::create(
        &TunConfig {
            name: "karst/0".to_owned(),
            ..TunConfig::default()
        },
        unchecked,
    );
    assert!(matches!(bad_name, Err(TunError::InvalidName(_))));
}
