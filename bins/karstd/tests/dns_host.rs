// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Host-resolver lifecycle checks run from the privileged DNS target.
//!
//! The bare-file row uses a private temporary root so it proves the exact
//! crash-recovery sequence without risking the runner's `/etc/resolv.conf`.

#![allow(clippy::expect_used)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CHILD: &str = "apply_and_wait_for_sigkill";
const MACOS_CHILD: &str = "apply_resolver_files_and_wait_for_sigkill";

#[test]
#[ignore = "helper for bare_resolv_conf_recovers_after_an_unclean_daemon_exit"]
fn apply_and_wait_for_sigkill() {
    let Ok(root) = std::env::var("KARST_DNS_SIGKILL_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let resolv_conf = root.join("resolv.conf");
    let state = root.join("dns-revert");
    let host = karst_dns::host::ResolvConf::new(&resolv_conf, &state);
    let mut controller = karst_dns::host::Controller::new(host);
    controller
        .update(true, "100.100.100.100", &["aquifer.karst".to_owned()])
        .expect("apply KarstDNS");
    // The parent waits for the state marker then kills us. Do not clean up on
    // the way out: that would turn this into an orderly shutdown test.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "run with just test-dns"]
fn bare_resolv_conf_recovers_after_an_unclean_daemon_exit() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("karstd-dns-host-{nonce}"));
    std::fs::create_dir(&root).expect("private root");
    let resolv_conf = root.join("resolv.conf");
    let state = root.join("dns-revert");
    let original = b"nameserver 192.0.2.53\nsearch example.test\n";
    std::fs::write(&resolv_conf, original).expect("original resolver state");

    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", CHILD, "--ignored"])
        .env("KARST_DNS_SIGKILL_ROOT", &root)
        .spawn()
        .expect("spawn DNS helper");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !state.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(state.exists(), "helper did not persist DNS recovery state");
    child.kill().expect("SIGKILL DNS helper");
    let status = child.wait().expect("wait for killed helper");
    assert!(!status.success(), "killed helper exited successfully");

    let host = karst_dns::host::ResolvConf::new(&resolv_conf, &state);
    let second = karst_dns::host::Controller::new(host);
    assert!(second.recover().expect("recover stale state"));
    assert_eq!(
        std::fs::read(&resolv_conf).expect("recovered file"),
        original
    );
    assert!(!state.exists(), "recovery removes its stale revert marker");
    std::fs::remove_dir_all(root).expect("private root cleanup");
}

/// The macOS half of the pair above.
///
/// **Not `#[ignore]`d, and not gated to macOS.** `/etc/resolver` integration is
/// file handling, so the recovery it is proving happens identically on a Linux
/// runner against a private temporary directory — which means the crash path
/// for the macOS client is exercised on every push rather than only on the one
/// job that has a Mac. What a Mac adds is the resolver actually reading the
/// files, and that is the walkthrough's job, not this test's.
#[test]
#[ignore = "helper for the resolver-directory SIGKILL recovery test"]
fn apply_resolver_files_and_wait_for_sigkill() {
    let Ok(root) = std::env::var("KARST_DNS_RESOLVER_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let mut host = karst_dns::host::Macos::new(root.join("resolver"), root.join("dns-revert"));
    host.apply(
        "100.100.100.100:53".parse().expect("stub address"),
        "aquifer.karst.",
        &["corp.example".to_owned()],
    )
    .expect("apply resolver files");
    // As above: the parent kills us, and cleaning up on the way out would turn
    // this into an orderly-shutdown test instead.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn resolver_files_recover_after_an_unclean_daemon_exit() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("karstd-dns-resolver-{nonce}"));
    std::fs::create_dir(&root).expect("private root");
    let directory = root.join("resolver");
    let state = root.join("dns-revert");
    // A resolver file somebody else installed. Recovery has to give this one
    // back byte for byte, not merely stop pointing it at the mesh.
    let theirs = b"nameserver 192.0.2.53\n";
    std::fs::create_dir(&directory).expect("resolver directory");
    std::fs::write(directory.join("corp.example"), theirs).expect("their resolver file");

    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", MACOS_CHILD, "--ignored"])
        .env("KARST_DNS_RESOLVER_ROOT", &root)
        .spawn()
        .expect("spawn DNS helper");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !state.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(state.exists(), "helper did not persist DNS recovery state");
    child.kill().expect("SIGKILL DNS helper");
    let status = child.wait().expect("wait for killed helper");
    assert!(!status.success(), "killed helper exited successfully");
    assert!(
        directory.join("aquifer.karst").exists(),
        "the killed helper should have left the mesh zone pointing at the stub"
    );

    let mut second = karst_dns::host::Macos::new(&directory, &state);
    assert!(second.recover().expect("recover stale state"));
    assert!(
        !directory.join("aquifer.karst").exists(),
        "a file Karst created must be removed, not merely rewritten"
    );
    assert_eq!(
        std::fs::read(directory.join("corp.example")).expect("recovered file"),
        theirs
    );
    assert!(!state.exists(), "recovery removes its stale revert marker");
    std::fs::remove_dir_all(root).expect("private root cleanup");
}
