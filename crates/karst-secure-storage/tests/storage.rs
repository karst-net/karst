// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against **real files and directories**, on the actual
//! `windows-latest` CI runner (`.github/workflows/ci.yml`'s `windows-core`
//! job) — this crate is only ever cross-checked from a machine with no
//! Windows to run it on, so this is what actually exercises it. No
//! Administrator privilege is needed: creating a file or directory with a
//! security descriptor is an ordinary user operation, the ACL just says who
//! else may open it afterward.

#![cfg(windows)]
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::path::PathBuf;

use karst_secure_storage::{create_secure_dir, is_restricted, SecureFile};

/// A distinct path per test, so a slow CI runner cannot collide between
/// them — mirrors `karst-ipc/tests/pipe.rs`'s per-instance names for the
/// same reason.
fn scratch_dir(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karst-secure-storage-test-{case}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_secure_dir_is_created_and_usable() {
    let dir = scratch_dir("dir");
    create_secure_dir(&dir).expect("create");
    assert!(dir.is_dir());

    // A directory this process just created should also be one it can
    // write into — the ACL must include this process's own identity
    // (LocalSystem or an Administrator, whichever is running the test),
    // not lock it out of what it made.
    std::fs::write(dir.join("probe"), b"ok").expect("write inside secured dir");
}

/// Idempotent, like `create_dir_all` — a second `karstd` start after a
/// clean shutdown must not fail just because the directory is already
/// there.
#[test]
fn creating_an_existing_secure_dir_again_is_not_an_error() {
    let dir = scratch_dir("dir-twice");
    create_secure_dir(&dir).expect("first create");
    create_secure_dir(&dir).expect("second create must not fail");
}

#[test]
fn a_secure_file_round_trips_its_content() {
    let dir = scratch_dir("file");
    create_secure_dir(&dir).expect("create dir");
    let path = dir.join("state");

    let mut file = SecureFile::create_new(&path).expect("create file");
    file.write_all(b"exit-eu\n").expect("write");
    file.sync_all().expect("sync");
    drop(file);

    let got = std::fs::read_to_string(&path).expect("read back");
    assert_eq!(got, "exit-eu\n");
}

/// `bins/karstd/src/exit_node.rs::Selection::select` renames its temporary
/// file into place *before* dropping the `SecureFile` handle it wrote
/// through (the handle only goes out of scope when the enclosing closure
/// returns, after the rename). On Unix that is unremarkable; on Windows it
/// needs `FILE_SHARE_DELETE` in `create_file_exclusive`'s share mode, or the
/// rename's own internal open fails with `ERROR_SHARING_VIOLATION` — a real
/// failure only real `windows-latest` CI caught, the first time
/// `exit_node`'s own test ran there.
#[test]
fn a_secure_file_can_be_renamed_while_still_open() {
    let dir = scratch_dir("rename-open");
    create_secure_dir(&dir).expect("create dir");
    let temporary = dir.join("state.tmp");
    let target = dir.join("state");

    let mut file = SecureFile::create_new(&temporary).expect("create");
    file.write_all(b"exit-eu\n").expect("write");
    file.sync_all().expect("sync");
    std::fs::rename(&temporary, &target).expect("rename while still open");
    drop(file);

    let got = std::fs::read_to_string(&target).expect("read back");
    assert_eq!(got, "exit-eu\n");
}

/// `CREATE_NEW`'s whole point: `bins/karstd/src/exit_node.rs::Selection::select`
/// relies on this failing so its temporary-file-then-rename pattern can
/// never silently overwrite a file it didn't create itself.
#[test]
fn creating_an_existing_secure_file_again_fails() {
    let dir = scratch_dir("file-twice");
    create_secure_dir(&dir).expect("create dir");
    let path = dir.join("state");

    drop(SecureFile::create_new(&path).expect("first create"));
    assert!(
        SecureFile::create_new(&path).is_err(),
        "a second exclusive create over an existing file must fail"
    );
}

/// `is_restricted` is what `bins/karstd/src/config.rs`'s and
/// `bins/karstd/src/control.rs`'s `check_permissions` fall back to on
/// Windows, so a file this crate itself locked down at creation is the
/// baseline it must agree with: `SecureFile`'s Administrators/`LocalSystem`
/// SDDL grants nothing to Everyone, Authenticated Users, or the local Users
/// group.
#[test]
fn a_secure_file_reports_as_restricted() {
    let dir = scratch_dir("restricted");
    create_secure_dir(&dir).expect("create dir");
    let path = dir.join("state");
    drop(SecureFile::create_new(&path).expect("create"));

    assert!(
        is_restricted(&path).expect("read ACL"),
        "a file SecureFile just created must report as restricted"
    );
}

/// The other half: a file `icacls` has explicitly opened up to Everyone —
/// standing in for the real case this whole mechanism exists to catch, an
/// operator hand-placing `karstd genkey`'s output without thinking about who
/// else can read it — must report as *not* restricted. `icacls`, not this
/// crate's own SDDL machinery, builds the fixture: testing the read side
/// against a permissive ACL this code itself never wrote is what makes this
/// a check of real Windows behavior rather than of this crate agreeing with
/// itself.
#[test]
fn a_world_readable_file_reports_as_not_restricted() {
    let dir = scratch_dir("insecure");
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("state");
    std::fs::write(&path, b"exit-eu\n").expect("write");

    let output = std::process::Command::new("icacls")
        .arg(&path)
        .arg("/grant")
        .arg("Everyone:(R)")
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !is_restricted(&path).expect("read ACL"),
        "a file readable by Everyone must not report as restricted"
    );
}
