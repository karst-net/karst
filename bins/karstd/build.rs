// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// Embeds the version `--version` and karstd's own first startup log line
// report, so a running process can be matched back to the release it was
// built from rather than trusted on faith — the question this exists to
// answer came up directly while debugging a macOS enrollment failure where
// it was unclear whether a stale, still-running daemon predated the fix
// under test.
//
// `KARST_VERSION` is scripts/release-version.sh's third output line, set in
// CI before every `cargo build` — the exact pushed tag (`v0.1.0-rc.6`) on a
// tagged build, `0.0.0+git.<sha>` otherwise. Deliberately not read from
// `.git` directly here: a build from a source tarball with no `.git` at all
// must still get the version CI computed for it, and reading the same
// environment variable CI already sets is simpler than re-deriving it a
// second way that could disagree with the first.
//
// A local `cargo build` with neither `KARST_VERSION` nor a `.git` to fall
// back to gets the literal "dev" — never a build failure over a string that
// exists only to be read, not acted on.
fn main() {
    println!("cargo:rerun-if-env-changed=KARST_VERSION");
    let version = std::env::var("KARST_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| "dev".to_owned());
    println!("cargo:rustc-env=KARST_VERSION={version}");
}

/// Best-effort only: a local dev build without `KARST_VERSION` set. Not
/// re-run when HEAD moves — `cargo:rerun-if-changed` on the right `.git`
/// ref file is more machinery than a string nothing but a human reads is
/// worth; `cargo build` after a fresh checkout or in CI is unaffected
/// either way, since both always run this from scratch.
fn git_describe() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
