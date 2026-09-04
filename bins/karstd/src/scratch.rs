// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A temporary directory for tests that removes itself.
//!
//! # Why this exists
//!
//! Every fixture in this crate used to build a path under `/tmp`, clear it, and
//! create it — and never remove it. The name carries the process id so two runs
//! cannot collide, which also means **every run leaves its directories
//! behind**. Across this crate and its integration tests that had accumulated
//! 4,756 directories and 965 MB before anyone looked.
//!
//! Clearing on *creation* also makes each test's first act depend on what a
//! previous run left there, which is the wrong direction for a fixture to face.
//!
//! # Why there is no `Deref`
//!
//! A guard that derefs to `Path` reads exactly like the `PathBuf` it replaces,
//! which means this keeps compiling:
//!
//! ```ignore
//! let socket = scratch("rt").join("karstd.sock");   // ← directory already gone
//! ```
//!
//! The temporary is dropped at the end of the statement and takes the directory
//! with it. Several call sites in this crate were written in that exact shape,
//! so the transparent version would have converted a leak into a set of
//! puzzling failures.
//!
//! Requiring [`Scratch::path`] or [`Scratch::join`] does not make the mistake
//! *impossible* — `Scratch::new("x").path().join("y")` still compiles, because
//! the temporary survives to the end of the statement and the mistake is only
//! visible afterwards. What it does is make the mistake **visible at the call
//! site**: a bare `Scratch::new(...)` with a method hung off it looks wrong,
//! where a deref would have looked like ordinary path handling. That is a
//! weaker guarantee than a compile error and is worth stating as one.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// A directory that exists for as long as this value does.
#[derive(Debug)]
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    /// Create an empty directory named for `tag`.
    ///
    /// Two things keep this short rather than merely unique, found by a real
    /// macOS CI failure — `bind control socket: path must be shorter than
    /// SUN_LEN` — not caught in review:
    ///
    /// - The base is `/tmp`, not [`std::env::temp_dir`]. The latter is
    ///   `TMPDIR`, which on macOS is a long per-session path under
    ///   `/var/folders/...`; `/tmp` is a short, always-present symlink on
    ///   every platform this crate targets. A Unix domain socket path
    ///   created under a test's scratch directory has a small fixed limit
    ///   (macOS's `SUN_LEN` is ~104 bytes) that the long form can exceed
    ///   once joined with a socket file name, even though Linux's own
    ///   `/tmp`-based `temp_dir()` never gets close.
    /// - The uniqueness suffix is a hash of `(pid, thread id)`, not their
    ///   `Debug` forms spelled out — `ThreadId(12)` alone is eleven bytes
    ///   this doesn't need to spend.
    ///
    /// # Panics
    /// If the directory cannot be created, which a test cannot proceed without.
    #[must_use]
    pub(crate) fn new(tag: &str) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (std::process::id(), std::thread::current().id()).hash(&mut hasher);
        let base = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let dir = base.join(format!("krst-{:x}-{tag}", hasher.finish()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    /// Where it is.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// A path inside it.
    #[must_use]
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best effort: a test that has already failed should report that
        // failure, not a cleanup error on top of it.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
