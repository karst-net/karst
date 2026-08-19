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
    /// # Panics
    /// If the directory cannot be created, which a test cannot proceed without.
    #[must_use]
    pub(crate) fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "karst-scratch-{}-{:?}-{tag}",
            std::process::id(),
            std::thread::current().id()
        ));
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
