// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Durable, local consent for one advertised exit route.
//!
//! # Windows
//!
//! `PermissionsExt`/`OpenOptionsExt` have no Windows equivalent — access
//! control there is a security descriptor set at creation, not a mode
//! bitmask set after — so the locked-down directory and exclusively-created
//! file below come from [`karst_secure_storage`] instead, restricted to
//! Administrators and `LocalSystem` (plan §5's "Administrators and SYSTEM
//! only"). See that crate for why the Win32 FFI lives there rather than
//! here (`karstd` `#![forbid(unsafe_code)]`).

use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// `/var/lib` does not exist on a stock macOS install; `/var/db` is this
// codebase's macOS analogue (see `karstd::setup::STATE` and
// `karst_dns::host::macos::REVERT_STATE`).
#[cfg(target_os = "linux")]
pub const DEFAULT_STATE_FILE: &str = "/var/lib/karst/exit-route";
#[cfg(target_os = "macos")]
pub const DEFAULT_STATE_FILE: &str = "/var/db/karst/exit-route";
/// `%ProgramData%\Karst\state\` is the plan §5 convention for protected
/// per-node state; `exit-route` is this module's file within it, same as
/// the Unix paths above name a file directly rather than a directory.
#[cfg(windows)]
pub const DEFAULT_STATE_FILE: &str = r"C:\ProgramData\Karst\state\exit-route";

/// The temporary-then-rename file this module creates, restricted the same
/// way the final file is — see [`create_temp_file`].
#[cfg(unix)]
type TempFile = std::fs::File;
#[cfg(windows)]
type TempFile = karst_secure_storage::SecureFile;

/// Lock down `parent` so only Administrators and `LocalSystem` can enter it
/// — the Unix `0700` directory's counterpart.
///
/// # Errors
/// Any failure creating or securing the directory.
#[cfg(unix)]
fn secure_parent(parent: &Path) -> io::Result<()> {
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
}

/// As above, on Windows. Only `parent` itself is restricted — its ancestors
/// (`%ProgramData%\Karst`) are created with ordinary, unrestricted
/// `create_dir_all` first, matching [`create_secure_dir`](karst_secure_storage::create_secure_dir)'s
/// documented split between "the one directory this guards" and everything
/// above it.
#[cfg(windows)]
fn secure_parent(parent: &Path) -> io::Result<()> {
    if let Some(grandparent) = parent.parent() {
        fs::create_dir_all(grandparent)?;
    }
    karst_secure_storage::create_secure_dir(parent)
}

/// Create `path` exclusively, restricted the same way the final file is —
/// the Unix `0600`, `O_EXCL` file's counterpart.
///
/// # Errors
/// Any failure creating the file, including it already existing.
#[cfg(unix)]
fn create_temp_file(path: &Path) -> io::Result<TempFile> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// As above, on Windows.
#[cfg(windows)]
fn create_temp_file(path: &Path) -> io::Result<TempFile> {
    karst_secure_storage::SecureFile::create_new(path)
}

#[derive(Debug)]
pub struct Selection {
    path: PathBuf,
    active: Option<String>,
}

impl Selection {
    /// Load a persisted selection, or an empty selection when no file exists.
    ///
    /// # Errors
    /// If the file cannot be read or contains an invalid route identifier.
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let active = match fs::read_to_string(&path) {
            Ok(value) => Some(validate(value.trim())?.to_owned()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(Self { path, active })
    }

    #[must_use]
    pub fn active(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// Atomically persist a selected stable route identifier.
    ///
    /// # Errors
    /// If the identifier is invalid or the private state cannot be written.
    pub fn select(&mut self, route_id: &str) -> io::Result<()> {
        let route_id = validate(route_id)?;
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "exit-route state has no parent",
            )
        })?;
        secure_parent(parent)?;

        let temporary = temporary_path(&self.path);
        let result: io::Result<()> = (|| {
            let mut file = create_temp_file(&temporary)?;
            writeln!(file, "{route_id}")?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.active = Some(route_id.to_owned());
        Ok(())
    }

    /// Withdraw consent and remove its state file.
    ///
    /// # Errors
    /// If an existing state file cannot be removed.
    pub fn disable(&mut self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.active = None;
        Ok(())
    }
}

fn validate(route_id: &str) -> io::Result<&str> {
    if route_id.is_empty() || route_id.len() > 128 || route_id.contains(char::is_whitespace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exit route id must be 1-128 non-whitespace bytes",
        ));
    }
    Ok(route_id)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn selection_survives_restart_and_disable() {
        let dir = Scratch::new("exit-selection");
        let path = dir.join("selected");
        let mut selection = Selection::load(&path).unwrap();
        assert_eq!(selection.active(), None);

        selection.select("exit-eu").unwrap();
        assert_eq!(Selection::load(&path).unwrap().active(), Some("exit-eu"));
        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        // The Windows counterpart — the file's security descriptor grants
        // only Administrators/LocalSystem — is asserted in
        // `karst_secure_storage`'s own tests, run on real `windows-latest`
        // CI where it can actually be checked; there is no mode bitmask
        // here to inspect on that platform the way `PermissionsExt` gives
        // on Unix.

        selection.disable().unwrap();
        assert_eq!(Selection::load(&path).unwrap().active(), None);
    }

    #[test]
    fn malformed_state_fails_closed() {
        let dir = Scratch::new("exit-malformed");
        let path = dir.join("selected");
        fs::write(&path, "two routes\n").unwrap();
        assert!(Selection::load(path).is_err());
    }
}
