// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Safe surface over [`crate::sys_windows`], shaped for
//! `bins/karstd/src/exit_node.rs`'s two needs: a directory only
//! Administrators and `LocalSystem` can enter, and a file only they can
//! read — the Windows counterpart to that module's `0700`/`0600` POSIX
//! permissions.

use std::io::{self, Write};
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;

use crate::sys_windows::{self, OwnedHandle, SecurityDescriptor};

/// `LocalSystem` and the Builtin Administrators group; no one else is
/// named, which for a non-null DACL means no one else has access. The same
/// SDDL `karst_ipc`'s admin-only pipe uses, for the same reason: this is
/// what "administrative access" (plan §5's "Administrators and SYSTEM
/// only") means as a Windows ACL.
const ADMIN_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

/// Create `path` as a directory restricted to Administrators and
/// `LocalSystem`, with the ACL applied from the moment it exists — no
/// window, however brief, during which a looser default applies.
///
/// **Only `path` itself, not its ancestors.** Unlike
/// `std::fs::create_dir_all`, this creates exactly one directory; the state
/// this guards (`bins/karstd/src/exit_node.rs`) needs only its own
/// directory locked down, not `%ProgramData%\Karst` above it, so callers
/// create ancestors with the ordinary unrestricted `create_dir_all` first
/// and call this only for the directory that actually needs the ACL.
///
/// Idempotent: an existing directory at `path` is not an error, matching
/// `create_dir_all`'s own tolerance — though note this does **not** verify
/// an already-existing directory carries this ACL, only that a freshly
/// created one does.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, for any failure other than
/// the directory already existing.
pub fn create_secure_dir(path: &Path) -> io::Result<()> {
    let name = sys_windows::wide_z(&path.to_string_lossy());
    let security = SecurityDescriptor::from_sddl(ADMIN_SDDL)?;
    match sys_windows::create_directory(&name, &security) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(i32_of(ERROR_ALREADY_EXISTS)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// A newly created file restricted to Administrators and `LocalSystem`,
/// with the ACL applied from the moment it exists.
#[derive(Debug)]
pub struct SecureFile(OwnedHandle);

impl SecureFile {
    /// Create `path` exclusively (failing if it already exists — the same
    /// `O_EXCL`-shaped contract `OpenOptions::create_new` gives on Unix, so
    /// the atomic-rename-into-place pattern
    /// `bins/karstd/src/exit_node.rs::Selection::select` uses works
    /// identically on both platforms).
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error, `ERROR_FILE_EXISTS`
    /// included.
    pub fn create_new(path: &Path) -> io::Result<Self> {
        let name = sys_windows::wide_z(&path.to_string_lossy());
        let security = SecurityDescriptor::from_sddl(ADMIN_SDDL)?;
        let handle = sys_windows::create_file_exclusive(&name, &security)?;
        Ok(Self(handle))
    }

    /// Flush to stable storage — `std::fs::File::sync_all`'s counterpart,
    /// named identically so call sites read the same on both platforms.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error.
    pub fn sync_all(&self) -> io::Result<()> {
        sys_windows::flush(&self.0)
    }
}

impl Write for SecureFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        sys_windows::write(&self.0, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        // `Write::flush` is about a buffered layer above the OS, which
        // there is none of here — every `write` already reaches Windows
        // directly. Durability past that is `SecureFile::sync_all`, the
        // same split `std::fs::File` draws between the two.
        Ok(())
    }
}

/// `ERROR_ALREADY_EXISTS`'s `u32` as the `i32` `raw_os_error()` returns,
/// saturating rather than wrapping — this specific code is far below
/// `i32::MAX`, so the cast is exact in practice; a named function documents
/// that rather than a bare `as`.
fn i32_of(code: u32) -> i32 {
    i32::try_from(code).unwrap_or(i32::MAX)
}
