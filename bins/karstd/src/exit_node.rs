// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Durable, local consent for one advertised exit route.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_STATE_FILE: &str = "/var/lib/karst/exit-route";

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
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

        let temporary = temporary_path(&self.path);
        let result: io::Result<()> = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
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
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);

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
