// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A persisted original resolver file. The state file is written before the
/// live file changes, which lets a restarted daemon recover after SIGKILL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revert {
    original: Vec<u8>,
    applied: Vec<u8>,
}

/// Atomic `resolv.conf` integration rooted at caller-supplied paths.
///
/// The root is explicit so tests never touch `/etc`, and production can follow
/// a managed symlink to its target without moving the symlink itself.
#[derive(Clone, Debug)]
pub struct ResolvConf {
    path: PathBuf,
    state_path: PathBuf,
}

/// The lifecycle state a daemon keeps for one bare-file host integration.
/// A false `magic_dns` update uses the same revert path as clean shutdown.
#[derive(Debug)]
pub struct Controller {
    host: ResolvConf,
    revert: Option<Revert>,
}

impl ResolvConf {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            state_path: state_path.into(),
        }
    }

    /// Capture and persist the original content before replacing it atomically.
    pub fn apply(&self, nameserver: &str, search_domains: &[String]) -> io::Result<Revert> {
        let live = self.live_path()?;
        let original = fs::read(&live)?;
        let mut content =
            format!("# Managed by KarstDNS; restored on shutdown\nnameserver {nameserver}\n");
        if !search_domains.is_empty() {
            content.push_str("search ");
            content.push_str(&search_domains.join(" "));
            content.push('\n');
        }
        let revert = Revert {
            original,
            applied: content.into_bytes(),
        };
        Self::write_atomic(&self.state_path, &revert.encode())?;
        Self::write_atomic(&live, &revert.applied)?;
        Ok(revert)
    }

    /// Restore an explicit revert record and remove its durable marker.
    pub fn revert(&self, revert: &Revert) -> io::Result<()> {
        Self::write_atomic(&self.live_path()?, &revert.original)?;
        match fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Recover a previous interrupted application. Missing state means no
    /// prior change, so startup is idempotent.
    pub fn recover(&self) -> io::Result<bool> {
        let revert = match fs::read(&self.state_path) {
            Ok(state) => Revert::decode(&state)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        // A later administrator or network manager change wins. Do not restore
        // stale bytes over a configuration Karst no longer owns.
        if fs::read(self.live_path()?)? != revert.applied {
            fs::remove_file(&self.state_path)?;
            return Ok(false);
        }
        self.revert(&revert)?;
        Ok(true)
    }

    /// Read the resolver file that existed before a KarstDNS apply. While a
    /// durable revert record exists, its original bytes are authoritative;
    /// reading the live file then would feed the stub address back into the
    /// forwarder on the next netmap poll.
    pub fn original_contents(&self) -> io::Result<Vec<u8>> {
        match fs::read(&self.state_path) {
            Ok(state) => Ok(Revert::decode(&state)?.original),
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::read(self.live_path()?),
            Err(error) => Err(error),
        }
    }

    fn is_applied(&self, revert: &Revert) -> io::Result<bool> {
        Ok(fs::read(self.live_path()?)? == revert.applied)
    }

    fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("DNS path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("DNS path has no filename"))?;
        let temporary = parent.join(format!(".{}.karst-new", name.to_string_lossy()));
        fs::write(&temporary, data)?;
        fs::rename(temporary, path)
    }

    /// Follow an existing symlink without replacing it. `/etc/resolv.conf`
    /// commonly points into `/run`; renaming the link itself would detach it
    /// from the resolver manager and make reversion fundamentally unreliable.
    fn live_path(&self) -> io::Result<PathBuf> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_symlink() {
            return Ok(self.path.clone());
        }
        let target = fs::read_link(&self.path)?;
        if target.is_absolute() {
            Ok(target)
        } else {
            Ok(self
                .path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target))
        }
    }
}

impl Controller {
    #[must_use]
    pub fn new(host: ResolvConf) -> Self {
        Self { host, revert: None }
    }

    /// Apply one netmap DNS state. Turning MagicDNS off restores host DNS
    /// immediately; it does not wait for process shutdown or a later poll.
    pub fn update(
        &mut self,
        magic_dns: bool,
        nameserver: &str,
        search_domains: &[String],
    ) -> io::Result<()> {
        if !magic_dns {
            if let Some(revert) = self.revert.take() {
                self.host.revert(&revert)?;
            }
            return Ok(());
        }
        if let Some(previous) = self.revert.take() {
            // A netmap DNS update may change the search list. Revert before
            // applying the replacement so the persisted original remains the
            // host state from before KarstDNS, never a prior KarstDNS file.
            self.host.revert(&previous)?;
        }
        self.revert = Some(self.host.apply(nameserver, search_domains)?);
        Ok(())
    }

    /// Restore a state file left by a killed daemon before a new update can
    /// take ownership of the host resolver configuration.
    pub fn recover(&self) -> io::Result<bool> {
        self.host.recover()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.update(false, "", &[])
    }

    /// Whether the live file still contains the exact bytes installed by this
    /// controller. This is deliberately a comparison, not a marker check: an
    /// administrator's later edit must be reported as external ownership.
    pub fn observe(&self) -> io::Result<bool> {
        match &self.revert {
            Some(revert) => self.host.is_applied(revert),
            None => Ok(false),
        }
    }
}

impl Revert {
    fn encode(&self) -> Vec<u8> {
        let original_len = u64::try_from(self.original.len()).unwrap_or(u64::MAX);
        let mut state = Vec::with_capacity(8 + self.original.len() + self.applied.len());
        state.extend_from_slice(&original_len.to_be_bytes());
        state.extend_from_slice(&self.original);
        state.extend_from_slice(&self.applied);
        state
    }

    fn decode(state: &[u8]) -> io::Result<Self> {
        let Some(prefix) = state.get(..8) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated KarstDNS revert state",
            ));
        };
        let mut length = [0u8; 8];
        length.copy_from_slice(prefix);
        let original_len = usize::try_from(u64::from_be_bytes(length)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "KarstDNS revert state is too large",
            )
        })?;
        let Some(original) = state.get(8..8 + original_len) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated KarstDNS revert original",
            ));
        };
        Ok(Self {
            original: original.to_vec(),
            applied: state
                .get(8 + original_len..)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated KarstDNS state")
                })?
                .to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_apply_recovers_the_original_resolvers() {
        let root = std::env::temp_dir().join(format!("karst-dns-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");
        let host = ResolvConf::new(&resolv, &state);
        host.apply("100.100.100.100", &[]).expect("apply");
        assert!(host.recover().expect("recover"));
        assert_eq!(
            fs::read(&resolv).expect("restored"),
            b"nameserver 9.9.9.9\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_does_not_clobber_an_administrators_later_change() {
        let root = std::env::temp_dir().join(format!("karst-dns-admin-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");
        let host = ResolvConf::new(&resolv, &state);
        host.apply("100.100.100.100", &[]).expect("apply");
        fs::write(&resolv, b"nameserver 1.1.1.1\n").expect("administrator edit");
        assert!(!host.recover().expect("recover"));
        assert_eq!(fs::read(&resolv).expect("current"), b"nameserver 1.1.1.1\n");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn magic_dns_off_reverts_on_the_same_update() {
        let root = std::env::temp_dir().join(format!("karst-dns-off-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");
        let mut controller = Controller::new(ResolvConf::new(&resolv, &state));
        controller
            .update(true, "100.100.100.100", &[])
            .expect("enable");
        controller.update(false, "", &[]).expect("disable");
        assert_eq!(
            fs::read(&resolv).expect("restored"),
            b"nameserver 9.9.9.9\n"
        );
        assert!(!state.exists(), "revert marker survives disabled MagicDNS");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn observe_reports_a_later_external_change() {
        let root = std::env::temp_dir().join(format!("karst-dns-observe-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original");
        let mut controller = Controller::new(ResolvConf::new(&resolv, &state));
        controller
            .update(true, "100.100.100.100", &[])
            .expect("enable");
        assert!(controller.observe().expect("Karst owns file"));
        fs::write(&resolv, b"nameserver 1.1.1.1\n").expect("external edit");
        assert!(!controller.observe().expect("external ownership"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_second_netmap_update_still_reverts_to_the_pre_karst_file() {
        let root = std::env::temp_dir().join(format!("karst-dns-update-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");
        let mut controller = Controller::new(ResolvConf::new(&resolv, &state));
        controller
            .update(true, "100.100.100.100", &["first.karst".to_owned()])
            .expect("first enable");
        controller
            .update(true, "100.100.100.100", &["second.karst".to_owned()])
            .expect("netmap update");
        assert!(
            String::from_utf8_lossy(&fs::read(&resolv).expect("updated config"))
                .contains("second.karst")
        );
        controller.update(false, "", &[]).expect("disable");
        assert_eq!(
            fs::read(&resolv).expect("restored"),
            b"nameserver 9.9.9.9\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn apply_preserves_a_resolv_conf_symlink() {
        let root = std::env::temp_dir().join(format!("karst-dns-link-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let managed = root.join("managed.conf");
        let resolv = root.join("resolv.conf");
        let state = root.join("dns-revert");
        fs::write(&managed, b"nameserver 9.9.9.9\n").expect("managed config");
        #[cfg(unix)]
        std::os::unix::fs::symlink("managed.conf", &resolv).expect("resolv symlink");
        let host = ResolvConf::new(&resolv, &state);
        host.apply("100.100.100.100", &[]).expect("apply");
        assert!(fs::symlink_metadata(&resolv)
            .expect("metadata")
            .file_type()
            .is_symlink());
        assert!(fs::read(&managed)
            .expect("managed content")
            .starts_with(b"# Managed by KarstDNS"));
        let _ = fs::remove_dir_all(root);
    }
}
