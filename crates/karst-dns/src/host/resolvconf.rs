// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The live resolver file on a host with no resolver manager of its own.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The revert record.
///
/// `/var/lib` rather than `/run`, and the asymmetry with the NetworkManager
/// record next door is deliberate. NetworkManager's snapshot describes settings
/// applied to the TUN device, which the kernel destroys along with the daemon —
/// a snapshot that outlived it would describe a device that no longer exists,
/// which is why [`NetworkManager::recover`] refuses one whose D-Bus path has
/// changed. This mechanism rewrites `/etc/resolv.conf`, an ordinary file that
/// outlives the daemon *and* the boot, so the record describing how to undo
/// that has to outlive them both.
///
/// Under `/run` it did not: the unit's `RuntimeDirectory=karst` deletes the
/// directory on every stop — including the stop where `ExecStopPost=` failed,
/// which is the only stop the record exists for. FINDINGS.md 62.
///
/// [`NetworkManager::recover`]: super::NetworkManager::recover
pub const REVERT_STATE: &str = "/var/lib/karst/dns-revert";

/// Where the record lived before FINDINGS.md 62 moved it. Read, never written.
///
/// A node upgraded in place while MagicDNS was applied has its only copy here,
/// and dropping it would be worse than never having written one: the next
/// [`ResolvConf::apply`] would capture the *stub-pointing* `resolv.conf` as the
/// original, making the bad state the one recovery restores. Removable once no
/// supported upgrade can begin before the release that moved the record.
pub const LEGACY_REVERT_STATE: &str = "/run/karst/dns-revert";

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
    legacy_state_path: Option<PathBuf>,
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
            legacy_state_path: None,
        }
    }

    /// Integrate against the real `/etc/resolv.conf` and `/var/lib/karst`.
    #[must_use]
    pub fn system() -> Self {
        Self::new(RESOLV_CONF, REVERT_STATE).with_legacy_state(LEGACY_REVERT_STATE)
    }

    /// Also read a record left at an older location. See [`LEGACY_REVERT_STATE`].
    #[must_use]
    pub fn with_legacy_state(mut self, path: impl Into<PathBuf>) -> Self {
        self.legacy_state_path = Some(path.into());
        self
    }

    /// Capture and persist the original content before replacing it atomically.
    pub fn apply(&self, nameserver: &str, search_domains: &[String]) -> io::Result<Revert> {
        let live = self.live_path()?;
        let original = self.original_contents()?;
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
        // Exactly one record exists at any moment. Writing the durable copy
        // first and retiring the legacy one second means a crash in between
        // leaves two identical originals rather than none.
        self.remove_legacy_state()?;
        Self::write_atomic(&live, &revert.applied)?;
        Ok(revert)
    }

    /// Restore an explicit revert record and remove its durable marker.
    pub fn revert(&self, revert: &Revert) -> io::Result<()> {
        Self::write_atomic(&self.live_path()?, &revert.original)?;
        self.remove_state()
    }

    /// Recover a previous interrupted application. Missing state means no
    /// prior change, so startup is idempotent.
    pub fn recover(&self) -> io::Result<bool> {
        let Some(revert) = self.read_state()? else {
            return Ok(false);
        };
        // A later administrator or network manager change wins. Do not restore
        // stale bytes over a configuration Karst no longer owns.
        if fs::read(self.live_path()?)? != revert.applied {
            self.remove_state()?;
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
        match self.read_state()? {
            Some(revert) => Ok(revert.original),
            None => fs::read(self.live_path()?),
        }
    }

    /// The current revert record, from the durable location or failing that the
    /// legacy one. A record written by this build always wins.
    fn read_state(&self) -> io::Result<Option<Revert>> {
        for path in self.state_paths().into_iter().flatten() {
            match fs::read(path) {
                Ok(state) => return Ok(Some(Revert::decode(&state)?)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Remove the record from every location it can be read from. A revert is
    /// complete only when no copy survives to be replayed over a resolver
    /// configuration Karst no longer owns.
    fn remove_state(&self) -> io::Result<()> {
        for path in self.state_paths().into_iter().flatten() {
            Self::remove_file(path)?;
        }
        Ok(())
    }

    fn remove_legacy_state(&self) -> io::Result<()> {
        match &self.legacy_state_path {
            Some(path) => Self::remove_file(path),
            None => Ok(()),
        }
    }

    /// The durable location first, then the legacy one when it is a different
    /// file. Order is the precedence [`Self::read_state`] relies on.
    fn state_paths(&self) -> [Option<&Path>; 2] {
        let legacy = self
            .legacy_state_path
            .as_deref()
            .filter(|path| *path != self.state_path.as_path());
        [Some(self.state_path.as_path()), legacy]
    }

    fn remove_file(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
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
        // The packages ship `/var/lib/karst` at 0700 and `StateDirectory=karst`
        // recreates it at that mode, but a `karstd` run by hand has neither. The
        // mode is not tidiness: the netmap cache shares this directory and holds
        // one pre-shared key per peer — THREAT-MODEL R5, FINDINGS.md 61 — so
        // creating it at the process umask would publish them to every local
        // user. An existing directory is left exactly as the operator has it.
        if !parent.as_os_str().is_empty() && !parent.exists() {
            create_private_dir(parent)?;
        }
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

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
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

    /// FINDINGS.md 62. A node upgraded in place while MagicDNS was applied has
    /// its only revert record at the old `/run` location. If the new build
    /// cannot see it, the host keeps pointing at a stub that stopped listening
    /// and nothing on the machine can say what it pointed at before.
    #[test]
    fn a_record_left_at_the_old_location_is_still_recovered() {
        let root = std::env::temp_dir().join(format!("karst-dns-legacy-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let legacy = root.join("run-dns-revert");
        let durable = root.join("state-dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");

        // The old build: one record, at the location it knew.
        ResolvConf::new(&resolv, &legacy)
            .apply("100.100.100.100", &[])
            .expect("apply");

        let upgraded = ResolvConf::new(&resolv, &durable).with_legacy_state(&legacy);
        assert!(upgraded.recover().expect("recover"), "the record was found");
        assert_eq!(
            fs::read(&resolv).expect("restored"),
            b"nameserver 9.9.9.9\n"
        );
        assert!(!legacy.exists(), "a consumed record leaves no copy behind");
        let _ = fs::remove_dir_all(root);
    }

    /// The durable record is the one that gets written, and the legacy copy is
    /// retired rather than left to be replayed by a downgrade or a stale reader.
    #[test]
    fn applying_moves_the_record_to_the_durable_location() {
        let root = std::env::temp_dir().join(format!("karst-dns-migrate-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let legacy = root.join("run-dns-revert");
        let durable = root.join("state-dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");

        let host = ResolvConf::new(&resolv, &durable).with_legacy_state(&legacy);
        host.apply("100.100.100.100", &[]).expect("apply");
        assert!(durable.exists(), "the durable record was written");
        assert!(!legacy.exists(), "the legacy location holds nothing");

        // And the original it captured is the host's, not the stub it installed.
        assert_eq!(
            host.original_contents().expect("original"),
            b"nameserver 9.9.9.9\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The state directory is a confidentiality boundary — the netmap cache
    /// shares it — so a daemon that has to create it must not use its umask.
    #[cfg(unix)]
    #[test]
    fn a_created_state_directory_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("karst-dns-mode-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temporary root");
        let resolv = root.join("resolv.conf");
        let state = root.join("created/dns-revert");
        fs::write(&resolv, b"nameserver 9.9.9.9\n").expect("original config");

        ResolvConf::new(&resolv, &state)
            .apply("100.100.100.100", &[])
            .expect("apply");

        let mode = fs::metadata(root.join("created"))
            .expect("state directory")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "state directory mode");
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
