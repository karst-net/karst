// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! macOS host DNS integration: the `/etc/resolver` directory.
//!
//! A file named for a domain in `/etc/resolver/` tells `mDNSResponder` to send
//! queries below that domain to the nameserver the file names, longest suffix
//! winning. That is exactly the split-DNS semantics [`crate::Config`] already
//! describes, and it needs no daemon restart and no privileged API — a file
//! write and a cache flush are the whole mechanism.
//!
//! **Compiled on every platform, on purpose.** Nothing here is a syscall; it is
//! path handling, byte formats and a crash-recovery protocol, all of which are
//! easy to get wrong and none of which need a Mac to exercise. Building it
//! everywhere means the tests below run on the same job as the rest of the
//! suite rather than only on the macOS runner, and it means a Linux build
//! type-checks the whole macOS DNS path. `karstd` still refuses to *select*
//! this mechanism off macOS, where the files it writes would change nothing.
//!
//! # What this does not do
//!
//! `/etc/resolver` routes names **that are already fully qualified**. It has no
//! key for the resolver search list, so a bare `laptop` does not become
//! `laptop.aquifer.karst` through this mechanism — that list lives in the
//! SystemConfiguration store, and putting an entry there requires holding an
//! `SCDynamicStore` session open for as long as the entry should live. A
//! `scutil` child process cannot do it: its session ends when it exits, and the
//! store drops the keys with it. Doing it properly means linking
//! SystemConfiguration and calling `SCDynamicStoreSetValue` from `karstd`
//! itself, which under ADR-0003 means the FFI belongs in `karst-tun`. That is
//! the remaining piece of `plans/phase-5/06-macos-client.md` §5 and it is
//! recorded there rather than half-built here.
//!
//! Because the absence is invisible from the outside — every search domain
//! still gets a resolver file, and names below it still resolve when qualified
//! — `karstd` states it rather than leaving it to be discovered: `karst dns
//! status` reports `search_list = "not applied"` beneath the search-domain
//! list, and the daemon warns once on the first netmap that carries one. See
//! `karstd`'s `HostRuntime::search_list`.
//!
//! # Crash recovery
//!
//! The revert record is written before the first resolver file and removed
//! after the last one is restored, so a daemon killed mid-apply leaves enough
//! behind to undo. Two things make that record less load-bearing here than in
//! [`super::resolvconf`]:
//!
//! - It lives under `/var/db`, not `/var/run`. macOS clears the latter on boot,
//!   and resolver files do not disappear with it — a laptop that panics would
//!   otherwise come back with permanent stale DNS and no record of why.
//! - Every file Karst writes carries a marker line, so [`Macos::recover`] can
//!   still find and remove its own leftovers when the record is gone entirely.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};

/// The first bytes of every resolver file Karst writes. It is what makes an
/// orphaned file recognizable as ours after the revert record is lost, so it is
/// matched as a prefix and must not be reworded without reading
/// [`Macos::recover`].
const MARKER: &str = "# Managed by KarstDNS";

/// Where `mDNSResponder` looks for per-domain resolver configuration.
pub const RESOLVER_DIRECTORY: &str = "/etc/resolver";

/// The revert record. `/var/db` rather than `/var/run` — see the module docs.
pub const REVERT_STATE: &str = "/var/db/karst/dns-revert";

/// Errors applying macOS host DNS configuration.
#[derive(Debug, thiserror::Error)]
pub enum MacosError {
    #[error("{path}: {source}")]
    Io {
        /// The path the operation was against.
        path: String,
        /// The underlying failure.
        source: io::Error,
    },
    /// A name arrived that Karst will not turn into a path component. Resolver
    /// file names come from the netmap, so this is a refusal, not a repair.
    #[error(
        "{domain:?} is not a name KarstDNS will create a resolver file for: \
         every label must be 1-63 bytes of ASCII letters, digits or '-'"
    )]
    Domain {
        /// The name as it arrived.
        domain: String,
    },
    #[error("KarstDNS revert state at {path} is {detail}")]
    State {
        /// The record that could not be read.
        path: String,
        /// What is wrong with it.
        detail: &'static str,
    },
}

/// One resolver file Karst owns, and whatever was there before it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedFile {
    /// The file name inside the resolver directory, already validated.
    name: String,
    /// The bytes to put back, or `None` if the file did not exist.
    original: Option<Vec<u8>>,
    /// The bytes Karst wrote, so recovery can tell its own file from a
    /// replacement somebody else installed afterwards.
    applied: Vec<u8>,
}

/// Everything one apply must undo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Revert {
    files: Vec<ManagedFile>,
    /// Whether Karst created the resolver directory itself. A machine that had
    /// no `/etc/resolver` before should not keep an empty one afterwards.
    created_directory: bool,
}

/// How to nudge `mDNSResponder` after the resolver files change.
///
/// macOS caches negative results aggressively enough that skipping this makes
/// the first minute after connecting look broken, so it is part of apply and of
/// revert rather than an optimization. It is an enum because the alternative
/// spelling — a boxed closure — costs the struct its `Debug`, and because the
/// counting variant lets the tests assert the flush happened at all.
#[derive(Debug)]
enum Flush {
    /// `dscacheutil -flushcache`, then `killall -HUP mDNSResponder`.
    Responder,
    /// Count the calls instead of making them. Tests only — a Linux runner has
    /// neither command, and asserting the count is how the flush stays part of
    /// apply and revert rather than something a refactor can quietly drop.
    #[cfg(test)]
    Counted(AtomicU32),
}

/// macOS host DNS integration over one resolver directory.
///
/// The directory and the revert record are constructor arguments so tests never
/// touch `/etc`; [`Macos::system`] supplies the real pair.
#[derive(Debug)]
pub struct Macos {
    directory: PathBuf,
    state_path: PathBuf,
    flush: Flush,
    applied: Option<Revert>,
    flush_error: Option<String>,
}

impl Macos {
    /// Integrate against caller-supplied paths.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            state_path: state_path.into(),
            flush: Flush::Responder,
            applied: None,
            flush_error: None,
        }
    }

    /// Integrate against the real `/etc/resolver` and `/var/db/karst`.
    #[must_use]
    pub fn system() -> Self {
        Self::new(RESOLVER_DIRECTORY, REVERT_STATE)
    }

    /// Point every mesh name at the KarstDNS stub.
    ///
    /// The zone and each search domain get a file of their own: `mDNSResponder`
    /// matches the longest suffix, so a name below any of them reaches the stub
    /// and every other name keeps the resolvers the host already had. This is
    /// the same shape as the `resolved` integration's link domains with
    /// `SetLinkDefaultRoute(false)`, reached by a different mechanism.
    ///
    /// Applying twice reverts the first application first, so the persisted
    /// original is always the host's pre-Karst state and never a previous
    /// generation of Karst's own files.
    pub fn apply(
        &mut self,
        stub: SocketAddr,
        zone: &str,
        search_domains: &[String],
    ) -> Result<(), MacosError> {
        // Validate every name before touching the filesystem: a netmap that
        // names one domain Karst will not write must leave host DNS alone
        // rather than half-configured.
        let names = resolver_names(zone, search_domains)?;
        // `restore`, not `revert`: the difference is the cache flush, and this
        // one is not worth making. The apply below ends with a flush of its
        // own, so flushing here would spend a second pair of subprocesses
        // publishing a configuration that exists for microseconds.
        if let Some(previous) = self.applied.take() {
            self.restore(&previous)?;
        }
        let created_directory = !self.directory.exists();
        fs::create_dir_all(&self.directory).map_err(io_at(&self.directory))?;

        let content = resolver_file(stub);
        let mut files = Vec::with_capacity(names.len());
        for name in names {
            let path = self.directory.join(&name);
            let original = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(io_at(&path)(error)),
            };
            files.push(ManagedFile {
                name,
                original,
                applied: content.clone(),
            });
        }
        let revert = Revert {
            files,
            created_directory,
        };

        // The record first, always. Everything after this point is undoable by
        // a later process; anything written before it would not be.
        self.write_state(&revert)?;
        for file in &revert.files {
            let path = self.directory.join(&file.name);
            write_atomic(&path, &file.applied).map_err(io_at(&path))?;
        }
        self.applied = Some(revert);
        self.flush();
        Ok(())
    }

    /// Put the resolver directory back the way it was found.
    pub fn revert(&mut self) -> Result<(), MacosError> {
        let Some(revert) = self.applied.take() else {
            // Nothing is applied, so a flush failure recorded by an earlier
            // generation describes a cache that no longer shadows anything.
            // Left in place it would be re-reported on every netmap poll.
            self.flush_error = None;
            return Ok(());
        };
        self.restore(&revert)?;
        self.flush();
        Ok(())
    }

    /// Undo an application this process did not make.
    ///
    /// Returns whether anything was undone. Missing state is not an error: it
    /// is the ordinary case on a first start, and it is the whole reason
    /// startup can call this unconditionally.
    ///
    /// Two recoveries happen here, and they cover different failures:
    ///
    /// 1. **The record.** Each file it names is restored only if it still holds
    ///    the bytes Karst wrote. A file somebody has since replaced belongs to
    ///    whoever replaced it, and writing stale bytes over their change would
    ///    be worse than leaving it.
    /// 2. **The marker sweep.** Any *other* file in the directory beginning
    ///    with [`MARKER`] is Karst's leftover from a run whose record is gone —
    ///    a reboot that cleared it, or a partial write. Those can only ever be
    ///    files Karst created, so removing them is the correct restoration.
    pub fn recover(&mut self) -> Result<bool, MacosError> {
        let recorded = match fs::read(&self.state_path) {
            Ok(state) => Some(Revert::decode(&state).ok_or_else(|| MacosError::State {
                path: self.state_path.display().to_string(),
                detail: "truncated or malformed",
            })?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_at(&self.state_path)(error)),
        };

        let mut restored = false;
        let mut known: Vec<String> = Vec::new();
        if let Some(revert) = &recorded {
            for file in &revert.files {
                known.push(file.name.clone());
                let path = self.directory.join(&file.name);
                match fs::read(&path) {
                    Ok(live) if live == file.applied => {
                        restore_file(&path, file.original.as_deref())?;
                        restored = true;
                    }
                    // Replaced by somebody else, or already gone. Either way it
                    // is no longer Karst's to put back.
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io_at(&path)(error)),
                }
            }
            remove_if_present(&self.state_path)?;
            if revert.created_directory {
                remove_directory_if_empty(&self.directory);
            }
        }

        restored |= self.sweep_orphans(&known)?;
        if restored {
            self.flush();
        }
        Ok(restored)
    }

    /// Whether every file this process applied still holds the bytes it wrote.
    ///
    /// A comparison rather than a marker check, for the same reason the
    /// `resolv.conf` controller compares: an administrator's later edit has to
    /// read as external ownership, not as Karst's own state.
    pub fn observe(&self) -> Result<bool, MacosError> {
        let Some(revert) = &self.applied else {
            return Ok(false);
        };
        if revert.files.is_empty() {
            return Ok(false);
        }
        for file in &revert.files {
            let path = self.directory.join(&file.name);
            match fs::read(&path) {
                Ok(live) if live == file.applied => {}
                Ok(_) => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(io_at(&path)(error)),
            }
        }
        Ok(true)
    }

    /// Why the last cache flush failed, if it did.
    ///
    /// A failed flush is reported rather than returned: the resolver files are
    /// already correct when it happens, so failing [`Macos::apply`] for it would
    /// tell the operator the opposite of what occurred. The consequence is
    /// bounded and worth naming — resolutions cached before the change are
    /// served until they expire.
    #[must_use]
    pub fn flush_error(&self) -> Option<&str> {
        self.flush_error.as_deref()
    }

    fn restore(&mut self, revert: &Revert) -> Result<(), MacosError> {
        for file in &revert.files {
            let path = self.directory.join(&file.name);
            restore_file(&path, file.original.as_deref())?;
        }
        remove_if_present(&self.state_path)?;
        if revert.created_directory {
            remove_directory_if_empty(&self.directory);
        }
        Ok(())
    }

    fn sweep_orphans(&self, known: &[String]) -> Result<bool, MacosError> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_at(&self.directory)(error)),
        };
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(io_at(&self.directory))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if known.contains(&name) {
                continue;
            }
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            match fs::read(&path) {
                Ok(live) if live.starts_with(MARKER.as_bytes()) => {
                    remove_if_present(&path)?;
                    removed = true;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_at(&path)(error)),
            }
        }
        Ok(removed)
    }

    fn write_state(&self, revert: &Revert) -> Result<(), MacosError> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).map_err(io_at(parent))?;
        }
        write_atomic(&self.state_path, &revert.encode()).map_err(io_at(&self.state_path))
    }

    fn flush(&mut self) {
        let outcome = self.flush.run().err();
        self.flush_error = outcome;
    }
}

impl Flush {
    fn run(&self) -> Result<(), String> {
        let commands: [(&str, &[&str]); 2] = [
            ("/usr/bin/dscacheutil", &["-flushcache"]),
            ("/usr/bin/killall", &["-HUP", "mDNSResponder"]),
        ];
        match self {
            #[cfg(test)]
            Self::Counted(calls) => {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Self::Responder => {
                for (program, args) in commands {
                    let output = Command::new(program)
                        .args(args)
                        .output()
                        .map_err(|error| format!("{program}: {error}"))?;
                    if !output.status.success() {
                        return Err(format!(
                            "{program} exited {}: {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr).trim()
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// The bytes of one resolver file.
///
/// `port` is written even when it is 53, because one file format is easier to
/// reason about than two and `resolver(5)` accepts it either way.
fn resolver_file(stub: SocketAddr) -> Vec<u8> {
    format!(
        "{MARKER}; removed on shutdown.\nnameserver {}\nport {}\n",
        stub.ip(),
        stub.port()
    )
    .into_bytes()
}

/// The resolver file names for one netmap DNS configuration, deduplicated and
/// ordered so two identical configurations produce identical records.
fn resolver_names(zone: &str, search_domains: &[String]) -> Result<Vec<String>, MacosError> {
    let mut names = Vec::with_capacity(search_domains.len() + 1);
    for domain in std::iter::once(zone).chain(search_domains.iter().map(String::as_str)) {
        let name = resolver_name(domain)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// One domain, as a file name inside the resolver directory.
///
/// **This is a path component built from control-plane data**, and the check is
/// [`crate::canonical_name`] — the same rule [`crate::Config::new`] applies to
/// the zone and the search list before a resolver is ever built. Reusing it is
/// deliberate: a second, subtly different definition of "an acceptable domain"
/// is how a name gets past one gate and not the other, and this one decides
/// where a file lands on disk.
///
/// It is a whitelist — a sequence of ordinary DNS labels — rather than a search
/// for the dangerous cases, so `.`, `..`, an embedded `/`, and anything else
/// that would escape the directory are refused without depending on having
/// thought of them.
///
/// The empty name is the one case handled here rather than there:
/// `canonical_name` returns it unchanged, because an absent search domain is
/// not an error, and an empty *file name* very much is.
fn resolver_name(domain: &str) -> Result<String, MacosError> {
    let refuse = || MacosError::Domain {
        domain: domain.to_owned(),
    };
    let name = crate::canonical_name(domain.trim()).map_err(|_| refuse())?;
    if name.is_empty() {
        return Err(refuse());
    }
    Ok(name)
}

fn restore_file(path: &Path, original: Option<&[u8]>) -> Result<(), MacosError> {
    match original {
        Some(bytes) => write_atomic(path, bytes).map_err(io_at(path)),
        None => remove_if_present(path),
    }
}

fn remove_if_present(path: &Path) -> Result<(), MacosError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_at(path)(error)),
    }
}

/// Best effort, and deliberately so: another resolver file appearing between
/// the emptiness check and the removal means the directory is in use, which is
/// the outcome this wants anyway.
fn remove_directory_if_empty(directory: &Path) {
    if let Ok(mut entries) = fs::read_dir(directory) {
        if entries.next().is_none() {
            let _ = fs::remove_dir(directory);
        }
    }
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> MacosError + '_ {
    move |source| MacosError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Write through a temporary file in the same directory, so a reader never sees
/// a partial resolver file and a crash leaves either the old bytes or the new.
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

impl Revert {
    /// `count`, then per file: name, whether an original existed, the original,
    /// and the applied bytes; then the directory flag. Length-prefixed
    /// throughout, which is what lets [`Revert::decode`] be total.
    fn encode(&self) -> Vec<u8> {
        let mut state = Vec::new();
        let count = u64::try_from(self.files.len()).unwrap_or(u64::MAX);
        state.extend_from_slice(&count.to_be_bytes());
        for file in &self.files {
            put_bytes(&mut state, file.name.as_bytes());
            match &file.original {
                Some(original) => {
                    state.push(1);
                    put_bytes(&mut state, original);
                }
                None => state.push(0),
            }
            put_bytes(&mut state, &file.applied);
        }
        state.push(u8::from(self.created_directory));
        state
    }

    /// `None` for anything that does not decode exactly. A revert record is
    /// read as root and acted on by writing files, so a partial parse is not
    /// something to salvage.
    fn decode(state: &[u8]) -> Option<Self> {
        let mut rest = state;
        let count = usize::try_from(u64::from_be_bytes(take_array(&mut rest)?)).ok()?;
        let mut files = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let name = String::from_utf8(take_bytes(&mut rest)?.to_vec()).ok()?;
            let original = match take_array::<1>(&mut rest)? {
                [0] => None,
                [1] => Some(take_bytes(&mut rest)?.to_vec()),
                _ => return None,
            };
            let applied = take_bytes(&mut rest)?.to_vec();
            files.push(ManagedFile {
                name,
                original,
                applied,
            });
        }
        let created_directory = match take_array::<1>(&mut rest)? {
            [0] => false,
            [1] => true,
            _ => return None,
        };
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            files,
            created_directory,
        })
    }
}

fn put_bytes(state: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    state.extend_from_slice(&length.to_be_bytes());
    state.extend_from_slice(bytes);
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_at_checked(N)?;
    *rest = tail;
    head.try_into().ok()
}

fn take_bytes<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = usize::try_from(u64::from_be_bytes(take_array(rest)?)).ok()?;
    let (head, tail) = rest.split_at_checked(length)?;
    *rest = tail;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disposable resolver directory and revert record, removed on drop so a
    /// failing assertion does not leave the next run's fixtures behind.
    struct Fixture {
        root: PathBuf,
        host: Macos,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "karst-dns-macos-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("temporary root");
            let mut host = Macos::new(root.join("resolver"), root.join("state/dns-revert"));
            host.flush = Flush::Counted(AtomicU32::new(0));
            Self { root, host }
        }

        fn resolver(&self, name: &str) -> PathBuf {
            self.root.join("resolver").join(name)
        }

        fn flushes(&self) -> u32 {
            match &self.host.flush {
                Flush::Counted(calls) => calls.load(Ordering::Relaxed),
                Flush::Responder => panic!("fixture must count flushes"),
            }
        }
    }

    fn stub() -> SocketAddr {
        "100.100.100.100:53".parse().expect("stub address")
    }

    #[test]
    fn the_zone_and_every_search_domain_get_a_file() {
        let mut fixture = Fixture::new("apply");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["corp.example.".to_owned()])
            .expect("apply");

        let zone = fs::read_to_string(fixture.resolver("aquifer.karst")).expect("zone file");
        assert!(zone.starts_with(MARKER), "{zone}");
        assert!(zone.contains("nameserver 100.100.100.100"), "{zone}");
        assert!(zone.contains("port 53"), "{zone}");
        assert_eq!(
            fs::read_to_string(fixture.resolver("corp.example")).expect("split file"),
            zone
        );
        assert!(fixture.host.observe().expect("observe"));
        assert_eq!(fixture.flushes(), 1, "apply must flush the resolver cache");
    }

    /// The plan's exit criterion 3 and 5: nothing of Karst's is left behind,
    /// including the directory on a machine that had none.
    #[test]
    fn revert_leaves_the_machine_as_it_was_found() {
        let mut fixture = Fixture::new("revert");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &[])
            .expect("apply");
        fixture.host.revert().expect("revert");

        assert!(!fixture.resolver("aquifer.karst").exists());
        assert!(
            !fixture.root.join("resolver").exists(),
            "a directory Karst created must not survive its revert"
        );
        assert!(!fixture.root.join("state/dns-revert").exists());
        assert_eq!(fixture.flushes(), 2, "revert must flush too");
    }

    #[test]
    fn a_pre_existing_resolver_file_is_restored_byte_for_byte() {
        let fixture = Fixture::new("preexisting");
        let directory = fixture.root.join("resolver");
        fs::create_dir_all(&directory).expect("resolver directory");
        let theirs = b"nameserver 10.0.0.53\n";
        fs::write(fixture.resolver("corp.example"), theirs).expect("their file");

        let mut host = Macos::new(&directory, fixture.root.join("state/dns-revert"));
        host.flush = Flush::Counted(AtomicU32::new(0));
        host.apply(stub(), "aquifer.karst.", &["corp.example".to_owned()])
            .expect("apply");
        assert!(fs::read(fixture.resolver("corp.example"))
            .expect("replaced")
            .starts_with(MARKER.as_bytes()));

        host.revert().expect("revert");
        assert_eq!(
            fs::read(fixture.resolver("corp.example")).expect("restored"),
            theirs
        );
        assert!(
            directory.exists(),
            "a directory Karst did not create must survive its revert"
        );
    }

    /// The SIGKILL case: the process that applied is gone, and the next start
    /// has only the record to work from.
    #[test]
    fn a_killed_daemon_leaves_a_record_the_next_start_consumes() {
        let fixture = Fixture::new("recover");
        let directory = fixture.root.join("resolver");
        let state = fixture.root.join("state/dns-revert");
        let mut killed = Macos::new(&directory, &state);
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed
            .apply(stub(), "aquifer.karst.", &["corp.example".to_owned()])
            .expect("apply");
        drop(killed);

        let mut restarted = Macos::new(&directory, &state);
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(restarted.recover().expect("recover"));
        assert!(!fixture.resolver("aquifer.karst").exists());
        assert!(!fixture.resolver("corp.example").exists());
        assert!(!state.exists());
        assert!(!restarted.observe().expect("observe after recovery"));
    }

    /// A reboot clears `/var/run` but not `/etc/resolver`. The marker is what
    /// makes the leftovers recoverable when the record is gone with it.
    #[test]
    fn orphaned_files_are_recovered_without_a_record_at_all() {
        let fixture = Fixture::new("orphan");
        let directory = fixture.root.join("resolver");
        let state = fixture.root.join("state/dns-revert");
        let mut killed = Macos::new(&directory, &state);
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed.apply(stub(), "aquifer.karst.", &[]).expect("apply");
        drop(killed);
        fs::remove_file(&state).expect("simulate a cleared /var/run");

        let mut restarted = Macos::new(&directory, &state);
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(restarted.recover().expect("recover"));
        assert!(!fixture.resolver("aquifer.karst").exists());
    }

    /// A file somebody else replaced is theirs. Recovery must not write stale
    /// bytes over a change Karst no longer owns.
    #[test]
    fn recovery_does_not_clobber_a_later_external_change() {
        let fixture = Fixture::new("external");
        let directory = fixture.root.join("resolver");
        let state = fixture.root.join("state/dns-revert");
        let mut killed = Macos::new(&directory, &state);
        killed.flush = Flush::Counted(AtomicU32::new(0));
        killed.apply(stub(), "aquifer.karst.", &[]).expect("apply");
        drop(killed);
        fs::write(fixture.resolver("aquifer.karst"), b"nameserver 10.0.0.53\n")
            .expect("administrator edit");

        let mut restarted = Macos::new(&directory, &state);
        restarted.flush = Flush::Counted(AtomicU32::new(0));
        assert!(!restarted.recover().expect("recover"));
        assert_eq!(
            fs::read(fixture.resolver("aquifer.karst")).expect("their file"),
            b"nameserver 10.0.0.53\n"
        );
        assert!(!state.exists(), "a consumed record must not be left behind");
    }

    #[test]
    fn observe_reports_a_later_external_change() {
        let mut fixture = Fixture::new("observe");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &[])
            .expect("apply");
        assert!(fixture.host.observe().expect("Karst owns the file"));
        fs::write(fixture.resolver("aquifer.karst"), b"nameserver 10.0.0.53\n")
            .expect("external edit");
        assert!(!fixture.host.observe().expect("external ownership"));
    }

    /// A second netmap generation with a different search list must leave the
    /// first generation's files behind — and revert to the host's own state,
    /// not to the previous Karst state.
    #[test]
    fn a_second_apply_removes_the_first_generations_files() {
        let mut fixture = Fixture::new("regenerate");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["first.example".to_owned()])
            .expect("first apply");
        fixture
            .host
            .apply(stub(), "aquifer.karst.", &["second.example".to_owned()])
            .expect("second apply");

        assert!(!fixture.resolver("first.example").exists());
        assert!(fixture.resolver("second.example").exists());
        // One flush per apply. Undoing the previous generation on the way is
        // not a state anything should be told about — it exists for the length
        // of a few file writes.
        assert_eq!(fixture.flushes(), 2);

        fixture.host.revert().expect("revert");
        assert!(!fixture.root.join("resolver").exists());
    }

    /// The zone is normally also reachable as a search domain. One file, not a
    /// duplicate pair, and no ordering dependence on how the netmap listed it.
    #[test]
    fn a_domain_that_repeats_the_zone_is_written_once() {
        assert_eq!(
            resolver_names(
                "Aquifer.Karst.",
                &["aquifer.karst".to_owned(), "corp.example.".to_owned()]
            )
            .expect("names"),
            vec!["aquifer.karst".to_owned(), "corp.example".to_owned()]
        );
    }

    /// Resolver file names come from the netmap, so this is the boundary where
    /// a control plane stops being able to choose a path.
    #[test]
    fn a_domain_that_would_escape_the_directory_is_refused() {
        let long_label = "a".repeat(64);
        let long_name = "a.".repeat(200);
        for bad in [
            "..",
            ".",
            "",
            "../../etc/cron.d/karst",
            "corp.example/../../x",
            "corp..example",
            ".corp.example",
            "corp example",
            "corp\0example",
            "corp$example",
            // Not an escape, and refused anyway: this is the same rule
            // `Config::new` already applied, and the two must not diverge.
            "corp_example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(resolver_name(bad), Err(MacosError::Domain { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    /// One bad name in the search list must not leave the others applied.
    #[test]
    fn a_refused_domain_leaves_host_dns_untouched() {
        let mut fixture = Fixture::new("refused");
        let error = fixture
            .host
            .apply(stub(), "aquifer.karst.", &["../escape".to_owned()])
            .expect_err("refused");
        assert!(matches!(error, MacosError::Domain { .. }));
        assert!(!fixture.root.join("resolver").exists());
        assert!(!fixture.root.join("state/dns-revert").exists());
        assert_eq!(fixture.flushes(), 0);
    }

    #[test]
    fn the_revert_record_round_trips() {
        let revert = Revert {
            files: vec![
                ManagedFile {
                    name: "aquifer.karst".to_owned(),
                    original: None,
                    applied: resolver_file(stub()),
                },
                ManagedFile {
                    name: "corp.example".to_owned(),
                    original: Some(b"nameserver 10.0.0.53\n".to_vec()),
                    applied: resolver_file(stub()),
                },
            ],
            created_directory: true,
        };
        let encoded = revert.encode();
        assert_eq!(Revert::decode(&encoded), Some(revert));
    }

    /// A record read as root and acted on by writing files is not something to
    /// salvage a prefix of.
    #[test]
    fn a_truncated_or_padded_record_is_refused_outright() {
        let encoded = Revert {
            files: vec![ManagedFile {
                name: "aquifer.karst".to_owned(),
                original: Some(b"nameserver 10.0.0.53\n".to_vec()),
                applied: resolver_file(stub()),
            }],
            created_directory: false,
        }
        .encode();
        for length in 0..encoded.len() {
            assert_eq!(
                Revert::decode(&encoded[..length]),
                None,
                "a {length}-byte prefix must not decode"
            );
        }
        let mut padded = encoded.clone();
        padded.push(0);
        assert_eq!(Revert::decode(&padded), None);
    }

    #[test]
    fn a_malformed_record_is_an_error_rather_than_a_silent_skip() {
        let fixture = Fixture::new("malformed");
        let state = fixture.root.join("state/dns-revert");
        fs::create_dir_all(state.parent().expect("state parent")).expect("state directory");
        fs::write(&state, b"not a revert record").expect("write");
        let mut host = Macos::new(fixture.root.join("resolver"), &state);
        host.flush = Flush::Counted(AtomicU32::new(0));
        assert!(matches!(
            host.recover(),
            Err(MacosError::State { detail, .. }) if detail.contains("malformed")
        ));
    }

    #[test]
    fn recovery_of_a_machine_karst_never_touched_is_a_no_op() {
        let fixture = Fixture::new("untouched");
        let mut host = Macos::new(
            fixture.root.join("resolver"),
            fixture.root.join("state/dns-revert"),
        );
        host.flush = Flush::Counted(AtomicU32::new(0));
        assert!(!host.recover().expect("recover"));
    }

    /// A stub on a non-standard port is what the userspace and test
    /// configurations use, and `resolver(5)` needs to be told.
    #[test]
    fn a_non_standard_stub_port_reaches_the_resolver_file() {
        let file = String::from_utf8(resolver_file("100.100.100.100:5354".parse().expect("stub")))
            .expect("utf-8");
        assert!(file.contains("port 5354"), "{file}");
    }
}
